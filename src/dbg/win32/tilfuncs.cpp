
#include <ida.hpp>
#include <err.h>
#include <idp.hpp>
#include <expr.hpp>
#include "debmod.h"
#include "tilfuncs.hpp"

#define PDB_WIN32_SERVER
#include "../../plugins/pdb/common.cpp"
#include "../../plugins/pdb/msdia.cpp"
#include "../../plugins/pdb/varser.hpp"

pdb_thread_t pdb_thread;

//----------------------------------------------------------------------------
pdb_thread_t::pdb_thread_t()
  : pdb_rsess(nullptr), thread_handle(nullptr)
{
  accepting_request = qsem_create(nullptr, 0);
  request_available = qsem_create(nullptr, 0);
  opener_mutex = qmutex_create();
}

//----------------------------------------------------------------------------
//lint -e{1579} might have been freed by a separate function
//lint -esym(1540,pdb_thread_t::*) not deallocated nor zeroed by destructor
pdb_thread_t::~pdb_thread_t()
{
  kill();
  qsem_free(accepting_request);
  qsem_free(request_available);
  qmutex_free(opener_mutex);
}

//----------------------------------------------------------------------------
pdb_remote_session_t::client_read_request_t::client_read_request_t()
  : kind(NONE),
    off_ea(BADADDR),
    buffer(nullptr),
    size(0),
    result(false)
{
  read_req = qsem_create(nullptr, 0);
  read_resp = qsem_create(nullptr, 0);
}

//--------------------------------------------------------------------------
pdb_remote_session_t::client_read_request_t::~client_read_request_t()
{
  qsem_free(read_req);
  qsem_free(read_resp);
  read_req = nullptr;
  read_resp = nullptr;
  buffer = nullptr;
}

//----------------------------------------------------------- pdb thread ---
bool pdb_remote_session_t::client_read_request_t::request_read(
        pdb_rr_kind_t _kind,
        uint64  _off_ea,
        uint32  _count,
        void   *_buffer,
        uint32 *_nread)
{
  // ask the main thread to read memory or file
  off_ea = _off_ea;
  size   = _count;
  buffer = _buffer;
  kind   = _kind;
  qsem_post(read_req);
  qsem_wait(read_resp, INFINITE);
  if ( _nread != nullptr )
    *_nread = size;
  return result;
}

//----------------------------------------------------------- pdb thread ---
int pdb_remote_session_t::pack_symbol(IDiaSymbol *symbol)
{
  sym_storage.qclear();

  DWORD id = 0;
  if ( symbol->get_symIndexId((DWORD *) &id) != S_OK )
    return E_FAIL;
  storage.pack_dd(id);

  DWORD type;
  symbol->get_symTag(&type);

#define PROC_PROP(type, prop, appender_sfx, cast)       \
  do                                                    \
  {                                                     \
    type data;                                          \
    if ( symbol->ge##prop(&data) == S_OK )              \
    {                                                   \
      sym_storage.pack_##appender_sfx((cast) data);     \
      present |= prop;                                  \
    }                                                   \
  } while ( false )

  token_mask_t present = 0;

#define PROC_BOOL(prop) PROC_PROP(BOOL, prop, db, uchar)
  PROC_BOOL(t_constType);
  PROC_BOOL(t_isStatic);
  PROC_BOOL(t_virtual);
  PROC_BOOL(t_volatileType);
  PROC_BOOL(t_code);
  PROC_BOOL(t_hasAssignmentOperator);
  PROC_BOOL(t_hasCastOperator);
  PROC_BOOL(t_function);
  PROC_BOOL(t_constructor);
#undef PROC_BOOL

#define PROC_DWORD(prop) PROC_PROP(DWORD, prop, dd, uint32)
  PROC_DWORD(t_backEndMajor);
  PROC_DWORD(t_baseType);
  PROC_DWORD(t_bitPosition);
  PROC_DWORD(t_callingConvention);
  PROC_DWORD(t_count);
  PROC_DWORD(t_dataKind);
  PROC_DWORD(t_locationType);
  PROC_DWORD(t_registerId);
  PROC_DWORD(t_relativeVirtualAddress);
  PROC_DWORD(t_symIndexId);
  PROC_DWORD(t_symTag);
  PROC_DWORD(t_udtKind);
  PROC_DWORD(t_virtualBaseOffset);
#undef PROC_DWORD

#define PROC_SYMID_FROM_SYM(SymGetter, TokenId)            \
    do                                                     \
    {                                                      \
      DWORD _id;                                           \
      IDiaSymbol *_sym;                                    \
      if ( symbol->SymGetter(&_sym) == S_OK )              \
      {                                                    \
        if ( _sym->get_symIndexId(&_id) == S_OK )          \
        {                                                  \
          sym_storage.pack_dd(_id);                        \
          present |= TokenId;                              \
        }                                                  \
        _sym->Release();                                   \
      }                                                    \
    } while ( false )

  /*
    WARNING: Do ***not*** change the logic below, unless you
    really, absolutely, positively know what you are doing.

    If you think using PROC_DWORD() here is a nicer solution, you are
    (alas) wrong: calling get_classParentId() and get_typeId()
    directly will return IDs to types that, if they are
    attempted to be fetched later, will ... not have the
    same ID anymore.

    That means:
    - get_typeId() -> 0x5325
    - <= current object information (incl. typeId == 0x5325) is returned to client
    - => later, client requests object whose id is 0x5325
    - server succesfully retrieves it, and calls pack_symbol() (i.e., this function)
    - symbol->get_symIndexId() -> 0x5326. Ooops!?!

    Tested w/ pc_aswscan.pe.
  */
  PROC_SYMID_FROM_SYM(get_classParent, t_classParentId);
  PROC_SYMID_FROM_SYM(get_type, t_typeId);
  PROC_SYMID_FROM_SYM(get_lexicalParent, t_lexicalParentId);
#undef PROC_SYMID_FROM_SYM

#define PROC_DWORD64(prop) PROC_PROP(DWORD64, prop, dq, uint64)
  PROC_DWORD64(t_length);
#undef PROC_DWORD64

  // strings
#define PROC_STR(PropGetter, TokenId)           \
  do                                            \
  {                                             \
    BSTR tmp;                                   \
    qstring tmpstr;                             \
    if ( symbol->PropGetter(&tmp) == S_OK )     \
    {                                           \
      utf16_utf8(&tmpstr, tmp);                 \
      SysFreeString(tmp);                       \
      sym_storage.pack_str(tmpstr);             \
      present |= TokenId;                       \
    }                                           \
  } while ( false )
  PROC_STR(get_name, t_name);
#undef PROC_STR

#define PROC_LONG(prop) PROC_PROP(LONG, prop, dd, LONG)
  PROC_LONG(t_offset);
#undef PROC_LONG

#define PROC_ULONGLONG(prop) PROC_PROP(ULONGLONG, prop, dq, LONG)
  PROC_ULONGLONG(t_virtualAddress);
#undef PROC_ULONGLONG

  // variants
  VARIANT var;
  VariantInit(&var);
  if ( symbol->get_value(&var) == S_OK )
  {
    bytevec_t variant_data;
    if ( varser_t::serialize(variant_data, var) )
    {
      sym_storage.append(variant_data.begin(), variant_data.size());
      present |= t_value;
    }
#ifdef _DEBUG
    else
    {
      msg("Cannot serialize variant\n");
    }
#endif
  }
#undef PROC_PROP

  size_t stsz = sym_storage.size();
  storage.pack_dq(present);
  storage.pack_dd(stsz);
  storage.append(sym_storage.begin(), stsz);
  return 0;
}

//-------------------------------------------------------------------------
//                            pdb_remote_session_t
//-------------------------------------------------------------------------
int pdb_remote_session_t::last_id = 0;

//-------------------------------------------------------------------------
pdb_remote_session_t::pdb_remote_session_t()
  : fetch_type(FT_NONE),
    fetch_id(0),
    fetch_va(BADADDR),
    fetch_length(0),
    fetch_file_id(0),
    fetch_lnnum(0),
    fetch_colnum(0),
    fetch_symbol_type(SymTagNull),
    fetch_ok(false),
    is_opening(false)
{
  // NOTE: Don't memzero the entire instance: it holds a
  // client_read_request_t that has semaphores
  memset(&compiler_info, 0, sizeof(compiler_info));
  session_id = ++last_id;
  fetch_complete = qsem_create(nullptr, 0);
  msg("PDB: started session (%d)\n", session_id);
}
//-------------------------------------------------------------------------
pdb_remote_session_t::~pdb_remote_session_t()
{
  qsem_free(fetch_complete);
  fetch_complete = nullptr;
  msg("PDB: terminated session (%d)\n", session_id);
}

//----------------------------------------------------------------------------
bool pdb_remote_session_t::request_pdb_thread(bool wait_for_completion)
{
  qsem_wait(pdb_thread.accepting_request, INFINITE);
  pdb_thread.pdb_rsess = this;
  qsem_post(pdb_thread.request_available);
  if ( wait_for_completion )
    qsem_wait(fetch_complete, INFINITE);
  return fetch_ok;
}

//----------------------------------------------------------------------------
bool pdb_remote_session_t::open(const compiler_info_t &_cc, const pdbargs_t &_args)
{
  compiler_info = _cc;
  args = _args;
  fetch_type = FT_OPEN;
  // For opening a PDB, we don't want to wait for the fetch to be complete:
  // it's up to the win32_server_impl.cpp part to query on that semaphore
  // as part of WIN32_IOCTL_PDB_OPERATION_COMPLETE.
  return request_pdb_thread(/*wait_for_completion=*/ false);
}

//----------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_symbol(uint32 id)
{
  fetch_type = FT_SYMBOL;
  fetch_id = id;
  fetch_symbol_type = SymTagNull;
  return request_pdb_thread();
}

//----------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_children(uint32 id, enum SymTagEnum children_type)
{
  fetch_type = FT_CHILDREN;
  fetch_id = id;
  fetch_symbol_type = children_type;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_lines_by_va(ea_t va, uint64 length)
{
  fetch_type = FT_LINES_BY_VA;
  fetch_va = va;
  fetch_length = length;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_lines_by_coords(uint32 file_id, uint32 lnnum, uint32 colnum)
{
  fetch_type = FT_LINES_BY_COORDS;
  fetch_file_id = file_id;
  fetch_lnnum = lnnum;
  fetch_colnum = colnum;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_symbols_at_va(ea_t va, uint64 length, enum SymTagEnum type)
{
  fetch_type = FT_SYMBOLS_AT_VA;
  fetch_va = va;
  fetch_length = length;
  fetch_symbol_type = type;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_file_compilands(uint32 file_id)
{
  fetch_type = FT_FILE_COMPILANDS;
  fetch_file_id = file_id;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_file_path(uint32 file_id)
{
  fetch_type = FT_FILE_PATH;
  fetch_file_id = file_id;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_symbol_files(uint32 id)
{
  fetch_type = FT_SYMBOL_FILES;
  fetch_id = id;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
bool pdb_remote_session_t::fetch_files(const char *fname)
{
  fetch_type = FT_FIND_FILES;
  fetch_str = fname;
  return request_pdb_thread();
}

//-------------------------------------------------------------------------
struct symbol_packer_t : public pdb_access_t::children_visitor_t
{
  pdb_remote_session_t *pdb_rsess;
  int count;
  symbol_packer_t(pdb_remote_session_t *_pdb_rsess)
    : pdb_rsess(_pdb_rsess), count(0) {}

  HRESULT visit_child(pdb_sym_t &_sym)
  {
    QASSERT(1551, _sym.whoami() == DIA_PDB_SYM);
    dia_pdb_sym_t &diasym = (dia_pdb_sym_t &)_sym;
    if ( pdb_rsess->pack_symbol(diasym.data) == 0 )
      ++count;
    return S_OK;
  }
};

//----------------------------------------------------------- pdb thread ---
bool pdb_remote_session_t::perform()
{
  QASSERT(628, session_ref.opened() || fetch_type == FT_OPEN);
  QASSERT(629, fetch_id != (uint32) -1 || fetch_type == FT_OPEN);

  storage.qclear();
  uint32 syms_count = 0;

  bool stores_syms = fetch_type == FT_CHILDREN
                  || fetch_type == FT_SYMBOL
                  || fetch_type == FT_SYMBOLS_AT_VA
                  || fetch_type == FT_FILE_COMPILANDS;

  if ( stores_syms )
    // Reserve room for the count.
    storage.append(&syms_count, sizeof(syms_count));

  try
  {
    local_pdb_access_t *acc = fetch_type != FT_OPEN
                            ? session_ref.session->pdb_access : nullptr;
    HRESULT hr = E_FAIL;
    switch ( fetch_type )
    {
      // Open
      case FT_OPEN:
        {
          if ( !session_ref.opened() )
          {
            args.user_data = this;
            // pdb_path, input_path, and loaded_base are set by remote
            // in win32_debmod_t::handle_ioctl() WIN32_IOCTL_PDB_OPEN
            hr = session_ref.open_session(args);
            if ( SUCCEEDED(hr) )
            {
              const char *fname = session_ref.session->get_used_fname();
              msg("PDB: successfully opened %s (%d)\n", fname, session_id);
            }
            else
            {
              pdberr_suggest_vs_runtime(hr);
            }
          }
          else
          {
            hr = S_OK; // already opened
          }
        }
        break;
      // Single symbol
      case FT_SYMBOL:
        {
          pdb_sym_t *sym = acc->create_sym(fetch_id);
          pdb_sym_janitor_t janitor_sym(sym);
          QASSERT(1552, sym->whoami() == DIA_PDB_SYM);
          dia_pdb_sym_t *diasym = (dia_pdb_sym_t *)sym;
          if ( pack_symbol(diasym->data) == 0 )
          {
            ++syms_count;
            hr = S_OK;
          }
        }
        break;
      // Children
      case FT_CHILDREN:
        {
          pdb_sym_t *sym = acc->create_sym(fetch_id);
          pdb_sym_janitor_t janitor_sym(sym);
          symbol_packer_t packer(this);
          hr = session_ref.session->pdb_access->iterate_children(
            *sym,
            fetch_symbol_type,
            packer);
          if ( SUCCEEDED(hr) )
            syms_count = packer.count;
        }
        break;
      case FT_LINES_BY_VA:
      case FT_LINES_BY_COORDS:
        {
          pdb_lnnums_t lnnums;
          hr = fetch_type == FT_LINES_BY_VA
            ? acc->sip_retrieve_lines_by_va(&lnnums, fetch_va, fetch_length)
            : acc->sip_retrieve_lines_by_coords(
                    &lnnums, fetch_file_id, fetch_lnnum, fetch_colnum);
          if ( SUCCEEDED(hr) )
          {
            const uint32 sz = uint32(lnnums.size());
            storage.pack_dd(sz);
            for ( uint32 i = 0; i < sz; ++i )
            {
              const pdb_lnnum_t &ln = lnnums[i];
              storage.pack_ea64(ln.va);
              storage.pack_dd(ln.length);
              storage.pack_dd(ln.columnNumber);
              storage.pack_dd(ln.columnNumberEnd);
              storage.pack_dd(ln.lineNumber);
              storage.pack_dd(ln.lineNumberEnd);
              storage.pack_dd(ln.file_id);
              storage.pack_db(ln.statement);
            }
          }
        }
        break;
      case FT_SYMBOLS_AT_VA:
      case FT_FILE_COMPILANDS:
        {
          symbol_packer_t packer(this);
          hr = fetch_type == FT_SYMBOLS_AT_VA
            ? acc->sip_iterate_symbols_at_ea(
                    fetch_va, fetch_length, fetch_symbol_type, packer)
            : acc->sip_iterate_file_compilands(fetch_file_id, packer);
          if ( SUCCEEDED(hr) )
            syms_count = packer.count;
        }
        break;
      case FT_FILE_PATH:
        {
          qstring res;
          hr = acc->sip_retrieve_file_path(&res, nullptr, fetch_file_id);
          if ( SUCCEEDED(hr) )
            storage.pack_str(res.c_str());
        }
        break;
      case FT_SYMBOL_FILES:
      case FT_FIND_FILES:
        {
          qvector<DWORD> res;
          if ( fetch_type == FT_SYMBOL_FILES )
          {
            pdb_sym_t *_sym = acc->create_sym(fetch_id);
            pdb_sym_janitor_t janitor_sym(_sym);
            hr = acc->sip_retrieve_symbol_files(&res, *_sym);
          }
          else
          {
            hr = acc->sip_find_files(&res, fetch_str.c_str());
          }
          if ( SUCCEEDED(hr) )
          {
            // pack_files_ids(res);
            const uint32 sz = uint32(res.size());
            storage.pack_dd(sz);
            for ( uint32 i = 0; i < sz; ++i )
              storage.pack_dd(res[i]);
          }
        }
        break;
      default:
        INTERR(630);
    }

    if ( stores_syms )
      // Patch the count.
      memcpy(storage.begin(), &syms_count, sizeof(syms_count));

    return hr == S_OK;
  }
  catch ( const pdb_exception_t &e )
  {
    msg("Failed fetching data: %s\n", e.what.c_str());
    return false;
  }
}

//----------------------------------------------------------------------------
void pdb_remote_session_t::stop()
{
  // Make sure open file request has finished.
  if ( is_opening )
  {
    while ( !is_done() )
    {
      if ( client_read_request.pending() )
      {
        // Ignore read requests on fetch thread.
        client_read_request.result = false;
        client_read_request.read_complete();
      }
      qsleep(100);
    }
  }
}

//-------------------------------------------------------------------------
bool pdb_thread_t::is_running() const
{
  qmutex_locker_t lock(opener_mutex);
  bool running = thread_handle != nullptr;
  return running;
}

//----------------------------------------------------------------------------
void pdb_thread_t::kill()
{
  qmutex_locker_t lock(opener_mutex);
  if ( thread_handle != nullptr )
  {
    msg("PDB: forcibly killing thread...\n");
    qthread_kill(thread_handle);
    qthread_free(thread_handle);
    thread_handle = nullptr;
  }
}

//----------------------------------------------------------------------------
//lint -e{527} unreachable code
static int idaapi main_pdb_func(void *)
{
  while ( true )
  {
    // wait for the next request from the server thread
    qsem_post(pdb_thread.accepting_request);
    qsem_wait(pdb_thread.request_available, INFINITE);
    pdb_remote_session_t *pdb_rsess = pdb_thread.pdb_rsess;
    pdb_rsess->fetch_ok = pdb_rsess->perform();
    // notify server thread that we are ready
    qsem_post(pdb_rsess->fetch_complete);
  }
  return 0;
}

//----------------------------------------------------------------------------
void pdb_thread_t::start_if_needed()
{
  qmutex_locker_t lock(opener_mutex);
  if ( thread_handle == nullptr )
    thread_handle = qthread_create(main_pdb_func, nullptr);
}
