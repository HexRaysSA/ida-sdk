//
//
//      This file contains win32 specific implementations of win32_debugger_module class
//      server-side functionality only
//
//

#include <pro.h>
#include "win32_rpc.h"
#include "win32_debmod.h"
#include "dbg_rpc_hlp.h"

bool ida_export idb_utf8(qstring *, const char *, int, int) { return false; }

#include "tilfuncs.hpp"

//---------------------------------------------------------- main thread ---
static AS_PRINTF(3, 4) int pdb_ioctl_error(void **poutbuf, ssize_t *poutsize, const char *format, ...)
{
  char buf[MAXSTR];
  va_list va;
  va_start(va, format);
  int len = qvsnprintf(buf, sizeof(buf), format, va);
  va_end(va);
  msg("%s", buf);

  *poutsize = len + 1;
  *poutbuf  = qstrdup(buf);
  return pdb_error;
}

//---------------------------------------------------------- main thread ---
void win32_debmod_t::handle_pdb_thread_request(void *_pdb_rsess)
{
  pdb_remote_session_t *pdb_rsess = (pdb_remote_session_t *) _pdb_rsess;
  pdb_remote_session_t::client_read_request_t &rr = pdb_rsess->client_read_request;
  if ( rr.kind == READ_INPUT_FILE )
  {
    // read input file
    bytevec_t req;
    req.pack_dq(rr.off_ea);
    req.pack_dd(rr.size);
    void *outbuf = nullptr;
    ssize_t outsize = 0;
    // send request to IDA
    int rc = send_ioctl(WIN32_IOCTL_READFILE, req.begin(), req.size(), &outbuf, &outsize);
    if ( rc == 1 && outbuf != nullptr )
    {
      // OK
      size_t copylen = qmin(rr.size, outsize);
      memcpy(rr.buffer, outbuf, copylen);
      rr.size   = copylen;
      rr.result = true;
    }
    else
    {
      rr.result = false;
    }
    if ( outbuf != nullptr )
      qfree(outbuf);
  }
  else if ( rr.kind == READ_MEMORY )
  {
    // read memory
    ea_t ea = ea_t(rr.off_ea);
    void *buf = rr.buffer;
    size_t size = rr.size;
    ssize_t rc = _read_memory(ea, buf, size);
    if ( rc >= 0 )
      rr.size = rc;
    rr.result = rc >= 0;
  }
  else
  {
    // unknown request
    rr.result = false;
  }

  rr.read_complete();
}

//-------------------------------------------------------------------------
pdb_remote_session_t *win32_debmod_t::get_pdb_session(int id)
{
  for ( size_t i = 0; i < pdb_remote_sessions.size(); ++i )
    if ( pdb_remote_sessions[i]->get_id() == id )
      return pdb_remote_sessions[i];
  return nullptr;
}

//-------------------------------------------------------------------------
void win32_debmod_t::delete_pdb_session(int id)
{
  for ( size_t i = 0; i < pdb_remote_sessions.size(); ++i )
  {
    if ( pdb_remote_sessions[i]->get_id() == id )
    {
      pdb_remote_sessions[i]->stop();
      delete pdb_remote_sessions[i];
      pdb_remote_sessions.erase(pdb_remote_sessions.begin() + i);
      break;
    }
  }
}

//----------------------------------------------------------------------------
void close_pdb_remote_session(pdb_remote_session_t *session)
{
  session->stop();
  delete session;
}

//---------------------------------------------------------- main thread ---
int idaapi win32_debmod_t::handle_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  qnotused(size);
  int sid = 0; // pdb_remote_session_t ID
  pdb_remote_session_t *pdb_rsess = nullptr;
  switch ( fn )
  {
    case WIN32_IOCTL_RDMSR:
      QASSERT(30119, size == sizeof(uval_t));
      {
        uint64 value;
        uval_t reg = *(uval_t *)buf;
        int code = rdmsr(reg, &value);
        if ( SUCCEEDED(code) )
        {
          *poutbuf = qalloc(sizeof(value));
          if ( *poutbuf != nullptr )
          {
            memcpy(*poutbuf, &value, sizeof(value));
            *poutsize = sizeof(value);
          }
        }
        return code;
      }

    case WIN32_IOCTL_WRMSR:
      QASSERT(30120, size == sizeof(win32_wrmsr_t));
      {
        win32_wrmsr_t &msr = *(win32_wrmsr_t *)buf;
        return wrmsr(msr.reg, msr.value);
      }

#define ENSURE_PDB_THREAD()                                             \
      do                                                                \
      {                                                                 \
        if ( !pdb_thread.is_running() )                                 \
          return pdb_ioctl_error(                                       \
                  poutbuf, poutsize, "PDB thread not running?!?\n");    \
      } while ( false )

#define GET_OPENED_SESSION()                                            \
      do                                                                \
      {                                                                 \
        if ( mmdsr.empty() )                                            \
          return pdb_error;                                             \
        sid = mmdsr.unpack_dd();                                        \
        pdb_rsess = get_pdb_session(sid);                               \
      } while ( false )

#define ENSURE_SESSION_OPENED()                                         \
      do                                                                \
      {                                                                 \
        GET_OPENED_SESSION();                                           \
        if ( pdb_rsess == nullptr )                                        \
          return pdb_ioctl_error(                                       \
                  poutbuf, poutsize, "Unknown PDB session #%d\n", sid); \
      } while ( false )

#define FLUSH_PDB_REQUEST_STORAGE()                                     \
      do                                                                \
      {                                                                 \
        size_t sz  = pdb_rsess->storage.size();                         \
        uint8 *raw = (uint8 *) qalloc(sz);                              \
        if ( raw == nullptr )                                              \
          return pdb_error;                                             \
        memcpy(raw, pdb_rsess->storage.begin(), sz);                    \
        *poutbuf   = raw;                                               \
        *poutsize  = sz;                                                \
      } while ( false )

    case WIN32_IOCTL_PDB_OPEN:
      {
        pdb_thread.start_if_needed();
        memory_deserializer_t mmdsr(buf, size);

        pdb_rsess = new pdb_remote_session_t();
        pdb_remote_sessions.push_back(pdb_rsess);

        compiler_info_t cci;
        mmdsr.unpack_obj(&cci, sizeof(cci));
        pdbargs_t args;
        args.pdb_path    = mmdsr.unpack_str();
        args.input_path  = mmdsr.unpack_str();
        mmdsr.unpack_obj(&args.pdb_sign, sizeof(args.pdb_sign));
        args.spath       = mmdsr.unpack_str();
        args.loaded_base = mmdsr.unpack_ea64();
        args.flags       = mmdsr.unpack_dd();
        pdb_rsess->open(cci, args);
        bytevec_t storage;
        storage.pack_dd(pdb_rsess->get_id());
        *poutsize = storage.size();
        *poutbuf = storage.extract();
        pdb_rsess->is_opening = true;
      }
      return pdb_ok;

    case WIN32_IOCTL_PDB_OPERATION_COMPLETE:
      // This is used, in a polling fashion, by the the client,
      // to check on completeness of the fetch. At the same time,
      // this is our wake-up call for looking whether the
      // fetch thread requires more information.
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        // If we've got a read request, handle it now
        if ( pdb_rsess->client_read_request.pending() )
          handle_pdb_thread_request(pdb_rsess);

        bytevec_t storage;
        bool done = pdb_rsess->is_done();
        if ( done )
        {
          pdb_rsess->is_opening = false;
          const char *fname = pdb_rsess->session_ref.session->get_used_fname();
          local_pdb_access_t *acc = pdb_rsess->session_ref.session->pdb_access;
          HRESULT hr = acc != nullptr ? S_OK : E_FAIL;
          if ( SUCCEEDED(hr) )
          {
            storage.pack_dd(uint32(pdb_op_complete));
            storage.pack_dd(acc->get_global_symbol_id());
            storage.pack_dd(acc->get_machine_type());
            storage.pack_dd(acc->get_dia_version());
            storage.pack_str(fname);
          }
          else
          {
            storage.pack_dd(uint32(pdb_op_failure));
            qstring errmsg;
            errmsg.sprnt("%s: %s\n", fname, pdberr(hr));
            storage.pack_str(errmsg.c_str());
            delete_pdb_session(sid);
          }
        }
        else
        {
          storage.pack_dd(uint32(pdb_op_not_complete));
        }

        *poutsize = storage.size();
        *poutbuf = storage.extract();
        return pdb_ok;
      }

    case WIN32_IOCTL_PDB_FETCH_SYMBOL:
    case WIN32_IOCTL_PDB_FETCH_CHILDREN:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        DWORD sym_id = mmdsr.unpack_dd();
        // msg("Fetch%s 0x%x\n",
        //     (fn == WIN32_IOCTL_PDB_FETCH_CHILDREN ? " children for" : ""),
        //     (uint32) sym);
        bool ok;
        if ( fn == WIN32_IOCTL_PDB_FETCH_SYMBOL )
        {
          // Symbol
          ok = pdb_rsess->fetch_symbol(sym_id);
        }
        else
        {
          // Children
          enum SymTagEnum children_type = (enum SymTagEnum) mmdsr.unpack_dd();
          ok = pdb_rsess->fetch_children(sym_id, children_type);
        }

        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();

        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_CLOSE:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        GET_OPENED_SESSION();
        if ( pdb_rsess != nullptr )
          delete_pdb_session(sid);

        return pdb_ok;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_VA:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();
        ea_t va       = mmdsr.unpack_ea64();
        uint64 length = mmdsr.unpack_dq();

        bool ok = pdb_rsess->fetch_lines_by_va(
                va, length);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_COORDS:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        DWORD file_id = mmdsr.unpack_dd();
        DWORD lnnum   = mmdsr.unpack_dd();
        DWORD colnum  = mmdsr.unpack_dd();
        bool ok = pdb_rsess->fetch_lines_by_coords(file_id, lnnum, colnum);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_SYMBOLS_AT_VA:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        ea_t va = mmdsr.unpack_ea64();
        uint64 length = mmdsr.unpack_dq();
        enum SymTagEnum type = (enum SymTagEnum) mmdsr.unpack_dd();
        bool ok = pdb_rsess->fetch_symbols_at_va(va, length, type);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_FILE_COMPILANDS:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        uint32 file_id = mmdsr.unpack_dd();
        bool ok = pdb_rsess->fetch_file_compilands(file_id);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_FILE_PATH:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        uint32 file_id = mmdsr.unpack_dd();
        bool ok = pdb_rsess->fetch_file_path(file_id);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FETCH_SYMBOL_FILES:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        DWORD sym_id = mmdsr.unpack_dd();
        bool ok = pdb_rsess->fetch_symbol_files(sym_id);
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    case WIN32_IOCTL_PDB_SIP_FIND_FILES:
      {
        ENSURE_PDB_THREAD();
        memory_deserializer_t mmdsr(buf, size);
        ENSURE_SESSION_OPENED();

        qstring fname = mmdsr.unpack_str();
        bool ok = pdb_rsess->fetch_files(fname.c_str());
        if ( ok )
          FLUSH_PDB_REQUEST_STORAGE();
        return ok ? pdb_ok : pdb_error;
      }

    default:
      break;
  }
  return 0;
}
