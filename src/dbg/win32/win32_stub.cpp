//lint -e528 not referenced
#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote Windows debugger";

#define DEBUGGER_NAME  "win32"
#define PROCESSOR_NAME "metapc"
#define DEFAULT_PLATFORM_NAME "win32"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE       \
                      | DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_DEBTHREAD    \
                      | DBG_FLAG_ANYSIZE_HWBPT\
                      | DBG_FLAG_ADD_ENVS     \
                      | DBG_FLAG_MERGE_ENVS)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <network.hpp>
#include <dbg.hpp>
#include "dbg_plugmod.hpp"

#include "w32sehch.h"
#include "dbg_rpc_client.h"
#include "rpc_debmod.h"
#include "pc_regs.hpp"
#include "deb_pc.hpp"

#include "common_stub_impl.cpp"
#include "win32_local_impl.cpp"

class win32_rpc_debmod_t : public rpc_debmod_t
{
  typedef rpc_debmod_t inherited;
public:
  win32_rpc_debmod_t(const char *default_platform)
    : rpc_debmod_t(default_platform) {}

  virtual bool idaapi open_remote(
        const char *hostname,
        int port_number,
        const char *password,
        qstring *errbuf) override
  {
    char path[QMAXPATH];
    get_input_file_path(path, sizeof(path));
    pdb_file_path = path;
    return inherited::open_remote(hostname, port_number, password, errbuf);
  }

  qstring pdb_file_path;
};
inline win32_rpc_debmod_t &get_win32_rpc_debmod() { return *static_cast<win32_rpc_debmod_t *>(&get_debmod()); }

//--------------------------------------------------------------------------
// handler on IDA: Server -> IDA
static int ioctl_handler(
        rpc_engine_t * /*rpc*/,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  qnotused(size);
  switch ( fn )
  {
    case WIN32_IOCTL_READFILE:
      {
        user_cancelled();
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;
        uint64 offset = unpack_dq(&ptr, end);
        uint32 length = unpack_dd(&ptr, end);

        *poutbuf = nullptr;
        *poutsize = 0;
        if ( length != 0 )
        {
          FILE *infile = qfopen(get_win32_rpc_debmod().pdb_file_path.c_str(), "rb");
          if ( infile == nullptr )
            return -2;

          void *outbuf = qalloc(length);
          if ( outbuf == nullptr )
            return -2;

          qfseek(infile, offset, SEEK_SET);
          int readlen = qfread(infile, outbuf, length);
          qfclose(infile);

          if ( readlen < 0 || readlen > length )
          {
            qfree(outbuf);
            return -2;
          }
          *poutbuf = outbuf;
          *poutsize = readlen;
        }
        return 1;
      }
  }
  return 0;
}

//--------------------------------------------------------------------------
struct dbg_plugmod_t : public dbg_plugmod_stub_t
{
  virtual ~dbg_plugmod_t() override;

  win32_rpc_debmod_t g_dbgmod = win32_rpc_debmod_t(DEFAULT_PLATFORM_NAME);
  virtual debmod_t &get_debmod() override { return g_dbgmod; }

  //--------------------------------------------------------------------------
  // Initialize Win32 debugger stub
  bool init_plugin()
  {
    // There is no need to call win32_init_plugin() (which checks the PE
    // file parameters) if the debugger is only being used to fetch PDBs.
    bool should_init = !netnode(PDB_NODE_NAME).altval(PDB_LOADING_WIN32_DBG);
    if ( should_init && !win32_init_plugin(&debugger) )
      return false;
    g_dbgmod.set_ioctl_handler(ioctl_handler);
    debugger.flags |= DBG_HAS_OPEN_FILE;
    debugger.flags |= DBG_HAS_APPCALL;
    debugger.filetype = f_PE;
    return true;
  }

  void term_plugin(void) {}
};

//--------------------------------------------------------------------------
static const char idc_win32_rdmsr_args[] = { VT_LONG, 0 };
static error_t idaapi idc_win32_rdmsr(idc_value_t *argv, idc_value_t *res)
{
  uint64 value = 0; // shut up the compiler
  uval_t reg = argv[0].num;
  void *out = nullptr;
  ssize_t outsize;
  int code = get_win32_rpc_debmod().send_ioctl(WIN32_IOCTL_RDMSR, &reg, sizeof(reg), &out, &outsize);
  if ( SUCCEEDED(code) && outsize == sizeof(value) )
    value = *(uint64*)out;
  qfree(out);
  if ( FAILED(code) )
  {
    res->num = code;
    return set_qerrno(eExecThrow); // read error, raise exception
  }
  res->set_int64(value);
  return eOk;
}

//--------------------------------------------------------------------------
static const char idc_win32_wrmsr_args[] = { VT_LONG, VT_INT64, 0 };
static error_t idaapi idc_win32_wrmsr(idc_value_t *argv, idc_value_t *res)
{
  win32_wrmsr_t msr;
  msr.reg = argv[0].num;
  msr.value = argv[1].i64;
  res->num = get_win32_rpc_debmod().send_ioctl(WIN32_IOCTL_WRMSR, &msr, sizeof(msr), nullptr, nullptr);
  return eOk;
}

//--------------------------------------------------------------------------
// Installs or uninstalls debugger specific idc functions
static bool register_idc_funcs(bool reg)
{
  static const ext_idcfunc_t idcfuncs[] =
  {
    { IDC_READ_MSR,  idc_win32_rdmsr, idc_win32_rdmsr_args, nullptr, 0, 0 },
    { IDC_WRITE_MSR, idc_win32_wrmsr, idc_win32_wrmsr_args, nullptr, 0, 0 },
  };
  return add_idc_funcs(idcfuncs, qnumber(idcfuncs), reg);
}

#include "common_local_impl.cpp"
