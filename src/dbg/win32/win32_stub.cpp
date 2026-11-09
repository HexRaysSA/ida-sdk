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
#define HAVE_APPCALL
#define S_FILETYPE     f_PE
#define win32_term_plugin       term_plugin

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <network.hpp>

#include "w32sehch.h"
#include "dbg_rpc_client.h"
#include "rpc_debmod.h"

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

win32_rpc_debmod_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "win32_local_impl.cpp"

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
          FILE *infile = qfopen(g_dbgmod.pdb_file_path.c_str(), "rb");
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

//lint -esym(528,init_plugin) static symbol '' not referenced

//--------------------------------------------------------------------------
// Initialize Win32 debugger stub
static bool init_plugin(void)
{
  // There is no need to call win32_init_plugin() (which checks the PE
  // file parameters) if the debugger is only being used to fetch PDBs.
  bool should_init = !netnode(PDB_NODE_NAME).altval(PDB_LOADING_WIN32_DBG);
  if ( should_init && !win32_init_plugin() )
    return false;
  g_dbgmod.set_ioctl_handler(ioctl_handler);
  return true;
}

#include "common_local_impl.cpp"
