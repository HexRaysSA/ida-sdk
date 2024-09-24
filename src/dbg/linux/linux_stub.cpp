#define REMOTE_DEBUGGER
#define RPC_CLIENT
#if defined(__EA64__) && defined(USE_LIBUNWIND) && !defined(__ANDROID__)
  #define HAVE_UPDATE_CALL_STACK
  #define SET_DBG_OPTIONS set_linux_options
  #define LINUX_NODE "$ remote linux options"

//lint -e754 local struct member '' not referenced
  struct libunwind_pair_name_t
  {
    const char *libx86_64_name;
    const char *libptrace_name;
  };
//lint +e754
//lint -e528 static symbol '' not referenced
  static const libunwind_pair_name_t libunwind_pair_name[] =
  {
    { "libunwind-x86_64.so.8", "libunwind-ptrace.so.0" },
    { "libunwind-x86_64.so", "libunwind-ptrace.so" },
  };
//lint +e528
#endif

static const char wanted_name[] = "Remote Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
#define DEFAULT_PLATFORM_NAME "linux"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#define DEBUGGER_FLAGS_BASE (DBG_FLAG_REMOTE    \
                           | DBG_FLAG_LOWCNDS   \
                           | DBG_FLAG_DEBTHREAD \
                           | DBG_FLAG_ADD_ENVS)
#ifndef __ANDROID__
#define DEBUGGER_FLAGS (DEBUGGER_FLAGS_BASE|DBG_FLAG_DISABLE_ASLR)
#else
#define DEBUGGER_FLAGS (DEBUGGER_FLAGS_BASE)
#endif
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)
#define HAVE_APPCALL
#define S_FILETYPE     f_ELF

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <network.hpp>

#include "dbg_rpc_client.h"
#include "rpc_debmod.h"
#include "linux_rpc.h"

//-----------------------------------------------------------------------------
class linux_rpc_debmod_stub_t : public rpc_debmod_t
{
  typedef rpc_debmod_t inherited;

public:
#ifdef  HAVE_UPDATE_CALL_STACK
  qstring libunwind_path;
  drc_t idaapi dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf)
  {
    if ( !libunwind_path.empty() )
    {
      bytevec_t req;
      req.pack_ds(libunwind_path.c_str());
      if ( send_ioctl(LINUX_IOCTL_LIBUNWIND_PATH, req.begin(), req.size(), nullptr, 0) == 0 )
        dbg_rpc_client_t::dmsg("libunwind: error while sending path to remote debugger\n");
    }
    return inherited::dbg_start_process(
                path, args, envs,
                startdir,
                flags,
                input_path,
                input_file_crc32,
                errbuf);
  }
#endif

  linux_rpc_debmod_stub_t(const char *plfm_name) : inherited(plfm_name) {}
};

linux_rpc_debmod_stub_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "linux_local_impl.cpp"
#include "common_local_impl.cpp"
