#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
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

#define LINUX_NODE "$ remote linux options"   //lint !e750 not referenced

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

#include "dbg_rpc_client.h"
#include "rpc_debmod.h"
#include "linux_rpc.h"
#include "stack_unwind.hpp"
#include "pc_regs.hpp"
#include "deb_pc.hpp"

//-----------------------------------------------------------------------------
class linux_rpc_debmod_stub_t : public rpc_debmod_t
{
  typedef rpc_debmod_t inherited;

public:
  qstring libunwind_path;
  bool g_must_save_cfg = false;   //lint !e754 not referenced

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

  linux_rpc_debmod_stub_t(const char *plfm_name) : inherited(plfm_name) {}
};
#define LINUX_DEBMOD_T linux_rpc_debmod_stub_t    //lint !e750 not referenced
inline linux_rpc_debmod_stub_t &get_linux_debmod() { return *static_cast<linux_rpc_debmod_stub_t*>(&get_debmod()); }

#include "common_stub_impl.cpp"
#include "linux_local_impl.cpp"

struct dbg_plugmod_t : public dbg_plugmod_stub_t
{
  dbg_plugmod_t()
  {
    debugger.filetype = f_ELF;
  }
  virtual ~dbg_plugmod_t() override;

#define DEFAULT_PLATFORM_NAME "linux"
  linux_rpc_debmod_stub_t g_dbgmod = linux_rpc_debmod_stub_t(DEFAULT_PLATFORM_NAME);
  virtual debmod_t &get_debmod() override { return g_dbgmod; }

  ui_listener_t ui_listener = ui_listener_t(*this);

  //--------------------------------------------------------------------------
  bool init_plugin()
  {
    bool ok = init_linux_plugin(&debugger);
    if ( ok )
    {
      hook_event_listener(HT_UI, &ui_listener);
      debugger.flags |= DBG_HAS_OPEN_FILE;
      debugger.flags |= DBG_HAS_APPCALL;
    }
    return ok;
  }

  void term_plugin()
  {
    save_linux_options();
  }

  //--------------------------------------------------------------------------
  void init_debugger_finished() override
  {
#ifdef HAVE_UPDATE_CALL_STACK
    debugger.flags |= DBG_HAS_UPDATE_CALL_STACK;
#endif
  }

  //--------------------------------------------------------------------------
  const char *set_dbg_options(const char *keyword, int pri, int value_type, const void *value) override
  {
    return set_linux_options(keyword, pri, value_type, value);
  }
};

ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list)
{
  if ( code == ui_saving )
    save_linux_options();
  return 0;
}
#include "common_local_impl.cpp"
