static const char wanted_name[] = "Local Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#define DEBUGGER_FLAGS_BASE (DBG_FLAG_LOWCNDS   \
                           | DBG_FLAG_DEBTHREAD \
                           | DBG_FLAG_ADD_ENVS)
#ifndef __ANDROID__
#define DEBUGGER_FLAGS (DEBUGGER_FLAGS_BASE|DBG_FLAG_DISABLE_ASLR)
#else
#define DEBUGGER_FLAGS (DEBUGGER_FLAGS_BASE)
#endif
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#define LINUX_NODE "$ local linux options"  //lint !e750 not referenced

#include <fpro.h>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <dbg.hpp>
#include "dbg_plugmod.hpp"
#include "linux_debmod.h"
#include "stack_unwind.hpp"

#include "pc_regs.hpp"
#include "deb_pc.hpp"
#include "common_stub_impl.cpp"
#include "linux_local_impl.cpp"

struct dbg_plugmod_t : public dbg_plugmod_user_t
{
  dbg_plugmod_t()
  {
    debugger.filetype = f_ELF;
  }
  virtual ~dbg_plugmod_t() override;

  linux_debmod_t g_dbgmod;
  virtual debmod_t &get_debmod() override { return g_dbgmod; }

  ui_listener_t ui_listener = ui_listener_t(*this);

  //--------------------------------------------------------------------------
  bool init_plugin()
  {
    if ( !init_subsystem() )
      return false;
    bool ok = init_linux_plugin(&debugger);
    if ( ok )
    {
      hook_event_listener(HT_UI, &ui_listener);
      debugger.flags |= DBG_HAS_APPCALL;
    }
    else
    {
      term_subsystem();
    }
    return ok;
  }

  void term_plugin()
  {
    term_subsystem();
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
