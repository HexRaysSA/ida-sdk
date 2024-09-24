#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  int g_nb_insn = 0;
  const int g_max_insn = 20;

  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case dbg_process_start:
      // reset instruction counter
      g_nb_insn = 0;
      break;

    case dbg_run_to:
      msg("tracer: entrypoint reached\n");
      enable_insn_trace(true);
      // while continue_process() would work here too, request+run is more universal
      // because they do not ignore the request queue
      request_continue_process();
      run_requests();
      break;

    // A step occurred (one instruction was executed). This event
    // notification is only generated if step tracing is enabled.
    case dbg_trace:
      {
        /*thid_t tid =*/ va_arg(va, thid_t);
        ea_t ip = va_arg(va, ea_t);
        msg("[%d] tracing over: %a\n", g_nb_insn, ip);
        if ( g_nb_insn == g_max_insn )
        {
          // stop the trace mode and suspend the process
          disable_step_trace();
          suspend_process();
          msg("process suspended (traced %d instructions)\n", g_max_insn);
        }
        else
        {
          g_nb_insn++;
        }
      }
      break;

    case dbg_process_exit:
      unhook_event_listener(HT_DBG, this);
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  if ( !hook_event_listener(HT_DBG, this) )
  {
    warning("Could not hook to notification point");
    return true;
  }

  if ( dbg == nullptr )
    load_debugger("win32", false);

  // Let's start the debugger
  if ( !run_to(inf_get_start_ea()) )
    unhook_event_listener(HT_DBG, this);

  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // Our plugin works only for x86 PE executables
  if ( PH.id != PLFM_386 || inf_get_filetype() != f_PE )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "Instruction tracer sample", // long comment about the plugin
  "",                   // multiline help about the plugin
  "tracer",             // the preferred short name of the plugin
  "",                   // the preferred hotkey to run the plugin
};
