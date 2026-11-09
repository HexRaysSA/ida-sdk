//
// This file is included from other files, do not directly compile it.
// It contains the implementation of debugger plugin callback functions
//

#include <err.h>
#include <name.hpp>
#include <expr.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

//---------------------------------------------------------------------------
//lint -esym(714, rebase_or_warn) not referenced
int rebase_or_warn(ea_t base, ea_t new_base)
{
  move_segm_code_t code = rebase_program(new_base - base, MSF_FIXONCE);
  if ( code != MOVE_SEGM_OK )
  {
    msg("Failed to rebase program: %s\n", move_segm_strerror(code));
    warning("IDA failed to rebase the program.\n"
      "Most likely it happened because of the debugger\n"
      "segments created to reflect the real memory state.\n\n"
      "Please stop the debugger and rebase the program manually.\n"
      "For that, please select the whole program and\n"
      "use Edit, Segments, Rebase program with delta 0x%08a",
      new_base - base);
  }
  return code;
}

//--------------------------------------------------------------------------
// This code is compiled for local debuggers (like win32_user.plw)
#ifndef RPC_CLIENT

//--------------------------------------------------------------------------
AS_PRINTF(3,0) ssize_t dvmsg(int code, rpc_engine_t *, const char *format, va_list va)
{
  if ( code == 0 )
    return vmsg(format, va);
  if ( code > 0 )
    vwarning(format, va);
  else
    verror(format, va);
  return 0;
}

//--------------------------------------------------------------------------
AS_PRINTF(2,0) void dmsg(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(0, rpc, format, va);
}

//--------------------------------------------------------------------------
AS_PRINTF(2,0) void derror(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(-1, rpc, format, va);
}

//--------------------------------------------------------------------------
AS_PRINTF(2,0) void dwarning(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(1, rpc, format, va);
}

#endif // end of 'local debugger' code

//--------------------------------------------------------------------------
bool lock_begin(void)
{
  return true;
}

//--------------------------------------------------------------------------
bool lock_end(void)
{
  return true;
}

//--------------------------------------------------------------------------
void report_idc_error(
        rpc_engine_t *,
        ea_t ea,
        error_t code,
        ssize_t errval,
        const char *errprm)
{
  // Copy errval/errprm to the locations expected by qstrerror()
  if ( errprm != nullptr && errprm != get_error_string(0) )
    QPRM(1, errprm);
  else if ( code == eOS )
    errno = errval;
  else
    set_error_data(0, errval);

  warning("AUTOHIDE NONE\n%a: %s", ea, qstrerror(code));
}

//--------------------------------------------------------------------------
int for_all_debuggers(debmod_visitor_t &v)
{
  return v.visit(&get_debmod());
}

//--------------------------------------------------------------------------
// Local debuggers must call setup_lowcnd_regfuncs() in order to handle
// register read/write requests from low level bpts.
void init_dbg_idcfuncs(bool init)
{
#if !defined(ENABLE_LOWCNDS)                    \
  || defined(REMOTE_DEBUGGER)                   \
  || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  qnotused(init);
#else
  setup_lowcnd_regfuncs(init ? idc_get_reg_value : nullptr,
                        init ? idc_set_reg_value : nullptr);
#endif
}
