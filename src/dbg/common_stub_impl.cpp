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

//---------------------------------------------------------------------------
void idaapi s_stopped_at_debug_event(thread_name_vec_t *thr_names, bool dlls_added)
{
  // Let the debugger module populate the names
  g_dbgmod.dbg_stopped_at_debug_event(nullptr, dlls_added, thr_names);
  if ( dlls_added )
  {
#if !defined(RPC_CLIENT) || defined(RPC_CLIENT_HAS_IMPORT_DLL)
    // Pass the debug names to the kernel
    g_dbgmod.set_debug_names();
#endif
  }
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
  return v.visit(&g_dbgmod);
}

//--------------------------------------------------------------------------
drc_t idaapi s_write_register(thid_t tid, int reg_idx, const regval_t *value, qstring *errbuf)
{
  return g_dbgmod.dbg_write_register(tid, reg_idx, value, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi s_read_registers(thid_t tid, int clsmask, regval_t *values, qstring *errbuf)
{
  return g_dbgmod.dbg_read_registers(tid, clsmask, values, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi s_update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf)
{
  return g_dbgmod.dbg_update_bpts(nbpts, bpts, nadd, ndel, errbuf);
}

//--------------------------------------------------------------------------
drc_t s_init(uint32_t *flags2, qstring *errbuf)
{
  g_dbgmod.debugger_flags = debugger.flags;
  drc_t retcode = g_dbgmod.dbg_init(flags2, errbuf);
  if ( retcode > DRC_NONE )
    update_idd_registers();
  return retcode;
}

//--------------------------------------------------------------------------
static drc_t s_attach_process(
        pid_t process_id,
        int event_id,
        int flags,
        qstring *errbuf)
{
  drc_t retcode = g_dbgmod.dbg_attach_process(process_id, event_id, flags, errbuf);
  if ( retcode > DRC_NONE )
    update_idd_registers();
  return retcode;
}

//--------------------------------------------------------------------------
static drc_t s_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf)
{
  drc_t retcode = g_dbgmod.dbg_start_process(path,
                                             args,
                                             envs,
                                             startdir,
                                             flags,
                                             input_path,
                                             input_file_crc32,
                                             errbuf);
  if ( retcode > DRC_NONE )
    update_idd_registers();
  return retcode;
}

#ifdef SET_DBG_OPTIONS
//--------------------------------------------------------------------------
// forward declaration
const char *idaapi SET_DBG_OPTIONS(
        const char *keyword,
        int pri,
        int value_type,
        const void *value);

//--------------------------------------------------------------------------
static const char *idaapi s_set_dbg_options(
        const char *keyword,
        int pri,
        int value_type,
        const void *value)
{
  const char *ret = SET_DBG_OPTIONS(keyword, pri, value_type, value);
  update_idd_registers();
  return ret;
}
#endif

//--------------------------------------------------------------------------
#ifdef REMOTE_DEBUGGER
bool s_open_remote(const char *hostname, int port_number, const char *password, qstring *errbuf)
{
  return g_dbgmod.open_remote(hostname, port_number, password, errbuf);
}
drc_t s_close_remote(void)
{
  return g_dbgmod.close_remote();
}
#else
bool s_open_remote(const char *, int, const char *, qstring *)
{
  return true;
}
drc_t s_close_remote(void)
{
  return DRC_OK;
}
#endif

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
