//
// This file is included from other files, do not directly compile it.
// It contains the debugger_t structure definition and a few other helper functions
//

#include <loader.hpp>
#include <segregs.hpp>
#include <network.hpp>

bool plugin_inited;
bool debugger_inited;

#define IS_GDB_DEBUGGER (DEBUGGER_ID == DEBUGGER_ID_GDB_USER || DEBUGGER_ID == DEBUGGER_ID_ARM_IPHONE_USER || DEBUGGER_ID == DEBUGGER_ID_XNU_USER)

#if TARGET_PROCESSOR == PLFM_386
  #ifndef REGISTERS
    #define REGISTERS              x86_registers
  #endif
  #if !defined(REGISTER32) && defined(__EA64__)
    #define REGISTERS32              x86_x86_registers  // for 32bit app under ida64
  #endif
  #define REGISTERS_SIZE           qnumber(REGISTERS)
  #define REGISTERS32_SIZE         qnumber(REGISTERS32)
  #define REGISTER_CLASSES         x86_register_classes
  #define REGISTER_CLASSES_DEFAULT X86_RC_GENERAL
  #define READ_REGISTERS           x86_read_registers
  #define WRITE_REGISTER           x86_write_register
  #if !IS_GDB_DEBUGGER
    #define is_valid_bpt           is_x86_valid_bpt
  #endif
  #define BPT_CODE                 X86_BPT_CODE
  #define BPT_CODE_SIZE            X86_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_ARM
  #define REGISTERS                arm_registers
  #if !defined(REGISTER32) && defined(__EA64__)
    #define REGISTERS32              arm32_registers
  #endif
  #define REGISTERS_SIZE           qnumber(REGISTERS)
  #define REGISTERS32_SIZE         qnumber(REGISTERS32)
  #define REGISTER_CLASSES         arm_register_classes
  #define REGISTER_CLASSES_DEFAULT ARM_RC_GENERAL
  #define READ_REGISTERS           s_read_registers
  #define WRITE_REGISTER           s_write_register
  #if !IS_GDB_DEBUGGER
    #define is_valid_bpt           is_arm_valid_bpt
  #else
    #define is_valid_bpt           gdb_valid_bpt
  #endif
  #define BPT_CODE                 ARM_BPT_CODE
  #define BPT_CODE_SIZE            ARM_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_DALVIK
  #define BPT_CODE                 { 0 }
  #define BPT_CODE_SIZE            0
  #define READ_REGISTERS           s_read_registers
  #define WRITE_REGISTER           s_write_register
  #define is_valid_bpt             is_dalvik_valid_bpt
#elif IS_GDB_DEBUGGER
  #define REGISTERS                nullptr
  #define REGISTERS_SIZE           0
  #define REGISTER_CLASSES         nullptr
  #define REGISTER_CLASSES_DEFAULT 0
  #define READ_REGISTERS           simple_read_registers
  #define WRITE_REGISTER           simple_write_register
  #define is_valid_bpt             gdb_valid_bpt
  #define BPT_CODE                 { 0 }
  #define BPT_CODE_SIZE            0
#else
  #error This processor is not supported yet
#endif

static const uchar bpt_code[] = BPT_CODE;

//--------------------------------------------------------------------------
// use actual bitness from ea_helper for local debuggers
int get_default_app_addrsize()
{
  return EAH.ea_size;
}

//--------------------------------------------------------------------------
void update_idd_registers()
{
#if DEBUGGER_ID != DEBUGGER_ID_TRACE_REPLAYER // replayer handles its register itself
  size_t nregs = g_dbgmod.idaregs.nregs();
  if ( nregs > 0 ) // dynamic register definitions?
  {
    // register classes
    debugger.regclasses = g_dbgmod.idaregs.regclasses();
    debugger.default_regclasses = 1; // TODO 1 is the general register set

    // registers
    debugger.nregisters = nregs;
    debugger.registers = g_dbgmod.idaregs.registers();
  }
  else // static register definitions
  {
#ifdef REGISTERS32
    bool is_64bit = g_dbgmod.is_64bit_app();
    debugger.nregisters = is_64bit ? REGISTERS_SIZE : REGISTERS32_SIZE;
    debugger.registers = is_64bit ? REGISTERS : REGISTERS32;
#else
    debugger.nregisters = REGISTERS_SIZE;
    debugger.registers = REGISTERS;
#endif
    debugger.regclasses = REGISTER_CLASSES;
    debugger.default_regclasses = REGISTER_CLASSES_DEFAULT;
  }
#endif
}

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  int ret = is_valid_bpt(type, ea, len);
  if ( ret != BPT_OK )
    return ret;
  else
    return g_dbgmod.dbg_is_ok_bpt(type, ea, len);
}

//--------------------------------------------------------------------------
// For ARM, we have to set the low bit of the address to 1 for thumb mode
#if DEBUGGER_ID == DEBUGGER_ID_ARM_LINUX_USER
static drc_t idaapi arm_update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf)
{
  // This function is called from debthread, but to use get_sreg() we must
  // switch to the mainthread
  struct ida_local arm_bptea_fixer_t : public exec_request_t
  {
    update_bpt_info_t *bpts;
    update_bpt_info_t *e;
    qvector<ea_t *> thumb_mode;
    virtual ssize_t idaapi execute(void) override
    {
      for ( update_bpt_info_t *b=bpts; b != e; b++ )
      {
        if ( b->type == BPT_SOFT && get_sreg(b->ea, ARM_T) == 1 )
        {
          b->ea++; // odd address means that thumb bpt must be set
          thumb_mode.push_back(&b->ea);
        }
      }
      return 0;
    }
    arm_bptea_fixer_t(update_bpt_info_t *p1, update_bpt_info_t *p2)
      : bpts(p1), e(p2) {}
  };
  arm_bptea_fixer_t abf(bpts, bpts+nadd);
  execute_sync(abf, MFF_READ);

  drc_t drc = s_update_bpts(nbpts, bpts, nadd, ndel, errbuf);

  // reset the odd bit because the addresses are required by the caller
  for ( int i=0; i < abf.thumb_mode.size(); i++ )
    (*abf.thumb_mode[i])--;

  return drc;
}
#define s_update_bpts arm_update_bpts
#endif

//--------------------------------------------------------------------------
static drc_t idaapi update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf)
{
  bool valid_bpt_exists = false;
  update_bpt_info_t *e = bpts + nadd;
  for ( update_bpt_info_t *b=bpts; b != e; b++ )
  {
    if ( b->code == BPT_SKIP )
      continue;

    b->code = is_valid_bpt(b->type, b->ea, b->size);
    if ( b->code == BPT_OK )
      valid_bpt_exists = true;
  }

  if ( !valid_bpt_exists && ndel == 0 )
  {
    if ( nbpts != nullptr )
      *nbpts = 0;
    return DRC_OK;    // none of bpts is writable
  }

  drc_t drc = s_update_bpts(nbpts, bpts, nadd, ndel, errbuf);
  return drc;
}

//--------------------------------------------------------------------------
#ifndef REMOTE_DEBUGGER
// another copy of this function (for remote debugging) is defined in dbg_rpc_handler.cpp
int send_ioctl(
        void *,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
}
#endif

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_names_to_ida(
        ea_t *addrs,
        const char *const *names,
        int qty)
{
  return ::send_debug_names_to_ida(addrs, names, qty);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_names_to_ida(
        ea_t *addrs,
        const char *const *names,
        int qty)
{
  struct debug_name_handler_t : public exec_request_t
  {
    ea_t *addrs;
    const char *const *names;
    int qty;
    debug_name_handler_t(ea_t *_addrs, const char *const *_names, int _qty)
      : addrs(_addrs), names(_names), qty(_qty) {}
    ssize_t idaapi execute(void) override
    {
      set_arm_thumb_modes(addrs, qty);
      return set_debug_names(addrs, names, qty);
    }
  };
  debug_name_handler_t dnh(addrs, names, qty);
  return execute_sync(dnh, MFF_WRITE);
}

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_event_to_ida(
        const debug_event_t *ev,
        int rqflags)
{
  return ::send_debug_event_to_ida(ev, rqflags);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_event_to_ida(
        const debug_event_t *ev,
        int rqflags)
{
  return handle_debug_event(ev, rqflags);
}

//--------------------------------------------------------------------------
THREAD_SAFE int import_dll(const import_request_t &req)
{
  struct dll_importer_t : public exec_request_t
  {
    const import_request_t &req;
    dll_importer_t(const import_request_t &_req) : req(_req) {}
    ssize_t idaapi execute(void) override
    {
      return g_dbgmod.import_dll(req) ? 0 : 1;
    }
  };
  dll_importer_t di(req);
  return execute_sync(di, MFF_WRITE);
}

//--------------------------------------------------------------------------
#if TARGET_PROCESSOR != PLFM_ARM
void set_arm_thumb_modes(ea_t * /*addrs*/, int /*qty*/)
{
}
#endif

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
bool add_idc_funcs(const ext_idcfunc_t efuncs[], size_t nfuncs, bool reg)
{
  if ( reg )
  {
    for ( int i=0; i < nfuncs; i++ )
      if ( !add_idc_func(efuncs[i]) )
        return false;
  }
  else
  {
    for ( int i=0; i < nfuncs; i++ )
      if ( !del_idc_func(efuncs[i].name) )
        return false;
  }
  return true;
}

//--------------------------------------------------------------------------
static drc_t init_debugger(
        const char *hostname,
        int port_num,
        const char *password,
        qstring *errbuf)
{
  g_dbgmod.dbg_set_debugging((debug & IDA_DEBUG_DEBUGGER) != 0);

  if ( !s_open_remote(hostname, port_num, password, errbuf) )
    return DRC_FAILED;

  uint32_t flags2 = 0;
  drc_t drc = s_init(&flags2, errbuf);
  if ( drc != DRC_OK )
  {
    s_close_remote();
    return drc;
  }

  debugger.flags2 |= flags2;
#if defined(REMOTE_DEBUGGER) && !defined(NO_OPEN_FILE)
  setflag(debugger.flags2, DBG_HAS_OPEN_FILE, true);
#endif
#ifdef HAVE_UPDATE_CALL_STACK
  setflag(debugger.flags2, DBG_HAS_UPDATE_CALL_STACK, true);
#endif
#ifdef HAVE_APPCALL
  setflag(debugger.flags2, DBG_HAS_APPCALL, true);
#endif
#ifdef HAVE_MAP_ADDRESS
  setflag(debugger.flags2, DBG_HAS_MAP_ADDRESS, true);
#endif
  debugger_inited = true;
  processor_specific_init();
  register_idc_funcs(true);
  init_dbg_idcfuncs(true);
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  install_x86seh_menu();
#endif
  return DRC_OK;
}

//--------------------------------------------------------------------------
static drc_t term_debugger(void)
{
  if ( debugger_inited )
  {
    debugger_inited = false;
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
    remove_x86seh_menu();
#endif
    init_dbg_idcfuncs(false);
    register_idc_funcs(false);
    processor_specific_term();
    g_dbgmod.dbg_term();
    return s_close_remote();
  }
  return DRC_FAILED;
}

//--------------------------------------------------------------------------
static ssize_t idaapi idd_notify(void *, int msgid, va_list va)
{
  int retcode = DRC_NONE;
  qstring *errbuf;

  switch ( msgid )
  {
    case debugger_t::ev_init_debugger:
      {
        const char *hostname = va_arg(va, const char *);
        int portnum = va_arg(va, int);
        const char *password = va_arg(va, const char *);
        errbuf = va_arg(va, qstring *);
        QASSERT(1522, errbuf != nullptr);
        retcode = init_debugger(hostname, portnum, password, errbuf);
      }
      break;

    case debugger_t::ev_term_debugger:
      retcode = term_debugger();
      break;

    case debugger_t::ev_get_processes:
      {
        procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
        errbuf = va_arg(va, qstring *);
        retcode = g_dbgmod.dbg_get_processes(procs, errbuf);
      }
      break;

    case debugger_t::ev_start_process:
      {
        const char *path = va_arg(va, const char *);
        const char *args = va_arg(va, const char *);
        const char *startdir = va_arg(va, const char *);
        uint32 dbg_proc_flags = va_arg(va, uint32);
        const char *input_path = va_arg(va, const char *);
        uint32 input_file_crc32 = va_arg(va, uint32);
        errbuf = va_arg(va, qstring *);
        launch_env_t *envs = va_arg(va, launch_env_t *);
        retcode = s_start_process(path,
                                  args,
                                  envs,
                                  startdir,
                                  dbg_proc_flags,
                                  input_path,
                                  input_file_crc32,
                                  errbuf);
      }
      break;

    case debugger_t::ev_attach_process:
      {
        pid_t pid = va_argi(va, pid_t);
        int event_id = va_arg(va, int);
        uint32 dbg_proc_flags = va_arg(va, uint32);
        errbuf = va_arg(va, qstring *);
        retcode = s_attach_process(pid, event_id, dbg_proc_flags, errbuf);
      }
      break;

    case debugger_t::ev_detach_process:
      retcode = g_dbgmod.dbg_detach_process();
      break;

    case debugger_t::ev_get_debapp_attrs:
      {
        debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
        g_dbgmod.dbg_get_debapp_attrs(out_pattrs);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_rebase_if_required_to:
      {
        ea_t new_base = va_arg(va, ea_t);
        rebase_if_required_to(new_base);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_request_pause:
      errbuf = va_arg(va, qstring *);
      retcode = g_dbgmod.dbg_prepare_to_pause_process(errbuf);
      break;

    case debugger_t::ev_exit_process:
      errbuf = va_arg(va, qstring *);
      retcode = g_dbgmod.dbg_exit_process(errbuf);
      break;

    case debugger_t::ev_get_debug_event:
      {
        gdecode_t *code = va_arg(va, gdecode_t *);
        debug_event_t *event = va_arg(va, debug_event_t *);
        int timeout_ms = va_arg(va, int);
        *code = g_dbgmod.dbg_get_debug_event(event, timeout_ms);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_resume:
      {
        debug_event_t *event = va_arg(va, debug_event_t *);
        retcode = g_dbgmod.dbg_continue_after_event(event);
      }
      break;

    case debugger_t::ev_set_exception_info:
      {
        exception_info_t *info = va_arg(va, exception_info_t *);
        int qty = va_arg(va, int);
        g_dbgmod.dbg_set_exception_info(info, qty);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_suspended:
      {
        bool dlls_added = va_argi(va, bool);
        thread_name_vec_t *thr_names = va_arg(va, thread_name_vec_t *);
        s_stopped_at_debug_event(thr_names, dlls_added);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_thread_suspend:
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = g_dbgmod.dbg_thread_suspend(tid);
      }
      break;

    case debugger_t::ev_thread_continue:
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = g_dbgmod.dbg_thread_continue(tid);
      }
      break;

    case debugger_t::ev_set_resume_mode:
      {
        thid_t tid = va_argi(va, thid_t);
        resume_mode_t resmod = va_argi(va, resume_mode_t);
        retcode = g_dbgmod.dbg_set_resume_mode(tid, resmod);
      }
      break;

    case debugger_t::ev_read_registers:
      {
        thid_t tid = va_argi(va, thid_t);
        int clsmask = va_arg(va, int);
        regval_t *values = va_arg(va, regval_t *);
        errbuf = va_arg(va, qstring *);
        retcode = READ_REGISTERS(tid, clsmask, values, errbuf);
      }
      break;

    case debugger_t::ev_write_register:
      {
        thid_t tid = va_argi(va, thid_t);
        int regidx = va_arg(va, int);
        const regval_t *value = va_arg(va, const regval_t *);
        errbuf = va_arg(va, qstring *);
        retcode = WRITE_REGISTER(tid, regidx, value, errbuf);
      }
      break;

    case debugger_t::ev_thread_get_sreg_base:
      {
        ea_t *answer = va_arg(va, ea_t *);
        thid_t tid = va_argi(va, thid_t);
        int sreg_value = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        retcode = g_dbgmod.dbg_thread_get_sreg_base(answer, tid, sreg_value, errbuf);
      }
      break;

    case debugger_t::ev_get_memory_info:
      {
        meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
        errbuf = va_arg(va, qstring *);
        retcode = g_dbgmod.dbg_get_memory_info(*ranges, errbuf);
      }
      break;

    case debugger_t::ev_read_memory:
      {
        size_t *nbytes = va_arg(va, size_t *);
        ea_t ea = va_arg(va, ea_t);
        void *buffer = va_arg(va, void *);
        size_t size = va_arg(va, size_t);
        errbuf = va_arg(va, qstring *);
        ssize_t code = g_dbgmod.dbg_read_memory(ea, buffer, size, errbuf);
        *nbytes = code >= 0 ? code : 0;
        retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
      }
      break;

    case debugger_t::ev_write_memory:
      {
        size_t *nbytes = va_arg(va, size_t *);
        ea_t ea = va_arg(va, ea_t);
        const void *buffer = va_arg(va, void *);
        size_t size = va_arg(va, size_t);
        errbuf = va_arg(va, qstring *);
        ssize_t code = g_dbgmod.dbg_write_memory(ea, buffer, size, errbuf);
        *nbytes = code >= 0 ? code : 0;
        retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
      }
      break;

    case debugger_t::ev_check_bpt:
      {
        int *bptvc = va_arg(va, int *);
        bpttype_t type = va_argi(va, bpttype_t);
        ea_t ea = va_arg(va, ea_t);
        int len = va_arg(va, int);
        *bptvc = is_ok_bpt(type, ea, len);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_update_bpts:
      {
        int *nbpts = va_arg(va, int *);
        update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
        int nadd = va_arg(va, int);
        int ndel = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        retcode = update_bpts(nbpts, bpts, nadd, ndel, errbuf);
      }
      break;

    case debugger_t::ev_update_lowcnds:
      {
        int *nupdated = va_arg(va, int *);
        const lowcnd_t *lowcnds = va_arg(va, const lowcnd_t *);
        int nlowcnds = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        retcode = g_dbgmod.dbg_update_lowcnds(nupdated, lowcnds, nlowcnds, errbuf);
      }
      break;

    case debugger_t::ev_open_file:
      {
        const char *file = va_arg(va, const char *);
        uint64 *fsize = va_arg(va, uint64 *);
        bool readonly = va_argi(va, bool);
        retcode = g_dbgmod.dbg_open_file(file, fsize, readonly);
      }
      break;

    case debugger_t::ev_close_file:
      {
        int fn = va_arg(va, int);
        g_dbgmod.dbg_close_file(fn);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_read_file:
      {
        int fn = va_arg(va, int);
        qoff64_t off = va_arg(va, qoff64_t);
        void *buf = va_arg(va, void *);
        size_t size = va_arg(va, size_t);
        retcode = g_dbgmod.dbg_read_file(fn, off, buf, size);
      }
      break;

    case debugger_t::ev_write_file:
      {
        int fn = va_arg(va, int);
        qoff64_t off = va_arg(va, qoff64_t);
        const void *buf = va_arg(va, const void *);
        size_t size = va_arg(va, size_t);
        retcode = g_dbgmod.dbg_write_file(fn, off, buf, size);
      }
      break;

    case debugger_t::ev_map_address:
      {
        ea_t *mapped = va_arg(va, ea_t *);
        ea_t ea = va_arg(va, ea_t);
        const regval_t *regs = va_arg(va, const regval_t *);
        int regnum = va_arg(va, int);
        *mapped = g_dbgmod.map_address(ea, regs, regnum);
        return DRC_OK;
      }
      break;

    #ifdef GET_DEBMOD_EXTS
    case debugger_t::ev_get_debmod_extensions:
      {
        const void **ext = va_arg(va, const void **);
        *ext = GET_DEBMOD_EXTS();
        retcode = DRC_OK;
      }
      break;
    #endif

    #ifdef HAVE_UPDATE_CALL_STACK
    case debugger_t::ev_update_call_stack:
      {
        thid_t tid = va_argi(va, thid_t);
        call_stack_t *trace = va_arg(va, call_stack_t *);
        if ( dbg->has_update_call_stack() )
          retcode = g_dbgmod.dbg_update_call_stack(tid, trace);
        if ( retcode == DRC_FAILED )
        {
          setflag(dbg->flags2, DBG_HAS_UPDATE_CALL_STACK, false);
          retcode = DRC_NONE;
        }
      }
      break;
    #endif

    #ifdef HAVE_APPCALL
    case debugger_t::ev_appcall:
      {
        ea_t *blob_ea = va_arg(va, ea_t *);
        ea_t func_ea = va_arg(va, ea_t);
        thid_t tid = va_arg(va, thid_t);
        const func_type_data_t *fti = va_arg(va, const func_type_data_t *);
        int nargs = va_arg(va, int);
        const regobjs_t *regargs = va_arg(va, const regobjs_t *);
        relobj_t *stkargs = va_arg(va, relobj_t *);
        regobjs_t *retregs = va_arg(va, regobjs_t *);
        errbuf = va_arg(va, qstring *);
        debug_event_t *event = va_arg(va, debug_event_t *);
        int opts = va_arg(va, int);
        qnotused(nargs);
        *blob_ea = g_dbgmod.dbg_appcall(func_ea, tid, fti->stkargs, regargs, stkargs, retregs, errbuf, event, opts);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_cleanup_appcall:
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = g_dbgmod.dbg_cleanup_appcall(tid);
      }
      break;
    #endif

    case debugger_t::ev_eval_lowcnd:
      {
        thid_t tid = va_argi(va, thid_t);
        ea_t ea = va_arg(va, ea_t);
        errbuf = va_arg(va, qstring *);
        retcode = g_dbgmod.dbg_eval_lowcnd(tid, ea, errbuf);
      }
      break;

    case debugger_t::ev_send_ioctl:
      {
        int fn = va_arg(va, int);
        const void *buf = va_arg(va, const void *);
        size_t size = va_arg(va, size_t);
        void **poutbuf = va_arg(va, void **);
        ssize_t *poutsize = va_arg(va, ssize_t *);
        retcode = g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
      }
      break;

    case debugger_t::ev_dbg_enable_trace:
      {
        thid_t tid = va_arg(va, thid_t);
        bool enable = va_argi(va, bool);
        int trace_flags = va_arg(va, int);
        retcode = g_dbgmod.dbg_enable_trace(tid, enable, trace_flags) ? DRC_OK : DRC_NONE;
      }
      break;

    case debugger_t::ev_is_tracing_enabled:
      {
        thid_t tid = va_arg(va, thid_t);
        int tracebit = va_arg(va, int);
        retcode = g_dbgmod.dbg_is_tracing_enabled(tid, tracebit) ? DRC_OK : DRC_NONE;
      }
      break;

    case debugger_t::ev_rexec:
      {
        const char *cmdline = va_arg(va, const char *);
        retcode = g_dbgmod.dbg_rexec(cmdline);
      }
      break;

    #ifdef HAVE_GET_SRCINFO_PATH
    case debugger_t::ev_get_srcinfo_path:
      {
        qstring *path = va_arg(va, qstring *);
        ea_t base = va_arg(va, ea_t);
        bool ok = g_dbgmod.dbg_get_srcinfo_path(path, base);
        retcode = ok ? DRC_OK : DRC_NONE;
      }
      break;
    #endif

    case debugger_t::ev_bin_search:
      {
        ea_t *ea = va_arg(va, ea_t *);
        ea_t start_ea = va_arg(va, ea_t);
        ea_t end_ea = va_arg(va, ea_t);
        const compiled_binpat_vec_t *ptns = va_arg(va, const compiled_binpat_vec_t *);
        int srch_flags = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        if ( ptns != nullptr )
          retcode = g_dbgmod.dbg_bin_search(ea, start_ea, end_ea, *ptns, srch_flags, errbuf);
      }
      break;
  }

  return retcode;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static plugmod_t *idaapi init(void)
{
  // copy of the definitions from loader.hpp
  // we will delete them after improving the debuggers to use PLUGIN_MULTI.
#define PLUGIN_SKIP  nullptr
#define PLUGIN_KEEP  ((plugmod_t *)2)

  if ( init_plugin() )
  {
    update_idd_registers();
    dbg = &debugger;
    plugin_inited = true;
    return PLUGIN_KEEP;
  }
  return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
  if ( plugin_inited )
  {
    term_plugin();
    plugin_inited = false;
  }
  // we're being unloaded, clear the 'dbg' pointer if it's ours
  if ( dbg == &debugger )
    dbg = nullptr;
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static bool idaapi run(size_t arg)
{
#ifdef HAVE_PLUGIN_RUN
  plugin_run(int(arg));
#else
  qnotused(arg);
#endif
  return true;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

#ifdef SET_DBG_OPTIONS
#  define S_SET_DBG_OPTIONS s_set_dbg_options
#else
#  define S_SET_DBG_OPTIONS nullptr
#  define SET_DBG_OPTIONS nullptr
#endif

#ifndef S_FILETYPE
#  define S_FILETYPE 0
#endif

// DBG_HAS_SET_RESUME_MODE must be set before init_debugger.
// typically arm has no single step mechanism, arm64 macOS11 is an exception.
#if TARGET_PROCESSOR == PLFM_ARM && DEBUGGER_ID != DEBUGGER_ID_ARM_MACOS_USER
#  define S_DBG_HAS_SET_RESUME_MODE 0
#else
#  define S_DBG_HAS_SET_RESUME_MODE DBG_HAS_SET_RESUME_MODE
#endif

#ifndef DEBUGGER_RESMOD
#  define DEBUGGER_RESMOD 0
#endif

debugger_t debugger =
{
  IDD_INTERFACE_VERSION,
  DEBUGGER_NAME,
  DEBUGGER_ID,
  PROCESSOR_NAME,
  DEBUGGER_FLAGS,   // flags
  DBG_HAS_ATTACH_PROCESS
| DBG_HAS_REQUEST_PAUSE
| DBG_HAS_SET_EXCEPTION_INFO
| DBG_HAS_THREAD_SUSPEND
| DBG_HAS_THREAD_CONTINUE
| S_DBG_HAS_SET_RESUME_MODE
| DBG_HAS_THREAD_GET_SREG_BASE
| DBG_HAS_CHECK_BPT
| DBG_HAS_REXEC,  // flags2

  REGISTER_CLASSES,
  REGISTER_CLASSES_DEFAULT,
  REGISTERS,
  REGISTERS_SIZE,

  MEMORY_PAGE_SIZE,

  bpt_code,
  sizeof(bpt_code),
  S_FILETYPE,
  DEBUGGER_RESMOD,

  S_SET_DBG_OPTIONS,
  idd_notify,
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE|PLUGIN_DBG, // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be nullptr.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  comment,              // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
