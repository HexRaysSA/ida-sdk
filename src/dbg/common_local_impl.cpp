//
// This file is included from other files, do not directly compile it.
// It contains the debugger_t structure definition and a few other helper functions
//

#include <loader.hpp>
#include <segregs.hpp>
#include <network.hpp>

int data_id; // idb specific data id

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
  #define is_valid_bpt             is_dalvik_valid_bpt
#elif IS_GDB_DEBUGGER
  #define REGISTERS                nullptr
  #define REGISTERS_SIZE           0
  #define REGISTER_CLASSES         nullptr
  #define REGISTER_CLASSES_DEFAULT 0
  #define is_valid_bpt             gdb_valid_bpt
  #define BPT_CODE                 { 0 }
  #define BPT_CODE_SIZE            0
#else
  #error This processor is not supported yet
#endif

//--------------------------------------------------------------------------
// use actual bitness from ea_helper for local debuggers
int get_default_app_addrsize()
{
  return EAH.ea_size;
}

//--------------------------------------------------------------------------
void update_idd_registers(bool get_idaregs)
{
  dbg_plugmod_base_t *pm = GET_MODULE_DATA(dbg_plugmod_t);
  if ( pm != nullptr )
    pm->update_idd_registers(pm->debugger_inited && get_idaregs);
}

//--------------------------------------------------------------------------
drc_t dbg_plugmod_base_t::g_dbgmod_update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf)
{
  return get_debmod().dbg_update_bpts(nbpts, bpts, nadd, ndel, errbuf);
}

//--------------------------------------------------------------------------
drc_t dbg_plugmod_base_t::update_bpts(
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

    b->code = is_valid_bpt(debugger, b->type, b->ea, b->size);
    if ( b->code == BPT_OK )
      valid_bpt_exists = true;
  }

  if ( !valid_bpt_exists && ndel == 0 )
  {
    if ( nbpts != nullptr )
      *nbpts = 0;
    return DRC_OK;    // none of bpts is writable
  }

  return g_dbgmod_update_bpts(nbpts, bpts, nadd, ndel, errbuf);
}

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_names_to_ida(
        ea_t *addrs,
        const char *const *names,
        int qty)
{
  return do_set_debug_names(addrs, names, qty);
}

//---------------------------------------------------------------------------
THREAD_SAFE int do_set_debug_names(
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
      return get_debmod().import_dll(req) ? 0 : 1;
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
// Initialize debugger plugin
static plugmod_t *idaapi init(void)
{
  dbg_plugmod_t *pm = SET_MODULE_DATA(dbg_plugmod_t);
  deb(IDA_DEBUG_DEBUGGER, "%s: dbg_plugmod_t created\n", pm->dstr().c_str());
  if ( pm->init_plugin() )
  {
    deb(IDA_DEBUG_DEBUGGER, "%s: init_plugin() is successful\n", pm->dstr().c_str());
    pm->hook_event_listener(HT_IDD, pm);
    dbg = &pm->debugger;
    return pm;
  }
  delete pm;
  return nullptr;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
#ifndef DEBUGGER_RESMOD
#  define DEBUGGER_RESMOD 0
#endif

//--------------------------------------------------------------------------
dbg_plugmod_base_t::dbg_plugmod_base_t()
{
  debugger =
  {
    IDD_INTERFACE_VERSION,
    DEBUGGER_NAME,
    DEBUGGER_ID,
    PROCESSOR_NAME,
    DEBUGGER_FLAGS
  | DBG_HAS_ATTACH_PROCESS
  | DBG_HAS_REQUEST_PAUSE
  | DBG_HAS_SET_EXCEPTION_INFO
  | DBG_HAS_THREAD_SUSPEND
  | DBG_HAS_THREAD_CONTINUE
  | DBG_HAS_SET_RESUME_MODE
  | DBG_HAS_THREAD_GET_SREG_BASE
  | DBG_HAS_CHECK_BPT
  | DBG_HAS_REXEC,  // flags

    REGISTER_CLASSES,
    REGISTER_CLASSES_DEFAULT,
    REGISTERS,
    REGISTERS_SIZE,

    MEMORY_PAGE_SIZE,

    nullptr,  // bpt_bytes will be assigned dynamically
    0,        // bpt_size will be assigned dynamically
    0,
    DEBUGGER_RESMOD,
  };

  uchar _bpt_code[] = BPT_CODE;
  constexpr int n = sizeof(_bpt_code);
  CASSERT(n <= MAX_BPT_SIZE);
  memcpy(bpt_code, _bpt_code, n);
  debugger.bpt_bytes = bpt_code;
  debugger.bpt_size = n;
}

dbg_plugmod_t::~dbg_plugmod_t()
{
  deb(IDA_DEBUG_DEBUGGER, "%s: dbg_plugmod_t deleting...\n", dstr().c_str());
  term_plugin();
  // we're being unloaded, clear the 'dbg' pointer if it's ours
  if ( dbg == &debugger )
    dbg = nullptr;
  clr_module_data(data_id);
}

//--------------------------------------------------------------------------
debugger_t &get_debugger()
{
  dbg_plugmod_base_t *pm = GET_MODULE_DATA(dbg_plugmod_t);
  QASSERT(3340, pm != nullptr);
  return pm->debugger;
}

//--------------------------------------------------------------------------
dbg_plugmod_t *get_dbg_plugmod()
{
  dbg_plugmod_t *pm = GET_MODULE_DATA(dbg_plugmod_t);
  QASSERT(3341, pm != nullptr);
  return pm;
}

//--------------------------------------------------------------------------
debmod_t &get_debmod()
{
  return get_dbg_plugmod()->get_debmod();
}

//--------------------------------------------------------------------------
// Variables to be used by built-in IDC functions
void set_idc_ctx(debmod_t *, thid_t tid)
{
  get_dbg_plugmod()->idc_thread = tid;
}

debmod_t *get_idc_debmod()
{
  dbg_plugmod_t *pm = GET_MODULE_DATA(dbg_plugmod_t);
  return pm == nullptr ? nullptr : &pm->get_debmod();
}

thid_t get_idc_tid()
{
  dbg_plugmod_t *pm = GET_MODULE_DATA(dbg_plugmod_t);
  return pm == nullptr ? NO_THREAD : pm->idc_thread;
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
bool dbg_plugmod_base_t::run(size_t arg)
{
  plugin_run(int(arg));
  return true;
}

//--------------------------------------------------------------------------
drc_t dbg_plugmod_base_t::init_debugger(
        const char *hostname,
        int port_num,
        const char *password,
        qstring *errbuf)
{
  auto &dm = get_debmod();
  dm.dbg_set_debugging((debug & IDA_DEBUG_DEBUGGER) != 0);
  dm.debugger_name = debugger.name;
  dm.debugger_processor = debugger.processor;
  dm.debugger_id = debugger.id;
  dm.debugger_flags = debugger.flags; // general debugger capabilities

  if ( !dm.open_remote(hostname, port_num, password, errbuf) )
    return DRC_FAILED;

  uint64 add_debugger_flags = 0;
  drc_t drc = dm.dbg_init(&add_debugger_flags, errbuf);
  if ( drc != DRC_OK )
  {
    dm.close_remote();
    return drc;
  }
  debugger.flags |= add_debugger_flags;
  update_idd_registers();   // TODO DBG ???

  debugger_inited = true;
  register_idc_funcs(true);
  init_dbg_idcfuncs(true);
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  install_x86seh_menu();
#endif
  init_debugger_finished();
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t dbg_plugmod_base_t::term_debugger(void)
{
  if ( debugger_inited )
  {
    debugger_inited = false;
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
    remove_x86seh_menu();
#endif
    init_dbg_idcfuncs(false);
    register_idc_funcs(false);
    auto &dm = get_debmod();
    dm.dbg_term();
    return dm.close_remote();
  }
  return DRC_FAILED;
}

//--------------------------------------------------------------------------
// check that ::dbg points to our debugger
bool dbg_plugmod_base_t::is_our_event() const
{
  return ::dbg->id == debugger.id && ::dbg->flags == debugger.flags;
}

//--------------------------------------------------------------------------
ssize_t idaapi dbg_plugmod_base_t::on_event(ssize_t msgid, va_list va)
{
  // TODO dbg: introduce notion of "active debugger"
  if ( !is_our_event() )
    return DRC_NONE;

  int retcode = DRC_NONE;
  qstring *errbuf;
  auto &dm = get_debmod();

  switch ( msgid )
  {
    case debugger_t::ev_init_debugger:
      {
        const char *hostname = va_arg(va, const char *);
        int portnum = va_arg(va, int);
        const char *password = va_arg(va, const char *);
        errbuf = va_arg(va, qstring *);
        QASSERT(1522, errbuf != nullptr);
        deb(IDA_DEBUG_DEBUGGER, "%s: debugger_t::ev_init_debugger (%s,%d,)\n", dstr().c_str(), hostname, portnum);
        retcode = init_debugger(hostname, portnum, password, errbuf);
      }
      break;

    case debugger_t::ev_term_debugger:
      deb(IDA_DEBUG_DEBUGGER, "%s: debugger_t::ev_term_debugger\n", dstr().c_str());
      retcode = term_debugger();
      break;

    case debugger_t::ev_get_processes:
      {
        procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_get_processes(procs, errbuf);
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
        retcode = dm.dbg_start_process(path,
                                       args,
                                       envs,
                                       startdir,
                                       dbg_proc_flags,
                                       input_path,
                                       input_file_crc32,
                                       errbuf);
        if ( retcode > DRC_NONE )
          update_idd_registers();
      }
      break;

    case debugger_t::ev_attach_process:
      {
        pid_t pid = va_argi(va, pid_t);
        int event_id = va_arg(va, int);
        uint32 dbg_proc_flags = va_arg(va, uint32);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_attach_process(pid, event_id, dbg_proc_flags, errbuf);
        if ( retcode > DRC_NONE )
          update_idd_registers();
      }
      break;

    case debugger_t::ev_detach_process:
      retcode = dm.dbg_detach_process();
      break;

    case debugger_t::ev_get_debapp_attrs:
      {
        debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
        dm.dbg_get_debapp_attrs(out_pattrs);
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
      retcode = dm.dbg_prepare_to_pause_process(errbuf);
      break;

    case debugger_t::ev_exit_process:
      errbuf = va_arg(va, qstring *);
      retcode = dm.dbg_exit_process(errbuf);
      break;

    case debugger_t::ev_get_debug_event:
      {
        gdecode_t *code = va_arg(va, gdecode_t *);
        debug_event_t *event = va_arg(va, debug_event_t *);
        int timeout_ms = va_arg(va, int);
        *code = dm.dbg_get_debug_event(event, timeout_ms);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_resume:
      {
        debug_event_t *event = va_arg(va, debug_event_t *);
        retcode = dm.dbg_continue_after_event(event);
      }
      break;

    case debugger_t::ev_set_backwards:
      {
        bool backwards = va_argi(va, bool);
        retcode = dm.dbg_set_backwards(backwards);
      }
      break;

    case debugger_t::ev_set_exception_info:
      {
        exception_info_t *info = va_arg(va, exception_info_t *);
        int qty = va_arg(va, int);
        dm.dbg_set_exception_info(info, qty);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_suspended:
      {
        bool dlls_added = va_argi(va, bool);
        thread_name_vec_t *thr_names = va_arg(va, thread_name_vec_t *);
        // Let the debugger module populate the names
        dm.dbg_stopped_at_debug_event(nullptr, dlls_added, thr_names);
        if ( dlls_added )
        {
#if !defined(RPC_CLIENT) || defined(RPC_CLIENT_HAS_IMPORT_DLL)
          // Pass the debug names to the kernel
          dm.dispatch_debug_names();
#endif
        }
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_thread_suspend:
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = dm.dbg_thread_suspend(tid);
      }
      break;

    case debugger_t::ev_thread_continue:
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = dm.dbg_thread_continue(tid);
      }
      break;

    case debugger_t::ev_set_resume_mode:
      {
        thid_t tid = va_argi(va, thid_t);
        resume_mode_t resmod = va_argi(va, resume_mode_t);
        retcode = dm.dbg_set_resume_mode(tid, resmod);
      }
      break;

    case debugger_t::ev_read_registers:
      {
        thid_t tid = va_argi(va, thid_t);
        int clsmask = va_arg(va, int);
        regval_t *values = va_arg(va, regval_t *);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_read_registers(tid, clsmask, values, errbuf);
      }
      break;

    case debugger_t::ev_write_register:
      {
        thid_t tid = va_argi(va, thid_t);
        int regidx = va_arg(va, int);
        const regval_t *value = va_arg(va, const regval_t *);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_write_register(tid, regidx, value, errbuf);
      }
      break;

    case debugger_t::ev_thread_get_sreg_base:
      {
        ea_t *answer = va_arg(va, ea_t *);
        thid_t tid = va_argi(va, thid_t);
        int sreg_value = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_thread_get_sreg_base(answer, tid, sreg_value, errbuf);
      }
      break;

    case debugger_t::ev_get_memory_info:
      {
        meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_get_memory_info(*ranges, errbuf);
      }
      break;

    case debugger_t::ev_read_memory:
      {
        size_t *nbytes = va_arg(va, size_t *);
        ea_t ea = va_arg(va, ea_t);
        void *buffer = va_arg(va, void *);
        size_t size = va_arg(va, size_t);
        errbuf = va_arg(va, qstring *);
        ssize_t code = dm.dbg_read_memory(ea, buffer, size, errbuf);
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
        ssize_t code = dm.dbg_write_memory(ea, buffer, size, errbuf);
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
        *bptvc = is_valid_bpt(debugger, type, ea, len);
        if ( *bptvc == BPT_OK )
          *bptvc = dm.dbg_is_ok_bpt(type, ea, len);
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
        retcode = dm.dbg_update_lowcnds(nupdated, lowcnds, nlowcnds, errbuf);
      }
      break;

    case debugger_t::ev_open_file:
      {
        const char *file = va_arg(va, const char *);
        uint64 *fsize = va_arg(va, uint64 *);
        bool readonly = va_argi(va, bool);
        retcode = dm.dbg_open_file(file, fsize, readonly);
      }
      break;

    case debugger_t::ev_close_file:
      {
        int fn = va_arg(va, int);
        dm.dbg_close_file(fn);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_read_file:
      {
        int fn = va_arg(va, int);
        qoff64_t off = va_arg(va, qoff64_t);
        void *buf = va_arg(va, void *);
        size_t size = va_arg(va, size_t);
        retcode = dm.dbg_read_file(fn, off, buf, size);
      }
      break;

    case debugger_t::ev_write_file:
      {
        int fn = va_arg(va, int);
        qoff64_t off = va_arg(va, qoff64_t);
        const void *buf = va_arg(va, const void *);
        size_t size = va_arg(va, size_t);
        retcode = dm.dbg_write_file(fn, off, buf, size);
      }
      break;

    case debugger_t::ev_map_address:
      {
        ea_t *mapped = va_arg(va, ea_t *);
        ea_t ea = va_arg(va, ea_t);
        const regval_t *regs = va_arg(va, const regval_t *);
        int regnum = va_arg(va, int);
        *mapped = dm.map_address(ea, regs, regnum);
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

    case debugger_t::ev_update_call_stack:
      {
        thid_t tid = va_argi(va, thid_t);
        call_stack_t *trace = va_arg(va, call_stack_t *);
        if ( dbg->has_update_call_stack() )
        {
          retcode = dm.dbg_update_call_stack(tid, trace);
          if ( retcode == DRC_FAILED || retcode == DRC_NONE )
          {
            setflag(dbg->flags, DBG_HAS_UPDATE_CALL_STACK, false);
            retcode = DRC_NONE;
          }
        }
      }
      break;

    case debugger_t::ev_appcall:
      if ( debugger.has_appcall() )
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
        *blob_ea = dm.dbg_appcall(func_ea, tid, fti->stkargs, regargs, stkargs, retregs, errbuf, event, opts);
        retcode = DRC_OK;
      }
      break;

    case debugger_t::ev_cleanup_appcall:
      if ( debugger.has_appcall() )
      {
        thid_t tid = va_argi(va, thid_t);
        retcode = dm.dbg_cleanup_appcall(tid);
      }
      break;

    case debugger_t::ev_eval_lowcnd:
      {
        thid_t tid = va_argi(va, thid_t);
        ea_t ea = va_arg(va, ea_t);
        errbuf = va_arg(va, qstring *);
        retcode = dm.dbg_eval_lowcnd(tid, ea, errbuf);
      }
      break;

    case debugger_t::ev_send_ioctl:
      {
        int fn = va_arg(va, int);
        const void *buf = va_arg(va, const void *);
        size_t size = va_arg(va, size_t);
        void **poutbuf = va_arg(va, void **);
        ssize_t *poutsize = va_arg(va, ssize_t *);
        retcode = dm.handle_ioctl(fn, buf, size, poutbuf, poutsize);
      }
      break;

    case debugger_t::ev_dbg_enable_trace:
      {
        thid_t tid = va_arg(va, thid_t);
        bool enable = va_argi(va, bool);
        int trace_flags = va_arg(va, int);
        retcode = dm.dbg_enable_trace(tid, enable, trace_flags) ? DRC_OK : DRC_NONE;
      }
      break;

    case debugger_t::ev_is_tracing_enabled:
      {
        thid_t tid = va_arg(va, thid_t);
        int tracebit = va_arg(va, int);
        retcode = dm.dbg_is_tracing_enabled(tid, tracebit) ? DRC_OK : DRC_NONE;
      }
      break;

    case debugger_t::ev_rexec:
      {
        const char *cmdline = va_arg(va, const char *);
        retcode = dm.dbg_rexec(cmdline);
      }
      break;

    case debugger_t::ev_get_srcinfo_path:
      {
        qstring *path = va_arg(va, qstring *);
        ea_t base = va_arg(va, ea_t);
        bool ok = dm.dbg_get_srcinfo_path(path, base);
        retcode = ok ? DRC_OK : DRC_NONE;
      }
      break;

    case debugger_t::ev_bin_search:
      {
        ea_t *ea = va_arg(va, ea_t *);
        ea_t start_ea = va_arg(va, ea_t);
        ea_t end_ea = va_arg(va, ea_t);
        const compiled_binpat_vec_t *ptns = va_arg(va, const compiled_binpat_vec_t *);
        int srch_flags = va_arg(va, int);
        errbuf = va_arg(va, qstring *);
        if ( ptns != nullptr )
        {
          retcode = dm.dbg_bin_search(ea, start_ea, end_ea, *ptns, srch_flags, errbuf);
          deb(IDA_DEBUG_DEBUGGER,
              "debugger_t::ev_bin_search(%a, %a) -> %d(%s) ea %a\n",
              start_ea,
              end_ea,
              retcode,
              errbuf != nullptr ? errbuf->c_str() : "",
              retcode == DRC_OK && ea != nullptr ? *ea : BADADDR);
        }
      }
      break;


    case debugger_t::ev_get_dynamic_register_set:
      if ( debugger_inited )
      {
        dynamic_register_set_t *regset = va_arg(va, dynamic_register_set_t *);
        // refresh IDAREGS for remote debugger
        retcode = dm.dbg_get_register_descriptions();
        if ( retcode < DRC_NONE )
          return retcode;
        retcode = DRC_OK;
        // copy dynamic register set
        bytevec_t buf;
        serialize_dynamic_register_set(&buf, dm.idaregs);
        memory_deserializer_t mmdsr(buf);
        deserialize_dynamic_register_set(regset, mmdsr);
      }
      break;

    case debugger_t::ev_set_dbg_options:
      {
        const char **res = va_arg(va, const char **);
        const char *keyword = va_arg(va, const char *);
        int pri = va_arg(va, int);
        int value_type = va_arg(va, int);
        const void *value = va_arg(va, const char *);
        deb(IDA_DEBUG_DEBUGGER, "debugger_t::ev_set_dbg_options(%s)\n", keyword);
        const char *tmp = set_dbg_options(keyword, pri, value_type, value);
        if ( keyword != nullptr && streq(keyword, " ") )
        { // special case: check for event implementation
          retcode = tmp == IDPOPT_OK
                  ? DRC_NONE  // not implemented
                  : DRC_OK;   // returned IDPOPT_BADKEY
        }
        else
        {
          if ( res != nullptr )
            *res = tmp;
          update_idd_registers(debugger_inited);
          retcode = DRC_OK;
        }
      }
      break;
  }

  return retcode;
}

//--------------------------------------------------------------------------
void dbg_plugmod_base_t::update_idd_registers(bool get_idaregs)
{
  qnotused(get_idaregs);
#if DEBUGGER_ID != DEBUGGER_ID_TRACE_REPLAYER // replayer handles its register itself
  auto &dm = get_debmod();
  if ( get_idaregs )
    dm.dbg_get_register_descriptions();

  size_t nregs = dm.idaregs.nregs();
  deb(IDA_DEBUG_DEBUGGER, "%s: update_idd_registers(%d) idaregs nregs %d\n", dstr().c_str(), get_idaregs, (int)nregs);
  if ( nregs > 0 ) // dynamic register definitions?
  {
    // register classes
    debugger.regclasses = dm.idaregs.regclasses();
    debugger.default_regclasses = dm.idaregs.default_regclasses;

    // registers
    debugger.nregisters = nregs;
    debugger.registers = dm.idaregs.registers();
  }
  else // static register definitions
  {
    // UI needs to the any register set
#ifdef REGISTERS32
    bool is_64bit = dm.is_64bit_app();
    debugger.nregisters = is_64bit ? REGISTERS_SIZE : REGISTERS32_SIZE;
    debugger.registers = is_64bit ? REGISTERS : REGISTERS32;
#else
    debugger.nregisters = REGISTERS_SIZE;
    debugger.registers = REGISTERS;
#endif
    debugger.regclasses = REGISTER_CLASSES;
    debugger.default_regclasses = REGISTER_CLASSES_DEFAULT;
  }
  deb(IDA_DEBUG_DEBUGGER, "%s: update_idd_registers(%d) debugger.nregisters %d\n", dstr().c_str(), get_idaregs, (int)debugger.nregisters);
#endif
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI|PLUGIN_HIDE|PLUGIN_DBG, // plugin flags
  init,                 // initialize

  nullptr,              // terminate. this pointer may be nullptr.

  nullptr,              // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  comment,              // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
