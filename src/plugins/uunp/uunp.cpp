// Universal Unpacker based on IDA debugger 1.2
// Unpacks PE files

// The algorithm of this plugin is:

//     1. start the process until the entry point of the packed program
//     2. add a breakpoint at kernel32.GetProcAddress
//     3. resume the execution and wait until the packer calls GetProcAddress
//        if the function name passed to GetProcAddress is not in the ignore-list,
//        then switch to the trace mode
//        A call to GetProcAddress() most likely means that the program has been
//        unpacked in the memory and now it setting up its import table
//     4. trace the program in the single step mode until we jump to
//        the range with the original entry point.
//     5. as soon as the current ip belongs OEP range, suspend the execution and
//        inform the user
//
//  So, in short, we allow the unpacker to do its job full speed until
//  it starts to setup the import table. At this moment we switch to the single
//  step mode and try to find the original entry point.
//
//  While this algorithm works with UPX, aspack, and several other packers,
//  it might fail and execution of the packed program might go out of control.
//  So please use this plugin with precaution.
//
//  Ilfak Guilfanov, Yury Haron

#include <windows.h>

#ifdef _MSC_VER
#  pragma warning(disable: 4996) // GetVersion was declared deprecated
#endif

#include <ida.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <name.hpp>
#include "uunp.hpp"
#include <mergemod.hpp>
int data_id;

//--------------------------------------------------------------------------
#define REGNAME_EAX (inf_is_64bit() ? "rax" : "eax")
#define REGNAME_ECX (inf_is_64bit() ? "rcx" : "ecx")
#define REGVALUE_MASK (inf_is_64bit() ? ea_t(-1) : ea_t(0xffffffffu))

//--------------------------------------------------------------------------
static size_t get_ptrsize(void)
{
#ifndef __EA64__
  return sizeof(ea_t);
#else
  static size_t ptr_sz = 0;
  if ( ptr_sz == 0 )
    ptr_sz = inf_is_64bit() ? 8 : 4;
  return ptr_sz;
#endif
}

//--------------------------------------------------------------------------
bool doPtr(ea_t ea)
{
  bool ok = get_ptrsize() == 4 ? create_dword(ea, 4) : create_qword(ea, 8);
  return ok && op_plain_offset(ea, 0, 0);
}

//--------------------------------------------------------------------------
ea_t getPtr(ea_t ea)
{
  return get_ptrsize() == 4 ? get_dword(ea) : get_qword(ea);
}

//--------------------------------------------------------------------------
inline bool my_add_bpt(uunp_ctx_t &ctx, ea_t ea)
{
  ctx.bpt_ea = ea;
  return add_bpt(ea);
}

//--------------------------------------------------------------------------
inline bool my_del_bpt(uunp_ctx_t &ctx, ea_t ea)
{
  ctx.bpt_ea = BADADDR;
  return del_bpt(ea);
}

//---------------------------------------------------------------------------
inline void uunp_ctx_t::_hide_wait_box()
{
  if ( wait_box_visible )
  {
    wait_box_visible = false;
    hide_wait_box();
  }
}

//--------------------------------------------------------------------------
inline void uunp_ctx_t::set_wait_box(const char *mesg)
{
  if ( wait_box_visible )
  {
    replace_wait_box("HIDECANCEL\n%s", mesg);
  }
  else
  {
    wait_box_visible = true;
    show_wait_box("HIDECANCEL\n%s", mesg);
  }
}

//--------------------------------------------------------------------------
static void move_entry(uunp_ctx_t &ctx, ea_t rstart)
{
  // remove old start
  set_name(inf_get_start_ea(), "");

  // patch inf struct
  inf_set_start_ea(rstart);
  inf_set_start_ip(rstart);

  // add new entry point
  add_entry(rstart, rstart, "start", true);
  ctx.success = true;

  segment_t *ps = getseg(rstart);
  if ( ps != nullptr )
  {
    ps->set_loader_segm(true);
    ps->update();
  }
}

//--------------------------------------------------------------------------
// Unpacker might use some Win32 functions to perform their function
// This function verifies whether we must switch to the trace mode
// or continue to wait for GetProcAddress() of some other interesting function
static bool ignore_win32_api(const char *name)
{
  static const char *const ignore_names[] = { "VirtualAlloc", "VirtualFree" };
  for ( size_t i=0; i < qnumber(ignore_names); i++ )
  {
    if ( strcmp(name, ignore_names[i]) == 0 )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
inline bool is_library_entry(const uunp_ctx_t &ctx, ea_t ea)
{
  return !ctx.curmod.contains(ea);
}

//--------------------------------------------------------------------------
static bool find_module(ea_t ea, modinfo_t *mi)
{
  bool ok;
  for ( ok=get_first_module(mi); ok; ok=get_next_module(mi) )
  {
    if ( range_t(mi->base, mi->base+mi->size).contains(ea) )
      break;
  }
  return ok;
}

//--------------------------------------------------------------------------
static bool create_idata_segm(const range_t &impdir)
{
  segment_t ns;
  segment_t *s = getseg(impdir.start_ea);
  if ( s != nullptr )
    ns = *s;
  else
    ns.sel = setup_selector(0);

  ns.start_ea = impdir.start_ea;
  ns.end_ea   = impdir.end_ea;
  ns.type     = SEG_XTRN;
  ns.set_loader_segm(true);
  bool ok = add_segm_ex(&ns, ".idata", "XTRN", ADDSEG_NOSREG) != 0;
  if ( !ok )
    ok = ask_yn(ASKBTN_NO,
                "HIDECANCEL\n"
                "Cannot create the import segment. Continue anyway?") > ASKBTN_NO;

  return ok;
}

//--------------------------------------------------------------------------
static bool find_impdir(uunp_ctx_t &ctx, range_t *impdir)
{
  impdir->start_ea = impdir->end_ea = 0;

  uint32 ea32 = uint32(ctx.an_imported_func);
  for ( ea_t pos = ctx.curmod.start_ea;
        pos <= ctx.curmod.end_ea;
        pos += sizeof(DWORD) )
  {
    pos = bin_search(pos, ctx.curmod.end_ea, (uchar *)&ea32, nullptr, 4,
                     BIN_SEARCH_NOBREAK|BIN_SEARCH_CASE|BIN_SEARCH_FORWARD);
    if ( pos == BADADDR )
      break;

    // skip unaligned matches
    if ( (pos & 3) != 0 )
      continue;

    // cool, we found a pointer to an imported function
    // now try to determine the impdir bounds
    ea_t bounds[2] = { pos, pos };

    for ( int k=0; k < 2; k++ )
    {
      ea_t ea = pos;
      while ( true )
      {
        if ( k == 1 )
          ea += get_ptrsize();
        else
          ea -= get_ptrsize();

        ea_t func = ctx.is_9x ? ctx.win9x_find_thunk(ea) : getPtr(ea);
        if ( func == 0 )
          continue;

        if ( !is_mapped(func) )
          break;

        if ( ctx.curmod.contains(func) )
          break;

        modinfo_t mi;
        if ( !find_module(func, &mi) )
          break;

        bounds[k] = ea;
      }
    }

    bounds[1] += get_ptrsize();

    asize_t bsize = bounds[1] - bounds[0];
    if ( bsize > impdir->size() )
      *impdir = range_t(bounds[0], bounds[1]);
  }
  return impdir->start_ea != 0;
}

//--------------------------------------------------------------------------
static bool create_impdir(uunp_ctx_t &ctx, const range_t &impdir)
{
  // now rename all entries in impdir
  del_items(impdir.start_ea, DELIT_EXPAND, impdir.size());
  if ( !create_idata_segm(impdir) )
    return false;

  char dll[MAXSTR];
  qstring buf;
  dll[0] = '\0';
  modinfo_t mi;
  mi.base = BADADDR;
  mi.size = 0;
  size_t len = 0;
  for ( ea_t ea=impdir.start_ea; ea < impdir.end_ea; ea += get_ptrsize() )
  {
    doPtr(ea);
    ea_t func = ctx.is_9x ? ctx.win9x_find_thunk(ea) : getPtr(ea);
    if ( get_name(&buf, func) <= 0 )
      continue;

    if ( !range_t(mi.base, mi.base+mi.size).contains(func) )
    {
      find_module(func, &mi);
      qstrncpy(dll, qbasename(mi.name.c_str()), sizeof(dll));
      char *ptr = strrchr(dll, '.');
      if ( ptr != nullptr )
        *ptr = '\0';
      if ( streq(dll, "ntdll32") ) // ntdll32 -> ntdll
        dll[5] = '\0';
      len = strlen(dll);
    }
    const char *name = buf.begin();
    if ( strnicmp(dll, name, len) == 0 && name[len] == '_' )
      name += len + 1;
    if ( !force_name(ea, name, SN_IDBENC) )
      msg("%a: cannot rename to imported name '%s'\n", ea, name);
  }

  return true;
}

//--------------------------------------------------------------------------
static void create_impdir(uunp_ctx_t &ctx)
{
  // refresh dll entry point names
  dbg->suspended(true);

  // refresh memory configuration
  invalidate_dbgmem_config();

  // found impdir?
  range_t impdir;
  if ( !find_impdir(ctx, &impdir) )
    return;

  msg("Uunp: Import directory bounds %a..%a\n", impdir.start_ea, impdir.end_ea);
  create_impdir(ctx, impdir);
}

//--------------------------------------------------------------------------
static void tell_about_failure(void)
{
  warning("The plugin failed to unpack the program, sorry.\n"
          "If you want to improve it, the source code is in the SDK!");
}

//--------------------------------------------------------------------------
ssize_t idaapi dbg_listener_t::on_event(ssize_t code, va_list va)
{
  return ctx.on_dbg_event(code, va);
}

ssize_t idaapi uunp_ctx_t::on_dbg_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case dbg_process_start:
    case dbg_process_attach:
      get_input_file_path(needed_file, sizeof(needed_file));
      // no break
    case dbg_library_load:
      if ( stage == 0 )
      {
        const debug_event_t *pev = va_arg(va, const debug_event_t *);
        const char *modname = pev->modinfo().name.c_str();
        const char *myname = needed_file;
        if ( !inf_is_dll() )
        { // ignore the full path for exe names (to handle subst drives)
          modname = qbasename(modname);
          myname = qbasename(myname);
        }
        if ( !strieq(modname, myname) )
          break;
        if ( code == dbg_library_load )
          is_dll = true;
        // remember the current module bounds
        if ( pev->modinfo().rebase_to != BADADDR )
          curmod.start_ea = pev->modinfo().rebase_to;
        else
          curmod.start_ea = pev->modinfo().base;
        curmod.end_ea = curmod.start_ea + pev->modinfo().size;
        deb(IDA_DEBUG_DBGINFO, "UUNP: module space %a-%a\n", curmod.start_ea, curmod.end_ea);
        ++stage;
      }
      break;

    case dbg_library_unload:
      if ( stage != 0 && is_dll )
      {
        const debug_event_t *pev = va_arg(va, const debug_event_t *);
        if ( curmod.start_ea == pev->modinfo().base
          || curmod.start_ea == pev->modinfo().rebase_to )
        {
          deb(IDA_DEBUG_DBGINFO, "UUNP: unload unpacked module\n");
          if ( stage > 2 )
            enable_step_trace(false);
          stage = 0;
          curmod.start_ea = 0;
          curmod.end_ea = 0;
          _hide_wait_box();
        }
      }
      break;

    case dbg_run_to:   // Parameters: const debug_event_t *event
      dbg->suspended(true);
      bp_gpa = get_name_ea(BADADDR, "kernel32_GetProcAddress");
      if ( (LONG)GetVersion() < 0 )  // win9x mode -- use thunk's
      {
        is_9x = true;
        win9x_resolve_gpa_thunk();
      }
      if ( bp_gpa == BADADDR )
      {
        bring_debugger_to_front();
        warning("Sorry, could not find kernel32.GetProcAddress");
FORCE_STOP:
        stage = 4;  // last stage
        clear_requests_queue();
        request_exit_process();
        run_requests();
        break;
      }
      else if ( !my_add_bpt(*this, bp_gpa) )
      {
        bring_debugger_to_front();
        warning("Sorry, cannot set bpt to kernel32.GetProcAddress");
        goto FORCE_STOP;
      }
      else
      {
        ++stage;
        set_wait_box("Waiting for a call to GetProcAddress()");
      }
      continue_process();
      break;

    case dbg_bpt:      // A user defined breakpoint was reached.
                       // Parameters: thid_t tid
                       //             ea_t        breakpoint_ea
                       //             int        *warn = -1
                       //             Return (in *warn):
                       //              -1 - to display a breakpoint warning dialog
                       //                   if the process is suspended.
                       //               0 - to never display a breakpoint warning dialog.
                       //               1 - to always display a breakpoint warning dialog.
      {
        thid_t tid = va_arg(va, thid_t); qnotused(tid);
        ea_t ea    = va_arg(va, ea_t);
        ea &= REGVALUE_MASK;
        //int *warn = va_arg(va, int*);
        if ( stage == 2 )
        {
          if ( ea == bp_gpa )
          {
            ea_t esp;
            if ( get_sp_val(&esp) )
            {
              invalidate_dbgmem_contents(esp, 1024);
              ea_t gpa_caller = getPtr(esp);
              if ( !is_library_entry(*this, gpa_caller) )
              {
                ea_t nameaddr;
                if ( get_ptrsize() == 4 )
                {
                  nameaddr = get_dword(esp+8);
                }
                else
                {
                  regval_t rv;
                  get_reg_val(REGNAME_ECX, &rv);
                  nameaddr = ea_t(rv.ival) & REGVALUE_MASK;
                }
                invalidate_dbgmem_contents(nameaddr, 1024);
                qstring name;
                size_t len = get_max_strlit_length(nameaddr, STRTYPE_C, ALOPT_IGNHEADS);
                get_strlit_contents(&name, nameaddr, len, STRTYPE_C);
                if ( !ignore_win32_api(name.c_str()) )
                {
                  deb(IDA_DEBUG_DBGINFO, "%a: found a call to GetProcAddress(%s)\n", gpa_caller, name.c_str());
                  if ( !my_del_bpt(*this, bp_gpa) || !my_add_bpt(*this, gpa_caller) )
                    error("Cannot modify breakpoint");
                }
              }
            }
          }
          else if ( ea == bpt_ea )
          {
            my_del_bpt(*this, ea);
            if ( !is_library_entry(*this, ea) )
            {
              msg("Uunp: reached unpacker code at %a, switching to trace mode\n", ea);
              enable_step_trace(true);
              ++stage;
              uint64 eax = 0;
              if ( get_reg_val(REGNAME_EAX, &eax) )
                an_imported_func = ea_t(eax) & REGVALUE_MASK;
              set_wait_box("Waiting for the unpacker to finish");
            }
            else
            {
              warning("%a: bpt in library code", ea); // how can it be?
              my_add_bpt(*this, bp_gpa);
            }
          }
          // not our bpt? skip it
          else
          {
            // hide the wait box to allow others plugins to properly stop
            _hide_wait_box();
            break;
          }
        }
      }
      // while continue_process() would work here too, request+run is more universal
      // because they do not ignore the request queue
      request_continue_process();
      run_requests();
      break;

    case dbg_trace:    // A step occurred (one instruction was executed). This event
                       // notification is only generated if step tracing is enabled.
                       // Parameter:  none
      if ( stage == 3 )
      {
        thid_t tid = va_arg(va, thid_t); qnotused(tid);
        ea_t ip    = va_arg(va, ea_t);
        ip &= REGVALUE_MASK;

        // ip reached the OEP range?
        if ( oep_range.contains(ip) )
        {
          // stop the trace mode
          enable_step_trace(false);
          msg("Uunp: reached OEP %a\n", ip);
          set_wait_box("Reanalyzing the unpacked code");

          // reanalyze the unpacked code
          del_items(oep_range.start_ea, DELIT_EXPAND, oep_range.size());
          auto_make_code(ip); // plan to make code
          plan_range(oep_range.start_ea, oep_range.end_ea); // plan to reanalyze
          auto_mark_range(oep_range.start_ea, oep_range.end_ea, AU_FINAL); // plan to analyze
          move_entry(*this, ip); // mark the program's entry point

          _hide_wait_box();

          // inform the user
          bring_debugger_to_front();
          if ( ask_yn(ASKBTN_YES,
                     "HIDECANCEL\n"
                     "The universal unpacker has finished its work.\n"
                     "Do you want to take a memory snapshot and stop now?\n"
                     "(you can do it yourself if you want)\n") > ASKBTN_NO )
          {
            set_wait_box("Recreating the import table");
            invalidate_dbgmem_config();

            if ( is_9x )
              find_thunked_imports();

            create_impdir(*this);

            set_wait_box("Extracting resources");
            if ( !resfile.empty() )
              extract_resource(resfile.c_str());

            _hide_wait_box();
            if ( take_memory_snapshot(SNAP_LOAD_SEG) )
              goto FORCE_STOP;
          }
          suspend_process();
          unhook_event_listener(HT_DBG, &dbg_listener);
        }
      }
      break;

    case dbg_process_exit:
      {
        stage = 0;
        // stop the tracing
        _hide_wait_box();
        unhook_event_listener(HT_DBG, &dbg_listener);
        if ( success )
          jumpto(inf_get_start_ea(), -1);
        else
          tell_about_failure();
      }
      break;

    case dbg_exception:// Parameters: const debug_event_t *event
                       //             int                 *warn = -1
                       //             Return (in *warn):
                       //              -1 - to display an exception warning dialog
                       //                   if the process is suspended.
                       //               0 - to never display an exception warning dialog.
                       //               1 - to always display an exception warning dialog.

    {
//      const debug_event_t *event = va_arg(va, const debug_event_t *);
//      int *warn = va_arg(va, int *);
      // FIXME: handle code which uses SEH to unpack itself
      if ( ask_yn(ASKBTN_YES,
                  "AUTOHIDE DATABASE\n"
                  "HIDECANCEL\n"
                  "An exception occurred in the program.\n"
                  "UUNP does not support exceptions yet.\n"
                  "The execution has been suspended.\n"
                  "Do you want to continue the unpacking?") <= ASKBTN_NO )
      {
        _hide_wait_box();
        stage = 0;
        enable_step_trace(false); // stop the trace mode
        suspend_process();
      }
      else
      {
        continue_process();
      }
    }
    break;

    case dbg_request_error:
                       // An error occurred during the processing of a request.
                       // Parameters: ui_notification_t  failed_command
                       //             dbg_notification_t failed_dbg_notification
      {
        ui_notification_t  failed_cmd = va_arg(va, ui_notification_t);
        dbg_notification_t failed_dbg_notification = va_arg(va, dbg_notification_t);
        _hide_wait_box();
        stage = 0;
        warning("dbg request error: command: %d notification: %d",
                        failed_cmd, failed_dbg_notification);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// 0 - run uunp interactively
// 1 - run without questions
// 2 - run manual reconstruction
bool idaapi uunp_ctx_t::run(size_t arg)
{
  if ( arg == 2 )
  {
    range_t impdir = range_t(0, 0);
    ea_t oep;

    netnode n;

    // Settings never stored before?
    if ( n.create(UUNP_NODE_NAME) )
    {
      // Populate default values
      oep = get_screen_ea();
      segment_t *s = getseg(oep);
      if ( s != nullptr )
      {
        oep_range.start_ea = s->start_ea;
        oep_range.end_ea = s->end_ea;
      }
    }
    else
    {
      // Restore previous settings
      oep                = n.altval(0);
      oep_range.start_ea = n.altval(1);
      oep_range.end_ea   = n.altval(2);
      impdir.start_ea    = n.altval(3);
      impdir.end_ea      = n.altval(4);
    }
    CASSERT(sizeof(oep_range.start_ea) == sizeof(ea_t));
    CASSERT(sizeof(oep_range.end_ea) == sizeof(ea_t));
    if ( !ask_form("Reconstruction parameters\n"
                   "\n"
                   "  <~O~riginal entrypoint:N::32::>\n"
                   "  <Code ~s~tart address:N::32::>\n"
                   "  <Code ~e~nd address  :N::32::>\n"
                   "\n"
                   "  <IAT s~t~art address:N::32::>\n"
                   "  <IAT e~n~d address:N::32::>\n"
                   "\n",
                   &oep,
                   &oep_range.start_ea, &oep_range.end_ea,
                   &impdir.start_ea, &impdir.end_ea) )
    {
      // Cancelled?
      return true;
    }

    // Invalid settings?
    if ( impdir.start_ea == 0 || impdir.end_ea == 0 )
    {
      msg("Invalid import address table boundaries\n");
      return true;
    }

    // Store settings
    n.altset(0, oep);
    n.altset(1, oep_range.start_ea);
    n.altset(2, oep_range.end_ea);
    n.altset(3, impdir.start_ea);
    n.altset(4, impdir.end_ea);

    if ( !create_impdir(*this, impdir) )
      return false;

    // reanalyze the unpacked code
    del_items(oep_range.start_ea, DELIT_EXPAND, oep_range.size());
    auto_make_code(oep);
    plan_range(oep_range.start_ea, oep_range.end_ea);
    auto_mark_range(oep_range.start_ea, oep_range.end_ea, AU_FINAL);

    // mark the program's entry point
    move_entry(*this, oep);

    take_memory_snapshot(SNAP_LOAD_SEG);
    arg = 0;
    goto oep_setted;
  }

  // Determine the original entry point range
  for ( segment_t *s = get_first_seg(); s != nullptr; s=get_next_seg(s->start_ea) )
  {
    if ( s->type != SEG_GRP )
    {
      oep_range = *s;
      break;
    }
  }

oep_setted:
  if ( arg == 0
    && ask_yn(ASKBTN_NO,
              "HIDECANCEL\n"
              "AUTOHIDE REGISTRY\n"
              "Universal PE unpacker\n"
              "\n"
              "IMPORTANT INFORMATION, PLEASE READ CAREFULLY!\n"
              "\n"
              "This plugin will start the program execution and try to suspend it\n"
              "as soon as the packer finishes its work. Since there might be many\n"
              "variations in packers and packing methods, the execution might go out\n"
              "of control. There are many ways how things can go wrong, but since you\n"
              "have the source code of this plugin, you can modify it as you wish.\n"
              "\n"
              "Do you really want to launch the program?\n") <= 0 )
  {
    return true;
  }

  success = false;

  char resfile_[QMAXPATH];
  set_file_ext(resfile_, sizeof(resfile_), get_path(PATH_TYPE_IDB), "res");
  if ( arg == 0
    && !ask_form("Uunp parameters\n"
                 "IDA will suspend the program when the execution reaches\n"
                 "the original entry point range. The default values are in\n"
                 "this dialog box. Please verify them and correct if you wish.\n"
                 "\n"
                 "ORIGINAL ENTRY POINT AREA\n"
                 "  <~S~tart address:N::32::>\n"
                 "  <~E~nd address  :N::32::>\n"
                 "\n"
                 "OUTPUT RESOURCE FILE NAME\n"
                 "  <~R~esource file:f:1:32::>\n"
                 "\n",
                 &oep_range.start_ea,
                 &oep_range.end_ea,
                 resfile_) )
  {
    return true;
  }
  resfile = resfile_;

  if ( !hook_event_listener(HT_DBG, &dbg_listener) )
  {
    warning("Could not hook to notification point");
    return true;
  }

  if ( dbg == nullptr )
    load_debugger("win32", false);

  // Let's start the debugger
  if ( !run_to(inf_get_start_ea()) )
  {
    warning("Sorry, could not start the process");
    unhook_event_listener(HT_DBG, &dbg_listener);
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // Our plugin works only for x86 PE executables
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 || inf_get_filetype() != f_PE )
    return nullptr;

  return new uunp_ctx_t;
}

//--------------------------------------------------------------------------
uunp_ctx_t::uunp_ctx_t()
{
  set_module_data(&data_id, this);
}

uunp_ctx_t::~uunp_ctx_t()
{
  // listeners are uninstalled automatically
  // when the owner module is unloaded

  // just to be safe
  _hide_wait_box();
  fr = nullptr;

  clr_module_data(data_id);
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Universal PE unpacker";

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

  wanted_name,          // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  wanted_name,          // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
