//
//	This file is executed when a PalmPilot program is loaded.
//	You may customize it as you wish.
//
//	TODO:
//		- decompilation of various resource types
//		  (we don't have any information on the formats)
//

#include <idc.idc>

//-----------------------------------------------------------------------
//
// Process each resource and make some routine tasks
//
static process_segments()
{
  auto ea,segname,prefix;

  for ( ea=get_first_seg(); ea != BADADDR; ea=get_next_seg(ea) )
  {
    segname = get_segm_name(ea);
    prefix = substr(segname,0,4);
    if ( segname == "data0000" )
    {
      if ( get_wide_dword(ea) == 0xFFFFFFFF )
      {
        create_dword(ea);
        set_cmt(ea,"Loader stores SysAppInfoPtr here", 0);
      }
      continue;
    }
    if ( prefix == "TRAP" )
    {
      create_word(ea);
      op_hex(ea,0);
      set_cmt(ea,"System trap function code", 0);
      continue;
    }
    if ( prefix == "tSTR" )
    {
      create_strlit(ea,get_segm_end(ea));
      set_cmt(ea,"String resource", 0);
      continue;
    }
    if ( prefix == "tver" )
    {
      create_strlit(ea,get_segm_end(ea));
      set_cmt(ea,"Version number string", 0);
      continue;
    }
    if ( prefix == "tAIN" )
    {
      create_strlit(ea,get_segm_end(ea));
      set_cmt(ea,"Application icon name", 0);
      continue;
    }
    if ( prefix == "pref" )
    {
      auto flags,cmt;
      flags = get_wide_word(ea);
      create_word(ea); op_hex(ea,0); set_name(ea,"flags");
#define sysAppLaunchFlagNewThread  0x0001
#define sysAppLaunchFlagNewStack   0x0002
#define sysAppLaunchFlagNewGlobals 0x0004
#define sysAppLaunchFlagUIApp      0x0008
#define sysAppLaunchFlagSubCall    0x0010
      cmt = "";
      if ( flags & sysAppLaunchFlagNewThread ) cmt = cmt + "sysAppLaunchFlagNewThread\n";
      if ( flags & sysAppLaunchFlagNewStack  ) cmt = cmt + "sysAppLaunchFlagNewStack\n";
      if ( flags & sysAppLaunchFlagNewGlobals) cmt = cmt + "sysAppLaunchFlagNewGlobals\n";
      if ( flags & sysAppLaunchFlagUIApp     ) cmt = cmt + "sysAppLaunchFlagUIApp\n";
      if ( flags & sysAppLaunchFlagSubCall   ) cmt = cmt + "sysAppLaunchFlagSubCall";
      set_cmt(ea,cmt, 0);
      ea = ea + 2;
      create_dword(ea); op_hex(ea,0); set_name(ea,"stack_size");
      ea = ea + 4;
      create_dword(ea); op_hex(ea,0); set_name(ea,"heap_size");
    }
  }
}

//-----------------------------------------------------------------------
//
//	Create a enumeration with system action codes
//
static make_actions()
{
  auto ename = "SysAppLaunchCmd";
  auto id = get_named_type_tid(ename);
  if ( id == BADADDR )
  {
    auto ei = enum_type_data_t();
    ei.bte = ei.bte | BTE_UDEC;
    ei.add_constant("sysAppLaunchCmdNormalLaunch",         0, "Normal Launch");
    ei.add_constant("sysAppLaunchCmdFind",                 1, "Find string");
    ei.add_constant("sysAppLaunchCmdGoTo",                 2, "Launch and go to a particular record");
    ei.add_constant("sysAppLaunchCmdSyncNotify",           3, "Sent to apps whose databases changed\n"
                                                              "during HotSync after the sync has\n"
                                                              "been completed");
    ei.add_constant("sysAppLaunchCmdTimeChange",           4, "The system time has changed");
    ei.add_constant("sysAppLaunchCmdSystemReset",          5, "Sent after System hard resets");
    ei.add_constant("sysAppLaunchCmdAlarmTriggered",       6, "Schedule next alarm");
    ei.add_constant("sysAppLaunchCmdDisplayAlarm",         7, "Display given alarm dialog");
    ei.add_constant("sysAppLaunchCmdCountryChange",        8, "The country has changed");
    ei.add_constant("sysAppLaunchCmdSyncRequest",          9, "The \"HotSync\" button was pressed");
    ei.add_constant("sysAppLaunchCmdSaveData",            10, "Sent to running app before\n"
                                                              "sysAppLaunchCmdFind or other\n"
                                                              "action codes that will cause data\n"
                                                              "searches or manipulation");
    ei.add_constant("sysAppLaunchCmdInitDatabase",        11, "Initialize a database; sent by\n"
                                                              "DesktopLink server to the app whose\n"
                                                              "creator ID matches that of the database\n"
                                                              "created in response to the \"create db\" request");
    ei.add_constant("sysAppLaunchCmdSyncCallApplication", 12, "Used by DesktopLink Server command\n"
                                                              "\"call application\"");

    id = create_enum_type(ename, ei, 0, TYPE_SIGN_NO_SIGN, 0, "Action codes");
  }
}

//-----------------------------------------------------------------------
//
//	Create a enumeration with event codes
//
static make_events()
{
  auto ename = "events";
  auto id = get_named_type_tid(ename);
  if ( id == BADADDR )
  {
    auto ei = enum_type_data_t();
    ei.bte = ei.bte | BTE_UDEC;
    ei.add_constant( "nilEvent",              0);
    ei.add_constant("penDownEvent",           1);
    ei.add_constant("penUpEvent",             2);
    ei.add_constant("penMoveEvent",           3);
    ei.add_constant("keyDownEvent",           4);
    ei.add_constant("winEnterEvent",          5);
    ei.add_constant("winExitEvent",           6);
    ei.add_constant("ctlEnterEvent",          7);
    ei.add_constant("ctlExitEvent",           8);
    ei.add_constant("ctlSelectEvent",         9);
    ei.add_constant("ctlRepeatEvent",        10);
    ei.add_constant("lstEnterEvent",         11);
    ei.add_constant("lstSelectEvent",        12);
    ei.add_constant("lstExitEvent",          13);
    ei.add_constant("popSelectEvent",        14);
    ei.add_constant("fldEnterEvent",         15);
    ei.add_constant("fldHeightChangedEvent", 16);
    ei.add_constant("fldChangedEvent",       17);
    ei.add_constant("tblEnterEvent",         18);
    ei.add_constant("tblSelectEvent",        19);
    ei.add_constant("daySelectEvent",        20);
    ei.add_constant("menuEvent",             21);
    ei.add_constant("appStopEvent",          22);
    ei.add_constant("frmLoadEvent",          23);
    ei.add_constant("frmOpenEvent",          24);
    ei.add_constant("frmGotoEvent",          25);
    ei.add_constant("frmUpdateEvent",        26);
    ei.add_constant("frmSaveEvent",          27);
    ei.add_constant("frmCloseEvent",         28);
    ei.add_constant("tblExitEvent",          29);
    id = create_enum_type(ename, ei, 0, TYPE_SIGN_NO_SIGN, 0, "Event codes");
  }
}

//-----------------------------------------------------------------------
static main()
{
  process_segments();
  make_actions();
  make_events();
}

//-----------------------------------------------------------------------
#ifdef __undefined_symbol__
	// WE DO NOT USE IDC HOTKEYS, JUST SIMPLE KEYBOARD MACROS
	// (see IDA.CFG, macro Alt-5 for mc68k)
//-----------------------------------------------------------------------
//
//	Register Ctrl-R as a hotkey for "make offset from A5" command
//	(not used, simple keyboard macro is used instead, see IDA.CFG)
//
//	There is another (manual) way to convert an operand to an offset:
//	  - press Ctrl-R
//	  - enter "A5BASE"
//	  - press Enter
//
static setup_pilot()
{
  auto h0,h1;
  h0 = "Alt-1";
  h1 = "Alt-2";
  add_idc_hotkey(h0,"a5offset0");
  add_idc_hotkey(h1,"a5offset1");
  msg("Use %s to convert the first operand to an offset from A5\n",h0);
  msg("Use %s to convert the second operand to an offset from A5\n",h1);
}

static a5offset0(void) { op_plain_offset(get_screen_ea(),0,get_name_ea_simple("A5BASE")); }
static a5offset1(void) { op_plain_offset(get_screen_ea(),1,get_name_ea_simple("A5BASE")); }

#endif // 0
