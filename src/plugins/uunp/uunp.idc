/*

  This is a reimplementation of the uunp universal unpacker in IDC.
  It illustrates the use of the new debugger functions in IDA v5.2

*/

#include <idc.idc>

//--------------------------------------------------------------------------
static main()
{
  auto ea, bptea, tea1, tea2, code, minea, maxea, r_esp, r_eip, caller, funcname;

  // Calculate the target IP range. It is the first segment.
  // As soon as the EIP register points to this range, we assume that
  // the unpacker has finished its work.
  tea1 = get_first_seg();
  tea2 = get_segm_end(tea1);

  // Calculate the current module boundaries. Any calls to GetProcAddress
  // outside of these boundaries will be ignored.
  minea = get_inf_attr(INF_MIN_EA);
  maxea = get_inf_attr(INF_MAX_EA);

  // Use win32 local debugger
  load_debugger("win32", 0);

  // Launch the debugger and run until the entry point
  if ( !run_to(get_inf_attr(INF_START_EA)) )
    return Failed(-10);

  // Wait for the process to stop at the entry point
  code = wait_for_next_event(WFNE_SUSP, -1);
  if ( code <= 0 )
    return Failed(code);

  // Set a breakpoint at GetProcAddress
  bptea = get_name_ea_simple("kernel32_GetProcAddress");
  if ( bptea == BADADDR )
    return warning("Could not locate GetProcAddress");
  add_bpt(bptea);

  while ( 1 )
  {
    // resume the execution and wait until the unpacker calls GetProcAddress
    code = wait_for_next_event(WFNE_SUSP|WFNE_CONT, -1); // CONT means resume
    if ( code <= 0 )
      return Failed(code);

    // check the caller, it must be from our module
    r_esp = get_reg_value("ESP");
    caller = get_wide_dword(r_esp);
    if ( caller < minea || caller >= maxea )
      continue;

    // if the function name passed to GetProcAddress is not in the ignore-list,
    // then switch to the trace mode
    funcname = get_strlit_contents(get_wide_dword(r_esp+8), -1, STRTYPE_C);
    // ignore some api calls because they might be used by the unpacker
    if ( funcname == "VirtualAlloc" )
      continue;
    if ( funcname == "VirtualFree" )
      continue;

    // A call to GetProcAddress() probably means that the program has been
    // unpacked in the memory and now is setting up its import table
    break;
  }

  // trace the program in the single step mode until we jump to
  // the area with the original entry point.
  del_bpt(bptea);
  enable_tracing(TRACE_STEP, 1);
  for ( code = wait_for_next_event(WFNE_ANY|WFNE_CONT, -1); // resume
        code > 0;
        code = wait_for_next_event(WFNE_ANY, -1) )
  {
    r_eip = get_event_ea();
    if ( r_eip >= tea1 && r_eip < tea2 )
      break;
  }
  if ( code <= 0 )
    return Failed(code);

  // as soon as the current ip belongs OEP area, suspend the execution and
  // inform the user
  suspend_process();
  code = wait_for_next_event(WFNE_SUSP, -1);
  if ( code <= 0 )
    return Failed(code);

  enable_tracing(TRACE_STEP, 0);

  // Clean up the disassembly so it looks nicer
  del_items(tea1, DELIT_EXPAND|DELIT_DELNAMES, tea2-tea1);
  create_insn(r_eip);
  auto_mark_range(tea1, tea2, AU_USED);
  auto_mark_range(tea1, tea2, AU_FINAL);
  take_memory_snapshot(1);
  set_name(r_eip, "real_start");
  warning("Successfully traced to the completion of the unpacker code\n"
          "Please rebuild the import table using renimp.idc\n"
          "before stopping the debugger");
}

//--------------------------------------------------------------------------
// Print an failure message
static Failed(code)
{
  warning("Failed to unpack the file, sorry (code %d)", code);
  return 0;
}
