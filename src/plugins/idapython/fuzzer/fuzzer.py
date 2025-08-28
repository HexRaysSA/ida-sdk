import idc
import importlib
import random
import string
import re
import ida_hexrays
import ida_registry

old_strings = []
MAX_OLD_STRINGS = 1024 # number of strings to remember

asmInst = [
    "mov",
    "movsbl",
    "movzbl",
    "cmov",
    "cmp",
    "test",
    "add",
    "sub",
    "mul",
    "div"
]
asm32Reg = [
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esi",
    "edi",
    "esp",
    "ebp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d"
]
actions = [
    "Action",
    "Abort",
    "About",
    "AddWatch",
    "AddressDetails",
    "Analysis",
    "Anchor",
    "ApplyPatches",
    "AskBinaryText",
    "AskNextImmediate",
    "AskNextText",
    "Assemble",
    "BitwiseNegate",
    "BreakpointAdd",
    "BreakpointToggle",
    "Breakpoints",
    "BugReport",
    "CLICopyAddress",
    "CLICopySize",
    "Calculate",
    "CallFlow",
    "CenterInWindow",
    "ChangeSign",
    "ChangeStackPointer",
    "ChartXrefsFrom",
    "ChartXrefsTo",
    "ChartXrefsUser",
    "CheckFreeUpdate",
    "ClearMark",
    "CloseBase",
    "CloseWindow",
    "ColorInstruction",
    "CommandPalette",
    "CopyFieldsToPointers",
    "CreateSegment",
    "CreateStructFromData",
    "DeclareStructVar",
    "DelFunction",
    "DeleteDesktop",
    "DumpDatabase",
    "DumpTypes",
    "Edit/Plugins/COM Helper",
    "Edit/Plugins/Change the callee address",
    "Edit/Plugins/Create IDT file",
    "Edit/Plugins/Jump to next fixup",
    "Edit/Plugins/Load DWARF file",
    "Edit/Plugins/SVD file management",
    "Edit/Plugins/Sample plugin",
    "Edit/Plugins/Universal PE unpacker",
    "Edit/Plugins/Universal Unpacker Manual Reconstruct",
    "EditFunction",
    "EditSegment",
    "EmptyStack",
    "Execute",
    "ExecuteLine",
    "ExportData",
    "ExternalHelp",
    "FindAllErrors",
    "FindAllSuspicious",
    "FloatingBorrow",
    "FloatingReturn",
    "FocusCLI",
    "FocusCLI2",
    "FullScreen",
    "Function",
    "FunctionEnd",
    "GraphColor",
    "GraphColor1",
    "GraphColor2",
    "GraphDefaultColor",
    "GraphFlatView",
    "GraphHideAllGroups",
    "GraphHideGroup",
    "GraphLayout",
    "GraphNewProximityView",
    "GraphOverview",
    "GraphPrint",
    "GraphProximityAddGraph",
    "GraphProximityAddNode",
    "GraphProximityAddNodeByAddr",
    "GraphProximityAddParents",
    "GraphProximityDelChilds",
    "GraphProximityDelNode",
    "GraphProximityDelParents",
    "GraphProximityExpand",
    "GraphProximityFindPath",
    "GraphProximityReset",
    "GraphProximityView",
    "GraphSelectColor",
    "GraphSetupColors",
    "GraphSetupOptions",
    "GraphUnHideAllGroups",
    "GraphUnHideGroup",
    "GraphZoom100",
    "GraphZoomFit",
    "GraphZoomIn",
    "GraphZoomOut",
    "HelpHexraysSDK",
    "HelpIDASDK",
    "HelpIDCFunctions",
    "HelpPythonAPI", "Hide", "HideAll",
    "Homepage",
    "JumpAsk",
    "JumpBinaryText",
    "JumpCode",
    "JumpData",
    "JumpEnter",
    "JumpEnterNew",
    "JumpEntryPoint",
    "JumpError",
    "JumpExplored",
    "JumpFileOffset",
    "JumpFunction",
    "JumpImmediate",
    "JumpName",
    "JumpNewDump",
    "JumpNextFunc",
    "JumpNotFunction",
    "JumpOpXref",
    "JumpPosition",
    "JumpPrevFunc",
    "JumpQ",
    "JumpSegment",
    "JumpSegmentRegister",
    "JumpSuspicious",
    "JumpText",
    "JumpUnknown",
    "JumpXref",
    "JumpXrefFrom",
    "KillSegment",
    "LoadDbgFile",
    "LoadDesktop",
    "LoadFile",
    "LoadHeaderFile",
    "LoadIdsFile",
    "LoadModuleDebugSymbols",
    "LoadNewFile",
    "LoadPdbFile",
    "LoadSigFile",
    "LoadTdsFile",
    "Locals",
    "LockHighlight_0",
    "LockHighlight_1",
    "LockHighlight_2",
    "LockHighlight_3",
    "LockHighlight_4",
    "LockHighlight_5",
    "LockHighlight_6",
    "LockHighlight_7",
    "LuminaIDAViewPullMd",
    "LuminaIDAViewPushMd",
    "LuminaPullAllMds",
    "LuminaPushAllMds",
    "LuminaViewAllMds",
    "MakeAlignment",
    "MakeArray",
    "MakeCode",
    "MakeComment",
    "MakeData",
    "MakeExtraLineA",
    "MakeExtraLineB",
    "MakeName",
    "MakeRptCmt",
    "MakeStrlit",
    "MakeUnknown",
    "ManualInstruction",
    "ManualOperand",
    "MarkPosition",
    "MoveSegment",
    "NavGraphJumpLinkedNeighborDown",
    "NavGraphJumpLinkedNeighborUp",
    "NavJumpEnd",
    "NavJumpHome",
    "NavJumpListingEnd",
    "NavJumpListingStart",
    "NavJumpWindowBottom",
    "NavJumpWindowTop",
    "NavLeft",
    "NavLineDown",
    "NavLineUp",
    "NavPageDown",
    "NavPageUp",
    "NavRight",
    "NavWordLeft",
    "NavWordRight",
    "NewFile",
    "NewInstance",
    "NextWindow",
    "OpAnyOffset",
    "OpBinary",
    "OpChar",
    "OpDecimal",
    "OpEnum",
    "OpFloat",
    "OpHex",
    "OpNumber",
    "OpOctal",
    "OpOffset",
    "OpOffsetCs",
    "OpSegment",
    "OpStackVariable",
    "OpStructOffset",
    "OpUserOffset",
    "OpenBookmarks",
    "OpenCallers",
    "OpenEnums",
    "OpenExports",
    "OpenFunctions",
    "OpenImports",
    "OpenLocalTypes",
    "OpenNames",
    "OpenNotepad",
    "OpenProblems",
    "OpenSegmentRegisters",
    "OpenSegments",
    "OpenSelectors",
    "OpenSignatures",
    "OpenStackVariables",
    "OpenStrings",
    "OpenStructures",
    "OpenTypeLibraries",
    "OpenXrefs",
    "Options",
    "OutputWindow",
    "PatchByte",
    "PatchWord",
    "PatchedBytes",
    "PrevWindow",
    "ProcessorAnalysisOptions",
    "ProduceAsm",
    "ProduceCallGdl",
    "ProduceDiff",
    "ProduceExe",
    "ProduceFuncGdl",
    "ProduceHeader",
    "ProduceHtml",
    "ProduceInc",
    "ProduceLst",
    "ProduceMap",
    "QuickDbgView",
    "QuickRunPlugins",
    "QuickStart",
    "QuickView",
    "QuitIDA",
    "ReanalyzeProgram",
    "RebaseProgram",
    "RecentScripts",
    "ReloadFile",
    "RenameRegister",
    "RepeatLastPaletteCommand",
    "ResetDesktop",
    "ResetHiddenMessages",
    "ResetUndoHistory",
    "SaveBase",
    "SaveBaseAs",
    "SaveBaseSnap",
    "SaveDesktop",
    "SearchHighlightDown",
    "SearchHighlightUp",
    "SegmentTranslation",
    "SelectAll",
    "SelectIdentifier",
    "SelectUnionMember",
    "SetColors",
    "SetDemangledNames",
    "SetDirection",
    "SetDirectives",
    "SetFont",
    "SetNameType",
    "SetOpType",
    "SetSegmentRegister",
    "SetSegmentRegisterDefault",
    "SetStrlitStyle",
    "SetType",
    "SetupCompiler",
    "SetupData",
    "SetupHidden",
    "SetupSrcPaths",
    "SetupSrcPathsRevert",
    "ShortcutEditor",
    "ShowFlags",
    "ShowHelp",
    "ShowRegisters",
    "ShowSnapMan",
    "ShowUndoHistory",
    "SnippetsRunCurrent",
    "StringC",
    "StringDOS",
    "StringDelphi",
    "StringPascal1",
    "StringPascal2",
    "StringUnicode",
    "StringUnicodePascal2",
    "StringUnicodePascal4",
    "SupportForum",
    "SwitchDebugger",
    "ToggleBorder",
    "ToggleDump",
    "ToggleLeadingZeroes",
    "ToggleRenderer",
    "ToggleSourceDebug",
    "ToggleStatusBarAnalysisIndicator",
    "ToolbarsAll",
    "ToolbarsNone",
    "UnHideAll",
    "UndoAction",
    "UndoToggle",
    "WatchView",
    "WindowActivate1",
    "WindowActivate2",
    "WindowActivate3",
    "WindowActivate4",
    "WindowActivate5",
    "WindowActivate6",
    "WindowActivate7",
    "WindowActivate8",
    "WindowActivate9",
    "WindowOpen",
    "WindowsList",
    "WindowsListNext",
    "WindowsListPrev",
    "ZeroStructOffset",
    "commdbg:EditExceptions",
    "commdbg:ReloadExceptions",
    "dummy_hexrays:warn",
    "golang:search_pclntab",
    "navigator:FitWholeProgram",
    "navigator:Refresh",
    "navigator:Set1024Bytes",
    "navigator:Set16384Bytes",
    "navigator:Set16Bytes",
    "navigator:Set1Bytes",
    "navigator:Set256Bytes",
    "navigator:Set4096Bytes",
    "navigator:Set4Bytes",
    "navigator:Set64Bytes",
    "navigator:ToggleDisplay",
    "navigator:ToggleLegend",
    "navigator:ZoomIn",
    "navigator:ZoomOut",
    "uiswitch:SpecSwitchIdiom"
]

def random_string(max_length: int = 100, char_start: int = 32, char_range: int = 32) -> str:
    string_length = random.randrange(0, max_length + 1)
    out = ""
    for i in range(0, string_length):
        out += chr(random.randrange(char_start, char_start + char_range))
    return out

def  random_int():
    return random.randint(-9, 9)

def random_char():
    return random.choice(string.ascii_letters)

def random_addr():
     return random.randint(0, 0xFFFFFFFF)

def random_valid_bool():
    return random.randint(0,1)

def random_valid_addr():
    nseg = ida_segment.get_segm_qty()
    seg_pick = random.randint(0, nseg-1)
    s = ida_segment.getnseg(seg_pick)
    return random.randint(s.start_ea, s.end_ea-1)

def random_valid_asm():
    i = random.randint(0, 9)
    j = random.randint(0, 15)
    k = random.randint(0, 15)
    return str(asmInst[i] + " " + asm32Reg[j] + "," + " " + asm32Reg[k])

def random_valid_action():
    i = random.randint(0, 344)
    return actions[i]

def latest_random_sid_valid():
    for idx, sid, name in idautils.Structs():
        return sid

def random_object():
    return object()

def delete_rand_char(s: str) -> str:
     if s =="":
         return str
     pos = random.randint(0, len(s) -1)
     return s[:pos] + s[pos +1:]

def insert_rand_char(s: str) -> str:
     pos = random.randint(0, len(s))
     random_char = chr(random.randrange(32, 127))
     return s[:pos] + random_char + s[pos:]

def flip_rand_char(s):
     if s == "":
         return s
     pos = random.randint(0, len(s) -1)
     c = s[pos]
     bit = 1 << random.randint(0, 6)
     new_c = chr(ord(c) ^ bit)
     return s[:pos] + new_c + s[pos + 1:]

def mutate(s):
     if isinstance(s, str):
       mutators = [
         delete_rand_char,
         insert_rand_char,
         flip_rand_char
       ]
       mutator = random.choice(mutators)
       s = mutator(s)
     return s

def noner():
    arg = None
    return arg

def save_old_string(s):
    if len(old_strings) < MAX_OLD_STRINGS:
      old_strings.append(s)
    else: # replace any random string
      i = random.randint(0, MAX_OLD_STRINGS-1)
      old_strings[i] = s

def get_mutated_old_string():
    if len(old_strings) == 0:
      return None
    s = random.choice(old_strings)
    return mutate(s)

fuzzer_functions = [
    random_char,
    random_string,
    random_int,
    random_valid_addr,
    random_valid_action,
    random_valid_asm,
    random_addr,
    random_valid_bool,
    random_object,
    get_mutated_old_string,
    noner,
]

def gen_random_arg():
    func = random.choice(fuzzer_functions)
    s = func()
    if s is not None:
      if random.random() < 0.3:
        s = mutate(s)
    save_old_string(s)
    return s

def wrapper(func, args):
  try:
    func(*args)
  except:
    pass

def clean_name(name):
    name = re.sub("<function ", '', name)
    name = re.sub(" at .*", '', name)
    name = re.sub("<class '(.*)'>", r'\1', name)
    return name

# these functions cannot be fuzzed because passing a wrong argument to them
# will crash IDA. there is no way to check arguments on IDA side, unfortunately.
non_fuzzable_funcs = [
    ida_idp.gen_idb_event,
    ida_expr.pyw_unregister_idc_func,
    ida_expr.pyw_register_idc_func,
    ida_expr.call_idc_func__,
    ida_kernwin.formchgcbfa_close,
    ida_kernwin.formchgcbfa_enable_field,
    ida_kernwin.formchgcbfa_show_field,
    ida_kernwin.formchgcbfa_get_focused_field,
    ida_kernwin.formchgcbfa_get_field_value,
    ida_kernwin.formchgcbfa_move_field,
    ida_kernwin.formchgcbfa_set_focused_field,
    ida_kernwin.formchgcbfa_set_field_value,
    ida_kernwin.formchgcbfa_refresh_field,
    ida_kernwin.formchgcbfa_close,
    ida_kernwin.set_nav_colorizer,
    # do not exit
    ida_kernwin.error,
    ida_kernwin.nomem,
    ida_pro.qexit,
    ida_diskio.eclose,  # eclose causes ida to exit, fixme!
    # thouroughly tested already:
    ida_kernwin.open_url,
    # do not call qwingraph
    ida_gdl.display_gdl,
    ida_gdl.gen_flow_graph,
    ida_gdl.gen_simple_call_chart,
    # do not execute system commands
    ida_expr.exec_system_script,
    ida_expr.exec_idc_script,
    ida_idaapi.IDAPython_ExecSystem,
    # do not create files on the disk
    ida_diskio.fopenWB,
    ida_diskio.fopenWT,
    ida_kernwin.msg_save,
    ida_hexrays.decompile_many,
    ida_loader.save_database,
    ida_kernwin.take_database_snapshot,
    idc.save_database,
    idc.save_trace_file,
    ida_typeinf.store_til,
    ida_registry.set_registry_root,
    idc.qsleep,
]

modules = [
#    'ida_allins',
#    'ida_auto',
#    'ida_bitrange',
    'ida_bytes',
    'ida_dbg',
#    'ida_dirtree',
#    'ida_diskio',
#    'ida_entry',
#    'ida_expr',
#    'ida_fixup',
#    'ida_fpro',
#    'ida_frame',
#    'ida_funcs',
#    'ida_gdl',
#    'ida_graph',
    'ida_hexrays',
#    'ida_ida',
#    'ida_idaapi',
#    'ida_idc',
#    'ida_idd',
    'ida_idp',
#    'ida_ieee',
    'ida_kernwin',
#    'ida_lines',
    'ida_loader',
#    'ida_moves',
    'ida_nalt',
#    'ida_name',
#    'ida_netnode',
#    'ida_offset',
    'ida_pro',
#    'ida_problems',
#    'ida_range',
#    'ida_registry',
#    'ida_search',
    'ida_segment',
#    'ida_segregs',
#    'ida_strlist',
#    'ida_tryblks',
    'ida_typeinf',
#    'ida_ua',
#    'ida_xref',
    'idc',
    'idautils'
]
input_file = idaapi.get_input_file_path()
underscore = input_file.rfind('_')
idx = int(input_file[underscore+1:])
idx = idx % len(modules)
modname = modules[idx]
lib = importlib.import_module(modname)

# prepare list of callable functions
names = []
for name in dir(lib):
  function = getattr(lib, name)
  if not hasattr(function, '__call__'):
    continue
  if function in non_fuzzable_funcs:
    continue
  names.append(name)

# now loop until crashing
while True:
  funcname = random.choice(names)
  function = getattr(lib, funcname)
  n = random.randint(0, 10)
  args = []
  argstr = []
  for i in range(n):
    a = gen_random_arg()
    args.append(a)
    if type(a) is object:
      argstr.append('OBJ')
    else:
      argstr.append(a)
  argstr = str(tuple(argstr))
  argstr = argstr.replace("'OBJ'", 'object()')
  if len(args) == 1:
    argstr = argstr.replace(',)',')') # cvt 1-element tuple into arglist
  print("%s.%s%s" % (modname, funcname, argstr))
  wrapper(function, args)

#print("The script ran with no crash.")
#idaapi.process_config_directive("ABANDON_DATABASE=YES")
#idaapi.qexit(0)
