# -----------------------------------------------------------------------
#<pycode(py_kernwin)>

IWID_EXPORTS = 1 << BWN_EXPORTS
IWID_IMPORTS = 1 << BWN_IMPORTS
IWID_NAMES = 1 << BWN_NAMES
IWID_FUNCS = 1 << BWN_FUNCS
IWID_STRINGS = 1 << BWN_STRINGS
IWID_SEGS = 1 << BWN_SEGS
IWID_SEGREGS = 1 << BWN_SEGREGS
IWID_SELS = 1 << BWN_SELS
IWID_SIGNS = 1 << BWN_SIGNS
IWID_TILS = 1 << BWN_TILS
IWID_TITREE = 1 << BWN_TITREE
IWID_PROBS = 1 << BWN_PROBS
IWID_BPTS = 1 << BWN_BPTS
IWID_THREADS = 1 << BWN_THREADS
IWID_MODULES = 1 << BWN_MODULES
IWID_TRACE = 1 << BWN_TRACE
IWID_CALL_STACK = 1 << BWN_CALL_STACK
IWID_XREFS = 1 << BWN_XREFS
IWID_SEARCH = 1 << BWN_SEARCH
IWID_FRAME = 1 << BWN_FRAME
IWID_NAVBAND = 1 << BWN_NAVBAND
IWID_DISASM = 1 << BWN_DISASM
IWID_HEXVIEW = 1 << BWN_HEXVIEW
IWID_NOTEPAD = 1 << BWN_NOTEPAD
IWID_OUTPUT = 1 << BWN_OUTPUT
IWID_CLI = 1 << BWN_CLI
IWID_WATCH = 1 << BWN_WATCH
IWID_LOCALS = 1 << BWN_LOCALS
IWID_STKVIEW = 1 << BWN_STKVIEW
IWID_CHOOSER = 1 << BWN_CHOOSER
IWID_SHORTCUTCSR = 1 << BWN_SHORTCUTCSR
IWID_SHORTCUTWIN = 1 << BWN_SHORTCUTWIN
IWID_CPUREGS = 1 << BWN_CPUREGS
IWID_SO_STRUCTS = 1 << BWN_SO_STRUCTS
IWID_SO_OFFSETS = 1 << BWN_SO_OFFSETS
IWID_CMDPALCSR = 1 << BWN_CMDPALCSR
IWID_CMDPALWIN = 1 << BWN_CMDPALWIN
IWID_SNIPPETS = 1 << BWN_SNIPPETS
IWID_CUSTVIEW = 1 << BWN_CUSTVIEW
IWID_ADDRWATCH = 1 << BWN_ADDRWATCH
IWID_PSEUDOCODE = 1 << BWN_PSEUDOCODE
IWID_MDVIEWCSR = 1 << BWN_MDVIEWCSR
IWID_DISASM_ARROWS = 1 << BWN_DISASM_ARROWS
IWID_CV_LINE_INFOS = 1 << BWN_CV_LINE_INFOS
IWID_SRCPTHMAP_CSR = 1 << BWN_SRCPTHMAP_CSR
IWID_SRCPTHUND_CSR = 1 << BWN_SRCPTHUND_CSR
IWID_UNDOHIST = 1 << BWN_UNDOHIST
IWID_SNIPPETS_CSR = 1 << BWN_SNIPPETS_CSR
IWID_SCRIPTS_CSR = 1 << BWN_SCRIPTS_CSR
IWID_BOOKMARKS = 1 << BWN_BOOKMARKS
IWID_TILIST = 1 << BWN_TILIST
IWID_TIL_VIEW = 1 << BWN_TIL_VIEW
IWID_TYPE_EDITOR = 1 << BWN_TYPE_EDITOR
IWID_XREF_TREE = 1 << BWN_XREF_TREE

IWID_ANY_LISTING = IWID_DISASM | IWID_HEXVIEW | IWID_TILIST | IWID_FRAME | IWID_PSEUDOCODE | IWID_CUSTVIEW
IWID_EA_LISTING = IWID_DISASM | IWID_HEXVIEW | IWID_PSEUDOCODE
IWID_ALL = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# ----------------------------------------------------------------------
def load_custom_icon(file_name=None, data=None, format=None):
    """
    Loads a custom icon and returns an identifier that can be used with other APIs

    If file_name is passed then the other two arguments are ignored.

    :param file_name: The icon file name
    :param data: The icon data
    :param format: The icon data format

    :returns: Icon id or 0 on failure.
             Use free_custom_icon() to free it
    """
    if file_name is not None:
       return _ida_kernwin.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _ida_kernwin.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def ask_long(defval: int, prompt: str) -> Union[int, None]:
    res, val = _ida_kernwin._ask_long(defval, prompt)
    return val if res == 1 else None

# ----------------------------------------------------------------------
def ask_addr(defval: ida_idaapi.ea_t, prompt: str) -> Union[ida_idaapi.ea_t, None]:
    res, ea = _ida_kernwin._ask_addr(defval, prompt)
    return ea if res == 1 else None

# ----------------------------------------------------------------------
def ask_seg(defval: int, prompt: str) -> Union[int, None]:
    res, sel = _ida_kernwin._ask_seg(defval, prompt)
    return sel if res == 1 else None

# ----------------------------------------------------------------------
def ask_ident(defval: str, prompt: str) -> bool:
    return ask_str(defval, HIST_IDENT, prompt)

# ----------------------------------------------------------------------
class action_handler_t(object):
    def __init__(self):
        pass

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        pass

# ----------------------------------------------------------------------
# This provides an alternative to register_action()+attach_action_to_popup_menu()
class quick_widget_commands_t:

    class _cmd_t:
        def __init__(self, caption, flags, menu_index, icon, emb, shortcut):
            self.caption = caption
            self.flags = flags
            self.menu_index = menu_index
            self.icon = icon
            self.emb = emb
            self.shortcut = shortcut

    class _ah_t(action_handler_t):
        def __init__(self, parent, cmd_id):
            action_handler_t.__init__(self)
            self.parent = parent
            self.cmd_id = cmd_id

        def activate(self, ctx):
            self.parent.callback(ctx, self.cmd_id)

        def update(self, ctx):
            return AST_ENABLE_ALWAYS


    def __init__(self, callback):
        self.callback = callback
        self.cmds = []

    def add(self, caption, flags, menu_index, icon, emb, shortcut):
        for idx, cmd in enumerate(self.cmds):
            if cmd.caption == caption:
                return idx
        self.cmds.append(
            quick_widget_commands_t._cmd_t(
                caption, flags, menu_index, icon, emb, shortcut))
        return len(self.cmds) - 1

    def populate_popup(self, widget, popup):
        for idx, cmd in enumerate(self.cmds):
            if (cmd.flags & CHOOSER_POPUP_MENU) != 0:
                desc = action_desc_t(None,
                                     cmd.caption,
                                     quick_widget_commands_t._ah_t(self, idx),
                                     cmd.shortcut,
                                     None,
                                     cmd.icon)
                attach_dynamic_action_to_popup(None, popup, desc)

class disabled_script_timeout_t(object):
    def __enter__(self):
        import _ida_idaapi
        self.was_timeout = _ida_idaapi.set_script_timeout(0)

    def __exit__(self, type, value, tb):
        import _ida_idaapi
        _ida_idaapi.set_script_timeout(self.was_timeout)

import ida_ida
ida_ida.__wrap_hooks_callback(
    UI_Hooks,
    "database_closed",
    "term",
    lambda cb, *args: cb(*args))


# ----------------------------------------------------------------------
# bw-compat/deprecated. You shouldn't rely on this in new code
from ida_pro import str2user
SETMENU_IF_ENABLED = 4

# bw-compat (flag removed in IDA 8.4):
CH_NOIDB = CH_UNUSED

BWN_TICSR = BWN_TITREE
IWID_TICSR = IWID_TITREE

BWN_TILVIEW = BWN_TICSR
IWID_TILVIEW = IWID_TICSR

BWN_LOCTYPS = BWN_TILVIEW
IWID_LOCTYPS = IWID_TILVIEW

BWN_DISASMS = BWN_DISASM
IWID_DISASMS = IWID_DISASM

BWN_CALLS = 11
BWN_CALLS_CALLERS = 47
BWN_CALLS_CALLEES = 48

IWID_CALLS = 1 << BWN_CALLS
IWID_CALLS_CALLERS = 1 << BWN_CALLS_CALLERS
IWID_CALLS_CALLEES = 1 << BWN_CALLS_CALLEES

#</pycode(py_kernwin)>
