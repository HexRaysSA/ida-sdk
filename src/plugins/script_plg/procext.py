import idaapi

mymnem = "linux_kernel_call"

"""
    This is a sample plugin for extending processor modules

    It extends the IBM PC processor module to disassemble
        "int 80h"
    as
        "%s"

    for ELF files

(c) Hex-Rays
""" % mymnem

NN_kernel_call = idaapi.CUSTOM_INSN_ITYPE

#--------------------------------------------------------------------------
class linux_idp_hook_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def ev_ana_insn(self, insn):
        if idaapi.get_bytes(insn.ea, 2) != b"\xCD\x80":
            return False
        insn.itype = NN_kernel_call
        insn.size = 2
        return True

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype != NN_kernel_call:
            return 0
        outctx.out_custom_mnem(mymnem)
        return 1

#--------------------------------------------------------------------------
# This class is instantiated once per each opened database.
class linux_procext_plugmod_t(idaapi.plugmod_t):

    def __init__(self):
        print("linux_procext_plugmod_t.__init__() called!")
        self.prochook = linux_idp_hook_t()
        self.prochook.hook()

    def __del__(self):
        print("linux_procext_plugmod_t.term() called!")
        self.prochook.unhook()

    # normally run() is not called because of PLUGIN_HIDE
    def run(self, arg):
        pass

#--------------------------------------------------------------------------
# This class is instantiated when IDA loads the plugin.
class linuxprocext_t(idaapi.plugin_t):
    # Processor fix plugin module
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MULTI
    comment = ""
    wanted_hotkey = ""
    help = "Replaces int 0x80 with %s" % mymnem
    wanted_name = mymnem

    def init(self):
        if idaapi.ph_get_id() != idaapi.PLFM_386 or idaapi.inf_get_filetype() != idaapi.f_ELF:
            print("linuxprocext_t.init() skipped!")
            return None

        print("linuxprocext_t.init() called!")
        return linux_procext_plugmod_t()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return linuxprocext_t()
