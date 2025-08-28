import ida_idaapi, ida_kernwin

class myplugmod_t(ida_idaapi.plugmod_t):
    def __del__(self):
        ida_kernwin.msg("unloaded myplugmod\n")

    def run(self, arg):
        ida_kernwin.msg("run() called with %d!\n" % arg)
        return (arg % 2) == 0

class myplugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "This is a sample Python plugin"
    help = "This is help"
    wanted_name = "Sample Python plugin"
    wanted_hotkey = "Alt-F8"

    #def __del__(self):
        #ida_kernwin.msg("unloaded globally\n")

    def init(self):
        ida_kernwin.msg("init() called!\n")
        return myplugmod_t()

    def run(self, arg):
        ida_kernwin.msg("ERROR: run() called for global object!\n")
        return (arg % 2) == 0

    def term(self):
        ida_kernwin.msg("ERROR: term() called (should never be called)\n")

def PLUGIN_ENTRY():
    return myplugin_t()

