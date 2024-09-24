"""
summary: Display information about function type information changes.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
     * Create an IDB hook that intercept ti_changed IDB event.
        - We deserialize the type data to reconstruct the tinfo_t
        object
        - We check it is a function and print details if it is the
        case
"""
import ida_funcs
import ida_idp
import ida_typeinf

class ti_changed_t(ida_idp.IDB_Hooks):

    def __del__(self):
        self.unhook()
    

    def print_details(self, tif, ea):
        if tif.is_func():
            func_name = ida_funcs.get_func_name(ea)
            print(f'\t{tif._print(func_name)}')
    
   
    def ti_changed(self, ea, types, fields):
        tif = ida_typeinf.tinfo_t()
        tif.deserialize(None, types, fields)
        if tif.is_func():
            print(f'Function type information changed @ {ea:x}')
            self.print_details(tif, ea)


try:
    my_hook_stat = "un"
    my_hook_stat2 = ""
    print("IDB hook: Checking for hook...")
    idbhook
    print("IDB hook: unhooking...")
    del idbhook
except:
    print("IDB hook: not installed, installing now...")
    my_hook_stat = ""
    my_hook_stat2 = "un"
    idbhook = ti_changed_t()
    idbhook.hook()

print(f'IDB hook {my_hook_stat}installed. Run the script again to {my_hook_stat2}install')