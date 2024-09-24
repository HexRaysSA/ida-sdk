"""
summary: Programatically displays information about functions types.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we demonstrate how to list a function return type
    allong with its parameters types and name if any. We do this for 
    all the functions found in the database.
"""
import ida_funcs
import ida_typeinf
import ida_kernwin
import ida_nalt
import idautils

ida_kernwin.msg_clear()
func_qty = ida_funcs.get_func_qty()
print(f'Listing {func_qty} functions')
for _, ea in enumerate(idautils.Functions()):
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        print(f'Function @ {ea:x} has no type.')
        continue
    if tif.is_func():
        print(f'Function @ {ea:x} return type: {tif.get_rettype()}')
        funcdata = ida_typeinf.func_type_data_t()
        tif.get_func_details(funcdata)
        for pos, argument in enumerate(funcdata):
            print(f'\targument {pos + 1}: {argument.type} {argument.name}')