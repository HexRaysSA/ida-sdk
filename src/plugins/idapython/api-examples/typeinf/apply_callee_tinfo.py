"""
summary: Programatically apply locally created function type info 
    to all the addresses refering to that function.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
    * Open the private type libary.
    * Load its declaration in the type library by parsing its declaration and
    keep the return tuple for future use.
    * Deserialize the type info stored in the returned tuple.
    * Get the address of the function.
    * Get the address of the code reference to the function and apply
    the type info there.
"""
import ida_typeinf
import ida_name
import idautils
import ida_idaapi

til = ida_typeinf.get_idati()
tuple = ida_typeinf.idc_parse_decl(til, 'NTSTATUS __fastcall KdInitSystem(ULONG BootPhase, _LOADER_PARAMETER_BLOCK *LoaderBlock);', ida_typeinf.PT_REPLACE)
if not tuple == None:
    tif = ida_typeinf.tinfo_t()
    if tif.deserialize(til, tuple[1], tuple[2]):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'KdInitSystem')
        if not ea == ida_idaapi.BADADDR:
            print(f'KdIniSystem function found @ {ea:x}.')
            for xref in idautils.CodeRefsTo(ea, 0):
                print(f'\tApplying type info @ {xref:x}.')
                ida_typeinf.apply_callee_tinfo(xref, tif)
