"""
summary: Programatically list some frame information.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
    * Get the function object surrounding the cursor location.
    * Get the corresponding frame object.
    * Get the details about the frame.
    * Iterate them and display their:
        - Index
        - Name
        - Offset (starting and ending in bytes)
        - Type
"""
import ida_funcs
import ida_frame
import ida_typeinf

func = ida_funcs.get_func(here())
if func:
    func_name = ida_funcs.get_func_name(func.start_ea)
    frame_tif = ida_typeinf.tinfo_t()
    if ida_frame.get_func_frame(frame_tif, func):
        frame_udt = ida_typeinf.udt_type_data_t()
        if frame_tif.get_udt_details(frame_udt):
            print('List frame information:')
            print('-----------------------')
            print(f'{func_name} @ {func.start_ea:x} framesize {frame_tif.get_size():x}')
            print(f'Local variable size: {func.frsize:x}')
            print(f'Saved registers: {func.frregs:x}')
            print(f'Argument size: {func.argsize:x}')
            print('{')
            idx = 0
            for udm in frame_udt:
                print(f'\t[{idx}] {udm.name}: soff={udm.offset//8:x} eof={udm.end()//8:x} {udm.type.dstr()}')
                idx += 1
            print('}')
else:
    print(f'{here():x} is not inside a function.')
