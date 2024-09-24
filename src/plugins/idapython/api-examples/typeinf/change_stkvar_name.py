"""
summary: Programatically change the name of an *existing* stack variable.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we demonstrate a way to change the name of a
    stack variable:
    * Get the function object surrounding cursor location.
    * Use this function to retrieve the corresponding frame object.
    * Find the frame member matching the given name.
    * Using its offset in the frame structure object, calculate
      the actual stack delta.
    * Use the previous result to redefine the stack variable name if
      it is not a special or argument member.
"""
import ida_funcs
import ida_frame
import ida_typeinf

old_name = 'arg_8'
new_name = 'Renamed'

func = ida_funcs.get_func(here())
if func:
    print(f'Function @ {func.start_ea:x}')
    frame_tif = ida_typeinf.tinfo_t()
    if ida_frame.get_func_frame(frame_tif, func):
        print(f'{frame_tif._print()}')
        idx = frame_tif.find_udm(old_name)
        if idx >= 0:
            print(f'Udm of {old_name} index: {idx}')
            udm = ida_typeinf.udm_t()
            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                print(f'{old_name} is a special frame member. Will not change the name.')
            else:
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    print(f'{old_name} is an argument member. Will not change the name.')
                else:
                    sval = ida_frame.soff_to_fpoff(func, offset)
                    print(f'Frame offset: {sval:x}')
                    ida_frame.define_stkvar(func, new_name, sval, udm.type)
        else:
            print(f'{old_name} not found.')
    else:
        print('No frame returned.')
else:
    print('Please position the cursor inside a function.')