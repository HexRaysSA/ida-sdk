"""
summary: Programatically list the xref for each stack variables
    in the frame.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we demonstrate how to list each stack variables
    xref:
    * Get the function object surrounding cursor location.
    * Use this function to retrieve the corresponding frame object.
    * For each frame element:
        - Build the stack variable xref list
        - Print it.
"""
import ida_typeinf
import ida_frame
import ida_funcs
import ida_xref

func = ida_funcs.get_func(here())
if func:
    print(f'Function @ {func.start_ea:x}')
    
    frame_tif = ida_typeinf.tinfo_t()
    if ida_frame.get_func_frame(frame_tif, func):
        print('Frame found')
        nmembers = frame_tif.get_udt_nmembers()
        print(f'Frame has {nmembers} members')

        if nmembers > 0:
            frame_udt = ida_typeinf.udt_type_data_t()
            if frame_tif.get_udt_details(frame_udt):

                for frame_udm in frame_udt:
                    start_off = frame_udm.begin() // 8 
                    end_off = frame_udm.end() // 8
                    xreflist = ida_frame.xreflist_t()
                    ida_frame.build_stkvar_xrefs(xreflist, func, start_off, end_off)
                    size = xreflist.size()
                    print(f'{frame_udm.name} stack variable starts @ {start_off:x}, ends @ {end_off:x}, xref size: {size}')

                    for idx in range(size):
                        match xreflist[idx].type:
                            case ida_xref.dr_R:
                                type = 'READ'
                            case ida_xref.dr_W:
                                type = 'WRITE'
                            case _:
                                type = 'UNK'
                        print(f'\t[{idx}]: xref @ {xreflist[idx].ea:x} of type {type}')
            else:
                print('Unable to get the frame details.')
        else:
            print('No members found.')
else:
    print('No function under the cursor')
