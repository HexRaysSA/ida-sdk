"""
summary: Programatically create a segment hodling the user
    shared data area in ntdll.dll.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we show how to create, set type and name of
    a user shared data region in an ntdll IDB:
    * Get _KUSER_SHARED_DATA type info.
    * Create a data segment with UserSharedData as its name.
    * Apply the type to the start of the newly created segment base
      address.
    * Set the address name.
"""
import ida_segment
import ida_typeinf
import ida_name
import ida_kernwin

USE64 = 2
PERM_RW  = 0x6
start_ea = 0x7FFE0000
type_name = '_KUSER_SHARED_DATA'

tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
    segm = ida_segment.segment_t()
    segm.start_ea = start_ea
    segm.end_ea = start_ea + tif.get_size()
    segm.sel = ida_segment.setup_selector(0)
    segm.bitness = USE64
    segm.align = ida_segment.saRelPara
    segm.comb = ida_segment.scPub
    segm.perm = PERM_RW
    if ida_segment.add_segm_ex(segm, 'UserSharedData', 'DATA', 0) < 0:
        ida_kernwin.msg('Unable to create the shared data segment.\n')
    else:
        if not ida_typeinf.apply_tinfo(start_ea, tif, ida_typeinf.TINFO_DEFINITE):
            ida_kernwin.msg(f'Unable to apply type information @ {start_ea:x}.\n')
        else:
            if ida_name.set_name(start_ea, 'UserSharedData'):
                ida_kernwin.msg('Done!')
            else:
                ida_kernwin.msg(f'Unable to set {start_ea:x} name.\n')
else:
    ida_kernwin.msg(f'Unable to import {type_name}')
