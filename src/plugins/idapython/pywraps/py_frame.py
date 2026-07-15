#<pycode(py_frame)>
import ida_idaapi

add_frame = ida_idaapi._ida_deprecated(add_frame, "add_frame_ea")
del_frame = ida_idaapi._ida_deprecated(del_frame, "del_frame_ea")
set_frame_size = ida_idaapi._ida_deprecated(set_frame_size, "set_frame_size_ea")
get_frame_size = ida_idaapi._ida_deprecated(get_frame_size, "get_frame_size_ea")
get_frame_retsize = ida_idaapi._ida_deprecated(get_frame_retsize, "get_frame_retsize_ea")
get_frame_part = ida_idaapi._ida_deprecated(get_frame_part, "get_frame_part_ea")
get_func_frame = ida_idaapi._ida_deprecated(get_func_frame, "get_func_frame_ea")
soff_to_fpoff = ida_idaapi._ida_deprecated(soff_to_fpoff, "soff_to_fpoff_ea")
update_fpd = ida_idaapi._ida_deprecated(update_fpd, "update_fpd_ea")

define_stkvar = ida_idaapi._ida_deprecated(define_stkvar, "define_stkvar_ea")
add_frame_member = ida_idaapi._ida_deprecated(add_frame_member, "add_frame_member_ea")
set_frame_member_type = ida_idaapi._ida_deprecated(set_frame_member_type, "set_frame_member_type_ea")
delete_frame_members = ida_idaapi._ida_deprecated(delete_frame_members, "delete_frame_members_ea")
build_stkvar_name = ida_idaapi._ida_deprecated(build_stkvar_name, "build_stkvar_name_ea")
calc_stkvar_struc_offset = ida_idaapi._ida_deprecated(calc_stkvar_struc_offset, "calc_stkvar_struc_offset_ea")
calc_frame_offset = ida_idaapi._ida_deprecated(calc_frame_offset, "calc_frame_offset_ea")

add_regvar = ida_idaapi._ida_deprecated(add_regvar, "add_func_regvar")
find_regvar = ida_idaapi._ida_deprecated(find_regvar, "find_func_regvar")
rename_regvar = ida_idaapi._ida_deprecated(rename_regvar, "rename_func_regvar")
set_regvar_cmt = ida_idaapi._ida_deprecated(set_regvar_cmt, "set_func_regvar_cmt")
del_regvar = ida_idaapi._ida_deprecated(del_regvar, "del_func_regvar")
has_regvar = ida_idaapi._ida_deprecated(has_regvar, "has_func_regvar")

add_auto_stkpnt = ida_idaapi._ida_deprecated(add_auto_stkpnt, "add_func_auto_stkpnt")
del_stkpnt = ida_idaapi._ida_deprecated(del_stkpnt, "del_func_stkpnt")
get_spd = ida_idaapi._ida_deprecated(get_spd, "get_func_spd")
get_effective_spd = ida_idaapi._ida_deprecated(get_effective_spd, "get_func_effective_spd")
get_sp_delta = ida_idaapi._ida_deprecated(get_sp_delta, "get_func_sp_delta")
set_auto_spd = ida_idaapi._ida_deprecated(set_auto_spd, "set_func_auto_spd")
recalc_spd_for_basic_block = ida_idaapi._ida_deprecated(recalc_spd_for_basic_block, "recalc_func_spd_for_basic_block")

build_stkvar_xrefs = ida_idaapi._ida_deprecated(build_stkvar_xrefs, "build_stkvar_xrefs_ea")

frame_off_args = ida_idaapi._ida_deprecated(frame_off_args, "frame_off_args_ea")
frame_off_retaddr = ida_idaapi._ida_deprecated(frame_off_retaddr, "frame_off_retaddr_ea")
frame_off_savregs = ida_idaapi._ida_deprecated(frame_off_savregs, "frame_off_savregs_ea")
frame_off_lvars = ida_idaapi._ida_deprecated(frame_off_lvars, "frame_off_lvars_ea")
is_funcarg_off = ida_idaapi._ida_deprecated(is_funcarg_off, "is_funcarg_off_ea")
lvar_off = ida_idaapi._ida_deprecated(lvar_off, "lvar_off_ea")

#</pycode(py_frame)>
