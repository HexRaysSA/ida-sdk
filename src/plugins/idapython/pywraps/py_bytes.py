#<pycode(py_bytes)>
import ida_idaapi

update_hidden_range = ida_idaapi._ida_deprecated(update_hidden_range, "update_hidden_range_info")
get_hidden_range = ida_idaapi._ida_deprecated(get_hidden_range, "get_hidden_range_info")
getn_hidden_range = ida_idaapi._ida_deprecated(getn_hidden_range, "get_hidden_range_info_by_num")
get_prev_hidden_range = ida_idaapi._ida_deprecated(get_prev_hidden_range, "get_prev_hidden_range_ea")
get_next_hidden_range = ida_idaapi._ida_deprecated(get_next_hidden_range, "get_next_hidden_range_ea")
get_first_hidden_range = ida_idaapi._ida_deprecated(get_first_hidden_range, "get_first_hidden_range_ea")
get_last_hidden_range = ida_idaapi._ida_deprecated(get_last_hidden_range, "get_last_hidden_range_ea")

#</pycode(py_bytes)>
