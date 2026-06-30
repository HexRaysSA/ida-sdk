#<pycode(py_funcs)>
import ida_idaapi
@ida_idaapi.replfun
def calc_thunk_func_target(*args):
    if len(args) == 2:
        pfn, rawptr = args
        target, fptr = calc_thunk_func_target.__dict__["orig"](pfn)
        import ida_pro
        ida_pro.ea_pointer.frompointer(rawptr).assign(fptr)
        return target
    else:
        return calc_thunk_func_target.__dict__["orig"](*args)
@ida_idaapi.replfun
def calc_thunk_function_target(*args):
    if len(args) == 2:
        fi, rawptr = args
        target, fptr = calc_thunk_function_target.__dict__["orig"](fi)
        import ida_pro
        ida_pro.ea_pointer.frompointer(rawptr).assign(fptr)
        return target
    else:
        return calc_thunk_function_target.__dict__["orig"](*args)
is_func_entry = ida_idaapi._ida_deprecated(is_func_entry, "is_function_entry")
is_func_tail = ida_idaapi._ida_deprecated(is_func_tail, "is_function_tail")
lock_func_range = ida_idaapi._ida_deprecated(lock_func_range, "lock_func_range_ea")
is_func_locked = ida_idaapi._ida_deprecated(is_func_locked, "is_func_locked_ea")
get_func = ida_idaapi._ida_deprecated(get_func, "get_func_start or get_func_entry_info")
get_func_chunknum = ida_idaapi._ida_deprecated(get_func_chunknum, "get_func_chunknum_ea")
getn_func = ida_idaapi._ida_deprecated(getn_func, "get_func_ea_by_num or get_func_entry_info_by_num")
get_prev_func = ida_idaapi._ida_deprecated(get_prev_func, "get_prev_func_ea")
get_next_func = ida_idaapi._ida_deprecated(get_next_func, "get_next_func_ea")
get_func_ranges = ida_idaapi._ida_deprecated(get_func_ranges, "get_func_ranges_ea")
get_func_cmt = ida_idaapi._ida_deprecated(get_func_cmt, "get_func_cmt_ea")
set_func_cmt = ida_idaapi._ida_deprecated(set_func_cmt, "set_func_cmt_ea")
update_func = ida_idaapi._ida_deprecated(update_func, "set_func_entry_info")
add_func_ex = ida_idaapi._ida_deprecated(add_func_ex, "add_function_ex")
reanalyze_function = ida_idaapi._ida_deprecated(reanalyze_function, "reanalyze_function_ea")
find_func_bounds = ida_idaapi._ida_deprecated(find_func_bounds, "find_function_bounds")
calc_func_size = ida_idaapi._ida_deprecated(calc_func_size, "calc_func_size_ea")
get_func_bitness = ida_idaapi._ida_deprecated(get_func_bitness, "get_func_bitness_ea")
set_visible_func = ida_idaapi._ida_deprecated(set_visible_func, "set_visible_func_ea")
set_func_name_if_jumpfunc = ida_idaapi._ida_deprecated(set_func_name_if_jumpfunc, "set_function_name_if_jumpfunc")
calc_thunk_func_target = ida_idaapi._ida_deprecated(calc_thunk_func_target, "calc_thunk_function_target")
get_fchunk = ida_idaapi._ida_deprecated(get_fchunk, "get_fchunk_start or get_fchunk_info")
getn_fchunk = ida_idaapi._ida_deprecated(getn_fchunk, "get_fchunk_ea_by_num")
get_prev_fchunk = ida_idaapi._ida_deprecated(get_prev_fchunk, "get_prev_fchunk_ea")
get_next_fchunk = ida_idaapi._ida_deprecated(get_next_fchunk, "get_next_fchunk_ea")
append_func_tail = ida_idaapi._ida_deprecated(append_func_tail, "append_func_tail_ea")
remove_func_tail = ida_idaapi._ida_deprecated(remove_func_tail, "remove_func_tail_ea")
set_tail_owner = ida_idaapi._ida_deprecated(set_tail_owner, "set_tail_owner_ea")
add_regarg = ida_idaapi._ida_deprecated(add_regarg, "add_func_regarg")
func_contains = ida_idaapi._ida_deprecated(func_contains, "function_contains")
get_prev_func_addr = ida_idaapi._ida_deprecated(get_prev_func_addr, "get_prev_function_addr")
get_next_func_addr = ida_idaapi._ida_deprecated(get_next_func_addr, "get_next_function_addr")
get_func_bits = ida_idaapi._ida_deprecated(get_func_bits, "get_func_bits_ea")
get_func_bytes = ida_idaapi._ida_deprecated(get_func_bytes, "get_func_bytes_ea")

is_visible_func = ida_idaapi._deprecated_overload(
    "is_visible_func",
    is_visible_func, func_t, _is_visible_func_pfn,
    "is_visible_func(func_t)",
    "is_visible_func(ea_t)")
is_finally_visible_func = ida_idaapi._deprecated_overload(
    "is_finally_visible_func",
    is_finally_visible_func, func_t, _is_finally_visible_func_pfn,
    "is_finally_visible_func(func_t)",
    "is_finally_visible_func(ea_t)")

lock_func = ida_idaapi._ida_deprecated_class(lock_func, "lock_func_ea")
func_tail_iterator_t = ida_idaapi._ida_deprecated_class(
    func_tail_iterator_t, "function_tail_iterator_t")
func_item_iterator_t = ida_idaapi._ida_deprecated_class(
    func_item_iterator_t, "function_item_iterator_t")
func_parent_iterator_t = ida_idaapi._ida_deprecated_class(
    func_parent_iterator_t, "function_parent_iterator_t")

ida_idaapi._ida_deprecated_init_overload(
    lock_func_with_tails_t, func_t,
    "lock_func_with_tails_t(func_t)",
    "lock_func_with_tails_t(ea_t)")

#</pycode(py_funcs)>
