#<pycode(py_fixup)>
import ida_idaapi
import ida_segment

# fixup_data_t::set_sel(const segment_t *) is deprecated in favor of
# set_sel(sel_t); warn callers who still pass a segment.
ida_idaapi._ida_deprecated_method_overload(
    fixup_data_t, "set_sel", ida_segment.segment_t,
    "fixup_data_t.set_sel(segment_t)",
    "fixup_data_t.set_sel(sel_t)")
#</pycode(py_fixup)>
