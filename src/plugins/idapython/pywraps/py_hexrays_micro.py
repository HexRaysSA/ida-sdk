"""This is python wrapper code that will be inserted into final
ida_hexrays_micro.py"""
#<pycode(py_hexrays_micro)>
hexrays_failure_t.__repr__ = lambda self: str("%x: %s" % (self.errea, self.desc()))

# ---------------------------------------------------------------------
# Renamings
is_small_struni = is_small_udt
mbl_array_t = mba_t


# ---------------------------------------------------------------------
# listify all list types
import ida_idaapi
ida_idaapi._listify_types(qvector_lvar_t, lvar_saved_infos_t)


lvar_t.used = property(lvar_t.used)
lvar_t.typed = property(lvar_t.typed)
lvar_t.mreg_done = property(lvar_t.mreg_done)
lvar_t.has_nice_name = property(lvar_t.has_nice_name)
lvar_t.is_unknown_width = property(lvar_t.is_unknown_width)
lvar_t.has_user_info = property(lvar_t.has_user_info)
lvar_t.has_user_name = property(lvar_t.has_user_name)
lvar_t.has_user_type = property(lvar_t.has_user_type)
lvar_t.is_result_var = property(lvar_t.is_result_var)
lvar_t.is_arg_var = property(lvar_t.is_arg_var)
lvar_t.is_fake_var = property(lvar_t.is_fake_var)
lvar_t.is_overlapped_var = property(lvar_t.is_overlapped_var)
lvar_t.is_floating_var = property(lvar_t.is_floating_var)
lvar_t.is_spoiled_var = property(lvar_t.is_spoiled_var)
lvar_t.is_mapdst_var = property(lvar_t.is_mapdst_var)

#</pycode(py_hexrays_micro)>
