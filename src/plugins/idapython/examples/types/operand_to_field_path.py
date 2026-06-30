"""
summary: turn an instruction operand into a structure-field reference by name

description:
    Demonstrates how to use ida_typeinf.resolve_field_path() to convert a
    user-friendly dotted field path (e.g.
    "_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode") into
    the path[] inputs that ida_bytes.op_stroff() expects.

    resolve_field_path() is needed when the chain crosses anonymous types --
    unnamed types are stored with synthetic "::$HASH" names, so the
    friendly dotted form the user writes does not match the canonical
    names directly. resolve_field_path() walks the chain segment by
    segment and produces a ready-to-use op_stroff() path.

    Companion to operand_to_struct_member.py, which does the same thing
    interactively (the user picks the top struct and any union members
    through a chooser dialog). This one is for scripts that already know
    exactly where in the type tree the operand should point.

level: intermediate
"""
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_typeinf
import ida_ua
import idc


# ---------------------------------------------------------------------------
# Edit these for your IDB:
FIELD_PATH = "_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode"
OPNUM = 1                       # 0 = destination operand, 1 = source, etc.
# ---------------------------------------------------------------------------


def retype_as_field_path(ea, opnum, field_path):
    """Annotate operand `opnum` of the instruction at `ea` as `field_path`.

    field_path: a dotted name like "MyStruct.field1.field2.leaf".

    Returns the ida_typeinf.field_path_t produced by resolve_field_path()
    on success or None on failure.
    """
    # Make sure the top struct is in local types so it has a TID.
    # resolve_field_path needs that for path[0]; types loaded only from
    # base TILs don't have TIDs until imported.
    top_name = field_path.split(".", 1)[0]
    if idc.import_type(-1, top_name) == ida_idaapi.BADADDR:
        print(f"Type {top_name!r} not found in any loaded TIL.")
        return None

    # Resolve the dotted path. The walker returns:
    #   r.stroff_path  - ready-to-pass to op_stroff()
    #   r.leaf_tif     - the type of the leaf field
    #   r.cumul_bitoff - bit offset of the leaf from the top
    r = ida_typeinf.field_path_t()
    if not ida_typeinf.resolve_field_path(r, None, field_path):
        print(f"resolve_field_path({field_path!r}) failed -- "
              f"check the field names along the path.")
        return None

    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        print(f"could not decode instruction at {ea:#x}")
        return None

    if not ida_bytes.op_stroff(insn, opnum, r.stroff_path, 0):
        print(f"op_stroff failed at {ea:#x} op{opnum}")
        return None

    print(f"{ea:#x}: operand {opnum} now refers to "
          f"{field_path} (leaf type: {r.leaf_tif._print()})")
    return r


result = retype_as_field_path(ida_kernwin.get_screen_ea(), OPNUM, FIELD_PATH)
