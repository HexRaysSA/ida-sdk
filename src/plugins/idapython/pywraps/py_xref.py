
#<pycode(py_xref)>

import ida_idaapi
ida_idaapi._listify_types(
        casevec_t)

XREF_ALL = XREF_FLOW
XREF_FAR = XREF_NOFLOW

has_external_refs = ida_idaapi._ida_deprecated(has_external_refs, "has_external_refs_ea")

#</pycode(py_xref)>
