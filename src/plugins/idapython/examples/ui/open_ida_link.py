"""
summary: navigate to entities using ida:// links

description:
  Demonstrates ``ida_kernwin.open_ida_link()`` which provides URL-style
  navigation within the current IDB. The function accepts URIs of the
  form ``ida:///resource?params`` and navigates to the matching entity,
  optionally opening a specific view.

  Nine resource types are supported: functions, addresses, strings,
  segments, names, imports, exports, types, and bookmarks.

  Most resources use ``rva=`` or ``ea=`` to specify the target address.
  The ``types`` resource uses ``name=`` instead. An optional ``view=``
  parameter selects which view to open (e.g., ``view=pseudocode``).

keywords: navigation, links

level: intermediate
"""

import ida_entry
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_strlist

def try_open_ida_link(uri):
    """Call open_ida_link and print the URI and result."""
    ok = ida_kernwin.open_ida_link(uri)
    print("open_ida_link(%s) => %s" % (repr(uri), ok))
    return ok

# Compute the image base so we can derive RVAs from EAs.
image_base = ida_nalt.get_imagebase()

#
# 1. Functions — navigate to first function using RVA
#
func = ida_funcs.get_next_func(0)
if func:
    rva = func.start_ea - image_base
    try_open_ida_link("ida:///functions?rva=0x%x" % rva)

#
# 2. Addresses — navigate to entry point using EA
#
entry_ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
if entry_ea != ida_idaapi.BADADDR:
    try_open_ida_link("ida:///addresses?ea=0x%x" % entry_ea)

#
# 3. Strings — navigate to first string using RVA
#
si = ida_strlist.string_info_t()
if ida_strlist.get_strlist_item(si, 0):
    rva = si.ea - image_base
    try_open_ida_link("ida:///strings?rva=0x%x" % rva)

#
# 4. Segments — navigate to first segment using RVA
#
seg = ida_segment.get_first_seg()
if seg:
    rva = seg.start_ea - image_base
    try_open_ida_link("ida:///segments?rva=0x%x" % rva)

#
# 5. Names — navigate to first named location using RVA
#
name_ea = ida_name.get_nlist_ea(0)
if name_ea != ida_idaapi.BADADDR:
    rva = name_ea - image_base
    try_open_ida_link("ida:///names?rva=0x%x" % rva)

#
# 6. Imports — navigate to first import using RVA
#
import_ea = ida_idaapi.BADADDR
def _get_first_import(ea, name, ordinal):
    global import_ea
    import_ea = ea
    return False  # stop after first
if ida_nalt.get_import_module_qty() > 0:
    ida_nalt.enum_import_names(0, _get_first_import)
if import_ea != ida_idaapi.BADADDR:
    rva = import_ea - image_base
    try_open_ida_link("ida:///imports?rva=0x%x" % rva)

#
# 7. Exports — navigate to first export using RVA
#
if ida_entry.get_entry_qty() > 0:
    ordinal = ida_entry.get_entry_ordinal(0)
    export_ea = ida_entry.get_entry(ordinal)
    if export_ea != ida_idaapi.BADADDR:
        rva = export_ea - image_base
        try_open_ida_link("ida:///exports?rva=0x%x" % rva)

#
# 8. Types — navigate by type name
#
try_open_ida_link("ida:///types?name=size_t")

#
# 9. Bookmarks — navigate to entry point (it's a mapped address)
#
if entry_ea != ida_idaapi.BADADDR:
    rva = entry_ea - image_base
    try_open_ida_link("ida:///bookmarks?rva=0x%x" % rva)

print("All done.")
