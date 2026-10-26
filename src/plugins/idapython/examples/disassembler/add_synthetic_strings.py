"""
summary: add strings that exist only in the code to the string list

description:
  Some strings are never stored in the bytes of a file: the code builds
  them from immediates, or they are slices of a larger blob. A plugin can
  still have IDA show them, as a synthetic string provider:

  * the provider registers once; its name is shown in the "Type" column
    of the Strings window
  * `synth_string_provider_t.set()` stores strings at an address: the
    listing shows them as a comment there, and the Strings window lists
    them
  * with `SYNTHSTR_REPEATABLE`, the listing also shows the string at the
    instructions that refer to its address, as it does for a string
    literal
  * `synth_string_provider_t.set_strings()` stores strings together with
    the instructions that build their pieces (`parts`) and that use them
    (`uses`); `synth_string_get_related()` finds a string from any of
    those instructions
  * `synth_string_provider_t.forget()` removes them again

  The strings are stored in the database: they stay after the database is
  closed and reopened, also when no provider is registered.

level: intermediate
"""

import itertools

import ida_bytes
import ida_ida
import ida_idp
import ida_lines
import ida_segment
import ida_strlist
import ida_ua
import idautils

provider = ida_strlist.synth_string_provider_t(
    ida_strlist.SYNTHSTR_PROVIDER_CUSTOM, "Example")
provider.register_provider()

def line_showing(ea, text):
    """the line of the listing at EA that shows TEXT"""
    for line in ida_lines.generate_disassembly(ea, 40, False, True)[1]:
        if text in line:
            return " ".join(line.split())
    return "(not shown)"

# a string that the code at the entry point builds
code_ea = ida_ida.inf_get_start_ea()
provider.set(code_ea, ["built by the code"])
print(line_showing(code_ea, "built by the code"))

# a string held by a data item (not a string literal, which has its own
# text) that the code refers to; it is repeatable, so the instruction that
# refers to the item shows it too
def first_referenced_data():
    for seg_ea in idautils.Segments():
        si = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(si, seg_ea) \
           or si.get_type() != ida_segment.SEG_DATA:
            continue
        for head in idautils.Heads(si.start_ea, si.end_ea):
            if ida_bytes.is_strlit(ida_bytes.get_flags(head)):
                continue
            for frm in idautils.DataRefsTo(head):
                if ida_bytes.is_code(ida_bytes.get_flags(frm)):
                    return head, frm
    return None, None

data_ea, user_ea = first_referenced_data()
if data_ea is not None:
    provider.set(data_ea, ["held by the data"], ida_strlist.SYNTHSTR_REPEATABLE)
    print(line_showing(data_ea, "held by the data"))
    print(line_showing(user_ea, "held by the data"))

# a string that the code builds piece by piece (e.g. on the stack) and then
# passes to a call: it is stored at the instruction that completes it, and
# names the instructions that build its pieces and the call that uses it
def first_call(func_ea):
    insn = ida_ua.insn_t()
    for ea in idautils.FuncItems(func_ea):
        if ida_ua.decode_insn(insn, ea) and ida_idp.is_call_insn(insn):
            return ea
    return None

pieces = list(itertools.islice(idautils.Heads(code_ea, ida_ida.inf_get_max_ea()), 3))
call_ea = first_call(code_ea)
s = ida_strlist.synth_string_t()
s.text = "built piece by piece"
s.parts = pieces
s.uses = [call_ea] if call_ea is not None else []
strings = ida_strlist.synth_strings_t()
strings.push_back(s)
provider.set_strings(pieces[-1], strings)

# whoever looks at one of those instructions finds the string from it
def related(ea, rels=ida_strlist.SYNTHREL_ALL):
    out = ida_strlist.synth_strings_t()
    ida_strlist.synth_string_get_related(out, ea, rels)
    return ["%x: %s" % (r.ea, r.text) for r in out]

print("%x builds a piece of %s" % (pieces[0], related(pieces[0], ida_strlist.SYNTHREL_PART)))
if call_ea is not None:
    print("%x uses %s" % (call_ea, related(call_ea, ida_strlist.SYNTHREL_USE)))

# the Strings window lists them under the name of the provider
ida_strlist.build_strlist()
for s in idautils.Strings():
    if s.provider == provider.id:
        print("%x: %s (%s)" % (s.ea, s, ida_strlist.synth_string_provider_name(s.provider)))
