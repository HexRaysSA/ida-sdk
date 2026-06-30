"""
summary: serialize and deserialize a microcode instruction (minsn_t)

description:
  Generates microcode for the current function, takes its first
  instruction, serializes it to a byte string, and then deserializes
  those bytes back into a fresh minsn_t. equal_insns() is used to
  confirm the round trip preserves the structure.

  Note: minsn_t::deserialize is an instance method (returns bool), not
  a static factory like mba_t::deserialize / cfunc_t::deserialize. We
  construct an empty minsn_t with minsn_t(ea) and deserialize into it.

  This is the minsn_t-level counterpart to serialize.py, which
  round-trips a whole mba_t / cfunc_t pair.

level: beginner
"""

import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin


def first_insn(mba):
    for i in range(mba.qty):
        head = mba.get_mblock(i).head
        if head is not None:
            return head
    return None


def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler is not available")
        return

    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func_start(ea) == ida_idaapi.BADADDR:
        print(f"0x{ea:x}: not inside a function")
        return

    hf = ida_hexrays.hexrays_failure_t()
    dcr = ida_hexrays.decomp_ranges_t(ea)
    mba = ida_hexrays.gen_microcode(dcr, hf, None, ida_hexrays.DECOMP_NO_WAIT)
    if mba is None:
        print(f"0x{hf.errea:x}: gen_microcode failed: {hf.str}")
        return

    insn = first_insn(mba)
    if insn is None:
        print("no microcode instruction to round-trip")
        return

    print(f"original: {insn.dstr()}")

    fmt, data = insn.serialize()
    print(f"serialized: {len(data)} bytes (format version {fmt})")

    clone = ida_hexrays.minsn_t(insn.ea)
    if not clone.deserialize(data, fmt):
        print("deserialize failed")
        return

    print(f"match: {insn.equal_insns(clone, 0)}")


main()
