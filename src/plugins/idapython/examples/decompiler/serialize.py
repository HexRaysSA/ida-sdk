"""
summary: serialize and deserialize the decompilation output

description:
  Decompiles the current function and serializes it into two byte vectors:
  one for mba and one for cfunc_t. Then deserializes these bytes and creates
  new mba and cfunc_t objects.

  This sample shows how the decompilation output can be converted into
  a pair of strings that can later be stored somewhere.

level: beginner
"""

import ida_hexrays

def main():
    hf = ida_hexrays.hexrays_failure_t()
    ea = ida_kernwin.get_screen_ea()
    cfunc = ida_hexrays.decompile(ea, hf)
    if not cfunc:
        print("%x: %s" % (ea, hf.desc()))
        return
    s1 = cfunc.mba.serialize()
    s2 = cfunc.serialize()
    print("%x: successfully serialized mba and cfunc objects" % ea)
    mba2 = ida_hexrays.mba_t.deserialize(s1)
    cfunc2 = ida_hexrays.cfunc_t.deserialize(mba2, s2)
    if not cfunc2:
        print("%x: deserialization error" % ea)
        return
    print("%x: successfully deserialized:\n%s" % (ea, str(cfunc2)))

main()
