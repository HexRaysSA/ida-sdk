"""
summary: list the program's classes through the decompiler's class API

description:
  Prints every class the decompiler's class view knows (Dalvik databases
  today), then the outline of the class under the cursor and the rendering
  of its first method with code.

  The names and types are the database's: rename a method's function or
  retype a static field's global and the output follows.
"""
import ida_hexrays
import ida_kernwin
import idc


def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("no decompiler")
        return
    classes = ida_hexrays.classes_t()
    if not ida_hexrays.get_classes(classes):
        print("this decompiler has no class model")
        return
    for c in classes:
        print("%s%s" % ("  " * c.name.count("$"), c.name))

    # the class owning the member under the cursor
    flt = ida_hexrays.class_filter_t()
    flt.ea = ida_kernwin.get_screen_ea()
    here = ida_hexrays.classes_t()
    if not ida_hexrays.get_classes(here, flt) or len(here) == 0:
        print("no class at %x" % flt.ea)
        return
    cls = here[0]

    ok, outline = ida_hexrays.render_class(cls, ida_hexrays.RCF_NO_BODIES)
    if ok:
        print("\n".join(outline))

    info = ida_hexrays.class_info_t()
    if ida_hexrays.get_class_info(info, cls):
        for m in info.methods:
            if m.ea != idc.BADADDR and not (m.flags & ida_hexrays.CLF_ABSTRACT):
                ok, body = ida_hexrays.render_member(m.ea)
                if ok:
                    print("\n".join(body))
                break


main()
