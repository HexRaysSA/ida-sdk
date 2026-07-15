# -*- coding: utf-8 -*-
"""
summary: dump function flowchart, new API

description:
  Dumps the current function's flowchart, using 2 methods:

    * the low-level `ida_gdl.qflow_chart_ea_t` type

level: beginner
"""

import idaapi
import ida_gdl
import ida_funcs
import ida_kernwin

def out(p, msg):
    if p:
        print(msg)

def out_succ(p, start_ea, end_ea):
    out(p, "  SUCC:  %x - %x" % (start_ea, end_ea))

def out_pred(p, start_ea, end_ea):
    out(p, "  PRED:  %x - %x" % (start_ea, end_ea))


# -----------------------------------------------------------------------
# Using ida_gdl.qflow_chart_ea_t
def using_qflow_chart_ea_t(ea, p=True):
    func_ea = ida_funcs.get_func_start(ea)
    if func_ea == idaapi.BADADDR:
        return

    q = ida_gdl.qflow_chart_ea_t("The title", func_ea, 0, 0, 0)
    for n in range(q.size()):
        b = q[n]
        out(p, "%x - %x [%d]:" % (b.start_ea, b.end_ea, n))
        for ns in range(q.nsucc(n)):
            b2 = q[q.succ(n, ns)]
            out_succ(p, b2.start_ea, b2.end_ea)

        for ns in range(q.npred(n)):
            b2 = q[q.pred(n, ns)]
            out_pred(p, b2.start_ea, b2.end_ea)

# -----------------------------------------------------------------------
ea = ida_kernwin.get_screen_ea()

print(">>> Dumping flow chart using ida_gdl.qflow_chart_ea_t")
using_qflow_chart_ea_t(ea)
