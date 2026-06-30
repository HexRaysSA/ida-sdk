"""
summary: a flat list, with checkboxes

description:
  Shows how to subclass the ida_kernwin.Choose class to
  show data organized in a simple table, and react to
  "checked state" events.

keywords: chooser, actions

see_also: choose_multi

level: intermediate
"""

import ida_kernwin
from ida_kernwin import Choose

# -----------------------------------------------------------------------
class grocery_list_chooser_t(Choose):

    def __init__(self, title, flags = 0, modal = False):
        Choose.__init__(
            self,
            title,
            [
                ["Item", 30 | ida_kernwin.CHCOL_CHECKBOX],
                ["Count", 10]
            ],
            flags = flags | ida_kernwin.CH_RESTORE
                          | (ida_kernwin.CH_CAN_INS
                           | ida_kernwin.CH_CAN_DEL
                           | ida_kernwin.CH_CAN_REFRESH))
        self.n = 0
        self.items = [
            ["Onions", "6"],
            ["Waffles", "3"], # Onions & waffles - we're treating ourselves!
        ]

        self.excluded = set()
        self.modal = modal

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        color = 0xFFFFFFFF
        flags = 0
        if n not in self.excluded:
            flags |= ida_kernwin.CHITEM_CHKST_CHECKED
        return [color, flags]

    def OnInsertLine(self, n):
        # we ignore current selection
        n = self.n # position at the just added item
        what = ida_kernwin.ask_str("", 0, "What should we pick?")
        if not what:
            return (Choose.NOTHING_CHANGED, n)
        count = ida_kernwin.ask_str("", 0, "And how many?")
        if not count:
            return (Choose.NOTHING_CHANGED, n)
        self.items.append([what, count])
        return (Choose.ALL_CHANGED, n)

    def OnDeleteLine(self, n):
        del self.items[n]
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnCheckedLine(self, n, state):
        checked = state == ida_kernwin.CHITEM_CHKST_CHECKED
        if checked and n in self.excluded:
            self.excluded.remove(n)
            return [Choose.ALL_CHANGED] + self.adjust_last_item(n)
        elif not checked and n not in self.excluded:
            self.excluded.add(n)
            return [Choose.ALL_CHANGED] + self.adjust_last_item(n)
        return (Choose.NOTHING_CHANGED, n)

    def show(self):
        return self.Show(self.modal) >= 0

groceries = grocery_list_chooser_t("Grocery list")
groceries.show()
