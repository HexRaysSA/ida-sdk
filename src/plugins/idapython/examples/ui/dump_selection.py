"""
summary: retrieve & dump current selection

description:
  Shows how to retrieve the selection from a listing
  widget ("IDA View-A", "Hex View-1", "Pseudocode-A", ...) as
  two "cursors", and from there retrieve (in fact, generate)
  the corresponding text.

  After running this script:

    * select some text in one of the listing widgets (i.e.,
      "IDA View-...", "Local Types", "Pseudocode-...")
    * press Ctrl+Shift+S to dump the selection

level: advanced
"""

import ida_kernwin
import ida_lines

def get_widget_lines(widget, tp0, tp1):
    """
    get lines between places tp0 and tp1 in widget
    """
    ud = ida_kernwin.get_viewer_user_data(widget)
    lnar = ida_kernwin.linearray_t(ud)
    # l_compare2 doesn't always match visual left-to-right order: in
    # pseudocode, places on the same line are ordered by source EA, not
    # column, so `callfn(arg)` may have `callfn > arg`. Walk from the
    # smaller place to the larger one; tp0.x / tp1.x clip horizontally.
    if ida_kernwin.l_compare2(tp0.at, tp1.at, ud) > 0:
        start_at, end_at = tp1.at, tp0.at
    else:
        start_at, end_at = tp0.at, tp1.at
    lnar.set_place(start_at)
    lines = []
    while ida_kernwin.l_compare2(lnar.get_place(), end_at, ud) <= 0:
        lines.append(ida_lines.tag_remove(lnar.down()))
    if lines:
        lines[-1] = lines[-1][:tp1.x]                 # clip selection end
        lines[0] = " " * tp0.x + lines[0][tp0.x:]     # clip selection start
    return lines

class dump_selection_handler_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if ctx.has_flag(ida_kernwin.ACF_HAS_SELECTION):
            lines = get_widget_lines(ctx.widget, ctx.cur_sel._from, ctx.cur_sel.to)
            for line in lines:
                print(line)
        return 1

    def update(self, ctx):
        ok_widgets = [
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_TILVIEW,
            ida_kernwin.BWN_PSEUDOCODE,
        ]
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type in ok_widgets \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


# -----------------------------------------------------------------------
# create actions (and attach them to IDA View-A's context menu if possible)
ACTION_NAME = "dump_selection"
ACTION_SHORTCUT = "Ctrl+Shift+S"

if ida_kernwin.unregister_action(ACTION_NAME):
    print("Unregistered previously-registered action \"%s\"" % ACTION_NAME)

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Dump selection",
            dump_selection_handler_t(),
            ACTION_SHORTCUT)):
    print("Registered action \"%s\"" % ACTION_NAME)

# dump current selection
p0 = ida_kernwin.twinpos_t()
p1 = ida_kernwin.twinpos_t()
view = ida_kernwin.get_last_widget(ida_kernwin.IWID_ANY_LISTING)
if ida_kernwin.read_selection(view, p0, p1):
    lines = get_widget_lines(view, p0, p1)
    print("\n".join(lines))

