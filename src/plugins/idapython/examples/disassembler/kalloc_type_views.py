"""
summary: a plugin that browses the typed allocations of a kernelcache

description:
  From iOS 16 and macOS 13 on, an XNU allocation of a known type does
  not pass a size. The kalloc_type() macro emits a descriptor into
  __DATA_CONST.__kalloc_type and passes its address instead; the
  runtime uses it to pick a zone segregated by the type's memory
  layout. A descriptor names the type, gives its size, and carries a
  map saying which of its eight-byte granules hold pointers. A second
  flavour, in __kalloc_var, describes an allocation whose length is
  only known at run time: a header, then a run of elements.

  Taken together they are an inventory of what a kernel allocates, and
  this plugin browses it: one row per type, with its size, what its
  granules hold, its flags, its signature, and how many descriptors
  describe it. Double-click a row to jump to a descriptor; the context
  menu lists every allocation site of that type.

  The point of the context menu is that it does not walk the xrefs of
  one descriptor. A type is commonly described by several -- on an
  iOS 26 kernel, 438 of the 696 types allocated have more than one --
  so the references of any single descriptor are only part of the
  answer. ida_kcu.kcu_svc_t.get_kalloc_views() gathers them.

  Nothing here knows the shape of a descriptor. The kcu plugin reads
  the fields through the kernel's own type library, so a kernel that
  moves them is picked up with the type library rather than here, and
  the flag and granule names below are read from that library's enums
  too. A script that parses the sections itself is hardcoding a layout
  that changes.

  Using it: drop this file in your plugins directory and open a
  kernelcache. Ctrl-Alt-K opens the browser, which is also under
  Edit > Plugins. On a cache loaded on demand it lists the types of
  the images mapped so far; map more KEXTs and refresh it.

level: intermediate
"""

import ida_funcs
import ida_idaapi
import ida_kcu
import ida_kernwin
import ida_typeinf
import ida_xref

TITLE = "kalloc_type views"


def _bits(enum_name, value, drop_prefix):
    """Spell out a bitmask using the type library's own enum."""
    tif = ida_typeinf.tinfo_t()
    details = ida_typeinf.enum_type_data_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), enum_name) \
       or not tif.get_enum_details(details):
        return "%#x" % value if value else ""
    out = []
    for member in details:
        if member.value and (value & member.value) == member.value:
            out.append(str(member.name)[len(drop_prefix):].lower())
    return ", ".join(out)


def _granules(sig):
    """What a signature's granules hold, as kt_granule_t names it.

    Each granule is one hex digit: the bitwise or of the kinds of the
    members sharing those eight bytes.
    """
    kinds = 0
    for c in sig:
        kinds |= int(c, 16)
    return _bits("kt_granule_t", kinds, "KT_GRANULE_") if kinds else ""


def _elide(sig, width=32):
    """A signature is one digit per granule, and a big type has hundreds."""
    return sig if len(sig) <= width else sig[:width - 3] + "..."


def _image_of(svc, ea):
    kext = svc.get_kext_by_ea(ea)
    if not kext.is_valid():
        return ""
    name = svc.get_kext_name(kext)
    return str(name) if name else ""


def collect():
    """One row per allocated type, and the descriptors describing it.

    Returns the descriptor vector as well: the rows point into it, so it
    has to outlive them.
    """
    svc = ida_kcu.get_kcu_svc(ida_kcu.kcu_config_t())
    if svc is None:
        return None, []
    views = svc.get_kalloc_views()
    rows = {}
    for view in views:
        # a descriptor whose site name is not a type ("typeof(*region)") is
        # still worth a row, under the name the macro was given
        key = str(view.type) or str(view.site_name)
        row = rows.get(key)
        if row is None:
            row = rows[key] = {
                "name": key + "*" * view.ptr_depth,
                "kind": "var" if view.var_view else "fixed",
                "size": view.size + view.size_hdr,
                "granules": _granules(str(view.sig)),
                "flags": _bits("kalloc_type_flags_t", view.flags, "KT_"),
                "signature": _elide(str(view.sig_hdr) + "+" + str(view.sig)
                                    if view.size_hdr else str(view.sig)),
                "eas": [],
                "images": set(),
            }
        row["eas"].append(view.ea)
        image = _image_of(svc, view.ea)
        if image:
            row["images"].add(image)
    out = sorted(rows.values(), key=lambda r: r["name"])
    for row in out:
        images = sorted(row["images"])
        row["image"] = (images[0] if len(images) == 1
                        else "%d images" % len(images) if images else "")
    return views, out


def sites_of(type_name):
    """Every allocation site of `type_name`, through all its descriptors."""
    svc = ida_kcu.get_kcu_svc(ida_kcu.kcu_config_t())
    sites = []
    for view in svc.get_kalloc_views(type_name):
        frm = ida_xref.get_first_dref_to(view.ea)
        while frm != ida_idaapi.BADADDR:
            sites.append((frm, ida_funcs.get_func_name(frm) or ""))
            frm = ida_xref.get_next_dref_to(view.ea, frm)
    sites.sort()
    return sites


class sites_chooser_t(ida_kernwin.Choose):
    def __init__(self, type_name, sites):
        ida_kernwin.Choose.__init__(
            self,
            "Allocations of %s" % type_name,
            [["Address", 20], ["Function", 48]],
            flags=ida_kernwin.Choose.CH_RESTORE)
        self.sites = sites

    def OnGetSize(self):
        return len(self.sites)

    def OnGetLine(self, n):
        return ["%#x" % self.sites[n][0], self.sites[n][1]]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.sites[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


class views_chooser_t(ida_kernwin.Choose):
    COLUMNS = [["Image", 22], ["Kind", 5], ["Type", 32], ["Size", 8],
               ["Granules", 18], ["Flags", 26], ["Signature", 28], ["Views", 5]]

    def __init__(self, views, rows):
        ida_kernwin.Choose.__init__(
            self,
            TITLE,
            self.COLUMNS,
            flags=ida_kernwin.Choose.CH_RESTORE | ida_kernwin.Choose.CH_CAN_REFRESH)
        self.views = views   # keeps the records the rows point into alive
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        row = self.rows[n]
        return [row["image"], row["kind"], row["name"], "%#x" % row["size"],
                row["granules"], row["flags"], row["signature"],
                str(len(row["eas"]))]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n]["eas"][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.views, self.rows = collect()
        return (ida_kernwin.Choose.ALL_CHANGED, n)

    def OnGetEA(self, n):
        return self.rows[n]["eas"][0]

    def show_sites(self, n):
        row = self.rows[n]
        sites = sites_of(str(row["name"]).rstrip("*"))
        if not sites:
            ida_kernwin.info("Nothing in the mapped images allocates %s."
                             % row["name"])
            return
        sites_chooser_t(row["name"], sites).Show()


ACTION_SITES = "kalloc_type_views:sites"


class sites_action_t(ida_kernwin.action_handler_t):
    def __init__(self, chooser):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser

    def activate(self, ctx):
        for n in ctx.chooser_selection:
            self.chooser.show_sites(n)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_title == TITLE \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


def show():
    """Open the browser. Returns it, or None when there is nothing to browse."""
    views, rows = collect()
    if not rows:
        ida_kernwin.warning("No typed allocations here: this is not a "
                            "kernelcache, or it predates iOS 16.")
        return None
    browser = views_chooser_t(views, rows)
    browser.Show()
    # Show() keeps the chooser alive, and the action handler below holds the
    # one it acts on, so neither needs a reference kept here.
    ida_kernwin.unregister_action(ACTION_SITES)
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_SITES, "Allocation sites of this type",
            sites_action_t(browser)))
    ida_kernwin.attach_action_to_popup(
        ida_kernwin.find_widget(TITLE), None, ACTION_SITES)
    return browser


ACTION_SHOW = "kalloc_type_views:show"
SHORTCUT = "Ctrl-Alt-K"


class show_action_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class kalloc_type_views_t(ida_idaapi.plugmod_t):
    """One database's worth of the plugin: just the action that opens it."""

    def __init__(self):
        ida_idaapi.plugmod_t.__init__(self)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_SHOW, "Browse typed allocations", show_action_t(),
                SHORTCUT))

    def __del__(self):
        ida_kernwin.unregister_action(ACTION_SHOW)
        ida_kernwin.unregister_action(ACTION_SITES)

    def run(self, arg):
        show()
        return 0


class kalloc_type_views_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Browse the typed allocations of a kernelcache"
    help = comment
    wanted_name = "kalloc_type views"
    wanted_hotkey = ""   # the action above owns the shortcut

    def init(self):
        return kalloc_type_views_t()


def PLUGIN_ENTRY():
    return kalloc_type_views_plugin_t()
