/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows xrefs to the called function as the decompiler output.
 *      All calls are displayed with the call arguments.
 *      Usage: Shift-X or Jump, Jump to call xrefs...
 */

#include <hexrays.hpp>

#define ACTION_NAME "vds14:call_xrefs"

//-------------------------------------------------------------------------
struct vds14_t : public plugmod_t
{
  vds14_t();
  virtual bool idaapi run(size_t) override { return false; }
};

//-------------------------------------------------------------------------
struct xref_info_t
{
  qstring text;
  ea_t ea;
  char xref_type;
};
DECLARE_TYPE_AS_MOVABLE(xref_info_t);
typedef qvector<xref_info_t> xrefvec_t;

//-------------------------------------------------------------------------
// go backwards until the beginning of the basic block
static ea_t find_bb_start(ea_t call_ea)
{
  ea_t ea = call_ea;
  while ( true )
  {
    flags64_t F = get_flags(ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
    insn_t tmp;
    ea_t prev = decode_prev_insn(&tmp, ea);
    if ( prev == BADADDR )
      break;
    ea = prev;
  }
  return ea;
}

//-------------------------------------------------------------------------
static bool determine_decompilation_range(
        mba_ranges_t *mbr,
        ea_t call_ea,
        const tinfo_t &tif)
{
  func_t *pfn = get_func(call_ea);
  if ( pfn != nullptr && calc_func_size(pfn) <= 1024 )
  { // a small function, decompile it entirely
    mbr->pfn = pfn;
    return true;
  }

  ea_t minea = call_ea;
  ea_t maxea = call_ea;
  eavec_t addrs;
  if ( !get_arg_addrs(&addrs, call_ea) )
  {
    apply_callee_tinfo(call_ea, tif);
    if ( !get_arg_addrs(&addrs, call_ea) )
      minea = find_bb_start(call_ea);
  }
  for ( size_t i=0; i < addrs.size(); i++ )
  {
    if ( minea > addrs[i] )
      minea = addrs[i];
    if ( maxea < addrs[i] )
      maxea = addrs[i];
  }
  range_t &r = mbr->ranges.push_back();
  r.start_ea = minea;
  r.end_ea = get_item_end(maxea);
  return true;
}

//-------------------------------------------------------------------------
// decompile the snippet
static bool generate_call_line(
        qstring *out,
        bool *canceled,
        ea_t call_ea,
        const tinfo_t &tif)
{
  mba_ranges_t mbr;
  if ( !determine_decompilation_range(&mbr, call_ea, tif) )
    return false;
  hexrays_failure_t hf;
  cfuncptr_t func = decompile(mbr, &hf, DECOMP_NO_WAIT);
  if ( func == nullptr )
  {
    if ( hf.code == MERR_CANCELED )
      *canceled = true;
    return false;
  }
  citem_t *call = func->body.find_closest_addr(call_ea);
  if ( call == nullptr || call->ea != call_ea )
    return false;
  const strvec_t &sv = func->get_pseudocode();
  int y;
  if ( !func->find_item_coords(call, nullptr, &y) )
    return false;
  *out = sv[y].line;
  tag_remove(out);
  // indentation does not convey much info, so remove the leading spaces
  out->ltrim();
  return true;
}

//-------------------------------------------------------------------------
struct xref_chooser_t : public chooser_t
{
protected:
  ea_t func_ea;
  const xrefvec_t &list;

  static const int widths_[];
  static const char *const header_[];
  enum { ICON = 55 };

public:
  xref_chooser_t(uint32 flags, ea_t func_ea, const xrefvec_t &list, const char *title);
  ea_t choose_modal(ea_t xrefpos_ea);

  virtual size_t idaapi get_count() const override { return list.size(); }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;

  // calculate the location of the item,
  // item_data is a pointer to a xref position
  virtual ssize_t idaapi get_item_index(const void *item_data) const override;

protected:
  static const char *direction_str(ea_t ea, ea_t refea)
  {
    return ea > refea ? "Up" : ea < refea ? "Down" : "";
  }
  static void get_xrefed_name(qstring *buf, ea_t ref);

  xrefvec_t::const_iterator find(const xrefpos_t &pos) const
  {
    xrefvec_t::const_iterator it = list.begin();
    xrefvec_t::const_iterator end = list.end();
    for ( ; it != end; ++it )
    {
      const xref_info_t &cur = *it;
      if ( cur.ea == pos.ea && cur.xref_type == pos.type )
        break;
    }
    return it;
  }
};

//-------------------------------------------------------------------------
const int xref_chooser_t::widths_[] =
{
  6,  // Direction
  1,  // Type
  15, // Address
  50, // Text
};
const char *const xref_chooser_t::header_[] =
{
  "Direction",  // 0
  "Type",       // 1
  "Address",    // 2
  "Text",       // 3
};

//-------------------------------------------------------------------------
inline xref_chooser_t::xref_chooser_t(
        uint32 flags_,
        ea_t func_ea_,
        const xrefvec_t &list_,
        const char *title_)
  : chooser_t(flags_,
              qnumber(widths_), widths_, header_,
              title_),
    func_ea(func_ea_),
    list(list_)
{
  CASSERT(qnumber(widths_) == qnumber(header_));
  icon = ICON;
  deflt_col = 2;
}

//-------------------------------------------------------------------------
inline ea_t xref_chooser_t::choose_modal(ea_t xrefpos_ea)
{
  if ( list.empty() )
  {
    warning("There are no %s", title);
    return BADADDR;
  }

  xrefpos_t defpos;
  get_xrefpos(&defpos, xrefpos_ea);
  ssize_t n = ::choose(this, &defpos);
  if ( n < 0 || n >= list.size() )
    return BADADDR;
  const xref_info_t &entry = list[n];
  if ( n == 0 )
  {
    del_xrefpos(xrefpos_ea);
  }
  else
  {
    xrefpos_t xp(entry.ea, entry.xref_type);
    set_xrefpos(xrefpos_ea, &xp);
  }
  return entry.ea;
}

//-------------------------------------------------------------------------
void idaapi xref_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  const xref_info_t &entry = list[n];
  qstrvec_t &cols = *cols_;
  cols[0] = direction_str(func_ea, entry.ea);
  cols[1].sprnt("%c", xrefchar(entry.xref_type));
  get_xrefed_name(&cols[2], entry.ea);
  cols[3] = entry.text;
}

//------------------------------------------------------------------------
ssize_t idaapi xref_chooser_t::get_item_index(const void *item_data) const
{
  if ( list.empty() )
    return NO_SELECTION;

  // `item_data` is a pointer to a xref position
  xrefpos_t item_pos = *(const xrefpos_t *)item_data;

  if ( !item_pos.is_valid() )
    return 0; // first item by default

  xrefvec_t::const_iterator it = find(item_pos);
  if ( it == list.end() )
    return 0; // first item by default
  return it - list.begin();
}

//-------------------------------------------------------------------------
void xref_chooser_t::get_xrefed_name(qstring *buf, ea_t ref)
{
  int f2 = GNCN_NOCOLOR; //-V688
  if ( !inf_show_xref_fncoff() )
    f2 |= GNCN_NOFUNC;
  if ( !inf_show_xref_seg() )
    f2 |= GNCN_NOSEG;
  get_nice_colored_name(buf, ref, f2);
}

//-------------------------------------------------------------------------
static bool jump_to_call(ea_t func_ea)
{
  // Retrieve all xrefs to the function
  xrefblk_t xb;
  xrefvec_t list;
  for ( bool ok = xb.first_to(func_ea, 0); ok; ok=xb.next_to() )
  {
    xref_info_t &entry = list.push_back();
    entry.ea = xb.from;
    entry.xref_type = xb.type;
  }

  // Generate decompiler output or disassembly output for each xref
  tinfo_t tif;
  if ( get_tinfo(&tif, func_ea) )
    guess_tinfo(&tif, func_ea);
  show_wait_box("Decompiling...");
  bool canceled = false;
  size_t n = list.size();
  for ( size_t i=0; i < n; i++ )
  {
    xref_info_t &entry = list[i];
    bool success = false;
    if ( entry.xref_type >= fl_CF && !canceled )
    {
      replace_wait_box("Decompiling %a (%" FMT_Z "/%" FMT_Z ")...", entry.ea, i, n);
      success = generate_call_line(&entry.text, &canceled, entry.ea, tif);
    }
    if ( !success )
      generate_disasm_line(&entry.text, entry.ea, GENDSM_REMOVE_TAGS);
  }
  hide_wait_box();

  // Display the xref chooser
  qstring title;
  get_short_name(&title, func_ea);
  title.insert("xrefs to ");

  xref_chooser_t xrefch(CH_MODAL | CH_KEEP, func_ea, list, title.c_str());
  ea_t target = xrefch.choose_modal(func_ea);
  if ( target == BADADDR )
    return false;

  // Jump to the seleected target
  return jumpto(target);
}

//-------------------------------------------------------------------------
struct func_xrefs_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    ea_t ea = ctx->cur_value;
    flags64_t F = get_flags(ea);
    if ( !is_func(F) )
    { // we are not staying on a call.
      // check if we stay on the entry point of a function
      ea = ctx->cur_ea;
      F = get_flags(ea);
      if ( !is_func(F) )
        ea = BADADDR;
    }
    if ( ea != BADADDR )
      return jump_to_call(ea);
    return process_ui_action("JumpOpXref"); // fallback to the built-in action
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    switch ( ctx->widget_type )
    {
      case BWN_EXPORTS: // exports
      case BWN_IMPORTS: // imports
      case BWN_NAMES:   // names
      case BWN_FUNCS:   // functions
      case BWN_DISASM:  // disassembly views
      case BWN_HEXVIEW: // hex views
      case BWN_PSEUDOCODE: // decompiler view
        return AST_ENABLE_FOR_WIDGET;
    }
    return AST_DISABLE_FOR_WIDGET;
  }
};
static func_xrefs_t func_xrefs_ah;

//-------------------------------------------------------------------------
//                                 vds14_t
//-------------------------------------------------------------------------
vds14_t::vds14_t()
{
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      get_hexrays_version(),
      PLUGIN.wanted_name);

  register_action(ACTION_DESC_LITERAL_PLUGMOD(
                          ACTION_NAME,
                          "Jump to call x~r~efs",
                          &func_xrefs_ah,
                          this,
                          "Shift-X",
                          nullptr,
                          -1));
  attach_action_to_menu("Jump/Jump to func", ACTION_NAME, SETMENU_APP);
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return init_hexrays_plugin() ? new vds14_t : nullptr;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample14 plugin for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI, // plugin flags
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  "",                   // multiline help about the plugin
  "Call xrefs",         // the preferred short name of the plugin
                        // (not visible because of PLUGIN_HIDE)
  ""                    // the preferred hotkey to run the plugin
};
