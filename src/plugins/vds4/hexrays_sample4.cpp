/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It dumps all user-defined information about the current
 *      function to the messages window. Namely, it displays:
 *        - user defined label names
 *        - user defined indented comments
 *        - user defined number formats
 *        - user defined local variable names, types, comments
 * The plugin loads information from the database without decompiling anything.
 *
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  ~plugin_ctx_t()
  {
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
static void print_location(qstring *buf, const vdloc_t &vdloc)
{
  buf->qclear();
  // we do not have the width info handy, so try 1 and sizeof(int)
  // this is not quite correct, but we just need to print something
  print_vdloc(buf, vdloc, 1);
  if ( buf->empty() )
    print_vdloc(buf, vdloc, inf_get_cc_size_i());
  if ( buf->empty() )
    *buf = "?";
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  func_t *pfn = get_func(get_screen_ea());
  if ( pfn == nullptr )
  {
    warning("AUTOHIDE NONE\nPlease move the cursor into a function");
    return true;
  }
  ea_t entry_ea = pfn->start_ea;
  msg("Dump of user-defined information for function at %a\n", entry_ea);

  // Display user defined labels.
  user_labels_t *labels = restore_user_labels(entry_ea);
  if ( labels != nullptr )
  {
    msg("------- %" FMT_Z " user defined labels\n", user_labels_size(labels));
    user_labels_iterator_t p;
    for ( p=user_labels_begin(labels);
          p != user_labels_end(labels);
          p=user_labels_next(p) )
    {
      int org_label = user_labels_first(p);
      qstring &name = user_labels_second(p);
      msg("Label %d: %s\n", org_label, name.c_str());
    }
    user_labels_free(labels);
  }

  // Display user defined comments
  user_cmts_t *cmts = restore_user_cmts(entry_ea);
  if ( cmts != nullptr )
  {
    msg("------- %" FMT_Z " user defined comments\n", user_cmts_size(cmts));
    user_cmts_iterator_t p;
    for ( p=user_cmts_begin(cmts);
          p != user_cmts_end(cmts);
          p=user_cmts_next(p) )
    {
      const treeloc_t &tl = user_cmts_first(p);
      citem_cmt_t &cmt = user_cmts_second(p);
      msg("Comment at %a, preciser %x:\n%s\n\n", tl.ea, tl.itp, cmt.c_str());
    }
    user_cmts_free(cmts);
  }

  // Display user defined citem iflags
  user_iflags_t *iflags = restore_user_iflags(entry_ea);
  if ( iflags != nullptr )
  {
    msg("------- %" FMT_Z " user defined citem iflags\n", user_iflags_size(iflags));
    user_iflags_iterator_t p;
    for ( p=user_iflags_begin(iflags);
          p != user_iflags_end(iflags);
          p=user_iflags_next(p) )
    {
      const citem_locator_t &cl = user_iflags_first(p);
      int f = user_iflags_second(p);
      msg("%a(%d): %08X", cl.ea, cl.op, f);
      if ( f & CIT_COLLAPSED )
        msg(" CIT_COLLAPSED");
      msg("\n");
    }
    user_iflags_free(iflags);
  }

  // Display user defined number formats
  user_numforms_t *numforms = restore_user_numforms(entry_ea);
  if ( numforms != nullptr )
  {
    msg("------- %" FMT_Z " user defined number formats\n", user_numforms_size(numforms));
    user_numforms_iterator_t p;
    for ( p=user_numforms_begin(numforms);
          p != user_numforms_end(numforms);
          p=user_numforms_next(p) )
    {
      const operand_locator_t &ol = user_numforms_first(p);
      number_format_t &nf = user_numforms_second(p);
      msg("Number format at %a, operand %d: %s",
          ol.ea, ol.opnum, (nf.props & NF_NEGATE) != 0 ? "negated " : "");
      if ( nf.is_enum() )
      {
        msg("enum %s (serial %d)\n", nf.type_name.c_str(), nf.serial);
      }
      else if ( nf.is_char() )
      {
        msg("char\n");
      }
      else if ( nf.is_stroff() )
      {
        msg("struct offset %s\n", nf.type_name.c_str());
      }
      else
      {
        msg("number base=%d\n", get_radix(nf.flags, ol.opnum));
      }
    }
    user_numforms_free(numforms);
  }

  // Display user-defined local variable information
  lvar_uservec_t lvinf;
  if ( restore_user_lvar_settings(&lvinf, entry_ea) )
  {
    qstring buf;
    msg("------- User defined local variable information\n");
    lvar_saved_infos_t::const_iterator ptr = lvinf.lvvec.begin();
    lvar_saved_infos_t::const_iterator end = lvinf.lvvec.end();
    while ( ptr != end )
    {
      const lvar_saved_info_t &lv = *ptr++;
      msg("Lvar defined at %a ", lv.ll.defea);
      const vdloc_t &vdloc = lv.ll.location;
      print_location(&buf, vdloc);
      msg("%s", buf.c_str());
      if ( lv.is_kept() )
        msg("  Preserved info about deleted variable\n");
      if ( lv.is_split_lvar() )
        msg("  Split variable\n");
      if ( !lv.name.empty() )
        msg("  Name: %s\n", lv.name.c_str());
      if ( !lv.type.empty() )
      {
        qstring out;
        lv.type.print(&out);
        msg("  Type: %s\n", out.c_str());
      }
      if ( !lv.cmt.empty() )
        msg("  Comment: %s\n", lv.cmt.c_str());
    }

    msg("\n------- Variable mappings\n");
    lvar_mapping_t &lm = lvinf.lmaps;
    for ( lvar_mapping_t::iterator p=lm.begin(); p != lm.end(); ++p )
    {
      print_location(&buf, p->first.location);
      msg("MAP LVAR %s ->", buf.c_str());
      print_location(&buf, p->second.location);
      msg(" %s\n", buf.c_str());
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr; // no decompiler
  const char *hxver = get_hexrays_version();
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      hxver, PLUGIN.wanted_name);
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample plugin4 for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Hex-Rays Dump User Info", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
