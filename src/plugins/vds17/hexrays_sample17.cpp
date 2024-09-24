/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows how to use "Select offsets" widget (select_udt_by_offset() call).
 *      This plugin repeats the Alt-Y functionality.
 *      Usage: place cursor on the union field and press Shift-T
 */

#include <hexrays.hpp>

#define ACTION_NAME "vds17:strchoose"

//-------------------------------------------------------------------------
struct func_stroff_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    // get the current item
    vdui_t &vu = *get_widget_vdui(ctx->widget);
    vu.get_current_item(USE_KEYBOARD);

    // check that the current item is union field
    if ( !vu.item.is_citem() )
    {
NOT_UNION_MEMBER:
      warning("Please position the cursor on a union member");
      return 0;
    }
    const cexpr_t *e = vu.item.e;
    while ( true )
    {
      ctype_t op = e->op;
      if ( op != cot_memptr && op != cot_memref )
        goto NOT_UNION_MEMBER;
      e = e->x;
      if ( op == cot_memref )
      {
        if ( e->type.is_union() )
          break;
      }
      else // cot_memptr
      {
        if ( remove_pointer(e->type).is_union() )
          break;
      }
      if ( !e->type.is_udt() )
        goto NOT_UNION_MEMBER;
    }

    // calculate the member offset
    uval_t off = 0;
    e = vu.item.e;
    while ( true )
    {
      const cexpr_t *e2 = e->x;
      tinfo_t type = remove_pointer(e2->type);
      if ( !type.is_union() )
        off += e->m;
      e = e2;
      if ( e2->op != cot_memref && e2->op != cot_memptr )
        break;
      if ( !e2->type.is_udt() )
        break;
    }

    // go up and collect more member references (in order to calculate the final offset)
    const citem_t *p = vu.item.e;
    while ( true )
    {
      const cinsn_t &body = vu.cfunc->body;
      const citem_t *p2 = body.find_parent_of(p);
      const cexpr_t *e2 = (const cexpr_t *)p2;
      if ( p2->op == cot_memptr )
        break;
      if ( p2->op == cot_memref )
      {
        tinfo_t type = remove_pointer(e2->x->type);
        if ( !type.is_union() )
          off += e2->m;
        p = p2;
        continue;
      }
      if ( p2->op == cot_ref )
      { // handle &a.b + N (this expression may appear if the user previously selected
        //                  a wrong field)
        uint64 delta;
        const citem_t *add = body.find_parent_of(p2);
        if ( add->op == cot_cast )
          add = body.find_parent_of(add);
        if ( add->op == cot_add && ((cexpr_t*)add)->y->get_const_value(&delta) )
        {
          int objsize = ((cexpr_t*)add)->type.get_ptrarr_objsize();
          uval_t nbytes = uval_t(delta * objsize);
          off += nbytes;
          // break
        }
      }
      // we could use helpers like WORD/BYTE/... to calculate a more precise offset
      // if ( p2->op == cot_call && (e2->exflags & EXFL_LVALUE) != 0 )
      break;
    }

    // we'll need the operand's address to apply the selected UDT
    ea_t ea = vu.item.e->ea;
    // the item itself may be unaddressable.
    // TODO: find its addressable parent.
    if ( ea == BADADDR )
    {
      warning("Sorry, the current item is not addressable");
      return 0;
    }

    // prepare the text representation for the item,
    // use the neighborhoods of cursor
    qstring line;
    tag_remove(&line, get_custom_viewer_curline(vu.ct, false));
    size_t line_len = line.length();
    size_t x = qmax(0, vu.cpos.x - 10);
    size_t l = qmin(10, line_len - vu.cpos.x) + 10;   //-V658 A value is being subtracted from the unsigned variable
    qstring text(&line[x], l);

    ui_stroff_ops_t ops;
    ui_stroff_op_t &op = ops.push_back();
    op.offset = off;
    op.text = text;

    struct set_union_sel_t : public ui_stroff_applicator_t
    {
      vdui_t &vu;
      ea_t ea;

      set_union_sel_t(vdui_t &_vu, ea_t _ea) : vu(_vu), ea(_ea) {}

      virtual bool idaapi apply(
        size_t /*opnum*/,
        const intvec_t &path,
        const tinfo_t & /*top_tif*/,
        const char * /*spath*/) override
      { // save the user selection
        if ( path.empty() )
          return false;
        vu.cfunc->set_user_union_selection(ea, path);
        vu.cfunc->save_user_unions();
        return true;
      }
    };
    set_union_sel_t su(vu, ea);
    int res = select_udt_by_offset(nullptr, ops, su);
    if ( res != 0 )
    { // regenerate ctree
      try
      {
        vu.cfunc->build_c_tree();      // update ctree
      }
      catch ( const vd_failure_t & )
      {
        // if failed to rebuild the c tree, still generate new text
        // in order to get rid of old text that does not correspond to the ctree
        // (in fact we do not have the ctree anymore)
        vu.refresh_ctext();
        throw;
      }
      vu.refresh_ctext();
    }
    return res;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  { // decompiler view
    return ctx->widget_type == BWN_PSEUDOCODE
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};
static func_stroff_t func_stroff_ah;

//-------------------------------------------------------------------------
struct vds17_t : public plugmod_t
{
  vds17_t();
  virtual bool idaapi run(size_t) override;
};

//-------------------------------------------------------------------------
vds17_t::vds17_t()
{
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      get_hexrays_version(),
      PLUGIN.wanted_name);
  register_action(ACTION_DESC_LITERAL_PLUGMOD(
                          ACTION_NAME,
                          "Structure offsets",
                          &func_stroff_ah,
                          this,
                          "Shift-T",
                          nullptr,
                          -1));
}

//--------------------------------------------------------------------------
bool idaapi vds17_t::run(size_t)
{
  warning("The '%s' plugin is fully automatic", PLUGIN.wanted_name);
  return false;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return init_hexrays_plugin() ? new vds17_t : nullptr;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample17 plugin for Hex-Rays decompiler";

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
  "Structure offsets",  // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
