/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It introduces a new command for the user: invert if-statement
 *      For example, a statement like
 *
 *      if ( cond )
 *      {
 *        statements1;
 *      }
 *      else
 *      {
 *        statements2;
 *      }
 *
 *      will be displayed as
 *
 *      if ( !cond )
 *      {
 *        statements2;
 *      }
 *      else
 *      {
 *        statements1;
 *      }
 *
 *      Please note that the plugin cannot directly modify the current ctree.
 *      If the ctree is recreated, the changes will be lost.
 *      To make them persistent, we need to save information about the inverted
 *      if statements in the database and automatically reapply them
 *      for each new build. This approach makes all modifications
 *      persistent. The user can quit IDA and restart the session:
 *      his changes will be intact.
 *
 */

#include <hexrays.hpp>

// The node to keep inverted-if information.
static const char nodename[] = "$ hexrays inverted-if";

//-------------------------------------------------------------------------
struct vds3_t;
struct invert_if_ah_t : public action_handler_t
{
  vds3_t *plugmod;

  invert_if_ah_t(vds3_t *_plugmod) : plugmod(_plugmod) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;
};

//-------------------------------------------------------------------------
struct vds3_t : public plugmod_t
{
  invert_if_ah_t invert_ah;
  eavec_t inverted_ifs; // Cached copy of inverted if-statement addresses

  vds3_t();
  virtual ~vds3_t();
  virtual bool idaapi run(size_t) override { return false; }

  void do_invert_if(cinsn_t *i); //lint !e818 could be declared as const*
  void add_inverted_if(ea_t ea);
  cinsn_t *find_if_statement(const vdui_t &vu);
  void convert_marked_ifs(cfunc_t *cfunc);
};

#define ACTION_NAME "sample3:invertif"

//--------------------------------------------------------------------------
// This callback handles various hexrays events.
static ssize_t idaapi callback(void *ud, hexrays_event_t event, va_list va)
{
  vds3_t *plugmod = (vds3_t *) ud;
  switch ( event )
  {
    case hxe_populating_popup:
      { // If the current item is an if-statement, then add the menu item
        TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *popup = va_arg(va, TPopupMenu *);
        vdui_t &vu = *va_arg(va, vdui_t *);
        if ( plugmod->find_if_statement(vu) != nullptr )
          attach_action_to_popup(widget, popup, ACTION_NAME);
      }
      break;

    case hxe_maturity:
      if ( !plugmod->inverted_ifs.empty() )
      { // If the ctree is ready, invert marked ifs
        cfunc_t *cfunc = va_arg(va, cfunc_t *);
        ctree_maturity_t new_maturity = va_argi(va, ctree_maturity_t);
        if ( new_maturity == CMAT_FINAL ) // ctree is ready
          plugmod->convert_marked_ifs(cfunc);
      }
      break;

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
//                                 vds3_t
//-------------------------------------------------------------------------
vds3_t::vds3_t()
  : invert_ah(this)
{
  netnode node;
  if ( !node.create(nodename) ) // create failed -> node existed
  {
    size_t n;
    void *blob = node.getblob(nullptr, &n, 0, 'I');
    if ( blob != nullptr )
    {
      inverted_ifs.inject((ea_t *)blob, n / sizeof(ea_t));
      for ( int i=0; i < inverted_ifs.size(); i++ )
        inverted_ifs[i] = node2ea(inverted_ifs[i]);
    }
  }
  install_hexrays_callback(callback, this);
  register_action(ACTION_DESC_LITERAL_PLUGMOD(
                          ACTION_NAME,
                          "Invert then/else",
                          &invert_ah,
                          this,
                          nullptr,
                          nullptr,
                          -1));
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      get_hexrays_version(),
      PLUGIN.wanted_name);
}

//-------------------------------------------------------------------------
vds3_t::~vds3_t()
{
  remove_hexrays_callback(callback, this);
}

//--------------------------------------------------------------------------
// The user has selected to invert the if statement. Update ctree
// and refresh the view.
void vds3_t::do_invert_if(cinsn_t *i) //lint !e818 could be declared as const*
{
  QASSERT(30198, i->op == cit_if);
  cif_t &cif = *i->cif;
  // create an inverted condition and swap it with the if-condition
  cexpr_t *notcond = lnot(new cexpr_t(cif.expr));
  notcond->swap(cif.expr);
  delete notcond;
  // swap if branches
  qswap(cif.ielse, cif.ithen);
}

//--------------------------------------------------------------------------
void vds3_t::add_inverted_if(ea_t ea)
{
  eavec_t::iterator p = inverted_ifs.find(ea);
  if ( p != inverted_ifs.end() ) // already present?
    inverted_ifs.erase(p);       // delete the mark
  else
    inverted_ifs.push_back(ea);  // remember if-statement address
  // immediately save data into the database
  eavec_t copy = inverted_ifs;
  for ( int i=0; i < copy.size(); i++ )
    copy[i] = ea2node(copy[i]);
  netnode node(nodename);
  node.setblob(copy.begin(), copy.size()*sizeof(ea_t), 0, 'I');
}
//--------------------------------------------------------------------------
// Check if the item under the cursor is 'if' or 'else' keyword
// If yes, return pointer to the corresponding ctree item
cinsn_t *vds3_t::find_if_statement(const vdui_t &vu)
{
  // 'if' keyword: straightforward check
  if ( vu.item.is_citem() )
  {
    cinsn_t *i = vu.item.i;
    // we can handle only if-then-else statements, so check that the 'else'
    // clause exists
    if ( i->op == cit_if && i->cif->ielse != nullptr )
      return i;
  }
  // check for 'else' line. The else lines do not correspond
  // to any ctree item. That's why we have to check for them separately.
  // we could extract the corresponding text line but this would be a bad approach
  // a line with single 'else' would not give us enough information to locate
  // the corresponding 'if'. That's why we use the line tail marks.
  // All 'else' line will have the ITP_ELSE mark
  if ( vu.tail.citype == VDI_TAIL && vu.tail.loc.itp == ITP_ELSE )
  {
    // for tail marks, we know only the corresponding ea,
    // not the pointer to if-statement
    // find it by walking the whole ctree
    struct ida_local if_finder_t : public ctree_visitor_t
    {
      ea_t ea;
      cinsn_t *found;
      if_finder_t(ea_t e)
        : ctree_visitor_t(CV_FAST|CV_INSNS), ea(e), found(nullptr) {}
      int idaapi visit_insn(cinsn_t *i) override
      {
        if ( i->op == cit_if && i->ea == ea )
        {
          found = i;
          return 1; // stop enumeration
        }
        return 0;
      }
    };
    if_finder_t iff(vu.tail.loc.ea);
    if ( iff.apply_to(&vu.cfunc->body, nullptr) )
      return iff.found;
  }
  return nullptr;
}

//--------------------------------------------------------------------------
void vds3_t::convert_marked_ifs(cfunc_t *cfunc)
{
  // we walk the ctree and for each if-statement check if has to be inverted
  struct ida_local if_inverter_t : public ctree_visitor_t
  {
    vds3_t *self;
    if_inverter_t(vds3_t *_self)
      : ctree_visitor_t(CV_FAST|CV_INSNS),
        self(_self) {}
    int idaapi visit_insn(cinsn_t *i) override
    {
      if ( i->op == cit_if && self->inverted_ifs.has(i->ea) )
        self->do_invert_if(i);
      return 0; // continue enumeration
    }
  };
  if_inverter_t ifi(this);
  ifi.apply_to(&cfunc->body, nullptr); // go!
}


//-------------------------------------------------------------------------
//                            invert_if_ah_t
//-------------------------------------------------------------------------
int idaapi invert_if_ah_t::activate(action_activation_ctx_t *ctx)
{
  vdui_t &vu = *get_widget_vdui(ctx->widget);
  cinsn_t *i = plugmod->find_if_statement(vu);
  plugmod->add_inverted_if(i->ea);
  // we manually invert this if and recreate text.
  // this is faster than rebuilding ctree from scratch.
  plugmod->do_invert_if(i);
  vu.refresh_ctext();
  return 1;
}

//-------------------------------------------------------------------------
action_state_t idaapi invert_if_ah_t::update(action_update_ctx_t *ctx)
{
  vdui_t *vu = get_widget_vdui(ctx->widget);
  if ( vu == nullptr )
    return AST_DISABLE_FOR_WIDGET;
  return plugmod->find_if_statement(*vu) == nullptr ? AST_DISABLE : AST_ENABLE;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t *idaapi init()
{
  return init_hexrays_plugin() ? new vds3_t : nullptr;
}

//--------------------------------------------------------------------------
static char comment[] = "Sample3 plugin for Hex-Rays decompiler";

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
  "Hex-Rays if-inverter", // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
