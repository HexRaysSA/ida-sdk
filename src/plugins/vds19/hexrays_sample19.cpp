/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It installs a custom microcode optimization rule:
 *        x | ~x => -1
 *
 *      To see this plugin in action please use be_ornot_be.idb
 *
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
// recognize "x | ~x" and replace by -1
struct subinsn_optimizer_t : public minsn_visitor_t
{
  int cnt = 0;
  int idaapi visit_minsn() override // for each instruction...
  {
    // THE CORE OF THE PLUGIN IS HERE:
    // check the pattern "x | ~x"
    if ( curins->opcode == m_or
      && curins->r.is_insn(m_bnot)
      && curins->l == curins->r.d->l )
    {
      if ( !curins->l.has_side_effects() ) // avoid destroying side effects
      {
        // pattern matched, convert to "mov -1, ..."
        curins->opcode = m_mov;
        curins->l.make_number(-1, curins->r.size);
        curins->r.erase();
        cnt = cnt + 1; // number of changes we made
      }
    }
    return 0; // continue traversal
  }
};

//--------------------------------------------------------------------------
// a custom instruction optimizer, boilerplate code
struct sample_optimizer_t : public optinsn_t
{
  virtual int idaapi func(
        mblock_t *blk,
        minsn_t *ins,
        int /*optflags*/) override
  {
    subinsn_optimizer_t so;
    ins->for_all_insns(so);
    if ( so.cnt != 0 && blk != nullptr ) // if we modified microcode,
      blk->mba->verify(true);            // run the verifier
    return so.cnt;                       // report the number of changes
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  sample_optimizer_t tiny_optimizer;

  plugin_ctx_t()
  {
    install_optinsn_handler(&tiny_optimizer);
  }
  ~plugin_ctx_t()
  {
    remove_optinsn_handler(&tiny_optimizer);
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t arg)
{
  if ( arg == 1 )
  {
    remove_optinsn_handler(&tiny_optimizer);
    msg("%s disabled\n", PLUGIN.wanted_name);
  }
  else if ( arg == 2 )
  {
    install_optinsn_handler(&tiny_optimizer);
    msg("%s enabled\n", PLUGIN.wanted_name);
  }
  else
  {
    msg("The %d arg is unknown (1 disable, 2 enable)\n", int(arg));
  }
  return false;
}

//--------------------------------------------------------------------------
// a plugin interface, boilerplate code
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
static const char comment[] = "Sample plugin19 for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE           // Plugin should not appear in the Edit, Plugins menu
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Optimize x | ~x",    // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
