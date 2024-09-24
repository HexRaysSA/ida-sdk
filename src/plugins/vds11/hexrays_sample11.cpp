/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It installs a custom block optimization rule:
 *
 *        goto L1     =>        goto L2
 *        ...
 *      L1:
 *        goto L2
 *
 *      In other words we fix a goto target if it points to a chain of gotos.
 *      This improves the decompiler output in some cases.
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
struct goto_optimizer_t : public optblock_t
{
  virtual int idaapi func(mblock_t *blk) override
  {
    if ( handle_goto_chain(blk) )
      return 1;
    return 0;
  }
  //lint -e{818} ins could be made const
  bool handle_goto_chain(mblock_t *blk) const
  {
    minsn_t *mgoto = blk->tail;
    if ( mgoto == nullptr || mgoto->opcode != m_goto )
      return false;

    intvec_t visited;
    int t0 = mgoto->l.b;
    int i = t0;
    mba_t *mba = blk->mba;

    // follow the goto chain
    while ( true )
    {
      if ( !visited.add_unique(i) )
        return false; // an endless loop, prefer to keep things as is
      mblock_t *b = mba->get_mblock(i);
      // skip assertion instructions and find first regular instruction
      minsn_t *m2 = getf_reginsn(b->head);
      if ( m2 == nullptr || m2->opcode != m_goto )
        break; // not a goto
      i = m2->l.b;
    }
    if ( i == t0 )
      return false; // not a chain

    // all ok, found a goto chain
    mgoto->l.b = i; // jump directly to the end of the chain

    // fix the successor/predecessor lists
    blk->succset[0] = i;
    mba->get_mblock(i)->predset.add(blk->serial);
    mba->get_mblock(t0)->predset.del(blk->serial);

    // since we changed the control flow graph, invalidate the use/def chains.
    // stricly speaking it is not really necessary in our plugin because
    // we did not move around any microcode operands.
    mba->mark_chains_dirty();

    // it is a good idea to verify microcode after each change
    // however, it may be time consuming, so comment it out eventually
    mba->verify(true);
    return true;
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  goto_optimizer_t goto_optimizer;

  plugin_ctx_t()
  {
    install_optblock_handler(&goto_optimizer);
  }
  ~plugin_ctx_t()
  {
    remove_optblock_handler(&goto_optimizer);
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
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
bool idaapi plugin_ctx_t::run(size_t arg)
{
  if ( arg == 1 )
  {
    remove_optblock_handler(&goto_optimizer);
    msg("%s disabled\n", PLUGIN.wanted_name);
  }
  else if ( arg == 2 )
  {
    install_optblock_handler(&goto_optimizer);
    msg("%s enabled\n", PLUGIN.wanted_name);
  }
  else
  {
    msg("The %d arg is unknown (1 disable, 2 enable)\n", int(arg));
  }
  return false;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample11 plugin for Hex-Rays decompiler";

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
  "Optimize goto chains", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
