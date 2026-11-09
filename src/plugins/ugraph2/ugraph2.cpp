/*
 *  This is a sample plugin module.
 *  It demonstrates how to modify ida graphs on the fly.
 *  This plugin combines sequential nodes into one.
 *  It is fully automatic.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//-------------------------------------------------------------------------
struct plugin_ctx_t;
DECLARE_LISTENER(idb_listener_t, plugin_ctx_t, ctx);
DECLARE_LISTENER(ui_listener_t, plugin_ctx_t, ctx);

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  typedef std::map<int, rangevec_t> cmbnodes_t;
  cmbnodes_t cmbnodes; // for each combined node: ranges that it represents

  idb_listener_t idb_listener = idb_listener_t(*this);
  ui_listener_t  ui_listener  = ui_listener_t(*this);

  plugin_ctx_t()
  {
    hook_event_listener(HT_IDB, &idb_listener);
    hook_event_listener(HT_UI, &ui_listener);
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;

  void combine_blocks(qflow_chart_t &fc, int n, int m);
};

//--------------------------------------------------------------------------
static void removed_block(intvec_t &seq, int m)
{
  for ( int i=0; i < seq.size(); i++ )
    if ( seq[i] >= m )
      seq[i]--;
}

//--------------------------------------------------------------------------
void plugin_ctx_t::combine_blocks(qflow_chart_t &fc, int n, int m)
{
  // copy successors of m to successors of n
  qbasic_block_t &bn = fc.blocks[n];
  qbasic_block_t &bm = fc.blocks[m];
  bn.succ = bm.succ;

  // remember that n includes m
  rangevec_t &vn = cmbnodes[n];
  if ( vn.empty() )
    vn.push_back(bn);

  cmbnodes_t::iterator pm = cmbnodes.find(m);
  if ( pm == cmbnodes.end() )
  {
    vn.push_back(bm);
  }
  else
  {
    vn.insert(vn.end(), pm->second.begin(), pm->second.end());
    cmbnodes.erase(pm);
  }

  // update the end address
  bn.end_ea = bm.end_ea;

  // correct the predecessors of successors of m to be n:
  for ( int j=0; j < bn.succ.size(); j++ )
  {
    int p = bn.succ[j];
    intvec_t &bp = fc.blocks[p].pred;
    int idx = bp.index(m);
    QASSERT(30172, idx != -1);
    bp[idx] = n;
  }

  // remove block m
  fc.nproper--;
  fc.blocks.erase(fc.blocks.begin()+m);

  // renumber blocks >= m
  for ( int i=0; i < fc.size(); i++ )
  {
    removed_block(fc.blocks[i].pred, m);
    removed_block(fc.blocks[i].succ, m);
  }

  cmbnodes_t ninc; // updated ranges
  for ( cmbnodes_t::iterator p=cmbnodes.begin(); p != cmbnodes.end(); )
  {
    int i = p->first;
    rangevec_t &vec = p->second;
    if ( i >= m )
    {
      ninc[i-1] = vec;
      p = cmbnodes.erase(p);
    }
    else
    {
      ++p;
    }
  }
  cmbnodes.insert(ninc.begin(), ninc.end());
}

//--------------------------------------------------------------------------
static void combine_sequential_nodes(plugin_ctx_t &ctx, qflow_chart_t &fc)
{
  // calculate predecessors
  for ( int n=0; n < fc.size(); n++ )
  {
    int ns = (int)fc.nsucc(n);
    for ( int j=0; j < ns; j++ )
      fc.blocks[fc.succ(n, j)].pred.push_back(n);
  }

  // n -> m, n&m can be combined if
  //    nsucc(n) == 1
  //    npred(m) == 1
  ctx.cmbnodes.clear();
  for ( int n=0; n < fc.size(); n++ )
  {
    if ( fc.nsucc(n) != 1 )
      continue;

    int m = fc.succ(n, 0);
    if ( fc.npred(m) != 1 )
      continue;

    if ( n == m )
      continue;

    // ok, found a sequence, combine the blocks
    ctx.combine_blocks(fc, n, m);
    n--; // check once more
  }
}

//--------------------------------------------------------------------------
static bool generate_combined_node_text(
        plugin_ctx_t &ctx,
        int n,
        text_t &text)
{
  plugin_ctx_t::cmbnodes_t::iterator p = ctx.cmbnodes.find(n);
  if ( p == ctx.cmbnodes.end() )
    return false; // this node has not been combined

  // generate combine node text by generating text for all nodes in it
  rangevec_t &vec = p->second;
  for ( int i=0; i < vec.size(); i++ )
  {
    ea_t ea = vec[i].start_ea;
    gen_disasm_text(text, ea, vec[i].end_ea, false);
  }
  return true;
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::flow_chart_created:
                                // gui has retrieved a function flow chart
                                // in: qflow_chart_t *fc
                                // returns: none
                                // Plugins may modify the flow chart in this callback
      {
        qflow_chart_t *fc = va_arg(va, qflow_chart_t *);
        combine_sequential_nodes(ctx, *fc);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case ui_gen_idanode_text:   // cb: generate disassembly text for a node
                                // qflow_chart_t *fc
                                // int node
                                // text_t *text
                                // Plugins may intercept this event and provide
                                // custom text for an IDA graph node
                                // They may use gen_disasm_text() for that.
                                // Returns: bool text_has_been_generated
      {
        /*qflow_chart_t *fc =*/ va_arg(va, qflow_chart_t *);
        int node = va_arg(va, int);
        text_t *text = va_arg(va, text_t *);
        return generate_combined_node_text(ctx, node, *text);
      }
  }
  return 0;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // unload us if text mode, no graph are there
  if ( !is_idaq() )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  info("This plugin is fully automatic");
  return true;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI          // The plugin can work with multiple idbs in parallel
  | PLUGIN_HIDE,        // Plugin should not appear in the Edit, Plugins menu
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "Combine sequential nodes",
  nullptr,
};
