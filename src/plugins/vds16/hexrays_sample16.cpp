/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It installs a custom instruction optimization rule:
 *
 *        mov #N, var.4                  mov #N, var.4
 *        xor var@1.1, #M, var@1.1    => mov #NM, var@1.1
 *                                         where NM == (N>>8)^M
 *
 *      We need this rule because the decompiler cannot propagate the second
 *      byte of VAR into the xor instruction.
 *
 *      The XOR opcode can be replaced by any other, we do not rely on it.
 *      Also operand sizes can vary.
 *
 *      This improves the decompiler output for some obfuscated code.
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
// find backwards the instruction that defines anything from LST
static const minsn_t *find_prev_def(
        const mblock_t *blk,
        const mlist_t &lst,
        const minsn_t *ins)
{
  const minsn_t *p = ins;
  while ( (p=p->prev) != nullptr )
  {
    mlist_t def = blk->build_def_list(*p, MAY_ACCESS|FULL_XDSU);
    if ( def.has_common(lst) )
      break;
  }
  return p;
}

//--------------------------------------------------------------------------
struct glbprop_t : public optinsn_t
{
  virtual int idaapi func(mblock_t *blk, minsn_t *ins, int /*optflags*/) override
  {
    if ( ins->r.t != mop_n )
      return 0; // we want a constant as the second operand
    if ( ins->r.size > 2 )
      return 0; // bigger sizes are handled by the decompiler without problems

    // build list of data used by INS
    mlist_t use = blk->build_use_list(*ins, MAY_ACCESS);

    // find the instruction that defines anything from USE
    const minsn_t *di = find_prev_def(blk, use, ins);
    if ( di == nullptr )
      return 0; // not found

    if ( di->opcode != m_mov || di->l.t != mop_n )
      return 0; // must be 'mov #N, ...'

    // compare the destination of DI and the left operand of INS
    mop_t v1 = ins->l;
    const mop_t &v2 = di->d;
    if ( v1.t != v2.t )
      return 0; // operand types are different

    // if operand sizes are the same, hexrays can handle it without our help
    // if the size of INS->L is bigger than the size of DI->D, may not propagate
    // we handle only the case where the size of INS->L is less than the size
    // of DI->D because the hexrays sometimes has problems with it.
    if ( v1.size >= v2.size )
      return 0;

    // this is not very efficient... but acceptable
    int off = 0;
    while ( !v1.equal_mops(v2, EQ_IGNSIZE) )
    {
      if ( ++off >= v2.size )
        return 0;
      if ( !v1.shift_mop(-1) )
        return 0;
    }

    // found a match! shift N in order to propagate the correct part of it
    // we don't truncate the high bits, it will happen in make_number()
    uint64 N = di->l.value(false);
    N >>= (off * 8);

    // store the new value in INS
    ins->l.make_number(N, ins->l.size, di->l.nnn->ea, di->l.nnn->opnum);

    // optimize the instruction, it is highly likely that we will get
    // a much simpler instruction like 'mov'
    ins->optimize_solo();

    return 1; // success, we made one change
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  glbprop_t glbprop;

  plugin_ctx_t()
  {
    install_optinsn_handler(&glbprop);
  }
  ~plugin_ctx_t()
  {
    remove_optinsn_handler(&glbprop);
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  warning("The '%s' plugin is fully automatic", PLUGIN.wanted_name);
  return false;
}

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
static const char comment[] = "Sample16 plugin for Hex-Rays decompiler";

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
  "Propagation helper", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
