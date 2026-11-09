/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows known value ranges of a register using get_valranges().
 *
 *      Unfortunately this plugin is of limited use because:
 *        - simple cases where a single value is assigned to a register
 *          are automatically handled by the decompiler and the register
 *          is replaced by the value
 *        - too complex cases where the register gets its value from untrackable
 *          sources, it fails
 *        - only value ranges at the basic block start are shown
 */


#include <hexrays.hpp>
#include <frame.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  plugin_ctx_t() {}
  ~plugin_ctx_t()
  {
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//-------------------------------------------------------------------------
// find the first top micro-instruction after EA that uses or defines LIST
static bool find_insn_with_list(
        const mblock_t **blk,
        const minsn_t **ins,
        mba_t *mba,
        ea_t _ea,
        const mlist_t &_list,
        bool _is_dest)
{
  struct ida_local top_visitor_t : public minsn_visitor_t
  {
    const mblock_t *b = nullptr;
    const minsn_t *ins = nullptr;
    ea_t ea;
    const mlist_t &list;
    bool is_dest;
    top_visitor_t(ea_t e, const mlist_t &l, bool d) : ea(e), list(l), is_dest(d) {}
    int idaapi visit_minsn(void) override
    {
      if ( topins->ea == ea )
      {
        // exact match
        b = blk;
        ins = topins;
        return true;
      }
      if ( blk->start <= ea && topins->ea > ea )
      {
        mlist_t defuse = is_dest
                       ? blk->build_def_list(*topins, MUST_ACCESS)
                       : blk->build_use_list(*topins, MUST_ACCESS);
        if ( defuse.has_common(list)
          && (ins == nullptr || topins->ea < ins->ea) )
        {
          // nearest use/def to EA
          b = blk;
          ins = topins;
        }
      }
      return false;
    }
  };
  top_visitor_t tv(_ea, _list, _is_dest);
  mba->for_all_topinsns(tv);
  if ( tv.ins != nullptr )
  {
    *blk = tv.b;
    *ins = tv.ins;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  ea_t ea = get_screen_ea();
  func_t *pfn = get_func(ea);
  if ( pfn == nullptr )
  {
    msg("Please position the cursor within a function\n");
    return true;
  }

  flags64_t F = get_flags(ea);
  if ( !is_code(F) )
  {
    msg("Please position the cursor on an instruction\n\n");
    return true;
  }

  gco_info_t gco;
  if ( !get_current_operand(&gco) )
  {
    msg("Could not find a register or stkvar in the current operand\n");
    return true;
  }

  // generate microcode
  hexrays_failure_t hf;
  mba_ranges_t mbr(pfn);
  mba_t *mba = gen_microcode(mbr, &hf, nullptr, DECOMP_WARNINGS);
  if ( mba == nullptr )
  {
    msg("%a: %s\n", hf.errea, hf.desc().c_str());
    return true;
  }

  // prepare mlist for the current operand
  mlist_t list;
  if ( !gco.append_to_list(&list, mba) )
  {
    msg("Failed to represent %s as microcode list\n", gco.name.c_str());
    delete mba;
    return false;
  }

  // find micro-insn nearest to EA
  const mblock_t *b;
  const minsn_t *ins;
  if ( !find_insn_with_list(&b, &ins, mba, ea, list, gco.is_def()) )
  {
    msg("Could not find %s after %a in the microcode, sorry\n"
        "Probably it has been optimized away\n",
        gco.name.c_str(), ea);
    delete mba;
    return false;
  }

  valrng_t vr;
  int vrflags = VR_AT_START | VR_EXACT;
  if ( b->get_valranges(&vr, gco.cvt_to_ivl(), ins, vrflags) )
  {
    qstring vrstr;
    vr.print(&vrstr);
    msg("Value ranges of %s at %a: %s\n",
        gco.name.c_str(),
        ins->ea,
        vrstr.c_str());
  }
  else
  {
    msg("Cannot find value ranges of %s\n", gco.name.c_str());
  }

  // We must explicitly delete the microcode array
  delete mba;
  return true;
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
static const char comment[] = "Sample15 plugin for Hex-Rays decompiler";

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
  "Find value ranges of the register", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
