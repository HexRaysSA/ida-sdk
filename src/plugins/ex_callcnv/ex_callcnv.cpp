/*
 This file implements a sample custom calling convention for the LStrCatN function
 in Delphi. This variadic function purges its stack arguments, which is an unusual
 thing to do. Thus, it does not have a fixed number of purged bytes, it depends
 of the value of EDX.
*/

#include <ida.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <loader.hpp>
#include <typeinf.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>

static int data_id = 0;
static const RegNo REGARGS[] = { R_ax, R_dx };

//--------------------------------------------------------------------------
struct delphi_lstrcatn_t : public custom_callcnv_t
{
  delphi_lstrcatn_t()
    : custom_callcnv_t("__lstrcatn", CCI_VARARG|CCI_PURGE, ABI_STACK_VARARGS)
  {}

  //--------------------------------------------------------------------------
  // Check validity of the function protype
  bool validate_func(const func_type_data_t &fti, qstring *errbuf) const override
  {
    if ( !fti.is_vararg_cc() )
    {
      if ( errbuf != nullptr )
        *errbuf = "must be variadic function";
      return false;
    }
    // The number of stack arguments is passed in EDX.
    // However, to be generic, we allow any number of arguments. The last solid
    // argument will be considered to hold the number of stack arguments.
    if ( fti.empty() )
    {
      if ( errbuf != nullptr )
        *errbuf = "must have integer arguments";
      return false;
    }
    if ( !fti.back().type.is_integral() )
    {
      if ( errbuf != nullptr )
        *errbuf = "the last non-vararg argument must be an integer";
        // it must hold the number of variadic stack arguments
      return false;
    }
    return true;
  }

  //--------------------------------------------------------------------------
  // Calculate the location of the return value
  bool calc_retloc(func_type_data_t *fti) const override
  {
    if ( !fti->rettype.is_void() )
    { // Just use the standard location for the return value
      func_type_data_t fti2;
      fti2.rettype = fti->rettype;
      fti2.set_cc(CM_CC_FASTCALL);
      if ( !calc_retloc(&fti2) )
        return false;
      fti2.retloc.swap(fti->retloc);
    }
    return true;
  }

  //--------------------------------------------------------------------------
  // Calculate the argument locations
  bool calc_arglocs(func_type_data_t *fti) const override
  {
    // Use EAX, EDX, ECX for the first 3 arguments.
    // The rest is allocated on the stack
    int i = 0;
    sval_t off = 0;
    for ( funcarg_t &fa : *fti )
    {
      if ( i < 2 ) // only 2 registers are used!
      {
        fa.argloc.set_reg1(REGARGS[i]);
      }
      else
      {
        fa.argloc.set_stkoff(off);
        off += 4;
      }
      i++;
    }
    fti->stkargs = off;
    return calc_retloc(fti);
  }

  //--------------------------------------------------------------------------
  // Calculate the variadic argument locations
  // Use the same logic
  bool calc_varglocs(
        func_type_data_t *fti,
        regobjs_t * /*regs*/,
        relobj_t * /*stkargs*/,
        int /*nfixed*/) const override
  {
    return calc_arglocs(fti);
  }

  //--------------------------------------------------------------------------
  // What registers are usually used by the calling convention?
  // This information is used by the decompiler for deriving and checking
  // the calling convention.
  bool get_cc_regs(callregs_t *regs) const override
  {
    regs->nregs = qnumber(REGARGS);
    for ( int i=0; i < qnumber(REGARGS); i++ )
      regs->gpregs.push_back(REGARGS[i]);
    return true;
  }

  //--------------------------------------------------------------------------
  int64 find_edx_value(ea_t call_ea, mblock_t *blk) const
  {
    // EDX contains the number of stack arguments. Find its value
    // in the current block
    if ( blk != nullptr && init_hexrays_plugin() )
    {
      mop_t edx(reg2mreg(R_dx), 4);
      minsn_t *i1 = blk->tail;
      minsn_t *mov = blk->find_def(edx, &i1, nullptr, FD_BACKWARD);
      if ( mov != nullptr
        && mov->opcode == m_mov
        && mov->d == edx )
      {
        uint64 n;
        if ( mov->l.is_constant(&n) )
          return n;
      }
    }
    // if we failed to use the decompiler, try to find the register value
    // on the assembler level
    insn_t insn;
    if ( decode_insn(&insn, call_ea) <= 0 )
      return -1;
    uval_t val;
    if ( processor_t::find_reg_value(&val, insn, R_dx) <= 0 )
      return -1;
    return val;
  }

  //--------------------------------------------------------------------------
  ssize_t find_varargs(
        func_type_data_t *fti,
        ea_t call_ea,
        class mblock_t *blk) const override
  {
    int64 nvargs = find_edx_value(call_ea, blk);
    if ( nvargs <= 0 )
      return 0; // failed to find the EDX value
    if ( nvargs >= 128 )
      return 0; // don't accept insane values

    // append the found varargs to the function prototype
    funcarg_t fa;
    fa.type = tinfo_t::get_stock(STI_PCHAR); // char *
    for ( int i=0; i < nvargs; i++ )
      fti->push_back(fa);
    if ( !calc_arglocs(fti) )
      return 0;
    return fti->size();
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  plugin_ctx_t() { set_module_data(&data_id, this); }
  ~plugin_ctx_t() { clr_module_data(data_id); }
  bool idaapi run(size_t) override { return false; }
};

static const delphi_lstrcatn_t delphi_lstrcatn;

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 )
    return nullptr;
  if ( !inf_is_32bit_exactly() )
    return nullptr;
  register_custom_callcnv(delphi_lstrcatn);
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // we want the custom calling convention to be available
                        // immediately
| PLUGIN_HIDE           // don't show in the menu
| PLUGIN_MULTI,         // this plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin. not used.
  nullptr,              // multiline help about the plugin. not used.
  "LStrCatN callcnv",   // the preferred short name of the plugin
  nullptr               // the preferred hotkey to run the plugin
};
