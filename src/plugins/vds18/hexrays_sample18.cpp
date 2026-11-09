/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows how to specify a register value at a desired location.
 *      Such a functionality may be useful when the code to decompile is
 *      obfuscated and uses opaque predicates.
 *
 *      The basic idea of this plugin is very simple: we add assertions like
 *
 *        mov #VALUE, reg
 *
 *      at the specified addresses in the microcode. The decompiler will use this
 *      info during the microcode optimization phase. However, the assertion
 *      will not appear in the output listing.
 *
 *      Usage: use Edit, Plugins, Specify register value.
 */

#include <hexrays.hpp>

struct fixed_regval_info_t
{
  ea_t ea;      // address in the decompiled function
  mreg_t reg;   // register number
  int nbytes;   // size of the register in bytes
  uint64 value; // user-specified value
  fixed_regval_info_t() : ea(BADADDR), reg(mr_none), nbytes(0), value(0) {}
};
DECLARE_TYPE_AS_MOVABLE(fixed_regval_info_t);
typedef qvector<fixed_regval_info_t> fixed_regvals_t;

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  // Info about the user specified register values. Since this plugin exists
  // only for illustration purposes, we keep this info in the memory.
  // Ideally this info should saved into idb.
  fixed_regvals_t user_regvals;

  plugin_ctx_t()
  {
    install_hexrays_callback(hr_callback, this);
  }
  ~plugin_ctx_t()
  {
    remove_hexrays_callback(hr_callback, this);
    term_hexrays_plugin();
  }

  virtual bool idaapi run(size_t) override;
  static ssize_t idaapi hr_callback(
        void *ud,
        hexrays_event_t event,
        va_list va);

  void insert_assertions(mba_t *mba) const;
};

//--------------------------------------------------------------------------
// Code for making debugging easy
// Ensure that the debug helper functions are linked in.
// With them it is possible to print microinstructions like this:
//      insn->dstr()
//      operand->dstr()
// in your favorite debugger. Having these functions greatly
// simplifies debugging.

//lint -e{413} Likely use of null pointer
void refs_for_linker(void)
{
#ifdef _DEBUG
GCC_DIAG_OFF(nonnull)
#define CALL_DSTR(type) ((type*)0)->dstr()
  CALL_DSTR(bitset_t);
  CALL_DSTR(rlist_t);
  CALL_DSTR(ivl_t);
  CALL_DSTR(ivlset_t);
  CALL_DSTR(mlist_t);
  CALL_DSTR(valrng_t);
  CALL_DSTR(chain_t);
  CALL_DSTR(block_chains_t);
  CALL_DSTR(tinfo_t);
  CALL_DSTR(mcases_t);
  CALL_DSTR(lvar_t);
  CALL_DSTR(mop_t);
  CALL_DSTR(minsn_t);
  CALL_DSTR(mcallarg_t);
  CALL_DSTR(vdloc_t);
  dstr((tinfo_t*)0);
  ((mba_t*)0)->dump();
  ((mblock_t*)0)->dump();
#undef CALL_DSTR
GCC_DIAG_OFF(nonnull)
#endif
}
//--------------------------------------------------------------------------
static minsn_t *create_mov(const fixed_regval_info_t &fri)
{
  minsn_t *m = new minsn_t(fri.ea);
  m->opcode = m_mov;
  m->l.make_number(fri.value, fri.nbytes, fri.ea);
  m->d.make_reg(fri.reg, fri.nbytes);
  // declare this 'mov' as an assertion.
  // assertions are deleted before generating ctree and don't
  // appear in the output
  m->iprops |= IPROP_ASSERT;
  // Just for debugging let us print the constructed assertion:
  msg("Created insn: %s\n", m->dstr());
  return m;
}

//--------------------------------------------------------------------------
void plugin_ctx_t::insert_assertions(mba_t *mba) const
{
  func_t *pfn = mba->get_curfunc();
  if ( pfn == nullptr )
    return; // currently only functions are supported, not snippets

  // filter out the addresses outside of the decompiled function
  fixed_regvals_t regvals;
  for ( const auto &rv : user_regvals )
  {
    if ( func_contains(pfn, rv.ea) )
      regvals.push_back(rv);
  }
  if ( regvals.empty() )
    return; // no addresses inside our function

  struct ida_local assertion_inserter_t : public minsn_visitor_t
  {
    fixed_regvals_t &regvals;
    virtual int idaapi visit_minsn(void) override
    {
      for ( size_t i=0; i < regvals.size(); i++ )
      {
        fixed_regval_info_t &fri = regvals[i];
        if ( curins->ea == fri.ea )
        {
          // create "mov #value, reg"
          minsn_t *m = create_mov(fri);
          // insert it before the current instruction
          blk->insert_into_block(m, curins->prev);
          // remove this fixed regval from consideration
          regvals.erase(regvals.begin()+i);
          --i;
        }
      }
      return regvals.empty(); // stop if regvals becomes empty
    }
    assertion_inserter_t(fixed_regvals_t &fr) : regvals(fr) {}
  };
  assertion_inserter_t ai(regvals);

  // find the specified addresses in mba and insert assertions.
  // note: if the address specified by the user has the 'nop' instruction, it
  // won't be translated into mircocode. we may fail to add an assertion because
  // of this. the user should not specify the address of a 'nop' instruction
  // or the logic in visit_minsn() should be improved to handle the situation
  // when the specified address is not present in the microcode.
  mba->for_all_topinsns(ai);

  // This will work if IDA_DUMPDIR envvar points to a directory
  mba->dump();

  // it is a good idea to ensure that we did not break anything
  // call the verifier for that
  mba->verify(true);
}

//--------------------------------------------------------------------------
// This callback intercepts control as soon microcode is generated
// and adds necessary assertions to it. These assertions will inform
// the decompiler about the user-specifed register values.
ssize_t idaapi plugin_ctx_t::hr_callback(
        void *ud,
        hexrays_event_t event,
        va_list va)
{
  plugin_ctx_t &ctx = *(plugin_ctx_t *)ud;
  if ( event == hxe_microcode )
  {
    mba_t *mba = va_arg(va, mba_t *);
    ctx.insert_assertions(mba);
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  // Currently the user can only add new regvals. Since the main goal of
  // this plugin to illustrate how to modify the microcode, deleting or showing
  // fixed regvals is left as an exercise to the reader.
  static const char form[] =
    "Specify known register value\n"
    "<~A~ddress :$::16::>\n"
    "<~R~egister:q::16::>\n"
    "<~V~alue   :L::16::>\n"
    "\n";
  static qstring regname;
  static fixed_regval_info_t fri;
  CASSERT(sizeof(fri.ea) == sizeof(ea_t));
  CASSERT(sizeof(fri.value) == sizeof(uint64));
  while ( ask_form(form, &fri.ea, &regname, &fri.value) )
  {
    reg_info_t ri;
    if ( !parse_reg_name(&ri, regname.c_str()) )
    {
      warning("Sorry, bad register name: %s", regname.c_str());
      continue;
    }
    fri.nbytes = ri.size;
    fri.reg = reg2mreg(ri.reg);
    if ( fri.reg == mr_none )
    {
      warning("Failed to convert to microregister: %s", regname.c_str());
      continue; // apparently this register is not supported by the decompiler
    }
    bool found = false;
    for ( auto &rv : user_regvals )
    {
      if ( rv.ea == fri.ea && rv.reg == fri.reg )
      {
        rv.nbytes = fri.nbytes;
        rv.value = fri.value;
        found = true;
        break;
      }
    }
    if ( !found )
      user_regvals.push_back(fri);
    static const char fmt[] = "Register %s at %a is considered to be equal to 0x%" FMT_64 "X\n";
    info(fmt, regname.c_str(), fri.ea, fri.value);
    msg(fmt, regname.c_str(), fri.ea, fri.value);
    return true;
  }
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
static const char comment[] = "Sample18 plugin for Hex-Rays decompiler";

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
  "Specify register value",  // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
