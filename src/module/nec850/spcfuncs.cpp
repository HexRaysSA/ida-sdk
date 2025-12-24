#include "necv850.hpp"
#include <name.hpp>

//-------------------------------------------------------------------------
static special_func_t check_name(reglist_t *regs, const qstring &name)
{
  special_func_t res = SPF_NONE;
  if ( name.starts_with("save_") ) // GCC
    res = SPF_SAVE;
  else if ( name.starts_with("return_") ) // GCC
    res = SPF_RETURN;
  if ( res != SPF_NONE )
  {
    const char *p = qstrchr(name.begin(), '_') + 1;
    if ( streq(p, "r2_r29") )
    {
      if ( regs != nullptr )
        regs->add(rR2);
      p += 3;
    }
    if ( streq(p, "r29") )
    {
      if ( regs != nullptr )
        regs->add(rR29);
      return res;
    }
    if ( streq(p, "r31") )
    {
      if ( regs != nullptr )
        regs->add(rLP);
      return res;
    }
    int reglo;
    int reghi;
    int len;
    if ( qsscanf(p, "r%u_r%u%n", &reglo, &reghi, &len) != 2 || p[len] != 0 )
      return SPF_NONE;
    if ( reghi == 29 )
    {
      if ( reglo < 20 || reglo > 28 )
        return SPF_NONE;
      if ( regs != nullptr )
        regs->add_range(reglo, 29 - reglo + 1);
      return res;
    }
    if ( reghi == 31 )
    {
      if ( reglo < 20 || reglo > 29 )
        return SPF_NONE;
      if ( regs != nullptr )
      {
        regs->add_range(reglo, 29 - reglo + 1);
        regs->add(rLP);
      }
      return res;
    }
    return SPF_NONE;
  }
  return SPF_NONE;
}

//-------------------------------------------------------------------------
special_func_t v850_is_special_func(reglist_t *regs, ea_t ea)
{
  qstring name;
  if ( get_name(&name, ea, GN_NOT_DUMMY) > 0
    && cleanup_name(&name, ea, name.c_str(), CN_KEEP_TRAILING_DIGITS) )
  {
    special_func_t res = check_name(regs, name);
    if ( res != SPF_NONE )
      return res;
  }
  // TODO detect save/return thunks
  return SPF_NONE;
}

//-------------------------------------------------------------------------
// jarl save..., r10
// jarl return..., lp
// jr   return...     -- the tail call
special_func_t nec850_t::v850_is_special_func_call(
        reglist_t *regs,
        const insn_t &insn) const
{
  if ( insn.itype != NEC850_JARL && insn.itype != NEC850_JR )
    return SPF_NONE;
  if ( insn.Op1.type != o_near )
    return SPF_NONE;
  // assert: insn.Op2.type == o_reg
  int retreg = insn.itype == NEC850_JARL ? insn.Op2.reg : rLP;
  if ( retreg != rLP && retreg != rR10 )
    return SPF_NONE;
  ea_t target = this->to_ea(insn.cs, insn.Op1.addr);
  special_func_t res = v850_is_special_func(regs, target);
  if ( res == SPF_SAVE && retreg == rR10 )
    return res;
  if ( res == SPF_RETURN && retreg == rLP )
    return res;
  return SPF_NONE;
}

