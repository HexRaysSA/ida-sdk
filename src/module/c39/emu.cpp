/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

//----------------------------------------------------------------------
// use/change of operands
void c39_t::handle_operand(
        const insn_t &insn,
        const op_t &x,
        bool is_forced,
        bool isload)
{
  ea_t ea = map_code_ea(insn, x);
  switch ( x.type )
  {
    case o_void:
      break;
    // nothing to do here
    case o_reg:
      break;

    case o_imm:
      if ( !isload )
        goto badTouch;
      set_immd(insn.ea);
      if ( !is_forced && is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ea, x.offb, dr_O); // offset!
      break;

  // jump or call
  case o_near:
    if ( has_insn_feature(insn.itype, CF_CALL) )
    {
      // add xref to code
      insn.add_cref(ea, x.offb, fl_CN);
      // is nonreturning function?
      flow = func_does_return(ea);
    }
    else
    {
      insn.add_cref(ea, x.offb, fl_JN);
    }
    break;

  // memory reference
  case o_mem:
    insn.create_op_data(ea, x);
    insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
    // add xref to the target address
    if ( insn.itype == C39_jmp && x.dtype == dt_word && is_loaded(ea) )
    {
      ea_t callee = get_word(ea);
      if ( callee > 32 && is_mapped(callee) ) // is good address?
      {
        add_cref(insn.ea, callee, fl_JN);
        if ( !is_defarg0(get_flags(ea)) )
          op_plain_offset(ea, 0, 0);
      }
    }
    break;

  default:
badTouch:
    warning("%a %s,%d: bad optype %d",
            insn.ea, insn.get_canon_mnem(ph),
            x.n, x.type);
    break;
  }
}

//----------------------------------------------------------------------
int c39_t::C39_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3) handle_operand(insn, insn.Op3, flag3, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP,insn.ea);

  if ( Feature & CF_CHG1) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3) handle_operand(insn, insn.Op3, flag3, false);
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
