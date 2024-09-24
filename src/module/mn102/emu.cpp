/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "pan.hpp"

//----------------------------------------------------------------------
// handle use/change of operands
void mn102_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  ea_t ea = map_code_ea(insn, x);
  switch ( x.type )
  {
    // unused
    case o_void:
      break;
    // nothing to do
    case o_reg:
      break;

    // try to handle as offset
    case o_displ: // if not forced and marked as offset
      if ( !is_forced && is_off(get_flags(insn.ea), x.n) )
      {
        // add cross-reference
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      }
      break;

    // immediate operand
    case o_imm:
      // may not be changed
      if ( !isload )
        goto badTouch;
      // set immediate flag
      set_immd(insn.ea);
      if ( !is_forced )
      {
        flags64_t F = get_flags(insn.ea);
        if ( is_off(F, x.n)
          || (x.specflag1 & URB_ADDR) != 0 && !is_defarg(F, x.n) )
        {
          if ( !is_off(F, x.n) )
            op_plain_offset(insn.ea, x.n, 0);
          // it's an offset
          insn.add_dref(ea, x.offb, dr_O);
        }
      }
      break;

    // jump or call
    case o_near:
      // is it a call?
      if ( has_insn_feature(insn.itype,CF_CALL) )
      {
        // add code xref
        insn.add_cref(ea, x.offb, fl_CN);
        // does the function return?
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
      // add cross-reference
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      break;

    // othewrwise - error
    default:
badTouch:
      warning("%a %s,%d: bad optype %d",
                      insn.ea, insn.get_canon_mnem(ph),
                      x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
// emulator
int mn102_t::mn102_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  // get operand types
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  // add cross-references for operands
  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, flag3, true);
  // add jumps to problem queue
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  // handle changed operands
  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, flag3, false);
  // if not stopping, continue with the next instruction
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
