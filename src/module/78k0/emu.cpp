/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

//----------------------------------------------------------------------
// usage/change of operands
void nec78k0_t::handle_operand(const op_t &x, bool forced_op, bool isload, const insn_t &insn)
{
  ea_t ea = map_code_ea(insn, x.addr, x.n);
  ea_t ev = map_code_ea(insn, x.value, x.n);
  switch ( x.type )
  {
    // unused!
    case o_void:
      break;

    case o_reg:
      if ( forced_op )
        break;
      if ( is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ev, x.n, dr_O);
      break;

    case o_imm:     // immediate can't be changed
      if ( !isload )
        goto badTouch;
      // set immediate flag
      set_immd(insn.ea);
      // if not forced and not offset
      if ( !forced_op && is_off(get_flags(insn.ea), x.n) )
        insn.add_dref(ev, x.offb, dr_O); // it's an offset!
      break;

    case o_mem:
      insn.create_op_data(ea, x);
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      break;


    case o_near:// a call or jump
      if ( has_insn_feature(insn.itype, CF_CALL) )
      {
        // add a code xref
        insn.add_cref(ea, x.offb, fl_CN);
        flow = func_does_return(ea);
      }
      else
      {
        insn.add_cref(ea, x.offb, fl_JN);
      }
      break;

    case o_bit:
      switch ( x.FormOut )
      {
        case FORM_OUT_S_ADDR:
        case FORM_OUT_SFR:
          insn.create_op_data(ea, x);
          insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
          break;
      }
      break;
    // other - show a warning
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
int nec78k0_t::N78K_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  // get operand types
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);

  flow = (Feature & CF_STOP) == 0;

  // handle xrefs for the two operands
  if ( Feature & CF_USE1 )
    handle_operand(insn.Op1, flag1, 1, insn);
  if ( Feature & CF_USE2 )
    handle_operand(insn.Op2, flag2, 1, insn);
  // add xref to the queue
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);
  // handle changing operands
  if ( Feature & CF_CHG1 )
    handle_operand(insn.Op1, flag1, 0, insn);
  if ( Feature & CF_CHG2 )
    handle_operand(insn.Op2, flag2, 0, insn);
  // if not stop, continue with the next instruction
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);
  return 1;
}
