/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

//----------------------------------------------------------------------
// handle using/changing of operands
void cr16_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_void:
    case o_reg:
      break;

    case o_imm:
      if ( !isload )
        goto badTouch;
      set_immd(insn.ea);
      // no break
    case o_displ:
      if ( !is_forced && op_adds_xrefs(get_flags(insn.ea), x.n) )
      {
        int outf = (x.type == o_displ ? OOF_ADDR : 0)
                 | OOF_SIGNED
                 | (x.dtype == dt_word ? OOFW_16 : OOFW_8);
        dref_t dt = x.type == o_imm ? dr_O : isload ? dr_R : dr_W;
        ea = insn.add_off_drefs(x, dt, outf);
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
      }
      break;

    // jump or call
    case o_near:
      ea = map_code_ea(insn, x);
      if ( has_insn_feature(insn.itype, CF_CALL) )
      {
        // add cross-reference
        insn.add_cref(ea, x.offb, fl_CN);
        // doesn't return?
        flow = func_does_return(ea);
      }
      else
      {
        insn.add_cref(ea, x.offb, fl_JN);
      }
      break;

    // memory reference
    case o_mem:
      ea = map_data_ea(insn, x);
      insn.create_op_data(ea, x);
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      break;

    // other - report error
    default:
    badTouch:
      warning("%a %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
// emulator
int cr16_t::CR16_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  // get operand types
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);

  flow = ((Feature & CF_STOP) == 0);

  // handle reads
  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, flag2, true);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  // handle writes
  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, flag2, false);
  // if not stopping, add flow xref
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}
