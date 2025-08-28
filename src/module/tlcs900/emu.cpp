/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

//----------------------------------------------------------------------
void tlcs900_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  ea_t ea = map_code_ea(insn, x);
  flags64_t F = get_flags(insn.ea);
  switch ( x.type )
  {
    case o_void:
      break;
    case o_phrase:                // 2 registers or indirect addressing
    case o_reg:
      break;

    case o_displ:
      break;

    case o_imm:
      if ( !isload )
        goto badTouch;
      set_immd(insn.ea);
      if ( !is_forced && is_off(F,x.n) )
        insn.add_dref(ea, x.offb, dr_O);    // offset!
      break;

    case o_near:
      if ( has_insn_feature(insn.itype,CF_CALL) )
      {
        insn.add_cref(ea, x.offb, fl_CN);
        flow = func_does_return(ea);
      }
      else
      {
        insn.add_cref(ea, x.offb, fl_JN);
      }
      break;

    case o_mem:
      if ( x.specflag1&URB_LDA )
      {
        if ( x.specflag1&URB_LDA2 )
        {
          if ( is_defarg1(F) )
          {
            set_immd(insn.ea);
            if ( !is_forced && is_off(F,x.n) )
              insn.add_dref(ea, x.offb, dr_O);
            break;
          }
        }
        insn.add_dref(x.addr, x.offb, dr_O);
      }
      else
      {
        insn.create_op_data(ea, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      }
      break;

    default:
badTouch:
      warning("%a %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
int tlcs900_t::T900_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);


  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
