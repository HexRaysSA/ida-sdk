/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

//----------------------------------------------------------------------
void m6502_t::handle_operand(
        const op_t &x,
        bool isload,
        const insn_t &insn,
        bool *flow) const
{
  ea_t ea;
  dref_t xreftype;
  switch ( x.type )
  {
    case o_reg:
      break;
    case o_imm:
      if ( !isload )
        goto badTouch;
      xreftype = dr_O;
      goto MAKE_IMMD;
    case o_displ:
      xreftype = isload ? dr_R : dr_W;
MAKE_IMMD:
      set_immd(insn.ea);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, xreftype, m65_opflags(x));
      break;
    case o_mem:
      ea = map_data_ea(insn, x);
      insn.create_op_data(ea, x);
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      // add xref to the target address
      if ( insn.itype == M65_jmpi && x.dtype == dt_word && is_loaded(ea) )
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
    case o_near:
      {
        ea = map_code_ea(insn, x);
        ea_t segbase = (ea - x.addr) >> 4;
        ea_t thisseg = insn.cs;
        bool iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(
                ea,
                x.offb,
                iscall ? (segbase == thisseg ? fl_CN : fl_CF)
                       : (segbase == thisseg ? fl_JN : fl_JF));
        if ( iscall && *flow )
          *flow = func_does_return(ea);
      }
      break;
    default:
badTouch:
      const char *mnem = insn.get_canon_mnem(ph);
      warning("%a: %s,%d: bad optype %d", insn.ea, mnem, x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
int m6502_t::emu(const insn_t &insn) const
{
  uint32 Feature = insn.get_canon_feature(ph);
  bool flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn.Op1, 1, insn, &flow);
  if ( Feature & CF_USE2 ) handle_operand(insn.Op2, 1, insn, &flow);
  if ( Feature & CF_CHG1 ) handle_operand(insn.Op1, 0, insn, &flow);
  if ( Feature & CF_CHG2 ) handle_operand(insn.Op2, 0, insn, &flow);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}
