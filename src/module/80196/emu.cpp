/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//----------------------------------------------------------------------
void i196_t::handle_operand(const insn_t &insn, const op_t &x, int isload)
{
  switch ( x.type )
  {
    case o_imm:
      set_immd(insn.ea);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, OOF_SIGNED);
      break;
    case o_indexed:                                 // addr[value]
      set_immd(insn.ea);
      if ( x.value == 0 && !is_defarg(get_flags(insn.ea), x.n) )
        op_plain_offset(insn.ea, x.n, to_ea(insn.cs, 0));
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )              // xref to addr
      {
        insn_t tmp = insn;
        tmp.ops[x.n].value = x.addr;
        tmp.add_off_drefs(tmp.ops[x.n], x.value ? dr_O : isload ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR);
      }
      if ( x.value != 0 )                           // xref to value
      {                                             // no references to ZERO_REG
        ea_t ea = to_ea(insn.cs, x.value);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
      }
      break;
    case o_indirect:
    case o_indirect_inc:
    case o_mem:
      {
        ea_t dea = to_ea(insn.cs, x.addr);
        insn.create_op_data(dea, x);
        insn.add_dref(dea, x.offb, isload ? dr_R : dr_W);
        if ( !isload && (x.addr == 0x14 || x.addr == 0x15) )
        {
          sel_t wsrval = BADSEL;
          if ( insn.Op2.type == o_imm )
            wsrval = sel_t(insn.Op2.value);
          split_sreg_range(insn.ea, x.addr == 0x14 ? WSR : WSR1, wsrval, SR_auto);
        }
      }
      break;

    case o_near:
      ea_t ea = to_ea(insn.cs, x.addr);
      int iscall = has_insn_feature(insn.itype, CF_CALL);
      insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
      if ( flow && iscall )
        flow = func_does_return(ea);
  }
}

//----------------------------------------------------------------------

int i196_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, 1);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, 1);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, 1);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, 0);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, 0);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, 0);

  switch ( insn.itype )
  {
    case I196_popa:
      split_sreg_range(insn.ea, WSR,  BADSEL, SR_auto);
      split_sreg_range(insn.ea, WSR1, BADSEL, SR_auto);
      break;
  }

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}
