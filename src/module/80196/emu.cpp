/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//-------------------------------------------------------------------------
static bool is_good_target(ea_t ea)
{
  // exclude the register file
  if ( ea < 0x100 )
    return false;
  // must belong to a segment
  return get_segment_info(nullptr, ea);
}

//-------------------------------------------------------------------------
bool i196_t::is_sane_insn(const insn_t &insn) const
{
  for ( int i = 0; i < 2; ++i )
  {
    ea_t reg;
    const op_t &op = insn.ops[i];
    switch ( op.type )
    {
      case o_indexed:
        reg = op.value;
        break;
      case o_indirect:
      case o_indirect_inc:
      case o_mem:
        reg = op.addr;
        break;
      default:
        continue;
    }
    if ( reg >= 0x100 )
      continue;
    // the unaligned access to registers is suspicious
    if ( op.dtype == dt_word  && (reg & 1) != 0
      || op.dtype == dt_dword && (reg & 3) != 0 )
    {
      return false;
    }
  }
  return true;
}

//-------------------------------------------------------------------------
static void handle_reg_access(const insn_t &insn, int offb, int reg)
{
  insn.add_dref(reg, offb, dr_R);
  if ( is_ext_insn(insn) )
    create_dword(reg, 4);
  else
    create_word(reg, 2);
}

//-------------------------------------------------------------------------
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
      // VALUE is the address of a word register in the Register File which
      // contains a 16-bit base address.
      // ADDR is a 16-bit signed displacement
      set_immd(insn.ea);
      if ( !is_defarg(get_flags(insn.ea), x.n) )
        if ( x.value == 0 || is_good_target(to_ea(insn.cs, x.addr)) )
          op_plain_offset(insn.ea, x.n, to_ea(insn.cs, 0));
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) ) // xref to ADDR (displacement)
      {
        // we assume that the offset points to the base address
        insn_t tmp = insn;
        op_t &xx = tmp.ops[x.n];
        xx.type = o_displ;
        int outf = OOF_ADDR
                 | OOF_SIGNED
                 | (is_ext_insn(insn) ? OOFW_32 : OOFW_16);
        if ( x.value == 0 )
        {
          ea_t target = tmp.add_off_drefs(xx, isload ? dr_R : dr_W, outf);
          if ( target != BADADDR )
            insn.create_op_data(target, x);
        }
        else
        {
          tmp.add_off_drefs(xx, dr_O, outf);
        }
      }
      if ( x.value != 0 )                           // xref to VALUE (register)
        handle_reg_access(insn, x.offb, to_ea(insn.cs, x.value));
      break;

    case o_indirect:
    case o_indirect_inc:
      // we don't know the target address
      handle_reg_access(insn, x.offb, to_ea(insn.cs, x.addr));
      break;

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
