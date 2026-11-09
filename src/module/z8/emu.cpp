/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"

//----------------------------------------------------------------------
// Calculate the target data address
ea_t z8_t::map_addr(const insn_t &insn, asize_t off, int opnum, bool isdata) const
{
  if ( isdata )
  {
    if ( is_off(get_flags(insn.ea), opnum) )
      return get_offbase(insn.ea, opnum) >> 4;
    return intmem + off;
  }
  return map_code_ea(insn, off, opnum);
}

//----------------------------------------------------------------------
void z8_t::handle_operand(const insn_t &insn, const op_t &x, bool isload)
{
  switch ( x.type )
  {
    case o_displ:
    case o_imm:
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
      {
        int outf = x.type != o_imm ? OOF_ADDR|OOFW_16 : 0;
        insn.add_off_drefs(x, dr_O, outf|OOF_SIGNED);
      }
      break;

    case o_mem:
    case o_ind_mem:
    case o_reg:
    case o_ind_reg:
      {
        ea_t dea;
        if ( x.type == o_mem || x.type == o_ind_mem )
        {
          dea = map_addr(insn, x.addr, x.n, true);
        }
        else
        {
          if ( x.reg >= rRR0 )
            dea = map_addr(insn, x.reg - rRR0, x.n, true);
          else
            dea = map_addr(insn, x.reg - rR0, x.n, true);
        }
        insn.create_op_data(dea, x);
        insn.add_dref(dea, x.offb, isload ? dr_R : dr_W);
        if ( !has_user_name(get_flags(dea)) && dea > intmem )
        {
          char buf[10];
          int num = dea - intmem;
          if ( num < 0x100 )
          {
            qsnprintf(buf, sizeof(buf), "R%d", num);
          }
          else if ( num < 0x1000 )
          {
            qsnprintf(buf, sizeof(buf), "ERF_%X_%d", num >> 8, num & 0xFF);
          }
          else
          {
            int reg_no     = ((num >> 4) & 0xF0) + (num & 0xF);
            int subbank_no = ((num >> 4) & 0xF) + 1;
            qsnprintf(buf, sizeof(buf), "R%d_%X", reg_no, subbank_no);
          }
          set_name(dea, buf, SN_NOCHECK|SN_NOWARN|SN_NODUMMY);
        }
      }
      break;

    case o_near:
      {
        ea_t ea = map_code_ea(insn, x);
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
          flow = func_does_return(ea);
      }
      break;

  }
}

//----------------------------------------------------------------------
int z8_t::z8_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, false);

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  if ( insn.itype == Z8_srp // Set register pointer
    || (insn.itype == Z8_pop && insn.Op1.type == o_mem && insn.Op1.addr == 0xFD) ) // popping RP
  {
    // set the RP value
    sel_t val = insn.itype == Z8_srp ? (insn.Op1.value & 0xFF) : BADSEL;
    split_sreg_range(insn.ea + insn.size, rRp, val, SR_auto, true);
  }
  return 1;
}
