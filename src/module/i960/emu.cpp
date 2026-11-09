/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

//----------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea)
{
  return to_ea(insn.cs, ea);
}

//----------------------------------------------------------------------
void i960_t::handle_operand(const insn_t &insn, const op_t &x, bool isload)
{
  ea_t ea;
  dref_t dref;
  if ( is_forced_operand(insn.ea, x.n) )
    return;
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
      break;

    case o_imm:
      {
        flags64_t F = get_flags(insn.ea);
        QASSERT(10105, isload);
        set_immd(insn.ea);
        if ( op_adds_xrefs(F, x.n) )
          insn.add_off_drefs(x, dr_O, OOFS_IFSIGN|OOFW_IMM);
      }
      break;

    case o_mem:
      ea = calc_mem(insn, x.addr);
      insn.create_op_data(ea, x);
      dref = insn.itype == I960_lda ? dr_O : isload ? dr_R : dr_W;
      insn.add_dref(ea, x.offb, dref);
      break;

    case o_near:
      {
        cref_t ftype = fl_JN;
        ea = calc_mem(insn, x.addr);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          // don't add call xref to next instruction
          if ( ea == insn.ea + insn.size )
            break;
          flow = func_does_return(ea);
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      break;

    case o_displ:
      {
        dref = insn.itype == I960_lda ? dr_O : isload ? dr_R : dr_W;
        set_immd(insn.ea);
        if ( x.reg == IP )
        {
          ea = insn.ea + 8 + x.addr;
          insn.add_dref(ea, x.offb, dref);
        }
        else
        {
          flags64_t F = get_flags(insn.ea);
          if ( op_adds_xrefs(F, x.n) )
            insn.add_off_drefs(x, dref, OOFS_IFSIGN|OOF_SIGNED|OOF_ADDR|OOFW_32);
        }
      }
      break;

    default:
      INTERR(10364);
  }
}


//----------------------------------------------------------------------
int i960_t::i960_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, false);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea,insn.ea+insn.size,fl_F);

//
//      convert "lda imm, reg" to "lda mem, reg"
//

  if ( insn.itype == I960_lda
    && insn.Op1.type == o_imm
    && !is_defarg(get_flags(insn.ea), 0)
    && is_mapped(insn.Op1.value) )
  {
    op_plain_offset(insn.ea, 0, 0);
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t /*ea*/)
{
  return false;
}
