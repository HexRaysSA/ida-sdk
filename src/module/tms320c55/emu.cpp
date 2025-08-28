/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c55.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//------------------------------------------------------------------------
ea_t calc_data_mem(const insn_t &insn, const op_t &op)
{
  ea_t addr = op.addr;
  sel_t dph = 0;
  if ( op.tms_regH == DPH )
  {
    dph = get_sreg(to_ea(insn.cs, insn.ip), DPH);
    if ( dph == BADSEL )
      return BADSEL;
    addr &= 0xFFFF;
  }
  sel_t dp = 0;
  if ( op.tms_regP == DP )
  {
    dp = get_sreg(to_ea(insn.cs, insn.ip), DP);
    if ( dp == BADSEL )
      return BADSEL;
    addr &= 0xFFFF;
  }
  return (((dph & 0x7F) << 16) | (dp + addr)) << 1;
}

//----------------------------------------------------------------------
ea_t calc_io_mem(const insn_t &insn, const op_t &op)
{
  ea_t addr = op.addr;
  sel_t pdp = 0;
  if ( op.tms_regP == PDP )
  {
    pdp = get_sreg(to_ea(insn.cs, insn.ip), PDP);
    if ( pdp == BADSEL )
      return BADSEL;
    addr &= 0x7F;
  }
  ea_t ea = ((pdp & 0x1FF) << 7) | addr;
  return to_ea(insn.cs, ea);
}

//----------------------------------------------------------------------
int tms320c55_t::get_mapped_register(ea_t ea) const
{
  ea = ea >> 1;
  if ( idpflags & TMS320C55_MMR )
  {
    static const int registers[] =
    {
      IER0,   IFR0,  ST0_55, ST1_55, ST3_55, -1,    ST0,   ST1,
      AC0L,   AC0H,  AC0G,   AC1L,   AC1H,   AC1G,  T3,    TRN0,
      AR0,    AR1,   AR2,    AR3,    AR4,    AR5,   AR6,   AR7,
      SP,     BK03,  BRC0,   RSA0L,  REA0L,  PMST,  XPC,   -1,
      T0,     T1,    T2,     T3,     AC2L,   AC2H,  AC2G,  CDP,
      AC3L,   AC3H,  AC3H,   DPH,    -1,     -1,    DP,    PDP,
      BK47,   BKC,   BSA01,  BSA23,  BSA45,  BSA67, BSAC,  -1,
      TRN1,   BRC1,  BRS1,   CSR,    RSA0H,  RSA0L, REA0H, REA0L,
      RSA1H,  RSA1L, REA1H,  REA1L,  RPTC,   IER1,  IFR1,  DBIER0,
      DBIER1, IVPD,  IVPH,   ST2_55, SSP,    SP,    SPH,   CDPH
    };
    if ( ea <= 0x4F )
      return registers[int(ea)];
  }
  return -1;
}

//----------------------------------------------------------------------
static void process_imm(const insn_t &insn, const op_t &x, flags64_t F)
{
  set_immd(insn.ea); // assign contextual menu for conversions
  if ( is_defarg(F, x.n) )
    return; // if already defined by user
  switch ( insn.itype )
  {
    case TMS320C55_rptcc:
    case TMS320C55_rpt:
    case TMS320C55_aadd:
    case TMS320C55_amov:
    case TMS320C55_asub:
    case TMS320C55_mov2:
    case TMS320C55_and3:
    case TMS320C55_or3:
    case TMS320C55_xor2:
    case TMS320C55_xor3:
    case TMS320C55_mpyk2:
    case TMS320C55_mpyk3:
    case TMS320C55_mpykr2:
    case TMS320C55_mpykr3:
    case TMS320C55_mack3:
    case TMS320C55_mack4:
    case TMS320C55_mackr3:
    case TMS320C55_mackr4:
    case TMS320C55_bclr2:
    case TMS320C55_bset2:
    case TMS320C55_rptadd:
    case TMS320C55_rptsub:
    case TMS320C55_add2:
    case TMS320C55_add3:
    case TMS320C55_sub2:
    case TMS320C55_sub3:
    case TMS320C55_and2:
    case TMS320C55_or2:
    case TMS320C55_intr:
    case TMS320C55_trap:
    case TMS320C55_btst:
      op_num(insn.ea, x.n);
  }
}

//----------------------------------------------------------------------
void tms320c55_t::handle_operand(const insn_t &insn, const op_t &op, flags64_t F, bool use)
{
  switch ( op.type )
  {
    case o_cond:
    case o_shift:
    case o_io:
      return;

    case o_reg:
      // analyze immediate values
      if ( op.tms_modifier == TMS_MODIFIER_REG_OFFSET
        || op.tms_modifier == TMS_MODIFIER_P_REG_OFFSET
        || op.tms_modifier == TMS_MODIFIER_REG_SHORT_OFFSET )
      {
        set_immd(insn.ea);
      }
      // analyze local vars
      if ( op.reg == SP && op.tms_modifier == TMS_MODIFIER_REG_OFFSET )
      {
        if ( may_create_stkvars()
          && get_func(insn.ea) != nullptr
          && insn.create_stkvar(op, 2 * op.value, STKVAR_VALID_SIZE) )
        {
          op_stkvar(insn.ea, op.n);
        }
      }
      // DP, DPH and PDP unknown changes
      if ( !use )
      {
        if ( op.reg == DP || op.reg == DPH || op.reg == PDP )
          split_sreg_range(get_item_end(insn.ea), op.reg, BADSEL, SR_auto);
      }
      break;

    case o_relop: // analyze immediate value
      if ( op.tms_relop_type == TMS_RELOP_IMM )
        set_immd(insn.ea);
      break;

    case o_near:
      {
        if ( insn.itype != TMS320C55_rptb && insn.itype != TMS320C55_rptblocal )
        {
          cref_t ftype = fl_JN;
          ea_t ea = calc_code_mem(insn, op.addr);
          if ( has_insn_feature(insn.itype, CF_CALL) )
          {
            if ( !func_does_return(ea) )
              flow = false;
            ftype = fl_CN;
          }
#ifndef TMS320C55_NO_NAME_NO_REF
          insn.add_cref(ea, op.offb, ftype);
#endif
        }

#ifndef TMS320C55_NO_NAME_NO_REF
        else // evaluate RPTB loops as dref
          insn.add_dref(calc_code_mem(insn, op.addr), op.offb, dr_I);
#endif
        break;
      }

    case o_imm:
      QASSERT(10114, use);
      process_imm(insn, op, F);
#ifndef TMS320C55_NO_NAME_NO_REF
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, op.tms_signed ? OOF_SIGNED : 0);
#endif
      break;

    case o_mem:
      {
        ea_t ea = calc_data_mem(insn, op);
        if ( ea != BADADDR )
        {
#ifndef TMS320C55_NO_NAME_NO_REF
          insn.add_dref(ea, op.offb, use ? dr_R : dr_W);
#endif
          insn.create_op_data(ea, op);
          if ( !use )
          {
            int reg = get_mapped_register(ea);
            if ( reg == DP || reg == DPH || reg == PDP )
              split_sreg_range(get_item_end(insn.ea), reg, BADSEL, SR_auto);
          }
        }
      }
      break;

    default:
      warning("interr: emu2 address:%a operand:%d type:%d", insn.ea, op.n, op.type);
  }
}

//----------------------------------------------------------------------
static bool add_stkpnt(const insn_t &insn, sval_t delta)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  return add_auto_stkpnt(pfn, insn.ea+insn.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case TMS320C55_pop1: // pop dst; pop dbl(ACx); pop Smem; pop dbl(Lmem)
      add_stkpnt(insn, (insn.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? 4:2);
      break;
    case TMS320C55_pop2: // pop dst1, dst2; pop dst, Smem
      add_stkpnt(insn, 4);
      break;
    case TMS320C55_psh1: // psh dst; psh dbl(ACx); psh Smem; psh dbl(Lmem)
      add_stkpnt(insn, (insn.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? -4:-2);
      break;
    case TMS320C55_psh2: // psh src1, src2; psh src, Smem
      add_stkpnt(insn, -4);
      break;
    case TMS320C55_popboth:
    case TMS320C55_ret:
      add_stkpnt(insn, 2);
      break;
    case TMS320C55_pshboth:
      add_stkpnt(insn, -2);
      break;
    case TMS320C55_reti:
      add_stkpnt(insn, 6);
      break;
    case TMS320C55_aadd:
      if ( insn.Op2.type == o_reg && insn.Op2.reg == SP && insn.Op1.type == o_imm )
        add_stkpnt(insn, 2 * insn.Op1.value);
      break;
  }
}

//----------------------------------------------------------------------
int tms320c55_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = (feature & CF_STOP) == 0;

  flags64_t F = get_flags(insn.ea);
  if ( feature & CF_USE1 ) handle_operand(insn, insn.Op1, F, true);
  if ( feature & CF_USE2 ) handle_operand(insn, insn.Op2, F, true);
  if ( feature & CF_USE3 ) handle_operand(insn, insn.Op3, F, true);
  if ( feature & CF_USE4 ) handle_operand(insn, insn.Op4, F, true);
  if ( feature & CF_USE5 ) handle_operand(insn, insn.Op5, F, true);
  if ( feature & CF_USE6 ) handle_operand(insn, insn.Op6, F, true);

  if ( feature & CF_CHG1 ) handle_operand(insn, insn.Op1, F, false);
  if ( feature & CF_CHG2 ) handle_operand(insn, insn.Op2, F, false);
  if ( feature & CF_CHG3 ) handle_operand(insn, insn.Op3, F, false);
  if ( feature & CF_CHG4 ) handle_operand(insn, insn.Op4, F, false);
  if ( feature & CF_CHG5 ) handle_operand(insn, insn.Op5, F, false);
  if ( feature & CF_CHG6 ) handle_operand(insn, insn.Op6, F, false);

  // CPL and ARMS status flags changes
  if ( (insn.itype == TMS320C55_bclr1 || insn.itype == TMS320C55_bset1)
    && insn.Op1.type == o_reg
    && (insn.Op1.reg == CPL || insn.Op1.reg == ARMS) )
  {
    int value = insn.itype == TMS320C55_bclr1 ? 0 : 1;
    split_sreg_range(get_item_end(insn.ea), insn.Op1.reg, value, SR_auto);
  }

  // DP, DPH and PDP changes
  if ( insn.itype == TMS320C55_mov2
    && insn.Op2.type == o_reg
    && insn.Op1.type == o_imm )
  {
    ea_t end = insn.ea + insn.size;
    if ( insn.Op2.reg == DP )
      split_sreg_range(end, DP, insn.Op1.value & 0xFFFF, SR_auto);
    else if ( insn.Op2.reg == DPH )
      split_sreg_range(end, DPH, insn.Op1.value & 0x7F, SR_auto);
    else if ( insn.Op2.reg == PDP )
      split_sreg_range(end, PDP, insn.Op1.value & 0x1FF, SR_auto);
  }

  // determine if the next instruction should be executed
  if ( flow && segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(insn.ea);     // recalculate SP register for the next insn
    else
      trace_sp(insn);
  }
  return 1;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      insn_t insn;
      ushort regsize = 0;
      ea_t ea = pfn->start_ea;
      while ( ea < pfn->end_ea ) // check for register pushs
      {
        decode_insn(&insn, ea);
        ea += insn.size;
        if ( insn.itype == TMS320C55_psh1 )
          regsize += (insn.Op1.tms_operator1 & TMS_OPERATOR_DBL) ? 4 : 2;
        else if ( insn.itype == TMS320C55_psh2 )
          regsize += 4;
        else if ( insn.itype == TMS320C55_pshboth )
          regsize += 2;
        else
          break;
      }
      int localsize = 0;
      while ( ea < pfn->end_ea ) // check for frame creation
      {
        if ( decode_insn(&insn, ea) < 1 )
          break;
        ea += insn.size;
        if ( insn.itype == TMS320C55_aadd
          && insn.Op2.type == o_reg
          && insn.Op2.reg == SP
          && insn.Op1.type == o_imm )
        {
          localsize = int(2 * insn.Op1.value);
          break;
        }
      }
      add_frame(pfn, localsize, regsize, 0);
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case TMS320C55_nop:
    case TMS320C55_nop_16:
      break;
    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------

bool idaapi can_have_type(const op_t &op)
{
  switch ( op.type )
  {
    case o_io:
    case o_reg:
    case o_relop:
    case o_imm:
      return true;
  }
  return false;
}
