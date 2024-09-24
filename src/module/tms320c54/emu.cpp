/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//------------------------------------------------------------------------
ea_t calc_code_mem(const insn_t &insn, ea_t ea, bool is_near)
{
  ea_t rv;
  if ( is_near )
  {
    sel_t xpc = get_sreg(insn.ea, XPC);
    if ( xpc == BADSEL )
      xpc = 0;
    rv = ((xpc & 0x7F) << 16) | (ea & 0xFFFF);
  }
  else
  {
    rv = to_ea(insn.cs, ea);
  }
  return use_mapping(rv);
}

//------------------------------------------------------------------------
ea_t tms320c54_t::calc_data_mem(const insn_t &insn, ea_t ea, bool is_mem) const
{
  ea_t rv;
  if ( is_mem )
  {
    sel_t dp = get_sreg(insn.ea, DP);
    if ( dp == BADSEL )
      return BADSEL;
    rv = ((dp & 0x1FF) << 7) | (ea & 0x7F);
  }
  else
  {
    rv = ea;
  }
  rv += dataseg;
  return use_mapping(rv);
}

//----------------------------------------------------------------------
regnum_t tms320c54_t::get_mapped_register(ea_t ea) const
{
  if ( idpflags & TMS320C54_MMR )
  {
    switch ( ea-dataseg )
    {
      case 0x00: return IMR;
      case 0x01: return IFR;
      case 0x06: return ST0;
      case 0x07: return ST1;
      case 0x08: return AL;
      case 0x09: return AH;
      case 0x0A: return AG;
      case 0x0B: return BL;
      case 0x0C: return BH;
      case 0x0D: return BG;
      case 0x0E: return T;
      case 0x0F: return TRN;
      case 0x10: return AR0;
      case 0x11: return AR1;
      case 0x12: return AR2;
      case 0x13: return AR3;
      case 0x14: return AR4;
      case 0x15: return AR5;
      case 0x16: return AR6;
      case 0x17: return AR7;
      case 0x18: return SP;
      case 0x19: return BK;
      case 0x1A: return BRC;
      case 0x1B: return RSA;
      case 0x1C: return REA;
      case 0x1D: return PMST;
      case 0x1E: return XPC;
      default:   return rnone;
    }
  }
  else
    return rnone;
}

//----------------------------------------------------------------------
static void process_imm(const insn_t &insn, const op_t &x, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, x.n) )
    return; // if already defined by user
  switch ( insn.itype )
  {
    case TMS320C54_cmpm:
    case TMS320C54_bitf:
    case TMS320C54_andm:
    case TMS320C54_orm:
    case TMS320C54_xorm:
    case TMS320C54_addm:
    case TMS320C54_st:
    case TMS320C54_stm:
    case TMS320C54_rpt:
    case TMS320C54_ld3:
    case TMS320C54_mpy2:
    case TMS320C54_rptz:
    case TMS320C54_add3:
    case TMS320C54_sub3:
    case TMS320C54_and3:
    case TMS320C54_or3:
    case TMS320C54_xor3:
    case TMS320C54_mac2:
      op_num(insn.ea, x.n);
  }
}

//----------------------------------------------------------------------
void tms320c54_t::handle_operand(const insn_t &insn, const op_t &x, flags64_t F, bool use)
{
  switch ( x.type )
  {
    case o_bit:
    case o_reg:
    case o_cond8:
    case o_cond2:
      return;

    case o_near:
    case o_far:
      {
        if ( insn.itype != TMS320C54_rptb && insn.itype != TMS320C54_rptbd )
        {
          cref_t ftype = fl_JN;
          ea_t ea = calc_code_mem(insn, x.addr, x.type == o_near);
          if ( has_insn_feature(insn.itype, CF_CALL) )
          {
            if ( !func_does_return(ea) )
              flow = false;
            ftype = fl_CN;
          }
#ifndef TMS320C54_NO_NAME_NO_REF
          if ( x.dtype == dt_byte )
            insn.add_dref(ea, x.offb, dr_R);
          else
            insn.add_cref(ea, x.offb, ftype);
#endif
        }
#ifndef TMS320C54_NO_NAME_NO_REF
        else // evaluate RPTB[D] loops as dref
          insn.add_dref(calc_code_mem(insn, x.addr), x.offb, dr_I);
#endif
      }
      break;

    case o_imm:
      QASSERT(10113, use);
      process_imm(insn, x, F);
#ifndef TMS320C54_NO_NAME_NO_REF
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, x.Signed ? OOF_SIGNED : 0);
#endif
      break;

    case o_mem:
    case o_farmem:
    case o_mmr:
      {
        ea_t ea = calc_data_mem(insn, x.addr, x.type == o_mem);
        if ( ea != BADADDR )
        {
#ifndef TMS320C54_NO_NAME_NO_REF
          insn.add_dref(ea, x.offb, use ? dr_R : dr_W);
#endif
          insn.create_op_data(ea, x);
        }
      }
      break;

    case o_local: // local variables
      if ( may_create_stkvars()
        && (get_func(insn.ea) != nullptr)
        && insn.create_stkvar(x, x.addr, STKVAR_VALID_SIZE) )
      {
        op_stkvar(insn.ea, x.n);
      }
      break;

    case o_displ:
      set_immd(insn.ea);
      break;

    default:
      warning("interr: emu2 address:%a operand:%d type:%d", insn.ea, x.n, x.type);
  }
}

//----------------------------------------------------------------------
// is the previous instruction a delayed jump ?
//
// The following array shows all delayed instructions (xxx[D])
// who are required to always stop.
//
// Z = 1 : delay instruction bit
//
// BRANCH INSTRUCTIONS
//
// TMS320C54_bd,      // Branch Unconditionally                            1111 00Z0 0111 0011 16-bit constant      B[D] pmad
// TMS320C54_baccd,   // Branch to Location Specified by Accumulator       1111 01ZS 1110 0010                      BACC[D] src
// TMS320C54_fbd,     // Far Branch Unconditionally                        1111 10Z0 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FB[D] extpmad
// TMS320C54_fbaccd,  // Far Branch to Location Specified by Accumulator   1111 01ZS 1110 0110                      FBACC[D] src
//
// RETURN INSTRUCTIONS
//
// TMS320C54_fretd,   // Far Return                                        1111 01Z0 1110 0100                      FRET[D]
// TMS320C54_freted,  // Enable Interrupts and Far Return From Interrupt   1111 01Z0 1110 0101                      FRETE[D]
// TMS320C54_retd,    // Return                                            1111 11Z0 0000 0000                      RET[D]
// TMS320C54_reted,   // Enable Interrupts and Return From Interrupt       1111 01Z0 1110 1011                      RETE[D]
// TMS320C54_retfd,   // Enable Interrupts and Fast Return From Interrupt  1111 01Z0 1001 1011                      RETF[D]

static bool delayed_stop(const insn_t &insn, flags64_t F)
{
  if ( !is_flow(F) )
    return false;

  if ( insn.size == 0 || insn.size > 2 )
    return false;

  uint sub = 2 - insn.size; // backward offset to skip the previous 1-word instruction in the case of 2 consecutive 1-word instructions
  if ( insn.ea < (sub + 1) )
    return false;

  // first, we analyze 1-word instructions
  ea_t ea = insn.ea - sub - 1;
  if ( ea < insn.ea && is_code(get_flags(ea)) )
  {
    int code = get_wide_byte(ea); // get the instruction word
    switch ( code )
    {
      case 0xF6E2: // TMS320C54_baccd,   // Branch to Location Specified by Accumulator       1111 01ZS 1110 0010                      BACC[D] src
      case 0xF7E2:
      case 0xF6E6: // TMS320C54_fbaccd,  // Far Branch to Location Specified by Accumulator   1111 01ZS 1110 0110                      FBACC[D] src
      case 0xF7E6:
      case 0xF6E4: // TMS320C54_fretd,   // Far Return                                        1111 01Z0 1110 0100                      FRET[D]
      case 0xF6E5: // TMS320C54_freted,  // Enable Interrupts and Far Return From Interrupt   1111 01Z0 1110 0101                      FRETE[D]
      case 0xFE00: // TMS320C54_retd,    // Return                                            1111 11Z0 0000 0000                      RET[D]
      case 0xF6EB: // TMS320C54_reted,   // Enable Interrupts and Return From Interrupt       1111 01Z0 1110 1011                      RETE[D]
      case 0xF69B: // TMS320C54_retfd,   // Enable Interrupts and Fast Return From Interrupt  1111 01Z0 1001 1011                      RETF[D]
        return true;
    }
  }
  // else, we analyze 2-word instructions
  ea = insn.ea - sub - 2;
  if ( ea < insn.ea && is_code(get_flags(ea)) )
  {
    int code = get_wide_byte(ea); // get the first instruction word
    if ( code == 0xF273              // TMS320C54_bd,      // Branch Unconditionally      1111 00Z0 0111 0011 16-bit constant      B[D] pmad
      || (code & 0xFF80) == 0xFA80 ) // TMS320C54_fbd,     // Far Branch Unconditionally  1111 10Z0 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FB[D] extpmad
    {
      return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------
bool is_basic_block_end(const insn_t &insn)
{
  flags64_t F = get_flags(insn.ea);
  if ( delayed_stop(insn, F) )
    return true;
  return !is_flow(get_flags(insn.ea+insn.size));
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
  // trace SP changes
  switch ( insn.itype )
  {
    case TMS320C54_fret:
    case TMS320C54_fretd:
    case TMS320C54_frete:
    case TMS320C54_freted:
      add_stkpnt(insn, 2);
      break;
    case TMS320C54_ret:
    case TMS320C54_retd:
    case TMS320C54_rete:
    case TMS320C54_reted:
    case TMS320C54_retf:
    case TMS320C54_retfd:
      add_stkpnt(insn, 1);
      break;
    case TMS320C54_frame:
      add_stkpnt(insn, insn.Op1.value);
      break;
    case TMS320C54_popd:
    case TMS320C54_popm:
      add_stkpnt(insn, 1);
      break;
    case TMS320C54_pshd:
    case TMS320C54_pshm:
      add_stkpnt(insn, -1);
      break;
  }
}

//----------------------------------------------------------------------
int tms320c54_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = (feature & CF_STOP) == 0;

  flags64_t F = get_flags(insn.ea);
  if ( feature & CF_USE1 ) handle_operand(insn, insn.Op1, F, true);
  if ( feature & CF_USE2 ) handle_operand(insn, insn.Op2, F, true);
  if ( feature & CF_USE3 ) handle_operand(insn, insn.Op3, F, true);

  if ( feature & CF_CHG1 ) handle_operand(insn, insn.Op1, F, false);
  if ( feature & CF_CHG2 ) handle_operand(insn, insn.Op2, F, false);
  if ( feature & CF_CHG3 ) handle_operand(insn, insn.Op3, F, false);

  // check for CPL changes
  if ( (insn.itype == TMS320C54_rsbx1 || insn.itype == TMS320C54_ssbx1)
    && insn.Op1.type == o_reg && insn.Op1.reg == CPL )
  {
    int value = insn.itype == TMS320C54_rsbx1 ? 0 : 1;
    split_sreg_range(get_item_end(insn.ea), CPL, value, SR_auto);
  }

  // check for DP changes
  if ( insn.itype == TMS320C54_ld2
    && insn.Op1.type == o_imm
    && insn.Op1.dtype == dt_byte
    && insn.Op2.type == o_reg
    && insn.Op2.reg == DP )
  {
    split_sreg_range(get_item_end(insn.ea), DP, insn.Op1.value & 0x1FF, SR_auto);
  }

  // determine if the next instruction should be executed
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow && delayed_stop(insn, F) )
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
bool tms320c54_t::create_func_frame(func_t *pfn) const
{
  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      insn_t insn;
      int regsize = 0;
      ea_t ea = pfn->start_ea;
      while ( ea < pfn->end_ea ) // check for register pushs
      {
        if ( decode_insn(&insn, ea) < 1 )
          break;
        if ( insn.itype != TMS320C54_pshm )
          break;
        if ( insn.Op1.type != o_mem && insn.Op1.type != o_mmr )
          break;
        if ( get_mapped_register(insn.Op1.addr) == rnone )
          break;
        regsize++;
        ea += insn.size;
      }
      int localsize = 0;
      while ( ea < pfn->end_ea ) // check for frame creation
      {
        if ( insn.itype == TMS320C54_frame && insn.Op1.type == o_imm )
        {
          localsize = -(int)insn.Op1.value;
          break;
        }
        ea += insn.size;
        if ( decode_insn(&insn, ea) < 1 )
          break;
      }
      add_frame(pfn, localsize+regsize, 0, 0);
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi tms_get_frame_retsize(const func_t * /*pfn*/)
{
  return 1;     // 1 'byte' for the return address
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case TMS320C54_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

