/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#include "tms6.hpp"

//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn, int n, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, n) )
    return;
  switch ( insn.itype )
  {
    case TMS6_mvk:
      if ( is_mvk_scst16_form(insn.ea) )
      {
        op_hex(insn.ea, n);
        break;
      }
      // fallthrough for scst5 form
    case TMS6_addk:
    case TMS6_and:              // Rd = Op1 & Op2
    case TMS6_xor:              // Rd = Op1 ^ Op2
    case TMS6_or:               // Rd = Op2 | Op1
    case TMS6_cmpeq:
    case TMS6_cmpgt:
    case TMS6_cmplt:
    case TMS6_mpy:
    case TMS6_mpyi:
    case TMS6_mpyid:
    case TMS6_mpysu:
    case TMS6_sadd:
    case TMS6_ssub:
    case TMS6_sub:
    case TMS6_set:              // Rd = Op1 & ~Op2
    case TMS6_clr:              // Rd = Op1 & ~Op2
    case TMS6_ext:              // Rd = Op1 & ~Op2
    case TMS6_extu:             // Rd = Op1 & ~Op2
      op_dec(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
static void handle_operand(const insn_t &insn, const op_t &x, flags64_t F, bool isload)
{
  switch ( x.type )
  {
    case o_regpair:
    case o_reg:
    case o_phrase:
    case o_spmask:
    case o_stgcyc:
      break;
    case o_imm:
      if ( !isload )
        goto badTouch;
      /* no break */
    case o_displ:
      set_immd_bit(insn, x.n, F);
      if ( op_adds_xrefs(F, x.n) )
      {
        int outf = x.type != o_imm ? OOF_ADDR : 0;
        if ( x.dtype == dt_word )
          outf |= OOF_SIGNED;
        insn.add_off_drefs(x, dr_O, outf);
      }
      break;
    case o_near:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        ea_t ref = get_start_of_exec_packet(ea);
        insn.add_cref(ref, x.offb, fl_JN);
      }
      break;
    default:
badTouch:
      INTERR(10380);
  }
}

//----------------------------------------------------------------------
bool insn_has_pbit(ea_t ea)
{
  uint32 fph = 0;
  if ( get_fph(&fph, get_fph_pos(ea)) )
  {
    if ( fph_is_compact_insn(fph, get_word_pos(ea, false)) )
      return fph_has_pbit(fph, fph_layout_pos(fph, ea));
  }

  return (get_dword(ea) & BIT0) != 0;
}

//----------------------------------------------------------------------
ea_t get_prev(ea_t ea)
{
  ea_t prev_ea = prev_not_tail(ea);
  if ( prev_ea == BADADDR || !is_code(get_flags32(prev_ea)) )
    return BADADDR;

  return prev_ea;
}

//----------------------------------------------------------------------
bool is_first_insn_of_exec_packet(ea_t ea, bool prev)
{
  if ( prev )
  {
    ea = get_prev(ea);
    if ( ea == BADADDR )
      return 1;
  }

  // we can't just simply skip the fph above the insn,
  // because there might be a compact instruction where the p-bit is set
  // example: .text:00000020 5A A3 20 02       ||      MVK     .L2    8, B4
  if ( is_fph(ea, get_dword(ea)) )
  {
    // skip the fph
    ea_t above_fph = prev_not_tail(ea);
    if ( above_fph != BADADDR && is_code(get_flags32(above_fph)) )
    {
      // figure out if its not a compact insn in the fph
      ea_t above_fph_pos = get_fph_pos(above_fph);
      if ( above_fph_pos == ea ) // if its the same fph
        return !insn_has_pbit(above_fph);
    }
  }

  // fixes an issue where the subroutine may end
  // .text:00000D74 000 62 01 86 01   ||      ADDKPC  .S2    __stub_ret, B3, 0
  return !insn_has_pbit(ea);
}

//----------------------------------------------------------------------
// ea = current fetch packet
ea_t get_start_of_exec_packet(ea_t ea)
{
  if ( is_spec_ea(ea) )
    return ea;

  if ( !is_fph(ea, get_dword(ea))
    && is_first_insn_of_exec_packet(ea, true) )
  {
    return ea;
  }

  // execute packets can cross fetch packet bounds
  for ( size_t i = 8; i != 0; --i )
  {
    ea_t prev_ea = prev_not_tail(ea);
    if ( prev_ea == BADADDR || !is_code(get_flags32(prev_ea))
      || (!is_fph(prev_ea, get_dword(prev_ea))
       && is_first_insn_of_exec_packet(prev_ea)) )
    {
      break;
    }

    ea = prev_ea;
  }

  return ea;
}

//----------------------------------------------------------------------
static int get_delay(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case TMS6_nop:
      return insn.Op1.value;
    case TMS6_bnop:
      return insn.Op2.value;
    case TMS6_daddsp:
    case TMS6_dinthspu:
    case TMS6_dintspu:
    case TMS6_dspint:
    case TMS6_dspinth:
    case TMS6_dsubsp:
    case TMS6_fsubdp:
    case TMS6_fsubsp:
      return 2;
    case TMS6_cmatmpy:
    case TMS6_ccmatmpyr1:
    case TMS6_ccmpy32r1:
    case TMS6_ccmatmpy:
    case TMS6_cmatmpyr1:
    case TMS6_cmpysp:
    case TMS6_dccmpy:
    case TMS6_dccmpyr1:
    case TMS6_dcmpy:
    case TMS6_dcmpyr1:
    case TMS6_dmpy2:
    case TMS6_dmpysp:
    case TMS6_dmpysu4:
    case TMS6_dmpyu2:
    case TMS6_dmpyu4:
    case TMS6_dmvd:
    case TMS6_dsmpy2:
    case TMS6_fadddp:
    case TMS6_faddsp:
    case TMS6_fmpydp:
    case TMS6_mpyu2:
    case TMS6_qmpy32:
    case TMS6_qmpysp:
    case TMS6_qsmpy32r1:
      return 3;
    case TMS6_callp:
      return 5;
    default: // DAVG2, DAVGNR2, DAVGNRU4, DAVGU4, DXPND2, DXPND4
      return 1;
  }
}

//----------------------------------------------------------------------
struct call_info_t
{
  ea_t mvk;
  ea_t mvkh;
  uint32 next;
  int reg;
  call_info_t(ea_t n) : mvk(BADADDR), mvkh(BADADDR), next(n), reg(rB3) {}
  bool call_is_present(void) const { return mvk != BADADDR && mvkh != BADADDR; }
  void test(const insn_t &insn);
};

//----------------------------------------------------------------------
inline bool is_s_unit(const insn_t &insn)
{
  return insn.funit == FU_S1 || insn.funit == FU_S2;
}

//----------------------------------------------------------------------
void call_info_t::test(const insn_t &insn)
{
  if ( !is_s_unit(insn) )
    return;

  if ( mvk == BADADDR && insn.itype == TMS6_mvk )
  {
    if ( (reg == -1 || reg == insn.Op2.reg) && ushort(next) == ushort(insn.Op1.value) )
    {
      reg = insn.Op2.reg;
      mvk = insn.ea;
    }
  }

  if ( mvkh == BADADDR && insn.itype == TMS6_mvkh )
  {
    if ( (reg == -1 || reg == insn.Op2.reg) && ushort(next >> 16) == ushort(insn.Op1.value >> 16) )
    {
      reg = insn.Op2.reg;
      mvkh = insn.ea;
    }
  }
}

//----------------------------------------------------------------------
static int calc_packet_delay(ea_t ea, call_info_t *ci)
{
  int delay = 1;

  insn_t insn;
  while ( decode_insn(&insn, ea) > 0 )
  {
    int d2 = get_delay(insn);
    if ( d2 > delay )
      delay = d2;

    ci->test(insn);
    if ( (insn.cflags & aux_para) == 0 )
      break;

    ea += insn.size;
  }

  return delay;
}

//----------------------------------------------------------------------
static ea_t find_prev_packet(ea_t ea)
{
  ea_t res = BADADDR;

  while ( true )
  {
    ea_t ea2 = prev_not_tail(res != BADADDR ? res : ea);
    if ( ea2 == BADADDR )
      break;

    if ( !is_code(get_flags32(ea2)) )
      break;

    res = ea2;

    if ( !insn_has_pbit(ea2) )
      break;
  }

  return res;
}

//----------------------------------------------------------------------
// returns the branch instruction
static ea_t get_branch_ea(ea_t ea)
{
  insn_t insn;
  while ( decode_insn(&insn, ea) > 0 )
  {
    if ( insn.cond == cAL )
    {
      if ( insn.itype == TMS6_b
        || insn.itype == TMS6_bnop // sunit check needed?_
        || insn.itype == TMS6_bdec
        || insn.itype == TMS6_bpos )
      {
        return insn.ea;
      }
    }

    // looks downwards inside the packet until the bottom
    if ( (insn.cflags & aux_para) == 0 )
      break;

    ea += insn.size;
  }

  return BADADDR;
}

//----------------------------------------------------------------------
int tms6_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  flow = ((Feature & CF_STOP) == 0);

  if ( segtype(insn.ea) == SEG_XTRN )
  {
    flow = false;
  }
  else if ( (insn.cflags & aux_para) == 0 && insn.itype != TMS6_fphead ) // the last instruction of packet
  {
    // From spru732j.pdf:
    // Although branch instructions take one execute phase, there are five
    // delay slots between the execution of the branch and execution of the
    // target code.

    // We look backwards for five delay slots to check for an unconditionnal
    // branch instruction.
    ea_t ea = get_start_of_exec_packet(insn.ea);
    int delay = 0;
    call_info_t ci(insn.ea+insn.size);
    while ( true )
    {
      // If there are any crefs to this address, we cannot guarantee that
      // the branch instruction really got executed.
      if ( has_xref(get_flags32(ea)) )
        break;

      // Increment delay count for this packet.
      delay += calc_packet_delay(ea, &ci);
      if ( delay > 5 )
        break;

      insn_t ea_insn;
      if ( decode_insn(&ea_insn, ea) <= 0 )
        break;

      // Unless we have a bnop instruction, seek to the previous packet.
      bool is_bnop = ea_insn.itype == TMS6_bnop;
      if ( !is_bnop )
      {
        ea = find_prev_packet(ea); // returns the bottom of the previous packet
        if ( ea == BADADDR )
          break;
        ea = get_start_of_exec_packet(ea);
      }

      ea_t brea;
      if ( delay == 5 && (brea=get_branch_ea(ea)) != BADADDR )
      {
        if ( decode_insn(&ea_insn, ea) <= 0 )
          break;

        // We seeked to the previous packet and it was a bnop. The check
        // for delay == 5 is no longer correct, since we did not take into
        // account the delays of the bnop instruction itself.
        if ( ea_insn.itype == TMS6_bnop && !is_bnop )
          break;

        insn_t brins;
        calc_packet_delay(ea, &ci);      // just to test for MVK/MVKH
        bool iscall = ci.call_is_present();
        if ( decode_insn(&brins, brea) <= 0 )
          break;

        tgtinfo_t tgt;
        if ( brins.Op1.type == o_near )
        {
          ea_t target = to_ea(brins.cs, brins.Op1.addr);
          if ( iscall )
          {
            target = get_start_of_exec_packet(target);
            brins.add_cref(target, brins.Op1.offb, fl_CN);
            if ( !func_does_return(target) )
              flow = false;
          }
          tgt.type = iscall ? tgtinfo_t::CALL : tgtinfo_t::BRANCH;
          tgt.target = target;
        }
        else
        {
          tgt.type = iscall ? tgtinfo_t::IND_CALL : tgtinfo_t::IND_BRANCH;
        }
        if ( !iscall )
          flow = false;
        tgt.save_to_idb(*this, insn.ea);
        if ( iscall )
        {
          if ( !is_off0(get_flags32(ci.mvk)) )
            op_offset(ci.mvk, 0, REF_LOW16, ci.next, brins.cs, 0);
          if ( !is_off0(get_flags32(ci.mvkh)) )
            op_offset(ci.mvkh, 0, REF_HIGH16, ci.next, brins.cs, 0);
        }
        break;
      }

      // We don't check past one bnop instruction.
      if ( is_bnop )
        break;
    }
  }

  flags64_t F = get_flags(insn.ea);
  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, F, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, F, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, F, true);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, F, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, F, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, F, false);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return 0;

  switch ( insn.itype )
  {
    case TMS6_mv:
      if ( insn.Op1.reg == insn.Op2.reg )
        break;
    default:
      return 0;
    case TMS6_nop:
      break;
  }
  return insn.size;
}
