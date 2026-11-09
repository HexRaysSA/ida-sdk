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
        ea_t ref = find_first_insn_in_packet(ea);
        insn.add_cref(ref, x.offb, fl_JN);
      }
      break;
    default:
badTouch:
      INTERR(10380);
  }
}

//----------------------------------------------------------------------
ea_t find_first_insn_in_packet(ea_t ea)
{
  if ( !is_spec_ea(ea) )
  {
    while ( (ea & 0x1F) != 0 )
    {
      ea_t ea2 = prev_not_tail(ea);
      if ( ea2 == BADADDR
        || !is_code(get_flags(ea2))
        || (get_dword(ea2) & BIT0) == 0 )
      {
        break;
      }
      ea = ea2;
    }
  }
  return ea;
}

//----------------------------------------------------------------------
inline bool is_tms6_nop(uint32 code)
{
  return (code & 0x21FFE) == 0;
}

//----------------------------------------------------------------------
inline bool is_tms6_bnop(uint32 code)
{
  return (code & 0x00001FFC) == 0x00000120      // Branch Using a Displacement With NOP
      || (code & 0x0F830FFE) == 0x00800362;     // Branch Using a Register With NOP
}

//----------------------------------------------------------------------
static int get_delay(uint32 code)
{
  if ( is_tms6_nop(code) )                        // NOP
    return int((code >> 13) & 0xF) + 1;
  if ( is_tms6_bnop(code) )                       // BNOP
    return int((code >> 13) & 0x7);
  return 1;
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
  void test(ea_t ea, uint32 code);
};

//----------------------------------------------------------------------
inline ushort get_mvk_op(uint32 code) { return ushort(code >> 7); }

void call_info_t::test(ea_t ea, uint32 code)
{
  if ( (code & 0xF000007C) == 0x28 && mvk == BADADDR )
  { // unconditional MVK.S
    int mvk_reg = int(code >> 23) & 0x1F;
    if ( code & BIT1 )
      mvk_reg += rB0;
    if ( (reg == -1 || reg == mvk_reg) && ushort(next) == get_mvk_op(code) )
    {
      reg  = mvk_reg;
      mvk  = ea;
    }
  }
  else if ( (code & 0xF000007C) == 0x68 && mvkh == BADADDR )
  { // unconditional MVKH.S
    int mvk_reg = int(code >> 23) & 0x1F;
    if ( code & BIT1 )
      mvk_reg += rB0;
    if ( (reg == -1 || reg == mvk_reg) && ushort(next>>16) == get_mvk_op(code) )
    {
      reg  = mvk_reg;
      mvkh = ea;
    }
  }
}

//----------------------------------------------------------------------
static int calc_packet_delay(ea_t ea, call_info_t *ci)
{
  int delay = 1;
  while ( true )
  {
    uint32 code = get_dword(ea);
    int d2 = get_delay(code);
    if ( d2 > delay )
      delay = d2;
    ci->test(ea, code);
    if ( (code & BIT0) == 0 )
      break;
    ea += 4;
    if ( !is_code(get_flags(ea)) )
      break;
  }
  return delay;
}

//----------------------------------------------------------------------
static ea_t find_prev_packet(ea_t ea)
{
  ea_t res = BADADDR;
  while ( 1 )
  {
    ea_t ea2 = prev_not_tail(res != BADADDR ? res : ea);
    if ( ea2 == BADADDR )
      break;
    if ( !is_code(get_flags(ea2)) )
      break;
    res = ea2;
    if ( (get_dword(ea2) & BIT0) == 0 )
      break;
  }
  return res;
}

//----------------------------------------------------------------------
static ea_t get_branch_ea(ea_t ea)
{
  while ( 1 )
  {
    uint32 code = get_dword(ea);
    if ( (code >> 28) == cAL )
    {
      switch ( (code >> 2) & 0x1F )
      {
        case 0x04:                      // bcond()
          return ea;
        case 0x08:                      // S unit
        case 0x18:
          {
            int opcode = int(code >> 6) & 0x3F;
            switch ( opcode )
            {
              case 0:           // bdec/bpos
              case 3:           // b irp
              case 4:           // bnop
              case 13:          // b
                return ea;
            }
          }
          break;
      }
    }
    if ( (code & BIT0) == 0 )
      break;
    ea += 4;
    if ( !is_code(get_flags(ea)) )
      break;
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
  else if ( (insn.cflags & aux_para) == 0 )           // the last instruction of packet
  {
    // From spru732j.pdf:
    // Although branch instructions take one execute phase, there are five
    // delay slots between the execution of the branch and execution of the
    // target code.

    // We look backwards for five delay slots to check for an unconditionnal
    // branch instruction.

    ea_t ea = find_first_insn_in_packet(insn.ea);
    int delay = 0;
    call_info_t ci(insn.ea+insn.size);
    while ( 1 )
    {
      // If there are any crefs to this address, we cannot guarantee that
      // the branch instruction really got executed.
      if ( has_xref(get_flags(ea)) )
        break;

      // Increment delay count for this packet.
      delay += calc_packet_delay(ea, &ci);
      if ( delay > 5 )
        break;

      // Unless we have a bnop instruction, seek to the previous packet.
      bool is_bnop = is_tms6_bnop(get_dword(ea));
      if ( !is_bnop )
      {
        ea = find_prev_packet(ea);
        if ( ea == BADADDR )
          break;
        ea = find_first_insn_in_packet(ea);
      }

      ea_t brea;
      if ( delay == 5 && (brea=get_branch_ea(ea)) != BADADDR )
      {
        // We seeked to the previous packet and it was a bnop. The check
        // for delay == 5 is no longer correct, since we did not take into
        // account the delays of the bnop instruction itself.
        if ( is_tms6_bnop(get_dword(ea)) && !is_bnop )
          break;

        insn_t brins;
        calc_packet_delay(ea, &ci);      // just to test for MVK/MVKH
        bool iscall = ci.call_is_present();
        decode_insn(&brins, brea);
        tgtinfo_t tgt;
        if ( brins.Op1.type == o_near )
        {
          ea_t target = to_ea(brins.cs, brins.Op1.addr);
          if ( iscall )
          {
            target = find_first_insn_in_packet(target);
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
          if ( !is_off0(get_flags(ci.mvk)) )
            op_offset(ci.mvk, 0, REF_LOW16, ci.next, brins.cs, 0);
          if ( !is_off0(get_flags(ci.mvkh)) )
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
  decode_insn(&insn, ea);
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
