/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

/*
Operand types:
1) none
2) Register              a, x, y
3) address                $xx           address may be 8 or 16 bits
4) indirect address       ($xx)         address of the cell with the target address
5) immediate             #$xx           constant
6) label                Label           target label of the jump
*/

//----------------------------------------------------------------------
// current byte(s) is immediate data, 1 byte
static void SetImmData(op_t &op, uchar code)
{
  op.type = o_imm;
  // always in the second byte
  op.offb = 1;
  // element size
  op.dtype = dt_byte;
  // value
  op.addr = op.value = code;
  // it can't be an offset!
  op.flags |= OF_NUMBER;   // only number
}

//----------------------------------------------------------------------
// registres are considered  byte-sized
static void SetReg(op_t &op, uchar reg_n)
{
  op.type = o_reg;          // only register
  op.reg  = reg_n;          // register number
  op.dtype = dt_byte;       // size is always 8 bits
}

//----------------------------------------------------------------------
// memory cell
static void SetMemVar(op_t &op, ushort addr)
{
  op.type = o_mem;
  op.addr = op.value = addr;
  op.dtype = dt_word;
}

//----------------------------------------------------------------------
// memory cell with an address
static void SetMemVarI(op_t &op, ushort addr)
{
  op.type = o_mem;
  op.specflag1 |= URR_IND;
  op.addr = op.value = addr;
  op.dtype = dt_word;
}

//----------------------------------------------------------------------
// relative branch
static void SetRelative(const insn_t &insn, op_t &op, signed char disp)
{
  op.type = o_near;
  op.dtype = dt_word;
  op.offb = 1;      // in fact, not always...
  // calculate indirect value
  op.addr = op.value = insn.ip + insn.size + (int32)disp;
}

//----------------------------------------------------------------------
// absolute branch
static void SetAbs(op_t &op, unsigned short disp)
{
  op.type = o_near;
  op.dtype = dt_word;
  op.offb = 1;      // in fact, not always...
  // calculate final value
  op.addr = op.value = disp;
}

//----------------------------------------------------------------------
// analyzer
int idaapi C39_ana(insn_t *_insn)
{
  static const uchar Dt[] =
  {
    C39_brk, C39_ora, C39_mpy, C39_tip,       0, C39_ora, C39_asl, C39_rmb, // 00
    C39_php, C39_ora, C39_asl, C39_jsb, C39_jpi, C39_ora, C39_asl, C39_bbr, // 08

    C39_bpl, C39_ora, C39_mpa, C39_lab,       0, C39_ora, C39_asl, C39_rmb, // 10
    C39_clc, C39_ora, C39_neg, C39_jsb,       0, C39_ora, C39_asl, C39_bbr, // 18

    C39_jsr, C39_and, C39_psh, C39_phw, C39_bit, C39_and, C39_rol, C39_rmb, // 20
    C39_plp, C39_and, C39_rol, C39_jsb, C39_bit, C39_and, C39_rol, C39_bbr, // 28

    C39_bmi, C39_and, C39_pul, C39_plw,       0, C39_and, C39_rol, C39_rmb, // 30
    C39_sec, C39_and, C39_asr, C39_jsb,       0, C39_and, C39_rol, C39_bbr, // 38

    C39_rti, C39_eor, C39_rnd,       0,       0, C39_eor, C39_lsr, C39_rmb, // 40
    C39_pha, C39_eor, C39_lsr, C39_jsb, C39_jmp, C39_eor, C39_lsr, C39_bbr, // 48

    C39_bvc, C39_eor, C39_clw,       0,       0, C39_eor, C39_lsr, C39_rmb, // 50
    C39_cli, C39_eor, C39_phy, C39_jsb,       0, C39_eor, C39_lsr, C39_bbr, // 58

    C39_rts, C39_adc, C39_taw,       0, C39_add, C39_adc, C39_ror, C39_rmb, // 60
    C39_pla, C39_adc, C39_ror, C39_jsb, C39_jmp, C39_adc, C39_ror, C39_bbr, // 68

    C39_bvs, C39_adc, C39_twa,       0, C39_add, C39_adc, C39_ror, C39_rmb, // 70
    C39_sei, C39_adc, C39_ply, C39_jsb, C39_jmp, C39_adc, C39_ror, C39_bbr, // 78

    C39_bra, C39_sta,       0,       0, C39_sty, C39_sta, C39_stx, C39_smb, // 80
    C39_dey, C39_add, C39_txa, C39_nxt, C39_sty, C39_sta, C39_stx, C39_bbs, // 88

    C39_bcc, C39_sta,       0,       0, C39_sty, C39_sta, C39_stx, C39_smb, // 90
    C39_tya, C39_sta, C39_txs, C39_lii,       0, C39_sta,       0, C39_bbs, // 98

    C39_ldy, C39_lda, C39_ldx,       0, C39_ldy, C39_lda, C39_ldx, C39_smb, // A0
    C39_tay, C39_lda, C39_tax, C39_lan, C39_ldy, C39_lda, C39_ldx, C39_bbs, // A8

    C39_bcs, C39_lda, C39_sti,       0, C39_ldy, C39_lda, C39_ldx, C39_smb, // B0
    C39_clv, C39_lda, C39_tsx, C39_ini, C39_ldy, C39_lda, C39_ldx, C39_bbs, // B8


    C39_cpy, C39_cmp, C39_rba,       0, C39_cpy, C39_cmp, C39_dec, C39_smb, // C0
    C39_iny, C39_cmp, C39_dex, C39_phi, C39_cpy, C39_cmp, C39_dec, C39_bbs, // C8

    C39_bne, C39_cmp, C39_sba,       0, C39_exc, C39_cmp, C39_dec, C39_smb, // D0
    C39_cld, C39_cmp, C39_phx, C39_pli,       0, C39_cmp, C39_dec, C39_bbs, // D8

    C39_cpx, C39_sbc, C39_bar,       0, C39_cpx, C39_sbc, C39_inc, C39_smb, // E0
    C39_inx, C39_sbc, C39_nop, C39_lai, C39_cpx, C39_sbc, C39_inc, C39_bbs, // E8

    C39_beq, C39_sbc, C39_bas,       0,       0, C39_sbc, C39_inc, C39_smb, // F0
    C39_sed, C39_sbc, C39_plx, C39_pia,       0, C39_sbc, C39_inc, C39_bbs  // F8
  };

  // get instruction byte
  insn_t &insn = *_insn;
  uchar code = insn.get_next_byte();
  // get instruction code
  insn.itype = Dt[code];
  // analyze instruction type
  switch ( insn.itype )
  {
    // unknown instruction
    case 0:
      return 0;
    // smb/rmb
    case C39_smb:
    case C39_rmb:
      SetImmData(insn.Op1, (code>>4) & 7);
      SetMemVar(insn.Op2, insn.get_next_byte());
      break;
    // bbs/bbr
    case C39_bbs:
    case C39_bbr:
      SetImmData(insn.Op1, (code>>4)&7);
      SetMemVar(insn.Op2, insn.get_next_byte());
      SetRelative(insn, insn.Op3, insn.get_next_byte());
      break;

    // bpl/bmi/bvc/bvs/bra/bcc/bcs/bne/beq
    case C39_beq:
    case C39_bne:
    case C39_bcs:
    case C39_bcc:
    case C39_bra:
    case C39_bvs:
    case C39_bvc:
    case C39_bmi:
    case C39_bpl:
      SetRelative(insn, insn.Op1, insn.get_next_byte());
      break;

    // jsb
    case C39_jsb:
      SetMemVar(insn.Op1,0xFFE0+((code>>4) & 7)*2);
      break;

    // ora, and, eor, adc, sta, lda, cmp, sbc
    case C39_sbc:
    case C39_cmp:
    case C39_lda:
    case C39_sta:
    case C39_adc:
    case C39_eor:
    case C39_and:
    case C39_ora:
      switch ( code&0x1E )
      {
        // 01 - xxx ($b)
        case 0x00:
          SetMemVarI(insn.Op1, insn.get_next_byte());
          break;
        // 05 - xxx $b
        case 0x04:
          SetMemVar(insn.Op1, insn.get_next_byte());
          break;
        // 09 - xxx #$b
        case 0x08:
          SetImmData(insn.Op1, insn.get_next_byte());
          break;
        // 0D - xxx $w
        case 0x0C:
          SetMemVar(insn.Op1, insn.get_next_word());
          break;
        // 11 - xxx ($b), x
        case 0x10:
          SetMemVarI(insn.Op1, insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        // 15 - xxx $b, x
        case 0x14:
          SetMemVar(insn.Op1, insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        // 19 - xxx $w, y
        case 0x18:
          SetMemVar(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2,rY);
          break;
        // 1d - xxx $w, x
        case 0x1C:
          SetMemVar(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2,rX);
          break;
        }
        break;

    // asl, rol, lsr, ror, asr
    case C39_asr:         // this one has a single variant (asr a)
    case C39_ror:
    case C39_lsr:
    case C39_rol:
    case C39_asl:
      switch ( code & 0x1C )
      {
        // 6 - xxx $b
        case 0x04:
          SetMemVar(insn.Op1, insn.get_next_byte());
          break;
        // A - xxx a
        case 0x08:
          SetReg(insn.Op1,rA);
          break;
        // E - xxx $w
        case 0x0C:
          SetMemVar(insn.Op1, insn.get_next_word());
          break;
        // 16 - xxx $b, x
        case 0x14:
          SetMemVar(insn.Op1, insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        // 1E - xxx $w, x
        case 0x1C:
          SetMemVar(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2,rX);
          break;
      }
      break;

    // inc, dec
    case C39_dec:
    case C39_inc:
      switch ( code&0x18 )
      {
        // e6 - xxx $b
        case 0x00:
          SetMemVar(insn.Op1, insn.get_next_byte());
          break;
        // ee - xxx $w
        case 0x08:
          SetMemVar(insn.Op1, insn.get_next_word());
          break;
        // f6 - xxx $b, x
        case 0x10:
          SetMemVar(insn.Op1, insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        // fe - xxx $w, x
        case 0x18:
          SetMemVar(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2,rX);
          break;
      }
      break;

    // rba/sba $b, $w
    case C39_rba:
    case C39_sba:
      SetImmData(insn.Op1, insn.get_next_byte());
      SetMemVar(insn.Op2, insn.get_next_word());
      break;

    // cpy/cpx
    case C39_cpx:
    case C39_cpy:
      switch ( code & 0x1C )
      {
        // a0 - xxx #$b
        case 0x00:
          SetImmData(insn.Op1, insn.get_next_byte());
          break;
        // a4 - xxx $b
        case 0x04:
          SetMemVar(insn.Op1, insn.get_next_byte());
          break;
        // ac - xxx $w
        case 0x0C:
          SetMemVar(insn.Op1, insn.get_next_word());
          break;
        // 14 - xxx $b, x
        case 0x14:
          SetMemVar(insn.Op1, insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        // 1C - xxx $w, x
        case 0x1C:
          SetMemVar(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2,rX);
          break;
      }
      break;

    // lab/neg
    case C39_neg:
    case C39_lab:
      SetReg(insn.Op1,rA);
      break;

    // jpi ($w)
    case C39_jpi:
      SetMemVarI(insn.Op1, insn.get_next_word());
      break;

    // jsr $w
    case C39_jsr:
      SetAbs(insn.Op1, insn.get_next_word());
      break;

    // bar/bas $w, $b ,$rel
    case C39_bar:
    case C39_bas:
      SetMemVar(insn.Op1, insn.get_next_word());
      SetImmData(insn.Op2, insn.get_next_byte());
      SetRelative(insn, insn.Op3, insn.get_next_byte());
      break;

    // bit
    case C39_bit:
      if ( code & 8 )
        SetMemVar(insn.Op1, insn.get_next_word()); // bit $w
      else
        SetMemVar(insn.Op1, insn.get_next_byte()); // bit $b
      break;

    // jmp
    case C39_jmp:
      switch ( code )
      {
        case 0x4C:
          SetAbs(insn.Op1, insn.get_next_word());
          break;
        case 0x6C:
          SetMemVarI(insn.Op1, insn.get_next_word());
          break;
        case 0x7C:
          SetMemVarI(insn.Op1, insn.get_next_word());
          SetReg(insn.Op2, rX);
          break;
      }
      break;

    // sti
    case C39_sti:
      SetImmData(insn.Op1,insn.get_next_byte());
      SetMemVar(insn.Op2,insn.get_next_byte());
      break;

    // exc
    case C39_exc:
      SetMemVar(insn.Op1,insn.get_next_byte());
      SetReg(insn.Op2,rX);
      break;

    // add
    case C39_add:
      switch ( code )
      {
        case 0x64:
          SetMemVar(insn.Op1,insn.get_next_byte());
          break;
        case 0x74:
          SetMemVar(insn.Op1,insn.get_next_byte());
          SetReg(insn.Op2,rX);
          break;
        case 0x89:
          SetImmData(insn.Op1,insn.get_next_byte());
          break;
      }
      break;

    // sty
    case C39_stx:
    case C39_ldx:
    case C39_ldy:
    case C39_sty:
      switch ( code & 0x1C )
      {
        // A0   xxx #$b
        case 0x00:
          SetImmData(insn.Op1,insn.get_next_byte());
          break;
        // A4   xxx $b
        case 0x04:
          SetMemVar(insn.Op1,insn.get_next_byte());
          break;
        // AC   xxx $w
        case 0x0C:
          SetMemVar(insn.Op1,insn.get_next_word());
          break;
        // B4   xxx $b, x
        case 0x14:
          SetMemVar(insn.Op1,insn.get_next_byte());
          SetReg(insn.Op2,
                 insn.itype == C39_sty || insn.itype == C39_ldy ? rX : rY);
          break;
        // BC   xxx $w, x
        case 0x1C:
          SetMemVar(insn.Op1,insn.get_next_word());
          SetReg(insn.Op2,
                 insn.itype == C39_sty || insn.itype == C39_ldy ? rX : rY);
          break;
      }
      break;
  }
  return insn.size;
}
