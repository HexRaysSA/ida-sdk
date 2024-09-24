/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

static const uchar nmos[256] =
{
//       0        1        2        3        4        5        6        7        8        9        A        B        C        D        E        F
/* 00 */ M65_brk, M65_ora, M65_null,M65_slo, M65_nop, M65_ora, M65_asl, M65_slo, M65_php, M65_ora, M65_asl, M65_anc, M65_nop, M65_ora, M65_asl, M65_slo, /* 00 */
/* 10 */ M65_bpl, M65_ora, M65_null,M65_slo, M65_nop, M65_ora, M65_asl, M65_slo, M65_clc, M65_ora, M65_nop, M65_slo, M65_nop, M65_ora, M65_asl, M65_slo, /* 10 */
/* 20 */ M65_jsr, M65_and, M65_null,M65_rla, M65_bit, M65_and, M65_rol, M65_rla, M65_plp, M65_and, M65_rol, M65_anc, M65_bit, M65_and, M65_rol, M65_rla, /* 20 */
/* 30 */ M65_bmi, M65_and, M65_null,M65_rla, M65_nop, M65_and, M65_rol, M65_rla, M65_sec, M65_and, M65_nop, M65_rla, M65_nop, M65_and, M65_rol, M65_rla, /* 30 */
/* 40 */ M65_rti, M65_eor, M65_null,M65_sre, M65_nop, M65_eor, M65_lsr, M65_sre, M65_pha, M65_eor, M65_lsr, M65_asr, M65_jmp, M65_eor, M65_lsr, M65_sre, /* 40 */
/* 50 */ M65_bvc, M65_eor, M65_null,M65_sre, M65_nop, M65_eor, M65_lsr, M65_sre, M65_cli, M65_eor, M65_nop, M65_sre, M65_nop, M65_eor, M65_lsr, M65_sre, /* 50 */
/* 60 */ M65_rts, M65_adc, M65_null,M65_rra, M65_nop, M65_adc, M65_ror, M65_rra, M65_pla, M65_adc, M65_ror, M65_arr, M65_jmpi,M65_adc, M65_ror, M65_rra, /* 60 */
/* 70 */ M65_bvs, M65_adc, M65_null,M65_rra, M65_nop, M65_adc, M65_ror, M65_rra, M65_sei, M65_adc, M65_nop, M65_rra, M65_nop, M65_adc, M65_ror, M65_rra, /* 70 */
/* 80 */ M65_nop, M65_sta, M65_nop, M65_sax, M65_sty, M65_sta, M65_stx, M65_sax, M65_dey, M65_nop, M65_txa, M65_ane, M65_sty, M65_sta, M65_stx, M65_sax, /* 80 */
/* 90 */ M65_bcc, M65_sta, M65_null,M65_sha, M65_sty, M65_sta, M65_stx, M65_sax, M65_tya, M65_sta, M65_txs, M65_shs, M65_shy, M65_sta, M65_shx, M65_sha, /* 90 */
/* A0 */ M65_ldy, M65_lda, M65_ldx, M65_lax, M65_ldy, M65_lda, M65_ldx, M65_lax, M65_tay, M65_lda, M65_tax, M65_lxa, M65_ldy, M65_lda, M65_ldx, M65_lax, /* A0 */
/* B0 */ M65_bcs, M65_lda, M65_null,M65_lax, M65_ldy, M65_lda, M65_ldx, M65_lax, M65_clv, M65_lda, M65_tsx, M65_lae, M65_ldy, M65_lda, M65_ldx, M65_lax, /* B0 */
/* C0 */ M65_cpy, M65_cmp, M65_nop, M65_dcp, M65_cpy, M65_cmp, M65_dec, M65_dcp, M65_iny, M65_cmp, M65_dex, M65_sbx, M65_cpy, M65_cmp, M65_dec, M65_dcp, /* C0 */
/* D0 */ M65_bne, M65_cmp, M65_null,M65_dcp, M65_nop, M65_cmp, M65_dec, M65_dcp, M65_cld, M65_cmp, M65_nop, M65_dcp, M65_nop, M65_cmp, M65_dec, M65_dcp, /* D0 */
/* E0 */ M65_cpx, M65_sbc, M65_nop, M65_isb, M65_cpx, M65_sbc, M65_inc, M65_isb, M65_inx, M65_sbc, M65_nop, M65_sbc, M65_cpx, M65_sbc, M65_inc, M65_isb, /* E0 */
/* F0 */ M65_beq, M65_sbc, M65_null,M65_isb, M65_nop, M65_sbc, M65_inc, M65_isb, M65_sed, M65_sbc, M65_nop, M65_isb, M65_nop, M65_sbc, M65_inc, M65_isb  /* F0 */
};

static const uchar cmos[256] =
{
//       0        1        2        3        4        5        6        7        8        9        A        B        C        D        E        F
/* 00 */ M65_brk, M65_ora, M65_null,M65_null,M65_tsb, M65_ora, M65_asl, M65_rmb0,M65_php, M65_ora, M65_asl, M65_null,M65_tsb, M65_ora, M65_asl, M65_bbr0, /* 00 */
/* 10 */ M65_bpl, M65_ora, M65_ora, M65_null,M65_trb, M65_ora, M65_asl, M65_rmb1,M65_clc, M65_ora, M65_inc, M65_null,M65_trb, M65_ora, M65_asl, M65_bbr1, /* 10 */
/* 20 */ M65_jsr, M65_and, M65_null,M65_null,M65_bit, M65_and, M65_rol, M65_rmb2,M65_plp, M65_and, M65_rol, M65_null,M65_bit, M65_and, M65_rol, M65_bbr2, /* 20 */
/* 30 */ M65_bmi, M65_and, M65_and, M65_null,M65_bit, M65_and, M65_rol, M65_rmb3,M65_sec, M65_and, M65_dec, M65_null,M65_bit, M65_and, M65_rol, M65_bbr3, /* 30 */
/* 40 */ M65_rti, M65_eor, M65_null,M65_null,M65_null,M65_eor, M65_lsr, M65_rmb4,M65_pha, M65_eor, M65_lsr, M65_null,M65_jmp, M65_eor, M65_lsr, M65_bbr4, /* 40 */
/* 50 */ M65_bvc, M65_eor, M65_eor, M65_null,M65_null,M65_eor, M65_lsr, M65_rmb5,M65_cli, M65_eor, M65_phy, M65_null,M65_null,M65_eor, M65_lsr, M65_bbr5, /* 50 */
/* 60 */ M65_rts, M65_adc, M65_null,M65_null,M65_stz, M65_adc, M65_ror, M65_rmb6,M65_pla, M65_adc, M65_ror, M65_null,M65_jmpi,M65_adc, M65_ror, M65_bbr6, /* 60 */
/* 70 */ M65_bvs, M65_adc, M65_adc, M65_null,M65_stz, M65_adc, M65_ror, M65_rmb7,M65_sei, M65_adc, M65_ply, M65_null,M65_jmpi,M65_adc, M65_ror, M65_bbr7, /* 70 */
/* 80 */ M65_bra, M65_sta, M65_null,M65_null,M65_sty, M65_sta, M65_stx, M65_smb0,M65_dey, M65_bit, M65_txa, M65_null,M65_sty, M65_sta, M65_stx, M65_bbs0, /* 80 */
/* 90 */ M65_bcc, M65_sta, M65_sta, M65_null,M65_sty, M65_sta, M65_stx, M65_smb1,M65_tya, M65_sta, M65_txs, M65_null,M65_stz, M65_sta, M65_stz, M65_bbs1, /* 90 */
/* A0 */ M65_ldy, M65_lda, M65_ldx, M65_null,M65_ldy, M65_lda, M65_ldx, M65_smb2,M65_tay, M65_lda, M65_tax, M65_null,M65_ldy, M65_lda, M65_ldx, M65_bbs2, /* A0 */
/* B0 */ M65_bcs, M65_lda, M65_lda, M65_null,M65_ldy, M65_lda, M65_ldx, M65_smb3,M65_clv, M65_lda, M65_tsx, M65_null,M65_ldy, M65_lda, M65_ldx, M65_bbs3, /* B0 */
/* C0 */ M65_cpy, M65_cmp, M65_null,M65_null,M65_cpy, M65_cmp, M65_dec, M65_smb4,M65_iny, M65_cmp, M65_dex, M65_wai,M65_cpy, M65_cmp, M65_dec, M65_bbs4, /* C0 */
/* D0 */ M65_bne, M65_cmp, M65_cmp, M65_null,M65_null,M65_cmp, M65_dec, M65_smb5,M65_cld, M65_cmp, M65_phx, M65_stp,M65_null,M65_cmp, M65_dec, M65_bbs5, /* D0 */
/* E0 */ M65_cpx, M65_sbc, M65_null,M65_null,M65_cpx, M65_sbc, M65_inc, M65_smb6,M65_inx, M65_sbc, M65_nop, M65_null,M65_cpx, M65_sbc, M65_inc, M65_bbs6, /* E0 */
/* F0 */ M65_beq, M65_sbc, M65_sbc, M65_null,M65_null,M65_sbc, M65_inc, M65_smb7,M65_sed, M65_sbc, M65_plx, M65_null,M65_null,M65_sbc, M65_inc, M65_bbs7  /* F0 */
//       0        1        2        3        4        5        6        7        8        9        A        B        C        D        E        F
};

//----------------------------------------------------------------------
int m6502_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  insn.Op1.dtype = dt_byte;
  uchar code = insn.get_next_byte();
  insn.itype = (is_cmos ? cmos : nmos)[code];
  if ( insn.itype == M65_null )
    return 0;

  switch ( code & 0x1F )
  {
// +08  PHP     PLP     PHA     PLA     DEY     TAY     INY     INX     Implied
// +18  CLC     SEC     CLI     SEI     TYA     CLV     CLD     SED     Implied
// +1a  NOP*    NOP*    NOP*    NOP*    TXS     TSX     NOP*    NOP*    Implied
// +1a  inc     dec     phy     ply     txs     tsx     phx     ply
    case 0x1A:
    case 0x08:
    case 0x18:
      switch ( insn.itype )
      {
        case M65_inc:
        case M65_dec:
          insn.Op1.type = o_reg;
          insn.Op1.reg = rA;
      }
      break;
// +0a  ASL     ROL     LSR     ROR     TXA     TAX     DEX     NOP     Accu/impl
    case 0x0A:
      switch ( insn.itype )
      {
        case M65_asl:
        case M65_rol:
        case M65_lsr:
        case M65_ror:
          insn.Op1.type = o_reg;
          insn.Op1.reg = rA;
      }
      break;
// +00  BRK     JSR     RTI     RTS     NOP*/bra LDY     CPY     CPX     Impl/immed
// +02   t       t       t       t      NOP*t    LDX     NOP*t   NOP*t     ? /immed
// +09  ORA     AND     EOR     ADC     NOP*     LDA     CMP     SBC     Immediate
// +0b  ANC**   ANC**   ASR**   ARR**   ANE**    LXA**   SBX**   SBC*    Immediate
    case 0x00:
    case 0x02:
    case 0x09:
    case 0x0B:
      switch ( insn.itype )
      {
        case M65_jsr:
          insn.Op1.dtype = dt_code;
          insn.Op1.type = o_near;
          insn.Op1.addr = insn.get_next_word();
          break;
        case M65_brk:
        case M65_rti:
        case M65_rts:
        case M65_wai:

          // no operands
          break;
        case M65_bra:
          goto M65_RELATIVE;
        default:
          insn.Op1.type = o_imm;
          insn.Op1.value = insn.get_next_byte();
          break;
      }
      break;
// +0c NOP*/tsb BIT     JMP     JMP  () STY     LDY     CPY     CPX     Absolute
// +0d  ORA     AND     EOR     ADC     STA     LDA     CMP     SBC     Absolute
// +0e  ASL     ROL     LSR     ROR     STX     LDX     DEC     INC     Absolute
// +0f  SLO*    RLA*    SRE*    RRA*    SAX*    LAX*    DCP*    ISB*    Absolute
// +0f  bbr0    bbr2    bbr4    bbr6    bbs0    bbs2    bbs4    bbs6    Zero page relative
    case 0x0F:
      if ( is_cmos )
        goto ZP_RELATIVE;
    case 0x0C:
    case 0x0D:
    case 0x0E:
M65_ABSOLUTE:
      switch ( insn.itype )
      {
        case M65_jmp:
          insn.Op1.dtype = dt_code;
          insn.Op1.type = o_near;
          break;
        case M65_jmpi:
          insn.Op1.dtype = dt_word;
          insn.indirect = 1;
          /* no break */
        default:
          insn.Op1.type = o_mem;
          break;
      }
      insn.Op1.addr = insn.get_next_word();
      break;
// +1c NOP*/trb NOP*/bit NOP*   NOP*/jmp SHY**/stz LDY     NOP*    NOP*    Absolute, x
// +1d  ORA      AND     EOR     ADC     STA       LDA     CMP     SBC     Absolute, x
// +1e  ASL      ROL     LSR     ROR     SHX**y)   LDX  y) DEC     INC     Absolute, x
// +1f  SLO*     RLA*    SRE*    RRA*    SHA**y)   LAX* y) DCP     ISB     Absolute, x
// +0f  bbr1     bbr3    bbr5    bbr7    bbs1      bbs3    bbs5    bbs7    Zero page relative
    case 0x1F:
      if ( is_cmos )
      {
ZP_RELATIVE:
        insn.Op1.type = o_mem;
        insn.Op1.addr = insn.get_next_byte();
        insn.Op2.dtype = dt_code;
        insn.Op2.type = o_near;
        char x = insn.get_next_byte();
        insn.Op2.addr = insn.ip + insn.size + x;
        break;
      }
      /* fall thru */
    case 0x1C:
    case 0x1D:
    case 0x1E:
      insn.Op1.type = o_displ;
      insn.Op1.phrase = rX;
      switch ( insn.itype )
      {
        case M65_stz:
          if ( code == 0x9E )
            break;
          // no break
        case M65_trb:
          goto M65_ABSOLUTE;
        case M65_shx:
        case M65_sha:
        case M65_ldx:
        case M65_lax:
          insn.Op1.phrase = rY;
          break;
        case M65_jmpi:
          insn.Op1.phrase = riX;
          break;
      }
      insn.Op1.addr = insn.get_next_word();
      break;
// +19  ORA     AND     EOR     ADC     STA     LDA     CMP     SBC     Absolute, y
// +1b  SLO*    RLA*    SRE*    RRA*    SHS**   LAS**   DCP*    ISB*    Absolute, y
    case 0x19:
    case 0x1B:
      if ( insn.itype == M65_stp )
        // no operands
        break;
      insn.Op1.type = o_displ;
      insn.Op1.phrase = rY;
      insn.Op1.addr = insn.get_next_word();
      break;
// +10  BPL     BMI     BVC     BVS     BCC     BCS     BNE     BEQ     Relative
    case 0x10:
M65_RELATIVE:
      insn.Op1.dtype = dt_code;
      insn.Op1.type = o_near;
      {
        char x = insn.get_next_byte();
        insn.Op1.addr = insn.ip + insn.size + x;
      }
      break;
// +01  ORA     AND     EOR     ADC     STA     LDA     CMP     SBC     (indir, x)
// +03  SLO*    RLA*    SRE*    RRA*    SAX*    LAX* y) DCP*    ISB*    (indir, x)
    case 0x01:
    case 0x03:
      insn.Op1.type = o_displ;
      insn.Op1.phrase = uint16((insn.itype == M65_lax) ? riY : riX);
      insn.Op1.addr = insn.get_next_byte();    // what about LAX?
      break;
// +11  ORA     AND     EOR     ADC     STA     LDA     CMP     SBC     (indir), y
// +13  SLO*    RLA*    SRE*    RRA*    SHA**   LAX*    DCP*    ISB*    (indir), y
    case 0x11:
    case 0x13:
      insn.Op1.type = o_displ;
      insn.Op1.phrase = riY;
      insn.Op1.addr = insn.get_next_byte();
      break;
// +04 NOP*/tsb BIT     NOP*   NOP*/stz STY     LDY     CPY     CPX     Zeropage
// +05  ORA     AND     EOR     ADC     STA     LDA     CMP     SBC     Zeropage
// +06  ASL     ROL     LSR     ROR     STX     LDX     DEC     INC     Zeropage
// +07  SLO*    RLA*    SRE*    RRA*    SAX*    LAX*    DCP*    ISB*    Zeropage
// +07  rmb0    rmb2    rmb4    rmb6    smb0    smb2    smb4    smb6    Zeropage
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
ZEROPAGE:
      insn.Op1.type = o_mem;
      insn.Op1.addr = insn.get_next_byte();
      break;
// +14 NOP*/trb NOP*/bit NOP*   NOP*/stz STY     LDY     NOP*    NOP*    Zeropage, x
// +15  ORA     AND      EOR     ADC     STA     LDA     CMP     SBC     Zeropage, x
// +16  ASL     ROL      LSR     ROR     STX  y) LDX  y) DEC     INC     Zeropage, x
// +17  SLO*    RLA*     SRE*    RRA*    SAX* y) LAX* y) DCP     ISB     Zeropage, x
// +17  rmb1    rmb3     rmb5    rmb7    smb1    smb3    smb5    smb7    Zeropage
    case 0x17:
      if ( is_cmos )
        goto ZEROPAGE;
      /* fall thru */
    case 0x14:
    case 0x15:
    case 0x16:
      insn.Op1.type = o_displ;
      insn.Op1.phrase = zX;
      switch ( insn.itype )
      {
        case M65_trb:
          goto ZEROPAGE;
        case M65_stx:
        case M65_sax:
        case M65_ldx:
        case M65_lax:
          insn.Op1.phrase = zY;
          break;
      }
      insn.Op1.addr = insn.get_next_byte();
      break;
// +12  ora     and     eor     adc     sta     lda     cmp     sbc     Zeropage, indirect
    case 0x12:
      insn.indirect = 1;
      insn.Op1.type = o_mem;
      insn.Op1.addr = insn.get_next_byte();
      break;
    default:
      error("ana: bad code %x",code);
  }
  if ( insn.itype == M65_nop )
    insn.Op1.type = o_void;
  return insn.size;
}
