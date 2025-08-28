
#include "m65816.hpp"

#define DI(itype, len, addr_mode, cpus) { (itype), (addr_mode), (cpus) },
#define DV(itype, len, addr_mode, cpus, flags) { (itype), (addr_mode), (cpus), (flags) },

static const struct opcode_info_t opinfos[] =
{
  // 0x00
  DI(M65816_brk, 2, STACK_INT,              M6X             )
  DI(M65816_ora, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_cop, 2, STACK_INT,              M65816          )
  DI(M65816_ora, 2, STACK_REL,              M65816          )
  DI(M65816_tsb, 2, DP,                     M65C02 | M65816 )
  DI(M65816_ora, 2, DP,                     M6X)
  DI(M65816_asl, 2, DP,                     M6X)
  DI(M65816_ora, 2, DP_INDIR_LONG,          M6X)

  // 0x08
  DI(M65816_php, 1, STACK_PUSH,             M6X )
  DV(M65816_ora, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_asl, 1, ACC,                    M6X             )
  DI(M65816_phd, 1, STACK_PUSH,             M65816          )
  DI(M65816_tsb, 3, ABS,                    M65C02 | M65816 )
  DI(M65816_ora, 3, ABS,                    M6X             )
  DI(M65816_asl, 3, ABS,                    M6X             )
  DI(M65816_ora, 4, ABS_LONG,               M65816          )

  // 0x10
  DI(M65816_bpl, 2, PC_REL,                 M6X             )
  DI(M65816_ora, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_ora, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_ora, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_trb, 2, DP,                     M65C02 | M65816 )
  DI(M65816_ora, 2, DP_IX,                  M6X             )
  DI(M65816_asl, 2, DP_IX,                  M6X             )
  DI(M65816_ora, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0x18
  DI(M65816_clc, 1, IMPLIED,                M6X             )
  DI(M65816_ora, 3, ABS_IY,                 M6X             )
  DI(M65816_inc, 1, ACC,                    M65C02 | M65816 )
  DI(M65816_tcs, 1, IMPLIED,                M65816          )
  DI(M65816_trb, 3, ABS,                    M65C02 | M65816 )
  DI(M65816_ora, 3, ABS_IX,                 M6X             )
  DI(M65816_asl, 3, ABS_IX,                 M6X             )
  DI(M65816_ora, 4, ABS_LONG_IX,            M65816          )

  // 0x20
  DI(M65816_jsr, 3, ABS,                    M6X             )
  DI(M65816_and, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_jsl, 4, ABS_LONG,               M65816          )
  DI(M65816_and, 2, STACK_REL,              M65816          )
  DI(M65816_bit, 2, DP,                     M6X             )
  DI(M65816_and, 2, DP,                     M6X             )
  DI(M65816_rol, 2, DP,                     M6X             )
  DI(M65816_and, 2, DP_INDIR_LONG,          M65816          )

  // 0x28
  DI(M65816_plp, 1, STACK_PULL,             M6X             )
  DV(M65816_and, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_rol, 1, ACC,                    M6X             )
  DI(M65816_pld, 1, STACK_PULL,             M65816          )
  DI(M65816_bit, 3, ABS,                    M6X             )
  DI(M65816_and, 3, ABS,                    M6X             )
  DI(M65816_rol, 3, ABS,                    M6X             )
  DI(M65816_and, 4, ABS_LONG,               M65816          )

  // 0x30
  DI(M65816_bmi, 2, PC_REL,                 M6X             )
  DI(M65816_and, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_and, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_and, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_bit, 2, DP_IX,                  M65C02 | M65816 )
  DI(M65816_and, 2, DP_IX,                  M6X             )
  DI(M65816_rol, 2, DP_IX,                  M6X             )
  DI(M65816_and, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0x38
  DI(M65816_sec, 1, IMPLIED,                M6X             )
  DI(M65816_and, 3, ABS_IY,                 M6X             )
  DI(M65816_dec, 1, ACC,                    M65C02 | M65816 )
  DI(M65816_tsc, 1, IMPLIED,                M65816          )
  DI(M65816_bit, 3, ABS_IX,                 M65C02 | M65816 )
  DI(M65816_and, 3, ABS_IX,                 M6X             )
  DI(M65816_rol, 3, ABS_IX,                 M6X             )
  DI(M65816_and, 4, ABS_LONG_IX,            M65816          )

  // 0x40
  DI(M65816_rti, 1, STACK_RTI,              M6X             )
  DI(M65816_eor, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_wdm, 2, IMPLIED,                M65816          )
  DI(M65816_eor, 2, STACK_REL,              M65816          )
  DI(M65816_mvp, 3, BLK_MOV,                M65816          )
  DI(M65816_eor, 2, DP,                     M6X             )
  DI(M65816_lsr, 2, DP,                     M6X             )
  DI(M65816_eor, 2, DP_INDIR_LONG,          M65816          )

  // 0x48
  DI(M65816_pha, 1, STACK_PUSH,             M6X             )
  DV(M65816_eor, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_lsr, 1, ACC,                    M6X             )
  DI(M65816_phk, 1, STACK_PUSH,             M65816          )
  DI(M65816_jmp, 3, ABS,                    M6X             )
  DI(M65816_eor, 3, ABS,                    M6X             )
  DI(M65816_lsr, 3, ABS,                    M6X             )
  DI(M65816_eor, 4, ABS_LONG,               M65816          )

  // 0x50
  DI(M65816_bvc, 2, PC_REL,                 M6X             )
  DI(M65816_eor, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_eor, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_eor, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_mvn, 3, BLK_MOV,                M65816          )
  DI(M65816_eor, 2, DP_IX,                  M6X             )
  DI(M65816_lsr, 2, DP_IX,                  M6X             )
  DI(M65816_eor, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0x58
  DI(M65816_cli, 1, IMPLIED,                M6X             )
  DI(M65816_eor, 3, ABS_IY,                 M6X             )
  DI(M65816_phy, 1, STACK_PUSH,             M65C02 | M65816 )
  DI(M65816_tcd, 1, IMPLIED,                M65816          )
  DI(M65816_jml, 4, ABS_LONG,               M65816          )
  DI(M65816_eor, 3, ABS_IX,                 M6X             )
  DI(M65816_lsr, 3, ABS_IX,                 M6X             )
  DI(M65816_eor, 4, ABS_LONG_IX,            M65816          )

  // 0x60
  DI(M65816_rts, 1, STACK_RTS,              M6X             )
  DI(M65816_adc, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_per, 3, STACK_PC_REL,           M65816          )
  DI(M65816_adc, 2, STACK_REL,              M65816          )
  DI(M65816_stz, 2, DP,                     M65C02 | M65816 )
  DI(M65816_adc, 2, DP,                     M6X             )
  DI(M65816_ror, 2, DP,                     M6X             )
  DI(M65816_adc, 2, DP_INDIR_LONG,          M65816          )

  // 0x68
  DI(M65816_pla, 1, STACK_PULL,             M6X             )
  DV(M65816_adc, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_ror, 1, ACC,                    M6X             )
  DI(M65816_rtl, 1, STACK_RTL,              M65816          )
  DI(M65816_jmp, 3, ABS_INDIR,              M6X             )
  DI(M65816_adc, 3, ABS,                    M6X             )
  DI(M65816_ror, 3, ABS,                    M6X             )
  DI(M65816_adc, 4, ABS_LONG,               M65816          )

  // 0x70
  DI(M65816_bvs, 2, PC_REL,                 M6X             )
  DI(M65816_adc, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_adc, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_adc, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_stz, 2, DP_IX,                  M65C02 | M65816 )
  DI(M65816_adc, 2, DP_IX,                  M6X             )
  DI(M65816_ror, 2, DP_IX,                  M6X             )
  DI(M65816_adc, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0x78
  DI(M65816_sei, 1, IMPLIED,                M6X             )
  DI(M65816_adc, 3, ABS_IY,                 M6X             )
  DI(M65816_ply, 1, STACK_PULL,             M65C02 | M65816 )
  DI(M65816_tdc, 1, IMPLIED,                M65816          )
  DI(M65816_jmp, 3, ABS_IX_INDIR,           M65C02 | M65816 )
  DI(M65816_adc, 3, ABS_IX,                 M6X             )
  DI(M65816_ror, 3, ABS_IX,                 M6X             )
  DI(M65816_adc, 4, ABS_LONG_IX,            M6X             )

  // 0x80
  DI(M65816_bra, 2, PC_REL,                 M65C02 | M65816 )
  DI(M65816_sta, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_brl, 3, PC_REL_LONG,            M65816          )
  DI(M65816_sta, 2, STACK_REL,              M65816          )
  DI(M65816_sty, 2, DP,                     M6X             )
  DI(M65816_sta, 2, DP,                     M6X             )
  DI(M65816_stx, 2, DP,                     M6X             )
  DI(M65816_sta, 2, DP_INDIR_LONG,          M65816          )

  // 0x88
  DI(M65816_dey, 1, IMPLIED,                M6X             )
  DV(M65816_bit, 2, IMM,                    M65C02 | M65816, ACC16_INCBC)
  DI(M65816_txa, 1, IMPLIED,                M6X             )
  DI(M65816_phb, 1, STACK_PUSH,             M65816          )
  DI(M65816_sty, 3, ABS,                    M6X             )
  DI(M65816_sta, 3, ABS,                    M6X             )
  DI(M65816_stx, 3, ABS,                    M6X             )
  DI(M65816_sta, 4, ABS_LONG,               M65816          )

  // 0x90
  DI(M65816_bcc, 2, PC_REL,                 M6X             )
  DI(M65816_sta, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_sta, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_sta, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_sty, 2, DP_IX,                  M6X             )
  DI(M65816_sta, 2, DP_IX,                  M6X             )
  DI(M65816_stx, 2, DP_IY,                  M6X             )
  DI(M65816_sta, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0x98
  DI(M65816_tya, 1, IMPLIED,                M6X             )
  DI(M65816_sta, 3, ABS_IY,                 M6X             )
  DI(M65816_txs, 1, IMPLIED,                M6X             )
  DI(M65816_txy, 1, IMPLIED,                M65816          )
  DI(M65816_stz, 3, ABS,                    M65C02 | M65816 )
  DI(M65816_sta, 3, ABS_IX,                 M6X             )
  DI(M65816_stz, 3, ABS_IX,                 M65C02 | M65816 )
  DI(M65816_sta, 4, ABS_LONG_IX,            M65816          )

  // 0xa0
  DV(M65816_ldy, 2, IMM,                    M6X, XY16_INCBC )
  DI(M65816_lda, 2, DP_IX_INDIR,            M6X             )
  DV(M65816_ldx, 2, IMM,                    M6X, XY16_INCBC )
  DI(M65816_lda, 2, STACK_REL,              M65816          )
  DI(M65816_ldy, 2, DP,                     M6X             )
  DI(M65816_lda, 2, DP,                     M6X             )
  DI(M65816_ldx, 2, DP,                     M6X             )
  DI(M65816_lda, 2, DP_INDIR_LONG,          M65816          )

  // 0xa8
  DI(M65816_tay, 1, IMPLIED,                M6X             )
  DV(M65816_lda, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_tax, 1, IMPLIED,                M6X             )
  DI(M65816_plb, 1, STACK_PULL,             M65816          )
  DI(M65816_ldy, 3, ABS,                    M6X             )
  DI(M65816_lda, 3, ABS,                    M6X             )
  DI(M65816_ldx, 3, ABS,                    M6X             )
  DI(M65816_lda, 4, ABS_LONG,               M65816          )

  // 0xb0
  DI(M65816_bcs, 2, PC_REL,                 M6X             )
  DI(M65816_lda, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_lda, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_lda, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_ldy, 2, DP_IX,                  M6X             )
  DI(M65816_lda, 2, DP_IX,                  M6X             )
  DI(M65816_ldx, 2, DP_IY,                  M6X             )
  DI(M65816_lda, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0xb8
  DI(M65816_clv, 1, IMPLIED,                M6X             )
  DI(M65816_lda, 3, ABS_IY,                 M6X             )
  DI(M65816_tsx, 1, IMPLIED,                M6X             )
  DI(M65816_tyx, 1, IMPLIED,                M65816          )
  DI(M65816_ldy, 3, ABS_IX,                 M6X             )
  DI(M65816_lda, 3, ABS_IX,                 M6X             )
  DI(M65816_ldx, 3, ABS_IY,                 M6X             )
  DI(M65816_lda, 4, ABS_LONG_IX,            M65816          )

  // 0xc0
  DV(M65816_cpy, 2, IMM,                    M6X, XY16_INCBC)
  DI(M65816_cmp, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_rep, 2, IMM,                    M65816          )
  DI(M65816_cmp, 2, STACK_REL,              M65816          )
  DI(M65816_cpy, 2, DP,                     M6X             )
  DI(M65816_cmp, 2, DP,                     M6X             )
  DI(M65816_dec, 2, DP,                     M6X             )
  DI(M65816_cmp, 2, DP_INDIR_LONG,          M65816          )

  // 0xc8
  DI(M65816_iny, 1, IMPLIED,                M6X             )
  DV(M65816_cmp, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_dex, 1, IMPLIED,                M6X             )
  DI(M65816_wai, 1, IMPLIED,                M65816          )
  DI(M65816_cpy, 3, ABS,                    M6X             )
  DI(M65816_cmp, 3, ABS,                    M6X             )
  DI(M65816_dec, 3, ABS,                    M6X             )
  DI(M65816_cmp, 4, ABS_LONG,               M65816          )

  // 0xd0
  DI(M65816_bne, 2, PC_REL,                 M6X             )
  DI(M65816_cmp, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_cmp, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_cmp, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_pei, 2, STACK_DP_INDIR,         M65816          )
  DI(M65816_cmp, 2, DP_IX,                  M6X             )
  DI(M65816_dec, 2, DP_IX,                  M6X             )
  DI(M65816_cmp, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0xd8
  DI(M65816_cld, 1, IMPLIED,                M6X             )
  DI(M65816_cmp, 3, ABS_IY,                 M6X             )
  DI(M65816_phx, 1, STACK_PUSH,             M65C02 | M65816 )
  DI(M65816_stp, 1, IMPLIED,                M65816          )
  DI(M65816_jmp, 3, ABS_INDIR_LONG,         M65816          )
  DI(M65816_cmp, 3, ABS_IX,                 M6X             )
  DI(M65816_dec, 3, ABS_IX,                 M6X             )
  DI(M65816_cmp, 4, ABS_LONG_IX,            M65816          )

  // 0xe0
  DV(M65816_cpx, 2, IMM,                    M6X, XY16_INCBC)
  DI(M65816_sbc, 2, DP_IX_INDIR,            M6X             )
  DI(M65816_sep, 2, IMM,                    M65816          )
  DI(M65816_sbc, 2, STACK_REL,              M65816          )
  DI(M65816_cpx, 2, DP,                     M6X             )
  DI(M65816_sbc, 2, DP,                     M6X             )
  DI(M65816_inc, 2, DP,                     M6X             )
  DI(M65816_sbc, 2, DP_INDIR_LONG,          M65816          )

  // 0xe8
  DI(M65816_inx, 1, IMPLIED,                M6X             )
  DV(M65816_sbc, 2, IMM,                    M6X, ACC16_INCBC)
  DI(M65816_nop, 1, IMPLIED,                M6X             )
  DI(M65816_xba, 1, IMPLIED,                M65816          )
  DI(M65816_cpx, 3, ABS,                    M6X             )
  DI(M65816_sbc, 3, ABS,                    M6X             )
  DI(M65816_inc, 3, ABS,                    M6X             )
  DI(M65816_sbc, 4, ABS_LONG,               M65816          )

  // 0xf0
  DI(M65816_beq, 2, PC_REL,                 M6X             )
  DI(M65816_sbc, 2, DP_INDIR_IY,            M6X             )
  DI(M65816_sbc, 2, DP_INDIR,               M65C02 | M65816 )
  DI(M65816_sbc, 2, STACK_REL_INDIR_IY,     M65816          )
  DI(M65816_pea, 3, STACK_ABS,              M65816          )
  DI(M65816_sbc, 2, DP_IX,                  M6X             )
  DI(M65816_inc, 2, DP_IX,                  M6X             )
  DI(M65816_sbc, 2, DP_INDIR_LONG_IY,       M65816          )

  // 0xf8
  DI(M65816_sed, 1, IMPLIED,                M6X             )
  DI(M65816_sbc, 3, ABS_IY,                 M6X             )
  DI(M65816_plx, 1, STACK_PULL,             M65C02 | M65816 )
  DI(M65816_xce, 1, IMPLIED,                M65816          )
  DI(M65816_jsr, 3, ABS_IX_INDIR,           M65816          )
  DI(M65816_sbc, 3, ABS_IX,                 M6X             )
  DI(M65816_inc, 3, ABS_IX,                 M6X             )
  DI(M65816_sbc, 4, ABS_LONG_IX,            M65816          )
  };

#undef DI
#undef DV


// ---------------------------------------------------------------------------
const struct opcode_info_t &get_opcode_info(uint8 opcode)
{
  return opinfos[opcode];
}

// ---------------------------------------------------------------------------
inline bool is_acc_16_sensitive_op(const struct opcode_info_t &opinfo)
{
  return (opinfo.flags & ACC16_INCBC) == ACC16_INCBC;
}

// ---------------------------------------------------------------------------
inline bool is_xy_16_sensitive_op(const struct opcode_info_t &opinfo)
{
  return (opinfo.flags & XY16_INCBC) == XY16_INCBC;
}

// ---------------------------------------------------------------------------
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  insn.Op1.dtype = dt_byte;
  uint8 code = insn.get_next_byte();

  // Fetch instruction info
  const struct opcode_info_t &opinfo = get_opcode_info(code);
  insn.itype = opinfo.itype;

  switch ( opinfo.addr )
  {
    case ACC:
    case STACK_PUSH:
    case STACK_PULL:
    case STACK_RTS:
    case STACK_RTI:
    case STACK_RTL:
    case IMPLIED:
      break;
    case STACK_INT:
      // COP & BRK; they are 1-byte, but have
      // another, signature byte.
      insn.get_next_byte();
      break;
    case STACK_ABS:
      // Always 16 bits
      insn.Op1.type  = o_imm;
      insn.Op1.value = insn.get_next_word();
      insn.Op1.dtype = dt_word;
      break;
    case STACK_REL:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rS;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = dt_byte;
      break;
    case STACK_REL_INDIR_IY:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rSiY;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = dt_byte;
      break;
    case STACK_PC_REL:
      {
        int16 disp = insn.get_next_word();
        insn.Op1.type = o_near;
        insn.Op1.addr = uint16(insn.ip + insn.size + disp);
        insn.Op1.dtype = dt_word;
      }
      break;
    case STACK_DP_INDIR:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rSDi;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = dt_word;
      break;
    case IMM:
      insn.Op1.type = o_imm;
      if ( (is_acc_16_sensitive_op (opinfo) && is_acc_16_bits(insn))
        || (is_xy_16_sensitive_op  (opinfo) && is_xy_16_bits(insn)) ) //
      {
        insn.Op1.value = insn.get_next_word();
        insn.Op1.dtype = dt_word;
      }
      else
      {
        insn.Op1.value = insn.get_next_byte();
        insn.Op1.dtype = dt_byte;
      }
      break;
    case ABS:
      insn.Op1.type = o_mem;
      insn.Op1.addr = insn.get_next_word();
      insn.Op1.dtype = dt_word;
      insn.Op1.full_target_ea = insn.Op1.addr;
      if ( insn.itype == M65816_jsr || insn.itype == M65816_jmp )
      {
        insn.Op1.type = o_near;
      }
      else if ( insn.itype == M65816_stx || insn.itype == M65816_sty
             || insn.itype == M65816_ldx || insn.itype == M65816_ldy
             || insn.itype == M65816_cpx || insn.itype == M65816_cpy )
      {
        insn.Op1.dtype = is_xy_16_bits(insn) ? dt_word : dt_byte;
      }
      else
      {
        insn.Op1.dtype = is_acc_16_bits(insn) ? dt_word : dt_byte;
      }
      break;
    case ABS_LONG:
      insn.Op1.type = o_mem_far;
      insn.Op1.addr = insn.get_next_word();
      insn.Op1.addr|= insn.get_next_byte() << 16;
      insn.Op1.full_target_ea = insn.Op1.addr;
      if ( insn.itype == M65816_jsl || insn.itype == M65816_jml )
        insn.Op1.type = o_far;
      else
        insn.Op1.dtype = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case ABS_IX:
    case ABS_IY:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = opinfo.addr == ABS_IX ? rAbsX : rAbsY;
      insn.Op1.addr   = insn.get_next_word();
      if ( insn.itype == M65816_ldx || insn.itype == M65816_ldy )
        insn.Op1.dtype = is_xy_16_bits(insn) ? dt_word : dt_byte;
      else
        insn.Op1.dtype = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case ABS_LONG_IX:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rAbsLX;
      insn.Op1.addr   = insn.get_next_word();
      insn.Op1.addr  |= insn.get_next_byte() << 16;
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case ABS_INDIR:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rAbsi;
      insn.Op1.addr   = insn.get_next_word();
      insn.Op1.dtype  = dt_word;
      break;
    case ABS_INDIR_LONG:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rAbsiL;
      insn.Op1.addr   = insn.get_next_word();
      insn.Op1.dtype  = dt_word;
      break;
    case ABS_IX_INDIR:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rAbsXi;
      insn.Op1.addr   = insn.get_next_word();
      insn.Op1.dtype  = dt_word;
      break;
    case DP:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rD;
      insn.Op1.addr   = insn.get_next_byte();
      if ( insn.itype == M65816_stx || insn.itype == M65816_sty
        || insn.itype == M65816_ldx || insn.itype == M65816_ldy
        || insn.itype == M65816_cpx || insn.itype == M65816_cpy )
      {
        insn.Op1.dtype = is_xy_16_bits(insn) ? dt_word : dt_byte;
      }
      else
      {
        insn.Op1.dtype = is_acc_16_bits(insn) ? dt_word : dt_byte;
      }
      break;
    case DP_IY:
    case DP_IX:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = opinfo.addr == DP_IX ? rDX : rDY;
      insn.Op1.addr   = insn.get_next_byte();
      if ( insn.itype == M65816_stx || insn.itype == M65816_sty
        || insn.itype == M65816_ldx || insn.itype == M65816_ldy )
      {
        insn.Op1.dtype = is_xy_16_bits(insn) ? dt_word : dt_byte;
      }
      else
      {
        insn.Op1.dtype = is_acc_16_bits(insn) ? dt_word : dt_byte;
      }
      break;
    case DP_IX_INDIR:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = riDX;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case DP_INDIR:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rDi;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case DP_INDIR_LONG:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rDiL;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case DP_INDIR_IY:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rDiY;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case DP_INDIR_LONG_IY:
      insn.Op1.type   = o_displ;
      insn.Op1.phrase = rDiLY;
      insn.Op1.addr   = insn.get_next_byte();
      insn.Op1.dtype  = is_acc_16_bits(insn) ? dt_word : dt_byte;
      break;
    case PC_REL:
      insn.Op1.type = o_near;
      {
        char x = insn.get_next_byte();
        insn.Op1.addr = uint16(insn.ip + insn.size + x);
        insn.Op1.full_target_ea = insn.Op1.addr;
        insn.Op1.dtype = dt_word;
      }
      break;
    case PC_REL_LONG:
      insn.Op1.type = o_far;
      {
        int16 x = insn.get_next_word();
        insn.Op1.addr           = uint16(insn.ip + insn.size + x) | (insn.ea & 0xff0000);
        insn.Op1.full_target_ea = insn.Op1.addr;
        insn.Op1.dtype          = dt_word;
      }
      break;
    case BLK_MOV:
      insn.Op1.type  = o_imm;
      insn.Op1.value = insn.get_next_byte();
      insn.Op1.dtype = dt_byte;
      insn.Op2.type  = o_imm;
      insn.Op2.value = insn.get_next_byte();
      insn.Op2.dtype = dt_byte;
      break;
    default:
      warning("ana: bad code 0x%x, @: 0x%a (IP=%a)", code, insn.ea, insn.ip);
      return 0;
  }

  return insn.size;
}
