/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Hitchi H8
 *
 */

#include "h8500.hpp"

//--------------------------------------------------------------------------
#define MAP3         ushort(-3)
#define MAP4         ushort(-4)
#define MAP5         ushort(-5)
#define MAP6         ushort(-6)

static const ushort A2[] =
{
/* 00 */ H8500_nop,   MAP6,          H8500_ldm,   H8500_pjsr,  MAP5,        MAP4,        MAP6,         MAP6,
/* 08 */ H8500_trapa, H8500_trap_vs, H8500_rte,   H8500_bpt,   MAP5,        MAP4,        H8500_bsr,    H8500_unlk,
/* 10 */ H8500_jmp,   MAP6,          H8500_stm,   H8500_pjmp,  H8500_rtd,   MAP4,        H8500_null,   H8500_link,
/* 18 */ H8500_jsr,   H8500_rts,     H8500_sleep, H8500_null,  H8500_rtd,   MAP4,        H8500_bsr,    H8500_link,
/* 20 */ H8500_bra,   H8500_brn,     H8500_bhi,   H8500_bls,   H8500_bcc,   H8500_bcs,   H8500_bne,    H8500_beq,
/* 28 */ H8500_bvc,   H8500_bvs,     H8500_bpl,   H8500_bmi,   H8500_bge,   H8500_blt,   H8500_bgt,    H8500_ble,
/* 30 */ H8500_bra,   H8500_brn,     H8500_bhi,   H8500_bls,   H8500_bcc,   H8500_bcs,   H8500_bne,    H8500_beq,
/* 38 */ H8500_bvc,   H8500_bvs,     H8500_bpl,   H8500_bmi,   H8500_bge,   H8500_blt,   H8500_bgt,    H8500_ble,
/* 40 */ H8500_cmp_e, H8500_cmp_e,   H8500_cmp_e, H8500_cmp_e, H8500_cmp_e, H8500_cmp_e, H8500_cmp_e,  H8500_cmp_e,
/* 48 */ H8500_cmp_i, H8500_cmp_i,   H8500_cmp_i, H8500_cmp_i, H8500_cmp_i, H8500_cmp_i, H8500_cmp_i,  H8500_cmp_i,
/* 50 */ H8500_mov_e, H8500_mov_e,   H8500_mov_e, H8500_mov_e, H8500_mov_e, H8500_mov_e, H8500_mov_e,  H8500_mov_e,
/* 58 */ H8500_mov_i, H8500_mov_i,   H8500_mov_i, H8500_mov_i, H8500_mov_i, H8500_mov_i, H8500_mov_i,  H8500_mov_i,
};

static const ushort A2tail[] =
{
/* 60 */ H8500_mov_l,
/* 70 */ H8500_mov_s,
/* 80 */ H8500_mov_f,
/* 90 */ H8500_mov_f,
/* A0 */ MAP3,
/* B0 */ MAP4,
/* C0 */ MAP4,
/* D0 */ MAP4,
/* E0 */ MAP4,
/* F0 */ MAP4,
};

static const ushort A3[] =
{
/* 00 */ MAP6,        H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 08 */ H8500_add_q, H8500_add_q,   H8500_null,  H8500_null,  H8500_add_q, H8500_add_q, H8500_null,   H8500_null,
/* 10 */ H8500_swap,  H8500_exts,    H8500_extu,  H8500_clr,   H8500_neg,   H8500_not,   H8500_tst,    H8500_tas,
/* 18 */ H8500_shal,  H8500_shar,    H8500_shll,  H8500_shlr,  H8500_rotl,  H8500_rotr,  H8500_rotxl,  H8500_rotxr,
};

static const ushort A3tail[] =
{
/* 20 */ H8500_add_g, H8500_adds,
/* 30 */ H8500_sub,   H8500_subs,
/* 40 */ H8500_or,    H8500_bset,
/* 50 */ H8500_and,   H8500_bclr,
/* 60 */ H8500_xor,   H8500_bnot,
/* 70 */ H8500_cmp_g, H8500_btst,
/* 80 */ H8500_mov_g, H8500_ldc,
/* 90 */ H8500_xch,   H8500_stc,
/* A0 */ H8500_addx,  H8500_mulxu,
/* B0 */ H8500_subx,  H8500_divxu,
/* C0 */ H8500_bset,  H8500_bset,
/* D0 */ H8500_bclr,  H8500_bclr,
/* E0 */ H8500_bnot,  H8500_bnot,
/* F0 */ H8500_btst,  H8500_btst,
};

static const ushort A4[] =
{
/* 00 */ MAP6,        H8500_null,    H8500_null,  H8500_null,  H8500_cmp_g, H8500_cmp_g, H8500_mov_g,  H8500_mov_g,
/* 08 */ H8500_add_q, H8500_add_q,   H8500_null,  H8500_null,  H8500_add_q, H8500_add_q, H8500_null,   H8500_null,
/* 10 */ H8500_null,  H8500_null,    H8500_null,  H8500_clr,   H8500_neg,   H8500_not,   H8500_tst,    H8500_tas,
/* 18 */ H8500_shal,  H8500_shar,    H8500_shll,  H8500_shlr,  H8500_rotl,  H8500_rotr,  H8500_rotxl,  H8500_rotxr,
};

static const ushort A4tail[] =
{
/* 20 */ H8500_add_g, H8500_adds,
/* 30 */ H8500_sub,   H8500_subs,
/* 40 */ H8500_or,    H8500_bset,
/* 50 */ H8500_and,   H8500_bclr,
/* 60 */ H8500_xor,   H8500_bnot,
/* 70 */ H8500_cmp_g, H8500_btst,
/* 80 */ H8500_mov_g, H8500_ldc,
/* 90 */ H8500_mov_g, H8500_stc,
/* A0 */ H8500_addx,  H8500_mulxu,
/* B0 */ H8500_subx,  H8500_divxu,
/* C0 */ H8500_bset,  H8500_bset,
/* D0 */ H8500_bclr,  H8500_bclr,
/* E0 */ H8500_bnot,  H8500_bnot,
/* F0 */ H8500_btst,  H8500_btst,
};

static const ushort A5[] =
{
/* 00 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 08 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 10 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 18 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
};

static const ushort A5tail[] =
{
/* 20 */ H8500_add_g, H8500_adds,
/* 30 */ H8500_sub,   H8500_subs,
/* 40 */ H8500_or,    H8500_orc,
/* 50 */ H8500_and,   H8500_andc,
/* 60 */ H8500_xor,   H8500_xorc,
/* 70 */ H8500_cmp_g, H8500_null,
/* 80 */ H8500_mov_g, H8500_ldc,
/* 90 */ H8500_null,  H8500_null,
/* A0 */ H8500_addx,  H8500_mulxu,
/* B0 */ H8500_subx,  H8500_divxu,
/* C0 */ H8500_null,  H8500_null,
/* D0 */ H8500_null,  H8500_null,
/* E0 */ H8500_null,  H8500_null,
/* F0 */ H8500_null,  H8500_null,
};

static const ushort A6[] =
{
/* 00 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 08 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_null,  H8500_null,  H8500_null,   H8500_null,
/* 10 */ H8500_null,  H8500_null,    H8500_null,  H8500_null,  H8500_prtd,  H8500_null,  H8500_null,   H8500_null,
/* 18 */ H8500_null,  H8500_prts,    H8500_null,  H8500_null,  H8500_prtd,  H8500_null,  H8500_null,   H8500_null,
};

static const ushort A6tail[] =
{
/* 20 */ H8500_null,   H8500_null,
/* 30 */ H8500_null,   H8500_null,
/* 40 */ H8500_null,   H8500_null,
/* 50 */ H8500_null,   H8500_null,
/* 60 */ H8500_null,   H8500_null,
/* 70 */ H8500_null,   H8500_null,
/* 80 */ H8500_movfpe, H8500_null,
/* 90 */ H8500_movtpe, H8500_null,
/* A0 */ H8500_dadd,   H8500_null,
/* B0 */ H8500_dsub,   H8500_scb,
/* C0 */ H8500_pjmp,   H8500_pjsr,
/* D0 */ H8500_jmp,    H8500_jsr,
/* E0 */ H8500_jmp,    H8500_jsr,
/* F0 */ H8500_jmp,    H8500_jsr,
};

struct tables_t
{
  const ushort *head;
  const ushort *tail;
};

static const tables_t tables[] =
{
  { A3, A3tail },
  { A4, A4tail },
  { A5, A5tail },
  { A6, A6tail },
};

//--------------------------------------------------------------------------
inline void immv(op_t &x, int v)
{
  x.type  = o_imm;
  x.dtype = dt_dword;
  x.value = v;
}

//--------------------------------------------------------------------------
inline void imm8(insn_t &insn, op_t &x)
{
  insn.auxpref |= aux_disp8;
  x.type  = o_imm;
  x.dtype = dt_byte;
  x.value = insn.get_next_byte();
}

//--------------------------------------------------------------------------
inline void imm16(insn_t &insn, op_t &x)
{
  insn.auxpref |= aux_disp16;
  x.type  = o_imm;
  x.dtype = dt_word;
  x.value = insn.get_next_word();
}

//--------------------------------------------------------------------------
inline void opreg(op_t &x, int code, char dtype)
{
  x.type  = o_reg;
  x.dtype = dtype;
  x.reg   = code & 7;
}

//--------------------------------------------------------------------------
inline void aa8(insn_t &insn, op_t &x, char dtype)
{
  insn.auxpref |= aux_page|aux_disp8;
  x.type  = o_mem;
  x.dtype = dtype;
  x.addr  = insn.get_next_byte();
}

//--------------------------------------------------------------------------
inline void aa16(insn_t &insn, op_t &x, char dtype)
{
  insn.auxpref |= aux_disp16;
  x.type  = o_mem;
  x.dtype = dtype;
  x.addr  = insn.get_next_word();
}

//--------------------------------------------------------------------------
inline void ds8(insn_t &insn, op_t &x, int reg, char dtype)
{
  insn.auxpref |= aux_disp8;
  x.type  = o_displ;
  x.dtype = dtype;
  x.reg   = reg & 7;
  x.addr  = insn.get_next_byte();
}

//--------------------------------------------------------------------------
inline void ds16(insn_t &insn, op_t &x, int reg, char dtype)
{
  insn.auxpref |= aux_disp16;
  x.type  = o_displ;
  x.dtype = dtype;
  x.reg   = reg & 7;
  x.addr  = insn.get_next_word();
}

//--------------------------------------------------------------------------
inline void phrase(op_t &x, int code, uchar pht, char dtype)
{
  x.type   = o_phrase;
  x.dtype  = dtype;
  x.phrase = code & 7;
  x.phtype = pht;
}

//--------------------------------------------------------------------------
inline void h8500_t::d8(insn_t &insn, op_t &x) const
{
  insn.auxpref |= aux_disp8;
  int32 disp = char(insn.get_next_byte());
  x.type  = o_near;
  x.dtype = dt_code;
  x.addr  = trunc_uval(insn.ip + insn.size + disp);
}

//--------------------------------------------------------------------------
int h8500_t::h8500_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  uint8 code = insn.get_next_byte();
  uint8 saved_code = code;
  char dtype = dt_byte;
  if ( code < 0x60 )
  {
    insn.itype = A2[code];
  }
  else
  {
    if ( code & 8 )
    {
      insn.auxpref |= aux_word;
      dtype = dt_word;
    }
    else
    {
      insn.auxpref |= aux_byte;
      dtype = dt_byte;
    }
    insn.itype = A2tail[(code>>4)-6];
  }
  if ( insn.itype == H8500_null )
    return 0;
  switch ( code )
  {
    case 0x02:  // ldm.w @sp+, <reglist>
//      insn.auxpref |= aux_word;
      phrase(insn.Op1, SP, ph_post, dt_word);
      insn.Op2.type = o_reglist;
      insn.Op2.reg  = insn.get_next_byte();
      if ( !insn.Op2.reg )
        return 0;
      break;
    case 0x12:  // stm.w <reglist>, @-sp
//      insn.auxpref |= aux_word;
      insn.Op1.type = o_reglist;
      insn.Op1.reg  = insn.get_next_byte();
      if ( !insn.Op1.reg )
        return 0;
      phrase(insn.Op2, SP, ph_pre, dt_word);
      break;
    case 0x01:  // scb/f
      insn.auxpref |= aux_f;
      break;
    case 0x06:  // scb/ne
      insn.auxpref |= aux_ne;
      break;
    case 0x07:  // scb/eq
      insn.auxpref |= aux_eq;
      break;
    case 0x08:  // trapa #xx
      code = insn.get_next_byte();
      if ( (code & 0xF0) != 0x10 )
        return 0;
      insn.Op1.type = o_imm;
      insn.Op1.dtype = dt_byte;
      insn.Op1.value = code & 15;
      break;
    case 0x0F:  // unlk
      opreg(insn.Op1, FP, dt_word);
      break;
    case 0x10:  // jmp @aa:16
    case 0x18:  // jsr @aa:16
      aa16(insn, insn.Op1, dt_code);
      insn.Op1.type = o_near;
      insn.Op1.addr = trunc_uval(insn.Op1.addr + (insn.ea & ~0xFFFF));
      break;
    case 0x17:  // link #xx:8
      opreg(insn.Op1, FP, dt_word);
      imm8(insn, insn.Op2);
      break;
    case 0x1F:  // link #xx:16
      opreg(insn.Op1, FP, dt_word);
      imm16(insn, insn.Op2);
      break;
    case 0x03:  // pjsr @aa:24
    case 0x13:  // pjmp @aa:24
      {
        insn.auxpref |= aux_disp24;
        uint32 page  = insn.get_next_byte();
        insn.Op1.type = o_far;
        insn.Op1.dtype = dt_code;
        insn.Op1.addr = (page<<16) | insn.get_next_word();
      }
      break;
    case 0x04:  // #xx:8
      insn.auxpref |= aux_byte;
      // fallthrough
    case 0x14:  // #xx:8
      imm8(insn, insn.Op1);
      break;
    case 0x05:  // #aa:8.B
      insn.auxpref |= aux_byte;
      aa8(insn, insn.Op1, dt_byte);
      break;
    case 0x15:  // #aa:16.B
      insn.auxpref |= aux_byte;
      aa16(insn, insn.Op1, dt_byte);
      break;
    case 0x0C:  // #xx:16
      insn.auxpref |= aux_word;
      // fallthrough
    case 0x1C:  // #xx:16
      imm16(insn, insn.Op1);
      break;
    case 0x0D:  // #aa:8.W
      insn.auxpref |= aux_word;
      aa8(insn, insn.Op1, dt_word);
      dtype = dt_word;
      break;
    case 0x1D:  // #aa:16.W
      insn.auxpref |= aux_word;
      aa16(insn, insn.Op1, dt_word);
      dtype = dt_word;
      break;
    case 0x0E:                                  // bsr d:8
    case 0x20: case 0x21: case 0x22: case 0x23: // d:8
    case 0x24: case 0x25: case 0x26: case 0x27:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x2C: case 0x2D: case 0x2E: case 0x2F:
      d8(insn, insn.Op1);
      break;
    case 0x1E:                                  // bsr d:16
    case 0x30: case 0x31: case 0x32: case 0x33: // d:16
    case 0x34: case 0x35: case 0x36: case 0x37:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x3C: case 0x3D: case 0x3E: case 0x3F:
      {
        insn.auxpref |= aux_disp16;
        int32 disp = short(insn.get_next_word());
        insn.Op1.type = o_near;
        insn.Op1.dtype = dt_code;
        insn.Op1.addr = trunc_uval(insn.ip + insn.size + disp);
      }
      break;
    case 0x40: case 0x41: case 0x42: case 0x43: // cmp:e #xx:8, Rn
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x50: case 0x51: case 0x52: case 0x53: // mov:e #xx:8, Rn
    case 0x54: case 0x55: case 0x56: case 0x57:
      insn.auxpref |= aux_byte;
      imm8(insn, insn.Op1);
      opreg(insn.Op2, code, dtype);
      break;
    case 0x48: case 0x49: case 0x4A: case 0x4B: // cmp:i #xx:16, Rn
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x58: case 0x59: case 0x5A: case 0x5B: // mov:i #xx:16, Rn
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
      insn.auxpref |= aux_word;
      imm16(insn, insn.Op1);
      opreg(insn.Op2, code, dtype);
      break;
    case 0x60: case 0x61: case 0x62: case 0x63: // @aa:8, Rn
    case 0x64: case 0x65: case 0x66: case 0x67:
    case 0x68: case 0x69: case 0x6A: case 0x6B:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
      aa8(insn, insn.Op1, dtype);
      opreg(insn.Op2, code, dtype);
      break;
    case 0x70: case 0x71: case 0x72: case 0x73: // Rn, @aa:8
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
      opreg(insn.Op1, code, dtype);
      aa8(insn, insn.Op2, dtype);
      break;
    case 0x80: case 0x81: case 0x82: case 0x83: // mov:f @(d:8, R6), Rn
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
      ds8(insn, insn.Op1, R6, dtype);
      opreg(insn.Op2, code, dtype);
      break;
    case 0x90: case 0x91: case 0x92: case 0x93: // mov:f Rn, @(d:8, R6)
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
      opreg(insn.Op1, code, dtype);
      ds8(insn, insn.Op2, R6, dtype);
      break;
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: // Rn, Rn
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xA8: case 0xA9: case 0xAA: case 0xAB:
    case 0xAC: case 0xAD: case 0xAE: case 0xAF:
      opreg(insn.Op1, code, dtype);
      break;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: // @-Rn, Rn
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
      phrase(insn.Op1, code, ph_pre, dtype);
      break;
    case 0xC0: case 0xC1: case 0xC2: case 0xC3: // @Rn+, Rn
    case 0xC4: case 0xC5: case 0xC6: case 0xC7:
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
      phrase(insn.Op1, code, ph_post, dtype);
      break;
    case 0xD0: case 0xD1: case 0xD2: case 0xD3: // @Rn, Rn
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
      phrase(insn.Op1, code, ph_normal, dtype);
      break;
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: // @(d:8,Rn), Rn
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
      ds8(insn, insn.Op1, code, dtype);
      break;
    case 0xF0: case 0xF1: case 0xF2: case 0xF3: // @(d:16,Rn), Rn
    case 0xF4: case 0xF5: case 0xF6: case 0xF7:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
      ds16(insn, insn.Op1, code, dtype);
      break;
  }
  while ( insn.itype > H8500_last )     // while MAPs are not resolved
  {
    int index = -(3+short(insn.itype));
    if ( index < 0 || index >= qnumber(tables) )
      INTERR(10089);
    code = insn.get_next_byte();
    if ( code < 0x20 )
    {
      insn.itype = tables[index].head[code];
    }
    else
    {
      insn.itype = tables[index].tail[(code>>3)-4];
      opreg(insn.Op2, code, dtype);
    }
    if ( index == 3 ) switch ( saved_code ) // MAP6
    {
      case 0x01:
      case 0x06:
      case 0x07:
        if ( insn.itype != H8500_scb )
          return 0;
        break;
      case 0x11:
        if ( insn.itype != H8500_prts
          && insn.itype != H8500_prtd
          && insn.itype != H8500_jmp
          && insn.itype != H8500_pjmp
          && insn.itype != H8500_jsr
          && insn.itype != H8500_pjsr )
        {
          return 0;
        }
        break;
      default:
        if ( insn.itype != H8500_movfpe
          && insn.itype != H8500_movtpe
          && insn.itype != H8500_dadd
          && insn.itype != H8500_dsub )
        {
          return 0;
        }
    }
    switch ( insn.itype )
    {
      case H8500_null:
        return 0;
      case H8500_add_q:
        insn.Op2 = insn.Op1;
        switch ( code )
        {
          case 0x08: immv(insn.Op1, 1);  break;
          case 0x09: immv(insn.Op1, 2);  break;
          case 0x0C: immv(insn.Op1, -1); break;
          case 0x0D: immv(insn.Op1, -2); break;
        }
        break;
      case H8500_bset:
      case H8500_bclr:
      case H8500_bnot:
      case H8500_btst:
        insn.Op2 = insn.Op1;
        if ( code < 0xC0 )
          opreg(insn.Op1, code, dtype);
        else
          immv(insn.Op1, code & 15);
        break;
      case H8500_mov_g:
        if ( (code & 0xF8) == 0x80 )
          break;
        insn.Op2 = insn.Op1;
        if ( code == 0x06 )
        {
          if ( (insn.auxpref & aux_word) == 0 )
            insn.auxpref |= aux_byte;
          insn.Op1.type  = o_imm;
          insn.Op1.dtype = dt_byte;
          insn.Op1.value = insn.get_next_byte();
        }
        else if ( code == 0x07 )
        {
          if ( (insn.auxpref & aux_byte) == 0 )
            insn.auxpref |= aux_word;
          insn.auxpref  |= aux_mov16;
          insn.Op1.type  = o_imm;
          insn.Op1.dtype = dt_word;
          insn.Op1.value = insn.get_next_word();
        }
        else
          opreg(insn.Op1, code, dtype);
        break;
      case H8500_cmp_g:
        if ( code > 5 )
          break;
        insn.Op2 = insn.Op1;
        if ( code == 0x04 )
        {
          insn.auxpref  |= aux_byte;
          insn.Op1.type  = o_imm;
          insn.Op1.dtype = dt_byte;
          insn.Op1.value = insn.get_next_byte();
        }
        else
        {
          insn.auxpref  |= aux_word;
          insn.Op1.type  = o_imm;
          insn.Op1.dtype = dt_word;
          insn.Op1.value = insn.get_next_word();
        }
        break;
      case H8500_andc:
      case H8500_orc:
      case H8500_xorc:
      case H8500_ldc:
      case H8500_stc:
        insn.Op2.reg += SR;
        if ( insn.Op2.reg == RES1 || insn.Op2.reg == CP )
          return 0;
        if ( ((insn.auxpref & aux_word) != 0) != (insn.Op2.reg == SR) )
          return 0;
        if ( insn.itype != H8500_stc )
          break;
        // no break
      case H8500_movtpe:
        {
          op_t x   = insn.Op1;
          insn.Op1 = insn.Op2;
          insn.Op2 = x;
        }
        break;
      case H8500_pjmp:
      case H8500_pjsr:
      case H8500_jmp:
      case H8500_jsr:
        insn.Op2.type = o_void;
        switch ( code & 0xF0 )
        {
          case 0xC0:
          case 0xD0: phrase(insn.Op1, code, ph_normal, dt_code); break;
          case 0xE0: ds8(insn, insn.Op1, code, dt_code); break;
          case 0xF0: ds16(insn, insn.Op1, code, dt_code); break;
        }
        break;
      case H8500_rtd:
      case H8500_prtd:
        if ( code == 0x14 )
          imm8(insn, insn.Op1);
        else
          imm16(insn, insn.Op1);
        break;
      case H8500_scb:
        insn.Op1 = insn.Op2;
        d8(insn, insn.Op2);
        break;
      case H8500_dadd:
      case H8500_dsub:
        if ( (insn.auxpref & aux_byte) == 0 )
          return 0;
        insn.auxpref &= ~aux_byte;
        break;
    }
  }
  if ( !is_mixed_size_insns() )
  {
    if ( (insn.auxpref & aux_word) && insn.Op1.dtype == dt_byte
      || (insn.auxpref & aux_byte) && insn.Op1.dtype == dt_word )
    {
      if ( insn.itype != H8500_mov_g )
        return 0;
    }
  }
  return insn.size;
}
