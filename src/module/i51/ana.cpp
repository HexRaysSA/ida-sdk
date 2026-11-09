/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"

//----------------------------------------------------------------------
inline uint32 get_next_24bits(insn_t &insn)
{
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_word();
  return low | (high<<16);
}

//----------------------------------------------------------------------
static void operand1(insn_t &insn, int nibble)
{
  switch ( nibble )
  {
    case 4:
      insn.Op1.type = o_reg;
      insn.Op1.reg = rAcc;
      break;
    case 5:
      insn.Op1.type = o_mem;
      insn.Op1.addr = insn.get_next_byte();
      break;
    case 6:
      insn.Op1.type = o_phrase;
      insn.Op1.phrase = fR0;
      break;
    case 7:
      insn.Op1.type = o_phrase;
      insn.Op1.phrase = fR1;
      break;
    default:
      insn.Op1.type = o_reg;
      insn.Op1.phrase = uint16(rR0 + (nibble-8));
      break;
  }
}

//----------------------------------------------------------------------
static void operand2(insn_t &insn, ushort nibble)
{
  switch ( nibble )
  {
    case 4:
      insn.Op2.type = o_imm;
      insn.Op2.value = insn.get_next_byte();
      break;
    case 5:
      insn.Op2.type = o_mem;
      insn.Op2.addr = insn.get_next_byte();
      break;
    case 6:
      insn.Op2.type = o_phrase;
      insn.Op2.phrase = fR0;
      break;
    case 7:
      insn.Op2.type = o_phrase;
      insn.Op2.phrase = fR1;
      break;
    default:
      insn.Op2.type = o_reg;
      insn.Op2.phrase = rR0 + (nibble-8);
      break;
  }
}

//----------------------------------------------------------------------
inline void opAcc(op_t &op)
{
  op.type = o_reg;
  op.reg = rAcc;
}

//----------------------------------------------------------------------
inline void opC(op_t &op)
{
  op.type = o_reg;
  op.reg = rC;
}

//----------------------------------------------------------------------
// register direct
static int op_rd(op_t &x, uint16 reg, uchar dtyp)
{
  if ( reg >= rDR32 && reg <= rDR52 )
    return 0;
  x.type = o_reg;
  x.dtype = dtyp;
  x.reg  = reg;
  return 1;
}

//----------------------------------------------------------------------
// register indirect (fRi registers)
static int op_ph(op_t &x, int reg, uchar dtyp)
{
  if ( reg >= rDR32 && reg <= rDR52 )
    return 0;
  x.type = o_phrase;
  x.dtype = dtyp;
  x.reg = fRi;
  x.indreg = uchar(reg);
  return 1;
}

//----------------------------------------------------------------------
// register indirect
static int op_ph(op_t &op, i51_phrases phr, uchar dtyp, uval_t disp = 0)
{
  op.type = o_phrase;
  op.dtype = dtyp;
  op.phrase = phr;
  if ( disp > 0 )
  {
    op.imm_disp = 1;
    op.value = disp;
  }
  return 1;
}


//----------------------------------------------------------------------
// register indirect with displacement
static int op_ds(op_t &x, uint16 phrase, uval_t disp, uchar dtyp)
{
  if ( phrase >= rDR32 && phrase <= rDR52 )
    return 0;
  x.type = o_displ;
  x.dtype = dtyp;
  x.phrase = phrase;
  x.addr = disp;
  return 1;
}

//----------------------------------------------------------------------
inline void op_mm(op_t &x, uval_t addr, uchar dtyp)
{
  x.type = o_mem;
  x.dtype = dtyp;
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_near(op_t &x, uval_t addr)
{
  x.type = o_near;
  x.dtype = dt_word;
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_im(op_t &x, uval_t value, uchar dtyp)
{
  x.type = o_imm;
  x.dtype = dtyp;
  x.value = value;
}

//----------------------------------------------------------------------
uint32 i51_t::truncate(uval_t addr) const
{
  if ( ptype == prc_51 )
    return addr & 0xFFFF;
  else
    return addr & 0xFFFFFF;
}

//----------------------------------------------------------------------
static int make_short(insn_t &insn, uint16 itype, uchar b)
{
  insn.itype = itype;
  static const uchar bregs[] = { rR0, rWR0, 0, rDR0 };
  static const uchar dtyps[] = { dt_byte, dt_word, dt_dword };
  int idx = (b >> 2) & 3;
  if ( !op_rd(insn.Op1, bregs[idx] + (b>>4), dtyps[idx]) )
    return 0;
  b &= 3;
  if ( b == 3 )
    return 0;
  op_im(insn.Op2, uval_t(1)<<b, dt_byte);
  return insn.size;
}

//----------------------------------------------------------------------
// analyze extended instruction set

int i51_t::ana_extended(insn_t &insn)
{
  int code = insn.get_next_byte();
  if ( (code & 8) == 0 )
    return 0;
  if ( (code & 0xF0) >= 0xE0 )
    return 0;

  static const uchar itypes[] =
  {
/*      8         9          A          B         C         D         E         F  */
/* 0 */ I51_jsle, I51_mov,   I51_movz,  I51_mov,  I51_null, I51_null, I51_sra,  I51_null,
/* 1 */ I51_jsg,  I51_mov,   I51_movs,  I51_mov,  I51_null, I51_null, I51_srl,  I51_null,
/* 2 */ I51_jle,  I51_mov,   I51_null,  I51_null, I51_add,  I51_add,  I51_add,  I51_add,
/* 3 */ I51_jg,   I51_mov,   I51_null,  I51_null, I51_null, I51_null, I51_sll,  I51_null,
/* 4 */ I51_jsl,  I51_mov,   I51_null,  I51_null, I51_orl,  I51_orl,  I51_orl,  I51_null,
/* 5 */ I51_jsge, I51_mov,   I51_null,  I51_null, I51_anl,  I51_anl,  I51_anl,  I51_null,
/* 6 */ I51_je,   I51_mov,   I51_null,  I51_null, I51_xrl,  I51_xrl,  I51_xrl,  I51_null,
/* 7 */ I51_jne,  I51_mov,   I51_mov,   I51_null, I51_mov,  I51_mov,  I51_mov,  I51_mov,
/* 8 */ I51_null, I51_ljmp,  I51_ejmp,  I51_null, I51_div,  I51_div,  I51_null, I51_null,
/* 9 */ I51_null, I51_lcall, I51_ecall, I51_null, I51_sub,  I51_sub,  I51_sub,  I51_sub,
/* A */ I51_null, I51_last,  I51_eret,  I51_null, I51_mul,  I51_mul,  I51_null, I51_null,
/* B */ I51_null, I51_trap,  I51_null,  I51_null, I51_cmp,  I51_cmp,  I51_cmp,  I51_cmp,
/* C */ I51_null, I51_null,  I51_push,  I51_null, I51_null, I51_null, I51_null, I51_null,
/* D */ I51_null, I51_null,  I51_pop,   I51_null, I51_null, I51_null, I51_null, I51_null,
  };
  insn.itype = itypes[ ((code&0xF0)>>1) | (code & 7) ];
  if ( insn.itype == I51_null )
    return 0;

  uchar b1, b2;
  int oax = 0;
  switch ( code )
  {
    case 0x08:          // rel
    case 0x18:
    case 0x28:
    case 0x38:
    case 0x48:
    case 0x58:
    case 0x68:
    case 0x78:
      {
        insn.Op1.type = o_near;
        insn.Op1.dtype = dt_word;
        signed char off = insn.get_next_byte();
        insn.Op1.addr = truncate(insn.ip + insn.size + off); // signed addition
      }
      break;

    case 0x09:          // mov Rm, @WRj+dis
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rR0 +(b1>>4), dt_byte);
      insn.Op2.offb = (uchar)insn.size;
      op_ds(insn.Op2, rWR0+(b1&15), insn.get_next_word(), dt_byte);
      break;

    case 0x49:          // mov WRk, @WRj+dis
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
      insn.Op2.offb = (uchar)insn.size;
      op_ds(insn.Op2, rWR0+(b1&15), insn.get_next_word(), dt_word);
      break;

    case 0x29:          // mov Rm, @DRj+dis
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rR0 +(b1>>4), dt_byte);
      insn.Op2.offb = (uchar)insn.size;
      if ( !op_ds(insn.Op2, rDR0+(b1&15), insn.get_next_word(), dt_byte) )
        return 0;
      break;

    case 0x69:          // mov WRj, @DRk+dis
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
      insn.Op2.offb = (uchar)insn.size;
      if ( !op_ds(insn.Op2, rDR0+(b1&15), insn.get_next_word(), dt_word) )
        return 0;
      break;

    case 0x19:          // mov @WRj+dis, Rm
      b1 = insn.get_next_byte();
      insn.Op1.offb = (uchar)insn.size;
      op_ds(insn.Op1, rWR0+(b1&15), insn.get_next_word(), dt_byte);
      op_rd(insn.Op2, rR0 +(b1>>4), dt_byte);
      break;

    case 0x59:          // mov @WRj+dis, WRk
      b1 = insn.get_next_byte();
      insn.Op1.offb = (uchar)insn.size;
      op_ds(insn.Op1, rWR0+(b1&15), insn.get_next_word(), dt_word);
      op_rd(insn.Op2, rWR0+(b1>>4), dt_word);
      break;

    case 0x39:          // mov @DRj+dis, Rm
      b1 = insn.get_next_byte();
      insn.Op1.offb = (uchar)insn.size;
      if ( !op_ds(insn.Op1, rDR0+(b1&15), insn.get_next_word(), dt_byte) )
        return 0;
      op_rd(insn.Op2, rR0 +(b1>>4), dt_byte);
      break;

    case 0x79:          // mov @DRk+dis, WRj
      b1 = insn.get_next_byte();
      insn.Op1.offb = (uchar)insn.size;
      if ( !op_ds(insn.Op1, rDR0+(b1&15), insn.get_next_word(), dt_word) )
        return 0;
      op_rd(insn.Op2, rWR0+(b1>>4), dt_word);
      break;

    case 0x0A:          // movz WRj, Rm
    case 0x1A:          // movs WRj, Rm
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
      op_rd(insn.Op2, rR0 +(b1&15), dt_byte);
      break;

    case 0x0B:          // 1000 mov WRj, @WRj
                        // 1010 mov WRj, @DRk
      {
        b1 = insn.get_next_byte();
        int ri;
        switch ( b1 & 15 )
        {
          case 0x8: ri = rWR0; break;
          case 0xA: ri = rDR0; break;
          case 0x9: return 0;
          case 0xB: return 0;
          default:  return make_short(insn, I51_inc, b1);
        }
        b2 = insn.get_next_byte();
        if ( b2 & 15 )
          return 0;
        op_rd(insn.Op1, rWR0+(b2>>4), dt_word);
        if ( !op_ph(insn.Op2, ri + (b1>>4), dt_word) )
          return 0;
      }
      break;

    case 0x1B:          // 1000 mov @WRj, WRj
                        // 1010 mov @DRk, WRj
      {
        b1 = insn.get_next_byte();
        int ri;
        switch ( b1 & 15 )
        {
          case 0x8: ri = rWR0; break;
          case 0xA: ri = rDR0; break;
          case 0x9: return 0;
          case 0xB: return 0;
          default:  return make_short(insn, I51_dec, b1);
        }
        b2 = insn.get_next_byte();
        if ( b2 & 15 )
          return 0;
        if ( !op_ph(insn.Op1, ri + (b1>>4), dt_word) )
          return 0;
        op_rd(insn.Op2, rWR0+(b2>>4), dt_word);
      }
      break;

    case 0x7A:
      {
        b1 = insn.get_next_byte();
        switch ( b1&15 )
        {
          case 9:                 // 1001 mov @WRj, Rm
          case 0xB:               // 1011 mov @DRk, Rm
            b2 = insn.get_next_byte();
            if ( b2 & 15 )
              return 0;
            if ( !op_ph(insn.Op1, ((b1&2) ? rDR0 : rWR0) + (b1>>4), dt_byte) )
              return 0;
            op_rd(insn.Op2, rR0+(b2>>4), dt_byte);
            break;
          case 0xC:               // movh DRk, #data16
            insn.itype = I51_movh;
            if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
              return 0;
            insn.Op2.offb = (uchar)insn.size;
            op_im(insn.Op2, insn.get_next_word(), dt_word);
            break;
          default:
            goto CONT;
        }
        break;
CONT:
        uval_t addr = (b1&2) ? insn.get_next_word() : insn.get_next_byte();
        switch ( b1&15 )
        {
          case 0x1:               // mov dir8, Rm
          case 0x3:               // mov dir16, Rm
            op_mm(insn.Op1, addr, dt_byte);
            op_rd(insn.Op2, rR0+(b1>>4), dt_byte);
            break;
          case 0x5:               // mov dir8, WRj
          case 0x7:               // mov dir16, WRj
            op_mm(insn.Op1, addr, dt_word);
            op_rd(insn.Op2, rWR0+(b1>>4), dt_word);
            break;
          case 0xD:               // mov dir8, DRj
          case 0xF:               // mov dir16, DRj
            op_mm(insn.Op1, addr, dt_dword);
            if ( !op_rd(insn.Op2, rDR0+(b1>>4), dt_dword) )
              return 0;
            break;
          default: return 0;
        }
      }
      break;

    case 0x89:          // ljmp  @WRj or @DRj
    case 0x99:          // lcall @WRj or @DRj
      {
        int r;
        uchar dt;
        b1 = insn.get_next_byte();
        switch ( b1 & 15 )
        {
          case 4:
            r = rWR0;
            dt = dt_word;
            break;
          case 8:
            r = rDR0;
            dt = dt_dword;
            insn.itype = (insn.itype == I51_ljmp) ? I51_ejmp : I51_ecall;
            break;
          default:
            return 0;
        }
        if ( !op_ph(insn.Op1, r+(b1>>4), dt) )
          return 0;
      }
      break;

    case 0x8A:          // ejmp  addr24
    case 0x9A:          // ecall addr24
      op_near(insn.Op1, get_next_24bits(insn));
      break;

    case 0xAA:          // eret
    case 0xB9:          // trap
      break;

    case 0xCA:          // push
    case 0xDA:          // pop
      b1 = insn.get_next_byte();
      switch ( b1 & 15 )
      {
        case 0x1:                                       // mov DRk, PC
          if ( code != 0xCA )
            return 0;
          insn.itype = I51_mov;
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          op_rd(insn.Op2, rPC, dt_dword);
          break;
        case 0x2:                                       // #data8
          insn.Op1.offb = (uchar)insn.size;
          op_im(insn.Op1, insn.get_next_byte(), dt_byte);
          break;
        case 0x6:                                       // #data16
          insn.Op1.offb = (uchar)insn.size;
          op_im(insn.Op1, insn.get_next_word(), dt_word);
          break;
        case 0x8:                                       // Rm
          op_rd(insn.Op1, rR0+(b1>>4), dt_byte);
          break;
        case 0x9:                                       // WRj
          op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
          break;
        case 0xB:                                       // DRj
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          break;
        default:
          return 0;
      }
      break;

    case 0xA9:          // bit instructions
      {
        static const uchar subtypes[] =
        {
          I51_null, I51_jbc,  I51_jb,   I51_jnb,
          I51_null, I51_null, I51_null, I51_orl,
          I51_anl,  I51_mov,  I51_mov,  I51_cpl,
          I51_clr,  I51_setb, I51_orl,  I51_anl
        };
        b1 = insn.get_next_byte();
        if ( b1 & 8 )
          return 0;
        insn.itype = subtypes[ b1 >> 4];
        if ( insn.itype == I51_null )
          return 0;
        insn.Op1.type = o_bit251;
        insn.Op1.dtype = dt_byte;
        insn.Op1.b251_bit = b1 & 7;
        insn.Op1.addr = insn.get_next_byte();
        insn.Op1.b251_bitneg = 0;
        switch ( b1 >> 4 )
        {
          case 0x1:             // jbc bit, rel
          case 0x2:             // jb  bit, rel
          case 0x3:             // jnb bit, rel
            {
              signed char rel = insn.get_next_byte();
              op_near(insn.Op2, truncate(insn.ip + insn.size + rel));
            }
            break;
          case 0xE:             // orl cy, /bit
          case 0xF:             // anl cy, /bit
            insn.Op1.b251_bitneg = 1;
            /* no break */
          case 0x7:             // orl cy, bit
          case 0x8:             // anl cy, bit
          case 0xA:             // mov cy, bit
            insn.Op2 = insn.Op1;
            opC(insn.Op1);
            break;
          case 0x9:             // mov bit, cy
            opC(insn.Op2);
            break;
          case 0xB:             // cpl  bit
          case 0xC:             // clr  bit
          case 0xD:             // setb bit
            break;
        }
      }
      break;

    case 0x0E:          // sra
    case 0x1E:          // srl
    case 0x3E:          // sll
      b1 = insn.get_next_byte();
      switch ( b1 & 15 )
      {
        case 0:
          op_rd(insn.Op1, rR0 +(b1>>4), dt_byte);
          break;
        case 4:
          op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
          break;
        default:
          return 0;
      }
      break;

    case 0x2C:          // add Rm, Rm
    case 0x4C:          // orl Rm, Rm
    case 0x5C:          // anl Rm, Rm
    case 0x6C:          // xrl Rm, Rm
    case 0x7C:          // mov Rm, Rm
    case 0x8C:          // div Rm, Rm
    case 0x9C:          // sub Rm, Rm
    case 0xAC:          // mul Rm, Rm
    case 0xBC:          // cmp Rm, Rm
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rR0+(b1>>4), dt_byte);
      op_rd(insn.Op2, rR0+(b1&15), dt_byte);
      break;

    case 0x2D:          // add WRj, WRj
    case 0x4D:          // orl WRj, WRj
    case 0x5D:          // anl WRj, WRj
    case 0x6D:          // xrl WRj, WRj
    case 0x7D:          // mov WRj, WRj
    case 0x8D:          // div WRj, WRj
    case 0x9D:          // sub WRj, WRj
    case 0xAD:          // mul WRj, WRj
    case 0xBD:          // cmp WRj, WRj
      b1 = insn.get_next_byte();
      op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
      op_rd(insn.Op2, rWR0+(b1&15), dt_word);
      break;

    case 0x2F:          // add DRj, DRj
    case 0x7F:          // mov DRj, DRj
    case 0x9F:          // sub DRj, DRj
    case 0xBF:          // cmp DRj, DRj
      b1 = insn.get_next_byte();
      if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
        return 0;
      if ( !op_rd(insn.Op2, rDR0+(b1&15), dt_dword) )
        return 0;
      break;

    case 0x4E:          // orl reg, op2
    case 0x5E:          // anl reg, op2
    case 0x6E:          // xrl reg, op2
      oax = 1;  // orl, anl, xrl
      /* no break */
    case 0x2E:          // add reg, op2
    case 0x7E:          // mov reg, op2
    case 0x8E:          // div reg, op2
    case 0x9E:          // sub reg, op2
    case 0xAE:          // mul reg, op2
    case 0xBE:          // cmp reg, op2
      b1 = insn.get_next_byte();
      switch ( b1 & 15 )
      {
        case 0x0:                                       // Rm, #8
          op_rd(insn.Op1, rR0+(b1>>4), dt_byte);
          insn.Op2.offb = (uchar)insn.size;
          op_im(insn.Op2, insn.get_next_byte(), dt_byte);
          break;
        case 0x4:                                       // WRj, #16
          op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
          insn.Op2.offb = (uchar)insn.size;
          op_im(insn.Op2, insn.get_next_word(), dt_word);
          break;
        case 0x8:                                       // DRk, #16
          if ( oax )
            return 0;
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          insn.Op2.offb = (uchar)insn.size;
          op_im(insn.Op2, insn.get_next_word(), dt_word);
          break;
        case 0xC:                                       // DRk, #(1)16
          if ( oax )
            return 0;
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          insn.Op2.offb = (uchar)insn.size;
          op_im(insn.Op2, insn.get_next_word(), dt_word);
          insn.auxpref |= aux_1ext;
          break;
        case 0x1:                                       // Rm, dir8
          op_rd(insn.Op1, rR0+(b1>>4), dt_byte);
          op_mm(insn.Op2, insn.get_next_byte(), dt_byte);
          break;
        case 0x5:                                       // WRj, dir8
          op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
          op_mm(insn.Op2, insn.get_next_byte(), dt_word);
          break;
        case 0xD:                                       // DRk, dir8
          if ( oax )
            return 0;
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          op_mm(insn.Op2, insn.get_next_byte(), dt_word);
          break;
        case 0x3:                                       // Rm, dir16
          op_rd(insn.Op1, rR0+(b1>>4), dt_byte);
          op_mm(insn.Op2, insn.get_next_word(), dt_byte);
          break;
        case 0x7:                                       // WRj, dir16
          op_rd(insn.Op1, rWR0+(b1>>4), dt_word);
          op_mm(insn.Op2, insn.get_next_word(), dt_word);
          break;
        case 0xF:                                       // DRk, dir16
          if ( code != 0x7E )
            return 0;         // only mov works
          if ( !op_rd(insn.Op1, rDR0+(b1>>4), dt_dword) )
            return 0;
          op_mm(insn.Op2, insn.get_next_word(), dt_word);
          break;
        case 0x9:                                       // Rm, @WRj
          b2 = insn.get_next_byte();
          if ( b2 & 15 )
            return 0;
          op_rd(insn.Op1, rR0 +(b2>>4), dt_byte);
          op_ph(insn.Op2, rWR0+(b1>>4), dt_byte);
          break;
        case 0xB:                                       // Rm, @DRk
          b2 = insn.get_next_byte();
          if ( b2 & 15 )
            return 0;
          op_rd(insn.Op1, rR0 +(b2>>4), dt_byte);
          if ( !op_ph(insn.Op2, rDR0+(b1>>4), dt_byte) )
            return 0;
          break;
        default:
          return 0;
      }
      break;

    default:
      error("%a: internal ana_extended() error, code=%x", insn.ea, code);
  }

  return insn.size;
}

//----------------------------------------------------------------------
// analyze an basic instruction
int i51_t::ana_basic(insn_t &insn)
{
  ushort code = insn.get_next_byte();
  bool mx_a5 = false;
  if ( code == 0xA5 && ptype == prc_51mx )
  {
    code = insn.get_next_byte();
    mx_a5 = true;
  }

  ushort nibble0 = (code & 0xF);
  ushort nibble1 = (code >> 4);
  char off;
  if ( mx_a5 )
  {
    if ( nibble1 == 0x6 && nibble0 >= 0x8 ) // ADD PRi,#data2 (0 1 1 0 1 i d1 d2)
    {
      insn.itype = I51_add;
      op_rd(insn.Op1, (nibble0 & 4) == 0 ? rPR0 : rPR1, dt_dword);
      int val = nibble0 & 3;
      op_im(insn.Op2, val == 0 ? 4 : val, dt_byte);
      return insn.size;
    }
    if ( nibble1 == 0x4 && nibble0 >= 0x8 ) // EMOVE A, @PRi+#data2
    {
      insn.itype = I51_emov;
      opAcc(insn.Op1);
      int val = nibble0 & 3;
      op_ph(insn.Op2, (nibble0 & 4) == 0 ? fPr0 : fPr1, dt_dword, val == 0 ? 4 : val);
      return insn.size;
    }
    if ( nibble1 == 0x5 && nibble0 >= 0x8 ) // EMOVE @PRi+#data2, A
    {
      insn.itype = I51_emov;
      int val = nibble0 & 3;
      op_ph(insn.Op1, (nibble0 & 4) == 0 ? fPr0 : fPr1, dt_dword, val == 0 ? 4 : val);
      opAcc(insn.Op2);
      return insn.size;
    }
  }
  if ( nibble0 < 4 )              // complex coding, misc instructions
  {
    switch ( nibble0 )
    {
      case 0:
        {
          static const uchar misc0[16] =
          {
            I51_nop, I51_jbc, I51_jb,  I51_jnb,
            I51_jc,  I51_jnc, I51_jz,  I51_jnz,
            I51_sjmp,I51_mov, I51_orl, I51_anl,
            I51_push,I51_pop, I51_movx,I51_movx
          };
          insn.itype = misc0[nibble1];
        }
        switch ( nibble1 )
        {
          case 0x1: case 0x2: case 0x3: // jbc, jb, jnb
            insn.Op1.type  = o_bit;
            insn.Op1.reg = insn.get_next_byte();
            insn.Op2.type = o_near;
            off = insn.get_next_byte();
            insn.Op2.addr = truncate(insn.ip + insn.size + off); // signed addition
            insn.Op2.dtype = dt_word;
            break;
          case 0x4: case 0x5: case 0x6: case 0x7: case 0x8: // jc, jnc, jz, jnz, sjmp
            insn.Op1.type = o_near;
            off = insn.get_next_byte();
            insn.Op1.addr = truncate(insn.ip + insn.size + off); // signed addition
            insn.Op1.dtype = dt_word;
            break;
          case 0x9: // mov
            insn.Op1.type = o_reg;
            insn.Op1.reg = mx_a5 ? rEptr : rDptr;
            insn.Op1.dtype = mx_a5 ? dt_dword : dt_word;
            insn.Op2.type  = o_imm;
            insn.Op2.offb  = (uchar)insn.size;
            if ( mx_a5 )
            {
              insn.Op2.value = (((ea_t)insn.get_next_word()) << 8) + insn.get_next_byte();
              insn.Op2.dtype = dt_dword;
            }
            else
            {
              insn.Op2.value = insn.get_next_word();
              insn.Op2.dtype = dt_word;
            }
            break;
          case 0xA: case 0xB: // orl, anl
            opC(insn.Op1);
            insn.Op2.type = o_bitnot;
            insn.Op2.reg = insn.get_next_byte();
            break;
          case 0xC: case 0xD: // push, pop
            insn.Op1.type = o_mem;
            insn.Op1.addr = insn.get_next_byte();
            break;
          case 0xE: // movx
            opAcc(insn.Op1);
            insn.Op2.type = o_phrase;
            insn.Op2.phrase = mx_a5 ? fEptr : fDptr;
            break;
          case 0xF: // movx
            opAcc(insn.Op2);
            insn.Op1.type = o_phrase;
            insn.Op1.phrase = mx_a5 ? fEptr : fDptr;
            break;
        }
        break;
      case 1: // acall, ajmp
        {
          ushort lowbits = insn.get_next_byte();
          insn.Op1.type = o_near;
          insn.Op1.addr = truncate((code&0xE0)<<3) + lowbits + ((insn.ip+insn.size) & ~0x7FF);
          insn.Op1.dtype = dt_word;
          insn.itype = (nibble1 & 1) ? I51_acall : I51_ajmp;
        }
        break;
      case 2:
        {
          static const uchar misc2[16] =
          {
            I51_ljmp,I51_lcall,I51_ret,I51_reti,
            I51_orl, I51_anl, I51_xrl, I51_orl,
            I51_anl, I51_mov, I51_mov, I51_cpl,
            I51_clr, I51_setb,I51_movx,I51_movx
          };
          insn.itype = misc2[nibble1];
        }
        switch ( nibble1 )
        {
          case 0x0: case 0x1: // ljump (ejmp), lcall (ecall)
            insn.Op1.type = o_near;
            if ( mx_a5 ) // ecall
            {
              insn.itype = nibble1 == 0 ? I51_ejmp : I51_ecall;
              insn.Op1.addr = (((ea_t)insn.get_next_word()) << 8) + insn.get_next_byte();
              if ( insn.Op1.addr >= 0x800000 )
                insn.Op1.addr -= 0x800000;
            }
            else
            {
              insn.Op1.addr = insn.get_next_word();
            }
            insn.Op1.addr|= (insn.ip+insn.size) & ~0xFFFF;
            insn.Op1.dtype = mx_a5 ? dt_dword : dt_word;
            break;
          case 0x2: // ret (eret);
            if ( mx_a5 )
              insn.itype = I51_eret;
            break;
          case 0x4: case 0x5: case 0x6: // orl, anl, xrl,
            insn.Op1.type = o_mem;
            insn.Op1.addr = insn.get_next_byte();
            opAcc(insn.Op2);
            break;
          case 0x7: case 0x8: case 0xA: // orl, anl, mov
            opC(insn.Op1);
            insn.Op2.type = o_bit;
            insn.Op2.reg = insn.get_next_byte();
            break;
          case 0x9: // mov
            opC(insn.Op2);
            /* no break */
          case 0xB: case 0xC: case 0xD: // cpl, clr, setb
            insn.Op1.type = o_bit;
            insn.Op1.reg = insn.get_next_byte();
            break;
          case 0xE: // movx
            opAcc(insn.Op1);
            insn.Op2.type = o_phrase;
            insn.Op2.phrase = fR0;
            break;
          case 0xF: // movx
            insn.Op1.type = o_phrase;
            insn.Op1.phrase = fR0;
            opAcc(insn.Op2);
            break;
        }
        break;
      case 3:
        {
          static const uchar misc3[16] =
          {
            I51_rr,  I51_rrc, I51_rl,  I51_rlc,
            I51_orl, I51_anl, I51_xrl, I51_jmp,
            I51_movc,I51_movc,I51_inc, I51_cpl,
            I51_clr, I51_setb,I51_movx,I51_movx
          };
          insn.itype = misc3[nibble1];
        }
        switch ( nibble1 )
        {
          case 0x0: case 0x1: case 0x2: case 0x3: // rr, rrc, rl, rlc
            opAcc(insn.Op1);
            break;
          case 0x4: case 0x5: case 0x6: // orl, anl, xrl
            insn.Op1.type = o_mem;
            insn.Op1.addr = insn.get_next_byte();
            insn.Op2.offb  = (uchar)insn.size;
            insn.Op2.type  = o_imm;
            insn.Op2.value = insn.get_next_byte();
            break;
          case 0x7: // jmp
            insn.Op1.type = o_phrase;
            insn.Op1.phrase = mx_a5 ? fAeptr : fAdptr;
            break;
          case 0x8: case 0x9: // movc
            opAcc(insn.Op1);
            insn.Op2.type = o_phrase;
            insn.Op2.phrase = nibble1 == 0x8 ? fApc : (mx_a5 ? fAeptr : fAdptr);
            break;
          case 0xA: // inc
            insn.Op1.type = o_reg;
            insn.Op1.reg = mx_a5 ? rEptr : rDptr;
            insn.Op1.dtype = mx_a5 ? dt_dword : dt_word;
            break;
          case 0xB: case 0xC: case 0xD: // cpl, clr, setb
            opC(insn.Op1);
            break;
          case 0xE: // movx
            opAcc(insn.Op1);
            insn.Op2.type = o_phrase;
            insn.Op2.phrase = fR1;
            break;
          case 0xF: // movx
            insn.Op1.type = o_phrase;
            insn.Op1.phrase = fR1;
            opAcc(insn.Op2);
            break;
        }
        break;
    }
  }
  else
  {         // i.e. nibble0 >= 4
    static const uchar regulars[16] =
    {
      I51_inc, I51_dec, I51_add, I51_addc,
      I51_orl, I51_anl, I51_xrl, I51_mov,
      I51_mov, I51_subb,I51_mov, I51_cjne,
      I51_xch, I51_djnz,I51_mov, I51_mov
    };
    insn.itype = regulars[nibble1];
    switch ( nibble1 )
    {
      case 0x00: case 0x01:     // inc, dec
        operand1(insn, nibble0);
        break;
      case 0x0C:                // xch
        if ( nibble0 == 4 )
        {
          insn.itype = I51_swap;
          opAcc(insn.Op1);
          break;
        }
        // fallthrough
      case 0x02: case 0x03: case 0x04: // add, addc, orl
      case 0x05: case 0x06: case 0x09: // anl, xrl, subb
        operand2(insn, nibble0);
        opAcc(insn.Op1);
        break;
      case 0x07:                // mov
        operand1(insn, nibble0);
        insn.Op2.offb = (uchar)insn.size;
        insn.Op2.type = o_imm;
        insn.Op2.value = insn.get_next_byte();
        break;
      case 0x08:                // mov
        if ( nibble0 == 4 )
        {
          insn.itype = I51_div;
          insn.Op1.type = o_reg;
          insn.Op1.reg = rAB;
          break;
        }
        operand2(insn, nibble0);
        insn.Op1.type = o_mem;
        insn.Op1.addr = insn.get_next_byte();
        break;
      case 0x0A:                // mov
        if ( nibble0 == 4 )
        {
          insn.itype = I51_mul;
          insn.Op1.type = o_reg;
          insn.Op1.reg = rAB;
          break;
        }
        if ( nibble0 == 5 )
          return 0;   // mov to imm - no sense (0xA5)
        operand1(insn, nibble0);
        insn.Op2.type = o_mem;
        insn.Op2.addr = insn.get_next_byte();
        break;
      case 0x0B:                // cjne
        if ( nibble0 == 5 )
        {
          opAcc(insn.Op1);
          insn.Op2.type = o_mem;
          insn.Op2.addr = insn.get_next_byte();
        }
        else
        {
          operand1(insn, nibble0);
          insn.Op2.offb  = (uchar)insn.size;
          insn.Op2.type  = o_imm;
          insn.Op2.value = insn.get_next_byte();
        }
        insn.Op3.type = o_near;
        off = insn.get_next_byte();
        insn.Op3.addr = truncate(insn.ip + insn.size + off);  // signed addition
        insn.Op3.dtype = dt_word;
        break;
      case 0x0D:                // djnz
        switch ( nibble0 )
        {
          case 4:
            insn.itype = I51_da;
            opAcc(insn.Op1);
            break;
          case 6: case 7:
            insn.itype = I51_xchd;
            opAcc(insn.Op1);
            operand2(insn, nibble0);
            break;
          default:
            operand1(insn, nibble0);
            off = insn.get_next_byte();
            insn.Op2.type = o_near;
            insn.Op2.addr = truncate(insn.ip + insn.size + off); // signed addition
            insn.Op2.dtype = dt_word;
            break;
        }
        break;
      case 0x0E:                // mov
        opAcc(insn.Op1);
        if ( nibble0 == 4 )
        {
          insn.itype = I51_clr;
          break;
        }
        operand2(insn, nibble0);
        break;
      case 0x0F:                // mov
        if ( nibble0 == 4 )
        {
          insn.itype = I51_cpl;
          opAcc(insn.Op1);
          break;
        }
        operand1(insn, nibble0);
        insn.Op2.type = o_reg;
        insn.Op2.reg = rAcc;
        break;
    }
  }
  return insn.size;
}

//----------------------------------------------------------------------
// analyze an instruction
int i51_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  insn.Op1.dtype = dt_byte;
  insn.Op2.dtype = dt_byte;
  insn.Op3.dtype = dt_byte;

  uchar code = get_byte(insn.ea);
  switch ( ptype )
  {
    case prc_51:
    case prc_51mx:
      return ana_basic(insn);

    case prc_251_src:
    case prc_930_src:
      if ( code == 0xA5 )
      {
        insn.size++;             // skip A5
        code = get_byte(insn.ea+1);
        if ( (code & 15) < 6 )
          return 0;
        return ana_basic(insn);
      }
      if ( (code & 15) < 6 )
        return ana_basic(insn);
      return ana_extended(insn);

    case prc_251_bin:
    case prc_930_bin:
      if ( code == 0xA5 )
      {
        insn.size++;             // skip A5
        return ana_extended(insn);
      }
      return ana_basic(insn);
  }
  return 0;   //lint !e527 statement is unreachable
}
