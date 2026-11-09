/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"

static int ana_basic(insn_t &insn);

//----------------------------------------------------------------------
inline int ua_next_word_be(insn_t &insn)
{
  int32 result;
  result = ((uchar)insn.get_next_byte()) << 8;
  result += (uchar)insn.get_next_byte();
  return (int)result;
}

//----------------------------------------------------------------------
inline void opC(op_t &op)
{
  op.type = o_reg;
  op.reg = rC;
}

//----------------------------------------------------------------------
// register direct
static int op_rd(op_t &x, int reg, int dtype)
{
  x.type = o_reg;
  x.dtype = uchar(dtype);
  x.reg = uint16((dtype == dt_byte ? rR0L : rR0) + reg);
  return 1;
}

//----------------------------------------------------------------------
// register indirect
static int op_ph(op_t &x, uint16 phrase, int reg, int dtype)
{
  x.type = o_phrase;
  x.dtype = uchar(dtype);
  x.phrase = phrase; // union with x.reg
  x.indreg = (uchar)reg;
  if ( (phrase != fRlistL) && (phrase != fRlistH) )
    x.indreg += rR0;
  return 1;
}

//----------------------------------------------------------------------
// register indirect with displacement
static int op_ds(op_t &x, uint16 phrase, int ireg, sval_t disp, int dtype)
{
  if ( disp > 0xFD00 )
    disp = disp - 0x10000; // heuristics: treat large values from -300h as negative
  x.type = o_displ;
  x.dtype = uchar(dtype);
  x.phrase = phrase;
  x.indreg = rR0 + (uchar)ireg;
  x.addr = disp;
  return 1;
}

//----------------------------------------------------------------------
inline void op_mm(op_t &x, uval_t addr, int dtype)
{
  x.type = o_mem;
  x.dtype = uchar(dtype);
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_rel(const insn_t &insn, op_t &x, sval_t addr)
{
  if ( addr > 32767 )
    addr -= 0x10000;
  x.type = o_near;
  x.dtype = dt_code;
  x.addr = (insn.ip + insn.size + 2*addr) & ~1;
}

//----------------------------------------------------------------------
inline void op_near(op_t &x, uval_t addr)
{
  x.type = o_near;
  x.dtype = dt_word;
  x.addr = addr;
}

//----------------------------------------------------------------------
inline void op_im(op_t &x, uval_t value, int dtype)
{
  x.type = o_imm;
  x.dtype = uchar(dtype);
  x.value = value;
}

//----------------------------------------------------------------------
inline void op_bit(op_t &x, int type, uval_t addr)
{
  x.type = optype_t(type);
  x.dtype = dt_word;
  x.addr = addr;
}

//----------------------------------------------------------------------
// analyze an basic instruction
static int ana_basic(insn_t &insn)
{

  static const nameNum xa_basic[16] =
  {
    XA_add, XA_addc, XA_sub,  XA_subb, XA_cmp,  XA_and,  XA_or,   XA_xor,
    XA_mov, XA_null, XA_null, XA_null, XA_null, XA_null, XA_null, XA_null,
  };

  static const nameNum xa_branches[16] =
  {
    XA_bcc, XA_bcs, XA_bne, XA_beq, XA_bnv, XA_bov, XA_bpl, XA_bmi,
    XA_bg,  XA_bl,  XA_bge, XA_blt, XA_bgt, XA_ble, XA_br,  XA_bkpt,
  };

  static const nameNum xa_pushpop[] =
  {
    XA_push, XA_pushu, XA_pop, XA_popu,
  };

  static const nameNum xa_bitops[] =
  {
    XA_clr, XA_setb, XA_mov, XA_mov, XA_anl, XA_anl, XA_orl, XA_orl,
  };

  static const nameNum xa_Jxx[] =
  {
    XA_jb, XA_jnb, XA_jbc, XA_null,
  };

  static const nameNum xa_misc[] =
  {
    XA_da, XA_sext, XA_cpl, XA_neg,
  };

  static const nameNum xa_shifts[] =
  {
    XA_lsr, XA_asl, XA_asr, XA_norm,
  };

  ushort code = insn.get_next_byte();

  ushort nibble0 = (code & 0xF);
  ushort nibble1 = (code >> 4);
  signed char off;
  int size = 0;
  ushort b1;

  if ( nibble1 <= 0xB )
  {
    switch ( nibble0 & 0x7 )
    {
      case 0: // Specials
      case 7: // dtto
        switch ( code )
        {
          case 0x00: // 00 - NOP
            insn.itype = XA_nop;
            break;

          case 0x07: // PUSH.B Rlist
          case 0x0F: // PUSH.W Rlist
          case 0x17: // PUSHU.B Rlist
          case 0x1F: // PUSHU.W Rlist
          case 0x27: // POP.B Rlist
          case 0x2F: // POP.W Rlist
          case 0x37: // POPU.B Rlist
          case 0x3F: // POPU.W Rlist
          case 0x47: // PUSH.B Rlist
          case 0x4F: // PUSH.W Rlist
          case 0x57: // PUSHU.B Rlist
          case 0x5F: // PUSHU.W Rlist
          case 0x67: // POP.B Rlist
          case 0x6F: // POP.W Rlist
          case 0x77: // POPU.B Rlist
          case 0x7F: // POPU.W Rlist
            size = (nibble0 < 8) ? dt_byte : dt_word;
            b1 = insn.get_next_byte(); // Rlist
            insn.itype = xa_pushpop[nibble1 & 3];
            if ( nibble1 & 4 ) // High
              op_ph(insn.Op1, fRlistH, b1, size);
            else
              op_ph(insn.Op1, fRlistL, b1, size);
            break;

          case 0x08: // 08 - misc
            b1 = insn.get_next_byte();
            switch ( b1 & 0xfc )
            {
              case 0x00: // CLR
              case 0x10: // SETB
                insn.itype = xa_bitops[(b1>>4) & 7];
                op_bit(insn.Op1, o_bit, ((b1&3)<<8) + (uchar)insn.get_next_byte());
                break;
              case 0x20: // MOV C,bit
                insn.itype = xa_bitops[(b1>>4) & 7];
                opC(insn.Op1);
                op_bit(insn.Op2, o_bit, ((b1&3)<<8) + (uchar)insn.get_next_byte());
                break;
              case 0x30: // MOV bit,C
                insn.itype = xa_bitops[(b1>>4) & 7];
                op_bit(insn.Op1, o_bit, ((b1&3)<<8) + (uchar)insn.get_next_byte());
                opC(insn.Op2);
                break;
              case 0x40: // ANL C, bit
              case 0x50: // ANL C, /bit
              case 0x60: // ORL C, bit
              case 0x70: // ORL C, /bit
                insn.itype = xa_bitops[(b1>>4) & 7];
                opC(insn.Op1);
                op_bit(insn.Op2,
                  (b1&0x10)?o_bitnot:o_bit, ((b1&3)<<8) + (uchar)insn.get_next_byte());
                break;
              default: // undefined
                return 0;
            }
            break;

          case 0x40: // LEA
          case 0x48: // LEA
            insn.itype = XA_lea;
            b1 = insn.get_next_byte();
            if ( b1 & 0x88 )
              return 0;
            op_rd(insn.Op1, b1>>4, dt_word);
            if ( code & 0x8 ) // 16bit offset
              op_ds(insn.Op2, fRid16, b1&0x07, (int32)ua_next_word_be(insn), dt_word);
            else
              op_ds(insn.Op2, fRid8, b1&0x07, (signed char)insn.get_next_byte(), dt_word);
            break;

          case 0x50: // XCH.B Rd,[Rs]
          case 0x58: // XCH.W Rd,[Rs]
          case 0x60: // XCH.B Rd,Rs
          case 0x68: // XCH.W Rd,Rs
            insn.itype = XA_xch;
            size = (nibble0 < 8) ? dt_byte : dt_word;
            b1 = insn.get_next_byte();
            op_rd(insn.Op1, b1>>4, size);
            switch ( nibble1 )
            {
              case 0x5: // Rd,[Rs]
                if ( b1 & 8 )
                  return 0;
                op_ds(insn.Op2, fRi, b1&7, 0, size);
                break;
              case 0x6: // Rd,Rs
                op_rd(insn.Op2, b1&0xf, size);
                break;
            }
            break;

          case 0x80: // MOVC
          case 0x88: // MOVC
            b1 = insn.get_next_byte();
            size = (nibble0 < 8) ? dt_byte : dt_word;
            if ( b1 & 8 )
              return 0;
            insn.itype = XA_movc;
            op_rd(insn.Op1, b1>>4, size);
            op_ph(insn.Op2, fRip, b1&7, size);
            break;

          case 0x87: // DJNZ Rd, rel8
          case 0x8F: // POP, POPU, PUSH, PUSHU direct
            b1 = insn.get_next_byte();
            size = (nibble0 < 8) ? dt_byte : dt_word;
            if ( b1 & 8 ) // DJNZ
            {
              if ( b1 & 7 )
                return 0;
              insn.itype = XA_djnz;
              op_rd(insn.Op1, b1>>4, size);
              op_rel(insn, insn.Op2, (signed char)insn.get_next_byte());
            }
            else
            { // POP, POPU, PUSH, PUSHU
              if ( b1 & 0xc0 )
                return 0;
              insn.itype = xa_pushpop[3-((b1>>4)&3)];
              op_mm(insn.Op1, ((b1 & 7) << 8) + insn.get_next_byte(), size);
            }
            break;

          case 0x90: // CPL, DA, SEXT
          case 0x98: // CPL & MOV [Rd+], [Rs+] & MOV direct, [Rs]
            b1 = insn.get_next_byte();
            size = (nibble0 < 8) ? dt_byte : dt_word;
            switch ( b1 & 0x0f )
            {
              case 0x0: // MOV [Rd+], [Rs+]
              case 0x1:
              case 0x2:
              case 0x3:
              case 0x4:
              case 0x5:
              case 0x6:
              case 0x7: // MOV [Rd+], [Rs+]
                if ( b1 & 0x80 )
                  return 0;
                insn.itype = XA_mov;
                op_ph(insn.Op1, fRip, (b1>>4)&7, size);
                op_ph(insn.Op2, fRip, (b1&7), size);
                break;

              case 0x8: // DA
              case 0x9: // SEXT
              case 0xA: // CPL
              case 0xB: // NEG
                insn.itype = xa_misc[b1&3];
                op_rd(insn.Op1, b1>>4, size);
                if ( (nibble0&8) != 0 && insn.itype == XA_da )
                  return 0;
                break;

              case 0xC: // MOVC A,[A+PC] 904C
                if ( (nibble0 != 0) & ((b1&0xf0) != 0xc0) )
                  return 0;
                insn.itype = XA_movc;
                op_rd(insn.Op1, rA, dt_byte);
                op_ph(insn.Op2, fApc, 0, dt_byte);
                break;

              case 0xE: // MOVC A,[A+DPTR] 904E
                if ( (nibble0 != 0) & ((b1&0xf0) != 0xc0) )
                  return 0;
                insn.itype = XA_movc;
                op_rd(insn.Op1, rA, dt_byte);
                op_ph(insn.Op2, fAdptr, 0, dt_byte);
                break;

              case 0xF: // MOV Rd,USP & MOV USP, Rs
                insn.itype = XA_mov;
                if ( nibble0&8 ) // USP,Rs
                {
                  op_rd(insn.Op1, rUSP-rR0, dt_word);
                  op_rd(insn.Op2, b1>>4, dt_word);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, dt_word);
                  op_rd(insn.Op2, rUSP-rR0, dt_word);
                }
                break;

              default:
                return 0;
            }
            break;

          case 0x97: // {JB,JBC,JNB} bit, rel8 & MOV direct, direct
          case 0x9F: // {JB,JBC,JNB} bit, rel8 & MOV direct, direct
            b1 = insn.get_next_byte();
            if ( (b1 & 0x88) == 0x00 ) // MOV direct, direct
            {
              insn.itype = XA_mov;
              size = (nibble0 < 8) ? dt_byte : dt_word;
              op_mm(insn.Op1, ((b1 & 0x70) << 4) + (uchar)insn.get_next_byte(), size);
              op_mm(insn.Op2, ((b1 & 0x7) << 8) + (uchar)insn.get_next_byte(), size);
            }
            else
            {
              if ( nibble0 & 8 )
                return 0;
              switch ( b1 & 0xfc )
              {
                case 0x80: // JB
                case 0xA0: // JNB
                case 0xC0: // JBC
                  insn.itype = xa_Jxx[(b1>>5)&3];
                  op_bit(insn.Op1, o_bit, ((b1&3)<<8) + (uchar)insn.get_next_byte());
                  op_rel(insn, insn.Op2, (signed char)insn.get_next_byte());
                  break;
                default:
                  return 0;
              }
            }
            break;

          case 0xA0: // MOV.B direct, [Rs] & [Rd], direct & XCH
          case 0xA8: // MOV.W direct, [Rs] & [Rd], direct & XCH
            b1 = insn.get_next_byte();
            size = (nibble0 < 8) ? dt_byte : dt_word;
            if ( b1 & 8 ) // XCH
            {
              insn.itype = XA_xch;
              op_rd(insn.Op1, b1>>4, size);
              op_mm(insn.Op2, ((b1 & 7) << 8) + (uchar)insn.get_next_byte(), size);
            }
            else
            { // MOV
              insn.itype = XA_mov;
              if ( b1 & 0x80 ) // direct, [Rs]
              {
                op_mm(insn.Op1, ((b1 & 7) << 8) + (uchar)insn.get_next_byte(), size);
                op_ds(insn.Op2, fRi, (b1>>4)&7, 0, size);
              }
              else
              {
                op_ds(insn.Op1, fRi, (b1>>4)&7, 0, size);
                op_mm(insn.Op2, ((b1 & 7) << 8) + (uchar)insn.get_next_byte(), size);
              }
            }
            break;

          case 0xA7: // MOVX
          case 0xAF: // MOVX
            insn.itype = XA_movx;
            size = (nibble0 < 8) ? dt_byte : dt_word;
            b1 = insn.get_next_byte();
            if ( b1 & 8 ) // [Rd],Rs
            {
              op_ds(insn.Op1, fRi, b1&0x7, 0, size);
              op_rd(insn.Op2, b1>>4, size);
            }
            else
            { // Rd,[Rs]
              op_rd(insn.Op1, b1>>4, size);
              op_ds(insn.Op2, fRi, b1&0x7, 0, size);
            }
            break;

          case 0xB0: // RR
          case 0xB7: // RRC
          case 0xB8: // RR
          case 0xBF: // RRC
            insn.itype = (nibble0 & 7) ? XA_rrc : XA_rr;
            size = (nibble0 < 8) ? dt_byte : dt_word;
            b1 = insn.get_next_byte();
            op_rd(insn.Op1, b1>>4, size);
            op_im(insn.Op2, b1&0xf, size);
            break;

          default:
            return 0;
        }
        break;

      default:
        switch ( nibble1 )
        {
          case 0: // ADD
          case 1: // ADDC
          case 2: // SUB
          case 3: // SUBB
          case 4: // CMP
          case 5: // AND
          case 6: // OR
          case 7: // XOR
          case 8: // MOV
            insn.itype = xa_basic[nibble1];
            size = (nibble0 < 8) ? dt_byte : dt_word;
            b1 = insn.get_next_byte();
            switch ( nibble0 & 0x7 )
            {
              case 0x1: // OP Rd,Rs
                op_rd(insn.Op1, b1>>4, size);
                op_rd(insn.Op2, b1&0xF, size);
                break;

              case 0x2: // OP Rd,[Rs]
                if ( b1 & 8 ) // [Rd], Rs
                {
                  op_ds(insn.Op1, fRi, b1&7, 0, size);
                  op_rd(insn.Op2, b1>>4, size);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, size);
                  op_ds(insn.Op2, fRi, b1&7, 0, size);
                }
                break;

              case 0x3: // OP Rd,[Rs+]
                if ( b1 & 8 ) // [Rd], Rs
                {
                  op_ph(insn.Op1, fRip, (b1&7), size);
                  op_rd(insn.Op2, b1>>4, size);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, size);
                  op_ph(insn.Op2, fRip, (b1&7), size);
                }
                break;

              case 0x4: // OP Rd,[Rs+o8]
                if ( b1 & 8 ) // [Rd], Rs
                {
                  op_ds(insn.Op1, fRid8, (b1&7), (signed char)insn.get_next_byte(), size);
                  op_rd(insn.Op2, b1>>4, size);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, size);
                  op_ds(insn.Op2, fRid8, (b1&7), (signed char)insn.get_next_byte(), size);
                }
                break;

              case 0x5: // OP Rd,[Rs+o16]
                if ( b1 & 8 ) // [Rd], Rs
                {
                  op_ds(insn.Op1, fRid16, (b1&7), (int)ua_next_word_be(insn), size);
                  op_rd(insn.Op2, b1>>4, size);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, size);
                  op_ds(insn.Op2, fRid16, (b1&7), (int)ua_next_word_be(insn), size);
                }
                break;

              case 0x6: // OP Rd,direct
                if ( b1 & 8 ) // direct, Rs
                {
                  op_mm(insn.Op1, ((b1 & 7) << 8) + insn.get_next_byte(), size);
                  op_rd(insn.Op2, b1>>4, size);
                }
                else
                {
                  op_rd(insn.Op1, b1>>4, size);
                  op_mm(insn.Op2, ((b1 & 7) << 8) + insn.get_next_byte(), size);
                }
                break;
            }
            break;

          case 9: // Immediate operations
            b1 = insn.get_next_byte();
            insn.itype = xa_basic[b1 & 0x0f];
            size = (nibble0 < 8) ? dt_byte : dt_word;
            switch ( nibble0 & 0x7 )
            {
              case 0x1:
                op_rd(insn.Op1, b1>>4, size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;

              case 0x2:
                op_ds(insn.Op1, fRi, (b1>>4) & 0x7, 0, size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;

              case 0x3:
                op_ph(insn.Op1, fRip, (b1>>4) & 0x7, size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;

              case 0x4:
                op_ds(insn.Op1, fRid8, (b1>>4) & 0x7, (signed char)insn.get_next_byte(), size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;

              case 0x5:
                op_ds(insn.Op1, fRid16, (b1>>4) & 0x7, (int)ua_next_word_be(insn), size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;

              case 0x6:
                op_mm(insn.Op1, (((b1>>4) & 0x7) << 8) + insn.get_next_byte(), size);
                op_im(insn.Op2, (size == dt_byte) ? insn.get_next_byte() : ua_next_word_be(insn), size);
                break;
            }
            break;

          case 0xA: // ADDS
          case 0xB: // MOVS
            b1 = insn.get_next_byte();
            insn.itype = (nibble1 == 0x0A) ? XA_adds : XA_movs;
            size = (nibble0 < 8) ? dt_byte : dt_word;
            off = b1 & 0xf;
            if ( off > 7 )
              off -= 16;
            op_im(insn.Op2, (int32)off, size);
            switch ( nibble0 & 0x7 )
            {
              case 0x1:
                op_rd(insn.Op1, b1>>4, size);
                break;

              case 0x2:
                op_ds(insn.Op1, fRi, (b1>>4) & 0x7, 0, size);
                break;

              case 0x3:
                op_ph(insn.Op1, fRip, (b1>>4) & 0x7, size);
                break;

              case 0x4:
                op_ds(insn.Op1, fRid8, (b1>>4) & 0x7, (signed char)insn.get_next_byte(), size);
                break;

              case 0x5:
                op_ds(insn.Op1, fRid16, (b1>>4) & 0x7, (int)ua_next_word_be(insn), size);
                break;

              case 0x6:
                op_mm(insn.Op1, (((b1>>4) & 0x7) << 8) + (uchar)insn.get_next_byte(), size);
                break;
            }
            break;
        }
    }
  }
  else
  { // nibble1 > B
    switch ( nibble1 )
    {
      case 0xC: // Shifts, CALL, FCALL
        switch ( nibble0 & 0xc )
        {
          case 0x0:
            size = dt_byte;
            break;
          case 0x8:
            size = dt_word;
            break;
          case 0xC:
            size = dt_dword;
            break;
          case 0x4: // Special instructions
            switch ( nibble0 )
            {
              case 4: // FCALL addr24
                insn.itype = XA_fcall;
                insn.Op1.type = o_far;
                insn.Op1.dtype = dt_code;
                insn.Op1.addr = (ushort)ua_next_word_be(insn);
                insn.Op1.specval = (uchar)insn.get_next_byte();
                break;
              case 5: // CALL rel16
                insn.itype = XA_call;
                op_rel(insn, insn.Op1, (int)ua_next_word_be(insn));
                break;
              case 6: // CALL [Rs]
                b1 = insn.get_next_byte();
                if ( b1 & 0xf8 )
                  return 0;
                insn.itype = XA_call;
                op_ds(insn.Op1, fRi, b1&7, 0, dt_word);
                break;
              default:
                return 0;
            }
            break;
        }
        if ( insn.itype == XA_null )
        {
          insn.itype = xa_shifts[nibble0 & 3];
          b1 = insn.get_next_byte();
          op_rd(insn.Op1, b1>>4, size);
          op_rd(insn.Op2, b1&0xf, size);
        }
        break;

      case 0xD: // JMP, FJMP, rotations & shifts with #d4/#d5
        switch ( nibble0 & 0xC )
        {
          case 0x4: // Special instructions
            switch ( nibble0 )
            {
              case 7: // rotate
                break;
              case 4: // FJMP addr24
                insn.itype = XA_fjmp;
                insn.Op1.type = o_far;
                insn.Op1.dtype = dt_code;
                insn.Op1.addr = (ushort)ua_next_word_be(insn);
                insn.Op1.specval = (uchar)insn.get_next_byte();
                break;
              case 5: // JMP rel16
                insn.itype = XA_jmp;
                op_rel(insn, insn.Op1, (int)ua_next_word_be(insn));
                break;
              case 6: // specials
                insn.itype = XA_jmp;
                b1 = insn.get_next_byte();
                switch ( b1 & 0xf8 )
                {
                  case 0x10: // RESET
                    if ( b1 & 7 )
                      return 0;
                    insn.itype = XA_reset;
                    break;
                  case 0x30: // TRAP
                  case 0x38: // TRAP
                    insn.itype = XA_trap;
                    op_im(insn.Op1, b1 & 0xf, dt_byte);
                    break;
                  case 0x40: // JMP [A+DPTR]
                    if ( (b1&7) != 6 )
                      return 0;
                    op_ph(insn.Op1, fAdptr, 0, dt_word);
                    break;
                  case 0x60: // JMP [[Rs+]]
                    op_ph(insn.Op1, fRipi, b1&7, dt_word);
                    break;
                  case 0x70: // JMP [Rs]
                    op_ph(insn.Op1, fRi, b1&7, dt_word);
                    break;
                  case 0x80: // RET
                    if ( b1 & 7 )
                      return 0;
                    insn.itype = XA_ret;
                    break;
                  case 0x90: // RETI
                    if ( b1 & 7 )
                      return 0;
                    insn.itype = XA_reti;
                    break;
                  default:
                    return 0;
                }
                break;
              default:
                return 0;
            }
            break;

          case 0x0:
            size = dt_byte;
            break;

          case 0x8:
            size = dt_word;
            break;

          case 0xC:
            size = dt_dword;
            break;
        }
        if ( insn.itype == XA_null )
        {
          insn.itype = xa_shifts[nibble0 & 3];
          if ( insn.itype == XA_norm )
          { // rotations
            size = (nibble0 < 8) ? dt_byte : dt_word;
            insn.itype = (nibble0 & 4) ? XA_rlc : XA_rl;
            b1 = insn.get_next_byte();
            op_rd(insn.Op1, b1>>4, size);
            op_im(insn.Op2, b1&0xf, size);
          }
          else
          { // shifts
            b1 = insn.get_next_byte();
            if ( size == dt_dword )
            {
              op_rd(insn.Op1, (b1>>4)&0x0e, size); // Only even registers allowed
              op_im(insn.Op2, b1&0x1f, size);
            }
            else
            {
              op_rd(insn.Op1, b1>>4, size);
              op_im(insn.Op2, b1&0xf, size);
            }
          }
        }
        break;

      case 0xE: // DIV & MUL & cjne & jz/jnz
        b1 = insn.get_next_byte();
        switch ( nibble0 )
        {
          case 0x0: // MULU.B Rd,Rs
            insn.itype = XA_mulu;
            op_rd(insn.Op1, b1>>4, dt_byte);
            op_rd(insn.Op2, b1&0xf, dt_byte);
            break;
          case 0x1: // DIVU.B Rd,Rs
            insn.itype = XA_divu;
            op_rd(insn.Op1, b1>>4, dt_byte);
            op_rd(insn.Op2, b1&0xf, dt_byte);
            break;
          case 0x4: // MULU.W Rd,Rs
            insn.itype = XA_mulu;
            op_rd(insn.Op1, b1>>4, dt_word);
            op_rd(insn.Op2, b1&0xf, dt_word);
            break;
          case 0x5: // DIVU.W Rd,Rs
            insn.itype = XA_divu;
            op_rd(insn.Op1, b1>>4, dt_word);
            op_rd(insn.Op2, b1&0xf, dt_word);
            break;
          case 0x6: // MUL.W Rd,Rs
            insn.itype = XA_mul;
            op_rd(insn.Op1, b1>>4, dt_word);
            op_rd(insn.Op2, b1&0xf, dt_word);
            break;
          case 0x7: // DIV.W Rd, Rs
            insn.itype = XA_div;
            op_rd(insn.Op1, b1>>4, dt_word);
            op_rd(insn.Op2, b1&0xf, dt_word);
            break;
          case 0x8: // MUL & DIV Rd,#8
            switch ( b1 & 0xf )
            {
              case 0x0: // MULU.B Rd,#d8
                insn.itype = XA_mulu;
                size = dt_byte;
                break;
              case 0x1: // DIVU.B Rd,#d8
                insn.itype = XA_divu;
                size = dt_byte;
                break;
              case 0x3: // DIVU.W Rd,#d8
                insn.itype = XA_divu;
                size = dt_word;
                break;
              case 0xB: // DIV.W Rd,#d8
                insn.itype = XA_div;
                size = dt_word;
                break;
              default:
                return 0;
            }
            op_rd(insn.Op1, b1>>4, size);
            op_im(insn.Op2, insn.get_next_byte(), dt_word);
            break;
          case 0x9: // MUL & DIV Rd,#16
            switch ( b1 & 0xf )
            {
              case 0x0: // MULU.W Rd,#d16
                insn.itype = XA_mulu;
                size = dt_word;
                break;
              case 0x1: // DIVU.D Rd,#d16
                if ( b1&0x10 )
                  return 0;
                insn.itype = XA_divu;
                size = dt_dword;
                break;
              case 0x8: // MUL.W Rd,#d16
                insn.itype = XA_mul;
                size = dt_word;
                break;
              case 0x9: // DIV.D Rd,#d16
                if ( b1&0x10 )
                  return 0;
                insn.itype = XA_div;
                size = dt_dword;
                break;
              default:
                return 0;
            }
            op_rd(insn.Op1, b1>>4, size);
            op_im(insn.Op2, ua_next_word_be(insn), dt_byte);
            break;
          case 0xD: // DIVU.D Rd,Rs
            if ( b1&0x10 )
              return 0;
            insn.itype = XA_divu;
            op_rd(insn.Op1, b1>>4, dt_dword);
            op_rd(insn.Op2, b1&0xf, dt_dword);
            break;
          case 0xF: // DIV.D Rd, Rs
            if ( b1&0x10 )
              return 0;
            insn.itype = XA_div;
            op_rd(insn.Op1, b1>>4, dt_dword);
            op_rd(insn.Op2, b1&0xf, dt_dword);
            break;
          case 0x2: // cjne direct & [Rd] & DJNZ direct
          case 0xA: // cjne direct & [Rd] & DJNZ direct
            size = (nibble0 < 8) ? dt_byte : dt_word;
            if ( b1 & 8 )
            { // DJNZ direct, rel8
              insn.itype = XA_djnz;
              op_mm(insn.Op1, ((b1&7)<<8)+(uchar)insn.get_next_byte(), size);
              op_rel(insn, insn.Op2, (signed char)insn.get_next_byte());
            }
            else
            { // CJNE.s Rd, direct, rel8
              insn.itype = XA_cjne;
              op_rd(insn.Op1, b1>>4, size);
              op_mm(insn.Op2, ((b1&7)<<8)+(uchar)insn.get_next_byte(), size);
              op_rel(insn, insn.Op3, (signed char)insn.get_next_byte());
            }
            break;
          case 0x3: // cjne #,rel
          case 0xB: // cjne #,rel
            if ( b1 & 7 )
              return 0;
            insn.itype = XA_cjne;
            size = (nibble0 < 8) ? dt_byte : dt_word;
            off = insn.get_next_byte();
            if ( b1 & 0x8 )
              op_ds(insn.Op1, fRi, b1>>4, 0, size);
            else
              op_rd(insn.Op1, b1>>4, size);
            op_im(insn.Op2, size == dt_byte ? insn.get_next_byte() : ua_next_word_be(insn), size);
            op_rel(insn, insn.Op3, off);
            break;
          case 0xC: // JZ rel8
            insn.itype = XA_jz;
            op_rel(insn, insn.Op1, (signed char)b1);
            break;
          case 0xE: // JNZ rel8
            insn.itype = XA_jnz;
            op_rel(insn, insn.Op1, (signed char)b1);
            break;
          default:
            return 0;
        }
        break;

      case 0xF: // Bxx
        insn.itype = xa_branches[nibble0];
        if ( nibble0 != 0xF )
        {
          op_rel(insn, insn.Op1, (signed char)insn.get_next_byte());
        }
        break;
    }
  }
  return insn.size;
}

//----------------------------------------------------------------------
// analyze an instruction
int xa_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  insn.itype = XA_null;
  insn.Op1.dtype = dt_byte;
  insn.Op2.dtype = dt_byte;
  insn.Op3.dtype = dt_byte;

  switch ( ptype )    //-V785 Constant expression in switch statement
  {
    case prc_xaG3:
      return ana_basic(insn);
  }
  return 0;   //lint !e527 statement is unreachable
}
