/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Texas Instruments's TMS5320C54
 *
 */

#include "tms320c54.hpp"
#include <segregs.hpp>

//--------------------------------------------------------------------------
static int get_signed(int byte, int mask)
{
  int bits = mask >> 1;
  int sign = bits + 1;
  if ( byte & sign ) // offset < 0
  {
    byte = ( byte & bits ) - sign;
  }
  else // offset >= 0
  {
    byte = byte & mask;
  }
  return byte;
}

//--------------------------------------------------------------------------
static void op_reg_word(insn_t &insn, int op, ushort reg)
{
  if ( op <= 3 )
  {
    insn.ops[op-1].type  = o_reg;
    insn.ops[op-1].dtype = dt_byte;
    insn.ops[op-1].reg   = reg;
  }
  else
  {
    insn.Op4_type = o_reg;
    insn.Op4_value = (uchar)reg;
  }
}

//--------------------------------------------------------------------------
static void op_bit(op_t &op, char value, bool NoCardinal = true)
{
  op.type  = o_bit;
  op.dtype = dt_byte;
  op.value = value;
  op.NoCardinal = NoCardinal;
}

//--------------------------------------------------------------------------
static void op_imm(op_t &op, int value, bool Signed = false, bool NoCardinal = false)
{
  op.type  = o_imm;
  op.dtype = dt_byte;
  op.value = value;
  op.Signed = Signed;
  op.NoCardinal = NoCardinal;
}

//--------------------------------------------------------------------------
static void op_mem(insn_t &insn, op_t &op, char dtype, int byte, bool mmr = false)
{
  op.dtype = dtype;
  if ( (byte & 0x80) == 0 ) // Direct addressing mode
  {
    op.addr = byte & 0x7F;
    if ( !mmr )
    {
      sel_t cpl = get_sreg(insn.ea, CPL);
      if ( cpl == BADSEL )
        cpl = 0;
      if ( !cpl ) // check ST1:CPL
        op.type = o_mem; // use DP
      else
        op.type = o_local; // use SP if CPL is set
    }
    else  // MMR (Memory-Mapped Registers)
      op.type = o_mmr;
  }
  else // Indirect addressing mode
  { // Single-Operand Addressing
    op.type = o_displ;
    op.reg  = AR0 + (byte & 0x07);
    op.IndirectAddressingMOD = (byte>>3) & 0xF;
    if ( op.IndirectAddressingMOD >= 0xC ) // 16-bit long offset (lk)
    {
      if ( !mmr )
      {
        if ( op.IndirectAddressingMOD == ABSOLUTE_INDIRECT_ADRESSING )
          op.type = o_farmem;
        op.addr = get_wide_byte(insn.ea+insn.size);
        insn.size++;
      }
      else // invalide indirect addressing modes (p141)
      {
        insn.itype = TMS320C54_null;
      }
    }
  }
}
#define op_Smem(insn, OP, BYTE) op_mem(insn, OP, dt_byte, BYTE, false)
#define op_MMR(insn, OP, BYTE)  op_mem(insn, OP, dt_byte, BYTE, true)
#define op_Lmem(insn, OP, BYTE) op_mem(insn, OP, dt_word, BYTE, false)

//--------------------------------------------------------------------------
static void op_MMRxy(insn_t &insn, const op_t &op, ushort byte)
{
  byte &= 0x0F;
  if ( byte <= 7 )
    op_reg_word(insn, op.n+1, AR0+byte);
  else
    op_reg_word(insn, op.n+1, SP);
}
#define op_MMRx(insn, OP, BYTE) op_MMRxy(insn, OP, (BYTE)>>4)
#define op_MMRy(insn, OP, BYTE) op_MMRxy(insn, OP, BYTE)


//--------------------------------------------------------------------------
static void op_XYmem(op_t &op, int four)
{
  four &= 0xF;
  op.type = o_displ;
  op.reg  = AR2 + (four & 0x3);
  // map Dual-Operand Indirect Addressing Types to Single-Operand Indirect Addressing Types
  four = (four>>2) & 0x3;
  if ( four < 3 )
    op.IndirectAddressingMOD = (uchar)four;
  else
    op.IndirectAddressingMOD = 11;
}
#define op_Xmem(OP,BYTE) op_XYmem(OP, (BYTE)>>4)
#define op_Ymem(OP,BYTE) op_XYmem(OP, BYTE)

//--------------------------------------------------------------------------
static void op_src_dst(insn_t &insn, int op, int src_dst)
{
  op_reg_word(insn, op, (src_dst & 1) ? B : A);
}

//--------------------------------------------------------------------------
static void op_lk(insn_t &insn, op_t &op)
{
  op_imm(op, get_wide_byte(insn.ea+insn.size), false, false);
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_pmad(insn_t &insn, op_t &op)
{
  op.type  = o_near;
  op.dtype = dt_code;
  op.addr  = get_wide_byte(insn.ea+insn.size);
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_pmad_data(insn_t &insn, op_t &op)
{
  op.type  = o_near;
  op.dtype = dt_byte;            // o_near with dt_byte - rare combination!
  op.addr  = get_wide_byte(insn.ea+insn.size);
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_extpmad(insn_t &insn, op_t &op, int byte)
{
  op.type  = o_far;
  op.dtype = dt_code;
  op.addr  = ((byte & 0x7F) << 16) | get_wide_byte(insn.ea+insn.size);
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_dmad(insn_t &insn, op_t &op)
{
  op.type  = o_farmem;
  op.dtype = dt_byte;
  op.addr  = get_wide_byte(insn.ea+insn.size);
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_PA(insn_t &insn, op_t &op)
{
  op.type  = o_imm;
  op.dtype = dt_byte;
  op.value = get_wide_byte(insn.ea+insn.size);
  op.NoCardinal = true;
  op.IOimm      = true;
  insn.size++;
}

//--------------------------------------------------------------------------
static void op_cond8(insn_t &insn, op_t &op, uchar byte)
{
  if ( get_cond8(byte) == nullptr )
  {
    insn.itype = TMS320C54_null;
    return;
  }
  op.type = o_cond8;
  op.value = byte;
}

//--------------------------------------------------------------------------
static void op_cond8(insn_t &insn, uchar op, uchar byte)
{
  if ( get_cond8(byte) == nullptr )
  {
    insn.itype = TMS320C54_null;
  }
  else if ( op <= 3 && op > 0 )
  {
    op_cond8(insn, insn.ops[op-1], byte);
  }
  else
  {
    insn.Op4_type = o_cond8;
    insn.Op4_value = byte;
  }
}

//--------------------------------------------------------------------------
static void op_cond4(insn_t &insn, op_t &op, uchar quart)
{
  quart &= 0xF;
  // map cond4 to cond8
  op_cond8(insn, op, COND8_FROM_COND4 | quart);
}

//--------------------------------------------------------------------------
static void op_cond2(op_t &op, int cond)
{
  op.type = o_cond2;
  op.value = cond & 0x3;
}

//--------------------------------------------------------------------------
// insn.itype must be set to <op> operands
static void ops_conds(insn_t &insn, uchar op, int byte)
{
  byte &= 0xFF;
  int bits7_6 = (byte >> 6) & 0x3;

  uchar n = 0; // number of operands added
  if ( bits7_6 == 1 ) // Group 1, = 01?? ????
  {
    if ( byte & 0x7 )  // Category A, 01?? ?MMM with MMM != 0
      op_cond8(insn, op+n++, byte & 0xCF); // & 1100 1111
    if ( byte & 0x30 ) // Category B, 01MM ???? with MM != 0
      op_cond8(insn, op+n++, byte & 0xF8); // & 1111 1000
  }
  else if ( bits7_6 == 0 ) // Group 2, = 00?? ????
  {
    if ( byte & 0x30 ) // Category A,     & 0011 0000
      op_cond8(insn, op+n++, byte & 0x30); // & 0011 0000
    if ( byte & 0x0C ) // Category B,     & 0000 1100
      op_cond8(insn, op+n++, byte & 0x0C); // & 0000 1100
    if ( byte & 0x03 ) // Category C,     & 0000 0011
      op_cond8(insn, op+n++, byte & 0x03); // & 0000 0011
  }
  else
    insn.itype = TMS320C54_null;
  if ( insn.itype != TMS320C54_null )
  {
    if ( n == 0 )
      op_cond8(insn, op+n++, COND8_UNC);
    // modify insn.itype
    if ( op-1+n <= 3 )
      insn.itype += n-1;
    else
      insn.itype += 3-op;
  }
}

//--------------------------------------------------------------------------
void ana_TMS320C54(insn_t *_insn)
{
  insn_t &insn = *_insn;
  ushort code = (ushort)get_wide_byte(insn.ea);
  insn.size = 1;

  uchar bits7_0   = code & 0xFF;
  uchar bits4_0   = code & 0x1F;
  uchar bits3_0   = code & 0xF;
  uchar bits2_0   = code & 0x7;
  uchar bits1_0   = code & 0x3;
  bool  bit0      = code & 1;
  uchar bits8_3   = (code >> 3) & 0x3F;
  ushort bits15_4 = code >> 4;
  uchar bits7_4   = bits15_4 & 0xF;
  uchar bits7_5   = bits7_4 >> 1;
  uchar bits6_5   = bits7_5 & 0x3;
  uchar bit7      = bits7_0 >> 7;
  uchar bits15_8  = code >> 8;
  uchar bits11_8  = bits15_8 & 0xF;
  uchar bits9_8   = bits11_8 & 0x3;
  bool  bit8      = bits9_8 & 1;
  uchar bits15_9  = code >> 9;
  uchar bits11_9  = bits15_9 & 0x7;
  uchar bits10_9  = bits11_9 & 0x3;
  bool  bit9      = bits10_9 & 1;
  uchar bits15_10 = code >> 10;
  uchar bits12_10 = bits15_10 & 0x7;
  uchar bits11_10 = bits12_10 & 0x3;
  uchar bits15_12 = code >> 12;

  if ( bits15_8 <= 0x2F ) // <= 0010 11RS
// 0000 000S IAAA AAAA                      ADD Smem, src
// 0000 001S IAAA AAAA                      ADDS Smem, src
// 0000 010S IAAA AAAA                      ADD Smem, TS, src
// 0000 011S IAAA AAAA                      ADDC Smem, src
// 0000 100S IAAA AAAA                      SUB Smem, src
// 0000 101S IAAA AAAA                      SUBS Smem, src
// 0000 110S IAAA AAAA                      SUB Smem, TS, src
// 0000 111S IAAA AAAA                      SUBB Smem, src
// 0001 000D IAAA AAAA                      LD Smem, dst
// 0001 001D IAAA AAAA                      LDU Smem, dst
// 0001 010D IAAA AAAA                      LD Smem, TS, dst
// 0001 011D IAAA AAAA                      LDR Smem, dst
// 0001 100S IAAA AAAA                      AND Smem, src
// 0001 101S IAAA AAAA                      OR Smem, src
// 0001 110S IAAA AAAA                      XOR Smem, src
// 0001 111S IAAA AAAA                      SUBC Smem, src
// 0010 00RD IAAA AAAA                      MPY[R] Smem, dst
// 0010 010D IAAA AAAA                      MPYU Smem, dst
// 0010 011D IAAA AAAA                      SQUR Smem, dst
// 0010 10RS IAAA AAAA                      MAC[R] Smem, src
// 0010 11RS IAAA AAAA                      MAS[R] Smem, src
  {
    static const ushort codes[24] =
    {
      TMS320C54_add2, TMS320C54_adds,  TMS320C54_add3, TMS320C54_addc,
      TMS320C54_sub2, TMS320C54_subs,  TMS320C54_sub3, TMS320C54_subb,
      TMS320C54_ld2,  TMS320C54_ldu,   TMS320C54_ld3,  TMS320C54_ldr,
      TMS320C54_and2, TMS320C54_or2,   TMS320C54_xor2, TMS320C54_subc,
      TMS320C54_mpy2, TMS320C54_mpyr2, TMS320C54_mpyu, TMS320C54_squr,
      TMS320C54_mac2, TMS320C54_macr2, TMS320C54_mas2, TMS320C54_masr2
    };
    insn.itype = codes[bits15_9];
    op_Smem(insn, insn.Op1, code);
    if ( insn.itype != TMS320C54_add3
      && insn.itype != TMS320C54_sub3
      && insn.itype != TMS320C54_ld3 )
    {
      op_src_dst(insn, 2, bit8);
    }
    else
    {
      op_reg_word(insn, 2, TS);
      op_src_dst(insn, 3, bit8);
    }
  }
  else if ( bits15_8 == 0x30 ) // == 0011 0000
  {
// 0011 0000 IAAA AAAA                      LD Smem, T
    insn.itype = TMS320C54_ld2;
    op_Smem(insn, insn.Op1, code);
    op_reg_word(insn, 2, T);
  }
  else if ( bits15_8 == 0x32 ) // == 0011 0010
  {
// 0011 0010 IAAA AAAA                      LD Smem, ASM
    insn.itype = TMS320C54_ld2;
    op_Smem(insn, insn.Op1, code);
    op_reg_word(insn, 2, ASM);
  }
  else if ( bits15_8 <= 0x37 ) // <= 0011 01R1
// 0011 0001 IAAA AAAA                      MPYA Smem
// 0011 0011 IAAA AAAA                      MASA Smem [,B]
// 0011 0100 IAAA AAAA                      BITT Smem
// 0011 0110 IAAA AAAA                      POLY Smem
// 0011 01R1 IAAA AAAA                      MACA[R] Smem [,B]
  {
    static const ushort codes[8] =
    {
      TMS320C54_null, TMS320C54_mpya,  TMS320C54_null, TMS320C54_masa1,
      TMS320C54_bitt, TMS320C54_maca1, TMS320C54_poly, TMS320C54_macar1
    };
    insn.itype = codes[bits11_8];
    if ( insn.itype != TMS320C54_null )
      op_Smem(insn, insn.Op1, code);
  }
  else if ( bits15_8 <= 0x3B ) // <= 0011 101S
// 0011 100S IAAA AAAA                      SQURA Smem, src
// 0011 101S IAAA AAAA                      SQURS Smem, src
  {
    insn.itype = bit9 ? TMS320C54_squrs : TMS320C54_squra;
    op_Smem(insn, insn.Op1, code);
    op_src_dst(insn, 2, bit8);
  }
  else if ( bits15_8 <= 0x45 ) // <= 0100 0101
  {
// 0011 11SD IAAA AAAA                      ADD Smem, 16, src [,dst]
// 0100 00SD IAAA AAAA                      SUB Smem, 16, src [,dst]
// 0100 010D IAAA AAAA                      LD Smem, 16, dst
    static const ushort codes[4] =
    {
      TMS320C54_sub3, TMS320C54_ld3, TMS320C54_null, TMS320C54_add3
    };
    insn.itype = codes[bits11_10];
    if ( insn.itype != TMS320C54_null )
    {
      op_Smem(insn, insn.Op1, code);
      op_bit(insn.Op2, 16);
      if ( insn.itype != TMS320C54_ld3 )
      {
        op_src_dst(insn, 3, bit9);
        if ( bit8 != bit9 )
          op_src_dst(insn, 4, bit8);
      }
      else
        op_src_dst(insn, 3, bit8);
    }
  }
  else if ( bits15_8 == 0x46 ) // <= 0100 0110
  {
// 0100 0110 IAAA AAAA                      LD Smem, DP
    insn.itype = TMS320C54_ld2;
    op_Smem(insn, insn.Op1, code);
    op_reg_word(insn, 2, DP);
  }
  else if ( bits15_8 == 0x47 ) // <= 0100 0111
// 0100 0111 IAAA AAAA                      RPT Smem
  {
    insn.itype = TMS320C54_rpt;
    op_Smem(insn, insn.Op1, code);
  }
  else if ( bits15_8 <= 0x4A ) // <= 0100 1010
// 0100 100D IAAA AAAA                      LDM MMR, dst
// 0100 1010 IAAA AAAA                      PSHM MMR
  {
    insn.itype = bit9 ? TMS320C54_pshm : TMS320C54_ldm;
    op_MMR(insn, insn.Op1, code);
    if ( insn.itype == TMS320C54_ldm )
      op_src_dst(insn, 2, bit8);
  }
  else if ( bits15_8 <= 0x4D ) // <= 0100 1101
// 0100 1011 IAAA AAAA                      PSHD Smem
// 0100 1100 IAAA AAAA                      LTD Smem
// 0100 1101 IAAA AAAA                      DELAY Smem
  {
    static const ushort codes[4] =
    {
      TMS320C54_ltd, TMS320C54_delay, TMS320C54_null, TMS320C54_pshd
    };
    insn.itype = codes[bits9_8];
    if ( insn.itype != TMS320C54_null )
      op_Smem(insn, insn.Op1, code);
  }

  else if ( bits15_8 <= 0x4F ) // <= 0100 111S
// 0100 111S IAAA AAAA                      DST src, Lmem
  {
    insn.itype = TMS320C54_dst;
    op_src_dst(insn, 1, bit8);
    op_Lmem(insn, insn.Op2, code);
  }
  else if ( bits15_8 <= 0x5F ) // <= 0101 111D
// 0101 00SD IAAA AAAA                      DADD Lmem, src [,dst]
// 0101 010S IAAA AAAA                      DSUB Lmem, src
// 0101 011D IAAA AAAA                      DLD Lmem, dst
// 0101 100S IAAA AAAA                      DRSUB Lmem, src
// 0101 101D IAAA AAAA                      DADST Lmem, dst
// 0101 110D IAAA AAAA                      DSUBT Lmem, dst
// 0101 111D IAAA AAAA                      DSADT Lmem, dst
  {
    static const ushort codes[8] =
    {
      TMS320C54_dadd2, TMS320C54_dadd2, TMS320C54_dsub,  TMS320C54_dld,
      TMS320C54_drsub, TMS320C54_dadst, TMS320C54_dsubt, TMS320C54_dsadt
    };
    insn.itype = codes[bits11_9];
    op_Lmem(insn, insn.Op1, code);
    if ( insn.itype != TMS320C54_dadd2 )
    {
      op_src_dst(insn, 2, bit8);
    }
    else
    {
      op_src_dst(insn, 2, bit9);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 3, bit8);
        insn.itype++;
      }
    }
  }
  else if ( bits15_8 <= 0x67 ) // <= 0110 01SD
// 0110 0000 IAAA AAAA 16-bit constant      CMPM Smem, #lk
// 0110 0001 IAAA AAAA 16-bit constant      BITF Smem, #lk
// 0110 001D IAAA AAAA 16-bit constant      MPY Smem, #lk, dst
// 0110 01SD IAAA AAAA 16-bit constant      MAC Smem, #lk, src [,dst]
  {
    static const ushort codes[8] =
    {
      TMS320C54_cmpm, TMS320C54_bitf, TMS320C54_mpy3, TMS320C54_mpy3,
      TMS320C54_mac3, TMS320C54_mac3, TMS320C54_mac3, TMS320C54_mac3
    };
    insn.itype = codes[bits11_8];
    op_Smem(insn, insn.Op1, code);
    op_lk(insn, insn.Op2); // constant always = last word
    if ( insn.itype == TMS320C54_mpy3 )
    {
      op_src_dst(insn, 3, bit8);
    }
    else if ( insn.itype == TMS320C54_mac3 )
    {
      op_src_dst(insn, 3, bit9);
      if ( bit8 != bit9 )
        op_src_dst(insn, 4, bit8);
    }
  }
  else if ( bits15_8 <= 0x6B ) // <= 0110 1011
// 0110 1000 IAAA AAAA 16-bit constant      ANDM #lk, Smem
// 0110 1001 IAAA AAAA 16-bit constant      ORM #lk, Smem
// 0110 1010 IAAA AAAA                      XORM #lk, Smem
// 0110 1011 IAAA AAAA 16-bit constant      ADDM #lk, Smem
  {
    static const ushort codes[4] =
    {
      TMS320C54_andm, TMS320C54_orm, TMS320C54_xorm, TMS320C54_addm
    };
    insn.itype = codes[bits9_8];
    op_Smem(insn, insn.Op2, code);
    op_lk(insn, insn.Op1); // constant always = last word
  }
  else if ( bits15_8 == 0x6D ) // == 0110 1101
// 0110 1101 IAAA AAAA                      MAR Smem
  {
    insn.itype = TMS320C54_mar;
    op_Smem(insn, insn.Op1, code);
  }
  else if ( bits15_8 == 0x6F ) // == 0110 1111
// 0110 1111 IAAA AAAA 0000 110D 010S HIFT  LD Smem [,SHIFT], dst
// 0110 1111 IAAA AAAA 0000 110S 011S HIFT  STH src [,SHIFT], Smem
// 0110 1111 IAAA AAAA 0000 110S 100S HIFT  STL src [,SHIFT], Smem
// 0110 1111 IAAA AAAA 0000 11SD 000S HIFT  ADD Smem [,SHIFT], src [,dst]
// 0110 1111 IAAA AAAA 0000 11SD 001S HIFT  SUB Smem [,SHIFT], src [,dst]
  {
    op_t op;
    op = insn.Op1;
    op_Smem(insn, op, code); // IAAA AAAA/Smem eventual offset must be read before 2nd opcode  byte!
    int code2 = get_wide_byte(insn.ea+insn.size);
    insn.size += 1;
    int mask1 = code2 & 0xFEE0;   //-V537 not misprint
    int mask2 = code2 & 0xFCE0;
    if ( mask1 == 0x0C40 )
      insn.itype = TMS320C54_ld2;
    else if ( mask1 == 0x0C60 )
      insn.itype = TMS320C54_sth2;
    else if ( mask1 == 0x0C80 )
      insn.itype = TMS320C54_stl2;
    else if ( mask2 == 0x0C00 )
      insn.itype = TMS320C54_add2;
    else if ( mask2 == 0x0C20 )
      insn.itype = TMS320C54_sub2;
    else
      insn.itype = TMS320C54_null;
    if ( insn.itype != TMS320C54_null )
    {
      uchar n = 2; // current operand
      uchar shift = (uchar)get_signed(code2, 0x1F);
      if ( shift != 0 )
      {
        op_bit(insn.Op2, shift);
        n++;
        insn.itype++;
      }
      if ( insn.itype == TMS320C54_ld2 || insn.itype == TMS320C54_ld3 )
      {
        op.n = 0;
        insn.Op1 = op; // op_Smem(insn, insn.Op1, code);
        op_src_dst(insn, n, code2>>8);
      }
      else if ( insn.itype == TMS320C54_sth2 || insn.itype == TMS320C54_stl2
             || insn.itype == TMS320C54_sth3 || insn.itype == TMS320C54_stl3 )
      {
        op_src_dst(insn, 1, code2>>8);
        op.n = n-1;
        insn.ops[n-1] = op; // op_Smem(insn, insn.ops[n-1], code);
      }
      else if ( insn.itype == TMS320C54_add2 || insn.itype == TMS320C54_sub2
             || insn.itype == TMS320C54_add3 || insn.itype == TMS320C54_sub3 ) //-V560 is always true: insn.itype == TMS320C54_sub3
      {
        int code2_bit9 = (code2>>9) & 1;
        int code2_bit8 = (code2>>8) & 1;
        op.n = 0;
        insn.Op1 = op; // op_Smem(insn, insn.Op1, code);
        op_src_dst(insn, n, code2_bit9);
        if ( code2_bit8 != code2_bit9 )
        {
          n++;
          op_src_dst(insn, n, code2_bit8);
          if ( n < 4 )
            insn.itype++;
        }
      }
    }
  }
  else if ( (bits15_8 & 0xFD) == 0x6C ) // == 0110 11Z0
// 0110 11Z0 IAAA AAAA 16-bit constant      BANZ[D] pmad, Sind
  {
    insn.itype = bit9 ? TMS320C54_banzd : TMS320C54_banz;
    op_Smem(insn, insn.Op2, code);
    op_pmad(insn, insn.Op1);
    if ( insn.Op2.type == o_mem )
    { // Sind = Smem to code
      insn.Op2.type = o_near;
      insn.Op2.dtype = dt_code;
    }
  }
  else if ( bits15_12 < 0x7 ) // < 0111
    insn.itype = TMS320C54_null;
  else if ( bits15_8 <= 0x73 ) // <= 0111 0000
// 0111 0000 IAAA AAAA 16-bit constant      MVKD dmad, Smem
// 0111 0001 IAAA AAAA 16-bit constant      MVDK Smem, dmad
// 0111 0010 IAAA AAAA 16-bit constant      MVDM dmad, MMR
// 0111 0011 IAAA AAAA 16-bit constant      MVMD MMR, dmad
  {
    static const ushort codes[4] =
    {
      TMS320C54_mvkd, TMS320C54_mvdk, TMS320C54_mvdm, TMS320C54_mvmd
    };
    insn.itype = codes[bits9_8];
    switch ( insn.itype )
    {
      case TMS320C54_mvkd:
        op_Smem(insn, insn.Op2, code);
        op_dmad(insn, insn.Op1);
        break;
      case TMS320C54_mvdk:
        op_Smem(insn, insn.Op1, code);
        op_dmad(insn, insn.Op2);
        break;
      case TMS320C54_mvdm:
        op_dmad(insn, insn.Op1);
        op_MMR(insn, insn.Op2, code);
        break;
      case TMS320C54_mvmd:
        op_MMR(insn, insn.Op1, code);
        op_dmad(insn, insn.Op2);
        break;
    }
  }
  else if ( bits15_8 <= 0x75 ) // <= 0111 0101
// 0111 0100 IAAA AAAA Port address         PORTR PA, Smem
// 0111 0101 IAAA AAAA Port address         PORTW Smem, PA
  {
    insn.itype = bit8 ? TMS320C54_portw : TMS320C54_portr;
    op_Smem(insn, insn.ops[1-bit8], code);
    op_PA(insn, insn.ops[bit8]);
  }
  else if ( bits15_8 <= 0x77 ) // <= 0111 0111
// 0111 0110 IAAA AAAA 16-bit constant      ST #lk, Smem
// 0111 0111 IAAA AAAA 16-bit constant      STM #lk, MMR
  {
    insn.itype = bit8 ? TMS320C54_stm : TMS320C54_st;
    op_mem(insn, insn.Op2, dt_byte, code, bit8);
    op_lk(insn, insn.Op1); // constant always = last word

  }
  else if ( bits15_8 <= 0x7B ) // <= 0111 101S
// 0111 100S IAAA AAAA 16-bit constant      MACP Smem, pmad, src
// 0111 101S IAAA AAAA 16-bit constant      MACD Smem, pmad, src
  {
    insn.itype = bit9 ? TMS320C54_macd : TMS320C54_macp;
    op_Smem(insn, insn.Op1, code);
    op_pmad_data(insn, insn.Op2);
    op_src_dst(insn, 3, bit8);
  }
  else if ( bits15_8 <= 0x7D ) // <= 0111 1101
// 0111 1100 IAAA AAAA 16-bit constant      MVPD pmad, Smem
// 0111 1101 IAAA AAAA 16-bit constant      MVDP Smem, pmad
  {
    insn.itype = bit8 ? TMS320C54_mvdp : TMS320C54_mvpd;
    op_Smem(insn, insn.ops[1-bit8], code);
    op_pmad_data(insn, insn.ops[bit8]);
  }
  else if ( bits15_8 <= 0x7F ) // <= 0111 1111
// 0111 1110 IAAA AAAA                      READA Smem
// 0111 1111 IAAA AAAA                      WRITA Smem
  {
    insn.itype = bit8 ? TMS320C54_writa : TMS320C54_reada;
    op_Smem(insn, insn.Op1, code);
  }
  else if ( bits15_8 <= 0x83 ) // <= 1000 001S
// 1000 000S IAAA AAAA                      STL src, Smem
// 1000 001S IAAA AAAA                      STH src, Smem
  {
    insn.itype = bit9 ? TMS320C54_sth2 : TMS320C54_stl2;
    op_src_dst(insn, 1, bit8);
    op_Smem(insn, insn.Op2, code);
  }
  else if ( bits15_8 <= 0x87 ) // <= 1000 001S
// 1000 010S IAAA AAAA                      STL src, ASM, Smem
// 1000 011S IAAA AAAA                      STH src, ASM, Smem
  {
    insn.itype = bit9 ? TMS320C54_sth3 : TMS320C54_stl3;
    op_src_dst(insn, 1, bit8);
    op_reg_word(insn, 2, ASM);
    op_Smem(insn, insn.Op3, code);
  }

  else if ( bits15_8 <= 0x89 ) // <= 1000 100S
// 1000 100S IAAA AAAA                      STLM src, MMR
  {
    insn.itype = TMS320C54_stlm;
    op_src_dst(insn, 1, bit8);
    op_MMR(insn, insn.Op2, code);
  }
  else if ( bits15_8 == 0x8A ) // == 1000 1010
// 1000 1010 IAAA AAAA                      POPM MMR
  {
    insn.itype = TMS320C54_popm;
    op_MMR(insn, insn.Op1, code);
  }
  else if ( bits15_8 == 0x8B ) // == 1000 1011
// 1000 1011 IAAA AAAA                      POPD Smem
  {
    insn.itype = TMS320C54_popd;
    op_Smem(insn, insn.Op1, code);
  }
  else if ( bits15_8 <= 0x8D ) // <= 1000 1101
// 1000 1100 IAAA AAAA                      ST T, Smem
// 1000 1101 IAAA AAAA                      ST TRN, Smem
  {
    insn.itype = TMS320C54_st;
    op_reg_word(insn, 1, bit8 ? TRN : T);
    op_Smem(insn, insn.Op2, code);
  }
  else if ( bits15_8 <= 0x8F ) // <= 1000 111S
// 1000 111S IAAA AAAA                      CMPS src, Smem
  {
    insn.itype = TMS320C54_cmps;
    op_src_dst(insn, 1, bit8);
    op_Smem(insn, insn.Op2, code);
  }
  else if ( bits15_8 <= 0x96 ) // <= 1001 0110
// 1001 000S XXXX SHFT                      ADD Xmem, SHFT, src
// 1001 001S XXXX SHFT                      SUB Xmem, SHFT, src
// 1001 010D XXXX SHFT                      LD Xmem, SHFT, dst
// 1001 0110 XXXX BITC                      BIT Xmem, BITC
  {
    static const ushort codes[4] =
    {
      TMS320C54_add3, TMS320C54_sub3, TMS320C54_ld3, TMS320C54_bit
    };
    insn.itype = codes[bits10_9];
    op_Xmem(insn.Op1, code);
    op_bit(insn.Op2, code & 0x0F);
    if ( insn.itype != TMS320C54_bit )
      op_src_dst(insn, 3, bit8);
  }
  else if ( bits15_8 == 0x97 ) // == 1001 0111
  {
    insn.itype = TMS320C54_null;
  }
  else if ( bits15_8 <= 0x9B ) // <= 1001 101S
// 1001 100S XXXX SHFT                      STL src, SHFT, Xmem
// 1001 101S XXXX SHFT                      STH src, SHFT, Xmem
  {
    insn.itype = bit9 ? TMS320C54_sth3 : TMS320C54_stl3;
    op_src_dst(insn, 1, bit8);
    op_bit(insn.Op2, code & 0x0F);
    op_Xmem(insn.Op3, code);
  }
  else if ( bits15_8 <= 0x9D ) // <= 1001 1101
// 1001 1100 XXXX COND                      STRCD Xmem, cond
// 1001 1101 XXXX COND                      SRCCD Xmem, cond
  {
    insn.itype = bit8 ? TMS320C54_srccd : TMS320C54_strcd;
    op_Xmem(insn.Op1, code);
    op_cond4(insn, insn.Op2, (uchar)code);
  }
  else if ( bits15_8 <= 0x9F ) // <= 1001 111S
// 1001 111S XXXX COND                      SACCD src, Xmem, cond
  {
    insn.itype = TMS320C54_saccd;
    op_src_dst(insn, 1, bit8);
    op_Xmem(insn.Op2, code);
    op_cond4(insn, insn.Op3, (uchar)code);
  }
  else if ( bits15_8 <= 0xA7 ) // <= 1010 011S
// 1010 000D XXXX YYYY                      ADD Xmem, Ymem, dst
// 1010 001D XXXX YYYY                      SUB Xmem, Ymem, dst
// 1010 010D XXXX YYYY                      MPY Xmem, Ymem, dst
// 1010 011S XXXX YYYY                      MACSU Xmem, Ymem, src
  {
    static const ushort codes[4] =
    {
      TMS320C54_add3, TMS320C54_sub3, TMS320C54_mpy3, TMS320C54_macsu
    };
    insn.itype = codes[bits10_9];
    op_Xmem(insn.Op1, code);
    op_Ymem(insn.Op2, code);
    op_src_dst(insn, 3, bit8);
  }
  else if ( bits15_8 <= 0xAF ) // <= 1010 11RD
// 1010 10RD XXXX YYYY                      LD Xmem, dst || MAC[R] Ymem [,dst_]
// 1010 11RD XXXX YYYY                      LD Xmem, dst || MAS[R] Ymem [,dst_]
  {
    static const ushort codes[4] =
    {
      TMS320C54_ld_mac, TMS320C54_ld_macr, TMS320C54_ld_mas, TMS320C54_ld_masr
    };
    insn.itype = codes[bits10_9];
    insn.IsParallel = 1;
    op_Xmem(insn.Op1, code);
    op_src_dst(insn, 2, bit8);
    op_Ymem(insn.Op3, code);
    op_src_dst(insn, 4, 1-bit8); // dst_
  }
  else if ( bits15_8 <= 0xBF ) // <= 1010 11RD
// 1011 0RSD XXXX YYYY                      MAC[R] Xmem, Ymem, src [,dst]
// 1011 1RSD XXXX YYYY                      MAS[R] Xmem, Ymem, src [,dst]
  {
    static const ushort codes[4] =
    {
      TMS320C54_mac3, TMS320C54_macr3, TMS320C54_mas3, TMS320C54_masr3
    };
    insn.itype = codes[bits11_10];
    op_Xmem(insn.Op1, code);
    op_Ymem(insn.Op2, code);
    op_src_dst(insn, 3, bit9);
    if ( bit8 != bit9 )
      op_src_dst(insn, 4, bit8);
  }
  else if ( bits15_8 <= 0xDF ) // <= 1101 1RSD
// 1100 00SD XXXX YYYY                      ST src, Ymem || ADD Xmem, dst
// 1100 01SD XXXX YYYY                      ST src, Ymem || SUB Xmem, dst
// 1100 10SD XXXX YYYY                      ST src, Ymem || LD Xmem, dst
// 1100 11SD XXXX YYYY                      ST src, Ymem || MPY Xmem, dst
// 1101 0RSD XXXX YYYY                      ST src, Ymem || MAC[R] Xmem, dst
// 1101 1RSD XXXX YYYY                      ST src, Ymem || MAS[R] Xmem, dst
  {
    static const ushort codes[8] =
    {
      TMS320C54_st_add, TMS320C54_st_sub,  TMS320C54_st_ld,  TMS320C54_st_mpy,
      TMS320C54_st_mac, TMS320C54_st_macr, TMS320C54_st_mas, TMS320C54_st_masr
    };
    insn.itype = codes[bits12_10];
    insn.IsParallel = 1;
    op_src_dst(insn, 1, bit9);
    op_Ymem(insn.Op2, code);
    op_Xmem(insn.Op3, code);
    op_src_dst(insn, 4, bit8);
  }
  else if ( bits15_8 <= 0xE3 ) // <= 1101 1RSD
// 1110 0000 XXXX YYYY 16-bit constant      FIRS Xmem, Ymem, pmad
// 1110 0001 XXXX YYYY                      LMS Xmem, Ymem
// 1110 0010 XXXX YYYY                      SQDST Xmem, Ymem
// 1110 0011 XXXX YYYY                      ABDST Xmem, Ymem
  {
    static const ushort codes[4] =
    {
      TMS320C54_firs, TMS320C54_lms, TMS320C54_sqdst, TMS320C54_abdst
    };
    insn.itype = codes[bits9_8];
    op_Xmem(insn.Op1, code);
    op_Ymem(insn.Op2, code);
    if ( insn.itype == TMS320C54_firs )
      op_pmad_data(insn, insn.Op3);
  }
  else if ( bits15_8 == 0xE5 ) // == 1110 0101
// 1110 0101 XXXX YYYY                      MVDD Xmem, Ymem
  {
    insn.itype = TMS320C54_mvdd;
    op_Xmem(insn.Op1, code);
    op_Ymem(insn.Op2, code);
  }
  else if ( bits15_8 <= 0xE6 ) // <= 1110 01S0
// 1110 01S0 XXXX YYYY                      ST src, Ymem || LD Xmem, T
  {
    insn.itype = TMS320C54_st_ld;
    insn.IsParallel = 1;
    op_src_dst(insn, 1, bit9);
    op_Ymem(insn.Op2, code);
    op_Xmem(insn.Op3, code);
    op_reg_word(insn, 4, T);
  }
  else if ( bits15_8 == 0xE7 ) // == 1110 0111
// 1110 0111 MMRX MMRY                      MVMM MMRx, MMRy
  {
    insn.itype = TMS320C54_mvmm;
    op_MMRx(insn, insn.Op1, code);
    op_MMRy(insn, insn.Op2, code);
  }
  else if ( bits15_8 <= 0xE9 ) // <= 1110 100D
// 1110 100D KKKK KKKK                      LD #K, dst
  {
    insn.itype = TMS320C54_ld2;
    op_imm(insn.Op1, code & 0xFF);
    op_src_dst(insn, 2, bit8);
  }
  else if ( bits15_8 <= 0xEB ) // <= 1110 101k
// 1110 101K KKKK KKKK                      LD #k9, DP
  {
    insn.itype = TMS320C54_ld2;
    op_imm(insn.Op1, code & 0x1FF);
    op_reg_word(insn, 2, DP);
  }
  else if ( bits15_8 == 0xEC ) // == 1110 1100
// 1110 1100 KKKK KKKK                      RPT #K
  {
    insn.itype = TMS320C54_rpt;
    op_imm(insn.Op1, code & 0xFF);
  }
  else if ( bits15_8 == 0xED ) // == 1110 1101
// 1110 1101 000K KKKK                      LD #k5, ASM
  {
    insn.itype = TMS320C54_ld2;
    op_bit(insn.Op1, (uchar)get_signed(code, 0x1F), false);
    op_reg_word(insn, 2, ASM);
  }
  else if ( bits15_8 == 0xEE ) // == 1110 1110
// 1110 1110 KKKK KKKK                      FRAME k
  {
    insn.itype = TMS320C54_frame;
    op_imm(insn.Op1, get_signed(code, 0xFF), true, true);
  }
  else if ( bits15_12 < 0xF )
    insn.itype = TMS320C54_null;

  else if ( code == 0xF070 ) // == 1111 0000 0111 0000
// 1111 0000 0111 0000 16-bit constant      RPT #lk
  {
    insn.itype = TMS320C54_rpt;
    op_lk(insn, insn.Op1);
  }
  else if ( (bits15_4 & 0xFEF) == 0xF02 ) // == 1111 000D 0010
// 1111 000D 0010 SHFT 16-bit constant      LD #lk [,SHFT], dst
  {
    insn.itype = TMS320C54_ld3;
    op_lk(insn, insn.Op1);
    op_bit(insn.Op2, code & 0x0F);
    op_src_dst(insn, 3, bit8);
  }
  else if ( (code & 0xFEFF) == 0xF062 ) // == 1111 000D 0110 0010
// 1111 000D 0110 0010 16-bit constant      LD #lk, 16, dst
  {
    insn.itype = TMS320C54_ld3;
    op_lk(insn, insn.Op1);
    op_bit(insn.Op2, 16);
    op_src_dst(insn, 3, bit8);
  }

  else if ( (code & 0xFEFF) == 0xF066 ) // == 1111 000D 0110 0110
// 1111 000D 0110 0110 16-bit constant      MPY #lk, dst
  {
    insn.itype = TMS320C54_mpy2;
    op_lk(insn, insn.Op1);
    op_src_dst(insn, 2, bit8);
  }
  else if ( (code & 0xFEFF) == 0xF071 ) // == 1111 000D 0111 0001
// 1111 000D 0111 0001 16-bit constant      RPTZ dst, #lk
  {
    insn.itype = TMS320C54_rptz;
    op_src_dst(insn, 1, bit8);
    op_lk(insn, insn.Op2);
  }

  else if ( bits15_10 == 0x3C ) // == 1111 00xx
  {
    if ( bits7_4 <= 0x5 )
// 1111 00SD 0000 SHFT 16-bit constant      ADD #lk [,SHFT], src [,dst]
// 1111 00SD 0001 SHFT 16-bit constant      SUB #lk [,SHFT], src [,dst]
// 1111 00SD 0011 SHFT 16-bit constant      AND #lk [,SHFT] ,src [,dst]
// 1111 00SD 0100 SHFT 16-bit constant      OR #lk [,SHFT], src [,dst]
// 1111 00SD 0101 SHFT 16-bit constant      XOR #lk [,SHFT], src [,dst]
    {
      static const ushort codes[6] =
      {
        TMS320C54_add3, TMS320C54_sub3, TMS320C54_null, TMS320C54_and3,
        TMS320C54_or3,  TMS320C54_xor3
      };
      insn.itype = codes[bits7_4];
      if ( insn.itype != TMS320C54_null )
      {
        op_lk(insn, insn.Op1);
        if ( bits3_0 != 0 )
        {
          op_bit(insn.Op2, bits3_0);
          op_src_dst(insn, 3, bit9);
          if ( bit8 != bit9 )
            op_src_dst(insn, 4, bit8);
        }
        else
        {
          op_src_dst(insn, 2, bit9);
          if ( bit8 != bit9 )
            op_src_dst(insn, 3, bit8);
          else
            insn.itype--;
        }
      }
    }
    else if ( bits7_4 == 0x6 && bits3_0 <= 0x5 )
// 1111 00SD 0110 0000 16-bit constant      ADD #lk, 16, src [,dst]
// 1111 00SD 0110 0001 16-bit constant      SUB #lk, 16, src [,dst]
// 1111 00SD 0110 0011 16-bit constant      AND #lk, 16, src [,dst]
// 1111 00SD 0110 0100 16-bit constant      OR #lk, 16, src [,dst]
// 1111 00SD 0110 0101 16-bit constant      XOR #lk, 16, src [,dst]
    {
      static const ushort codes[6] =
      {
        TMS320C54_add3, TMS320C54_sub3, TMS320C54_null, TMS320C54_and3,
        TMS320C54_or3,  TMS320C54_xor3
      };
      insn.itype = codes[bits3_0];
      if ( insn.itype != TMS320C54_null )
      {
        op_lk(insn, insn.Op1);
        op_bit(insn.Op2, 16);
        op_src_dst(insn, 3, bit9);
        if ( bit8 != bit9 )
          op_src_dst(insn, 4, bit8);
      }
    }
    else if ( bits7_4 == 0x6 && bits3_0 == 0x7 )
// 1111 00SD 0110 0111 16-bit constant      MAC #lk, src [,dst]
    {
      insn.itype = TMS320C54_mac2;
      op_lk(insn, insn.Op1);
      op_src_dst(insn, 2, bit9);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 3, bit8);
        insn.itype++;
      }
    }
    else if ( bits7_5 >= 0x4 )
// 1111 00SD 100S HIFT                      AND src [,SHIFT] [,dst]
// 1111 00SD 101S HIFT                      OR src [,SHIFT] [,dst]
// 1111 00SD 110S HIFT                      XOR src [,SHIFT] [,dst]
// 1111 00SD 111S HIFT                      SFTL src, SHIFT [,dst]
    {
      static const ushort codes[4] =
      {
        TMS320C54_and1, TMS320C54_or1, TMS320C54_xor1, TMS320C54_sftl2,
      };
      insn.itype = codes[bits6_5];
      op_src_dst(insn, 1, bit9);
      uchar shift = (uchar)get_signed(code, 0x1F);
      int n = 2; // current operand
      if ( insn.itype == TMS320C54_sftl2 || shift != 0 )
      {
        op_bit(insn.ops[n-1], shift);
        n++;
        if ( insn.itype != TMS320C54_sftl2 )
          insn.itype++;
      }
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, n, bit8);
        insn.itype++;
      }
    }
    else if ( bits8_3 == 0xE ) // == 0 0111 0
// 1111 00Z0 0111 0010 16-bit constant      RPTB[D] pmad
// 1111 00Z0 0111 0011 16-bit constant      B[D] pmad
// 1111 00Z0 0111 0100 16-bit constant      CALL[D] pmad
    {
      static const ushort codes[8] =
      {
        TMS320C54_null, TMS320C54_null, TMS320C54_rptb, TMS320C54_b,
        TMS320C54_call, TMS320C54_null, TMS320C54_null, TMS320C54_null
      };
      insn.itype = codes[bits2_0];
      if ( insn.itype != TMS320C54_null )
      {
        if ( bit9 )
        {
          switch ( insn.itype )
          {
            case TMS320C54_rptb: insn.itype = TMS320C54_rptbd; break;
            case TMS320C54_b:    insn.itype = TMS320C54_bd;    break;
            case TMS320C54_call: insn.itype = TMS320C54_calld; break;
          }
        }
        op_pmad(insn, insn.Op1);
      }
    }
    else
      insn.itype = TMS320C54_null;
  }

  else if ( bits15_10 == 0x3D ) // == 1111 01xx
  {
    if ( code == 0xF495 ) // == 1111 0100 1001 0101
// 1111 0100 1001 0101                      NOP
      insn.itype = TMS320C54_nop;
    else if ( (code & 0xFFF8) == 0xF4A0 ) // == 1111 0100 1010 0KKK
// 1111 0100 1010 0KKK                       LD #k3, ARP
    {
      insn.itype = TMS320C54_ld2;
      op_imm(insn.Op1, code & 0x7);
      op_reg_word(insn, 2, ARP);
    }
    else if ( (code & 0xFFE0) == 0xF4C0 ) // == 1111 0100 110K KKKK
// 1111 0100 110K KKKK                      TRAP K
    {
      insn.itype = TMS320C54_trap;
      op_imm(insn.Op1, code & 0x001F, false, true);
    }
    else if ( bits7_4 <= 0x7 )
// 1111 01SD 000S HIFT                      ADD src [,SHIFT] [,dst]
// 1111 01SD 001S HIFT                      SUB src [,SHIFT] [,dst]
// 1111 01SD 010S HIFT                      LD src [,SHIFT], dst
// 1111 01SD 011S HIFT                      SFTA src, SHIFT [,dst]
    {
      static const ushort codes[4] =
      {
        TMS320C54_add1, TMS320C54_sub1, TMS320C54_ld1, TMS320C54_sfta2
      };
      insn.itype = codes[bits7_5];
      op_src_dst(insn, 1, bit9);
      uchar shift = (uchar)get_signed(code, 0x1F);
      int n = 2; // current operand
      if ( insn.itype == TMS320C54_sfta2 || shift != 0 )
      {
        op_bit(insn.ops[n-1], shift);
        n++;
        if ( insn.itype != TMS320C54_sfta2 )
          insn.itype++;
      }
      if ( insn.itype == TMS320C54_ld1 || insn.itype == TMS320C54_ld2 || bit8 != bit9 )
      {
        op_src_dst(insn, n, bit8);
        insn.itype++;
      }
    }
    else if ( bits7_0 < 0x80 ) // < 1000 0000
    {
      insn.itype = TMS320C54_null;
    }
    else if ( bits7_0 <= 0x82 ) // <= 1000 0010
// 1111 01SD 1000 0000                      ADD src, ASM [,dst]
// 1111 01SD 1000 0001                      SUB src, ASM [,dst]
// 1111 01SD 1000 0010                      LD src, ASM [,dst]
    {
      static const ushort codes[3] =
      {
        TMS320C54_add2, TMS320C54_sub2, TMS320C54_ld2
      };
      insn.itype = codes[bits2_0];
      op_src_dst(insn, 1, bit9);
      op_reg_word(insn, 2, ASM);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 3, bit8);
        insn.itype++;
      }
    }
    else if ( bit9 == 0 && bits7_0 == 0x83 ) // == 1111 010S 1000 0011
// 1111 010S 1000 0011                      SAT src
    {
      insn.itype = TMS320C54_sat;
      op_src_dst(insn, 1, bit8);
    }
    else if ( bits7_0 <= 0x85 ) // <= 1000 0101
// 1111 01SD 1000 0100                      NEG src [,dst]
// 1111 01SD 1000 0101                      ABS src [,dst]
    {
      insn.itype = bit0 ? TMS320C54_abs1 : TMS320C54_neg1;
      op_src_dst(insn, 1, bit9);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 2, bit8);
        insn.itype++;
      }
    }
    else if ( bit9 == 0 && bits7_0 <= 0x87 ) // <= 1000 0111
// 1111 010D 1000 0110                      MAX dst
// 1111 010D 1000 0111                      MIN dst
    {
      insn.itype = bit0 ? TMS320C54_min : TMS320C54_max;
      op_src_dst(insn, 1, bit8);
    }
    else if ( bits7_0 <= 0x8B ) // <= 1000 101R
// 1111 01SD 1000 100R                      MACA[R] T, src [,dst]
// 1111 01SD 1000 101R                      MASA[R] T, src [,dst]
    {
      static const ushort codes[4] =
      {
        TMS320C54_maca2, TMS320C54_macar2, TMS320C54_masa2, TMS320C54_masar2
      };
      insn.itype = codes[bits1_0];
      op_reg_word(insn, 1, T);
      op_src_dst(insn, 2, bit9);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 3, bit8);
        insn.itype++;
      }
    }
    else if ( bits7_0 <= 0x94 ) // <= 1001 0100
// 1111 010D 1000 1100                      MPYA dst
// 1111 010D 1000 1101                      SQUR A, dst
// 1111 010S 1000 1110                      EXP src
// 1111 01SD 1000 1111                      NORM src [,dst]
// 1111 010S 1001 0000                      ROR src
// 1111 010S 1001 0001                      ROL src
// 1111 010S 1001 0010                      ROLTC src
// 1111 01SD 1001 0011                      CMPL src [,dst]
// 1111 010S 1001 0100                      SFTC src
    {
      static const ushort codes[9] =
      {
        TMS320C54_mpya, TMS320C54_squr, TMS320C54_exp,   TMS320C54_norm1,
        TMS320C54_ror,  TMS320C54_rol,  TMS320C54_roltc, TMS320C54_cmpl1,
        TMS320C54_sftc
      };
      insn.itype = codes[bits4_0-0xC];    //lint !e676 possibly indexing before the beginning of an allocation
      if ( insn.itype == TMS320C54_squr )
      {
        if ( !bit9 )
        {
          op_reg_word(insn, 1, A);
          op_src_dst(insn, 2, bit8);
        }
        else
          insn.itype = TMS320C54_null;
      }
      else if ( insn.itype == TMS320C54_norm1 || insn.itype == TMS320C54_cmpl1 )
      {
        op_src_dst(insn, 1, bit9);
        if ( bit8 != bit9 )
        {
          op_src_dst(insn, 2, bit8);
          insn.itype++;
        }
      }
      else
      {
        if ( !bit9 )
          op_src_dst(insn, 1, bit8);
        else
          insn.itype = TMS320C54_null;
      }
    }
    else if ( bit8 == 0 && bits7_0 == 0x9B ) // == 1111 01Z0 1001 1011
// 1111 01Z0 1001 1011                      RETF[D]
      insn.itype = bit9 ? TMS320C54_retfd : TMS320C54_retf;
    else if ( bits7_0 == 0x9F ) // == 1001 1111
// 1111 01SD 1001 1111                      RND src [,dst]
    {
      insn.itype = TMS320C54_rnd1;
      op_src_dst(insn, 1, bit9);
      if ( bit8 != bit9 )
      {
        op_src_dst(insn, 2, bit8);
        insn.itype++;
      }
    }
    else if ( bits7_4 == 0xA ) // == 1010 1ARX
// 1111 01CC 1010 1ARX                      CMPR CC, ARx
    {
      insn.itype = TMS320C54_cmpr;
      op_cond2(insn.Op1, bits15_8);
      op_reg_word(insn, 2, AR0+bits2_0);
    }
    else if ( bits7_4 == 0xB ) // == 1111 01N0 1011 SBIT
// 1111 01N0 1011 SBIT                      RSBX N, SBIT
// 1111 01N1 1011 SBIT                      SSBX N, SBIT
    {
      uchar reg = rnone;
      if ( bit9 == 0 ) // ST0
      {
        switch ( bits3_0 )
        {
          case 9  : reg = OVB; break;
          case 10 : reg = OVA; break;
          case 11 : reg = C;   break;
          case 12 : reg = TC;  break;
        }
      }
      else // ST1
      {
        switch ( bits3_0 )
        {
          case 5  : reg = CMPT; break;
          case 6  : reg = FRCT; break;
          case 7  : reg = C16;  break;
          case 8  : reg = SXM;  break;
          case 9  : reg = OVM;  break;
          case 11 : reg = INTM; break;
          case 12 : reg = HM;   break;
          case 13 : reg = XF;   break;
          case 14 : reg = CPL;  break;
          case 15 : reg = BRAF; break;
        }
      }
      if ( reg != rnone )
      {
        insn.itype = bit8 ? TMS320C54_ssbx1 : TMS320C54_rsbx1;
        op_reg_word(insn, 1, reg);
      }
      else
      {
        insn.itype = bit8 ? TMS320C54_ssbx2 : TMS320C54_rsbx2;
        op_bit(insn.Op1, bit9);
        op_bit(insn.Op2, bits3_0);
      }
    }
    else if ( (code & 0xFFE0) == 0xF7C0 ) // == 1111 0111 110K KKKK
// 1111 0111 110K KKKK                      INTR k
    {
      insn.itype = TMS320C54_intr;
      op_imm(insn.Op1, bits4_0, false, true);
    }



    else if ( code == 0xF7E0 ) // == 1111 0111 1110 0000
// 1111 0111 1110 0000                      RESET
      insn.itype = TMS320C54_reset;
    else if ( bits7_0 == 0xE1 ) // == 1111 01NN 1110 0001
// 1111 01NN 1110 0001                      IDLE k
    {
      insn.itype = TMS320C54_idle;
      op_bit(insn.Op1, 1+bit9+(bit8<<1));
    }
    else if ( bits7_4 == 0xE ) // == 1111 01ZS 1110 nnnn
// 1111 01ZS 1110 0010                      BACC[D] src
// 1111 01ZS 1110 0011                      CALA[D] src
// 1111 01Z0 1110 0100                      FRET[D]
// 1111 01Z0 1110 0101                      FRETE[D]
// 1111 01ZS 1110 0110                      FBACC[D] src
// 1111 01ZS 1110 0111                      FCALA[D] src
// 1111 01Z0 1110 1011                      RETE[D]
    {
      static const ushort codes[16] =
      {
        TMS320C54_null, TMS320C54_null,  TMS320C54_bacc,  TMS320C54_cala,
        TMS320C54_fret, TMS320C54_frete, TMS320C54_fbacc, TMS320C54_fcala,
        TMS320C54_null, TMS320C54_null,  TMS320C54_null,  TMS320C54_rete,
        TMS320C54_null, TMS320C54_null,  TMS320C54_null,  TMS320C54_null
      };
      insn.itype = codes[bits3_0];
      if ( insn.itype != TMS320C54_null )
      {
        if ( insn.itype == TMS320C54_bacc
          || insn.itype == TMS320C54_cala
          || insn.itype == TMS320C54_fbacc
          || insn.itype == TMS320C54_fcala )
        {
          op_src_dst(insn, 1, bit8);
        }
        else if ( bit8 )
        {
          insn.itype = TMS320C54_null;
        }
        if ( insn.itype != TMS320C54_null && bit9 )
          insn.itype++;
      }
    }
    else
      insn.itype = TMS320C54_null;
  }
  else if ( bits15_10 == 0x3E ) // == 1111 10xx
  {
    if ( bit7 )
// 1111 10Z0 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FB[D] extpmad
// 1111 10Z1 1 7bit constant=pmad(22-16) 16-bit constant=pmad(15-0)  FCALL[D] extpmad
    {
      static const ushort codes[4] =
      {
        TMS320C54_fb, TMS320C54_fcall, TMS320C54_fbd, TMS320C54_fcalld
      };
      insn.itype = codes[bits9_8];
      op_extpmad(insn, insn.Op1, code);
    }
    else
// 1111 10Z0 CCCC CCCC 16-bit constant      BC[D] pmad, cond [,cond] [,cond]
// 1111 10Z1 CCCC CCCC 16-bit constant      CC[D] pmad, cond [,cond] [,cond]
    {
      static const ushort codes[4] =
      {
        TMS320C54_bc2, TMS320C54_cc2, TMS320C54_bcd2, TMS320C54_ccd2
      };
      insn.itype = codes[bits9_8];
      op_pmad(insn, insn.Op1);
      ops_conds(insn, 2, code);
    }
  }
  else if ( bits15_10 == 0x3F ) // == 1111 11xx
  {
    if ( bit8 )
// 1111 11N1 CCCC CCCC                      XC n, cond [,cond] [,cond]
    {
      insn.itype = TMS320C54_xc2;
      uchar n = bit9+1;
      op_bit(insn.Op1, n);
      ops_conds(insn, 2, code);
/*
      ea_t ea = insn.ea + insn.size;
      for ( int i=0; i<n ; i++ ) // loop for all instructions to ignore
      {
        insn_t insn;
        int size = ana(ea, insn);
        if ( size == 0 )
        {
          ea = BADADDR;
          break;
        }
        ea += size;
      }
      if ( ea != BADADDR ) // jump is possible
      {
        insn.Op1.type = o_near;
        insn.Op1.dtype = dt_code;
        insn.Op1.addr = ea;
      }
*/
    }
    else if ( bits7_0 == 0 )
// 1111 11Z0 0000 0000                      RET[D]
      insn.itype = bit9 ? TMS320C54_retd : TMS320C54_ret;
    else
// 1111 11Z0 CCCC CCCC                      RC[D] cond [,cond] [,cond]
    {
      insn.itype = bit9 ? TMS320C54_rcd1 : TMS320C54_rc1;
      ops_conds(insn, 1, code);
    }
  }
}

//--------------------------------------------------------------------------
int tms320c54_t::ana(insn_t *insn)
{
  switch ( ptype )
  {
    case TMS320C54:
      ana_TMS320C54(insn);
      break;
    default:
      error("interr: ana: ana()");
  }
  if ( insn->itype == TMS320C54_null )
    return 0;
  return insn->size;
}

