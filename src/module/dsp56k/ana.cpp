/*
   Motorola DSP56K processor module for IDA.
   The instruction decoder of this processor module is based on the disassembler
   for DSP5600x processor by Miloslaw Smyk.

   The source code was modified to conform IDA by Ilfak Guilfanov.
   Support for DSP 563xx was added by Ivan Litvin <ltv@microset.ru> (December 2003)
   Support for DSP 561xx was added by Ivan Litvin <ltv@microset.ru> (January 2004)

*/

/*
 * Copyright (c) 1998 Miloslaw Smyk
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Miloslaw Smyk
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dsp56k.hpp"

#define FUNCS_COUNT 5
#define F_SWITCH nullptr
//lint -e1762 member function 'dsp56k_t::' could be made const


struct funcdesc_t
{
  bool (dsp56k_t:: *func)(insn_t &, int);
  uint32 mask;
  uint32 shift;
};

struct opcode_t
{
  ushort proc;
#define p5600x  0x01    // valid for 5600x
#define p561xx  0x02    // valid for 561xx
#define p563xx  0x04    // valid for 563xx
#define p566xx  0x08    // valid for 566xx

#define pall    (p5600x|p561xx|p563xx|p566xx)
#define p_1      p561xx
#define p_0_3   (p5600x|p563xx)
#define p_3_6   (p563xx|p566xx)

  ushort itype;
  const char *recog;    //lint !e958 padding is required to align members
  char pmov_cl; // class of acceptable parallel movs for the instruction
  funcdesc_t funcs[FUNCS_COUNT]; //lint !e958 padding is required to align members
  uint32 mask;
  uint32 value;
};

struct par_move
{
  ushort proc;
  const char *recog; //lint !e958 padding is required to align members
  funcdesc_t funcs[FUNCS_COUNT];
  ushort mask;
  ushort value;
};

//----------------------------------------------------------------------
static uint32 ua_next_24bits(insn_t &insn)
{
  uint32 x = get_wide_byte(insn.ea+insn.size);
  insn.size++;
  return x;
}

//----------------------------------------------------------------------
static uint32 ua_32bits(const insn_t &insn)
{

  uint32 x = ((get_wide_byte(insn.ea)        ) & 0x0000FFFF)
           | ((get_wide_byte(insn.ea+1) << 16) & 0xFFFF0000);
  return x;
}


//----------------------------------------------------------------------
// make sure that the additional args are good
void dsp56k_t::fill_additional_args(const insn_t &insn) const
{
  if ( aa.ea != insn.ea )
  {
    insn_t tmp;
    decode_insn(&tmp, insn.ea);
  }
}

//----------------------------------------------------------------------
void dsp56k_t::switch_to_additional_args(insn_t &)
{
  op = aa.args[aa.nargs++];
  op[0].flags = OF_SHOW;
  op[1].flags = OF_SHOW;
  op[0].n     = 1;        // just something else than 0
  op[1].n     = 1;        // just something else than 0
}

//----------------------------------------------------------------------
inline void dsp56k_t::opreg(insn_t &, int reg)
{
  op->type = o_reg;
  op->reg  = (uint16)reg;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_EE(insn_t &insn, int value)
{
  uchar reg;
  if ( is561xx() )
  {
    static const char regs[] = { -1, MR, CCR, OMR };

    if ( value < 1 )
      return false;

    reg = regs[value];
  }
  else
  {
    static const char regs[] = { MR, CCR, OMR };

    if ( value == 3 )
      return false;

    reg = regs[value];
  }
  opreg(insn, reg);
  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_DDDDD(insn_t &insn, int value)
{
  if ( is561xx() )
  {
    static const uchar regs[] =
    {
      X0, Y0, X1, Y1, A,  B, A0, B0,
      uchar(-1), SR, OMR,SP, A1, B1, A2, B2,
      R0, R1, R2, R3, M0, M1, M2, M3,
      SSH,SSL,LA, LC, N0, N1, N2, N3
    };

    if ( value >= qnumber(regs) )
      return false;
    opreg(insn, regs[value]);
    if ( op->reg == uchar(-1) )
      return false;
  }
  else
  {
    static const uchar regs[] = { 0, SR, OMR, SP, SSH, SSL, LA, LC };
    if ( value < 8 )
    {
      opreg(insn, M0 + (value & 7));
    }
    else
    {
      value &= 7;
      if ( value == 0 )
        return false;
      opreg(insn, regs[value & 7]);
    }
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_ff(const insn_t &insn, int value, int reg_bank)
{
  op->type = o_reg;
  switch ( value )
  {
    case 0:
      op->reg = reg_bank ? Y0 : X0;
      break;
    case 1:
      op->reg = reg_bank ? Y1 : X1;
      break;
    case 2:
      op->reg = A;
      break;
    case 3:
      op->reg = B;
      break;
    default:
      interr(&insn, "D_ff");
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_df(insn_t &insn, int value, int reg_bank)
{
  opreg(insn, value & 0x02 ? B : A);
  op++;
  opreg(insn, reg_bank
             ? (value & 1) ? X1 : X0
             : (value & 1) ? Y1 : Y0);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_xi(insn_t &, int value)
{
  op->type  = o_imm;
  op->value = is561xx() ? (value & 0xFF) : value;
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_ximm(insn_t &insn, int /*value*/)
{
  op->type = o_imm;
  op->value = ua_next_24bits(insn);
  if ( is566xx() )
    op->value &= 0xffff;

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_ximm(insn_t &insn, int value)
{
  if ( D_ximm(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_sssss(insn_t &, int value)
{
  static const int vals[] =
  {
    0x800000, 0x400000, 0x200000, 0x100000,
    0x080000, 0x040000, 0x020000, 0x010000,
    0x008000, 0x004000, 0x002000, 0x001000,
    0x000800, 0x000400, 0x000200, 0x000100,
    0x000080, 0x000040, 0x000020, 0x000010,
    0x000008, 0x000004, 0x000002, 0x000001,
    0x000000, 0x000000, 0x000000, 0x000000,
    0x000000, 0x000000, 0x000000, 0x000000,
  };

  op->type = o_imm;
  op->value = vals[value & 0x1f];
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_ssss(insn_t &, int value)
{
  static const int vals[] =
  {
    0x8000, 0x4000, 0x2000, 0x1000,
    0x0800, 0x0400, 0x0200, 0x0100,
    0x0080, 0x0040, 0x0020, 0x0010,
    0x0008, 0x0004, 0x0002, 0x0001
  };

  op->type = o_imm;
  op->value = vals[value & 0xf];
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_xih(insn_t &, int value)
{
  op->type  = o_imm;
  op->value = (value & 0xF) << 8;
  op->value |= (value >> 8) & 0xFF;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_xih(insn_t &insn, int value)
{
  if ( D_xih(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}


//----------------------------------------------------------------------
bool dsp56k_t::SD_d(insn_t &insn, int value)
{
  if ( value )
  {
    opreg(insn, A);
    op++;
    opreg(insn, B);
  }
  else
  {
    opreg(insn, B);
    op++;
    opreg(insn, A);
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::SS_JJJd(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };

  if ( value > 1 && value < 8 )
    return false;

  switch ( value >> 1 )
  {
    case 0:
      return SD_d(insn, value & 0x01);

    default:
      opreg(insn, regs[(value >> 1) - 4]);
      op++;
      break;
  }
  opreg(insn, value & 0x01 ? B : A);
  return true;
}


//----------------------------------------------------------------------
bool dsp56k_t::SD_JJJd(insn_t &insn, int value)
{
  static const uchar regs[] = { X, Y, X0, Y0, X1, Y1 };
  switch ( value >> 1 )
  {
    case 0:
      return false;

    case 1:
      return SD_d(insn, value & 0x01);

    default:
      opreg(insn, regs[(value >> 1) - 2]);
      op++;
      break;
  }
  opreg(insn, value & 0x01 ? B : A);
  return true;
}


//----------------------------------------------------------------------
bool dsp56k_t::SD_Jd(insn_t &insn, int value)
{
  opreg(insn, (value & 2) ? Y : X);
  op++;
  opreg(insn, (value & 1) ? B : A);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_d(insn_t &insn, int value)
{
  opreg(insn, value ? B : A);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_S(insn_t &insn, int value)
{
  if ( D_d(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::SD_JJd(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };
  opreg(insn, regs[value>>1]);
  op++;
  return D_d(insn, value & 0x01);
}

//----------------------------------------------------------------------
bool dsp56k_t::D_dddd(insn_t &insn, int value)
{
  opreg(insn, ((value & 8) ? N0 : R0) + (value & 0xF));
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_ddddd(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, X1, Y0, Y1, A0, B0, A2, B2, A1, B1, A, B };

  if ( value >= 4 )
  {
    if ( value < 16 )
      opreg(insn, regs[value - 4]);
    else
      opreg(insn, ((value < 24) ? R0 : N0) + (value & 7));
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_ddddd(insn_t &insn, int value)
{
  if ( D_ddddd(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_LLL(insn_t &insn, int value)
{
  static const uchar regs[] = { A10, B10, X, Y, A, B, AB, BA };
  opreg(insn, regs[value]);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_sss(insn_t &insn, int value)
{
  static const char regs[] = { -1, -1, A1, B1, X0, Y0, X1, Y1 };

  if ( value > 1 )
  {
    opreg(insn, regs[value]);
    return true;
  }
  else
    return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_sss(insn_t &insn, int value)
{
  if ( D_sss(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_qqq(insn_t &insn, int value)
{
  static const char regs[] = { -1, -1, A0, B0, X0, Y0, X1, Y1 };

  if ( value > 1 )
  {
    opreg(insn, regs[value]);
    return true;
  }
  else
    return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_qqq(insn_t &insn, int value)
{
  if ( D_qqq(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_qq(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };

  opreg(insn, regs[value & 0x03]);
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_QQ(insn_t &insn, int value)
{
  int idx = value & 0x03;
  if ( is561xx() )
  {
    static const uchar regs1[] = { X0, X0, X1, X1 };
    static const uchar regs2[] = { Y0, Y1, Y0, Y1 };
    opreg(insn, regs1[idx]);
    op++;
    opreg(insn, regs2[idx]);
  }
  else
  {
    static const uchar regs[] = { Y1, X0, Y0, X1 };
    opreg(insn, regs[idx]);
  }
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_gggd(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };

  if ( value < 2 )
  {
    opreg(insn, value == 0 ? B : A);
  }
  else
  {
    opreg(insn, regs[(value>>1) & 0x03]);
  }
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_MMRRR(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = value & 0x07;
  op->phtype = uchar(value >> 3);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_MMRRR(insn_t &insn, int value)
{
  if ( D_MMRRR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_MMRRR_XY(insn_t &, int value)
{
  static const char phtypes[] =
  {
    4,  // (Rn)
    1,  // (Rn)+Nn
    2,  // (Rn)-
    3   // (Rn)+
  };
  op->type   = o_phrase;
  op->phrase = value & 0x07;
  op->phtype = phtypes[value >> 3];
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_pppppp(insn_t &, int value)
{
  int base = is563xx() ? 0xFFFFC0 : 0xFFC0;

  value += base;

  op->amode |= amode_ioshort;
  op->type  = o_mem;
  op->addr  = value;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_pppppp(insn_t &insn, int value)
{
  if ( D_pppppp(insn, value) )
  {
    op++;
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_qqqqqq(insn_t &, int value)
{
  int base = is563xx() ? 0xFFFF80 : 0xFF80;

  value += base;

  op->amode |= amode_ioshort;
  op->type  = o_mem;
  op->addr  = value;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_qqqqqq(insn_t &insn, int value)
{
  if ( D_qqqqqq(insn, value) )
  {
    op++;
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_qXqqqqq(insn_t &insn, int value)
{
  return D_qqqqqq(insn, (value & 0x1f) + ((value & 0x40)>>1));
}

//----------------------------------------------------------------------
bool dsp56k_t::D_DDDDDD(insn_t &insn, int value)
{
  static const char regs[] =
  {
    -1, -1, -1, -1, X0, X1, Y0, Y1,
    A0, B0, A2, B2, A1, B1, A,  B,
    R0, R1, R2, R3, R4, R5, R6, R7,
    N0, N1, N2, N3, N4, N5, N6, N7,
    M0, M1, M2, M3, M4, M5, M6, M7,
    -1, -1, EP, -1, -1, -1, -1, -1,
    VBA, SC, -1,-1, -1, -1, -1, -1,
    SZ, SR, OMR,SP, SSH,SSL,LA, LC
  };

  if ( value >= qnumber(regs) )
    return false;
  char r = regs[value];
  if ( r == -1 )
    return false;
  opreg(insn, r);
  // if ( op->reg >= SZ && !is563xx() ) return false;

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_DDDDDD(insn_t &insn, int value)
{
  if ( D_DDDDDD(insn, value) )
  {
    op++;
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_DDDD(insn_t &insn, int value)
{
  if ( D_DDDDDD(insn, value & 0x0f) )
    return true;

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_RRR(insn_t &insn, int value)
{
  opreg(insn, R0 + value);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_RRR(insn_t &insn, int value)
{
  opreg(insn, R0 + value);
  op++;
  return true;
}

//----------------------------------------------------------------------
//lint -e{1764} insn could be const
void dsp56k_t::make_o_mem(insn_t &insn)
{
  if ( !(op->amode & (amode_x|amode_y)) ) switch ( insn.itype )
  {
    case DSP56_do:
    case DSP56_do_f:
    case DSP56_dor:
    case DSP56_dor_f:
      if ( !is561xx() )
        op->addr++;
      // no break
    case DSP56_jcc:
    case DSP56_jclr:
    case DSP56_jmp:
    case DSP56_jscc:
    case DSP56_jsclr:
    case DSP56_jsr:
    case DSP56_jsset:
    case DSP56_jset:

    case DSP56_bcc:
    case DSP56_bra:
    case DSP56_brclr:
    case DSP56_brset:
    case DSP56_bscc:
    case DSP56_bsclr:
    case DSP56_bsr:
    case DSP56_bsset:
      op->type  = o_near;
      op->dtype = dt_code;
      return;
  }
  op->type = o_mem;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_mMMMRRR(insn_t &insn, int value)
{
  if ( !(value & 0x40) )
  {
    op->amode |= amode_short;   // <
    op->addr = value & 0x3F;
    make_o_mem(insn);
    return true;
  }

  value &= ~0x40;

  D_MMRRR(insn, value);               // phrase
  if ( op->phtype == 6 )
  {
    if ( value & 0x4 )
    {
      op->type = o_imm;
      op->value = ua_next_24bits(insn);
      if ( is566xx() )
        op->value &= 0xffff;
    }
    else
    {
      op->addr = ua_next_24bits(insn);
      if ( is566xx() )
        op->addr &= 0xffff;
      make_o_mem(insn);
    }
  }
  return true;
}


//----------------------------------------------------------------------
bool dsp56k_t::S_mMMMRRR(insn_t &insn, int value)
{
  if ( D_mMMMRRR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
inline bool dsp56k_t::D_aaaaaa(insn_t &insn, int value)
{
  return D_mMMMRRR(insn, value & 0x3f);
}

//----------------------------------------------------------------------
bool dsp56k_t::S_aaaaaa(insn_t &insn, int value)
{
  if ( D_aaaaaa(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
inline bool dsp56k_t::D_MMMRRR(insn_t &insn, int value)
{
  return D_mMMMRRR(insn, value | 0x40);
}

//----------------------------------------------------------------------
bool dsp56k_t::S_MMMRRR(insn_t &insn, int value)
{
  if ( D_MMMRRR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::P_type(insn_t &, int)
{
  op->amode |= amode_p;
  return true;
}

//------------------------------------------------------------------
bool dsp56k_t::X_type(insn_t &, int)
{
  op->amode |= amode_x;
  return true;
}

//------------------------------------------------------------------
bool dsp56k_t::Y_type(insn_t &, int)
{
  op->amode |= amode_y;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::mem_type(insn_t &, int value)
{
  if ( value == 1 )
    op->amode |= amode_y;
  else
    op->amode |= amode_x;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::space(insn_t &insn, int)
{
  switch_to_additional_args(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::sign(insn_t &, int value)
{
  if ( value == 1 )
    op->amode |= amode_neg;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::AAE(insn_t &insn, int)
{
  op->addr = ushort(ua_next_24bits(insn));
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_dispL(insn_t &insn, int value)
{
  if ( is561xx() )
  {
    op->addr = insn.ea + short(value) + 2; // +2 - PC should point to next instruction
  }
  else
  {
    value = ua_next_24bits(insn);
    if ( is566xx() )
    {
      op->addr = insn.ea + short(value);
    }
    else
    {
      if ( value & 0x00800000 )
        value |= ~0x007FFFFF;
      op->addr = insn.ea + value;
    }
  }
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_PC_dispL(insn_t &insn, int value)
{
  if ( D_PC_dispL(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_dispS(insn_t &insn, int value)
{
  value = (value & 0x1f) + ((value & 0x3c0) >> 1);

  if ( value & 0x100 )
  {
    value = (value^0x1ff) + 1;
    op->addr = insn.ea - value;
  }
  else
  {
    op->addr = insn.ea + value;
  }
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_RRR(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = (uint16)value;
  op->phtype = 8;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_RRR_dispL(insn_t &insn, int value)
{
  op->type   = o_displ;
  op->reg    = value & 0x07;
  op->phtype = 0; // "R + displ"

  value = ua_next_24bits(insn);
  if ( is566xx() )
    op->value &= 0xffff;

  if ( is566xx() )
  {
    if ( value & 0x8000 )
    {
      value = (value^0xffff) + 1;
      op->phtype = 1; // "R - displ"
    }
  }
  else
  {
    if ( value & 0x800000 )
    {
      value = (value^0xffffff) + 1;
      op->phtype = 1; // "R - displ"
    }
  }


  op->addr = value;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_RRR_dispS(insn_t &, int value)
{
  op->type = o_displ;
  op->reg = (value >> 2) & 0x07;
  op->phtype = 0; // "R + displ"

  value = (value & 0x1) + ((value & 0x7e0) >> 4);

  if ( value & 0x40 )
  {
    op->phtype = 1; // "R - displ"
    value = (value^0x7f) + 1;
  }

  op->addr = value;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_RR_dispS(insn_t &, int value)
{

  op->type   = o_displ;
  op->reg    = (value >> 4) & 0x07;
  op->phtype = 0; // "R + displ"

  value = (value & 0x0f) + ((value & 0x380) >> 3);

  if ( value & 0x40 )
  {
    op->phtype = 1; // "R - displ"
    value = (value^0x7f) + 1;
  }

  op->addr = value;
  op++;
  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::AA(insn_t &, int value)
{
  op->amode |= amode_short;

  op->type  = o_near;
  op->dtype = dt_code;
  op->addr  = value;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_F(insn_t &insn, int value)
{
  opreg(insn, value ? B : A);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_F(insn_t &insn, int value)
{
  if ( D_F(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::CCCC(insn_t &insn, int value)
{
  insn.auxpref |= value & 0xF;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::s(insn_t &insn, int value)
{
  static const char s_u[] = { s_SU, s_UU };

  insn.auxpref |= s_u[value & 0x01];
  return true;
}


//----------------------------------------------------------------------
bool dsp56k_t::ss(insn_t &insn, int value)
{
  static const char s_u[] = { s_SS, s_SS, s_SU, s_UU };

  int idx = is561xx()
          ? ((value & 0x08)>>2) + (value & 0x01)
          : ((value & 0x04)>>1) + (value & 0x01);
  insn.auxpref |= s_u[idx];
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::SD_IIII(insn_t &insn, int value)
{
  // 0100IIII----F---
  static const char regs1[] =
  {
    X0, Y0, X1, Y1,
     A,  B, A0, B0,
    -1, -1, -1, -1,
     A,  B, A0, B0
   };

  static const char regs2[] =
  {
    -1, -1, -1, -1,
    X0, Y0, X0, Y0,
    -1, -1, -1, -1,
    X1, Y1, X1, Y1
  };

  unsigned idx = ((value >> 8) & 0x0f);

  if ( idx < 4 )
  {
    op->type = o_reg;
    op->reg  = regs1[idx];
    op++;
    D_F(insn, ((value & 0x08)>>3) ^ 0x01);
    return true;
  }

  if ( ( idx == 8 ) || ( idx == 9 ) )
  {
    S_F(insn, ((value & 0x08)>>3));
    D_F(insn, ((value & 0x08)>>3) ^ 0x01);
    return true;
  }


  if ( ( idx == 0x0a ) || ( idx == 0x0b ) )
    return false;

  op->type = o_reg;
  op->reg  = regs1[idx];
  if ( regs1[idx] == -1 )
    return false;
  op++;
  op->type = o_reg;
  op->reg  = regs2[idx];
  if ( regs2[idx] == -1 )
    return false;

  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_zRR(insn_t &, int value)
{
  // 00110zRR----F---

  op->type   = o_phrase;
  op->phrase = (value >> 8) & 0x03;
  if ( ((value >> 10) & 0x01) == 1 )
    op->phtype = 1;
  else
    op->phtype = 2;

  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_mRR(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = value & 0x03;

  if ( (value >> 2) & 0x01 )
    op->phtype = 1;
  else
    op->phtype = 3;

  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_RRm(insn_t &insn, int value)
{
  return D_mRR(insn, ((value & 0x06)>>1) + ((value & 0x01)<<2));
}

//----------------------------------------------------------------------
bool dsp56k_t::D_RR11m(insn_t &insn, int value)
{
  return D_mRR(insn, ((value & 0x18)>>3) + (value <<2));
}
//----------------------------------------------------------------------
bool dsp56k_t::D_MMRR(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = value & 0x03;

  switch ( (value & 0x0c)>>2 )
  {
    case 0:
      op->phtype = 4;
      break;
    case 1:
      op->phtype = 3;
      break;
    case 2:
      op->phtype = 2;
      break;
    case 3:
      op->phtype = 1;
      break;
  }

  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::S_MMRR(insn_t &insn, int value)
{
  if ( D_MMRR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_RR0MM(insn_t &insn, int value)
{
  return D_MMRR(insn, ((value & 0x18)>>3) + ((value & 0x03)<<2));
}

//----------------------------------------------------------------------
bool dsp56k_t::D_qRR(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = value & 0x03;

  switch ( (value & 0x08)>>3 )
  {
    case 0:
      op->phtype = 1;
      break;
    case 1:
      op->phtype = 7;
      break;
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_HHH(insn_t &, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1, A, B, A0, B0 };

  int idx = value & 0x07;

  op->type = o_reg;
  op->reg  = regs[idx];

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_HH(insn_t &, int value)
{
  static const uchar regs[] = { X0, Y0, A,  B };

  int idx = value & 0x03;

  op->type = o_reg;
  op->reg  = regs[idx];

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::SD_mWRRHHH(insn_t &insn, int value)
// 001001mWRRDDFHHH
{
  if ( value & 0x0100 )
  {
    X_type(insn, 0);
    D_mRR(insn, ((value & 0xc0)>>6) + ((value & 0x200)>>7));
    op++;
    D_HHH(insn, value & 0x07);
  }
  else
  {
    D_HHH(insn, value & 0x07);
    op++;
    X_type(insn, 0);
    D_mRR(insn, ((value & 0xc0)>>6) + ((value & 0x200)>>7));
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_FJJJ(insn_t &insn, int value)
{
  static const char regs[] = { -1, -1, X, Y, X0, Y0, X1, Y1 };

  int idx = value & 0x07;

  if ( idx != 0x01 )
  {
    if ( idx )
    {
      op->type = o_reg;
      op->reg  = regs[idx];
    }
    else
    {
      opreg(insn, (value & 0x08) ? A : B);
    }
    op++;
    return true;
  }
  else
  {
    return false;
  }
}
//----------------------------------------------------------------------
bool dsp56k_t::S_QQQ(insn_t &, int value)
{
  int idx = value & 0x07;

  if ( is561xx() )
  {
    static const uchar regs1_61[] = { X0, X1, A1, B1, Y0, Y1, Y0, Y1 };
    static const uchar regs2_61[] = { X0, X0, Y0, X0, X0, X0, X1, X1 };
    op->type = o_reg;
    op->reg  = regs1_61[idx];
    op++;
    op->type = o_reg;
    op->reg  = regs2_61[idx];
    op++;
  }
  else
  {
    static const uchar regs1_6x[] = { X0, Y0, X1, Y1, X0, Y0, X1, Y1 };
    static const uchar regs2_6x[] = { X0, Y0, X0, Y0, Y1, X0, Y0, X1 };
    op->type = o_reg;
    op->reg  = regs1_6x[idx];
    op++;
    op->type = o_reg;
    op->reg  = regs2_6x[idx];
    op++;
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_QQ2(insn_t &, int value)
{
  static const uchar regs1[] = { Y0, Y1, Y0, Y1 };
  static const uchar regs2[] = { X0, X0, X1, X1 };

  int idx = value & 0x03;

  op->type = o_reg;
  op->reg  = regs1[idx];
  op++;
  op->type = o_reg;
  op->reg  = regs2[idx];
  op++;

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_QQQQ(insn_t &, int value)
{
  static const uchar regs1[] = { X0, Y0, X1, Y1, X0, Y0, X1, Y1,
                                 X1, Y1, X0, Y0, Y1, X0, Y0, X1 };
  static const uchar regs2[] = { X0, Y0, X0, Y0, Y1, X0, Y0, X1,
                                 X1, Y1, X1, Y1, X0, Y0, X1, Y1 };

  int idx = value & 0xf;
  op->type = o_reg;
  op->reg  = regs1[idx];
  op++;
  op->type = o_reg;
  op->reg  = regs2[idx];
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_Fh0h(insn_t &insn, int value)
{
  // 000100ccccTTFh0h
  static const char regs[] = { -1, -1, X0, Y0 };

  if ( (((value & 0x04)>>1) + (value & 0x01)) > 1 )
    opreg(insn, regs[(((value & 0x04)>>1) + (value & 0x01))]);
  else
    opreg(insn, ((value & 0x08)>>3) == (value & 0x01) ? B : A);

  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_uFuuu_add(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };

  if ( ((value & 0x07) + ((value & 0x10)>>1)) == 0x0c )
  {
    opreg(insn, (value & 0x08) ? A : B);
    op++;
    return true;
  }
  if ( ((value & 0x07) + ((value & 0x10)>>1)) > 0x03 )
    return false;

  opreg(insn, regs[value & 0x03]);
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_uFuuu_sub(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };

  if ( ((value & 0x07) + ((value & 0x10)>>1)) == 0x0d )
  {
    opreg(insn, (value & 0x08) ? A : B);
    op++;
    return true;
  }
  if ( ((value & 0x07) + ((value & 0x10)>>1)) < 0x04 )
    return false;

  opreg(insn, regs[value & 0x03]);
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_RR(insn_t &insn, int value)
{
  opreg(insn, R0 + (value & 0x03));
  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::D_NN(insn_t &insn, int value)
{
  opreg(insn, N0 + (value & 0x03));
  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::DB_RR(insn_t &, int value)
{
  // P_type(0);
  op->type   = o_phrase;
  op->phrase = (uint16)value;
  op->phtype = 4;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_RR(insn_t &, int value)
{
  // P_type(0);
  op->type   = o_phrase;
  op->phrase = (uint16)value;
  op->phtype = 8;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::DX_RR(insn_t &insn, int value)
{
  X_type(insn, 0);
  op->type   = o_phrase;
  op->phrase = (uint16)value;
  op->phtype = 4;
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_RR(insn_t &insn, int value)
{
  if ( D_RR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::m_A_B(insn_t &, int /*value*/)
{
  op->type = o_reg;
  op->reg  = A;
  op++;
  op->type = o_reg;
  op->reg  = B;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::IF(insn_t &, int /*value*/)
{
  op->type  = o_iftype;
  op->imode = imode_if;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::IFU(insn_t &, int /*value*/)
{
  op->type  = o_iftype;
  op->imode = imode_ifu;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_i(insn_t &insn, int value)
{
  op->type = o_vsltype;
  insn.auxpref |= (value & 0x01);
  op++;
  op->amode |= amode_l;   // set L type for last operand
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::SD_TT(insn_t &insn, int value)
{
  // 000100ccccTTFh0h >> 4

  if ( (value & 0x03) == 0 )        // exclude bogus transfer R0 -> R0
    return true;

  opreg(insn, R0);
  op++;

  if ( D_RR(insn, value & 0x03) )
    return true;

  return false;
}
//----------------------------------------------------------------------
bool dsp56k_t::S_BBBiiiiiiii(insn_t &, int value)
{
  // BBB10010iiiiiiii0001010011Pppppp >> 16
  op->type = o_imm;
  op->value = uint32((value & 0xff) << (((value & 0xe000) >> 14) * 4));
  op++;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_Pppppp(insn_t &insn, int value)
{
  X_type(insn, 0);
  if ( value & 0x20 )
  {
    op->amode |= amode_ioshort;   // <<
    value = 0xffe0 + (value & 0x1f);
  }
  else
  {
    value = value & 0x1f;
  }

  op->addr = value;
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_ppppp(insn_t &insn, int value)
{
  return D_Pppppp(insn, (value & 0x1f) + 0x20);
}

//----------------------------------------------------------------------
bool dsp56k_t::D_aaaaa(insn_t &insn, int value)
{
  return D_Pppppp(insn, value & 0x1f);
}

//----------------------------------------------------------------------
bool dsp56k_t::S_DDDDD(insn_t &insn, int value)
{
  if ( D_DDDDD(insn, value) )
  {
    op++;
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_xi(insn_t &, int value)
{
  op->type  = o_imm;
  op->value = value & 0xff;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_xi16(insn_t &, int value)
{
  op->type = o_imm;
  op->value = value & 0xffff;
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_xi_adr_16(insn_t &insn, int value)
{
  op->addr = value & 0xffff;
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_DD(insn_t &insn, int value)
{
  static const uchar regs[] = { X0, Y0, X1, Y1 };
  opreg(insn, regs[value & 0x03]);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::S_DD(insn_t &insn, int value)
{
  if ( D_DD(insn, value) )
  {
    op++;
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_Z(insn_t &, int value)
{
  op->type   = o_phrase;
  op->phrase = 0;
  op->phtype = (value ? 9 : 10);
  return true;
}

//----------------------------------------------------------------------
// new
bool dsp56k_t::D_t(insn_t &insn, int value)
{
  // xxxxxxxxxxxxxxxx00111WDDDDD1t10- >>3
  if ( value & 0x01 )
  {
    D_xi16(insn, (value >> 13) & 0xffff);
  }
  else
  {
    X_type(insn, 0);
    op->addr = (value >> 13) & 0xffff;
    make_o_mem(insn);
  }

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::SD_F00J(insn_t &insn, int value)
{
  opreg(insn, (value & 0x08) ? B : A);
  op++;
  opreg(insn, (value & 0x01) ? Y : X);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_eeeeee(insn_t &insn, int value)
{
  if ( value & 0x20 )
  {
    value = (value^0x3f) + 1;
    op->addr = insn.ea - value + 1; // +1 - PC should point to next instruction
  }
  else
  {
    op->addr = insn.ea + value + 1;
  }
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_PC_aaaaaaaa(insn_t &insn, int value)
{
  if ( value & 0x80 )
  {
    value = (value^0xff) + 1;
    op->addr = insn.ea - value + 1;// +1 - PC should point to next instruction
  }
  else
  {
    op->addr = insn.ea + value + 1;
  }
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::D_BBBBBBBB(insn_t &, int value)
{
  op->type   = o_displ;
  op->reg    = 2;
  op->phtype = 0; // "R + displ"

  if ( value & 0x80 )
  {
    value = ((value & 0xff) ^ 0xff) + 1;
    op->phtype = 1; // "R - displ"
  }
  else
  {
    value = value & 0xff;
  }

  op->addr = value;
  return true;
}

//----------------------------------------------------------------------
static par_move pmoves_6x[] =
{
  { pall,   "0010000000000000",                                             },// no movement
  { pall,   "001dddddiiiiiiii", {{ &dsp56k_t::S_xi,    0x00ff }, { &dsp56k_t::D_ddddd, 0x1f00 }}, },// imm short move
  { pall,   "001000eeeeeddddd", {{ &dsp56k_t::S_ddddd, 0x03e0 }, { &dsp56k_t::D_ddddd, 0x001f }}, },// regto reg move
  { pall,   "00100000010MMRRR", {{ &dsp56k_t::D_MMRRR, 0x001f }                                }, },// Register update
  { p563xx, "001000000010CCCC", {{ &dsp56k_t::IF,      0x0000 }, { &dsp56k_t::CCCC,    0x000f }}, },// Execute conditionally without CCR Update
  { p563xx, "001000000011CCCC", {{ &dsp56k_t::IFU,     0x0000 }, { &dsp56k_t::CCCC,    0x000f }}, },// Execute conditionally with CCR Update
};

static opcode_t table_6x_24[] =
{
// No Parallel move
// A
  { p_3_6,  DSP56_add,     "0000000101iiiiii1000d000", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_add,     "00000001010000001100d000", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_and,     "0000000101iiiiii1000d110", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_and,     "00000001010000001100d110", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { pall,   DSP56_andi,    "00000000iiiiiiii101110EE", 0, {{ &dsp56k_t::S_xi,     0x00ff00 }, { &dsp56k_t::D_EE,     0x000003 },                                                                    }},
  { p_3_6,  DSP56_asl,     "0000110000011101SiiiiiiD", 0, {{ &dsp56k_t::S_xi,     0x00007e }, { &dsp56k_t::S_S,      0x000080 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_asl,     "0000110000011110010SsssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_asr,     "0000110000011100SiiiiiiD", 0, {{ &dsp56k_t::S_xi,     0x00007e }, { &dsp56k_t::S_S,      0x000080 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_asr,     "0000110000011110011SsssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
// B
  { p563xx, DSP56_bcc,     "00001101000100000100CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_PC_dispL, 0x0000 },                                                                    }},
  { p_3_6,  DSP56_bcc,     "00000101CCCC01aaaa0aaaaa", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::D_PC_dispS, 0x03ff },                                                                    }},
  { p_3_6,  DSP56_bcc,     "0000110100011RRR0100CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_PC_RRR,   0x000700 },                                                                  }},
  { p_0_3,  DSP56_bchg,    "000010110mMMMRRR0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p566xx, DSP56_bchg,    "000010110mMMMRRR0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p_0_3,  DSP56_bchg,    "0000101110pppppp0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p566xx, DSP56_bchg,    "0000101110pppppp0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p563xx, DSP56_bchg,    "0000000101qqqqqq0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p566xx, DSP56_bchg,    "0000000101qqqqqq0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p_0_3,  DSP56_bchg,    "0000101111DDDDDD010bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p566xx, DSP56_bchg,    "0000101111DDDDDD0100bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p_0_3,  DSP56_bclr,    "0000101011DDDDDD010bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p566xx, DSP56_bclr,    "0000101011DDDDDD0100bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p_0_3,  DSP56_bclr,    "000010100mMMMRRR0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p566xx, DSP56_bclr,    "000010100mMMMRRR0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p563xx, DSP56_bclr,    "0000000100qqqqqq0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p566xx, DSP56_bclr,    "0000000100qqqqqq0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p_0_3,  DSP56_bclr,    "0000101010pppppp0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p566xx, DSP56_bclr,    "0000101010pppppp0S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p563xx, DSP56_bra,     "000011010001000011000000", 0, {{ &dsp56k_t::D_PC_dispL,0x000000},                                                                                            }},
  { p_3_6,  DSP56_bra,     "00000101000011aaaa0aaaaa", 0, {{ &dsp56k_t::D_PC_dispS,0x0003df},                                                                                            }},
  { p_3_6,  DSP56_bra,     "0000110100011RRR11000000", 0, {{ &dsp56k_t::D_PC_RRR, 0x000700 },                                                                                            }},
  { p563xx, DSP56_brclr,   "0000110010MMMRRR0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_MMMRRR,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brclr,   "0000110010aaaaaa1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_aaaaaa,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brclr,   "0000110011pppppp0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brclr,   "0000010010qqqqqq0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brclr,   "0000110011DDDDDD100bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::D_PC_dispL, 0x000 },                                             }},
  { p_3_6,  DSP56_brkcc,   "00000000000000100001CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f },                                                                                            }},
  { p563xx, DSP56_brset,   "0000110010MMMRRR0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_MMMRRR,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brset,   "0000110010aaaaaa1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_aaaaaa,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brset,   "0000110011pppppp0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brset,   "0000010010qqqqqq0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_brset,   "0000110011DDDDDD101bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::D_PC_dispL, 0x001 },                                             }},
  { p563xx, DSP56_bscc,    "00001101000100000000CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_PC_dispL, 0x0000 },                                                                    }},
  { p_3_6,  DSP56_bscc,    "00000101CCCC00aaaa0aaaaa", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::D_PC_dispS, 0x03df },                                                                    }},
  { p_3_6,  DSP56_bscc,    "0000110100011RRR0000CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_PC_RRR,   0x0700 },                                                                    }},
  { p563xx, DSP56_bsclr,   "0000110110MMMRRR0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_MMMRRR,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsclr,   "0000110110aaaaaa1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_aaaaaa,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsclr,   "0000110111pppppp0S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsclr,   "0000010010qqqqqq1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsclr,   "0000110111DDDDDD100bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                                             }},
  { p_0_3,  DSP56_bset,    "0000101011DDDDDD011bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p566xx, DSP56_bset,    "0000101011DDDDDD0110bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p_0_3,  DSP56_bset,    "000010100mMMMRRR0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p566xx, DSP56_bset,    "000010100mMMMRRR0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p563xx, DSP56_bset,    "0000000100qqqqqq0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p566xx, DSP56_bset,    "0000000100qqqqqq0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p_0_3,  DSP56_bset,    "0000101010pppppp0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p566xx, DSP56_bset,    "0000101010pppppp0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p563xx, DSP56_bsr,     "000011010001000010000000", 0, {{ &dsp56k_t::D_PC_dispL,0x000000},                                                                                            }},
  { p_3_6,  DSP56_bsr,     "00000101000010aaaa0aaaaa", 0, {{ &dsp56k_t::D_PC_dispS,0x0003df},                                                                                            }},
  { p_3_6,  DSP56_bsr,     "0000110100011RRR10000000", 0, {{ &dsp56k_t::D_PC_RRR, 0x000700 },                                                                                            }},
  { p563xx, DSP56_bsset,   "0000110110MMMRRR0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_MMMRRR,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsset,   "0000110110aaaaaa1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_aaaaaa,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsset,   "0000110111pppppp0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsset,   "0000010010qqqqqq1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                      }},
  { p563xx, DSP56_bsset,   "0000110111DDDDDD101bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::D_PC_dispL,  0x00 },                                             }},
  { p_0_3,  DSP56_btst,    "000010110mMMMRRR0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p566xx, DSP56_btst,    "000010110mMMMRRR0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 },                                             }},
  { p_0_3,  DSP56_btst,    "0000101110pppppp0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p566xx, DSP56_btst,    "0000101110pppppp0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_pppppp,  0x3f00 },                                             }},
  { p563xx, DSP56_btst,    "0000000101qqqqqq0S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p566xx, DSP56_btst,    "0000000101qqqqqq0S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_qqqqqq,  0x3f00 },                                             }},
  { p_0_3,  DSP56_btst,    "0000101111DDDDDD011bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
  { p566xx, DSP56_btst,    "0000101111DDDDDD0110bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                    }},
// C
  { p_3_6,  DSP56_clb,     "0000110000011110000000SD", 0, {{ &dsp56k_t::S_S,      0x000002 }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_cmp,     "0000000101iiiiii1000d101", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_cmp,     "00000001010000001100d101", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_cmpu,    "00001100000111111111gggd", 0, {{ &dsp56k_t::S_gggd,   0x00000f }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
// D
  { pall,   DSP56_debug,   "000000000000001000000000", 0, {{ 0 }                                                                                                              }},
  { pall,   DSP56_debugcc, "00000000000000110000CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f },                                                                                            }},
  { pall,   DSP56_dec,     "00000000000000000000101d", 0, {{ &dsp56k_t::D_d,      0x000001 },                                                                                            }},
  { pall,   DSP56_div,     "000000011000000001JJd000", 0, {{ &dsp56k_t::SD_JJd,   0x000038 },                                                                                            }},
  { p_3_6,  DSP56_dmac,    "000000010010010s1sdkQQQQ", 0, {{ &dsp56k_t::ss,       0x000140 }, { &dsp56k_t::sign,     0x000010 }, { &dsp56k_t::S_QQQQ,    0x000f }, { &dsp56k_t::D_d,         0x00020 },                   }},
  { pall,   DSP56_do,      "000001100mMMMRRR0S000000", 0, {{ &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR,0x007f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { pall,   DSP56_do,      "00000110iiiiiiii1000hhhh", 0, {{ &dsp56k_t::S_xih,    0x00ff0f }, { &dsp56k_t::AAE,      0x000000 },                                                                    }},
  { pall,   DSP56_do,      "0000011011DDDDDD00000000", 0, {{ &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,      0x000000 },                                                                    }},
  { p_3_6,  DSP56_do_f,    "000000000000001000000011", 0, {{ &dsp56k_t::AAE,      0x000000 },                                                                                            }},
  { p563xx, DSP56_dor,     "000001100mMMMRRR0S010000", 0, {{ &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR,0x007f00 }, { &dsp56k_t::D_PC_dispL,0x0000 },                                             }},
  { p563xx, DSP56_dor,     "00000110iiiiiiii1001hhhh", 0, {{ &dsp56k_t::S_xih,    0x00ff0f }, { &dsp56k_t::D_PC_dispL, 0x0000 },                                                                    }},
  { p563xx, DSP56_dor,     "0000011011DDDDDD00010000", 0, {{ &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::D_PC_dispL, 0x0000 },                                                                    }},
  { p563xx, DSP56_dor_f,   "000000000000001000000010", 0, {{ &dsp56k_t::D_PC_dispL,0x00000 },                                                                                            }},
// E
  { pall,   DSP56_enddo,   "000000000000000010001100", 0, {{ 0 }                                                                                                              }},
  { p_3_6,  DSP56_eor,     "0000000101iiiiii1000d011", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_eor,     "00000001010000001100d011", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_extract, "0000110000011010000sSSSD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_extract, "0000110000011000000s000D", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_extractu,"0000110000011010100sSSSD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_extractu,"0000110000011000100s000D", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::S_S,      0x000010 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
// I
  { pall,   DSP56_ill,     "000000000000000000000101", 0, {{ 0 }                                                                                                              }},
  { pall,   DSP56_inc,     "00000000000000000000100d", 0, {{ &dsp56k_t::D_d,      0x000001 },                                                                                            }},
  { p_3_6,  DSP56_insert,  "00001100000110110qqqSSSD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::S_qqq,    0x000070 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
  { p_3_6,  DSP56_insert,  "00001100000110010qqq000D", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::S_qqq,    0x000070 }, { &dsp56k_t::D_d,       0x0001 },                                             }},
// J
  { pall,   DSP56_jcc,     "0000101011MMMRRR1010CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                    }},
  { pall,   DSP56_jcc,     "00001110CCCCaaaaaaaaaaaa", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::AA,       0x000fff },                                                                    }},
// exception is possible, it should be moved lower, after move
//  { DSP56_jclr,    "000010100mMMMRRR1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,      0x00000 },
  { p_0_3,  DSP56_jclr,    "0000101010pppppp1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jclr,    "0000101010pppppp1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p563xx, DSP56_jclr,    "0000000110qqqqqq1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jclr,    "0000000110qqqqqq1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jclr,    "0000101011DDDDDD000bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { p566xx, DSP56_jclr,    "0000101011DDDDDD0000bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { pall,   DSP56_jmp,     "0000101011MMMRRR10000000", 0, {{ &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                                            }},
  { pall,   DSP56_jmp,     "000011000000aaaaaaaaaaaa", 0, {{ &dsp56k_t::AA,       0x000fff },                                                                                            }},
  { pall,   DSP56_jscc,    "0000101111MMMRRR1010CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f }, { &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                    }},
  { pall,   DSP56_jscc,    "00001111CCCCaaaaaaaaaaaa", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::AA,       0x000fff },                                                                    }},
// exception is possible, it should be moved lower, after move
//  { DSP56_jsclr,   "000010110mMMMRRR1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,      0x00000 },
  { p_0_3,  DSP56_jsclr,   "0000101110pppppp1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsclr,   "0000101110pppppp1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p563xx, DSP56_jsclr,   "0000000111qqqqqq1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsclr,   "0000000111qqqqqq1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jsclr,   "0000101111DDDDDD000bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { p566xx, DSP56_jsclr,   "0000101111DDDDDD0000bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
// exception is possible, it should be moved lower, after move
//  { DSP56_jset,    "000010100mMMMRRR1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,      0x00000 },
  { p_0_3,  DSP56_jset,    "0000101010pppppp1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jset,    "0000101010pppppp1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p563xx, DSP56_jset,    "0000000110qqqqqq1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jset,    "0000000110qqqqqq1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jset,    "0000101011DDDDDD001bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { p566xx, DSP56_jset,    "0000101011DDDDDD0010bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { pall,   DSP56_jsr,     "0000101111MMMRRR10000000", 0, {{ &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                                            }},
  { pall,   DSP56_jsr,     "000011010000aaaaaaaaaaaa", 0, {{ &dsp56k_t::AA,       0x000fff },                                                                                            }},
// exception is possible, it should be moved lower, after move
//  { DSP56_jsset,   "000010110mMMMRRR1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,      0x00000 },
  { p_0_3,  DSP56_jsset,   "0000101110pppppp1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsset,   "0000101110pppppp1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_pppppp,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p563xx, DSP56_jsset,   "0000000111qqqqqq1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsset,   "0000000111qqqqqq1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_qqqqqq,  0x3f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jsset,   "0000101111DDDDDD001bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
  { p566xx, DSP56_jsset,   "0000101111DDDDDD0010bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::S_DDDDDD, 0x003f00 }, { &dsp56k_t::AAE,       0x0000 },                                             }},
// L
  { p_3_6,  DSP56_lra,     "0000010011000RRR000ddddd", 0, {{ &dsp56k_t::S_RRR,    0x000700 }, { &dsp56k_t::D_ddddd,  0x00001f },                                                                    }},
  { p_3_6,  DSP56_lra,     "0000010001000000010ddddd", 0, {{ &dsp56k_t::S_PC_dispL,0x000000}, { &dsp56k_t::D_ddddd,  0x00001f },                                                                    }},
  { p_3_6,  DSP56_lsl,     "000011000001111010iiiiiD", 0, {{ &dsp56k_t::S_xi,     0x00003e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_lsl,     "00001100000111100001sssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_lsr,     "000011000001111011iiiiiD", 0, {{ &dsp56k_t::S_xi,     0x00003e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_lsr,     "00001100000111100011sssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_lua,     "0000010000aaaRRRaaaadddd", 0, {{ &dsp56k_t::S_RR_dispS,0x003ff0}, { &dsp56k_t::D_dddd,   0x00000f },                                                                    }},
  { p_3_6,  DSP56_lua,     "00000100010MMRRR000ddddd", 0, {{ &dsp56k_t::S_MMRRR,  0x001f00 }, { &dsp56k_t::D_ddddd,  0x00001f },                                                                    }},
  { p5600x, DSP56_lua,     "00000100010MMRRR0001dddd", 0, {{ &dsp56k_t::S_MMRRR,  0x001f00 }, { &dsp56k_t::D_dddd,   0x00000f },                                                                    }},
// M
  { p_0_3,  DSP56_mac,     "00000001000sssss11QQdk10", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030 }, { &dsp56k_t::S_sssss,   0x1f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p566xx, DSP56_mac,     "000000010000ssss11QQdk10", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030 }, { &dsp56k_t::S_ssss,    0x0f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_maci,    "000000010100000111qqdk10", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::S_qq,      0x0030 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_mac_s_u, "00000001001001101sdkQQQQ", 0, {{ &dsp56k_t::s,        0x000040 }, { &dsp56k_t::sign,     0x000010 }, { &dsp56k_t::S_QQQQ,    0x000f }, { &dsp56k_t::D_d,         0x00020 },                   }},
  { p_0_3,  DSP56_macr,    "00000001000sssss11QQdk11", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030 }, { &dsp56k_t::S_sssss,   0x1f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p566xx, DSP56_macr,    "000000010000ssss11QQdk11", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030 }, { &dsp56k_t::S_ssss,    0x0f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_macri,   "000000010100000111qqdk11", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::S_qq,      0x0030 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_merge,   "00001100000110111000sssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
  { p_3_6,  DSP56_move,    "0000101s01110RRR1Wdddddd", 0, {{ F_SWITCH,            0x000040 }, { &dsp56k_t::mem_type, 0x010000 }, { &dsp56k_t::D_RRR_dispL, 0x000700 }, { &dsp56k_t::D_DDDDDD,0x3f },                      }},
  { p_3_6,  DSP56_move,    "0000001aaaaaaRRR1asWdddd", 0, {{ F_SWITCH,            0x000010 }, { &dsp56k_t::mem_type, 0x000020 }, { &dsp56k_t::D_RRR_dispS, 0x01ff40 }, { &dsp56k_t::D_DDDD,  0x0f },                      }},
// moved lower due to potential opcode overlap
  { p_0_3,  DSP56_jclr,    "000010100mMMMRRR1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jclr,    "000010100mMMMRRR1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jsclr,   "000010110mMMMRRR1S0bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsclr,   "000010110mMMMRRR1S00bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jset,    "000010100mMMMRRR1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jset,    "000010100mMMMRRR1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p_0_3,  DSP56_jsset,   "000010110mMMMRRR1S1bbbbb", 0, {{ &dsp56k_t::S_xi,     0x00001f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { p566xx, DSP56_jsset,   "000010110mMMMRRR1S10bbbb", 0, {{ &dsp56k_t::S_xi,     0x00000f }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::S_mMMMRRR, 0x7f00 }, { &dsp56k_t::AAE,         0x00000 },                   }},
  { pall,   DSP56_movec,   "00000100W1eeeeee101ddddd", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::D_DDDDDD, 0x003f00 }, { nullptr,      0x0000 }, { &dsp56k_t::D_DDDDD,     0x0001f },                   }},
  { pall,   DSP56_movec,   "00000101WmMMMRRR0s1ddddd", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 }, { &dsp56k_t::D_DDDDD,     0x0001f },                   }},
  { pall,   DSP56_movec,   "00000101iiiiiiii101ddddd", 0, {{ &dsp56k_t::S_xi,     0x00ff00 }, { &dsp56k_t::D_DDDDD,  0x00001f },                                                                    }},
  { pall,   DSP56_movem,   "00000111WmMMMRRR10dddddd", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::P_type,   0x000000 }, { &dsp56k_t::D_mMMMRRR, 0x7f00 }, { &dsp56k_t::D_DDDDDD,    0x0003f },                   }},
  { pall,   DSP56_movem,   "00000111W0aaaaaa00dddddd", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::P_type,   0x000000 }, { &dsp56k_t::D_aaaaaa,  0x3f00 }, { &dsp56k_t::D_DDDDDD,    0x0003f },                   }},
  { pall,   DSP56_movep,   "0000100SW1MMMRRR01pppppp", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::P_type,   0x000000 }, { &dsp56k_t::D_MMMRRR,  0x3f00 }, { &dsp56k_t::mem_type,    0x10000 }, { &dsp56k_t::D_pppppp, 0x3f }}},
  { pall,   DSP56_movep,   "0000100SW1dddddd00pppppp", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::D_DDDDDD, 0x003f00 }, { nullptr,      0x0000 }, { &dsp56k_t::mem_type,    0x10000 }, { &dsp56k_t::D_pppppp, 0x3f }}},
  { pall,   DSP56_movep,   "0000100sW1MMMRRR1spppppp", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_MMMRRR,  0x3f00 }, { &dsp56k_t::mem_type,    0x10000 }, { &dsp56k_t::D_pppppp, 0x3f }}},
  { p_3_6,  DSP56_movep,   "00000111W1MMMRRR0sqqqqqq", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_MMMRRR,  0x3f00 }, { &dsp56k_t::X_type,      0x00000 }, { &dsp56k_t::D_qqqqqq, 0x3f }}},
  { p_3_6,  DSP56_movep,   "00000111W0MMMRRR1sqqqqqq", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_MMMRRR,  0x3f00 }, { &dsp56k_t::Y_type,      0x00000 }, { &dsp56k_t::D_qqqqqq, 0x3f }}},
  { p_3_6,  DSP56_movep,   "00000100W1dddddd1q0qqqqq", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::D_DDDDDD, 0x003f00 }, { nullptr,      0x0000 }, { &dsp56k_t::X_type,      0x00000 }, { &dsp56k_t::D_qXqqqqq,0x5f }}},
  { p_3_6,  DSP56_movep,   "00000100W1dddddd0q1qqqqq", 0, {{ F_SWITCH,            0x008000 }, { &dsp56k_t::D_DDDDDD, 0x003f00 }, { nullptr,      0x0000 }, { &dsp56k_t::Y_type,      0x00000 }, { &dsp56k_t::D_qXqqqqq,0x5f }}},
  { p_3_6,  DSP56_movep,   "000000001WMMMRRR0sqqqqqq", 0, {{ F_SWITCH,            0x004000 }, { &dsp56k_t::P_type,   0x000000 }, { &dsp56k_t::D_MMMRRR,  0x3f00 }, { &dsp56k_t::mem_type,    0x00040 }, { &dsp56k_t::D_qqqqqq, 0x3f }}},
  { p_0_3,  DSP56_mpy,     "00000001000sssss11QQdk00", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030,}, { &dsp56k_t::S_sssss,   0x1f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p566xx, DSP56_mpy,     "000000010000ssss11QQdk00", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030,}, { &dsp56k_t::S_ssss,    0x0f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_mpy_s_u, "00000001001001111sdkQQQQ", 0, {{ &dsp56k_t::s,        0x000040 }, { &dsp56k_t::sign,     0x000010,}, { &dsp56k_t::S_QQQQ,    0x000f }, { &dsp56k_t::D_d,         0x00020 },                   }},
  { p_3_6,  DSP56_mpyi,    "000000010100000111qqdk00", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_ximm,   0x000000,}, { &dsp56k_t::S_qq,      0x0030 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_0_3,  DSP56_mpyr,    "00000001000sssss11QQdk01", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030,}, { &dsp56k_t::S_sssss,   0x1f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p566xx, DSP56_mpyr,    "000000010000ssss11QQdk01", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQ,     0x000030,}, { &dsp56k_t::S_ssss,    0x0f00 }, { &dsp56k_t::D_d,         0x00008 },                   }},
  { p_3_6,  DSP56_mpyri,   "000000010100000111qqdk01", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_ximm,   0x000000,}, { &dsp56k_t::S_qq,      0x0030 }, { &dsp56k_t::D_d,         0x00008 },                   }},
// N
  { pall,   DSP56_nop,     "000000000000000000000000", 0, {{ 0 }                                                                                                              }},
  { pall,   DSP56_norm,    "0000000111011RRR0001d101", 0, {{ &dsp56k_t::S_RRR,    0x000700 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_normf,   "00001100000111100010sssD", 0, {{ &dsp56k_t::S_sss,    0x00000e }, { &dsp56k_t::D_d,      0x000001 },                                                                    }},
// O
  { p_3_6,  DSP56_or,      "0000000101iiiiii1000d010", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_or,      "00000001010000001100d010", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { pall,   DSP56_ori,     "00000000iiiiiiii111110EE", 0, {{ &dsp56k_t::S_xi,     0x00ff00 }, { &dsp56k_t::D_EE,     0x000003 },                                                                    }},
// P
  { p563xx, DSP56_pflush,  "000000000000000000000011", 0, {{ 0 }                                                                                                              }},
  { p563xx, DSP56_pflushun,"000000000000000000000001", 0, {{ 0 }                                                                                                              }},
  { p563xx, DSP56_pfree,   "000000000000000000000010", 0, {{ 0 }                                                                                                              }},
  { p563xx, DSP56_plock,   "0000101111MMMRRR10000001", 0, {{ &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                                            }},
  { p563xx, DSP56_plockr,  "000000000000000000001111", 0, {{ &dsp56k_t::D_PC_dispL,0x00000 },                                                                                            }},
  { p563xx, DSP56_punlock, "0000101011MMMRRR10000001", 0, {{ &dsp56k_t::D_MMMRRR, 0x003f00 },                                                                                            }},
  { p563xx, DSP56_punlockr,"000000000000000000001110", 0, {{ &dsp56k_t::D_PC_dispL,0x00000 },                                                                                            }},
// R
  { pall,   DSP56_rep,     "000001100mMMMRRR0S100000", 0, {{ &dsp56k_t::mem_type, 0x000040 }, { &dsp56k_t::D_mMMMRRR,0x007f00 },                                                                    }},
  { pall,   DSP56_rep,     "0000011011dddddd00100000", 0, {{ &dsp56k_t::D_DDDDDD, 0x003f00 },                                                                                            }},
  { pall,   DSP56_rep,     "00000110iiiiiiii1010hhhh", 0, {{ &dsp56k_t::D_xih,    0x00ff0f },                                                                                            }},
  { pall,   DSP56_reset,   "000000000000000010000100", 0, {{ 0 }                                                                                                              }},
  { pall,   DSP56_rti,     "000000000000000000000100", 0, {{ 0 }                                                                                                              }},
  { pall,   DSP56_rts,     "000000000000000000001100", 0, {{ 0 }                                                                                                              }},
// S
  { pall,   DSP56_stop,    "000000000000000010000111", 0, {{ 0 }                                                                                                              }},
  { p_3_6,  DSP56_sub,     "0000000101iiiiii1000d100", 0, {{ &dsp56k_t::S_xi,     0x003f00 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p_3_6,  DSP56_sub,     "00000001010000001100d100", 0, {{ &dsp56k_t::S_ximm,   0x000000 }, { &dsp56k_t::D_d,      0x000008 },                                                                    }},
  { p5600x, DSP56_swi,     "000000000000000000000110", 0, {{ 0 }                                                                                                              }},
// T
  { pall,   DSP56_tcc,     "00000010CCCC00000JJJD000", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::SS_JJJd,  0x000078 },                                                                    }},
  { pall,   DSP56_tcc,     "00000011CCCC0ttt0JJJDTTT", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::SS_JJJd,  0x000078 }, { &dsp56k_t::space,     0x0000 }, { &dsp56k_t::S_RRR,       0x00700 }, { &dsp56k_t::D_RRR,    0x07 }}},
  { p_3_6,  DSP56_tcc,     "00000010CCCC1ttt00000TTT", 0, {{ &dsp56k_t::CCCC,     0x00f000 }, { &dsp56k_t::S_RRR,    0x000700 }, { &dsp56k_t::D_RRR,     0x0007 },                                             }},
  { p_3_6,  DSP56_trap,    "000000000000000000000110", 0, {{ 0 }                                                                                                              }},
  { p_3_6,  DSP56_trapcc,  "00000000000000000001CCCC", 0, {{ &dsp56k_t::CCCC,     0x00000f },                                                                                            }},
// V
  { p_3_6,  DSP56_vsl,     "0000101S11MMMRRR110i0000", 0, {{ &dsp56k_t::S_S,      0x010000 }, { &dsp56k_t::S_i,      0x000010 }, { &dsp56k_t::D_MMMRRR,  0x3f00 },                                             }},
// W
  { pall,   DSP56_wait,    "000000000000000010000110", 0, {{ 0 }                                                                                                              }},

// Parallel move

  { pall,   DSP56_move,    "00000000", 0, {{ 0 }                                                                                                                              }},
  { p_3_6,  DSP56_max,     "00011101", 0, {{ &dsp56k_t::m_A_B,    0x000001 },                                                                                                            }},
  { p_3_6,  DSP56_maxm,    "00010101", 0, {{ &dsp56k_t::m_A_B,    0x000001 },                                                                                                            }},
  { pall,   DSP56_addr,    "0000d010", 0, {{ &dsp56k_t::SD_d,     0x000008 },                                                                                                            }},
  { pall,   DSP56_tst,     "0000d011", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_subr,    "0000d110", 0, {{ &dsp56k_t::SD_d,     0x000008 },                                                                                                            }},
  { pall,   DSP56_rnd,     "0001d001", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_addl,    "0001d010", 0, {{ &dsp56k_t::SD_d,     0x000008 },                                                                                                            }},
  { pall,   DSP56_clr,     "0001d011", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_subl,    "0001d110", 0, {{ &dsp56k_t::SD_d,     0x000008 },                                                                                                            }},
  { pall,   DSP56_not,     "0001d111", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_asr,     "0010d010", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_lsr,     "0010d011", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_abs,     "0010d110", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_ror,     "0010d111", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_asl,     "0011d010", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_lsl,     "0011d011", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_neg,     "0011d110", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_rol,     "0011d111", 0, {{ &dsp56k_t::D_d,      0x000008 },                                                                                                            }},
  { pall,   DSP56_adc,     "001Jd001", 0, {{ &dsp56k_t::SD_Jd,    0x000018 },                                                                                                            }},
  { pall,   DSP56_sbc,     "001Jd101", 0, {{ &dsp56k_t::SD_Jd,    0x000018 },                                                                                                            }},
  { pall,   DSP56_or,      "01JJd010", 0, {{ &dsp56k_t::SD_JJd,   0x000038 },                                                                                                            }},
  { pall,   DSP56_eor,     "01JJd011", 0, {{ &dsp56k_t::SD_JJd,   0x000038 },                                                                                                            }},
  { pall,   DSP56_and,     "01JJd110", 0, {{ &dsp56k_t::SD_JJd,   0x000038 },                                                                                                            }},
  { pall,   DSP56_add,     "0JJJd000", 0, {{ &dsp56k_t::SD_JJJd,  0x000078 },                                                                                                            }},
  { pall,   DSP56_tfr,     "0JJJd001", 0, {{ &dsp56k_t::SS_JJJd,  0x000078 },                                                                                                            }},
  { pall,   DSP56_sub,     "0JJJd100", 0, {{ &dsp56k_t::SD_JJJd,  0x000078 },                                                                                                            }},
  { pall,   DSP56_cmp,     "0JJJd101", 0, {{ &dsp56k_t::SS_JJJd,  0x000078 },                                                                                                            }},
  { pall,   DSP56_cmpm,    "0JJJd111", 0, {{ &dsp56k_t::SS_JJJd,  0x000078 },                                                                                                            }},
  { pall,   DSP56_mpy,     "1QQQdk00", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQQ,    0x000070 }, { &dsp56k_t::D_d,       0x0008 },                                                             }},
  { pall,   DSP56_mpyr,    "1QQQdk01", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQQ,    0x000070 }, { &dsp56k_t::D_d,       0x0008 },                                                             }},
  { pall,   DSP56_mac,     "1QQQdk10", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQQ,    0x000070 }, { &dsp56k_t::D_d,       0x0008 },                                                             }},
  { pall,   DSP56_macr,    "1QQQdk11", 0, {{ &dsp56k_t::sign,     0x000004 }, { &dsp56k_t::S_QQQ,    0x000070 }, { &dsp56k_t::D_d,       0x0008 },                                                             }},
};
static opcode_t table_6x_32[qnumber(table_6x_24)];

//----------------------------------------------------------------------
static par_move pmoves_61[] =
{
  { p_1, "01001010----F---"                                   },// No Parallel Data Move
  { p_1, "0100IIII----F---", {{&dsp56k_t::SD_IIII, 0x0fff }}, },// Register to Register Data Move
  { p_1, "00110zRR----F---", {{&dsp56k_t::D_zRR,   0x07ff }}, },// Address Register Update
};

//----------------------------------------------------------------------
static opcode_t table_61_24[] =
{
// Warning! All 32-masks have swapped halves (compared to the documentation)
// Cmd with No Parallel move
  { p_1, DSP56_bfchg,           "BBB10010iiiiiiii0001010011Pppppp", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_Pppppp,         0x3f}}},
  { p_1, DSP56_bfchg,           "BBB10010iiiiiiii00010100101---RR", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::DX_RR,            0x03}}},
  { p_1, DSP56_bfchg,           "BBB10010iiiiiiii00010100100DDDDD", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_bfclr,           "BBB00100iiiiiiii0001010011Pppppp", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_Pppppp,         0x3f}}},
  { p_1, DSP56_bfclr,           "BBB00100iiiiiiii00010100101---RR", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::DX_RR,            0x03}}},
  { p_1, DSP56_bfclr,           "BBB00100iiiiiiii00010100100DDDDD", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_bfset,           "BBB11000iiiiiiii0001010011Pppppp", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_Pppppp,         0x3f}}},
  { p_1, DSP56_bfset,           "BBB11000iiiiiiii00010100101---RR", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::DX_RR,            0x03}}},
  { p_1, DSP56_bfset,           "BBB11000iiiiiiii00010100100DDDDD", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_bftsth,          "BBB10000iiiiiiii0001010001Pppppp", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_Pppppp,         0x3f}}},
  { p_1, DSP56_bftsth,          "BBB10000iiiiiiii00010100001---RR", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::DX_RR,            0x03}}},
  { p_1, DSP56_bftsth,          "BBB10000iiiiiiii00010100000DDDDD", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_bftstl,          "BBB00000iiiiiiii0001010001Pppppp", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_Pppppp,         0x3f}}},
  { p_1, DSP56_bftstl,          "BBB00000iiiiiiii00010100001---RR", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::DX_RR,            0x03}}},
  { p_1, DSP56_bftstl,          "BBB00000iiiiiiii00010100000DDDDD", cl_0, {{&dsp56k_t::S_BBBiiiiiiii,              0xe0ff0000}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_movec,           "00111WDDDDD0----00000101BBBBBBBB", cl_0, {{F_SWITCH,                              0x04000000}, {&dsp56k_t::X_type,           0       },{&dsp56k_t::D_BBBBBBBB, 0xff}, {&dsp56k_t::D_DDDDD, 0x03e00000 }}},
  { p_1, DSP56_movem,           "0000001W--0--HHH00000101BBBBBBBB", cl_0, {{F_SWITCH,                              0x01000000}, {&dsp56k_t::P_type,           0       },{&dsp56k_t::D_BBBBBBBB, 0xff}, {&dsp56k_t::D_HHH,   0x00070000 }}},
  { p_1, DSP56_adc,                             "000101010000F01J", cl_0, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_asl4,                            "000101010011F001", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_asr4,                            "000101010011F000", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_asr16,                           "000101010111F000", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_asr16,                           "000101010111F000", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_bcc,             "xxxxxxxxxxxxxxxx00000111--11cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_PC_dispL,       0xffff0000}}},
  { p_1, DSP56_bcc,                             "001011cccceeeeee", cl_0, {{&dsp56k_t::CCCC,                       0x000003c0}, {&dsp56k_t::D_PC_eeeeee,      0x3f}}},
  { p_1, DSP56_bcc,                             "00000111RR10cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_PC_RR,          0xc0}}},
  { p_1, DSP56_bra,             "xxxxxxxxxxxxxxxx00000001001111--", cl_0, {{&dsp56k_t::D_PC_dispL,                 0xffff0000}}},
  { p_1, DSP56_bra,                             "00001011aaaaaaaa", cl_0, {{&dsp56k_t::D_PC_aaaaaaaa,              0x000000ff}}},
  { p_1, DSP56_bra,                             "00000001001011RR", cl_0, {{&dsp56k_t::D_PC_RR,                    0x00000003}}},
  { p_1, DSP56_brkcc,                           "000000010001cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}}},
  { p_1, DSP56_bscc,            "xxxxxxxxxxxxxxxx00000111--01cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_PC_dispL,       0xffff0000}}},
  { p_1, DSP56_bscc,                            "00000111RR00cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_PC_RR,          0xc0}}},
  { p_1, DSP56_bsr,             "xxxxxxxxxxxxxxxx00000001001110--", cl_0, {{&dsp56k_t::D_PC_dispL,                 0xffff0000}}},
  { p_1, DSP56_bsr,                             "00000001001010RR", cl_0, {{&dsp56k_t::D_PC_RR,                    0x00000003}}},
  { p_1, DSP56_chkaau,                          "0000000000000100", cl_0},
  { p_1, DSP56_debug,                           "0000000000000001", cl_0},
  { p_1, DSP56_debugcc,                         "000000000101cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}}},
  { p_1, DSP56_div,                             "000101010--0F1DD", cl_0, {{&dsp56k_t::S_DD,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_dmac,                            "0001010110s1FsQQ", cl_0, {{&dsp56k_t::ss,                         0x00000024}, {&dsp56k_t::S_QQ2,            0x03}, {&dsp56k_t::D_F, 0x08}}},
  { p_1, DSP56_do,              "xxxxxxxxxxxxxxxx00000000110---RR", cl_0, {{&dsp56k_t::D_RR,                       0x00000003}, {&dsp56k_t::D_PC_dispL,       0xffff0000}}},
  { p_1, DSP56_do,              "xxxxxxxxxxxxxxxx00001110iiiiiiii", cl_0, {{&dsp56k_t::S_xi,                       0x000000ff}, {&dsp56k_t::D_PC_dispL,       0xffff0000}}},
  { p_1, DSP56_do,              "xxxxxxxxxxxxxxxx00000100000DDDDD", cl_0, {{&dsp56k_t::S_DDDDD,                    0x0000001f}, {&dsp56k_t::D_PC_dispL,       0xffff0000}}},
  { p_1, DSP56_do_f,            "xxxxxxxxxxxxxxxx0000000000000010", cl_0, {{&dsp56k_t::D_PC_dispL,                 0xffff0000}}},
  { p_1, DSP56_enddo,                           "0000000000001001", cl_0},
  { p_1, DSP56_ext,                             "000101010101F010", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_ill,                             "0000000000001111", cl_0},
  { p_1, DSP56_imac,                            "000101011010FQQQ", cl_0, {{&dsp56k_t::S_QQQ,                      0x00000007}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_impy,                            "000101011000FQQQ", cl_0, {{&dsp56k_t::S_QQQ,                      0x00000007}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_jcc,             "xxxxxxxxxxxxxxxx00000110--11cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_xi_adr_16,      0xffff0000}}},
  { p_1, DSP56_jcc,                             "00000110RR10cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::DB_RR,            0xc0}}},
  { p_1, DSP56_jmp,             "xxxxxxxxxxxxxxxx00000001001101--", cl_0, {{&dsp56k_t::D_xi_adr_16,                0xffff0000}}},
  { p_1, DSP56_jmp,                             "00000001001001RR", cl_0, {{&dsp56k_t::DB_RR,                      0x00000003}}},
  { p_1, DSP56_jscc,            "xxxxxxxxxxxxxxxx00000110--01cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::D_xi_adr_16,      0xffff0000}}},
  { p_1, DSP56_jscc,                            "00000110RR00cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}, {&dsp56k_t::DB_RR,            0xc0}}},
  { p_1, DSP56_jsr,             "xxxxxxxxxxxxxxxx00000001001100--", cl_0, {{&dsp56k_t::D_xi_adr_16,                0xffff0000}}},
  { p_1, DSP56_jsr,                             "00001010AAAAAAAA", cl_0, {{&dsp56k_t::D_xi,                       0x000000ff}}},
  { p_1, DSP56_jsr,                             "00000001001000RR", cl_0, {{&dsp56k_t::DB_RR,                      0x00000003}}},
  { p_1, DSP56_lea,                             "0000000111TTMMRR", cl_0, {{&dsp56k_t::S_MMRR,                     0x0000000f}, {&dsp56k_t::D_RR,             0x30}}},
  { p_1, DSP56_lea,                             "0000000110NNMMRR", cl_0, {{&dsp56k_t::S_MMRR,                     0x0000000f}, {&dsp56k_t::D_NN,             0x30}}},
  { p_1, DSP56_mac_s_u,                         "000101011110FsQQ", cl_0, {{&dsp56k_t::s,                          0x00000004}, {&dsp56k_t::S_QQ2,            0x03},  {&dsp56k_t::D_F,   0x08}}},
  { p_1, DSP56_movec,                           "00111WDDDDD0MMRR", cl_0, {{F_SWITCH,                              0x00000400}, {&dsp56k_t::X_type,           0},     {&dsp56k_t::D_MMRR,0x0f}, {&dsp56k_t::D_DDDDD, 0x3e0}}},
  { p_1, DSP56_movec,                           "00111WDDDDD1q0RR", cl_0, {{F_SWITCH,                              0x00000400}, {&dsp56k_t::X_type,           0},     {&dsp56k_t::D_qRR, 0x0b}, {&dsp56k_t::D_DDDDD, 0x3e0}}},
  { p_1, DSP56_movec,                           "00111WDDDDD1Z11-", cl_0, {{F_SWITCH,                              0x00000400}, {&dsp56k_t::X_type,           0},     {&dsp56k_t::D_Z,   0x08}, {&dsp56k_t::D_DDDDD, 0x3e0}}},
  { p_1, DSP56_movec,           "xxxxxxxxxxxxxxxx00111WDDDDD1t10-", cl_0, {{F_SWITCH,                              0x00000400}, {&dsp56k_t::D_t,              0xffff0008}, {0,0},        {&dsp56k_t::D_DDDDD, 0x3e0}}},
  { p_1, DSP56_movec,                           "001010dddddDDDDD", cl_0, {{&dsp56k_t::S_DDDDD,                    0x000003e0}, {&dsp56k_t::D_DDDDD,          0x1f}}},
  { p_1, DSP56_movei,                           "001000DDBBBBBBBB", cl_0, {{&dsp56k_t::S_xi,                       0x000000ff}, {&dsp56k_t::D_DD,             0x300}}},
  { p_1, DSP56_movem,                           "0000001WRR0MMHHH", cl_0, {{F_SWITCH,                              0x00000100}, {&dsp56k_t::P_type,           0},             {&dsp56k_t::D_RR0MM, 0xd8}, {&dsp56k_t::D_HHH, 0x07}}},
  { p_1, DSP56_movem,                           "0000001WRR11mmRR", cl_0, {{F_SWITCH,                              0x00000100}, {&dsp56k_t::P_type,           0},             {&dsp56k_t::D_RR11m, 0xc8}, {&dsp56k_t::X_type,0}, {&dsp56k_t::D_mRR, 0x07}}},
  { p_1, DSP56_movep,                           "0001100WHH1ppppp", cl_0, {{F_SWITCH,                              0x00000100}, {&dsp56k_t::D_ppppp,          0x1f},  {0, 0}, {&dsp56k_t::D_HH,  0xc0}}},
  { p_1, DSP56_movep,                           "0000110WRRmppppp", cl_0, {{F_SWITCH,                              0x00000100}, {&dsp56k_t::D_ppppp,          0x1f},  {0, 0}, {&dsp56k_t::D_RRm, 0xe0}}},
  { p_1, DSP56_moves,                           "0001100WHH0aaaaa", cl_0, {{F_SWITCH,                              0x00000100}, {&dsp56k_t::D_aaaaa,          0x1f},  {0, 0}, {&dsp56k_t::D_HH,  0xc0}}},
  { p_1, DSP56_mpy_s_u,                         "000101011100FsQQ", cl_0, {{&dsp56k_t::s,                          0x00000004}, {&dsp56k_t::S_QQ2,            0x03},  {&dsp56k_t::D_F,   0x08}}},
  { p_1, DSP56_negc,                            "000101010110F000", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_nop,                             "0000000000000000", cl_0},
  { p_1, DSP56_norm,                            "000101010010F0RR", cl_0, {{&dsp56k_t::S_RR,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_andi,                            "00011EE0iiiiiiii", cl_0, {{&dsp56k_t::S_xi,                       0x000000ff}, {&dsp56k_t::D_EE,             0x0600}}},
  { p_1, DSP56_ori,                             "00011EE1iiiiiiii", cl_0, {{&dsp56k_t::S_xi,                       0x000000ff}, {&dsp56k_t::D_EE,             0x0600}}},
  { p_1, DSP56_rep,                             "00000000111---RR", cl_0, {{&dsp56k_t::D_RR,                       0x00000003}}},
  { p_1, DSP56_rep,                             "00001111iiiiiiii", cl_0, {{&dsp56k_t::D_xi,                       0x000000ff}}},
  { p_1, DSP56_rep,                             "00000100001DDDDD", cl_0, {{&dsp56k_t::D_DDDDD,                    0x0000001f}}},
  { p_1, DSP56_repcc,                           "000000010101cccc", cl_0, {{&dsp56k_t::CCCC,                       0x0000000f}}},
  { p_1, DSP56_reset,                           "0000000000001000", cl_0},
  { p_1, DSP56_rti,                             "0000000000000111", cl_0},
  { p_1, DSP56_rts,                             "0000000000000110", cl_0},
  { p_1, DSP56_stop,                            "0000000000001010", cl_0},
  { p_1, DSP56_swap,                            "000101010111F001", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_swi,                             "0000000000000101", cl_0},
  { p_1, DSP56_tcc,                             "000100ccccTTFh0h", cl_0, {{&dsp56k_t::CCCC,                       0x000003c0}, {&dsp56k_t::S_Fh0h,           0x0d}, {&dsp56k_t::D_F,    0x08},  {&dsp56k_t::space, 0},     {&dsp56k_t::SD_TT, 0x30}}},
  { p_1, DSP56_tfr2,                            "000101010000F00J", cl_0, {{&dsp56k_t::SD_F00J,                    0x00000009}}},
  { p_1, DSP56_tfr3,                            "001001mWRRDDFHHH", cl_0, {{&dsp56k_t::S_F,                        0x00000008}, {&dsp56k_t::D_DD,             0x30}, {&dsp56k_t::space, 0},      {&dsp56k_t::SD_mWRRHHH, 0x03ff}}},
  { p_1, DSP56_tst2,                            "000101010001-1DD", cl_0, {{&dsp56k_t::D_DD,                       0x00000003}}},
  { p_1, DSP56_wait,                            "0000000000001011", cl_0},
  { p_1, DSP56_zero,                            "000101010101F000", cl_0, {{&dsp56k_t::D_F,                        0x00000008}}},
// Cmd with Parallel move
// 32-bit mask
  { p_1, DSP56_pmov,            "----HHHW--------00000101BBBBBBBB", cl_1_3 },// X Memory Data Move with short displacement
// 16-bit mask
  { p_1, DSP56_mac,                             "00010111RRDDFQQQ", cl_3, {{&dsp56k_t::S_QQQ,                      0x00000007}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_mpy,                             "00010110RRDDFQQQ", cl_3, {{&dsp56k_t::S_QQQ,                      0x00000007}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_mpy,                             "011mmKKK1--0F0QQ", cl_2, {{&dsp56k_t::S_QQ,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_mpyr,                            "011mmKKK1--1F0QQ", cl_2, {{&dsp56k_t::S_QQ,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_mac,                             "011mmKKK1--0F1QQ", cl_2, {{&dsp56k_t::S_QQ,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_macr,                            "011mmKKK1--1F1QQ", cl_2, {{&dsp56k_t::S_QQ,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_move,                            "011mmKKK0rr10000", cl_2 },
  { p_1, DSP56_tfr,                             "011mmKKK0rr1F0DD", cl_2, {{&dsp56k_t::S_DD,                       0x00000003}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_sub,                             "011mmKKK0rruF1uu", cl_2, {{&dsp56k_t::S_uFuuu_sub,                0x0000001f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_add,                             "011mmKKK0rruFuuu", cl_2, {{&dsp56k_t::S_uFuuu_add,                0x0000001f}, {&dsp56k_t::D_F,              0x08}}},
// 8-bit mask
  { p_1, DSP56_clr,                                     "0000F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_add,                                     "0000FJJJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_move,                                    "00010001", cl_1 },
  { p_1, DSP56_tfr,                                     "0001FJJJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_rnd,                                     "0010F000", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_tst,                                     "0010F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_inc,                                     "0010F010", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_inc24,                                   "0010F011", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_inc,                                     "0010F010", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_or,                                      "0010F1JJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_asr,                                     "0011F000", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_asl,                                     "0011F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_lsr,                                     "0011F010", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_lsl,                                     "0011F011", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_eor,                                     "0011F1JJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_subl,                                    "0100F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_sub,                                     "0100FJJJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_clr24,                                   "0101F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_sbc,                                     "0101F01J", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_cmp,                                     "0101FJJJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_neg,                                     "0110F000", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_not,                                     "0110F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_dec,                                     "0110F010", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_dec24,                                   "0110F011", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_and,                                     "0110F1JJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_abs,                                     "0111F001", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_ror,                                     "0111F010", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_rol,                                     "0111F011", cl_1, {{&dsp56k_t::D_F,                        0x00000008}}},
  { p_1, DSP56_cmpm,                                    "0111FJJJ", cl_1, {{&dsp56k_t::S_FJJJ,                     0x0000000f}, {&dsp56k_t::D_F,              0x08}}},
  { p_1, DSP56_mpy,                                     "1k00FQQQ", cl_1, {{&dsp56k_t::sign,                       0x00000040}, {&dsp56k_t::S_QQQ,            0x07}, {&dsp56k_t::D_F, 0x08}}},
  { p_1, DSP56_mpyr,                                    "1k01FQQQ", cl_1, {{&dsp56k_t::sign,                       0x00000040}, {&dsp56k_t::S_QQQ,            0x07}, {&dsp56k_t::D_F, 0x08}}},
  { p_1, DSP56_mac,                                     "1k10FQQQ", cl_1, {{&dsp56k_t::sign,                       0x00000040}, {&dsp56k_t::S_QQQ,            0x07}, {&dsp56k_t::D_F, 0x08}}},
  { p_1, DSP56_macr,                                    "1k11FQQQ", cl_1, {{&dsp56k_t::sign,                       0x00000040}, {&dsp56k_t::S_QQQ,            0x07}, {&dsp56k_t::D_F, 0x08}}},
};
static opcode_t table_61_32[qnumber(table_61_24)];

static void make_masks(opcode_t *table, int qty, int n_bits)
{
  for ( int i = 0; i < qty; i++ )
  {
    for ( int b = 0; b < strlen(table[i].recog); b++ )
    {
      table[i].value <<= 1;
      table[i].mask <<= 1;

      if ( table[i].recog[b] == '1' || table[i].recog[b] == '0' )
        table[i].mask++;

      if ( table[i].recog[b] == '1' )
        table[i].value++;
    }

    // int n_bits = is561xx() ? 32 : 24;
    for ( int j = 0; j < FUNCS_COUNT; j++ )
    {
      if ( table[i].funcs[j].func )
      {
        for ( int b = 0; b < n_bits; b++ )
        {
          if ( table[i].funcs[j].mask & (1 << b) )
            break;
          table[i].funcs[j].shift++;
        }
      }
    }
  }
}

//----------------------------------------------------------------------
static void make_masks2(par_move *pmoves, int qty)
{
  for ( int i = 0; i < qty; i++ )
  {
    for ( int b = 0; b < 16; b++ )
    {
      pmoves[i].value <<= 1;
      pmoves[i].mask <<= 1;

      if ( pmoves[i].recog[b] == '1' || pmoves[i].recog[b] == '0' )
        pmoves[i].mask++;

      if ( pmoves[i].recog[b] == '1' )
        pmoves[i].value++;
    }

    for ( int j = 0; j < FUNCS_COUNT; j++ )
    {
      if ( pmoves[i].funcs[j].func )
      {
        for ( int b = 0; b < 16; b++ )
        {
          if ( pmoves[i].funcs[j].mask & (1 << b) )
            break;
          pmoves[i].funcs[j].shift++;
        }
      }
    }
  }
}


//----------------------------------------------------------------------
// singletons to init tables thread-aware
struct table_61_24_t
{
  static const opcode_t *get()
  {
    static table_61_24_t instance;    //lint !e1788 only by its constructor/destructor
    return table_61_24;
  }
private:
  table_61_24_t()
  {
    make_masks(table_61_24, qnumber(table_61_24), 24);
  }
  ~table_61_24_t() = default;
  table_61_24_t(const table_61_24_t&) = delete;
  table_61_24_t &operator=(const table_61_24_t&) = delete;
};

struct table_61_32_t
{
  static const opcode_t *get()
  {
    static table_61_32_t instance;    //lint !e1788 only by its constructor/destructor
    return table_61_32;
  }
private:
  table_61_32_t()
  {
    memcpy(table_61_32, table_61_24, sizeof(table_61_24));
    make_masks(table_61_32, qnumber(table_61_32), 32);
  }
  ~table_61_32_t() = default;
  table_61_32_t(const table_61_32_t&) = delete;
  table_61_32_t &operator=(const table_61_32_t&) = delete;
};

struct table_6x_24_t
{
  static const opcode_t *get()
  {
    static table_6x_24_t instance;    //lint !e1788 only by its constructor/destructor
    return table_6x_24;
  }
private:
  table_6x_24_t()
  {
    make_masks(table_6x_24, qnumber(table_6x_24), 24);
  }
  ~table_6x_24_t() = default;
  table_6x_24_t(const table_6x_24_t&) = delete;
  table_6x_24_t &operator=(const table_6x_24_t&) = delete;
};

struct table_6x_32_t
{
  static const opcode_t *get()
  {
    static table_6x_32_t instance;    //lint !e1788 only by its constructor/destructor
    return table_6x_32;
  }
private:
  table_6x_32_t()
  {
    memcpy(table_6x_32, table_6x_24, sizeof(table_6x_24));
    make_masks(table_6x_32, qnumber(table_6x_32), 32);
  }
  ~table_6x_32_t() = default;
  table_6x_32_t(const table_6x_32_t&) = delete;
  table_6x_32_t &operator=(const table_6x_32_t&) = delete;
};

struct pmoves_61_t
{
  static const par_move *get()
  {
    static pmoves_61_t instance;    //lint !e1788 only by its constructor/destructor
    return pmoves_61;
  }
private:
  pmoves_61_t()
  {
    make_masks2(pmoves_61, qnumber(pmoves_61));
  }
  ~pmoves_61_t() = default;
  pmoves_61_t(const pmoves_61_t&) = delete;
  pmoves_61_t &operator=(const pmoves_61_t&) = delete;
};

struct pmoves_6x_t
{
  static const par_move *get()
  {
    static pmoves_6x_t instance;    //lint !e1788 only by its constructor/destructor
    return pmoves_6x;
  }
private:
  pmoves_6x_t()
  {
    make_masks2(pmoves_6x, qnumber(pmoves_6x));
  }
  ~pmoves_6x_t() = default;
  pmoves_6x_t(const pmoves_6x_t&) = delete;
  pmoves_6x_t &operator=(const pmoves_6x_t&) = delete;
};

//----------------------------------------------------------------------
// check if the instruction may be disassembled for the current processor
bool dsp56k_t::is_valid_insn(ushort proc)
{
  if ( is566xx() )
  {
    if ( (proc & p566xx) == 0 )
      return false;
  }
  else if ( is563xx() )
  {
    if ( (proc & p563xx) == 0 )
      return false;
  }
  else if ( is561xx() )
  {
    if ( (proc & p561xx) == 0 )
      return false;
  }
  else
  {
    if ( (proc & p5600x) == 0 )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::disassemble_parallel_move(insn_t &insn, int i, int value)
{
  switch_to_additional_args(insn);

  const par_move *pmoves = is561xx() ? pmoves_61_t::get() : pmoves_6x_t::get();
  const par_move &ptr = pmoves[i];
  if ( !is_valid_insn(ptr.proc) )
    return false;
  for ( int j = 0; j < FUNCS_COUNT; j++ )
  {
    if ( ptr.funcs[j].func != nullptr )
    {
      int v = (value & ptr.funcs[j].mask) >> ptr.funcs[j].shift;
      (this->*ptr.funcs[j].func)(insn, v);
    }
  }
  return true;
}


//----------------------------------------------------------------------
bool dsp56k_t::decode_XY_R_mem(insn_t &insn, int value)
{
  /* order of operands depends on whether we are writing or reading */

  if ( value & 0x0080 )
  {
    mem_type(insn, (value >> 6) & 0x01);

    D_mMMMRRR(insn, (value & 0x3f) | 0x40);
    op++;

    if ( value & 0x40 )
      D_ff(insn, (value >> 8) & 0x03, value & 0x40);
    else
      D_ff(insn, (value >> 10) & 0x03, value & 0x40);
  }
  else
  {
    if ( value & 0x40 )
      D_ff(insn, (value >> 8) & 0x03, value & 0x40);
    else
      D_ff(insn, (value >> 10) & 0x03, value & 0x40);
    op++;

    mem_type(insn, (value >> 6) & 0x01);

    D_mMMMRRR(insn, (value & 0x3f) | 0x40);
  }

  return true;
}

//----------------------------------------------------------------------
bool dsp56k_t::recognize_parallel_move_class1(insn_t &insn, int value)
{
  int index = -1;

  if ( (value & 0xff00) == 0x4a00 )
  {
    index = 0;  // No Parallel Data Move 01001010----F---
  }
  else if ( (value & 0xf000) == 0x4000 )
  {
    index = 1;  // Register to Register Data Move 0100IIII----F---
  }
  else if ( (value & 0xf800) == 0x3000 )
  {
    index = 2;  // Address Register Update 00110zRR----F---
  }
  else if ( (value & 0x8000) == 0x8000 ) // X Memory Data Move 1 1mRRHHHW----F---
  {
    switch_to_additional_args(insn);

    if ( value & 0x0100 )
    {
      X_type(insn, 0);
      D_mRR(insn, (value >>12) & 0x07);
      op++;
      D_HHH(insn, (value >>9) & 0x07);
    }
    else
    {
      D_HHH(insn, (value >>9) & 0x07);
      op++;
      X_type(insn, 0);
      D_mRR(insn, (value >>12) & 0x07);
    }
    return true;
  }
  else if ( (value & 0xf000) == 0x5000 ) // X Memory Data Move 2 0101HHHW----F---
  {
    switch_to_additional_args(insn);

    if ( value & 0x0100 )
    {
      X_type(insn, 0);
      op->type   = o_phrase;
      op->phrase = 0;
      op->phtype = ((value & 0x08) ? 9 : 10);
      op++;
      D_HHH(insn, (value >>9) & 0x07);
    }
    else
    {
      D_HHH(insn, (value >>9) & 0x07);
      op++;
      X_type(insn, 0);
      op->type   = o_phrase;
      op->phrase = 0;
      op->phtype = ((value & 0x08) ? 9 : 10);
    }
    return true;
  }

  if ( index != -1 )
    return disassemble_parallel_move(insn, index, value);
  return false;
}
//----------------------------------------------------------------------
bool dsp56k_t::recognize_parallel_move_class1_3(insn_t &insn, int value)
{
  // X Memory Data Move with short displacement
  //----HHHW--------00000101BBBBBBBB

  switch_to_additional_args(insn);
  if ( (value >> 24) & 0x01 )
  {
    X_type(insn, 0);
    D_BBBBBBBB(insn, value & 0x0ff);
    op++;
    D_HHH(insn, (value >> 25 ) & 0x07);
  }
  else
  {
    D_HHH(insn, (value >> 25 ) & 0x07);
    op++;
    X_type(insn, 0);
    D_BBBBBBBB(insn, value & 0x0ff);
  }
  return true;
}
//----------------------------------------------------------------------
bool dsp56k_t::recognize_parallel_move_class2(insn_t &insn, int value)
{
  // Dual X Memory Data Read
  // 011mmKKKXrrXXXXX

  static const char regs1[] = { -1, Y0, X1, Y1, X0, Y0, -1, Y1 };
  static const char regs2[] = { X0, X0, X0, X0, X1, X1, Y0, X1 };

  switch_to_additional_args(insn);

  X_type(insn, 0);
  D_mRR(insn, ((value >> 10) & 0x04) + ((value >> 5) & 0x03));
  op++;
  char r = regs1[(value >>8) & 0x07];
  if ( r != -1 )
    opreg(insn, r);
  else
    D_F(insn, ((value & 0x08)>>3) ^ 0x01);


  switch_to_additional_args(insn);

  X_type(insn, 0);
  op->type   = o_phrase;
  op->phrase = 3;

  if ( (value >> 11) & 0x01 )
    op->phtype = 1;
  else
    op->phtype = 3;

  op++;
  opreg(insn, regs2[(value >>8) & 0x07]);

  return true;

}
//----------------------------------------------------------------------
bool dsp56k_t::recognize_parallel_move_class3(insn_t &insn, int value)
{
  // X Memory Data Write and Register Data Move
  // 0001011kRRDDXXXX


  switch_to_additional_args(insn);
  opreg(insn, ((value >>8) & 0x01) == 1 ? A : B);
  op++;
  X_type(insn, 0);
  D_mRR(insn, 0x04 + ((value >> 6) & 0x03));


  switch_to_additional_args(insn);
  S_DD(insn, (value >>4) & 0x03);
  opreg(insn, ((value >>8) & 0x01) == 1 ? A : B);

  return true;

}


//----------------------------------------------------------------------
bool dsp56k_t::is_parallel_move(insn_t &insn, int value)
{
  int index = -1;

  if ( value == 0x2000 )
    index = 0;      /* NOP */
  else if ( ((value & 0xe000) == 0x2000) && (((value >> 8) & 0x1f) >= 4) )
    index = 1;      /* I */
  else if ( ((value >> 10) == 0x08) && (((value >> 5) & 0x1f) >= 4) && ((value & 0x1f) >= 4) )
    index = 2;      /* R */
  else if ( (value >> 5) == 0x102 )
    index = 3;      /* U */
  else if ( (value >> 4) == 0x202 )
    index = 4;    /* IF */
  else if ( (value >> 4) == 0x203 )
    index = 5;    /* IF.U */
  else if ( ((value & 0xc000) == 0x4000) && (((value >> 8) & 0x37) >= 4) )
  {
    switch_to_additional_args(insn);

    if ( value & 0x0080 )
    {
      mem_type(insn, (value >> 11) & 0x01);
      D_mMMMRRR(insn, value & 0x7f);
      op++;
      D_ddddd(insn, ((value >> 8) & 0x07) | ((value >> 9) & 0x18));
    }
    else
    {
      D_ddddd(insn, ((value >> 8) & 0x07) | ((value >> 9) & 0x18));
      op++;
      mem_type(insn, (value >> 11) & 0x01);
      D_mMMMRRR(insn, value & 0x7f);
    }

    return true;
  }
  else if ( (value & 0xf000) == 0x1000 )  /* class I */
  {
    switch_to_additional_args(insn);

    if ( value & 0x40 )        /* Y:R */
    {
      D_df(insn, (value >> 10) & 0x03, value & 0x40);
      switch_to_additional_args(insn);
      decode_XY_R_mem(insn, value);
    }
    else                                                 /* X:R */
    {
      decode_XY_R_mem(insn, value);
      switch_to_additional_args(insn);
      D_df(insn, (value >> 8) & 0x03, value & 0x40);
    }

    return true;
  }
  else if ( (value & 0xfe40) == 0x0800 )  /* class II */
  {
    switch_to_additional_args(insn);

    if ( value & 0x0080 )      /* Y:R */
    {
      opreg(insn, Y0);
      op++;
      opreg(insn, (value & 0x0100) ? B : A);

      switch_to_additional_args(insn);

      D_d(insn, (value >> 8) & 0x01);
      op++;
      op->amode |= amode_y;
      D_mMMMRRR(insn, (value & 0x3f) | 0x40);
    }
    else                                                            /* X:R */
    {
      D_d(insn, (value >> 8) & 0x01);
      op++;
      op->amode |= amode_x;
      D_mMMMRRR(insn, (value & 0x3f) | 0x40);

      switch_to_additional_args(insn);

      opreg(insn, X0);
      op++;
      opreg(insn, (value & 0x0100) ? B : A);
    }

    return true;
  }
  else if ( (value & 0xf400) == 0x4000 )  /* L: */
  {
    switch_to_additional_args(insn);

    if ( value & 0x0080 )
    {
      op->amode |= amode_l;
      D_mMMMRRR(insn, value & 0x7f);
      op++;
      D_LLL(insn, ((value & 0x0800) >> 9) | ((value & 0x0300) >> 8));
    }
    else
    {
      D_LLL(insn, ((value & 0x0800) >> 9) | ((value & 0x0300) >> 8));
      op++;
      op->amode |= amode_l;
      D_mMMMRRR(insn, value & 0x7f);
    }

    return true;
  }
  else if ( value & 0x8000 )      /* X: Y: */
  {
    switch_to_additional_args(insn);

    /* X: */
    if ( value & 0x0080 )
    {
      op->amode |= amode_x;
      D_MMRRR_XY(insn, value & 0x1f);
      op++;
      D_ff(insn, (value >> 10) & 0x3, false);
    }
    else
    {
      D_ff(insn, (value >> 10) & 0x3, false);
      op++;
      op->amode |= amode_x;
      D_MMRRR_XY(insn, value & 0x1f);
    }

    switch_to_additional_args(insn);

    /* Y: */
    if ( value & 0x4000 )
    {
      op->amode |= amode_y;
      D_MMRRR_XY(insn, ((value >> 5) & 0x03) | (~value & 0x04) | ((value >> 9) & 0x18));
      op++;
      D_ff(insn, (value >> 8) & 0x3, true);
    }
    else
    {
      D_ff(insn, (value >> 8) & 0x3, true);
      op++;
      op->amode |= amode_y;
      D_MMRRR_XY(insn, ((value >> 5) & 0x03) | (~value & 0x04) | ((value >> 9) & 0x18));
    }

    return true;
  }

  if ( index != -1 )
    return disassemble_parallel_move(insn, index, value);
  return false;
}

//----------------------------------------------------------------------
bool dsp56k_t::use_table(
        insn_t &insn,
        const opcode_t *table,
        uint32 code,
        int entry,
        int start,
        int end)
{
  const opcode_t &ptr = table[entry];
  for ( int j = start; j <= end; j++ )
  {
    if ( ptr.funcs[j].func == nullptr )
      break;
    int value = (code & ptr.funcs[j].mask) >> ptr.funcs[j].shift;
    if ( !(this->*ptr.funcs[j].func)(insn, value) )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
void dsp56k_t::reset_ops(insn_t &insn)
{
  op = &insn.Op1;
  for ( int i=0; i < UA_MAXOP; i++ )
    insn.ops[i].type = o_void;
  memset(&aa, 0, sizeof(aa));
}

//----------------------------------------------------------------------
int dsp56k_t::ana_61(insn_t &insn)
{
  int prev_insn_p_class = cl_0;
  int insn_p_class;
  uint code = ua_32bits(insn);
  op = &insn.Op1;
  memset(&aa, 0, sizeof(aa));
  aa.ea = insn.ea;

  const opcode_t *table_61_xx = is561xx() ? table_61_32_t::get() : table_61_24_t::get();
  for ( int i = 0; i < qnumber(table_61_24); i++ )
  {
    const auto &te = table_61_xx[i];
    if ( (code & te.mask) == te.value )
    {
      insn.itype = te.itype;
      insn.size = 1;
      insn_p_class = te.pmov_cl;
      if ( strlen(te.recog) > 16 )
        insn.size = 2;

      // X Memory Data Move with short displacement
      if ( prev_insn_p_class == cl_1_3 )
      {
        insn.size = 2;
        insn_p_class = cl_1_3;
      }
      else if ( insn_p_class == cl_1_3 )
      {
        prev_insn_p_class = insn_p_class;
        code >>= 16;
        continue;
      }


      if ( te.funcs[0].func == F_SWITCH )
      {
        int first, second;
        if ( (code & te.funcs[0].mask) >> te.funcs[0].shift )
        {
          first = 1;
          second = 3;
        }
        else
        {
          first = 3;
          second = 1;
        }
        if ( !use_table(insn, table_61_xx, code, i, first, first + 1) )
        {
          reset_ops(insn);
          continue;
        }
        op++;
        if ( !use_table(insn, table_61_xx, code, i, second, second + 1) )
        {
          reset_ops(insn);
          continue;
        }
      }
      else
      {
        if ( !use_table(insn, table_61_xx, code, i, 0, FUNCS_COUNT - 1) )
        {
          reset_ops(insn);
          continue;
        }
      }

      // analyze additional operands of parallel moves
      switch ( insn_p_class )
      {
        case cl_0:// No Parallel move
          break;
        case cl_1:// X Memory Data Move (common)
          code = ushort(code & 0xffff);
          recognize_parallel_move_class1(insn, code);
          break;
        case cl_1_3:// X Memory Data Move with short displacement
          code = ua_32bits(insn);
          recognize_parallel_move_class1_3(insn, code);
          break;
        case cl_2:// Dual X Memory Data Read
          code = ushort(code & 0xffff);
          recognize_parallel_move_class2(insn, code);
          break;
        case cl_3:// X Memory Data Write and Register Data Move
          code = ushort(code & 0xffff);
          recognize_parallel_move_class3(insn, code);
          break;
      }

      if ( insn.Op1.type == o_void && aa.nargs != 0 )
      {
        insn.Op1 = aa.args[0][0];
        insn.Op2 = aa.args[0][1];
        aa.args[0][0].type = o_void;
        aa.args[0][1].type = o_void;
      }
      return insn.size;
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int dsp56k_t::ana_6x(insn_t &insn)
{
  uint32 code = ua_next_24bits(insn);
  op = &insn.Op1;
  memset(&aa, 0, sizeof(aa));
  aa.ea = insn.ea;

  const opcode_t *table_6x_xx = is561xx() ? table_6x_32_t::get() : table_6x_24_t::get();
  for ( int i = 0; i < qnumber(table_6x_24); i++ )
  {
    const auto &te = table_6x_xx[i];
    if ( (code & te.mask) == te.value
      && is_valid_insn(te.proc) )
    {
      insn.itype = te.itype;
      if ( te.funcs[0].func == F_SWITCH )
      {
        int first, second;
        if ( (code & te.funcs[0].mask) >> te.funcs[0].shift )
        {
          first = 1;
          second = 3;
        }
        else
        {
          first = 3;
          second = 1;
        }
        if ( !use_table(insn, table_6x_xx, code, i, first, first + 1) )
        {
          reset_ops(insn);
          continue;
        }
        op++;
        if ( !use_table(insn, table_6x_xx, code, i, second, second + 1) )
        {
          reset_ops(insn);
          continue;
        }
      }
      else
      {
        if ( !use_table(insn, table_6x_xx, code, i, 0, FUNCS_COUNT - 1) )
        {
          reset_ops(insn);
          continue;
        }
      }

      if ( te.recog[8] == '\0' )
      {
        code = ushort(code>>8);
        is_parallel_move(insn, code);
      }
      if ( insn.Op1.type == o_void && aa.nargs != 0 )
      {
        insn.Op1 = aa.args[0][0];
        insn.Op2 = aa.args[0][1];
        aa.args[0][0].type = o_void;
        aa.args[0][1].type = o_void;
      }
      return insn.size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
int dsp56k_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  return is561xx() ? ana_61(insn) : ana_6x(insn);
}

//--------------------------------------------------------------------------
void interr(const insn_t *insn, const char *module)
{
  const char *name = nullptr;
  if ( insn->itype < DSP56_last )
    name = Instructions[insn->itype].name;
  warning("%a(%s): internal error in %s", insn->ea, name, module);
}
