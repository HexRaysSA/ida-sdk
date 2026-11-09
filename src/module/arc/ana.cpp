/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2012-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      ARC (Argonaut RISC Core) processor module
 *
 *      Based on code contributed by by Felix Domke <tmbinc@gmx.net>
 */

#include "arc.hpp"
#include <frame.hpp>

/*
doRegisterOperand converts the 6 bit field 'code' to an IDA-"op_t"-operand.

'd' is the maybe-used (signed) immediate in the lowest 9 bits, li is the
long-immediate which is loaded in the instruction decoding, since it's
loaded only once, even if an instructions uses multiple times a long immediate

when it's all about a branch (isbranch is true), we have to multiply the absolute
address by 4, since it's granularity are words then (and not bytes)

FYI:
register code 61 means "short immediate with .f-flag set", 63 "short immediate
without .f-flag" and 62 means "long immediate (4 bytes following the instruction,
making the instruction 8 bytes long (insn.size)).
*/

//----------------------------------------------------------------------
void doRegisterOperand(int code, op_t &op, int d, int li, int isbranch)
{
  /* we always deal with double words, exceptions are load/stores
     with 8 or 16 bits. these are covered by the instruction decoding */

  op.dtype = dt_dword;
  if ( code == SHIMM_F || code == SHIMM )     // short immediate with/wo flags
  {
    if ( isbranch )
    {
      op.type = o_near;
      op.addr = d * 4;
    }
    else
    {
      op.type = o_imm;
      op.value = d;
    }
  }
  else if ( code == LIMM )          // long immediate
  {
    if ( isbranch )
    {
      op.type = o_near;
      /* the upper 7 bits containing processor flags to set  */
      /* they are handled in the instruction decoding, since */
      /* they produce a second (ida-)operand */
      op.addr = (li & 0x1FFFFFF) * 4;
    }
    else
    {
      op.type = o_imm;
      op.value = li;
    }
    op.offb = 4;
  }
  else                          /* just a register */
  {
    op.type = o_reg;
    op.reg = uint16(code);
  }
}

//----------------------------------------------------------------------
// make indirect [b,c] operand
//  b   c
// imm imm  mem:   [imm1+imm2]
// reg imm  displ: [reg, imm]
// imm reg  displ: [imm, reg] (membase=1)
// reg reg  phrase: [reg, reg]
void arc_t::doIndirectOperand(const insn_t &insn, int b, int c, op_t &op, int d, int li, bool special)
{
  if ( is_imm(b) && is_imm(c) )
  {
    // [#imm, #imm]
    int imm1 = b == LIMM ? li : d;
    int imm2 = c == LIMM ? li : d;
    if ( special )
    {
      // use a simple immediate for AUX reg numbers
      op.type = o_imm;
      op.value = imm1;
    }
    else
    {
      op.type = o_mem;
      op.immdisp = is_a4() ? 0 : imm2;
      op.addr = trunc_ea(imm1 + imm2 * get_scale_factor(insn));
    }
  }
  else if ( !is_imm(b) && !is_imm(c) )
  {
    // [reg, reg]
    op.type = o_phrase;
    op.reg = b;
    op.secreg = c;
  }
  else
  {
    op.type = o_displ;
    if ( is_imm(c) )
    {
      // [reg, #imm]
      op.reg = b;
      op.addr = c == LIMM ? li : d;
      if ( special )
        op.addr = 0;
      op.membase = 0;
    }
    else
    {
      // [#imm, reg]
      op.reg = c;
      op.addr = b == LIMM ? li : d;
      op.membase = 1;
    }
  }
  switch ( insn.auxpref & aux_zmask )
  {
    default:
      op.dtype = dt_dword;
      break;
    case aux_b:
      op.dtype = dt_byte;
      break;
    case aux_w:
      op.dtype = dt_word;
      break;
  }
}

//----------------------------------------------------------------------
// doBranchOperand handles pc-relative word offsets.
// nothing special here.
void arc_t::doBranchOperand(const insn_t &insn, op_t &op, int l) const
{
  op.dtype = dt_dword;
  op.type = o_near;
  op.addr = trunc_ea(insn.ip + l * 4 + 4);
  op.offb = 0;
}

//----------------------------------------------------------------------
void arc_t::doRegisterInstruction(insn_t &insn, uint32 code)
{

  int i = (code >> 27) & 31;
  int a = (code >> 21) & 63;
  int b = (code >> 15) & 63;
  int c = (code >> 9)  & 63;

  /* the (maybe used?) short immediate value */
  uint32 d = code & 0x1FF;

  // sign-extend
  if ( d >= 0x100 )
    d -= 0x200;

  /* store the flags. if there are actually no flags at that place, they */
  /* will be reconstructed later */
  insn.auxpref = code & (aux_cmask|aux_f);

  switch ( i )
  {
    case 0:                    // LD register+register
      insn.itype = ARC_ld;
      insn.auxpref |= (code & aux_di);
      break;
    case 1:                    // LD register+offset, LR
      if ( code & (1 << 13) )
        insn.itype = ARC_lr;
      else
        insn.itype = ARC_ld;
      break;
    case 2:                    // ST, SR
      if ( code & (1 << 25) )
      {
        insn.itype = ARC_sr;
      }
      else
      {
        insn.itype = ARC_st;
        // 26 = Di
        // 24 = A
        // 23..22 = ZZ
        insn.auxpref = (code >> 20) & (aux_di|aux_amask|aux_zmask);
      }
      break;
    case 3:                    // single operand instructions
      switch ( c )
      {
        case 0:
          insn.itype = ARC_flag;
          a = b;                // flag has no 'a' operand, so we're moving the b-operand to a.
          break;
        case 1:
          insn.itype = ARC_asr;
          break;
        case 2:
          insn.itype = ARC_lsr;
          break;
        case 3:
          insn.itype = ARC_ror;
          break;
        case 4:
          insn.itype = ARC_rrc;
          break;
        case 5:
          insn.itype = ARC_sexb;
          break;
        case 6:
          insn.itype = ARC_sexw;
          break;
        case 7:
          insn.itype = ARC_extb;
          break;
        case 8:
          insn.itype = ARC_extw;
          break;
        case 9:
          insn.itype = ARC_swap;
          break;
        case 10:
          insn.itype = ARC_norm;
          break;
        case 0x3F:
          switch ( d )
          {
            case 0:
              insn.itype = ARC_brk;
              break;
            case 1:
              insn.itype = ARC_sleep;
              break;
            case 2:
              insn.itype = ARC_swi;
              break;
            default:
              return;
          }
          a = b = -1;
          insn.auxpref = 0;
          break;
      }
      c = -1;                   // c operand is no real operand, so don't try to convert it.
      break;
    case 7:                    // Jcc, JLcc
      insn.itype = ARC_j;
      if ( code & (1<<9) )
        insn.itype = ARC_jl;
      else
        insn.itype = ARC_j;
      // copy the NN bits
      insn.auxpref |= (code & aux_nmask);
      break;
    case 8:                    // ADD
      insn.itype = ARC_add;
      break;
    case 9:                    // ADC
      insn.itype = ARC_adc;
      break;
    case 10:                   // SUB
      insn.itype = ARC_sub;
      break;
    case 11:                   // SBC
      insn.itype = ARC_sbc;
      break;
    case 12:                   // AND
      insn.itype = ARC_and;
      break;
    case 13:                   // OR
      insn.itype = ARC_or;
      break;
    case 14:                   // BIC
      insn.itype = ARC_bic;
      break;
    case 15:                   // XOR
      insn.itype = ARC_xor;
      break;
    case 0x10:
      insn.itype = ARC_asl;
      break;
    case 0x11:
      insn.itype = ARC_lsr;
      break;
    case 0x12:
      insn.itype = ARC_asr;
      break;
    case 0x13:
      insn.itype = ARC_ror;
      break;
    case 0x14:
      insn.itype = ARC_mul64;
      break;
    case 0x15:
      insn.itype = ARC_mulu64;
      break;
    case 0x1E:
      insn.itype = ARC_max;
      break;
    case 0x1F:
      insn.itype = ARC_min;
      break;
  }

  uint32 immediate = 0;
  int noop3 = 0, isnop = 0;

  if ( a == SHIMM_F || b == SHIMM_F || c == SHIMM_F )
    insn.auxpref = aux_f;       // .f

  if ( b == SHIMM || c == SHIMM )
    insn.auxpref = 0;

  if ( b == LIMM || c == LIMM )
    immediate = insn.get_next_dword();

  /*
  pseudo instruction heuristic:

  we have some types of pseudo-instructions:

  (rS might be an immediate)
  insn                    will be coded as
  move rD, rS             and rD, rS, rS
  asl rD, rS              add rD, rS, rS
  lsl rD, rS              add rD, rS, rS (the same as asl, of course...)
  rlc rD, rS              adc.f rD, rS, rS
  rol rD, rS              add.f rD, rS, rS; adc rD, rD, 0
  nop                     xxx 0, 0, 0
  */

  switch ( insn.itype )
  {
    case ARC_flag:
      // special handling for flag, since its a-operand is a source here
      b = -1;
      break;

    case ARC_and:
    case ARC_or:
      if ( b == c )
      {
        noop3 = 1;
        insn.itype = ARC_mov;
      }
      break;

    case ARC_add:
      if ( b == c )
      {
        noop3 = 1;
        if ( b >= SHIMM_F )
        {
          // add rD, imm, imm -> move rD, imm*2
          insn.itype = ARC_mov;
          d <<= 1;
          immediate <<= 1;
        }
        else
        {
          insn.itype = ARC_lsl;
        }
      }
      break;

    case ARC_adc:
      if ( b == c )
      {
        noop3 = 1;
        insn.itype = ARC_rlc;
      }
      break;

    case ARC_xor:
      if ( code == 0x7FFFFFFF ) // XOR 0x1FF, 0x1FF, 0x1FF
        isnop = 1;
      break;
  }

  if ( !isnop )
  {
    if ( i == 0 )
    {
      // ld a, [b,c]
      doRegisterOperand(a, insn.Op1, d, immediate, 0);
      doIndirectOperand(insn, b, c, insn.Op2, d, immediate, false);
    }
    else if ( i == 1 || i == 2 )
    {
      /* fetch the flag-bits from the right location */
      if ( insn.itype == ARC_ld )
        insn.auxpref = (code >> 9) & 0x3F;
      else if ( insn.itype == ARC_st )
        insn.auxpref = (code >> 21) & 0x3F;
      else
        insn.auxpref = 0;
      if ( insn.itype == ARC_st || insn.itype == ARC_sr )
      {
        /* in a move to special register or load from special register,
           we have the target operand somewhere else */
        a = c;
        /* c=-1; not used anyway */
      }
      doRegisterOperand(a, insn.Op1, d, immediate, 0);
      doIndirectOperand(insn, b, SHIMM, insn.Op2, d, immediate, insn.itype == ARC_lr || insn.itype == ARC_sr);
    }
    else if ( i == 7 )
    {
      /* the jump (absolute) instruction, with a special imm-encoding */
      doRegisterOperand(b, insn.Op1, d, immediate, 1);
    }
    else
    {
      if ( a != -1 )
        doRegisterOperand(a, insn.Op1, 0, immediate, 0);
      /* this is a bugfix for the gnu-as: long immediate must be equal, while short */
      /* immediates don't have to. */
      if ( b != -1 )
        doRegisterOperand(b, insn.Op2, d, immediate, 0);
      if ( c != -1 && !noop3 )
        doRegisterOperand(c, insn.Op3, d, immediate, 0);
    }
  }
  else
  {
    insn.itype = ARC_nop;
    insn.auxpref = 0;
  }
}

//----------------------------------------------------------------------
void arc_t::doBranchInstruction(insn_t &insn, uint32 code) const
{
  int i = (code >> 27) & 31;

  int l = (code >> 7) & 0xFFFFF;  // note: bits 21..2, so it's in WORDS

  if ( l >= 0x80000 )             // sign-extend
    l = l - 0x100000;

  doBranchOperand(insn, insn.Op1, l);

  switch ( i )
  {
    case 4:                    // Bcc
      insn.itype = ARC_b;
      break;
    case 5:                    // BLcc
      insn.itype = ARC_bl;
      break;
    case 6:                    // LPcc
      insn.itype = ARC_lp;
      break;
  }
  insn.auxpref = code & (aux_cmask | aux_nmask);
}

//----------------------------------------------------------------------
// analyze ARCTangent-A4 (32-bit) instruction
int arc_t::ana_old(insn_t &insn)
{
  if ( insn.ea & 3 )
    return 0;

  insn.Op1.dtype = dt_dword;
  insn.Op2.dtype = dt_dword;
  insn.Op3.dtype = dt_dword;

  uint32 code = insn.get_next_dword();

  int i = (code >> 27) & 31;

  insn.itype = 0;

  switch ( i )
  {
    case 0:                    // LD register+register
    case 1:                    // LD register+offset, LR
    case 2:                    // ST, SR
    case 3:                    // single operand instructions
      doRegisterInstruction(insn, code);
      break;
    case 4:                    // Bcc
    case 5:                    // BLcc
    case 6:                    // LPcc
      doBranchInstruction(insn, code);
      break;
    case 7:                    // Jcc, JLcc
    case 8:                    // ADD
    case 9:                    // ADC
    case 10:                   // SUB
    case 11:                   // ADC
    case 12:                   // AND
    case 13:                   // OR
    case 14:                   // BIC
    case 15:                   // XOR
    default:
      doRegisterInstruction(insn, code);
      break;
  }

  return insn.size;
}

#define SUBTABLE(high, low, name) (0x80000000 | (high << 8) | low), 0, { 0,0,0 }, name
#define SUBTABLE2(high1, low1, high2, low2, name) (0x80000000 | (high1 << 24) | (low1 << 16) | (high2 << 8) | low2), 0, { 0,0,0 }, name

//----------------------------------------------------------------------
struct arcompact_opcode_t
{
  uint32 mnem;   // instruction itype, or indicator of sub-field decoding
  uint32 aux;    // auxpref and other flags
  uint32 ops[3]; // description of operands
  const arcompact_opcode_t *subtable; //lint !e958 padding is required to align members
};

enum aux_flags_t ENUM_SIZE(uint32)
{
  AUX_B = 1,          // implicit byte size access
  AUX_W = 2,          // implicit word size access
  Q_4_0 = 4,          //  4..0 QQQQQ condition code
  AAZZXD_23_15 = 8,   //  23..22,18..15  aa, ZZ, X, D flags (load reg+reg)
  DAAZZX_11_6 = 0x10, // 11..6   Di, aa, ZZ, X flags (load)
  DAAZZ_5_1   = 0x20, //  5..0   Di, aa, ZZ, R flags (store)
  AUX_D  = 0x40,      // implicit delay slot (.d)
  AUX_X  = 0x80,      // implicit sign extend (.x)
  AUX_CND = 0x100,    // implicit condition (in low 5 bits)
  N_5     = 0x200,    //  5..5     N delay slot bit
  AUX_GEN  = 0x400,   // 4..0 = Q if 23..22=0x3, bit 15 = F
  AUX_GEN2 = 0x800,   // 4..0 = Q if 23..22=0x3
  AUX_GEN3 =
    AUX_GEN|AUX_GEN2, // 4..0 = Q if 23..22=0x3, bit 15 = Di
  AUX_V2   = 0x1000,  // only available on ARCv2
  AUX_F    = 0x2000,  // use alternative instruction when F = 1
  AUX_AS   = 0x8000,  // implicit scaled access
  Q_5_0    = 0x10000, //  5..0 0QQQQQ condition code
  Y_3      = 0x20000, //  3         Y static branch prediction bit
};

enum op_fields_t ENUM_SIZE(uint32)
{
  fA32=1,         //  5..0                   a register operand (6 bits, r0-r63)
  fA16,           //  2..0                   a register operand (3 bits, r0-r3, r12-r15)
  fB32,           // 14..12 & 26..24         b register operand (6 bits)
  fB16,           // 10..8                   b register operand (3 bits)
  fC32,           // 11..6                   c register operand (6 bits)
  fC32_w6,        // 11..6 & 0            c/w6 register/immediate operand (6 bits)
  fC16,           //  7..5                   c register operand (3 bits)
  fH16,           //  2..0 & 7..5            h register operand (6 bits)
  fH16v2,         //  1..0 & 7..5            h register operand (5 bits)
  fH16v2_U5,      //  1..0 & 7..5, 10&4..3  [h, u5] (u5=u3*4)
  fG16,           //  4..3 & 10..8           g register operand (5 bits)
  fR16_2,         //  9..8                   R register operand (2 bits)
  fR16_1,         //  7                      R register operand (1 bit)
  S25,            // 15..6 & 26..17 & 0..3 s25 signed branch displacement
  S21,            // 15..6 & 26..17        s21 signed branch displacement
  S25L,           // 15..6 & 26..18 & 0..3 s25 signed branch displacement for branch and link
  S21L,           // 15..6 & 26..18        s21 signed branch displacement for branch and link
  S10,            //  8..0                 s10 signed branch displacement
  S9,             // 15..15 & 23..17        s9 signed branch displacement
  S8,             //  6..0                  s8 signed branch displacement
  S7,             //  5..0                  s7 signed branch displacement
  S13,            // 10..0                 s13 signed branch displacement
  U3,             //  2..0                  u2 unsigned immediate
  U5,             //  4..0                  u5 unsigned immediate
  U6,             // 11..6                  u6 unsigned immediate
  U6_SWI,         // 10..5                  u6 unsigned immediate
  U7,             //  6..0                  u7 unsigned immediate
  U7L,            //  4..0                  u7 unsigned immediate (u5*4)
  U8,             //  7..0                  u8 unsigned immediate
  U6_16,          //  6..4 & 2..0           u6 unsigned immediate
  U7_16,          //  7..4 & 2..0           u7 unsigned immediate
  U10_16,         //  9..0                 u10 unsigned immediate
  SP_U7,          //  4..0                 [SP, u7]   stack + offset (u7 = u5*4)
  PCL_U10,        //  7..0                 [PCL, u10] PCL + offset (u8*4)
  fB_U5,          //  10..8 & 4..0         [b, u5]
  fB_U6,          //  10..8 & 4..0         [b, u6] (u6=u5*2)
  fB_U7,          //  10..8 & 4..0         [b, u7] (u6=u5*4)
  fB_S9,          //  14..12&26..26, 15&23..16   [b, s9]
  GENA,           //  5..0
  GENB,           //  14..12 & 26..24
  GENC,           // 11..6 or 5..0 & 11..6
  GENC_PCREL,     // 11..6 or 5..0 & 11..6
  fBC_IND,        //  14..12 & 26..24, 11..6  [b, c]
  fBC16_IND,      //  10..8, 7..5  [b, c]
  R_SP,           // implicit SP
  R_BLINK,        // implicit BLINK
  O_ZERO,         // implicit immediate 0
  R_R0,           // implicit R0
  R_R1,           // implicit R1
  R_GP,           // implicit GP
  GP_S9,          //  8..0                 [GP, s9]   GP + offset
  GP_S10,         //  8..0                 [GP, s10]  GP + offset (s10 = s9*2)
  GP_S11,         //  8..0                 [GP, s11]  GP + offset (s11 = s9*4)
  S11,            //  8..0                  s11 signed immediate (s11 = s9*4)
  GP_S11_16,      // 10..5 & 4..2          [GP, s11]  GP + offset (s11 = s9*4)
  S3,             // 10..8                   s3 signed immediate
  EL,             //  4..1 & 10..8              enter / leave register set

  O_IND  = 0x80000000, // [reg], [imm] (jumps: only [reg])
  O_WIDE = 0x40000000, // register pair rNrN+1 with N even
  O_IDX  = 0x20000000, // instruction specific index

  O_FLAGS = O_IND|O_WIDE|O_IDX,
};

// indexed by bit 16 (maj = 0)
static const arcompact_opcode_t arcompact_maj0[2] =
{
  { ARC_b, Q_4_0 | N_5, {S21, 0, 0}, nullptr }, // 0
  { ARC_b, N_5,         {S25, 0, 0}, nullptr }, // 1
};

// indexed by bit 17 (maj = 1, b16 = 0)
static const arcompact_opcode_t arcompact_bl[2] =
{
  { ARC_bl, Q_4_0 | N_5, {S21L, 0, 0}, nullptr }, // 0
  { ARC_bl, N_5,         {S25L, 0, 0}, nullptr }, // 1
};

// indexed by bits 3..0 (maj = 1, b16 = 1, b4 = 0)
static const arcompact_opcode_t arcompact_br_regreg[0x10] =
{
  { ARC_br, AUX_CND|cEQ|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x00
  { ARC_br, AUX_CND|cNE|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x01
  { ARC_br, AUX_CND|cLT|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x02
  { ARC_br, AUX_CND|cGE|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x03
  { ARC_br, AUX_CND|cLO|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x04
  { ARC_br, AUX_CND|cHS|N_5|Y_3,        {fB32, fC32, S9}, nullptr }, // 0x05
  { ARC_bbit0, N_5|Y_3|AUX_V2,          {fB32, fC32, S9}, nullptr }, // 0x06
  { ARC_bbit1, N_5|Y_3|AUX_V2,          {fB32, fC32, S9}, nullptr }, // 0x07
  { ARC_br, AUX_CND|cEQ|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x08
  { ARC_br, AUX_CND|cNE|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x09
  { ARC_br, AUX_CND|cLT|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x0A
  { ARC_br, AUX_CND|cGE|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x0B
  { ARC_br, AUX_CND|cLO|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x0C
  { ARC_br, AUX_CND|cHS|N_5|Y_3|AUX_V2, {fB32, fC32, S9}, nullptr }, // 0x0D
  { ARC_bbit0, N_5|Y_3,                 {fB32, fC32, S9}, nullptr }, // 0x0E
  { ARC_bbit1, N_5|Y_3,                 {fB32, fC32, S9}, nullptr }, // 0x0F
};

// indexed by bits 3..0 (maj = 1, b16 = 1, b4 = 1)
static const arcompact_opcode_t arcompact_br_regimm[0x10] =
{
  { ARC_br, AUX_CND|cEQ|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x00
  { ARC_br, AUX_CND|cNE|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x01
  { ARC_br, AUX_CND|cLT|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x02
  { ARC_br, AUX_CND|cGE|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x03
  { ARC_br, AUX_CND|cLO|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x04
  { ARC_br, AUX_CND|cHS|N_5|Y_3,        {fB32, U6, S9}, nullptr }, // 0x05
  { ARC_bbit0, N_5|Y_3|AUX_V2,          {fB32, U6, S9}, nullptr }, // 0x06
  { ARC_bbit1, N_5|Y_3|AUX_V2,          {fB32, U6, S9}, nullptr }, // 0x07
  { ARC_br, AUX_CND|cEQ|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x08
  { ARC_br, AUX_CND|cNE|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x09
  { ARC_br, AUX_CND|cLT|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x0A
  { ARC_br, AUX_CND|cGE|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x0B
  { ARC_br, AUX_CND|cLO|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x0C
  { ARC_br, AUX_CND|cHS|N_5|Y_3|AUX_V2, {fB32, U6, S9}, nullptr }, // 0x0D
  { ARC_bbit0, N_5|Y_3,                 {fB32, U6, S9}, nullptr }, // 0x0E
  { ARC_bbit1, N_5|Y_3,                 {fB32, U6, S9}, nullptr }, // 0x0F
};

// indexed by bit 4 (maj = 1, b16 = 1)
static const arcompact_opcode_t arcompact_br[4] =
{
  { SUBTABLE( 3,  0, arcompact_br_regreg)       }, // 0
  { SUBTABLE( 3,  0, arcompact_br_regimm)       }, // 1
};

// indexed by bit 16 (maj = 1)
static const arcompact_opcode_t arcompact_maj1[0x40] =
{
  { SUBTABLE(17, 17, arcompact_bl)              }, // 0
  { SUBTABLE( 4,  4, arcompact_br)              }, // 1
};

// indexed by bits 14..12 & 26..24 (maj = 4, 21..16=0x2F, 5..0=0x3F)
static const arcompact_opcode_t arcompact_zop[0x40] =
{
  { 0 },                                  // 0x00
  { ARC_sleep, 0,   {GENC, 0, 0}, nullptr }, // 0x01
  { ARC_swi,   0,   {   0, 0, 0}, nullptr }, // 0x02
  { ARC_sync,  0,   {   0, 0, 0}, nullptr }, // 0x03
  { ARC_rtie,  0,   {   0, 0, 0}, nullptr }, // 0x04
  { ARC_brk,   0,   {   0, 0, 0}, nullptr }, // 0x05
  { ARC_seti,AUX_V2,{GENC, 0, 0}, nullptr }, // 0x06
  { ARC_clri,AUX_V2,{GENC, 0, 0}, nullptr }, // 0x07
  { ARC_wevt,  0,   {GENC, 0, 0}, nullptr }, // 0x08
  { 0 },                                  // 0x09
  { 0 },                                  // 0x0A
  { 0 },                                  // 0x0B
  { 0 },                                  // 0x0C
  { 0 },                                  // 0x0D
  { 0 },                                  // 0x0E
  { 0 },                                  // 0x0F
  { 0 },                                  // 0x20
  { 0 },                                  // 0x21
  { 0 },                                  // 0x22
  { 0 },                                  // 0x23
  { 0 },                                  // 0x24
  { 0 },                                  // 0x25
  { 0 },                                  // 0x26
  { 0 },                                  // 0x27
  { 0 },                                  // 0x28
  { 0 },                                  // 0x29
  { 0 },                                  // 0x2A
  { 0 },                                  // 0x2B
  { 0 },                                  // 0x2C
  { 0 },                                  // 0x2D
  { 0 },                                  // 0x2E
  { 0 },                                  // 0x2F
  { 0 },                                  // 0x30
  { 0 },                                  // 0x31
  { 0 },                                  // 0x32
  { 0 },                                  // 0x33
  { 0 },                                  // 0x34
  { 0 },                                  // 0x35
  { 0 },                                  // 0x36
  { 0 },                                  // 0x37
  { 0 },                                  // 0x38
  { 0 },                                  // 0x39
  { 0 },                                  // 0x3A
  { 0 },                                  // 0x3B
  { 0 },                                  // 0x3C
  { 0 },                                  // 0x3D
  { 0 },                                  // 0x3E
  { 0 },                                  // 0x3F
};

// indexed by bits 5..0 (maj = 4, 21..16=0x2F)
static const arcompact_opcode_t arcompact_sop[0x40] =
{
  { ARC_asl,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x00
  { ARC_asr,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x01
  { ARC_lsr,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x02
  { ARC_ror,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x03
  { ARC_rrc,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x04
  { ARC_sexb, AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x05
  { ARC_sexw, AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x06
  { ARC_extb, AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x07
  { ARC_extw, AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x08
  { ARC_abs,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x09
  { ARC_not,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x0A
  { ARC_rlc,  AUX_GEN, {GENB, GENC,    0}, nullptr }, // 0x0B
  { ARC_ex,   AUX_GEN, {GENB, GENC|O_IND,0},nullptr}, // 0x0C
  { ARC_rol,  AUX_V2|AUX_GEN, {GENB, GENC, 0}, nullptr }, // 0x0D
  { 0 },                                       // 0x0E
  { 0 },                                       // 0x0F
  { ARC_llock,AUX_GEN, {GENB, GENC|O_IND, 0}, nullptr }, // 0x10
  { ARC_scond,AUX_GEN, {GENB, GENC|O_IND, 0}, nullptr }, // 0x11
  { 0 },                                       // 0x12
  { 0 },                                       // 0x13
  { 0 },                                       // 0x14
  { 0 },                                       // 0x15
  { 0 },                                       // 0x16
  { 0 },                                       // 0x17
  { 0 },                                       // 0x18
  { 0 },                                       // 0x19
  { 0 },                                       // 0x1A
  { 0 },                                       // 0x1B
  { 0 },                                       // 0x1C
  { 0 },                                       // 0x1D
  { 0 },                                       // 0x1E
  { 0 },                                       // 0x1F
  { 0 },                                       // 0x20
  { 0 },                                       // 0x21
  { 0 },                                       // 0x22
  { 0 },                                       // 0x23
  { 0 },                                       // 0x24
  { 0 },                                       // 0x25
  { 0 },                                       // 0x26
  { 0 },                                       // 0x27
  { 0 },                                       // 0x28
  { 0 },                                       // 0x29
  { 0 },                                       // 0x2A
  { 0 },                                       // 0x2B
  { 0 },                                       // 0x2C
  { 0 },                                       // 0x2D
  { 0 },                                       // 0x2E
  { 0 },                                       // 0x2F
  { 0 },                                       // 0x30
  { 0 },                                       // 0x31
  { 0 },                                       // 0x32
  { 0 },                                       // 0x33
  { 0 },                                       // 0x34
  { 0 },                                       // 0x35
  { 0 },                                       // 0x36
  { 0 },                                       // 0x37
  { 0 },                                       // 0x38
  { 0 },                                       // 0x39
  { 0 },                                       // 0x3A
  { 0 },                                       // 0x3B
  { 0 },                                       // 0x3C
  { 0 },                                       // 0x3D
  { 0 },                                       // 0x3E
  { SUBTABLE2(14, 12, 26, 24, arcompact_zop) },// 0x3F
};

// indexed by bits 21..16 (maj = 4)
static const arcompact_opcode_t arcompact_maj4[0x40] =
{
  { ARC_add,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x00
  { ARC_adc,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x01
  { ARC_sub,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x02
  { ARC_sbc,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x03
  { ARC_and,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x04
  { ARC_or,   AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x05
  { ARC_bic,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x06
  { ARC_xor,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x07
  { ARC_max,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x08
  { ARC_min,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x09
  { ARC_mov,  AUX_GEN,          {GENB, GENC,    0},    nullptr }, // 0x0A
  { ARC_tst,  AUX_GEN2,         {GENB, GENC,    0},    nullptr }, // 0x0B
  { ARC_cmp,  AUX_GEN2,         {GENB, GENC,    0},    nullptr }, // 0x0C
  { ARC_rcmp, AUX_GEN,          {GENB, GENC,    0},    nullptr }, // 0x0D
  { ARC_rsub, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x0E
  { ARC_bset, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x0F
  { ARC_bclr, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x10
  { ARC_btst, AUX_GEN2,         {GENB, GENC,    0},    nullptr }, // 0x11
  { ARC_bxor, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x12
  { ARC_bmsk, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x13
  { ARC_add1, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x14
  { ARC_add2, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x15
  { ARC_add3, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x16
  { ARC_sub1, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x17
  { ARC_sub2, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x18
  { ARC_sub3, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x19
  { ARC_mpy,  AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1A
  { ARC_mpyh, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1B
  { ARC_mpyhu,AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1C
  { ARC_mpyu, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1D
  { ARC_mpyw, AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x1E
  { ARC_mpyuw,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x1F
  { ARC_j,    AUX_GEN,          {GENC|O_IND, 0, 0},    nullptr }, // 0x20
  { ARC_j,    AUX_GEN|AUX_D,    {GENC|O_IND, 0, 0},    nullptr }, // 0x21
  { ARC_jl,   AUX_GEN,          {GENC|O_IND, 0, 0},    nullptr }, // 0x22
  { ARC_jl,   AUX_GEN|AUX_D,    {GENC|O_IND, 0, 0},    nullptr }, // 0x23
  { ARC_bi,   AUX_V2,           {fC32|O_IDX, 0, 0},    nullptr }, // 0x24
  { ARC_bih,  AUX_V2,           {fC32|O_IDX, 0, 0},    nullptr }, // 0x25
  { ARC_ldi,  AUX_V2|Q_5_0,     {GENB, GENC|O_IDX, 0}, nullptr }, // 0x26
  { ARC_aex,  AUX_V2|AUX_GEN2,  {fB32, GENC|O_IND, 0}, nullptr }, // 0x27
  { ARC_lp,   AUX_GEN2,         {GENC_PCREL, 0, 0},    nullptr }, // 0x28
  { ARC_flag, AUX_GEN2,         {GENC,       0, 0},    nullptr }, // 0x29
  { ARC_lr,   0,                {GENB, GENC|O_IND, 0}, nullptr }, // 0x2A
  { ARC_sr,   0,                {GENB, GENC|O_IND, 0}, nullptr }, // 0x2B
  { ARC_bmskn,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x2C
  { ARC_null, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1C
  { ARC_null, AUX_GEN,          {GENA, GENB, GENC},    nullptr }, // 0x1D
  { SUBTABLE(5, 0, arcompact_sop)                           }, // 0x2F
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x30
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x31
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x32
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x33
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x34
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x35
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x36
  { ARC_ld, AAZZXD_23_15,       {fA32, fBC_IND, 0},    nullptr }, // 0x37
  { ARC_seteq,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x38
  { ARC_setne,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x39
  { ARC_setlt,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3A
  { ARC_setge,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3B
  { ARC_setlo,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3C
  { ARC_seths,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3D
  { ARC_setle,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3E
  { ARC_setgt,AUX_V2|AUX_GEN,   {GENA, GENB, GENC},    nullptr }, // 0x3F
};

// indexed by bits 14..12 & 26..24 (maj = 5, 21..16=0x2F, 5..0=0x3F)
static const arcompact_opcode_t arcompact_zop5[0x40 * 2] =
{
  { ARC_aslacc,  AUX_V2|AUX_F, {GENC, 0, 0}, nullptr }, // 0x00
  { ARC_aslsacc, AUX_V2|AUX_F, {GENC, 0, 0}, nullptr }, // 0x01
  { 0 },                                             // 0x02
  { 0 },                                             // 0x03
  { 0, AUX_F, {0, 0, 0}, nullptr },                     // 0x04(F=0)
  { ARC_modif, AUX_V2|AUX_F,   {GENC, 0, 0}, nullptr }, // 0x05
  { 0 },                                             // 0x06
  { 0 },                                             // 0x07
  { 0 },                                             // 0x08
  { 0 },                                             // 0x09
  { 0 },                                             // 0x0A
  { 0 },                                             // 0x0B
  { 0 },                                             // 0x0C
  { 0 },                                             // 0x0D
  { 0 },                                             // 0x0E
  { 0 },                                             // 0x0F
  { 0 },                                             // 0x10
  { 0 },                                             // 0x11
  { 0 },                                             // 0x12
  { 0 },                                             // 0x13
  { 0 },                                             // 0x14
  { 0 },                                             // 0x15
  { 0 },                                             // 0x16
  { 0 },                                             // 0x17
  { 0 },                                             // 0x18
  { 0 },                                             // 0x19
  { 0 },                                             // 0x1A
  { 0 },                                             // 0x1B
  { 0 },                                             // 0x1C
  { 0 },                                             // 0x1D
  { 0 },                                             // 0x1E
  { 0 },                                             // 0x1F
  { 0 },                                             // 0x20
  { 0 },                                             // 0x21
  { 0 },                                             // 0x22
  { 0 },                                             // 0x23
  { 0 },                                             // 0x24
  { 0 },                                             // 0x25
  { 0 },                                             // 0x26
  { 0 },                                             // 0x27
  { 0 },                                             // 0x28
  { 0 },                                             // 0x29
  { 0 },                                             // 0x2A
  { 0 },                                             // 0x2B
  { 0 },                                             // 0x2C
  { 0 },                                             // 0x2D
  { 0 },                                             // 0x2E
  { 0 },                                             // 0x2F
  { 0 },                                             // 0x30
  { 0 },                                             // 0x31
  { 0 },                                             // 0x32
  { 0 },                                             // 0x33
  { 0 },                                             // 0x34
  { 0 },                                             // 0x35
  { 0 },                                             // 0x36
  { 0 },                                             // 0x37
  { 0 },                                             // 0x38
  { 0 },                                             // 0x39
  { 0 },                                             // 0x3A
  { 0 },                                             // 0x3B
  { 0 },                                             // 0x3C
  { 0 },                                             // 0x3D
  { 0 },                                             // 0x3E
  { 0 },                                             // 0x3F

  { 0 },                                             // 0x00
  { 0 },                                             // 0x01
  { 0 },                                             // 0x02
  { 0 },                                             // 0x03
  { ARC_flagacc, AUX_V2, {GENC, 0, 0}, nullptr },       // 0x04(F=1)
  { 0 },                                             // 0x05
  { 0 },                                             // 0x06
  { 0 },                                             // 0x07
  { 0 },                                             // 0x08
  { 0 },                                             // 0x09
  { 0 },                                             // 0x0A
  { 0 },                                             // 0x0B
  { 0 },                                             // 0x0C
  { 0 },                                             // 0x0D
  { 0 },                                             // 0x0E
  { 0 },                                             // 0x0F
  { 0 },                                             // 0x10
  { 0 },                                             // 0x11
  { 0 },                                             // 0x12
  { 0 },                                             // 0x13
  { 0 },                                             // 0x14
  { 0 },                                             // 0x15
  { 0 },                                             // 0x16
  { 0 },                                             // 0x17
  { 0 },                                             // 0x18
  { 0 },                                             // 0x19
  { 0 },                                             // 0x1A
  { 0 },                                             // 0x1B
  { 0 },                                             // 0x1C
  { 0 },                                             // 0x1D
  { 0 },                                             // 0x1E
  { 0 },                                             // 0x1F
  { 0 },                                             // 0x20
  { 0 },                                             // 0x21
  { 0 },                                             // 0x22
  { 0 },                                             // 0x23
  { 0 },                                             // 0x24
  { 0 },                                             // 0x25
  { 0 },                                             // 0x26
  { 0 },                                             // 0x27
  { 0 },                                             // 0x28
  { 0 },                                             // 0x29
  { 0 },                                             // 0x2A
  { 0 },                                             // 0x2B
  { 0 },                                             // 0x2C
  { 0 },                                             // 0x2D
  { 0 },                                             // 0x2E
  { 0 },                                             // 0x2F
  { 0 },                                             // 0x30
  { 0 },                                             // 0x31
  { 0 },                                             // 0x32
  { 0 },                                             // 0x33
  { 0 },                                             // 0x34
  { 0 },                                             // 0x35
  { 0 },                                             // 0x36
  { 0 },                                             // 0x37
  { 0 },                                             // 0x38
  { 0 },                                             // 0x39
  { 0 },                                             // 0x3A
  { 0 },                                             // 0x3B
  { 0 },                                             // 0x3C
  { 0 },                                             // 0x3D
  { 0 },                                             // 0x3E
  { 0 },                                             // 0x3F
};

// indexed by bits 5..0 (maj = 5, 21..16=0x2F)
static const arcompact_opcode_t arcompact_sop5[0x40] =
{
  { ARC_swap,      AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x00
  { ARC_norm,      AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x01
  { ARC_sat16,     AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x02
  { ARC_rnd16,     AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x03
  { ARC_abssw,     AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x04
  { ARC_abss,      AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x05
  { ARC_negsw,     AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x06
  { ARC_negs,      AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x07
  { ARC_normw,     AUX_GEN,         {GENB, GENC, 0}, nullptr }, // 0x08
  { ARC_swape,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x09
  { ARC_lsl16,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0A
  { ARC_lsr16,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0B
  { ARC_asr16,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0C
  { ARC_asr8,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0D
  { ARC_lsr8,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0E
  { ARC_lsl8,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x0F
  { ARC_rol8,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x10
  { ARC_ror8,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x11
  { ARC_ffs,       AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x12
  { ARC_fls,       AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x13
  { 0 },                                                     // 0x14
  { 0 },                                                     // 0x15
  { 0 },                                                     // 0x16
  { 0 },                                                     // 0x17
  { ARC_getacc,    AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x18
  { ARC_normacc,   AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x19
  { ARC_satf,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x1A
  { 0 },                                                     // 0x1B
  { ARC_vpack2hbl, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x1C
  { ARC_vpack2hbm, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x1D
  { ARC_vpack2hblf,AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x1E
  { ARC_vpack2hbmf,AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x1F
  { ARC_vext2bhlf, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x20
  { ARC_vext2bhmf, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x21
  { ARC_vrep2hl,   AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x22
  { ARC_vrep2hm,   AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x23
  { ARC_vext2bhl,  AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x24
  { ARC_vext2bhm,  AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x25
  { ARC_vsext2bhl, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x26
  { ARC_vsext2bhm, AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x27
  { ARC_vabs2h,    AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x28
  { ARC_vabss2h,   AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x29
  { ARC_vneg2h,    AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x2A
  { ARC_vnegs2h,   AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x2B
  { ARC_vnorm2h,   AUX_GEN2|AUX_V2, {GENB, GENC, 0}, nullptr }, // 0x2C
  { 0 },                                                     // 0x2D
  { ARC_bspeek,    AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x2E
  { ARC_bspop,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x2F
  { ARC_sqrt,      AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x30
  { ARC_sqrtf,     AUX_GEN|AUX_V2,  {GENB, GENC, 0}, nullptr }, // 0x31
  { 0 },                                                     // 0x32
  { 0 },                                                     // 0x33
  { 0 },                                                     // 0x34
  { 0 },                                                     // 0x35
  { 0 },                                                     // 0x36
  { 0 },                                                     // 0x37
  { 0 },                                                     // 0x38
  { 0 },                                                     // 0x39
  { 0 },                                                     // 0x3A
  { 0 },                                                     // 0x3B
  { 0 },                                                     // 0x3C
  { 0 },                                                     // 0x3D
  { 0 },                                                     // 0x3E
  { SUBTABLE2(14, 12, 26, 24, arcompact_zop5)             }, // 0x3F
};

// indexed by bits 21..16 (maj = 5)
static const arcompact_opcode_t arcompact_maj5[0x40] =
{
  { ARC_asl,     AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x00
  { ARC_lsr,     AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x01
  { ARC_asr,     AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x02
  { ARC_ror,     AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x03
  { ARC_mul64,   AUX_GEN, {O_ZERO,GENB,GENC}, nullptr }, // 0x04
  { ARC_mulu64,  AUX_GEN, {O_ZERO,GENB,GENC}, nullptr }, // 0x05
  { ARC_adds,    AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x06
  { ARC_subs,    AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x07
  { ARC_divaw,   AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x08
  { 0 },                                      // 0x09
  { ARC_asls,    AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x0A
  { ARC_asrs,    AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x0B
  { ARC_muldw,   AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x0C
  { ARC_muludw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x0D
  { ARC_mulrdw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x0E
  { 0 },                                      // 0x0F
  { ARC_macdw,   AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x10
  { ARC_macudw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x11
  { ARC_macrdw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x12
  { 0 },                                              // 0x13
  { ARC_msubdw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x14
  { 0 },                                              // 0x15
  { 0 },                                              // 0x16
  { 0 },                                              // 0x17
  { 0 },                                              // 0x18
  { 0 },                                              // 0x19
  { 0 },                                              // 0x1A
  { 0 },                                              // 0x1B
  { 0 },                                              // 0x1C
  { 0 },                                              // 0x1D
  { 0 },                                              // 0x1E
  { 0 },                                              // 0x1F
  { 0 },                                              // 0x20
  { 0 },                                              // 0x21
  { 0 },                                              // 0x22
  { 0 },                                              // 0x23
  { 0 },                                              // 0x24
  { 0 },                                              // 0x25
  { 0 },                                              // 0x26
  { 0 },                                              // 0x27
  { ARC_addsdw,  AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x28
  { ARC_subsdw,  AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 0x29
  { 0 },                                              // 0x2A
  { 0 },                                              // 0x2B
  { 0 },                                              // 0x2C
  { 0 },                                              // 0x2D
  { 0 },                                              // 0x2E
  { SUBTABLE(5,  0, arcompact_sop5)                }, // 0x2F
  { ARC_mululw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x30
  { ARC_mullw,   AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x31
  { ARC_mulflw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x32
  { ARC_maclw,   AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x33
  { ARC_macflw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x34
  { ARC_machulw, AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x35
  { ARC_machlw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x36
  { ARC_machflw, AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x37
  { ARC_mulhlw,  AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x38
  { ARC_mulhflw, AUX_GEN, {GENB, GENC, GENC}, nullptr }, // 0x39
  { 0 },                                              // 0x3A
  { 0 },                                              // 0x3B
  { 0 },                                              // 0x3C
  { 0 },                                              // 0x3D
  { 0 },                                              // 0x3E
  { 0 },                                              // 0x3F
};

// indexed by bits 21..16 (maj = 5)
static const arcompact_opcode_t arcv2_maj5[0x40 * 2] =
{
  { ARC_asl,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x00
  { ARC_lsr,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x01
  { ARC_asr,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x02
  { ARC_ror,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x03
  { ARC_div,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x04
  { ARC_divu,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x05
  { ARC_adds,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x06
  { ARC_subs,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x07
  { ARC_rem,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x08
  { ARC_remu,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x09
  { ARC_asls,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x0A
  { ARC_asrs,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x0B
  { ARC_asrsr,    AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x0C
  { ARC_valgn2h,  AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x0D(F=0)
  { ARC_mac,      AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x0E
  { ARC_macu,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x0F
  { ARC_dmpyh,    AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x10
  { ARC_dmpyhu,   AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x11
  { ARC_dmach,    AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x12
  { ARC_dmachu,   AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x13
  { ARC_vadd2h,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x14(F=0)
  { ARC_vsub2h,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x15(F=0)
  { ARC_vaddsub2h,AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x16(F=0)
  { ARC_vsubadd2h,AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x17(F=0)
  { ARC_mpyd,     AUX_GEN,       {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x18
  { ARC_mpydu,    AUX_GEN,       {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x19
  { ARC_macd,     AUX_GEN,       {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1A
  { ARC_macdu,    AUX_GEN,       {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1B
  { ARC_vmpy2h,   AUX_GEN|AUX_F, {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1C(F=0)
  { ARC_vmpy2hu,  AUX_GEN|AUX_F, {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1D(F=0)
  { ARC_vmac2h,   AUX_GEN|AUX_F, {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1E(F=0)
  { ARC_vmac2hu,  AUX_GEN|AUX_F, {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x1F(F=0)
  { ARC_vmpy2hwf, AUX_GEN|AUX_F, {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x20(F=0)
  { ARC_vasl2h,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x21(F=0)
  { ARC_vasr2h,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x22(F=0)
  { ARC_vlsr2h,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x23(F=0)
  { ARC_vadd4b,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x24(F=0)
  { ARC_vsub4b,   AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x25(F=0)
  { ARC_adcs,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x26
  { ARC_sbcs,     AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x27
  { ARC_dmpyhwf,  AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x28
  { ARC_vpack2hl, AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x29(F=0)
  { ARC_dmpyhf,   AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x2A
  { ARC_dmpyhfr,  AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x2B
  { ARC_dmachf,   AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x2C
  { ARC_dmachfr,  AUX_GEN,       {GENA,        GENB, GENC}, nullptr }, // 0x2D
  { ARC_vperm,    AUX_GEN|AUX_F, {GENA,        GENB, GENC}, nullptr }, // 0x2E
  { SUBTABLE(5,  0, arcompact_sop5)                              }, // 0x2F
  { 0 },                                                            // 0x30
  { 0 },                                                            // 0x31
  { 0 },                                                            // 0x32
  { 0 },                                                            // 0x33
  { 0 },                                                            // 0x34
  { 0 },                                                            // 0x35
  { 0 },                                                            // 0x36
  { 0 },                                                            // 0x37
  { 0 },                                                            // 0x38
  { 0 },                                                            // 0x39
  { 0 },                                                            // 0x3A
  { 0 },                                                            // 0x3B
  { 0 },                                                            // 0x3C
  { 0 },                                                            // 0x3D
  { 0 },                                                            // 0x3E
  { 0 },                                                            // 0x3F

  { 0 },                                                    // 0x00(F=1)
  { 0 },                                                    // 0x01(F=1)
  { 0 },                                                    // 0x02(F=1)
  { 0 },                                                    // 0x03(F=1)
  { 0 },                                                    // 0x04(F=1)
  { 0 },                                                    // 0x05(F=1)
  { 0 },                                                    // 0x06(F=1)
  { 0 },                                                    // 0x07(F=1)
  { 0 },                                                    // 0x08(F=1)
  { 0 },                                                    // 0x09(F=1)
  { 0 },                                                    // 0x0A(F=1)
  { 0 },                                                    // 0x0B(F=1)
  { 0 },                                                    // 0x0C(F=1)
  { ARC_setacc,     AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x0D(F=1)
  { 0 },                                                    // 0x0E(F=1)
  { 0 },                                                    // 0x0F(F=1)
  { 0 },                                                    // 0x10(F=1)
  { 0 },                                                    // 0x11(F=1)
  { 0 },                                                    // 0x12(F=1)
  { 0 },                                                    // 0x13(F=1)
  { ARC_vadds2h,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x14(F=1)
  { ARC_vsubs2h,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x15(F=1)
  { ARC_vaddsubs2h, AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x16(F=1)
  { ARC_vsubadds2h, AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x17(F=1)
  { 0 },                                                    // 0x18(F=1)
  { 0 },                                                    // 0x19(F=1)
  { 0 },                                                    // 0x1A(F=1)
  { 0 },                                                    // 0x1B(F=1)
  { ARC_vmpy2hf,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x1C(F=1)
  { ARC_vmpy2hfr,   AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x1D(F=1)
  { ARC_vmac2hf,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x1E(F=1)
  { ARC_vmac2hfr,   AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x1F(F=1)
  { 0 },                                                    // 0x20(F=1)
  { ARC_vasls2h,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x21(F=1)
  { ARC_vasrs2h,    AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x22(F=1)
  { ARC_vasrsr2h,   AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x23(F=1)
  { ARC_vmax2h,     AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x24(F=1)
  { ARC_vmin2h,     AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x25(F=1)
  { 0 },                                                    // 0x26(F=1)
  { 0 },                                                    // 0x27(F=1)
  { 0 },                                                    // 0x28(F=1)
  { ARC_vpack2hm,   AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x29(F=1)
  { 0 },                                                    // 0x2A(F=1)
  { 0 },                                                    // 0x2B(F=1)
  { 0 },                                                    // 0x2C(F=1)
  { 0 },                                                    // 0x2D(F=1)
  { ARC_bspush,     AUX_GEN2,   {GENA, GENB, GENC}, nullptr }, // 0x2E(F=1)
  { 0 },                                                    // 0x2F(F=1)
  { 0 },                                                    // 0x30(F=1)
  { 0 },                                                    // 0x31(F=1)
  { 0 },                                                    // 0x32(F=1)
  { 0 },                                                    // 0x33(F=1)
  { 0 },                                                    // 0x34(F=1)
  { 0 },                                                    // 0x35(F=1)
  { 0 },                                                    // 0x36(F=1)
  { 0 },                                                    // 0x37(F=1)
  { 0 },                                                    // 0x38(F=1)
  { 0 },                                                    // 0x39(F=1)
  { 0 },                                                    // 0x3A(F=1)
  { 0 },                                                    // 0x3B(F=1)
  { 0 },                                                    // 0x3C(F=1)
  { 0 },                                                    // 0x3D(F=1)
  { 0 },                                                    // 0x3E(F=1)
  { 0 },                                                    // 0x3F(F=1)
};

// indexed by bits 21..16
static const arcompact_opcode_t arcompact_maj6_1[0x40] =
{
  { ARC_fmul, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 00
  { ARC_fadd, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 01
  { ARC_fsub, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 02
  { 0 },                                               // 03
  { 0 },                                               // 04
  { 0 },                                               // 05
  { 0 },                                               // 06
  { 0 },                                               // 07
  { ARC_dmulh11, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 08
  { ARC_dmulh12, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 09
  { ARC_dmulh21, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0a
  { ARC_dmulh22, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0b
  { ARC_daddh11, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0c
  { ARC_daddh12, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0d
  { ARC_daddh21, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0e
  { ARC_daddh22, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 0f
  { ARC_dsubh11, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 10
  { ARC_dsubh12, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 11
  { ARC_dsubh21, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 12
  { ARC_dsubh22, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 13
  { ARC_drsubh11, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 14
  { ARC_drsubh12, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 15
  { ARC_drsubh21, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 16
  { ARC_drsubh22, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 17
  { ARC_dexcl1, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 18
  { ARC_dexcl2, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 19
  { 0 },                                                // 1a
  { 0 },                                                // 1b
  { 0 },                                                // 1c
  { 0 },                                                // 1d
  { 0 },                                                // 1e
  { 0 },                                                // 1f
  { ARC_pkqb,  AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 20
  { ARC_upkqb, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 21
  { ARC_xpkqb, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 22
  { ARC_avgqb, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 23
  { ARC_addqbs, AUX_GEN, {GENA, GENB, GENC}, nullptr },// 24
  { ARC_mpyqb, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 25
  { ARC_fxtr, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 26
  { ARC_iaddr, AUX_GEN, {GENA, GENB, GENC}, nullptr }, // 27
  { ARC_acm, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 28
  { ARC_sfxtr, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 29
  { ARC_clamp, AUX_GEN, {GENA, GENB, GENC}, nullptr },  // 2a
  { 0 },                                               // 2b
  { 0 },                                               // 2c
  { 0 },                                               // 2d
  { 0 },                                               // 2e
  { 0 },                                               // 2f
  { 0 },                                                // 30
  { 0 },                                                // 31
  { 0 },                                                // 32
  { 0 },                                                // 33
  { 0 },                                                // 34
  { 0 },                                                // 35
  { 0 },                                                // 36
  { 0 },                                                // 37
  { 0 },                                                // 38
  { 0 },                                                // 39
  { 0 },                                                // 3a
  { 0 },                                                // 3b
  { 0 },                                                // 3c
  { 0 },                                                // 3d
  { 0 },                                                // 3e
  { 0 }                                                // 3f
};

// indexed by bits 23..22
static const arcompact_opcode_t arcompact_maj6[4] =
{
  { SUBTABLE(21, 16, arcompact_maj6_1) }, // 00
  { SUBTABLE(21, 16, arcompact_maj6_1) }, // 01
  { SUBTABLE(21, 16, arcompact_maj6_1) }, // 02
  { 0 } // to be implemented
};

// indexed by bits 5..0 (maj = 6, 21..16=0x2F)
static const arcompact_opcode_t arcv2_sop6[0x40] =
{
  { ARC_fssqrt,     AUX_GEN2,       {GENB, GENC, 0}, nullptr }, // 0x00(F=0) reference doesn't specify minor opcode
  { 0 },                                                     // 0x01
  { 0 },                                                     // 0x02
  { 0 },                                                     // 0x03
  { 0 },                                                     // 0x04
  { 0 },                                                     // 0x05
  { 0 },                                                     // 0x06
  { 0 },                                                     // 0x07
  { 0 },                                                     // 0x08
  { 0 },                                                     // 0x09
  { 0 },                                                     // 0x0A
  { 0 },                                                     // 0x0B
  { 0 },                                                     // 0x0C
  { 0 },                                                     // 0x0D
  { 0 },                                                     // 0x0E
  { 0 },                                                     // 0x0F
  { 0 },                                                     // 0x10
  { 0 },                                                     // 0x11
  { 0 },                                                     // 0x12
  { 0 },                                                     // 0x13
  { 0 },                                                     // 0x14
  { 0 },                                                     // 0x15
  { 0 },                                                     // 0x16
  { 0 },                                                     // 0x17
  { 0 },                                                     // 0x18
  { 0 },                                                     // 0x18
  { 0 },                                                     // 0x1A
  { ARC_cbflyhf1r,  AUX_GEN2,       {GENB, GENC, 0}, nullptr }, // 0x1B(F=0) according to reference
  { 0 },                                                     // 0x1C
  { 0 },                                                     // 0x1D
  { 0 },                                                     // 0x1E
  { 0 },                                                     // 0x1F
  { 0 },                                                     // 0x20
  { 0 },                                                     // 0x21
  { 0 },                                                     // 0x22
  { 0 },                                                     // 0x23
  { 0 },                                                     // 0x24
  { 0 },                                                     // 0x25
  { 0 },                                                     // 0x26
  { 0 },                                                     // 0x27
  { 0 },                                                     // 0x28
  { 0 },                                                     // 0x29
  { 0 },                                                     // 0x2A
  { 0 },                                                     // 0x2B
  { 0 },                                                     // 0x2C
  { 0 },                                                     // 0x2D
  { 0 },                                                     // 0x2E
  { 0 },                                                     // 0x2F
  { 0 },                                                     // 0x30
  { 0 },                                                     // 0x31
  { 0 },                                                     // 0x32
  { 0 },                                                     // 0x33
  { 0 },                                                     // 0x34
  { 0 },                                                     // 0x35
  { 0 },                                                     // 0x36
  { 0 },                                                     // 0x37
  { 0 },                                                     // 0x38
  { ARC_cbflyhf1r,  AUX_GEN2,       {GENB, GENC, 0}, nullptr }, // 0x39(F=0) as encoded by the toolchain
  { 0 },                                                     // 0x3A
  { 0 },                                                     // 0x3B
  { 0 },                                                     // 0x3C
  { 0 },                                                     // 0x3D
  { 0 },                                                     // 0x3E
  { 0 },                                                     // 0x3F
};

static const arcompact_opcode_t arcv2_maj6[0x40 * 2] =
{
  { ARC_fmul,       AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x00(F=0)
  { ARC_fadd,       AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x01(F=0)
  { ARC_fsub,       AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x02(F=0)
  { ARC_vmsub2hfr,  AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x03(F=0)
  { ARC_vmsub2hf,   AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x04(F=0)
  { ARC_fsmadd,     AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x05(F=0)
  { ARC_fsmsub,     AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x06(F=0)
  { ARC_fsdiv,      AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x07(F=0)
  { ARC_fcvt32,     AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x08(F=0)
  { 0, AUX_F, {0, 0, 0}, nullptr },                                     // 0x09(F=0)
  { ARC_mpyf,       AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0A
  { ARC_mpyfr,      AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0B
  { ARC_macf,       AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0C
  { ARC_macfr,      AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0D
  { ARC_msubf,      AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0E
  { ARC_msubfr,     AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x0F
  { ARC_divf,       AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x10
  { ARC_vmac2hnfr,  AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x11
  { ARC_mpydf,      AUX_GEN,      {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x12
  { ARC_macdf,      AUX_GEN,      {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x13
  { ARC_msubwhfl,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x14
  { ARC_msubdf,     AUX_GEN,      {GENA|O_WIDE, GENB, GENC}, nullptr }, // 0x15
  { ARC_dmpyhbl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x16
  { ARC_dmpyhbm,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x17
  { ARC_dmachbl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x18
  { ARC_dmachbm,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x19
  { ARC_msubwhflr,  AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x1A
  { ARC_cmpyhfmr,   AUX_GEN|AUX_F,{GENA,        GENB, GENC}, nullptr }, // 0x1B
  { ARC_mpywhl,     AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x1C
  { ARC_macwhl,     AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x1D
  { ARC_mpywhul,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x1E
  { ARC_macwhul,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x1F
  { ARC_mpywhfm,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x20
  { ARC_mpywhfmr,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x21
  { ARC_macwhfm,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x22
  { ARC_macwhfmr,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x23
  { ARC_mpywhfl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x24
  { ARC_mpywhflr,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x25
  { ARC_macwhfl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x26
  { ARC_macwhflr,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x27
  { ARC_macwhkl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x28
  { ARC_macwhkul,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x29
  { ARC_mpywhkl,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x2A
  { ARC_mpywhkul,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x2B
  { ARC_msubwhfm,   AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x2C
  { ARC_msubwhfmr,  AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x2D
  { 0 },                                                             // 0x2E
  { SUBTABLE(5,  0, arcv2_sop6)                                   }, // 0x2F
  { ARC_dmulh11,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x30
  { ARC_dmulh12,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x31
  { ARC_dmulh21,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x32
  { ARC_dmulh22,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x33
  { ARC_daddh11,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x34
  { ARC_daddh12,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x35
  { ARC_daddh21,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x36
  { ARC_daddh22,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x37
  { ARC_dsubh11,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x38
  { ARC_dsubh12,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x39
  { ARC_dsubh21,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x3A
  { ARC_dsubh22,    AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x3B
  { ARC_dexcl1,     AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x3C
  { ARC_dexcl2,     AUX_GEN,      {GENA,        GENB, GENC}, nullptr }, // 0x3D
  { 0 },                                                             // 0x3E
  { 0 },                                                             // 0x3F

  { ARC_cmpyhnfr,   AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x00
  { ARC_cmpyhfr,    AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x01
  { ARC_cmpychnfr,  AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x02
  { ARC_fscmp,      AUX_GEN2,     {GENB,        GENC,    0}, nullptr }, // 0x03
  { ARC_fscmpf,     AUX_GEN2,     {GENB,        GENC,    0}, nullptr }, // 0x04
  { ARC_cmpychfr,   AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x05
  { ARC_cmachnfr,   AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x06
  { ARC_cmachfr,    AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x07
  { ARC_cmacchnfr,  AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x08
  { ARC_cmacchfr,   AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x09
  { 0 },                                                             // 0x0A
  { 0 },                                                             // 0x0B
  { 0 },                                                             // 0x0C
  { 0 },                                                             // 0x0D
  { 0 },                                                             // 0x0E
  { 0 },                                                             // 0x0F
  { 0 },                                                             // 0x10
  { ARC_vmsub2hnfr, AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x11
  { 0 },                                                             // 0x12
  { 0 },                                                             // 0x13
  { 0 },                                                             // 0x14
  { 0 },                                                             // 0x15
  { 0 },                                                             // 0x16
  { 0 },                                                             // 0x17
  { 0 },                                                             // 0x18
  { 0 },                                                             // 0x19
  { 0 },                                                             // 0x1A
  { ARC_cbflyhf0r,  AUX_GEN2,     {GENA,        GENB, GENC}, nullptr }, // 0x1B
  { 0 },                                                             // 0x1C
  { 0 },                                                             // 0x1D
  { 0 },                                                             // 0x1E
  { 0 },                                                             // 0x1F
  { 0 },                                                             // 0x20
  { 0 },                                                             // 0x21
  { 0 },                                                             // 0x22
  { 0 },                                                             // 0x23
  { 0 },                                                             // 0x24
  { 0 },                                                             // 0x25
  { 0 },                                                             // 0x26
  { 0 },                                                             // 0x27
  { 0 },                                                             // 0x28
  { 0 },                                                             // 0x29
  { 0 },                                                             // 0x2A
  { 0 },                                                             // 0x2B
  { 0 },                                                             // 0x2C
  { 0 },                                                             // 0x2D
  { 0 },                                                             // 0x2E
  { 0 },                                                             // 0x2F
  { 0 },                                                             // 0x30
  { 0 },                                                             // 0x31
  { 0 },                                                             // 0x32
  { 0 },                                                             // 0x33
  { 0 },                                                             // 0x34
  { 0 },                                                             // 0x35
  { 0 },                                                             // 0x36
  { 0 },                                                             // 0x37
  { 0 },                                                             // 0x38
  { 0 },                                                             // 0x39
  { 0 },                                                             // 0x3A
  { 0 },                                                             // 0x3B
  { 0 },                                                             // 0x3C
  { 0 },                                                             // 0x3D
  { 0 },                                                             // 0x3E
  { 0 },                                                             // 0x3F
};

// indexed by bits 4..3 (maj = 0xC)
static const arcompact_opcode_t arcompact_maj0C[4] =
{
  { ARC_ld, 0,     { fA16, fBC16_IND, 0}, nullptr }, // 0x0
  { ARC_ld, AUX_B, { fA16, fBC16_IND, 0}, nullptr }, // 0x1
  { ARC_ld, AUX_W, { fA16, fBC16_IND, 0}, nullptr }, // 0x2
  { ARC_add, 0,    { fA16, fB16,  fC16 }, nullptr }, // 0x3
};

// indexed by bits 4..3 (maj = 0xD)
static const arcompact_opcode_t arcompact_maj0D[4] =
{
  { ARC_add, 0, {fC16, fB16, U3 }, nullptr }, // 0x00
  { ARC_sub, 0, {fC16, fB16, U3 }, nullptr }, // 0x01
  { ARC_asl, 0, {fC16, fB16, U3 }, nullptr }, // 0x02
  { ARC_asr, 0, {fC16, fB16, U3 }, nullptr }, // 0x03
};

// indexed by bits 4..3 (maj = 0xE)
static const arcompact_opcode_t arcompact_maj0E[4] =
{
  { ARC_add, 0,        {fB16, fB16, fH16}, nullptr }, // 0x00
  { ARC_mov, 0,        {fB16, fH16, 0   }, nullptr }, // 0x01
  { ARC_cmp, 0,        {fB16, fH16, 0   }, nullptr }, // 0x02
  { ARC_mov, 0,        {fH16, fB16, 0   }, nullptr }, // 0x03
};

// indexed by bits 4..3 (maj = 0xE)
static const arcompact_opcode_t arcv2_maj0E[8] =
{
  { ARC_add, 0,           {fB16,   fB16,   fH16v2}, nullptr }, // 0x00
  { ARC_add, 0,           {fH16v2, fH16v2, S3    }, nullptr }, // 0x01
  { 0 },                                                    // 0x02
  { ARC_mov, 0,           {fH16v2, S3,     0     }, nullptr }, // 0x03
  { ARC_cmp, 0,           {fB16,   fH16v2, 0     }, nullptr }, // 0x04
  { ARC_cmp, 0,           {fH16v2, S3,     0     }, nullptr }, // 0x05
  { 0 },                                                    // 0x06
  { ARC_mov, AUX_CND|cNE, {fB16,   fH16v2, 0     }, nullptr }, // 0x07
};

// indexed by bits 10..8 (maj = 0xF, 4..0 = 0x0, 7..5=0x7)
// 01111 iii 111 00000
static const arcompact_opcode_t arcompact_zop16[8] =
{
  { ARC_nop,          0, { 0, 0, 0},            nullptr }, // 0x00
  { ARC_unimp,        0, { 0, 0, 0},            nullptr }, // 0x01
  { ARC_swi,          0, { 0, 0, 0},            nullptr }, // 0x02
  { 0 },                                                // 0x03
  { ARC_j,  AUX_CND|cEQ, {R_BLINK|O_IND, 0, 0}, nullptr }, // 0x04
  { ARC_j,  AUX_CND|cNE, {R_BLINK|O_IND, 0, 0}, nullptr }, // 0x05
  { ARC_j,            0, {R_BLINK|O_IND, 0, 0}, nullptr }, // 0x06
  { ARC_j,        AUX_D, {R_BLINK|O_IND, 0, 0}, nullptr }, // 0x07
};

// indexed by bits 7..5 (maj = 0xF, 4..0 = 0x0)
// 01111 bbb iii 00000
static const arcompact_opcode_t arcompact_sop16[8] =
{
  { ARC_j,            0,  {fB16|O_IND, 0, 0}, nullptr }, // 0x00
  { ARC_j,        AUX_D,  {fB16|O_IND, 0, 0}, nullptr }, // 0x01
  { ARC_jl,           0,  {fB16|O_IND, 0, 0}, nullptr }, // 0x02
  { ARC_jl,       AUX_D,  {fB16|O_IND, 0, 0}, nullptr }, // 0x03
  { 0 },                                              // 0x04
  { 0 },                                              // 0x05
  { ARC_sub, AUX_CND|cNE, {fB16, fB16, fB16}, nullptr }, // 0x06
  { SUBTABLE(10, 8, arcompact_zop16)               }, // 0x07
};

// indexed by bits 4..0 (maj = 0xF)
// 01111 bbb ccc iiiii
static const arcompact_opcode_t arcompact_maj0F[0x20] =
{
  { SUBTABLE(7, 5, arcompact_sop16)        }, // 0x00
  { 0 },                                      // 0x01
  { ARC_sub,   0, {fB16, fB16, fC16}, nullptr }, // 0x02
  { 0 },                                      // 0x03
  { ARC_and,   0, {fB16, fB16, fC16}, nullptr }, // 0x04
  { ARC_or,    0, {fB16, fB16, fC16}, nullptr }, // 0x05
  { ARC_bic,   0, {fB16, fB16, fC16}, nullptr }, // 0x06
  { ARC_xor,   0, {fB16, fB16, fC16}, nullptr }, // 0x05
  { 0 },                                      // 0x08
  { 0 },                                      // 0x09
  { 0 },                                      // 0x0A
  { ARC_tst,   0, {fB16, fC16, 0   }, nullptr }, // 0x0B
  { ARC_mul64, 0, {fB16, fC16, 0   }, nullptr }, // 0x0C
  { ARC_sexb,  0, {fB16, fC16, 0   }, nullptr }, // 0x0D
  { ARC_sexw,  0, {fB16, fC16, 0   }, nullptr }, // 0x0E
  { ARC_extb,  0, {fB16, fC16, 0   }, nullptr }, // 0x0F
  { ARC_extw,  0, {fB16, fC16, 0   }, nullptr }, // 0x10
  { ARC_abs,   0, {fB16, fC16, 0   }, nullptr }, // 0x11
  { ARC_not,   0, {fB16, fC16, 0   }, nullptr }, // 0x12
  { ARC_neg,   0, {fB16, fC16, 0   }, nullptr }, // 0x13
  { ARC_add1,  0, {fB16, fB16, fC16}, nullptr }, // 0x14
  { ARC_add2,  0, {fB16, fB16, fC16}, nullptr }, // 0x15
  { ARC_add3,  0, {fB16, fB16, fC16}, nullptr }, // 0x16
  { 0 },                                      // 0x17
  { ARC_asl,   0, {fB16, fB16, fC16}, nullptr }, // 0x18
  { ARC_lsr,   0, {fB16, fB16, fC16}, nullptr }, // 0x19
  { ARC_asr,   0, {fB16, fB16, fC16}, nullptr }, // 0x1A
  { ARC_asl,   0, {fB16, fC16, 0   }, nullptr }, // 0x1B
  { ARC_asr,   0, {fB16, fC16, 0   }, nullptr }, // 0x1C
  { ARC_lsr,   0, {fB16, fC16, 0   }, nullptr }, // 0x1D
  { ARC_trap,  0, {   0,    0, 0   }, nullptr }, // 0x1E
  { ARC_brk,   0, {   0,    0, 0   }, nullptr }, // 0x1F
};

// indexed by bits 4..0 (maj = 0xF)
// 01111 bbb ccc iiiii
static const arcompact_opcode_t arcv2_maj0F[0x20] =
{
  { SUBTABLE(7, 5, arcompact_sop16)        }, // 0x00
  { 0 },                                      // 0x01
  { ARC_sub,   0, {fB16, fB16, fC16}, nullptr }, // 0x02
  { 0 },                                      // 0x03
  { ARC_and,   0, {fB16, fB16, fC16}, nullptr }, // 0x04
  { ARC_or,    0, {fB16, fB16, fC16}, nullptr }, // 0x05
  { ARC_bic,   0, {fB16, fB16, fC16}, nullptr }, // 0x06
  { ARC_xor,   0, {fB16, fB16, fC16}, nullptr }, // 0x05
  { 0 },                                      // 0x08
  { ARC_mpyw,  0, {fB16, fB16, fC16}, nullptr }, // 0x09
  { ARC_mpyuw, 0, {fB16, fB16, fC16}, nullptr }, // 0x0A
  { ARC_tst,   0, {fB16, fC16, 0   }, nullptr }, // 0x0B
  { ARC_mpy,   0, {fB16, fB16, fC16}, nullptr }, // 0x0C breaking change
  { ARC_sexb,  0, {fB16, fC16, 0   }, nullptr }, // 0x0D
  { ARC_sexw,  0, {fB16, fC16, 0   }, nullptr }, // 0x0E
  { ARC_extb,  0, {fB16, fC16, 0   }, nullptr }, // 0x0F
  { ARC_extw,  0, {fB16, fC16, 0   }, nullptr }, // 0x10
  { ARC_abs,   0, {fB16, fC16, 0   }, nullptr }, // 0x11
  { ARC_not,   0, {fB16, fC16, 0   }, nullptr }, // 0x12
  { ARC_neg,   0, {fB16, fC16, 0   }, nullptr }, // 0x13
  { ARC_add1,  0, {fB16, fB16, fC16}, nullptr }, // 0x14
  { ARC_add2,  0, {fB16, fB16, fC16}, nullptr }, // 0x15
  { ARC_add3,  0, {fB16, fB16, fC16}, nullptr }, // 0x16
  { 0 },                                      // 0x17
  { ARC_asl,   0, {fB16, fB16, fC16}, nullptr }, // 0x18
  { ARC_lsr,   0, {fB16, fB16, fC16}, nullptr }, // 0x19
  { ARC_asr,   0, {fB16, fB16, fC16}, nullptr }, // 0x1A
  { ARC_asl,   0, {fB16, fC16, 0   }, nullptr }, // 0x1B
  { ARC_asr,   0, {fB16, fC16, 0   }, nullptr }, // 0x1C
  { ARC_lsr,   0, {fB16, fC16, 0   }, nullptr }, // 0x1D
  { ARC_trap,  0, {U6_SWI,  0, 0   }, nullptr }, // 0x1E
  { ARC_swi,   0, {U6_SWI,  0, 0   }, nullptr }, // 0x1F
};

// indexed by bits 7..5 (maj = 0x17)
static const arcompact_opcode_t arcompact_maj17[8] =
{
  { ARC_asl,   0, {fB16, fB16, U5}, nullptr }, // 0x00
  { ARC_lsr,   0, {fB16, fB16, U5}, nullptr }, // 0x01
  { ARC_asr,   0, {fB16, fB16, U5}, nullptr }, // 0x02
  { ARC_sub,   0, {fB16, fB16, U5}, nullptr }, // 0x03
  { ARC_bset,  0, {fB16, fB16, U5}, nullptr }, // 0x04
  { ARC_bclr,  0, {fB16, fB16, U5}, nullptr }, // 0x05
  { ARC_bmsk,  0, {fB16, fB16, U5}, nullptr }, // 0x06
  { ARC_btst,  0, {fB16,   U5,  0}, nullptr }, // 0x07
};

// indexed by bits 10..8 (maj = 0x18, i=5)
static const arcompact_opcode_t arcompact_sp_addsub[8] =
{
  { ARC_add, 0,     {R_SP, R_SP, U7L }, nullptr }, // 0x00
  { ARC_sub, 0,     {R_SP, R_SP, U7L }, nullptr }, // 0x01
  { 0 },                                        // 0x02
  { 0 },                                        // 0x03
  { 0 },                                        // 0x04
  { 0 },                                        // 0x05
  { 0 },                                        // 0x06
  { 0 },                                        // 0x07
};

// indexed by bits 4..0 (maj = 0x18, i=6)
static const arcompact_opcode_t arcompact_sp_pops[0x20] =
{
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x00
  { ARC_pop,   0,      {fB16, 0, 0},    nullptr }, // 0x01
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x02
  { 0 },                                        // 0x03
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x04
  { 0 },                                        // 0x05
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x06
  { 0 },                                        // 0x07
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x08
  { 0 },                                        // 0x09
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0A
  { 0 },                                        // 0x0B
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0C
  { 0 },                                        // 0x0D
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0E
  { 0 },                                        // 0x0F
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x10
  { ARC_pop,   0,      {R_BLINK, 0, 0}, nullptr }, // 0x11
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x12
  { 0 },                                        // 0x13
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x14
  { 0 },                                        // 0x15
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x16
  { 0 },                                        // 0x17
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x18
  { 0 },                                        // 0x19
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1A
  { 0 },                                        // 0x1B
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1C
  { 0 },                                        // 0x1D
  { ARC_leave, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1E
  { 0 },                                        // 0x1F
};

// indexed by bits 4..0 (maj = 0x18, i=7)
static const arcompact_opcode_t arcompact_sp_pushs[0x20] =
{
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x00
  { ARC_push,  0,      {fB16, 0, 0},    nullptr }, // 0x01
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x02
  { 0 },                                        // 0x03
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x04
  { 0 },                                        // 0x05
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x06
  { 0 },                                        // 0x07
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x08
  { 0 },                                        // 0x09
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0A
  { 0 },                                        // 0x0B
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0C
  { 0 },                                        // 0x0D
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x0E
  { 0 },                                        // 0x0F
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x10
  { ARC_push,  0,      {R_BLINK, 0, 0}, nullptr }, // 0x11
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x12
  { 0 },                                        // 0x13
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x14
  { 0 },                                        // 0x15
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x16
  { 0 },                                        // 0x17
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x18
  { 0 },                                        // 0x19
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1A
  { 0 },                                        // 0x1B
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1C
  { 0 },                                        // 0x1D
  { ARC_enter, AUX_V2, {EL, 0, 0},      nullptr }, // 0x1E
  { 0 },                                        // 0x1F
};

// indexed by bits 7..5 (maj = 0x18)
// sp-based instructions
static const arcompact_opcode_t arcompact_maj18[8] =
{
  { ARC_ld,  0,     {fB16, SP_U7,    0 }, nullptr }, // 0x00
  { ARC_ld,  AUX_B, {fB16, SP_U7,    0 }, nullptr }, // 0x01
  { ARC_st,  0,     {fB16, SP_U7,    0 }, nullptr }, // 0x02
  { ARC_st,  AUX_B, {fB16, SP_U7,    0 }, nullptr }, // 0x03
  { ARC_add, 0,     {fB16, R_SP,   U7L }, nullptr }, // 0x04
  { SUBTABLE( 10, 8, arcompact_sp_addsub)       }, // 0x05
  { SUBTABLE(  4, 0, arcompact_sp_pops)         }, // 0x06
  { SUBTABLE(  4, 0, arcompact_sp_pushs)        }, // 0x07
};

// indexed by bits 10..9 (maj = 0x19)
// gp-based ld/add (data aligned offset)
static const arcompact_opcode_t arcompact_maj19[4] =
{
  { ARC_ld,  0,     {R_R0, GP_S11,   0 }, nullptr }, // 0x00
  { ARC_ld,  AUX_B, {R_R0, GP_S9,    0 }, nullptr }, // 0x01
  { ARC_ld,  AUX_W, {R_R0, GP_S10,   0 }, nullptr }, // 0x02
  { ARC_add, 0,     {R_R0, R_GP,   S11 }, nullptr }, // 0x03
};

// indexed by bits 7..7 (maj = 0x1C)
static const arcompact_opcode_t arcompact_maj1C[2] =
{
  { ARC_add, 0,        { fB16, fB16, U7}, nullptr }, // 0x00
  { ARC_cmp, 0,        { fB16, U7,    0}, nullptr }, // 0x01
};

// indexed by bits 7..7 (maj = 0x1D)
static const arcompact_opcode_t arcompact_maj1D[2] =
{
  { ARC_br, AUX_CND|cEQ, { fB16, O_ZERO, S8}, nullptr }, // 0x00
  { ARC_br, AUX_CND|cNE, { fB16, O_ZERO, S8}, nullptr }, // 0x01
};

// indexed by bits 8..6 (maj = 0x1E, 10..9=0x3)
static const arcompact_opcode_t arcompact_bcc16[8] =
{
  { ARC_b,  AUX_CND|cGT, { S7, 0, 0}, nullptr }, // 0x00
  { ARC_b,  AUX_CND|cGE, { S7, 0, 0}, nullptr }, // 0x01
  { ARC_b,  AUX_CND|cLT, { S7, 0, 0}, nullptr }, // 0x02
  { ARC_b,  AUX_CND|cLE, { S7, 0, 0}, nullptr }, // 0x03
  { ARC_b,  AUX_CND|cHI, { S7, 0, 0}, nullptr }, // 0x04
  { ARC_b,  AUX_CND|cHS, { S7, 0, 0}, nullptr }, // 0x05
  { ARC_b,  AUX_CND|cLO, { S7, 0, 0}, nullptr }, // 0x06
  { ARC_b,  AUX_CND|cLS, { S7, 0, 0}, nullptr }, // 0x07
};

// indexed by bits 10..9 (maj = 0x1E)
static const arcompact_opcode_t arcompact_maj1E[4] =
{
  { ARC_b,            0, { S10, 0, 0}, nullptr }, // 0x00
  { ARC_b,  AUX_CND|cEQ, { S10, 0, 0}, nullptr }, // 0x01
  { ARC_b,  AUX_CND|cNE, { S10, 0, 0}, nullptr }, // 0x02
  { SUBTABLE(8, 6, arcompact_bcc16)         }, // 0x03
};

// indexed by major opcode (bits 15..11)
static const arcompact_opcode_t arcompact_major[0x20] =
{
  { SUBTABLE(16, 16, arcompact_maj0) },          // 0x00
  { SUBTABLE(16, 16, arcompact_maj1) },          // 0x01
  { ARC_ld, DAAZZX_11_6, {fA32, fB_S9, 0}, nullptr},// 0x02
  { ARC_st, DAAZZ_5_1,   {fC32, fB_S9, 0}, nullptr},// 0x03
  { SUBTABLE(21, 16, arcompact_maj4) },          // 0x04
  { SUBTABLE(21, 16, arcompact_maj5) },          // 0x05
  { SUBTABLE(23, 22, arcompact_maj6) },          // 0x06
  { 0 },                                         // 0x07
  { 0 },                                         // 0x08
  { 0 },                                         // 0x09
  { 0 },                                         // 0x0A
  { 0 },                                         // 0x0B
  { SUBTABLE( 4,  3, arcompact_maj0C) },         // 0x0C
  { SUBTABLE( 4,  3, arcompact_maj0D) },         // 0x0D
  { SUBTABLE( 4,  3, arcompact_maj0E) },         // 0x0E
  { SUBTABLE( 4,  0, arcompact_maj0F) },         // 0x0F
  { ARC_ld, 0,     { fC16, fB_U7, 0}, nullptr },      // 0x10
  { ARC_ld, AUX_B, { fC16, fB_U5, 0}, nullptr },      // 0x11
  { ARC_ld, AUX_W, { fC16, fB_U6, 0}, nullptr },      // 0x12
  { ARC_ld, AUX_W|AUX_X, { fC16, fB_U6, 0}, nullptr },// 0x13
  { ARC_st, 0,     { fC16, fB_U7, 0}, nullptr },      // 0x14
  { ARC_st, AUX_B, { fC16, fB_U5, 0}, nullptr },      // 0x15
  { ARC_st, AUX_W, { fC16, fB_U6, 0}, nullptr },      // 0x16
  { SUBTABLE( 7,  5, arcompact_maj17) },         // 0x17
  { SUBTABLE( 7,  5, arcompact_maj18) },         // 0x18
  { SUBTABLE(10,  9, arcompact_maj19) },         // 0x19
  { ARC_ld,  0, { fB16, PCL_U10, 0}, nullptr },     // 0x1A
  { ARC_mov, 0, { fB16, U8, 0}, nullptr },          // 0x1B
  { SUBTABLE( 7,  7, arcompact_maj1C) },         // 0x1C
  { SUBTABLE( 7,  7, arcompact_maj1D) },         // 0x1D
  { SUBTABLE(10,  9, arcompact_maj1E) },         // 0x1E
  { ARC_bl, 0, { S13, 0, 0}, nullptr },             // 0x1F
};

// indexed by bit 2 (maj = 8)
static const arcompact_opcode_t arcv2_maj8[2] =
{
  { ARC_mov, 0, {fG16,   fH16v2,    0}, nullptr },  // 0x00
  { ARC_ld,  0, {fR16_2, fH16v2_U5, 0}, nullptr },  // 0x01
};

// indexed by bits 4..3 (maj = 8)
static const arcompact_opcode_t arcv2_maj9[4] =
{
  { ARC_ld,  AUX_AS, {fA16,   fBC16_IND, 0}, nullptr }, // 0x00
  { ARC_add, 0,      {fR16_1, fB16,  U6_16}, nullptr }, // 0x01
  { ARC_sub, 0,      {fA16,   fB16,   fC16}, nullptr }, // 0x02
  { ARC_add, 0,      {fR16_1, fB16,  U6_16}, nullptr }, // 0x03
};

// indexed by bits 4..3 (maj = 0x0A)
static const arcompact_opcode_t arcv2_maj0A[4] =
{
  { ARC_ld,  0, {R_R1, GP_S11_16,   0}, nullptr }, // 0x00
  { ARC_ldi, 0, {fB16, U7_16|O_IDX, 0}, nullptr }, // 0x01
  { ARC_st,  0, {R_R0, GP_S11_16,   0}, nullptr }, // 0x02
  { ARC_ldi, 0, {fB16, U7_16|O_IDX, 0}, nullptr }, // 0x03
};

// indexed by bit 10 (maj = 0x0B)
static const arcompact_opcode_t arcv2_maj0B[2] =
{
  { ARC_jli, 0, {U10_16|O_IDX, 0, 0}, nullptr },  // 0x00
  { ARC_ei,  0, {U10_16|O_IDX, 0, 0}, nullptr },  // 0x01
};


// indexed by major opcode (bits 15..11)
static const arcompact_opcode_t arcv2_major[0x20] =
{
  { SUBTABLE(16, 16, arcompact_maj0) },             // 0x00
  { SUBTABLE(16, 16, arcompact_maj1) },             // 0x01
  { ARC_ld, DAAZZX_11_6, {fA32,    fB_S9, 0}, nullptr},// 0x02
  { ARC_st, DAAZZ_5_1,   {fC32_w6, fB_S9, 0}, nullptr},// 0x03
  { SUBTABLE(21, 16, arcompact_maj4) },             // 0x04
  { SUBTABLE(21, 16, arcv2_maj5) },                 // 0x05
  { SUBTABLE(21, 16, arcv2_maj6) },                 // 0x06
  { 0 },                                            // 0x07
  { SUBTABLE( 2,  2, arcv2_maj8) },                 // 0x08
  { SUBTABLE( 4,  3, arcv2_maj9) },                 // 0x09
  { SUBTABLE( 4,  3, arcv2_maj0A) },                // 0x0A
  { SUBTABLE(10, 10, arcv2_maj0B) },                // 0x0B
  { SUBTABLE( 4,  3, arcompact_maj0C) },            // 0x0C
  { SUBTABLE( 4,  3, arcompact_maj0D) },            // 0x0D
  { SUBTABLE( 4,  2, arcv2_maj0E) },                // 0x0E
  { SUBTABLE( 4,  0, arcv2_maj0F) },                // 0x0F
  { ARC_ld, 0,     { fC16, fB_U7, 0}, nullptr },       // 0x10
  { ARC_ld, AUX_B, { fC16, fB_U5, 0}, nullptr },       // 0x11
  { ARC_ld, AUX_W, { fC16, fB_U6, 0}, nullptr },       // 0x12
  { ARC_ld, AUX_W|AUX_X, { fC16, fB_U6, 0}, nullptr }, // 0x13
  { ARC_st, 0,     { fC16, fB_U7, 0}, nullptr },       // 0x14
  { ARC_st, AUX_B, { fC16, fB_U5, 0}, nullptr },       // 0x15
  { ARC_st, AUX_W, { fC16, fB_U6, 0}, nullptr },       // 0x16
  { SUBTABLE( 7,  5, arcompact_maj17) },            // 0x17
  { SUBTABLE( 7,  5, arcompact_maj18) },            // 0x18
  { SUBTABLE(10,  9, arcompact_maj19) },            // 0x19
  { ARC_ld,  0, { fB16, PCL_U10, 0}, nullptr },        // 0x1A
  { ARC_mov, 0, { fB16, U8, 0}, nullptr },             // 0x1B
  { SUBTABLE( 7,  7, arcompact_maj1C) },            // 0x1C
  { SUBTABLE( 7,  7, arcompact_maj1D) },            // 0x1D
  { SUBTABLE(10,  9, arcompact_maj1E) },            // 0x1E
  { ARC_bl, 0, { S13, 0, 0}, nullptr },                // 0x1F
};

// extract bit numbers high..low from val (inclusive, start from 0)
#define BITS(val, high, low) ( ((val)>>low) & ( (1<<(high-low+1))-1) )
// sign extend b low bits in x
// from "Bit Twiddling Hacks"
static sval_t SIGNEXT(sval_t x, int b)
{
  uint32 m = 1 << (b - 1);
  x &= ((sval_t(1) << b) - 1);
  return (x ^ m) - m;
}

// extract bitfield with sign extension
#define SBITS(val, high, low) SIGNEXT(BITS(val, high, low), high-low+1)

//----------------------------------------------------------------------
int arc_t::get_limm(insn_t &insn)
{
  if ( !got_limm )
  {
    g_limm  = (insn.get_next_word() << 16);
    g_limm |= insn.get_next_word();
    got_limm = true;
  }
  return g_limm;
}

//----------------------------------------------------------------------
// register, or a reference to long immediate (r62)
inline void arc_t::opreg(insn_t &insn, op_t &x, int rgnum, int limm)
{
  if ( rgnum != limm )
  {
    x.reg  = uint16(rgnum);
    x.type = o_reg;
  }
  else
  {
    x.type = o_imm;
    // limm as destination is not used
    // so check for instructions where first operand is source
    if ( x.n == 0 && (insn.get_canon_feature(ph) & CF_CHG1) != 0 )
      x.value = 0;
    else
      x.value = get_limm(insn);
  }
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
inline void opimm(op_t &x, uval_t val)
{
  x.value = val;
  x.type  = o_imm;
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
inline void arc_t::opdisp(insn_t &insn, op_t &x, int rgnum, ea_t disp)
{
  if ( rgnum != LIMM )
  {
    x.type  = o_displ;
    x.addr  = disp;
    x.reg   = rgnum;
  }
  else
  {
    x.type = o_mem;
    x.immdisp = disp;
    x.addr = trunc_ea(get_limm(insn) + disp * get_scale_factor(insn));
  }
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
inline int reg16(int rgnum)
{
  // 0..3 r0-r3
  // 4..7 r12-r15
  return ( rgnum > 3 ) ? (rgnum + 8) : rgnum;
}

//----------------------------------------------------------------------
void arc_t::opbranch(const insn_t &insn, op_t &x, sval_t delta) const
{
  // cPC <- (cPCL+delta)
  // PCL is current instruction address with 2 low bits set to 0
  ea_t pcl = insn.ip & ~3;
  x.type = o_near;
  x.dtype = dt_code;
  x.addr = trunc_ea(pcl + delta);
}

//----------------------------------------------------------------------
void arc_t::decode_operand(
        insn_t &insn,
        uint32 code,
        int &op_pos,
        uint32 opkind)
{
  op_t &x = insn.ops[op_pos];
  ++op_pos;
  if ( opkind == 0 )
  {
    x.type = o_void;
    return;
  }
  int reg, p;
  sval_t displ;
  switch ( opkind & ~O_FLAGS )
  {
    case fA16:
      opreg(insn, x, reg16(BITS(code, 2, 0)));
      break;
    case fB16:
      opreg(insn, x, reg16(BITS(code, 10, 8)));
      break;
    case fC16:
      opreg(insn, x, reg16(BITS(code, 7, 5)));
      break;

    case fA32:    //  5..0                   a register operand (6 bits, r0-r63)
      opreg(insn, x, BITS(code, 5, 0));
      break;
    case fB32:    // 14..12 & 26..24         b register operand (6 bits)
      opreg(insn, x, (BITS(code, 14, 12)<<3) | BITS(code, 26, 24));
      break;
    case fC32:    // 11..6                   c register operand (6 bits)
      opreg(insn, x, BITS(code, 11, 6));
      break;
    case fC32_w6: // 11..6 & 0            c/w6 register/immediate operand (6 bits)
      if ( BITS(code, 0, 0) != 0 )
        opimm(x, SBITS(code, 11, 6));
      else
        opreg(insn, x, BITS(code, 11, 6));
      break;
    case fH16:  //  2..0 & 7..5            h register operand (6 bits)
      reg = (BITS(code, 2, 0) << 3) | BITS(code, 7, 5);
      opreg(insn, x, reg);
      break;
    case fH16v2:    //  1..0 & 7..5            h register operand (5 bits)
      reg = (BITS(code, 1, 0) << 3) | BITS(code, 7, 5);
      opreg(insn, x, reg, LIMM5);
      break;
    case fH16v2_U5: //  1..0 & 7..5, 10&4..3  [h, u5] (u5=u3*4)
      displ = ((BITS(code, 10, 10) << 2) | BITS(code, 4, 3)) * 4;
      reg = (BITS(code, 1, 0) << 3) | BITS(code, 7, 5);
      opdisp(insn, x, reg, displ);
      break;
    case fG16:      //  4..3 & 10..8           g register operand (5 bits)
      reg = (BITS(code, 4, 3) << 3) | BITS(code, 10, 8);
      opreg(insn, x, reg, LIMM5);
      break;
    case fR16_2:    //  9..8                   R register operand (2 bits)
      opreg(insn, x, BITS(code, 9, 8));
      break;
    case fR16_1:    //  7                      R register operand (1 bits)
      opreg(insn, x, BITS(code, 7, 7));
      break;

    case S25L:           // 15..6 & 26..18 & 0..3 s25 signed branch displacement for branch and link
    case S21L:           // 15..6 & 26..18        s21 signed branch displacement for branch and link
    case S25:            // 15..6 & 26..17 & 3..0 s25 signed branch displacement
    case S21:            // 15..6 & 26..17        s21 signed branch displacement
      displ = (BITS(code, 15, 6) << 10) | BITS(code, 26, 17);
      if ( opkind == S25 || opkind == S25L )
      {
        displ |= BITS(code, 3, 0) << 20;
        if ( displ & (1<<23) )
          displ -= (1<<24);
      }
      else
      {
        if ( displ & (1<<19) )
          displ -= (1<<20);
      }
      if ( opkind == S25L || opkind == S21L )
      {
        // branch-and-link uses 32-bit aligned target
        displ &= ~1;
      }
      opbranch(insn, x, displ * 2);
      break;

    case S9:              // 15&23..17             s9 signed branch displacement (16-bit aligned)
      displ = BITS(code, 23, 17);
      if ( BITS(code, 15, 15) ) // sign bit
        displ -= (1<<7);
      opbranch(insn, x, displ * 2);
      break;

    case S7:              // 5..0                  s7 signed branch displacement (16-bit aligned)
      displ = SBITS(code, 5, 0);
      opbranch(insn, x, displ * 2);
      break;

    case S8:              // 6..0                  s8 signed branch displacement (16-bit aligned)
      displ = SBITS(code, 6, 0);
      opbranch(insn, x, displ * 2);
      break;

    case S10:             // 8..0                  s10 signed branch displacement (16-bit aligned)
      displ = SBITS(code, 8, 0);
      opbranch(insn, x, displ * 2);
      break;

    case S13:             // 10..0                 s13 signed branch displacement (32-bit aligned)
      displ = SBITS(code, 10, 0);
      opbranch(insn, x, displ * 4);
      break;

    case PCL_U10:
      displ = BITS(code, 7, 0);
      opdisp(insn, x, PCL, displ*4);
      break;

    case SP_U7: //  4..0                 [SP, u7]   stack + offset (u7 = u5*4)
      displ = BITS(code, 4, 0);
      opdisp(insn, x, SP, displ*4);
      break;

    case S3:             // 10..8                  s3 signed immediate
      p = BITS(code, 10, 8);
      opimm(x, p == 7 ? -1 : p);
      break;

    case U3:             //  2..0                  u2 unsigned immediate
      opimm(x, BITS(code, 2, 0));
      break;

    case U7:
      opimm(x, BITS(code, 6, 0));
      break;

    case U6:
      opimm(x, BITS(code, 11, 6));
      break;

    case U6_SWI:
      opimm(x, BITS(code, 10, 5));
      break;

    case U5:
    case U7L:
      displ = BITS(code, 4, 0);
      if ( opkind == U7L )
        displ *= 4;
      opimm(x, displ);
      break;

    case U8:
      opimm(x, BITS(code, 7, 0));
      break;

    case U6_16:          //  6..4 & 2..0           u6 unsigned immediate
      opimm(x, (BITS(code, 6, 4) << 3) | BITS(code, 2, 0));
      break;

    case U7_16:          //  7..4 & 2..0           u7 unsigned immediate
      opimm(x, (BITS(code, 7, 4) << 3) | BITS(code, 2, 0));
      break;

    case U10_16:
      opimm(x, BITS(code, 9, 0));
      break;

    case fB_U5:          //  10..8 & 4..0         [b, u5]
    case fB_U6:          //  10..8 & 4..0         [b, u6] (u6=u5*2)
    case fB_U7:          //  10..8 & 4..0         [b, u7] (u6=u5*4)
      displ = BITS(code, 4, 0);
      if ( opkind == fB_U6 )
        displ *= 2;
      else if ( opkind == fB_U7 )
        displ *= 4;
      reg = reg16(BITS(code, 10, 8));
      opdisp(insn, x, reg, displ);
      break;

    case fB_S9:          //  14..12&26..26, 15&23..16   [b, s9]
      displ = BITS(code, 23, 16);
      if ( BITS(code, 15, 15) ) // sign bit
        displ -= (1<<8);
      reg = (BITS(code, 14, 12)<<3) | BITS(code, 26, 24);
      opdisp(insn, x, reg, displ);
      break;

    // handing of the "gen" format:
    //                 P   M
    //  REG_REG        00 N/A Destination and both sources are registers
    //  REG_U6IMM      01 N/A Source 2 is a 6-bit unsigned immediate
    //  REG_S12IMM     10 N/A Source 2 is a 12-bit signed immediate
    //  COND_REG       11  0  Conditional instruction. Destination (if any) is source 1. Source 2 is a register
    //  COND_REG_U6IMM 11  1  Conditional instruction. Destination (if any) is source 1. Source 2 is a 6-bit unsigned immediate
    //    P=23..22, M=5
    //  0x04, [0x00 - 0x3F]
    //   00100 bbb 00 iiiiii F BBB CCCCCC AAAAAA   reg-reg      op<.f> a,b,c
    //   00100 bbb 01 iiiiii F BBB UUUUUU AAAAAA   reg-u6imm    op<.f> a,b,u6
    //   00100 bbb 10 iiiiii F BBB ssssss SSSSSS   reg-s12imm   op<.f> b,b,s12
    //   00100 bbb 11 iiiiii F BBB CCCCCC 0 QQQQQ  cond reg-reg op<.cc><.f> b,b,c
    //   00100 bbb 11 iiiiii F BBB UUUUUU 1 QQQQQ  cond reg-u6  op<.cc><.f> b,b,u6
    //  0x04, [0x30 - 0x37]
    //   00100 bbb aa 110 ZZ X D BBB CCCCCC AAAAAA LD<zz><.x><.aa><.di> a,[b,c]

    case GENA:    //  5..0
      p = BITS(code, 23, 22);
      if ( p <= 1 )
        reg = BITS(code, 5, 0);
      else
        reg = (BITS(code, 14, 12)<<3) | BITS(code, 26, 24);
      opreg(insn, x, reg);
      break;

    case GENB:    // 14..12 & 26..24
      reg = (BITS(code, 14, 12)<<3) | BITS(code, 26, 24);
      opreg(insn, x, reg);
      break;

    case GENC:       // 11..6 reg/u6 or 0..5&11..6 s12
    case GENC_PCREL: // 11..6 u6 or 0..5&11..6 s12 pc-relative displacement
      p = BITS(code, 23, 22);
      if ( p != 2 )
      {
        reg = BITS(code, 11, 6);
        if ( p == 0 || (p == 3 && BITS(code, 5, 5) == 0) )
          opreg(insn, x, reg);
        else
          opimm(x, reg);
      }
      else
      {
        // s12
        reg = (BITS(code, 5, 0) << 6) | BITS(code, 11, 6);
        reg = SIGNEXT(reg, 12);
        opimm(x, reg);
      }
      if ( (opkind & ~O_IND) == GENC_PCREL && x.type == o_imm )
        opbranch(insn, x, reg * 2);
      break;

    case fBC_IND:
      {
        int b = (BITS(code, 14, 12)<<3) | BITS(code, 26, 24);
        int c = BITS(code, 11, 6);
        int li = 0;
        if ( b == LIMM || c == LIMM )
          li = get_limm(insn);
        doIndirectOperand(insn, b, c, x, 0, li, false);
      }
      break;

    case fBC16_IND:
      {
        int b = BITS(code, 10, 8);
        int c = BITS(code,  7, 5);
        doIndirectOperand(insn, reg16(b), reg16(c), x, 0, 0, false);
      }
      break;

    case O_ZERO:
      opimm(x, 0);
      break;

    case R_SP:           // implicit SP
      opreg(insn, x, SP);
      break;

    case R_BLINK:        // implicit BLINK
      opreg(insn, x, BLINK);
      break;

    case R_R0:           // implicit R0
      opreg(insn, x, R0);
      break;

    case R_R1:           // implicit R1
      opreg(insn, x, R1);
      break;

    case R_GP:           // implicit GP
      opreg(insn, x, GP);
      break;

    case GP_S9:          //  8..0  [GP, s9]   GP + offset
    case GP_S10:         //  8..0  [GP, s10]  GP + offset (s10 = s9*2)
    case GP_S11:         //  8..0  [GP, s11]  GP + offset (s11 = s9*4)
    case S11:            //  8..0  s11 signed immediate (s11 = s9*4)
      displ = SBITS(code, 8, 0);
      if ( opkind == GP_S10 )
        displ *= 2;
      else if ( opkind != GP_S9 )
        displ *= 4;
      if ( opkind == S11 )
        opimm(x, displ);
      else
        opdisp(insn, x, GP, displ);
      break;

    case GP_S11_16:
      displ = (SBITS(code, 10, 5) << 5) | (BITS(code, 2, 0) << 2);
      opdisp(insn, x, GP, displ);
      break;

    case EL:             // 4..1 & 10..8               enter / leave register set
      x.type    = o_reglist;
      x.reglist = BITS(code, 4, 1) | (BITS(code, 10, 8) << 4);
      x.dtype   = dt_dword;
      break;

    default:
      msg("%a: cannot decode operand %d (opkind=%u)\n", insn.ea, x.n, opkind);
      return;
  }
  if ( opkind & O_IND )
  {
    // indirect access
    if ( x.type == o_reg )
    {
      x.type = o_displ;
      x.addr = 0;
    }
    else if ( x.type == o_imm && insn.itype != ARC_lr && insn.itype != ARC_sr )
    {
      if ( insn.itype == ARC_j || insn.itype == ARC_jl )
        x.type = o_near;
      else
        x.type = o_mem;
      x.addr = trunc_ea(x.value);
      x.immdisp = 0;
    }
  }
  if ( opkind & O_WIDE )
  {
    // register pair for 64-bit values
    op_t &y = insn.ops[op_pos];
    ++op_pos;
    if ( x.type == o_reg && (x.reg & 1) == 0 && x.reg <= R58 )
    {
      y.type = o_reg;
      y.reg = x.reg + 1;
      y.regpair = true;
    }
    else
    {
      y.type = o_void;
    }
  }
  if ( opkind & O_IDX )
  {
    int base;
    switch ( insn.itype )
    {
      case ARC_bi:
      case ARC_bih:
        base = NEXT_PC;
        break;

      case ARC_ldi:
        base = LDI_BASE;
        break;

      case ARC_jli:
        base = JLI_BASE;
        break;

      case ARC_ei:
        base = EI_BASE;
        break;

      default:
        msg("%a: unknown implicit base for indexed access\n", insn.ea);
        return;
    }
    if ( x.type == o_reg )
    {
      x.type = o_phrase;
      x.secreg = x.reg;
      x.reg = base;
    }
    else if ( x.type == o_imm )
    {
      x.type = o_displ;
      x.addr = trunc_ea(x.value);
      x.reg = base;
    }
    else
    {
      msg("%a: unknown operand type for indexed access\n", insn.ea);
    }
  }
}

//----------------------------------------------------------------------
// decode non-operand bits of the instruction
static void decode_aux(insn_t &insn, uint32 code, uint32 aux)
{
  aux &= ~AUX_V2 & ~AUX_F;
  if ( aux & AUX_CND )
  {
    // condition in low bits of 'aux'
    insn.auxpref = (insn.auxpref & ~aux_cmask) | (aux & aux_cmask);
    aux &= ~(AUX_CND | aux_cmask);
  }
  if ( aux & Q_4_0 )
  {
    // condition in low bits of instruction
    insn.auxpref = (insn.auxpref & ~aux_cmask) | (code & aux_cmask);
    aux &= ~Q_4_0;
  }
  if ( aux & Q_5_0 )
  {
    // condition in low bits of instruction if the next higer bit is 1
    if ( BITS(code, 5, 5) == 1 )
      insn.auxpref = (insn.auxpref & ~aux_cmask) | (code & aux_cmask);
    aux &= ~Q_5_0;
  }
  if ( aux & AUX_GEN3 )
  {
    // bit 15 = F/Di, 4..0 = Q if 23..22=0x3
    if ( BITS(code, 15, 15) )
    {
      if ( (aux & AUX_GEN3) == AUX_GEN )
        insn.auxpref |= aux_f;
      else if ( (aux & AUX_GEN3) == AUX_GEN3 )
        insn.auxpref |= aux_di;
    }
    if ( BITS(code, 23, 22) == 3 )
      insn.auxpref = (insn.auxpref & ~aux_cmask) | (code & aux_cmask);
    aux &= ~AUX_GEN3;
  }
  if ( aux & N_5 )
  {
    insn.auxpref = (insn.auxpref & ~aux_d) | (code & aux_d);
    aux &= ~N_5;
  }
  if ( aux & AUX_W )
  {
    insn.auxpref = (insn.auxpref & ~aux_zmask) | aux_w;
    aux &= ~AUX_W;
  }
  if ( aux & AUX_B )
  {
    insn.auxpref = (insn.auxpref & ~aux_zmask) | aux_b;
    aux &= ~AUX_B;
  }
  if ( aux & AUX_X )
  {
    insn.auxpref |= aux_x;
    aux &= ~AUX_X;
  }
  if ( aux & AUX_D )
  {
    insn.auxpref = (insn.auxpref & ~aux_nmask) | aux_d;
    aux &= ~AUX_D;
  }
  if ( aux & DAAZZX_11_6 ) // 11..6   Di, aa, ZZ, X flags (load)
  {
    insn.auxpref = (insn.auxpref & ~0x3F) | (BITS(code, 11, 6));
    aux &= ~DAAZZX_11_6;
  }
  if ( aux & DAAZZ_5_1 )  //  5..1   Di, aa, ZZ (store)
  {
    insn.auxpref = (insn.auxpref & ~0x3F) | (BITS(code, 5, 1) << 1);
    aux &= ~DAAZZ_5_1;
  }
  if ( aux & AAZZXD_23_15 ) //  23..22,18..15  aa, ZZ, X, D flags (load reg+reg)
  {
    // load instructions flags: Di.AA.ZZ.X
    insn.auxpref &= ~0x3F;
    insn.auxpref |= BITS(code, 15, 15) << 5; // Di
    insn.auxpref |= BITS(code, 23, 22) << 3; // aa
    insn.auxpref |= BITS(code, 18, 17) << 1; // ZZ
    insn.auxpref |= BITS(code, 16, 16) << 0; // X
    aux &= ~AAZZXD_23_15;
  }
  if ( aux & AUX_AS )
  {
    insn.auxpref |= aux_as;
    aux &= ~AUX_AS;
  }
  if ( aux & Y_3 )
  {
    // static prediction bit Y is bit 3
    // in default case (no hint specified) it's 0 for BRcc and 1 for BBITn
    if ( (BITS(code, 3, 3) == 0) != (insn.itype == ARC_br) )
    {
      insn.auxpref |= aux_bhint;
    }
    aux &= ~Y_3;
  }
  if ( aux != 0 )
    msg("%a: unhandled aux bits: %08X\n", insn.ea, aux);
}

//----------------------------------------------------------------------
int arc_t::analyze_compact(insn_t &insn, uint32 code, int idx, const arcompact_opcode_t *table)
{
  const arcompact_opcode_t *line = &table[idx];
  while ( (line->mnem & 0x80000000) != 0 )
  {
    // it's a pointer into subtable
    // indexed by some of the instruction's bits
    int high1 = (line->mnem >> 24) & 0x1F;
    int low1  = (line->mnem >> 16) & 0x1F;
    int high2 = (line->mnem >>  8) & 0x1F;
    int low2  = (line->mnem >>  0) & 0x1F;
    idx = BITS(code, high2, low2);
    if ( high1 != 0 && low1 != 0 )
      idx |= BITS(code, high1, low1) << (high2-low2+1);
    line = &(line->subtable[idx]);
  }
  if ( line->aux & AUX_F && BITS(code, 15, 15) )
    line += 0x40;
  if ( (line->mnem == 0 && line->aux == 0) || !is_arcv2() && line->aux & AUX_V2 )
  {
    return 0;
  }

  insn.itype = line->mnem;
  decode_aux(insn, code, line->aux);

  if ( is_arcv2() && insn.itype == ARC_flag && BITS(code, 15, 15) )
    insn.itype = ARC_kflag;

  int j = 0;
  for ( int i = 0; i < 3; i++ )
    decode_operand(insn, code, j, line->ops[i]);
  for ( ; j < PROC_MAXOP; ++j )
    insn.ops[j].type = o_void;

  if ( insn.itype == ARC_swi
    && insn.Op1.type == o_imm
    && insn.Op1.value == 0x3f )
  {
    insn.itype = ARC_brk;
    insn.Op1.type = o_void;
  }

  return insn.size;
}

//----------------------------------------------------------------------
// analyze ARCompact instruction
int arc_t::ana_compact(insn_t &insn)
{
  // must be 16-bit aligned
  if ( insn.ea & 1 )
    return 0;
  uint32 code = insn.get_next_word();
  got_limm = false;
  // first 5 bits is the major opcode
  int i = (code >> 11) & 0x1F;
  if ( i < 0x8 )
  {
    // this is a 32-bit instruction
    // get the full word
    code = (code << 16) | insn.get_next_word();
  }
  else
  {
    insn.auxpref |= aux_s;
  }
  return analyze_compact(insn, code, i,
                         is_arcv2() ? arcv2_major : arcompact_major);
}

//----------------------------------------------------------------------
static void simplify(insn_t &insn)
{
  for ( int i = 0; i < PROC_MAXOP; ++i )
  {
    if ( insn.ops[i].type == o_mem )
      insn.ops[i].immdisp = 0;
  }

  switch ( insn.itype )
  {
    case ARC_st:
    case ARC_ld:
      // ld.as r1, [r2, delta] -> ld r1, [r2, delta*size]
      if ( insn.Op2.type == o_displ
        && insn.Op2.membase == 0
        && (insn.auxpref & aux_amask) == aux_as )
      {
        insn.Op2.addr *= get_scale_factor(insn);
        insn.auxpref &= ~aux_amask;
      }
      else if ( insn.Op2.type == o_mem
             && (insn.auxpref & aux_amask) == aux_as )
      {
        insn.Op2.immdisp = 0;
        insn.auxpref &= ~aux_amask;
      }
      break;
    case ARC_add1:
    case ARC_add2:
    case ARC_add3:
    case ARC_sub1:
    case ARC_sub2:
    case ARC_sub3:
      // addN a, b, c -> add a, b, c<<N
      if ( insn.Op3.type == o_imm )
      {
        switch ( insn.itype )
        {
          case ARC_add1:
          case ARC_sub1:
            insn.Op3.value *= 2;
            break;
          case ARC_add2:
          case ARC_sub2:
            insn.Op3.value *= 4;
            break;
          case ARC_add3:
          case ARC_sub3:
            insn.Op3.value *= 8;
            break;
        }
        switch ( insn.itype )
        {
          case ARC_add1:
          case ARC_add2:
          case ARC_add3:
            insn.itype = ARC_add;
            break;
          case ARC_sub3:
          case ARC_sub2:
          case ARC_sub1:
            insn.itype = ARC_sub;
            break;
        }
      }
      break;
    case ARC_sub:
      // sub.f   0, a, b -> cmp a, b
      if ( insn.Op1.is_imm(0) && (insn.auxpref & aux_f) != 0 )
      {
        insn.auxpref &= ~aux_f;
        insn.itype = ARC_cmp;
        insn.Op1 = insn.Op2;
        insn.Op2 = insn.Op3;
        insn.Op3.type = o_void;
      }
      break;
    case ARC_mov:
      // mov     0, 0 -> nop
      if ( insn.Op1.is_imm(0) && insn.Op2.is_imm(0) )
      {
        insn.itype = ARC_nop;
        insn.Op1.type = o_void;
        insn.Op2.type = o_void;
      }
      break;
  }
}

//----------------------------------------------------------------------
// fix operand size for byte or word loads/stores
inline void fix_ldst(insn_t &insn)
{
  if ( insn.itype == ARC_ld || insn.itype == ARC_st )
  {
    switch ( insn.auxpref & aux_zmask )
    {
      case aux_b:
        insn.Op2.dtype = dt_byte;
        break;
      case aux_w:
        insn.Op2.dtype = dt_word;
        break;
    }
  }
}

//----------------------------------------------------------------------
// convert pc-relative loads
// ld r1, [pc,#delta] -> ld r1, [memaddr]
void arc_t::inline_const(insn_t &insn) const
{
  if ( insn.itype == ARC_ld
    && insn.Op2.type == o_displ
    && insn.Op2.reg == PCL
    && (insn.auxpref & (aux_a|aux_zmask)) == 0 ) // no .a and 32-bit access
  {
    ea_t val_ea = (insn.ea & ~3) + insn.Op2.addr;
    if ( val_ea != BADADDR )
    {
      val_ea = trunc_ea(val_ea);
      if ( is_mapped(val_ea) )
      {
        insn.Op2.type = o_mem;
        insn.Op2.addr = val_ea;
        insn.Op2.immdisp = 0;
        insn.auxpref |= aux_pcload;
      }
    }
  }
}

//----------------------------------------------------------------------
// analyze an instruction
int arc_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  int sz = is_a4() ? ana_old(insn) : ana_compact(insn);
  if ( sz != 0 )
  {
    fix_ldst(insn);
    if ( (idpflags & ARC_SIMPLIFY) != 0 )
      simplify(insn);
    if ( (idpflags & ARC_INLINECONST) != 0 )
      inline_const(insn);
  }
  return insn.size;
}
