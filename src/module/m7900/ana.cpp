/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "7900.hpp"

#define SetTypeDataM (getFlag_M ? dt_byte : dt_word)
#define SetTypeDataX (getFlag_X ? dt_byte : dt_word)

//----------------------------------------------------------------------
//      reg - register
//
inline void Operand_Registr(op_t &x, uint16 rReg)
{
  x.type = o_reg;
  x.reg = rReg;
  // x.dtype = dt_word; // For A and B, for E need dt_dword
}

//----------------------------------------------------------------------
static void Operand_Imm_32(insn_t &insn, op_t &x)
{
  uint32 L_L = insn.get_next_byte();
  uint32 L_H = insn.get_next_byte();
  uint32 H_L = insn.get_next_byte();
  uint32 H_H = insn.get_next_byte();

  uint32 data = ((L_L | (H_H<<24)) | (H_L << 16)) | (L_H<<8);

  x.type = o_imm;
  x.value = data;
  x.dtype = dt_dword;
  x.xmode = IMM_32;

}

//----------------------------------------------------------------------
static void Operand_Imm_16(insn_t &insn, op_t &x)
{
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();
  uint32 data = high | (low<<8);

  x.type = o_imm;
  x.value = data;
  x.dtype = dt_word;
  x.xmode = IMM_16;
}

//----------------------------------------------------------------------
static void Operand_Imm_8(insn_t &insn, op_t &x)
{
  uint32 high = insn.get_next_byte();

  x.type = o_imm;
  x.value = high;
  x.dtype = dt_byte;
  x.xmode = IMM_8;
}

//----------------------------------------------------------------------
// Raz - instruction bitness (8, 16, 32)
//----------------------------------------------------------------------
static void Operand_Imm(insn_t &insn, op_t &x, int Raz)
{
  switch ( Raz )
  {
    case 8:  Operand_Imm_8(insn, x);  break;
    case 16: Operand_Imm_16(insn, x); break;
    case 32: Operand_Imm_32(insn, x); break;
  }
}

//----------------------------------------------------------------------
static void Operand_Imm_Spesh(op_t &x, uchar dtype, uint32 data)
{
  uchar type = 0;

  x.type = o_imm;
  x.value = data;
  x.dtype = dtype;

  if ( dtype == dt_byte )
    type= IMM_8;

  if ( dtype == dt_word )
    type= IMM_16;

  x.xmode = type;
}

sel_t getDPR(const insn_t &insn, int iDPR)
{
  switch ( iDPR )
  {
    case 0x0: return getDPR0;
    case 0x40: return getDPR1;
    case 0x80: return getDPR2;
    case 0xC0: return getDPR3;
  }
  return 0;
}

//----------------------------------------------------------------------
// TypeDIR
//   TDIR_DIR       - Direct addressing mode DIR
//   TDIR_DIR_X     - Direct index X addressing DIR,X
//   TDIR_DIR_Y     -  Direct index Y addressing DIR,Y
//   TDIR_INDIRECT_DIR     - Direct indirect addressing mode (DIR)
//   TDIR_INDIRECT_DIR_X   - Direct index X indirect addressing mode (DIR,X)
//   TDIR_INDIRECT_DIR_Y   - Direct index Y indirect addressing mode (DIR,Y)
//   TDIR_L_INDIRECT_DIR   - Direct indirect long addressing mode L(DIR)
//   TDIR_L_INDIRECT_DIR_Y - Direct indirect long indexed Y addressing mode L(DIR),Y
//
//----------------------------------------------------------------------
inline void DIR(insn_t &insn, op_t &x, uchar TypeDir, char dtype)
{
  uint32 higth = insn.get_next_byte();

  uint32 Addr;
  if ( getDPReg == 1 )
  {
    sel_t ValDPR = getDPR(insn, higth & 0xC0);
    Addr = uint32(ValDPR + higth);
  }
  else
  {
    Addr = uint32(getDPR0 + higth);
  }
  x.type = o_mem;
  x.addr = Addr;
  x.dtype = dtype;
  x.TypeOper = TypeDir;
}

static void LDIR(insn_t &insn, op_t &x, uchar TypeDir, char dtype)
{
  uint32 higth = insn.get_next_byte();
  uint32 Addr;
  if ( getDPReg == 1 )
  {
    sel_t ValDPR = getDPR(insn, higth & 0xC0);
    Addr = uint32(ValDPR + higth);
  }
  else
  {
    Addr = uint32(getDPR0 + higth);
  }

  x.type = o_mem;
  x.addr = Addr;
  x.dtype = dtype;
  x.TypeOper = TypeDir;
}

//----------------------------------------------------------------------
// TypeDIR
//   TDIR_DIR       - Direct addressing mode DIR
//   TDIR_DIR_X     - Direct index X addressing DIR,X
//   TDIR_DIR_Y     -  Direct index Y addressing DIR,Y
//   TDIR_INDIRECT_DIR     - Direct indirect addressing mode (DIR)
//   TDIR_INDIRECT_DIR_X   - Direct index X indirect addressing mode (DIR,X)
//   TDIR_INDIRECT_DIR_Y   - Direct index Y indirect addressing mode (DIR,Y)
//   TDIR_L_INDIRECT_DIR   - Direct indirect long addressing mode L(DIR)
//   TDIR_L_INDIRECT_DIR_Y - Direct indirect long indexed Y addressing mode L(DIR),Y
//
//
// dtype - target data type for memory cell
//----------------------------------------------------------------------
static void Operand_Dir(insn_t &insn, op_t &x, uchar TypeDir, char dtype = dt_word)
{
  switch ( TypeDir )
  {
    case TDIR_DIR://       - Direct addressing mode DIR
      DIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_DIR_X://     - Direct index X addressing DIR,X
      DIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_DIR_Y://     -  Direct index Y addressing DIR,Y
      DIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_INDIRECT_DIR://     - Direct indirect addressing mode (DIR)
      LDIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_INDIRECT_DIR_X://   - Direct index X indirect addressing mode (DIR,X)
      LDIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_INDIRECT_DIR_Y://   - Direct index Y indirect addressing mode (DIR,Y)
      LDIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_L_INDIRECT_DIR://   - Direct indirect long addressing mode L(DIR)
      LDIR(insn, x, TypeDir, dtype);
      break;
    case TDIR_L_INDIRECT_DIR_Y:// - Direct indirect long indexed Y addressing mode L(DIR),Y
      LDIR(insn, x, TypeDir, dtype);
      break;
  }
}

//----------------------------------------------------------------------
static void Operand_SR_16(insn_t &insn, op_t &x, uchar Type)
{
  uint32 data = insn.get_next_byte();

  x.type = o_sr;
  x.value = data;
  x.dtype = dt_word;
  x.TypeOper = Type;
}

//----------------------------------------------------------------------
static void Operand_SR_8(insn_t &insn, op_t &x, uchar Type)
{
  uint32 data = insn.get_next_byte();

  x.type = o_sr;
  x.value = data;
  x.dtype = dt_byte;
  x.TypeOper = Type;
}

//----------------------------------------------------------------------
static void Operand_SR(insn_t &insn, op_t &x, uchar TypeDir, int Raz)
{
  switch ( Raz )
  {
    case 8:  Operand_SR_8(insn, x, TypeDir); break;
    case 16: Operand_SR_16(insn, x, TypeDir); break;
  }
}

//----------------------------------------------------------------------
static void ABS(insn_t &insn, op_t &x, uchar Type, sel_t gDT, char dtype)
{
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();
  uint32 data = high | (low<<8);

  data = uint32(data | (gDT<<16));

  x.type = o_ab;
  x.addr = data;
  x.dtype = dtype;
  x.TypeOper = Type;
}

//----------------------------------------------------------------------
static void ABL(insn_t &insn, op_t &x, uchar Type, char dtype)
{
  uint32 ll = insn.get_next_byte();
  uint32 mm = insn.get_next_byte();
  uint32 hh = insn.get_next_byte();

  uint32 data = (ll | (hh<<16)) | (mm<<8);

  x.type = o_ab;
  x.addr = data;
  x.dtype = dtype;
  x.TypeOper = Type;
}

//----------------------------------------------------------------------
static void Indirect_ABS(insn_t &insn, op_t &x, uchar Type, sel_t /*gPG*/, char dtype)
{
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();

  uint32 addr = high | (low<<8);

  // This looks like a bug, FIXME!
  /*uint32 Addr =*/ get_word(addr);
  // Addr = uint32(Addr | (gPG<<16));

  x.type = o_ab;
  x.addr = addr;
  x.dtype = dtype;
  x.TypeOper = Type;
}

//----------------------------------------------------------------------
static void Operand_AB(insn_t &insn, op_t &x, uchar TypeDir, int /*Raz*/, char dtype = dt_word)
{
  switch ( TypeDir )
  {
    case TAB_ABS:  //   - Absolute addressing mode(ABS)
      ABS(insn, x, TypeDir, getDT, dtype);
      break;

    case TAB_ABS_X://  - Absolute indexed X addressing mode(ABS,X)
      ABS(insn, x, TypeDir, getDT, dtype);
      break;

    case TAB_ABS_Y://  - Absolute indexed Y addressing mode(ABS,Y)
      ABS(insn, x, TypeDir, getDT, dtype);
      break;

    case TAB_ABL:  //  - Absolute long addressing mode(ABL)
      ABL(insn, x, TypeDir, dtype);
      break;
    case TAB_ABL_X:// - Absolute long indexed X addressing mode(ABS,X)
      ABL(insn, x, TypeDir, dtype);
      break;

    case TAB_INDIRECTED_ABS:// - Absolute indirect addressing mode((ABS))
      Indirect_ABS(insn, x, TypeDir, getPG, dtype);//???
      break;

    case TAB_L_INDIRECTED_ABS:// - Absolute indirect long addressing mode(L(ABS))
      Indirect_ABS(insn, x, TypeDir, getPG, dtype);//???
      break;

    case TAB_INDIRECTED_ABS_X:// - Absolute indexed X indirect addressing mode((ABS,X))
      Indirect_ABS(insn, x, TypeDir, getPG, dtype);//???
      break;
  }
}

//----------------------------------------------------------------------
static void Bral(insn_t &insn, op_t &x, int del)
{
  x.type = o_near;
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();
  uint32 addr = high | (low<<8);

  x.addr = insn.ip + (signed short)addr + del;
}

//----------------------------------------------------------------------
inline void Operand_BSR(const insn_t &insn, op_t &x, uint32 addr, int del)
{
  x.type = o_near;
  x.addr = insn.ip + (int32)addr + del;
}

//----------------------------------------------------------------------
inline void Operand_BBC(const insn_t &insn, op_t &x, uchar addr, int del)
{
  x.type = o_near;
  x.addr = insn.ip + (signed char)addr + del;
}

//----------------------------------------------------------------------
inline void Operand_BBS(const insn_t &insn, op_t &x, uchar addr, int del)
{
  Operand_BBC(insn, x, addr, del);
}

//----------------------------------------------------------------------
inline void Operand_DEBNE(const insn_t &insn, op_t &x, uchar addr, int del)
{
  x.type = o_near;
  x.addr = insn.ip + (signed char)addr + del;
}

//----------------------------------------------------------------------
inline void Operand_Near(const insn_t &insn, op_t &x, uchar addr, int del)
{
  x.type = o_near;
  x.addr = insn.ip + (signed char)addr + del;
}

//----------------------------------------------------------------------
inline void Operand_IMP(op_t & /*x*/)
{
}

//----------------------------------------------------------------------
static void Jsr_24(insn_t &insn, op_t &x)
{
  x.type = o_near;

  uint32 ll = insn.get_next_byte();
  uint32 mm  = insn.get_next_byte();
  uint32 hh  = insn.get_next_byte();

  uint32 data = (ll | (hh<<16)) | (mm<<8);

  x.addr = data;
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
static void Jsr_16(insn_t &insn, op_t &x, sel_t gPG)
{
  x.type = o_near;

  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();
  uint32 data = high | (low<<8);
  data = uint32(data | (gPG<<16));

  x.addr = data;
  x.dtype = dt_word;
}

//----------------------------------------------------------------------
//   dt_byte
//   dt_word
//   dt_dword
//----------------------------------------------------------------------
static void Operand_STK_16(insn_t &insn, op_t &x, uchar dtype)
{
  uint32 high = insn.get_next_byte();
  uint32 low  = insn.get_next_byte();
  uint32 data = high | (low<<8);

  x.type = o_stk;
  x.value = data;
  x.dtype = dtype;
  x.xmode = IMM_16;
}

//----------------------------------------------------------------------
//   dt_byte
//   dt_word
//   dt_dword
//----------------------------------------------------------------------
inline void Operand_STK_8(insn_t &insn, op_t &x, uchar dt_type)
{
  uint32 high = insn.get_next_byte();

  x.type = o_stk;
  x.value = high;
  x.dtype = dt_type;
  x.xmode = IMM_8;
}

//----------------------------------------------------------------------
inline void Operand_STK(insn_t &insn, op_t &x, int Razr)
{
  switch ( Razr )
  {
    case 8:  Operand_STK_8(insn, x, dt_byte);  break;
    case 16: Operand_STK_16(insn, x, dt_word); break;
  }
}

//----------------------------------------------------------------------
static void Branch(insn_t &insn, op_t &x, int cd)
{
  static const uchar icode[] =
  {
    0, // 0
    m7900_bpl,  // 1
    m7900_bra,  // 2
    m7900_bmi,  // 3
    m7900_bgtu, // 4
    m7900_bvc,  // 5
    m7900_bleu, // 6
    m7900_bvs,  // 7
    m7900_bgt,  // 8
    m7900_bcc,  // 9
    m7900_ble,  // a
    m7900_bcs,  // b
    m7900_bge,  // c
    m7900_bne,  // d
    m7900_blt,  // e
    m7900_beq   // F
  };
  insn.itype = icode[ cd ];
  Operand_Near(insn, x, insn.get_next_byte(), 2);
}

//----------------------------------------------------------------------
int Opcode_91(insn_t &insn)
{
  TRACE("Opcode_91");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
    // ________________________ ADD________________________
    // 101 - ADd
    // add B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 20 dd]
    case 0x20:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 101 - ADd
    // add B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 21 dd]
    case 0x21:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 101 - ADd
    // add B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 28 dd]
    case 0x28:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 22 dd]
    case 0x22:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 101 - ADd
    // add B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 29 dd]
    case 0x29:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      // Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, 8, SetTypeDataM);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 23 nn]
    case 0x23:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 101 - ADd
    // add B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 24 nn]
    case 0x24:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 26 ll mm]
    case 0x26:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 2C ll mm hh]
    case 0x2C:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 101 - ADd
    // add B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 2D ll mm hh]
    case 0x2D:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

   // ______________________ END ADD _____________________
   // ________________________ CMP________________________
    // 161 - CoMPare
    // cmp B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 40 dd]
    case 0x40:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 41 dd]
    case 0x41:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 48 dd]
    case 0x48:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 42 dd]
    case 0x42:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 161 - CoMPare
    // cmp B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 49 dd]
    case 0x49:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 43 nn]
    case 0x43:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 161 - CoMPare
    // cmp B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 44 nn]
    case 0x44:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 46 ll mm]
    case 0x46:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 4C ll mm hh]
    case 0x4C:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 4D ll mm hh]
    case 0x4D:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END CMP _____________________

   // ________________________ AND________________________
    // 111 - logical AND
    // and B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 60 dd]
    case 0x60:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 111 - logical AND
    // and B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 61 dd]
    case 0x61:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 111 - logical AND
    // and B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 68 dd]
    case 0x68:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 62 dd]
    case 0x62:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 111 - logical AND
    // and B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 69 dd]
    case 0x69:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 63 nn]
    case 0x63:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 111 - logical AND
    // and B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 64 nn]
    case 0x64:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 66 ll mm]
    case 0x66:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 6C ll mm hh]
    case 0x6C:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 111 - logical AND
    // and B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 6D ll mm hh]
    case 0x6D:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END AND _____________________
   // ________________________ EOR________________________
    // 180 - Exclusive OR memory with accumulator
    // eor B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 70 dd]
    case 0x70:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 71 dd]
    case 0x71:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 78 dd]
    case 0x78:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 72 dd]
    case 0x72:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 79 dd]
    case 0x79:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 73 nn]
    case 0x73:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 74 nn]
    case 0x74:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 76 ll mm]
    case 0x76:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 7C ll mm hh]
    case 0x7C:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 7D ll mm hh]
    case 0x7D:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END eor _____________________

    // ___________________  LDA _________________________
    // 195 - LoaD Accumulator from memory
    // lda B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 10 dd]
    case 0x10:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 11 dd]
    case 0x11:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 12 dd]
    case 0x12:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 13 nn]
    case 0x13:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 14 nn]
    case 0x14:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 16 ll mm]
    case 0x16:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END LDA  ____________________

    // ___________________  LDAB _________________________
    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 00 dd]
    case 0x00:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 01 dd]
    case 0x01:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 02 dd]
    case 0x02:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 03 nn]
    case 0x03:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 04 nn]
    case 0x04:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 06 ll mm]
    case 0x06:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END LDAB  ____________________

    // ___________________  STA _________________________
    // 271 - STore Accumulator in memory
    // sta B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 D0 dd]
    case 0xD0:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 D1 dd]
    case 0xD1:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 D2 dd]
    case 0xD2:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_byte);
      break;

    // 271 - STore Accumulator in memory
    // sta B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 D3 nn]
    case 0xD3:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 271 - STore Accumulator in memory
    // sta B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 D4 nn]
    case 0xD4:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 D6 ll mm]
    case 0xD6:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END STA  ____________________
    // _____________________  STAB  ____________________
    // 272 - STore Accumulator in memory at Byte
    // stab B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 C0 dd]
    case 0xC0:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 C1 dd]
    case 0xC1:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 C2 dd]
    case 0xC2:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 C3 nn]
    case 0xC3:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 C4 nn]
    case 0xC4:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 C6 ll mm]
    case 0xC6:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________  END STAB  ____________________

   // ________________________ ORA________________________
    // 220 - OR memory with Accumulator
    // ora B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 50 dd]
    case 0x50:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 51 dd]
    case 0x51:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
          break;

    // 220 - OR memory with Accumulator
    // ora B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 58 dd]
    case 0x58:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 52 dd]
    case 0x52:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 220 - OR memory with Accumulator
    // ora B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 59 dd]
    case 0x59:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 53 nn]
    case 0x53:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 220 - OR memory with Accumulator
    // ora B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 54 nn]
    case 0x54:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 56 ll mm]
    case 0x56:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 5C ll mm hh]
    case 0x5C:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // ora B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 5D ll mm hh]
    case 0x5D:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END ora _____________________

   // ________________________ SUB________________________
    // 278 - SUBtract
    // sub B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 30 dd]
    case 0x30:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [91 31 dd]
    case 0x31:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [91 38 dd]
    case 0x38:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 32 dd]
    case 0x32:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 278 - SUBtract
    // sub B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [91 39 dd]
    case 0x39:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [91 33 nn]
    case 0x33:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 278 - SUBtract
    // sub B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [91 34 nn]
    case 0x34:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [91 36 ll mm]
    case 0x36:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [91 3C ll mm hh]
    case 0x3C:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [91 3D ll mm hh]
    case 0x3D:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END SUB _____________________

   default:
     return 0;

  }
  return insn.size;
}

//--------------------------------------------------------------------------------------------
static int Opcode_21(insn_t &insn)
{
  TRACE("Opcode_21");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
    // ___________________  ADC _________________________
    // 96 - ADd with Carry
    // adc A, dd
    // Operation data length: 16 bits or 8 bits
    // [21 8A dd]
    case 0x8A:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 8B dd]
    case 0x8B:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 96 - ADd with Carry
    // adc A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 80 dd]
    case 0x80:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 81 dd]
    case 0x81:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 88 dd]
    case 0x88:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 82 dd]
    case 0x82:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 96 - ADd with Carry
    // adc A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 89 dd]
    case 0x89:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 83 nn]
    case 0x83:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 96 - ADd with Carry
    // adc A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 84 nn]
    case 0x84:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 8E ll mm]
    case 0x8E:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16,SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 8F ll mm]
    case 0x8F:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 96 - ADd with Carry
    // adc A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 86 ll mm]
    case 0x86:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 8C ll mm hh]
    case 0x8C:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 8D ll mm hh]
    case 0x8D:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END ADC _________________________

    // ___________________  LSR _________________________
    // 204 - Logical Shift Right
    // lsr  dd
    // Operation data length: 16 bits or 8 bits
    // [21 2A dd]
    case 0x2A:
      insn.itype = m7900_lsr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 204 - Logical Shift Right
    // lsr dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 2B dd]
    case 0x2B:
      insn.itype = m7900_lsr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 204 - Logical Shift Right
    // lsr  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 2E ll mm]
    case 0x2E:
      insn.itype = m7900_lsr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 204 - Logical Shift Right
    // lsr  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 2F ll mm]
    case 0x2F:
      insn.itype = m7900_lsr;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END LSR _________________________

    // ___________________  ROL _________________________
    // 254 - ROtate one bit Left
    // rol  dd
    // Operation data length: 16 bits or 8 bits
    // [21 1A dd]
    case 0x1A:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 254 - ROtate one bit Left
    // rol dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 1B dd]
    case 0x1B:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 254 - ROtate one bit Left
    // rol  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 1E ll mm]
    case 0x1E:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 254 - ROtate one bit Left
    // rol  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 1F ll mm]
    case 0x1F:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END ROL _________________________
    // ___________________  ROR _________________________
    // 255 - ROtate one bit Right
    // rol  dd
    // Operation data length: 16 bits or 8 bits
    // [21 3A dd]
    case 0x3A:
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 255 - ROtate one bit Right
    // rol dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 3B dd]
    case 0x3B:
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 255 - ROtate one bit Right
    // ror  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 3E ll mm]
    case 0x3E:
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 255 - ROtate one bit Right
    // ror  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 3F ll mm]
    case 0x3F:
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END ROR _________________________

    // ___________________  ASL _________________________

    // 116 - Arithmetic Shift to Left
    // asl dd
    // Operation data length: 16 bits or 8 bits
    // [21 0A dd]
    case 0x0A:
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 116 - Arithmetic Shift to Left
    // asl  dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 0B dd]
    case 0x0B:
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 116 - Arithmetic Shift to Left
    // asl  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 0E ll mm]
    case 0x0E:
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 116 - Arithmetic Shift to Left
    // asl  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 0F ll mm]
    case 0x0F:
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________ END ASL _________________________

    // ___________________  ASR _________________________

    // 119 - Arithmetic Shift to Right
    // asr dd
    // Operation data length: 16 bits or 8 bits
    // [21 4A dd]
    case 0x4A:
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 119 - Arithmetic Shift to Right
    // asr  dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 4B dd]
    case 0x4B:
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 119 - Arithmetic Shift to Right
    // asr  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 4E ll mm]
    case 0x4E:
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 119 - Arithmetic Shift to Right
    // asr  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 4F ll mm]
    case 0x4F:
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________ END ASR _________________________

    // ___________________  ADCD _________________________

    // 99 - ADd with Carry at Double-word
    // adcd E, dd
    // Operation data length: 32 bits
    // [21 9A dd]
    case 0x9A:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32
    // [21 9B dd]
    case 0x9B:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [21 90 dd]
    case 0x90:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 buts
    // [21 91 dd]
    case 0x91:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, (dd), Y  ()
    // Operation data length: 32 bits
    // [21 98 dd]
    case 0x98:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [21 92 dd]
    case 0x92:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);

      // should collect 3 bytes, but collect as 2 bytes
      // can use dt_tbyte
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [21 99 dd]
    case 0x99:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      // should collect 3 bytes, but collect as 2 bytes
      // can use dt_tbyte
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [21 93 nn]
    case 0x93:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [21 94 nn]
    case 0x94:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [21 9E ll mm]
    case 0x9E:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [21 9F ll mm]
    case 0x9F:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [21 96 ll mm]
    case 0x96:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 9C ll mm hh]
    case 0x9C:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd A, hhmmll, X (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [21 9D ll mm hh]
    case 0x9D:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END ADCD _________________________

    // ___________________  DIV _________________________
    // 174 - DIVide unsigned
    // div A, dd
    // Operation data length: 16 bits or 8 bits
    // [21 EA dd]
    case 0xEA:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 174 - DIVide unsigned
    // div A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 EB dd]
    case 0xEB:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 174 - DIVide unsigned
    // div A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 E0 dd]
    case 0xE0:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 174 - DIVide unsigned
    // div A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 E1 dd]
    case 0xE1:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 174 - DIVide unsigned
    // div A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 E8 dd]
    case 0xE8:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 174 - DIVide unsigned
    // div A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 E2 dd]
    case 0xE2:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 174 - DIVide unsigned
    // div A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 E9 dd]
    case 0xE9:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op2, rY);
      break;

    // 174 - DIVide unsigned
    // div A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 E3 nn]
    case 0xE3:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_SP, 8);
      Operand_Registr(insn.Op2, rPS);
      break;

    // 174 - DIVide unsigned
    // div A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 E4 nn]
    case 0xE4:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op2, rY);
      break;

    // 174 - DIVide unsigned
    // div A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 EE ll mm]
    case 0xEE:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 174 - DIVide unsigned
    // div A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 EF ll mm]
    case 0xEF:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 174 - DIVide unsigned
    // div A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 E6 ll mm]
    case 0xE6:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 174 - DIVide unsigned
    // div A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 EC ll mm hh]
    case 0xEC:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL, 24, SetTypeDataM);
      break;

    // 174 - DIVide unsigned
    // div A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 ED ll mm hh]
    case 0xED:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END DIV _________________________
    // ___________________  DIVS _________________________
    // 176 - DIVide with Sign
    // divs A, dd
    // Operation data length: 16 bits or 8 bits
    // [21 FA dd]
    case 0xFA:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 176 - DIVide with Sign
    // divs A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 FB dd]
    case 0xFB:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 176 - DIVide with Sign
    // divs A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 F0 dd]
    case 0xF0:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 176 - DIVide with Sign
    // divs A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 F1 dd]
    case 0xF1:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 176 - DIVide with Sign
    // divs A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 F8 dd]
    case 0xF8:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 176 - DIVide with Sign
    // divs A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 F2 dd]
    case 0xF2:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 176 - DIVide with Sign
    // divs A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 F9 dd]
    case 0xF9:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op2, rY);
      break;

    // 176 - DIVide with Sign
    // divs A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 F3 nn]
    case 0xF3:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_SP, 8);
      Operand_Registr(insn.Op2, rPS);
      break;

    // 176 - DIVide with Sign
    // divs A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 F4 nn]
    case 0xF4:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op2, rY);
      break;

    // 176 - DIVide with Sign
    // divs A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 FE ll mm]
    case 0xFE:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 176 - DIVide with Sign
    // divs A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 FF ll mm]
    case 0xFF:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 176 - DIVide with Sign
    // divs A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 F6 ll mm]
    case 0xF6:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 176 - DIVide with Sign
    // divs A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 FC ll mm hh]
    case 0xFC:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL, 24, SetTypeDataM);
      break;

    // 176 - DIVide with Sign
    // divs A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 FD ll mm hh]
    case 0xFD:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END DIVS _________________________

    // ___________________  MPY _________________________
    // 212 - MultiPlY
    // Operation data length: 16 bits or 8 bits
    // [21 CA dd]
    case 0xCA:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 212 - MultiPlY
    // mpy dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 CB dd]
    case 0xCB:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 212 - MultiPlY
    // mpy  (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 C0 dd]
    case 0xC0:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 212 - MultiPlY
    // mpy (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 C1 dd]
    case 0xC1:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 212 - MultiPlY
    // mpy (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 C8 dd]
    case 0xC8:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 212 - MultiPlY
    // mpy L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 C2 dd]
    case 0xC2:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 212 - MultiPlY
    // mpy L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 C9 dd]
    case 0xC9:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op2, rY);
      break;

    // 212 - MultiPlY
    // mpy nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 C3 nn]
    case 0xC3:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_SP, 8);
      Operand_Registr(insn.Op2, rPS);
      break;

    // 212 - MultiPlY
    // mpy (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 C4 nn]
    case 0xC4:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op2, rY);
      break;

    // 212 - MultiPlY
    // mpy  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 CE ll mm]
    case 0xCE:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 212 - MultiPlY
    // mpy  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 CF ll mm]
    case 0xCF:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 212 - MultiPlY
    // mpy A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 C6 ll mm]
    case 0xC6:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 212 - MultiPlY
    // mpy  hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 CC ll mm hh]
    case 0xCC:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL, 24, SetTypeDataM);
      break;

    // 212 - MultiPlY
    // mpy  hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 CD ll mm hh]
    case 0xCD:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END MPY _________________________
    // ___________________  MPYS _________________________
    // 213 - MultiPlY with Sign
    // Operation data length: 16 bits or 8 bits
    // [21 DA dd]
    case 0xDA:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 213 - MultiPlY with Sign
    // mpys dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 DB dd]
    case 0xDB:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 213 - MultiPlY with Sign
    // mpys  (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 D0 dd]
    case 0xD0:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 213 - MultiPlY with Sign
    // mpys (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 D1 dd]
    case 0xD1:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 213 - MultiPlY with Sign
    // mpys (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 D8 dd]
    case 0xD8:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 213 - MultiPlY with Sign
    // mpys L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 D2 dd]
    case 0xD2:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 213 - MultiPlY with Sign
    // mpys L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 D9 dd]
    case 0xD9:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op2, rY);
      break;

    // 213 - MultiPlY with Sign
    // mpys nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 D3 nn]
    case 0xD3:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_SP, 8);
      Operand_Registr(insn.Op2, rPS);
      break;

    // 213 - MultiPlY with Sign
    // mpys (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 D4 nn]
    case 0xD4:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_SR(insn, insn.Op1, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op2, rY);
      break;

    // 213 - MultiPlY with Sign
    // mpys  mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 DE ll mm]
    case 0xDE:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // 213 - MultiPlY with Sign
    // mpys  mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 DF ll mm]
    case 0xDF:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 213 - MultiPlY with Sign
    // mpys A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 D6 ll mm]
    case 0xD6:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;

    // 213 - MultiPlY with Sign
    // mpys  hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 DC ll mm hh]
    case 0xDC:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL, 24, SetTypeDataM);
      break;

    // 213 - MultiPlY with Sign
    // mpys  hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 DD ll mm hh]
    case 0xDD:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // ___________________  END MPYS _________________________

    // ___________________  SBC _________________________
    // 264 - SuBtract with Carry
    // sbc A, dd
    // Operation data length: 16 bits or 8 bits
    // [21 AA dd]
    case 0xAA:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 AB dd]
    case 0xAB:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 264 - SuBtract with Carry
    // sbc A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A0 dd]
    case 0xA0:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 A1 dd]
    case 0xA1:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 A8 dd]
    case 0xA8:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A2 dd]
    case 0xA2:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 264 - SuBtract with Carry
    // sbc A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A9 dd]
    case 0xA9:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 A3 nn]
    case 0xA3:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 264 - SuBtract with Carry
    // sbc A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 A4 nn]
    case 0xA4:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 AE ll mm]
    case 0xAE:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 AF ll mm]
    case 0xAF:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 264 - SuBtract with Carry
    // sbc A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 A6 ll mm]
    case 0xA6:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 AC ll mm hh]
    case 0xAC:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 AD ll mm hh]
    case 0xAD:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END sbc _________________________

    // ___________________  SBCD _________________________
    // 266 - SuBtract with Carry at Double-word
    // sbcd E, dd
    // Operation data length: 16 bits or 8 bits
    // [21 BA dd]
    case 0xBA:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 BB dd]
    case 0xBB:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 B0 dd]
    case 0xB0:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 B1 dd]
    case 0xB1:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 B8 dd]
    case 0xB8:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 B2 dd]
    case 0xB2:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 B9 dd]
    case 0xB9:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 B3 nn]
    case 0xB3:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 B4 nn]
    case 0xB4:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd BE mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 BE ll mm]
    case 0xBE:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 BF ll mm]
    case 0xBF:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 B6 ll mm]
    case 0xB6:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 BC ll mm hh]
    case 0xBC:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 BD ll mm hh]
    case 0xBD:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END SBCD _________________________

    default:
      return 0;
  }

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_31(insn_t &insn)
{
  TRACE("Opcode_31");

  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;

  switch ( code )
  {

    // _____________________  JMPJMPL  ____________________
    // 192 - JuMP
    // jmp (mmll)
    // Operation data -
    // [31 5C ll mm]
    case 0x5C:// jmp (mmll) ((ABS))
      insn.itype = m7900_jmp;
      Operand_AB(insn, insn.Op1, TAB_INDIRECTED_ABS, 16, dt_word);
      break;

    // 192 - JuMP
    // jmp L(mmll)
    // Operation data -
    // [31 5D ll mm]
    case 0x5D:// jmp L(mmll) (L(ABS))
      insn.itype = m7900_jmp;
      Operand_AB(insn, insn.Op1, TAB_L_INDIRECTED_ABS, 16, dt_tbyte);
      break;
    // _____________________ END JMP/JMPL  ____________________

    // 232 - PusH proGram bank register on stack
    // phg
    // Operation data length: 8 bits
    // [31 60]
    case 0x60:
      insn.itype = m7900_phg;
      RAZOPER = INSN_PREF_U;
      break;

    // 235 -
    // pht
    // Operation data length: 8 bits
    // [31 40]
    case 0x40:
      insn.itype = m7900_pht;
      RAZOPER = INSN_PREF_U;
      break;

    // 243 - PuLl daTa bank register from stack
    // plt
    // Operation data length: 8 bits
    // [31 50]
    case 0x50:
      insn.itype = m7900_plt;
      RAZOPER = INSN_PREF_U;
      break;

    // 96 - ADd with Carry
    // adc A, #imm
    // Operation data length: 16 bits or 8 bits
    // [31 87 imm]
    case 0x87:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 274 -
    // stp
    // Operation data length: -
    // [31 30]
    case 0x30:
      insn.itype = m7900_stp;
      break;

    // 284 - SUBtract Stack pointer
    // subs #imm
    // Operation data length: 16 bits
    // [31 0B imm]
    case 0x0B:
      insn.itype = m7900_subs;
      RAZOPER = INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, 8);
      break;

    // 288 - Transfer accumulator A to Stack pointer
    // tas
    // Operation data length: 16 bits
    // [31 82]
    case 0x82:
      insn.itype = m7900_tas;
      break;

    // 297 - Transfer Direct page register to Stack pointer
    // tds
    // Operation data length: 16 bits
    // [31 73]
    case 0x73:
      insn.itype = m7900_tds;
      break;

    // 298- Transfer Stack pointer to accumulator A
    // tsa
    // Operation data length: 16 bits or 8 bit
    // [31 92]
    case 0x92:
      insn.itype = m7900_tsa;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 300- Transfer Stack pointer to Direct page register
    // tsd
    // Operation data length: 16 bits
    // [31 70]
    case 0x70:
      insn.itype = m7900_tsd;
      break;

    // 301- Transfer Stack pointer to index register X
    // tsx
    // Operation data length: 16 bits or 8 bits
    // [31 F2]
    case 0xF2:
      insn.itype = m7900_tsx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 304- Transfer index register X to Stack pointer
    // txs
    // Operation data length: 16 bits or 8 bits
    // [31 E2]
    case 0xE2:
      insn.itype = m7900_txs;
      break;

    // 305- Transfer index register X to Y
    // txy
    // Operation data length: 16 bits or 8 bits
    // [31 C2]
    case 0xC2:
      insn.itype = m7900_txy;
      break;

    // 308- Transfer index register Y to X
    // tyx
    // Operation data length: 16 bits or 8 bits
    // [31 D2]
    case 0xD2:
      insn.itype = m7900_tyx;
      break;

    // 309- WaIT
    // wit
    // Operation data length: 16 bits or 8 bits
    // [31 10]
    case 0x10:
      insn.itype = m7900_wit;
      break;

 //---------------------------BYTE-------------------------------------//
    // 98 - ADd with Carry at Byte
    // adcb A, #imm
    // Operation data length: 8 bits
    // [31 1A imm]
    case 0x1A:
      insn.itype = m7900_adcb;
      RAZOPER =  8;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 199 - LoaD immediate to DaTa bank register
    // ldt A, #imm
    // Operation data length: 8 bits
    // [31 4A imm]
    case 0x4A:
      insn.itype = m7900_ldt;
      RAZOPER = INSN_PREF_U;
      Operand_Imm(insn, insn.Op1, 8);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, #imm
    // Operation data length: 8 bits
    // [3B imm ll mm]
    case 0x3B:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Imm(insn, insn.Op3, 8);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Registr(insn.Op2, rX);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb dd, #imm
    // Operation data length: 8 bits
    // [3A imm dd]
    case 0x3A:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op3, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Registr(insn.Op2, rX);
      break;

    // 265 - SuBtract with Carry at Byte
    // sbcb A, #imm
    // Operation data length: 8 bits
    // [31 1B imm]
    case 0x1B:
      insn.itype = m7900_sbcb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

 //---------------------------WORD------------------------------------//

    // 107 - ADD Stack pointer and immediate
    // adds #imm
    // Operation data length: 16 bits
    // [31 0A imm]
    case 0x0A:
      insn.itype = m7900_adds;
      RAZOPER = INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, 8);
      break;

 //---------------------------DWORD------------------------------------//

    // 95 - ABSolute at Double-word
    // absd E
    // Operation data length: 32 bits
    // [31 90]
    case 0x90:
      insn.itype = m7900_absd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      break;

    // 186 - EXTension Sign at Double-word
    // extsd E
    // Operation data length: 32 bits
    // [31 B0]
    case 0xB0:// extsd
      insn.itype = m7900_extsd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      break;

    // 188 - EXTension Zero at Double-word
    // extzd E
    // Operation data length: 32 bits
    // [31 A0]
    case 0xA0:// extsd
      insn.itype = m7900_extzd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      break;

    // 99 - ADd with Carry at Double-word
    // adcd E, #imm
    // Operation data length: 32 bits
    // [31 1C imm imm imm imm]
    case 0x1C:
      insn.itype = m7900_adcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 217 - NEGative at Double-word
    // negd E
    // Operation data length: 32 bits
    // [31 80]
    case 0x80:
      insn.itype = m7900_negd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      break;

    // 266 - SuBtract with Carry at Double-word
    // sbcd E
    // Operation data length: 32 bits
    // [31 1D]
    case 0x1D:
      insn.itype = m7900_sbcd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

 //---------------------------WORD/byte------------------------------------//

    // 174 - DIVide unsigned
    // div  #imm
    // Operation data length: 16 bits or 8 bits
    // [31 E7 imm]
    case 0xE7:
      insn.itype = m7900_div;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      break;

    // 174 - DIVide with Sign
    // divs  #imm
    // Operation data length: 16 bits or 8 bits
    // [31 F7 imm]
    case 0xF7:
      insn.itype = m7900_divs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      break;

    // 207 - MOVe Memory to memory
    // movm mmll, X, #imm
    // Operation data length: 16 bits or 8 bits
    // [31 57 imm]
    case 0x57:
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op3, getFlag_M ? 8 : 16);
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // 207 - MOVe Memory to memory
    // movm  #imm dd
    // Operation data length: 16 bits or 8 bits
    // [31 47 imm]
    case 0x47:
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op3, getFlag_M ? 8 : 16);
      Operand_Dir(insn, insn.Op1, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    // _____________________   MPY  ____________________
    // 212 - MultiPlY
    // MPY #imm
    // Operation data - 16 bits or 8 bits
    // [31 C7 imm]
    case 0xC7:
      insn.itype = m7900_mpy;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      break;
    // _____________________  END MPY  ____________________

    // _____________________   MPYS  ____________________
    // 213 - MultiPlY
    // MPYS #imm
    // Operation data - 16 bits or 8 bits
    // [31 D7 imm]
    case 0xD7:
      insn.itype = m7900_mpys;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      break;
    // _____________________  END MPY  ____________________
    // _____________________   MVN  ____________________
    // 214 - MoVe Negative
    // mvn hh1 hh2
    // Operation data - 16 bits or 8 bits
    // [31 2B hh1 hh2]
    case 0x2B:
      insn.itype = m7900_mvn;
      Operand_Dir(insn, insn.Op1, TDIR_DIR);
      Operand_Dir(insn, insn.Op2, TDIR_DIR);
      break;
    // _____________________  END MVN  ____________________

    // _____________________   MVP  ____________________
    // 215 - MoVe Positive
    // mvp hh1 hh2
    // Operation data - 16 bits or 8 bits
    // [31 2A hh1 hh2]
    case 0x2A:
      insn.itype = m7900_mvp;
      Operand_Dir(insn, insn.Op1, TDIR_DIR);
      Operand_Dir(insn, insn.Op2, TDIR_DIR);
      break;
    // _____________________  END MVP  ____________________

    case 0x4B:// pei
      insn.itype = m7900_pei;
      RAZOPER = INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR);
      break;

    case 0x4C:// pea
      insn.itype = m7900_pea;
      RAZOPER = INSN_PREF_W;
      Operand_STK(insn, insn.Op1, 16);
      break;

    case 0x4D:// per
      insn.itype = m7900_per;
      RAZOPER = INSN_PREF_W;
      Operand_STK(insn, insn.Op1, 16);
      break;

    // _____________________   RLA  ____________________
    // 250 - Rotate Left accumulator A
    // RLA #imm
    // Operation data - 16 bits or 8 bits
    // [31 07 imm]
    case 0x07:
      insn.itype = m7900_rla;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      break;
    // _____________________  END RLA  ____________________

    // _____________________   RMPA  ____________________
    // 250 - Repeat Multiply and Accumulate
    // RMPA #imm
    // Operation data - 16 bits or 8 bits
    // [31 5A imm]
    case 0x5A:
      insn.itype = m7900_rmpa;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END RMPA  ____________________
    // _____________________   SBC  ____________________
    // 264 - SuBtract with Carry
    // sbc A,#imm
    // Operation data - 16 bits or 8 bits
    // [31 A7 imm]
    case 0xA7:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _____________________  END SBC  ____________________

    default:
      {
        uchar cm = code & 0x40;
        if ( cm == 0x40 )
        {
          insn.itype = m7900_tdan;
          RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, dt_byte, (((code-0x40) >> 4) & 0xF)+0x1);
        }
        else
        {
          insn.itype = m7900_tadn;
          Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
        }
      }
      break;
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_41(insn_t &insn)
{
  TRACE("Opcode_41");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
   // ________________________ BBC________________________

    // 122 -Branch on Bit Clear
    // bbc #imm dd rr (DIR)
    // Operation data length: 16 bits or 8 bits
    // [41 5A dd imm rr]
    case 0x5A:
      insn.itype = m7900_bbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      Operand_BBC(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 5 : 6);
      break;

    // 122 -Branch on Bit Clear
    // bbc #imm mmll rr (ABS)
    // Operation data length: 16 bits or 8 bits
    // [41 5E ll mm imm rr]
    case 0x5E:
      insn.itype = m7900_bbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      Operand_BBC(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 6 : 7);
      break;

   // ________________________ END BBC________________________
   // ________________________ BBS________________________

    // 124 - Branch on Bit Set
    // bbs #imm dd rr (DIR)
    // Operation data length: 16 bits or 8 bits
    // [41 4A dd imm rr]
    case 0x4A:
      insn.itype = m7900_bbs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      Operand_BBS(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 5 : 6);
      break;

    // 124 - Branch on Bit Set
    // bbs #imm mmll rr (ABS)
    // Operation data length: 16 bits or 8 bits
    // [41 4E ll mm imm rr]
    case 0x4E:
      insn.itype = m7900_bbs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Imm(insn, insn.Op1, getFlag_M ? 8 : 16);
      Operand_BBS(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 6 : 7);
      break;
   // ________________________ END BBS________________________

    // _____________________  CBEQ  ____________________

    // 145 - Compare immediate and Branch on EQual
    // cbeq dd, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [41 6A  dd imm rr]
    case 0x6A:
      insn.itype = m7900_cbeq;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 5 : 6);
      break;
    // _____________________ END CBEQ  ____________________

    // _____________________  CBNE  ____________________

    // 147 - Compare immediate and Branch on Not Equal
    // cbne dd, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [7A dd imm rr]
    case 0x7A:
      insn.itype = m7900_cbne;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 5 : 6);
      break;
    // _____________________ END CBNE  ____________________
    // _____________________  CPX  ____________________
    // 167 - ComPare memory and index register X
    // cpx mmll
    // Operation data length: 16 bits or 8 bits
    // [41 2E ll mm]
    case 0x2E:
      insn.itype = m7900_cpx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_X ? 8 : 16, SetTypeDataX);
      break;
    // _____________________  END CPX  ____________________
    // 168 - ComPare memory and index register Y
    // cpy mmll
    // Operation data length: 16 bits or 8 bits
    // [41 3E ll mm]
    case 0x3E:// cpy
      insn.itype = m7900_cpy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_M ? 8 : 16, SetTypeDataX);
      break;

    // _____________________  DEC  ____________________
    // 170 - DECrement by one
    // dec dd, X
    // Operation data - 16 bits or 8 bits
    // [41 9B dd]
    case 0x9B:
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    case 0x9F:// dec
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // _____________________  END DEC  ____________________

    // _____________________  INC  ____________________
    // 189 - INCrement by one
    // inc dd, X
    // Operation data - 16 bits or 8 bits
    // [41 8B dd]
    case 0x8B:
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;

    case 0x8F:// inc
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rX);
      break;
    // _____________________  END INC  ____________________

    // _____________________  DEX  ____________________
    // 171 - DEcrement index register X by one
    // dex
    // Operation data - 16 bits or 8 bits
    // [E3]
    case 0xE3:
      insn.itype = m7900_dex;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;
    // _____________________  END DEX  ____________________
    // _____________________  DEY  ____________________
    // 172 - DEcrement index register Y by one
    // dex
    // Operation data - 16 bits or 8 bits
    // [F3]
    case 0xF3:
      insn.itype = m7900_dey;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;
    // _____________________  END DEY  ____________________


    // _____________________  LDX  ____________________
    // 200 - Load
    // ldx dd, Y
    // Operation data - 16 bits or 8 bits
    // [41 05 dd]
    case 0x05:
      insn.itype = m7900_ldx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      Operand_Registr(insn.Op2, rY);
      break;

    case 0x06:
      insn.itype = m7900_ldx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op2, rY);
      break;
    // _____________________  END LDX  ____________________

    // _____________________  LDY  ____________________
    // 202 - LoaD index register Y from memory
    // ldy dd, X
    // Operation data - 16 bits or 8 bits
    // [41 1B dd]
    case 0x1B:
      insn.itype = m7900_ldy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      Operand_Registr(insn.Op2, rX);
      break;

    case 0x1F:
      insn.itype = m7900_ldy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS_X, 16);
      Operand_Registr(insn.Op2, rX);
      break;
    // _____________________  END INC  ____________________
    // _____________________  STX  ____________________
    // 275 - STore index register X in memory
    // stx dd, Y
    // Operation data - 16 bits or 8 bits
    // [41 E5 dd]
    case 0xE5:// stx dd,Y (DIR,Y)
      insn.itype = m7900_stx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_Y, SetTypeDataX);
      Operand_Registr(insn.Op2, rY);
      break;
    // _____________________  END STX  ____________________

    // _____________________  STY  ____________________
    // 276 - STore index register Y in memory
    // sty dd, X
    // Operation data - 16 bits or 8 bits
    // [41 FB dd]
    case 0xFB:// sty dd,X (DIR,X)
      insn.itype = m7900_sty;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR_Y, SetTypeDataX);
      Operand_Registr(insn.Op2, rX);
      break;
    // _____________________  END STX  ____________________

    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_51(insn_t &insn)
{
  TRACE("Opcode_51");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
 //---------------------------BYTE-------------------------------------//
    // 105 - ADD immediate and Memory at Byte
    // addmb dd, #imm
    // Operation data length: 8 bits
    // [51 02 dd imm]
    case 0x02:
      insn.itype = m7900_addmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 105 - ADD immediate and Memory at Byte
    // addmb mmll, #imm
    // Operation data length: 8 bits
    // [51 06 ll mm imm]
    case 0x06:
      insn.itype = m7900_addmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 114 - logical AND between immediate value and Memory (Byte)
    // andmb dd, #imm
    // Operation data length: 8 bits
    // [51 62 dd imm]
    case 0x62:
      insn.itype = m7900_andmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 105 - ADD immediate and Memory at Byte
    // addmb mmll, #imm
    // Operation data length: 8 bits
    // [51 66 ll mm imm]
    case 0x66:
      insn.itype = m7900_andmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 165 - CoMPare immediate with Memory at Byte
    // cmpmb dd, #imm
    // Operation data length: 8 bits
    // [51 22 dd imm]
    case 0x22:
      insn.itype = m7900_cmpmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 165 - CoMPare immediate with Memory at Byte
    // cmpmb  mmll, #imm
    // Operation data length: 8 bits
    // [51 26 ll mm imm]
    case 0x26:
      insn.itype = m7900_cmpmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 183 - Exclusive OR immediate with Memory at Byte
    // eormb dd, #imm
    // Operation data length: 8 bits
    // [51 72 dd imm]
    case 0x72:
      insn.itype = m7900_eormb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 183 - Exclusive OR immediate with Memory at Byte
    // eormb  mmll, #imm
    // Operation data length: 8 bits
    // [51 76 ll mm imm]
    case 0x76:
      insn.itype = m7900_eormb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 223 - OR immediAte with Memory at Byte
    // oramb dd, #imm
    // Operation data length: 8 bits
    // [51 32 dd imm]
    case 0x32:
      insn.itype = m7900_oramb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 223 - OR immediAte with Memory at Byte
    // oramb  mmll, #imm
    // Operation data length: 8 bits
    // [51 36 ll mm imm]
    case 0x36:
      insn.itype = m7900_oramb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 282 - SUBtract immediate from Memory at Byte SUBMB
    // submb dd, #imm
    // Operation data length: 8 bits
    // [51 12 dd imm]
    case 0x12:
      insn.itype = m7900_submb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 282 - SUBtract immediate from Memory at Byte SUBMB
    // submb  mmll, #imm
    // Operation data length: 8 bits
    // [51 16 ll mm imm]
    case 0x16:
      insn.itype = m7900_submb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // __________________________  ADDM ___________________
    // 104 - ADD immediate and Memory
    // addm  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 03 dd imm]
    case 0x03:
      insn.itype = m7900_addm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 104 - ADD immediate and Memory
    // addm  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 07 ll mm imm]
    case 0x07:
      insn.itype = m7900_addm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 8, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  ADDM ___________________

    // __________________________  ANDM ___________________
    // 113 - logical AND between immediate value and Memory
    // andm  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 63 dd imm]
    case 0x63:
      insn.itype = m7900_andm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 113 - logical AND between immediate value and Memory
    // andm  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 67 ll mm imm]
    case 0x67:
      insn.itype = m7900_andm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 8, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  ANDM ___________________
    // __________________________  CMPM ___________________
    // 164 - CoMPare immediate with Memory
    // cmpm  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 23 dd imm]
    case 0x23:
      insn.itype = m7900_cmpm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 164 - CoMPare immediate with Memory
    // cmpm  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 27 ll mm imm]
    case 0x27:
      insn.itype = m7900_cmpm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 8, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  CMPM ___________________

    // __________________________  EORM ___________________
    // 182 - Exclusive OR immediate with Memory
    // eorm  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 73 dd imm]
    case 0x73:
      insn.itype = m7900_eorm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 182 - Exclusive OR immediate with Memory
    // eorm  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 77 ll mm imm]
    case 0x77:
      insn.itype = m7900_eorm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_M ? 8 : 16, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  EORM ___________________

    // __________________________  ORAM ___________________
    // 222 - OR immediAte with Memory
    // oram  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 33 dd imm]
    case 0x33:
      insn.itype = m7900_oram;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 222 - OR immediAte with Memory
    // oram  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 37 ll mm imm]
    case 0x37:
      insn.itype = m7900_oram;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_M ? 8 : 16, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  oraM ___________________

    // __________________________  subM ___________________
    // 281 - SUBtract immediate from Memory
    // subm  dd, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 13 dd imm]
    case 0x13:
      insn.itype = m7900_subm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 281 - SUBtract immediate from Memory
    // subm  mmll, #imm
    // Operation data length: 16 bits or 8 bits
    // [51 17 ll mm imm]
    case 0x17:
      insn.itype = m7900_subm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 8, SetTypeDataM);

      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _______________________END  subM ___________________

    // __________________________  ADDMD ___________________
    // 106 - ADD immediate and Memory at Double-word
    // addmd  dd, #imm32
    // Operation data length: 32 bits
    // [51 83 dd imm imm imm imm]
    case 0x83:
      insn.itype = m7900_addmd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 106 - ADD immediate and Memory at Double-word
    // addmd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 87 ll mm imm imm imm imm]
    case 0x87:
      insn.itype = m7900_addmd;
      RAZOPER = INSN_PREF_D;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  ADDMD ___________________

    // __________________________  ANDMD ___________________
    // 115 - logical AND between immediate value and Memory (Double word)
    // andmd  dd, #imm32
    // Operation data length: 32 bits
    // [51 E3 dd imm imm imm imm]
    case 0xE3:
      insn.itype = m7900_andmd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 115 - logical AND between immediate value and Memory (Double word)
    // andmd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 E7 ll mm imm imm imm imm]
    case 0xE7:
      insn.itype = m7900_andmd;
      RAZOPER = INSN_PREF_D;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  ADDMD ___________________

    // __________________________ CMPMD ___________________
    // 166 - CoMPare immediate with Memory at Double-word
    // cmpmd  dd, #imm32
    // Operation data length: 32 bits
    // [51 A3 dd imm imm imm imm]
    case 0xA3:
      insn.itype = m7900_cmpmd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 166 - CoMPare immediate with Memory at Double-word
    // cmpmd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 A7 ll mm imm imm imm imm]
    case 0xA7:
      insn.itype = m7900_cmpmd;
      RAZOPER = INSN_PREF_D;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  CMPMD ___________________

    // __________________________  EORMD ___________________
    // 184 - Exclusive OR immediate with Memory at Double-word
    // eormd  dd, #imm32
    // Operation data length: 32 bits
    // [51 F3 dd imm imm imm imm]
    case 0xF3:
      insn.itype = m7900_eormd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 184 - Exclusive OR immediate with Memory at Double-word
    // eormd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 F7 ll mm imm imm imm imm]
    case 0xF7:
      insn.itype = m7900_eormd;
      RAZOPER = INSN_PREF_D;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  EORMD ___________________

    // __________________________  ORAMD ___________________
    // 224 -OR immediAte with Memory at Double-word
    // oramd  dd, #imm32
    // Operation data length: 32 bits
    // [51 B3 dd imm imm imm imm]
    case 0xB3:
      insn.itype = m7900_oramd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 224 - OR immediAte with Memory at Double-word
    // oramd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 B7 ll mm imm imm imm imm]
    case 0xB7:
      insn.itype = m7900_oramd;
      RAZOPER = INSN_PREF_D;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  ORAMD ___________________

    // __________________________  SUBMD ___________________
    // 283 - SUBtract immediate from Memory at Double-word
    // submd  dd, #imm32
    // Operation data length: 32 bits
    // [51 93 dd imm imm imm imm]
    case 0x93:
      insn.itype = m7900_submd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 283 - SUBtract immediate from Memory at Double-word
    // submd  mmll, #imm32
    // Operation data length: 32 bits
    // [51 97 ll mm imm imm imm imm]
    case 0x97:
      insn.itype = m7900_submd;
      RAZOPER = INSN_PREF_D;
      Operand_Dir(insn, insn.Op1, TAB_ABS, dt_dword);
      Operand_Imm(insn, insn.Op2, 32);
      break;
    // _______________________END  ORAMD ___________________

    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_81(insn_t &insn)
{
  TRACE("Opcode_81");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
    case 0x85:// phb
      insn.itype = m7900_phb;
      break;
    // [ 81 A4]
    case 0xA4:// txb
      insn.itype = m7900_txb;
      break;

    case 0xB4:// tyb
      insn.itype = m7900_tyb;
      break;

    case 0x95:// plb
      insn.itype = m7900_plb;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 116 - Arithmetic Shift to Left
    // asl B
    // Operation data length: 16 bits or 8 bits
    // [81 03]
    case 0x03:// asl
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 119 - Arithmetic Shift to Right
    // asr B
    // Operation data length: 16 bits or 8 bits
    // [64]
    case 0x64:// asr
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 94 - Absolute value
    // abs B
    case 0xE1:
      insn.itype = m7900_abs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 185 - EXTension Sign
    // exts B
    // Operation data length: 16 bits
    // [35]
    case 0x35:// exts
      insn.itype = m7900_exts;
      RAZOPER = INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 187 - EXTension Zero
    // extz B
    // Operation data length: 16 bits
    // [34]
    case 0x34:// extz
      insn.itype = m7900_extz;
      RAZOPER = INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 216 - NEGative
    // neg B
    // Operation data length: 16 bits or 8 bits
    // [24]
    case 0x24:// neg
      insn.itype = m7900_neg;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;

    // 293 - Transfer accumulator B to index register X
    // tbx
    // Operation data length: 16 bits or 8 bits
    // [C4]
    case 0xC4:
      insn.itype = m7900_tbx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 294 - Transfer accumulator B to index register Y
    // tby
    // Operation data length: 16 bits or 8 bits
    // [D4]
    case 0xD4:
      insn.itype = m7900_tby;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    // _____________________  DEC  ____________________
    // 170 - DECrement by one
    // dec B
    // Operation data - 16 bits or 8 bits
    // [B3]
    case 0xB3:
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________  END DEC  ____________________

    // _____________________  INC  ____________________
    // 189 - INCrement by one
    // inc B
    // Operation data - 16 bits or 8 bits
    // [A3]
    case 0xA3:
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________  END INC  ____________________

    // _____________________   LSR  ____________________
    // 204 - Logical Shift Right
    // lsr B
    // Operation data - 16 bits or 8 bits
    // [43]
    case 0x43:
      insn.itype = m7900_lsr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________  END LSR  ____________________
    // _____________________   ROL  ____________________
    // 254 - ROtate one bit Left
    // rol B
    // Operation data - 16 bits or 8 bits
    // [13]
    case 0x13:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________  END ROL  ____________________
    // _____________________  ROR  ____________________
    // 255 - ROtate one bit Right
    // ror B
    // Operation data - 16 bits or 8 bits
    // [53]
    case 0x53:// ror
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________  END ROR  ____________________

 //---------------------------BYTE/WORD-------------------------------------//
    // _____________________  ADD ____________________
    // 101 - ADd
    // add B, #imm
    // Operation data length: 16 bits or 8 bits
    // [26 imm]
    case 0x26:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 101 - ADd
    // add B, dd
    // Operation data length: 16 bits or 8 bits
    // [2A dd]
    case 0x2A:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR,SetTypeDataM);
      break;

    // 101 - ADd
    // add B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [2B dd]
    case 0x2B:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 101 - ADd
    // add B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [2E ll mm]
    case 0x2E:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 101 - ADd
    // add B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [2F ll mm]
    case 0x2F:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END ADD  ____________________
    // _____________________  CMP  ____________________
    // 161 - CoMPare
    // cmp B, #imm
    // Operation data length: 16 bits or 8 bits
    // [46 imm]
    case 0x46:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 161 - CoMPare
    // cmp B, dd
    // Operation data length: 16 bits or 8 bits
    // [4A dd]
    case 0x4A:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [4B dd]
    case 0x4B:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 161 - CoMPare
    // cmp B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [4E ll mm]
    case 0x4E:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [4F ll mm]
    case 0x4F:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END CMP  ____________________

    // _____________________  AND  ____________________

    // 111 - logical AND
    // and B, #imm
    // Operation data length: 16 bits or 8 bits
    // [66 imm]
    case 0x66:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 111 - logical AND
    // and B, #imm
    // Operation data length: 16 bits or 8 bits
    // [6A dd]
    case 0x6A:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 111 - logical AND
    // and B, #imm
    // Operation data length: 16 bits or 8 bits
    // [6B dd]
    case 0x6B:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 111 - logical AND
    // and B, #imm
    // Operation data length: 16 bits or 8 bits
    // [6E ll mm]
    case 0x6E:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 111 - logical AND
    // and B, #imm
    // Operation data length: 16 bits or 8 bits
    // [6F ll mm]
    case 0x6F:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END AND  ____________________

    // _____________________  CBEQ  ____________________

    // 145 - Compare immediate and Branch on EQual
    // cbeq B, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [A6 imm rr]
    case 0xA6:
      insn.itype = m7900_cbeq;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 4 : 5);
      break;
    // _____________________ END CBEQ  ____________________
    // _____________________  CBNE  ____________________
    // 147 - Compare immediate and Branch on Not Equal
    // cbne B, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [B6 imm rr]
    case 0xB6:
      insn.itype = m7900_cbne;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 4 : 5);
      break;
    // _____________________ END CBNE  ____________________

    // _____________________ CLr  ____________________
    // 153 - CLeaR accumulator
    // clr B
    // Operation data length: 16 bits or 8 bits
    // [54]
    case 0x54:// clr
      insn.itype = m7900_clr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      break;
    // _____________________ END CLr ____________________

    // _____________________  EOR  ____________________
    // 180 - Exclusive OR memory with accumulator
    // eor B, #imm
    // Operation data length: 16 bits or 8 bits
    // [76 imm]
    case 0x76:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, dd
    // Operation data length: 16 bits or 8 bits
    // [7A dd]
    case 0x7A:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [7B dd]
    case 0x7B:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [7E ll mm]
    case 0x7E:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [7F ll mm]
    case 0x7F:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END EOR  ____________________

    // _____________________  LDA  ____________________
    // 195 - LoaD Accumulator from memory
    // lda B, #imm
    // Operation data length: 16 bits or 8 bits
    // [16 imm]
    case 0x16:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, dd
    // Operation data length: 16 bits or 8 bits
    // [1A dd]
    case 0x1A:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [1B dd]
    case 0x1B:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [18 dd]
    case 0x18:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [19 dd]
    case 0x19:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [1E ll mm]
    case 0x1E:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [1F ll mm]
    case 0x1F:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [1C ll mm hh]
    case 0x1C:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda B, hhmmll, X (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [1D ll mm hh]
    case 0x1D:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END LDA  ____________________

    // _____________________  LDAB  ____________________
    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, #imm
    // Operation data length: 16 bits
    // [28 imm]
    case 0x28:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, dd
    // Operation data length: 16 bits
    // [0A dd]
    case 0x0A:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits
    // [0B dd]
    case 0x0B:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X);
      Operand_Registr(insn.Op3, rX);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [08 dd]
    case 0x08:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits
    // [09 dd]
    case 0x09:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [0E ll mm]
    case 0x0E:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [0F ll mm]
    case 0x0F:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [0C ll mm hh]
    case 0x0C:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_byte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [0D ll mm hh]
    case 0x0D:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END LDAB  ____________________

    // _____________________  ORA  ____________________
    // 220 - OR memory with Accumulator
    // ora B, #imm
    // Operation data length: 16 bits or 8 bits
    // [56 imm]
    case 0x56:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 220 - OR memory with Accumulator
    // ora B, dd
    // Operation data length: 16 bits or 8 bits
    // [5A dd]
    case 0x5A:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [5B dd]
    case 0x5B:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 220 - OR memory with Accumulator
    // ora B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [5E ll mm]
    case 0x5E:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [5F ll mm]
    case 0x5F:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END ORA  ____________________
    // _____________________  STA  ____________________
    // 271 - STore Accumulator in memory
    // sta B, dd
    // Operation data length: 16 bits or 8 bits
    // [DA dd]
    case 0xDA:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [DB dd]
    case 0xDB:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 271 - STore Accumulator in memory
    // sta B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [D8 dd]
    case 0xD8:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [D9 dd]
    case 0xD9:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [DE ll mm]
    case 0xDE:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [DF ll mm]
    case 0xDF:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 271 - STore Accumulator in memory
    // sta B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [DC ll mm hh]
    case 0xDC:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [DD ll mm hh]
    case 0xDD:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END STA  ____________________
    // _____________________  STAB  ____________________
    // 272 - STore Accumulator in memory at Byte
    // stab B, dd
    // Operation data length: 16 bits or 8 bits
    // [CA dd]
    case 0xCA:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [CB dd]
    case 0xCB:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [C8 dd]
    case 0xC8:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [C9 dd]
    case 0xC9:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [CE ll mm]
    case 0xCE:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [CF ll mm]
    case 0xCF:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [CC ll mm hh]
    case 0xCC:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [CD ll mm hh]
    case 0xCD:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END STAB  ____________________

    // _____________________  SUB  ____________________
    // 278 - SUBtract
    // sub B, #imm
    // Operation data length: 16 bits or 8 bits
    // [36 #imm]
    case 0x36:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 278 - SUBtract
    // sub B, dd
    // Operation data length: 16 bits or 8 bits
    // [3A dd]
    case 0x3A:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [3B dd]
    case 0x3B:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 278 - SUBtract
    // sub B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [3E ll mm]
    case 0x3E:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [3F ll mm]
    case 0x3F:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END SUB  ____________________

 //---------------------------BYTE-------------------------------------//
    // 102 - ADD at Byte
    // addb B, #imm
    // Operation data length: 8 bits
    // [81 29 imm]
    case 0x29:
      insn.itype = m7900_addb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 112 - logical AND between immediate (Byte)
    // andb B, #imm
    // Operation data length: 8 bits
    // [81 23 imm]
    case 0x23:
      insn.itype = m7900_andb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 146 - Compare immediate and Branch on EQual at Byte
    // cbeqb B, #imm, rr (DIR)
    // Operation data length: 8 bits
    // [A2 imm rr]
    case 0xA2:
      insn.itype = m7900_cbeqb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    // 148 - Compare immediate and Branch on Not Equal at Byte
    // cbneb B, #imm, rr ()
    // Operation data length: 8 bits
    // [B2 imm rr]
    case 0xB2:
      insn.itype = m7900_cbneb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    // 154 - CLeaR accumulator at Byte
    // clrb B
    // Operation data length: 8 bits
    // [44]
    case 0x44:// clrb
      insn.itype = m7900_clrb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      break;

    // 162 - CoMPare at Byte
    // cmpb B, #imm
    // Operation data length: 8 bits
    // [38 imm]
    case 0x38:
      insn.itype = m7900_cmpb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 181 - Exclusive OR immediate with accumulator at Byte
    // eorb B, #imm
    // Operation data length: 8 bits
    // [33 imm]
    case 0x33:
      insn.itype = m7900_eorb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 221 - OR immediate with Accumulator at Byte
    // orab B, #imm
    // Operation data length: 8 bits
    // [63 imm]
    case 0x63:
      insn.itype = m7900_orab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 279 - OR immediate with Accumulator at Byte
    // subb B, #imm
    // Operation data length: 8 bits
    // [81 39 imm]
    case 0x39:
      insn.itype = m7900_subb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    default:
      return 0;
  }

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_A1(insn_t &insn)
{
  TRACE("Opcode_A1");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
    // ___________________  ADC _________________________
    // 96 - ADd with Carry
    // adc B, dd
    // Operation data length: 16 bits or 8 bits
    // [A1 8A dd]
    case 0x8A:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [A1 8B dd]
    case 0x8B:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [A1 80 dd]
    case 0x80:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [A1 81 dd]
    case 0x81:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [A1 88 dd]
    case 0x88:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [A1 82 dd]
    case 0x82:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 96 - ADd with Carry
    // adc B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [A1 89 dd]
    case 0x89:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [A1 83 nn]
    case 0x83:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 96 - ADd with Carry
    // adc B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [A1 84 nn]
    case 0x84:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [A1 8E ll mm]
    case 0x8E:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [A1 8F ll mm]
    case 0x8F:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 96 - ADd with Carry
    // adc B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [A1 86 ll mm]
    case 0x86:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 96 - ADd with Carry
    // adc B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [A1 8C ll mm hh]
    case 0x8C:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 96 - ADd with Carry
    // adc B, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [A1 8D ll mm hh]
    case 0x8D:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END ADC _________________________

    // ___________________  SBC _________________________
    // 264 - SuBtract with Carry
    // sbc B, dd
    // Operation data length: 16 bits or 8 bits
    // [21 AA dd]
    case 0xAA:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc B, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [21 AB dd]
    case 0xAB:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 264 - SuBtract with Carry
    // sbc B, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A0 dd]
    case 0xA0:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc B, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [21 A1 dd]
    case 0xA1:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc B, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [21 A8 dd]
    case 0xA8:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc B, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A2 dd]
    case 0xA2:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 264 - SuBtract with Carry
    // sbc B, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [21 A9 dd]
    case 0xA9:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc B, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [21 A3 nn]
    case 0xA3:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 264 - SuBtract with Carry
    // sbc B, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 A4 nn]
    case 0xA4:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc B, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [21 AE ll mm]
    case 0xAE:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc B, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 AF ll mm]
    case 0xAF:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 264 - SuBtract with Carry
    // sbc B, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [21 A6 ll mm]
    case 0xA6:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 264 - SuBtract with Carry
    // sbc B, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 AC ll mm hh]
    case 0xAC:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 264 - SuBtract with Carry
    // sbc B, hhmmll, X (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 AD ll mm hh]
    case 0xAD:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END sbc _________________________

    default:
      return 0;
  }

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_11(insn_t &insn)
{
  TRACE("Opcode_11");

  uchar code = insn.get_next_byte();
  TRACE(code);

  switch ( code )
  {
   // ________________________ ADD________________________
    // 101 - ADd
    // add A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 20 dd]
    case 0x20:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 101 - ADd
    // add A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 21 dd]
    case 0x21:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 101 - ADd
    // add A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 28 dd]
    case 0x28:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 22 dd]
    case 0x22:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_byte);
      break;

    // 101 - ADd
    // add A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 29 dd]
    case 0x29:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 23 nn]
    case 0x23:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 101 - ADd
    // add A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 24 nn]
    case 0x24:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 26 ll mm]
    case 0x26:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 101 - ADd
    // add A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 2C ll mm hh]
    case 0x2C:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 101 - ADd
    // add A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 2D ll mm hh]
    case 0x2D:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // ______________________ END ADD _____________________
   // ________________________ CMP________________________
    // 161 - CoMPare
    // cmp A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 40 dd]
    case 0x40:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 41 dd]
    case 0x41:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 48 dd]
    case 0x48:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 42 dd]
    case 0x42:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 161 - CoMPare
    // cmp A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 49 dd]
    case 0x49:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 43 nn]
    case 0x43:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 161 - CoMPare
    // cmp A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 44 nn]
    case 0x44:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 46 ll mm]
    case 0x46:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 161 - CoMPare
    // cmp A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 4C ll mm hh]
    case 0x4C:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 4D ll mm hh]
    case 0x4D:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END CMP _____________________

   // ________________________ AND________________________
    // 111 - logical AND
    // and A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 60 dd]
    case 0x60:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 111 - logical AND
    // and A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 61 dd]
    case 0x61:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 111 - logical AND
    // and A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 68 dd]
    case 0x68:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 62 dd]
    case 0x62:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 111 - logical AND
    // and A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 69 dd]
    case 0x69:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 63 nn]
    case 0x63:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 111 - logical AND
    // and A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 64 nn]
    case 0x64:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 66 ll mm]
    case 0x66:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 111 - logical AND
    // and A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 6C ll mm hh]
    case 0x6C:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 111 - logical AND
    // and A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [ 6D ll mm hh]
    case 0x6D:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END AND _____________________
   // ________________________ EOR________________________
    // 180 - Exclusive OR memory with accumulator
    // eor A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 70 dd]
    case 0x70:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 71 dd]
    case 0x71:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 78 dd]
    case 0x78:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 72 dd]
    case 0x72:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 79 dd]
    case 0x79:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 73 nn]
    case 0x73:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 74 nn]
    case 0x74:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 76 ll mm]
    case 0x76:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [21 7C ll mm hh]
    case 0x7C:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [21 7D ll mm hh]
    case 0x7D:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END eor _____________________

    // ___________________  LDA _________________________
    // 195 - LoaD Accumulator from memory
    // lda A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 10 dd]
    case 0x10:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 11 dd]
    case 0x11:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 12 dd]
    case 0x12:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 13 nn]
    case 0x13:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [11 14 nn]
    case 0x14:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 16 ll mm]
    case 0x16:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END LDA  ____________________

    // ___________________  LDAB _________________________
    // 196 - LoaD Accumulator from memory at Byte
    // ldab a, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 00 dd]
    case 0x00:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 01 dd]
    case 0x01:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 02 dd]
    case 0x02:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 03 nn]
    case 0x03:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [11 04 nn]
    case 0x04:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 06 ll mm]
    case 0x06:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END LDAB  ____________________

    // ___________________  STA _________________________
    // 271 - STore Accumulator in memory
    // sta A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [D0 dd]
    case 0xD0:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [D1 dd]
    case 0xD1:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [D2 dd]
    case 0xD2:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 271 - STore Accumulator in memory
    // sta A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [D3 nn]
    case 0xD3:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 271 - STore Accumulator in memory
    // sta A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [D4 nn]
    case 0xD4:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [D6 ll mm]
    case 0xD6:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________ END STA  ____________________
    // _____________________  STAB  ____________________
    // 272 - STore Accumulator in memory at Byte
    // stab A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [C0 dd]
    case 0xC0:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [C1 dd]
    case 0xC1:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [C2 dd]
    case 0xC2:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [C3 nn]
    case 0xC3:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [C4 nn]
    case 0xC4:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [C6 ll mm]
    case 0xC6:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________  END STAB  ____________________

    // _____________________  STAD  ____________________
    // 273 - STore Accumulator in memory at Double-word
    // stad E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [E0 dd]
    case 0xE0:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 bits
    // [E1 dd]
    case 0xE1:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 E2 dd]
    case 0xE2:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [E3 nn]
    case 0xE3:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [E4 nn]
    case 0xE4:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [E6 ll mm]
    case 0xE6:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;
    // _____________________  END STAD  ____________________

   // ________________________ ORA________________________
    // 220 - OR memory with Accumulator
    // ora A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 50 dd]
    case 0x50:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 51 dd]
    case 0x51:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 58 dd]
    case 0x58:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 52 dd]
    case 0x52:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 220 - OR memory with Accumulator
    // ora A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 59 dd]
    case 0x59:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 53 nn]
    case 0x53:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 220 - OR memory with Accumulator
    // ora A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 54 nn]
    case 0x54:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 56 ll mm]
    case 0x56:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 220 - OR memory with Accumulator
    // ora A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [11 5C ll mm hh]
    case 0x5C:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // ora A, hhmmll, X (Absolute long indexed X addressing mode(ABL,X)
    // Operation data length: 16 bits or 8 bits
    // [11 5D ll mm hh]
    case 0x5D:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END ora _____________________

   // ________________________ SUB________________________
    // 278 - SUBtract
    // sub A, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 30 dd]
    case 0x30:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub A, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 16 bits or 8 bits
    // [11 31 dd]
    case 0x31:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [11 38 dd]
    case 0x38:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub A, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 32 dd]
    case 0x32:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 278 - SUBtract
    // sub A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [11 39 dd]
    case 0x39:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub A, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 16 bits or 8 bits
    // [11 33 nn]
    case 0x33:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 278 - SUBtract
    // sub A, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 16 bits or 8 bits
    // [21 34 nn]
    case 0x34:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub A, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 16 bits or 8 bits
    // [11 36 ll mm]
    case 0x36:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 278 - SUBtract
    // sub A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [11 3C ll mm hh]
    case 0x3C:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [11 3D ll mm hh]
    case 0x3D:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // ______________________ END SUB _____________________

    // ___________________  ADDD _________________________

    // 101 - ADd Double-word
    // addd E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [11 90 dd]
    case 0x90:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 103 - ADd at Double-word
    // addd E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 buts
    // [11 91 dd]
    case 0x91:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 103 - ADd at Double-word
    // addd E, (dd), Y  ()
    // Operation data length: 32 bits
    // [11 98 dd]
    case 0x98:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 103 - ADd Double-word
    // addd E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 92 dd]
    case 0x92:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 103 - ADd at Double-word
    // addd E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 99 dd]
    case 0x99:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 103 - ADd at Double-word
    // addd E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [11 93 nn]
    case 0x93:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 103 - ADd at Double-word
    // addd E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [11 94 nn]
    case 0x94:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 103 - ADd at Double-word
    // addd E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [11 9E ll mm]
    case 0x9E:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 103 - ADd at Double-word
    // addd E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [11 9F ll mm]
    case 0x9F:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 103 - ADd at Double-word
    // addd E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [11 96 ll mm]
    case 0x96:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 103 - ADd at Double-word
    // addd E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [11 9C ll mm hh]
    case 0x9C:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 103 - ADd at Double-word
    // addd A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [11 9D ll mm hh]
    case 0x9D:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END ADCD _________________________
    // ___________________  CMPD _________________________

    // 163 - CoMPare at Double-word
    // cmpd E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [11 B0 dd]
    case 0xB0:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 buts
    // [11 B1 dd]
    case 0xB1:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, (dd), Y  ()
    // Operation data length: 32 bits
    // [11 B8 dd]
    case 0xB8:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 B2 dd]
    case 0xB2:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 B9 dd]
    case 0xB9:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [11 B3 nn]
    case 0xB3:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [11 B4 nn]
    case 0xB4:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [11 BE ll mm]
    case 0xBE:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [11 BF ll mm]
    case 0xBF:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [11 B6 ll mm]
    case 0xB6:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [11 BC ll mm hh]
    case 0xBC:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [11 BD ll mm hh]
    case 0xBD:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END CMPD _________________________

    // ___________________  LDAD _________________________

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [11 80 dd]
    case 0x80:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 buts
    // [11 81 dd]
    case 0x81:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 82 dd]
    case 0x82:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [11 83 nn]
    case 0x83:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [11 84 nn]
    case 0x84:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [11 86 ll mm]
    case 0x86:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;
    // ___________________  END LDAD _________________________

    // ___________________  SUBD _________________________

    // 280 - SUBtract Double-word
    // subd E, (dd) (Direct indirect addressing mode (DIR))
    // Operation data length: 32 bits
    // [11 A0 dd]
    case 0xA0:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      break;

    // 280 - SUBtract Double-word
    // subd E, (dd, X)  (Direct index X indirect addressing mode (DIR,X))
    // Operation data length: 32 bits
    // [11 A1 dd]
    case 0xA1:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR_X, dt_dword);
      break;

    // 280 - SUBtract Double-word
    // subd E, (dd), Y  ()
    // Operation data length: 32 bits
    // [11 A8 dd]
    case 0xA8:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 280 - SUBtract Double-word
    // subd E, L(dd)(Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 A2 dd]
    case 0xA2:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      break;

    // 280 - SUBtract Double-word
    // subd E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [11 A9 dd]
    case 0xA9:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 280 - SUBtract Double-word
    // subd E, nn, S (Stack pointer relative addressing mode(SR))
    // Operation data length: 32 bits
    // [11 A3 nn]
    case 0xA3:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_SP, 8);
      Operand_Registr(insn.Op3, rPS);
      break;

    // 280 - SUBtract Double-word
    // subd E, (nn,S), Y (Stack pointer relative indexed Y addressing mode((SR),Y))
    // Operation data length: 32 bits
    // [11 A4 nn]
    case 0xA4:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_SR(insn, insn.Op2, TSP_INDEX_SP_Y, 8);
      Operand_Registr(insn.Op3, rY);
      break;

    // 280 - SUBtract Double-word
    // subd E, mmll, Y (Absolute indexed X addressing mode(ABS,Y))
    // Operation data length: 32 bits
    // [11 A6 ll mm]
    case 0xA6:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_Y, 16, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 280 - SUBtract Double-word
    // subd E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [11 AC ll mm hh]
    case 0xAC:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 280 - SUBtract Double-word
    // subd A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [11 AD ll mm hh]
    case 0xAD:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // ___________________  END SUBD _________________________

    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_B1(insn_t &insn)
{
  TRACE("Opcode_B1");

  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;

  switch ( code )
  {

    // 292 - Transfer accumulator B to Stack pointer
    // tbs
    // Operation data length: 8 bits
    // [B1 82]
    case 0x82:
      insn.itype = m7900_tbs;
      break;

    // 96 - ADc with Carry
    // adc B, #imm
    // Operation data length: 16 bits or 8 bits
    // [B1 87 imm]
    case 0x87:
      insn.itype = m7900_adc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 98 - ADd with Carry at Byte
    // adcb B, #imm
    // Operation data length: 8 bits
    // [B1 1A imm]
    case 0x1A:
      insn.itype = m7900_adcb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 265 - SuBtract with Carry at Byte
    // sbcb A, #imm
    // Operation data length: 8 bits
    // [B1 1B imm]
    case 0x1B:
      insn.itype = m7900_sbcb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 299 - Transfer Stack pointer to accumulator B
    // tsb
    // Operation data length: 16 bits or 8 bits
    // [B1 92]
    case 0x92:
      insn.itype = m7900_tsb;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    // _____________________   SBC  ____________________
    // 264 - SuBtract with Carry
    // sbc B, #imm
    // Operation data - 16 bits or 8 bits
    // [B1 A7 imm]
    case 0xA7:
      insn.itype = m7900_sbc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;
    // _____________________  END SBC  ____________________

    default:
      {
        uchar cm = code & 0x40;
        if ( cm == 0x40 )
        {
          insn.itype = m7900_tdbn;
          RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, dt_byte, (((code-0x40) >> 4) & 0xF)+0x1);
        }
        else
        {
          insn.itype = m7900_tbdn;
          Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
        }
      }
      break;
  }

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_B8(insn_t &insn)
{
  TRACE("Opcode_B8");

  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;
  uchar cd = code & 0xF;
  uchar Nib;

  if ( nib == 0 && cd == 0 )
    return 0;

  if ( nib == 0 )
  {
    insn.itype = m7900_phdn;
    RAZOPER = INSN_PREF_W;
    Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
    return insn.size;
  }
  else if ( cd == 0 )
  {
    insn.itype = m7900_lddn;
    RAZOPER = INSN_PREF_W;
    Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
    Nib = nib;
  }
  else
  {
    if ( nib != cd )
      return 0;
    insn.itype = m7900_phldn;
    RAZOPER = INSN_PREF_W;
    Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
    Nib = cd;
  }

  for ( int i=0; i < 4; ++i )
    if ( GETBIT(Nib, i) == 1 )
      Operand_STK(insn, insn.ops[1+i], 16);

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_77(insn_t &insn)
{
  TRACE("Opcode_77");

  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;
  uchar cd = code & 0xF;

  switch ( cd )
  {
    case 0xC:
      insn.itype = m7900_rtld;
      Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
      break;

    case 0x0:
      insn.itype = m7900_pldn;
      RAZOPER = INSN_PREF_W;
      Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
      break;

    case 0x8:
      insn.itype = m7900_rtsdn;
      Operand_Imm_Spesh(insn.Op1, dt_byte, nib);
      break;

    default:
      return 0;
  }

  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_61(insn_t &insn)
{
  TRACE("Opcode_61");

  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;
  uchar count = code & 0x0F;

  Operand_Imm_Spesh(insn.Op1, dt_byte, count);

  uchar i;

  switch ( nib )
  {
    case 0x0:
      insn.itype = m7900_movrb;
      // This instruction is unaffected by flag m
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// imm
        insn.get_next_byte();// dd
      }
      break;

    case 0x2:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// imm
        insn.get_next_word();// llmm
      }
      break;

    case 0x4:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// dds1
        insn.get_next_byte();// ddd1
      }
      break;

    case 0x6:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// dd
        insn.get_next_word();// llmm
      }
      break;

    case 0x8:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_word();// llmm
        insn.get_next_byte();// dd
      }
      break;

    case 0xA:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_word();// mmll1
        insn.get_next_word();// mmll2
      }
      break;
    // ______________________________________________

    case 0x1:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// dd

        if ( getFlag_M == 0 )
          insn.get_next_word();// imm
        else
          insn.get_next_byte();// imm
      }
      break;

    case 0x3:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < count; i++ )
      {
        if ( getFlag_M != 0 )
        {
          insn.get_next_byte();// imm
          insn.get_next_word();// llmm
        }
        else
        {
          insn.get_next_word();// imm
          insn.get_next_word();// llmm
        }
      }
      break;

    case 0x5:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// dd1
        insn.get_next_byte();// dd2
      }
      break;

    case 0x7:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;
      for ( i=0; i < count; i++ )
      {
        insn.get_next_byte();// dd
        insn.get_next_word();// llmm
      }
      break;

    case 0x9:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < count; i++ )
      {
        insn.get_next_word();// llmm
        insn.get_next_byte();// dd
      }
      break;

    case 0xB:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;
      for ( i=0; i < count; i++ )
      {
        insn.get_next_word();// mmll1
        insn.get_next_word();// mmll2
      }
      break;

    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_71(insn_t &insn)
{
  int i;
  TRACE("Opcode_71");
  uchar code = insn.get_next_byte();
  TRACE(code);

  uchar nib = (code >> 4) & 0xF;
  uchar cd = code & 0x0F;

  Operand_Imm_Spesh(insn.Op1, dt_byte, cd);

  // 140 - Branch on Single bit Clear
  // bsc n, dd, rr
  // bsc n, mmll, rr
  // Operation data length: 16 bits or 8 bits
  // [71 n+E0 ll mm rr]
  // [71 n+A0 dd rr]

  switch ( nib )
  {
    case 0x0:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < cd; i++ )
      {
        insn.get_next_word();// mmll1
        insn.get_next_byte();// dd
      }
      break;

    case 0x6:
      insn.itype = m7900_movrb;
      RAZOPER = INSN_PREF_U;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movr;

      for ( i=0; i < cd; i++ )
      {
        insn.get_next_word();// mmll1
        insn.get_next_byte();// dd
      }
      break;

    case 0x1:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < cd; i++ )
      {
        insn.get_next_word();// mmll1
        insn.get_next_byte();// dd
      }
      break;

    case 0x7:
      insn.itype = m7900_movr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      insn.Op2.type = o_mem;
      insn.Op2.TypeOper = m7900_movrb;

      for ( i=0; i < cd; i++ )
      {
        insn.get_next_byte();// dd
        insn.get_next_word();// llmm
      }
      break;

    case 0xA:
      insn.itype = m7900_bsc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    case 0xE:
      insn.itype = m7900_bsc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 5);
      break;

    case 0x8:
      insn.itype = m7900_bss;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    case 0xC:
      insn.itype = m7900_bss;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm_Spesh(insn.Op1, dt_byte, cd);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 5);
      break;

    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  TRACE("ana");

  RAZOPER = 0;

  uchar code = insn.get_next_byte();
  uchar nib = (code >> 4) & 0xF;
  uchar imm, com;

  switch ( code )
  {
    // 116 - Arithmetic Shift to Left
    // asl A
    // Operation data length: 16 bits or 8 bits
    // [03]
    case 0x03:// asl
      insn.itype = m7900_asl;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    // 119 - Arithmetic Shift to Right
    // asr A
    // Operation data length: 16 bits or 8 bits
    // [64]
    case 0x64:// asr
      insn.itype = m7900_asr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    case 0x91:
      return Opcode_91(insn);

    case 0x21:
      return Opcode_21(insn);

    case 0x31:
      return Opcode_31(insn);

    case 0x41:
      return Opcode_41(insn);

    case 0x51:
      return Opcode_51(insn);

    case 0x81:
      return Opcode_81(insn);

    case 0x11:
      return Opcode_11(insn);

    case 0xA1:
      return Opcode_A1(insn);

    case 0xB1:
      return Opcode_B1(insn);

    case 0xB8:
      return Opcode_B8(insn);

      // 94 - Absolute value
      // abs A
    case 0xE1:
      insn.itype = m7900_abs;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

   //-----------------------------------------------------------//
     // 139 - force BReaK
     // brk
     // Operation data length: -
     // [00 74]
    case 0x00:// brk (IMP)
      if ( get_byte(insn.ea + 1) == 0x74 )
      {
        insn.get_next_byte();
        insn.itype = m7900_brk;
        Operand_IMP(insn.Op1);
      }
      else
      {
        return 0;
      }
      break;

    case 0x14:// clc
      insn.itype = m7900_clc;
      break;

    case 0x15:// cli
      insn.itype = m7900_cli;
      break;

    case 0x65:// clv
      insn.itype = m7900_clv;
      break;

     // 154 - CLeaR accumulator at Byte
     // clrb A
     // Operation data length: 8 bits
     // [44]
    case 0x44:// clrb
      insn.itype = m7900_clrb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      break;

     // 153 - CLeaR accumulator
     // clr A
     // Operation data length: 16 bits or 8 bits
     // [54]
    case 0x54:// clr
      insn.itype = m7900_clr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    case 0xA4:// txa
      insn.itype = m7900_txa;
      break;

    case 0xB4:// tya
      insn.itype = m7900_tya;
      break;

    case 0xC4:// tax
      insn.itype = m7900_tax;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xD4:// tay
      insn.itype = m7900_tay;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0x55:// xab
      insn.itype = m7900_xab;
      break;

    case 0xE3:// dex
      insn.itype = m7900_dex;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xF3:// dey
      insn.itype = m7900_dey;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 185 - EXTension Sign
    // exts A
    // Operation data length: 16 bits
    // [35]
    case 0x35:// exts
      insn.itype = m7900_exts;
      RAZOPER = INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    // 187 - EXTension Zero
    // extz A
    // Operation data length: 16 bits
    // [34]
    case 0x34:// extz
      insn.itype = m7900_extz;
      RAZOPER = INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

//********************************************************IN
    case 0xC3:// inx (IMP)
      insn.itype = m7900_inx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xD3:// iny (IMP)
      insn.itype = m7900_iny;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

//************************************************
    case 0x24:// neg
      insn.itype = m7900_neg;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    case 0x74:// nop
      insn.itype = m7900_nop;
      break;

//*********************************************************PUSH

    case 0x85:// pha
      insn.itype = m7900_pha;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0x83:// phd
      insn.itype = m7900_phd;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xA5:// php
      insn.itype = m7900_php;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xC5:// phx
      insn.itype = m7900_phx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xE5:// phy
      insn.itype = m7900_phy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0x95:// pla
      insn.itype = m7900_pla;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0x93:// pld
      insn.itype = m7900_pld;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xB5:// plp
      insn.itype = m7900_plp;
      RAZOPER = INSN_PREF_W;
      break;

    case 0xD5:// plx
      insn.itype = m7900_plx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    case 0xF5:// ply
      insn.itype = m7900_ply;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

//****************************************************************
    case 0xF1:// rti
      insn.itype = m7900_rti;
      break;

    case 0x94:// rtl
      insn.itype = m7900_rtl;
      break;

    case 0x84:// rts
      insn.itype = m7900_rts;
      break;

    case 0x04:// sec
      insn.itype = m7900_sec;
      break;

    case 0x05:// sei
      insn.itype = m7900_sei;
      break;

    case 0x45:// clm
      insn.itype = m7900_clm;
      break;

    case 0x25:// sem
      insn.itype = m7900_sem;
      break;

    case 0x77://
      return Opcode_77(insn);

    case 0x61:
      return Opcode_61(insn);

    case 0x71:
      return Opcode_71(insn);

    // 102 - ADD at Byte
    // addb A, #imm
    // Operation data length: 8 bits
    // [29 imm]
    case 0x29:
      insn.itype = m7900_addb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 112 - logical AND between immediate (Byte)
    // andb A, #imm
    // Operation data length: 8 bits
    // [23 imm]
    case 0x23:
      insn.itype = m7900_andb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 123 -Branch on Bit Clear (Byte)
    // bbcb #imm dd rr (DIR)
    // Operation data length: 8 bits
    // [52 dd imm rr]
    case 0x52:
      insn.itype = m7900_bbcb;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      RAZOPER = INSN_PREF_U;
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    // 123 -Branch on Bit Clear (Byte)
    // bbcb #imm dd rr (ABS)
    // Operation data length: 8 bits
    // [57 dd imm rr]
    case 0x57:
      insn.itype = m7900_bbcb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op2, TAB_ABS, 8, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 5);
      break;

    // 125 - Branch on Bit Set (Byte)
    // bbsb #imm dd rr (DIR)
    // Operation data length: 8 bits
    // [42 dd imm rr]
    case 0x42:
      insn.itype = m7900_bbsb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 4);
      break;

    // 125 - Branch on Bit Set (Byte)
    // bbsb #imm dd rr (ABS)
    // Operation data length: 8 bits
    // [47 dd imm rr]
    case 0x47:
      insn.itype = m7900_bbsb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op2, TAB_ABS, 8, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 5);
      break;

    // 146 - Compare immediate and Branch on EQual at Byte
    // cbeqb A, #imm, rr ()
    // Operation data length: 8 bits
    // [A2 imm rr]
    case 0xA2:
      insn.itype = m7900_cbeqb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 3);
      break;

    // 146 - Compare immediate and Branch on EQual at Byte
    // cbeqb A,dd, #imm, rr (DIR)
    // Operation data length: 8 bits
    // [62 dd imm rr]
    case 0x62:// cbeqb dd,#imm,rr
      insn.itype = m7900_cbeqb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3,insn.get_next_byte(), 4);
      break;

    // 148 - Compare immediate and Branch on Not Equal at Byte
    // cbneb A, #imm, rr (DIR)
    // Operation data length: 8 bits
    // [B2 imm rr]
    case 0xB2:
      insn.itype = m7900_cbneb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), 3);
      break;

    // 148 - Compare immediate and Branch on Not Equal at Byte
    // cbneb A,dd, #imm, rr (DIR)
    // Operation data length: 8 bits
    // [72 dd imm rr]
    case 0x72:// cbneb dd,#imm,rr
      insn.itype = m7900_cbneb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op2, 8);
      Operand_Near(insn, insn.Op3,insn.get_next_byte(), 4);
      break;

    // 156 - CLeaR Memory at Byte
    // clrmb dd(DIR)
    // Operation data length: 8 bits
    // [C2 dd]
    case 0xC2:
      insn.itype = m7900_clrmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      break;

    // 156 - CLeaR Memory at Byte
    // clrmb mmll(ABS)
    // Operation data length: 8 bits
    // [C2 ll mm]
    case 0xC7:// clrmb
      insn.itype = m7900_clrmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      break;

    // 162 - CoMPare at Byte
    // cmpb A, #imm
    // Operation data length: 8 bits
    // [38 imm]
    case 0x38:
      insn.itype = m7900_cmpb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 181 - Exclusive OR immediate with accumulator at Byte
    // eorb A, #imm
    // Operation data length: 8 bits
    // [33 imm]
    case 0x33:
      insn.itype = m7900_eorb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // __________________________________________________________//

    // 208 - MOVe Memory to memory at Byte
    // movmb dd, #imm
    // Operation data length: 8 bits
    // [A9 imm dd]
    case 0xA9:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb dd, mmll
    // Operation data length: 8 bits
    // [4C imm ll mm]
    case 0x4C:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb dd, mmll, X
    // Operation data length: 8 bits
    // [4D imm ll mm]
    case 0x4D:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      Operand_Imm(insn, insn.Op1, 8);
      Operand_Registr(insn.Op3, rX);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, #imm
    // Operation data length: 8 bits
    // [B9 imm ll mm]
    case 0xB9:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Imm(insn, insn.Op2, 8);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, dd
    // Operation data length: 8 bits
    // [68 dd ll mm]
    case 0x68:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, dd
    // Operation data length: 8 bits
    // [69 dd ll mm]
    case 0x69:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, mmll
    // Operation data length: 8 bits
    // [6C ll mm ll mm]
    case 0x6C:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, dt_byte);
      break;

    // 208 - MOVe Memory to memory at Byte
    // movmb mmll, mmll
    // Operation data length: 8 bits
    // [48 dd dd]
    case 0x48:
      insn.itype = m7900_movmb;
      RAZOPER = INSN_PREF_U;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      Operand_Dir(insn, insn.Op1, TDIR_DIR, dt_byte);
      break;

    // 221 - OR immediate with Accumulator at Byte
    // orab A, #imm
    // Operation data length: 8 bits
    // [63 imm]
    case 0x63:
      insn.itype = m7900_orab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 279 - OR immediate with Accumulator at Byte
    // subb A, #imm
    // Operation data length: 8 bits
    // [39 imm]
    case 0x39:
      insn.itype = m7900_subb;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // _____________________  ADD  ____________________
    // 101 - ADd
    // add A, #imm
    // Operation data length: 16 bits or 8 bits
    // [26 imm]
    case 0x26:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 101 - ADd
    // add A, dd
    // Operation data length: 16 bits or 8 bits
    // [2A dd]
    case 0x2A:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 101 - ADd
    // add A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [2B dd]
    case 0x2B:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 101 - ADd
    // add A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [2E ll mm]
    case 0x2E:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 101 - ADd
    // add A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [2F ll mm]
    case 0x2F:
      insn.itype = m7900_add;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END ADD  ____________________
    // _____________________  CMP  ____________________
    // 161 - CoMPare
    // cmp A, #imm
    // Operation data length: 16 bits or 8 bits
    // [46 imm]
    case 0x46:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 161 - CoMPare
    // cmp A, dd
    // Operation data length: 16 bits or 8 bits
    // [4A dd]
    case 0x4A:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [4B dd]
    case 0x4B:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 161 - CoMPare
    // cmp A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [4E ll mm]
    case 0x4E:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 161 - CoMPare
    // cmp A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [4F ll mm]
    case 0x4F:
      insn.itype = m7900_cmp;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END CMP  ____________________

    // _____________________  EOR  ____________________
    // 180 - Exclusive OR memory with accumulator
    // eor A, #imm
    // Operation data length: 16 bits or 8 bits
    // [76 imm]
    case 0x76:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, dd
    // Operation data length: 16 bits or 8 bits
    // [7A dd]
    case 0x7A:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [7B dd]
    case 0x7B:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [7E ll mm]
    case 0x7E:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 180 - Exclusive OR memory with accumulator
    // eor A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [7F ll mm]
    case 0x7F:
      insn.itype = m7900_eor;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END EOR  ____________________

    // _____________________  LDA  ____________________
    // 195 - LoaD Accumulator from memory
    // lda A, #imm
    // Operation data length: 16 bits or 8 bits
    // [16 imm]
    case 0x16:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, dd
    // Operation data length: 16 bits or 8 bits
    // [1A dd]
    case 0x1A:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [1B dd]
    case 0x1B:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [18 dd]
    case 0x18:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rB);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [19 dd]
    case 0x19:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [1E ll mm]
    case 0x1E:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [1F ll mm]
    case 0x1F:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [1C ll mm hh]
    case 0x1C:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 195 - LoaD Accumulator from memory
    // lda A, hhmmll, X (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [1D ll mm hh]
    case 0x1D:
      insn.itype = m7900_lda;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END LDA  ____________________

    // _____________________  LDAB  ____________________
    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, #imm
    // Operation data length: 16 bits
    // [28 imm]
    case 0x28:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, 8);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, dd
    // Operation data length: 16 bits
    // [0A dd]
    case 0x0A:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits
    // [0B dd]
    case 0x0B:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X);
      Operand_Registr(insn.Op3, rX);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [08 dd]
    case 0x08:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits
    // [09 dd]
    case 0x09:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [0E ll mm]
    case 0x0E:
      insn.itype = m7900_ldab;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [0F ll mm]
    case 0x0F:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [0C ll mm hh]
    case 0x0C:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_byte);
      break;

    // 196 - LoaD Accumulator from memory at Byte
    // ldab A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [0D ll mm hh]
    case 0x0D:
      insn.itype = m7900_ldab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END LDAB  ____________________

    // _____________________  STA  ____________________

    // 271 - STore Accumulator in memory
    // sta A, dd
    // Operation data length: 16 bits or 8 bits
    // [DA dd]
    case 0xDA:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [DB dd]
    case 0xDB:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 271 - STore Accumulator in memory
    // sta A, (dd), Y  ()
    // Operation data length: 16 bits or 8 bits
    // [D8 dd]
    case 0xD8:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 16 bits or 8 bits
    // [D9 dd]
    case 0xD9:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 271 - STore Accumulator in memory
    // sta A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [DE ll mm]
    case 0xDE:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [DF ll mm]
    case 0xDF:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 271 - STore Accumulator in memory
    // sta A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [DC ll mm hh]
    case 0xDC:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, SetTypeDataM);
      break;

    // 271 - STore Accumulator in memory
    // sta A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [DD ll mm hh]
    case 0xDD:
      insn.itype = m7900_sta;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END STA  ____________________
    // _____________________  ORA  ____________________
    // 220 - OR memory with Accumulator
    // ora A, #imm
    // Operation data length: 16 bits or 8 bits
    // [56 imm]
    case 0x56:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 220 - OR memory with Accumulator
    // ora A, dd
    // Operation data length: 16 bits or 8 bits
    // [5A dd]
    case 0x5A:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [5B dd]
    case 0x5B:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 220 - OR memory with Accumulator
    // ora A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [5E ll mm]
    case 0x5E:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 220 - OR memory with Accumulator
    // ora A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [5F ll mm]
    case 0x5F:
      insn.itype = m7900_ora;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END ORA  ____________________
    // _____________________  ADDD  ____________________
    // 103 - ADd at Double-word
    // addd E, #imm
    // Operation data length: 32 bits
    // [2D imm imm imm imm]
    case 0x2D:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 103 - ADd at Double-word
    // addd E, dd
    // Operation data length: 32 bits
    // [9A dd]
    case 0x9A:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 103 - ADd at Double-word
    // addd E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32 bits
    // [9B dd]
    case 0x9B:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 103 - ADd at Double-word
    // addD E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [9E ll mm]
    case 0x9E:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 103 - ADd at Double-word
    // add A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [9F ll mm]
    case 0x9F:
      insn.itype = m7900_addd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END ADDD  ____________________

    // _____________________  LDAD  ____________________
    // 197 - LoaD Accumulator from memory at Double-word
    // addd E, #imm
    // Operation data length: 32 bits
    // [2C imm imm imm imm]
    case 0x2C:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, dd
    // Operation data length: 32 bits
    // [8A dd]
    case 0x8A:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32 bits
    // [8B dd]
    case 0x8B:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, (dd), Y  ()
    // Operation data length: 32 bits
    // [88 dd]
    case 0x88:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [89 dd]
    case 0x89:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldaD E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [8E ll mm]
    case 0x8E:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [8F ll mm]
    case 0x8F:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 16 bits or 8 bits
    // [8C ll mm hh]
    case 0x8C:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 197 - LoaD Accumulator from memory at Double-word
    // ldad A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [8D ll mm hh]
    case 0x8D:
      insn.itype = m7900_ldad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END LDAD  ____________________

    // _____________________  CMPD  ____________________

    // 163 - CoMPare at Double-word
    // cmpd E, #imm
    // Operation data length: 32 bits
    // [3C imm imm imm imm]
    case 0x3C:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, dd
    // Operation data length: 32 bits
    // [BA dd]
    case 0xBA:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32 bits
    // [BB dd]
    case 0xBB:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 163 - CoMPare at Double-word
    // cmpd E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [BE ll mm]
    case 0xBE:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 163 - CoMPare at Double-word
    // cmpd A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [BF ll mm]
    case 0xBF:
      insn.itype = m7900_cmpd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END CMPD  ____________________

    // 108 - ADD index register X and immediate
    // addx #imm
    // Operation data length: 16 bits
    // [01 imm]

    // 140 - Branch on Single bit Clear
    // bsc n, A, rr
    // Operation data length: 16 bits or 8 bits
    // [01 n+A0 rr]

    // 142 - Branch on Single bit Set
    // bss n, A, rr
    // Operation data length: 16 bits or 8 bits
    // [01 n+80 rr]

    case 0x01:
      imm = insn.get_next_byte();
      switch ( imm & 0xE0 )
      {
        case 0x0:  /*addx*/
          insn.itype = m7900_addx;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, imm);
          break;

        case 0x20: /*addy*/
          insn.itype = m7900_addy;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm & 0x1F));
          break;

        case 0x40: /*subx*/
          insn.itype = m7900_subx;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm & 0x1F));
          break;

        case 0x60: /*suby*/
          insn.itype = m7900_suby;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm & 0x1F));
          break;

        case 0x80: /*bss*/
          insn.itype = m7900_bss;
          RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm & 0x0F));
          Operand_Registr(insn.Op2, rA);
          Operand_Near(insn, insn.Op3, insn.get_next_byte(), 3);
          break;

        case 0xA0: /*bcs*/
          insn.itype = m7900_bsc;
          RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm & 0x0F));
          Operand_Registr(insn.Op2, rA);
          Operand_Near(insn, insn.Op3, insn.get_next_byte(), 3);
          break;

        case 0xC0: /*dxbne*/
          insn.itype = m7900_dxbne;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm -0xC0));
          Operand_Near(insn, insn.Op2, insn.get_next_byte(), 3);
          break;

        case 0xE0: /*dybne*/
          insn.itype = m7900_dybne;
          RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
          Operand_Imm_Spesh(insn.Op1, SetTypeDataX, (imm - 0xE0));
          Operand_Near(insn, insn.Op2, insn.get_next_byte(), 3);
          break;
      }
      break;

    // _____________________  AND  ____________________

    // 111 - logical AND
    // and A, #imm
    // Operation data length: 16 bits or 8 bits
    // [66 imm]
    case 0x66:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 111 - logical AND
    // and A, #imm
    // Operation data length: 16 bits or 8 bits
    // [6A dd]
    case 0x6A:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 111 - logical AND
    // and A, #imm
    // Operation data length: 16 bits or 8 bits
    // [6B dd]
    case 0x6B:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 111 - logical AND
    // and A, #imm
    // Operation data length: 16 bits or 8 bits
    // [6E ll mm]
    case 0x6E:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 111 - logical AND
    // and A, #imm
    // Operation data length: 16 bits or 8 bits
    // [6F ll mm]
    case 0x6F:
      insn.itype = m7900_and;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // _____________________  END AND  ____________________

    // 117 - Arithmetic Shift to Left by n bits
    // asl n A,#imm
    // Operation data length: 16 bits or 8 bits
    // [C1 imm+40]

    // 120 - Arithmetic Shift to Right by n bits
    // asr n A,#imm
    // Operation data length: 16 bits or 8 bits
    // [C1 imm+80]

    // 169 - DEcrement memory and Branch on Not Equal
    // debne dd #imm rr
    // Operation data length: 16 bits or 8 bits
    // [D1 imm+A0 dd rr]

    // 253 - n bits ROtate Left
    // rol n #imm
    // Operation data length: 16 bits or 8 bits
    // [C1 imm+A0]

    // 256 - n bits ROtate Right
    // ror n #imm
    // Operation data length: 16 bits or 8 bits
    // [C1 imm+20]

    case 0xC1:
      imm = insn.get_next_byte();
      com = imm & 0xE0;
      if ( com == 0x20 )
      {
        insn.itype = m7900_rorn;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Registr(insn.Op1, rA);
        Operand_Imm_Spesh(insn.Op2, dt_byte, (imm & 0x1F));
      }
      else if ( com == 0x40 )
      {
        insn.itype = m7900_asln;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Registr(insn.Op1, rA);
        Operand_Imm_Spesh(insn.Op2, dt_byte, (imm & 0x0F));
      }
      else if ( com == 0x60 )
      {
        insn.itype = m7900_roln;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Registr(insn.Op1, rA);
        Operand_Imm_Spesh(insn.Op2, dt_byte, (imm & 0x1F));
      }
      else if ( com == 0x80 )
      {
        insn.itype = m7900_asrn;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Registr(insn.Op1, rA);
        Operand_Imm_Spesh(insn.Op2, dt_byte, (imm & 0x1F));
      }
      else if ( com == 0xA0 )
      {
        insn.itype = m7900_debne;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Imm_Spesh(insn.Op2, dt_byte, (imm & 0x1F));
        Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
        Operand_DEBNE(insn, insn.Op3, insn.get_next_byte(), 4);
      }
      else
      {
        insn.itype = m7900_lsrn;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Registr(insn.Op1, rA);
        Operand_Imm_Spesh(insn.Op2, dt_byte, imm);
      }
      break;

    // 118 - Arithmetic Shift to Left by n bits (Double word)
    // asld n E,#imm
    // Operation data length: 32 bits
    // [D1 imm+40]

    // 169 - DEcrement memory and Branch on Not Equal
    // debne mmll #imm rr
    // Operation data length: 16 bits or 8 bits
    // [D1 imm+E0  ll mm rr]

    // 206 - Logical n bits Shift Right at Double-word
    // lsrd E #imm
    // Operation data length: 32 bits
    // [D1 imm]

    // 254 - n bits ROtate Left at Double-word
    // rold E #imm
    // Operation data length: 32 bits
    // [D1 imm+60]

    // 254 - n bits ROtate Right at Double-word
    // rord E #imm
    // Operation data length: 32 bits
    // [D1 imm+20]

    case 0xD1:
      imm = insn.get_next_byte();
      com = imm & 0xE0;
      if ( com == 0x20 )
      {
        insn.itype = m7900_rordn;
        RAZOPER = INSN_PREF_D;
        Operand_Registr(insn.Op1, rE);
        Operand_Imm_Spesh(insn.Op2, dt_dword, imm & 0x1F);
      }
      else if ( com == 0x40 )
      {
        insn.itype = m7900_asldn;
        RAZOPER = INSN_PREF_D;
        Operand_Registr(insn.Op1, rE);
        Operand_Imm_Spesh(insn.Op2, dt_dword, imm & 0x1F);
      }
      else if ( com == 0x60 )
      {
        insn.itype = m7900_roldn;
        RAZOPER = INSN_PREF_D;
        Operand_Registr(insn.Op1, rE);
        Operand_Imm_Spesh(insn.Op2, dt_dword, imm & 0x1F);
      }
      else if ( com == 0x80 )
      {
        insn.itype = m7900_asrdn;
        RAZOPER = INSN_PREF_D;
        Operand_Registr(insn.Op1, rE);
        Operand_Imm_Spesh(insn.Op2, dt_dword, imm & 0x1F);
      }
      else if ( com == 0xE0 )
      {
        insn.itype = m7900_debne;
        RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
        Operand_Imm_Spesh(insn.Op2, dt_dword, (imm & 0x1F));
        Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
        Operand_DEBNE(insn, insn.Op3, insn.get_next_byte(), 5);
      }
      else
      {
        insn.itype = m7900_lsrdn;
        RAZOPER =  32;
        Operand_Registr(insn.Op1, rE);
        Operand_Imm_Spesh(insn.Op2, dt_dword, imm);
      }
      break;

    // 126 - Branch on Carry Clear
    // bcc rr
    // Operation data length: -
    // [90 rr]

    // 138 - BRanch Always
    // bra rr
    // Operation data length: -
    // [20 rr]

    // 127 - Branch on Carry Set
    // bcs rr
    // Operation data length: -
    // [B0 rr]

    // 128 - Branch on EQual
    // beq rr
    // Operation data length: -
    // [F0 rr]

    // 129 - Branch on Greater or Equal
    // bge rr
    // Operation data length: -
    // [C0 rr]

    // 130 -
    // bgt rr
    // Operation data length: -
    // [80 rr]

    // 131 - Branch on Greater Than with Unsign
    // bgtu rr
    // Operation data length: -
    // [40 rr]

    // 132 - Branch on Less or Equal
    // ble rr
    // Operation data length: -
    // [A0 rr]

    // 133 - Branch on Less Equal with Unsign
    // bleu rr
    // Operation data length: -
    // [60 rr]

    // 134 - Branch on Less Than
    // blt rr
    // Operation data length: -
    // [E0 rr]

    // 135 - Branch on result MInus
    // bmi rr
    // Operation data length: -
    // [30 rr]

    // 136 - Branch on Not Equal
    // bne rr
    // Operation data length: -
    // [D0 rr]

    // 137 - Branch on result PLus
    // bpl rr
    // Operation data length: -
    // [10 rr]

    // 143 - Branch on oVerflow Clear
    // bvc rr
    // Operation data length: -
    // [50 rr]

    // 144 - Branch on oVerflow Set
    // bvs rr
    // Operation data length: -
    // [70 rr]

    case 0x10:
    case 0x20:
    case 0x30:
    case 0x40:
    case 0x50:
    case 0x60:
    case 0x70:
    case 0x80:
    case 0x90:
    case 0xA0:
    case 0xB0:
    case 0xC0:
    case 0xD0:
    case 0xE0:
    case 0xF0:
      RAZOPER = 0;
      Branch(insn, insn.Op1, nib);
      break;

    case 0xA7:
      insn.itype = m7900_bral;
      RAZOPER = 0;
      Bral(insn, insn.Op1, 3);
      break;

    // _____________________  CBEQ  ____________________

    // 145 - Compare immediate and Branch on EQual
    // cbeq A, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [A6 imm rr]
    case 0xA6:
      insn.itype = m7900_cbeq;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 3 : 4);
      break;
    // _____________________ END CBEQ  ____________________
    // _____________________  CBNE  ____________________
    // 147 - Compare immediate and Branch on Not Equal
    // cbne A, #imm, rr
    // Operation data length: 16 bits or 8 bits
    // [B6 imm rr]
    case 0xB6:
      insn.itype = m7900_cbne;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Near(insn, insn.Op3, insn.get_next_byte(), getFlag_M ? 3 : 4);
      break;
    // _____________________ END CBNE  ____________________

    // _____________________  CLP  ____________________
    // 153 - CLear Processor status
    // clp #imm
    // Operation data -
    // [98 imm]
    case 0x98:// clp
      insn.itype = m7900_clp;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END CLP  ____________________

    // _____________________  CLPM  ____________________
    // 155 - CLeaR Memory
    // clpm dd
    // Operation data - 16 bits or 8 bits
    // [D2 dd]
    case 0xD2:// clrm
      insn.itype = m7900_clrm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    // 155 - CLeaR Memory
    // clpm mmll
    // Operation data - 16 bits or 8 bits
    // [D7 ll mm]
    case 0xD7:// clrm
      insn.itype = m7900_clrm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;
    // _____________________ END CLPM  ____________________

    // _____________________  CLPX  ____________________
    // 157 - CLeaR index register X
    // clpx
    // Operation data - 16 bits or 8 bits
    // [E4]
    case 0xE4:
      insn.itype = m7900_clrx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;

    // 158 - CLeaR index register Y
    // clpy
    // Operation data - 16 bits or 8 bits
    // [F4]
    case 0xF4:
      insn.itype = m7900_clry;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      break;
    // _____________________  END CLPX CLPY ____________________

    // _____________________  CPX  ____________________
    // 167 - ComPare memory and index register X
    // cpx #imm
    // Operation data - 16 bits or 8 bits
    // [E6 imm]
    case 0xE6:// cpx
      insn.itype = m7900_cpx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_X ? 8 : 16);
      break;

    // 167 - ComPare memory and index register X
    // cpx dd
    // Operation data - 16 bits or 8 bits
    // [22 dd]
    case 0x22:// cpx
      insn.itype = m7900_cpx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;
    // _____________________  END CPX  ____________________

    // _____________________  CPY  ____________________
    // 168 - ComPare memory and index register Y
    // cpy #imm
    // Operation data - 16 bits or 8 bits
    // [F6 imm]
    case 0xF6:// cpy
      insn.itype = m7900_cpy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_X ? 8 : 16);
      break;

    // 168 - ComPare memory and index register Y
    // cpy dd
    // Operation data - 16 bits or 8 bits
    // [32 dd]
    case 0x32:// cpy
      insn.itype = m7900_cpy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;
    // _____________________  END CPY  ____________________
    // _____________________  DEC  ____________________
    // 170 - DECrement by one
    // dec A
    // Operation data - 16 bits or 8 bits
    // [B3]
    case 0xB3:
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    case 0x92:
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    case 0x97:
      insn.itype = m7900_dec;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    // _____________________  END DEC  ____________________

    // _____________________  INC  ____________________
    // 189 - INCrement by one
    // inc A
    // Operation data - 16 bits or 8 bits
    // [A3]
    case 0xA3:
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;

    case 0x82:
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    case 0x87:
      insn.itype = m7900_inc;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;
    // _____________________  END INC  ____________________

    // _____________________  LDX  ____________________
    // 200 - load
    // ldx #imm
    // Operation data - 16 bits or 8 bits
    // [C6]
    case 0xC6:
      insn.itype = m7900_ldx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_X ? 8 : 16);
      break;

    case 0x02:
      insn.itype = m7900_ldx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;

    case 0x07:
      insn.itype = m7900_ldx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataX);
      break;
    // _____________________  END LDX  ____________________
    // _____________________   LDXB  ____________________

    // 201 - LoaD index register X from memory at Byte
    // ldxb #imm
    // Operation data - 16 bits
    // [27]
    case 0x27:
      insn.itype = m7900_ldxb;
      RAZOPER = INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END LDXB  ____________________

    // _____________________  LDY  ____________________
    // 202 - LoaD index register Y from memory
    // ldy #imm
    // Operation data - 16 bits or 8 bits
    // [D6]
    case 0xD6:
      insn.itype = m7900_ldy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op1, getFlag_X ? 8 : 16);
      break;

    case 0x12:
      insn.itype = m7900_ldy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;

    case 0x17:
      insn.itype = m7900_ldy;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16);
      break;
    // _____________________  END LDY  ____________________
    // _____________________   LDYB  ____________________
    // 202 - LoaD index register Y from memory at Byte
    // ldyb #imm
    // Operation data - 16 bits
    // [37]
    case 0x37:
      insn.itype = m7900_ldyb;
      RAZOPER = INSN_PREF_U;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END LDX  ____________________
    // _____________________  JMP  ____________________
    // 192 - JUMP
    // jmp mmll
    // Operation data -
    // [9C ll mm]
    case 0x9C:
      {
        insn.itype = m7900_jmp;
        insn.Op1.type = o_near;
        uint32 high = insn.get_next_byte();
        uint32 low  = insn.get_next_byte();
        uint32 addr = high | (low<<8);
        addr = uint32(addr | (getPG<<16));
        insn.Op1.addr = addr;
      }
      break;

    // [AC ll mm hh]
    case 0xAC:// jmpl hhmmll
      {
        insn.itype = m7900_jmpl;
        insn.Op1.type = o_near;
        uint32 ll = insn.get_next_byte();
        uint32 mm  = insn.get_next_byte();
        uint32 hh  = insn.get_next_byte();
        uint32 addr = (ll | (hh<<16)) | (mm<<8);
        insn.Op1.addr = addr;
      }
      break;

    case 0xBC:// jmpl mmll((ABS,X))
      insn.itype = m7900_jmp;
      Operand_AB(insn, insn.Op1, TAB_INDIRECTED_ABS_X, 16, dt_word);
      break;
    // _____________________  END JMP  ____________________

    // _____________________  JSR  ____________________

    case 0x9D:// jsr mmll
      insn.itype = m7900_jsr;
      Jsr_16(insn, insn.Op1, getPG);
      break;

    case 0xAD:// jsrl hhmmll
      insn.itype = m7900_jsrl;
      Jsr_24(insn, insn.Op1);
      break;

    case 0xBD:// jsr mmll((ABS,X))
      insn.itype = m7900_jsr;
      Operand_AB(insn, insn.Op1, TAB_INDIRECTED_ABS_X, 16, dt_word);
      break;
    // _____________________  END JSR  ____________________

    // _____________________   LSR  ____________________
    // 204 - Logical Shift Right
    // lsr A
    // Operation data - 16 bits or 8 bits
    // [43]
    case 0x43:
      insn.itype = m7900_lsr;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;
    // _____________________  END LSR  ____________________
    // _____________________   ROL  ____________________
    // 254 - ROtate one bit Left
    // rol A
    // Operation data - 16 bits or 8 bits
    // [13]
    case 0x13:
      insn.itype = m7900_rol;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;
    // _____________________  END ROL  ____________________

    // _____________________  ROR  ____________________
    // 255 - ROtate one bit Right
    // ror A
    // Operation data - 16 bits or 8 bits
    // [53]
    case 0x53:// ror
      insn.itype = m7900_ror;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      break;
    // _____________________  END ROR  ____________________

    // _____________________  MOVM  ____________________

    case 0x86:// movm dd,#imm(DIR, IMM)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    case 0x5C:// movm dd, mmll(DIR, ABS)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;

    case 0x5D:// movm dd, mmll(DIR, ABS,X)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    case 0x96:// movm dd, mmll(ABS, IMM)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    case 0x78:// movm dd, mmll(ABS, DIR)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_M ? 8 : 16,SetTypeDataM);
      break;

    case 0x79:// movm dd, mmll(ABS, DIR)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_AB(insn, insn.Op1, TAB_ABS, getFlag_M ? 8 : 16, SetTypeDataM);
      break;

    case 0x7C:// movm mmll1,mmll2(ABS, ABS)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataM);
      break;

    case 0x58:// movm dd1, dd2(DIR, DIR)
      insn.itype = m7900_movm;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataM);
      break;
    // _____________________  END MOVM  ____________________

    // _____________________  PSH  ____________________
    // 246 - PuSH
    // psh #imm
    // Operation data - 16 bits or 8 bits
    // [A8 imm]
    case 0xA8:
      insn.itype = m7900_psh;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END PSH  ____________________

    // _____________________  PUL  ____________________
    // 246 - PuLl
    // pul #imm
    // Operation data - 16 bits or 8 bits
    // [67 imm]
    case 0x67:
      insn.itype = m7900_pul;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END PUL  ____________________
    // _____________________  SEP  ____________________
    case 0x99:
      insn.itype = m7900_sep;
      Operand_Imm(insn, insn.Op1, 8);
      break;
    // _____________________  END SEP  ____________________

    // _____________________  STAB  ____________________
    // 272 - STore Accumulator in memory at Byte
    // stab A, dd
    // Operation data length: 8 bits
    // [CA dd]
    case 0xCA:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length:  8 bits
    // [CB dd]
    case 0xCB:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, (dd), Y  ()
    // Operation data length:  8 bits
    // [C8 dd]
    case 0xC8:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_byte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length:  8 bits
    // [C9 dd]
    case 0xC9:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 8 bits
    // [CE ll mm]
    case 0xCE:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 8 bits
    // [CF ll mm]
    case 0xCF:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length:  8 bits
    // [CC ll mm hh]
    case 0xCC:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_byte);
      break;

    // 272 - STore Accumulator in memory at Byte
    // stab A, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length:  8 bits
    // [CD ll mm hh]
    case 0xCD:
      insn.itype = m7900_stab;
      RAZOPER = INSN_PREF_U;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_byte);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END STAB  ____________________

    // _____________________  STAD  ____________________
    // 273 - STore Accumulator in memory at Double-word
    // stad E, dd
    // Operation data length: 32 bits
    // [EA dd]
    case 0xEA:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32 bits
    // [EB dd]
    case 0xEB:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 273 - STore Accumulator in memory at  Double-word
    // stad E, (dd), Y  ()
    // Operation data length: 32 bits
    // [E8 dd]
    case 0xE8:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_INDIRECT_DIR, dt_dword);
      Operand_Registr(insn.Op3, rY);
      break;

    // 273 - STore Accumulator in memory at  Double-word
    // stad E, L(dd),Y (Direct indirect long addressing mode L(DIR))
    // Operation data length: 32 bits
    // [E9 dd]
    case 0xE9:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_L_INDIRECT_DIR, dt_tbyte);
      Operand_Registr(insn.Op3, rY);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [EE ll mm]
    case 0xEE:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [EF ll mm]
    case 0xEF:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, hhmmll, Y (Absolute long addressing mode(ABL))
    // Operation data length: 32 bits
    // [EC ll mm hh]
    case 0xEC:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL, 24, dt_dword);
      break;

    // 273 - STore Accumulator in memory at Double-word
    // stad E, hhmmll, Y (Absolute long indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [ED ll mm hh]
    case 0xED:
      insn.itype = m7900_stad;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABL_X, 24, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END STAD  ____________________
    // _____________________  STX  ____________________
    // 275 - STore index register X in memory
    // stx dd
    // Operation data length: 16 bits or 8 bits
    // [E2 dd]
    case 0xE2:// stx (DIR)
      insn.itype = m7900_stx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;

    // 275 - STore index register X in memory
    // stx mmll
    // Operation data length: 16 bits or 8 bits
    // [E7 ll mm]
    case 0xE7:// stx ABS
      insn.itype = m7900_stx;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataX);
      break;
    // _____________________  END STX  ____________________
    // _____________________  STY  ____________________
    // 276 - STore index register Y in memory
    // sty dd
    // Operation data length: 16 bits or 8 bits
    // [F2 dd]
    case 0xF2:// sty (DIR)
      insn.itype = m7900_sty;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_Dir(insn, insn.Op1, TDIR_DIR, SetTypeDataX);
      break;

    case 0xF7:// sty ABS
      insn.itype = m7900_sty;
      RAZOPER = getFlag_X ? INSN_PREF_B : INSN_PREF_W;
      Operand_AB(insn, insn.Op1, TAB_ABS, 16, SetTypeDataX);
      break;
    // _____________________END  STY  ____________________

    // _____________________  SUB  ____________________
    // 278 - SUBtract
    // sub A, #imm
    // Operation data length: 16 bits or 8 bits
    // [36 #imm]
    case 0x36:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Imm(insn, insn.Op2, getFlag_M ? 8 : 16);
      break;

    // 278 - SUBtract
    // sub A, dd
    // Operation data length: 16 bits or 8 bits
    // [3A dd]
    case 0x3A:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub A, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 16 bits or 8 bits
    // [3B dd]
    case 0x3B:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;

    // 278 - SUBtract
    // sub A, mmll (Absolute addressing mode(ABS))
    // Operation data length: 16 bits or 8 bits
    // [3E ll mm]
    case 0x3E:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, SetTypeDataM);
      break;

    // 278 - SUBtract
    // sub A, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 16 bits or 8 bits
    // [3F ll mm]
    case 0x3F:
      insn.itype = m7900_sub;
      RAZOPER = getFlag_M ? INSN_PREF_B : INSN_PREF_W;
      Operand_Registr(insn.Op1, rA);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, SetTypeDataM);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END SUB  ____________________
    // _____________________  SUBD  ____________________
    // 280 - SUBtract at Double-word
    // subd E, #imm
    // Operation data length: 32 bits
    // [3D #imm]
    case 0x3D:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Imm(insn, insn.Op2, 32);
      break;

    // 280 - SUBtract at Double-word
    // subd E, dd
    // Operation data length: 32 bits
    // [AA dd]
    case 0xAA:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR, dt_dword);
      break;

    // 280 - SUBtract at Double-word
    // subd E, dd, X  (Direct index X addressing DIR,X)
    // Operation data length: 32 bits
    // [AB dd]
    case 0xAB:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_Dir(insn, insn.Op2, TDIR_DIR_X, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;

    // 280 - SUBtract at Double-word
    // subd E, mmll (Absolute addressing mode(ABS))
    // Operation data length: 32 bits
    // [AE ll mm]
    case 0xAE:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS, 16, dt_dword);
      break;

    // 280 - SUBtract at Double-word
    // subd E, mmll, X (Absolute indexed X addressing mode(ABS,X))
    // Operation data length: 32 bits
    // [AF ll mm]
    case 0xAF:
      insn.itype = m7900_subd;
      RAZOPER = INSN_PREF_D;
      Operand_Registr(insn.Op1, rE);
      Operand_AB(insn, insn.Op2, TAB_ABS_X, 16, dt_dword);
      Operand_Registr(insn.Op3, rX);
      break;
    // _____________________  END SUBD  ____________________

    default:
      {
        uchar cd = code & 0xF8;
        if ( cd == 0xF8 )
        {
          // 141 - Branch to SubRoutine
          // bsr rr
          // Operation data length: -
          // [11111 B10-b0]

          insn.itype = m7900_bsr;
          uint32 low  = insn.get_next_byte();
          uint32 addr = low | (code<<8);
          addr&=0x000007FF;
          if ( addr & 0x400 )
            addr |= 0xfffff800;
          Operand_BSR(insn, insn.Op1, addr, 2);
        }
        else
        {
          // msg("ana: %a: bad optype %d\n", insn.ip, code);
          return 0;
        }
      }
      break;
  }
  return insn.size;
}
