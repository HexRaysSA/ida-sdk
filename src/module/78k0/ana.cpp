/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

//----------------------------------------------------------------------
inline uint32 Get_Data_16bits(insn_t &insn)
{
  uint32 low  = insn.get_next_byte();
  uint32 high = insn.get_next_byte();
  return low | (high << 8);
}

//----------------------------------------------------------------------
inline void Operand_Sfr(insn_t &insn, op_t &x)
{
  x.type = o_mem;
  x.dtype = dt_byte;
  x.offb = (uchar)insn.size;
  x.value =
    x.addr = 0xFF00 + insn.get_next_byte();
}

//----------------------------------------------------------------------
inline void Operand_Registr(op_t &x, int rReg, uchar Flags)
{
  x.type = o_reg;
  x.reg = (uint16)rReg;
  x.FormOut = Flags;
}

//----------------------------------------------------------------------
inline void Operand_Bit(op_t &x, uchar TypeOrd, int Bit)
{
  x.type = o_bit;
  x.FormOut = TypeOrd;
  x.value  = Bit & 7;
  x.offb = 0;
}

//----------------------------------------------------------------------
// convert short address to full address
inline uint32 GetFullAddress(uchar addr)
{
  if ( addr < 0x20 )
    return 0xFF00 + addr;
  return 0xFE00 + addr;
}

//----------------------------------------------------------------------
inline void Operand_Saddr(op_t &x, uchar addr, const insn_t &insn)
{
  x.type = o_mem;
  x.dtype = dt_byte;
  x.offb = uchar(insn.size - 1);
  x.addr = GetFullAddress(addr);
  x.value = x.addr;
}

//----------------------------------------------------------------------
inline void Operand_Saddr1(insn_t &insn, op_t &x)
{
  Operand_Saddr(x, insn.get_next_byte(), insn);
}

//----------------------------------------------------------------------
inline void Operand_SaddrSP(insn_t &insn, op_t &x)
{
  uchar bt = insn.get_next_byte();
  if ( bt == 0x1C )
  {
    Operand_Registr(x, rSP, 0);
  }
  else
  {
    Operand_Saddr(x, bt, insn);
    x.dtype = dt_word;
  }
}

//----------------------------------------------------------------------
inline void Operand_SaddrPSW(insn_t &insn, op_t &x)
{
  uchar bt = insn.get_next_byte();
  if ( bt == 0x1E )
    Operand_Registr(x, rPSW, 0);
  else
    Operand_Saddr(x, bt, insn);
}

//----------------------------------------------------------------------
inline void Operand_SA_Bit(insn_t &insn, op_t &x, uchar Bit)
{
  uchar bt;
  x.offb = (uchar)insn.size;
  x.type = o_bit;
  x.dtype = dt_byte;
  bt = insn.get_next_byte();
  if ( bt == 0x1E )
  {
    x.FormOut = FORM_OUT_PSW;
  }
  else
  {
    x.addr = GetFullAddress(bt);
    x.FormOut = FORM_OUT_S_ADDR;
  }
  x.value = Bit & 7;
}

//----------------------------------------------------------------------
inline void Operand_SFR_Bit(insn_t &insn, op_t &x, uchar Bit)
{
  x.offb = (uchar)insn.size;
  x.addr = 0xFF00 + insn.get_next_byte();
  x.type = o_bit;
  x.FormOut = FORM_OUT_SFR;
  x.value = Bit & 7;
}

//----------------------------------------------------------------------
inline void Operand_Data_8bits(op_t &x, uchar Data)
{
  x.type  = o_imm;
  x.addr  = Data;
  x.value = Data;
  x.dtype = dt_byte;
}

//----------------------------------------------------------------------
inline void Operand_Data_8bitsI(insn_t &insn, op_t &x)
{
  x.offb = (uchar)insn.size;
  Operand_Data_8bits(x, insn.get_next_byte());
}

//----------------------------------------------------------------------
inline void Operand_Data_16bitsI(insn_t &insn, op_t &x)
{
  x.type  = o_imm;
  x.dtype = dt_word;
  x.offb  = (uchar)insn.size;
  x.value = Get_Data_16bits(insn);
  x.addr  = x.value;
}

//----------------------------------------------------------------------
inline void Operand_Addr16(op_t &x, uint32 Res, char Target_data_type)
{
  x.type    = o_mem;
  x.value   = Res;
  x.addr    = Res;
  x.dtype   = Target_data_type;
  x.FormOut = FORM_OUT_VSK;
}

//----------------------------------------------------------------------
inline void Operand_Addr16I(insn_t &insn, op_t &x, char Target_data_type)
{
  x.offb = (uchar)insn.size;
  Operand_Addr16(x, Get_Data_16bits(insn),Target_data_type);
}

//----------------------------------------------------------------------
//  [HL+XXX]
inline void Operand_HL_OffI(insn_t &insn, op_t &x)
{
  Operand_Registr(x, rHL, FORM_OUT_SKOBA | FORM_OUT_PLUS | FORM_OUT_DISP);
  x.offb = (uchar)insn.size;
  x.addr = x.value = insn.get_next_byte();
}

//----------------------------------------------------------------------
//  [HL+Reg]
inline void Operand_HL_OffReg(op_t &x, int rReg)
{
  Operand_Registr(x, rHL, FORM_OUT_SKOBA | FORM_OUT_PLUS | FORM_OUT_REG);
  x.SecondReg = (uchar)rReg;
}

//----------------------------------------------------------------------
inline void Operand_NearByteI(insn_t &insn, op_t &x)
{
  x.type = o_near;
  x.offb = (uchar)insn.size;
  x.addr = insn.ip + (signed char)insn.get_next_byte();
  x.addr += insn.size;
  x.value = x.addr;
}

//----------------------------------------------------------------------
static const uchar icode[16] =
{
  NEC_78K_0_add,  NEC_78K_0_sub, NEC_78K_0_addc,
  NEC_78K_0_subc, NEC_78K_0_cmp, NEC_78K_0_and,
  NEC_78K_0_or,   NEC_78K_0_xor, NEC_78K_0_xch
};

//----------------------------------------------------------------------
static int Opcode_61(insn_t &insn)
{
  uchar code = insn.get_next_byte();
  uchar nib  = (code >> 4) & 0xF;
  uchar cd = code & 0xF;

  // sel RBx
  // 11R1 R000
  if ( (code & 0xD7) == 0xD0 )
  {
    insn.itype = NEC_78K_0_sel;
    Operand_Registr(insn.Op1,
                    (rRB0 + ((code >>4) & 0x2)) | ((code>>3) & 0x1),
                    0);
    return insn.size;
  }
  if ( (code & 0x80) == 0 )
  {
    // add  A, r      ( 0000 1RRR )
    // add  r, A      ( 0000 0RRR )
    // sub  A, r      ( 0001 1RRR )
    // sub  r, A      ( 0001 0RRR )
    // addc A, r      ( 0010 1RRR )
    // addc r, A      ( 0010 0RRR )
    // subc A, r      ( 0011 1RRR )
    // subc r, A      ( 0011 0RRR )
    // cmp  A, r      ( 0100 1RRR )
    // cmp  r, A      ( 0100 0RRR )
    // and  A, r      ( 0101 1RRR )
    // and  r, A      ( 0101 0RRR )
    // or   A, r      ( 0110 1RRR )
    // or   r, A      ( 0110 0RRR )
    // xor  A, r      ( 0111 1RRR )
    // xor  r, A      ( 0111 0RRR )
    insn.itype = icode[nib];
    if ( code & 0x8 )
    {
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, code & 0x7, 0);
    }
    else
    {
      Operand_Registr(insn.Op1, code & 0x7, 0);
      Operand_Registr(insn.Op2, rA, 0);
    }
    return insn.size;
  }

  switch ( code )
  {
    // adjba                ( 0110 0001 1000 0000 )
    case 0x80:
      insn.itype = NEC_78K_0_adjba;
      break;
    // adjbs                ( 0110 0001 1000 0000 )
    case 0x90:
      insn.itype = NEC_78K_0_adjbs;
      break;
    default:
      switch ( cd )
      {
        // mov1 A.bit, CY
        case 0x9:
          insn.itype = NEC_78K_0_mov1;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          Operand_Registr(insn.Op2, bCY, 0);
          break;

        case 0xA:
          insn.itype = NEC_78K_0_set1;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          break;

        case 0xB:
          insn.itype = NEC_78K_0_clr1;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          break;

        // mov1 CY, A.bit
        case 0xC:
          insn.itype = NEC_78K_0_mov1;
          Operand_Registr(insn.Op1, bCY, 0);
          Operand_Bit(insn.Op2, FORM_OUT_A, nib);
          break;
        case 0xD:
          insn.itype = NEC_78K_0_and1;
          Operand_Registr(insn.Op1, bCY, 0);
          Operand_Bit(insn.Op2, FORM_OUT_A, nib);
          break;
        case 0xE:
          insn.itype = NEC_78K_0_or1;
          Operand_Registr(insn.Op1, bCY, 0);
          Operand_Bit(insn.Op2, FORM_OUT_A, nib);
          break;
        case 0xF:
          insn.itype = NEC_78K_0_xor1;
          Operand_Registr(insn.Op1, bCY, 0);
          Operand_Bit(insn.Op2, FORM_OUT_A, nib);
          break;
        default:
          return 0;
      }
  }
  return insn.size;
}

//----------------------------------------------------------------------
static int Opcode_71(insn_t &insn)
{
  uchar code = insn.get_next_byte();
  uchar nib  = code >> 4;
  // analyze the high bit by 1
  switch ( code & 0x8F )
  {
    // mov1 [HL].bit, CY
    case 0x81:
      insn.itype = NEC_78K_0_mov1;
      Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
      Operand_Registr(insn.Op2, bCY, 0);
      break;
    // set1 [HL].bit
    case 0x82:
      insn.itype = NEC_78K_0_set1;
      Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
      break;
    // clr1 [HL].bit
    case 0x83:
      insn.itype = NEC_78K_0_clr1;
      Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
      break;
    // mov1 CY,[HL].bit
    case 0x84:
      insn.itype = NEC_78K_0_mov1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_Bit(insn.Op2, FORM_OUT_HL, nib);
      break;
    // and1 CY,[HL].bit
    case 0x85:
      insn.itype = NEC_78K_0_and1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_Bit(insn.Op2, FORM_OUT_HL, nib);
      break;
    // or1 CY,[HL].bit
    case 0x86:
      insn.itype = NEC_78K_0_or1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_Bit(insn.Op2, FORM_OUT_HL, nib);
      break;
    // xor1 CY,[HL].bit
    case 0x87:
      insn.itype = NEC_78K_0_xor1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_Bit(insn.Op2, FORM_OUT_HL, nib);
      break;

    // mov1 CY, A.bit
    case 0x8C:
      insn.itype = NEC_78K_0_mov1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_Bit(insn.Op2, FORM_OUT_A, nib);
      break;

    case 0x0:
      switch ( nib & 7 )
      {
        case 0: insn.itype = NEC_78K_0_STOP; break;
        case 1: insn.itype = NEC_78K_0_HALT; break;
        default: return 0;
      }
      break;
    // mov1 PSW.bit, CY
    // mov1 saddr.bit, CY
    case 0x1:
      insn.itype = NEC_78K_0_mov1;
      Operand_SA_Bit(insn, insn.Op1, nib);
      Operand_Registr(insn.Op2, bCY, 0);
      break;
    // mov1 CY, saddr.bit
    // mov1 CY, PSW.bit
    case 0x4:
      insn.itype = NEC_78K_0_mov1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_SA_Bit(insn, insn.Op2, nib);
      break;
    // and1 CY, saddr.bit
    // and1 CY, PSW.bit
    case 0x5:
      insn.itype = NEC_78K_0_and1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_SA_Bit(insn, insn.Op2, nib);
      break;
    // or1 CY, addr.bit
    // or1 CY, PSW.bit
    case 0x6:
      insn.itype = NEC_78K_0_or1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_SA_Bit(insn, insn.Op2, nib);
      break;
    // xor1 CY, addr.bit
    // xor1 CY, PSW.bit
    case 0x7:
      insn.itype = NEC_78K_0_xor1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_SA_Bit(insn, insn.Op2, nib);
      break;
//?????
//  case 0x8:
//    insn.itype = NEC_78K_0_EI;
//    insn.get_next_byte();
//    break;

    // mov1 sfr.bit, CY
    case 0x9:
      insn.itype = NEC_78K_0_mov1;
      Operand_SFR_Bit(insn, insn.Op1, nib);
      Operand_Registr(insn.Op2, bCY, 0);
      break;
    // set1 sfr.bit
    case 0xA:
      insn.itype = NEC_78K_0_set1;
      Operand_SFR_Bit(insn, insn.Op1, nib);
      break;
    // clr1 sfr.bit
    case 0xB:
      insn.itype = NEC_78K_0_clr1;
      Operand_SFR_Bit(insn, insn.Op1, nib);
      break;

    // and1 CY, sfr.bit
    case 0xD:
      insn.itype = NEC_78K_0_and1;
      Operand_Registr(insn.Op1, bCY, 0);
      Operand_SFR_Bit(insn, insn.Op2, nib);
      break;
    // bad instruction
    default:
      return 0;
  }
  return insn.size;
}
//----------------------------------------------------------------------
static int Opcode_31(insn_t &insn)
{
  uchar code = insn.get_next_byte();
  uchar nib  = (code >> 4) & 0xF;
  switch ( code )
  {
    case 0x0B:// add  A,[HL+B]      ( 0000 1011 )
    case 0x1B:// sub  A,[HL+B]      ( 0001 1011 )
    case 0x2B:// addc A,[HL+B]      ( 0010 1011 )
    case 0x3B:// subc A,[HL+B]      ( 0011 1011 )
    case 0x4B:// cmp  A,[HL+B]      ( 0100 1011 )
    case 0x5B:// and  A,[HL+B]      ( 0101 1011 )
    case 0x6B:// or   A,[HL+B]      ( 0110 1011 )
    case 0x7B:// xor  A,[HL+B]      ( 0111 1011 )
    case 0x8B:// xch  A,[HL+B]      ( 1000 1011 )
      insn.itype = icode[nib];
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffReg(insn.Op2, rB);
      break;

    case 0x0A:// add  A,[HL+C]      ( 0000 1010 )
    case 0x1A:// sub  A,[HL+C]      ( 0001 1010 )
    case 0x2A:// addc A,[HL+C]      ( 0010 1010 )
    case 0x3A:// subc A,[HL+C]      ( 0011 1010 )
    case 0x4A:// cmp  A,[HL+C]      ( 0100 1010 )
    case 0x5A:// and  A,[HL+C]      ( 0101 1010 )
    case 0x6A:// or   A,[HL+C]      ( 0110 1010 )
    case 0x7A:// xor  A,[HL+C]      ( 0111 1010 )
    case 0x8A:// xch  A,[HL+C]      ( 1000 1010 )
      insn.itype = icode[nib];
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffReg(insn.Op2, rC);
      break;

    case 0x98:// br AX           (0011 0001 1001 1000)
      insn.itype = NEC_78K_0_br;
      Operand_Registr(insn.Op1, rAX, 0);
      break;

    case 0x88:// mulu X          ( 0011 0001 1000 1000)
      insn.itype = NEC_78K_0_mulu;
      Operand_Registr(insn.Op1, rX, 0);
      break;

    case 0x82:// divuw X          ( 0011 0001 1000 0010)
      insn.itype = NEC_78K_0_divuw;
      Operand_Registr(insn.Op1, rC, 0);
      break;

    case 0x90:// ror4 [HL]          ( 0011 0001 1001 0000)
      insn.itype = NEC_78K_0_ror4;
      Operand_Registr(insn.Op1, rHL, FORM_OUT_SKOBA);
      break;

    case 0x80:// rol4 [HL]          ( 0011 0001 1000 0000)
      insn.itype = NEC_78K_0_rol4;
      Operand_Registr(insn.Op1, rHL, FORM_OUT_SKOBA);
      break;

    default:
      switch ( code & 0x8F )
      {
        // sfr.bit, $addr16
        // A.bit, $addr16
        // PSW.bit,$addr16
        // 0xxx 0001
        case 0x1:
          insn.itype = NEC_78K_0_btclr;
          Operand_SA_Bit(insn, insn.Op1, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        // 0xxx 0011
        case 0x3:
          insn.itype = NEC_78K_0_bf;
          Operand_SA_Bit(insn, insn.Op1, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        // 0xxx 0101
        case 0x5:
          insn.itype = NEC_78K_0_btclr;
          Operand_SFR_Bit(insn, insn.Op1, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;
        // 0xxx 0110
        case 0x6:
          insn.itype = NEC_78K_0_bt;
          Operand_SFR_Bit(insn, insn.Op1, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;
        // 0xxx 0111
        case 0x7:
          insn.itype = NEC_78K_0_bf;
          Operand_SFR_Bit(insn, insn.Op1, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        // 0xxx 1101
        case 0xD:
          insn.itype = NEC_78K_0_btclr;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        // 0xxx 1110
        case 0xE:
          insn.itype = NEC_78K_0_bt;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        // 0xxx 1111 - bf
        case 0xF:
          insn.itype = NEC_78K_0_bf;
          Operand_Bit(insn.Op1, FORM_OUT_A, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;
        // 1xxx 01xx
        // btclr
        case 0x85:
          insn.itype = NEC_78K_0_btclr;
          Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;
        // bt
        case 0x86:
          insn.itype = NEC_78K_0_bt;
          Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;
        // bf
        case 0x87:
          insn.itype = NEC_78K_0_bf;
          Operand_Bit(insn.Op1, FORM_OUT_HL, nib);
          Operand_NearByteI(insn, insn.Op2);
          break;

        default:
          return 0;
        }
   }
   return insn.size;
}

//----------------------------------------------------------------------
int idaapi N78K_ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;
  uchar code = insn.get_next_byte();
  switch ( code )
  {
    // nop            ( 0000 0000 )
    case 0x00:
      insn.itype = NEC_78K_0_nop;
      break;
    // not1 CY            ( 0000 0001 )
    case 0x01:
      insn.itype = NEC_78K_0_not1;
      Operand_Registr(insn.Op1, bCY, 0);
      break;
    // movw AX,!addr16            ( 0000 0010)
    case 0x02:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Addr16I(insn, insn.Op2, dt_word);
      break;
    // movw !addr16, AX            ( 0000 0011)
    case 0x03:
      insn.itype = NEC_78K_0_movw;
      Operand_Addr16I(insn, insn.Op1, dt_word);
      Operand_Registr(insn.Op2, rAX, 0);
      break;
    // dbnz saddr,$addr16           (0000 0100)
    case 0x04:
      insn.itype = NEC_78K_0_dbnz;
      Operand_Saddr1(insn, insn.Op1);
      Operand_NearByteI(insn, insn.Op2);
      break;
    // xch A,[DE]              ( 0000 0101 )
    case 0x05:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op1, rDE, FORM_OUT_SKOBA);
      break;
    // Bad command
    case 0x06:
      return 0;
    // xch A,[HL]              ( 0000 0111 )
    case 0x07:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op1, rHL, FORM_OUT_SKOBA);
      break;
    // add A, addr16
    case 0x08:
      insn.itype = NEC_78K_0_add;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // add A, [HL+off]
    case 0x09:
      insn.itype = NEC_78K_0_add;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // set1 saddr.bit              (0xxx 1010)
    // set1 PSW.bit              (0xxx 1010)
    case 0x0A:
    case 0x1A:
    case 0x2A:
    case 0x3A:
    case 0x4A:
    case 0x5A:
    case 0x6A:
    case 0x7A:
      insn.itype = NEC_78K_0_set1;
      Operand_SA_Bit(insn, insn.Op1, code >> 4);
      // convert set PSW.EI to EI
      if ( code == 0x7A && insn.Op1.FormOut == FORM_OUT_PSW )
      {
        insn.itype = NEC_78K_0_EI;
        insn.Op1.type = o_void;
      }
      break;
    // clr1 saddr.bit              (0BBB 1011)
    // clr1 PSW.bit                (0BBB 1011)
    case 0x0B:
    case 0x1B:
    case 0x2B:
    case 0x3B:
    case 0x4B:
    case 0x5B:
    case 0x6B:
    case 0x7B:
      insn.itype = NEC_78K_0_clr1;
      Operand_SA_Bit(insn, insn.Op1, code >> 4);
      // convert clr PSW.EI to DI
      if ( code == 0x7B && insn.Op1.FormOut == FORM_OUT_PSW )
      {
        insn.itype = NEC_78K_0_DI;
        insn.Op1.type = o_void;
      }
      break;
    // call11 (0x800-0xFFF)
    case 0x0C:
    case 0x1C:
    case 0x2C:
    case 0x3C:
    case 0x4C:
    case 0x5C:
    case 0x6C:
    case 0x7C:
      insn.itype = NEC_78K_0_callf;
      insn.Op1.type = o_near;
      insn.Op1.addr = (uint32(( code & 0xF0 )<<8) | (uint32)insn.get_next_byte()) + 0x800;
      insn.Op1.FormOut = FORM_OUT_VSK;
      break;
    // add A, #byte
    case 0x0D:
      insn.itype = NEC_78K_0_add;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // add A, saddr
    case 0x0E:
      insn.itype = NEC_78K_0_add;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // add A, [HL]
    case 0x0F:
      insn.itype = NEC_78K_0_add;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // movw rp,#word
    case 0x10:
    case 0x12:
    case 0x14:
    case 0x16:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // mov saddr,#byte              ( 0001 0001 SADDR DATA)
    // mov PSW,#byte              ( 0001 0001 SADDR DATA)
    case 0x11:
      insn.itype = NEC_78K_0_mov;
      Operand_SaddrPSW(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // case 0x12 - movw rp,#word
    // mov sfr,#byte              ( 0001 0011 SFR DATA)
    case 0x13:
      insn.itype = NEC_78K_0_mov;
      Operand_Sfr(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // case 0x14 - movw rp,#word
    // Bad Opcode
    case 0x15:
      return 0;
    // case 0x16 - movw rp,#word
    // Bad Opcode
    case 0x17:
      return 0;
    // sub A, addr16
    case 0x18:
      insn.itype = NEC_78K_0_sub;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // sub A, [HL+off]
    case 0x19:
      insn.itype = NEC_78K_0_sub;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // sub A, #byte
    case 0x1D:
      insn.itype = NEC_78K_0_sub;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // sub A, saddr
    case 0x1E:
      insn.itype = NEC_78K_0_sub;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // sub A, [HL]
    case 0x1F:
      insn.itype = NEC_78K_0_sub;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // set1 CY            ( 0010 0000 )
    case 0x20:
      insn.itype = NEC_78K_0_set1;
      Operand_Registr(insn.Op1, bCY, 0);
      break;
    // clr1 CY            ( 0010 0001 )
    case 0x21:
      insn.itype = NEC_78K_0_clr1;
      Operand_Registr(insn.Op1, bCY, 0);
      break;
    // push PSW            ( 0010 0010 )
    case 0x22:
      insn.itype = NEC_78K_0_push;
      Operand_Registr(insn.Op1, rPSW, 0);
      break;
    // pop PSW            ( 0010 0011 )
    case 0x23:
      insn.itype = NEC_78K_0_pop;
      Operand_Registr(insn.Op1, rPSW, 0);
      break;
    // ror A,1           ( 0010 0100 )
    case 0x24:
      insn.itype = NEC_78K_0_ror;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bits(insn.Op2, 1);
      break;
    // rorc A,1           ( 0010 0101 )
    case 0x25:
      insn.itype = NEC_78K_0_rorc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bits(insn.Op2, 1);
      break;
    // rol A,1           ( 0010 0110 )
    case 0x26:
      insn.itype = NEC_78K_0_rol;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bits(insn.Op2, 1);
      break;
    // rolc A,1           ( 0010 0111 )
    case 0x27:
      insn.itype = NEC_78K_0_rolc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bits(insn.Op2, 1);
      break;
    // addc A, addr16
    case 0x28:
      insn.itype = NEC_78K_0_addc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // addc A, [HL+off]
    case 0x29:
      insn.itype = NEC_78K_0_addc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // addc A, #byte
    case 0x2D:
      insn.itype = NEC_78K_0_addc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // addc A, saddr
    case 0x2E:
      insn.itype = NEC_78K_0_addc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // addc A, [HL]
    case 0x2F:
      insn.itype = NEC_78K_0_addc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // xch A, r              (0011 0RRR)
    case 0x30:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, code & 7, 0);
      break;
    // xxx A,[HL+B], xxx A,[HL+C]
    case 0x31:
      return Opcode_31(insn);
    // subc A, addr16
    case 0x38:
      insn.itype = NEC_78K_0_subc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // subc A, [HL+off]
    case 0x39:
      insn.itype = NEC_78K_0_subc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // subc A, #byte
    case 0x3D:
      insn.itype = NEC_78K_0_subc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // subc A, saddr
    case 0x3E:
      insn.itype = NEC_78K_0_subc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // subc A, [HL]
    case 0x3F:
      insn.itype = NEC_78K_0_subc;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // inc r              (0100 0RRR)
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
      insn.itype = NEC_78K_0_inc;
      Operand_Registr(insn.Op1, code & 7, 0);
      break;
    // cmp A, addr16
    case 0x48:
      insn.itype = NEC_78K_0_cmp;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // cmp A, [HL+off]
    case 0x49:
      insn.itype = NEC_78K_0_cmp;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // cmp A, #byte
    case 0x4D:
      insn.itype = NEC_78K_0_cmp;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // cmp A, saddr
    case 0x4E:
      insn.itype = NEC_78K_0_cmp;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // cmp A, [HL]
    case 0x4F:
      insn.itype = NEC_78K_0_cmp;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // dec r              (0101 0RRR)
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
      insn.itype = NEC_78K_0_dec;
      Operand_Registr(insn.Op1, code & 7, 0);
      break;
    // and A, addr16
    case 0x58:
      insn.itype = NEC_78K_0_and;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // and A, [HL+off]
    case 0x59:
      insn.itype = NEC_78K_0_and;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // and A, #byte
    case 0x5D:
      insn.itype = NEC_78K_0_and;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // and A, saddr
    case 0x5E:
      insn.itype = NEC_78K_0_and;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // and A, [HL]
    case 0x5F:
      insn.itype = NEC_78K_0_and;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // mov A, r              (0110 0RRR)
    case 0x60:
    case 0x62:
    case 0x63:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, code & 7, 0);
      break;
    case 0x61:
      return Opcode_61(insn);
    // or A, addr16
    case 0x68:
      insn.itype = NEC_78K_0_or;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // or A, [HL+off]
    case 0x69:
      insn.itype = NEC_78K_0_or;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // or A, #byte
    case 0x6D:
      insn.itype = NEC_78K_0_or;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // or A, saddr
    case 0x6E:
      insn.itype = NEC_78K_0_or;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // or A, [HL]
    case 0x6F:
      insn.itype = NEC_78K_0_or;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // mov r, A              (0111 0RRR)
    case 0x70:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, code & 7, 0);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    case 0x71:
      return Opcode_71(insn);
    // xor A, addr16
    case 0x78:
      insn.itype = NEC_78K_0_xor;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // xor A, [HL+off]
    case 0x79:
      insn.itype = NEC_78K_0_xor;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // xor A, #byte
    case 0x7D:
      insn.itype = NEC_78K_0_xor;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // xor A, saddr
    case 0x7E:
      insn.itype = NEC_78K_0_xor;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // xor A, [HL]
    case 0x7F:
      insn.itype = NEC_78K_0_xor;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // incw rp              (1000 0PP0)
    case 0x80:
    case 0x82:
    case 0x84:
    case 0x86:
      insn.itype = NEC_78K_0_incw;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      break;
    // inc saddr           ( 1000 0001 SADDR)
    case 0x81:
      insn.itype = NEC_78K_0_inc;
      Operand_Saddr1(insn, insn.Op1);
      break;
    // xch A, saddr              ( 1000 0011 SADDR )
    case 0x83:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Saddr1(insn, insn.Op2);
      break;
    // mov A,[DE]              ( 1000 0101)
    case 0x85:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rDE, FORM_OUT_SKOBA);
      break;
    // mov A,[HL]              ( 1000 0111)
    case 0x87:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Registr(insn.Op2, rHL, FORM_OUT_SKOBA);
      break;
    // add saddr, #byte
    case 0x88:
      insn.itype = NEC_78K_0_add;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // movw AX, SP                ( 1000 1001 0001 1100 )
    // movw AX, SADDRP            ( 1000 1001 SADDRP )
    case 0x89:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_SaddrSP(insn, insn.Op2);
      break;
    // dbnz C,$addr16           (1000 1010 JDISP )
    case 0x8A:
      insn.itype = NEC_78K_0_dbnz;
      Operand_Registr(insn.Op1, rC, 0);
      Operand_NearByteI(insn, insn.Op2);
      break;
    // dbnz B,$addr16           (1000 1011 JDISP )
    case 0x8B:
      insn.itype = NEC_78K_0_dbnz;
      Operand_Registr(insn.Op1, rB, 0);
      Operand_NearByteI(insn, insn.Op2);
      break;
    // bt xxxxxxxx
    case 0x8C:
    case 0x9C:
    case 0xAC:
    case 0xBC:
    case 0xCC:
    case 0xDC:
    case 0xEC:
    case 0xFC:
      insn.itype = NEC_78K_0_bt;
      Operand_SA_Bit(insn, insn.Op1, code >> 4);
      Operand_NearByteI(insn, insn.Op2);
      break;
    // bc $addr16           (1000 1101 JDISP )
    case 0x8D:
      insn.itype = NEC_78K_0_bc;
      Operand_NearByteI(insn, insn.Op1);
      break;
    // mov A,!addr16              ( 1000 1110 LOW HIGH)
    case 0x8E:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // ret              ( 1000 1111 )
    case 0x8F:
      insn.itype = NEC_78K_0_reti;
      break;
    // decw
    case 0x90:
    case 0x92:
    case 0x94:
    case 0x96:
      insn.itype = NEC_78K_0_decw;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      break;
    // dec saddr           ( 1001 0001 SADDR)
    case 0x91:
      insn.itype = NEC_78K_0_dec;
      Operand_Saddr1(insn, insn.Op1);
      break;
    // xch A, sfr              ( 1001 0011 SFR )
    case 0x93:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Sfr(insn, insn.Op2);
      break;
    // mov [DE], A              ( 1001 0101)
    case 0x95:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rDE, FORM_OUT_SKOBA);
      Operand_Registr(insn.Op2, rA, 0);
      break;

    // mov [HL], A              ( 1001 0111)
    case 0x97:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rHL, FORM_OUT_SKOBA);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // sub saddr, #byte
    case 0x98:
      insn.itype = NEC_78K_0_sub;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // movw SP, AX                ( 1001 1001 0001 1100 )
    // movw SADDRP, AX            ( 1001 1001 SADDRP )
    case 0x99:
      insn.itype = NEC_78K_0_movw;
      Operand_SaddrSP(insn, insn.Op1);
      Operand_Registr(insn.Op2, rAX, 0);
      break;
    // call !addr16         ( 1001 1010 LOW HIGH )
    case 0x9A:
      insn.itype = NEC_78K_0_call;
      insn.Op1.FormOut = FORM_OUT_VSK;// outputting char '!'
      insn.Op1.type = o_near;
      insn.Op1.dtype = dt_word;
      insn.Op1.offb = (uchar)insn.size;
      insn.Op1.addr = Get_Data_16bits(insn);
      break;
    // br !addr16           (1111 1011 LOW HIGH)
    case 0x9B:
      insn.itype = NEC_78K_0_br;
      insn.Op1.FormOut = FORM_OUT_VSK;
      insn.Op1.type = o_near;
      insn.Op1.dtype = dt_word;
      insn.Op1.offb =  (uchar)insn.size;
      insn.Op1.value =
      insn.Op1.addr = Get_Data_16bits(insn);
      break;
    // case 9C - bt
    // bnc $addr16           (1001 1101 JDISP )
    case 0x9D:
      insn.itype = NEC_78K_0_bnc;
      Operand_NearByteI(insn, insn.Op1);
      break;
    // mov !addr16, A              ( 1001 1110 LOW HIGH)
    case 0x9E:
      insn.itype = NEC_78K_0_mov;
      Operand_Addr16I(insn, insn.Op1, dt_byte);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // retb              ( 1001 1111 )
    case 0x9F:
      insn.itype = NEC_78K_0_retb;
      break;
    // mov r,#byte              (1010 0RRR)
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA3:
    case 0xA4:
    case 0xA5:
    case 0xA6:
    case 0xA7:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, code & 7, 0);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // addc saddr, #byte
    case 0xA8:
      insn.itype = NEC_78K_0_addc;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // movw AX, SFR            ( 1010 1001 SFR )
    case 0xA9:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Sfr(insn, insn.Op2);
      break;
    // mov A,[HL+C]              ( 1010 1010)
    case 0xAA:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffReg(insn.Op2, rC);
      break;
    // mov A,[HL+B]              ( 1010 1011)
    case 0xAB:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffReg(insn.Op2, rB);
      break;
    // case 0xAC - bt
    // bz $addr16           (1010 1101 JDISP )
    case 0xAD:
      insn.itype = NEC_78K_0_bz;
      Operand_NearByteI(insn, insn.Op1);
      break;
    // mov A,[HL+byte]              ( 1010 1110)
    case 0xAE:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // ret              ( 1010 1111 )
    case 0xAF:
      insn.itype = NEC_78K_0_ret;
      break;
    // pop
    case 0xB0:
    case 0xB2:
    case 0xB4:
    case 0xB6:
      insn.itype=NEC_78K_0_pop;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      break;
    // Push
    case 0xB1:
    case 0xB3:
    case 0xB5:
    case 0xB7:
      insn.itype=NEC_78K_0_push;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      break;
    // subc saddr, #byte
    case 0xB8:
      insn.itype = NEC_78K_0_subc;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // movw SFR, AX            ( 1011 1001 SFR )
    case 0xB9:
      insn.itype = NEC_78K_0_movw;
      Operand_Sfr(insn, insn.Op1);
      Operand_Registr(insn.Op2, rAX, 0);
      break;
    // mov [HL+B], A              ( 1011 1010)
    case 0xBA:
      insn.itype = NEC_78K_0_mov;
      Operand_HL_OffReg(insn.Op1, rC);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // mov [HL+B], A              ( 1011 1011)
    case 0xBB:
      insn.itype = NEC_78K_0_mov;
      Operand_HL_OffReg(insn.Op1, rB);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // case 0xBC - bt
    // bnz $addr16           (1011 1101 JDISP )
    case 0xBD:
      insn.itype = NEC_78K_0_bnz;
      Operand_NearByteI(insn, insn.Op1);
      break;
    // mov [HL+byte], A              ( 1011 1110)
    case 0xBE:
      insn.itype = NEC_78K_0_mov;
      Operand_HL_OffI(insn, insn.Op1);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // brk              ( 1011 1111 )
    case 0xBF:
      insn.itype = NEC_78K_0_brk;
      break;
    // movw AX, rp           (1100 0PP0)
    case 0xC0:
    case 0xC2:
    case 0xC4:
    case 0xC6:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Registr(insn.Op2, rAX+((code>>1)&7), 0);
      break;
    // cmp saddr, #byte
    case 0xC8:
      insn.itype = NEC_78K_0_cmp;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // addw AX,#word           ( 1100 1010 LOW HIGH)
    case 0xCA:
      insn.itype = NEC_78K_0_addw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // case 0xCC - bt
    // xch A,!addr              ( 1100 1110 LOW HIGH )
    case 0xCE:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Addr16I(insn, insn.Op2, dt_byte);
      break;
    // movw rp, AX           (1101 0PP0)
    case 0xD0:
    case 0xD2:
    case 0xD4:
    case 0xD6:
      insn.itype = NEC_78K_0_movw;
      Operand_Registr(insn.Op1, rAX+((code>>1)&7), 0);
      Operand_Registr(insn.Op2, rAX, 0);
      break;
    // and saddr, #byte
    case 0xD8:
      insn.itype = NEC_78K_0_and;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // subw AX,#word           ( 1101 1010 LOW HIGH)
    case 0xDA:
      insn.itype = NEC_78K_0_subw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // case 0xDC - bt
    // xch A,[HL+byte]              ( 1101 1110 DATA )
    case 0xDE:
      insn.itype = NEC_78K_0_xch;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_HL_OffI(insn, insn.Op2);
      break;
    // xchw AX, rp           (1101 0PP0)
    case 0xE0:
    case 0xE2:
    case 0xE4:
    case 0xE6:
      insn.itype = NEC_78K_0_xchw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Registr(insn.Op2, rAX+((code>>1)&7), 0);
      break;
    // or saddr, #byte
    case 0xE8:
      insn.itype = NEC_78K_0_or;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // cmpw AX,#word           ( 1110 1010 LOW HIGH)
    case 0xEA:
      insn.itype = NEC_78K_0_cmpw;
      Operand_Registr(insn.Op1, rAX, 0);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // case 0xEC - bt
    // movw SP,#word            ( 1110 1110 0001 1100 LOW HIGH)
    // movw saddrp,#word            ( 1110 1110 SADDR LOW HIGH)
    case 0xEE:
      insn.itype = NEC_78K_0_movw;
      Operand_SaddrSP(insn, insn.Op1);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // mov A, saddr              ( 1111 0000 A SADDRR )
    // mov A, PSW                ( 1111 0000 A PSW )
    case 0xF0:
      insn.itype = NEC_78K_0_mov;
      Operand_SaddrPSW(insn, insn.Op2);
      Operand_Registr(insn.Op1, rA, 0);
      break;
    // mov saddr, A              ( 1111 0010 SADDRR A)
    // mov PSW, A                ( 1111 0010 SADDRR A)
    case 0xF2:
      insn.itype = NEC_78K_0_mov;
      Operand_SaddrPSW(insn, insn.Op1);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // mov A, sfr              ( 1111 0100 A SFR )
    case 0xF4:
      insn.itype = NEC_78K_0_mov;
      Operand_Registr(insn.Op1, rA, 0);
      Operand_Sfr(insn, insn.Op2);
      break;
    // mov saddr, A              ( 1111 0110 SFR A)
    case 0xF6:
      insn.itype = NEC_78K_0_mov;
      Operand_Sfr(insn, insn.Op1);
      Operand_Registr(insn.Op2, rA, 0);
      break;
    // xor saddr, #byte
    case 0xF8:
      insn.itype = NEC_78K_0_xor;
      Operand_Saddr1(insn, insn.Op1);
      Operand_Data_8bitsI(insn, insn.Op2);
      break;
    // br $addr16           (1111 01010 JDISP)
    case 0xFA:
      insn.itype = NEC_78K_0_br;
      Operand_NearByteI(insn, insn.Op1);
      break;
    // case 0xFC - bt
    // movw sfr,#word            ( 1111 1110 SFR LOW HIGH)
    case 0xFE:
      insn.itype = NEC_78K_0_movw;
      Operand_Sfr(insn, insn.Op1);
      Operand_Data_16bitsI(insn, insn.Op2);
      break;
    // callt
    case 0xC1:case 0xC3:case 0xC5:case 0xC7:case 0xC9:case 0xCB:case 0xCD:case 0xCF:
    case 0xD1:case 0xD3:case 0xD5:case 0xD7:case 0xD9:case 0xDB:case 0xDD:case 0xDF:
    case 0xE1:case 0xE3:case 0xE5:case 0xE7:case 0xE9:case 0xEB:case 0xED:case 0xEF:
    case 0xF1:case 0xF3:case 0xF5:case 0xF7:case 0xF9:case 0xFB:case 0xFD:case 0xFF:
      insn.itype = NEC_78K_0_callt;
      Operand_Addr16(insn.Op1,0x40 + (code & 0x3E), dt_word);
      // change format
      insn.Op1.FormOut = FORM_OUT_SKOBA;
      break;
    // unknown code - return error
    default:
      return 0;
   }
   return insn.size;
}
