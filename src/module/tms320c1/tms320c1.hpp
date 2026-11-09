// $Id: tms320c1.hpp,v 1.8 2000/11/06 22:11:17 jeremy Exp $
//
// Copyright (c) 2000 Jeremy Cooper.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//    This product includes software developed by Jeremy Cooper.
// 4. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//
// IDA TMS320C1X processor module.
//     TMS320C1X constants, etc.
//
#ifndef _IDP_TMS320C1X_H
#define _IDP_TMS320C1X_H

//////////////////////////////////////////////////////////////////////////////
// TMS320C1X Instruction Opcodes
//
// To ease decoding requirements, we have classified each TMS320C1X
// instruction by the number of significant bits that need to be scanned in
// the instruction opcode in order to uniquely identify it.
//

//
// Bit scanning masks
//
#define ISN_3_BIT_MASK  0xe000 // 111x xxxx xxxx xxxx
#define ISN_4_BIT_MASK  0xf000 // 1111 xxxx xxxx xxxx
#define ISN_5_BIT_MASK  0xf800 // 1111 1xxx xxxx xxxx
#define ISN_7_BIT_MASK  0xfe00 // 1111 111x xxxx xxxx
#define ISN_8_BIT_MASK  0xff00 // 1111 1111 xxxx xxxx
#define ISN_15_BIT_MASK 0xfffe // 1111 1111 1111 111x
#define ISN_16_BIT_MASK 0xffff // 1111 1111 1111 1111

//
// 3 bit Opcodes
//
enum isn_3bit
{
  ISN3_MPYK = 0x8000, // 100...
};
//
// 4 bit Opcodes
//
enum isn_4bit
{
  ISN4_ADD    = 0x0000, // 0000...
  ISN4_LAC    = 0x2000, // 0100...
  ISN4_SUB    = 0x1000, // 0001...
};
//
// 5 bit Opcodes
//
enum isn_5bit
{
  ISN5_SACH   = 0x5800, // 0101 1...
  ISN5_IN     = 0x4000, // 0100 0...
  ISN5_OUT    = 0x4800, // 0100 1...
};
//
// 7 bit Opcodes
//
enum isn_7bit
{
  ISN7_LAR    = 0x3800, // 0011 100...
  ISN7_LARK   = 0x7000, // 0111 000...
  ISN7_SAR    = 0x3000, // 0011 000...
};
//
// 8 bit Opcodes
//
enum isn_8bit
{
  ISN8_ADDH   = 0x6000, // 0110 0000 ...
  ISN8_ADDS   = 0x6100, // 0110 0001 ...
  ISN8_AND    = 0x7900, // 0111 1001 ...
  ISN8_LACK   = 0x7e00, // 0111 1110 ...
  ISN8_OR     = 0x7a00, // 0111 1010 ...
  ISN8_SACL   = 0x5000, // 0101 0000 ...
  ISN8_SUBC   = 0x6400, // 0110 0100 ...
  ISN8_SUBH   = 0x6200, // 0110 0010 ...
  ISN8_SUBS   = 0x6300, // 0110 0011 ...
  ISN8_XOR    = 0x7800, // 0111 1000 ...
  ISN8_ZALH   = 0x6500, // 0110 0101 ...
  ISN8_ZALS   = 0x6600, // 0110 0110 ...
  ISN8_LDP    = 0x6f00, // 0110 1111 ...
  ISN8_MAR    = 0x6800, // 0110 1000 ...
  ISN8_LT     = 0x6a00, // 0110 1010 ...
  ISN8_LTA    = 0x6c00, // 0110 1100 ...
  ISN8_LTD    = 0x6b00, // 0110 1011 ...
  ISN8_MPY    = 0x6d00, // 0110 1101 ...
  ISN8_LST    = 0x7b00, // 0111 1101 ...
  ISN8_SST    = 0x7c00, // 0111 1100 ...
  ISN8_DMOV   = 0x6900, // 0110 1001 ...
  ISN8_TBLR   = 0x6700, // 0110 0111 ...
  ISN8_TBLW   = 0x7d00, // 0111 1101 ...
};
//
// 15 bit Opcodes
//
enum isn_15bit
{
// LARP is a synonym for a special case of MAR
// ISN15_LARP = 0x6880, // 0110 1000 1000 000.
  ISN15_LDPK = 0x6e00, // 0110 1110 0000 000.
};
//
// 16 bit Opcodes
//
enum isn_16bit
{
  ISN16_ABS  = 0x7f88, // 0111 1111 1000 1000
  ISN16_ZAC  = 0x7f89, // 0111 1111 1000 0101
  ISN16_APAC = 0x7f8f, // 0111 1111 1000 1111
  ISN16_PAC  = 0x7f8e, // 0111 1111 1000 1110
  ISN16_SPAC = 0x7f90, // 0111 1111 1001 0000
  ISN16_B    = 0xf900, // 1111 1001 0000 0000
  ISN16_BANZ = 0xf400, // 1111 0100 0000 0000
  ISN16_BGEZ = 0xfd00, // 1111 1101 0000 0000
  ISN16_BGZ  = 0xfc00, // 1111 1100 0000 0000
  ISN16_BIOZ = 0xf600, // 1111 0110 0000 0000
  ISN16_BLEZ = 0xfb00, // 1111 1011 0000 0000
  ISN16_BLZ  = 0xfa00, // 1111 1010 0000 0000
  ISN16_BNZ  = 0xfe00, // 1111 1110 0000 0000
  ISN16_BV   = 0xf500, // 1111 0101 0000 0000
  ISN16_BZ   = 0xff00, // 1111 1111 0000 0000
  ISN16_CALA = 0x7f8c, // 0111 1111 1000 1100
  ISN16_CALL = 0xf800, // 1111 1000 0000 0000
  ISN16_RET  = 0x7f8d, // 0111 1111 1000 1101
  ISN16_DINT = 0x7f81, // 0111 1111 1000 0001
  ISN16_EINT = 0x7f82, // 0111 1111 1000 0010
  ISN16_NOP  = 0x7f80, // 0111 1111 1000 0000
  ISN16_POP  = 0x7f9d, // 0111 1111 1001 1101
  ISN16_PUSH = 0x7f9c, // 0111 1111 1001 1100
  ISN16_ROVM = 0x7f8a, // 0111 1111 1000 1010
  ISN16_SOVM = 0x7f8b, // 0111 1111 1000 1011
};

//
// Instruction property macros.
// These macros deduce certain facts about the instruction.
//
#define ISN_IMM1(op)       ((op) & 0x0001)   // Immediate 1 bit value
#define ISN_IMM8(op)       ((op) & 0x00ff)   // Immediate 8 bit value
#define ISN_IMM13(op)      ((op) & 0x1fff)   // Immediate 13 bit value
#define ISN_DIRECT(op)   (!((op) & 0x0080))  // Direct/Indirect reference flag
#define ISN_DIR_ADDR(op)   ((op) & 0x007f)   // Direct memory location
#define ISN_INDIR_INCR(op) ((op) & 0x0020)   // Aux reg. post-increment flag
#define ISN_INDIR_DECR(op) ((op) & 0x0010)   // Aux reg. post-decrement flag
#define ISN_INDIR_NARP(op) ((op) & 0x0008)   // Aux reg. change flag
#define ISN_INDIR_ARP(op)  ((op) & 0x0001)   // New aux reg. pointer value
#define ISN_AUX_AR(op)     ((op) & 0x0100)   // Aux register index
#define ISN_SHIFT(o)       (((o)&0x0f00)>>8) // Data bit shift amount
#define ISN_PORT(o)        (((o)&0x0700)>>8) // I/O port number

//
// TMS320C1X environment facts.
// These macros define the size of the TMS320C1X's addressable
// data RAM.
//
#define TMS320C1X_DATA_RAM_SIZE 256     // 256 bytes

//
// Reference type.  Used between emu() and handle_operand() to
// flag whether an operand is written to or read from.
//
enum opRefType
{
  hop_READ,
  hop_WRITE,
};

struct tms320c1_t : public procmod_t
{
  sel_t tms320c1x_dpage0; // Data page 0 selector
  sel_t tms320c1x_dpage1; // Data page 1 selector

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  // Kernel message handlers.
  void tms320c1x_Init() const;
  void tms320c1x_NewFile();

  int emu(const insn_t &insn) const;
  bool handle_operand(const insn_t &insn, const op_t &op, opRefType ref_type) const;
};

#endif // IDP_TMS320C1X_H
