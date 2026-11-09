// $Id: ana.cpp,v 1.13 2000/11/06 22:11:16 jeremy Exp $
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
// TMS320C1X Processor module
//       Instruction decode.
//
#include "../idaidp.hpp"
#include "tms320c1.hpp"
#include "ins.hpp"
#include "reg.hpp"

//
// After determining an instruction's opcode, ana() calls one of the
// functions below to decode its operands.
//
static int ana_di(insn_t &insn, uint16); // direct/indirect instruction
static int ana_di_shift(insn_t &insn, uint16); // direct/indirect w/ shift instruction
static int ana_di_port(insn_t &insn, uint16); // direct/indirect to/from I/O port
static int ana_di_aux(insn_t &insn, uint16); // direct/indirect to AR register
static int ana_imm_1(insn_t &insn, uint16); // immediate 1 bit
static int ana_imm_8(insn_t &insn, uint16); // immediate 8 bits
static int ana_imm_13(insn_t &insn, uint16); // immediate 13 bits
static int ana_imm_8_aux(insn_t &insn, uint16); // immediate 8 bits into AR register
static int ana_flow(insn_t &insn); // flow control
inline int ana_empty(const insn_t &insn); // no operands

//
// These functions in turn may call one of the functions below to help
// decode the individual operands within the instruction.
//
static int ana_op_di(const insn_t &insn, op_t &, op_t &, uint16); // direct/indirect operand
static int ana_op_narp(const insn_t &insn, op_t &, uint16);         // new ARP operand

//
// Due to limitations that IDA's some of IDA's helper functions have,
// they don't work well with processors whose byte size is greater
// than 8 bits.  (This processor has a 16-bit byte).  Therefore we
// have to make our own replacements for these functions.
//
// Simulates the effect of the IDA kernel helper function insn.get_next_byte(),
// but works with our 16-bit byte environment.
//
static uint16 tms320c1x_get_next_insn_byte(insn_t &insn)
{
  //
  // Fetch a 16 bit value from the (global) current instruction decode
  // pointer.
  //
  uint16 value = get_wide_byte(insn.ea+insn.size);

  //
  // Increment the size of the current instruction, to reflect the fact
  // that it contains the byte that we just read.
  //
  insn.size++;

  return value;
}


//lint -esym(714,ana)
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  //
  // Fetch the first 16 bits of the instruction.
  // (All instructions are at least 16 bits long).
  //
  uint16 opcode = tms320c1x_get_next_insn_byte(insn);

  //
  // Decode the instruction in the opcode by sifting through the
  // various instruction bit masks.
  //

  //
  // 3-bit mask instructions:
  // MPYK
  //
  switch ( opcode & ISN_3_BIT_MASK )
  {
    case ISN3_MPYK : insn.itype = I_MPYK; return ana_imm_13(insn, opcode);
  }

  //
  // 4-bit mask instructions:
  // ADD, LAC, SUB
  //
  switch ( opcode & ISN_4_BIT_MASK )
  {
    case ISN4_ADD  : insn.itype = I_ADD;  return ana_di_shift(insn, opcode);
    case ISN4_LAC  : insn.itype = I_LAC;  return ana_di_shift(insn, opcode);
    case ISN4_SUB  : insn.itype = I_SUB;  return ana_di_shift(insn, opcode);
  }

  //
  // 5-bit mask instructions:
  // SACH, IN, OUT
  //
  switch ( opcode & ISN_5_BIT_MASK )
  {
    case ISN5_SACH : insn.itype = I_SACH; return ana_di(insn, opcode);
    case ISN5_IN   : insn.itype = I_IN;   return ana_di_port(insn, opcode);
    case ISN5_OUT  : insn.itype = I_OUT;  return ana_di_port(insn, opcode);
  }

  //
  // 7-bit mask instructions:
  // LAR, LARK, SAR
  //
  switch ( opcode & ISN_7_BIT_MASK )
  {
    case ISN7_LAR  : insn.itype = I_LAR;  return ana_di_aux(insn, opcode);
    case ISN7_LARK : insn.itype = I_LARK; return ana_imm_8_aux(insn, opcode);
    case ISN7_SAR  : insn.itype = I_SAR;  return ana_di_aux(insn, opcode);
  }

  //
  // 8-bit mask instructions:
  // ADDH, ADDS, AND, LACK, OR, SACL, SUBC, SUBH, XOR, ZALH, LDP, MAR,
  // LT, LTA, LTD, MPY, LST, SST, DMOV, TBLR, TBLW
  //
  switch ( opcode & ISN_8_BIT_MASK )
  {
    case ISN8_ADDH : insn.itype = I_ADDH; return ana_di(insn, opcode);
    case ISN8_ADDS : insn.itype = I_ADDS; return ana_di(insn, opcode);
    case ISN8_AND  : insn.itype = I_AND;  return ana_di(insn, opcode);
    case ISN8_LACK : insn.itype = I_LACK; return ana_imm_8(insn, opcode);
    case ISN8_OR   : insn.itype = I_OR;   return ana_di(insn, opcode);
    case ISN8_SACL : insn.itype = I_SACL; return ana_di(insn, opcode);
    case ISN8_SUBC : insn.itype = I_SUBC; return ana_di(insn, opcode);
    case ISN8_SUBH : insn.itype = I_SUBH; return ana_di(insn, opcode);
    case ISN8_SUBS : insn.itype = I_SUBS; return ana_di(insn, opcode);
    case ISN8_XOR  : insn.itype = I_XOR;  return ana_di(insn, opcode);
    case ISN8_ZALH : insn.itype = I_ZALH; return ana_di(insn, opcode);
    case ISN8_ZALS : insn.itype = I_ZALS; return ana_di(insn, opcode);
    case ISN8_LDP  : insn.itype = I_LDP;  return ana_di(insn, opcode);
    case ISN8_MAR  : insn.itype = I_MAR;  return ana_di(insn, opcode);
    case ISN8_LT   : insn.itype = I_LT;   return ana_di(insn, opcode);
    case ISN8_LTA  : insn.itype = I_LTA;  return ana_di(insn, opcode);
    case ISN8_LTD  : insn.itype = I_LTD;  return ana_di(insn, opcode);
    case ISN8_MPY  : insn.itype = I_MPY;  return ana_di(insn, opcode);
    case ISN8_LST  : insn.itype = I_LST;  return ana_di(insn, opcode);
    case ISN8_SST  : insn.itype = I_SST;  return ana_di(insn, opcode);
    case ISN8_DMOV : insn.itype = I_DMOV; return ana_di(insn, opcode);
    case ISN8_TBLR : insn.itype = I_TBLR; return ana_di(insn, opcode);
    case ISN8_TBLW : insn.itype = I_TBLW; return ana_di(insn, opcode);
  }

  //
  // 15-bit mask instructions:
  // LARP, LDPK
  //
  switch ( opcode & ISN_15_BIT_MASK )
  {
    // LARP is a synonym for a special case of MAR
    // case ISN15_LARP: insn.itype = I_LARP; return ana_ar(opcode);
    case ISN15_LDPK: insn.itype = I_LDPK; return ana_imm_1(insn, opcode);
  }

  //
  // 16-bit mask instructions:
  // ABS, ZAC, APAC, PAC, SPAC, B, BANZ, BGEZ, BGZ, BIOZ, BLEZ, BLZ,
  // BNZ, BV, BZ, CALA, CALL, RET, DINT, EINT, NOP, POP, PUSH, ROVM,
  // SOVM
  //
  switch ( opcode & ISN_16_BIT_MASK )
  {
    case ISN16_ABS:  insn.itype = I_ABS;  return ana_empty(insn);
    case ISN16_ZAC:  insn.itype = I_ZAC;  return ana_empty(insn);
    case ISN16_APAC: insn.itype = I_APAC; return ana_empty(insn);
    case ISN16_PAC:  insn.itype = I_PAC;  return ana_empty(insn);
    case ISN16_SPAC: insn.itype = I_SPAC; return ana_empty(insn);
    case ISN16_B:    insn.itype = I_B;    return ana_flow(insn);
    case ISN16_BANZ: insn.itype = I_BANZ; return ana_flow(insn);
    case ISN16_BGEZ: insn.itype = I_BGEZ; return ana_flow(insn);
    case ISN16_BGZ:  insn.itype = I_BGZ;  return ana_flow(insn);
    case ISN16_BIOZ: insn.itype = I_BIOZ; return ana_flow(insn);
    case ISN16_BLEZ: insn.itype = I_BLEZ; return ana_flow(insn);
    case ISN16_BLZ:  insn.itype = I_BLZ;  return ana_flow(insn);
    case ISN16_BNZ:  insn.itype = I_BNZ;  return ana_flow(insn);
    case ISN16_BV:   insn.itype = I_BV;   return ana_flow(insn);
    case ISN16_BZ:   insn.itype = I_BZ;   return ana_flow(insn);
    case ISN16_CALA: insn.itype = I_CALA; return ana_empty(insn);
    case ISN16_CALL: insn.itype = I_CALL; return ana_flow(insn);
    case ISN16_RET:  insn.itype = I_RET;  return ana_empty(insn);
    case ISN16_DINT: insn.itype = I_DINT; return ana_empty(insn);
    case ISN16_EINT: insn.itype = I_EINT; return ana_empty(insn);
    case ISN16_NOP:  insn.itype = I_NOP;  return ana_empty(insn);
    case ISN16_POP:  insn.itype = I_POP;  return ana_empty(insn);
    case ISN16_PUSH: insn.itype = I_PUSH; return ana_empty(insn);
    case ISN16_ROVM: insn.itype = I_ROVM; return ana_empty(insn);
    case ISN16_SOVM: insn.itype = I_SOVM; return ana_empty(insn);
  }

  //
  // If control reaches this point, then the opcode does not represent
  // any known instruction.
  //
  return 0;
}

//
// ana_empty()
//
// Called to decode an 'empty' instruction's operands.
// (Very trivial, because an empty instruction has no operands).
//
inline int ana_empty(const insn_t &insn)
{
  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_flow()
//
// Called to decode a flow control instruction's operands.
// Decodes the branch address of the instruction.
//
// (Some flow control instructions have no arguments and are thus
// decoded by calling ana_empty()).
//
static int ana_flow(insn_t &insn)
{
  //
  // Fetch the next 16 bits from the instruction; they
  // constitute the branch address.
  //
  uint16 addr = tms320c1x_get_next_insn_byte(insn);

  //
  // Fill in the insn structure to reflect the first (and only)
  // operand of this instruction as being a reference to the CODE segment.
  //
  insn.Op1.type = o_near;
  insn.Op1.addr = addr;

  //
  // Set the operand type to reflect the size of the address
  // in the instruction.  Technically this instructions address
  // value is one processor byte (16 bits), but when it comes to defining
  // operand value sizes, IDA thinks in terms of 8-bit bytes.
  // Therefore, we specify this value as a word.
  //
  insn.Op1.dtype = dt_word;

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_di(opcode)
//
// Called to decode a direct/indirect memory reference instruction's
// operands.
//
static int ana_di(insn_t &insn, uint16 opcode)
{
  //
  // Decode the direct or indirect memory reference made
  // by the instruction as its first operand and the new arp value
  // (if it exists) as its second operand.
  //
  if ( ana_op_di(insn, insn.Op1, insn.Op2, opcode) == 0 )
  {
    //
    // The operand was invalid.
    //
    return 0;
  }

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_di_shift(opcode)
//
// Called to decode a direct/indirect memory reference plus shift
// instruction's operands.
//
static int ana_di_shift(insn_t &insn, uint16 opcode)
{
  //
  // First, decode the direct or indirect memory reference made
  // by the instruction as its first operand, and the new arp
  // value (if it exists) as its third operand.
  //
  if ( ana_op_di(insn, insn.Op1, insn.Op3, opcode) == 0 )
  {
    //
    // The operand was invalid.
    //
    return 0;
  }

  //
  // Finally, decode the shift value as the instruction's second operand.
  //
  insn.Op2.type  = o_imm;
  insn.Op2.value = ISN_SHIFT(opcode);

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_di_port(opcode)
//
// Called to decode a direct/indirect memory reference to/from I/O port
// instruction's operands.
//
static int ana_di_port(insn_t &insn, uint16 opcode)
{
  //
  // First, decode the direct or indirect memory reference made
  // by the instruction as its first operand and the new arp value
  // (if it exists) as its third operand.
  //
  if ( ana_op_di(insn, insn.Op1, insn.Op3, opcode) == 0 )
  {
    //
    // The operand was invalid.
    //
    return 0;
  }

  //
  // Next, decode the port number as the instruction's second operand.
  //
  insn.Op2.type  = o_imm;
  insn.Op2.value = ISN_PORT(opcode);

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_di_aux(opcode)
//
// Called to decode a direct/indirect memory reference to/from auxiliary
// register instruction's operands.
//
static int ana_di_aux(insn_t &insn, uint16 opcode)
{
  //
  // First, decode the auxiliary register number as the instruction's
  // first operand.
  //
  insn.Op1.type = o_reg;
  insn.Op1.reg  = (ISN_AUX_AR(opcode) ? IREG_AR1 : IREG_AR0);

  //
  // Finally, decode the direct or indirect memory reference made
  // by the instruction as its second operand and the new arp
  // value (if it exists) as its third operand.
  //
  if ( ana_op_di(insn, insn.Op2, insn.Op3, opcode) == 0 )
  {
    //
    // The operand was invalid.
    //
    return 0;
  }

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_imm_1(opcode)
//
// Called to decode a 1 bit immediate value instruction's operands.
//
static int ana_imm_1(insn_t &insn, uint16 opcode)
{
  //
  // Decode the 1 bit immediate value in this instruction's opcode
  // and make an immediate value operand out of it.
  //
  insn.Op1.type  = o_imm;
  insn.Op1.value = ISN_IMM1(opcode);
  insn.Op1.dtype = dt_byte;  // This means an 8 bit value, rather than 16.

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_imm_8(opcode)
//
// Called to decode an 8 bit immediate value instruction's operands.
//
static int ana_imm_8(insn_t &insn, uint16 opcode)
{
  //
  // Decode the 8 bit immediate value in this instruction's opcode
  // and make an immediate value operand out of it.
  //
  insn.Op1.type  = o_imm;
  insn.Op1.value = ISN_IMM8(opcode);
  insn.Op1.dtype = dt_byte;  // This means an 8 bit value, rather than 16.

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_imm_13(opcode)
//
// Called to decode a 13 bit immediate value instruction's operands.
//
static int ana_imm_13(insn_t &insn, uint16 opcode)
{
  //
  // Decode the 13 bit immediate value in this instruction's opcode
  // and make an immediate value operand out of it.
  //
  insn.Op1.type  = o_imm;
  insn.Op1.value = ISN_IMM13(opcode);
  insn.Op1.dtype = dt_word;  // This means an 8 bit value, rather than 16.

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_imm_8_aux(opcode)
//
// Called upon to decode an immediate 8 bit to aux register instruction's
// operands.
//
static int ana_imm_8_aux(insn_t &insn, uint16 opcode)
{
  //
  // Decode the AR bit of the instruction to determine which auxiliary
  // register is being loaded.  Make this register the first operand.
  //
  insn.Op1.type = o_reg;
  insn.Op1.reg  = (ISN_AUX_AR(opcode) ? IREG_AR1 : IREG_AR0);

  //
  // Next, decode the 8 bit immediate value in the instruction and
  // make it the second operand.
  //
  insn.Op2.type  = o_imm;
  insn.Op2.value = ISN_IMM8(opcode);
  insn.Op2.dtype = dt_word;  // This means an 8 bit value, rather than 16.

  //
  // Successful decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_op_di(addr_op, narp_op, opcode)
//
// Decodes the direct or indirect memory reference made in the instruction
// contained in 'opcode' and places the decoded information into the operand
// address operand 'operand' and the new ARP operand 'narp_op'.
//
// Returns instruction size on successful decode, 0 on illegal condition.
//
static int ana_op_di(const insn_t &insn, op_t &addr_op, op_t &narp_op, uint16 opcode)
{
  //
  // Check the direct/indirect bit.  This determines whether the
  // opcode makes a direct memory reference via an immediate value,
  // or an indirect memory reference via the current auxiliary
  // register.
  //
  if ( ISN_DIRECT(opcode) )
  {
    //
    // The direct bit is set.  This instruction makes a direct
    // memory reference to the memory location specified in its
    // immediate operand.
    //
    addr_op.type  = o_mem;
    addr_op.dtype = dt_byte; // This means an 8 bit value, rather than 16.
    addr_op.addr  = ISN_DIR_ADDR(opcode);
  }
  else
  {
    //
    // The direct bit is reset.  This instruction makes an
    // indirect memory reference.
    //
    // Determine whether this is an AR post-increment,
    // post-decrement, or no change reference.
    //
    if ( ISN_INDIR_INCR(opcode) && ISN_INDIR_DECR(opcode) )
    {
      //
      // Both the AR increment and AR decrement flags are
      // set.  This is an illegal instruction.
      //
      return 0;
    }
    else if ( ISN_INDIR_INCR(opcode) )
    {
      //
      // The AR increment flag is set.
      // This is an AR increment reference.
      //
      addr_op.type   = o_phrase;
      addr_op.phrase = IPH_AR_INCR;
    }
    else if ( ISN_INDIR_DECR(opcode) )
    {
      //
      // The AR decrement flag is set.
      // This is an AR decrement reference.
      //
      addr_op.type   = o_phrase;
      addr_op.phrase = IPH_AR_DECR;
    }
    else
    {
      //
      // Neither the AR auto-increment or auto-decrement
      // flags is set.  That makes this a regular AR
      // indirect reference.
      //
      addr_op.type   = o_phrase;
      addr_op.phrase = IPH_AR;
    }
    //
    // Next, decode the auxiliary register pointer change command,
    // if present, as the instruction's second operand.  If no
    // change is requested in this instruction, then the second operand
    // will not be filled in.
    //
    if ( ana_op_narp(insn, narp_op, opcode) == 0 )
    {
      //
      // The operand was invalid.
      //
      return 0;
    }
  }

  //
  // Successful operand decode.
  // Return the instruction size.
  //
  return insn.size;
}

//
// ana_op_narp(operand, opcode)
//
// Decodes the 'auxiliary-register-pointer-change' command that may
// be embededded in the opcode 'opcode' and places the information
// about the change in the operand 'operand'.  If the instruction does
// not have a pointer change request, then 'operand' is left alone.
//
// Returns instruction size on successful decode, 0 on illegal condition.
//
static int ana_op_narp(const insn_t &insn, op_t &op, uint16 opcode)
{
  //
  // Determine if the instruction contains a request
  // to change the ARP register after execution.
  //
  if ( ISN_INDIR_NARP(opcode) )
  {
    //
    // The instruction contains the request.
    // Reflect the request in the operand provided.
    //
    op.type = o_reg;
    if ( ISN_INDIR_ARP(opcode) )
    {
      // Change to AR1
      op.reg = IREG_AR1;
    }
    else
    {
      // Change to AR0
      op.reg = IREG_AR0;
    }
  }

  //
  // Successful operand decode.
  // Return the instruction size.
  //
  return insn.size;
}

