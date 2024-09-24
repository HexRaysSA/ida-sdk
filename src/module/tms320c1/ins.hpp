// $Id: ins.hpp,v 1.6 2000/11/06 22:11:16 jeremy Exp $
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
//     Software representation of TMS320C1X instructions.
//
#ifndef _IDP_TMS320C1X_INS_H
#define _IDP_TMS320C1X_INS_H

enum nameNum
{
  // Accumulator Memory Reference Instructions
  I__FIRST = 0,
  I_ABS = 0,
  I_ADD,
  I_ADDH,
  I_ADDS,
  I_AND,
  I_LAC,
  I_LACK,
  I_OR,
  I_SACH,
  I_SACL,
  I_SUB,
  I_SUBC,
  I_SUBH,
  I_SUBS,
  I_XOR,
  I_ZAC,
  I_ZALH,
  I_ZALS,
  // Auxiliary Register and Data Page Pointer Instructions
  I_LAR,
  I_LARK,
  I_LARP,
  I_LDP,
  I_LDPK,
  I_MAR,
  I_SAR,
  // T Register, P Register, and Multiply Instructions
  I_APAC,
  I_LT,
  I_LTA,
  I_LTD,
  I_MPY,
  I_MPYK,
  I_PAC,
  I_SPAC,
  // Branch/Call Instructions
  I_B,
  I_BANZ,
  I_BGEZ,
  I_BGZ,
  I_BIOZ,
  I_BLEZ,
  I_BLZ,
  I_BNZ,
  I_BV,
  I_BZ,
  I_CALA,
  I_CALL,
  I_RET,
  // Control Instructions
  I_DINT,
  I_EINT,
  I_LST,
  I_NOP,
  I_POP,
  I_PUSH,
  I_ROVM,
  I_SOVM,
  I_SST,
  // I/O and Data Memory Instructions
  I_DMOV,
  I_IN,
  I_OUT,
  I_TBLR,
  I_TBLW,
  I__LAST
};

//
// TMS320C1X register phrases.
// These are used to represent instruction operands that are not either
// immediate values or registers.
//
enum regPhrase
{
  IPH_AR,      // Dereference current aux register
  IPH_AR_INCR, // Dereference current aux register and post-increment
  IPH_AR_DECR, // Dereference current aux register and post-decrement
};

//
// Auxilliary instruction information.
// This is information that this processor module can add to the instruction,
// only to be examined and consumed by the processor module itself.
//
#define IX_DATA_PAGE_KNOWN 0x8000      // The current data page is known
#define IX_DATA_PAGE(x)    ((x) & 0x1) // Retrieves the known data page

extern const instruc_t Instructions[];

#endif  // _IDP_TMS320C1X_INS_H


