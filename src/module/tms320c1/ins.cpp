// $Id: ins.cpp,v 1.2 2000/11/06 22:11:16 jeremy Exp $
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
// TMS320C1X processor module.
//     Software representation of TMS320C1X instructions.
//
#include "../idaidp.hpp"

#include "ins.hpp"

//
// Names and side-effect features of all instructions.
// Used by the emu() function to determine instruction side effects
// and report them to the kernel.
//
const instruc_t Instructions[] =
{
  // Accumulator Memory Reference Instructions
  { "ABS",  0 },
  { "ADD",  CF_USE1 },
  { "ADDH", CF_USE1 },
  { "ADDS", CF_USE1 },
  { "AND",  CF_USE1 },
  { "LAC",  CF_USE1 },
  { "LACK", CF_USE1 },
  { "OR",   CF_USE1 },
  { "SACH", CF_CHG1 },
  { "SACL", CF_CHG1 },
  { "SUB",  CF_USE1 },
  { "SUBC", CF_USE1 },
  { "SUBH", CF_USE1 },
  { "SUBS", CF_USE1 },
  { "XOR",  CF_USE1 },
  { "ZAC",  0 },
  { "ZALH", CF_USE1 },
  { "ZALS", CF_USE1 },
  // Auxiliary Register and Data Page Pointer Instructions
  { "LAR",  CF_USE1 },
  { "LARK", CF_USE1 },
  { "LARP", CF_USE1 },
  { "LDP",  CF_USE1 },
  { "LDPK", CF_USE1 },
  { "MAR",  0 }, // no memory access occurs, just ARP and AR change
  { "SAR",  CF_CHG1 },
  // T Register, P Register, and Multiply Instructions
  { "APAC", 0 },
  { "LT",   CF_USE1 },
  { "LTA",  CF_USE1 },
  { "LTD",  CF_USE1|CF_CHG1 }, // changes [Op1 + 1]!
  { "MPY",  CF_USE1 },
  { "MPYK", CF_USE1 },
  { "PAC",  0 },
  { "SPAC", 0 },
  // Branch/Call Instructions
  { "B",    CF_USE1|CF_JUMP|CF_STOP },
  { "BANZ", CF_USE1|CF_JUMP },
  { "BGEZ", CF_USE1|CF_JUMP },
  { "BGZ",  CF_USE1|CF_JUMP },
  { "BIOZ", CF_USE1|CF_JUMP },
  { "BLEZ", CF_USE1|CF_JUMP },
  { "BLZ",  CF_USE1|CF_JUMP },
  { "BNZ",  CF_USE1|CF_JUMP },
  { "BV",   CF_USE1|CF_JUMP },
  { "BZ",   CF_USE1|CF_JUMP },
  { "CALA", CF_CALL },
  { "CALL", CF_USE1|CF_CALL },
  { "RET",  CF_STOP },
  // Control Instructions
  { "DINT", 0 },
  { "EINT", 0 },
  { "LST",  CF_USE1 },
  { "NOP",  0 },
  { "POP",  0 },
  { "PUSH", 0 },
  { "ROVM", 0 },
  { "SOVM", 0 },
  { "SST",  CF_CHG1 }, // Operates in page 1 ONLY if direct
  // I/O and Data Memory Instructions
  { "DMOV", CF_CHG1 }, // changes [Op1 + 1]!
  { "IN",   CF_CHG1 },
  { "OUT",  CF_USE1 },
  { "TBLR", CF_CHG1 },
  { "TBLW", CF_USE1 },
};

CASSERT(qnumber(Instructions) == I__LAST);
