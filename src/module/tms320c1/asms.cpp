// $Id: asms.cpp,v 1.2 2000/11/06 22:11:16 jeremy Exp $
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
//     TMS320C1X assembler types and implementations
//
#include "../idaidp.hpp"

#include "asms.hpp"

//////////////////////////////////////////////////////////////////////////////
// TI Assembler
//////////////////////////////////////////////////////////////////////////////
const asm_t tiAssembler =
{
                     // Assembler features:
  AS_ASCIIC          //   ASCII directive support C escape sequences
 |AS_ASCIIZ          //   ASCII directive appends implicit null character
 |ASH_HEXF3          //   Hexidecimal constant format: 0x<nn...>
 |ASD_DECF0          //   Decimal constant format    : 34
 |ASO_OCTF1          //   Octal format               : 0<nn..>
 |ASB_BINF0          //   Binary format              : <nn...>b
 |AS_ONEDUP,         //   One array directive per line
  0,                 // Assembler-defined flags (for local use)
  "TI",              // Assembler name
  0,                 // Help screen number
  nullptr,              // Array of automatically generated header lines
  ".org",            // Origin directive
  nullptr,              // End directive
  ";",               // Comment string
  '"',               // ASCII string delimiter
  '\'',              // ASCII character constant delimiter
  "\"",              // Characters that cannot appear inside a string
  ".asciiz",         // ASCII string     directive
  ".byte",           // Byte (8-bit)     directive
  ".short",          // Word (16-bit)    directive
  ".word",           // Dword (32-bit)   directive
  ".quad",           // Qword (64-bit)   directive
  nullptr,              // Oword (128-bit)  directive
  ".float",          // IEEE single      directive
  ".double",         // IEEE double      directive
  nullptr,              // IEEE tbyte       directive
  nullptr,              // IEEE packed-real directive
  ".fill #d, #sb, #v",// Array (dup) directive
  ".bss",            // BSS directive
  nullptr,              // EQU directive to use if AS_UNEQU is set
  nullptr,              // Segment operand keyword
  ".",               // Symbol for current assembly location
  nullptr,              // Function header generating function
  nullptr,              // Function footer generating function
  ".global",         // Public name keyword
  nullptr,              // Weak keyword
  ".extern",         // Extern keyword
  ".comm",           // Communal keyword
  nullptr,              // 'get_type_name()' function
  ".align",          // Align keyword
  '(',               // Left delimiter for complex expressions
  ')',               // Right delimiter for complex expressions
  "%",               // Remainder (MOD) operator
  "&",               // Bit-wise   AND  operator
  "|",               // Bit-wise   OR   operator
  "^",               // Bit-wise   XOR  operator
  "~",               // Bit-wise   NOT  operator
  "<<",              // Left shift operator
  ">>",              // Right shift operator
  nullptr,              // Sizeof() keyword
};

const asm_t *const tms320c1x_Assemblers[] =
{
  &tiAssembler,
  nullptr
};
