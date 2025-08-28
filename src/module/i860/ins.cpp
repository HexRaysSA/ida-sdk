/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },              // Unknown Operation
  //
  //      Intel 860 XP instructions
  //
  { "adds",       CF_USE1|CF_USE2|CF_CHG3         },              // Add Signed: o3 <- o1 + o2
  { "addu",       CF_USE1|CF_USE2|CF_CHG3         },              // Add Unsigned: o3 <- o1 + o2
  { "and",        CF_USE1|CF_USE2|CF_CHG3         },              // Logical AND: o3 <- o1 & o2
  { "andh",       CF_USE1|CF_USE2|CF_CHG3         },              // Logical AND High: o3 <- (o1<<16) & o2
  { "andnot",     CF_USE1|CF_USE2|CF_CHG3         },              // Logical AND NOT: o3 <- (!o1) & o2
  { "andnoth",    CF_USE1|CF_USE2|CF_CHG3         },              // Logical AND NOT High: o3 <- (!(o1<<16)) & o3
  { "bc",         CF_USE1                         },              // Branch on CC
  { "bc.t",       CF_USE1                         },              // Branch on CC,Taken:\nif CC then execute 1 more intruction\n      jump to o1\nelse skip next instruction
  { "bla",        CF_USE1|CF_USE2|CF_CHG2|CF_USE3 },              // Branch on LCC and Add:\nLCC' <- boolean(o1+o2 < 0)\no2 += o1\nexecute 1 more instruction\nif LCC then\n  LCC <- LCC'\n  jump to o3\nelse LCC <- LCC'
  { "bnc",        CF_USE1                         },              // Branch on NOT CC
  { "bnc.t",      CF_USE1                         },              // Branch on NOT CC, Taken:\nif !CC then execute 1 more intruction\n      jump to o1\nelse skip next instruction
  { "br",         CF_USE1                         },              // Branch Direct Unconditionally:\nexec 1 more instruction, jump to o3
  { "bri",        CF_USE1|CF_JUMP                 },              // Branch Indirect Unconditionally
  { "bte",        CF_USE1|CF_USE2|CF_USE3         },              // Branch If Equal
  { "btne",       CF_USE1|CF_USE2|CF_USE3         },              // Branch If Not Equal
  { "call",       CF_USE1|CF_CALL                 },              // Call Subroutine
  { "calli",      CF_USE1|CF_JUMP|CF_CALL         },              // Call Indirect Subroutine
  { "fadd",       CF_USE1|CF_USE2|CF_CHG3         },              // Floating-Point Add
  { "faddp",      CF_USE1|CF_USE2|CF_CHG3         },              // Add With Pixel Merge
  { "faddz",      CF_USE1|CF_USE2|CF_CHG3         },              // Add With Z Merge
  { "famov",      CF_USE1|CF_CHG2                 },              // Floating-Point Adder Move
  { "fiadd",      CF_USE1|CF_USE2|CF_CHG3         },              // Long Integer Add
  { "fisub",      CF_USE1|CF_USE2|CF_CHG3         },              // Long Integer Subtract
  { "fix",        CF_USE1|CF_CHG2                 },              // Floating-Point to Integer Conversion
  { "fld",        CF_USE1|CF_CHG2                 },              // Floating-Point Load
  { "flush",      CF_USE1                         },              // Cache Flush
  { "fmlow.dd",   CF_USE1|CF_USE2|CF_CHG3         },              // Floating-Point Multiply Low
  { "fmul",       CF_USE1|CF_USE2|CF_CHG3         },              // Floating-Point Multiply
  { "form",       CF_USE1|CF_CHG2                 },              // Or with MERGE register: o2 <- o1 | MERGE; MERGE <- 0
  { "frcp",       CF_USE1|CF_CHG2                 },              // Floating-Point Reciprocal: o2 <- 1 / o1
  { "frsqr",      CF_USE1|CF_CHG2                 },              // Floating-Point Reciprocal Square Root: o2 <- 1 / sqrt(o1)
  { "fst",        CF_CHG1|CF_USE2                 },              // Floating-Point Reciprocal Store
  { "fsub",       CF_USE1|CF_USE2|CF_CHG3         },              // Floating-Point Subtract
  { "ftrunc",     CF_USE1|CF_CHG2                 },              // Floating-Point to Integer Conversion
  { "fxfr",       CF_USE1|CF_CHG2                 },              // Transfer F-P to Integer Register
  { "fzchkl",     CF_USE1|CF_USE2|CF_CHG3         },              // 32-bit Z-Buffer Check
  { "fzchks",     CF_USE1|CF_USE2|CF_CHG3         },              // 16-bit Z-Buffer Check
  { "introvr",    0                               },              // Software Trap on Integer Overflow
  { "ixfr",       CF_USE1|CF_CHG2                 },              // Transfer Integer to F-P Register
  { "ld.c",       CF_USE1|CF_CHG2                 },              // Load from Control Register
  { "ld",         CF_USE1|CF_CHG2                 },              // Load Integer
  { "ldint",      CF_USE1|CF_CHG2                 },              // Load Interrupt Vector
  { "ldio",       CF_USE1|CF_CHG2                 },              // Load I/O
  { "lock",       0                               },              // Begin Interlocked Sequence
  { "or",         CF_USE1|CF_USE2|CF_CHG3         },              // Logical OR
  { "orh",        CF_USE1|CF_USE2|CF_CHG3         },              // Logical OR High
  { "pfadd",      CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating-Point Add
  { "pfaddp",     CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Add with Pixel Merge
  { "pfaddz",     CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Add with Z Merge
  { "pfamov",     CF_USE1|CF_CHG2                 },              // Pipelined Floating-Point Adder Move
  { "pfeq",       CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating Point Equal Compare
  { "pfgt",       CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating Point Greater-Than Compare
  { "pfiadd",     CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Long Integer Add
  { "pfisub",     CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Long Integer Subtract
  { "pfix",       CF_USE1|CF_CHG2                 },              // Pipelined Floating-Point to Integer Conversion
  { "pfld",       CF_USE1|CF_CHG2                 },              // Pipelined Floating-Point Load
  { "pfle",       CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating Point Less-Than or Equal Compare
  { "pfmul",      CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating-Point Multiply
  { "pfmul3.dd",  CF_USE1|CF_USE2|CF_CHG3         },              // Three-Stage Pipelined Floating-Point Multiply
  { "pform",      CF_USE1|CF_CHG2                 },              // Pipelined Or with MERGE register
  { "pfsub",      CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined Floating-Point Subtract
  { "pftrunc",    CF_USE1|CF_CHG2                 },              // Pipelined Floating-Point to Integer Conversion
  { "pfzchkl",    CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined 32-bit Z-Buffer Check
  { "pfzchks",    CF_USE1|CF_USE2|CF_CHG3         },              // Pipelined 16-bit Z-Buffer Check
  { "pst.d",      CF_CHG1|CF_USE2                 },              // Pixel Store
  { "scyc",       CF_USE1                         },              // Special Cycles
  { "shl",        CF_USE1|CF_USE2|CF_CHG3         },              // Shift Left
  { "shr",        CF_USE1|CF_USE2|CF_CHG3         },              // Shift Right
  { "shra",       CF_USE1|CF_USE2|CF_CHG3         },              // Shift Right Arithmetic
  { "shrd",       CF_USE1|CF_USE2|CF_CHG3         },              // Shift Right Double
  { "st.c",       CF_USE1|CF_CHG2                 },              // Store to Control Register
  { "st",         CF_USE1|CF_CHG2                 },              // Store Integer
  { "stio",       CF_USE1|CF_USE2                 },              // Store I/O
  { "subs",       CF_USE1|CF_USE2|CF_CHG3         },              // Subtract Signed: o3 <- o1 - o2
  { "subu",       CF_USE1|CF_USE2|CF_CHG3         },              // Subtract Unsigned: o3 <- o1 - o2
  { "trap",       CF_USE1|CF_USE2|CF_CHG3         },              // Software Trap
  { "unlock",     0                               },              // End Interlocked Sequence
  { "xor",        CF_USE1|CF_USE2|CF_CHG3         },              // Logical Exclusive OR: o3 <- o1 ^ o2
  { "xorh",       CF_USE1|CF_USE2|CF_CHG3         },              // Logical Exclusive OR High: o3 <- (o1<<16) ^ o2
  //
  // iNTEL 860 XP Pipelined F-P instructions
  //
  { "r2p1",       CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,o2)   A(o1,  Mres) T:No  K:No
  { "r2pt",       CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,o2)   A(T,   Mres) T:No  K:Yes
  { "r2ap1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,o2)   A(o1,  Ares) T:Yes K:No
  { "r2apt",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,o2)   A(T,   Ares) T:Yes K:Yes
  { "i2p1",       CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,o2)   A(o1,  Mres) T:No  K:No
  { "i2pt",       CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,o2)   A(T,   Mres) T:No  K:Yes
  { "i2ap1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,o2)   A(o1,  Ares) T:Yes K:No
  { "i2apt",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,o2)   A(T,   Ares) T:Yes K:Yes
  { "rat1p2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,Ares) A(o1,  o2)   T:Yes K:No
  { "m12apm",     CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(o1,o2)   A(Ares,Mres) T:No  K:No
  { "ra1p2",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KR,Ares) A(o1,  o2)   T:No  K:No
  { "m12ttpa",    CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(o1,o2)   A(T,   Ares) T:Yes K:No
  { "iat1p2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,Ares) A(o1,  o2)   T:Yes K:No
  { "m12tpm",     CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(o1,o2)   A(T,   Mres) T:No  K:No
  { "ia1p2",      CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(KI,Ares) A(o1,  o2)   T:No  K:No
  { "m12tpa",     CF_USE1|CF_USE2|CF_CHG3         },              // PFAM: M(o1,o2)   A(T,   Ares) T:No  K:No
  { "r2s1",       CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,o2)   A(o1,  Mres) T:No  K:No
  { "r2st",       CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,o2)   A(T,   Mres) T:No  K:Yes
  { "r2as1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,o2)   A(o1,  Ares) T:Yes K:No
  { "r2ast",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,o2)   A(T,   Ares) T:Yes K:Yes
  { "i2s1",       CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,o2)   A(o1,  Mres) T:No  K:No
  { "i2st",       CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,o2)   A(T,   Mres) T:No  K:Yes
  { "i2as1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,o2)   A(o1,  Ares) T:Yes K:No
  { "i2ast",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,o2)   A(T,   Ares) T:Yes K:Yes
  { "rat1s2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,Ares) A(o1,  o2)   T:Yes K:No
  { "m12asm",     CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(o1,o2)   A(Ares,Mres) T:No  K:No
  { "ra1s2",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KR,Ares) A(o1,  o2)   T:No  K:No
  { "m12ttsa",    CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(o1,o2)   A(T,   Ares) T:Yes K:No
  { "iat1s2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,Ares) A(o1,  o2)   T:Yes K:No
  { "m12tsm",     CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(o1,o2)   A(T,   Mres) T:No  K:No
  { "ia1s2",      CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(KI,Ares) A(o1,  o2)   T:No  K:No
  { "m12tsa",     CF_USE1|CF_USE2|CF_CHG3         },              // PFSM: M(o1,o2)   A(T,   Ares) T:No  K:No
  { "mr2p1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,o2)   A(o1,  Mres) T:No  K:No
  { "mr2pt",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,o2)   A(T,   Mres) T:No  K:Yes
  { "mr2mp1",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,o2)   A(o1,  Mres) T:Yes K:No
  { "mr2mpt",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,o2)   A(T,   Mres) T:Yes K:Yes
  { "mi2p1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,o2)   A(o1,  Mres) T:No  K:No
  { "mi2pt",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,o2)   A(T,   Mres) T:No  K:Yes
  { "mi2mp1",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,o2)   A(o1,  Mres) T:Yes K:No
  { "mi2mpt",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,o2)   A(T,   Mres) T:Yes K:Yes
  { "mrmt1p2",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,Mres) A(o1,  o2)   T:Yes K:No
  { "mm12mpm",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(o1,o2)   A(Mres,Mres) T:No  K:No
  { "mrm1p2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KR,Mres) A(o1,  o2)   T:No  K:No
  { "mm12ttpm",   CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(o1,o2)   A(T,   Mres) T:Yes K:No
  { "mimt1p2",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,Mres) A(o1,  o2)   T:Yes K:No
  { "mm12tpm",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(o1,o2)   A(T,   Mres) T:No  K:No
  { "mim1p2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMAM: M(KI,Mres) A(o1,  o2)   T:No  K:No
  { "mr2s1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,o2)   A(o1,  Mres) T:No  K:No
  { "mr2st",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,o2)   A(T,   Mres) T:No  K:Yes
  { "mr2ms1",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,o2)   A(o1,  Mres) T:Yes K:No
  { "mr2mst",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,o2)   A(T,   Mres) T:Yes K:Yes
  { "mi2s1",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,o2)   A(o1,  Mres) T:No  K:No
  { "mi2st",      CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,o2)   A(T,   Mres) T:No  K:Yes
  { "mi2ms1",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,o2)   A(o1,  Mres) T:Yes K:No
  { "mi2mst",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,o2)   A(T,   Mres) T:Yes K:Yes
  { "mrmt1s2",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,Mres) A(o1,  o2)   T:Yes K:No
  { "mm12msm",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(o1,o2)   A(Mres,Mres) T:No  K:No
  { "mrm1s2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KR,Mres) A(o1,  o2)   T:No  K:No
  { "mm12ttsm",   CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(o1,o2)   A(T,   Mres) T:Yes K:No
  { "mimt1s2",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,Mres) A(o1,  o2)   T:Yes K:No
  { "mm12tsm",    CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(o1,o2)   A(T,   Mres) T:No  K:No
  { "mim1s2",     CF_USE1|CF_USE2|CF_CHG3         },              // PFMSM: M(KI,Mres) A(o1,  o2)   T:No  K:No

};

CASSERT(qnumber(Instructions) == I860_last);
