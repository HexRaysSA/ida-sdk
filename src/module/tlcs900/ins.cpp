/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

// Attention!!! Word instruction must be followed
// byte instruction, used in ana.cpp
const instruc_t Instructions[] =
{
  { "",           0                               },      // Unknown Operation
  { "LD",         CF_USE1|CF_CHG1|CF_USE2         },      // Load  data
  { "LDW",        CF_USE1|CF_CHG1|CF_USE2         },      // Load  data
  { "PUSH",       CF_USE1                         },      // Push data
  { "PUSHW",      CF_USE1                         },      // Push data
  { "POP",        CF_USE1|CF_CHG1                 },      // pop data
  { "POPW",       CF_USE1|CF_CHG1                 },      // pop data
  { "LDA",        CF_USE1|CF_CHG1|CF_USE2         },      // load data from mem
  { "LDAR",       CF_USE1|CF_CHG1|CF_USE2         },      // load data from mem rel.
  { "EX",         CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // xchg
  { "MIRR",       CF_USE1|CF_CHG1                 },      // mirror
  { "LDI",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDIW",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDIR",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDIRW",      CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDD",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDDW",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDDR",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "LDDRW",      CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // copy
  { "CPI",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // compare
  { "CPIR",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // compare
  { "CPD",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // compare
  { "CPDR",       CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // compare
  { "ADD",        CF_USE1|CF_CHG1|CF_USE2         },
  { "ADDW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "ADC",        CF_USE1|CF_CHG1|CF_USE2         },
  { "ADCW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "SUB",        CF_USE1|CF_CHG1|CF_USE2         },
  { "SUBW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "SBC",        CF_USE1|CF_CHG1|CF_USE2         },
  { "SBCW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "CP",         CF_USE1|CF_USE2                 },      // cmp
  { "CPW",        CF_USE1|CF_USE2                 },      // cmp
  { "INC",        CF_USE1|CF_USE2|CF_CHG2         },
  { "INCW",       CF_USE1|CF_USE2|CF_CHG2         },
  { "DEC",        CF_USE1|CF_USE2|CF_CHG2         },
  { "DECW",       CF_USE1|CF_USE2|CF_CHG2         },
  { "NEG",        CF_USE1|CF_CHG1                 },
  { "EXTZ",       CF_USE1|CF_CHG1                 },
  { "EXTS",       CF_USE1|CF_CHG1                 },
  { "DAA",        CF_USE1|CF_CHG1                 },
  { "PAA",        CF_USE1|CF_CHG1                 },
  { "CPL",        CF_USE1|CF_CHG1                 },
  { "MUL",        CF_USE1|CF_CHG1|CF_USE2         },
  { "MULS",       CF_USE1|CF_CHG1|CF_USE2         },
  { "DIV",        CF_USE1|CF_CHG1|CF_USE2         },
  { "DIVS",       CF_USE1|CF_CHG1|CF_USE2         },
  { "MULA",       CF_USE1|CF_CHG1                 },      // rr+=(XDE)*(XHL--)
  { "MINC1",      CF_USE1|CF_USE2|CF_CHG2         },
  { "MINC2",      CF_USE1|CF_USE2|CF_CHG2         },
  { "MINC4",      CF_USE1|CF_USE2|CF_CHG2         },
  { "MDEC1",      CF_USE1|CF_USE2|CF_CHG2         },
  { "MDEC2",      CF_USE1|CF_USE2|CF_CHG2         },
  { "MDEC4",      CF_USE1|CF_USE2|CF_CHG2         },
  { "AND",        CF_USE1|CF_CHG1|CF_USE2         },
  { "ANDW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "OR",         CF_USE1|CF_CHG1|CF_USE2         },
  { "ORW",        CF_USE1|CF_CHG1|CF_USE2         },
  { "XOR",        CF_USE1|CF_CHG1|CF_USE2         },
  { "XORW",       CF_USE1|CF_CHG1|CF_USE2         },
  { "LDCF",       CF_USE1|CF_USE2                 },
  { "STCF",       CF_USE1|CF_USE2|CF_CHG2         },
  { "ANDCF",      CF_USE1|CF_USE2                 },
  { "ORCF",       CF_USE1|CF_USE2                 },
  { "XORCF",      CF_USE1|CF_USE2                 },
  { "RCF",        0                               },
  { "SCF",        0                               },
  { "CCF",        0                               },
  { "ZCF",        0                               },
  { "BIT",        CF_USE1|CF_USE2                 },
  { "RES",        CF_USE1|CF_USE2|CF_CHG2         },
  { "SET",        CF_USE1|CF_USE2|CF_CHG2         },
  { "CHG",        CF_USE1|CF_USE2|CF_CHG2         },
  { "TSET",       CF_USE1|CF_USE2|CF_CHG2         },
  { "BS1F",       CF_USE1|CF_CHG1|CF_USE2         },
  { "BS1B",       CF_USE1|CF_CHG1|CF_USE2         },
  { "NOP",        0                               },
  { "EI",         CF_USE1                         },
  { "DI",         0                               },
  { "SWI",        CF_USE1|CF_CALL                 },      // interrupt
  { "HALT",       CF_STOP                         },
  { "LDC",        CF_USE1|CF_USE2                 },      // actually changes
  { "LDX",        CF_USE1|CF_CHG1|CF_USE2         },
  { "LINK",       CF_USE1|CF_CHG1|CF_USE2|CF_HLL  },
  { "UNLK",       CF_USE1|CF_CHG1|CF_HLL          },
  { "LDF",        CF_USE1                         },      // set reg bank
  { "INCF",       0                               },
  { "DECF",       0                               },
  { "SCC",        CF_USE1|CF_USE2|CF_CHG2         },
  { "RLC",        CF_USE1|CF_USE2|CF_CHG2         },
  { "RLC",        CF_USE1|CF_CHG1                 },
  { "RLCW",       CF_USE1|CF_CHG2                 },
  { "RRC",        CF_USE1|CF_USE2|CF_CHG2         },
  { "RRC",        CF_USE1|CF_CHG1                 },
  { "RRCW",       CF_USE1|CF_CHG2                 },
  { "RL",         CF_USE1|CF_USE2|CF_CHG2         },
  { "RL",         CF_USE1|CF_CHG1                 },
  { "RLW",        CF_USE1|CF_CHG2                 },
  { "RR",         CF_USE1|CF_USE2|CF_CHG2         },
  { "RR",         CF_USE1|CF_CHG1                 },
  { "RRW",        CF_USE1|CF_CHG2                 },
  { "SLA",        CF_USE1|CF_USE2|CF_CHG2         },
  { "SLA",        CF_USE1|CF_CHG1                 },
  { "SLAW",       CF_USE1|CF_CHG2                 },
  { "SRA",        CF_USE1|CF_USE2|CF_CHG2         },
  { "SRA",        CF_USE1|CF_CHG1                 },
  { "SRAW",       CF_USE1|CF_CHG2                 },
  { "SLL",        CF_USE1|CF_USE2|CF_CHG2         },
  { "SLL",        CF_USE1|CF_CHG1                 },
  { "SLLW",       CF_USE1|CF_CHG2                 },
  { "SRL",        CF_USE1|CF_USE2|CF_CHG2         },
  { "SRL",        CF_USE1|CF_CHG1                 },
  { "SRLW",       CF_USE1|CF_CHG2                 },
  { "RLD",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },
  { "RRD",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },
  { "JP",         CF_USE1|CF_JUMP|CF_STOP         },
  { "JP",         CF_USE1|CF_USE2|CF_JUMP         },
  { "JR",         CF_USE1|CF_USE2|CF_JUMP|CF_STOP },
  { "JR",         CF_USE1|CF_USE2|CF_JUMP         },
  { "JRL",        CF_USE1|CF_USE2|CF_JUMP|CF_STOP },
  { "JRL",        CF_USE1|CF_USE2|CF_JUMP         },
  { "CALL",       CF_USE1|CF_USE2|CF_CALL         },
  { "CALR",       CF_USE1|CF_CALL                 },
  { "DJNZ",       CF_USE1|CF_CHG1|CF_USE2|CF_JUMP },
  { "RET",        CF_STOP                         },
  { "RET",        CF_USE1                         },
  { "RETD",       CF_USE1|CF_STOP                 },
  { "RETI",       CF_STOP|CF_USE1                 },
  { "MAX",        0                               },      // from IAR
  { "NORMAL",     0                               }       // from IAR
};

CASSERT(qnumber(Instructions) == T900_last);
