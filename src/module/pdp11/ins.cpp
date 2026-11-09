/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

const instruc_t Instructions[] =
{
  { "",       0       },      // Unknown Operation
  { "halt",   CF_STOP },  // Stop CPU
  { "wait",   0       },  // Wait Interrupt
  { "rti",    CF_STOP },  // Interrupt return
  { "bpt",    CF_CALL },  // Trap to Debugger
  { "iot",    CF_CALL },  // Trap to 20
  { "reset",  0       },  // Reset CPU and device
  { "rtt",    CF_STOP },  // Interrupt return and ignore Dbf flag
  { "mfpt", 0 },  // Load processor type
  { "jmp",  CF_USE1|CF_STOP     },  // Jmp
  { "rts",  CF_USE1|CF_STOP },  // Return into Subroutine
  { "spl", CF_USE1 },  // Set CPU Prioritet (>11-70)
  { "nop",  0       },  // Not operation
  { "clc",  0       },  // C=0
  { "clv",  0       },  // V=0
  { "clz",  0       },  // Z=0
  { "cln",  0       },  // N=0
  { "ccc",  0       },  // C=V=Z=N=0
  { "sec",  0       },  // C=1
  { "sev",  0       },  // V=1
  { "sez",  0       },  // Z=1
  { "sen",  0       },  // N=1
  { "scc",  0       },  // C=V=Z=N=1
  { "swab", CF_USE1|CF_CHG1   },  // Exchange byte
  { "br",   CF_USE1|CF_STOP   },  // Relative Jmp
  { "bne",  CF_USE1 },  // Jmp if Z=1
  { "beq",  CF_USE1 },  // Jmp if Z=0
  { "bge",  CF_USE1 },  // Jmp if N^V=0
  { "blt",  CF_USE1 },  // Jmp if N^V=1
  { "bgt",  CF_USE1 },  // Jmp if Z|(N^V)=0
  { "ble",  CF_USE1 },  // Jmp if Z|(N^V)=1
  { "jsr",  CF_USE2|CF_CALL|CF_CHG1 },  // Call
  { "clr",  CF_CHG1 },  // Clear
  { "com",  CF_USE1|CF_CHG1 },  // Reverse
  { "inc",  CF_USE1|CF_CHG1 },  // Increment
  { "dec",  CF_USE1|CF_CHG1 },  // Decrement
  { "neg",  CF_USE1|CF_CHG1 },  // op = -op
  { "adc",  CF_USE1|CF_CHG1 },  // Add with Carry
  { "sbc",  CF_USE1|CF_CHG1 },  // Substract with Carry
  { "tst",  CF_USE1 },  // Test
  { "ror",  CF_USE1|CF_CHG1 },  // Cyclic shift right
  { "rol",  CF_USE1|CF_CHG1 },  // Cyclic shift left
  { "asr",  CF_USE1|CF_CHG1 },  // Arifmetic shift right
  { "asl",  CF_USE1|CF_CHG1 },  // Arifmetic shift left
  { "mark", CF_USE1 },  // Return and empty stack
  { "mfpi", CF_USE1  },  // Load from previous instr. space
  { "mtpi", CF_USE1  },  // Store to previous instr. space
  { "sxt",  CF_CHG1 },  // N=>op
  { "mov",  CF_USE1|CF_CHG2     },  // Move
  { "cmp",  CF_USE1|CF_USE2     },  // Compare
  { "bit",  CF_USE1|CF_USE2     },  // Test bit's
  { "bic",  CF_USE1|CF_USE2|CF_CHG2 },  // Clear bit's
  { "bis",  CF_USE1|CF_USE2|CF_CHG2 },  // Set bit's
  { "add",  CF_USE1|CF_USE2|CF_CHG2 },  // Add
  { "sub",  CF_USE1|CF_USE2|CF_CHG2 },  // Substract
  { "mul",  CF_USE1|CF_USE2|CF_CHG2 },  // Multiple
  { "div",  CF_USE1|CF_USE2|CF_CHG2 },  // Divide
  { "ash",  CF_USE1|CF_USE2|CF_CHG2 },  // Multistep shift
  { "ashc", CF_USE1|CF_USE2|CF_CHG2 },  // Multistep shift 2 reg
  { "xor",  CF_USE1|CF_USE2|CF_CHG2 },  // Exclusive or
  { "fadd", CF_USE1|CF_CHG1 },  // Floating Add
  { "fsub", CF_USE1|CF_CHG1 },  // Floating Substract
  { "fmul", CF_USE1|CF_CHG1 },  // Floating Multiple
  { "fdiv", CF_USE1|CF_CHG1 },  // Floating Divide
  { "sob",  CF_USE2|CF_CHG1 },  //
  { "bpl",  CF_USE1 },  // Jmp if N=0
  { "bmi",  CF_USE1 },  // Jmp if N=1
  { "bhi",  CF_USE1 },  // Jmp if ( !C)&(!Z )=0
  { "blos", CF_USE1 },  // Jmp if C|Z=1
  { "bvc",  CF_USE1 },  // Jmp if V=0
  { "bvs",  CF_USE1 },  // Jmp if V=1
  { "bcc",  CF_USE1 },  // Jmp if C=0
  { "bcs",  CF_USE1 },  // Jmp if C=1
  { "emt",  CF_USE1|CF_CALL },  // Trap to system
  { "trap", CF_USE1|CF_CALL },  // Trap to user/compiler
  { "mtps", CF_USE1 },  // Store PSW
  { "mfpd", CF_USE1  },  // Load from previous data space
  { "mtpd", CF_USE1  },  // Store to previous data space
  { "mfps", CF_USE1 },  // Load PSW
  { "cfcc", 0 },  // Copy Cond.Codes into FPS to PSW
  { "setf", 0 },  // Set Float
  { "seti", 0 },  // Set Integer
  { "setd", 0 },  // Set Double
  { "setl", 0 },  // Set Long Integer
  { "ldfps", CF_CHG1 },  // Load FPS
  { "stfps", CF_USE1 },  // Store FPS
  { "stst", 0 },  // Load interrupt status
  { "clrd", CF_CHG1 },  // Clear
  { "tstd", CF_USE1 },  // Test
  { "absd", CF_USE1|CF_CHG1 },  // op = mod(op)
  { "negd", CF_USE1|CF_CHG1 },  // op = -op
  { "muld", CF_USE1|CF_USE2|CF_CHG2 },  // Multiple
  { "modd", CF_USE1|CF_USE2|CF_CHG2 },  // Load Int. part
  { "addd", CF_USE1|CF_USE2|CF_CHG2 },  // Add
  { "ldd", CF_USE1|CF_USE2|CF_CHG2 },  // Load Acc
  { "subd", CF_USE1|CF_USE2|CF_CHG2 },  // Substract
  { "cmpd", CF_USE1|CF_USE2 },  // Compare
  { "std", CF_USE1|CF_USE2|CF_CHG2 },  // Store Acc
  { "divd", CF_USE1|CF_USE2|CF_CHG2 },  // Divide
  { "stexp", CF_USE1 },  // Store exponent
  { "stcdi", CF_USE1|CF_CHG2 },  // Store and convert
  { "stcdf", CF_USE1|CF_CHG2 },  // Store and convert
  { "ldexp", CF_CHG1 },  // Load exponent
  { "ldcid", CF_USE2|CF_CHG1 },  // Load and convert
  { "ldcfd", CF_USE2|CF_CHG1 },  // Load and convert
  { "call",  CF_USE1|CF_CALL },  // Jsr PC,
  { "return",  CF_STOP },  // Rts PC
  { ".word",  0 },  // Complex Condition Codes
};

CASSERT(qnumber(Instructions) == pdp_last);
