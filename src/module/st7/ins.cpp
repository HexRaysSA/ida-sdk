/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st7.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },        // Unknown Operation

  { "adc",        CF_CHG1|CF_USE1|CF_USE2         },        // Add with Carry
  { "add",        CF_CHG1|CF_USE1|CF_USE2         },        // Addition
  { "and",        CF_CHG1|CF_USE1|CF_USE2         },        // Logical And
  { "bcp",        CF_USE1|CF_USE2                 },        // Bit compare
  { "bres",       CF_CHG1|CF_USE1                 },        // Bit Reset
  { "bset",       CF_CHG1|CF_USE1                 },        // Bit Set
  { "btjf",       CF_USE1|CF_USE2|CF_USE3         },        // Jump if bit is false
  { "btjt",       CF_USE1|CF_USE2|CF_USE3         },        // Jump if bit is true
  { "call",       CF_USE1|CF_CALL                 },        // Call subroutine
  { "callr",      CF_USE1|CF_CALL                 },        // Call subroutine relative
  { "clr",        CF_CHG1                         },        // Clear
  { "cp",         CF_USE1|CF_USE2                 },        // Arithmetic Compare
  { "cpl",        CF_USE1|CF_CHG1                 },        // One Complement
  { "dec",        CF_USE1|CF_CHG1                 },        // Decrement
  { "halt",       0                               },        // Halt
  { "iret",       CF_STOP                         },        // Interrupt routine return
  { "inc",        CF_USE1|CF_CHG1                 },        // Increment
  { "jp",         CF_USE1|CF_STOP                 },        // Absolute Jump
  { "jra",        CF_USE1|CF_STOP                 },        // Jump relative always
  { "jrt",        CF_USE1|CF_STOP                 },        // Jump relative
  { "jrf",        CF_USE1                         },        // Never jump
  { "jrih",       CF_USE1                         },        // Jump if Port INT pin = 1
  { "jril",       CF_USE1                         },        // Jump if Port INT pin = 0
  { "jrh",        CF_USE1                         },        // Jump if H = 1
  { "jrnh",       CF_USE1                         },        // Jump if H = 0
  { "jrm",        CF_USE1                         },        // Jump if I = 1
  { "jrnm",       CF_USE1                         },        // Jump if I = 0
  { "jrmi",       CF_USE1                         },        // Jump if N = 1 (minus)
  { "jrpl",       CF_USE1                         },        // Jump if N = 0 (plus)
  { "jreq",       CF_USE1                         },        // Jump if Z = 1 (equal)
  { "jrne",       CF_USE1                         },        // Jump if Z = 0 (not equal)
  { "jrc",        CF_USE1                         },        // Jump if C = 1
  { "jrnc",       CF_USE1                         },        // Jump if C = 0
  { "jrult",      CF_USE1                         },        // Jump if C = 1
  { "jruge",      CF_USE1                         },        // Jump if C = 0
  { "jrugt",      CF_USE1                         },        // Jump if ( C + Z = 0 )
  { "jrule",      CF_USE1                         },        // Jump if ( C + Z = 1 )
  { "ld",         CF_CHG1|CF_USE2                 },        // Load
  { "mul",        CF_CHG1|CF_USE1|CF_USE2         },        // Multiply
  { "neg",        CF_USE1|CF_CHG1                 },        // Negate
  { "nop",        0                               },        // No Operation
  { "or",         CF_CHG1|CF_USE1|CF_USE2         },        // OR Operation
  { "pop",        CF_CHG1                         },        // Pop from the Stack
  { "push",       CF_USE1                         },        // Push onto the Stack
  { "rcf",        0                               },        // Reset carry flag
  { "ret",        CF_STOP                         },        // Subroutine Return
  { "rim",        0                               },        // Enable Interrupts
  { "rlc",        CF_USE1|CF_CHG1                 },        // Rotate left true
  { "rrc",        CF_USE1|CF_CHG1                 },        // Rotate right true
  { "rsp",        0                               },        // Reset Stack Pointer
  { "sbc",        CF_CHG1|CF_USE1|CF_USE2         },        // Subtract with Carry
  { "scf",        0                               },        // Set carry flag
  { "sim",        0                               },        // Disable Interrupts
  { "sla",        CF_USE1|CF_CHG1                 },        // Shift left Arithmetic
  { "sll",        CF_USE1|CF_CHG1                 },        // Shift left Logic
  { "srl",        CF_USE1|CF_CHG1                 },        // Shift right Logic
  { "sra",        CF_USE1|CF_CHG1                 },        // Shift right Arithmetic
  { "sub",        CF_CHG1|CF_USE1|CF_USE2         },        // Substraction
  { "swap",       CF_USE1|CF_CHG1                 },        // SWAP nibbles
  { "tnz",        CF_USE1                         },        // Test for Neg & Zero
  { "trap",       0                               },        // S/W trap
  { "wfi",        0                               },        // Wait for Interrupt
  { "xor",        CF_CHG1|CF_USE1|CF_USE2         },        // Exclusive OR
};

CASSERT(qnumber(Instructions) == ST7_last);
