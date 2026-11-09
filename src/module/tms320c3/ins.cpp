/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c3x.hpp"


const struct instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation
  { "absf",       CF_USE1|CF_CHG2                 },      // Absolute value of a floating-point number
  { "absi",       CF_USE1|CF_CHG2                 },      // Absolute value of an integer
  { "addc",       CF_USE1|CF_USE2|CF_CHG2         },      // Add integers with carry
  { "addf",       CF_USE1|CF_USE2|CF_CHG2         },      // Add Floating-Point Values
  { "addi",       CF_USE1|CF_USE2|CF_CHG2         },      // Add Integer
  { "and",        CF_USE1|CF_USE2|CF_CHG2         },      // Bitwise-Logical AND
  { "andn",       CF_USE1|CF_USE2|CF_CHG2         },      // Bitwise-Logical AND With Complement
  { "ash",        CF_USE1|CF_USE2|CF_CHG2|CF_SHFT },      // Arithmetic Shift
  { "cmpf",       CF_USE1|CF_USE2                 },      // Compare Floating-Point Value
  { "cmpi",       CF_USE1|CF_USE2                 },      // Compare Integer
  { "fix",        CF_USE1|CF_CHG2                 },      // Floating-Point-to-Integer Conversion
  { "float",      CF_USE1|CF_CHG2                 },      // Integer-to-Floating-Point Conversion
  { "idle",       CF_STOP                         },      // Idle Until Interrupt
  { "idle2",      CF_STOP                         },      // Low-Power Idle
  { "lde",        CF_USE1|CF_CHG2                 },      // Load Floating-Point Exponent
  { "ldf",        CF_USE1|CF_CHG2                 },      // Load Floating-Point Value
  { "ldfi",       CF_USE1|CF_CHG2                 },      // Load Floating-Point Value, Interlocked
  { "ldi",        CF_USE1|CF_CHG2                 },      // Load Integer
  { "ldii",       CF_USE1|CF_CHG2                 },      // Load Integer, Interlocked
  { "ldm",        CF_USE1|CF_CHG2                 },      // Load Floating-Point Mantissa
  { "lsh",        CF_USE1|CF_USE2|CF_CHG2|CF_SHFT },      // Logical Shift
  { "mpyf",       CF_USE1|CF_USE2|CF_CHG2         },      // Multiply Floating-Point Value
  { "mpyi",       CF_USE1|CF_USE2|CF_CHG2         },      // Multiply Integer
  { "negb",       CF_USE1|CF_CHG2                 },      // Negative Integer With Borrow
  { "negf",       CF_USE1|CF_CHG2                 },      // Negate Floating-Point Value
  { "negi",       CF_USE1|CF_CHG2                 },      // Negate Integer
  { "nop",        0                               },      // No Operation
  { "norm",       CF_USE1|CF_CHG2                 },      // Normalize
  { "not",        CF_USE1|CF_CHG2                 },      // Bitwise-Logical Complement
  { "pop",        CF_CHG1                         },      // Pop Integer
  { "popf",       CF_CHG1                         },      // Pop Floating-Point Value
  { "push",       CF_USE1                         },      // PUSH Integer
  { "pushf",      CF_USE1                         },      // PUSH Floating-Point Value
  { "or",         CF_USE1|CF_USE2|CF_CHG2         },      // Bitwise-Logical OR
  { "lopower",    0                               },      // Divide Clock by 16
  { "maxspeed",   0                               },      // Restore Clock to Regular Speed
  { "rnd",        CF_USE1|CF_CHG2                 },      // Round Floating-Point Value
  { "rol",        CF_USE1|CF_CHG1                 },      // Rotate Left
  { "rolc",       CF_USE1|CF_CHG1                 },      // Rotate Left Through Carry
  { "ror",        CF_USE1|CF_CHG1                 },      // Rotate Right
  { "rorc",       CF_USE1|CF_CHG1                 },      // Rotate Right Through Carry
  { "rpts",       CF_USE1                         },      // Repeat Single Instruction
  { "stf",        CF_USE1|CF_CHG2                 },      // Store Floating-Point Value
  { "stfi",       CF_USE1|CF_CHG2                 },      // Store Floating-Point Value, Interlocked
  { "sti",        CF_USE1|CF_CHG2                 },      // Store Integer
  { "stii",       CF_USE1|CF_CHG2                 },      // Store Integer, Interlocked
  { "sigi",       0                               },      // Signal, Interlocked
  { "subb",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Integer With Borrow
  { "subc",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Integer Conditionally
  { "subf",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Floating-Point Value
  { "subi",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Integer
  { "subrb",      CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Reverse Integer With Borrow
  { "subrf",      CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Reverse Floating-Point Value
  { "subri",      CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Reverse Integer
  { "tstb",       CF_USE1|CF_USE2                 },      // Test Bit Fields
  { "xor",        CF_USE1|CF_USE2|CF_CHG2         },      // Bitwise-Exclusive OR
  { "iack",       0                               },      // Interrupt acknowledge
  { "addc3",      CF_USE1|CF_USE2|CF_CHG3         },      // Add integers with carry (3-operand)
  { "addf3",      CF_USE1|CF_USE2|CF_CHG3         },      // Add floating-point values (3-operand)
  { "addi3",      CF_USE1|CF_USE2|CF_CHG3         },      // Add integers (3 operand)
  { "and3",       CF_USE1|CF_USE2|CF_CHG3         },      // Bitwise-logical AND (3-operand)
  { "andn3",      CF_USE1|CF_USE2|CF_CHG3         },      // Bitwise-logical ANDN (3-operand)
  { "ash3",       CF_USE1|CF_USE2|CF_CHG3|CF_SHFT },      // Arithmetic shift (3-operand)
  { "cmpf3",      CF_USE1|CF_USE2                 },      // Compare floating-point values (3-operand)
  { "cmpi3",      CF_USE1|CF_USE2                 },      // Compare integers (3-operand)
  { "lsh3",       CF_USE1|CF_USE2|CF_CHG3|CF_SHFT },      // Logical shift (3-operand)
  { "mpyf3",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply floating-point value (3-operand)
  { "mpyi3",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply integers (3-operand)
  { "or3",        CF_USE1|CF_USE2|CF_CHG3         },      // Bitwise-logical OR (3-operand)
  { "subb3",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract integers with borrow (3-operand)
  { "subf3",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract floating-point values (3-operand)
  { "subi3",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract integers (3-operand)
  { "tstb3",      CF_USE1|CF_USE2                 },      // Test Bit Fields, 3-Operand
  { "xor3",       CF_USE1|CF_USE2|CF_CHG3         },      // Bitwise-Exclusive OR, 3-Operand
  { "ldf",        CF_USE1|CF_CHG2                 },      // Load floating-point value conditionally
  { "ldi",        CF_USE1|CF_CHG2                 },      // Load integer conditionally
  { "br",         CF_USE1|CF_JUMP|CF_STOP         },      // Branch unconditionally (standard)
  { "brd",        CF_USE1|CF_JUMP                 },      // Branch unconditionally (delayed)
  { "call",       CF_USE1|CF_CALL                 },      // Call subroutine
  { "rptb",       CF_USE1                         },      // Repeat block of instructions
  { "swi",        CF_JUMP                         },      // Software Interrupt
  { "b",          CF_USE1                         },      // Branch conditionally
  { "db",         CF_USE1|CF_USE2                 },      // Decrement and branch conditionally
  { "call",       CF_USE1|CF_CALL                 },      // Call subroutine conditionally
  { "trap",       CF_USE1|CF_JUMP                 },      // Trap Conditionally
  { "reti",       0                               },      // Return from interrupt conditionally
  { "rets",       0                               },      // Return from subroutine conditionally
  { "retiu",      CF_STOP                         },      // Return from interrupt unconditionally
  { "retsu",      CF_STOP                         },      // Return from subroutine unconditionally

  { "",           0                               },      // Pseudo insn (more accurate definition need)
  { "",           0                               },      // Pseudo insn (move to next index need)
};


CASSERT(qnumber(Instructions) == TMS320C3X_last);
