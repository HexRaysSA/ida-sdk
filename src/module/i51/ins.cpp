/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation
  { "acall",      CF_USE1|CF_CALL                 },      // Absolute Call
  { "add",        CF_USE1|CF_USE2|CF_CHG1         },      // Add Second Operand to Acc
  { "addc",       CF_USE1|CF_USE2|CF_CHG1         },      // Add Second Operand to Acc with carry
  { "ajmp",       CF_USE1|CF_STOP                 },      // Absolute Jump
  { "anl",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND (op1 &= op2)
  { "cjne",       CF_USE1|CF_USE2|CF_USE3         },      // Compare Operands and JNE
  { "clr",        CF_CHG1                         },      // Clear Operand (0)
  { "cpl",        CF_USE1|CF_CHG1                 },      // Complement Operand
  { "da",         CF_USE1|CF_CHG1                 },      // Decimal Adjust Accumulator
  { "dec",        CF_USE1|CF_CHG1                 },      // Decrement Operand
  { "div",        CF_USE1|CF_CHG1                 },      // Divide Acc by B
  { "djnz",       CF_USE1|CF_CHG1|CF_USE2         },      // Decrement Operand and JNZ
  { "inc",        CF_USE1|CF_CHG1                 },      // Increment Operand
  { "jb",         CF_USE1|CF_USE2                 },      // Jump if Bit is set
  { "jbc",        CF_USE1|CF_USE2                 },      // Jump if Bit is set & clear Bit
  { "jc",         CF_USE1                         },      // Jump if Carry is set
  { "jmp",        CF_USE1|CF_STOP|CF_JUMP         },      // Jump indirect relative to Data Pointer
  { "jnb",        CF_USE1|CF_USE2                 },      // Jump if Bit is clear
  { "jnc",        CF_USE1                         },      // Jump if Carry is clear
  { "jnz",        CF_USE1                         },      // Jump if Acc is not zero
  { "jz",         CF_USE1                         },      // Jump if Acc is zero
  { "lcall",      CF_USE1|CF_CALL                 },      // Long Subroutine Call
  { "ljmp",       CF_USE1|CF_STOP                 },      // Long Jump
  { "mov",        CF_CHG1|CF_USE2                 },      // Move (Op1 <- Op2)
  { "movc",       CF_CHG1|CF_USE2                 },      // Move code byte relative to second op to Acc
  { "movx",       CF_CHG1|CF_USE2                 },      // Move from/to external RAM
  { "mul",        CF_USE1|CF_CHG1                 },      // Multiply Acc by B
  { "nop",        0                               },      // No operation
  { "orl",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical OR (op1 |= op2)
  { "pop",        CF_CHG1                         },      // Pop  from Stack and put in Direct RAM
  { "push",       CF_USE1                         },      // Push from Direct RAM to Stack
  { "ret",        CF_STOP                         },      // Return from subroutine
  { "reti",       CF_STOP                         },      // Return from Interrupt
  { "rl",         CF_USE1|CF_CHG1                 },      // Rotate Acc left
  { "rlc",        CF_USE1|CF_CHG1                 },      // Rotate Acc left through Carry
  { "rr",         CF_USE1|CF_CHG1                 },      // Rotate Acc right
  { "rrc",        CF_USE1|CF_CHG1                 },      // Rotate Acc right through Carry
  { "setb",       CF_CHG1                         },      // Set Direct Bit
  { "sjmp",       CF_USE1|CF_STOP                 },      // Short jump
  { "subb",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Second Operand from Acc with Borrow
  { "swap",       CF_USE1|CF_CHG1                 },      // Swap nibbles of Acc
  { "xch",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // Exchange Operands
  { "xchd",       CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // Exchange Digit in Acc with Indirect RAM
  { "xrl",        CF_USE1|CF_USE2|CF_CHG1         },      // Exclusive OR (op1 ^= op2)

  // 80251 instructions

  { "jsle",       CF_USE1                         },      // Jump if less than or equal (signed)
  { "jsg",        CF_USE1                         },      // Jump if greater than (signed)
  { "jle",        CF_USE1                         },      // Jump if less than or equal
  { "jg",         CF_USE1                         },      // Jump if greater than
  { "jsl",        CF_USE1                         },      // Jump if less than (signed)
  { "jsge",       CF_USE1                         },      // Jump if greater than or equal (signed)
  { "je",         CF_USE1                         },      // Jump if equal
  { "jne",        CF_USE1                         },      // Jump if not equal
  { "trap",       0                               },      // Trap
  { "ejmp",       CF_USE1|CF_STOP                 },      // Extended jump
  { "ecall",      CF_USE1|CF_CALL                 },      // Extended call
  { "eret",       CF_STOP                         },      // Extended return
  { "movh",       CF_CHG1|CF_USE2                 },      // Move immediate 16-bit data to the high word of a dword (double-word) register
  { "movz",       CF_CHG1|CF_USE2                 },      // Move 8-bit register to 16-bit register with zero extension
  { "movs",       CF_CHG1|CF_USE2                 },      // Move 8-bit register to 16-bit register with sign extension
  { "srl",        CF_CHG1                         },      // Shift logical right by 1 bit
  { "sra",        CF_CHG1                         },      // Shift arithmetic right by 1 bit
  { "sll",        CF_CHG1                         },      // Shift logical left by 1 bit
  { "sub",        CF_CHG1|CF_USE2                 },      // Subtract
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare

  // 51mx instructions
  { "emov",       CF_CHG1|CF_USE2                 },      // Move (Op1 <- Op2)

};

CASSERT(qnumber(Instructions) == I51_last);
