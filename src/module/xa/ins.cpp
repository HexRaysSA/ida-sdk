/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },      // Unknown Operation
  { "add",        CF_USE1|CF_USE2|CF_CHG1         },      // Add Second Operand to Acc
  { "addc",       CF_USE1|CF_USE2|CF_CHG1         },      // Add Second Operand to Acc with carry
  { "adds",       CF_USE1|CF_USE2|CF_CHG1         },      // Add Second Operand to Acc
  { "and",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND (op1 &= op2)
  { "anl",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND Carry and Bit
  { "asl",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical shift left
  { "asr",        CF_USE1|CF_USE2|CF_CHG1         },      // Arithmetic shift left
  { "bcc",        CF_USE1                         },      // Branch if Carry clear
  { "bcs",        CF_USE1                         },      // Branch if Carry set
  { "beq",        CF_USE1                         },      // Branch if Zero
  { "bg",         CF_USE1                         },      // Branch if Greater than (unsigned)
  { "bge",        CF_USE1                         },      // Branch if Greater than or equal to (signed)
  { "bgt",        CF_USE1                         },      // Branch if Greater than (signed)
  { "bkpt",       0                               },      // Breakpoint
  { "bl",         CF_USE1                         },      // Branch if Less than or equal to (unsigned)
  { "ble",        CF_USE1                         },      // Branch if less than or equal to (signed)
  { "blt",        CF_USE1                         },      // Branch if less than (signed)
  { "bmi",        CF_USE1                         },      // Branch if negative
  { "bne",        CF_USE1                         },      // Branch if not equal
  { "bnv",        CF_USE1                         },      // Branch if no overflow
  { "bov",        CF_USE1                         },      // Branch if overflow flag
  { "bpl",        CF_USE1                         },      // Branch if positive
  { "br",         CF_USE1|CF_STOP|CF_JUMP         },      // Branch always
  { "call",       CF_USE1|CF_CALL                 },      // Call Subroutine
  { "cjne",       CF_USE1|CF_USE2|CF_USE3         },      // Compare Operands and JNE
  { "clr",        CF_CHG1                         },      // Clear Operand (0)
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare destination and source registers
  { "cpl",        CF_USE1|CF_CHG1                 },      // Complement Operand
  { "da",         CF_USE1|CF_CHG1                 },      // Decimal Adjust Accumulator
  { "div",        CF_USE1|CF_CHG1|CF_USE2         },      // Divide
  { "divu",       CF_USE1|CF_CHG1|CF_USE2         },      // Divide
  { "djnz",       CF_USE1|CF_CHG1|CF_USE2         },      // Decrement Operand and JNZ
  { "fcall",      CF_USE1|CF_CALL                 },      // Far Call
  { "fjmp",       CF_USE1|CF_STOP|CF_JUMP         },      // Far Jump
  { "jb",         CF_USE1|CF_USE2                 },      // Jump if Bit is set
  { "jbc",        CF_USE1|CF_USE2                 },      // Jump if Bit is set & clear Bit
  { "jmp",        CF_USE1|CF_STOP|CF_JUMP         },      // Jump indirect relative to Data Pointer
  { "jnb",        CF_USE1|CF_USE2                 },      // Jump if Bit is clear
  { "jnz",        CF_USE1                         },      // Jump if Acc is not zero
  { "jz",         CF_USE1                         },      // Jump if Acc is zero
  { "lea",        CF_CHG1|CF_USE2                 },      // Load effective address
  { "lsr",        CF_USE1|CF_CHG1|CF_USE2         },      // Logical shift right
  { "mov",        CF_CHG1|CF_USE2                 },      // Move (Op1 <- Op2)
  { "movc",       CF_CHG1|CF_USE2                 },      // Move code byte relative to second op to Acc
  { "movs",       CF_CHG1|CF_USE2                 },      // Move short
  { "movx",       CF_CHG1|CF_USE2                 },      // Move from/to external RAM
  { "mul",        CF_USE1|CF_CHG1|CF_USE2         },      // Multiply
  { "mulu",       CF_USE1|CF_CHG1|CF_USE2         },      // Multiply unsigned
  { "neg",        CF_USE1|CF_CHG1                 },      // Negate
  { "nop",        0                               },      // No operation
  { "norm",       CF_USE1|CF_CHG1|CF_CHG2         },      // Normalize
  { "or",         CF_USE1|CF_USE2|CF_CHG1         },      // Logical OR (op1 |= op2)
  { "orl",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical OR Carry
  { "pop",        CF_CHG1                         },      // Pop  from Stack and put in Direct RAM
  { "popu",       CF_CHG1                         },      // Pop  from Stack and put in Direct RAM
  { "push",       CF_USE1                         },      // Push from Direct RAM to Stack
  { "pushu",      CF_USE1                         },      // Push from Direct RAM to Stack
  { "reset",      0                               },      // Software reset
  { "ret",        CF_STOP                         },      // Return from subroutine
  { "reti",       CF_STOP                         },      // Return from Interrupt
  { "rl",         CF_USE1|CF_CHG1|CF_USE2         },      // Rotate Acc left
  { "rlc",        CF_USE1|CF_CHG1|CF_USE2         },      // Rotate Acc left through Carry
  { "rr",         CF_USE1|CF_CHG1|CF_USE2         },      // Rotate Acc right
  { "rrc",        CF_USE1|CF_CHG1|CF_USE2         },      // Rotate Acc right through Carry
  { "setb",       CF_CHG1                         },      // Set Direct Bit
  { "sext",       CF_CHG1                         },      // Sign extend
  { "sub",        CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Second Operand from Acc with Borrow
  { "subb",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Second Operand from Acc with Borrow
  { "trap",       CF_USE1                         },      // Software TRAP
  { "xch",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // Exchange Operands
  { "xor",        CF_USE1|CF_USE2|CF_CHG1         },      // Exclusive OR (op1 ^= op2)
};

CASSERT(sizeof(Instructions)/sizeof(Instructions[0]) == XA_last);
