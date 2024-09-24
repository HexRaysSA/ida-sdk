/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },      // Unknown Operation

  { "add",        CF_USE1|CF_USE2|CF_CHG2         },      // Add binary
  { "adds",       CF_USE1|CF_USE2|CF_CHG2         },      // Add with sign extension
  { "addx",       CF_USE1|CF_USE2|CF_CHG2         },      // Add with extend carry
  { "and",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND
  { "andc",       CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND with control register
  { "band",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit AND
  { "bra",        CF_USE1|CF_STOP|CF_JUMP         },      // Branch always
  { "brn",        CF_USE1                         },      // Branch never
  { "bhi",        CF_USE1                         },      // Branch if higher
  { "bls",        CF_USE1                         },      // Branch if lower or same
  { "bcc",        CF_USE1                         },      // Branch if carry clear (higher or same)
  { "bcs",        CF_USE1                         },      // Branch if carry set (lower)
  { "bne",        CF_USE1                         },      // Branch if not equal
  { "beq",        CF_USE1                         },      // Branch if equal
  { "bvc",        CF_USE1                         },      // Branch if overflow clear
  { "bvs",        CF_USE1                         },      // Branch if overflow set
  { "bpl",        CF_USE1                         },      // Branch if plus
  { "bmi",        CF_USE1                         },      // Branch if minus
  { "bge",        CF_USE1                         },      // Branch if greates or equal
  { "blt",        CF_USE1                         },      // Branch if less
  { "bgt",        CF_USE1                         },      // Branch if greater
  { "ble",        CF_USE1                         },      // Branch if less or equal
  { "bclr",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit clear
  { "biand",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert AND
  { "bild",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert load
  { "bior",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert OR
  { "bist",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert store
  { "bixor",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit invert XOR
  { "bld",        CF_USE1|CF_USE2                 },      // Bit load
  { "bnot",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit NOT
  { "bor",        CF_USE1|CF_USE2|CF_CHG2         },      // Bit OR
  { "bset",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit set
  { "bsr",        CF_USE1|CF_CALL                 },      // Branch to subroutine
  { "bst",        CF_USE1|CF_USE2|CF_CHG2         },      // Bit store
  { "btst",       CF_USE1|CF_USE2                 },      // Bit test
  { "bxor",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit XOR
  { "clrmac",     0                               },      // Clear MAC register
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare
  { "daa",        CF_USE1|CF_CHG1                 },      // Decimal adjust add
  { "das",        CF_USE1|CF_CHG1                 },      // Decimal adjust subtract
  { "dec",        CF_USE1|CF_USE2|CF_CHG2         },      // Decrement
  { "divxs",      CF_USE1|CF_USE2|CF_CHG2         },      // Divide extended as signed
  { "divxu",      CF_USE1|CF_USE2|CF_CHG2         },      // Divide extended as unsigned
  { "eepmov",     0                               },      // Move data to EEPROM
  { "exts",       CF_USE1|CF_USE2|CF_CHG2         },      // Extend as signed
  { "extu",       CF_USE1|CF_USE2|CF_CHG2         },      // Extend as unsigned
  { "inc",        CF_USE1|CF_USE2|CF_CHG2         },      // Increment
  { "jmp",        CF_USE1|CF_STOP|CF_JUMP         },      // Jump
  { "jsr",        CF_USE1|CF_CALL                 },      // Jump to subroutine
  { "ldc",        CF_USE1|CF_CHG2                 },      // Load to control register
  { "ldm",        CF_USE1|CF_CHG2                 },      // Load to multiple registers
  { "ldmac",      CF_USE1|CF_CHG2                 },      // Load to MAC register
  { "mac",        CF_USE1|CF_USE2                 },      // Multiply and accumulate
  { "mov",        CF_USE1|CF_CHG2                 },      // Move data
  { "movfpe",     CF_USE1|CF_CHG2                 },      // Move from peripheral with E clock
  { "movtpe",     CF_USE1|CF_CHG2                 },      // Move to peripheral with E clock
  { "mulxs",      CF_USE1|CF_USE2|CF_CHG2         },      // Multiply extend as signed
  { "mulxu",      CF_USE1|CF_USE2|CF_CHG2         },      // Multiply extend as unsigned
  { "neg",        CF_USE1|CF_CHG1                 },      // Negate
  { "nop",        0                               },      // No operation
  { "not",        CF_USE1|CF_CHG1                 },      // Logical complement
  { "or",         CF_USE1|CF_USE2|CF_CHG2         },      // Logical OR
  { "orc",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical OR with control register
  { "pop",        CF_CHG1                         },      // Pop data from stack
  { "push",       CF_USE1                         },      // Push data on stack
  { "rotl",       CF_USE1|CF_USE2|CF_CHG2         },      // Rotate left
  { "rotr",       CF_USE1|CF_USE2|CF_CHG2         },      // Rotate right
  { "rotxl",      CF_USE1|CF_USE2|CF_CHG2         },      // Rotate with extend carry left
  { "rotxr",      CF_USE1|CF_USE2|CF_CHG2         },      // Rotate with extend carry right
  { "rte",        CF_STOP                         },      // Return from exception
  { "rts",        CF_STOP                         },      // Return from subroutine
  { "shal",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift arithmetic left
  { "shar",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift arithmetic right
  { "shll",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift logical left
  { "shlr",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift logical right
  { "sleep",      0                               },      // Power down mode
  { "stc",        CF_USE1|CF_CHG2                 },      // Store from control register
  { "stm",        CF_USE1|CF_CHG2                 },      // Store from multiple registers
  { "stmac",      CF_USE1|CF_CHG2                 },      // Store from MAC register
  { "sub",        CF_USE1|CF_USE2|CF_CHG2         },      // Subtract binary
  { "subs",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract with sign extension
  { "subx",       CF_USE1|CF_USE2|CF_CHG2         },      // Subtract with extend carry
  { "tas",        CF_USE1|CF_CHG1                 },      // Test and set
  { "trapa",      CF_USE1|CF_CALL                 },      // Trap always
  { "xor",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical XOR
  { "xorc",       CF_USE1|CF_USE2|CF_CHG2         },      // Logical XOR with control register

  // H8SX
  { "rte/l",      CF_STOP|CF_USE1|CF_CHG1         },      // Returns from an exception,
                                                          // restoring data to multiple general registers
  { "rts/l",      CF_STOP|CF_USE1|CF_CHG1         },      // Returns from a subroutine,
                                                          // restoring data to multiple general registers
  { "movmd",      0                               },      // Transfers a data block
  { "movsd",      CF_USE1                         },      // Transfers a data block with zero detection
  { "bra/s",      CF_USE1|CF_STOP                 },      // Branch always after the next instruction (delay slot)
  { "mova/b",     CF_USE1|CF_CHG2                 },      // MOVe effective Address/B
  { "mova/w",     CF_USE1|CF_CHG2                 },      // MOVe effective Address/W
  { "mova/l",     CF_USE1|CF_CHG2                 },      // MOVe effective Address/L
  { "bset/ne",    CF_USE1|CF_USE2|CF_CHG2         },      // Bit SET if Not Equal
  { "bset/eq",    CF_USE1|CF_USE2|CF_CHG2         },      // Bit SET if EQual
  { "bclr/ne",    CF_USE1|CF_USE2|CF_CHG2         },      // Bit CLeaR if Not Equal
  { "bclr/eq",    CF_USE1|CF_USE2|CF_CHG2         },      // Bit CLear if EQual
  { "bstz",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit STore Zero flag
  { "bistz",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit Invert STore Zero flag
  { "bfld",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Bit Field LoaD
  { "bfst",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Bit Field STore
  { "muls",       CF_USE1|CF_USE2|CF_CHG2         },      // MULtiply as Signed
  { "divs",       CF_USE1|CF_USE2|CF_CHG2         },      // DIVide as Signed
  { "mulu",       CF_USE1|CF_USE2|CF_CHG2         },      // MULtiply as Unsigned
  { "divu",       CF_USE1|CF_USE2|CF_CHG2         },      // DIVide as Unsigned
  { "muls/u",     CF_USE1|CF_USE2|CF_CHG2         },      // MULtiply as Signed
  { "mulu/u",     CF_USE1|CF_USE2|CF_CHG2         },      // MULtiply as Unsigned
  { "bra/bc",     CF_USE1|CF_USE2|CF_USE3|CF_STOP },      // BRAnch if Bit Cleared
  { "bra/bs",     CF_USE1|CF_USE2|CF_USE3|CF_STOP },      // BRAnch if Bit Set
  { "bsr/bc",     CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Branch to SubRoutine if Bit Cleared
  { "bsr/bs",     CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Branch to SubRoutine if Bit Set
};

CASSERT(qnumber(Instructions) == H8_last);
