/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  // Data transfer

  { "mov:g",      CF_USE1|CF_CHG2                 },      // B/W Move data
  { "mov:e",      CF_USE1|CF_CHG2                 },      // B   Move data
  { "mov:i",      CF_USE1|CF_CHG2                 },      // W   Move data
  { "mov:f",      CF_USE1|CF_CHG2                 },      // B/W Move data
  { "mov:l",      CF_USE1|CF_CHG2                 },      // B/W Move data
  { "mov:s",      CF_USE1|CF_CHG2                 },      // B/W Move data
  { "ldm",        CF_USE1|CF_CHG2                 },      // W   Pop data from the stack to one or more registers
  { "stm",        CF_USE1|CF_CHG2                 },      // W   Push data from one or more registers onto the stack
  { "xch",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // W   Exchange data between two general registers
  { "swap",       CF_USE1|CF_CHG1                 },      // B   Exchange the upper and lower bytes in a general register
  { "movtpe",     CF_USE1|CF_CHG2                 },      // B   Transfer data from a general register to memory
  { "movfpe",     CF_USE1|CF_CHG2                 },      // B   Transfer data from memory to a general register

  // Arithmetic operations

  { "add:g",      CF_USE1|CF_USE2|CF_CHG2         },      // B/W Addition
  { "add:q",      CF_USE1|CF_USE2|CF_CHG2         },      // B/W Addition
  { "sub",        CF_USE1|CF_USE2|CF_CHG2         },      // B/W Subtraction
  { "adds",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Addition
  { "subs",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Subtraction
  { "addx",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Addition with carry
  { "subx",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Subtraction with borrow
  { "dadd",       CF_USE1|CF_USE2|CF_CHG2         },      // B   Decimal addition
  { "dsub",       CF_USE1|CF_USE2|CF_CHG2         },      // B   Decimal subtraction
  { "mulxu",      CF_USE1|CF_USE2|CF_CHG2         },      // B/W Unsigned multiplication
  { "divxu",      CF_USE1|CF_USE2|CF_CHG2         },      // B/W Unsigned division
  { "cmp:g",      CF_USE1|CF_USE2                 },      // B/W Compare data
  { "cmp:e",      CF_USE1|CF_USE2                 },      // B   Compare data
  { "cmp:i",      CF_USE1|CF_USE2                 },      // W   Compare data
  { "exts",       CF_USE1|CF_CHG1                 },      // B   Convert byte to word by extending the sign bit
  { "extu",       CF_USE1|CF_CHG1                 },      // B   Convert byte to word data by padding with zero bits
  { "tst",        CF_USE1                         },      // B/W Compare with 0
  { "neg",        CF_USE1|CF_CHG1                 },      // B/W Negate
  { "clr",        CF_CHG1                         },      // B/W Make zero
  { "tas",        CF_USE1|CF_CHG1                 },      // B   Test and set

  // Logic Operations

  { "and",        CF_USE1|CF_USE2|CF_CHG2         },      // B/W Logical AND
  { "or",         CF_USE1|CF_USE2|CF_CHG2         },      // B/W Logical OR
  { "xor",        CF_USE1|CF_USE2|CF_CHG2         },      // B/W Exclusive OR
  { "not",        CF_USE1|CF_CHG1                 },      // B/W Bitwise NOT

  // Shift Operations

  { "shal",       CF_USE1|CF_CHG1                 },      // B/W Arithmetic shift left
  { "shar",       CF_USE1|CF_CHG1                 },      // B/W Arithmetic shift right
  { "shll",       CF_USE1|CF_CHG1                 },      // B/W Logical shift left
  { "shlr",       CF_USE1|CF_CHG1                 },      // B/W Logical shift right
  { "rotl",       CF_USE1|CF_CHG1                 },      // B/W Rotate left
  { "rotr",       CF_USE1|CF_CHG1                 },      // B/W Rotate right
  { "rotxl",      CF_USE1|CF_CHG1                 },      // B/W Rotate through carry left
  { "rotxr",      CF_USE1|CF_CHG1                 },      // B/W Rotate through carry right

  // Bit Manipulations

  { "bset",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Test bit and set
  { "bclr",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Test bit and clear
  { "bnot",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Test bit and invert
  { "btst",       CF_USE1|CF_USE2                 },      // B/W Test bit

  // Branching Instructions

  { "bra",        CF_USE1|CF_STOP                 },      //     Branch Always
  { "brn",        CF_USE1                         },      //     Branch Never
  { "bhi",        CF_USE1                         },      //     Branch if High (C|Z = 0)
  { "bls",        CF_USE1                         },      //     Branch if Low or Same (C|Z = 1)
  { "bcc",        CF_USE1                         },      //     Branch if Carry Clear (C = 0)
  { "bcs",        CF_USE1                         },      //     Branch if Carry Set (C = 1)
  { "bne",        CF_USE1                         },      //     Branch if Not Equal (Z = 0)
  { "beq",        CF_USE1                         },      //     Branch if Equal (Z = 1)
  { "bvc",        CF_USE1                         },      //     Branch if Overflow Clear (V = 0)
  { "bvs",        CF_USE1                         },      //     Branch if Overflow Set (V = 1)
  { "bpl",        CF_USE1                         },      //     Branch if Plus (N = 0)
  { "bmi",        CF_USE1                         },      //     Branch if Minus (N = 1)
  { "bge",        CF_USE1                         },      //     Branch if Greater or Equal (N^V = 0)
  { "blt",        CF_USE1                         },      //     Branch if Less Than (N^V = 1)
  { "bgt",        CF_USE1                         },      //     Branch if Greater Than (Z|(N^V) = 0)
  { "ble",        CF_USE1                         },      //     Branch if Less or Equal (Z|(N^V) = 1)
  { "jmp",        CF_USE1|CF_STOP                 },      //     Branch unconditionally (same page)
  { "pjmp",       CF_USE1|CF_STOP                 },      //     Branch unconditionally (specified page)
  { "bsr",        CF_USE1|CF_CALL                 },      //     Branch to subroutine (same page)
  { "jsr",        CF_USE1|CF_CALL                 },      //     Branch to subroutine (same page)
  { "pjsr",       CF_USE1|CF_CALL                 },      //     Branch to subroutine (specified page)
  { "rts",        CF_STOP                         },      //     Return from subroutine (same page)
  { "prts",       CF_STOP                         },      //     Return from subroutine (different page)
  { "rtd",        CF_USE1|CF_STOP                 },      //     Return from subroutine (same page) and adjust SP
  { "prtd",       CF_USE1|CF_STOP                 },      //     Return from subroutine (different page) and adjust SP
  { "scb",        CF_USE1|CF_USE2                 },      //     Control loop

  // System Control Instructions

  { "trapa",      CF_USE1                         },      //     Generate trap exception
  { "trap/vs",    0                               },      //     Generate trap exception if the V bit is set
  { "rte",        CF_STOP                         },      //     Return from exception-handling routine
  { "link",       CF_USE1|CF_USE2                 },      //     Create stack frame
  { "unlk",       0                               },      //     Deallocate stack frame
  { "sleep",      0                               },      //     Go to power-down state
  { "ldc",        CF_USE1|CF_CHG2                 },      // B/W Move to control register
  { "stc",        CF_USE1|CF_CHG2                 },      // B/W Move from control register
  { "andc",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Logically AND control register
  { "orc",        CF_USE1|CF_USE2|CF_CHG2         },      // B/W Logically OR control register
  { "xorc",       CF_USE1|CF_USE2|CF_CHG2         },      // B/W Logically exclusive-OR control register
  { "nop",        0                               },      //     No operation
  { "bpt",        0                               },      //

};

CASSERT(qnumber(Instructions) == H8500_last);
