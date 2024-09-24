/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  // ARITHMETIC AND LOGIC INSTRUCTIONS
  { "add",        CF_USE1|CF_USE2|CF_CHG1         },      // Add without Carry
  { "adc",        CF_USE1|CF_USE2|CF_CHG1         },      // Add with Carry
  { "adiw",       CF_USE1|CF_USE2|CF_CHG1         },      // Add Immediate to Word
  { "sub",        CF_USE1|CF_USE2|CF_CHG1         },      // Subtract without Carry
  { "subi",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Immediate
  { "sbc",        CF_USE1|CF_USE2|CF_CHG1         },      // Subtract with Carry
  { "sbci",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Immediate with Carry
  { "sbiw",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract Immediate from Word
  { "and",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND
  { "andi",       CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND with Immediate
  { "or",         CF_USE1|CF_USE2|CF_CHG1         },      // Logical OR
  { "ori",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical OR with Immediate
  { "eor",        CF_USE1|CF_USE2|CF_CHG1         },      // Exclusive OR
  { "com",        CF_USE1|        CF_CHG1         },      // One's Complement
  { "neg",        CF_USE1|        CF_CHG1         },      // Two's Complement
  { "sbr",        CF_USE1|CF_USE2|CF_CHG1         },      // Set Bit(s) in Register
  { "cbr",        CF_USE1|CF_USE2|CF_CHG1         },      // Clear Bit(s) in Register
  { "inc",        CF_USE1|        CF_CHG1         },      // Increment
  { "dec",        CF_USE1|        CF_CHG1         },      // Decrement
  { "tst",        CF_USE1|        CF_CHG1         },      // Test for Zero or Minus
  { "clr",                        CF_CHG1         },      // Clear Register
  { "ser",                        CF_CHG1         },      // Set Register
  { "cp",         CF_USE1|CF_USE2                 },      // Compare
  { "cpc",        CF_USE1|CF_USE2                 },      // Compare with Carry
  { "cpi",        CF_USE1|CF_USE2                 },      // Compare with Immediate
  { "mul",        CF_USE1|CF_USE2|CF_CHG1         },      // Multiply

  // BRANCH INSTRUCTIONS
  { "rjmp",       CF_USE1|CF_STOP                 },      // Relative Jump
  { "ijmp",               CF_STOP|CF_JUMP         },      // Indirect Jump to (Z)
  { "jmp",        CF_USE1|CF_STOP                 },      // Jump
  { "rcall",      CF_USE1                |CF_CALL },      // Relative Call Subroutine
  { "icall",                      CF_JUMP|CF_CALL },      // Indirect Call to (Z)
  { "call",       CF_USE1                |CF_CALL },      // Call Subroutine
  { "ret",                CF_STOP                 },      // Subroutine Return
  { "reti",               CF_STOP                 },      // Interrupt Return
  { "cpse",       CF_USE1|CF_USE2                 },      // Compare", Skip if Equal
  { "sbrc",       CF_USE1|CF_USE2                 },      // Skip if Bit in Register Cleared
  { "sbrs",       CF_USE1|CF_USE2                 },      // Skip if Bit in Register Set
  { "sbic",       CF_USE1|CF_USE2                 },      // Skip if Bit in I/O Register Cleared
  { "sbis",       CF_USE1|CF_USE2                 },      // Skip if Bit in I/O Register Set
  { "brbs",       CF_USE1|CF_USE2                 },      // Branch if Status Flag Set
  { "brbc",       CF_USE1|CF_USE2                 },      // Branch if Status Flag Cleared
  { "breq",       CF_USE1                         },      // Branch if Equal
  { "brne",       CF_USE1                         },      // Branch if Not Equal
  { "brcs",       CF_USE1                         },      // Branch if Carry Set
  { "brcc",       CF_USE1                         },      // Branch if Carry Cleared
  { "brsh",       CF_USE1                         },      // Branch if Same or Higher
  { "brlo",       CF_USE1                         },      // Branch if Lower
  { "brmi",       CF_USE1                         },      // Branch if Minus
  { "brpl",       CF_USE1                         },      // Branch if Plus
  { "brge",       CF_USE1                         },      // Branch if Greater or Equal
  { "brlt",       CF_USE1                         },      // Branch if Less Than
  { "brhs",       CF_USE1                         },      // Branch if Half Carry Flag Set
  { "brhc",       CF_USE1                         },      // Branch if Half Carry Flag Cleared
  { "brts",       CF_USE1                         },      // Branch if T Flag Set
  { "brtc",       CF_USE1                         },      // Branch if T Flag Cleared
  { "brvs",       CF_USE1                         },      // Branch if Overflow Flag is Set
  { "brvc",       CF_USE1                         },      // Branch if Overflow Flag is Cleared
  { "brie",       CF_USE1                         },      // Branch if Interrupt Enabled
  { "brid",       CF_USE1                         },      // Branch if Interrupt Disabled

  // DATA TRANSFER INSTRUCTIONS
  { "mov",        CF_CHG1|CF_USE2                 },      // Copy Register
  { "ldi",        CF_CHG1|CF_USE2                 },      // Load Immediate
  { "lds",        CF_CHG1|CF_USE2                 },      // Load Direct
  { "ld",         CF_CHG1|CF_USE2                 },      // Load Indirect
  { "ldd",        CF_CHG1|CF_USE2                 },      // Load Indirect with Displacement
  { "sts",        CF_CHG1|CF_USE2                 },      // Store Direct to SRAM
  { "st",         CF_USE1|CF_USE2                 },      // Store Indirect
  { "std",        CF_USE1|CF_USE2                 },      // Store Indirect with Displacement
  { "lpm",        CF_USE1|CF_USE2|CF_CHG1         },      // Load Program Memory
  { "in",         CF_CHG1|CF_USE2                 },      // In Port
  { "out",        CF_USE1|CF_USE2                 },      // Out Port
  { "push",       CF_USE1                         },      // Push Register on Stack
  { "pop",        CF_CHG1                         },      // Pop Register from Stack

  // BIT AND BIT-TEST INSTRUCTIONS
  { "lsl",        CF_USE1|CF_CHG1                 },      // Logical Shift Left
  { "lsr",        CF_USE1|CF_CHG1                 },      // Logical Shift Right
  { "rol",        CF_USE1|CF_CHG1                 },      // Rotate Left Through Carry
  { "ror",        CF_USE1|CF_CHG1                 },      // Rotate Right Through Carry
  { "asr",        CF_USE1|CF_CHG1                 },      // Arithmetic Shift Right
  { "swap",       CF_USE1|CF_CHG1                 },      // Swap Nibbles
  { "bset",       CF_USE1                         },      // Flag Set
  { "bclr",       CF_USE1                         },      // Flag Clear
  { "sbi",        CF_USE1|CF_USE2                 },      // Set Bit in I/O Register
  { "cbi",        CF_USE1|CF_USE2                 },      // Clear Bit in I/O Register
  { "bst",        CF_USE1|CF_USE2                 },      // Bit Store from Register to T
  { "bld",        CF_USE1|CF_USE2                 },      // Bit load from T to Register
  { "sec",        0                               },      // Set Carry
  { "clc",        0                               },      // Clear Carry
  { "sen",        0                               },      // Set Negative Flag
  { "cln",        0                               },      // Clear Negative Flag
  { "sez",        0                               },      // Set Zero Flag
  { "clz",        0                               },      // Clear Zero Flag
  { "sei",        0                               },      // Global Interrupt Enable
  { "cli",        0                               },      // Global Interrupt Disable
  { "ses",        0                               },      // Set Signed Test Flag
  { "cls",        0                               },      // Clear Signed Test Flag
  { "sev",        0                               },      // Set Two's Complement Overflow
  { "clv",        0                               },      // Clear Two's Complement Overflow
  { "set",        0                               },      // Set T in SREG
  { "clt",        0                               },      // Clear T in SREG
  { "seh",        0                               },      // Set Half Carry Flag in SREG
  { "clh",        0                               },      // Clear Half Carry Flag in SREG
  { "nop",        0                               },      // No Operation
  { "sleep",      0                               },      // Sleep
  { "wdr",        0                               },      // Watchdog Reset

  // New MegaAVR instructions
  { "elpm",       CF_USE2|CF_CHG1                 },      // Extended Load Program Memory
  { "espm",       0                               },      // Extended Store Program Memory
  { "fmul",       CF_USE1|CF_USE2|CF_CHG1         },      // Fractional Multiply Unsigned
  { "fmuls",      CF_USE1|CF_USE2|CF_CHG1         },      // Fractional Multiply Signed
  { "fmulsu",     CF_USE1|CF_USE2|CF_CHG1         },      // Fractional Multiply Signed with Unsigned
  { "movw",       CF_USE1|CF_USE2|CF_CHG1         },      // Copy Register Word
  { "muls",       CF_USE1|CF_USE2|CF_CHG1         },      // Multiply Signed
  { "mulsu",      CF_USE1|CF_USE2|CF_CHG1         },      // Multiply Signed with Unsigned
  { "spm",        0                               },      // Store Program Memory
  { "eicall",     0                               },      // Extended Indirect Call to Subroutine
  { "eijmp",      0                               },      // Extended Indirect Jump

  // New XMega instructions
  { "des",        CF_USE1                         },      // Data Encryption Standard
  { "lac",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // Load And Clear
  { "las",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // Load And Set
  { "lat",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // Load And Toggle
  { "xch",        CF_USE1|CF_USE2|CF_CHG1|CF_CHG2 },      // Exchange
};

CASSERT(qnumber(Instructions) == AVR_last);
