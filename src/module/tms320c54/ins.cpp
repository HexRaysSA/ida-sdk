/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  // ARITHMETIC OPERATIONS

  // ADD INSTRUCTIONS

  { "add",        CF_CHG1                         },      // Add to Accumulator
  { "add",        CF_USE1|CF_CHG2                 },      // Add to Accumulator
  { "add",        CF_USE1|CF_USE2|CF_CHG3         },      // Add to Accumulator
  { "addc",       CF_USE1|CF_CHG2                 },      // Add to Accumulator With Carry
  { "addm",       CF_USE1|CF_CHG2                 },      // Add Long-Immediate Value to Memory
  { "adds",       CF_USE1|CF_CHG2                 },      // Add to Accumulator With Sign-Extension Suppressed

  // SUBTRACT INSTRUCTIONS

  { "sub",        CF_CHG1                         },      // Sub From Accumulator
  { "sub",        CF_USE1|CF_CHG2                 },      // Sub From Accumulator
  { "sub",        CF_USE1|CF_USE2|CF_CHG3         },      // Sub From Accumulator
  { "subb",       CF_USE1|CF_CHG2                 },      // Sub From Accumulator With Borrow
  { "subc",       CF_USE1|CF_CHG2                 },      // Subtract Conditionally
  { "subs",       CF_USE1|CF_CHG2                 },      // Subtract From Accumulator With Sign Extension Suppressed

  // MULTIPLY INSTRUCTIONS

  { "mpy",        CF_USE1|CF_CHG2                 },      // Multiply Without Rounding
  { "mpy",        CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Without Rounding
  { "mpyr",       CF_USE1|CF_CHG2                 },      // Multiply With Rounding
  { "mpya",       CF_CHG1                         },      // Multiply by Accumulator A
  { "mpyu",       CF_USE1|CF_CHG2                 },      // Multiply Unsigned
  { "squr",       CF_USE1|CF_CHG2                 },      // Square

  // MULTIPLY-ACCUMULATE AND MULTIPLY-SUBTRACT INSTRUCTIONS

  { "mac",        CF_USE1|CF_CHG2                 },      // Multiply Accumulate Without Rounding
  { "mac",        CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Accumulate Without Rounding
  { "macr",       CF_USE1|CF_CHG2                 },      // Multiply Accumulate With Rounding
  { "macr",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Accumulate With Rounding
  { "maca",       CF_CHG1                         },      // Multiply by Accumulator A and Accumulate Without Rounding
  { "maca",       CF_USE1|CF_CHG2                 },      // Multiply by Accumulator A and Accumulate Without Rounding
  { "maca",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Accumulator A and Accumulate Without Rounding
  { "macar",      CF_CHG1                         },      // Multiply by Accumulator A and Accumulate With Rounding
  { "macar",      CF_USE1|CF_CHG2                 },      // Multiply by Accumulator A and Accumulate With Rounding
  { "macar",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Accumulator A and Accumulate With Rounding
  { "macd",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Program Memory and Accumulate With Delay
  { "macp",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Program Memory and Accumulate
  { "macsu",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed by Unsigned and Accumulate
  { "mas",        CF_USE1|CF_CHG2                 },      // Multiply and Subtract Without Rounding
  { "mas",        CF_USE1|CF_USE2|CF_CHG3         },      // Multiply and Subtract Without Rounding
  { "masr",       CF_USE1|CF_CHG2                 },      // Multiply and Subtract With Rounding
  { "masr",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply and Subtract With Rounding
  // TMS320C54_mas,
  { "masa",       CF_CHG1                         },      // Multiply by Accumulator A and Subtract Without Rounding
  { "masa",       CF_USE1|CF_CHG2                 },      // Multiply by Accumulator A and Subtract Without Rounding
  { "masa",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Accumulator A and Subtract Without Rounding
  { "masar",      CF_CHG1                         },      // Multiply by Accumulator A and Subtract With Rounding
  { "masar",      CF_USE1|CF_CHG2                 },      // Multiply by Accumulator A and Subtract With Rounding
  { "masar",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply by Accumulator A and Subtract With Rounding
  { "squra",      CF_USE1|CF_CHG2                 },      // Square and Accumulate
  { "squrs",      CF_USE1|CF_CHG2                 },      // Square and Subtract

  // DOUBLE INSTRUCTIONS

  { "dadd",       CF_USE1|CF_CHG2                 },      // Double-Precision/Dual 16-Bit Add to Accumulator
  { "dadd",       CF_USE1|CF_USE2|CF_CHG3         },      // Double-Precision/Dual 16-Bit Add to Accumulator
  { "dadst",      CF_USE1|CF_CHG2                 },      // Double-Precision Load With T Add/Dual 16-Bit Load With T Add/Subtract
  { "drsub",      CF_USE1|CF_CHG2                 },      // Double-Precision/Dual 16-Bit Subtract From Long Word
  { "dsadt",      CF_USE1|CF_CHG2                 },      // Long-Word Load With T Add/Dual 16-Bit Load With T Subtract/Add
  { "dsub",       CF_USE1|CF_CHG2                 },      // Double-Precision/Dual 16-Bit Subtract From Accumulator
  { "dsubt",      CF_USE1|CF_CHG2                 },      // Long-Word Load With T Subtract/Dual 16-Bit Load With T Subtract

  // APPLICATION-SPECIFIC INSTRUCTIONS

  { "abdst",      CF_USE1|CF_USE2                 },      // Absolute distance
  { "abs",        CF_CHG1                         },      // Absolute Value of Accumulator
  { "abs",        CF_USE1|CF_CHG2                 },      // Absolute Value of Accumulator
  { "cmpl",       CF_CHG1                         },      // Complement Accumulator
  { "cmpl",       CF_USE1|CF_CHG2                 },      // Complement Accumulator
  { "delay",      CF_USE1                         },      // Memory Delay
  { "exp",        CF_USE1                         },      // Accumulator Exponent
  { "firs",       CF_USE1|CF_USE2                 },      // Symmetrical Finite Impulse Response Filter
  { "lms",        CF_USE1|CF_USE2                 },      // Least Mean Square
  { "max",        CF_CHG1                         },      // Accumulator Maximum
  { "min",        CF_CHG1                         },      // Accumulator Minimum
  { "neg",        CF_CHG1                         },      // Negate Accumulator
  { "neg",        CF_USE1|CF_CHG2                 },      // Negate Accumulator
  { "norm",       CF_CHG1                         },      // Normalization
  { "norm",       CF_USE1|CF_CHG2                 },      // Normalization
  { "poly",       CF_USE1                         },      // Polynominal Evaluation
  { "rnd",        CF_CHG1                         },      // Round Accumulator
  { "rnd",        CF_USE1|CF_CHG2                 },      // Round Accumulator
  { "sat",        CF_CHG1                         },      // Saturate Accumulator
  { "sqdst",      CF_USE1|CF_USE2                 },      // Square Distance

  // LOGICAL OPERATIONS

  // AND INSTRUCTIONS
  { "and",        CF_CHG1                         },      // AND With Accumulator
  { "and",        CF_USE1|CF_CHG2                 },      // AND With Accumulator
  { "and",        CF_USE1|CF_USE2|CF_CHG3         },      // AND With Accumulator
  { "andm",       CF_USE1|CF_CHG2                 },      // AND Memory With Long Immediate

  // OR INSTRUCTIONS

  { "or",         CF_CHG1                         },      // OR With Accumulator
  { "or",         CF_USE1|CF_CHG2                 },      // OR With Accumulator
  { "or",         CF_USE1|CF_USE2|CF_CHG3         },      // OR With Accumulator
  { "orm",        CF_USE1|CF_CHG2                 },      // OR Memory With Constant

  // XOR INSTRUCTIONS

  { "xor",        CF_CHG1                         },      // Exclusive OR With Accumulator
  { "xor",        CF_USE1|CF_CHG2                 },      // Exclusive OR With Accumulator
  { "xor",        CF_USE1|CF_USE2|CF_CHG3         },      // Exclusive OR With Accumulator
  { "xorm",       CF_USE1|CF_CHG2                 },      // Exclusive OR Memory With Constant

  // SHIFT INSTRUCTIONS

  { "rol",        CF_CHG1                         },      // Rotate Accumulator
  { "roltc",      CF_CHG1                         },      // Rotate Accumulator Left Using TC
  { "ror",        CF_CHG1                         },      // Rotate Accumulator Right
  { "sfta",       CF_CHG1|CF_USE2                 },      // Shift Accumulator Arithmetically
  { "sfta",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Accumulator Arithmetically
  { "sftc",       CF_CHG1                         },      // Shift Accumulator Conditionally
  { "sftl",       CF_CHG1|CF_USE2                 },      // Shift Accumulator Logically
  { "sftl",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Accumulator Logically

  // TEST INSTRUCTIONS

  { "bit",        CF_USE1|CF_USE2                 },      // Test Bit
  { "bitf",       CF_USE1|CF_USE2                 },      // Test Bit Field Specified by Immediate Value
  { "bitt",       CF_USE1                         },      // Test Bit Specified by T
  { "cmpm",       CF_USE1|CF_USE2                 },      // Compare Memory With Long Immediate
  { "cmpr",       CF_USE1|CF_USE2                 },      // Compare Auxiliary Register with AR0

  // PROGRAM CONTROL OPERATIONS

  // BRANCH INSTRUCTIONS

  { "b",          CF_USE1|CF_STOP                 },      // Branch Unconditionally
  { "bd",         CF_USE1                         },      // Branch Unconditionally
  { "bacc",       CF_USE1|CF_STOP                 },      // Branch to Location Specified by Accumulator
  { "baccd",      CF_USE1                         },      // Branch to Location Specified by Accumulator
  { "banz",       CF_USE1|CF_USE2                 },      // Branch on Auxiliary Register Not Zero
  { "banzd",      CF_USE1|CF_USE2                 },      // Branch on Auxiliary Register Not Zero
  { "bc",         CF_USE1|CF_USE2                 },      // Branch Conditionally
  { "bc",         CF_USE1|CF_USE2|CF_USE3         },      // Branch Conditionally
  { "bcd",        CF_USE1|CF_USE2                 },      // Branch Conditionally
  { "bcd",        CF_USE1|CF_USE2|CF_USE3         },      // Branch Conditionally
  { "fb",         CF_USE1|CF_STOP                 },      // Far Branch Unconditionally
  { "fbd",        CF_USE1                         },      // Far Branch Unconditionally
  { "fbacc",      CF_USE1                         },      // Far Branch to Location Specified by Accumulator
  { "fbaccd",     CF_USE1                         },      // Far Branch to Location Specified by Accumulator

  // CALL INSTRUCTIONS

  { "cala",       CF_USE1|CF_CALL                 },      // Call Subroutine at Location Specified by Accumulator
  { "calad",      CF_USE1|CF_CALL                 },      // Call Subroutine at Location Specified by Accumulator
  { "call",       CF_USE1|CF_CALL                 },      // Call Unconditionally
  { "calld",      CF_USE1|CF_CALL                 },      // Call Unconditionally
  { "cc",         CF_USE1|CF_USE2|CF_CALL         },      // Call Conditionally
  { "cc",         CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Call Conditionally
  { "ccd",        CF_USE1|CF_USE2|CF_CALL         },      // Call Conditionally
  { "ccd",        CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Call Conditionally
  { "fcala",      CF_USE1|CF_CALL                 },      // Far Call Subroutine at Location Specified by Accumulator
  { "fcalad",     CF_USE1|CF_CALL                 },      // Far Call Subroutine at Location Specified by Accumulator
  { "fcall",      CF_USE1|CF_CALL                 },      // Far Call Unconditionally
  { "fcalld",     CF_USE1|CF_CALL                 },      // Far Call Unconditionally

  // INTERRUPT INSTRUCTIONS

  { "intr",       CF_USE1|CF_CALL                 },      // Software Interrupt
  { "trap",       CF_USE1|CF_CALL                 },      // Software Interrupt

  // RETURN INSTRUCTIONS

  { "fret",       CF_STOP                         },      // Far Return
  { "fretd",      0                               },      // Far Return
  { "frete",      CF_STOP                         },      // Enable Interrupts and Far Return From Interrupt
  { "freted",     0                               },      // Enable Interrupts and Far Return From Interrupt
  { "rc",         CF_USE1                         },      // Return Conditionally
  { "rc",         CF_USE1|CF_USE2                 },      // Return Conditionally
  { "rc",         CF_USE1|CF_USE2|CF_USE3         },      // Return Conditionally
  { "rcd",        CF_USE1                         },      // Return Conditionally
  { "rcd",        CF_USE1|CF_USE2                 },      // Return Conditionally
  { "rcd",        CF_USE1|CF_USE2|CF_USE3         },      // Return Conditionally
  { "ret",        CF_STOP                         },      // Return
  { "retd",       0                               },      // Return
  { "rete",       CF_STOP                         },      // Enable Interrupts and Far Return From Interrupt
  { "reted",      0                               },      // Enable Interrupts and Far Return From Interrupt
  { "retf",       CF_STOP                         },      // Enable Interrupts and Fast Return From Interrupt
  { "retfd",      0                               },      // Enable Interrupts and Fast Return From Interrupt

  // REPEAT INSTRUCTIONS

  { "rpt",        CF_USE1                         },      // Repeat Next Instruction
  { "rptb",       CF_USE1                         },      // Block Repeat
  { "rptbd",      CF_USE1                         },      // Block Repeat
  { "rptz",       CF_CHG1|CF_USE2                 },      // Repeat Next Instruction And Clear Accumulator

  // STACK MANIPULATING INSTRUCTIONS

  { "frame",      CF_USE1                         },      // Stack Pointer Immediate Offset
  { "popd",       CF_CHG1                         },      // Pop Top of Stack to Data Memory
  { "popm",       CF_CHG1                         },      // Pop Top of Stack to Memory-Mapped Register
  { "pshd",       CF_USE1                         },      // Push Data-Memory Value Onto Stack
  { "pshm",       CF_USE1                         },      // Push Memory-Mapped Register Onto Stack

  // MISCELLANEOUS PROGRAM-CONTROL INSTRUCTIONS

  { "idle",       CF_USE1                         },      // Idle Until Interrupt
  { "mar",        CF_USE1                         },      // Modify Auxiliary Register
  { "nop",        0                               },      // No Operation
  { "reset",      0                               },      // Software Reset
  { "rsbx",       CF_CHG1                         },      // Reset Status Register Bit
  { "rsbx",       CF_USE1|CF_USE2                 },      // Reset Status Register Bit
  { "ssbx",       CF_CHG1                         },      // Set Status Register Bit
  { "ssbx",       CF_USE1|CF_USE2                 },      // Set Status Register Bit
  { "xc",         CF_USE1|CF_USE2                 },      // Execute Conditionally
  { "xc",         CF_USE1|CF_USE2|CF_USE3         },      // Execute Conditionally

  // LOAD AND STORE OPERATIONS

  // LOAD INSTRUCTIONS

  { "dld",        CF_USE1|CF_CHG2                 },      // Double-Precision/Dual 16-Bit Long-Word Load to Accumulator
  { "ld",         CF_CHG1                         },      // Load Accumulator With Shift
  { "ld",         CF_USE1|CF_CHG2                 },      // Load Accumulator With Shift
  { "ld",         CF_USE1|CF_USE2|CF_CHG3         },      // Load Accumulator With Shift
  { "ldm",        CF_USE1|CF_CHG2                 },      // Load Memory-Mapped Register
  { "ldr",        CF_USE1|CF_CHG2                 },      // Load Memory Value in Accumulator High With Rounding
  { "ldu",        CF_USE1|CF_CHG2                 },      // Load Unsigned Memory Value
  { "ltd",        CF_USE1                         },      // Load T and insert Delay

  // STORE INSTRUCTIONS

  { "dst",        CF_USE1|CF_CHG2                 },      // Store Accumulator in Long Word
  { "st",         CF_USE1|CF_CHG2                 },      // Store T, TRN, or Immediate Value into Memory
  { "sth",        CF_USE1|CF_CHG2                 },      // Store Accumulator High Into Memory
  { "sth",        CF_USE1|CF_USE2|CF_CHG3         },      // Store Accumulator High Into Memory
  { "stl",        CF_USE1|CF_CHG2                 },      // Store Accumulator Low Into Memory
  { "stl",        CF_USE1|CF_USE2|CF_CHG3         },      // Store Accumulator Low Into Memory
  { "stlm",       CF_USE1|CF_CHG2                 },      // Store Accumulator Low Into Memory-Mapped Register
  { "stm",        CF_USE1|CF_CHG2                 },      // Store Immediate Value Into Memory-Mapped Register

  // CONDITIONAL STORE INSTRUCTIONS

  { "cmps",       CF_USE1|CF_CHG2                 },      // Compare, Select and Store Maximum
  { "saccd",      CF_USE1|CF_CHG2|CF_USE3         },      // Store Accumulator Conditionally
  { "srccd",      CF_CHG1|CF_USE2                 },      // Store Block Repeat Counter Conditionally
  { "strcd",      CF_CHG1|CF_USE2                 },      // Store T Conditionally

  // PARALLEL LOAD AND STORE INSTRUCTIONS

  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Load // TMS320C54_st_ld

  // PARALLEL LOAD AND MULTIPLY INSTRUCTIONS

  { "ld",         CF_USE1|CF_CHG2|CF_CHG3         },      // Load Accumulator With Parallel Multiply Accumulate Without Rounding // TMS320C54_ld_mac
  { "ld",         CF_USE1|CF_CHG2|CF_CHG3         },      // Load Accumulator With Parallel Multiply Accumulate With Rounding // TMS320C54_ld_macr
  { "ld",         CF_USE1|CF_CHG2|CF_CHG3         },      // Load Accumulator With Parallel Multiply Subtract Without Rounding // TMS320C54_ld_mas
  { "ld",         CF_USE1|CF_CHG2|CF_CHG3         },      // Load Accumulator With Parallel Multiply Subtract With Rounding // TMS320C54_ld_masr

  // PARALLEL STORE AND ADD/SUBSTRACT INSTRUCTIONS

  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Add // TMS320C54_st_add
  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Subtract // TMS320C54_st_sub

  // PARALLEL STORE AND MULTIPLY INSTRUCTIONS

  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Multiply Accumulate Without Rounding // TMS320C54_st_mac
  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Multiply Accumulate With Rounding // TMS320C54_st_macr
  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Multiply Subtract Without Rounding // TMS320C54_st_mas
  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Multiply Subtract With Rounding // TMS320C54_st_masr
  { "st",         CF_USE1|CF_CHG2|CF_CHG3         },      // Store Accumulator With Parallel Multiply // TMS320C54_st_mpy

  // MISCELLANEOUS LOAD-TYPE AND STORE-TYPE INSTRUCTIONS

  { "mvdd",       CF_USE1|CF_CHG2                 },      // Move Data From Data Memory to Data Memory With X,Y Addressing
  { "mvdk",       CF_USE1|CF_CHG2                 },      // Move Data From Data Memory to Data Memory With Destination Addressing
  { "mvdm",       CF_USE1|CF_CHG2                 },      // Move Data From Data Memory to Memory-Mapped Register
  { "mvdp",       CF_USE1|CF_CHG2                 },      // Move Data From Data Memory to Program Memory
  { "mvkd",       CF_USE1|CF_CHG2                 },      // Move Data From Data Memory to Data Memory With Source Addressing
  { "mvmd",       CF_USE1|CF_CHG2                 },      // Move Data From Memory-Mapped Register to Data Memory
  { "mvmm",       CF_USE1|CF_CHG2                 },      // Move Data From Memory-Mapped Register to Memory-Mapped Register
  { "mvpd",       CF_USE1|CF_CHG2                 },      // Move Data From Program Memory to Data Memory
  { "portr",      CF_USE1|CF_USE2                 },      // Read Data From Port
  { "portw",      CF_USE1|CF_USE2                 },      // Write Data to Port
  { "reada",      CF_CHG1                         },      // Read Program Memory Addressed by Accumulator A and Store in Data Memory
  { "writa",      CF_USE1                         },      // Write Data to Program Memory Addressed by Accumulator A

};

CASSERT(qnumber(Instructions) == TMS320C54_last);
