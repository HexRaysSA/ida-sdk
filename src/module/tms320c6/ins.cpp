/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#include "tms6.hpp"

const instruc_t Instructions[] =
{

  // Original TMS320C62x instructions

  { "",           0                               },      // Unknown Operation
  { "ABS",        CF_USE1|CF_CHG2                 },      // Absolute value
  { "ADD",        CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition without saturation (signed)
  { "ADDU",       CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition without saturation (unsigned)
  { "ADDAB",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition using addressing mode (byte)
  { "ADDAH",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition using addressing mode (halfword)
  { "ADDAW",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition using addressing mode (word)
  { "ADDK",       CF_USE1|CF_CHG2                 },      // Integer addition 16bit signed constant
  { "ADD2",       CF_USE1|CF_USE2|CF_CHG3         },      // Two 16bit Integer adds on register halves
  { "AND",        CF_USE1|CF_USE2|CF_CHG3         },      // Logical AND
  { "B",          CF_USE1                         },      // Branch
  { "CLR",        CF_USE1|CF_USE2|CF_CHG3         },      // Clear a bit field
  { "CMPEQ",      CF_USE1|CF_USE2|CF_CHG3         },      // Compare for equality
  { "CMPGT",      CF_USE1|CF_USE2|CF_CHG3         },      // Compare for greater than (signed)
  { "CMPGTU",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for greater than (unsigned)
  { "CMPLT",      CF_USE1|CF_USE2|CF_CHG3         },      // Compare for less than (signed)
  { "CMPLTU",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for less than (unsigned)
  { "EXT",        CF_USE1|CF_USE2|CF_CHG3         },      // Extract and sign-extend a bit filed
  { "EXTU",       CF_USE1|CF_USE2|CF_CHG3         },      // Extract an unsigned bit field
  { "IDLE",       CF_STOP                         },      // Multicycle NOP with no termination until interrupt
  { "LDB",        CF_USE1|CF_CHG2                 },      // Load from memory (signed 8bit)
  { "LDBU",       CF_USE1|CF_CHG2                 },      // Load from memory (unsigned 8bit)
  { "LDH",        CF_USE1|CF_CHG2                 },      // Load from memory (signed 16bit)
  { "LDHU",       CF_USE1|CF_CHG2                 },      // Load from memory (unsigned 16bit)
  { "LDW",        CF_USE1|CF_CHG2                 },      // Load from memory (32bit)
  { "LMBD",       CF_USE1|CF_USE2|CF_CHG3         },      // Leftmost bit detection
  { "MPY",        CF_USE1|CF_USE2|CF_CHG3         },      // Signed Integer Multiply (LSB16 x LSB16)
  { "MPYU",       CF_USE1|CF_USE2|CF_CHG3         },      // Unsigned Integer Multiply (LSB16 x LSB16)
  { "MPYUS",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Signed*Unsigned (LSB16 x LSB16)
  { "MPYSU",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Unsigned*Signed (LSB16 x LSB16)
  { "MPYH",       CF_USE1|CF_USE2|CF_CHG3         },      // Signed Integer Multiply (MSB16 x MSB16)
  { "MPYHU",      CF_USE1|CF_USE2|CF_CHG3         },      // Unsigned Integer Multiply (MSB16 x MSB16)
  { "MPYHUS",     CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Unsigned*Signed (MSB16 x MSB16)
  { "MPYHSU",     CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Signed*Unsigned (MSB16 x MSB16)
  { "MPYHL",      CF_USE1|CF_USE2|CF_CHG3         },      // Signed Integer Multiply (MSB16 x LSB16)
  { "MPYHLU",     CF_USE1|CF_USE2|CF_CHG3         },      // Unsigned Integer Multiply (MSB16 x LSB16)
  { "MPYHULS",    CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Signed*Unsigned (MSB16 x LSB16)
  { "MPYHSLU",    CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Unsigned*Signed (MSB16 x LSB16)
  { "MPYLH",      CF_USE1|CF_USE2|CF_CHG3         },      // Signed Integer Multiply (LSB16 x MB16)
  { "MPYLHU",     CF_USE1|CF_USE2|CF_CHG3         },      // Unsigned Integer Multiply (LSB16 x MSB16)
  { "MPYLUHS",    CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Signed*Unsigned (LSB16 x MSB16)
  { "MPYLSHU",    CF_USE1|CF_USE2|CF_CHG3         },      // Integer Multiply Unsigned*Signed (LSB16 x MSB16)
  { "MV",         CF_USE1|CF_CHG2                 },      // Move from register to register
  { "MVC",        CF_USE1|CF_CHG2                 },      // Move between the control file & register file
  { "MVK",        CF_USE1|CF_CHG2                 },      // Move a 16bit signed constant into register
  { "MVKH",       CF_USE1|CF_CHG2                 },      // Move a 16bit constant into the upper bits of a register
  { "MVKLH",      CF_USE1|CF_CHG2                 },      // Move a 16bit constant into the upper bits of a register
  { "NEG",        CF_USE1|CF_CHG2                 },      // Negate
  { "NOP",        CF_USE1                         },      // No operation
  { "NORM",       CF_USE1|CF_CHG2                 },      // Normalize
  { "NOT",        CF_USE1|CF_CHG2                 },      // Bitwise NOT
  { "OR",         CF_USE1|CF_USE2|CF_CHG3         },      // Logical or
  { "SADD",       CF_USE1|CF_USE2|CF_CHG3         },      // Integer addition with saturation
  { "SAT",        CF_USE1|CF_CHG2                 },      // Saturate 40bit value to 32bits
  { "SET",        CF_USE1|CF_USE2|CF_CHG3         },      // Set a bit field
  { "SHL",        CF_USE1|CF_USE2|CF_CHG3         },      // Arithmetic shift left
  { "SHR",        CF_USE1|CF_USE2|CF_CHG3         },      // Arithmetic shift right
  { "SHRU",       CF_USE1|CF_USE2|CF_CHG3         },      // Logical shift left
  { "SMPY",       CF_USE1|CF_USE2|CF_CHG3         },      // Integer multiply with left shift & saturation (LSB16*LSB16)
  { "SMPYHL",     CF_USE1|CF_USE2|CF_CHG3         },      // Integer multiply with left shift & saturation (MSB16*LSB16)
  { "SMPYLH",     CF_USE1|CF_USE2|CF_CHG3         },      // Integer multiply with left shift & saturation (LSB16*MSB16)
  { "SMPYH",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer multiply with left shift & saturation (MSB16*MSB16)
  { "SSHL",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift left with saturation
  { "SSUB",       CF_USE1|CF_USE2|CF_CHG3         },      // Integer substraction with saturation
  { "STB",        CF_USE1|CF_CHG2                 },      // Store to memory (signed 8bit)
  { "STBU",       CF_USE1|CF_CHG2                 },      // Store to memory (unsigned 8bit)
  { "STH",        CF_USE1|CF_CHG2                 },      // Store to memory (signed 16bit)
  { "STHU",       CF_USE1|CF_CHG2                 },      // Store to memory (unsigned 16bit)
  { "STW",        CF_USE1|CF_CHG2                 },      // Store to memory (32bit)
  { "SUB",        CF_USE1|CF_USE2|CF_CHG3         },      // Integer substaraction without saturation (signed)
  { "SUBU",       CF_USE1|CF_USE2|CF_CHG3         },      // Integer substaraction without saturation (unsigned)
  { "SUBAB",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer subtraction using addressing mode (byte)
  { "SUBAH",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer subtraction using addressing mode (halfword)
  { "SUBAW",      CF_USE1|CF_USE2|CF_CHG3         },      // Integer subtraction using addressing mode (word)
  { "SUBC",       CF_USE1|CF_USE2|CF_CHG3         },      // Conditional subtract & shift (for division)
  { "SUB2",       CF_USE1|CF_USE2|CF_CHG3         },      // Two 16bit integer subtractions on register halves
  { "XOR",        CF_USE1|CF_USE2|CF_CHG3         },      // Exclusive OR
  { "ZERO",       CF_CHG1                         },      // Zero a register

  // New TMS320C674x instructions

  { "ABS2",       CF_USE1|CF_CHG2                 },      // Absolute Value With Saturation, Signed, Packed 16-bit
  { "ABSDP",      CF_USE1|CF_CHG2                 },      // Absolute Value, Double-Precision Floating-Point
  { "ABSSP",      CF_USE1|CF_CHG2                 },      // Absolute Value, Single-Precision Floating-Point
  { "ADD4",       CF_USE1|CF_USE2|CF_CHG3         },      // Add Without Saturation, Four 8-Bit Pairs for Four 8-Bit Results
  { "ADDAD",      CF_USE1|CF_USE2|CF_CHG3         },      // Add Using Doubleword Addressing Mode
  { "ADDDP",      CF_USE1|CF_USE2|CF_CHG3         },      // Add Two Double-Precision Floating-Point Values
  { "ADDKPC",     CF_USE1|CF_CHG2|CF_USE3         },      // Add Signed 7-bit Constant to Program Counter
  { "ADDSP",      CF_USE1|CF_USE2|CF_CHG3         },      // Add Two Single-Precision Floating-Point Values
  { "ADDSUB",     CF_USE1|CF_USE2|CF_CHG3         },      // Parallel ADD and SUB Operations On Common Inputs
  { "ADDSUB2",    CF_USE1|CF_USE2|CF_CHG3         },      // Parallel ADD2 and SUB2 Operations On Common Inputs
  { "ANDN",       CF_USE1|CF_USE2|CF_CHG3         },      // Bitwise AND Invert
  { "AVG2",       CF_USE1|CF_USE2|CF_CHG3         },      // Average, Signed, Packed 16-bit
  { "AVGU4",      CF_USE1|CF_USE2|CF_CHG3         },      // Average, Unsigned, Packed 16-bit
  { "BDEC",       CF_USE1|CF_CHG2                 },      // Branch and Decrement
  { "BITC4",      CF_USE1|CF_CHG2                 },      // Bit Count, Packed 8-bit
  { "BITR",       CF_USE1|CF_CHG2                 },      // Bit Reverse
  { "BNOP",       CF_USE1|CF_USE2                 },      // Branch With NOP
  { "BPOS",       CF_USE1|CF_CHG2                 },      // Branch Positive
  { "CALLP",      CF_USE1|CF_CHG2                 },      // Call Using a Displacement
  { "CMPEQ2",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Equality, Packed 16-bit
  { "CMPEQ4",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Equality, Packed 8-bit
  { "CMPEQDP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Equality, Double-Precision Floating-Point Values
  { "CMPEQSP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Equality, Single-Precision Floating-Point Values
  { "CMPGT2",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Greater Than, Packed 16-bit
  { "CMPGTDP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Greater Than, Double-Precision Floating-Point Values
  { "CMPGTSP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Greater Than, Single-Precision Floating-Point Values
  { "CMPGTU4",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Greater Than, Unsigned, Packed 8-bit
  { "CMPLT2",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Less Than, Packed 16-bit
  { "CMPLTDP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Less Than, Double-Precision Floating-Point Values
  { "CMPLTSP",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Less Than, Single-Precision Floating-Point Values
  { "CMPLTU4",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare for Less Than, Unsigned, Packed 8-bit
  { "CMPY",       CF_USE1|CF_USE2|CF_CHG3         },      // Complex Multiply Two Pairs, Signed, Packed 16-bit
  { "CMPYR",      CF_USE1|CF_USE2|CF_CHG3         },      // Complex Multiply Two Pairs, Signed, Packed 16-bit With Rounding
  { "CMPYR1",     CF_USE1|CF_USE2|CF_CHG3         },      // Complex Multiply Two Pairs, Signed, Packed 16-bit With Rounding
  { "DDOTP4",     CF_USE1|CF_USE2|CF_CHG3         },      // Double Dot Product, Signed, Packed 16-Bit and Signed, Packed 8-Bit
  { "DDOTPH2",    CF_USE1|CF_USE2|CF_CHG3         },      // Double Dot Product, Two Pairs, Signed, Packed 16-Bit
  { "DDOTPH2R",   CF_USE1|CF_USE2|CF_CHG3         },      // Double Dot Product With Rounding, Two Pairs, Signed, Packed 16-Bit
  { "DDOTPL2",    CF_USE1|CF_USE2|CF_CHG3         },      // Double Dot Product, Two Pairs, Signed, Packed 16-Bit
  { "DDOTPL2R",   CF_USE1|CF_USE2|CF_CHG3         },      // Double Dot Product With Rounding, Two Pairs, Signed Packed 16-Bit
  { "DEAL",       CF_USE1|CF_CHG2                 },      // Deinterleave and Pack
  { "DINT",       0                               },      // Disable Interrupts and Save Previous Enable State
  { "DMV",        CF_USE1|CF_USE2|CF_CHG3         },      // Move Two Independent Registers to Register Pair
  { "DOTP2",      CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product, Signed, Packed 16-Bit
  { "DOTPN2",     CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product With Negate, Signed, Packed 16-Bit
  { "DOTPNRSU2",  CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product With Negate, Shift and Round, Signed by Unsigned, Packed 16-Bit
  { "DOTPNRUS2",  CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product With Negate, Shift and Round, Unsigned by Signed, Packed 16-Bit
  { "DOTPRSU2",   CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product With Shift and Round, Signed by Unsigned, Packed 16-Bit
  { "DOTPRUS2",   CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product With Shift and Round, Unsigned by Signed, Packed 16-Bit
  { "DOTPSU4",    CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product, Signed by Unsigned, Packed 8-Bit
  { "DOTPU4",     CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product, Unsigned, Packed 8-Bit
  { "DOTPUS4",    CF_USE1|CF_USE2|CF_CHG3         },      // Dot Product, Unsigned by Signed, Packed 8-Bit
  { "DPACK2",     CF_USE1|CF_USE2|CF_CHG3         },      // Parallel PACK2 and PACKH2 Operations
  { "DPACKX2",    CF_USE1|CF_USE2|CF_CHG3         },      // Parallel PACKLH2 Operations
  { "DPINT",      CF_USE1|CF_CHG2                 },      // Convert Double-Precision Floating-Point Value to Integer
  { "DPSP",       CF_USE1|CF_CHG2                 },      // Convert Double-Precision Floating-Point Value to Single-Precision Floating-Point Value
  { "DPTRUNC",    CF_USE1|CF_CHG2                 },      // Convert Double-Precision Floating-Point Value to Integer With Truncation
  { "GMPY",       CF_USE1|CF_USE2|CF_CHG3         },      // Galois Field Multiply
  { "GMPY4",      CF_USE1|CF_USE2|CF_CHG3         },      // Galois Field Multiply, Packed 8-Bit
  { "INTDP",      CF_USE1|CF_CHG2                 },      // Convert Signed Integer to Double-Precision Floating-Point Value
  { "INTDPU",     CF_USE1|CF_CHG2                 },      // Convert Unsigned Integer to Double-Precision Floating-Point Value
  { "INTSP",      CF_USE1|CF_CHG2                 },      // Convert Signed Integer to Single-Precision Floating-Point Value
  { "INTSPU",     CF_USE1|CF_CHG2                 },      // Convert Unsigned Integer to Single-Precision Floating-Point Value
  { "LDDW",       CF_USE1|CF_CHG2                 },      // Load Doubleword From Memory With a 5-Bit Unsigned Constant Offset or Register Offset
  { "LDNDW",      CF_USE1|CF_CHG2                 },      // Load Nonaligned Doubleword From Memory With Constant or Register Offset
  { "LDNW",       CF_USE1|CF_CHG2                 },      // Load Nonaligned Word From Memory With Constant or Register Offset
  { "MAX2",       CF_USE1|CF_USE2|CF_CHG3         },      // Maximum, Signed, Packed 16-Bit
  { "MAXU4",      CF_USE1|CF_USE2|CF_CHG3         },      // Maximum, Unsigned, Packed 8-Bit
  { "MIN2",       CF_USE1|CF_USE2|CF_CHG3         },      // Minimum, Signed, Packed 16-Bit
  { "MINU4",      CF_USE1|CF_USE2|CF_CHG3         },      // Minimum, Unsigned, Packed 8-Bit
  { "MPY2",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed by Signed, 16 LSB x 16 LSB and 16 MSB x 16 MSB
  { "MPY2IR",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Two 16-Bit x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
  { "MPY32",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed 32-Bit x Signed 32-Bit Into 32-Bit Result
  { "MPY32SU",    CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed 32-Bit x Unsigned 32-Bit Into Signed 64-Bit Result
  { "MPY32U",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Unsigned 32-Bit x Unsigned 32-Bit Into Unsigned 64-Bit Result
  { "MPY32US",    CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Unsigned 32-Bit x Signed 32-Bit Into Signed 64-Bit Result
  { "MPYDP",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Two Double-Precision Floating-Point Values
  { "MPYHI",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 16 MSB x 32-Bit Into 64-Bit Result
  { "MPYHIR",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 16 MSB x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
  { "MPYI",       CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 32-Bit Into 32-Bit Result
  { "MPYID",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 32-Bit Into 64-Bit Result
  { "MPYIH",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 16-MSB Into 64-Bit Result
  { "MPYIHR",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 16 MSB, Shifted by 15 to Produce a Rounded 32-Bit Result
  { "MPYIL",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 16 LSB Into 64-Bit Result
  { "MPYILR",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 32-Bit x 16 LSB, Shifted by 15 to Produce a Rounded 32-Bit Result
  { "MPYLI",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 16 LSB x 32-Bit Into 64-Bit Result
  { "MPYLIR",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply 16 LSB x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
  { "MPYSP",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Two Single-Precision Floating-Point Values
  { "MPYSP2DP",   CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Two Single-Precision Floating-Point Values for Double-Precision Result
  { "MPYSPDP",    CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Single-Precision Floating-Point Value x Double-Precision Floating-Point Value
  { "MPYSU4",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed x Unsigned, Four 8-Bit Pairs for Four 8-Bit Results
  { "MPYU4",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Unsigned x Unsigned, Four 8-Bit Pairs for Four 8-Bit Results
  { "MPYUS4",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Unsigned x Signed, Four 8-Bit Pairs for Four 8-Bit Results
  { "MVD",        CF_USE1|CF_CHG2                 },      // Move From Register to Register, Delayed
  { "MVKL",       CF_USE1|CF_CHG2                 },      // Move Signed Constant Into Register and Sign Extend
  { "PACK2",      CF_USE1|CF_USE2|CF_CHG3         },      // Pack Two 16 LSBs Into Upper and Lower Register Halves
  { "PACKH2",     CF_USE1|CF_USE2|CF_CHG3         },      // Pack Two 16 MSBs Into Upper and Lower Register Halves
  { "PACKH4",     CF_USE1|CF_USE2|CF_CHG3         },      // Pack Four High Bytes Into Four 8-Bit Halfwords
  { "PACKHL2",    CF_USE1|CF_USE2|CF_CHG3         },      // Pack 16 MSB Into Upper and 16 LSB Into Lower Register Halves
  { "PACKL4",     CF_USE1|CF_USE2|CF_CHG3         },      // Pack Four Low Bytes Into Four 8-Bit Halfwords
  { "PACKLH2",    CF_USE1|CF_USE2|CF_CHG3         },      // Pack 16 LSB Into Upper and 16 MSB Into Lower Register Halves
  { "RCPDP",      CF_USE1|CF_CHG2                 },      // Double-Precision Floating-Point Reciprocal Approximation
  { "RCPSP",      CF_USE1|CF_CHG2                 },      // Single-Precision Floating-Point Reciprocal Approximation
  { "RINT",       0                               },      // Restore Previous Enable State
  { "ROTL",       CF_USE1|CF_USE2|CF_CHG3         },      // Rotate Left
  { "RPACK2",     CF_USE1|CF_USE2|CF_CHG3         },      // Shift With Saturation and Pack Two 16 MSBs Into Upper and Lower Register Halves
  { "RSQRDP",     CF_USE1|CF_CHG2                 },      // Double-Precision Floating-Point Square-Root Reciprocal Approximation
  { "RSQRSP",     CF_USE1|CF_CHG2                 },      // Single-Precision Floating-Point Square-Root Reciprocal Approximation
  { "SADD2",      CF_USE1|CF_USE2|CF_CHG3         },      // Add Two Signed 16-Bit Integers on Upper and Lower Register Halves With Saturation
  { "SADDSU2",    CF_USE1|CF_USE2|CF_CHG3         },      // Add Two Signed and Unsigned 16-Bit Integers on Register Halves With Saturation
  { "SADDSUB",    CF_USE1|CF_USE2|CF_CHG3         },      // Parallel SADD and SSUB Operations On Common Inputs
  { "SADDSUB2",   CF_USE1|CF_USE2|CF_CHG3         },      // Parallel SADD2 and SSUB2 Operations On Common Inputs
  { "SADDU4",     CF_USE1|CF_USE2|CF_CHG3         },      // Add With Saturation, Four Unsigned 8-Bit Pairs for Four 8-Bit Results
  { "SADDUS2",    CF_USE1|CF_USE2|CF_CHG3         },      // Add Two Unsigned and Signed 16-Bit Integers on Register Halves With Saturation
  { "SHFL",       CF_USE1|CF_CHG2                 },      // Shuffle
  { "SHFL3",      CF_USE1|CF_USE2|CF_CHG3         },      // 3-Way Bit Interleave On Three 16-Bit Values Into a 48-Bit Result
  { "SHLMB",      CF_USE1|CF_USE2|CF_CHG3         },      // Shift Left and Merge Byte
  { "SHR2",       CF_USE1|CF_USE2|CF_CHG3         },      // Arithmetic Shift Right, Signed, Packed 16-Bit
  { "SHRMB",      CF_USE1|CF_USE2|CF_CHG3         },      // Shift Right and Merge Byte
  { "SHRU2",      CF_USE1|CF_USE2|CF_CHG3         },      // Arithmetic Shift Right, Unsigned, Packed 16-Bit
  { "SMPY2",      CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed by Signed, 16 LSB x 16 LSB and 16 MSB x 16 MSB With Left Shift and Saturation
  { "SMPY32",     CF_USE1|CF_USE2|CF_CHG3         },      // Multiply Signed 32-Bit x Signed 32-Bit Into 64-Bit Result With Left Shift and Saturation
  { "SPACK2",     CF_USE1|CF_USE2|CF_CHG3         },      // Saturate and Pack Two 16 LSBs Into Upper and Lower Register Halves
  { "SPACKU4",    CF_USE1|CF_USE2|CF_CHG3         },      // Saturate and Pack Four Signed 16-Bit Integers Into Four Unsigned 8-Bit Halfwords
  { "SPDP",       CF_USE1|CF_CHG2                 },      // Convert Single-Precision Floating-Point Value to Double-Precision Floating-Point Value
  { "SPINT",      CF_USE1|CF_CHG2                 },      // Convert Single-Precision Floating-Point Value to Integer
  { "SPKERNEL",   CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation Code Boundary
  { "SPKERNELR",  0                               },      // Software Pipelined Loop (SPLOOP) Buffer Operation Code Boundary
  { "SPLOOP",     CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation
  { "SPLOOPD",    CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation With Delayed Testing
  { "SPLOOPW",    CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation With Delayed Testing and No Epilog
  { "SPMASK",     CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation Load/Execution Control
  { "SPMASKR",    CF_USE1                         },      // Software Pipelined Loop (SPLOOP) Buffer Operation Load/Execution Control
  { "SPTRUNC",    CF_USE1|CF_CHG2                 },      // Convert Single-Precision Floating-Point Value to Integer With Truncation
  { "SSHVL",      CF_USE1|CF_USE2|CF_CHG3         },      // Variable Shift Left
  { "SSHVR",      CF_USE1|CF_USE2|CF_CHG3         },      // Variable Shift Right
  { "SSUB2",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract Two Signed 16-Bit Integers on Upper and Lower Register Halves With Saturation
  { "STDW",       CF_USE1|CF_CHG2                 },      // Store Doubleword to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
  { "STNDW",      CF_USE1|CF_CHG2                 },      // Store Nonaligned Doubleword to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
  { "STNW",       CF_USE1|CF_CHG2                 },      // Store Nonaligned Word to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
  { "SUB4",       CF_USE1|CF_USE2|CF_CHG3         },      // Subtract Without Saturation, Four 8-Bit Pairs for Four 8-Bit Results
  { "SUBABS4",    CF_USE1|CF_USE2|CF_CHG3         },      // Subtract With Absolute Value, Four 8-Bit Pairs for Four 8-Bit Results
  { "SUBDP",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract Two Double-Precision Floating-Point Values
  { "SUBSP",      CF_USE1|CF_USE2|CF_CHG3         },      // Subtract Two Single-Precision Floating-Point Values
  { "SWAP2",      CF_USE1|CF_CHG2                 },      // Swap Bytes in Upper and Lower Register Halves
  { "SWAP4",      CF_USE1|CF_CHG2                 },      // Swap Byte Pairs in Upper and Lower Register Halves
  { "SWE",        0                               },      // Software Exception
  { "SWENR",      0                               },      // Software Exception, No Return
  { "UNPKHU4",    CF_USE1|CF_CHG2                 },      // Unpack 16 MSB Into Two Lower 8-Bit Halfwords of Upper and Lower Register Halves
  { "UNPKLU4",    CF_USE1|CF_CHG2                 },      // Unpack 16 LSB Into Two Lower 8-Bit Halfwords of Upper and Lower Register Halves
  { "XORMPY",     CF_USE1|CF_USE2|CF_CHG3         },      // Galois Field Multiply With Zero Polynomial
  { "XPND2",      CF_USE1|CF_CHG2                 },      // Expand Bits to Packed 16-Bit Masks
  { "XPND4",      CF_USE1|CF_CHG2                 },      // Expand Bits to Packed 8-Bit Masks

};

CASSERT(qnumber(Instructions) == TMS6_last);
