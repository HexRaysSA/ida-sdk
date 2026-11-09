/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
// Original TMS320C62x instructions

TMS6_null = 0,  // Unknown Operation
TMS6_abs,       // Absolute value
TMS6_add,       // Integer addition without saturation (signed)
TMS6_addu,      // Integer addition without saturation (unsigned)
TMS6_addab,     // Integer addition using addressing mode (byte)
TMS6_addah,     // Integer addition using addressing mode (halfword)
TMS6_addaw,     // Integer addition using addressing mode (word)
TMS6_addk,      // Integer addition 16bit signed constant
TMS6_add2,      // Two 16bit Integer adds on register halves
TMS6_and,       // Logical AND
TMS6_b,         // Branch
TMS6_clr,       // Clear a bit field
TMS6_cmpeq,     // Compare for equality
TMS6_cmpgt,     // Compare for greater than (signed)
TMS6_cmpgtu,    // Compare for greater than (unsigned)
TMS6_cmplt,     // Compare for less than (signed)
TMS6_cmpltu,    // Compare for less than (unsigned)
TMS6_ext,       // Extract and sign-extend a bit filed
TMS6_extu,      // Extract an unsigned bit field
TMS6_idle,      // Multicycle NOP with no termination until interrupt
TMS6_ldb,       // Load from memory (signed 8bit)
TMS6_ldbu,      // Load from memory (unsigned 8bit)
TMS6_ldh,       // Load from memory (signed 16bit)
TMS6_ldhu,      // Load from memory (unsigned 16bit)
TMS6_ldw,       // Load from memory (32bit)
TMS6_lmbd,      // Leftmost bit detection
TMS6_mpy,       // Signed Integer Multiply (LSB16 x LSB16)
TMS6_mpyu,      // Unsigned Integer Multiply (LSB16 x LSB16)
TMS6_mpyus,     // Integer Multiply Signed*Unsigned (LSB16 x LSB16)
TMS6_mpysu,     // Integer Multiply Unsigned*Signed (LSB16 x LSB16)
TMS6_mpyh,      // Signed Integer Multiply (MSB16 x MSB16)
TMS6_mpyhu,     // Unsigned Integer Multiply (MSB16 x MSB16)
TMS6_mpyhus,    // Integer Multiply Unsigned*Signed (MSB16 x MSB16)
TMS6_mpyhsu,    // Integer Multiply Signed*Unsigned (MSB16 x MSB16)
TMS6_mpyhl,     // Signed Integer Multiply (MSB16 x LSB16)
TMS6_mpyhlu,    // Unsigned Integer Multiply (MSB16 x LSB16)
TMS6_mpyhuls,   // Integer Multiply Signed*Unsigned (MSB16 x LSB16)
TMS6_mpyhslu,   // Integer Multiply Unsigned*Signed (MSB16 x LSB16)
TMS6_mpylh,     // Signed Integer Multiply (LSB16 x MB16)
TMS6_mpylhu,    // Unsigned Integer Multiply (LSB16 x MSB16)
TMS6_mpyluhs,   // Integer Multiply Signed*Unsigned (LSB16 x MSB16)
TMS6_mpylshu,   // Integer Multiply Unsigned*Signed (LSB16 x MSB16)
TMS6_mv,        // Move from register to register
TMS6_mvc,       // Move between the control file & register file
TMS6_mvk,       // Move a 16bit signed constant into register
TMS6_mvkh,      // Move a 16bit constant into the upper bits of a register
TMS6_mvklh,     // Move a 16bit constant into the upper bits of a register
TMS6_neg,       // Negate
TMS6_nop,       // No operation
TMS6_norm,      // Normalize
TMS6_not,       // Bitwise NOT
TMS6_or,        // Logical or
TMS6_sadd,      // Integer addition with saturation
TMS6_sat,       // Saturate 40bit value to 32bits
TMS6_set,       // Set a bit field
TMS6_shl,       // Arithmetic shift left
TMS6_shr,       // Arithmetic shift right
TMS6_shru,      // Logical shift left
TMS6_smpy,      // Integer multiply with left shift & saturation (LSB16*LSB16)
TMS6_smpyhl,    // Integer multiply with left shift & saturation (MSB16*LSB16)
TMS6_smpylh,    // Integer multiply with left shift & saturation (LSB16*MSB16)
TMS6_smpyh,     // Integer multiply with left shift & saturation (MSB16*MSB16)
TMS6_sshl,      // Shift left with saturation
TMS6_ssub,      // Integer substraction with saturation
TMS6_stb,       // Store to memory (signed 8bit)
TMS6_stbu,      // Store to memory (unsigned 8bit)
TMS6_sth,       // Store to memory (signed 16bit)
TMS6_sthu,      // Store to memory (unsigned 16bit)
TMS6_stw,       // Store to memory (32bit)
TMS6_sub,       // Integer substaraction without saturation (signed)
TMS6_subu,      // Integer substaraction without saturation (unsigned)
TMS6_subab,     // Integer subtraction using addressing mode (byte)
TMS6_subah,     // Integer subtraction using addressing mode (halfword)
TMS6_subaw,     // Integer subtraction using addressing mode (word)
TMS6_subc,      // Conditional subtract & shift (for division)
TMS6_sub2,      // Two 16bit integer subtractions on register halves
TMS6_xor,       // Exclusive OR
TMS6_zero,      // Zero a register

// New TMS320C674x instructions

TMS6_abs2,      // Absolute Value With Saturation, Signed, Packed 16-bit
TMS6_absdp,     // Absolute Value, Double-Precision Floating-Point
TMS6_abssp,     // Absolute Value, Single-Precision Floating-Point
TMS6_add4,      // Add Without Saturation, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_addad,     // Add Using Doubleword Addressing Mode
TMS6_adddp,     // Add Two Double-Precision Floating-Point Values
TMS6_addkpc,    // Add Signed 7-bit Constant to Program Counter
TMS6_addsp,     // Add Two Single-Precision Floating-Point Values
TMS6_addsub,    // Parallel ADD and SUB Operations On Common Inputs
TMS6_addsub2,   // Parallel ADD2 and SUB2 Operations On Common Inputs
TMS6_andn,      // Bitwise AND Invert
TMS6_avg2,      // Average, Signed, Packed 16-bit
TMS6_avgu4,     // Average, Unsigned, Packed 16-bit
TMS6_bdec,      // Branch and Decrement
TMS6_bitc4,     // Bit Count, Packed 8-bit
TMS6_bitr,      // Bit Reverse
TMS6_bnop,      // Branch With NOP
TMS6_bpos,      // Branch Positive
TMS6_callp,     // Call Using a Displacement
TMS6_cmpeq2,    // Compare for Equality, Packed 16-bit
TMS6_cmpeq4,    // Compare for Equality, Packed 8-bit
TMS6_cmpeqdp,   // Compare for Equality, Double-Precision Floating-Point Values
TMS6_cmpeqsp,   // Compare for Equality, Single-Precision Floating-Point Values
TMS6_cmpgt2,    // Compare for Greater Than, Packed 16-bit
TMS6_cmpgtdp,   // Compare for Greater Than, Double-Precision Floating-Point Values
TMS6_cmpgtsp,   // Compare for Greater Than, Single-Precision Floating-Point Values
TMS6_cmpgtu4,   // Compare for Greater Than, Unsigned, Packed 8-bit
TMS6_cmplt2,    // Compare for Less Than, Packed 16-bit
TMS6_cmpltdp,   // Compare for Less Than, Double-Precision Floating-Point Values
TMS6_cmpltsp,   // Compare for Less Than, Single-Precision Floating-Point Values
TMS6_cmpltu4,   // Compare for Less Than, Unsigned, Packed 8-bit
TMS6_cmpy,      // Complex Multiply Two Pairs, Signed, Packed 16-bit
TMS6_cmpyr,     // Complex Multiply Two Pairs, Signed, Packed 16-bit With Rounding
TMS6_cmpyr1,    // Complex Multiply Two Pairs, Signed, Packed 16-bit With Rounding
TMS6_ddotp4,    // Double Dot Product, Signed, Packed 16-Bit and Signed, Packed 8-Bit
TMS6_ddotph2,   // Double Dot Product, Two Pairs, Signed, Packed 16-Bit
TMS6_ddotph2r,  // Double Dot Product With Rounding, Two Pairs, Signed, Packed 16-Bit
TMS6_ddotpl2,   // Double Dot Product, Two Pairs, Signed, Packed 16-Bit
TMS6_ddotpl2r,  // Double Dot Product With Rounding, Two Pairs, Signed Packed 16-Bit
TMS6_deal,      // Deinterleave and Pack
TMS6_dint,      // Disable Interrupts and Save Previous Enable State
TMS6_dmv,       // Move Two Independent Registers to Register Pair
TMS6_dotp2,     // Dot Product, Signed, Packed 16-Bit
TMS6_dotpn2,    // Dot Product With Negate, Signed, Packed 16-Bit
TMS6_dotpnrsu2, // Dot Product With Negate, Shift and Round, Signed by Unsigned, Packed 16-Bit
TMS6_dotpnrus2, // Dot Product With Negate, Shift and Round, Unsigned by Signed, Packed 16-Bit
TMS6_dotprsu2,  // Dot Product With Shift and Round, Signed by Unsigned, Packed 16-Bit
TMS6_dotprus2,  // Dot Product With Shift and Round, Unsigned by Signed, Packed 16-Bit
TMS6_dotpsu4,   // Dot Product, Signed by Unsigned, Packed 8-Bit
TMS6_dotpu4,    // Dot Product, Unsigned, Packed 8-Bit
TMS6_dotpus4,   // Dot Product, Unsigned by Signed, Packed 8-Bit
TMS6_dpack2,    // Parallel PACK2 and PACKH2 Operations
TMS6_dpackx2,   // Parallel PACKLH2 Operations
TMS6_dpint,     // Convert Double-Precision Floating-Point Value to Integer
TMS6_dpsp,      // Convert Double-Precision Floating-Point Value to Single-Precision Floating-Point Value
TMS6_dptrunc,   // Convert Double-Precision Floating-Point Value to Integer With Truncation
TMS6_gmpy,      // Galois Field Multiply
TMS6_gmpy4,     // Galois Field Multiply, Packed 8-Bit
TMS6_intdp,     // Convert Signed Integer to Double-Precision Floating-Point Value
TMS6_intdpu,    // Convert Unsigned Integer to Double-Precision Floating-Point Value
TMS6_intsp,     // Convert Signed Integer to Single-Precision Floating-Point Value
TMS6_intspu,    // Convert Unsigned Integer to Single-Precision Floating-Point Value
TMS6_lddw,      // Load Doubleword From Memory With a 5-Bit Unsigned Constant Offset or Register Offset
TMS6_ldndw,     // Load Nonaligned Doubleword From Memory With Constant or Register Offset
TMS6_ldnw,      // Load Nonaligned Word From Memory With Constant or Register Offset
TMS6_max2,      // Maximum, Signed, Packed 16-Bit
TMS6_maxu4,     // Maximum, Unsigned, Packed 8-Bit
TMS6_min2,      // Minimum, Signed, Packed 16-Bit
TMS6_minu4,     // Minimum, Unsigned, Packed 8-Bit
TMS6_mpy2,      // Multiply Signed by Signed, 16 LSB x 16 LSB and 16 MSB x 16 MSB
TMS6_mpy2ir,    // Multiply Two 16-Bit x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
TMS6_mpy32,     // Multiply Signed 32-Bit x Signed 32-Bit Into 32-Bit Result
TMS6_mpy32su,   // Multiply Signed 32-Bit x Unsigned 32-Bit Into Signed 64-Bit Result
TMS6_mpy32u,    // Multiply Unsigned 32-Bit x Unsigned 32-Bit Into Unsigned 64-Bit Result
TMS6_mpy32us,   // Multiply Unsigned 32-Bit x Signed 32-Bit Into Signed 64-Bit Result
TMS6_mpydp,     // Multiply Two Double-Precision Floating-Point Values
TMS6_mpyhi,     // Multiply 16 MSB x 32-Bit Into 64-Bit Result
TMS6_mpyhir,    // Multiply 16 MSB x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
TMS6_mpyi,      // Multiply 32-Bit x 32-Bit Into 32-Bit Result
TMS6_mpyid,     // Multiply 32-Bit x 32-Bit Into 64-Bit Result
TMS6_mpyih,     // Multiply 32-Bit x 16-MSB Into 64-Bit Result
TMS6_mpyihr,    // Multiply 32-Bit x 16 MSB, Shifted by 15 to Produce a Rounded 32-Bit Result
TMS6_mpyil,     // Multiply 32-Bit x 16 LSB Into 64-Bit Result
TMS6_mpyilr,    // Multiply 32-Bit x 16 LSB, Shifted by 15 to Produce a Rounded 32-Bit Result
TMS6_mpyli,     // Multiply 16 LSB x 32-Bit Into 64-Bit Result
TMS6_mpylir,    // Multiply 16 LSB x 32-Bit, Shifted by 15 to Produce a Rounded 32-Bit Result
TMS6_mpysp,     // Multiply Two Single-Precision Floating-Point Values
TMS6_mpysp2dp,  // Multiply Two Single-Precision Floating-Point Values for Double-Precision Result
TMS6_mpyspdp,   // Multiply Single-Precision Floating-Point Value x Double-Precision Floating-Point Value
TMS6_mpysu4,    // Multiply Signed x Unsigned, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_mpyu4,     // Multiply Unsigned x Unsigned, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_mpyus4,    // Multiply Unsigned x Signed, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_mvd,       // Move From Register to Register, Delayed
TMS6_mvkl,      // Move Signed Constant Into Register and Sign Extend
TMS6_pack2,     // Pack Two 16 LSBs Into Upper and Lower Register Halves
TMS6_packh2,    // Pack Two 16 MSBs Into Upper and Lower Register Halves
TMS6_packh4,    // Pack Four High Bytes Into Four 8-Bit Halfwords
TMS6_packhl2,   // Pack 16 MSB Into Upper and 16 LSB Into Lower Register Halves
TMS6_packl4,    // Pack Four Low Bytes Into Four 8-Bit Halfwords
TMS6_packlh2,   // Pack 16 LSB Into Upper and 16 MSB Into Lower Register Halves
TMS6_rcpdp,     // Double-Precision Floating-Point Reciprocal Approximation
TMS6_rcpsp,     // Single-Precision Floating-Point Reciprocal Approximation
TMS6_rint,      // Restore Previous Enable State
TMS6_rotl,      // Rotate Left
TMS6_rpack2,    // Shift With Saturation and Pack Two 16 MSBs Into Upper and Lower Register Halves
TMS6_rsqrdp,    // Double-Precision Floating-Point Square-Root Reciprocal Approximation
TMS6_rsqrsp,    // Single-Precision Floating-Point Square-Root Reciprocal Approximation
TMS6_sadd2,     // Add Two Signed 16-Bit Integers on Upper and Lower Register Halves With Saturation
TMS6_saddsu2,   // Add Two Signed and Unsigned 16-Bit Integers on Register Halves With Saturation
TMS6_saddsub,   // Parallel SADD and SSUB Operations On Common Inputs
TMS6_saddsub2,  // Parallel SADD2 and SSUB2 Operations On Common Inputs
TMS6_saddu4,    // Add With Saturation, Four Unsigned 8-Bit Pairs for Four 8-Bit Results
TMS6_saddus2,   // Add Two Unsigned and Signed 16-Bit Integers on Register Halves With Saturation
TMS6_shfl,      // Shuffle
TMS6_shfl3,     // 3-Way Bit Interleave On Three 16-Bit Values Into a 48-Bit Result
TMS6_shlmb,     // Shift Left and Merge Byte
TMS6_shr2,      // Arithmetic Shift Right, Signed, Packed 16-Bit
TMS6_shrmb,     // Shift Right and Merge Byte
TMS6_shru2,     // Arithmetic Shift Right, Unsigned, Packed 16-Bit
TMS6_smpy2,     // Multiply Signed by Signed, 16 LSB x 16 LSB and 16 MSB x 16 MSB With Left Shift and Saturation
TMS6_smpy32,    // Multiply Signed 32-Bit x Signed 32-Bit Into 64-Bit Result With Left Shift and Saturation
TMS6_spack2,    // Saturate and Pack Two 16 LSBs Into Upper and Lower Register Halves
TMS6_spacku4,   // Saturate and Pack Four Signed 16-Bit Integers Into Four Unsigned 8-Bit Halfwords
TMS6_spdp,      // Convert Single-Precision Floating-Point Value to Double-Precision Floating-Point Value
TMS6_spint,     // Convert Single-Precision Floating-Point Value to Integer
TMS6_spkernel,  // Software Pipelined Loop (SPLOOP) Buffer Operation Code Boundary
TMS6_spkernelr, // Software Pipelined Loop (SPLOOP) Buffer Operation Code Boundary
TMS6_sploop,    // Software Pipelined Loop (SPLOOP) Buffer Operation
TMS6_sploopd,   // Software Pipelined Loop (SPLOOP) Buffer Operation With Delayed Testing
TMS6_sploopw,   // Software Pipelined Loop (SPLOOP) Buffer Operation With Delayed Testing and No Epilog
TMS6_spmask,    // Software Pipelined Loop (SPLOOP) Buffer Operation Load/Execution Control
TMS6_spmaskr,   // Software Pipelined Loop (SPLOOP) Buffer Operation Load/Execution Control
TMS6_sptrunc,   // Convert Single-Precision Floating-Point Value to Integer With Truncation
TMS6_sshvl,     // Variable Shift Left
TMS6_sshvr,     // Variable Shift Right
TMS6_ssub2,     // Subtract Two Signed 16-Bit Integers on Upper and Lower Register Halves With Saturation
TMS6_stdw,      // Store Doubleword to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
TMS6_stndw,     // Store Nonaligned Doubleword to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
TMS6_stnw,      // Store Nonaligned Word to Memory With a 5-Bit Unsigned Constant Offset or Register Offset
TMS6_sub4,      // Subtract Without Saturation, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_subabs4,   // Subtract With Absolute Value, Four 8-Bit Pairs for Four 8-Bit Results
TMS6_subdp,     // Subtract Two Double-Precision Floating-Point Values
TMS6_subsp,     // Subtract Two Single-Precision Floating-Point Values
TMS6_swap2,     // Swap Bytes in Upper and Lower Register Halves
TMS6_swap4,     // Swap Byte Pairs in Upper and Lower Register Halves
TMS6_swe,       // Software Exception
TMS6_swenr,     // Software Exception, no Return
TMS6_unpkhu4,   // Unpack 16 MSB Into Two Lower 8-Bit Halfwords of Upper and Lower Register Halves
TMS6_unpklu4,   // Unpack 16 LSB Into Two Lower 8-Bit Halfwords of Upper and Lower Register Halves
TMS6_xormpy,    // Galois Field Multiply With Zero Polynomial
TMS6_xpnd2,     // Expand Bits to Packed 16-Bit Masks
TMS6_xpnd4,     // Expand Bits to Packed 8-Bit Masks

TMS6_last,

    };

#endif
