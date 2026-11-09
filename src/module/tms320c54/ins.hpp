/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{

TMS320C54_null = 0, // Unknown Operation

// ARITHMETIC OPERATIONS

// ADD INSTRUCTIONS

TMS320C54_add1,     // Add to Accumulator
TMS320C54_add2,     // Add to Accumulator
TMS320C54_add3,     // Add to Accumulator
TMS320C54_addc,    // Add to Accumulator With Carry
TMS320C54_addm,    // Add Long-Immediate Value to Memory
TMS320C54_adds,    // Add to Accumulator With Sign-Extension Suppressed

// SUBTRACT INSTRUCTIONS

TMS320C54_sub1,     // Sub From Accumulator
TMS320C54_sub2,     // Sub From Accumulator
TMS320C54_sub3,     // Sub From Accumulator
TMS320C54_subb,    // Sub From Accumulator With Borrow
TMS320C54_subc,    // Subtract Conditionally
TMS320C54_subs,    // Subtract From Accumulator With Sign Extension Suppressed

// MULTIPLY INSTRUCTIONS

TMS320C54_mpy2,    // Multiply Without Rounding
TMS320C54_mpy3,    // Multiply Without Rounding
TMS320C54_mpyr2,   // Multiply With Rounding
TMS320C54_mpya,    // Multiply by Accumulator A
TMS320C54_mpyu,    // Multiply Unsigned
TMS320C54_squr,    // Square

// MULTIPLY-ACCUMULATE AND MULTIPLY-SUBTRACT INSTRUCTIONS

TMS320C54_mac2,    // Multiply Accumulate Without Rounding
TMS320C54_mac3,    // Multiply Accumulate Without Rounding
TMS320C54_macr2,   // Multiply Accumulate With Rounding
TMS320C54_macr3,   // Multiply Accumulate With Rounding
TMS320C54_maca1,   // Multiply by Accumulator A and Accumulate Without Rounding
TMS320C54_maca2,   // Multiply by Accumulator A and Accumulate Without Rounding
TMS320C54_maca3,   // Multiply by Accumulator A and Accumulate Without Rounding
TMS320C54_macar1,  // Multiply by Accumulator A and Accumulate With Rounding
TMS320C54_macar2,  // Multiply by Accumulator A and Accumulate With Rounding
TMS320C54_macar3,  // Multiply by Accumulator A and Accumulate With Rounding
TMS320C54_macd,    // Multiply by Program Memory and Accumulate With Delay
TMS320C54_macp,    // Multiply by Program Memory and Accumulate
TMS320C54_macsu,   // Multiply Signed by Unsigned and Accumulate
TMS320C54_mas2,    // Multiply and Subtract Without Rounding
TMS320C54_mas3,    // Multiply and Subtract Without Rounding
TMS320C54_masr2,   // Multiply and Subtract With Rounding
TMS320C54_masr3,   // Multiply and Subtract With Rounding
// TMS320C54_mas,
TMS320C54_masa1,   // Multiply by Accumulator A and Subtract Without Rounding
TMS320C54_masa2,   // Multiply by Accumulator A and Subtract Without Rounding
TMS320C54_masa3,   // Multiply by Accumulator A and Subtract Without Rounding
TMS320C54_masar1,  // Multiply by Accumulator A and Subtract With Rounding
TMS320C54_masar2,  // Multiply by Accumulator A and Subtract With Rounding
TMS320C54_masar3,  // Multiply by Accumulator A and Subtract With Rounding
TMS320C54_squra,   // Square and Accumulate
TMS320C54_squrs,   // Square and Subtract

// DOUBLE INSTRUCTIONS

TMS320C54_dadd2,   // Double-Precision/Dual 16-Bit Add to Accumulator
TMS320C54_dadd3,   // Double-Precision/Dual 16-Bit Add to Accumulator
TMS320C54_dadst,   // Double-Precision Load With T Add/Dual 16-Bit Load With T Add/Subtract
TMS320C54_drsub,   // Double-Precision/Dual 16-Bit Subtract From Long Word
TMS320C54_dsadt,   // Long-Word Load With T Add/Dual 16-Bit Load With T Subtract/Add
TMS320C54_dsub,    // Double-Precision/Dual 16-Bit Subtract From Accumulator
TMS320C54_dsubt,   // Long-Word Load With T Subtract/Dual 16-Bit Load With T Subtract

// APPLICATION-SPECIFIC INSTRUCTIONS

TMS320C54_abdst,   // Absolute distance
TMS320C54_abs1,    // Absolute Value of Accumulator
TMS320C54_abs2,    // Absolute Value of Accumulator
TMS320C54_cmpl1,   // Complement Accumulator
TMS320C54_cmpl2,   // Complement Accumulator
TMS320C54_delay,   // Memory Delay
TMS320C54_exp,     // Accumulator Exponent
TMS320C54_firs,    // Symmetrical Finite Impulse Response Filter
TMS320C54_lms,     // Least Mean Square
TMS320C54_max,     // Accumulator Maximum
TMS320C54_min,     // Accumulator Minimum
TMS320C54_neg1,    // Negate Accumulator
TMS320C54_neg2,    // Negate Accumulator
TMS320C54_norm1,   // Normalization
TMS320C54_norm2,   // Normalization
TMS320C54_poly,    // Polynominal Evaluation
TMS320C54_rnd1,    // Round Accumulator
TMS320C54_rnd2,    // Round Accumulator
TMS320C54_sat,     // Saturate Accumulator
TMS320C54_sqdst,   // Square Distance

// LOGICAL OPERATIONS

// AND INSTRUCTIONS

TMS320C54_and1,    // AND With Accumulator
TMS320C54_and2,    // AND With Accumulator
TMS320C54_and3,    // AND With Accumulator
TMS320C54_andm,    // AND Memory With Long Immediate

// OR INSTRUCTIONS

TMS320C54_or1,     // OR With Accumulator
TMS320C54_or2,     // OR With Accumulator
TMS320C54_or3,     // OR With Accumulator
TMS320C54_orm,     // OR Memory With Constant

// XOR INSTRUCTIONS

TMS320C54_xor1,    // Exclusive OR With Accumulator
TMS320C54_xor2,    // Exclusive OR With Accumulator
TMS320C54_xor3,    // Exclusive OR With Accumulator
TMS320C54_xorm,    // Exclusive OR Memory With Constant

// SHIFT INSTRUCTIONS

TMS320C54_rol,     // Rotate Accumulator
TMS320C54_roltc,   // Rotate Accumulator Left Using TC
TMS320C54_ror,     // Rotate Accumulator Right
TMS320C54_sfta2,   // Shift Accumulator Arithmetically
TMS320C54_sfta3,   // Shift Accumulator Arithmetically
TMS320C54_sftc,    // Shift Accumulator Conditionally
TMS320C54_sftl2,   // Shift Accumulator Logically
TMS320C54_sftl3,   // Shift Accumulator Logically

// TEST INSTRUCTIONS

TMS320C54_bit,     // Test Bit
TMS320C54_bitf,    // Test Bit Field Specified by Immediate Value
TMS320C54_bitt,    // Test Bit Specified by T
TMS320C54_cmpm,    // Compare Memory With Long Immediate
TMS320C54_cmpr,    // Compare Auxiliary Register with AR0

// PROGRAM CONTROL OPERATIONS

// BRANCH INSTRUCTIONS

TMS320C54_b,       // Branch Unconditionally
TMS320C54_bd,      // Branch Unconditionally
TMS320C54_bacc,    // Branch to Location Specified by Accumulator
TMS320C54_baccd,   // Branch to Location Specified by Accumulator
TMS320C54_banz,    // Branch on Auxiliary Register Not Zero
TMS320C54_banzd,   // Branch on Auxiliary Register Not Zero
TMS320C54_bc2,     // Branch Conditionally
TMS320C54_bc3,     // Branch Conditionally
TMS320C54_bcd2,    // Branch Conditionally
TMS320C54_bcd3,    // Branch Conditionally
TMS320C54_fb,      // Far Branch Unconditionally
TMS320C54_fbd,     // Far Branch Unconditionally
TMS320C54_fbacc,   // Far Branch to Location Specified by Accumulator
TMS320C54_fbaccd,  // Far Branch to Location Specified by Accumulator

// CALL INSTRUCTIONS

TMS320C54_cala,    // Call Subroutine at Location Specified by Accumulator
TMS320C54_calad,   // Call Subroutine at Location Specified by Accumulator
TMS320C54_call,    // Call Unconditionally
TMS320C54_calld,   // Call Unconditionally
TMS320C54_cc2,     // Call Conditionally
TMS320C54_cc3,     // Call Conditionally
TMS320C54_ccd2,    // Call Conditionally
TMS320C54_ccd3,    // Call Conditionally
TMS320C54_fcala,   // Far Call Subroutine at Location Specified by Accumulator
TMS320C54_fcalad,  // Far Call Subroutine at Location Specified by Accumulator
TMS320C54_fcall,   // Far Call Unconditionally
TMS320C54_fcalld,  // Far Call Unconditionally

// INTERRUPT INSTRUCTIONS

TMS320C54_intr,    // Software Interrupt
TMS320C54_trap,    // Software Interrupt

// RETURN INSTRUCTIONS

TMS320C54_fret,    // Far Return
TMS320C54_fretd,   // Far Return
TMS320C54_frete,   // Enable Interrupts and Far Return From Interrupt
TMS320C54_freted,  // Enable Interrupts and Far Return From Interrupt
TMS320C54_rc1,     // Return Conditionally
TMS320C54_rc2,     // Return Conditionally
TMS320C54_rc3,     // Return Conditionally
TMS320C54_rcd1,    // Return Conditionally
TMS320C54_rcd2,    // Return Conditionally
TMS320C54_rcd3,    // Return Conditionally
TMS320C54_ret,     // Return
TMS320C54_retd,    // Return
TMS320C54_rete,    // Enable Interrupts and Return From Interrupt
TMS320C54_reted,   // Enable Interrupts and Return From Interrupt
TMS320C54_retf,    // Enable Interrupts and Fast Return From Interrupt
TMS320C54_retfd,   // Enable Interrupts and Fast Return From Interrupt

// REPEAT INSTRUCTIONS

TMS320C54_rpt,     // Repeat Next Instruction
TMS320C54_rptb,    // Block Repeat
TMS320C54_rptbd,   // Block Repeat
TMS320C54_rptz,    // Repeat Next Instruction And Clear Accumulator

// STACK MANIPULATING INSTRUCTIONS

TMS320C54_frame,   // Stack Pointer Immediate Offset
TMS320C54_popd,    // Pop Top of Stack to Data Memory
TMS320C54_popm,    // Pop Top of Stack to Memory-Mapped Register
TMS320C54_pshd,    // Push Data-Memory Value Onto Stack
TMS320C54_pshm,    // Push Memory-Mapped Register Onto Stack

// MISCELLANEOUS PROGRAM-CONTROL INSTRUCTIONS

TMS320C54_idle,    // Idle Until Interrupt
TMS320C54_mar,     // Modify Auxiliary Register
TMS320C54_nop,     // No Operation
TMS320C54_reset,   // Software Reset
TMS320C54_rsbx1,   // Reset Status Register Bit
TMS320C54_rsbx2,   // Reset Status Register Bit
TMS320C54_ssbx1,   // Set Status Register Bit
TMS320C54_ssbx2,   // Set Status Register Bit
TMS320C54_xc2,     // Execute Conditionally
TMS320C54_xc3,     // Execute Conditionally

// LOAD AND STORE OPERATIONS

// LOAD INSTRUCTIONS

TMS320C54_dld,     // Double-Precision/Dual 16-Bit Long-Word Load to Accumulator
TMS320C54_ld1,     // Load Accumulator With Shift
TMS320C54_ld2,     // Load Accumulator With Shift
TMS320C54_ld3,     // Load Accumulator With Shift
TMS320C54_ldm,     // Load Memory-Mapped Register
TMS320C54_ldr,     // Load Memory Value in Accumulator High With Rounding
TMS320C54_ldu,     // Load Unsigned Memory Value
TMS320C54_ltd,     // Load T and insert Delay

// STORE INSTRUCTIONS

TMS320C54_dst,     // Store Accumulator in Long Word
TMS320C54_st,      // Store T, TRN, or Immediate Value into Memory
TMS320C54_sth2,    // Store Accumulator High Into Memory
TMS320C54_sth3,    // Store Accumulator High Into Memory
TMS320C54_stl2,    // Store Accumulator Low Into Memory
TMS320C54_stl3,    // Store Accumulator Low Into Memory
TMS320C54_stlm,    // Store Accumulator Low Into Memory-Mapped Register
TMS320C54_stm,     // Store Immediate Value Into Memory-Mapped Register

// CONDITIONAL STORE INSTRUCTIONS

TMS320C54_cmps,    // Compare, Select and Store Maximum
TMS320C54_saccd,   // Store Accumulator Conditionally
TMS320C54_srccd,   // Store Block Repeat Counter Conditionally
TMS320C54_strcd,   // Store T Conditionally

// PARALLEL LOAD AND STORE INSTRUCTIONS

TMS320C54_st_ld,   // Store Accumulator With Parallel Load

// PARALLEL LOAD AND MULTIPLY INSTRUCTIONS

TMS320C54_ld_mac,  // Load Accumulator With Parallel Multiply Accumulate Without Rounding
TMS320C54_ld_macr, // Load Accumulator With Parallel Multiply Accumulate With Rounding
TMS320C54_ld_mas,  // Load Accumulator With Parallel Multiply Subtract Without Rounding
TMS320C54_ld_masr, // Load Accumulator With Parallel Multiply Subtract With Rounding

// PARALLEL STORE AND ADD/SUBSTRACT INSTRUCTIONS

TMS320C54_st_add,  // Store Accumulator With Parallel Add
TMS320C54_st_sub,  // Store Accumulator With Parallel Subtract

// PARALLEL STORE AND MULTIPLY INSTRUCTIONS

TMS320C54_st_mac,  // Store Accumulator With Parallel Multiply Accumulate Without Rounding
TMS320C54_st_macr, // Store Accumulator With Parallel Multiply Accumulate With Rounding
TMS320C54_st_mas,  // Store Accumulator With Parallel Multiply Subtract Without Rounding
TMS320C54_st_masr, // Store Accumulator With Parallel Multiply Subtract With Rounding
TMS320C54_st_mpy,  // Store Accumulator With Parallel Multiply

// MISCELLANEOUS LOAD-TYPE AND STORE-TYPE INSTRUCTIONS

TMS320C54_mvdd,    // Move Data From Data Memory to Data Memory With X,Y Addressing
TMS320C54_mvdk,    // Move Data From Data Memory to Data Memory With Destination Addressing
TMS320C54_mvdm,    // Move Data From Data Memory to Memory-Mapped Register
TMS320C54_mvdp,    // Move Data From Data Memory to Program Memory
TMS320C54_mvkd,    // Move Data From Data Memory to Data Memory With Source Addressing
TMS320C54_mvmd,    // Move Data From Memory-Mapped Register to Data Memory
TMS320C54_mvmm,    // Move Data From Memory-Mapped Register to Memory-Mapped Register
TMS320C54_mvpd,    // Move Data From Program Memory to Data Memory
TMS320C54_portr,   // Read Data From Port
TMS320C54_portw,   // Write Data to Port
TMS320C54_reada,   // Read Program Memory Addressed by Accumulator A and Store in Data Memory
TMS320C54_writa,   // Write Data to Program Memory Addressed by Accumulator A

TMS320C54_last

};

#endif
