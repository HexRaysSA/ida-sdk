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

TMS320C55_null = 0,      // Unknown Operation

// ARITHMETICAL OPERATIONS

TMS320C55_abdst,         // Absolute Distance
TMS320C55_abs1,          // Absolute Value
TMS320C55_abs2,          // Absolute Value

TMS320C55_add1,          // Addition
TMS320C55_add2,          // Addition
TMS320C55_add3,          // Addition
TMS320C55_add4,          // Addition
TMS320C55_addv1,         // Addition
TMS320C55_addv2,         // Addition
TMS320C55_addrv1,        // Addition and Round
TMS320C55_addrv2,        // Addition and Round

TMS320C55_maxdiff,       // Compare and Select Maximum
TMS320C55_dmaxdiff,      // Compare and Select 40-bit Maximum
TMS320C55_mindiff,       // Compare and Select Minimum
TMS320C55_dmindiff,      // Compare and Select 40-bit Minimum

TMS320C55_addsubcc4,     // Conditional Add or Subtract
TMS320C55_addsubcc5,     // Conditional Add or Subtract
TMS320C55_addsub2cc,     // Conditional Add or Subtract

TMS320C55_sftcc,         // Conditional Shift

TMS320C55_subc2,         // Conditional Subtract
TMS320C55_subc3,         // Conditional Subtract

TMS320C55_addsub,        // Paralleled Add - Subtract
TMS320C55_subadd,        // Parallel Subtract - Add

TMS320C55_mpy_mpy,       // Two Parallel Multiply
TMS320C55_mpy_mpyr,      // Two Parallel Multiply, and Round
TMS320C55_mpy_mpy40,     // Two Parallel Multiply, on 40 bits
TMS320C55_mpy_mpyr40,    // Two Parallel Multiply, and Round on 40 bits
TMS320C55_mac_mpy,       // Parallel Multiply - Accumulate
TMS320C55_macr_mpyr,     // Parallel Multiply - Accumulate, and Round
TMS320C55_mac40_mpy40,   // Parallel Multiply - Accumulate, on 40 bits
TMS320C55_macr40_mpyr40, // Parallel Multiply - Accumulate, and Round on 40 bits
TMS320C55_mas_mpy,       // Parallel Multiply - Subtract
TMS320C55_masr_mpyr,     // Parallel Multiply - Subtract, and Round
TMS320C55_mas40_mpy40,   // Parallel Multiply - Subtract, on 40 bits
TMS320C55_masr40_mpyr40, // Parallel Multiply - Subtract, and Round on 40 bits
TMS320C55_amar_mpy,      // Parallel Modify Auxiliary Register - Multiply
TMS320C55_amar_mpyr,     // Parallel Modify Auxiliary Register - Multiply, and Round
TMS320C55_amar_mpy40,    // Parallel Modify Auxiliary Register - Multiply, on 40 bits
TMS320C55_amar_mpyr40,   // Parallel Modify Auxiliary Register - Multiply, and Round on 40 bits
TMS320C55_mac_mac,       // Two Parallel Multiply and Accumulate
TMS320C55_macr_macr,     // Two Parallel Multiply and Accumulate, and Round
TMS320C55_mac40_mac40,   // Two Parallel Multiply and Accumulate, on 40 bits
TMS320C55_macr40_macr40, // Two Parallel Multiply and Accumulate, and Round on 40 bits
TMS320C55_mas_mac,       // Parallel Multiply and Subtract - Multiply and Accumulate
TMS320C55_masr_macr,     // Parallel Multiply and Subtract - Multiply and Accumulate, and Round
TMS320C55_mas40_mac40,   // Parallel Multiply and Subtract - Multiply and Accumulate, on 40 bits
TMS320C55_masr40_macr40, // Parallel Multiply and Subtract - Multiply and Accumulate, and Round on 40 bits
TMS320C55_amar_mac,      // Parallel Modify Auxiliary Register - Multiply and Accumulate
TMS320C55_amar_macr,     // Parallel Modify Auxiliary Register - Multiply and Accumulate, and Round
TMS320C55_amar_mac40,    // Parallel Modify Auxiliary Register - Multiply and Accumulate, on 40 bits
TMS320C55_amar_macr40,   // Parallel Modify Auxiliary Register - Multiply and Accumulate, and Round on 40 bits
TMS320C55_mas_mas,       // Two Parallel Multiply and Subtract
TMS320C55_masr_masr,     // Two Parallel Multiply and Subtract, and Round
TMS320C55_mas40_mas40,   // Two Parallel Multiply and Subtract, on 40 bits
TMS320C55_masr40_masr40, // Two Parallel Multiply and Subtract, and Round on 40 bits
TMS320C55_amar_mas,      // Parallel Modify Auxiliary Register - Multiply and Subtract
TMS320C55_amar_masr,     // Parallel Modify Auxiliary Register - Multiply and Subtract, and Round
TMS320C55_amar_mas40,    // Parallel Modify Auxiliary Register - Multiply and Subtract, on 40 bits
TMS320C55_amar_masr40,   // Parallel Modify Auxiliary Register - Multiply and Subtract, and Round on 40 bits
TMS320C55_mpy_mac,       // Parallel Multiply - Multiply and Accumulate
TMS320C55_mpyr_macr,     // Parallel Multiply - Multiply and Accumulate, and Round
TMS320C55_mpy40_mac40,   // Parallel Multiply - Multiply and Accumulate, on 40 bits
TMS320C55_mpyr40_macr40, // Parallel Multiply - Multiply and Accumulate, and Round on 40 bits
TMS320C55_amar3,         // Three Parallel Modify Auxiliary Registers

TMS320C55_firsadd,       // Parallel Multiply and Accumulate - Add
TMS320C55_firssub,       // Parallel Multiply and Accumulate - Subtract

TMS320C55_mpym_mov,      // Parallel Multiply - Store
TMS320C55_mpymr_mov,     // Parallel Multiply - Store, and Round
TMS320C55_macm_mov,      // Parallel Multiply and Accumulate - Store
TMS320C55_macmr_mov,     // Parallel Multiply and Accumulate - Store, and Round
TMS320C55_masm_mov,      // Parallel Multiply and Subtract - Store
TMS320C55_masmr_mov,     // Parallel Multiply and Subtract - Store, and Round
TMS320C55_add_mov,       // Parallel Add - Store
TMS320C55_sub_mov,       // Parallel Subtract - Store
TMS320C55_mov_mov,       // Parallel Load - Store
TMS320C55_mov_aadd,      // Parallel Store - aadd
TMS320C55_mov_add,       // Parallel Store - Add
TMS320C55_amar_amar,     // Parallel Modify Auxiliary Register - Modify Auxiliary Register
TMS320C55_add_asub,      // Parallel Add - asub
TMS320C55_btst_mov,      // Parallel Bit Test - Store
TMS320C55_mov_asub,      // Parallel Store - asub

TMS320C55_lms,           // Least Mean Square

TMS320C55_max1,          // Maximum Comparison
TMS320C55_max2,          // Maximum Comparison
TMS320C55_min1,          // Minimum Comparison
TMS320C55_min2,          // Minimum Comparison

TMS320C55_cmp,           // Memory Comparison
TMS320C55_cmpu,          // Unsigned memory Comparison

TMS320C55_aadd,          // Add Two Registers
TMS320C55_asub,          // Subtract Two Registers
TMS320C55_amov,          // Move From Register to Register
TMS320C55_amar1,         // Auxiliary Register Modification

TMS320C55_sqr1,          // Square
TMS320C55_sqr2,          // Square
TMS320C55_sqrr1,         // Square and Round
TMS320C55_sqrr2,         // Square and Round
TMS320C55_mpy1,          // Multiply
TMS320C55_mpy2,          // Multiply
TMS320C55_mpy3,          // Multiply
TMS320C55_mpyr1,         // Multiply and Round
TMS320C55_mpyr2,         // Multiply and Round
TMS320C55_mpyr3,         // Multiply and Round
TMS320C55_mpyk2,         // Multiply by Constant
TMS320C55_mpyk3,         // Multiply by Constant
TMS320C55_mpykr2,        // Multiply by Constant and Round
TMS320C55_mpykr3,        // Multiply by Constant and Round
TMS320C55_mpym2,         // Multiply Memory Value
TMS320C55_mpym3,         // Multiply Memory Values
TMS320C55_mpymr2,        // Multiply Memory Value and Round
TMS320C55_mpymr3,        // Multiply Memory Values and Round
TMS320C55_mpym403,       // Multiply Memory Values on 40 bits
TMS320C55_mpymr403,      // Multiply Memory Values and Round on 40 bits
TMS320C55_mpymu3,        // Unsigned multiply Memory Values
TMS320C55_mpymru3,       // Unsigned multiply Memory Values and Round
TMS320C55_sqrm,          // Square Memory Value
TMS320C55_sqrmr,         // Square Memory Value, and Round
TMS320C55_mpymk,         // Multiply Memory Value by Constant
TMS320C55_mpymkr,        // Multiply Memory Value by Constant and Round

TMS320C55_sqa1,          // Square and Accumulate
TMS320C55_sqa2,          // Square and Accumulate
TMS320C55_sqar1,         // Square, Accumulate and Round
TMS320C55_sqar2,         // Square, Accumulate and Round
TMS320C55_mac3,          // Multiply and Accumulate
TMS320C55_mac4,          // Multiply and Accumulate
TMS320C55_macr3,         // Multiply, Accumulate and Round
TMS320C55_macr4,         // Multiply, Accumulate and Round
TMS320C55_mack3,         // Multiply by Constant and Accumulate
TMS320C55_mack4,         // Multiply by Constant and Accumulate
TMS320C55_mackr3,        // Multiply by Constant, Round and Accumulate
TMS320C55_mackr4,        // Multiply by Constant, Round and Accumulate
TMS320C55_macm2,         // Multiply and Accumulate Memory Values
TMS320C55_macm3,         // Multiply and Accumulate Memory Values
TMS320C55_macm4,         // Multiply and Accumulate Memory Values
TMS320C55_macmr2,        // Multiply and Accumulate Memory Values, and Round
TMS320C55_macmr3,        // Multiply and Accumulate Memory Values, and Round
TMS320C55_macmr4,        // Multiply and Accumulate Memory Values, and Round
TMS320C55_macm403,       // Multiply and Accumulate Memory Values, on 40 bits
TMS320C55_macm404,       // Multiply and Accumulate Memory Values, on 40 bits
TMS320C55_macmr403,      // Multiply and Accumulate Memory Values, and Round on 40 bits
TMS320C55_macmr404,      // Multiply and Accumulate Memory Values, and Round on 40 bits
TMS320C55_macmz,         // Multiply and Accumulate Memory Values
TMS320C55_macmrz,        // Multiply and Accumulate Memory Values, and Round
TMS320C55_sqam2,         // Square and Accumulate Memory Value
TMS320C55_sqam3,         // Square and Accumulate Memory Values
TMS320C55_sqamr2,        // Square and Accumulate Memory Value, and Round
TMS320C55_sqamr3,        // Square and Accumulate Memory Values, and Round
TMS320C55_macmk3,        // Multiply Memory Value by Constant and Accumulate
TMS320C55_macmk4,        // Multiply Memory Value by Constant and Accumulate
TMS320C55_macmkr3,       // Multiply Memory Value by Constant - Accumulate, and Round
TMS320C55_macmkr4,       // Multiply Memory Value by Constant - Accumulate, and Round

TMS320C55_sqs1,          // Square and Subtract
TMS320C55_sqs2,          // Square and Subtract
TMS320C55_sqsr1,         // Square, Subtract and Round
TMS320C55_sqsr2,         // Square, Subtract and Round

TMS320C55_mas2,          // Multiply and Subtract
TMS320C55_mas3,          // Multiply and Subtract
TMS320C55_masr2,         // Multiply, Subtract and Round
TMS320C55_masr3,         // Multiply, Subtract and Round
TMS320C55_masm2,         // Multiply and Subtract Memory Value
TMS320C55_masm3,         // Multiply and Subtract Memory Values
TMS320C55_masm4,         // Multiply and Subtract Memory Values
TMS320C55_masmr2,        // Multiply and Subtract Memory Values, and Round
TMS320C55_masmr3,        // Multiply and Subtract Memory Values, and Round
TMS320C55_masmr4,        // Multiply and Subtract Memory Values, and Round
TMS320C55_masm403,       // Multiply and Subtract Memory Values, on 40 bits
TMS320C55_masm404,       // Multiply and Subtract Memory Values, on 40 bits
TMS320C55_masmr403,      // Multiply and Subtract Memory Values, and Round on 40 bits
TMS320C55_masmr404,      // Multiply and Subtract Memory Values, and Round on 40 bits
TMS320C55_sqsm2,         // Square and Subtract Memory Values
TMS320C55_sqsm3,         // Square and Subtract Memory Values
TMS320C55_sqsmr2,        // Square and Subtract Memory Values, and Round
TMS320C55_sqsmr3,        // Square and Subtract Memory Values, and Round

TMS320C55_neg1,          // Negation
TMS320C55_neg2,          // Negation

TMS320C55_mant_nexp,     // Exponent and Mantissa
TMS320C55_exp,           // Exponent

TMS320C55_cmpand,        // Compare and AND
TMS320C55_cmpandu,       // Unsigned compare and AND
TMS320C55_cmpor,         // Compare and OR
TMS320C55_cmporu,        // Unsigned compare and OR

TMS320C55_round1,        // Round
TMS320C55_round2,        // Round

TMS320C55_sat1,          // Saturate
TMS320C55_sat2,          // Saturate
TMS320C55_satr1,         // Saturate and Round
TMS320C55_satr2,         // Saturate and Round

TMS320C55_sfts2,         // Signed Shift
TMS320C55_sfts3,         // Signed Shift
TMS320C55_sftsc2,        // Signed Shift with Carry
TMS320C55_sftsc3,        // Signed Shift with Carry

TMS320C55_sqdst,         // Square distance

TMS320C55_sub1,          // Subtract
TMS320C55_sub2,          // Subtract
TMS320C55_sub3,          // Subtract
TMS320C55_sub4,          // Subtract

TMS320C55_band,          // Bit Field Comparison

TMS320C55_bfxpa,         // Bit Field Expand

TMS320C55_bfxtr,         // Bit Field Extract

TMS320C55_btst,          // Bit Test
TMS320C55_bnot,          // Bit NOT
TMS320C55_bclr2,         // Bit Clear
TMS320C55_bset2,         // Bit Set
TMS320C55_btstset,       // Bit Test and Set
TMS320C55_btstclr,       // Bit Test and Clear
TMS320C55_btstnot,       // Bit Test and NOT
TMS320C55_btstp,         // Bit Pair Test
TMS320C55_bclr1,         // Bit Clear
TMS320C55_bset1,         // Bit Set

TMS320C55_amar2,         // Load Effective Address to Extended Auxiliary Register
TMS320C55_popboth,       // Pop Extended Auxiliary Register from Stack Pointers
TMS320C55_pshboth,       // Push Extended Auxiliary Register to Stack Pointers

// LOGICAL OPERATIONS

TMS320C55_bcnt,          // Count Bit Field

TMS320C55_not1,          // NOT
TMS320C55_not2,          // NOT

TMS320C55_and1,          // AND
TMS320C55_and2,          // AND
TMS320C55_and3,          // AND

TMS320C55_or1,           // OR
TMS320C55_or2,           // OR
TMS320C55_or3,           // OR

TMS320C55_xor1,          // XOR
TMS320C55_xor2,          // XOR
TMS320C55_xor3,          // XOR

TMS320C55_sftl2,         // Logical Shift
TMS320C55_sftl3,         // Logical Shift

TMS320C55_rol,           // Rotate Left

TMS320C55_ror,           // Rotate Right

// MISCELLANEOUS OPERATIONS

// MOVE OPERATIONS

TMS320C55_swap,          // Swap Registers
TMS320C55_swapp,         // Swap Pair Registers
TMS320C55_swap4,         // Swap 4 Registers

TMS320C55_mov2,          // Move Data
TMS320C55_mov3,          // Move 2 Data
TMS320C55_mov402,        // Move Data on 40 bits

TMS320C55_delay,         // Memory Delay

TMS320C55_pop1,          // Pop Top of Stack1
TMS320C55_pop2,          // Pop Top of Stack2

TMS320C55_psh1,          // Pop Top of Stack3
TMS320C55_psh2,          // Pop Top of Stack4

// PROGRAM CONTROL OPERATIONS

TMS320C55_bcc,           // Branch Conditionally
TMS320C55_bccu,          // Branch Conditionally

TMS320C55_b,             // Branch Unconditionally

TMS320C55_callcc,        // Call Conditionally

TMS320C55_call,          // Call Unconditionally

TMS320C55_xcc,           // Execute Conditionally
TMS320C55_xccpart,       // Execute Conditionally

TMS320C55_idle,          // Idle

TMS320C55_nop,           // No Operation
TMS320C55_nop_16,        // No Operation

TMS320C55_rptblocal,     // Repeat Block of Instructions Unconditionally
TMS320C55_rptb,          // Repeat Block of Instructions Unconditionally

TMS320C55_rptcc,         // Repeat Single Instruction Conditionally

TMS320C55_rpt,           // Repeat Single Instruction Unconditionally
TMS320C55_rptadd,        // Repeat Single Instruction Unconditionally and Add to Register
TMS320C55_rptsub,        // Repeat Single Instruction Unconditionally and Subtract to Register

TMS320C55_retcc,         // Return Conditionally
TMS320C55_ret,           // Return Unconditionally
TMS320C55_reti,          // Return from Interrupt

TMS320C55_intr,          // Software Interrupt

TMS320C55_reset,         // Software Reset

TMS320C55_trap,          // Software Trap

TMS320C55_last

};

#endif
