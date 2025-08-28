
#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
OAK_Dsp_null = 0,       // Unknown Operation
OAK_Dsp_proc,           // cmd need further process
// ALU-ALM subcodes
OAK_Dsp_or,             // 000  Logical Or
OAK_Dsp_and,            // 001  And
OAK_Dsp_xor,            // 010  Exclusive Or
OAK_Dsp_add,            // 011  Add
OAK_Dsp_alm_tst0,       // 100  Test Bit-field for Zeros
OAK_Dsp_alm_tst1,       // 101  Test Bit-field for Ones
OAK_Dsp_cmp,            // 110  Compare
OAK_Dsp_sub,            // 111  Subtract
// ALM subcodes
OAK_Dsp_alm_msu,        // 1000  Multiply and Subtract Previous Product
OAK_Dsp_addh,           // 1001  Add to High Accumulator
OAK_Dsp_addl,           // 1010  Add to Low Accumulator
OAK_Dsp_subh,           // 1011  Subtract from High Accumulator
OAK_Dsp_subl,           // 1100  Subtract from Low Accumulator
OAK_Dsp_sqr,            // 1101  Square
OAK_Dsp_sqra,           // 1110  Square and Accumulate Previous Product
OAK_Dsp_cmpu,           // 1111  Compare Unsigned
// MODA-MODB subcodes conditional
OAK_Dsp_shr,            // 000  Shift Accumulator Right
OAK_Dsp_shr4,           // 001  Shift Accumulator Right by 4 Bits
OAK_Dsp_shl,            // 010  Shift Accumulator Left
OAK_Dsp_shl4,           // 011  Shift Accumulator Left by 4 Bits
OAK_Dsp_ror,            // 100  Rotate Accumulator Right through Carry
OAK_Dsp_rol,            // 101  Rotate Accumulator Left through Carry
OAK_Dsp_clr,            // 110  Clear Accumulator
OAK_Dsp_mod_reserved,   // 111  Mod Reserved
// MODA subcodes conditional
OAK_Dsp_not,            // 1000  Logical Not
OAK_Dsp_neg,            // 1001  2's Complement of aX-accumulator
OAK_Dsp_rnd,            // 1010  Round Upper 20 Bits of aX-accumulator
OAK_Dsp_pacr,           // 1011  Product Move and Round to aX-accumulator
OAK_Dsp_clrr,           // 1100  Clear and Round aX-accumulator
OAK_Dsp_inc,            // 1101  Increment Accumulator by One
OAK_Dsp_dec,            // 1110  Decrement aX-accumulator by One
OAK_Dsp_copy,           // 1111  Copy aX-accumulator
// ---
OAK_Dsp_norm,           // Normalize
OAK_Dsp_divs,           // Division Step
// ALB subcodes
OAK_Dsp_set,            // 000  Set Bit-field
OAK_Dsp_rst,            // 001  Reset Bit-field
OAK_Dsp_chng,           // 010  Change Bit-field
OAK_Dsp_addv,           // 011  Add Long Immediate Value or Data Memory Location
OAK_Dsp_alb_tst0,       // 100  Test Bit-field for Zeros
OAK_Dsp_alb_tst1,       // 101  Test Bit-field for Ones
OAK_Dsp_cmpv,           // 110  Compare Long Immediate Value to Register or Data Memory Location
OAK_Dsp_subv,           // 111  Subtract Long Immediate Value from a Register or a Data Memory Location
// ---
OAK_Dsp_maxd,           // Maximum between Data Memory Location and Accumulator
OAK_Dsp_max,            // Maximum between Two Accumulators
OAK_Dsp_min,            // Minimum between Two Accumulators
OAK_Dsp_lim,            // Limit Accumulator     (lim aX[, aX])
// MUL subcodes
OAK_Dsp_mpy,            // 000  Multiply
OAK_Dsp_mpysu,          // 001  Multiply Signed by Unsigned
OAK_Dsp_mac,            // 010  Multiply and Accumulate Previous Product
OAK_Dsp_macus,          // 011  Multiply Unsigned by Signed and Accumulate Previous Product
OAK_Dsp_maa,            // 100  Multiply and Accumulate Aligned Previous Product
OAK_Dsp_macuu,          // 101  Multiply Unsigned by Unsigned and Accumulate Previous Product
OAK_Dsp_macsu,          // 110  Multiply Signed by Unsigned and Accumulate Previous Product
OAK_Dsp_maasu,          // 111  Multiply Signed by Unsigned and Accumulate Aligned Previous Product
//---
OAK_Dsp_mpyi,           // Multiply Signed Short Immediate
OAK_Dsp_msu,            // Multiply and Subtract Previous Product
OAK_Dsp_tstb,           // Test Specific Bit
OAK_Dsp_shfc,           // Shift Accumulators according to Shift Value Register
OAK_Dsp_shfi,           // Shift Accumulators by an Immediate Shift Value
OAK_Dsp_exp,            // Evaluate the Exponent Value
//---
OAK_Dsp_mov,            // Move Data
OAK_Dsp_movp,           // Move from Program Memory into Data Memory
OAK_Dsp_movs,           // Move and Shift According to Shift Value Register
OAK_Dsp_movsi,          // Move and Shift According to an Immediate Shift Value
OAK_Dsp_movr,           // Move and Round
OAK_Dsp_movd,           // Move from Data Memory into Program Memory
//---
OAK_Dsp_push,           // Push Register or Long Immediate Value onto Stack
OAK_Dsp_pop,            // Pop from Stack into Register
//---
OAK_Dsp_swap,           // Swap aX- and bX-accumulators
OAK_Dsp_banke,          // Bank Exchange
OAK_Dsp_rep,            // Repeat Next Instruction
OAK_Dsp_bkrep,          // Block-Repeat
OAK_Dsp_break,          // Break from Block-repeat
//---
OAK_Dsp_br,             // Conditional Branch
OAK_Dsp_brr,            // Relative Conditional Branch
OAK_Dsp_br_u,           // UnConditional Branch
OAK_Dsp_brr_u,          // Relative UnConditional Branch
OAK_Dsp_call,           // Conditional Call Subroutine
OAK_Dsp_callr,          // Relative Conditional Call Subroutine
OAK_Dsp_calla,          // Call Subroutine at Location Specified by Accumulator
//---
OAK_Dsp_ret,            // Return Conditionally
OAK_Dsp_ret_u,          // Return UnConditionally
OAK_Dsp_retd,           // Delayed Return
OAK_Dsp_reti,           // Return from Interrupt Conditionally
OAK_Dsp_reti_u,         // Return from Interrupt UnConditionally
OAK_Dsp_retid,          // Delayed Return from Interrupt
OAK_Dsp_rets,           // Return with Short Immediate Parameter
//---
OAK_Dsp_cntx,           // Context Switching Store or Restore
OAK_Dsp_nop,            // No operation
OAK_Dsp_modr,           // Modify rN
OAK_Dsp_dint,           // Disable Interrupt
OAK_Dsp_eint,           // Enable Interrupt
//---
OAK_Dsp_trap,           // Software Interrupt
//---
OAK_Dsp_lpg,            // Load the Page Bits
OAK_Dsp_load,           // Load Specific Fields into Registers
OAK_Dsp_mov_eu,         // Move Data, eu
OAK_Dsp_last,

};

#endif
