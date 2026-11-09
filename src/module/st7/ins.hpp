/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
ST7_null = 0,           // Unknown Operation

ST7_adc,                // Add with Carry
ST7_add,                // Addition
ST7_and,                // Logical And
ST7_bcp,                // Bit compare
ST7_bres,               // Bit Reset
ST7_bset,               // Bit Set
ST7_btjf,               // Jump if bit is false
ST7_btjt,               // Jump if bit is true
ST7_call,               // Call subroutine
ST7_callr,              // Call subroutine relative
ST7_clr,                // Clear
ST7_cp,                 // Arithmetic Compare
ST7_cpl,                // One Complement
ST7_dec,                // Decrement
ST7_halt,               // Halt
ST7_iret,               // Interrupt routine return
ST7_inc,                // Increment
ST7_jp,                 // Absolute Jump
ST7_jra,                // Jump relative always
ST7_jrt,                // Jump relative
ST7_jrf,                // Never jump
ST7_jrih,               // Jump if Port INT pin = 1
ST7_jril,               // Jump if Port INT pin = 0
ST7_jrh,                // Jump if H = 1
ST7_jrnh,               // Jump if H = 0
ST7_jrm,                // Jump if I = 1
ST7_jrnm,               // Jump if I = 0
ST7_jrmi,               // Jump if N = 1 (minus)
ST7_jrpl,               // Jump if N = 0 (plus)
ST7_jreq,               // Jump if Z = 1 (equal)
ST7_jrne,               // Jump if Z = 0 (not equal)
ST7_jrc,                // Jump if C = 1
ST7_jrnc,               // Jump if C = 0
ST7_jrult,              // Jump if C = 1
ST7_jruge,              // Jump if C = 0
ST7_jrugt,              // Jump if (C + Z = 0)
ST7_jrule,              // Jump if (C + Z = 1)
ST7_ld,                 // Load
ST7_mul,                // Multiply
ST7_neg,                // Negate
ST7_nop,                // No Operation
ST7_or,                 // OR Operation
ST7_pop,                // Pop from the Stack
ST7_push,               // Push onto the Stack
ST7_rcf,                // Reset carry flag
ST7_ret,                // Subroutine Return
ST7_rim,                // Enable Interrupts
ST7_rlc,                // Rotate left true
ST7_rrc,                // Rotate right true
ST7_rsp,                // Reset Stack Pointer
ST7_sbc,                // Subtract with Carry
ST7_scf,                // Set carry flag
ST7_sim,                // Disable Interrupts
ST7_sla,                // Shift left Arithmetic
ST7_sll,                // Shift left Logic
ST7_srl,                // Shift right Logic
ST7_sra,                // Shift right Arithmetic
ST7_sub,                // Substraction
ST7_swap,               // SWAP nibbles
ST7_tnz,                // Test for Neg & Zero
ST7_trap,               // S/W trap
ST7_wfi,                // Wait for Interrupt
ST7_xor,                // Exclusive OR

ST7_last,

    };

#endif
