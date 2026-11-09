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

H8500_null = 0,      // Unknown Operation

// Data transfer

H8500_mov_g,         // B/W Move data
H8500_mov_e,         // B   Move data
H8500_mov_i,         // W   Move data
H8500_mov_f,         // B/W Move data
H8500_mov_l,         // B/W Move data
H8500_mov_s,         // B/W Move data
H8500_ldm,           // W   Pop data from the stack to one or more registers
H8500_stm,           // W   Push data from one or more registers onto the stack
H8500_xch,           // W   Exchange data between two general registers
H8500_swap,          // B   Exchange the upper and lower bytes in a general register
H8500_movtpe,        // B   Transfer data from a general register to memory
H8500_movfpe,        // B   Transfer data from memory to a general register

// Arithmetic operations

H8500_add_g,         // B/W Addition
H8500_add_q,         // B/W Addition
H8500_sub,           // B/W Subtraction
H8500_adds,          // B/W Addition
H8500_subs,          // B/W Subtraction
H8500_addx,          // B/W Addition with carry
H8500_subx,          // B/W Subtraction with borrow
H8500_dadd,          // B   Decimal addition
H8500_dsub,          // B   Decimal subtraction
H8500_mulxu,         // B/W Unsigned multiplication
H8500_divxu,         // B/W Unsigned division
H8500_cmp_g,         // B/W Compare data
H8500_cmp_e,         // B   Compare data
H8500_cmp_i,         // W   Compare data
H8500_exts,          // B   Convert byte to word by extending the sign bit
H8500_extu,          // B   Convert byte to word data by padding with zero bits
H8500_tst,           // B/W Compare with 0
H8500_neg,           // B/W Negate
H8500_clr,           // B/W Make zero
H8500_tas,           // B   Test and set

// Logic Operations

H8500_and,           // B/W Logical AND
H8500_or,            // B/W Logical OR
H8500_xor,           // B/W Exclusive OR
H8500_not,           // B/W Bitwise NOT

// Shift Operations

H8500_shal,          // B/W Arithmetic shift left
H8500_shar,          // B/W Arithmetic shift right
H8500_shll,          // B/W Logical shift left
H8500_shlr,          // B/W Logical shift right
H8500_rotl,          // B/W Rotate left
H8500_rotr,          // B/W Rotate right
H8500_rotxl,         // B/W Rotate through carry left
H8500_rotxr,         // B/W Rotate through carry right

// Bit Manipulations

H8500_bset,          // B/W Test bit and set
H8500_bclr,          // B/W Test bit and clear
H8500_bnot,          // B/W Test bit and invert
H8500_btst,          // B/W Test bit

// Branching Instructions

H8500_bra,           //     Branch Always
H8500_brn,           //     Branch Never
H8500_bhi,           //     Branch if High (C|Z = 0)
H8500_bls,           //     Branch if Low or Same (C|Z = 1)
H8500_bcc,           //     Branch if Carry Clear (C = 0)
H8500_bcs,           //     Branch if Carry Set (C = 1)
H8500_bne,           //     Branch if Not Equal (Z = 0)
H8500_beq,           //     Branch if Equal (Z = 1)
H8500_bvc,           //     Branch if Overflow Clear (V = 0)
H8500_bvs,           //     Branch if Overflow Set (V = 1)
H8500_bpl,           //     Branch if Plus (N = 0)
H8500_bmi,           //     Branch if Minus (N = 1)
H8500_bge,           //     Branch if Greater or Equal (N^V = 0)
H8500_blt,           //     Branch if Less Than (N^V = 1)
H8500_bgt,           //     Branch if Greater Than (Z|(N^V) = 0)
H8500_ble,           //     Branch if Less or Equal (Z|(N^V) = 1)
H8500_jmp,           //     Branch unconditionally (same page)
H8500_pjmp,          //     Branch unconditionally (specified page)
H8500_bsr,           //     Branch to subroutine (same page)
H8500_jsr,           //     Branch to subroutine (same page)
H8500_pjsr,          //     Branch to subroutine (specified page)
H8500_rts,           //     Return from subroutine (same page)
H8500_prts,          //     Return from subroutine (different page)
H8500_rtd,           //     Return from subroutine (same page) and adjust SP
H8500_prtd,          //     Return from subroutine (different page) and adjust SP
H8500_scb,           //     Control loop

// System Control Instructions

H8500_trapa,         //     Generate trap exception
H8500_trap_vs,       //     Generate trap exception if the V bit is set
H8500_rte,           //     Return from exception-handling routine
H8500_link,          //     Create stack frame
H8500_unlk,          //     Deallocate stack frame
H8500_sleep,         //     Go to power-down state
H8500_ldc,           // B/W Move to control register
H8500_stc,           // B/W Move from control register
H8500_andc,          // B/W Logically AND control register
H8500_orc,           // B/W Logically OR control register
H8500_xorc,          // B/W Logically exclusive-OR control register
H8500_nop,           //     No operation
H8500_bpt,           //

H8500_last,

    };

#endif
