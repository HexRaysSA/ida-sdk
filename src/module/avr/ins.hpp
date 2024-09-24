/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{

AVR_null = 0,     // Unknown Operation

// ARITHMETIC AND LOGIC INSTRUCTIONS
AVR_add,          // Add without Carry
AVR_adc,          // Add with Carry
AVR_adiw,         // Add Immediate to Word
AVR_sub,          // Subtract without Carry
AVR_subi,         // Subtract Immediate
AVR_sbc,          // Subtract with Carry
AVR_sbci,         // Subtract Immediate with Carry
AVR_sbiw,         // Subtract Immediate from Word
AVR_and,          // Logical AND
AVR_andi,         // Logical AND with Immediate
AVR_or,           // Logical OR
AVR_ori,          // Logical OR with Immediate
AVR_eor,          // Exclusive OR
AVR_com,          // One's Complement
AVR_neg,          // Two's Complement
AVR_sbr,          // Set Bit(s) in Register
AVR_cbr,          // Clear Bit(s) in Register
AVR_inc,          // Increment
AVR_dec,          // Decrement
AVR_tst,          // Test for Zero or Minus
AVR_clr,          // Clear Register
AVR_ser,          // Set Register
AVR_cp,           // Compare
AVR_cpc,          // Compare with Carry
AVR_cpi,          // Compare with Immediate
AVR_mul,          // Multiply

// BRANCH INSTRUCTIONS
AVR_rjmp,         // Relative Jump
AVR_ijmp,         // Indirect Jump to (Z)
AVR_jmp,          // Jump
AVR_rcall,        // Relative Call Subroutine
AVR_icall,        // Indirect Call to (Z)
AVR_call,         // Call Subroutine
AVR_ret,          // Subroutine Return
AVR_reti,         // Interrupt Return
AVR_cpse,         // Compare, Skip if Equal
AVR_sbrc,         // Skip if Bit in Register Cleared
AVR_sbrs,         // Skip if Bit in Register Set
AVR_sbic,         // Skip if Bit in I/O Register Cleared
AVR_sbis,         // Skip if Bit in I/O Register Set
AVR_brbs,         // Branch if Status Flag Set
AVR_brbc,         // Branch if Status Flag Cleared
AVR_breq,         // Branch if Equal
AVR_brne,         // Branch if Not Equal
AVR_brcs,         // Branch if Carry Set
AVR_brcc,         // Branch if Carry Cleared
AVR_brsh,         // Branch if Same or Higher
AVR_brlo,         // Branch if Lower
AVR_brmi,         // Branch if Minus
AVR_brpl,         // Branch if Plus
AVR_brge,         // Branch if Greater or Equal
AVR_brlt,         // Branch if Less Than
AVR_brhs,         // Branch if Half Carry Flag Set
AVR_brhc,         // Branch if Half Carry Flag Cleared
AVR_brts,         // Branch if T Flag Set
AVR_brtc,         // Branch if T Flag Cleared
AVR_brvs,         // Branch if Overflow Flag is Set
AVR_brvc,         // Branch if Overflow Flag is Cleared
AVR_brie,         // Branch if Interrupt Enabled
AVR_brid,         // Branch if Interrupt Disabled

// DATA TRANSFER INSTRUCTIONS
AVR_mov,          // Copy Register
AVR_ldi,          // Load Immediate
AVR_lds,          // Load Direct
AVR_ld,           // Load Indirect
AVR_ldd,          // Load Indirect with Displacement
AVR_sts,          // Store Direct to SRAM
AVR_st,           // Store Indirect
AVR_std,          // Store Indirect with Displacement
AVR_lpm,          // Load Program Memory
AVR_in,           // In Port
AVR_out,          // Out Port
AVR_push,         // Push Register on Stack
AVR_pop,          // Pop Register from Stack

// BIT AND BIT-TEST INSTRUCTIONS
AVR_lsl,          // Logical Shift Left
AVR_lsr,          // Logical Shift Right
AVR_rol,          // Rotate Left Through Carry
AVR_ror,          // Rotate Right Through Carry
AVR_asr,          // Arithmetic Shift Right
AVR_swap,         // Swap Nibbles
AVR_bset,         // Flag Set
AVR_bclr,         // Flag Clear
AVR_sbi,          // Set Bit in I/O Register
AVR_cbi,          // Clear Bit in I/O Register
AVR_bst,          // Bit Store from Register to T
AVR_bld,          // Bit load from T to Register
AVR_sec,          // Set Carry
AVR_clc,          // Clear Carry
AVR_sen,          // Set Negative Flag
AVR_cln,          // Clear Negative Flag
AVR_sez,          // Set Zero Flag
AVR_clz,          // Clear Zero Flag
AVR_sei,          // Global Interrupt Enable
AVR_cli,          // Global Interrupt Disable
AVR_ses,          // Set Signed Test Flag
AVR_cls,          // Clear Signed Test Flag
AVR_sev,          // Set Two's Complement Overflow
AVR_clv,          // Clear Two's Complement Overflow
AVR_set,          // Set T in SREG
AVR_clt,          // Clear T in SREG
AVR_seh,          // Set Half Carry Flag in SREG
AVR_clh,          // Clear Half Carry Flag in SREG
AVR_nop,          // No Operation
AVR_sleep,        // Sleep
AVR_wdr,          // Watchdog Reset

// New MegaAVR instructions

AVR_elpm,         // Extended Load Program Memory
AVR_espm,         // Extended Store Program Memory
AVR_fmul,         // Fractional Multiply Unsigned
AVR_fmuls,        // Fractional Multiply Signed
AVR_fmulsu,       // Fractional Multiply Signed with Unsigned
AVR_movw,         // Copy Register Word
AVR_muls,         // Multiply Signed
AVR_mulsu,        // Multiply Signed with Unsigned
AVR_spm,          // Store Program Memory
AVR_eicall,       // Extended Indirect Call to Subroutine
AVR_eijmp,        // Extended Indirect Jump

// New XMega instructions

AVR_des,          // Data Encryption Standard
AVR_lac,          // Load And Clear
AVR_las,          // Load And Set
AVR_lat,          // Load And Toggle
AVR_xch,          // Exchange

AVR_last,

    };

#endif
