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

H8_null = 0,      // Unknown Operation

H8_add,            // Add binary
H8_adds,           // Add with sign extension
H8_addx,           // Add with extend carry
H8_and,            // Logical AND
H8_andc,           // Logical AND with control register
H8_band,           // Bit AND
H8_bra,            // Branch always
H8_brn,            // Branch never
H8_bhi,            // Branch if higher
H8_bls,            // Branch if lower or same
H8_bcc,            // Branch if carry clear (higher or same)
H8_bcs,            // Branch if carry set (lower)
H8_bne,            // Branch if not equal
H8_beq,            // Branch if equal
H8_bvc,            // Branch if overflow clear
H8_bvs,            // Branch if overflow set
H8_bpl,            // Branch if plus
H8_bmi,            // Branch if minus
H8_bge,            // Branch if greates or equal
H8_blt,            // Branch if less
H8_bgt,            // Branch if greater
H8_ble,            // Branch if less or equal
H8_bclr,           // Bit clear
H8_biand,          // Bit invert AND
H8_bild,           // Bit invert load
H8_bior,           // Bit invert OR
H8_bist,           // Bit invert store
H8_bixor,          // Bit invert XOR
H8_bld,            // Bit load
H8_bnot,           // Bit NOT
H8_bor,            // Bit OR
H8_bset,           // Bit set
H8_bsr,            // Branch to subroutine
H8_bst,            // Bit store
H8_btst,           // Bit test
H8_bxor,           // Bit XOR
H8_clrmac,         // Clear MAC register
H8_cmp,            // Compare
H8_daa,            // Decimal adjust add
H8_das,            // Decimal adjust subtract
H8_dec,            // Decrement
H8_divxs,          // Divide extended as signed
H8_divxu,          // Divide extended as unsigned
H8_eepmov,         // Move data to EEPROM
H8_exts,           // Extend as signed
H8_extu,           // Extend as unsigned
H8_inc,            // Increment
H8_jmp,            // Jump
H8_jsr,            // Jump to subroutine
H8_ldc,            // Load to control register
H8_ldm,            // Load to multiple registers
H8_ldmac,          // Load to MAC register
H8_mac,            // Multiply and accumulate
H8_mov,            // Move data
H8_movfpe,         // Move from peripheral with E clock
H8_movtpe,         // Move to peripheral with E clock
H8_mulxs,          // Multiply extend as signed
H8_mulxu,          // Multiply extend as unsigned
H8_neg,            // Negate
H8_nop,            // No operation
H8_not,            // Logical complement
H8_or,             // Logical OR
H8_orc,            // Logical OR with control register
H8_pop,            // Pop data from stack
H8_push,           // Push data on stack
H8_rotl,           // Rotate left
H8_rotr,           // Rotate right
H8_rotxl,          // Rotate with extend carry left
H8_rotxr,          // Rotate with extend carry right
H8_rte,            // Return from exception
H8_rts,            // Return from subroutine
H8_shal,           // Shift arithmetic left
H8_shar,           // Shift arithmetic right
H8_shll,           // Shift logical left
H8_shlr,           // Shift logical right
H8_sleep,          // Power down mode
H8_stc,            // Store from control register
H8_stm,            // Store from multiple registers
H8_stmac,          // Store from MAC register
H8_sub,            // Subtract binary
H8_subs,           // Subtract with sign extension
H8_subx,           // Subtract with extend carry
H8_tas,            // Test and set
H8_trapa,          // Trap always
H8_xor,            // Logical XOR
H8_xorc,           // Logical XOR with control register

// H8SX
H8_rtel,           // Returns from an exception, restoring data to multiple general registers
H8_rtsl,           // Returns from a subroutine, restoring data to multiple general registers
H8_movmd,          // Transfers a data block
H8_movsd,          // Transfers a data block with zero detection
H8_bras,           // Branch always after the next instruction (delay slot)
H8_movab,          // MOVe effective Address/B
H8_movaw,          // MOVe effective Address/W
H8_moval,          // MOVe effective Address/L
H8_bsetne,         // Bit SET if Not Equal
H8_bseteq,         // Bit SET if EQual
H8_bclrne,         // Bit CLeaR if Not Equal
H8_bclreq,         // Bit CLeaR if Equal
H8_bstz,           // Bit STore Zero flag
H8_bistz,          // Bit Invert STore Zero flag
H8_bfld,           // Bit Field LoaD
H8_bfst,           // Bit Field STore
H8_muls,           // MULtiply as Signed
H8_divs,           // DIVide as Signed
H8_mulu,           // MULtiply as Unsigned
H8_divu,           // DIVide as Unsigned
H8_mulsu,          // MULtiply as Signed
H8_muluu,          // MULtiply as Unsigned
H8_brabc,          // BRAnch if Bit Cleared
H8_brabs,          // BRAnch if Bit Set
H8_bsrbc,          // Branch to SubRoutine if Bit Cleared
H8_bsrbs,          // Branch to SubRoutine if Bit Set

H8_last,

};

#endif
