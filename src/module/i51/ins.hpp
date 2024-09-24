/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint8)
{
I51_null = 0,   // Unknown Operation

I51_acall,      // Absolute Call
I51_add,        // Add Second Operand to Acc
I51_addc,       // Add Second Operand to Acc with carry
I51_ajmp,       // Absolute Jump
I51_anl,        // Logical AND (op1 &= op2)
I51_cjne,       // Compare Operands and JNE
I51_clr,        // Clear Operand (0)
I51_cpl,        // Complement Operand
I51_da,         // Decimal Adjust Accumulator
I51_dec,        // Decrement Operand
I51_div,        // Divide Acc by B
I51_djnz,       // Decrement Operand and JNZ
I51_inc,        // Increment Operand
I51_jb,         // Jump if Bit is set
I51_jbc,        // Jump if Bit is set & clear Bit
I51_jc,         // Jump if Carry is set
I51_jmp,        // Jump indirect relative to Data Pointer
I51_jnb,        // Jump if Bit is clear
I51_jnc,        // Jump if Carry is clear
I51_jnz,        // Jump if Acc is not zero
I51_jz,         // Jump if Acc is zero
I51_lcall,      // Long Subroutine Call
I51_ljmp,       // Long Jump
I51_mov,        // Move (Op1 <- Op2)
I51_movc,       // Move code byte relative to second op to Acc
I51_movx,       // Move from/to external RAM
I51_mul,        // Multiply Acc by B
I51_nop,        // No operation
I51_orl,        // Logical OR (op1 |= op2)
I51_pop,        // Pop  from Stack and put in Direct RAM
I51_push,       // Push from Direct RAM to Stack
I51_ret,        // Return from subroutine
I51_reti,       // Return from Interrupt
I51_rl,         // Rotate Acc left
I51_rlc,        // Rotate Acc left through Carry
I51_rr,         // Rotate Acc right
I51_rrc,        // Rotate Acc right through Carry
I51_setb,       // Set Direct Bit
I51_sjmp,       // Short jump
I51_subb,       // Subtract Second Operand from Acc with Borrow
I51_swap,       // Swap nibbles of Acc
I51_xch,        // Exchange Operands
I51_xchd,       // Exchange Digit in Acc with Indirect RAM
I51_xrl,        // Exclusive OR (op1 ^= op2)

// 80251 instructions

I51_jsle,       // Jump if less than or equal (signed)
I51_jsg,        // Jump if greater than (signed)
I51_jle,        // Jump if less than or equal
I51_jg,         // Jump if greater than
I51_jsl,        // Jump if less than (signed)
I51_jsge,       // Jump if greater than or equal (signed)
I51_je,         // Jump if equal
I51_jne,        // Jump if not equal
I51_trap,       // Trap
I51_ejmp,       // Extended jump
I51_ecall,      // Extended call
I51_eret,       // Extended return
I51_movh,       // Move immediate 16-bit data to the high word of a dword (double-word) register
I51_movz,       // Move 8-bit register to 16-bit register with zero extension
I51_movs,       // Move 8-bit register to 16-bit register with sign extension
I51_srl,        // Shift logical right by 1 bit
I51_sra,        // Shift arithmetic right by 1 bit
I51_sll,        // Shift logical left by 1 bit
I51_sub,        // Subtract
I51_cmp,        // Compare

// 51mx instructions
I51_emov,       // Move (A <- @PRi+disp) or (@PRi+disp <- A)

I51_last,

    };

#endif
