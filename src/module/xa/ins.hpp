/*
        This module has been created by Petr Novak
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
XA_null = 0,   // Unknown Operation

XA_add,         // Add Second Operand to Acc
XA_addc,        // Add Second Operand to Acc with carry
XA_adds,        // Add Second Operand to Acc
XA_and,         // Logical AND (op1 &= op2)
XA_anl,         // Logical AND Carry and Bit
XA_asl,         // Logical shift left
XA_asr,         // Arithmetic shift left
XA_bcc,         // Branch if Carry clear
XA_bcs,         // Branch if Carry set
XA_beq,         // Branch if Zero
XA_bg,          // Branch if Greater than (unsigned)
XA_bge,         // Branch if Greater than or equal to (signed)
XA_bgt,         // Branch if Greater than (signed)
XA_bkpt,        // Breakpoint
XA_bl,          // Branch if Less than or equal to (unsigned)
XA_ble,         // Branch if less than or equal to (signed)
XA_blt,         // Branch if less than (signed)
XA_bmi,         // Branch if negative
XA_bne,         // Branch if not equal
XA_bnv,         // Branch if no overflow
XA_bov,         // Branch if overflow flag
XA_bpl,         // Branch if positive
XA_br,          // Branch always
XA_call,        // Call Subroutine
XA_cjne,        // Compare Operands and JNE
XA_clr,         // Clear Operand (0)
XA_cmp,         // Compare destination and source registers
XA_cpl,         // Complement Operand
XA_da,          // Decimal Adjust Accumulator
XA_div,         // Divide
XA_divu,        // Divide
XA_djnz,        // Decrement Operand and JNZ
XA_fcall,       // Far Call
XA_fjmp,        // Far Jump
XA_jb,          // Jump if Bit is set
XA_jbc,         // Jump if Bit is set & clear Bit
XA_jmp,         // Jump indirect relative to Data Pointer
XA_jnb,         // Jump if Bit is clear
XA_jnz,         // Jump if Acc is not zero
XA_jz,          // Jump if Acc is zero
XA_lea,         // Load effective address
XA_lsr,         // Logical shift right
XA_mov,         // Move (Op1 <- Op2)
XA_movc,        // Move code byte relative to second op to Acc
XA_movs,        // Move short
XA_movx,        // Move from/to external RAM
XA_mul,         // Multiply
XA_mulu,        // Multiply unsigned
XA_neg,         // Negate
XA_nop,         // No operation
XA_norm,        // Normalize
XA_or,          // Logical OR (op1 |= op2)
XA_orl,         // Logical OR Carry
XA_pop,         // Pop  from Stack and put in Direct RAM
XA_popu,        // Pop  from Stack and put in Direct RAM
XA_push,        // Push from Direct RAM to Stack
XA_pushu,       // Push from Direct RAM to Stack
XA_reset,       // Software reset
XA_ret,         // Return from subroutine
XA_reti,        // Return from Interrupt
XA_rl,          // Rotate Acc left
XA_rlc,         // Rotate Acc left through Carry
XA_rr,          // Rotate Acc right
XA_rrc,         // Rotate Acc right through Carry
XA_setb,        // Set Direct Bit
XA_sext,        // Sign extend
XA_sub,         // Subtract Second Operand from Acc with Borrow
XA_subb,        // Subtract Second Operand from Acc with Borrow
XA_trap,        // Software TRAP
XA_xch,         // Exchange Operands
XA_xor,         // Exclusive OR (op1 ^= op2)

XA_last,

    };

#endif
