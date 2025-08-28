/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  I196_null = 0,    // Unknown Operation

  I196_add2,        // Add words (2 operands)
  I196_add3,        // Add words (3 operands)
  I196_addb2,       // Add bytes (2 operands)
  I196_addb3,       // Add bytes (3 operands)

  I196_addc,        // Add words with carry
  I196_addcb,       // Add bytes with carry

  I196_and2,        // Logical AND words (2 operands)
  I196_and3,        // Logical AND words (3 operands)
  I196_andb2,       // Logical AND bytes (2 operands)
  I196_andb3,       // Logical AND bytes (3 operands)

  I196_bmov,        // Block move
  I196_bmovi,       // Interruptable block move

  I196_br,          // Branch indirect

  I196_clr,         // Clear word
  I196_clrb,        // Clear byte
  I196_clrc,        // Clear carry flag
  I196_clrvt,       // Clear overflow-trap flag

  I196_cmp,         // Compare words
  I196_cmpb,        // Compare bytes
  I196_cmpl,        // Compare long

  I196_dec,         // Decrement word
  I196_decb,        // Decrement byte

  I196_di,          // Disable interrupts

  I196_div,         // Divide integers
  I196_divb,        // Divide short-integers
  I196_divu,        // Divide words, unsigned
  I196_divub,       // Divide bytes, unsigned

  I196_djnz,        // Decrement and jump if not zero
  I196_djnzw,       // Decrement and jump if not zero word

  I196_dpts,        // Disable peripheral transaction server

  I196_ei,          // Enable interrupts

  I196_epts,        // Enable peripheral transaction server

  I196_ext,         // Sign-extend integer into long-integer
  I196_extb,        // Sign-extend short-integer into integer

  I196_idlpd,       // Idle/powerdown

  I196_inc,         // Increment word
  I196_incb,        // Increment byte

  I196_jbc,         // Jump if bit is clear
  I196_jbs,         // Jump if bit is set
  I196_jc,          // Jump if carry flag is set
  I196_je,          // Jump if equal
  I196_jge,         // Jump if signed greater than or equal
  I196_jgt,         // Jump if signed greater than
  I196_jh,          // Jump if higher (unsigned)
  I196_jle,         // Jump if signed less than or equal
  I196_jlt,         // Jump if signed less than
  I196_jnc,         // Jump if carry flag is clear
  I196_jne,         // Jump if not equal
  I196_jnh,         // Jump if not higher (unsigned)
  I196_jnst,        // Jump if sticky bit flag is clear
  I196_jnv,         // Jump if overflow flag is clear
  I196_jnvt,        // Jump if overflow-trap flag is clear
  I196_jst,         // Jump if sticky bit flag is set
  I196_jv,          // Jump if overflow flag is set
  I196_jvt,         // Jump if overflow-trap flag is set

  I196_lcall,       // Long call

  I196_ld,          // Load word
  I196_ldb,         // Load byte
  I196_ldbse,       // Load byte sign-extended
  I196_ldbze,       // Load byte zero-extended

  I196_ljmp,        // Long jump

  I196_mul2,        // Multiply integers (2 operands)
  I196_mul3,        // Multiply integers (3 operands)
  I196_mulb2,       // Multiply short-integers (2 operands)
  I196_mulb3,       // Multiply short-integers (3 operands)
  I196_mulu2,       // Multiply words, unsigned (2 operands)
  I196_mulu3,       // Multiply words, unsigned (3 operands)
  I196_mulub2,      // Multiply bytes, unsigned (2 operands)
  I196_mulub3,      // Multiply bytes, unsigned (3 operands)

  I196_neg,         // Negate integer
  I196_negb,        // Negate short-integer

  I196_nop,         // No operation

  I196_norml,       // Normalize long-integer

  I196_not,         // Complement word
  I196_notb,        // Complement byte

  I196_or,          // Logical OR words
  I196_orb,         // Logical OR bytes

  I196_pop,         // Pop word
  I196_popa,        // Pop all
  I196_popf,        // Pop flags
  I196_push,        // Push word
  I196_pusha,       // Push all
  I196_pushf,       // Push flags

  I196_ret,         // Return from subroutine

  I196_rst,         // Reset system

  I196_scall,       // Short call

  I196_setc,        // Set carry flag

  I196_shl,         // Shift word left
  I196_shlb,        // Shift byte left
  I196_shll,        // Shift double-word left
  I196_shr,         // Logical right shift word
  I196_shra,        // Arithmetic right shift word
  I196_shrab,       // Arithmetic right shift byte
  I196_shral,       // Arithmetic right shift double-word
  I196_shrb,        // Logical right shift byte
  I196_shrl,        // Logical right shift double-word

  I196_sjmp,        // Short jump

  I196_skip,        // Two byte no-operation

  I196_st,          // Store word
  I196_stb,         // Store byte

  I196_sub2,        // Subtract words (2 operands)
  I196_sub3,        // Subtract words (3 operands)
  I196_subb2,       // Subtract bytes (2 operands)
  I196_subb3,       // subtract bytes (3 operands)

  I196_subc,        // Subtract words with borrow
  I196_subcb,       // Subtract bytes with borrow

  I196_tijmp,       // Table indirect jump

  I196_trap,        // Software trap

  I196_xch,         // Exchange word
  I196_xchb,        // Exchange byte

  I196_xor,         // Logical exclusive-or words
  I196_xorb,        // Logical exclusive-or bytes

// 8x196NU, NP instructions

  I196_ebmovi,      // Extended interruptable block move
  I196_ebr,         // Extended branch indirect
  I196_ecall,       // Extended call
  I196_ejmp,        // Extended jump
  I196_eld,         // Extended load word
  I196_eldb,        // Extended load byte
  I196_est,         // Extended store word
  I196_estb,        // Extended store byte

  I196_last
};

#endif
