
#ifndef __INSTRS_HPP
#define __INSTRS_HPP

// exporting the ins.cpp array
extern const instruc_t Instructions[];

// m32r instructions declaration
enum nameNum ENUM_SIZE(uint16)
{
  m32r_null = 0,     // Null instruction
  m32r_add,          // Add
  m32r_add3,         // Add 3-operand
  m32r_addi,         // Add immediate
  m32r_addv,         // Add with overflow checking
  m32r_addv3,        // Add 3-operand with overflow checking
  m32r_addx,         // Add with carry
  m32r_and,          // AND
  m32r_and3,         // AND 3-operand
  m32r_bc,           // Branch on C-bit
  m32r_beq,          // Branch on equal
  m32r_beqz,         // Branch on equal zero
  m32r_bgez,         // Branch on greater than or equal zero
  m32r_bgtz,         // Branch on greater than zero
  m32r_bl,           // Branch and link
  m32r_blez,         // Branch on less than or equal zero
  m32r_bltz,         // Branch on less than zero
  m32r_bnc,          // Branch on not C-bit
  m32r_bne,          // Branch on not equal
  m32r_bnez,         // Branch on not equal zero
  m32r_bra,          // Branch
  m32r_cmp,          // Compare
  m32r_cmpi,         // Compare immediate
  m32r_cmpu,         // Compare unsigned
  m32r_cmpui,        // Compare unsigned immediate
  m32r_div,          // Divide
  m32r_divu,         // Divide unsigned
  m32r_jl,           // Jump and link
  m32r_jmp,          // Jump
  m32r_ld,           // Load
  m32r_ld24,         // Load 24-bit immediate
  m32r_ldb,          // Load byte
  m32r_ldh,          // Load halfword
  m32r_ldi,          // Load immediate
  m32r_ldub,         // Load unsigned byte
  m32r_lduh,         // Load unsigned halfword
  m32r_lock,         // Load locked
  m32r_machi,        // Multiply-accumulate high-order halfwords
  m32r_maclo,        // Multiply-accumulate low-order halfwords
  m32r_macwhi,       // Multiply-accumulate word and high-order halfword
  m32r_macwlo,       // Multiply-accumulate word and low-order halfword
  m32r_mul,          // Multiply
  m32r_mulhi,        // Multiply high-order halfwords
  m32r_mullo,        // Multiply low-order halfwords
  m32r_mulwhi,       // Multiply word high-order halfwords
  m32r_mulwlo,       // Multiply word low-order halfwords
  m32r_mv,           // Move register
  m32r_mvfachi,      // Move from accumulator high-order word
  m32r_mvfaclo,      // Move from accumulator low-order word
  m32r_mvfacmi,      // Move from accumulator middle-order word
  m32r_mvfc,         // Move from control register
  m32r_mvtachi,      // Move to accumulator high-order word
  m32r_mvtaclo,      // Move to accumulator low-order word
  m32r_mvtc,         // Move to control register
  m32r_neg,          // Negate
  m32r_nop,          // No operation
  m32r_not,          // Logical NOT
  m32r_or,           // OR
  m32r_or3,          // OR 3-operand
  m32r_push,         // Push, mnem for st reg, @-sp
  m32r_pop,          // Pop, mnem for ld reg, @sp+
  m32r_rac,          // Round accumulator
  m32r_rach,         // Round accumulator halfword
  m32r_rem,          // Remainder
  m32r_remu,         // Remainder unsigned
  m32r_rte,          // Return from EIT
  m32r_seth,         // Set high-order 16-bit
  m32r_sll,          // Shift left logical
  m32r_sll3,         // Shift left logical 3-operand
  m32r_slli,         // Shift left logical immediate
  m32r_sra,          // Shirt right arithmetic
  m32r_sra3,         // Shirt right arithmetic 3-operand
  m32r_srai,         // Shirt right arithmetic immediate
  m32r_srl,          // Shift right logical
  m32r_srl3,         // Shift right logical 3-operand
  m32r_srli,         // Shift right logical immediate
  m32r_st,           // Store
  m32r_stb,          // Store byte
  m32r_sth,          // Store halfword
  m32r_sub,          // Substract
  m32r_subv,         // Substract with overflow checking
  m32r_subx,         // Substract with borrow
  m32r_trap,         // Trap
  m32r_unlock,       // Store unlocked
  m32r_xor,          // Exclusive OR
  m32r_xor3,         // Exclusive OR 3-operand

  // M32RX :

  m32rx_bcl,
  m32rx_bncl,
  m32rx_cmpeq,
  m32rx_cmpz,
  m32rx_divh,
  m32rx_jc,
  m32rx_jnc,
  m32rx_machi,         // 'machi' 3-operand
  m32rx_maclo,         // 'maclo' 3-operand
  m32rx_macwhi,        // 'macwhi' 3-operand
  m32rx_macwlo,        // 'macwlo' 3-operand
  m32rx_mulhi,         // 'mulhi' 3-operand
  m32rx_mullo,         // 'mullo' 3-operand
  m32rx_mulwhi,        // 'mulwhi' 3-operand
  m32rx_mulwlo,        // 'mulwlo' 3-operand
  m32rx_mvfachi,       // 'mvfachi' 3-operand
  m32rx_mvfaclo,       // 'mvfaclo' 3-operand
  m32rx_mvfacmi,       // 'mvfacmi' 3-operand
  m32rx_mvtachi,       // 'mvtachi' 3-operand
  m32rx_mvtaclo,       // 'mvtaclo' 3-operand
  m32rx_rac,           // 'rac' 3 operand
  m32rx_rach,          // 'rach' 3 operand
  m32rx_satb,
  m32rx_sath,
  m32rx_sat,
  m32rx_pcmpbz,
  m32rx_sadd,
  m32rx_macwu1,
  m32rx_msblo,
  m32rx_mulwu1,
  m32rx_maclh1,
  m32rx_sc,
  m32rx_snc,

// Floating point
  m32r_fadd,           // Floating-point add
  m32r_fsub,           // Floating-point subtract
  m32r_fmul,           // Floating-point multiply
  m32r_fdiv,           // Floating-point divede
  m32r_fmadd,          // Floating-point multiply and add
  m32r_fmsub,          // Floating-point multiply and subtract
  m32r_itof,           // Integer to float
  m32r_utof,           // Unsigned integer to float
  m32r_ftoi,           // Float to integer
  m32r_ftos,           // Float to short
  m32r_fcmp,           // Floating-point compare
  m32r_fcmpe,          // Floating-point compare with exeption if unordered
// Bit Operation Instructions
  m32r_bset,           // Bit set
  m32r_bclr,           // Bit clear
  m32r_btst,           // Bit test
  m32r_setpsw,         // Set PSW
  m32r_clrpsw,         // Clear PSW

  m32r_last
};

#endif /* __INSTRS_HPP */

