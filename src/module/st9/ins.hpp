
#ifndef __INS_HPP
#define __INS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  st9_null = 0,           // Unknown Operation.
  st9_ld,                 // Load.
  st9_ldw,                // Load word.
  st9_ldpp,               // Load (using CSR) => (using CSR).
  st9_ldpd,               // Load (using DPRx) => (using CSR).
  st9_lddp,               // Load (using CSR) => (using DPRx).
  st9_lddd,               // Load (using DPRx) => (using DPRx).
  st9_add,                // Add.
  st9_addw,               // Add Word.
  st9_adc,                // Add with Carry.
  st9_adcw,               // Add Word with Carry.
  st9_sub,                // Substract.
  st9_subw,               // Substract Word.
  st9_sbc,                // Substract with Carry.
  st9_sbcw,               // Substract Word with Carry.
  st9_and,                // Logical AND.
  st9_andw,               // Logical Word AND.
  st9_or,                 // Logical OR.
  st9_orw,                // Logical Word OR.
  st9_xor,                // Logical Exclusive OR.
  st9_xorw,               // Logical Word Exclusive OR.
  st9_cp,                 // Compare.
  st9_cpw,                // Compare Word.
  st9_tm,                 // Test under Mask.
  st9_tmw,                // Test Word under Mask.
  st9_tcm,                // Test Complement under Mask.
  st9_tcmw,               // Test Word Complement under Mask.
  st9_inc,                // Increment.
  st9_incw,               // Increment Word.
  st9_dec,                // Decrement.
  st9_decw,               // Decrement Word.
  st9_sla,                // Shift Left Arithmetic.
  st9_slaw,               // Shift Word Left Arithmetic.
  st9_sra,                // Shift Right Arithmetic.
  st9_sraw,               // Shift Word Right Arithmetic.
  st9_rrc,                // Rotate Right through Carry.
  st9_rrcw,               // Rotate Word Right through Carry.
  st9_rlc,                // Rotate Left through Carry.
  st9_rlcw,               // Rotate Word Left through Carry.
  st9_ror,                // Rotate Right.
  st9_rol,                // Rotate Left.
  st9_clr,                // Clear Register.
  st9_cpl,                // Complement Register.
  st9_swap,               // Swap Nibbles.
  st9_da,                 // Decimal ajust.
  st9_push,               // Push on System Stack.
  st9_pushw,              // Push Word on System Stack.
  st9_pea,                // Push Effective Address on System Stack.
  st9_pop,                // Pop from System Stack.
  st9_popw,               // Pop Word from System Stack.
  st9_pushu,              // Push on User Stack.
  st9_pushuw,             // Push Word on User Stack.
  st9_peau,               // Push Effective Address on User Stack.
  st9_popu,               // Pop from User Stack.
  st9_popuw,              // Pop Word from User Stack.
  st9_link,               // Move System Stack Pointer upward; support for high-level language.
  st9_unlink,             // Move System Stack Pointer backward; support for high-level language.
  st9_linku,              // Move User Stack Pointer upward; support for high-level language.
  st9_unlinku,            // Move User Stack Pointer backward; support for high-level language.
  st9_mul,                // Multiply 8x8.
  st9_div,                // Divide 8x8.
  st9_divws,              // Divide Word Stepped 32/16.
  st9_bset,               // Bit Set.
  st9_bres,               // Bit Reset    .
  st9_bcpl,               // Bit Complement.
  st9_btset,              // Bit Test and Set.
  st9_bld,                // Bit Load.
  st9_band,               // Bit AND.
  st9_bor,                // Bit OR.
  st9_bxor,               // Bit XOR.
  st9_ret,                // Return from Subroutine.
  st9_rets,               // Inter-segment Return to Subroutine.
  st9_iret,               // Return from Interrupt.
  st9_jrcc,               // Jump Relative if Condition ``cc'' is Met.
  st9_jpcc,               // Jump if Condition ``cc'' is Met.
  st9_jp,                 // Unconditional Jump.
  st9_jps,                // Unconditional Inter-segment Jump.
  st9_call,               // Unconditional Call.
  st9_calls,              // Inter-segment Call to Subroutine.
  st9_btjf,               // Bit Test and Jump if False.
  st9_btjt,               // Bit Test and Jump if True.
  st9_djnz,               // Decrement a Working Register and Jump if Non Zero.
  st9_dwjnz,              // Decrement a Register Pair and Jump if Non Zero.
  st9_cpjfi,              // Compare and Jump on False.  Otherwise Post Increment.
  st9_cpjti,              // Compare and Jump on True.  Otherwise Post Increment.
  st9_xch,                // Exchange Registers.
  st9_srp,                // Set Register Pointer Long (16 working registers).
  st9_srp0,               // Set Register Pointer 0 (8 LSB working registers).
  st9_srp1,               // Set Register Pointer 1 (8 MSB working registers).
  st9_spp,                // Set Page Pointer.
  st9_ext,                // Sign Extend.
  st9_ei,                 // Enable Interrupts.
  st9_di,                 // Disable Interrupts.
  st9_scf,                // Set Carry Flag.
  st9_rcf,                // Reset Carry Flag.
  st9_ccf,                // Complement Carry Flag.
  st9_spm,                // Select Extended Memory addressing scheme through CSR Register.
  st9_sdm,                // Select Extended Memory addressing scheme through DPR Registers.
  st9_nop,                // No Operation.
  st9_wfi,                // Stop Program Execution and Wait for the next Enable Interrupt.
  st9_halt,               // Stop Program Execution until System Reset.
  st9_etrap,              // Undocumented instruction.
  st9_eret,               // Undocumented instruction.
  st9_ald,                // PSEUDO INSTRUCTION.  SHOULD NEVER BE USED.
  st9_aldw,               // PSEUDO INSTRUCTION.  SHOULD NEVER BE USED.
  st9_last
};

#endif /* __INS_HPP */

