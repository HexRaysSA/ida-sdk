/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  Z8_null = 0,    // Unknown Operation

  Z8_adc,         // Add with carry
  Z8_add,         // Add
  Z8_and,         // Logical AND
  Z8_call,        // Call procedure
  Z8_ccf,         // Complement carry flag
  Z8_clr,         // Clear
  Z8_com,         // Complement
  Z8_cp,          // Compare
  Z8_da,          // Decimal adjust
  Z8_dec,         // Decrement
  Z8_decw,        // Decrement word
  Z8_di,          // Disable interrupts
  Z8_djnz,        // Decrement and jump if non-zero
  Z8_ei,          // Enable interrupts
  Z8_halt,        // Enter HALT mode
  Z8_inc,         // Increment
  Z8_incw,        // Increment word
  Z8_iret,        // Return from interrupt
  Z8_jp,          // Unconditional jump
  Z8_jpcond,      // Conditional jump
  Z8_jr,          // Relative jump
  Z8_jrcond,      // Conditional relative jump
  Z8_ld,          // Load data
  Z8_ldc,         // Load constant
  Z8_ldci,        // Load constant with auto-increment
  Z8_lde,         // Load external data
  Z8_ldei,        // Load external data with auto-increment
  Z8_nop,         // NOP
  Z8_or,          // Logical OR
  Z8_pop,         // Pop
  Z8_push,        // Push
  Z8_rcf,         // Reset carry flag
  Z8_ret,         // Return
  Z8_rl,          // Rotate left
  Z8_rlc,         // Rotate left through carry
  Z8_rr,          // Rotate right
  Z8_rrc,         // Rotate right through carry
  Z8_sbc,         // Subtract with carry
  Z8_scf,         // Set carry flag
  Z8_sra,         // Shift right arithmetic
  Z8_srp,         // Set register pointer
  Z8_stop,        // Enter STOP mode
  Z8_sub,         // Subtract
  Z8_swap,        // Swap nibbles
  Z8_tm,          // Test under mask
  Z8_tcm,         // Test complement under mask
  Z8_xor,         // Logical EXCLUSIVE OR
  Z8_wdh,         // Enable WATCH-DOG in HALT mode
  Z8_wdt,         // Clear WATCH-DOG timer

  Z8_last
};

#endif
