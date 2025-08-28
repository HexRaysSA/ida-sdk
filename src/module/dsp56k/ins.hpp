
#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
DSP56_null = 0,     // Unknown Operation

DSP56_abs,          // Absolute Value
DSP56_adc,          // Add Long with Carry
DSP56_add,          // Addition
DSP56_addl,         // Shift Left and Add
DSP56_addr,         // Shift Right and Add
DSP56_and,          // Logical AND
DSP56_andi,         // AND Immediate to Control Register
DSP56_asl,          // Arithmetic Shift Left
DSP56_asl4,         // Arithmetic Shift Left 4
DSP56_asr,          // Arithmetic Shift Right
DSP56_asr4,         // Arithmetic Shift Right 4
DSP56_asr16,        // Arithmetic Shift Right 16
DSP56_bfchg,        // Test Bit Field and Change
DSP56_bfclr,        // Clear Bit Field
DSP56_bfset,        // Set Bit Field
DSP56_bftsth,       // Test Bit Field High
DSP56_bftstl,       // Test Bit Field Low
DSP56_bcc,          // Branch Conditionaly
DSP56_bchg,         // Bit Test and Change
DSP56_bclr,         // Bit Test and Clear
DSP56_bra,          // Branch Always
DSP56_brclr,        // Branch if Bit Clear
DSP56_brkcc,        // Exit Current DO Loop Conditionally
DSP56_brset,        // Branch if Bit Set
DSP56_bscc,         // Branch to Subroutine Conditionaly
DSP56_bsclr,        // Branch to Subroutine if Bit Clear
DSP56_bset,         // Bit Test and Set
DSP56_bsr,          // Branch to Subroutine
DSP56_bsset,        // Branch to Subroutine if Bit Set
DSP56_btst,         // Bit Test on Memory and Registers
DSP56_chkaau,           // Check address ALU result
DSP56_clb,          // Count Leading Bits
DSP56_clr,          // Clear an Operand
DSP56_clr24,        // Clear 24 MS-bits of Accumulator
DSP56_cmp,          // Compare
DSP56_cmpm,         // Compare Magnitude
DSP56_cmpu,         // Compare Unsigned
DSP56_debug,        // Enter Debug Mode
DSP56_debugcc,      // Enter Debug Mode Conditionally
DSP56_dec,          // Decrement by One
DSP56_dec24,        // Decrement 24 MS-bit of Accumulator
DSP56_div,          // Divide Iteration
DSP56_dmac,         // Double-Precision Multiply-Accumulate With Right Shift
DSP56_do,           // Start Hardware Loop
DSP56_do_f,         // Start Infinite Loop
DSP56_dor,          // Start PC-Relative Hardware Loop
DSP56_dor_f,        // Start PC-Relative Infinite Loop
DSP56_enddo,        // Exit from Hardware Loop
DSP56_eor,          // Logical Exclusive OR
DSP56_extract,      // Extract Bit Field
DSP56_extractu,     // Extract Unsigned Bit Field
DSP56_ext,          // Sign Extend Accumulator
DSP56_ill,          // Illegal Instruction
DSP56_imac,         // Integer Multiply-Accumulate
DSP56_impy,         // Integer Multiply
DSP56_inc,          // Increment by One
DSP56_inc24,        // Increment 24 MS-bit of Accumulator
DSP56_insert,       // Insert Bit Field
DSP56_jcc,          // Jump Conditionally
DSP56_jclr,         // Jump if Bit Clear
DSP56_jmp,          // Jump
DSP56_jscc,         // Jump to Subroutine Conditionally
DSP56_jsclr,        // Jump to Subroutine if Bit Clear
DSP56_jset,         // Jump if Bit Set
DSP56_jsr,          // Jump to Subroutine
DSP56_jsset,        // Jump to Subroutine if Bit Set
DSP56_lra,          // Load PC-Reliative Address
DSP56_lsl,          // Logical Shift Left
DSP56_lsr,          // Logical Shift Right
DSP56_lua,          // Load Updated Address
DSP56_lea,          // Load Updated Address
DSP56_mac,          // Signed Multiply-Accumulate
DSP56_maci,         // Signed Multiply-Accumulate With Immediate Operand
DSP56_mac_s_u,      // Mixed Multiply-Accumulate
DSP56_macr,         // Signed Multiply-Accumulate and Round
DSP56_macri,        // Signed Multiply-Accumulate and Round With Immediate Operand
DSP56_max,          // Transfer by Signed Value
DSP56_maxm,         // Transfer by Magnitude
DSP56_merge,        // Merge Two Half Words
DSP56_move,         // Move Data
DSP56_movec,        // Move Control Register
DSP56_movei,        // Move Immediate Short
DSP56_movem,        // Move Program Memory
DSP56_movep,        // Move Peripheral Data
DSP56_moves,        // Move Absolute Short
DSP56_mpy,          // Signed Multiply
DSP56_mpyi,         // Signed Multiply With Immediate Operand
DSP56_mpy_s_u,      // Mixed Multiply
DSP56_mpyr,         // Signed Multiply and Round
DSP56_mpyri,        // Signed Multiply and Round With Immediate Operand
DSP56_neg,          // Negate Accumulator
DSP56_negc,         // Negate Accumulator
DSP56_nop,          // No Operation
DSP56_norm,         // Norm Accumulator Iteration
DSP56_normf,        // Fast Accumulator Normalization
DSP56_not,          // Logical Complement
DSP56_or,           // Logical Inclusive OR
DSP56_ori,          // OR Immediate to Control Register
DSP56_pflush,       // Program Cache Flush
DSP56_pflushun,     // Program Cache Flush Unlocked Sectors
DSP56_pfree,        // Program Cache Global Unlock
DSP56_plock,        // Lock Instruction Cache Sector
DSP56_plockr,       // Lock Instruction Cache Relative Sector
DSP56_punlock,      // Unlock Instruction Cache Sector
DSP56_punlockr,     // Unlock Instruction Cache Relative Sector
DSP56_rep,          // Repeat Next Instruction
DSP56_repcc,        // Repeat Next Instruction
DSP56_reset,        // Reset On-Chip Peripheral Devices
DSP56_rnd,          // Round Accumulator
DSP56_rol,          // Rotate Left
DSP56_ror,          // Rotate Right
DSP56_rti,          // Return from Interrupt
DSP56_rts,          // Return from Subroutine
DSP56_sbc,          // Subtract Long with Carry
DSP56_stop,         // Stop Processing (Low-Power Standby)
DSP56_sub,          // Subtract
DSP56_subl,         // Shift Left and Subtract
DSP56_subr,         // Shift Right and Subtract
DSP56_swap,         // Swap Accumulator Words
DSP56_tcc,          // Transfer Conditionally
DSP56_tfr,          // Transfer Data ALU Register
DSP56_tfr2,         // Transfer Data ALU Register
DSP56_tfr3,         // Transfer Data ALU Register
DSP56_trap,         // Software Interrupt
DSP56_trapcc,       // Software Interrupt Conditionally
DSP56_tst,          // Test an Operand
DSP56_tst2,         // Test an Operand
DSP56_vsl,          // Viterbi Shift Left
DSP56_wait,         // Wait for Interrupt or DMA Request (Low-Power Standby)
DSP56_zero,         // Zero Extend Accumulator
DSP56_swi,          // Software Interrupt (only for 56000)
DSP56_pmov,         // Pseudo insn
DSP56_last,

};

#endif
