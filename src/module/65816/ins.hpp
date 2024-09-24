
#ifndef __INSTRS_HPP__
#define __INSTRS_HPP__

extern const struct instruc_t Instructions[];

// The instruction types (``itype''s)
// m65* CPUs implements.

enum m65_itype_t
{
  // http://www.westerndesigncenter.com/wdc/datasheets/Programmanual.pdf
  M65816_null=0, // Unknown Operation
  M65816_adc,    // Add with carry
  M65816_and,    // AND A with memory
  M65816_asl,    // Shift memory or A left
  M65816_bcc,    // Branch if carry clear
  M65816_bcs,    // Branch if carry set
  M65816_beq,    // Branch if equal
  M65816_bit,    // Test memory bits against A
  M65816_bmi,    // Branch if minus
  M65816_bne,    // Branch if not equal
  M65816_bpl,    // Branch if plus
  M65816_bra,    // Branch always
  M65816_brk,    // Software break
  M65816_brl,    // Branch always long
  M65816_bvc,    // Branch if overflow clear
  M65816_bvs,    // Branch if overflow set
  M65816_clc,    // Clear carry flag
  M65816_cld,    // Clear decimal mode flag
  M65816_cli,    // Clear interrupt disable flag
  M65816_clv,    // Clear overflow flag
  M65816_cmp,    // Compare A with memory
  M65816_cop,    // Co-processor enable
  M65816_cpx,    // Compare X with memory
  M65816_cpy,    // Compare Y with memory
  M65816_dec,    // Decrement
  M65816_dex,    // Decrement X
  M65816_dey,    // Decrement Y
  M65816_eor,    // XOR A with M
  M65816_inc,    // Increment
  M65816_inx,    // Increment X
  M65816_iny,    // Increment Y
  M65816_jml,    // Jump long (inter-bank)
  M65816_jmp,    // Jump
  M65816_jsl,    // Jump to subroutine long (inter-bank)
  M65816_jsr,    // Jump to subroutine
  M65816_lda,    // Load A from memory
  M65816_ldx,    // Load X from memory
  M65816_ldy,    // Load Y from memory
  M65816_lsr,    // Logical shift memory or A right
  M65816_mvn,    // Block move next
  M65816_mvp,    // Block move prev
  M65816_nop,    // Nop
  M65816_ora,    // Or A with memory
  M65816_pea,    // Push effective absolute address
  M65816_pei,    // Push effective indirect address
  M65816_per,    // Push effective PC-relative indirect address
  M65816_pha,    // Push A
  M65816_phb,    // Push B (data bank register)
  M65816_phd,    // Push D (direct page register)
  M65816_phk,    // Push K (program bank register)
  M65816_php,    // Push processor status
  M65816_phx,    // Push X
  M65816_phy,    // Push Y
  M65816_pla,    // Pull A
  M65816_plb,    // Pull B
  M65816_pld,    // Pull D
  M65816_plp,    // Pull processor status
  M65816_plx,    // Pull X
  M65816_ply,    // Pull Y
  M65816_rep,    // Reset status bits
  M65816_rol,    // Rotate memory or A left
  M65816_ror,    // Rotate memory or A right
  M65816_rti,    // Return from interrupt
  M65816_rtl,    // Return from subroutine long
  M65816_rts,    // Return from subroutine
  M65816_sbc,    // Subtract with borrow from A
  M65816_sec,    // Set carry flag
  M65816_sed,    // Set decimal mode flag
  M65816_sei,    // Set interrupt disable flag
  M65816_sep,    // Set status bits
  M65816_sta,    // Store A to memory
  M65816_stp,    // Stop processor
  M65816_stx,    // Store X to memory
  M65816_sty,    // Store Y to memory
  M65816_stz,    // Store zero to memory
  M65816_tax,    // Transfer A to X
  M65816_tay,    // Transfer A to Y
  M65816_tcd,    // Transfer 16-bit A to D (direct page register)
  M65816_tcs,    // Transfer A to S
  M65816_tdc,    // Transfer 16-bit D to A
  M65816_trb,    // Test and reset memory bits against A
  M65816_tsb,    // Test and set memory bits against A
  M65816_tsc,    // Transfer S to A
  M65816_tsx,    // Transfer S to X
  M65816_txa,    // Transfer X to A
  M65816_txs,    // Transfer X to S
  M65816_txy,    // Transfer X to Y
  M65816_tya,    // Transfer Y to A
  M65816_tyx,    // Transfer Y to X
  M65816_wai,    // Wait for interrupt
  M65816_wdm,    // Reserved
  M65816_xba,    // Exchange bytes in A
  M65816_xce,    // Exchange carry and emulation bits
  M65816_last
};

#endif
