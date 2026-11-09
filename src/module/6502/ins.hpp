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
  M65_null = 0,           // Unknown Operation

  // NMOS instructions

  M65_adc,                // A <- (A) + M + C
  M65_anc,                // A <- A /\ M, C <- ~A7
  M65_and,                // A <- (A) /\ M
  M65_ane,                // M <-[(A)\/$EE] /\ (X)/\(M)
  M65_arr,                // A <- [(A /\ M) >> 1]
  M65_asl,                // C <- A7, A <- (A) << 1
  M65_asr,                // A <- [(A /\ M) >> 1]
  M65_bcc,                // if C=0, PC = PC + offset
  M65_bcs,                // if C=1, PC = PC + offset
  M65_beq,                // if Z=1, PC = PC + offset
  M65_bit,                // Z <- ~(A /\ M) N<-M7 V<-M6
  M65_bmi,                // if N=1, PC = PC + offset
  M65_bne,                // if Z=0, PC = PC + offset
  M65_bpl,                // if N=0, PC = PC + offset
  M65_brk,                // Stack <- PC, PC <- ($fffe)
  M65_bvc,                // if V=0, PC = PC + offset
  M65_bvs,                // if V=1, PC = PC + offset
  M65_clc,                // C <- 0
  M65_cld,                // D <- 0
  M65_cli,                // I <- 0
  M65_clv,                // V <- 0
  M65_cmp,                // (A - M) -> NZC
  M65_cpx,                // (X - M) -> NZC
  M65_cpy,                // (Y - M) -> NZC
  M65_dcp,                // M <- (M)-1, (A-M) -> NZC
  M65_dec,                // M <- (M) - 1
  M65_dex,                // X <- (X) - 1
  M65_dey,                // Y <- (Y) - 1
  M65_eor,                // A <- (A) \-/ M
  M65_inc,                // M <- (M) + 1
  M65_inx,                // X <- (X) +1
  M65_iny,                // Y <- (Y) + 1
  M65_isb,                // M <- (M) - 1,A <- (A)-M-~C
  M65_jmp,                // PC <- Address
  M65_jmpi,               // (PC <- Address)
  M65_jsr,                // Stack <- PC, PC <- Address
  M65_lae,                // X,S,A <- (S /\ M)
  M65_lax,                // A <- M, X <- M
  M65_lda,                // A <- M
  M65_ldx,                // X <- M
  M65_ldy,                // Y <- M
  M65_lsr,                // C <- A0, A <- (A) >> 1
  M65_lxa,                // X04 <- (X04) /\ M04, A04 <- (A04) /\ M04
  M65_nop,                // [no operation]
  M65_ora,                // A <- (A) V M
  M65_pha,                // Stack <- (A)
  M65_php,                // Stack <- (P)
  M65_pla,                // A <- (Stack)
  M65_plp,                // A <- (Stack)
  M65_rla,                // M <- (M << 1) /\ (A)
  M65_rol,                // C <- A7 & A <- A << 1 + C
  M65_ror,                // C<-A0 & A<- (A7=C + A>>1)
  M65_rra,                // M <- (M >> 1) + (A) + C
  M65_rti,                // P <- (Stack), PC <-(Stack)
  M65_rts,                // PC <- (Stack)
  M65_sax,                // M <- (A) /\ (X)
  M65_sbc,                // A <- (A) - M - ~C
  M65_sbx,                // X <- (X)/\(A) - M
  M65_sec,                // C <- 1
  M65_sed,                // D <- 1
  M65_sei,                // I <- 1
  M65_sha,                // M <- (A) /\ (X) /\ (PCH+1)
  M65_shs,                // X <- (A) /\ (X), S <- (X), M <- (X) /\ (PCH+1)
  M65_shx,                // M <- (X) /\ (PCH+1)
  M65_shy,                // M <- (Y) /\ (PCH+1)
  M65_slo,                // M <- (M >> 1) + A + C
  M65_sre,                // M <- (M >> 1) \-/ A
  M65_sta,                // M <- (A)
  M65_stx,                // M <- (X)
  M65_sty,                // M <- (Y)
  M65_tax,                // X <- (A)
  M65_tay,                // Y <- (A)
  M65_tsx,                // X <- (S)
  M65_txa,                // A <- (X)
  M65_txs,                // S <- (X)
  M65_tya,                // A <- (Y)

  // CMOS instructions

  M65_bbr0,               // Branch if bit 0 reset
  M65_bbr1,               // Branch if bit 1 reset
  M65_bbr2,               // Branch if bit 2 reset
  M65_bbr3,               // Branch if bit 3 reset
  M65_bbr4,               // Branch if bit 4 reset
  M65_bbr5,               // Branch if bit 5 reset
  M65_bbr6,               // Branch if bit 6 reset
  M65_bbr7,               // Branch if bit 7 reset
  M65_bbs0,               // Branch if bit 0 set
  M65_bbs1,               // Branch if bit 1 set
  M65_bbs2,               // Branch if bit 2 set
  M65_bbs3,               // Branch if bit 3 set
  M65_bbs4,               // Branch if bit 4 set
  M65_bbs5,               // Branch if bit 5 set
  M65_bbs6,               // Branch if bit 6 set
  M65_bbs7,               // Branch if bit 7 set
  M65_rmb0,               // Reset memory bit 0
  M65_rmb1,               // Reset memory bit 1
  M65_rmb2,               // Reset memory bit 2
  M65_rmb3,               // Reset memory bit 3
  M65_rmb4,               // Reset memory bit 4
  M65_rmb5,               // Reset memory bit 5
  M65_rmb6,               // Reset memory bit 6
  M65_rmb7,               // Reset memory bit 7
  M65_smb0,               // Set memory bit 0
  M65_smb1,               // Set memory bit 1
  M65_smb2,               // Set memory bit 2
  M65_smb3,               // Set memory bit 3
  M65_smb4,               // Set memory bit 4
  M65_smb5,               // Set memory bit 5
  M65_smb6,               // Set memory bit 6
  M65_smb7,               // Set memory bit 7
  M65_stz,                // Store zero
  M65_tsb,                // Test and set bits
  M65_trb,                // Test and reset bits
  M65_phy,                // Push Y register
  M65_ply,                // Pull Y register
  M65_phx,                // Push X register
  M65_plx,                // Pull X register
  M65_bra,                // Branch always
  M65_wai,                // Wait for interrupt
  M65_stp,                // Stop processor

  M65_last,
};

#endif
