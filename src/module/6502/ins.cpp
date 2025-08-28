/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },
  { "ADC",        CF_USE1                         },      // A <- (A) + M + C
  { "ANC",        CF_USE1                         },      // A <- A /\ M, C <- ~A7
  { "AND",        CF_USE1                         },      // A <- (A) /\ M
  { "ANE",        CF_USE1                         },      // M <-[(A)\/$EE] /\ (X)/\(M)
  { "ARR",        CF_USE1                         },      // A <- [(A /\ M) >> 1]
  { "ASL",        CF_CHG1                         },      // C <- A7, A <- (A) << 1
  { "ASR",        CF_USE1                         },      // A <- [(A /\ M) >> 1]
  { "BCC",        CF_USE1                         },      // if C=0, PC = PC + offset
  { "BCS",        CF_USE1                         },      // if C=1, PC = PC + offset
  { "BEQ",        CF_USE1                         },      // if Z=1, PC = PC + offset
  { "BIT",        CF_USE1                         },      // Z <- ~(A /\ M) N<-M7 V<-M6
  { "BMI",        CF_USE1                         },      // if N=1, PC = PC + offset
  { "BNE",        CF_USE1                         },      // if Z=0, PC = PC + offset
  { "BPL",        CF_USE1                         },      // if N=0, PC = PC + offset
  { "BRK",        CF_STOP                         },      // Stack <- PC, PC <- ($fffe)
  { "BVC",        CF_USE1                         },      // if V=0, PC = PC + offset
  { "BVS",        CF_USE1                         },      // if V=1, PC = PC + offset
  { "CLC",        0                               },      // C <- 0
  { "CLD",        0                               },      // D <- 0
  { "CLI",        0                               },      // I <- 0
  { "CLV",        0                               },      // V <- 0
  { "CMP",        CF_USE1                         },      // (A - M) -> NZC
  { "CPX",        CF_USE1                         },      // (X - M) -> NZC
  { "CPY",        CF_USE1                         },      // (Y - M) -> NZC
  { "DCP",        CF_USE1|CF_CHG1                 },      // M <- (M)-1, (A-M) -> NZC
  { "DEC",        CF_USE1|CF_CHG1                 },      // M <- (M) - 1
  { "DEX",        0                               },      // X <- (X) - 1
  { "DEY",        0                               },      // Y <- (Y) - 1
  { "EOR",        CF_USE1                         },      // A <- (A) \-/ M
  { "INC",        CF_USE1|CF_CHG1                 },      // M <- (M) + 1
  { "INX",        0                               },      // X <- (X) +1
  { "INY",        0                               },      // Y <- (Y) + 1
  { "ISB",        CF_USE1|CF_CHG1                 },      // M <- (M) - 1,A <- (A)-M-~C
  { "JMP",        CF_USE1|CF_STOP                 },      // PC <- Address
  { "JMP",        CF_USE1|CF_JUMP|CF_STOP         },      // PC <- (Address)
  { "JSR",        CF_USE1|CF_CALL                 },      // Stack <- PC, PC <- Address
  { "LAE",        CF_USE1                         },      // X,S,A <- (S /\ M)
  { "LAX",        CF_USE1                         },      // A <- M, X <- M
  { "LDA",        CF_USE1                         },      // A <- M
  { "LDX",        CF_USE1                         },      // X <- M
  { "LDY",        CF_USE1                         },      // Y <- M
  { "LSR",        CF_CHG1                         },      // C <- A0, A <- (A) >> 1
  { "LXA",        CF_USE1                         },      // X04 <- (X04) /\ M04, A04 <- (A04) /\ M04
  { "NOP",        0                               },      // [no operation]
  { "ORA",        CF_USE1                         },      // A <- (A) V M
  { "PHA",        0                               },      // Stack <- (A)
  { "PHP",        0                               },      // Stack <- (P)
  { "PLA",        0                               },      // A <- (Stack)
  { "PLP",        0                               },      // A <- (Stack)
  { "RLA",        CF_USE1|CF_CHG1                 },      // M <- (M << 1) /\ (A)
  { "ROL",        CF_CHG1                         },      // C <- A7 & A <- A << 1 + C
  { "ROR",        CF_CHG1                         },      // C<-A0 & A<- (A7=C + A>>1)
  { "RRA",        CF_USE1|CF_CHG1                 },      // M <- (M >> 1) + (A) + C
  { "RTI",        CF_STOP                         },      // P <- (Stack), PC <-(Stack)
  { "RTS",        CF_STOP                         },      // PC <- (Stack)
  { "SAX",        CF_CHG1                         },      // M <- (A) /\ (X)
  { "SBC",        CF_USE1                         },      // A <- (A) - M - ~C
  { "SBX",        CF_USE1                         },      // X <- (X)/\(A) - M
  { "SEC",        0                               },      // C <- 1
  { "SED",        0                               },      // D <- 1
  { "SEI",        0                               },      // I <- 1
  { "SHA",        CF_CHG1                         },      // M <- (A) /\ (X) /\ (PCH+1)
  { "SHS",        CF_CHG1                         },      // X <- (A) /\ (X), S <- (X), M <- (X) /\ (PCH+1)
  { "SHX",        CF_CHG1                         },      // M <- (X) /\ (PCH+1)
  { "SHY",        CF_CHG1                         },      // M <- (Y) /\ (PCH+1)
  { "SLO",        CF_USE1|CF_CHG1                 },      // M <- (M >> 1) + A + C
  { "SRE",        CF_USE1|CF_CHG1                 },      // M <- (M >> 1) \-/ A
  { "STA",        CF_CHG1                         },      // M <- (A)
  { "STX",        CF_CHG1                         },      // M <- (X)
  { "STY",        CF_CHG1                         },      // M <- (Y)
  { "TAX",        0                               },      // X <- (A)
  { "TAY",        0                               },      // Y <- (A)
  { "TSX",        0                               },      // X <- (S)
  { "TXA",        0                               },      // A <- (X)
  { "TXS",        0                               },      // S <- (X)
  { "TYA",        0                               },      // A <- (Y)


  // CMOS instructions

  { "BBR0",       CF_USE1|CF_USE2                 },      // Branch if bit 0 reset
  { "BBR1",       CF_USE1|CF_USE2                 },      // Branch if bit 1 reset
  { "BBR2",       CF_USE1|CF_USE2                 },      // Branch if bit 2 reset
  { "BBR3",       CF_USE1|CF_USE2                 },      // Branch if bit 3 reset
  { "BBR4",       CF_USE1|CF_USE2                 },      // Branch if bit 4 reset
  { "BBR5",       CF_USE1|CF_USE2                 },      // Branch if bit 5 reset
  { "BBR6",       CF_USE1|CF_USE2                 },      // Branch if bit 6 reset
  { "BBR7",       CF_USE1|CF_USE2                 },      // Branch if bit 7 reset
  { "BBS0",       CF_USE1|CF_USE2                 },      // Branch if bit 0 set
  { "BBS1",       CF_USE1|CF_USE2                 },      // Branch if bit 1 set
  { "BBS2",       CF_USE1|CF_USE2                 },      // Branch if bit 2 set
  { "BBS3",       CF_USE1|CF_USE2                 },      // Branch if bit 3 set
  { "BBS4",       CF_USE1|CF_USE2                 },      // Branch if bit 4 set
  { "BBS5",       CF_USE1|CF_USE2                 },      // Branch if bit 5 set
  { "BBS6",       CF_USE1|CF_USE2                 },      // Branch if bit 6 set
  { "BBS7",       CF_USE1|CF_USE2                 },      // Branch if bit 7 set
  { "RMB0",       CF_CHG1                         },      // Reset memory bit 0
  { "RMB1",       CF_CHG1                         },      // Reset memory bit 1
  { "RMB2",       CF_CHG1                         },      // Reset memory bit 2
  { "RMB3",       CF_CHG1                         },      // Reset memory bit 3
  { "RMB4",       CF_CHG1                         },      // Reset memory bit 4
  { "RMB5",       CF_CHG1                         },      // Reset memory bit 5
  { "RMB6",       CF_CHG1                         },      // Reset memory bit 6
  { "RMB7",       CF_CHG1                         },      // Reset memory bit 7
  { "SMB0",       CF_CHG1                         },      // Set memory bit 0
  { "SMB1",       CF_CHG1                         },      // Set memory bit 1
  { "SMB2",       CF_CHG1                         },      // Set memory bit 2
  { "SMB3",       CF_CHG1                         },      // Set memory bit 3
  { "SMB4",       CF_CHG1                         },      // Set memory bit 4
  { "SMB5",       CF_CHG1                         },      // Set memory bit 5
  { "SMB6",       CF_CHG1                         },      // Set memory bit 6
  { "SMB7",       CF_CHG1                         },      // Set memory bit 7
  { "STZ",        CF_CHG1                         },      // Store zero
  { "TSB",        CF_USE1|CF_CHG1                 },      // Test and set bits
  { "TRB",        CF_USE1|CF_CHG1                 },      // Test and reset bits
  { "PHY",        0                               },      // Push Y register
  { "PLY",        0                               },      // Pull Y register
  { "PHX",        0                               },      // Push X register
  { "PLX",        0                               },      // Pull X register
  { "BRA",        CF_USE1|CF_STOP                 },      // Branch always
  { "WAI",        0                               },      // Wait for interrupt
  { "STP",        CF_STOP                         },      // Stop processor
};

CASSERT(qnumber(Instructions) == M65_last);
