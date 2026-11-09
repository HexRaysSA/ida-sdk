
#include "m65816.hpp"
#include "ins.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },
  { "ADC",        CF_USE1                         },      // A <- (A) + M + C
  { "AND",        CF_USE1                         },      // A <- A /\ M, C <- ~A7
  { "ASL",        CF_CHG1|CF_SHFT                 },      // C <- A7, A <- (A) << 1
  { "BCC",        CF_USE1                         },      // if C=0, PC = PC + offset
  { "BCS",        CF_USE1                         },      // if C=1, PC = PC + offset
  { "BEQ",        CF_USE1                         },      // if Z=1, PC = PC + offset
  { "BIT",        CF_USE1                         },      // Z <- ~(A /\ M) N<-M7 V<-M6
  { "BMI",        CF_USE1                         },      // if N=1, PC = PC + offset
  { "BNE",        CF_USE1                         },      // if Z=0, PC = PC + offset
  { "BPL",        CF_USE1                         },      // if N=0, PC = PC + offset
  { "BRA",        CF_USE1|CF_STOP                 },      // Branch always
  { "BRK",        0                               },      // Stack <- PC, PC <- ($fffe)  NOTE: Usually it stops the processor. However, some games (e.g. Dragon Quest VI) use BRK as a customized opcode, by overriding the behavior through the interrupt vector.
  { "BRL",        CF_USE1|CF_STOP                 },      // Branch always long
  { "BVC",        CF_USE1                         },      // if V=0, PC = PC + offset
  { "BVS",        CF_USE1                         },      // if V=1, PC = PC + offset
  { "CLC",        0                               },      // C <- 0
  { "CLD",        0                               },      // D <- 0
  { "CLI",        0                               },      // I <- 0
  { "CLV",        0                               },      // V <- 0
  { "CMP",        CF_USE1                         },      // (A - M) -> NZC
  { "COP",        0                               },      // Coprocessor enable
  { "CPX",        CF_USE1                         },      // (X - M) -> NZC
  { "CPY",        CF_USE1                         },      // (Y - M) -> NZC
  { "DEC",        CF_USE1|CF_CHG1                 },      // M <- (M) - 1
  { "DEX",        0                               },      // X <- (X) - 1
  { "DEY",        0                               },      // Y <- (Y) - 1
  { "EOR",        CF_USE1                         },      // A <- (A) \-/ M
  { "INC",        CF_USE1|CF_CHG1                 },      // M <- (M) + 1
  { "INX",        0                               },      // X <- (X) +1
  { "INY",        0                               },      // Y <- (Y) + 1
  { "JML",        CF_USE1|CF_STOP                 },      // K,PC <- Long Address
  { "JMP",        CF_USE1|CF_STOP                 },      // PC <- Address
  { "JSL",        CF_USE1|CF_CALL                 },      // Stack <- PC, PC <- Long Address
  { "JSR",        CF_USE1|CF_CALL                 },      // Stack <- PC, PC <- Address
  { "LDA",        CF_USE1                         },      // A <- M
  { "LDX",        CF_USE1                         },      // X <- M
  { "LDY",        CF_USE1                         },      // Y <- M
  { "LSR",        CF_CHG1|CF_SHFT                 },      // C <- A0, A <- (A) >> 1
  { "MVN",        CF_USE1|CF_USE2                 },      // Block move next
  { "MVP",        CF_USE1|CF_USE2                 },      // Block move previous
  { "NOP",        0                               },      // [no operation]
  { "ORA",        CF_USE1                         },      // A <- (A) V M
  { "PEA",        CF_USE1                         },      // Stack <- Address
  { "PEI",        CF_USE1                         },      // Stack <- [DP + M]
  { "PER",        CF_USE1                         },      // Stack <- PC + offset
  { "PHA",        0                               },      // Stack <- (A)
  { "PHB",        0                               },      // Stack <- (B)
  { "PHD",        0                               },      // Stack <- (D)
  { "PHK",        0                               },      // Stack <- (K)
  { "PHP",        0                               },      // Stack <- (P)
  { "PHX",        0                               },      // Push X register
  { "PHY",        0                               },      // Push Y register
  { "PLA",        0                               },      // A <- (Stack)
  { "PLB",        0                               },      // B <- (Stack)
  { "PLD",        0                               },      // D <- (Stack)
  { "PLP",        0                               },      // P <- (Stack)
  { "PLX",        0                               },      // Pull X register
  { "PLY",        0                               },      // Pull Y register
  { "REP",        CF_USE1                         },      // Reset bits
  { "ROL",        CF_CHG1|CF_SHFT                 },      // C <- A7 & A <- A << 1 + C
  { "ROR",        CF_CHG1|CF_SHFT                 },      // C<-A0 & A<- (A7=C + A>>1)
  { "RTI",        CF_STOP                         },      // P <- (Stack), PC <-(Stack)
  { "RTL",        CF_STOP                         },      // K,PC <- (Stack)
  { "RTS",        CF_STOP                         },      // PC <- (Stack)
  { "SBC",        CF_USE1                         },      // A <- (A) - M - ~C
  { "SEC",        0                               },      // C <- 1
  { "SED",        0                               },      // D <- 1
  { "SEI",        0                               },      // I <- 1
  { "SEP",        CF_USE1                         },      // P <- Values
  { "STA",        CF_CHG1                         },      // M <- (A)
  { "STP",        0                               },      // Stop processor
  { "STX",        CF_CHG1                         },      // M <- (X)
  { "STY",        CF_CHG1                         },      // M <- (Y)
  { "STZ",        CF_CHG1                         },      // Store zero
  { "TAX",        0                               },      // X <- (A)
  { "TAY",        0                               },      // Y <- (A)
  { "TCD",        0                               },      // D <- (A)
  { "TCS",        0                               },      // S <- (A)
  { "TDC",        0                               },      // A <- (D)
  { "TRB",        CF_USE1|CF_CHG1                 },      // Test and reset bits
  { "TSB",        CF_USE1|CF_CHG1                 },      // Test and set bits
  { "TSC",        0                               },      // A <- (S)
  { "TSX",        0                               },      // X <- (S)
  { "TXA",        0                               },      // A <- (X)
  { "TXS",        0                               },      // S <- (X)
  { "TXY",        0                               },      // Y <- (X)
  { "TYA",        0                               },      // A <- (Y)
  { "TYX",        0                               },      // X <- (Y)
  { "WAI",        0                               },      // Wait for interrupt
  { "WDM",        0                               },      // Reserved
  { "XBA",        0                               },      // Exchange A's bytes
  { "XCE",        0                               }       // Exchange carry & emu bits
};

CASSERT(qnumber(Instructions) == M65816_last);


const struct addrmode_info_t AddressingModes[] =
{
  { "Absolute" },                            // ABS
  { "Absolute Indexed X" },                  // ABS_IX,
  { "Absolute Indexed Y" },                  // ABS_IY,
  { "Absolute Indexed Indirect" },           // ABS_IX_INDIR,
  { "Absolute Indirect" },                   // ABS_INDIR,
  { "Absolute Indirect Long" },              // ABS_INDIR_LONG,
  { "Absolute Long" },                       // ABS_LONG,
  { "Absolute Long Indexed X" },             // ABS_LONG_IX,
  { "Accumulator" },                         // ACC,
  { "Block Move" },                          // BLK_MOV,
  { "Direct Page" },                         // DP,
  { "Direct Page Indexed X" },               // DP_IX,
  { "Direct Page Indexed Y" },               // DP_IY,
  { "Direct Page Indexed X Indirect" },      // DP_IX_INDIR,
  { "Direct Page Indirect" },                // DP_INDIR,
  { "Direct Page Indirect Long" },           // DP_INDIR_LONG,
  { "Direct Page Indirect Indexed Y" },      // DP_INDIR_IY,
  { "Direct Page Indirect Long Indexed Y" }, // DP_INDIR_LONG_IY,
  { "Immediate" },                           // IMM,
  { "Implied" },                             // IMPLIED,
  { "Program Counter Relative" },            // PC_REL,
  { "Program Counter Relative Long" },       // PC_REL_LONG,
  { "Stack Absolute" },                      // STACK_ABS,
  { "Stack Direct Page Indirect" },          // STACK_DP_INDIR,
  { "Stack Interrupt" },                     // STACK_INT,
  { "Stack Program Counter Relative" },      // STACK_PC_REL,
  { "Stack Pull" },                          // STACK_PULL,
  { "Stack Push" },                          // STACK_PUSH,
  { "Stack RTI" },                           // STACK_RTI,
  { "Stack RTL" },                           // STACK_RTL,
  { "Stack RTS" },                           // STACK_RTS,
  { "Stack REL" },                           // STACK_REL,
  { "Stack Relative Indirect Indexed Y" }    // STACK_REL_INDIR_IY,
};

CASSERT(qnumber(AddressingModes) == ADDRMODE_last);
