
#include "st9.hpp"

const instruc_t Instructions[] =
{
  { "",           0                           },        // Null instruction.
  { "ld",         CF_CHG1|CF_USE2             },        // Load.
  { "ldw",        CF_CHG1|CF_USE2             },        // Load word.
  { "ldpp",       CF_CHG1|CF_USE2             },        // Load (using CSR) => (using CSR).
  { "ldpd",       CF_CHG1|CF_USE2             },        // Load (using DPRx) => (using CSR).
  { "lddp",       CF_CHG1|CF_USE2             },        // Load (using CSR) => (using DPRx).
  { "lddd",       CF_CHG1|CF_USE2             },        // Load (using DPRx) => (using DPRx).
  { "add",        CF_CHG1|CF_USE2             },        // Add.
  { "addw",       CF_CHG1|CF_USE2             },        // Add Word.
  { "adc",        CF_CHG1|CF_USE2             },        // Add with Carry.
  { "adcw",       CF_CHG1|CF_USE2             },        // Add Word with Carry.
  { "sub",        CF_CHG1|CF_USE2             },        // Substract.
  { "subw",       CF_CHG1|CF_USE2             },        // Substract Word.
  { "sbc",        CF_CHG1|CF_USE2             },        // Substract with Carry.
  { "sbcw",       CF_CHG1|CF_USE2             },        // Substract Word with Carry.
  { "and",        CF_CHG1|CF_USE2             },        // Logical AND.
  { "andw",       CF_CHG1|CF_USE2             },        // Logical Word AND.
  { "or",         CF_CHG1|CF_USE2             },        // Logical OR.
  { "orw",        CF_CHG1|CF_USE2             },        // Logical Word OR.
  { "xor",        CF_CHG1|CF_USE2             },        // Logical Exclusive OR.
  { "xorw",       CF_CHG1|CF_USE2             },        // Logical Word Exclusive OR.
  { "cp",         CF_USE1|CF_USE2             },        // Compare.
  { "cpw",        CF_USE1|CF_USE2             },        // Compare Word.
  { "tm",         CF_USE1|CF_USE2             },        // Test under Mask.
  { "tmw",        CF_USE1|CF_USE2             },        // Test Word under Mask.
  { "tcm",        CF_USE1|CF_USE2             },        // Test Complement under Mask.
  { "tcmw",       CF_USE1|CF_USE2             },        // Test Word Complement under Mask.
  { "inc",        CF_USE1|CF_CHG1             },        // Increment.
  { "incw",       CF_USE1|CF_CHG1             },        // Increment Word.
  { "dec",        CF_USE1|CF_CHG1             },        // Decrement.
  { "decw",       CF_USE1|CF_CHG1             },        // Decrement Word.
  { "sla",        CF_USE1|CF_CHG1             },        // Shift Left Arithmetic.
  { "slaw",       CF_USE1|CF_CHG1             },        // Shift Word Left Arithmetic.
  { "sra",        CF_USE1|CF_CHG1             },        // Shift Right Arithmetic.
  { "sraw",       CF_USE1|CF_CHG1             },        // Shift Word Right Arithmetic.
  { "rrc",        CF_USE1|CF_CHG1             },        // Rotate Right through Carry.
  { "rrcw",       CF_USE1|CF_CHG1             },        // Rotate Word Right through Carry.
  { "rlc",        CF_USE1|CF_CHG1             },        // Rotate Left through Carry.
  { "rlcw",       CF_USE1|CF_CHG1             },        // Rotate Word Left through Carry.
  { "ror",        CF_USE1|CF_CHG1             },        // Rotate Right.
  { "rol",        CF_USE1|CF_CHG1             },        // Rotate Left.
  { "clr",        CF_USE1|CF_CHG1             },        // Clear Register.
  { "cpl",        CF_USE1|CF_CHG1             },        // Complement Register.
  { "swap",       CF_USE1|CF_CHG1             },        // Swap Nibbles.
  { "da",         CF_USE1|CF_CHG1             },        // Decimal ajust.
  { "push",       CF_USE1                     },        // Push on System Stack.
  { "pushw",      CF_USE1                     },        // Push Word on System Stack.
  { "pea",        CF_USE1                     },        // Push Effective Address on System Stack.
  { "pop",        CF_CHG1                     },        // Pop from System Stack.
  { "popw",       CF_CHG1                     },        // Pop Word from System Stack.
  { "pushu",      CF_USE1                     },        // Push on User Stack.
  { "pushuw",     CF_USE1                     },        // Push Word on User Stack.
  { "peau",       CF_USE1                     },        // Push Effective Address on User Stack.
  { "popu",       CF_CHG1                     },        // Pop from User Stack.
  { "popuw",      CF_CHG1                     },        // Pop Word from User Stack.
  { "link",       CF_USE1|CF_USE2             },        // Move System Stack Pointer upward; support for high-level language.
  { "unlink",     CF_USE1|CF_USE2             },        // Move System Stack Pointer backward; support for high-level language.
  { "linku",      CF_USE1|CF_USE2             },        // Move User Stack Pointer upward; support for high-level language.
  { "unlinku",    CF_USE1|CF_USE2             },        // Move User Stack Pointer backward; support for high-level language.
  { "mul",        CF_USE1|CF_USE2|CF_CHG1     },        // Multiply 8x8.
  { "div",        CF_USE1|CF_USE2|CF_CHG1     },        // Divide 8x8.
  { "divws",      CF_USE1|CF_USE2|CF_USE3|CF_CHG1|CF_CHG2     },        // Divide Word Stepped 32/16.
  { "bset",       CF_USE1|CF_CHG1             },        // Bit Set.
  { "bres",       CF_USE1|CF_CHG1             },        // Bit Reset.
  { "bcpl",       CF_USE1|CF_CHG1             },        // Bit Complement.
  { "btset",      CF_USE1|CF_CHG1             },        // Bit Test and Set.
  { "bld",        CF_USE1|CF_CHG1             },        // Bit Load.
  { "band",       CF_USE1|CF_CHG1             },        // Bit AND.
  { "bor",        CF_USE1|CF_CHG1             },        // Bit OR.
  { "bxor",       CF_USE1|CF_CHG1             },        // Bit XOR.
  { "ret",        CF_STOP                     },        // Return from Subroutine.
  { "rets",       CF_STOP                     },        // Inter-segment Return to Subroutine.
  { "iret",       CF_STOP                     },        // Return from Interrupt.
  { "jr",         CF_USE1                     },        // Jump Relative if Condition ``cc'' is Met.
  { "jp",         CF_USE1                     },        // Jump if Condition ``cc'' is Met.
  { "jp",         CF_USE1|CF_JUMP|CF_STOP     },        // Unconditional Jump.
  { "jps",        CF_USE1|CF_JUMP|CF_STOP     },        // Unconditional Inter-segment Jump.
  { "call",       CF_USE1|CF_CALL|CF_JUMP     },        // Unconditional Call.
  { "calls",      CF_USE1|CF_CALL|CF_JUMP     },        // Inter-segment Call to Subroutine.
  { "btjf",       CF_USE1|CF_USE2             },        // Bit Test and Jump if False.
  { "btjt",       CF_USE1|CF_USE2             },        // Bit Test and Jump if True.
  { "djnz",       CF_USE1|CF_CHG1|CF_USE2     },        // Decrement a Working Register and Jump if Non Zero.
  { "dwjnz",      CF_USE1|CF_CHG1|CF_USE2     },        // Decrement a Register Pair and Jump if Non Zero.
  { "cpjfi",      CF_USE1|CF_USE2|CF_USE3     },        // Compare and Jump on False.  Otherwise Post Increment.
  { "cpjti",      CF_USE1|CF_USE2|CF_USE3     },        // Compare and Jump on True.  Otherwise Post Increment.
  { "xch",        CF_USE1|CF_USE2             },        // Exchange Registers.
  { "srp",        CF_USE1                     },        // Set Register Pointer Long (16 working registers).
  { "srp0",       CF_USE1                     },        // Set Register Pointer 0 (8 LSB working registers).
  { "srp1",       CF_USE1                     },        // Set Register Pointer 1 (8 MSB working registers).
  { "spp",        CF_USE1                     },        // Set Page Pointer.
  { "ext",        CF_USE1|CF_CHG1             },        // Sign Extend.
  { "ei",         0                           },        // Enable Interrupts.
  { "di",         0                           },        // Disable Interrupts.
  { "scf",        0                           },        // Set Carry Flag.
  { "rcf",        0                           },        // Reset Carry Flag.
  { "ccf",        0                           },        // Complement Carry Flag.
  { "spm",        0                           },        // Select Extended Memory addressing scheme through CSR Register.
  { "sdm",        0                           },        // Select Extended Memory addressing scheme through DPR Registers.
  { "nop",        0                           },        // No Operation.
  { "wfi",        0                           },        // Stop Program Execution and Wait for the next Enable Interrupt.
  { "halt",       0                           },        // Stop Program Execution until System Reset.
  { "etrap",      0                           },        // Undocumented instruction.
  { "eret",       CF_STOP                     },        // Undocumented instruction.
  { "ald",        0                           },        // PSEUDO INSTRUCTION.  SHOULD NEVER BE USED.
  { "aldw",       0                           }         // PSEUDO INSTRUCTION.  SHOULD NEVER BE USED.
};

CASSERT(qnumber(Instructions) == st9_last);
