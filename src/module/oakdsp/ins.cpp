
#include "oakdsp.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               }, // Unknown Operation
  { "",           0                               }, // cmd need further process
  // ALU-ALM subcodes
  { "or",         CF_USE1|CF_USE2|CF_CHG2         }, // 000  Logical Or
  { "and",        CF_USE1|CF_USE2|CF_CHG2         }, // 001  And
  { "xor",        CF_USE1|CF_USE2|CF_CHG2         }, // 010  Exclusive Or
  { "add",        CF_USE1|CF_USE2|CF_CHG2         }, // 011  Add
  { "tst0",       CF_USE1|CF_USE2                 }, // 100  Test Bit-field for Zeros
  { "tst1",       CF_USE1|CF_USE2                 }, // 101  Test Bit-field for Ones
  { "cmp",        CF_USE1|CF_USE2                 }, // 110  Compare
  { "sub",        CF_USE1|CF_USE2|CF_CHG2         }, // 111  Subtract
  // ALM subcodes
  { "msu",        CF_USE1|CF_USE2|CF_CHG2         }, // 1000  Multiply and Subtract Previous Product
  { "addh",       CF_USE1|CF_USE2|CF_CHG2         }, // 1001  Add to High Accumulator
  { "addl",       CF_USE1|CF_USE2|CF_CHG2         }, // 1010  Add to Low Accumulator
  { "subh",       CF_USE1|CF_USE2|CF_CHG2         }, // 1011  Subtract from High Accumulator
  { "subl",       CF_USE1|CF_USE2|CF_CHG2         }, // 1100  Subtract from Low Accumulator
  { "sqr",        CF_USE1|CF_USE2|CF_CHG2         }, // 1101  Square
  { "sqra",       CF_USE1|CF_USE2|CF_CHG2         }, // 1110  Square and Accumulate Previous Product
  { "cmpu",       CF_USE1|CF_USE2                 }, // 1111  Compare Unsigned
  // MODA-MODB subcodes conditional
  { "shr",        CF_USE1|CF_CHG1                 }, // 000  Shift Accumulator Right
  { "shr4",       CF_USE1|CF_CHG1                 }, // 001  Shift Accumulator Right by 4 Bits
  { "shl",        CF_USE1|CF_CHG1                 }, // 010  Shift Accumulator Left
  { "shl4",       CF_USE1|CF_CHG1                 }, // 011  Shift Accumulator Left by 4 Bits
  { "ror",        CF_USE1|CF_CHG1                 }, // 100  Rotate Accumulator Right through Carry
  { "rol",        CF_USE1|CF_CHG1                 }, // 101  Rotate Accumulator Left through Carry
  { "clr",        CF_CHG1                         }, // 110  Clear Accumulator
  { "",           0                               }, // 111  Mod Reserved
  // MODA subcodes conditional
  { "not",        CF_USE1|CF_CHG1                 }, // 1000  Logical Not
  { "neg",        CF_USE1|CF_CHG1                 }, // 1001  2's Complement of aX-accumulator
  { "rnd",        CF_USE1|CF_CHG1                 }, // 1010  Round Upper 20 Bits of aX-accumulator
  { "pacr",       CF_USE1|CF_CHG1                 }, // 1011  Product Move and Round to aX-accumulator
  { "clrr",       CF_USE1|CF_CHG1                 }, // 1100  Clear and Round aX-accumulator
  { "inc",        CF_USE1|CF_CHG1                 }, // 1101  Increment Accumulator by One
  { "dec",        CF_USE1|CF_CHG1                 }, // 1110  Decrement aX-accumulator by One
  { "copy",       CF_USE1|CF_CHG1                 }, // 1111  Copy aX-accumulator
  // ---
  { "norm",       CF_USE1|CF_CHG1|CF_USE2         }, // Normalize
  { "divs",       CF_USE1|CF_USE2|CF_CHG2         }, // Division Step
  // ALB subcodes
  { "set",        CF_USE1|CF_USE2|CF_CHG2         }, // 000  Set Bit-field
  { "rst",        CF_USE1|CF_USE2|CF_CHG2         }, // 001  Reset Bit-field
  { "chng",       CF_USE1|CF_USE2|CF_CHG2         }, // 010  Change Bit-field
  { "addv",       CF_USE1|CF_USE2|CF_CHG2         }, // 011  Add Long Immediate Value or Data Memory Location
  { "tst0",       CF_USE1|CF_USE2                 }, // 100  Test Bit-field for Zeros
  { "tst1",       CF_USE1|CF_USE2                 }, // 101  Test Bit-field for Ones
  { "cmpv",       CF_USE1|CF_USE2                 }, // 110  Compare Long Immediate Value to Register or Data Memory Location
  { "subv",       CF_USE1|CF_USE2|CF_CHG2         }, // 111  Subtract Long Immediate Value from a Register or a Data Memory Location
  // ---
  { "maxd",       CF_USE1|CF_CHG1|CF_USE2         }, // Maximum between Data Memory Location and Accumulator
  { "max",        CF_USE1|CF_CHG1|CF_USE2         }, // Maximum between Two Accumulators
  { "min",        CF_USE1|CF_CHG1|CF_USE2         }, // Minimum between Two Accumulators
  { "lim",        CF_USE1|CF_CHG1|CF_USE2         }, // Limit Accumulator     (lim aX[, aX])
  // MUL subcodes
  { "mpy",        CF_USE1|CF_USE2                 }, // 000  Multiply
  { "mpysu",      CF_USE1|CF_USE2                 }, // 001  Multiply Signed by Unsigned
  { "mac",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 010  Multiply and Accumulate Previous Product
  { "macus",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 011  Multiply Unsigned by Signed and Accumulate Previous Product
  { "maa",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 100  Multiply and Accumulate Aligned Previous Product
  { "macuu",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 101  Multiply Unsigned by Unsigned and Accumulate Previous Product
  { "macsu",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 110  Multiply Signed by Unsigned and Accumulate Previous Product
  { "maasu",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // 111  Multiply Signed by Unsigned and Accumulate Aligned Previous Product
  //---
  { "mpyi",       CF_USE1|CF_USE2                 }, // Multiply Signed Short Immediate
  { "msu",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 }, // Multiply and Subtract Previous Product
  { "tstb",       CF_USE1|CF_USE2                 }, // Test Specific Bit
  { "shfc",       CF_USE1|CF_USE2|CF_CHG2         }, // Shift Accumulators according to Shift Value Register
  { "shfi",       CF_USE1|CF_USE2|CF_CHG2|CF_USE3 }, // Shift Accumulators by an Immediate Shift Value
  { "exp",        CF_USE1|CF_USE2|CF_CHG2         }, // Evaluate the Exponent Value
  //---
  { "mov",        CF_USE1|CF_CHG2                 }, // Move Data
  { "movp",       CF_USE1|CF_CHG2                 }, // Move from Program Memory into Data Memory
  { "movs",       CF_USE1|CF_CHG2                 }, // Move and Shift According to Shift Value Register
  { "movsi",      CF_USE1|CF_USE2|CF_CHG2|CF_USE3 }, // Move and Shift According to an Immediate Shift Value
  { "movr",       CF_USE1|CF_CHG2                 }, // Move and Round
  { "movd",       CF_USE1|CF_CHG2                 }, // Move from Data Memory into Program Memory
  //---
  { "push",       CF_USE1                         }, // Push Register or Long Immediate Value onto Stack
  { "pop",        CF_USE1|CF_CHG1                 }, // Pop from Stack into Register
  //---
  { "swap",       CF_USE1                         }, // Swap aX- and bX-accumulators
  { "banke",      CF_USE1                         }, // Bank Exchange
  { "rep",        CF_USE1                         }, // Repeat Next Instruction
  { "bkrep",      CF_USE1|CF_USE2                 }, // Block-Repeat
  { "break",      0                               }, // Break from Block-repeat
  //---
  { "br",         CF_USE1|CF_JUMP                 }, // Conditional Branch
  { "brr",        CF_USE1|CF_JUMP                 }, // Relative Conditional Branch
  { "br",         CF_USE1|CF_STOP|CF_JUMP         }, // UnConditional Branch
  { "brr",        CF_USE1|CF_STOP|CF_JUMP         }, // Relative UnConditional Branch
  { "call",       CF_USE1|CF_CALL                 }, // Conditional Call Subroutine
  { "callr",      CF_USE1|CF_CALL                 }, // Relative Conditional Call Subroutine
  { "calla",      CF_USE1                         }, // Call Subroutine at Location Specified by Accumulator
  //---
  { "ret",        0                               }, // Return Conditionally
  { "ret",        CF_STOP                         }, // Return UnConditionally
  { "retd",       0                               }, // Delayed Return
  { "reti",       0                               }, // Return from Interrupt Conditionally
  { "reti",       CF_STOP                         }, // Return from Interrupt UnConditionally
  { "retid",      0                               }, // Delayed Return from Interrupt
  { "rets",       CF_USE1|CF_STOP                 }, // Return with Short Immediate Parameter
  //---
  { "cntx",       CF_USE1                         }, // Context Switching Store or Restore
  { "nop",        0                               }, // No operation
  { "modr",       CF_USE1|CF_USE2                 }, // Modify rN
  { "dint",       0                               }, // Disable Interrupt
  { "eint",       0                               }, // Enable Interrupt
  //---
  { "trap",       CF_STOP                         }, // Software Interrupt
  //---
  { "lpg",        CF_USE1                         }, // Load the Page Bits
  { "load",       CF_USE1|CF_CHG2                 }, // Load Specific Fields into Registers
  { "mov",        CF_USE1|CF_CHG2|CF_USE3         }, // Move Data, eu
};

CASSERT(qnumber(Instructions) == OAK_Dsp_last);
