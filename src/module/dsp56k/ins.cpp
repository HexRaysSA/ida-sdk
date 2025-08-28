
#include "dsp56k.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  { "abs",        CF_USE1|CF_CHG1                 },      // Absolute Value
  { "adc",        CF_USE1|CF_USE2|CF_CHG2         },      // Add Long with Carry
  { "add",        CF_USE1|CF_USE2|CF_CHG2         },      // Addition
  { "addl",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift Left and Add
  { "addr",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift Right and Add
  { "and",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical AND
  { "andi",       CF_USE1|CF_USE2|CF_CHG2         },      // AND Immediate to Control Register
  { "asl",        CF_USE1|CF_CHG1                 },      // Arithmetic Shift Left
  { "asl4",       CF_USE1|CF_CHG1                 },      // Arithmetic Shift Left
  { "asr",        CF_USE1|CF_CHG1                 },      // Arithmetic Shift Right
  { "asr4",       CF_USE1|CF_CHG1                 },      // Arithmetic Shift Right
  { "asr16",      CF_USE1|CF_CHG1                 },      // Arithmetic Shift Right
  { "bfchg",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Change
  { "bfclr",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Clear
  { "bfset",      CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Set
  { "bftsth",     CF_USE1|CF_USE2|CF_CHG2         },      // Test Bit Field High
  { "bftstl",     CF_USE1|CF_USE2|CF_CHG2         },      // Test Bit Field Low
  { "b",          CF_USE1|CF_JUMP                 },      // Branch Conditionally
  { "bchg",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Change
  { "bclr",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Clear
  { "bra",        CF_USE1|CF_STOP|CF_JUMP         },      // Branch Always
  { "brclr",      CF_USE1|CF_USE2|CF_USE3|CF_JUMP },      // Branch if Bit Clear
  { "brk",        CF_USE1                         },      // Exit Current DO Loop Conditionally
  { "brset",      CF_USE1|CF_USE2|CF_USE3|CF_JUMP },      // Branch if Bit Set
  { "bs",         CF_USE1|CF_CALL                 },      // Branch to Subroutine Conditionally
  { "bsclr",      CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Branch to Subroutine if Bit Clear
  { "bset",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test and Set
  { "bsr",        CF_USE1|CF_CALL                 },      // Branch to Subroutine
  { "bsset",      CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Branch to Subroutine if Bit Set
  { "btst",       CF_USE1|CF_USE2|CF_CHG2         },      // Bit Test on Memory and Registers
  { "chkaau",     0                               },      // Check address ALU result
  { "clb",        CF_USE1|CF_CHG2                 },      // Count Leading Bits
  { "clr",        CF_USE1|CF_CHG1                 },      // Clear an Operand
  { "clr24",      CF_USE1|CF_CHG1                 },      // Clear 24 MS-bits of Accumulator
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare
  { "cmpm",       CF_USE1|CF_USE2                 },      // Compare Magnitude
  { "cmpu",       CF_USE1|CF_USE2                 },      // Compare Unsigned
  { "debug",      0                               },      // Enter Debug Mode
  { "debug",      0                               },      // Enter Debug Mode Conditionally
  { "dec",        CF_USE1|CF_CHG1                 },      // Decrement by One
  { "dec24",      CF_USE1|CF_CHG1                 },      // Decrement 24 MS-bit of Accumulator
  { "div",        CF_USE1|CF_USE2|CF_CHG2         },      // Divide Iteration
  { "dmac",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Double-Precision Multiply-Accumulate With Right Shift
  { "do",         CF_USE1|CF_USE2|CF_JUMP         },      // Start Hardware Loop
  { "do forever,",        CF_USE1|CF_JUMP         },      // Start Infinite Loop
  { "dor",        CF_USE1|CF_USE2|CF_JUMP         },      // Start PC-Relative Hardware Loop
  { "dor forever,",       CF_USE1|CF_JUMP         },      // Start PC-Relative Infinite Loop
  { "enddo",      0                               },      // Exit from Hardware Loop
  { "eor",        CF_USE1|CF_USE2|CF_CHG2         },      // Logical Exclusive OR
  { "extract",    CF_USE1|CF_USE2|CF_CHG3         },      // Extract Bit Field
  { "extractu",   CF_USE1|CF_USE2|CF_CHG3         },      // Extract Unsigned Bit Field
  { "ext",        CF_USE1|CF_CHG1                 },      // Sign Extend Accumulator
  { "illegal",    0                               },      // Illegal Instruction
  { "imac",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Integer Multiply-Accumulate
  { "impy",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Integer Multiply
  { "inc",        CF_USE1|CF_CHG1                 },      // Increment by One
  { "inc24",      CF_USE1|CF_CHG1                 },      // Increment 24 MS-bit of Accumulator
  { "insert",     CF_USE1|CF_USE2|CF_CHG3         },      // Insert Bit Field
  { "j",          CF_USE1|CF_JUMP                 },      // Jump Conditionally
  { "jclr",       CF_USE1|CF_USE2|CF_USE3|CF_JUMP },      // Jump if Bit Clear
  { "jmp",        CF_USE1|CF_STOP|CF_JUMP         },      // Jump
  { "js",         CF_USE1|CF_CALL                 },      // Jump to Subroutine Conditionally
  { "jsclr",      CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Jump to Subroutine if Bit Clear
  { "jset",       CF_USE1|CF_USE2|CF_USE3|CF_JUMP },      // Jump if Bit Set
  { "jsr",        CF_USE1|CF_CALL                 },      // Jump to Subroutine
  { "jsset",      CF_USE1|CF_USE2|CF_USE3|CF_CALL },      // Jump to Subroutine if Bit Set
  { "lra",        CF_USE1|CF_CHG2                 },      // Load PC-Reliative Address
  { "lsl",        CF_USE1|CF_CHG1                 },      // Logical Shift Left
  { "lsr",        CF_USE1|CF_CHG1                 },      // Logical Shift Right
  { "lua",        CF_USE1|CF_CHG2                 },      // Load Updated Address
  { "lea",        CF_USE1|CF_CHG2                 },      // Load Updated Address
  { "mac",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply-Accumulate
  { "maci",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply-Accumulate With Immediate Operand
  { "mac",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Mixed Multiply-Accumulate
  { "macr",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply-Accumulate and Round
  { "macri",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply-Accumulate and Round With Immediate Operand
  { "max",        CF_USE1|CF_USE2|CF_CHG2         },      // Transfer by Signed Value
  { "maxm",       CF_USE1|CF_USE2|CF_CHG2         },      // Transfer by Magnitude
  { "merge",      CF_USE1|CF_USE2|CF_CHG2         },      // Merge Two Half Words
  { "move",       CF_USE1|CF_CHG2                 },      // Move Data Register
  { "movec",      CF_USE1|CF_CHG2                 },      // Move Control Register
  { "movei",      CF_USE1|CF_CHG2                 },      // Move Immediate Short
  { "movem",      CF_USE1|CF_CHG2                 },      // Move Program Memory
  { "movep",      CF_USE1|CF_CHG2                 },      // Move Peripheral Data
  { "moves",      CF_USE1|CF_CHG2                 },      // Move Absolute Short
  { "mpy",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply
  { "mpyi",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply With Immediate Operand
  { "mpy",        CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Mixed Multiply
  { "mpyr",       CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply and Round
  { "mpyri",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },      // Signed Multiply and Round With Immediate Operand
  { "neg",        CF_USE1|CF_CHG1                 },      // Negate Accumulator
  { "negc",       CF_USE1|CF_CHG1                 },      // Negate Accumulator
  { "nop",        0                               },      // No Operation
  { "norm",       CF_USE1|CF_USE2|CF_CHG2         },      // Norm Accumulator Iteration
  { "normf",      CF_USE1|CF_USE2|CF_CHG2         },      // Fast Accumulator Normalization
  { "not",        CF_USE1|CF_CHG1                 },      // Logical Complement
  { "or",         CF_USE1|CF_USE2|CF_CHG2         },      // Logical Inclusive OR
  { "ori",        CF_USE1|CF_USE2|CF_CHG2         },      // OR Immediate to Control Register
  { "pflush",     0                               },      // Program Cache Flush
  { "pflushun",   0                               },      // Program Cache Flush Unlocked Sectors
  { "pfree",      0                               },      // Program Cache Global Unlock
  { "plock",      0                               },      // Lock Instruction Cache Sector
  { "plockr",     0                               },      // Lock Instruction Cache Relative Sector
  { "punlock",    0                               },      // Unlock Instruction Cache Sector
  { "punlockr",   0                               },      // Unlock Instruction Cache Relative Sector
  { "rep",        CF_USE1                         },      // Repeat Next Instruction
  { "rep",        CF_USE1                         },      // Repeat Next Instruction
  { "reset",      0                               },      // Reset On-Chip Peripheral Devices
  { "rnd",        CF_USE1|CF_CHG1                 },      // Round
  { "rol",        CF_USE1|CF_CHG1                 },      // Rotate Left
  { "ror",        CF_USE1|CF_CHG1                 },      // Rotate Right
  { "rti",        CF_STOP                         },      // Return from Interrupt
  { "rts",        CF_STOP                         },      // Return from Subroutine
  { "sbc",        CF_USE1|CF_USE2|CF_CHG2         },      // Subtract Long with Carry
  { "stop",       CF_STOP                         },      // Stop Processing (Low-Power Standby)
  { "sub",        CF_USE1|CF_USE2|CF_CHG2         },      // Subtract
  { "subl",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift Left and Subtract
  { "subr",       CF_USE1|CF_USE2|CF_CHG2         },      // Shift Right and Subtract
  { "swap",       CF_USE1|CF_CHG1                 },      // Swap Accumulator Words
  { "t",          CF_USE1|CF_USE2                 },      // Transfer Conditionally
  { "tfr",        CF_USE1|CF_USE2                 },      // Transfer Data ALU Register
  { "tfr2",       CF_USE1|CF_USE2|CF_CHG2         },      // Transfer Data ALU Register
  { "tfr3",       CF_USE1|CF_USE2|CF_CHG2         },      // Transfer Data ALU Register
  { "trap",       0                               },      // Software Interrupt
  { "trap",       0                               },      // Software Interrupt Conditionally
  { "tst",        CF_USE1                         },      // Test an Operand
  { "tst2",       CF_USE1                         },      // Test an Operand
  { "vsl",        CF_USE1|CF_USE2|CF_CHG3         },      // Viterbi Shift Left
  { "wait",       0                               },      // Wait for Interrupt or DMA Request (Low-Power Standby)
  { "zero",       0                               },      // Zero Extend Accumulator
  { "swi",        0                               },      // Software Interrupt
  { "pmov",       0                               },      // Pseudo insn

};

CASSERT(qnumber(Instructions) == DSP56_last);
