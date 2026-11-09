/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "arc.hpp"

instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation
  { "ld",         CF_CHG1|CF_USE2                 },      // Load
  { "lr",         CF_CHG1|CF_USE2                 },      // Load from auxiliary register
  { "st",         CF_USE1|CF_CHG2                 },      // Store
  { "sr",         CF_USE1|CF_USE2|CF_CHG2         },      // Store to auxiliary register
  { "flag",       CF_USE1                         },      // Set flags
  { "asr",        CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift right
  { "lsr",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical shift right
  { "sexb",       CF_CHG1|CF_USE2                 },      // Sign extend byte
  { "sexw",       CF_CHG1|CF_USE2                 },      // Sign extend word
  { "extb",       CF_CHG1|CF_USE2                 },      // Zero extend byte
  { "extw",       CF_CHG1|CF_USE2                 },      // Zero extend word
  { "ror",        CF_CHG1|CF_USE2|CF_USE3         },      // Rotate right
  { "rrc",        CF_CHG1|CF_USE2                 },      // Rotate right through carry
  { "b",          CF_USE1|CF_JUMP                 },      // Branch
  { "bl",         CF_USE1|CF_CALL                 },      // Branch and link
  { "lp",         CF_USE1                         },      // Zero-overhead loop setup
  { "j",          CF_USE1|CF_JUMP                 },      // Jump
  { "jl",         CF_USE1|CF_CALL                 },      // Jump and link
  { "add",        CF_CHG1|CF_USE2|CF_USE3         },      // Add
  { "adc",        CF_CHG1|CF_USE2|CF_USE3         },      // Add with carry
  { "sub",        CF_CHG1|CF_USE2|CF_USE3         },      // Subtract
  { "sbc",        CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with carry
  { "and",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise AND
  { "or",         CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise OR
  { "bic",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise AND with invert
  { "xor",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical bitwise exclusive-OR
  { "mov",        CF_CHG1|CF_USE2                 },      // Move
  { "nop",        0                               },      // No operation
  { "lsl",        CF_CHG1|CF_USE2|CF_USE3         },      // Logical shift left
  { "rlc",        CF_CHG1|CF_USE2                 },      // Rotate left through carry
  { "brk",        0                               },      // Breakpoint
  { "sleep",      0                               },      // Sleep until interrupt or restart
  { "swi",        0                               },      // Software interrupt
  { "asl",        CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift left
  { "mul64",      CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply
  { "mulu64",     CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply
  { "max",        CF_CHG1|CF_USE2|CF_USE3         },      // Maximum of two signed integers
  { "min",        CF_CHG1|CF_USE2|CF_USE3         },      // Minimum of two signed integers
  { "swap",       CF_CHG1|CF_USE2                 },      // Exchange upper and lower 16 bits
  { "norm",       CF_CHG1|CF_USE2                 },      // Normalize (find-first-bit)

  // ARCompact instructions
  { "bbit0",      CF_USE1|CF_USE2|CF_USE3         },      // Branch if bit cleared to 0
  { "bbit1",      CF_USE1|CF_USE2|CF_USE3         },      // Branch if bit set to 1
  { "br",         CF_USE1|CF_USE2|CF_USE3         },      // Branch on compare
  { "pop",        CF_CHG1                         },      // Restore register value from stack
  { "push",       CF_USE1                         },      // Store register value on stack

  { "abs",        CF_CHG1|CF_USE2                 },      // Absolute value
  { "add1",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 1 bit
  { "add2",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 2 bits
  { "add3",       CF_CHG1|CF_USE2|CF_USE3         },      // Add with left shift by 3 bits
  { "bclr",       CF_CHG1|CF_USE2|CF_USE3         },      // Clear specified bit (to 0)
  { "bmsk",       CF_CHG1|CF_USE2|CF_USE3         },      // Bit Mask
  { "bset",       CF_CHG1|CF_USE2|CF_USE3         },      // Set specified bit (to 1)
  { "btst",       CF_USE1|CF_USE2                 },      // Test value of specified bit
  { "bxor",       CF_CHG1|CF_USE2|CF_USE3         },      // Bit XOR
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare
  { "ex",         CF_CHG1|CF_USE2                 },      // Atomic Exchange
  { "mpy",        CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply (low)
  { "mpyh",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply (high)
  { "mpyhu",      CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply (high)
  { "mpyu",       CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply (low)
  { "neg",        CF_CHG1|CF_USE2                 },      // Negate
  { "not",        CF_CHG1|CF_USE2                 },      // Logical bit inversion
  { "rcmp",       CF_USE1|CF_USE2                 },      // Reverse Compare
  { "rsub",       CF_CHG1|CF_USE2|CF_USE3         },      // Reverse Subtraction
  { "rtie",       0                               },      // Return from Interrupt/Exception
  { "sub1",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 1 bit
  { "sub2",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 2 bits
  { "sub3",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract with left shift by 3 bits
  { "sync",       0                               },      // Synchronize
  { "trap",       CF_USE1                         },      // Raise an exception
  { "tst",        CF_USE1|CF_USE2                 },      // Test
  { "unimp",      0                               },      // Unimplemented instruction

  { "abss",       CF_CHG1|CF_USE2                 },      // Absolute and saturate
  { "abssw",      CF_CHG1|CF_USE2                 },      // Absolute and saturate of word
  { "adds",       CF_CHG1|CF_USE2|CF_USE3         },      // Add and saturate
  { "addsdw",     CF_CHG1|CF_USE2|CF_USE3         },      // Add and saturate dual word
  { "asls",       CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift left and saturate
  { "asrs",       CF_CHG1|CF_USE2|CF_USE3         },      // Arithmetic shift right and saturate
  { "divaw",      CF_CHG1|CF_USE2|CF_USE3         },      // Division assist
  { "negs",       CF_CHG1|CF_USE2                 },      // Negate and saturate
  { "negsw",      CF_CHG1|CF_USE2                 },      // Negate and saturate of word
  { "normw",      CF_CHG1|CF_USE2                 },      // Normalize to 16 bits
  { "rnd16",      CF_CHG1|CF_USE2                 },      // Round to word
  { "sat16",      CF_CHG1|CF_USE2                 },      // Saturate to word
  { "subs",       CF_CHG1|CF_USE2|CF_USE3         },      // Subtract and saturate
  { "subsdw",     CF_CHG1|CF_USE2|CF_USE3         },      // Subtract and saturate dual word

  { "muldw",      CF_CHG1|CF_USE2|CF_USE3         },      //
  { "muludw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "mulrdw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "macdw",      CF_CHG1|CF_USE2|CF_USE3         },      //
  { "macudw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "macrdw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "msubdw",     CF_CHG1|CF_USE2|CF_USE3         },      //

  { "mululw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "mullw",      CF_CHG1|CF_USE2|CF_USE3         },      //
  { "mulflw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "maclw",      CF_CHG1|CF_USE2|CF_USE3         },      //
  { "macflw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "machulw",    CF_CHG1|CF_USE2|CF_USE3         },      //
  { "machlw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "machflw",    CF_CHG1|CF_USE2|CF_USE3         },      //
  { "mulhlw",     CF_CHG1|CF_USE2|CF_USE3         },      //
  { "mulhflw",    CF_CHG1|CF_USE2|CF_USE3         },      //

  // Major 6 compact insns
  { "acm", CF_CHG1|CF_USE2|CF_USE3 },
  { "addqbs", CF_CHG1|CF_USE2|CF_USE3 },
  { "avgqb", CF_CHG1|CF_USE2|CF_USE3 },
  { "clamp", CF_CHG1|CF_USE2|CF_USE3 },
  { "daddh11", CF_CHG1|CF_USE2|CF_USE3 },
  { "daddh12", CF_CHG1|CF_USE2|CF_USE3 },
  { "daddh21", CF_CHG1|CF_USE2|CF_USE3 },
  { "daddh22", CF_CHG1|CF_USE2|CF_USE3 },
  { "dexcl1", CF_CHG1|CF_USE2|CF_USE3 },
  { "dexcl2", CF_CHG1|CF_USE2|CF_USE3 },
  { "dmulh11", CF_CHG1|CF_USE2|CF_USE3 },
  { "dmulh12", CF_CHG1|CF_USE2|CF_USE3 },
  { "dmulh21", CF_CHG1|CF_USE2|CF_USE3 },
  { "dmulh22", CF_CHG1|CF_USE2|CF_USE3 },
  { "dsubh11", CF_CHG1|CF_USE2|CF_USE3 },
  { "dsubh12", CF_CHG1|CF_USE2|CF_USE3 },
  { "dsubh21", CF_CHG1|CF_USE2|CF_USE3 },
  { "dsubh22", CF_CHG1|CF_USE2|CF_USE3 },
  { "drsubh11", CF_CHG1|CF_USE2|CF_USE3 },
  { "drsubh12", CF_CHG1|CF_USE2|CF_USE3 },
  { "drsubh21", CF_CHG1|CF_USE2|CF_USE3 },
  { "drsubh22", CF_CHG1|CF_USE2|CF_USE3 },
  { "fadd", CF_CHG1|CF_USE2|CF_USE3 },
  { "fmul", CF_CHG1|CF_USE2|CF_USE3 },
  { "fsub", CF_CHG1|CF_USE2|CF_USE3 },
  { "fxtr", CF_CHG1|CF_USE2|CF_USE3 },
  { "iaddr", CF_CHG1|CF_USE2|CF_USE3 },
  { "mpyqb", CF_CHG1|CF_USE2|CF_USE3 },
  { "sfxtr", CF_CHG1|CF_USE2|CF_USE3 },
  { "pkqb", CF_CHG1|CF_USE2|CF_USE3 },
  { "upkqb", CF_CHG1|CF_USE2|CF_USE3 },
  { "xpkqb", CF_CHG1|CF_USE2|CF_USE3 },


  // ARCv2 only major 4 instructions
  { "mpyw",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 16x16 multiply
  { "mpyuw",      CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 16x16 multiply
  { "bi",         CF_USE1|CF_JUMP                 },      // Branch indexed
  { "bih",        CF_USE1|CF_JUMP                 },      // Branch indexed half-word
  { "ldi",        CF_CHG1|CF_USE2                 },      // Load indexed
  { "aex",        CF_USE1|CF_CHG1|CF_USE2|CF_CHG2 },      // Exchange with auxiliary register
  { "bmskn",      CF_CHG1|CF_USE2|CF_USE3         },      // Bit mask negated
  { "seteq",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if equal
  { "setne",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if not equal
  { "setlt",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if less than
  { "setge",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if greater or equal
  { "setlo",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if lower than
  { "seths",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if higher or same
  { "setle",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if less than or equal
  { "setgt",      CF_CHG1|CF_USE2|CF_USE3         },      // Set if greater than

  { "rol",        CF_CHG1|CF_USE2                 },      // Rotate left
  { "llock",      CF_CHG1|CF_USE2                 },      // Load locked
  { "scond",      CF_USE1|CF_CHG2                 },      // Store conditional

  { "seti",       CF_USE1                         },      // Set interrupt enable and priority level
  { "clri",       CF_CHG1                         },      // Clear and get interrupt enable and priority level

  // ARCv2 compact prolog / epilog instructions
  { "enter",      CF_USE1|CF_JUMP                 },      // Function prologue sequence
  { "leave",      CF_USE1|CF_JUMP                 },      // Function epilogue sequence

  // ARCv2 32-bit extension major 5 DOP instructions
  { "div",        CF_CHG1|CF_USE2|CF_USE3         },      // Signed integer divsion
  { "divu",       CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned integer divsion
  { "rem",        CF_CHG1|CF_USE2|CF_USE3         },      // Signed integer remainder
  { "remu",       CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned integer remainder
  { "asrsr",      CF_CHG1|CF_USE2|CF_USE3         },      // Shift right rounding and saturating
  { "valgn2h",    CF_CHG1|CF_USE2|CF_USE3         },      // Two-way 16-bit vector align
  { "setacc",     CF_USE2|CF_USE3                 },      // Set the accumulator
  { "mac",        CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32x32 multiply accumulate
  { "macu",       CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32x32 multiply accumulate
  { "dmpyh",      CF_CHG1|CF_USE2|CF_USE3         },      // Sum of dual signed 16x16 multiplication
  { "dmpyhu",     CF_CHG1|CF_USE2|CF_USE3         },      // Sum of dual unsigned 16x16 multiplication
  { "dmach",      CF_CHG1|CF_USE2|CF_USE3         },      // Dual signed 16x16 multiply accumulate
  { "dmachu",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual unsigned 16x16 multiply accumulate
  { "vadd2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit addition
  { "vadds2h",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating addition
  { "vsub2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit subtraction
  { "vsubs2h",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating subtraction
  { "vaddsub2h",  CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit addition/subtraction
  { "vaddsubs2h", CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating addition/subtraction
  { "vsubadd2h",  CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit subtraction/addition
  { "vsubadds2h", CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating subtraction/addition
  { "mpyd",       CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Signed 32x32 multiply (wide)
  { "mpydu",      CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Unsigned 32x32 multiply (wide)
  { "macd",       CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Signed 32x32 multiply accumulate (wide)
  { "macdu",      CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Unsigned 32x32 multiply accumulate (wide)
  { "vmpy2h",     CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Dual signed 16x16 multiply (wide)
  { "vmpy2hf",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating fractional multiply
  { "vmpy2hu",    CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Dual unsigned 16x16 multiply (wide)
  { "vmpy2hfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating rounded fractional multiply
  { "vmac2h",     CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Dual signed 16x16 multiply (wide)
  { "vmac2hf",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating fractional multiply
  { "vmac2hu",    CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Dual unsigned 16x16 multiply (wide)
  { "vmac2hfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating rounded fractional multiply
  { "vmpy2hwf",   CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Dual 16x16 saturating fractional multiply (wide)
  { "vasl2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit arithmetic shift left
  { "vasls2h",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating arithmetic shift left
  { "vasr2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit arithmetic shift right
  { "vasrs2h",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating arithmetic shift right
  { "vlsr2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit logical shift right
  { "vasrsr2h",   CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit saturating rounded arithmetic shift right
  { "vadd4b",     CF_CHG1|CF_USE2|CF_USE3         },      // Quad 8-bit addition
  { "vmax2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit maximum
  { "vsub4b",     CF_CHG1|CF_USE2|CF_USE3         },      // Quad 8-bit subtraction
  { "vmin2h",     CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16-bit minimum
  { "adcs",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed saturating addition with carry in
  { "sbcs",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed saturating subtraction with carry in
  { "dmpyhwf",    CF_CHG1|CF_USE2|CF_USE3         },      // Fractional saturating sum of dual 16x16 signed fractional multiply
  { "vpack2hl",   CF_CHG1|CF_USE2|CF_USE3         },      // Compose lower 16-bits
  { "vpack2hm",   CF_CHG1|CF_USE2|CF_USE3         },      // Compose upper 16-bits
  { "dmpyhf",     CF_CHG1|CF_USE2|CF_USE3         },      // Saturating sum of dual 16x16 signed fractional multiply
  { "dmpyhfr",    CF_CHG1|CF_USE2|CF_USE3         },      // Saturating rounded sum of dual 16x16 signed fractional multiply
  { "dmachf",     CF_CHG1|CF_USE2|CF_USE3         },      // Saturating sum of dual 16x16 signed fractional multiply accumulate
  { "dmachfr",    CF_CHG1|CF_USE2|CF_USE3         },      // Saturating rounded sum of dual 16x16 signed fractional multiply accumulate
  { "vperm",      CF_CHG1|CF_USE2|CF_USE3         },      // Byte permutation with zero or sign extension
  { "bspush",     CF_CHG1|CF_USE2|CF_USE3         },      // Bitstream push

  // ARCv2 32-bit extension major 5 SOP instructions
  { "swape",      CF_CHG1|CF_USE2                 },      // Swap byte ordering
  { "lsl16",      CF_CHG1|CF_USE2                 },      // Logical shift left by 16 bits
  { "lsr16",      CF_CHG1|CF_USE2                 },      // Logical shift right by 16 bits
  { "asr16",      CF_CHG1|CF_USE2                 },      // Arithmetic shift right by 16 bits
  { "asr8",       CF_CHG1|CF_USE2                 },      // Arithmetic shift right by 8 bits
  { "lsr8",       CF_CHG1|CF_USE2                 },      // Logical shift right by 8 bits
  { "lsl8",       CF_CHG1|CF_USE2                 },      // Logical shift left by 8 bits
  { "rol8",       CF_CHG1|CF_USE2                 },      // Rotate left by 8 bits
  { "ror8",       CF_CHG1|CF_USE2                 },      // Rotate right by 8 bits
  { "ffs",        CF_CHG1|CF_USE2                 },      // Find first set bit
  { "fls",        CF_CHG1|CF_USE2                 },      // Find last set bit


  { "getacc",     CF_CHG1|CF_USE2                 },      // Get accumulator
  { "normacc",    CF_CHG1|CF_USE2                 },      // Normalize accumulator
  { "satf",       CF_CHG1|CF_USE2                 },      // Saturate according to flags
  { "vpack2hbl",  CF_CHG1|CF_USE2                 },      // Pack lower bytes into lower 16 bits
  { "vpack2hbm",  CF_CHG1|CF_USE2                 },      // Pack upper bytes into upper 16 bits
  { "vpack2hblf", CF_CHG1|CF_USE2                 },      // Pack upper bytes into lower 16 bits
  { "vpack2hbmf", CF_CHG1|CF_USE2                 },      // Pack lower bytes into upper 16 bits
  { "vext2bhlf",  CF_CHG1|CF_USE2                 },      // Pack lower 2 bytes into upper byte of 16 bits each
  { "vext2bhmf",  CF_CHG1|CF_USE2                 },      // Pack upper 2 bytes into upper byte of 16 bits each
  { "vrep2hl",    CF_CHG1|CF_USE2                 },      // Repeat lower 16 bits
  { "vrep2hm",    CF_CHG1|CF_USE2                 },      // Repeat upper 16 bits
  { "vext2bhl",   CF_CHG1|CF_USE2                 },      // Pack lower 2 bytes into zero extended 16 bits
  { "vext2bhm",   CF_CHG1|CF_USE2                 },      // Pack upper 2 bytes into zero extended 16 bits
  { "vsext2bhl",  CF_CHG1|CF_USE2                 },      // Pack lower 2 bytes into sign extended 16 bits
  { "vsext2bhm",  CF_CHG1|CF_USE2                 },      // Pack upper 2 bytes into sign extended 16 bits
  { "vabs2h",     CF_CHG1|CF_USE2                 },      // Dual 16-bit absolute value
  { "vabss2h",    CF_CHG1|CF_USE2                 },      // Dual saturating 16-bit absolute value
  { "vneg2h",     CF_CHG1|CF_USE2                 },      // Dual 16-bit negation
  { "vnegs2h",    CF_CHG1|CF_USE2                 },      // Dual saturating 16-bit negation
  { "vnorm2h",    CF_CHG1|CF_USE2                 },      // Dual 16-bit normalization
  { "bspeek",     CF_CHG1|CF_USE2                 },      // Bitstream peek
  { "bspop",      CF_CHG1|CF_USE2                 },      // Bitstream pop
  { "sqrt",       CF_CHG1|CF_USE2                 },      // Integer square root
  { "sqrtf",      CF_CHG1|CF_USE2                 },      // Fractional square root

  // ARCv2 32-bit extension major 5 ZOP instructions
  { "aslacc",     CF_USE1                         },      // Arithmetic shift of accumulator
  { "aslsacc",    CF_USE1                         },      // Saturating arithmetic shift of accumulator
  { "flagacc",    CF_USE1                         },      // Copy accumulator flags to status32 register
  { "modif",      CF_USE1                         },      // Update address pointer

  // ARCv2 32-bit extension major 6 DOP instructions
  { "cmpyhnfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded unshifted multiply
  { "cmpyhfr",    CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded multiply
  { "cmpychfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded conjugated multiply
  { "vmsub2hf",   CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating fractional multiply subtract
  { "vmsub2hfr",  CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x16 saturating rounded fractional multiply subtract
  { "cmpychnfr",  CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded unshifted conjugated multiply
  { "cmachnfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded unshifted multiply accumulate
  { "cmachfr",    CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded unshifted accumulate
  { "cmacchnfr",  CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded conjugated multiply accumulate
  { "cmacchfr",   CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex saturating rounded unshifted conjugated multiply accumulate
  { "mpyf",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating multiply
  { "mpyfr",      CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating rounded multiply
  { "macf",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating multiply accumulate
  { "macfr",      CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating rounded multiply accumulate
  { "msubf",      CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating multiply subtract
  { "msubfr",     CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional saturating rounded multiply subtract
  { "divf",       CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32-bit fractional division
  { "vmac2hnfr",  CF_CHG1|CF_USE2|CF_USE3         },      // Dual signed 16-bit fractional saturating rounded multiply accumulate
  { "vmsub2hnfr", CF_CHG1|CF_USE2|CF_USE3         },      // Dual signed 16-bit fractional saturating rounded multiply subtract
  { "mpydf",      CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Signed 32-bit fractional multiply (wide)
  { "macdf",      CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Signed 32-bit fractional multiply accumulate (wide)
  { "msubwhfl",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating multiply subtract
  { "msubdf",     CF_CHG1|CF_CHG2|CF_USE3|CF_USE4 },      // Signed 32-bit fractional multiply subtract (wide)
  { "dmpyhbl",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x8 signed multiply with lower two bytes
  { "dmpyhbm",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x8 signed multiply with upper two bytes
  { "dmachbl",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x8 signed multiply accumulate with lower two bytes
  { "dmachbm",    CF_CHG1|CF_USE2|CF_USE3         },      // Dual 16x8 signed multiply accumulate with upper two bytes
  { "msubwhflr",  CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating rounded multiply subtract
  { "cmpyhfmr",   CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex x 16bit real (upper) saturating rounded multiply
  { "cbflyhf0r",  CF_CHG1|CF_USE2|CF_USE3         },      // Fractional 16+16 bit complex FFT butterfly, first half
  { "mpywhl",     CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) multiply
  { "macwhl",     CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) multiply accumulate
  { "mpywhul",    CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32 x 16 (lower) multiply
  { "macwhul",    CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32 x 16 (lower) multiply accumulate
  { "mpywhfm",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating multiply
  { "mpywhfmr",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating rounded multiply
  { "macwhfm",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating multiply accumulate
  { "macwhfmr",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating rounded multiply accumulate
  { "mpywhfl",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating multiply
  { "mpywhflr",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating rounded multiply
  { "macwhfl",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating multiply accumulate
  { "macwhflr",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) fractional saturating rounded multiply accumulate
  { "macwhkl",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) 16-bit shifted multiply accumulate
  { "macwhkul",   CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32 x 16 (lower) 16-bit shifted multiply accumulate
  { "mpywhkl",    CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (lower) 16-bit shifted multiply
  { "mpywhkul",   CF_CHG1|CF_USE2|CF_USE3         },      // Unsigned 32 x 16 (lower) 16-bit shifted multiply
  { "msubwhfm",   CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating multiply subtract
  { "msubwhfmr",  CF_CHG1|CF_USE2|CF_USE3         },      // Signed 32 x 16 (upper) fractional saturating rounded multiply subtract

  // ARCv2 32-bit extension major 6 SOP instructions
  { "cbflyhf1r",  CF_CHG1|CF_USE2                 },      // Fractional 16+16 bit complex FFT butterfly, second half

  { "fscmp",      CF_USE1|CF_USE2                 },      // Single precision floating point compare
  { "fscmpf",     CF_USE1|CF_USE2                 },      // Single precision floating point compare (IEEE 754 flag generation)
  { "fsmadd",     CF_CHG1|CF_USE2|CF_USE3         },      // Single precision floating point fused multiply add
  { "fsmsub",     CF_CHG1|CF_USE2|CF_USE3         },      // Single precision floating point fused multiply subtract
  { "fsdiv",      CF_CHG1|CF_USE2|CF_USE3         },      // Single precision floating point division
  { "fcvt32",     CF_CHG1|CF_USE2                 },      // Single precision floating point / integer conversion
  { "fssqrt",     CF_CHG1|CF_USE2|CF_USE3         },      // Single precision floating point square root

  // ARCv2 jump / execute indexed instructions
  { "jli",        CF_USE1|CF_CALL                 },      // Jump and link
  { "ei",         CF_USE1|CF_CALL                 },      // Execute indexed

  { "kflag",      CF_USE1                         },      // Set kernel flags
  { "wevt",       CF_USE1                         },      // Enter sleep state
};

CASSERT(qnumber(Instructions) == ARC_last);

