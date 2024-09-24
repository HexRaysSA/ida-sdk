/*
*      Interactive disassembler (IDA).
*      Copyright (c) 1990-2024 Hex-Rays
*      ALL RIGHTS RESERVED.
*
*/

#include "ins.hpp"

const instruc_t Instructions[] =
{
  { "",               0                               }, // Unknown Operation

  { "breakpoint",     CF_STOP                         }, // undefined instruction
  { "xori",           CF_USE1|CF_USE2|CF_CHG3         }, // Exclusive Or Immediate
  { "xor",            CF_USE1|CF_USE2|CF_CHG2         }, // Exclusive OR
  { "tst1",           CF_USE1|CF_USE2                 }, // Test bit
  { "tst",            CF_USE1|CF_USE2                 }, // Test
  { "trap",           CF_USE1                         }, // Software trap
  { "subr",           CF_USE1|CF_USE2|CF_CHG2         }, // Substract reverse
  { "sub",            CF_USE1|CF_USE2|CF_CHG2         }, // Substract
  { "stsr",           CF_USE1|CF_CHG2                 }, // Store Contents of System Register
  { "st.b",           CF_USE1|CF_USE2|CF_CHG2         }, // Store byte
  { "st.h",           CF_USE1|CF_USE2|CF_CHG2         }, // Store half-word
  { "st.w",           CF_USE1|CF_USE2|CF_CHG2         }, // Store word
  { "sst.b",          CF_USE1|CF_USE2|CF_CHG2         }, // Store byte (use EP)
  { "sst.h",          CF_USE1|CF_USE2|CF_CHG2         }, // Store half-word (use EP)
  { "sst.w",          CF_USE1|CF_USE2|CF_CHG2         }, // Store word (use EP)
  { "sld.b",          CF_USE1|CF_CHG2                 }, // Load byte (use EP)
  { "sld.h",          CF_USE1|CF_CHG2                 }, // Load half-word (use EP)
  { "sld.w",          CF_USE1|CF_CHG2                 }, // Load word (use EP)
  { "shr",            CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Logical Right
  { "shl",            CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Logical Left
  { "set1",           CF_USE1|CF_USE2|CF_CHG2         }, // Set Bit
  { "setf",           CF_USE1|CF_CHG2                 }, // Set register to 1 if condition is satisfied
  { "satsubr",        CF_USE1|CF_USE2|CF_CHG2         }, // Saturated Subtract Reverse
  { "satsubi",        CF_USE1|CF_USE2|CF_CHG3         }, // Saturated Subtract Immediate
  { "satsub",         CF_USE1|CF_USE2|CF_CHG2         }, // Saturated Subtract
  { "satadd",         CF_USE1|CF_USE2|CF_CHG2         }, // Saturated Add
  { "sar",            CF_USE1|CF_USE2|CF_CHG2|CF_SHFT }, // Shift Arithmetic Right
  { "reti",           CF_STOP                         }, // Return from Trap or Interrupt
  { "ori",            CF_USE1|CF_USE2|CF_CHG2         }, // OR immediate
  { "or",             CF_USE1|CF_USE2|CF_CHG2         }, // OR
  { "not1",           CF_USE1|CF_USE2|CF_CHG2         }, // Not Bit
  { "not",            CF_USE1|CF_USE2|CF_CHG2         }, // Not
  { "nop",            0                               }, // No Operation
  { "mulhi",          CF_USE1|CF_USE2|CF_CHG3         }, // Multiply Half-Word Immediate
  { "mulh",           CF_USE1|CF_USE2|CF_CHG2         }, // Multiply Half-Word
  { "movhi",          CF_USE1|CF_USE2|CF_CHG3         }, // Move High Half-Word
  { "movea",          CF_USE1|CF_USE2|CF_CHG3         }, // Move Effective Address
  { "mov",            CF_USE1|CF_CHG2                 }, // Move
  { "ldsr",           CF_USE1|CF_CHG2                 }, // Load to system register
  { "ld.b",           CF_USE1|CF_CHG2                 }, // Load byte
  { "ld.h",           CF_USE1|CF_CHG2                 }, // Load half-word
  { "ld.w",           CF_USE1|CF_CHG2                 }, // Load word
  { "jr",             CF_USE1|CF_STOP                 }, // Jump Relative
  { "jmp",            CF_USE1|CF_JUMP|CF_STOP         }, // Jump Register
  { "jarl",           CF_CALL|CF_USE1|CF_CHG2         }, // Jump and Register Link
  { "halt",           CF_STOP                         }, // Halt
  { "ei",             0                               }, // Enable interrupt
  { "divh",           CF_USE1|CF_USE2|CF_CHG2         }, // Divide Half-Word
  { "di",             0                               }, // Disable Interrupt
  { "cmp",            CF_USE1|CF_USE2                 }, // Compare
  { "clr1",           CF_USE1|CF_USE2|CF_CHG2         }, // Clear bit
  { "bv",             CF_USE1                         }, // Branch if overflow
  { "bl",             CF_USE1                         }, // Branch if less
  { "bz",             CF_USE1                         }, // Branch if zero
  { "bnh",            CF_USE1                         }, // Branch if not higher
  { "bn",             CF_USE1                         }, // Branch if negative
  { "br",             CF_USE1|CF_STOP                 }, // Branch if always
  { "blt",            CF_USE1                         }, // Branch if less than (signed)
  { "ble",            CF_USE1                         }, // Branch if less than or equal (signed)
  { "bnv",            CF_USE1                         }, // Branch if no overflow
  { "bnc",            CF_USE1                         }, // Branch if no carry
  { "bnz",            CF_USE1                         }, // Branch if not zero
  { "bh",             CF_USE1                         }, // Branch if higher than
  { "bp",             CF_USE1                         }, // Branch if positive
  { "bsa",            CF_USE1                         }, // Branch if saturated
  { "bge",            CF_USE1                         }, // Branch if greater than or equal (signed)
  { "bgt",            CF_USE1                         }, // Branch if greater than (signed)
  { "andi",           CF_USE1|CF_USE2|CF_CHG3         }, // And immediate
  { "and",            CF_USE1|CF_USE2|CF_CHG2         }, // And
  { "addi",           CF_USE1|CF_USE2|CF_CHG3         }, // Add Immediate
  { "add",            CF_USE1|CF_USE2|CF_CHG2         }, // Add

  //
  // V850E/E1/ES
  //
  { "switch",         CF_USE1|CF_STOP|CF_JUMP         }, // Jump with table look up
  { "zxb",            CF_USE1|CF_CHG1                 }, // Zero-extend byte
  { "sxb",            CF_USE1|CF_CHG1                 }, // Sign-extend byte
  { "zxh",            CF_USE1|CF_CHG1                 }, // Zero-extend halfword
  { "sxh",            CF_USE1|CF_CHG1                 }, // Sign-extend halfword
  { "dispose",        CF_USE1|CF_USE2                 }, // Function dispose
  { "dispose",        CF_USE1|CF_USE2|CF_USE3|CF_STOP }, // Function dispose
  { "callt",          CF_USE1|CF_CALL                 }, // Call with table look up
  { "dbtrap",         CF_STOP                         }, // Debug trap
  { "dbret",          CF_STOP                         }, // Return from debug trap or interrupt
  { "ctret",          CF_STOP                         }, // Return from CALLT

  { "sasf",           CF_USE1|CF_USE2|CF_CHG2         }, // Shift and set flag condition

  { "prepare",        CF_USE1|CF_USE2|CF_USE3         }, // Function prepare
  { "prepare",        CF_USE1|CF_USE2                 }, // Function prepare

  { "mul",            CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Multiply word
  { "mulu",           CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Multiply word unsigned

  { "divh",           CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide halfword
  { "divhu",          CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide halfword unsigned
  { "div",            CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word
  { "divu",           CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word unsigned

  { "bsw",            CF_USE1|CF_CHG2                 }, // Byte swap word
  { "bsh",            CF_USE1|CF_CHG2                 }, // Byte swap halfword
  { "hsw",            CF_USE1|CF_CHG2                 }, // Halfword swap word

  { "cmov",           CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Conditional move

  { "sld.bu",         CF_USE1|CF_CHG2                 }, // Short format load byte unsigned
  { "sld.hu",         CF_USE1|CF_CHG2                 }, // Short format load halfword unsigned

  { "ld.bu",          CF_USE1|CF_CHG2                 }, // load byte unsigned
  { "ld.hu",          CF_USE1|CF_CHG2                 }, // load halfword unsigned

  //
  // V850E2
  //
  { "adf",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Add on condition flag
  { "hsh",            CF_USE1|CF_CHG2                 }, // Halfword swap halfword
  { "mac",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Multiply and add word
  { "macu",           CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Multiply and add word unsigned

  { "sbf",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Subtract on condition flag

  { "sch0l",          CF_USE1|CF_CHG2                 }, // Search zero from left
  { "sch0r",          CF_USE1|CF_CHG2                 }, // Search zero from right
  { "sch1l",          CF_USE1|CF_CHG2                 }, // Search one from left
  { "sch1r",          CF_USE1|CF_CHG2                 }, // Search one from right

  //
  // V850E2M
  //
  { "caxi",           CF_USE1|CF_USE2|CF_USE3         }, // Compare and exchange for interlock
  { "divq",           CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word quickly
  { "divqu",          CF_USE1|CF_USE2|CF_CHG2|CF_CHG3 }, // Divide word unsigned quickly
  { "eiret",          CF_STOP                         }, // Return from EI level exception
  { "feret",          CF_STOP                         }, // Return from FE level exception
  { "fetrap",         CF_USE1                         }, // FE-level Trap
  { "rmtrap",         0                               }, // Runtime monitor trap
  { "rie",            CF_STOP|CF_USE1|CF_USE2         }, // Reserved instruction exception
  { "synce",          0                               }, // Synchronize exceptions
  { "syncm",          0                               }, // Synchronize memory
  { "syncp",          0                               }, // Synchronize pipeline
  { "syscall",        CF_USE1                         }, // System call

  // floating poin    t (E1F only)
  { "cvt.sw",         CF_USE1|CF_CHG2                 }, // Real to integer conversion
  { "trnc.sw",        CF_USE1|CF_CHG2                 }, // Real to integer conversion
  { "cvt.ws",         CF_USE1|CF_CHG2                 }, // Integer to real conversion
  { "ldfc",           CF_USE1|CF_CHG2                 }, // Load to Floating Controls
  { "ldff",           CF_USE1|CF_CHG2                 }, // Load to Floating Flags
  { "stfc",           CF_USE1|CF_CHG2                 }, // Store Floating Controls
  { "stff",           CF_USE1|CF_CHG2                 }, // Store Floating Flags
  { "trff",           0                               }, // Transfer Floating Flags

  // floating poin    t (E2M+)
  { "absf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Absolute Value (Double)
  { "absf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Absolute Value (Single)
  { "addf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Add (Double)
  { "addf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Add (Single)
  { "divf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Divide (Double)
  { "divf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Divide (Single)
  { "maxf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Maximum (Double)
  { "maxf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Maximum (Single)
  { "minf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Minimum (Double)
  { "minf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Minimum (Single)
  { "mulf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Multiply (Double)
  { "mulf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Multiply (Single)
  { "negf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Negate (Double)
  { "negf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Negate (Single)
  { "recipf.d",       CF_USE1|CF_CHG2                 }, // Reciprocal of a floating-point value (Double)
  { "recipf.s",       CF_USE1|CF_CHG2                 }, // Reciprocal of a floating-point value (Single

  { "rsqrtf.d",       CF_USE1|CF_CHG2                 }, // Reciprocal of the square root of a floating-point value (Double)
  { "rsqrtf.s",       CF_USE1|CF_CHG2                 }, // Reciprocal of the square root of a floating-point value (Single)
  { "sqrtf.d",        CF_USE1|CF_CHG2                 }, // Floating-point Square Root (Double)
  { "sqrtf.s",        CF_USE1|CF_CHG2                 }, // Floating-point Square Root (Single)
  { "subf.d",         CF_USE1|CF_CHG2                 }, // Floating-point Subtract (Double)
  { "subf.s",         CF_USE1|CF_CHG2                 }, // Floating-point Subtract (Single)
  { "maddf.s",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Floating-point Multiply-Add (Single)
  { "msubf.s",        CF_USE1|CF_CHG2|CF_USE3|CF_CHG4 }, // Floating-point Multiply-Subtract (Single)
  { "nmaddf.s",       CF_USE1|CF_CHG2|CF_USE3|CF_CHG4 }, // Floating-point Negate Multiply-Add (Single)
  { "nmsubf.s",       CF_USE1|CF_CHG2|CF_USE3|CF_CHG4 }, // Floating-point Negate Multiply-Subtract (Single)

  { "ceilf.dl",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Double)
  { "ceilf.dw",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Double)
  { "ceilf.sl",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Single)
  { "ceilf.sw",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Single)
  { "ceilf.dul",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Long, rounded toward +inf (Double)
  { "ceilf.duw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Word, rounded toward +inf (Double)
  { "ceilf.sul",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Long, rounded toward +inf (Single)
  { "ceilf.suw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Word, rounded toward +inf (Single)
  { "cvtf.dl",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Long Fixed-point Format (Double)
  { "cvtf.ds",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Floating-point Format (Double)
  { "cvtf.dul",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Double to Unsigned-Long (Double)
  { "cvtf.duw",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Double to Unsigned-Word (Double)
  { "cvtf.dw",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Fixed-point Format (Double)
  { "cvtf.ld",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Floating-point Format (Double)
  { "cvtf.ls",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Floating-point Format (Single)
  { "cvtf.sd",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Double Floating-point Format (Double)
  { "cvtf.sl",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Long Fixed-point Format (Single)
  { "cvtf.sul",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Single to Unsigned-Long (Single)
  { "cvtf.suw",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Single to Unsigned-Word (Single)
  { "cvtf.sw",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Fixed-point Format (Single)
  { "cvtf.uld",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Unsigned-Long to Double (Double)
  { "cvtf.uls",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Unsigned-Long to Single (Single)
  { "cvtf.uwd",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Unsigned-Word to Double (Double)
  { "cvtf.uws",       CF_USE1|CF_CHG2                 }, // Floating-point Convert Unsigned-Word to Single (Single)
  { "cvtf.wd",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Floating-point Format (Double)
  { "cvtf.ws",        CF_USE1|CF_CHG2                 }, // Floating-point Convert to Single Floating-point Format (Single)
  { "floorf.dl",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Double)
  { "floorf.dw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Double)
  { "floorf.sl",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Single)
  { "floorf.sw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Single)
  { "floorf.dul",     CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Long, rounded toward -inf (Double)
  { "floorf.duw",     CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Word, rounded toward -inf (Double)
  { "floorf.sul",     CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Long, rounded toward -inf (Single)
  { "floorf.suw",     CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Unsigned Word, rounded toward -inf (Single)
  { "trncf.dl",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Double)
  { "trncf.dul",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate Double to Unsigned-Long (Double)
  { "trncf.duw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate Double to Unsigned-Word (Double)
  { "trncf.dw",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Double)
  { "trncf.sl",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Single)
  { "trncf.sul",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate Single to Unsigned-Long (Single)
  { "trncf.suw",      CF_USE1|CF_CHG2                 }, // Floating-point Truncate Single to Unsigned-Word (Single)
  { "trncf.sw",       CF_USE1|CF_CHG2                 }, // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Single)
  { "cmpf.s",         CF_USE1|CF_CHG2                 }, // Compares floating-point values (Single)
  { "cmpf.d",         CF_USE1|CF_CHG2                 }, // Compares floating-point values (Double)
  { "cmovf.s",        CF_USE1|CF_CHG2                 }, // Floating-point conditional move (Single)
  { "cmovf.d",        CF_USE1|CF_CHG2                 }, // Floating-point conditional move (Double)
  { "trfsr",          CF_USE1|CF_CHG2                 }, // Transfers specified CC bit to Zero flag in PSW (Single)

  //
  // RH850
  //
  { "synci",          0                               }, // Synchronize instruction pipeline
  { "snooze",         0                               }, // Snooze
  { "bins",           CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_CHG4 }, // Bitfield Insert
  { "rotl",           CF_USE1|CF_USE2|CF_CHG3         }, // Rotate Left
  { "loop",           CF_USE1|CF_USE2                 }, // Loop
  { "ld.dw",          CF_USE1|CF_CHG2                 }, // Load Double Word
  { "st.dw",          CF_USE1|CF_USE2|CF_CHG2         }, // Store Double Word
  { "ldl.w",          CF_USE1|CF_CHG2                 }, // Load Linked
  { "stc.w",          CF_USE1|CF_USE2|CF_CHG2         }, // Store Conditional
  { "cll",            0                               }, // Clear Load Link
  { "cache",          CF_USE1|CF_USE2                 }, // Cache operation
  { "pref",           CF_USE1|CF_USE2                 }, // Prefetch
  { "pushsp",         CF_USE1                         }, // Push registers to Stack
  { "popsp",          CF_CHG1                         }, // Pop registers from Stack

  // new RH850 FP     instructions
  { "cvtf.hs",        CF_USE1|CF_CHG2                 }, // Floating-point Convert Half to Single (Single)
  { "cvtf.sh",        CF_USE1|CF_CHG2                 }, // Floating-point Convert Single to Half (Single)
  { "fmaf.s",         CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point Fused-Multiply-add (Single)
  { "fmsf.s",         CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point Fused-Multiply-subtract (Single)
  { "fnmaf.s",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point Fused-Negate-Multiply-add (Single)
  { "fnmsf.s",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point Fused-Negate-Multiply-subtract (Single)

  // debug instruc    tions
  { "dbpush",         CF_USE1                         }, // Output registers as software trace data
  { "dbcp",           0                               }, // Output current PC value as software trace data
  { "dbtag",          CF_USE1                         }, // Output immediate value as software trace data
  { "dbhvtrap",       0                               }, // Debug hypervisor trap

  { "est",            0                               }, // Enable Single Thread mode
  { "dst",            0                               }, // Disable Single Thread mode
  { "hvtrap",         CF_USE1                         }, // Hypervisor trap
  { "hvcall",         CF_USE1                         }, // Hypervisor call
  { "ldvc.sr",        CF_USE1|CF_USE2                 }, // Load to virtual machine context (SR)
  { "stvc.sr",        CF_USE1|CF_USE2                 }, // Store contents of virtual machine context (SR)
  { "ldtc.gr",        CF_USE1|CF_USE2                 }, // Load to thread context (GR)
  { "sttc.gr",        CF_USE1|CF_USE2                 }, // Store contents of thread context (GR)
  { "ldtc.pc",        CF_USE1|CF_USE2                 }, // Load to thread context (PC)
  { "sttc.pc",        CF_USE1|CF_USE2                 }, // Store contents of thread context (PC)
  { "ldtc.sr",        CF_USE1|CF_USE2                 }, // Load to thread context (SR)
  { "sttc.sr",        CF_USE1|CF_USE2                 }, // Store contents of thread context (SR)
  { "ldtc.vr",        CF_USE1|CF_USE2                 }, // Load to thread context (VR)
  { "sttc.vr",        CF_USE1|CF_USE2                 }, // Store contents of thread context (VR)

  // TLB instructi    ons
  { "tlbai",          0                               }, // TLB ASID Invalidate
  { "tlbr",           0                               }, // TLB Read
  { "tlbs",           0                               }, // TLB Search
  { "tlbvi",          0                               }, // TLB VA Invalidate
  { "tlbw",           0                               }, // TLB Write

  // round instruc    tions
  { "roundf.dl",      CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Double to Long, round to nearest (Double)
  { "roundf.dw",      CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Double to Word, round to nearest (Double)
  { "roundf.dul",     CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Double to Unsigned-Long, round to nearest (Double)
  { "roundf.duw",     CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Double to Unsigned-Word, round to nearest (Double)
  { "roundf.sl",      CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Single to Long, round to nearest (Single)
  { "roundf.sw",      CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Single to Word, round to nearest (Single)
  { "roundf.sul",     CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Single to Unsigned-Long, round to nearest (Single)
  { "roundf.suw",     CF_USE1|CF_USE2|CF_CHG1         }, // Floating-point Convert Single to Unsigned-Word, round to nearest (Single)

  { "ldm.mp",         CF_USE1|CF_USE2                 }, // Load Multiple MPU entries from memory
  { "stm.mp",         CF_USE1|CF_USE2                 }, // Store Multiple MPU entries to memory

  { "clip.b",         CF_USE1|CF_USE2|CF_CHG2         }, // Signed data conversion from word to byte with saturation
  { "clip.bu",        CF_USE1|CF_USE2|CF_CHG2         }, // Unsigned data conversion from word to byte with saturation
  { "clip.h",         CF_USE1|CF_USE2|CF_CHG2         }, // Signed data conversion from word to halfword with saturation
  { "clip.hu",        CF_USE1|CF_USE2|CF_CHG2         }, // Unsigned data conversion from word to halfword with saturation

  { "ldl.bu",         CF_USE1|CF_USE2                 }, // Load to start atomic byte data manipulation
  { "ldl.hu",         CF_USE1|CF_USE2                 }, // Load to start atomic halfword data manipulation

  { "resbank"                                         }, // Restore from register bank

  { "stc.b",          CF_USE1|CF_USE2                 }, // Store conditional byte
  { "stc.h",          CF_USE1|CF_USE2                 }, // Store conditional halfword

  { "vand",           CF_USE1|CF_USE2|CF_CHG3         }, // Vector and
  { "vor",            CF_USE1|CF_USE2|CF_CHG3         }, // Vector or
  { "vxor",           CF_USE1|CF_USE2|CF_CHG3         }, // Vector xor
  { "vnot",           CF_USE1|CF_USE2|CF_CHG3         }, // Vector not

  { "vsar.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift arithmetic right halfword
  { "vsar.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift arithmetic right word
  { "vsar.dw",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift arithmetic right double-word
  { "vshr.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical right halfword
  { "vshr.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical right word
  { "vshr.dw",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical right double-word
  { "vshl.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical left halfword
  { "vshl.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical left word
  { "vshl.dw",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector shift logical left double-word

  { "vconcat.b",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Concatenate vector byte
  { "vitlv.h",        CF_CHG1|CF_CHG2                 }, // Interleave halfword
  { "vitlv.w",        CF_CHG1|CF_CHG2                 }, // Interleave word
  { "vitlvhw.h",      CF_CHG1|CF_CHG2                 }, // Interleave halfword (halfword to word)
  { "vitlvwh.h",      CF_CHG1|CF_CHG2                 }, // Interleave halfword (word to halfword)
  { "vshufl.b",       CF_USE1|CF_USE2|CF_CHG3         }, // Shuffle byte
  { "vbswap.dw",      CF_USE1|CF_CHG2                 }, // Swap double-word
  { "vbswap.h",       CF_USE1|CF_CHG2                 }, // Swap halfword
  { "vbswap.w",       CF_USE1|CF_CHG2                 }, // Swap word

  { "dup.h",          CF_USE1|CF_USE2|CF_CHG3         }, // Duplicate halfword
  { "dup.w",          CF_USE1|CF_USE2|CF_CHG3         }, // Dumplicate word
  { "mov.h",          CF_USE1|CF_USE2|CF_CHG3         }, // Move register (halfword)
  { "mov.w",          CF_USE1|CF_USE2|CF_CHG3         }, // Move register (word)
  { "mov.dw",         CF_USE1|CF_CHG2                 }, // Move register (double word)

  { "vld.b",          CF_CHG1|CF_USE2                 }, // Vector Load byte
  { "vld.b",          CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Load byte (3rd instruction format)
  { "vld.b",          CF_USE1|CF_CHG2|CF_CHG3         }, // Vector Load byte (4th instruction format)

  { "vld.h",          CF_CHG1|CF_CHG2                 }, // Vector Load halfword
  { "vld.h",          CF_USE1|CF_CHG2|CF_CHG3         }, // Vector Load halfword (4th instruction format)

  { "vld.w",          CF_CHG1|CF_CHG2                 }, // Vector Load word
  { "vld.w",          CF_USE1|CF_CHG2|CF_CHG3         }, // Vector Load word (4th instruction format)

  { "vld.dw",         CF_CHG1|CF_CHG2                 }, // Vector Load double - word
  { "vld.dw",         CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Load double - word (3rd instruction format)
  { "vld.dw",         CF_USE1|CF_CHG2|CF_CHG3         }, // Vector Load double - word (4th instruction format)
  { "vld.dw",         CF_USE1|CF_CHG2                 }, // Vector Load double - word (5th instruction format)

  { "vst.b",          CF_CHG1|CF_CHG2                 }, // Vector Store byte
  { "vst.b",          CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Store byte (4th instruction format)

  { "vst.h",          CF_CHG1|CF_CHG2                 }, // Vector Store halfword
  { "vst.h",          CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Store halfword (4th/5th instruction format)

  { "vst.w",          CF_CHG1|CF_CHG2                 }, // Vector Store word
  { "vst.w",          CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Store word (4th/5th instruction format)

  { "vst.dw",         CF_CHG1|CF_CHG2                 }, // Vector Store double - word
  { "vst.dw",         CF_CHG1|CF_USE2|CF_CHG3         }, // Vector Store double - word (4th/5th instruction format)
  { "vst.dw",         CF_CHG1|CF_USE2                 }, // Vector Store double - word (6th instruction format)

  { "vcmov",          CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Vector conditional move
  { "modadd",         CF_CHG1                         }, // Modulo Add

  { "vadd.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector add halfword
  { "vadd.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector add word
  { "vadd.dw",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector add double - word
  { "vsub.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract halfword
  { "vsub.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract word
  { "vsub.dw",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract double - word
  { "vaddsat.h",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector add halfword with saturation
  { "vaddsat.w",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector add word with saturation
  { "vsubsat.h",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract halfword with saturation
  { "vsubsat.w",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract word with saturation
  { "vadds.h",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector add halfword with scaling
  { "vadds.w",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector add word with scaling
  { "vsubs.h",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract halfword with scaling
  { "vsubs.w",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector subtract word with scaling

  { "vmul.h",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword
  { "vmul.w",         CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word
  { "vmult.h",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword with truncation
  { "vmult.w",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word with truncation
  { "vmulcx.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword with complex number
  { "vmulcx.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word with complex number

  { "vcmpeq.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare equal halfword
  { "vcmpeq.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare equal word
  { "vcmplt.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare less-than halfword
  { "vcmplt.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare less-than word
  { "vcmple.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare less-than-equal halfword
  { "vcmple.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare less-than-equal word
  { "vcmpne.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare not-equal halfword
  { "vcmpne.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector compare not-equal word

  { "vabs.h",         CF_USE1|CF_CHG2                 }, // Vector absolute halfword
  { "vabs.w",         CF_USE1|CF_CHG2                 }, // Vector absolute word

  { "vneg.h",         CF_USE1|CF_CHG2                 }, // Vector negate halfword
  { "vneg.w",         CF_USE1|CF_CHG2                 }, // Vector negate word

  { "vmaxgt.h",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector maximum greater-than halfword
  { "vmaxge.h",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector maximum greater-than-equal halfword
  { "vminlt.h",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector minimum less-than halfword
  { "vminle.h",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector minimum less-than-equal halfword
  { "vmaxgt.w",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector maximum greater-than word
  { "vmaxge.w",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector maximum greater-than-equal word
  { "vminlt.w",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector minimum less-than word
  { "vminle.w",       CF_CHG1|CF_USE2|CF_CHG3         }, // Vector minimum less-than-equal word

  { "vmadsat.h",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and add with saturation
  { "vmadsat.w",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and add with saturation
  { "vmadrn.h",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and add with rounding
  { "vmadrn.w",       CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and add with rounding

  { "vmsum.h",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and sum
  { "vmsum.w",        CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and sum

  { "vmsumad.h",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and sum and add to vector register
  { "vmsumad.w",      CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and sum and add to vector register
  { "vmsumadre.h",    CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and sum and add to vector register for real part result of complex number calculation
  { "vmsumadre.w",    CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and sum and add to vector register for real part result of complex number calculation
  { "vmsumadim.h",    CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and sum and add to vector register for imaginary part result of complex number calculation
  { "vmsumadim.w",    CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply word and sum and add to vector register for imaginary part result of complex number calculation
  { "vmsumadrn.h",    CF_USE1|CF_USE2|CF_CHG3         }, // Vector multiply halfword and sum and add to vector register with rounding
  { "vbiq.h",         CF_USE1|CF_CHG2|CF_CHG3         }, // Vector multiply halfword for biquad calculation

  { "pkui8i16",       CF_USE1|CF_CHG2|CF_CHG3         }, // Pack vector unsigned integer byte to vector signed integer halfword
  { "pki16i32",       CF_USE1|CF_CHG2|CF_CHG3         }, // Pack vector signed integer halfword to vector signed integer word
  { "pkq15q31",       CF_USE1|CF_CHG2|CF_CHG3         }, // Pack vector Q15 fractional halfword to vector Q31 fractional word
  { "pki16ui8",       CF_USE1|CF_USE2|CF_CHG3         }, // Pack vector signed integer halfword to vector unsigned integer byte
  { "pki32i16",       CF_USE1|CF_USE2|CF_CHG3         }, // Pack vector signed integer word to vector signed integer halfword
  { "pkq31q15",       CF_USE1|CF_USE2|CF_CHG3         }, // Pack vector Q31 fractional word to vector Q15 fractional halfword
  { "pkq30q31",       CF_USE1|CF_USE2|CF_CHG3         }, // Pack Q31 fractional double-word to vector Q31 fractional halfword
  { "pki64i32",       CF_USE1|CF_USE2|CF_CHG3         }, // Pack signed integer double-word to vector signed integer word
  { "cnvq15q30",      CF_USE1|CF_CHG2                 }, // Convert from Q15 fractional halfword to Q30 fractional double-word
  { "cnvq31q62",      CF_USE1|CF_CHG2                 }, // Convert from Q31 fractional word to Q62 fractional double-word
  { "cnvq30q15",      CF_USE1|CF_CHG2                 }, // Convert from Q30 fractional double-word to Q15 fractional halfword
  { "cnvq62q31",      CF_USE1|CF_CHG2                 }, // Convert from Q62 fractional double-word to Q31 fractional word

  { "expq31",         CF_USE1|CF_CHG2                 }, // Extract exponent of Q31 fractional word
  { "vcalc.h",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Vector calculate with halfword
  { "vcalc.w",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Vector calculate with word

  { "movv.w4",        CF_USE1|CF_CHG2                 }, // Move vector register to vector register

  { "flpv.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Flip (single)
  { "shflv.w4",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Vector Shuffle

  { "ldv.dw",         CF_USE1|CF_USE2|CF_CHG3         }, // Load Vector (Double-Word)
  { "ldv.qw",         CF_USE1|CF_CHG2                 }, // Load Vector (Quad-Word)
  { "ldv.w",          CF_USE1|CF_USE2|CF_CHG3         }, // Load Vector (Word)
  { "ldvz.h4",        CF_USE1|CF_USE2|CF_CHG3         }, // Load Vector at Even Halfword field

  { "stv.dw",         CF_USE1|CF_CHG2|CF_USE3         }, // Store Vector (Double-Word)
  { "stv.qw",         CF_CHG1|CF_USE2                 }, // Store Vector (Quad-Word)
  { "stv.w",          CF_USE1|CF_CHG2|CF_USE3         }, // Store Vector (Word)
  { "stvz.h4",        CF_CHG1|CF_USE2                 }, // Store Vector at Even Halfword field

  { "cmovf.w4",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }, // Conditional move of vector register (Single precision)
  { "trfsrv.w4",      CF_USE1|CF_USE2                 }, // Transfers compare result to PSW

  { "absf.s4",        CF_USE1|CF_CHG2                 }, // Floating-point SIMD Absolute (single)
  { "addf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add (single)
  { "divf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Divide (single)
  { "maxf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Maximum (single)
  { "minf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Minimum (single)
  { "mulf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Multiply (single)
  { "negf.s4",        CF_USE1|CF_CHG2                 }, // Floating-point SIMD Negative (single)
  { "recipf.s4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Reciprocal (single)
  { "rsqrtf.s4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Reciprocal Square-Root (single)
  { "sqrtf.s4",       CF_USE1|CF_CHG2                 }, // Floating-point SIMD Square-Root (single)
  { "subf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract (single)

  { "fmaf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Fused-Multiply-Add (Single)
  { "fmsf.s4",        CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Fused-Multiply-Subtract (Single)
  { "fnmaf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Fused-Negative-Multiply-Add (Single)
  { "fnmsf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Fused-Negative-Multiply-Subtract (Single)

  { "addsubf.s4",     CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add/Subtract (single)
  { "addsubnf.s4",    CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add/Subtract Negative (single)
  { "subaddf.s4",     CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract/Add (single)
  { "subaddnf.s4",    CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract/Add Negative (single)

  { "addxf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add Exchange (single)
  { "mulxf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Multiply Exchange (single)
  { "subxf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract Exchange (single)

  { "addsubnxf.s4",   CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add/Subtract Negative Exchange (single)
  { "addsubxf.s4",    CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add/Subtract Exchange (single)
  { "subaddnxf.s4",   CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract/Add Negative Exchange (single)
  { "subaddxf.s4",    CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract/Add Exchange (single)

  { "addrf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Add Reduction (single)
  { "maxrf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Maximum Reduction (single)
  { "minrf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Minimum Reduction (single)
  { "mulrf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Multiply Reduction (single)
  { "subrf.s4",       CF_USE1|CF_USE2|CF_CHG3         }, // Floating-point SIMD Subtract Reduction (single)

  { "ceilf.suw4",     CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Unsigned Word, round toward positive (single)
  { "ceilf.sw4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Word, round toward positive (single)
  { "cvtf.hs4",       CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Half to Single (single)
  { "cvtf.sh4",       CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Half (single)
  { "cvtf.suw4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Unsigned Word (single)
  { "cvtf.sw4",       CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Word (single)
  { "cvtf.uws4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Unsigned Word to Single (single)
  { "cvtf.ws4",       CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Word to Single (single)
  { "floorf.suw4",    CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Unsigned Word, round toward negative (single)
  { "floorf.sw4",     CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Word, round toward negative (single)
  { "roundf.suw4",    CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Unsigned Word, round to nearest (single)
  { "roundf.sw4",     CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Word, round to nearest (single)
  { "trncf.suw4",     CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Unsigned Word, round toward zero (single)
  { "trncf.sw4",      CF_USE1|CF_CHG2                 }, // Floating-point SIMD Convert Single to Word, round toward zero (single)
  { "cmpf.s4",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4 }  // Floating-point SIMD Comparison (single)
};

CASSERT(qnumber(Instructions) == NEC850_LAST_INSTRUCTION);
