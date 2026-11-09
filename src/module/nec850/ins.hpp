/*
*      Interactive disassembler (IDA).
*      Copyright (c) 1990-2024 Hex-Rays
*      ALL RIGHTS RESERVED.
*
*/

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

#include <idp.hpp>

//----------------------------------------------------------------------

extern const instruc_t Instructions[];

enum NEC850_Instructions
{
  NEC850_NULL = 0,

  NEC850_BREAKPOINT,    // undefined instruction
  NEC850_XORI,          // Exclusive Or Immediate
  NEC850_XOR,           // Exclusive OR
  NEC850_TST1,          // Test bit
  NEC850_TST,           // Test
  NEC850_TRAP,          // Software trap
  NEC850_SUBR,          // Substract reverse
  NEC850_SUB,           // Substract
  NEC850_STSR,          // Store Contents of System Register
  NEC850_ST_B,          // Store byte
  NEC850_ST_H,          // Store half-word
  NEC850_ST_W,          // Store word
  NEC850_SST_B,         // Store byte (use EP)
  NEC850_SST_H,         // Store half-word (use EP)
  NEC850_SST_W,         // Store word (use EP)
  NEC850_SLD_B,         // Load byte (use EP)
  NEC850_SLD_H,         // Load half-word (use EP)
  NEC850_SLD_W,         // Load word (use EP)
  NEC850_SHR,           // Shift Logical Right
  NEC850_SHL,           // Shift Logical Left
  NEC850_SET1,          // Set Bit
  NEC850_SETF,          // Set register to 1 if condition is satisfied
  NEC850_SATSUBR,       // Saturated Subtract Reverse
  NEC850_SATSUBI,       // Saturated Subtract Immediate
  NEC850_SATSUB,        // Saturated Subtract
  NEC850_SATADD,        // Saturated Add
  NEC850_SAR,           // Shift Arithmetic Right
  NEC850_RETI,          // Return from Trap or Interrupt
  NEC850_ORI,           // OR immediate
  NEC850_OR,            // OR
  NEC850_NOT1,          // Not Bit
  NEC850_NOT,           // Not
  NEC850_NOP,           // No Operation
  NEC850_MULHI,         // Multiply Half-Word Immediate
  NEC850_MULH,          // Multiply Half-Word
  NEC850_MOVHI,         // Move High Half-Word
  NEC850_MOVEA,         // Move Effective Address
  NEC850_MOV,           // Move
  NEC850_LDSR,          // Load to system register
  NEC850_LD_B,          // Load byte
  NEC850_LD_H,          // Load half-word
  NEC850_LD_W,          // Load word
  NEC850_JR,            // Jump Relative
  NEC850_JMP,           // Jump Register
  NEC850_JARL,          // Jump and Register Link
  NEC850_HALT,          // Halt
  NEC850_EI,            // Enable interrupt
  NEC850_DIVH,          // Divide Half-Word
  NEC850_DI,            // Disable Interrupt
  NEC850_CMP,           // Compare
  NEC850_CLR1,          // Clear bit
  NEC850_BV,            // Branch if overflow
  NEC850_BL,            // Branch if less
  NEC850_BZ,            // Branch if zero
  NEC850_BNH,           // Branch if not higher
  NEC850_BN,            // Branch if negative
  NEC850_BR,            // Branch if always
  NEC850_BLT,           // Branch if less than (signed)
  NEC850_BLE,           // Branch if less than or equal (signed)
  NEC850_BNV,           // Branch if no overflow
  NEC850_BNC,           // Branch if no carry
  NEC850_BNZ,           // Branch if not zero
  NEC850_BH,            // Branch if higher than
  NEC850_BP,            // Branch if positive
  NEC850_BSA,           // Branch if saturated
  NEC850_BGE,           // Branch if greater than or equal (signed)
  NEC850_BGT,           // Branch if greater than (signed)
  NEC850_ANDI,          // And immediate
  NEC850_AND,           // And
  NEC850_ADDI,          // Add Immediate
  NEC850_ADD,           // Add

  //
  // V850E/E1/ES
  //
  NEC850_SWITCH,        // Jump with table look up
  NEC850_ZXB,           // Zero-extend byte
  NEC850_SXB,           // Sign-extend byte
  NEC850_ZXH,           // Zero-extend halfword
  NEC850_SXH,           // Sign-extend halfword
  NEC850_DISPOSE_r0,    // Function dispose
  NEC850_DISPOSE_r,     // Function dispose
  NEC850_CALLT,         // Call with table look up
  NEC850_DBTRAP,        // Debug trap
  NEC850_DBRET,         // Return from debug trap or interrupt
  NEC850_CTRET,         // Return from CALLT

  NEC850_SASF,          // Shift and set flag condition

  NEC850_PREPARE_sp,    // Function prepare
  NEC850_PREPARE_i,     // Function prepare

  NEC850_MUL,           // Multiply word
  NEC850_MULU,          // Multiply word unsigned

  NEC850_DIVH_r3,       // Divide halfword
  NEC850_DIVHU,         // Divide halfword unsigned
  NEC850_DIV,           // Divide word
  NEC850_DIVU,          // Divide word unsigned

  NEC850_BSW,           // Byte swap word
  NEC850_BSH,           // Byte swap halfword
  NEC850_HSW,           // Halfword swap word

  NEC850_CMOV,          // Conditional move

  NEC850_SLD_BU,        // Short format load byte unsigned
  NEC850_SLD_HU,        // Short format load halfword unsigned
  NEC850_LD_BU,         // load byte unsigned
  NEC850_LD_HU,         // load halfword unsigned

  //
  // V850E2
  //
  NEC850_ADF,            // Add on condition flag

  NEC850_HSH,            // Halfword swap halfword
  NEC850_MAC,            // Multiply and add word
  NEC850_MACU,           // Multiply and add word unsigned

  NEC850_SBF,            // Subtract on condition flag

  NEC850_SCH0L,          // Search zero from left
  NEC850_SCH0R,          // Search zero from right
  NEC850_SCH1L,          // Search one from left
  NEC850_SCH1R,          // Search one from right

  //
  // V850E2M
  //
  NEC850_CAXI,           // Compare and exchange for interlock
  NEC850_DIVQ,           // Divide word quickly
  NEC850_DIVQU,          // Divide word unsigned quickly
  NEC850_EIRET,          // Return from EI level exception
  NEC850_FERET,          // Return from FE level exception
  NEC850_FETRAP,         // FE-level Trap
  NEC850_RMTRAP,         // Runtime monitor trap
  NEC850_RIE,            // Reserved instruction exception
  NEC850_SYNCE,          // Synchronize exceptions
  NEC850_SYNCM,          // Synchronize memory
  NEC850_SYNCP,          // Synchronize pipeline
  NEC850_SYSCALL,        // System call

  // floating point (E1F only)
  NEC850_CVT_SW,         // Real to integer conversion
  NEC850_TRNC_SW,        // Real to integer conversion
  NEC850_CVT_WS,         // Integer to real conversion
  NEC850_LDFC,           // Load to Floating Controls
  NEC850_LDFF,           // Load to Floating Flags
  NEC850_STFC,           // Store Floating Controls
  NEC850_STFF,           // Store Floating Flags
  NEC850_TRFF,           // Transfer Floating Flags

  // floating point (E2M)

  NEC850_ABSF_D,         // Floating-point Absolute Value (Double)
  NEC850_ABSF_S,         // Floating-point Absolute Value (Single)
  NEC850_ADDF_D,         // Floating-point Add (Double)
  NEC850_ADDF_S,         // Floating-point Add (Single)
  NEC850_DIVF_D,         // Floating-point Divide (Double)
  NEC850_DIVF_S,         // Floating-point Divide (Single)
  NEC850_MAXF_D,         // Floating-point Maximum (Double)
  NEC850_MAXF_S,         // Floating-point Maximum (Single)
  NEC850_MINF_D,         // Floating-point Minimum (Double)
  NEC850_MINF_S,         // Floating-point Minimum (Single)
  NEC850_MULF_D,         // Floating-point Multiply (Double)
  NEC850_MULF_S,         // Floating-point Multiply (Single)
  NEC850_NEGF_D,         // Floating-point Negate (Double)
  NEC850_NEGF_S,         // Floating-point Negate (Single)
  NEC850_RECIPF_D,       // Reciprocal of a floating-point value (Double)
  NEC850_RECIPF_S,       // Reciprocal of a floating-point value (Single

  NEC850_RSQRTF_D,       // Reciprocal of the square root of a floating-point value (Double)
  NEC850_RSQRTF_S,       // Reciprocal of the square root of a floating-point value (Single)
  NEC850_SQRTF_D,        // Floating-point Square Root (Double)
  NEC850_SQRTF_S,        // Floating-point Square Root (Single)
  NEC850_SUBF_D,         // Floating-point Subtract (Double)
  NEC850_SUBF_S,         // Floating-point Subtract (Single)
  NEC850_MADDF_S,        // Floating-point Multiply-Add (Single)
  NEC850_MSUBF_S,        // Floating-point Multiply-Subtract (Single)
  NEC850_NMADDF_S,       // Floating-point Negate Multiply-Add (Single)
  NEC850_NMSUBF_S,       // Floating-point Negate Multiply-Subtract (Single)

  NEC850_CEILF_DL,       // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Double)
  NEC850_CEILF_DW,       // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Double)
  NEC850_CEILF_SL,       // Floating-point Truncate to Long Fixed-point Format, rounded toward +inf (Single)
  NEC850_CEILF_SW,       // Floating-point Truncate to Single Fixed-point Format, rounded toward +inf (Single)
  NEC850_CEILF_DUL,      // Floating-point Truncate to Unsigned Long, rounded toward +inf (Double)
  NEC850_CEILF_DUW,      // Floating-point Truncate to Unsigned Word, rounded toward +inf (Double)
  NEC850_CEILF_SUL,      // Floating-point Truncate to Unsigned Long, rounded toward +inf (Single)
  NEC850_CEILF_SUW,      // Floating-point Truncate to Unsigned Word, rounded toward +inf (Single)
  NEC850_CVTF_DL,        // Floating-point Convert to Long Fixed-point Format (Double)
  NEC850_CVTF_DS,        // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_DUL,       // Floating-point Convert Double to Unsigned-Long (Double)
  NEC850_CVTF_DUW,       // Floating-point Convert Double to Unsigned-Word (Double)
  NEC850_CVTF_DW,        // Floating-point Convert to Single Fixed-point Format (Double)
  NEC850_CVTF_LD,        // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_LS,        // Floating-point Convert to Single Floating-point Format (Single)
  NEC850_CVTF_SD,        // Floating-point Convert to Double Floating-point Format (Double)
  NEC850_CVTF_SL,        // Floating-point Convert to Long Fixed-point Format (Single)
  NEC850_CVTF_SUL,       // Floating-point Convert Single to Unsigned-Long (Single)
  NEC850_CVTF_SUW,       // Floating-point Convert Single to Unsigned-Word (Single)
  NEC850_CVTF_SW,        // Floating-point Convert to Single Fixed-point Format (Single)
  NEC850_CVTF_ULD,       // Floating-point Convert Unsigned-Long to Double (Double)
  NEC850_CVTF_ULS,       // Floating-point Convert Unsigned-Long to Single (Single)
  NEC850_CVTF_UWD,       // Floating-point Convert Unsigned-Word to Double (Double)
  NEC850_CVTF_UWS,       // Floating-point Convert Unsigned-Word to Single (Single)
  NEC850_CVTF_WD,        // Floating-point Convert to Single Floating-point Format (Double)
  NEC850_CVTF_WS,        // Floating-point Convert to Single Floating-point Format (Single)
  NEC850_FLOORF_DL,      // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Double)
  NEC850_FLOORF_DW,      // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Double)
  NEC850_FLOORF_SL,      // Floating-point Truncate to Long Fixed-point Format, rounded toward -inf (Single)
  NEC850_FLOORF_SW,      // Floating-point Truncate to Single Fixed-point Format, rounded toward -inf (Single)
  NEC850_FLOORF_DUL,     // Floating-point Truncate to Unsigned Long, rounded toward -inf (Double)
  NEC850_FLOORF_DUW,     // Floating-point Truncate to Unsigned Word, rounded toward -inf (Double)
  NEC850_FLOORF_SUL,     // Floating-point Truncate to Unsigned Long, rounded toward -inf (Single)
  NEC850_FLOORF_SUW,     // Floating-point Truncate to Unsigned Word, rounded toward -inf (Single)
  NEC850_TRNCF_DL,       // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Double)
  NEC850_TRNCF_DUL,      // Floating-point Truncate Double to Unsigned-Long (Double)
  NEC850_TRNCF_DUW,      // Floating-point Truncate Double to Unsigned-Word (Double)
  NEC850_TRNCF_DW,       // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Double)
  NEC850_TRNCF_SL,       // Floating-point Truncate to Long Fixed-point Format, rounded to zero (Single)
  NEC850_TRNCF_SUL,      // Floating-point Truncate Single to Unsigned-Long (Single)
  NEC850_TRNCF_SUW,      // Floating-point Truncate Single to Unsigned-Word (Single)
  NEC850_TRNCF_SW,       // Floating-point Truncate to Single Fixed-point Format, rounded to zero (Single)
  NEC850_CMPF_S,         // Compares floating-point values (Single)
  NEC850_CMPF_D,         // Compares floating-point values (Double)
  NEC850_CMOVF_S,        // Floating-point conditional move (Single)
  NEC850_CMOVF_D,        // Floating-point conditional move (Double)
  NEC850_TRFSR,          // Transfers specified CC bit to Zero flag in PSW (Single)

  //
  // RH850
  //
  NEC850_SYNCI,          // Synchronize instruction pipeline
  NEC850_SNOOZE,         // Snooze
  NEC850_BINS,           // Bitfield Insert
  NEC850_ROTL,           // Rotate Left
  NEC850_LOOP,           // Loop
  NEC850_LD_DW,          // Load Double Word
  NEC850_ST_DW,          // Store Double Word
  NEC850_LDL_W,          // Load Linked
  NEC850_STC_W,          // Store Conditional
  NEC850_CLL,            // Clear Load Link
  NEC850_CACHE,          // Cache operation
  NEC850_PREF,           // Prefetch
  NEC850_PUSHSP,         // Push registers to Stack
  NEC850_POPSP,          // Pop registers from Stack

  // new RH850 FP instructions
  NEC850_CVTF_HS,        // Floating-point Convert Half to Single (Single)
  NEC850_CVTF_SH,        // Floating-point Convert Single to Half (Single)
  NEC850_FMAF_S,         // Floating-point Fused-Multiply-add (Single)
  NEC850_FMSF_S,         // Floating-point Fused-Multiply-subtract (Single)
  NEC850_FNMAF_S,        // Floating-point Fused-Negate-Multiply-add (Single)
  NEC850_FNMSF_S,        // Floating-point Fused-Negate-Multiply-subtract (Single)

  // debug instructions
  NEC850_DBPUSH,         // Output registers as software trace data
  NEC850_DBCP,           // Output current PC value as software trace data
  NEC850_DBTAG,          // Output immediate value as software trace data
  NEC850_DBHVTRAP,       // Debug hypervisor trap

  // virtualization instructions
  NEC850_EST,            // Enable Single Thread mode
  NEC850_DST,            // Disable Single Thread mode
  NEC850_HVTRAP,         // Debug hypervisor trap
  NEC850_HVCALL,         // Hypervisor call
  NEC850_LDVC_SR,        // Load to virtual machine context (SR)
  NEC850_STVC_SR,        // Store contents of virtual machine context (SR)
  NEC850_LDTC_GR,        // Load to thread context (GR)
  NEC850_STTC_GR,        // Store contents of thread context (GR)
  NEC850_LDTC_PC,        // Load to thread context (PC)
  NEC850_STTC_PC,        // Store contents of thread context (PC)
  NEC850_LDTC_SR,        // Load to thread context (SR)
  NEC850_STTC_SR,        // Store contents of thread context (SR)
  NEC850_LDTC_VR,        // Load to thread context (VR)
  NEC850_STTC_VR,        // Store contents of thread context (VR)

  // TLB instructions
  NEC850_TLBAI,          // TLB ASID Invalidate
  NEC850_TLBR,           // TLB Read
  NEC850_TLBS,           // TLB Search
  NEC850_TLBVI,          // TLB VA Invalidate
  NEC850_TLBW,           // TLB Write

  // RH850 rounding instructions
  NEC850_ROUNDF_DL,      // Floating-point Convert Double to Long, round to nearest (Double)
  NEC850_ROUNDF_DW,      // Floating-point Convert Double to Word, round to nearest (Double)
  NEC850_ROUNDF_DUL,     // Floating-point Convert Double to Unsigned-Long, round to nearest (Double)
  NEC850_ROUNDF_DUW,     // Floating-point Convert Double to Unsigned-Word, round to nearest (Double)
  NEC850_ROUNDF_SL,      // Floating-point Convert Single to Long, round to nearest (Single)
  NEC850_ROUNDF_SW,      // Floating-point Convert Single to Word, round to nearest (Single)
  NEC850_ROUNDF_SUL,     // Floating-point Convert Single to Unsigned-Long, round to nearest (Single)
  NEC850_ROUNDF_SUW,     // Floating-point Convert Single to Unsigned-Word, round to nearest (Single)

  NEC850_LDM_MP,         // Load Multiple MPU entries from memory
  NEC850_STM_MP,         // Store Multiple MPU entries to memory

  NEC850_CLIP_B,         // Signed data conversion from word to byte with saturation
  NEC850_CLIP_BU,        // Unsigned data conversion from word to byte with saturation
  NEC850_CLIP_H,         // Signed data conversion from word to halfword with saturation
  NEC850_CLIP_HU,        // Unsigned data conversion from word to halfword with saturation

  NEC850_LDL_BU,         // Load to start atomic byte data manipulation
  NEC850_LDL_HU,         // Load to start atomic halfword data manipulation

  NEC850_RESBANK,        // Restore from register bank

  NEC850_STC_B,          // Store conditional byte
  NEC850_STC_H,          // Store conditional halfword

  // RH850 SIMD instructions
  NEC850_VAND,           // Vector and
  NEC850_VOR,            // Vector or
  NEC850_VXOR,           // Vector xor
  NEC850_VNOT,           // Vector not

  NEC850_VSAR_H,         // Vector shift arithmetic right halfword
  NEC850_VSAR_W,         // Vector shift arithmetic right word
  NEC850_VSAR_DW,        // Vector shift arithmetic right double-word
  NEC850_VSHR_H,         // Vector shift logical right halfword
  NEC850_VSHR_W,         // Vector shift logical right word
  NEC850_VSHR_DW,        // Vector shift logical right double-word
  NEC850_VSHL_H,         // Vector shift logical left halfword
  NEC850_VSHL_W,         // Vector shift logical left word
  NEC850_VSHL_DW,        // Vector shift logical left double-word

  NEC850_VCONCAT_B,      // Concatenate vector byte
  NEC850_VITLV_H,        // Interleave halfword
  NEC850_VITLV_W,        // Interleave word
  NEC850_VITLVHW_H,      // Interleave halfword(halfword to word)
  NEC850_VITLVWH_H,      // Interleave halfword(word to halfword)
  NEC850_VSHUFL_B,       // Shuffle byte
  NEC850_VBSWAP_DW,      // Swap double - word
  NEC850_VBSWAP_H,       // Swap halfword
  NEC850_VBSWAP_W,       // Swap word

  NEC850_DUP_H,          // Duplicate halfword
  NEC850_DUP_W,          // Duplicate word
  NEC850_MOV_H,          // Move register (halfword)
  NEC850_MOV_W,          // Move register (word)
  NEC850_MOV_DW,         // Move register (double word)

  NEC850_VLD_B,          // Vector Load byte
  NEC850_VLD_B_FMT3,     // Vector Load byte (3rd instruction format)
  NEC850_VLD_B_FMT4,     // Vector Load byte (4th instruction format)

  NEC850_VLD_H,          // Vector Load halfword
  NEC850_VLD_H_FMT4,     // Vector Load halfword (4th instruction format)

  NEC850_VLD_W,          // Vector Load word
  NEC850_VLD_W_FMT4,     // Vector Load word (4th instruction format)

  NEC850_VLD_DW,         // Vector Load double - word
  NEC850_VLD_DW_FMT3,    // Vector Load double - word (3rd instruction format)
  NEC850_VLD_DW_FMT4,    // Vector Load double - word (4th instruction format)
  NEC850_VLD_DW_FMT5,    // Vector Load double - word (5th instruction format)

  NEC850_VST_B,          // Vector Store byte
  NEC850_VST_B_FMT4,     // Vector Store byte (4th instruction format)

  NEC850_VST_H,          // Vector Store halfword
  NEC850_VST_H_FMT_4_5,  // Vector Store halfword (4th/5th instruction format)

  NEC850_VST_W,          // Vector Store word
  NEC850_VST_W_FMT_4_5,  // Vector Store word (4th/5th instruction format)

  NEC850_VST_DW,         // Vector Store double - word
  NEC850_VST_DW_FMT_4_5, // Vector Store double - word (4th/5th instruction format)
  NEC850_VST_DW_FMT6,    // Vector Store double - word (6th instruction format)

  NEC850_VCMOV,          // Vector conditional move
  NEC850_MODADD,         // Modulo Add

  NEC850_VADD_H,         // Vector add halfword
  NEC850_VADD_W,         // Vector add word
  NEC850_VADD_DW,        // Vector add double - word
  NEC850_VSUB_H,         // Vector subtract halfword
  NEC850_VSUB_W,         // Vector subtract word
  NEC850_VSUB_DW,        // Vector subtract double - word
  NEC850_VADDSAT_H,      // Vector add halfword with saturation
  NEC850_VADDSAT_W,      // Vector add word with saturation
  NEC850_VSUBSAT_H,      // Vector subtract halfword with saturation
  NEC850_VSUBSAT_W,      // Vector subtract word with saturation
  NEC850_VADDS_H,        // Vector add halfword with scaling
  NEC850_VADDS_W,        // Vector add word with scaling
  NEC850_VSUBS_H,        // Vector subtract halfword with scaling
  NEC850_VSUBS_W,        // Vector subtract word with scaling

  NEC850_VMUL_H,         // Vector multiply halfword
  NEC850_VMUL_W,         // Vector multiply word
  NEC850_VMULT_H,        // Vector multiply halfword with truncation
  NEC850_VMULT_W,        // Vector multiply word with truncation
  NEC850_VMULCX_H,       // Vector multiply halfword with complex number
  NEC850_VMULCX_W,       // Vector multiply word with complex number

  NEC850_VCMPEQ_H,       // Vector compare equal halfword
  NEC850_VCMPEQ_W,       // Vector compare equal word
  NEC850_VCMPLT_H,       // Vector compare less-than halfword
  NEC850_VCMPLT_W,       // Vector compare less-than word
  NEC850_VCMPLE_H,       // Vector compare less-than-equal halfword
  NEC850_VCMPLE_W,       // Vector compare less-than-equal word
  NEC850_VCMPNE_H,       // Vector compare not-equal halfword
  NEC850_VCMPNE_W,       // Vector compare not-equal word

  NEC850_VABS_H,         // Vector absolute halfword
  NEC850_VABS_W,         // Vector absolute word

  NEC850_VNEG_H,         // Vector negate halfword
  NEC850_VNEG_W,         // Vector negate word

  NEC850_VMAXGT_H,       // Vector maximum greater-than halfword
  NEC850_VMAXGE_H,       // Vector maximum greater-than-equal halfword
  NEC850_VMINLT_H,       // Vector minimum less-than halfword
  NEC850_VMINLE_H,       // Vector minimum less-than-equal halfword
  NEC850_VMAXGT_W,       // Vector maximum greater-than word
  NEC850_VMAXGE_W,       // Vector maximum greater-than-equal word
  NEC850_VMINLT_W,       // Vector minimum less-than word
  NEC850_VMINLE_W,       // Vector minimum less-than-equal word

  NEC850_VMADSAT_H,      // Vector multiply halfword and add with saturation
  NEC850_VMADSAT_W,      // Vector multiply word and add with saturation
  NEC850_VMADRN_H,       // Vector multiply halfword and add with rounding
  NEC850_VMADRN_W,       // Vector multiply word and add with rounding

  NEC850_VMSUM_H,        // Vector multiply halfword and sum
  NEC850_VMSUM_W,        // Vector multiply word and sum

  NEC850_VMSUMAD_H,      // Vector multiply halfword and sum and add to vector register
  NEC850_VMSUMAD_W,      // Vector multiply word and sum and add to vector register
  NEC850_VMSUMADRE_H,    // Vector multiply halfword and sum and add to vector register for real part result of complex number calculation
  NEC850_VMSUMADRE_W,    // Vector multiply word and sum and add to vector register for real part result of complex number calculation
  NEC850_VMSUMADIM_H,    // Vector multiply halfword and sum and add to vector register for imaginary part result of complex number calculation
  NEC850_VMSUMADIM_W,    // Vector multiply word and sum and add to vector register for imaginary part result of complex number calculation
  NEC850_VMSUMADRN_H,    // Vector multiply halfword and sum and add to vector register with rounding
  NEC850_VBIQ_H,         // Vector multiply halfword for biquad calculation

  NEC850_PKUI8I16,       // Pack vector unsigned integer byte to vector signed integer halfword
  NEC850_PKI16I32,       // Pack vector signed integer halfword to vector signed integer word
  NEC850_PKQ15Q31,       // Pack vector Q15 fractional halfword to vector Q31 fractional word
  NEC850_PKI16UI8,       // Pack vector signed integer halfword to vector unsigned integer byte
  NEC850_PKI32I16,       // Pack vector signed integer word to vector signed integer halfword
  NEC850_PKQ31Q15,       // Pack vector Q31 fractional word to vector Q15 fractional halfword
  NEC850_PKQ30Q31,       // Pack Q31 fractional double-word to vector Q31 fractional halfword
  NEC850_PKI64I32,       // Pack signed integer double-word to vector signed integer word
  NEC850_CNVQ15Q30,      // Convert from Q15 fractional halfword to Q30 fractional double-word
  NEC850_CNVQ31Q62,      // Convert from Q31 fractional word to Q62 fractional double-word
  NEC850_CNVQ30Q15,      // Convert from Q30 fractional double-word to Q15 fractional halfword
  NEC850_CNVQ62Q31,      // Convert from Q62 fractional double-word to Q31 fractional word

  NEC850_EXPQ31,         // Extract exponent of Q31 fractional word
  NEC850_VCALCH,         // Vector calculate with halfword
  NEC850_VCALCW,         // Vector calculate with word

  NEC850_MOVV_W4,        // Move vector register to vector register

  NEC850_FLPV_S4,        // Floating-point SIMD Flip (single)
  NEC850_SHFLV_W4,       // Vector Shuffle

  NEC850_LDV_DW,         // Load Vector (Double-Word)
  NEC850_LDV_QW,         // Load Vector (Quad-Word)
  NEC850_LDV_W,          // Load Vector (Word)
  NEC850_LDVZ_H4,        // Load Vector at Even Halfword field

  NEC850_STV_DW,         // Store Vector (Double-Word)
  NEC850_STV_QW,         // Store Vector (Quad-Word)
  NEC850_STV_W,          // Store Vector (Word)
  NEC850_STVZ_H4,        // Store Vector at Even Halfword field

  NEC850_CMOVF_W4,       // Conditional move of vector register (Single precision)
  NEC850_TRFSRV_W4,      // Transfers compare result to PSW

  NEC850_ABSF_S4,        // Floating-point SIMD Absolute (single)
  NEC850_ADDF_S4,        // Floating-point SIMD Add (single)
  NEC850_DIVF_S4,        // Floating-point SIMD Divide (single)
  NEC850_MAXF_S4,        // Floating-point SIMD Maximum (single)
  NEC850_MINF_S4,        // Floating-point SIMD Minimum (single)
  NEC850_MULF_S4,        // Floating-point SIMD Multiply (single)
  NEC850_NEGF_S4,        // Floating-point SIMD Negative (single)
  NEC850_RECIPF_S4,      // Floating-point SIMD Reciprocal (single)
  NEC850_RSQRTF_S4,      // Floating-point SIMD Reciprocal Square-Root (single)
  NEC850_SQRTF_S4,       // Floating-point SIMD Square-Root (single)
  NEC850_SUBF_S4,        // Floating-point SIMD Subtract (single)

  NEC850_FMAF_S4,        // Floating-point SIMD Fused-Multiply-Add (Single)
  NEC850_FMSF_S4,        // Floating-point SIMD Fused-Multiply-Subtract (Single)
  NEC850_FNMAF_S4,       // Floating-point SIMD Fused-Negative-Multiply-Add (Single)
  NEC850_FNMSF_S4,       // Floating-point SIMD Fused-Negative-Multiply-Subtract (Single)

  NEC850_ADDSUBF_S4,     // Floating-point SIMD Add/Subtract (single)
  NEC850_ADDSUBNF_S4,    // Floating-point SIMD Add/Subtract Negative (single)
  NEC850_SUBADDF_S4,     // Floating-point SIMD Subtract/Add (single)
  NEC850_SUBADDNF_S4,    // Floating-point SIMD Subtract/Add Negative (single)

  NEC850_ADDXF_S4,       // Floating-point SIMD Add Exchange (single)
  NEC850_MULXF_S4,       // Floating-point SIMD Multiply Exchange (single)
  NEC850_SUBXF_S4,       // Floating-point SIMD Subtract Exchange (single)

  NEC850_ADDSUBNXF_S4,   // Floating-point SIMD Add/Subtract Negative Exchange (single)
  NEC850_ADDSUBXF_S4,    // Floating-point SIMD Add/Subtract Exchange (single)
  NEC850_SUBADDNXF_S4,   // Floating-point SIMD Subtract/Add Negative Exchange (single)
  NEC850_SUBADDXF_S4,    // Floating-point SIMD Subtract/Add Exchange (single)

  NEC850_ADDRF_S4,       // Floating-point SIMD Add Reduction (single)
  NEC850_MAXRF_S4,       // Floating-point SIMD Maximum Reduction (single)
  NEC850_MINRF_S4,       // Floating-point SIMD Minimum Reduction (single)
  NEC850_MULRF_S4,       // Floating-point SIMD Multiply Reduction (single)
  NEC850_SUBRF_S4,       // Floating-point SIMD Subtract Reduction (single)

  NEC850_CEILF_SUW4,     // Floating-point SIMD Convert Single to Unsigned Word, round toward positive (single)
  NEC850_CEILF_SW4,      // Floating-point SIMD Convert Single to Word, round toward positive (single)
  NEC850_CVTF_HS4,       // Floating-point SIMD Convert Half to Single (single)
  NEC850_CVTF_SH4,       // Floating-point SIMD Convert Single to Half (single)
  NEC850_CVTF_SUW4,      // Floating-point SIMD Convert Single to Unsigned Word (single)
  NEC850_CVTF_SW4,       // Floating-point SIMD Convert Single to Word (single)
  NEC850_CVTF_UWS4,      // Floating-point SIMD Convert Unsigned Word to Single (single)
  NEC850_CVTF_WS4,       // Floating-point SIMD Convert Word to Single (single)
  NEC850_FLOORF_SUW4,    // Floating-point SIMD Convert Single to Unsigned Word, round toward negative (single)
  NEC850_FLOORF_SW4,     // Floating-point SIMD Convert Single to Word, round toward negative (single)
  NEC850_ROUNDF_SUW4,    // Floating-point SIMD Convert Single to Unsigned Word, round to nearest (single)
  NEC850_ROUNDF_SW4,     // Floating-point SIMD Convert Single to Word, round to nearest (single)
  NEC850_TRNCF_SUW4,     // Floating-point SIMD Convert Single to Unsigned Word, round toward zero (single)
  NEC850_TRNCF_SW4,      // Floating-point SIMD Convert Single to Word, round toward zero (single)

  NEC850_CMPF_S4,        // Floating-point SIMD Comparison (single)

  NEC850_LAST_INSTRUCTION
};

#endif
