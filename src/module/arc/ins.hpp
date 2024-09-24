
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INS_HPP
#define __INS_HPP

extern instruc_t Instructions[];

enum nameNum
{

  ARC_null = 0,                 // Unknown Operation

  ARC_ld,                       // Load
  ARC_lr,                       // Load from auxiliary register
  ARC_st,                       // Store
  ARC_sr,                       // Store to auxiliary register
  ARC_store_instructions = ARC_sr,
  ARC_flag,                     // Set flags
  ARC_asr,                      // Arithmetic shift right
  ARC_lsr,                      // Logical shift right
  ARC_sexb,                     // Sign extend byte
  ARC_sexw,                     // Sign extend word
  ARC_sexh = ARC_sexw,
  ARC_extb,                     // Zero extend byte
  ARC_extw,                     // Zero extend word
  ARC_exth = ARC_extw,
  ARC_ror,                      // Rotate right
  ARC_rrc,                      // Rotate right through carry
  ARC_b,                        // Branch
  ARC_bl,                       // Branch and link
  ARC_lp,                       // Zero-overhead loop setup
  ARC_j,                        // Jump
  ARC_jl,                       // Jump and link
  ARC_add,                      // Add
  ARC_adc,                      // Add with carry
  ARC_sub,                      // Subtract
  ARC_sbc,                      // Subtract with carry
  ARC_and,                      // Logical bitwise AND
  ARC_or,                       // Logical bitwise OR
  ARC_bic,                      // Logical bitwise AND with invert
  ARC_xor,                      // Logical bitwise exclusive-OR

  // pseudo instructions
  ARC_mov,                      // Move
  ARC_nop,                      // No operation
  ARC_lsl,                      // Logical shift left
  ARC_rlc,                      // Rotate left through carry

  // arc7
  ARC_brk,                      // Breakpoint
  ARC_sleep,                    // Sleep until interrupt or restart

  // arc8
  ARC_swi,                      // Software interrupt

  // extra optional instrutions
  ARC_asl,                      // Arithmetic shift left
  ARC_mul64,                    // Signed 32x32 multiply
  ARC_mulu64,                   // Unsigned 32x32 multiply
  ARC_max,                      // Maximum of two signed integers
  ARC_min,                      // Minimum of two signed integers
  ARC_swap,                     // Exchange upper and lower 16 bits
  ARC_norm,                     // Normalize (find-first-bit)

  // ARCompact instructions
  ARC_bbit0,                    // Branch if bit cleared to 0
  ARC_bbit1,                    // Branch if bit set to 1
  ARC_br,                       // Branch on compare
  ARC_pop,                      // Restore register value from stack
  ARC_push,                     // Store register value on stack

  ARC_abs,                      // Absolute value
  ARC_add1,                     // Add with left shift by 1 bit
  ARC_add2,                     // Add with left shift by 2 bits
  ARC_add3,                     // Add with left shift by 3 bits
  ARC_bclr,                     // Clear specified bit (to 0)
  ARC_bmsk,                     // Bit Mask
  ARC_bset,                     // Set specified bit (to 1)
  ARC_btst,                     // Test value of specified bit
  ARC_bxor,                     // Bit XOR
  ARC_cmp,                      // Compare
  ARC_ex,                       // Atomic Exchange
  ARC_mpy,                      // Signed 32x32 multiply (low)
  ARC_mpyh,                     // Signed 32x32 multiply (high)
  ARC_mpym = ARC_mpyh,
  ARC_mpyhu,                    // Unsigned 32x32 multiply (high)
  ARC_mpyhm = ARC_mpyhu,
  ARC_mpyu,                     // Unsigned 32x32 multiply (low)
  ARC_neg,                      // Negate
  ARC_not,                      // Logical bit inversion
  ARC_rcmp,                     // Reverse Compare
  ARC_rsub,                     // Reverse Subtraction
  ARC_rtie,                     // Return from Interrupt/Exception
  ARC_sub1,                     // Subtract with left shift by 1 bit
  ARC_sub2,                     // Subtract with left shift by 2 bits
  ARC_sub3,                     // Subtract with left shift by 3 bits
  ARC_sync,                     // Synchronize
  ARC_trap,                     // Raise an exception
  ARC_tst,                      // Test
  ARC_unimp,                    // Unimplemented instruction

  ARC_abss,                     // Absolute and saturate
  ARC_abssw,                    // Absolute and saturate of word
  ARC_abssh = ARC_abssw,
  ARC_adds,                     // Add and saturate
  ARC_addsdw,                   // Add and saturate dual word
  ARC_asls,                     // Arithmetic shift left and saturate
  ARC_asrs,                     // Arithmetic shift right and saturate
  ARC_divaw,                    // Division assist
  ARC_negs,                     // Negate and saturate
  ARC_negsw,                    // Negate and saturate of word
  ARC_negsh = ARC_negsw,
  ARC_normw,                    // Normalize to 16 bits
  ARC_normh = ARC_normw,
  ARC_rnd16,                    // Round to word
  ARC_rndh = ARC_rnd16,
  ARC_sat16,                    // Saturate to word
  ARC_sath = ARC_sat16,
  ARC_subs,                     // Subtract and saturate
  ARC_subsdw,                   // Subtract and saturate dual word

  // mac d16
  ARC_muldw,
  ARC_muludw,
  ARC_mulrdw,
  ARC_macdw,
  ARC_macudw,
  ARC_macrdw,
  ARC_msubdw,

  // 32x16 MUL/MAC
  ARC_mululw,
  ARC_mullw,
  ARC_mulflw,
  ARC_maclw,
  ARC_macflw,
  ARC_machulw,
  ARC_machlw,
  ARC_machflw,
  ARC_mulhlw,
  ARC_mulhflw,

  // Major 6 compact insns
  ARC_acm,
  ARC_addqbs,
  ARC_avgqb,
  ARC_clamp,
  ARC_daddh11,
  ARC_daddh12,
  ARC_daddh21,
  ARC_daddh22,
  ARC_dexcl1,
  ARC_dexcl2,
  ARC_dmulh11,
  ARC_dmulh12,
  ARC_dmulh21,
  ARC_dmulh22,
  ARC_dsubh11,
  ARC_dsubh12,
  ARC_dsubh21,
  ARC_dsubh22,
  ARC_drsubh11,
  ARC_drsubh12,
  ARC_drsubh21,
  ARC_drsubh22,
  ARC_fadd,
  ARC_fsadd = ARC_fadd,
  ARC_fmul,
  ARC_fsmul = ARC_fmul,
  ARC_fsub,
  ARC_fssub = ARC_fsub,
  ARC_fxtr,
  ARC_iaddr,
  ARC_mpyqb,
  ARC_sfxtr,
  ARC_pkqb,
  ARC_upkqb,
  ARC_xpkqb,

  // ARCv2 only major 4 instructions
  ARC_mpyw,                     // Signed 16x16 multiply
  ARC_mpyuw,                    // Unsigned 16x16 multiply
  ARC_bi,                       // Branch indexed
  ARC_bih,                      // Branch indexed half-word
  ARC_ldi,                      // Load indexed
  ARC_aex,                      // Exchange with auxiliary register
  ARC_bmskn,                    // Bit mask negated
  ARC_seteq,                    // Set if equal
  ARC_setne,                    // Set if not equal
  ARC_setlt,                    // Set if less than
  ARC_setge,                    // Set if greater or equal
  ARC_setlo,                    // Set if lower than
  ARC_seths,                    // Set if higher or same
  ARC_setle,                    // Set if less than or equal
  ARC_setgt,                    // Set if greater than

  ARC_rol,                      // Rotate left
  ARC_llock,                    // Load locked
  ARC_scond,                    // Store conditional

  ARC_seti,                     // Set interrupt enable and priority level
  ARC_clri,                     // Cler and get interrupt enable and priority level

  // ARCv2 compact prolog / epilog instructions
  ARC_enter,                    // Function prologue sequence
  ARC_leave,                    // Function epilogue sequence

  // ARCv2 32-bit extension major 5 DOP instructions
  ARC_div,                      // Signed integer divsion
  ARC_divu,                     // Unsigned integer divsion
  ARC_rem,                      // Signed integer remainder
  ARC_remu,                     // Unsigned integer remainder
  ARC_asrsr,                    // Shift right rounding and saturating
  ARC_valgn2h,                  // Two-way 16-bit vector align
  ARC_setacc,                   // Set the accumulator
  ARC_mac,                      // Signed 32x32 multiply accumulate
  ARC_macu,                     // Unsigned 32x32 multiply accumulate
  ARC_dmpyh,                    // Sum of dual signed 16x16 multiplication
  ARC_dmpyhu,                   // Sum of dual unsigned 16x16 multiplication
  ARC_dmach,                    // Dual signed 16x16 multiply accumulate
  ARC_dmachu,                   // Dual unsigned 16x16 multiply accumulate
  ARC_vadd2h,                   // Dual 16-bit addition
  ARC_vadds2h,                  // Dual 16-bit saturating addition
  ARC_vsub2h,                   // Dual 16-bit subtraction
  ARC_vsubs2h,                  // Dual 16-bit saturating subtraction
  ARC_vaddsub2h,                // Dual 16-bit addition/subtraction
  ARC_vaddsubs2h,               // Dual 16-bit saturating addition/subtraction
  ARC_vsubadd2h,                // Dual 16-bit subtraction/addition
  ARC_vsubadds2h,               // Dual 16-bit saturating subtraction/addition
  ARC_mpyd,                     // Signed 32x32 multiply (wide)
  ARC_mpydu,                    // Unsigned 32x32 multiply (wide)
  ARC_macd,                     // Signed 32x32 multiply accumulate (wide)
  ARC_macdu,                    // Unsigned 32x32 multiply accumulate (wide)
  ARC_vmpy2h,                   // Dual signed 16x16 multiply (wide)
  ARC_vmpy2hf,                  // Dual 16x16 saturating fractional multiply
  ARC_vmpy2hu,                  // Dual unsigned 16x16 multiply (wide)
  ARC_vmpy2hfr,                 // Dual 16x16 saturating rounded fractional multiply
  ARC_vmac2h,                   // Dual signed 16x16 multiply (wide)
  ARC_vmac2hf,                  // Dual 16x16 saturating fractional multiply
  ARC_vmac2hu,                  // Dual unsigned 16x16 multiply (wide)
  ARC_vmac2hfr,                 // Dual 16x16 saturating rounded fractional multiply
  ARC_vmpy2hwf,                 // Dual 16x16 saturating fractional multiply (wide)
  ARC_vasl2h,                   // Dual 16-bit arithmetic shift left
  ARC_vasls2h,                  // Dual 16-bit saturating arithmetic shift left
  ARC_vasr2h,                   // Dual 16-bit arithmetic shift right
  ARC_vasrs2h,                  // Dual 16-bit saturating arithmetic shift right
  ARC_vlsr2h,                   // Dual 16-bit logical shift right
  ARC_vasrsr2h,                 // Dual 16-bit saturating rounded arithmetic shift right
  ARC_vadd4b,                   // Quad 8-bit addition
  ARC_vmax2h,                   // Dual 16-bit maximum
  ARC_vsub4b,                   // Quad 8-bit subtraction
  ARC_vmin2h,                   // Dual 16-bit minimum
  ARC_adcs,                     // Signed saturating addition with carry in
  ARC_sbcs,                     // Signed saturating subtraction with carry in
  ARC_dmpyhwf,                  // Fractional saturating sum of dual 16x16 signed fractional multiply
  ARC_vpack2hl,                 // Compose lower 16-bits
  ARC_vpack2hm,                 // Compose upper 16-bits
  ARC_dmpyhf,                   // Saturating sum of dual 16x16 signed fractional multiply
  ARC_dmpyhfr,                  // Saturating rounded sum of dual 16x16 signed fractional multiply
  ARC_dmachf,                   // Saturating sum of dual 16x16 signed fractional multiply accumulate
  ARC_dmachfr,                  // Saturating rounded sum of dual 16x16 signed fractional multiply accumulate
  ARC_vperm,                    // Byte permutation with zero or sign extension
  ARC_bspush,                   // Bitstream push

  // ARCv2 32-bit extension major 5 SOP instructions
  ARC_swape,                    // Swap byte ordering
  ARC_lsl16,                    // Logical shift left by 16 bits
  ARC_lsr16,                    // Logical shift right by 16 bits
  ARC_asr16,                    // Arithmetic shift right by 16 bits
  ARC_asr8,                     // Arithmetic shift right by 8 bits
  ARC_lsr8,                     // Logical shift right by 8 bits
  ARC_lsl8,                     // Logical shift left by 8 bits
  ARC_rol8,                     // Rotate left by 8 bits
  ARC_ror8,                     // Rotate right by 8 bits
  ARC_ffs,                      // Find first set bit
  ARC_fls,                      // Find last set bit

  ARC_getacc,                   // Get accumulator
  ARC_normacc,                  // Normalize accumulator
  ARC_satf,                     // Saturate according to flags
  ARC_vpack2hbl,                // Pack lower bytes into lower 16 bits
  ARC_vpack2hbm,                // Pack upper bytes into upper 16 bits
  ARC_vpack2hblf,               // Pack upper bytes into lower 16 bits
  ARC_vpack2hbmf,               // Pack lower bytes into upper 16 bits
  ARC_vext2bhlf,                // Pack lower 2 bytes into upper byte of 16 bits each
  ARC_vext2bhmf,                // Pack upper 2 bytes into upper byte of 16 bits each
  ARC_vrep2hl,                  // Repeat lower 16 bits
  ARC_vrep2hm,                  // Repeat upper 16 bits
  ARC_vext2bhl,                 // Pack lower 2 bytes into zero extended 16 bits
  ARC_vext2bhm,                 // Pack upper 2 bytes into zero extended 16 bits
  ARC_vsext2bhl,                // Pack lower 2 bytes into sign extended 16 bits
  ARC_vsext2bhm,                // Pack upper 2 bytes into sign extended 16 bits
  ARC_vabs2h,                   // Dual 16-bit absolute value
  ARC_vabss2h,                  // Dual saturating 16-bit absolute value
  ARC_vneg2h,                   // Dual 16-bit negation
  ARC_vnegs2h,                  // Dual saturating 16-bit negation
  ARC_vnorm2h,                  // Dual 16-bit normalization
  ARC_bspeek,                   // Bitstream peek
  ARC_bspop,                    // Bitstream pop
  ARC_sqrt,                     // Integer square root
  ARC_sqrtf,                    // Fractional square root

  // ARCv2 32-bit extension major 5 ZOP instructions
  ARC_aslacc,                   // Arithmetic shift of accumulator
  ARC_aslsacc,                  // Saturating arithmetic shift of accumulator
  ARC_flagacc,                  // Copy accumulator flags to status32 register
  ARC_modif,                    // Update address pointer

  // ARCv2 32-bit extension major 6 DOP instructions
  ARC_cmpyhnfr,                 // Fractional 16+16 bit complex saturating rounded unshifted multiply
  ARC_cmpyhfr,                  // Fractional 16+16 bit complex saturating rounded multiply
  ARC_cmpychfr,                 // Fractional 16+16 bit complex saturating rounded conjugated multiply
  ARC_vmsub2hf,                 // Dual 16x16 saturating fractional multiply subtract
  ARC_vmsub2hfr,                // Dual 16x16 saturating rounded fractional multiply subtract
  ARC_cmpychnfr,                // Fractional 16+16 bit complex saturating rounded unshifted conjugated multiply
  ARC_cmachnfr,                 // Fractional 16+16 bit complex saturating rounded unshifted multiply accumulate
  ARC_cmachfr,                  // Fractional 16+16 bit complex saturating rounded unshifted accumulate
  ARC_cmacchnfr,                // Fractional 16+16 bit complex saturating rounded conjugated multiply accumulate
  ARC_cmacchfr,                 // Fractional 16+16 bit complex saturating rounded unshifted conjugated multiply accumulate
  ARC_mpyf,                     // Signed 32-bit fractional saturating multiply
  ARC_mpyfr,                    // Signed 32-bit fractional saturating rounded multiply
  ARC_macf,                     // Signed 32-bit fractional saturating multiply accumulate
  ARC_macfr,                    // Signed 32-bit fractional saturating rounded multiply accumulate
  ARC_msubf,                    // Signed 32-bit fractional saturating multiply subtract
  ARC_msubfr,                   // Signed 32-bit fractional saturating rounded multiply subtract
  ARC_divf,                     // Signed 32-bit fractional division
  ARC_vmac2hnfr,                // Dual signed 16-bit fractional saturating rounded multiply accumulate
  ARC_vmsub2hnfr,               // Dual signed 16-bit fractional saturating rounded multiply subtract
  ARC_mpydf,                    // Signed 32-bit fractional multiply (wide)
  ARC_macdf,                    // Signed 32-bit fractional multiply accumulate (wide)
  ARC_msubwhfl,                 // Signed 32 x 16 (lower) fractional saturating multiply subtract
  ARC_msubdf,                   // Signed 32-bit fractional multiply subtract (wide)
  ARC_dmpyhbl,                  // Dual 16x8 signed multiply with lower two bytes
  ARC_dmpyhbm,                  // Dual 16x8 signed multiply with upper two bytes
  ARC_dmachbl,                  // Dual 16x8 signed multiply accumulate with lower two bytes
  ARC_dmachbm,                  // Dual 16x8 signed multiply accumulate with upper two bytes
  ARC_msubwhflr,                // Signed 32 x 16 (lower) fractional saturating rounded multiply subtract
  ARC_cmpyhfmr,                 // Fractional 16+16 bit complex x 16bit real (upper) saturating rounded multiply
  ARC_cbflyhf0r,                // Fractional 16+16 bit complex FFT butterfly, first half
  ARC_mpywhl,                   // Signed 32 x 16 (lower) multiply
  ARC_macwhl,                   // Signed 32 x 16 (lower) multiply accumulate
  ARC_mpywhul,                  // Unsigned 32 x 16 (lower) multiply
  ARC_macwhul,                  // Unsigned 32 x 16 (lower) multiply accumulate
  ARC_mpywhfm,                  // Signed 32 x 16 (upper) fractional saturating multiply
  ARC_mpywhfmr,                 // Signed 32 x 16 (upper) fractional saturating rounded multiply
  ARC_macwhfm,                  // Signed 32 x 16 (upper) fractional saturating multiply accumulate
  ARC_macwhfmr,                 // Signed 32 x 16 (upper) fractional saturating rounded multiply accumulate
  ARC_mpywhfl,                  // Signed 32 x 16 (lower) fractional saturating multiply
  ARC_mpywhflr,                 // Signed 32 x 16 (lower) fractional saturating rounded multiply
  ARC_macwhfl,                  // Signed 32 x 16 (lower) fractional saturating multiply accumulate
  ARC_macwhflr,                 // Signed 32 x 16 (lower) fractional saturating rounded multiply accumulate
  ARC_macwhkl,                  // Signed 32 x 16 (lower) 16-bit shifted multiply accumulate
  ARC_macwhkul,                 // Unsigned 32 x 16 (lower) 16-bit shifted multiply accumulate
  ARC_mpywhkl,                  // Signed 32 x 16 (lower) 16-bit shifted multiply
  ARC_mpywhkul,                 // Unsigned 32 x 16 (lower) 16-bit shifted multiply
  ARC_msubwhfm,                 // Signed 32 x 16 (upper) fractional saturating multiply subtract
  ARC_msubwhfmr,                // Signed 32 x 16 (upper) fractional saturating rounded multiply subtract

  // ARCv2 32-bit extension major 6 SOP instructions
  ARC_cbflyhf1r,                // Fractional 16+16 bit complex FFT butterfly, second half

  // ARCv2 FPU instructions
  ARC_fscmp,                    // Single precision floating point compare
  ARC_fscmpf,                   // Single precision floating point compare (IEEE 754 flag generation)
  ARC_fsmadd,                   // Single precision floating point fused multiply add
  ARC_fsmsub,                   // Single precision floating point fused multiply subtract
  ARC_fsdiv,                    // Single precision floating point division
  ARC_fcvt32,                   // Single precision floating point / integer conversion
  ARC_fssqrt,                   // Single precision floating point square root

  // ARCv2 jump / execute indexed instructions
  ARC_jli,                      // Jump and link indexed
  ARC_ei,                       // Execute indexed

  ARC_kflag,                    // Set kernel flags
  ARC_wevt,                     // Enter sleep state

  ARC_last,
};

#endif
