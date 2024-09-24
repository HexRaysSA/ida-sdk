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
HPPA_null = 0,     // Unknown Operation

HPPA_add,          // Add
HPPA_addb,         // Add and Branch
HPPA_addi,         // Add to Immediate
HPPA_addib,        // Add Immediate and Branch
HPPA_addil,        // Add to Immediate Left
HPPA_and,          // AND
HPPA_andcm,        // AND complement
HPPA_b,            // Branch
HPPA_bb,           // Branch on Bit
HPPA_be,           // Branch External
HPPA_blr,          // Branch and Link Register
HPPA_break,        // Break
HPPA_bv,           // Branch Vectored
HPPA_bve,          // Branch Vectored External
HPPA_cldd,         // Coprocessor Load Doubleword
HPPA_cldw,         // Coprocessor Load Word
HPPA_clrbts,       // Clear Branch Target Stack
HPPA_cmpb,         // Compare and Branch
HPPA_cmpclr,       // Compare and Clear
HPPA_cmpib,        // Compare Immediate and Branch
HPPA_cmpiclr,      // Compare Immediate and Clear
HPPA_copr,         // Coprocessor Operation
HPPA_cstd,         // Coprocessor Store Doubleword
HPPA_cstw,         // Coprocessor Store Word
HPPA_dcor,         // Decimal Correct
HPPA_depd,         // Deposit Doubleword
HPPA_depdi,        // Deposit Doubleword Immediate
HPPA_depw,         // Deposit Word
HPPA_depwi,        // Deposit Word Immediate
HPPA_diag,         // Diagnose
HPPA_ds,           // Divide Step
HPPA_extrd,        // Extract Doubleword
HPPA_extrw,        // Extract Word
HPPA_fdc,          // Flush Data Cache
HPPA_fdce,         // Flush Data Cache Entry
HPPA_fic,          // Flush Instruction Cache
HPPA_fice,         // Flush Instruction Cache Entry
HPPA_hadd,         // Halfword Parallel Add
HPPA_havg,         // Halfword Parallel Average
HPPA_hshl,         // Halfword Parallel Shift Left
HPPA_hshladd,      // Halfword Parallel Shift Left and Add
HPPA_hshr,         // Halfword Parallel Shift Right
HPPA_hshradd,      // Halfword Parallel Shift Right and Add
HPPA_hsub,         // Halfword Parallel Subtract
HPPA_idtlbt,       // Insert Data TLB Translation
HPPA_iitlbt,       // Insert Instruction TLB Translation
HPPA_lci,          // Load Coherence Index
HPPA_ldb,          // Load Byte
HPPA_ldcd,         // Load and Clear Doubleword
HPPA_ldcw,         // Load and Clear Word
HPPA_ldd,          // Load Doubleword
HPPA_ldda,         // Load Doubleword Absolute
HPPA_ldh,          // Load Halfword
HPPA_ldil,         // Load Immediate Left
HPPA_ldo,          // Load Offset
HPPA_ldsid,        // Load Space Identifier
HPPA_ldw,          // Load Word
HPPA_ldwa,         // Load Word Absolute
HPPA_lpa,          // Load Physical Address
HPPA_mfctl,        // Move From Control Register
HPPA_mfia,         // Move From Instruction Address
HPPA_mfsp,         // Move From Space Register
HPPA_mixh,         // Mix Halfwords
HPPA_mixw,         // Mix Words
HPPA_movb,         // Move and Branch
HPPA_movib,        // Move Immediate and Branch
HPPA_mtctl,        // Move To Control Register
HPPA_mtsarcm,      // Move To Shift Amount Register Complement
HPPA_mtsm,         // Move To System Mask
HPPA_mtsp,         // Move To Space Register
HPPA_or,           // Inclusive OR
HPPA_pdc,          // Purge Data Cache
HPPA_pdtlb,        // Purge Data TLB
HPPA_pdtlbe,       // Purge Data TLB Entry
HPPA_permh,        // Permute Halfwords
HPPA_pitlb,        // Purge Instruction TLB
HPPA_pitlbe,       // Purge Instruction TLB Entry
HPPA_popbts,       // Pop Branch Target Stack
HPPA_probe,        // Probe Access
HPPA_probei,       // Probe Access Immediate
HPPA_pushbts,      // Push Branch Target Stack
HPPA_pushnom,      // Push Nominated
HPPA_rfi,          // Return From Interruption
HPPA_rsm,          // Reset System Mask
HPPA_shladd,       // Shift Left and Add
HPPA_shrpd,        // Sihft Right Pair Doubleword
HPPA_shrpw,        // Sihft Right Pair Word
HPPA_spop0,        // Special Operation Zero
HPPA_spop1,        // Special Operation One
HPPA_spop2,        // Special Operation Two
HPPA_spop3,        // Special Operation Three
HPPA_ssm,          // Set System Mask
HPPA_stb,          // Store Byte
HPPA_stby,         // Store Bytes
HPPA_std,          // Store Doubleword
HPPA_stda,         // Store Doubleword Absolute
HPPA_stdby,        // Store Doubleword Bytes
HPPA_sth,          // Store Halfword
HPPA_stw,          // Store Word
HPPA_stwa,         // Store Word Absolute
HPPA_sub,          // Subtract
HPPA_subi,         // Subtract from Immediate
HPPA_sync,         // Synchronize Caches
HPPA_syncdma,      // Synchronize DMA
HPPA_uaddcm,       // Unit Add Complement
HPPA_uxor,         // Unit XOR
HPPA_xor,          // Exclusive OR

// Floating point instructions

HPPA_fabs,         // Floating-Point Absolute Value
HPPA_fadd,         // Floating-Point Add
HPPA_fcmp,         // Floating-Point Compare
HPPA_fcnv,         // Floating-Point Convert
HPPA_fcpy,         // Floating-Point Copy
HPPA_fdiv,         // Floating-Point Divide
HPPA_fid,          // Floating-Point Identity
HPPA_fldd,         // Floating-Point Load Doubleword
HPPA_fldw,         // Floating-Point Load Word
HPPA_fmpy,         // Floating-Point Multiply
HPPA_fmpyadd,      // Floating-Point Multiply/Add
HPPA_fmpyfadd,     // Floating-Point Multiply Fused Add
HPPA_fmpynfadd,    // Floating-Point Multiply Negate Fused Add
HPPA_fmpysub,      // Floating-Point Multiply/Subtract
HPPA_fneg,         // Floating-Point Negate
HPPA_fnegabs,      // Floating-Point Negate Absolute Value
HPPA_frem,         // Floating-Point Remainder
HPPA_frnd,         // Floating-Point Round to Integer
HPPA_fsqrt,        // Floating-Point Square Root
HPPA_fstd,         // Floating-Point Store Doubleword
HPPA_fstw,         // Floating-Point Store Word
HPPA_fsub,         // Floating-Point Subtract
HPPA_ftest,        // Floating-Point Test
HPPA_xmpyu,        // Fixed-Point Multiply Unsigned

// Performance Monitor Coprocessor

HPPA_pmdis,        // Performance Monitor Disable
HPPA_pmenb,        // Performance Monitor Enable

// Macros

HPPA_call,         // Call Subroutine
HPPA_ret,          // Return From Subroutine
HPPA_shld,         // Shift Left Doubleword
HPPA_shlw,         // Shift Left Word
HPPA_shrd,         // Shift Right Doubleword
HPPA_shrw,         // Shift Right Word
HPPA_ldi,          // Load Immediate
HPPA_copy,         // Copy Register
HPPA_mtsar,        // Move To %SAR
HPPA_nop,          // No Operation

HPPA_last,

};

#endif
