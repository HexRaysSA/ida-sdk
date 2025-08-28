/* -
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"

/*
#define u       1
#define c       2
#define o1(x)   ((x & u) ? CF_USE1 : 0) | (x & c) ? CF_CHG1 : 0))
#define o2(x)   ((x & u) ? CF_USE2 : 0) | (x & c) ? CF_CHG2 : 0))
#define o3(x)   ((x & u) ? CF_USE3 : 0) | (x & c) ? CF_CHG3 : 0))
#define OPS(x,y,z,others) (o1(x) | o2(y) | o3(z) | others)
*/

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  { "add",        CF_USE1|CF_USE2|CF_CHG3         },      // Add
  { "addb",       CF_USE1|CF_USE2|CF_CHG2|CF_USE3 },      // Add and Branch
  { "addi",       CF_USE1|CF_USE2|CF_CHG3         },      // Add to Immediate
  { "addib",      CF_USE1|CF_USE2|CF_CHG2|CF_USE3 },      // Add Immediate and Branch
  { "addil",      CF_USE1|CF_USE2                 },      // Add to Immediate Left
  { "and",        CF_USE1|CF_USE2|CF_CHG3         },      // AND
  { "andcm",      CF_USE1|CF_USE2|CF_CHG3         },      // AND complement
  { "b",          CF_USE1|CF_CHG2                 },      // Branch
  { "bb",         CF_USE1|CF_USE2|CF_USE3         },      // Branch on Bit
  { "be",         CF_USE1                         },      // Branch External
  { "blr",        CF_USE1|CF_CHG2|CF_CALL         },      // Branch and Link Register
  { "break",      CF_USE1|CF_USE2                 },      // Break
  { "bv",         CF_USE1                         },      // Branch Vectored
  { "bve",        CF_USE1                         },      // Branch Vectored External
  { "cldd",       CF_USE1|CF_CHG2                 },      // Coprocessor Load Doubleword
  { "cldw",       CF_USE1|CF_CHG2                 },      // Coprocessor Load Word
  { "clrbts",     0                               },      // Clear Branch Target Stack
  { "cmpb",       CF_USE1|CF_USE2|CF_USE3         },      // Compare and Branch
  { "cmpclr",     CF_USE1|CF_USE2|CF_CHG3         },      // Compare and Clear
  { "cmpib",      CF_USE1|CF_USE2|CF_USE3         },      // Compare Immediate and Branch
  { "cmpiclr",    CF_USE1|CF_USE2|CF_CHG3         },      // Compare Immediate and Clear
  { "copr",       0                               },      // Coprocessor Operation
  { "cstd",       CF_USE1|CF_CHG2                 },      // Coprocessor Store Doubleword
  { "cstw",       CF_USE1|CF_CHG2                 },      // Coprocessor Store Word
  { "dcor",       CF_USE1|CF_CHG2                 },      // Decimal Correct
  { "depd",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Deposit Doubleword
  { "depdi",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Deposit Doubleword Immediate
  { "depw",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Deposit Word
  { "depwi",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Deposit Word Immediate
  { "diag",       CF_USE1                         },      // Diagnose
  { "ds",         CF_USE1|CF_USE2|CF_CHG3         },      // Divide Step
  { "extrd",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Extract Doubleword
  { "extrw",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Extract Word
  { "fdc",        CF_USE1                         },      // Flush Data Cache
  { "fdce",       CF_USE1                         },      // Flush Data Cache Entry
  { "fic",        CF_USE1                         },      // Flush Instruction Cache
  { "fice",       CF_USE1                         },      // Flush Instruction Cache Entry
  { "hadd",       CF_USE1|CF_USE2|CF_CHG3         },      // Halfword Parallel Add
  { "havg",       CF_USE1|CF_USE2|CF_CHG3         },      // Halfword Parallel Average
  { "hshl",       CF_USE1|CF_USE2|CF_CHG3         },      // Halfword Parallel Shift Left
  { "hshladd",    CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Halfword Parallel Shift Left and Add
  { "hshr",       CF_USE1|CF_USE2|CF_CHG3         },      // Halfword Parallel Shift Right
  { "hshradd",    CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Halfword Parallel Shift Right and Add
  { "hsub",       CF_USE1|CF_USE2|CF_CHG3         },      // Halfword Parallel Subtract
  { "idtlbt",     CF_USE1|CF_USE2                 },      // Insert Data TLB Translation
  { "iitlbt",     CF_USE1|CF_USE2                 },      // Insert Instruction TLB Translation
  { "lci",        CF_USE1|CF_CHG2                 },      // Load Coherence Index
  { "ldb",        CF_USE1|CF_CHG2                 },      // Load Byte
  { "ldcd",       CF_USE1|CF_CHG2                 },      // Load and Clear Doubleword
  { "ldcw",       CF_USE1|CF_CHG2                 },      // Load and Clear Word
  { "ldd",        CF_USE1|CF_CHG2                 },      // Load Doubleword
  { "ldda",       CF_USE1|CF_CHG2                 },      // Load Doubleword Absolute
  { "ldh",        CF_USE1|CF_CHG2                 },      // Load Halfword
  { "ldil",       CF_USE1|CF_CHG2                 },      // Load Immediate Left
  { "ldo",        CF_USE1|CF_CHG2                 },      // Load Offset
  { "ldsid",      CF_USE1|CF_CHG2                 },      // Load Space Identifier
  { "ldw",        CF_USE1|CF_CHG2                 },      // Load Word
  { "ldwa",       CF_USE1|CF_CHG2                 },      // Load Word Absolute
  { "lpa",        CF_USE1|CF_CHG2                 },      // Load Physical Address
  { "mfctl",      CF_USE1|CF_CHG2                 },      // Move From Control Register
  { "mfia",       CF_CHG1                         },      // Move From Instruction Address
  { "mfsp",       CF_USE1|CF_CHG2                 },      // Move From Space Register
  { "mixh",       CF_USE1|CF_USE2|CF_CHG3         },      // Mix Halfwords
  { "mixw",       CF_USE1|CF_USE2|CF_CHG3         },      // Mix Words
  { "movb",       CF_USE1|CF_CHG2|CF_USE3         },      // Move and Branch
  { "movib",      CF_USE1|CF_CHG2|CF_USE3         },      // Move Immediate and Branch
  { "mtctl",      CF_USE1|CF_CHG2                 },      // Move To Control Register
  { "mtsarcm",    CF_USE1                         },      // Move To Shift Amount Register Complement
  { "mtsm",       CF_USE1                         },      // Move To System Mask
  { "mtsp",       CF_USE1|CF_CHG2                 },      // Move To Space Register
  { "or",         CF_USE1|CF_USE2|CF_CHG3         },      // Inclusive OR
  { "pdc",        CF_USE1                         },      // Purge Data Cache
  { "pdtlb",      CF_USE1                         },      // Purge Data TLB
  { "pdtlbe",     CF_USE1                         },      // Purge Data TLB Entry
  { "permh",      CF_USE1|CF_CHG2                 },      // Permute Halfwords
  { "pitlb",      CF_USE1                         },      // Purge Instruction TLB
  { "pitlbe",     CF_USE1                         },      // Purge Instruction TLB Entry
  { "popbts",     CF_USE1                         },      // Pop Branch Target Stack
  { "probe",      CF_USE1|CF_USE2|CF_CHG3         },      // Probe Access
  { "probei",     CF_USE1|CF_USE2|CF_CHG3         },      // Probe Access Immediate
  { "pushbts",    CF_USE1                         },      // Push Branch Target Stack
  { "pushnom",    0                               },      // Push Nominated
  { "rfi",        0                               },      // Return From Interruption
  { "rsm",        CF_USE1|CF_CHG2                 },      // Reset System Mask
  { "shladd",     CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Shift Left and Add
  { "shrpd",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Sihft Right Pair Doubleword
  { "shrpw",      CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Sihft Right Pair Word
  { "spop0",      0                               },      // Special Operation Zero
  { "spop1",      CF_CHG1                         },      // Special Operation One
  { "spop2",      CF_USE1                         },      // Special Operation Two
  { "spop3",      CF_USE1|CF_USE2                 },      // Special Operation Three
  { "ssm",        CF_USE1|CF_CHG2                 },      // Set System Mask
  { "stb",        CF_USE1|CF_CHG2                 },      // Store Byte
  { "stby",       CF_USE1|CF_CHG2                 },      // Store Bytes
  { "std",        CF_USE1|CF_CHG2                 },      // Store Doubleword
  { "stda",       CF_USE1|CF_CHG2                 },      // Store Doubleword Absolute
  { "stdby",      CF_USE1|CF_CHG2                 },      // Store Doubleword Bytes
  { "sth",        CF_USE1|CF_CHG2                 },      // Store Halfword
  { "stw",        CF_USE1|CF_CHG2                 },      // Store Word
  { "stwa",       CF_USE1|CF_CHG2                 },      // Store Word Absolute
  { "sub",        CF_USE1|CF_USE2|CF_CHG3         },      // Subtract
  { "subi",       CF_USE1|CF_USE2|CF_CHG3         },      // Subtract from Immediate
  { "sync",       0                               },      // Synchronize Caches
  { "syncdma",    0                               },      // Synchronize DMA
  { "uaddcm",     CF_USE1|CF_USE2|CF_CHG3         },      // Unit Add Complement
  { "uxor",       CF_USE1|CF_USE2|CF_CHG3         },      // Unit XOR
  { "xor",        CF_USE1|CF_USE2|CF_CHG3         },      // Exclusive OR

  // Floating point instructions

  { "fabs",       CF_USE1|CF_CHG2                 },      // Floating-Point Absolute Value
  { "fadd",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Add
  { "fcmp",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Compare
  { "fcnv",       CF_USE1|CF_CHG2                 },      // Floating-Point Convert
  { "fcpy",       CF_USE1|CF_CHG2                 },      // Floating-Point Copy
  { "fdiv",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Divide
  { "fid",        0                               },      // Floating-Point Identity
  { "fldd",       CF_USE1|CF_CHG2                 },      // Floating-Point Load Doubleword
  { "fldw",       CF_USE1|CF_CHG2                 },      // Floating-Point Load Word
  { "fmpy",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Multiply
  { "fmpyadd",    CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5 },      // Floating-Point Multiply/Add
  { "fmpyfadd",   CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Floating-Point Multiply Fused Add
  { "fmpynfadd",  CF_USE1|CF_USE2|CF_USE3|CF_CHG4 },      // Floating-Point Multiply Negate Fused Add
  { "fmpysub",    CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5 },      // Floating-Point Multiply/Subtract
  { "fneg",       CF_USE1|CF_CHG2                 },      // Floating-Point Negate
  { "fnegabs",    CF_USE1|CF_CHG2                 },      // Floating-Point Negate Absolute Value
  { "frem",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Remainder
  { "frnd",       CF_USE1|CF_CHG2                 },      // Floating-Point Round to Integer
  { "fsqrt",      CF_USE1|CF_CHG2                 },      // Floating-Point Square Root
  { "fstd",       CF_USE1|CF_CHG2                 },      // Floating-Point Store Doubleword
  { "fstw",       CF_USE1|CF_CHG2                 },      // Floating-Point Store Word
  { "fsub",       CF_USE1|CF_USE2|CF_CHG3         },      // Floating-Point Subtract
  { "ftest",      CF_CHG1                         },      // Floating-Point Test
  { "xmpyu",      CF_USE1|CF_USE2|CF_CHG3         },      // Fixed-Point Multiply Unsigned

  // Performance Monitor Coprocessor

  { "pmdis",      0                               },      // Performance Monitor Disable
  { "pmenb",      0                               },      // Performance Monitor Enable

  // Macros

  { "call",       CF_USE1|CF_CALL                 },      // Call Subroutine
  { "ret",        0                               },      // Return From Subroutine
  { "shld",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Left Doubleword
  { "shlw",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Left Word
  { "shrd",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Right Doubleword
  { "shrw",       CF_USE1|CF_USE2|CF_CHG3         },      // Shift Right Word
  { "ldi",        CF_USE1|CF_CHG2                 },      // Load Immediate
  { "copy",       CF_USE1|CF_CHG2                 },      // Copy Register
  { "mtsar",      CF_USE1                         },      // Move To %SAR
  { "nop",        0                               },      // No Operation

};

CASSERT(qnumber(Instructions) == HPPA_last);
