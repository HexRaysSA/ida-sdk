#ifndef __ELFR_ARM_H__
#define __ELFR_ARM_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object  (REAL section when symbol defined)
//  (not)          G-   offset into global objet table
//  (not)          GOT- adress of global object table
//  (not)          L-   linkage table entry
// P-   place of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_arm
{

  R_ARM_NONE      =  0,    // No reloc
  R_ARM_PC24      =  1,    // S-P+A  (relative 26 bit branch)
  R_ARM_ABS32     =  2,    // S+A
  R_ARM_REL32     =  3,    // S-P+A
  R_ARM_LDR_PC_G0 =  4,    // S-P+A
  R_ARM_ABS16     =  5,    // S+A
  R_ARM_ABS12     =  6,    // S+A
  R_ARM_THM_ABS5  =  7,    // S+A
  R_ARM_ABS8      =  8,    // S+A
  R_ARM_SBREL32   =  9,    // S-B+A
  R_ARM_THM_CALL  = 10,    // S-P+A
  R_ARM_THM_PC8   = 11,    // S-P+A
  R_ARM_BREL_ADJ  = 12,    // S-B+A
  R_ARM_TLS_DESC  = 13,    //
  R_ARM_THM_SWI8  = 14,    // S+A   (obsolete)
  R_ARM_XPC25     = 15,    // S-P+A (obsolete)
  R_ARM_THM_XPC22 = 16,    // S-P+A (obsolete)
  R_ARM_TLS_DTPMOD32 = 17,      /* ID of module containing symbol */
  R_ARM_TLS_DTPOFF32 = 18,      /* Offset in TLS block */
  R_ARM_TLS_TPOFF32  = 19,      /* Offset in static TLS block */
// linux-specific
  R_ARM_COPY      = 20,     // none (copy symbol at runtime)
  R_ARM_GLOB_DAT  = 21,     // S (create .got entry)
  R_ARM_JUMP_SLOT = 22,     // S (create .plt entry)
  R_ARM_RELATIVE  = 23,     // B+A (adjust by programm base)
  R_ARM_GOTOFF32  = 24,     // S+A-GOT (32bit offset to .got)
  R_ARM_BASE_PREL = 25,     // B+A-P
  R_ARM_GOT_BREL  = 26,     // G+A-GOT (32bit .got entry)
  R_ARM_PLT32     = 27,     // L+A-P (32bit .plt entry)

  R_ARM_CALL            =  28,
  R_ARM_JUMP24          =  29,
  R_ARM_THM_JUMP24      =  30, // ((S + A) | T) - P
  R_ARM_BASE_ABS        =  31, // B + A
  R_ARM_ALU_PCREL7_0    =  32,
  R_ARM_ALU_PCREL15_8   =  33,
  R_ARM_ALU_PCREL23_15  =  34,
  R_ARM_LDR_SBREL_11_0  =  35,
  R_ARM_ALU_SBREL_19_12 =  36,
  R_ARM_ALU_SBREL_27_20 =  37,
  R_ARM_TARGET1         =  38,
  R_ARM_ROSEGREL32      =  39,
  R_ARM_V4BX            =  40,
  R_ARM_TARGET2         =  41,
  R_ARM_PREL31          =  42,
  R_ARM_MOVW_ABS_NC     =  43, //  Static ARM       (S + A) | T
  R_ARM_MOVT_ABS        =  44, //  Static ARM       S + A
  R_ARM_MOVW_PREL_NC    =  45, //  Static ARM       ((S + A) | T) - P
  R_ARM_MOVT_PREL       =  46, //  Static ARM       S + A - P
  R_ARM_THM_MOVW_ABS_NC =  47, //  Static Thumb32   (S + A) | T
  R_ARM_THM_MOVT_ABS    =  48, //  Static Thumb32   S + A
  R_ARM_THM_MOVW_PREL_NC=  49, //  Static Thumb32   ((S + A) | T) - P
  R_ARM_THM_MOVT_PREL   =  50, //  Static Thumb32   S + A - P
  R_ARM_THM_JUMP19      =  51, //  Static Thumb32   ((S + A) | T) - P
  R_ARM_THM_JUMP6       =  52, //  Static Thumb16   S + A - P
  R_ARM_THM_ALU_PREL_11_0= 53, //  Static Thumb32   ((S + A) | T) - Pa
  R_ARM_THM_PC12        =  54, //  Static Thumb32   S + A - Pa
  R_ARM_ABS32_NOI       =  55, //  Static Data      S + A
  R_ARM_REL32_NOI       =  56, //  Static Data      S + A - P
  R_ARM_ALU_PC_G0_NC    =  57, //  Static ARM       ((S + A) | T) - P
  R_ARM_ALU_PC_G0       =  58, //  Static ARM       ((S + A) | T) - P
  R_ARM_ALU_PC_G1_NC    =  59, //  Static ARM       ((S + A) | T) - P
  R_ARM_ALU_PC_G1       =  60, //  Static ARM       ((S + A) | T) - P
  R_ARM_ALU_PC_G2       =  61, //  Static ARM       ((S + A) | T) - P
  R_ARM_LDR_PC_G1       =  62, //  Static ARM       S + A - P
  R_ARM_LDR_PC_G2       =  63, //  Static ARM       S + A - P
  R_ARM_LDRS_PC_G0      =  64, //  Static ARM       S + A - P

  R_ARM_LDRS_PC_G1 = 65,       // Static       ARM     S + A - P
  R_ARM_LDRS_PC_G2 = 66,       // Static       ARM     S + A - P
  R_ARM_LDC_PC_G0 = 67,        // Static       ARM     S + A - P
  R_ARM_LDC_PC_G1 = 68,        // Static       ARM     S + A - P
  R_ARM_LDC_PC_G2 = 69,        // Static       ARM     S + A - P
  R_ARM_ALU_SB_G0_NC = 70,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G0 = 71,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G1_NC = 72,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G1 = 73,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G2 = 74,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_LDR_SB_G0 = 75,        // Static       ARM     S + A - B(S)
  R_ARM_LDR_SB_G1 = 76,        // Static       ARM     S + A - B(S)
  R_ARM_LDR_SB_G2 = 77,        // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G0 = 78,       // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G1 = 79,       // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G2 = 80,       // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G0 = 81,        // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G1 = 82,        // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G2 = 83,        // Static       ARM     S + A - B(S)
  R_ARM_MOVW_BREL_NC = 84,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_MOVT_BREL = 85,        // Static       ARM     S + A - B(S)
  R_ARM_MOVW_BREL = 86,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_THM_MOVW_BREL_NC = 87, // Static       Thumb32 ((S + A) | T) - B(S)
  R_ARM_THM_MOVT_BREL    = 88, // Static       Thumb32 S + A - B(S)
  R_ARM_THM_MOVW_BREL    = 89, // Static       Thumb32 ((S + A) | T) - B(S)
  R_ARM_TLS_GOTDESC      = 90, // Static       Data
  R_ARM_TLS_CALL         = 91, // Static       ARM
  R_ARM_TLS_DESCSEQ      = 92, // Static       ARM     TLS relaxation
  R_ARM_THM_TLS_CALL     = 93, // Static       Thumb32
  R_ARM_PLT32_ABS        = 94, // Static       Data    PLT(S) + A

  R_ARM_GOT_ABS         = 95,   // G+A
  R_ARM_GOT_PREL        = 96,   // G+A-P
  R_ARM_GOT_BREL12      = 97,   // G+A-GOT
  R_ARM_GOTOFF12        = 98,   // S+A-GOT
  R_ARM_GOTRELAX        = 99,
  R_ARM_GNU_VTENTRY     = 100,
  R_ARM_GNU_VTINHERIT   = 101,

  R_ARM_THM_PC11        = 102, /* Cygnus extension to abi: Thumb unconditional branch.  */
  R_ARM_THM_PC9         = 103, /* Cygnus extension to abi: Thumb conditional branch.  */
  R_ARM_THM_JUMP11 = 102,       // Static       Thumb16 S + A - P
  R_ARM_THM_JUMP8 = 103,        // Static       Thumb16 S + A - P
  R_ARM_TLS_GD32 = 104,         // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LDM32 = 105,        // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LDO32 = 106,        // Static       Data    S + A - TLS
  R_ARM_TLS_IE32 = 107,         // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LE32 = 108,         // Static       Data    S + A - tp
  R_ARM_TLS_LDO12 = 109,        // Static       ARM     S + A - TLS
  R_ARM_TLS_LE12 = 110,         // Static       ARM     S + A - tp
  R_ARM_TLS_IE12GP = 111,       // Static       ARM     GOT(S) + A - GOT_ORG
  R_ARM_PRIVATE_0 = 112,        // Private (n = 0, 1, ... 15)
  R_ARM_PRIVATE_1 = 113,
  R_ARM_PRIVATE_2 = 114,
  R_ARM_PRIVATE_3 = 115,
  R_ARM_PRIVATE_4 = 116,
  R_ARM_PRIVATE_5 = 117,
  R_ARM_PRIVATE_6 = 118,
  R_ARM_PRIVATE_7 = 119,
  R_ARM_PRIVATE_8 = 120,
  R_ARM_PRIVATE_9 = 121,
  R_ARM_PRIVATE_10 = 122,
  R_ARM_PRIVATE_11 = 123,
  R_ARM_PRIVATE_12 = 124,
  R_ARM_PRIVATE_13 = 125,
  R_ARM_PRIVATE_14 = 126,
  R_ARM_PRIVATE_15 = 127,
  R_ARM_ME_TOO = 128,           // Obsolete
  R_ARM_THM_TLS_DESCSEQ16 = 129,// Static       Thumb16
  R_ARM_THM_TLS_DESCSEQ32 = 130,// Static       Thumb32
  R_ARM_THM_GOT_BREL12 = 131,   // GOT entry relative to GOT origin, 12 bit (Thumb32 LDR).
  R_ARM_THM_ALU_ABS_G0_NC = 132,
  R_ARM_THM_ALU_ABS_G1_NC = 133,
  R_ARM_THM_ALU_ABS_G2_NC = 134,
  R_ARM_THM_ALU_ABS_G3_NC = 135,

  R_ARM_THM_BF16          = 136,
  R_ARM_THM_BF12          = 137,
  R_ARM_THM_BF18          = 138,
  // 139                        Unallocated
  // 140 - 159                  Dynamic         Reserved for future allocation

  R_ARM_IRELATIVE         = 160,
  R_ARM_GOTFUNCDESC       = 161,
  R_ARM_GOTOFFFUNCDESC    = 162,
  R_ARM_FUNCDESC          = 163,
  R_ARM_FUNCDESC_VALUE    = 164,
  R_ARM_TLS_GD32_FDPIC    = 165,
  R_ARM_TLS_LDM32_FDPIC   = 166,
  R_ARM_TLS_IE32_FDPIC    = 167,

  // 168 - 248                  Unallocated

//
// ATT: R_ARM_RXPC25 used ONLY in OLD_ABI (+ 15 OTHER relocs!)
// dynamic sections only
  R_ARM_RXPC25    = 249,   // (BLX) call between segments
//
  R_ARM_RSBREL32  = 250,   // (Word) SBrelative offset
  R_ARM_THM_RPC22 = 251,   // (Thumb BL/BLX) call between segments
  R_ARM_RREL32    = 252,   // (Word) inter-segment offset
  R_ARM_RABS32    = 253,   // (Word) Target segment displacement
  R_ARM_RPC24     = 254,   // (BL/BLX) call between segment
  R_ARM_RBASE     = 255    // segment being relocated
};

// X          is the result of a relocation operation, before any masking or bit-selection
// Page(expr) is the page address of the expression expr, defined as (expr & ~0xFFF)
// GOT        is the address of the Global Offset Table
// GDAT(S+A)  represents a 64-bit entry in the GOT for address S+A
// G(expr)    is the address of the GOT entry for the expression expr
// Delta(S)   if S is a normal symbol, resolves to the difference between
//            the static link address of S and the execution address of S.
//            If S is the null symbol (ELF symbol index 0), resolves to the difference
//            between the static link address of P and the execution address of P.
// Indirect(expr) represents the result of calling expr as a function.
//                The result is the return value from the function that is returned in r0.
// [msb:lsb]  is a bit-mask operation representing the selection of bits in a value
enum elf_RTYPE_aarch64
{
  // ILP32 relocations

  // 5.7.5 Static Data relocations
  R_AARCH64_P32_ABS32                       = 1,
  R_AARCH64_P32_ABS16                       = 2,
  R_AARCH64_P32_PREL32                      = 3,
  R_AARCH64_P32_PREL16                      = 4,
  R_AARCH64_P32_PLT32                       = 29,

  // 5.7.6 Static AArch64 relocations
  R_AARCH64_P32_MOVW_UABS_G0                = 5,
  R_AARCH64_P32_MOVW_UABS_G0_NC             = 6,
  R_AARCH64_P32_MOVW_UABS_G1                = 7,

  R_AARCH64_P32_MOVW_SABS_G0                = 8,

  R_AARCH64_P32_LD_PREL_LO19                = 9,
  R_AARCH64_P32_ADR_PREL_LO21               = 10,
  R_AARCH64_P32_ADR_PREL_PG_HI21            = 11,
  R_AARCH64_P32_ADD_ABS_LO12_NC             = 12,
  R_AARCH64_P32_LDST8_ABS_LO12_NC           = 13,
  R_AARCH64_P32_LDST16_ABS_LO12_NC          = 14,
  R_AARCH64_P32_LDST32_ABS_LO12_NC          = 15,
  R_AARCH64_P32_LDST64_ABS_LO12_NC          = 16,
  R_AARCH64_P32_LDST128_ABS_LO12_NC         = 17,

  R_AARCH64_P32_TSTBR14                     = 18,
  R_AARCH64_P32_CONDBR19                    = 19,
  R_AARCH64_P32_JUMP26                      = 20,
  R_AARCH64_P32_CALL26                      = 21,

  R_AARCH64_P32_MOVW_PREL_G0                = 22,
  R_AARCH64_P32_MOVW_PREL_G0_NC             = 23,
  R_AARCH64_P32_MOVW_PREL_G1                = 24,

  R_AARCH64_P32_GOT_LD_PREL19               = 25,
  R_AARCH64_P32_ADR_GOT_PAGE                = 26,
  R_AARCH64_P32_LD32_GOT_LO12_NC            = 27,
  R_AARCH64_P32_LD32_GOTPAGE_LO14           = 28,

  // 5.7.11 Relocations for thread-local storage
  R_AARCH64_P32_TLSGD_ADR_PREL21            = 80,
  R_AARCH64_P32_TLSGD_ADR_PAGE21            = 81,
  R_AARCH64_P32_TLSGD_ADD_LO12_NC           = 82,

  R_AARCH64_P32_TLSLD_ADR_PREL21            = 83,
  R_AARCH64_P32_TLSLD_ADR_PAGE21            = 84,
  R_AARCH64_P32_TLSLD_ADD_LO12_NC           = 85,
  R_AARCH64_P32_TLSLD_LD_PREL19             = 86,
  R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1        = 87,
  R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0        = 88,
  R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC     = 89,
  R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12       = 90,
  R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12       = 91,
  R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC    = 92,
  R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12     = 93,
  R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC  = 94,
  R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12    = 95,
  R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC = 96,
  R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12    = 97,
  R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC = 98,
  R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12    = 99,
  R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC = 100,
  R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12   = 101,
  R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC= 102,

  R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21   = 103,
  R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC = 104,
  R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19    = 105,

  R_AARCH64_P32_TLSLE_MOVW_TPREL_G1         = 106,
  R_AARCH64_P32_TLSLE_MOVW_TPREL_G0         = 107,
  R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC      = 108,
  R_AARCH64_P32_TLSLE_ADD_TPREL_HI12        = 109,
  R_AARCH64_P32_TLSLE_ADD_TPREL_LO12        = 110,
  R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC     = 111,
  R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12      = 112,
  R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC   = 113,
  R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12     = 114,
  R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC  = 115,
  R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12     = 116,
  R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC  = 117,
  R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12     = 118,
  R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC  = 119,
  R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12    = 120,
  R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC = 121,

  R_AARCH64_P32_TLSDESC_LD_PREL19           = 122,
  R_AARCH64_P32_TLSDESC_ADR_PREL21          = 123,
  R_AARCH64_P32_TLSDESC_ADR_PAGE21          = 124,
  R_AARCH64_P32_TLSDESC_LD32_LO12           = 125,
  R_AARCH64_P32_TLSDESC_ADD_LO12            = 126,
  R_AARCH64_P32_TLSDESC_CALL                = 127,

  // 5.7.12 Dynamic relocations
/*R_AARCH64_P32_ABS32                       = 1,// Direct 32 bit.  */
  R_AARCH64_P32_COPY                        = 180,/* Copy symbol at runtime.  */
  R_AARCH64_P32_GLOB_DAT                    = 181,/* Create GOT entry.  */
  R_AARCH64_P32_JUMP_SLOT                   = 182,/* Create PLT entry.  */
  R_AARCH64_P32_RELATIVE                    = 183,/* Adjust by program base.  */
  R_AARCH64_P32_TLS_DTPMOD                  = 184,/* Module number, 32 bit.  */
  R_AARCH64_P32_TLS_DTPREL                  = 185,/* Module-relative offset, 32 bit.  */
  R_AARCH64_P32_TLS_TPREL                   = 186,/* TP-relative offset, 32 bit.  */
  R_AARCH64_P32_TLSDESC                     = 187,/* TLS Descriptor.  */
  R_AARCH64_P32_IRELATIVE                   = 188,/* STT_GNU_IFUNC relocation. */

  // LP64 relocations

  R_AARCH64_NONE                            = 0x100,

  // 4.6.5 Static Data relocations
  R_AARCH64_ABS64                           = 0x101,  // S + A
  R_AARCH64_ABS32                           = 0x102,  // S + A
  R_AARCH64_ABS16                           = 0x103,
  R_AARCH64_PREL64                          = 0x104,
  R_AARCH64_PREL32                          = 0x105,
  R_AARCH64_PREL16                          = 0x106,

  // 4.6.6 Static AArch64 relocations
  R_AARCH64_MOVW_UABS_G0                    = 0x107,
  R_AARCH64_MOVW_UABS_G0_NC                 = 0x108,
  R_AARCH64_MOVW_UABS_G1                    = 0x109,
  R_AARCH64_MOVW_UABS_G1_NC                 = 0x10a,
  R_AARCH64_MOVW_UABS_G2                    = 0x10b,
  R_AARCH64_MOVW_UABS_G2_NC                 = 0x10c,
  R_AARCH64_MOVW_UABS_G3                    = 0x10d,
  R_AARCH64_MOVW_SABS_G0                    = 0x10e,
  R_AARCH64_MOVW_SABS_G1                    = 0x10f,
  R_AARCH64_MOVW_SABS_G2                    = 0x110,

  R_AARCH64_LD_PREL_LO19                    = 0x111,
  R_AARCH64_ADR_PREL_LO21                   = 0x112,
  R_AARCH64_ADR_PREL_PG_HI21                = 0x113,  // Page(S+A) - Page(P); Set an ADRP immediate value to bits [32:12] of the X
  R_AARCH64_ADR_PREL_PG_HI21_NC             = 0x114,
  R_AARCH64_ADD_ABS_LO12_NC                 = 0x115,  // S+A; Set an ADD immediate value to bits [11:0] of X
  R_AARCH64_LDST8_ABS_LO12_NC               = 0x116,

  R_AARCH64_TSTBR14                         = 0x117,
  R_AARCH64_CONDBR19                        = 0x118,
  R_AARCH64_JUMP26                          = 0x11a,  // S+A-P; Set a B immediate field to bits [27:2] of X
  R_AARCH64_CALL26                          = 0x11b,  // S+A-P; Set a CALL immediate field to bits [27:2] of X

  R_AARCH64_LDST16_ABS_LO12_NC              = 0x11c,
  R_AARCH64_LDST32_ABS_LO12_NC              = 0x11d,
  R_AARCH64_LDST64_ABS_LO12_NC              = 0x11e,  // S+A; Set the LD/ST immediate value to bits [11:3] of X

  R_AARCH64_MOVW_PREL_G0                    = 0x11f,
  R_AARCH64_MOVW_PREL_G0_NC                 = 0x120,
  R_AARCH64_MOVW_PREL_G1                    = 0x121,
  R_AARCH64_MOVW_PREL_G1_NC                 = 0x122,
  R_AARCH64_MOVW_PREL_G2                    = 0x123,
  R_AARCH64_MOVW_PREL_G2_NC                 = 0x124,
  R_AARCH64_MOVW_PREL_G3                    = 0x125,

  R_AARCH64_LDST128_ABS_LO12_NC             = 0x12b,

  R_AARCH64_MOVW_GOTOFF_G0                  = 0x12c,
  R_AARCH64_MOVW_GOTOFF_G0_NC               = 0x12d,
  R_AARCH64_MOVW_GOTOFF_G1                  = 0x12e,
  R_AARCH64_MOVW_GOTOFF_G1_NC               = 0x12f,
  R_AARCH64_MOVW_GOTOFF_G2                  = 0x130,
  R_AARCH64_MOVW_GOTOFF_G2_NC               = 0x131,
  R_AARCH64_MOVW_GOTOFF_G3                  = 0x132,

  R_AARCH64_GOTREL64                        = 0x133,
  R_AARCH64_GOTREL32                        = 0x134,

  R_AARCH64_GOT_LD_PREL19                   = 0x135,
  R_AARCH64_LD64_GOTOFF_LO15                = 0x136,
  R_AARCH64_ADR_GOT_PAGE                    = 0x137,  // Page(G(GDAT(S+A)))-Page(P); Set the immediate value of an ADRP to bits [32:12] of X
  R_AARCH64_LD64_GOT_LO12_NC                = 0x138,  // G(GDAT(S+A)); Set the LD/ST immediate field to bits [11:3] of X
  R_AARCH64_LD64_GOTPAGE_LO15               = 0x139,

  R_AARCH64_TLSGD_ADR_PREL21                = 0x200,
  R_AARCH64_TLSGD_ADR_PAGE21                = 0x201,
  R_AARCH64_TLSGD_ADD_LO12_NC               = 0x202,
  R_AARCH64_TLSGD_MOVW_G1                   = 0x203,
  R_AARCH64_TLSGD_MOVW_G0_NC                = 0x204,

  R_AARCH64_TLSLD_ADR_PREL21                = 0x205,
  R_AARCH64_TLSLD_ADR_PAGE21                = 0x206,
  R_AARCH64_TLSLD_ADD_LO12_NC               = 0x207,
  R_AARCH64_TLSLD_MOVW_G1                   = 0x208,
  R_AARCH64_TLSLD_MOVW_G0_NC                = 0x209,
  R_AARCH64_TLSLD_LD_PREL19                 = 0x20a,
  R_AARCH64_TLSLD_MOVW_DTPREL_G2            = 0x20b,
  R_AARCH64_TLSLD_MOVW_DTPREL_G1            = 0x20c,
  R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC         = 0x20d,
  R_AARCH64_TLSLD_MOVW_DTPREL_G0            = 0x20e,
  R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC         = 0x20f,
  R_AARCH64_TLSLD_ADD_DTPREL_HI12           = 0x210,
  R_AARCH64_TLSLD_ADD_DTPREL_LO12           = 0x211,
  R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC        = 0x212,
  R_AARCH64_TLSLD_LDST8_DTPREL_LO12         = 0x213,
  R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC      = 0x214,
  R_AARCH64_TLSLD_LDST16_DTPREL_LO12        = 0x215,
  R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC     = 0x216,
  R_AARCH64_TLSLD_LDST32_DTPREL_LO12        = 0x217,
  R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC     = 0x218,
  R_AARCH64_TLSLD_LDST64_DTPREL_LO12        = 0x219,
  R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC     = 0x21a,

  R_AARCH64_TLSIE_MOVW_GOTTPREL_G1          = 0x21b,
  R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC       = 0x21c,
  R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21       = 0x21d,
  R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC     = 0x21e,
  R_AARCH64_TLSIE_LD_GOTTPREL_PREL19        = 0x21f,

  R_AARCH64_TLSLE_MOVW_TPREL_G2             = 0x220,
  R_AARCH64_TLSLE_MOVW_TPREL_G1             = 0x221,
  R_AARCH64_TLSLE_MOVW_TPREL_G1_NC          = 0x222,
  R_AARCH64_TLSLE_MOVW_TPREL_G0             = 0x223,
  R_AARCH64_TLSLE_MOVW_TPREL_G0_NC          = 0x224,
  R_AARCH64_TLSLE_ADD_TPREL_HI12            = 0x225,
  R_AARCH64_TLSLE_ADD_TPREL_LO12            = 0x226,
  R_AARCH64_TLSLE_ADD_TPREL_LO12_NC         = 0x227,
  R_AARCH64_TLSLE_LDST8_TPREL_LO12          = 0x228,
  R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC       = 0x229,
  R_AARCH64_TLSLE_LDST16_TPREL_LO12         = 0x22a,
  R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC      = 0x22b,
  R_AARCH64_TLSLE_LDST32_TPREL_LO12         = 0x22c,
  R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC      = 0x22d,
  R_AARCH64_TLSLE_LDST64_TPREL_LO12         = 0x22e,
  R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC      = 0x22f,

  R_AARCH64_TLSDESC_LD_PREL19               = 0x230,
  R_AARCH64_TLSDESC_ADR_PREL21              = 0x231,
  R_AARCH64_TLSDESC_ADR_PAGE21              = 0x232,  // R_AARCH64_TLSDESC_ADR_PAGE
  R_AARCH64_TLSDESC_LD64_LO12               = 0x233,  // R_AARCH64_TLSDESC_LD64_LO12_NC
  R_AARCH64_TLSDESC_ADD_LO12                = 0x234,  // R_AARCH64_TLSDESC_ADD_LO12_NC
  R_AARCH64_TLSDESC_OFF_G1                  = 0x235,
  R_AARCH64_TLSDESC_OFF_G0_NC               = 0x236,
  R_AARCH64_TLSDESC_LDR                     = 0x237,
  R_AARCH64_TLSDESC_ADD                     = 0x238,
  R_AARCH64_TLSDESC_CALL                    = 0x239,

  R_AARCH64_TLSLE_LDST128_TPREL_LO12        = 0x23a,
  R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC     = 0x23b,

  R_AARCH64_TLSLD_LDST128_DTPREL_Lo12       = 0x23c,
  R_AARCH64_TLSLD_LDST128_DTPREL_Lo12_NC    = 0x23d,

  // 4.6.11 Dynamic relocations
  R_AARCH64_COPY                            = 0x400,
  R_AARCH64_GLOB_DAT                        = 0x401,
  R_AARCH64_JUMP_SLOT                       = 0x402,
  R_AARCH64_RELATIVE                        = 0x403,
  R_AARCH64_TLS_DTPREL64                    = 0x404,
  R_AARCH64_TLS_DTPMOD64                    = 0x405,
  R_AARCH64_TLS_TPREL64                     = 0x406,
  R_AARCH64_TLSDESC                         = 0x407,
  R_AARCH64_IRELATIVE                       = 0x408,
};

// Flags:
#define EF_ARM_RELEXEC        0x00000001  // dynamic only how to relocation
#define EF_ARM_HASENTRY       0x00000002  // e_entry is real start address

// GNU flags (EABI version = 0)
#define EF_ARM_INTERWORK      0x00000004  // interworking enabled
#define EF_ARM_APCS_26        0x00000008  // APCS-26 used (otherwise APCS-32)
#define EF_ARM_APCS_FLOAT     0x00000010  // floats passed in float registers
#define EF_ARM_PIC            0x00000020  // Position-independent code
#define EF_ARM_ALIGN8         0x00000040  // 8-bit struct alignment
#define EF_ARM_NEW_ABI        0x00000080  // New ABI
#define EF_ARM_OLD_ABI        0x00000100  // Old ABI
#define EF_ARM_SOFT_FLOAT     0x00000200  // software FP
#define EF_ARM_VFP_FLOAT      0x00000400  // VFP float format
#define EF_ARM_MAVERICK_FLOAT 0x00000800  // Maverick float format

// ARM flags:
#define EF_ARM_SYMSARESORTED  0x00000004  // Each subsection of the symbol table is sorted by symbol value (NB conflicts with EF_INTERWORK)
#define EF_ARM_DYNSYMSUSESEGIDX 0x00000008 // Symbols in dynamic symbol tables that are defined in sections
                                          // included in program segment n have st_shndx = n + 1. (NB conflicts with EF_APCS26)
#define EF_ARM_MAPSYMSFIRST   0x00000010  // Mapping symbols precede other local symbols in the symbol
                                          // table (NB conflicts with EF_APCS_FLOAT)
#define EF_ARM_LE8            0x00400000  // LE-8 code
#define EF_ARM_BE8            0x00800000  // BE-8 code for ARMv6 or later
#define EF_ARM_EABIMASK       0xFF000000  // ARM EABI version

/* Additional symbol types for Thumb.  */
#define STT_ARM_TFUNC      STT_LOPROC   /* A Thumb function.  */
#define STT_ARM_16BIT      STT_HIPROC   /* A Thumb label.  */

// patching GOT loading,
// discard auxiliary values in plt/got
// can present offset bypass segment
#define ELF_RPL_ARM_DEFAULT  (ELF_RPL_GL | ELF_DIS_OFFW | ELF_DIS_GPLT)

enum elf_SHT_ARM
{
  SHT_ARM_EXIDX = 0x70000001,          // Exception Index table
  SHT_ARM_PREEMPTMAP = 0x70000002,     // BPABI DLL dynamic linking pre-emption map
  SHT_ARM_ATTRIBUTES = 0x70000003,     // Object file compatibility attributes
  SHT_ARM_DEBUGOVERLAY = 0x70000004,   //
  SHT_ARM_OVERLAYSECTION = 0x70000005, //
};

enum elf_PT_ARM
{
  // From binutils-2.27/elfcpp/elfcpp.h
  PT_ARM_ARCHEXT = 0x70000000, // Platform architecture compatibility information
  PT_ARM_EXIDX   = 0x70000001, // Exception unwind tables
};

enum elf_PT_AARCH64
{
  // From binutils-2.27/elfcpp/elfcpp.h
  PT_AARCH64_ARCHEXT = 0x70000000, // Platform architecture compatibility information
  PT_AARCH64_UNWIND  = 0x70000001, // Exception unwind tables
};

enum eabi_tags_t
{
  Tag_NULL,
  Tag_File,                       // (=1) <uint32: byte-size> <attribute>*
  Tag_Section,                    // (=2) <uint32: byte-size> <section number>* 0 <attribute>*
  Tag_Symbol,                     // (=3) <unit32: byte-size> <symbol number>* 0 <attribute>*
  Tag_CPU_raw_name,               // (=4), NTBS
  Tag_CPU_name,                   // (=5), NTBS
  Tag_CPU_arch,                   // (=6), uleb128
  Tag_CPU_arch_profile,           // (=7), uleb128
  Tag_ARM_ISA_use,                // (=8), uleb128
  Tag_THUMB_ISA_use,              // (=9), uleb128
  Tag_FP_arch,                   // (=10), uleb128 (formerly Tag_VFP_arch = 10)
  Tag_VFP_arch = Tag_FP_arch,
  Tag_WMMX_arch,                  // (=11), uleb128
  Tag_NEON_arch,                  // (=12), uleb128
  Tag_PCS_config,                 // (=13), uleb128
  Tag_ABI_PCS_R9_use,             // (=14), uleb128
  Tag_ABI_PCS_RW_data,            // (=15), uleb128
  Tag_ABI_PCS_RO_data,            // (=16), uleb128
  Tag_ABI_PCS_GOT_use,            // (=17), uleb128
  Tag_ABI_PCS_wchar_t,            // (=18), uleb128
  Tag_ABI_FP_rounding,            // (=19), uleb128
  Tag_ABI_FP_denormal,            // (=20), uleb128
  Tag_ABI_FP_exceptions,          // (=21), uleb128
  Tag_ABI_FP_user_exceptions,     // (=22), uleb128
  Tag_ABI_FP_number_model,        // (=23), uleb128
  Tag_ABI_align_needed,           // (=24), uleb128
  Tag_ABI_align8_needed = Tag_ABI_align_needed,
  Tag_ABI_align_preserved,        // (=25), uleb128
  Tag_ABI_align8_preserved = Tag_ABI_align_preserved,
  Tag_ABI_enum_size,              // (=26), uleb128
  Tag_ABI_HardFP_use,             // (=27), uleb128
  Tag_ABI_VFP_args,               // (=28), uleb128
  Tag_ABI_WMMX_args,              // (=29), uleb128
  Tag_ABI_optimization_goals,     // (=30), uleb128
  Tag_ABI_FP_optimization_goals,  // (=31), uleb128
  Tag_compatibility,              // (=32), uleb128: flag, NTBS: vendor-name
  Tag_CPU_unaligned_access=34,    // (=34), uleb128
  Tag_FP_HP_extension=36,         // (=36), uleb128 (formerly Tag_VFP_HP_extension = 36)
  Tag_VFP_HP_extension = Tag_FP_HP_extension,
  Tag_ABI_FP_16bit_format=38,     // (=38), uleb128
  Tag_MPextension_use=42,         // (=42), uleb128
  Tag_DIV_use=44,                 // (=44), uleb128
  Tag_DSP_extension=46,           // (=46), uleb128
  Tag_PAC_extension=50,           // (=50), uleb128
  Tag_BTI_extension=52,           // (=52), uleb128
  Tag_nodefaults=64,              // (=64), uleb128: ignored (write as 0)
  Tag_also_compatible_with,       // (=65), NTBS: data; ULEB128-encoded tag followed by a value of that tag.
  Tag_T2EE_use,                   // (=66), uleb128
  Tag_conformance,                // (=67), string: ABI-version
  Tag_Virtualization_use,         // (=68), uleb128
  Tag_MPextension_use_legacy=70,  // (=70),
  Tag_FramePointer_use=72,        // (=72), uleb128
  Tag_BTI_use=74,                 // (=74), uleb128
  Tag_PACRET_use=76,             //  (=76), uleb128
};

//----------------------------------------------------------------------------
class arm_arch_specific_t : public arch_specific_t
{
public:
  enum isa_t
  {
    isa_arm = 1,
    isa_thumb
  };
  typedef void isa_handler_t(
        reader_t &reader,
        sym_rel &symbol,
        isa_t isa,
        bool force);
private:
  typedef std::map<uint64, isa_t> section_isa_ranges_t;
  typedef std::map<elf_shndx_t, section_isa_ranges_t> isa_ranges_t;

  isa_ranges_t isa_ranges;
  std::set<ea_t> forced_isas;

  isa_handler_t *isa_handler = nullptr;
  ea_t debug_segbase = 0;
  bool has_mapsym = false;
  bool track_mapsym = false;
  bool be8_code = false;

  void notify_isa(reader_t &reader, sym_rel &symbol, isa_t isa, bool force)
  {
    if ( isa_handler != nullptr )
      isa_handler(reader, symbol, isa, force);
  }

  isa_t get_isa(const sym_rel &symbol) const;
  void  set_isa(const sym_rel &symbol, isa_t isa);

  friend void arm_isa_handler(
        reader_t &reader,
        sym_rel &symbol,
        arm_arch_specific_t::isa_t isa,
        bool force);

public:
  virtual ~arm_arch_specific_t() {}
  virtual void on_start_symbols(reader_t &reader) override;
  virtual void on_symbol_read(reader_t &reader, sym_rel &sym) override;
  bool is_mapping_symbol(const char *name) const;
  bool has_mapping_symbols() const { return has_mapsym; }

  // Tracking mapping symbols can be useful for
  // determining whether a certain function is using
  // the Thumb or ARM ISA.
  // In some ELF files, the only way to know what ISA
  // certain functions are in is by looking at some
  // mapping symbols (i.e., '$a', '$t').
  // By default, tracking of such symbols in an
  // instance of this class is _not_ enabled.
  void set_mapping_symbols_tracking(bool track) { track_mapsym = track; }
  bool  is_mapping_symbols_tracking() const { return track_mapsym; }

  void set_isa_handler(isa_handler_t *ih, ea_t dea)
  {
    isa_handler = ih;
    debug_segbase = dea;
  }

  void set_be8(bool be8)        { be8_code = be8; }
  bool is_be8()                 { return be8_code; }
};

//----------------------------------------------------------------------------
// Specific flags that will be set on sym_rel instances.
enum arm_sym_rel_flags
{
  thumb_function = 1
};

#endif
