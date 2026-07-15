#ifndef __ELFR_PC_H__
#define __ELFR_PC_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object
// G-   offset into global objet table
// GOT- adress of global object table
// L-   linkage table entry
// P-   plase of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_x86
{
  R_386_NONE      =  0,                      /* No reloc */
  R_386_32        =  1,       // S + A       /* Direct 32 bit  */
  R_386_PC32      =  2,       // S + A - P   /* PC relative 32 bit */
  R_386_GOT32     =  3,       // G + A - P   /* 32 bit GOT entry */
  R_386_PLT32     =  4,       // L + A - P   /* 32 bit PLT address */
  R_386_COPY      =  5,       // none        /* Copy symbol at runtime */
  R_386_GLOB_DAT  =  6,       // S           /* Create GOT entry */
  R_386_JMP_SLOT  =  7,       // S           /* Create PLT entry */
  R_386_RELATIVE  =  8,       // B + A       /* Adjust by program base */
  R_386_GOTOFF    =  9,       // S + A - GOT /* 32 bit offset to GOT */
  R_386_GOTPC     = 10,       // S + A - P   /* 32 bit PC relative offset to GOT */
  R_386_32PLT     = 11,       /* Used by Sun */
  FIRST_INVALID_RELOC = 12,
  LAST_INVALID_RELOC  = 13,
  R_386_TLS_TPOFF = 14,       // abi 3
  R_386_TLS_IE    = 15,       // abi 3
  R_386_TLS_GOTIE = 16,       // abi 3
  R_386_TLS_LE    = 17,
  R_386_TLS_GD    = 18,
  R_386_TLS_LDM   = 19,
  R_386_16        = 20,
  R_386_PC16      = 21,
  R_386_8         = 22,
  R_386_PC8       = 23,
  R_386_TLS_GD_32    = 24,
  R_386_TLS_GD_PUSH  = 25,
  R_386_TLS_GD_CALL  = 26,
  R_386_TLS_GD_POP   = 27,
  R_386_TLS_LDM_32   = 28,
  R_386_TLS_LDM_PUSH = 29,
  R_386_TLS_LDM_CALL = 30,
  R_386_TLS_LDM_POP  = 31,
  R_386_TLS_LDO_32   = 32,
  R_386_TLS_IE_32    = 33,
  R_386_TLS_LE_32    = 34,
  R_386_TLS_DTPMOD32 = 35,
  R_386_TLS_DTPOFF32 = 36,
  R_386_TLS_TPOFF32  = 37,
  R_386_SIZE32       = 38,
  R_386_TLS_GOTDESC  = 39,    // GOT offset for TLS descriptor.
  R_386_TLS_DESC_CALL = 40,   // Marker of call through TLS descriptor for relaxation.
  R_386_TLS_DESC      = 41,   // TLS descriptor containing pointer to code and to argument, returning the TLS offset for the symbol.
  R_386_IRELATIVE     = 42,   // Adjust indirectly by program base
  R_386_GOT32X        = 43,   // Load from 32 bit GOT entry, relaxable

  /* These are GNU extensions to enable C++ vtable garbage collection.  */
  R_386_GNU_VTINHERIT = 250,
  R_386_GNU_VTENTRY   = 251,
};

#endif
