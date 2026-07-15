#ifndef __ELFR_X64_H__
#define __ELFR_X64_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

enum elf_RTYPE_x64
{
  R_X86_64_NONE=     0,      /* No reloc */
  R_X86_64_64=       1,      /* Direct 64 bit  */
  R_X86_64_PC32=     2,      /* PC relative 32 bit signed */
  R_X86_64_GOT32=    3,      /* 32 bit GOT entry */
  R_X86_64_PLT32=    4,      /* 32 bit PLT address */
  R_X86_64_COPY=     5,      /* Copy symbol at runtime */
  R_X86_64_GLOB_DAT= 6,      /* Create GOT entry */
  R_X86_64_JUMP_SLOT=7,      /* Create PLT entry */
  R_X86_64_RELATIVE= 8,      /* Adjust by program base */
  R_X86_64_GOTPCREL= 9,      /* 32 bit signed pc relative
                                offset to GOT */
  R_X86_64_32=       10,     /* Direct 32 bit zero extended */
  R_X86_64_32S=      11,     /* Direct 32 bit sign extended */
  R_X86_64_16=       12,     /* Direct 16 bit zero extended */
  R_X86_64_PC16=     13,     /* 16 bit sign extended pc relative*/
  R_X86_64_8=        14,     /* Direct 8 bit sign extended */
  R_X86_64_PC8=      15,     /* 8 bit sign extended pc relative*/
  R_X86_64_DTPMOD64= 16,     /* ID of module containing symbol */
  R_X86_64_DTPOFF64= 17,     /* Offset in TLS block */
  R_X86_64_TPOFF64=  18,     /* Offset in initial TLS block */
  R_X86_64_TLSGD=    19,     /* PC relative offset to GD GOT block */
  R_X86_64_TLSLD=    20,     /* PC relative offset to LD GOT block */
  R_X86_64_DTPOFF32= 21,     /* Offset in TLS block */
  R_X86_64_GOTTPOFF= 22,     /* PC relative offset to IE GOT entry */
  R_X86_64_TPOFF32 = 23,     /* Offset in initial TLS block */
  R_X86_64_PC64    = 24,     // 64-bit PC relative
  R_X86_64_GOTOFF64 = 25,    // 64-bit GOT offset
  R_X86_64_GOTPC32 = 26,     // 32-bit PC relative offset to GOT

  R_X86_64_GOT64   = 27,     // 64-bit GOT entry offset
  R_X86_64_GOTPCREL64 = 28,  // 64-bit PC relative offset to GOT entry
  R_X86_64_GOTPC64  = 29,    // 64-bit PC relative offset to GOT
  R_X86_64_GOTPLT64 = 30,    // Like GOT64, indicates that PLT entry needed
  R_X86_64_PLTOFF64 = 31,    // 64-bit GOT relative offset to PLT entry

  R_X86_64_SIZE32 = 32,
  R_X86_64_SIZE64 = 33,

  R_X86_64_GOTPC32_TLSDESC = 34, // 32-bit PC relative to TLS descriptor in GOT
  R_X86_64_TLSDESC_CALL = 35,    // Relaxable call through TLS descriptor
  R_X86_64_TLSDESC = 36,         // 2 by 64-bit TLS descriptor
  R_X86_64_IRELATIVE = 37,       // Adjust indirectly by program base
  R_X86_64_RELATIVE64 = 38,      // word64 B + A (x32 only)
  R_X86_64_PC32_BND = 39,        // deprecated
  R_X86_64_PLT32_BND = 40,       // deprecated
  R_X86_64_GOTPCRELX = 41,       // word32 G + GOT + A - P
  R_X86_64_REX_GOTPCRELX = 42,   // word32 G + GOT + A - P

  R_X86_64_GNU_VTINHERIT= 250,       /* GNU C++ hack  */
  R_X86_64_GNU_VTENTRY= 251,         /* GNU C++ hack  */
};

#endif // __ELFR_X64_H__
