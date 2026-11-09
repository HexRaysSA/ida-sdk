#ifndef __ELFR_IA64_H__
#define __ELFR_IA64_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

/* Bits in the e_flags field of the Elf64_Ehdr:  */
#define EF_IA_64_MASKOS  0x00ff000f     /* os-specific flags */
#define EF_IA_64_ARCH    0xff000000     /* arch. version mask */
#define EFA_IA_64        0x00000000
/* ??? These four definitions are not part of the SVR4 ABI.
   They were present in David's initial code drop, so it is probable
   that they are used by HP/UX.  */
#define EF_IA_64_TRAPNIL      (1 << 0)  /* Trap NIL pointer dereferences.  */
#define EF_IA_64_LAZYSWAP     (1 << 1)  /* Lazy Swap algorithm */
#define EF_IA_64_EXT          (1 << 2)  /* Program uses arch. extensions.  */
#define EF_IA_64_BE            (1 << 3)  /* PSR BE bit set (big-endian).  */
#define EFA_IA_64_EAS2_3      0x23000000 /* IA64 EAS 2.3.  */

#define EF_IA_64_ABI64        (1 << 4)  /* 64-bit ABI.  */
/* Not used yet.  */
#define EF_IA_64_REDUCEDFP    (1 << 5)  /* Only FP6-FP11 used.  */
#define EF_IA_64_CONS_GP      (1 << 6)  /* gp as program wide constant.  */
#define EF_IA_64_NOFUNCDESC_CONS_GP (1 << 7) /* And no function descriptors.  */
/* Not used yet.  */
#define EF_IA_64_ABSOLUTE      (1 << 8)  /* Load at absolute addresses.  */

/*============================================================================
   The R_EM_* macros are the IA_64 relocation types
============================================================================*/
        /*
        ** These are "real" Tahoe relocations.  The offset in a relocation
        ** applied to a data location is the actual byte address of the
        ** 32-/64-bit field to relocate.  The value of (offset & ~3) in
        ** an instruction relocation is the byte offset of the bundle
        ** the instruction lives in; the value of (offset & 3) signifies:
        **   0: first  instruction slot in bundle
        **   1: second instruction slot in bundle
        **   2: third  instruction slot in bundle
        **
        ** Little piece of info: the first (hex) digit specifies the
        ** expression type, while the second specifies the format of
        ** the data word being relocated.
        */

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object
// G-   offset into global objet table
// GOT- adress of global object table
// L-   linkage table entry
// P-   plase of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_ia64
{
  R_IA64_NONE            = 0x00, /* none */

  R_IA64_IMM14           = 0x21, /* symbol + addend, add imm14 */
  R_IA64_IMM22           = 0x22, /* symbol + addend, add imm22 */
  R_IA64_IMM64           = 0x23, /* symbol + addend, mov imm64 */
  R_IA64_DIR32MSB        = 0x24, /* symbol + addend, data4 MSB */
  R_IA64_DIR32LSB        = 0x25, /* symbol + addend, data4 LSB */
  R_IA64_DIR64MSB        = 0x26, /* symbol + addend, data8 MSB */
  R_IA64_DIR64LSB        = 0x27, /* symbol + addend, data8 LSB */

  R_IA64_GPREL22         = 0x2a, /* @gprel(sym + add), add imm22 */
  R_IA64_GPREL64I        = 0x2b, /* @gprel(sym + add), mov imm64 */
  R_IA64_GPREL32MSB      = 0x2c, /* @gprel(sym + add), data4 MSB ## */
  R_IA64_GPREL32LSB      = 0x2d, /* @gprel(sym + add), data4 LSB ## */
  R_IA64_GPREL64MSB      = 0x2e, /* @gprel(sym + add), data8 MSB */
  R_IA64_GPREL64LSB      = 0x2f, /* @gprel(sym + add), data8 LSB */

  R_IA64_LTOFF22         = 0x32, /* @ltoff(sym + add), add imm22 */
  R_IA64_LTOFF64I        = 0x33, /* @ltoff(sym + add), mov imm64 */

  R_IA64_PLTOFF22        = 0x3a, /* @pltoff(sym + add), add imm22 */
  R_IA64_PLTOFF64I       = 0x3b, /* @pltoff(sym + add), mov imm64 */
  R_IA64_PLTOFF64MSB     = 0x3e, /* @pltoff(sym + add), data8 MSB */
  R_IA64_PLTOFF64LSB     = 0x3f, /* @pltoff(sym + add), data8 LSB */

  R_IA64_FPTR64I         = 0x43, /* @fptr(sym + add), mov imm64 */
  R_IA64_FPTR32MSB       = 0x44, /* @fptr(sym + add), data4 MSB */
  R_IA64_FPTR32LSB       = 0x45, /* @fptr(sym + add), data4 LSB */
  R_IA64_FPTR64MSB       = 0x46, /* @fptr(sym + add), data8 MSB */
  R_IA64_FPTR64LSB       = 0x47, /* @fptr(sym + add), data8 LSB */

  R_IA64_PCREL60B        = 0x48, /* @pcrel(sym + add), brl */
  R_IA64_PCREL21B        = 0x49, /* @pcrel(sym + add), ptb, call */
  R_IA64_PCREL21M        = 0x4a, /* @pcrel(sym + add), chk.s */
  R_IA64_PCREL21F        = 0x4b, /* @pcrel(sym + add), fchkf */
  R_IA64_PCREL32MSB      = 0x4c, /* @pcrel(sym + add), data4 MSB */
  R_IA64_PCREL32LSB      = 0x4d, /* @pcrel(sym + add), data4 LSB */
  R_IA64_PCREL64MSB      = 0x4e, /* @pcrel(sym + add), data8 MSB */
  R_IA64_PCREL64LSB      = 0x4f, /* @pcrel(sym + add), data8 LSB */

  R_IA64_LTOFF_FPTR22    = 0x52, /* @ltoff(@fptr(s+a)), imm22 */
  R_IA64_LTOFF_FPTR64I   = 0x53, /* @ltoff(@fptr(s+a)), imm64 */
  R_IA64_LTOFF_FPTR32MSB = 0x54, /* @ltoff(@fptr(s+a)), 4 MSB */
  R_IA64_LTOFF_FPTR32LSB = 0x55, /* @ltoff(@fptr(s+a)), 4 LSB */
  R_IA64_LTOFF_FPTR64MSB = 0x56, /* @ltoff(@fptr(s+a)), 8 MSB ##*/
  R_IA64_LTOFF_FPTR64LSB = 0x57, /* @ltoff(@fptr(s+a)), 8 LSB ##*/

  R_IA64_SEGBASE         = 0x58, /* set segment base for @segrel ## */
  R_IA64_SEGREL32MSB     = 0x5c, /* @segrel(sym + add), data4 MSB */
  R_IA64_SEGREL32LSB     = 0x5d, /* @segrel(sym + add), data4 LSB */
  R_IA64_SEGREL64MSB     = 0x5e, /* @segrel(sym + add), data8 MSB */
  R_IA64_SEGREL64LSB     = 0x5f, /* @segrel(sym + add), data8 LSB */

  R_IA64_SECREL32MSB     = 0x64, /* @secrel(sym + add), data4 MSB */
  R_IA64_SECREL32LSB     = 0x65, /* @secrel(sym + add), data4 LSB */
  R_IA64_SECREL64MSB     = 0x66, /* @secrel(sym + add), data8 MSB */
  R_IA64_SECREL64LSB     = 0x67, /* @secrel(sym + add), data8 LSB */

  R_IA64_REL32MSB        = 0x6c, /* data 4 + REL */
  R_IA64_REL32LSB        = 0x6d, /* data 4 + REL */
  R_IA64_REL64MSB        = 0x6e, /* data 8 + REL */
  R_IA64_REL64LSB        = 0x6f, /* data 8 + REL */

  R_IA64_LTV32MSB        = 0x74, /* symbol + addend, data4 MSB */
  R_IA64_LTV32LSB        = 0x75, /* symbol + addend, data4 LSB */
  R_IA64_LTV64MSB        = 0x76, /* symbol + addend, data8 MSB */
  R_IA64_LTV64LSB        = 0x77, /* symbol + addend, data8 LSB */

  R_IA64_PCREL21BI       = 0x79, /* @pcrel(sym + add), ptb, call */
  R_IA64_PCREL22         = 0x7a, /* @pcrel(sym + add), imm22 */
  R_IA64_PCREL64I        = 0x7b, /* @pcrel(sym + add), imm64 */

  R_IA64_IPLTMSB         = 0x80, /* dynamic reloc, imported PLT, MSB */
  R_IA64_IPLTLSB         = 0x81, /* dynamic reloc, imported PLT, LSB */
  R_IA64_EPLTMSB         = 0x82, /* dynamic reloc, exported PLT, ## */
  R_IA64_EPLTLSB         = 0x83, /* dynamic reloc, exported PLT, ## */
  R_IA64_COPY            = 0x84, /* dynamic reloc, data copy ## */
  R_IA64_SUB             = 0x85, /* Addend and symbol difference */
  R_IA64_LTOFF22X        = 0x86, /* LTOFF22, relaxable.  */
  R_IA64_LDXMOV          = 0x87, /* Use of LTOFF22X.  */

  R_IA64_TPREL14         = 0x91, /* @tprel(sym+add), add imm14 */
  R_IA64_TPREL22         = 0x92, /* sym-TP+add, add imm22 ## */
  R_IA64_TPREL64I        = 0x93, /* @tprel(sym+add), add imm64 */
  R_IA64_TPREL64MSB      = 0x96, /* sym-TP+add, data8 MSB ## */
  R_IA64_TPREL64LSB      = 0x97, /* sym-TP+add, data8 LSB ## */

  R_IA64_LTOFF_TP22      = 0x9a, /* @ltoff(sym-TP+add), add imm22 ## */

  R_IA64_DTPMOD64MSB     = 0xa6, /* @dtpmod(sym+add), data8 MSB */
  R_IA64_DTPMOD64LSB     = 0xa7, /* @dtpmod(sym+add), data8 LSB */
  R_IA64_LTOFF_DTPMOD22  = 0xaa, /* @ltoff(@dtpmod(s+a)), imm22 */

  R_IA64_DTPREL14        = 0xb1, /* @dtprel(sym+add), imm14 */
  R_IA64_DTPREL22        = 0xb2, /* @dtprel(sym+add), imm22 */
  R_IA64_DTPREL64I       = 0xb3, /* @dtprel(sym+add), imm64 */
  R_IA64_DTPREL32MSB     = 0xb4, /* @dtprel(sym+add), data4 MSB */
  R_IA64_DTPREL32LSB     = 0xb5, /* @dtprel(sym+add), data4 LSB */
  R_IA64_DTPREL64MSB     = 0xb6, /* @dtprel(sym+add), data8 MSB */
  R_IA64_DTPREL64LSB     = 0xb7, /* @dtprel(sym+add), data8 LSB */

  R_IA64_LTOFF_DTPREL22  = 0xba, /* @ltoff(@dtprel(s+a)), imm22 */

  R_IA64_MAX_RELOC_CODE  = 0xba

};

// convert plt PIC => noPIC,
// patching GOT loading,
// discard auxiliary values in plt/got
#define ELF_RPL_IA64_DEFAULT  (ELF_RPL_PLP | ELF_RPL_GL)


enum elf_SHT_IA64
{
  SHT_IA_64_EXT       = 0x70000000,        /* extension bits */
  SHT_IA_64_UNWIND    = 0x70000001,        /* unwind bits */
};

/*============================================================================
   The PT_* macros are the values of p_type in ElfXX_Phdr.
============================================================================*/
enum elf_PT_IA64
{

  PT_HP_TLS           = (PT_LOOS + 0x0), /* TLS */
  PT_HP_CORE_NONE     = (PT_LOOS + 0x1), /* core file information */
  PT_HP_CORE_VERSION  = (PT_LOOS + 0x2),
  PT_HP_CORE_KERNEL   = (PT_LOOS + 0x3),
  PT_HP_CORE_COMM     = (PT_LOOS + 0x4),
  PT_HP_CORE_PROC     = (PT_LOOS + 0x5),
  PT_HP_CORE_LOADABLE = (PT_LOOS + 0x6),
  PT_HP_CORE_STACK    = (PT_LOOS + 0x7),
  PT_HP_CORE_SHM      = (PT_LOOS + 0x8),
  PT_HP_CORE_MMF      = (PT_LOOS + 0x9),
  PT_HP_PARALLEL      = (PT_LOOS + 0x10), /* parallel information header */
  PT_HP_FASTBIND      = (PT_LOOS + 0x11), /* fastbind data segment */
  PT_HP_OPT_ANNOT     = (PT_LOOS + 0x12), /* dynamic opt. annotations */
  PT_HP_HSL_ANNOT     = (PT_LOOS + 0x13), /* HSL annotations */
  PT_HP_STACK         = (PT_LOOS + 0x14), /* executable stack */
  PT_HP_CORE_UTSNAME  = (PT_LOOS + 0x15), /* Extended utsname() core struct */
  PT_HP_LINKER_FOOTPRINT = (PT_LOOS + 0x16), /* linker footprint */

  PT_IA_64_ARCHEXT    = (PT_LOPROC + 0), /* arch. extension bits */
  PT_IA_64_UNWIND     = (PT_LOPROC + 1), /* IA64 unwind bits */
};

/*============================================================================
   The PF_* macros are the segment flag bits in p_flags of ElfXX_Phdr.
============================================================================*/
enum elf_PF_IA64
{
  PF_HP_ENABLE_RECOVER = 0x00020000, /* enable recovery mode */
  PF_HP_CODE           = 0x00040000, /* code hint */
  PF_HP_MODIFY         = 0x00080000, /* modify hint */
  PF_HP_PAGE_SIZE      = 0x00100000, /* use explicit page size */
  PF_HP_FAR_SHARED     = 0x00200000, /* far shared data */
  PF_HP_NEAR_SHARED    = 0x00400000, /* near shared data */
  PF_HP_LAZYSWAP       = 0x00800000, /* lazy swap allocation */
  PF_IA_64_NORECOV     = 0x80000000, /* segment contains code that uses
                                         speculative instructions w/o
                                         recovery code. */
};

/*============================================================================
   The NOTE_* macros are the note types for SHT_NOTE sections
============================================================================*/

#define NOTE_HP_COMPILER  1 /* Compiler identification string */
#define NOTE_HP_COPYRIGHT  2 /* Copyright string */
#define NOTE_HP_VERSION    3 /* Version string */
#define NOTE_HP_SRCFILE_INFO  4 /* Source file info for performance tools */
#define NOTE_HP_LINKER    5 /* Linker identification string */
#define NOTE_HP_INSTRUMENTED    6 /* instrumentation data */
#define NOTE_HP_UX_OPTIONS      7 /* elf hdr extension fields */

/*============================================================================
   The DT_* defines are the allowed values of d_tag in ElfXX_dyn.
   These are the Dynamic Array types.
============================================================================*/

                                           /* (i)gnore (m)andatory */
                                           /* (o)ptional */
                                           /* d_un    Exec  DLL */
                                           /* ----    ----  --- */
enum elf_DT_IA64
{
  DT_HP_LOAD_MAP        = (DT_LOOS + 0x0), /* d_ptr  m  -   */
  DT_HP_DLD_FLAGS       = (DT_LOOS + 0x1), /* d_val  m  -   */
  DT_HP_DLD_HOOK        = (DT_LOOS + 0x2), /* d_ptr  m  -   */
  DT_HP_UX10_INIT       = (DT_LOOS + 0x3), /* d_ptr  o  o   */
  DT_HP_UX10_INITSZ     = (DT_LOOS + 0x4), /* d_ptr  o  o   */
  DT_HP_PREINIT         = (DT_LOOS + 0x5), /* d_ptr  o  -   */
  DT_HP_PREINITSZ       = (DT_LOOS + 0x6), /* d_ptr  o  -   */
  DT_HP_NEEDED          = (DT_LOOS + 0x7), /* d_val  o  o   */
  DT_HP_TIME_STAMP      = (DT_LOOS + 0x8), /* d_val  o  o   */
  DT_HP_CHECKSUM        = (DT_LOOS + 0x9), /* d_val  o  o   */
  DT_HP_GST_SIZE        = (DT_LOOS + 0xa), /* d_val  o  -   */
  DT_HP_GST_VERSION     = (DT_LOOS + 0xb), /* d_val  o  o   */
  DT_HP_GST_HASHVAL     = (DT_LOOS + 0xc), /* d_ptr  o  o   */
  DT_HP_EPLTREL         = (DT_LOOS + 0xd), /* d_ptr  o  o   */
  DT_HP_EPLTRELSZ       = (DT_LOOS + 0xe), /* d_ptr  o  o   */
  DT_HP_FILTERED        = (DT_LOOS + 0xf), /* d_val  -  o   */
  DT_HP_FILTER_TLS      = (DT_LOOS + 0x10),/* d_val  -  o   */
  DT_HP_COMPAT_FILTERED = (DT_LOOS + 0x11),/* d_val  -  o   */
  DT_HP_LAZYLOAD        = (DT_LOOS + 0x12),/* d_val  o  -   */
  DT_HP_BIND_NOW_COUNT  = (DT_LOOS + 0x13),/* d_val  o  o   */
  DT_PLT                = (DT_LOOS + 0x14),/* d_ptr  o  o   */
  DT_PLT_SIZE           = (DT_LOOS + 0x15),/* d_val  o  o   */
  DT_DLT                = (DT_LOOS + 0x16),/* d_ptr  o  o   */
  DT_DLT_SIZE           = (DT_LOOS + 0x17),/* d_val  o  o   */
  DT_HP_SYM_CHECKSUM    = (DT_LOOS + 0x18),/* d_val  o  o   */
  DT_IA_64_PLT_RESERVE  = 0x70000000,
};

#endif
