#ifndef __ELFR_PPC_H__
#define __ELFR_PPC_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

#define EF_PPC_EMB              0x80000000      /* PowerPC embedded flag  */
#define EF_PPC_RELOCATABLE      0x00010000      /* PowerPC -mrelocatable flag */
#define EF_PPC_RELOCATABLE_LIB  0x00008000      /* PowerPC -mrelocatable-lib flag */

// PowerPC 64 ABI version
#define EF_PPC64_ABI_MASK 3     // original function descriptor using ABI
#define EF_PPC64_UNK_ABI  0     // unspecified or not using any features
                                // affected by the differences
#define EF_PPC64_AIX_ABI  1     // original function descriptor using ABI
#define EF_PPC64_V2_ABI   2     // revised ABI without function descriptors

enum elf_ET_PPC
{
  ET_PS3PRX = 0xFFA4, // Sony PS3 PRX
};

enum elf_SHT_PPC
{
  SHT_PS3PRX_RELA = 0x700000A4, // Sony PS3 PRX relocations
};

enum elf_PHT_PPC
{
  PHT_PS3PRX_RELA = 0x700000A4, // Sony PS3 PRX relocations
};

enum elf_DT_PPC
{
  DT_PPC_GOT = (DT_LOPROC + 0x0), // address of _GLOBAL_OFFSET_TABLE_
};

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object
// G-   offset into global objet table
// GOT- adress of global object table
// L-   linkage table entry
// P-   plase of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_ppc
{
  R_PPC_NONE              =  0,       // No reloc
  R_PPC_ADDR32            =  1,   // S+A-P Direct 32 bit
  R_PPC_ADDR24            =  2,
  R_PPC_ADDR16            =  3,
  R_PPC_ADDR16_LO         =  4,
  R_PPC_ADDR16_HI         =  5,
  R_PPC_ADDR16_HA         =  6,
  R_PPC_ADDR14            =  7,
  R_PPC_ADDR14_BRTAKEN    =  8,
  R_PPC_ADDR14_BRNTAKEN   =  9,
  R_PPC_REL24             = 10,   // S+A relative 24 bit
  R_PPC_REL14             = 11,
  R_PPC_REL14_BRTAKEN     = 12,
  R_PPC_REL14_BRNTAKEN    = 13,
  R_PPC_GOT16             = 14,
  R_PPC_GOT16_LO          = 15,
  R_PPC_GOT16_HI          = 16,
  R_PPC_GOT16_HA          = 17,
  R_PPC_PLTREL24          = 18,
  R_PPC_COPY              = 19,
  R_PPC_GLOB_DAT          = 20,
  R_PPC_JMP_SLOT          = 21,
  R_PPC_RELATIVE          = 22,
  R_PPC_LOCAL24PC         = 23,
  R_PPC_UADDR32           = 24,
  R_PPC_UADDR16           = 25,
  R_PPC_REL32             = 26,
  R_PPC_PLT32             = 27,
  R_PPC_PLTREL32          = 28,
  R_PPC_PLT16_LO          = 29,
  R_PPC_PLT16_HI          = 30,
  R_PPC_PLT16_HA          = 31,
  R_PPC_SDAREL16          = 32,
  R_PPC_SECTOFF           = 33,
  R_PPC_SECTOFF_LO        = 34,
  R_PPC_SECTOFF_HI        = 35,
  R_PPC_SECTOFF_HA        = 36,
  R_PPC_ADDR30            = 37, // word30 (S + A - P) >> 2


  // some undocumented relocs used by freescale
  // some seem to be the same as official VLE relocs below
  // NB! they conflict with some PPC64 relocations
  R_PPC_FVLE_REL8         = 38, // same as R_PPC_VLE_REL8?
  R_PPC_FVLE_REL15        = 39, // same as R_PPC_VLE_REL15?
  R_PPC_FVLE_REL24        = 40, // same as R_PPC_VLE_REL24?
  R_PPC_FVLE_ADDR8        = 44, // ??
  R_PPC_FVLE_ADDR4        = 45, // ??
  R_PPC_FVLE_SDA          = 47, // same as R_PPC_VLE_SDA21?
  R_PPC_FVLE_LO16A        = 49, // same as R_PPC_VLE_LO16A?
  R_PPC_FVLE_HI16A        = 50, // same as R_PPC_VLE_HI16A?
  R_PPC_FVLE_HA16A        = 51, // same as R_PPC_VLE_HA16A?
  R_PPC_FVLE_LO16D        = 56, // same as R_PPC_VLE_LO16D?
  R_PPC_FVLE_HI16D        = 57, // same as R_PPC_VLE_HI16D?
  R_PPC_FVLE_HA16D        = 58, // same as R_PPC_VLE_HA16D?

  /* Relocs added to support TLS.  */
  R_PPC_TLS               = 67,
  R_PPC_DTPMOD32          = 68,
  R_PPC_TPREL16           = 69,
  R_PPC_TPREL16_LO        = 70,
  R_PPC_TPREL16_HI        = 71,
  R_PPC_TPREL16_HA        = 72,
  R_PPC_TPREL32           = 73,
  R_PPC_DTPREL16          = 74,
  R_PPC_DTPREL16_LO       = 75,
  R_PPC_DTPREL16_HI       = 76,
  R_PPC_DTPREL16_HA       = 77,
  R_PPC_DTPREL32          = 78,
  R_PPC_GOT_TLSGD16       = 79,
  R_PPC_GOT_TLSGD16_LO    = 80,
  R_PPC_GOT_TLSGD16_HI    = 81,
  R_PPC_GOT_TLSGD16_HA    = 82,
  R_PPC_GOT_TLSLD16       = 83,
  R_PPC_GOT_TLSLD16_LO    = 84,
  R_PPC_GOT_TLSLD16_HI    = 85,
  R_PPC_GOT_TLSLD16_HA    = 86,
  R_PPC_GOT_TPREL16       = 87,
  R_PPC_GOT_TPREL16_LO    = 88,
  R_PPC_GOT_TPREL16_HI    = 89,
  R_PPC_GOT_TPREL16_HA    = 90,
  R_PPC_GOT_DTPREL16      = 91,
  R_PPC_GOT_DTPREL16_LO   = 92,
  R_PPC_GOT_DTPREL16_HI   = 93,
  R_PPC_GOT_DTPREL16_HA   = 94,
  R_PPC_TLSGD             = 95,
  R_PPC_TLSLD             = 96,

  R_PPC_EMB_NADDR32       = 101, // word32 (A - S)
  R_PPC_EMB_NADDR16       = 102, // half16* (A - S)
  R_PPC_EMB_NADDR16_LO    = 103, // half16 #lo(A - S)
  R_PPC_EMB_NADDR16_HI    = 104, // half16 #hi(A - S)
  R_PPC_EMB_NADDR16_HA    = 105, // half16 #ha(A - S)
  R_PPC_EMB_SDA_I16       = 106, // half16* T
  R_PPC_EMB_SDA2_I16      = 107, // half16* U
  R_PPC_EMB_SDA2REL       = 108, // half16* S + A - _SDA2_BASE_
  R_PPC_EMB_SDA21         = 109, // low21 Y || (X + A)
  R_PPC_EMB_MRKREF        = 110, // none See below
  R_PPC_EMB_RELSEC16      = 111, // half16* V + A
  R_PPC_EMB_RELST_LO      = 112, // half16 #lo(W + A)
  R_PPC_EMB_RELST_HI      = 113, // half16 #hi(W + A)
  R_PPC_EMB_RELST_HA      = 114, // half16 #ha(W + A)
  R_PPC_EMB_BIT_FLD       = 115, // word32* See below
  R_PPC_EMB_RELSDA        = 116, // half16* X + A. See below
  R_PPC_EMB_RELOC_120     = 120, // half16* S + A
  R_PPC_EMB_RELOC_121     = 121, // half16* Same calculation as U, except that the value 0 is used instead of _SDA2_BASE_.

/* The R_PPC_DIAB_SDA21_xx relocation modes work like the R_PPC_EMB_SDA21 mode
 * and the R_PPC_DIAB_RELSDA_xx relocation modes work like the R_PPC_EMB_RELSDA mode
 * with the following exceptions:
 * If the symbol is in .data, .sdata, .bss, .sbss the symbol is DATA relative
        (r13 base pointer/_SDA_BASE_ base address)
 * If the symbol is in .text, .sdata2, .sbss2 the symbol is CODE relative
        (r2 base pointer/_SDA_BASE2_ base address)
 * Otherwise the symbol is absolute (r0 base pointer/0 base address)
 */
  R_PPC_DIAB_SDA21_LO     = 180, // half21 Y || #lo(X + A)
  R_PPC_DIAB_SDA21_HI     = 181, // half21 Y || #hi(X + A)
  R_PPC_DIAB_SDA21_HA     = 182, // half21 Y || #ha(X + A)
  R_PPC_DIAB_RELSDA_LO    = 183, // half16 #lo(X + A)
  R_PPC_DIAB_RELSDA_HI    = 184, // half16 #hi(X + A)
  R_PPC_DIAB_RELSDA_HA    = 185, // half16 #ha(X + A)
  R_PPC_DIAB_IMTO         = 186,
  R_PPC_DIAB_IMT          = 187,
  R_PPC_DIAB_ADDR0        = 188,
  R_PPC_DIAB_OVERRIDE0    = 189,
  R_PPC_DIAB_VTBL32       = 190,
  R_PPC_DIAB_LAST         = 191,

  R_PPC_EMB_SPE_DOUBLE         = 201, // mid5* (#lo(S + A)) >> 3
  R_PPC_EMB_SPE_WORD           = 202, // mid5* (#lo(S + A)) >> 2
  R_PPC_EMB_SPE_HALF           = 203, // mid5* (#lo(S + A)) >> 1
  R_PPC_EMB_SPE_DOUBLE_SDAREL  = 204, // mid5* (#lo(S + A - _SDA_BASE_)) >> 3
  R_PPC_EMB_SPE_WORD_SDAREL    = 205, // mid5* (#lo(S + A - _SDA_BASE_)) >> 2
  R_PPC_EMB_SPE_HALF_SDAREL    = 206, // mid5* (#lo(S + A - _SDA_BASE_)) >> 1
  R_PPC_EMB_SPE_DOUBLE_SDA2REL = 207, // mid5* (#lo(S + A - _SDA2_BASE_)) >> 3
  R_PPC_EMB_SPE_WORD_SDA2REL   = 208, // mid5* (#lo(S + A - _SDA2_BASE_)) >> 2
  R_PPC_EMB_SPE_HALF_SDA2REL   = 209, // mid5* (#lo(S + A - _SDA2_BASE_)) >> 1
  R_PPC_EMB_SPE_DOUBLE_SDA0REL = 210, // mid5* (#lo(S + A)) >> 3
  R_PPC_EMB_SPE_WORD_SDA0REL   = 211, // mid5* (#lo(S + A)) >> 2
  R_PPC_EMB_SPE_HALF_SDA0REL   = 212, // mid5* (#lo(S + A)) >> 1
  R_PPC_EMB_SPE_DOUBLE_SDA     = 213, // mid10* Y || ((#lo(X + A)) >> 3)
  R_PPC_EMB_SPE_WORD_SDA       = 214, // mid10* Y || ((#lo(X + A)) >> 2)
  R_PPC_EMB_SPE_HALF_SDA       = 215, // mid10* Y || ((#lo(X + A)) >> 1)

  R_PPC_VLE_REL8          = 216, // bdh8 (S + A - P) >> 1
  R_PPC_VLE_REL15         = 217, // bdh15 (S + A - P) >> 1
  R_PPC_VLE_REL24         = 218, // bdh24 (S + A - P) >> 1
  R_PPC_VLE_LO16A         = 219, // split16a #lo(S + A)
  R_PPC_VLE_LO16D         = 220, // split16d #lo(S + A)
  R_PPC_VLE_HI16A         = 221, // split16a #hi(S + A)
  R_PPC_VLE_HI16D         = 222, // split16d #hi(S + A)
  R_PPC_VLE_HA16A         = 223, // split16a #ha(S + A)
  R_PPC_VLE_HA16D         = 224, // split16d #ha(S + A)
  R_PPC_VLE_SDA21         = 225, // low21, split20  Y || (X + A)
  R_PPC_VLE_SDA21_LO      = 226, // low21, split20 Y || #lo(X + A)
  R_PPC_VLE_SDAREL_LO16A  = 227, // split16a #lo(X + A)
  R_PPC_VLE_SDAREL_LO16D  = 228, // split16d #lo(X + A)
  R_PPC_VLE_SDAREL_HI16A  = 229, // split16a #hi(X + A)
  R_PPC_VLE_SDAREL_HI16D  = 230, // split16d #hi(X + A)
  R_PPC_VLE_SDAREL_HA16A  = 231, // split16a #ha(X + A)
  R_PPC_VLE_SDAREL_HA16D  = 232, // split16d #ha(X + A)

  R_PPC_REL16DX_HA        = 246,

  R_PPC_IRELATIVE         = 248, // GNU extension to support local ifunc.
 /* GNU relocs used in PIC code sequences.  */
  R_PPC_REL16             = 249, // half16*  S + A - P
  R_PPC_REL16_LO          = 250, // half16   #lo(S + A - P)
  R_PPC_REL16_HI          = 251, // half16   #hi(S + A - P)
  R_PPC_REL16_HA          = 252, // half16   #la(S + A - P)

  R_PPC_GNU_VTINHERIT     =  253,
  R_PPC_GNU_VTENTRY       =  254,
/* This is a phony reloc to handle any old fashioned TOC16 references
   that may still be in object files.  */
  R_PPC_TOC16             =  255,

  // PowerPC64 relocations. Many (but not all) of them are the same as for PPC32
  R_PPC64_NONE              =  R_PPC_NONE,
  R_PPC64_ADDR32            =  R_PPC_ADDR32,  /* 32bit absolute address.  */
  R_PPC64_ADDR24            =  R_PPC_ADDR24,  /* 26bit address, word aligned.  */
  R_PPC64_ADDR16            =  R_PPC_ADDR16,  /* 16bit absolute address. */
  R_PPC64_ADDR16_LO         =  R_PPC_ADDR16_LO, /* lower 16bits of abs. address.  */
  R_PPC64_ADDR16_HI         =  R_PPC_ADDR16_HI, /* high 16bits of abs. address. */
  R_PPC64_ADDR16_HA         =  R_PPC_ADDR16_HA, /* adjusted high 16bits.  */
  R_PPC64_ADDR14            =  R_PPC_ADDR14,   /* 16bit address, word aligned.  */
  R_PPC64_ADDR14_BRTAKEN    =  R_PPC_ADDR14_BRTAKEN,
  R_PPC64_ADDR14_BRNTAKEN   =  R_PPC_ADDR14_BRNTAKEN,
  R_PPC64_REL24             =  R_PPC_REL24, /* PC relative 26 bit, word aligned.  */
  R_PPC64_REL14             =  R_PPC_REL14, /* PC relative 16 bit. */
  R_PPC64_REL14_BRTAKEN     =  R_PPC_REL14_BRTAKEN,
  R_PPC64_REL14_BRNTAKEN    =  R_PPC_REL14_BRNTAKEN,
  R_PPC64_GOT16             =  R_PPC_GOT16,
  R_PPC64_GOT16_LO          =  R_PPC_GOT16_LO,
  R_PPC64_GOT16_HI          =  R_PPC_GOT16_HI,
  R_PPC64_GOT16_HA          =  R_PPC_GOT16_HA,
  R_PPC64_PLTREL24          =  R_PPC_PLTREL24,
  R_PPC64_COPY              =  R_PPC_COPY,
  R_PPC64_GLOB_DAT          =  R_PPC_GLOB_DAT,
  R_PPC64_JMP_SLOT          =  R_PPC_JMP_SLOT,
  R_PPC64_RELATIVE          =  R_PPC_RELATIVE,
  R_PPC64_LOCAL24PC         =  R_PPC_LOCAL24PC,
  R_PPC64_UADDR32           =  R_PPC_UADDR32,
  R_PPC64_UADDR16           =  R_PPC_UADDR16,
  R_PPC64_REL32             =  R_PPC_REL32,
  R_PPC64_PLT32             =  R_PPC_PLT32,
  R_PPC64_PLTREL32          =  R_PPC_PLTREL32,
  R_PPC64_PLT16_LO          =  R_PPC_PLT16_LO,
  R_PPC64_PLT16_HI          =  R_PPC_PLT16_HI,
  R_PPC64_PLT16_HA          =  R_PPC_PLT16_HA,
  R_PPC64_SDAREL16          =  R_PPC_SDAREL16,
  R_PPC64_SECTOFF           =  R_PPC_SECTOFF,
  R_PPC64_SECTOFF_LO        =  R_PPC_SECTOFF_LO,
  R_PPC64_SECTOFF_HI        =  R_PPC_SECTOFF_HI,
  R_PPC64_SECTOFF_HA        =  R_PPC_SECTOFF_HA,

  R_PPC64_ADDR30            =  37,  /* word30 (S + A - P) >> 2.  */
  R_PPC64_ADDR64            =  38,  /* doubleword64 S + A.  */
  R_PPC64_ADDR16_HIGHER     =  39,  /* half16 #higher(S + A).  */
  R_PPC64_ADDR16_HIGHERA    =  40,  /* half16 #highera(S + A).  */
  R_PPC64_ADDR16_HIGHEST    =  41,  /* half16 #highest(S + A).  */
  R_PPC64_ADDR16_HIGHESTA   =  42,  /* half16 #highesta(S + A). */
  R_PPC64_UADDR64           =  43,  /* doubleword64 S + A.  */
  R_PPC64_REL64             =  44,  /* doubleword64 S + A - P.  */
  R_PPC64_PLT64             =  45,  /* doubleword64 L + A.  */
  R_PPC64_PLTREL64          =  46,  /* doubleword64 L + A - P.  */
  R_PPC64_TOC16             =  47,  /* half16* S + A - .TOC.  */
  R_PPC64_TOC16_LO          =  48,  /* half16 #lo(S + A - .TOC.).  */
  R_PPC64_TOC16_HI          =  49,  /* half16 #hi(S + A - .TOC.).  */
  R_PPC64_TOC16_HA          =  50,  /* half16 #ha(S + A - .TOC.).  */
  R_PPC64_TOC               =  51,  /* doubleword64 .TOC. */
  R_PPC64_PLTGOT16          =  52,  /* half16* M + A.  */
  R_PPC64_PLTGOT16_LO       =  53,  /* half16 #lo(M + A).  */
  R_PPC64_PLTGOT16_HI       =  54,  /* half16 #hi(M + A).  */
  R_PPC64_PLTGOT16_HA       =  55,  /* half16 #ha(M + A).  */

  R_PPC64_ADDR16_DS         =  56, /* half16ds* (S + A) >> 2.  */
  R_PPC64_ADDR16_LO_DS      =  57, /* half16ds  #lo(S + A) >> 2.  */
  R_PPC64_GOT16_DS          =  58, /* half16ds* (G + A) >> 2.  */
  R_PPC64_GOT16_LO_DS       =  59, /* half16ds  #lo(G + A) >> 2.  */
  R_PPC64_PLT16_LO_DS       =  60, /* half16ds  #lo(L + A) >> 2.  */
  R_PPC64_SECTOFF_DS        =  61, /* half16ds* (R + A) >> 2.  */
  R_PPC64_SECTOFF_LO_DS     =  62, /* half16ds  #lo(R + A) >> 2.  */
  R_PPC64_TOC16_DS          =  63, /* half16ds* (S + A - .TOC.) >> 2.  */
  R_PPC64_TOC16_LO_DS       =  64, /* half16ds  #lo(S + A - .TOC.) >> 2.  */
  R_PPC64_PLTGOT16_DS       =  65, /* half16ds* (M + A) >> 2.  */
  R_PPC64_PLTGOT16_LO_DS    =  66, /* half16ds  #lo(M + A) >> 2.  */

/* PowerPC64 relocations defined for the TLS access ABI.  */
  R_PPC64_TLS               =  67, /* none      (sym+add)@tls */
  R_PPC64_DTPMOD64          =  68, /* doubleword64 (sym+add)@dtpmod */
  R_PPC64_TPREL16           =  69, /* half16*   (sym+add)@tprel */
  R_PPC64_TPREL16_LO        =  70, /* half16    (sym+add)@tprel@l */
  R_PPC64_TPREL16_HI        =  71, /* half16    (sym+add)@tprel@h */
  R_PPC64_TPREL16_HA        =  72, /* half16    (sym+add)@tprel@ha */
  R_PPC64_TPREL64           =  73, /* doubleword64 (sym+add)@tprel */
  R_PPC64_DTPREL16          =  74, /* half16*   (sym+add)@dtprel */
  R_PPC64_DTPREL16_LO       =  75, /* half16    (sym+add)@dtprel@l */
  R_PPC64_DTPREL16_HI       =  76, /* half16    (sym+add)@dtprel@h */
  R_PPC64_DTPREL16_HA       =  77, /* half16    (sym+add)@dtprel@ha */
  R_PPC64_DTPREL64          =  78, /* doubleword64 (sym+add)@dtprel */
  R_PPC64_GOT_TLSGD16       =  79, /* half16*   (sym+add)@got@tlsgd */
  R_PPC64_GOT_TLSGD16_LO    =  80, /* half16    (sym+add)@got@tlsgd@l */
  R_PPC64_GOT_TLSGD16_HI    =  81, /* half16    (sym+add)@got@tlsgd@h */
  R_PPC64_GOT_TLSGD16_HA    =  82, /* half16    (sym+add)@got@tlsgd@ha */
  R_PPC64_GOT_TLSLD16       =  83, /* half16*   (sym+add)@got@tlsld */
  R_PPC64_GOT_TLSLD16_LO    =  84, /* half16    (sym+add)@got@tlsld@l */
  R_PPC64_GOT_TLSLD16_HI    =  85, /* half16    (sym+add)@got@tlsld@h */
  R_PPC64_GOT_TLSLD16_HA    =  86, /* half16    (sym+add)@got@tlsld@ha */
  R_PPC64_GOT_TPREL16_DS    =  87, /* half16ds* (sym+add)@got@tprel */
  R_PPC64_GOT_TPREL16_LO_DS =  88, /* half16ds (sym+add)@got@tprel@l */
  R_PPC64_GOT_TPREL16_HI    =  89, /* half16    (sym+add)@got@tprel@h */
  R_PPC64_GOT_TPREL16_HA    =  90, /* half16    (sym+add)@got@tprel@ha */
  R_PPC64_GOT_DTPREL16_DS   =  91, /* half16ds* (sym+add)@got@dtprel */
  R_PPC64_GOT_DTPREL16_LO_DS = 92, /* half16ds (sym+add)@got@dtprel@l */
  R_PPC64_GOT_DTPREL16_HI   =  93, /* half16    (sym+add)@got@dtprel@h */
  R_PPC64_GOT_DTPREL16_HA   =  94, /* half16    (sym+add)@got@dtprel@ha */
  R_PPC64_TPREL16_DS        =  95, /* half16ds* (sym+add)@tprel */
  R_PPC64_TPREL16_LO_DS     =  96, /* half16ds  (sym+add)@tprel@l */
  R_PPC64_TPREL16_HIGHER    =  97, /* half16    (sym+add)@tprel@higher */
  R_PPC64_TPREL16_HIGHERA   =  98, /* half16    (sym+add)@tprel@highera */
  R_PPC64_TPREL16_HIGHEST   =  99, /* half16    (sym+add)@tprel@highest */
  R_PPC64_TPREL16_HIGHESTA  =  100, /* half16  (sym+add)@tprel@highesta */
  R_PPC64_DTPREL16_DS       =  101, /* half16ds* (sym+add)@dtprel */
  R_PPC64_DTPREL16_LO_DS    =  102, /* half16ds (sym+add)@dtprel@l */
  R_PPC64_DTPREL16_HIGHER   =  103, /* half16   (sym+add)@dtprel@higher */
  R_PPC64_DTPREL16_HIGHERA  =  104, /* half16  (sym+add)@dtprel@highera */
  R_PPC64_DTPREL16_HIGHEST  =  105, /* half16  (sym+add)@dtprel@highest */
  R_PPC64_DTPREL16_HIGHESTA =  106, /* half16 (sym+add)@dtprel@highesta */
#if 0
  // These relocation types appear in David Anderson's libdwarf and
  // dwarfdump only. The PPC 64-Bit ELF V2 ABI uses these numbers for
  // different types (see below).
  R_PPC64_TOC32             =  107, /* word32 (.TOC. & 0xffff_ffff)  */
  R_PPC64_DTPMOD32          =  108, /* word32 (@dtpmod & 0xffff_ffff) */
  R_PPC64_TPREL32           =  109, /* word32 (@tprel & 0xffff_ffff) */
  R_PPC64_DTPREL32          =  110, /* word32 (@dtprel & 0xffff_ffff) */
#else
  // The PPC 64-Bit ELF V2 ABI uses these numbers for different types
  R_PPC64_TLSGD             =  107, // used as markers on thread local
  R_PPC64_TLSLD             =  108, // storage (TLS) code sequences
  R_PPC64_TOCSAVE           =  109, // this relocation type indicates a
                                    // position where a TOC save may be
                                    // inserted in the function to avoid a
                                    // TOC save as part of the PLT stub code
  R_PPC64_ADDR16_HIGH       =  110, // half16  #hi(S + A)
  R_PPC64_ADDR16_HIGHA      =  111, // half16  #ha(S + A)
  R_PPC64_TPREL16_HIGH      =  112, // half16  #hi(@tprel)
  R_PPC64_TPREL16_HIGHA     =  113, // half16  #ha(@tprel)
  R_PPC64_DTPREL16_HIGH     =  114, // half16  #hi(@dtprel)
  R_PPC64_DTPREL16_HIGHA    =  115, // half16  #ha(@dtprel)
  R_PPC64_REL24_NOTOC       =  116, // low24*  (S + A - P) >> 2
  R_PPC64_ADDR64_LOCAL      =  117, // doubleword64 S + A (see 3.5.4)
  R_PPC64_ENTRY              = 118, // none      none
  R_PPC64_PLTSEQ             = 119, // none      none
  R_PPC64_PLTCALL            = 120, // none      none
  R_PPC64_PLTSEQ_NOTOC       = 121, // none      none
  R_PPC64_PLTCALL_NOTOC      = 122, // none      none
  R_PPC64_PCREL_OPT          = 123, // none      none
  R_PPC64_D34                = 128, // prefix34* S + A
  R_PPC64_D34_LO             = 129, // prefix34  #lo34(S + A)
  R_PPC64_D34_HI30           = 130, // prefix34  #hi30(S + A)
  R_PPC64_D34_HA30           = 131, // prefix34  #ha30(S + A)
  R_PPC64_PCREL34            = 132, // prefix34* S + A - P
  R_PPC64_GOT_PCREL34        = 133, // prefix34* G - P
  R_PPC64_PLT_PCREL34        = 134, // prefix34* L - P
  R_PPC64_PLT_PCREL34_NOTOC  = 135, // prefix34* L - P
  R_PPC64_ADDR16_HIGHER34    = 136, // half16    #higher34(S + A)
  R_PPC64_ADDR16_HIGHERA34   = 137, // half16    #highera34(S + A)
  R_PPC64_ADDR16_HIGHEST34   = 138, // half16    #highest34(S + A)
  R_PPC64_ADDR16_HIGHESTA34  = 139, // half16    #highesta34(S + A)
  R_PPC64_REL16_HIGHER34     = 140, // half16    #higher34(S + A - P)
  R_PPC64_REL16_HIGHERA34    = 141, // half16    #highera34(S + A - P)
  R_PPC64_REL16_HIGHEST34    = 142, // half16    #highest34(S + A - P)
  R_PPC64_REL16_HIGHESTA34   = 143, // half16    #highesta34(S + A - P)
  R_PPC64_D28                = 144, // prefix28* S + A
  R_PPC64_PCREL28            = 145, // prefix28* S + A - P
  R_PPC64_TPREL34            = 146, // prefix34* @tprel
  R_PPC64_DTPREL34           = 147, // prefix34* @dtprel
  R_PPC64_GOT_TLSGD_PCREL34  = 148, // prefix34* @got@tlsgd - P
  R_PPC64_GOT_TLSLD_PCREL34  = 149, // prefix34* @got@tlsld - P
  R_PPC64_GOT_TPREL_PCREL34  = 150, // prefix34* @got@tprel - P
  R_PPC64_GOT_DTPREL_PCREL34 = 151, // prefix34* @got@dtprel - P
#endif
  R_PPC64_JMP_IREL          =  247, // GNU extension to support local ifunc
  // The PPC 64-Bit ELF V2 ABI
  R_PPC64_IRELATIVE         =  248, // It is used to implement the
                                    // STT_GNU_IFUNC framework
  R_PPC64_REL16             =  R_PPC_REL16,     // half16*  S + A - P
  R_PPC64_REL16_LO          =  R_PPC_REL16_LO,  // half16   #lo(S + A - P)
  R_PPC64_REL16_HI          =  R_PPC_REL16_HI,  // half16*  #hi(S + A - P)
  R_PPC64_REL16_HA          =  R_PPC_REL16_HA,  // half16*  #la(S + A - P)
};

// flags for VLE code
#define SHF_PPC_VLE    0x10000000 /* section header flag */
#define PF_PPC_VLE     0x10000000 /* program header flag */

// patching GOT loading,
// discard auxiliary values in plt/got
// can present offset bypass segment
#define ELF_RPL_PPC_DEFAULT  (ELF_RPL_GL | ELF_DIS_OFFW | ELF_DIS_GPLT)

#endif
