#ifndef __AOUT_H__
#define __AOUT_H__
#pragma pack(push, 1)

struct exec
{
  uint32   a_info;    // Use macros N_MAGIC, etc for access
  uint32   a_text;    // length of text, in bytes
  uint32   a_data;    // length of data, in bytes
  uint32   a_bss;     // length of bss area for file, in bytes
  uint32   a_syms;    // length of symbol table data in file, in bytes
  uint32   a_entry;   // start address
  uint32   a_trsize;  // length of relocation info for text, in bytes
  uint32   a_drsize;  // length of relocation info for data, in bytes
// Added for i960
//  uint32   a_tload;   // Text runtime load adderr
//  uint32   a_dload;   // Data runtime load address
//  uchar   a_talign;   // Alignment of text segment
//  uchar   a_dalign;   // Alignmrnt of data segment
//  uchar   a_balign;   // Alignment of bss segment
//  char    a_relaxable;// Enough info for linker relax
};
//====================
#define N_TRSIZE(a)   ((a).a_trsize)
#define N_DRSIZE(a)   ((a).a_drsize)
#define N_SYMSIZE(a)    ((a).a_syms)

#define N_DYNAMIC(exec) ((exec).a_info & 0x80000000)

#define N_MAGIC(exec)    ((exec).a_info & 0xffff)
#define N_MACHTYPE(exec) ((enum machine_type)(((exec).a_info >> 16) & 0xff))
#define N_FLAGS(exec)    (((exec).a_info >> 24) & 0xff)
//====================
enum machine_type
{
//  M_OLDSUN2 = 0,
  M_UNKNOWN       = 0,
  M_68010         = 1,
  M_68020         = 2,
  M_SPARC         = 3,
  /*-----------------11.07.98 04:09-------------------
   * skip a bunch so we don't run into any of suns numbers */
  /*-----------------11.07.98 04:09-------------------
   * make these up for the ns32k*/
  M_NS32032       = (64),           /* ns32032 running ? */
  M_NS32532       = (64 + 5),       /* ns32532 running mach */
  M_386           = 100,
  M_29K           = 101,            /* AMD 29000 */
  M_386_DYNIX     = 102,            /* Sequent running dynix */
  M_ARM           = 103,            /* Advanced Risc Machines ARM */
  M_SPARCLET      = 131,            /* SPARClet = M_SPARC + 128 */
  M_386_NETBSD    = 134,            /* NetBSD/i386 binary */
  M_68K_NETBSD    = 135,            /* NetBSD/m68k binary */
  M_68K4K_NETBSD  = 136,            /* NetBSD/m68k4k binary */
  M_532_NETBSD    = 137,            /* NetBSD/ns32k binary */
  M_SPARC_NETBSD  = 138,            /* NetBSD/sparc binary */
  M_PMAX_NETBSD   = 139,            /* NetBSD/pmax (MIPS little-endian) binary */
  M_VAX_NETBSD    = 140,            /* NetBSD/vax binary */
  M_ALPHA_NETBSD  = 141,            /* NetBSD/alpha binary */
  M_ARM6_NETBSD   = 143,            /* NetBSD/arm32 binary */
  M_SPARCLET_1    = 147,            /* 0x93, reserved */
  M_MIPS1         = 151,            /* MIPS R2000/R3000 binary */
  M_MIPS2         = 152,            /* MIPS R4000/R6000 binary */
  M_SPARCLET_2    = 163,            /* 0xa3, reserved */
  M_SPARCLET_3    = 179,            /* 0xb3, reserved */
  M_SPARCLET_4    = 195,            /* 0xc3, reserved */
  M_HP200         = 200,            /* HP 200 (68010) BSD binary */
  M_HP300         = (300 % 256),    /* HP 300 (68020+68881) BSD binary */
  M_HPUX          = (0x20c % 256),  /* HP 200/300 HPUX binary */
  M_SPARCLET_5    = 211,            /* 0xd3, reserved */
  M_SPARCLET_6    = 227,            /* 0xe3, reserved */
  M_SPARCLET_7    = 243             /* 0xf3, reserved */
};
//====================
#define OMAGIC 0407   // object file or impure executable
#define NMAGIC 0410   // pure executeable
#define ZMAGIC 0413   // demand-paged executable
#define BMAGIC 0415   // Used by a b.out object
#define QMAGIC 0314   // demand-paged executable with the header in the text.
                      // The first page is unmapped to help trap nullptr pointer
                      // referenced
#define CMAGIC 0421   // core file
//====================
// Flags:
#define EX_PIC          0x80    /* contains position independent code */
#define EX_DYNAMIC      0x40    /* contains run-time link-edit info */
#define EX_DPMASK       0xC0    /* mask for the above */
//====================

#define N_BADMAG(x)   (N_MAGIC(x) != OMAGIC \
                    && N_MAGIC(x) != NMAGIC \
                    && N_MAGIC(x) != ZMAGIC \
                    && N_MAGIC(x) != QMAGIC)

#define _N_HDROFF(x) (1024 - sizeof(struct exec))

#define N_TXTOFF(x)                                              \
 (N_MAGIC(x) == ZMAGIC ? _N_HDROFF((x)) + sizeof (struct exec) : \
                        (N_MAGIC(x) == QMAGIC ? 0 : sizeof (struct exec)))

#define N_DATOFF(x) (N_TXTOFF(x) + (x).a_text)
#define N_TRELOFF(x) (N_DATOFF(x) + (x).a_data)
#define N_DRELOFF(x) (N_TRELOFF(x) + N_TRSIZE(x))
#define N_SYMOFF(x) (N_DRELOFF(x) + N_DRSIZE(x))
#define N_STROFF(x) (N_SYMOFF(x) + (x).a_syms)

// Address of text segment in memory after it is loaded
#define PAGE_SIZE (1 << 12)
#define N_TXTADDR(x) (N_MAGIC(x) == QMAGIC ? PAGE_SIZE : 0)

#define PAGE_SIZE_ARM 0x8000
#define N_TXTADDR_ARM(x) (N_MAGIC(x) == QMAGIC ? 0 : PAGE_SIZE_ARM)

// Address of data segment in memory after it is loaded. (for linux)
/*
#define SEGMENT_SIZE  1024
#define _N_SEGMENT_ROUND(x) (((x) + SEGMENT_SIZE - 1) & ~(SEGMENT_SIZE - 1))
#define _N_TXTENDADDR(x)    (N_TXTADDR(x)+(x).a_text)
#define N_DATADDR(x)                                           \
                     (N_MAGIC(x)==OMAGIC? (_N_TXTENDADDR(x)) : \
                     (_N_SEGMENT_ROUND (_N_TXTENDADDR(x))))
// Address of bss segment in memory after it is loaded
#define N_BSSADDR(x) (N_DATADDR(x) + (x).a_data)
*/
//========================
struct nlist
{
  union
  {
    int32 n_strx;
  } n_un;
  uchar n_type;
  char  n_other;
  short n_desc;
  uint32 n_value;
};

#define N_UNDF    0     // Undefined symbol
#define N_ABS     2     // Absolute symbol -- addr
#define N_TEXT    4     // Text sym -- offset in text segment
#define N_DATA    6     // Data sym -- offset in data segment
#define N_BSS     8     // BSS sym  -- offset in bss segment
#define N_COMM    0x12  // Common symbol (visible after shared)
#define N_FN      0x1F  // File name of .o file
#define N_FN_SEQ  0x0C  // N_FN from Sequent compilers

#define N_EXT     1     // External (ORed wits UNDF, ABS, TEXT, DATA or BSS)
#define N_TYPE    0x1E
#define N_STAB    0xE0  // If present - debug symbol

#define N_INDR    0xA   // symbol refernced to another symbol

#define N_SETA    0x14  // Absolute set element symbol
#define N_SETT    0x16  // Text set element symbol
#define N_SETD    0x18  // Data set element symbol
#define N_SETB    0x1A  // Bss set element symbol

#define N_SETV    0x1C  // Pointer to set vector in data area. (from LD)

#define N_WARNING 0x1E  // Text has warnings

// Weak symbols
#define N_WEAKU   0x0D  // Weak undefined
#define N_WEAKA   0x0E  // Weak Absolute
#define N_WEAKT   0x0F  // Weak Text
#define N_WEAKD   0x10  // Weak Data
#define N_WEAKB   0x11  // Weak BSS

//=======================

struct relocation_info
{
  int32 r_address;      // Adress (within segment) to be relocated
  uint32 r_symbolnum:24;// The meaning of r_symbolnum depends on r_extern
  uint32 r_pcrel:1;     // Nonzero means value is a pc-relative offset
  uint32 r_length:2;    // Length (exp of 2) of the field to be relocated.
  uint32 r_extern:1;    // 1 => relocate with value of symbol.
                        //      r_symbolnum is the index of the symbol
                        //      in file's the symbol table.
                        // 0 => relocate with the address of a segment.
                        //      r_symbolnum is N_TEXT, N_DATA, N_BSS or N_ABS
  uint32 r_bsr:1;
  uint32 r_disp:1;
  uint32 r_pad:2;
};

//============================
// The SPARC_ prefix is added to the canonical names below to avoid a name
// conflict if other architectures are added

enum reloc_type_sparc
{
  SPARC_RELOC_8,        SPARC_RELOC_16,        SPARC_RELOC_32,       // simplest relocs
  SPARC_RELOC_DISP8,    SPARC_RELOC_DISP16,    SPARC_RELOC_DISP32,   // disp's (pc-rel)
  SPARC_RELOC_WDISP30,  SPARC_RELOC_WDISP22,                         // SR word disp's
  SPARC_RELOC_HI22,     SPARC_RELOC_22,                              // SR 22-bit relocs
  SPARC_RELOC_13,       SPARC_RELOC_LO10,                            // SR 13&10-bit relocs
  SPARC_RELOC_SFA_BASE, SPARC_RELOC_SFA_OFF13,                       // SR S.F.A. relocs
  SPARC_RELOC_BASE10,   SPARC_RELOC_BASE13, SPARC_RELOC_BASE22,      // base_relative pic
  SPARC_RELOC_PC10,     SPARC_RELOC_PC22,                            // special pc-rel pic
  SPARC_RELOC_JMP_TBL,                                               // jmp_tbl_rel in pic
  SPARC_RELOC_SEGOFF16,                                              // ShLib offset-in-seg
  SPARC_RELOC_GLOB_DAT, SPARC_RELOC_JMP_SLOT, SPARC_RELOC_RELATIVE,  // rtld relocs
};

struct reloc_info_sparc
{
  uint32 r_address;     // relocation address (offset in segment)
  uint32 r_index:24;    // segment index or symbol index
  uint32 r_extern:1;    // if F, r_index==SEG#, if T, SYM index
  uint32 :2;            // unused
  uint32 r_type:5; // type of relocation to perform
  uint32 r_addend;      // addend for relocation value
};

CASSERT(sizeof(reloc_info_sparc) == 12);

#define N_PAGSIZ_SPARC(x) 0x02000
#define N_SEGSIZ_SPARC(x) N_PAGSIZ_SPARC

#define N_TXTOFF_SPARC(x) ((N_MAGIC(x) == ZMAGIC) ? 0 : sizeof (struct exec))
#define N_TXTADDR_SPARC(x) \
    ((N_MAGIC(x) == OMAGIC) ? (x).a_entry \
    : ((N_MAGIC(x) == ZMAGIC) && ((x).a_entry < N_PAGSIZ_SPARC(x)) ? 0 \
    : N_PAGSIZ_SPARC(x)) \
    )

#define N_DATOFF_SPARC(x) (N_TXTOFF_SPARC(x) + (x).a_text)
#define N_DATADDR_SPARC(x) \
    ((N_MAGIC(x) == OMAGIC) ? (N_TXTADDR_SPARC(x) + (x).a_text) \
    : (N_SEGSIZ_SPARC(x)+((N_TXTADDR_SPARC(x)+(x).a_text-1) \
                         & ~(N_SEGSIZ_SPARC(x)-1))))

#define N_BSSADDR_SPARC(x) (N_DATADDR_SPARC(x) + (x).a_data)

#define N_TRELOFF_SPARC(x) (N_DATOFF_SPARC(x) + (x).a_data)
#define N_DRELOFF_SPARC(x) (N_TRELOFF_SPARC(x) + N_TRSIZE(x))
#define N_SYMOFF_SPARC(x) (N_DRELOFF_SPARC(x) + N_DRSIZE(x))
#define N_STROFF_SPARC(x) (N_SYMOFF_SPARC(x) + (x).a_syms)


//============================
// Dynamic loader info (restored from a binary form in pc_bsd.aout, not exact):

struct lddir_t
{
  uint32 unknown0; // 8
  uint32 unknown1; // offset dword_5010
  uint32 ldinfo;
};

struct ld_info_t
{
  uint32 unknown0; // 0
  uint32 onemoretable;
  uint32 unknown1; // 0
  uint32 off_5060; // points to the end of this struct
  uint32 ldentry;  // main dynamic loader entry
  uint32 imports;
  uint32 pairs;    // pairs of symbol numbers
  uint32 symbols;
  uint32 unknown2; // 0
  uint32 unknown3; // 16h
  uint32 strings;
  uint32 unknown4; // 310h
  uint32 unknown5; // 4000h
  uint32 unknown6; // 148h
  uint32 unknown7; // offset dword_5000
};

struct ld_symbol_t
{
  uint32 nameoff;  // offset from the beginning of the string table
  uint32 flags;
#define AOUT_LD_FUNC   0x200
#define AOUT_LD_DEF    0x004 // defined, otherwise - imported
#define AOUT_LD_DATA   0x002 // data
  uint32 addr;     // pointer to the object
  uint32 zero;     // always zero?
};

#pragma pack(pop)
#endif
