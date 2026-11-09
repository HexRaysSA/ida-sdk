#ifndef __ELFBASE_H__
#define __ELFBASE_H__
#pragma pack(push, 4)

//=========================================================================
struct elf_ident_t
{
  uint32 magic;
#if __MF__
#  define ELF_MAGIC 0x7F454C46 // big endian \x7FELF
#else
#  define ELF_MAGIC 0x464C457F // litte endian \x7FELF
#endif
  uint8 elf_class;
#define   ELFCLASSNONE  0    // Invalid class
#define   ELFCLASS32    1    // 32bit object
#define   ELFCLASS64    2    // 64bit object
  uint8 bytesex;
#define   ELFDATANONE    0   // Invalid data encoding
#define   ELFDATA2LSB    1   // low byte first
#define   ELFDATA2MSB    2   // high byte first
  uint8 version;             // file version
  uint8 osabi;               // Operating System/ABI indication
#define   ELFOSABI_NONE          0 // UNIX System V ABI
#define   ELFOSABI_HPUX          1 // HP-UX operating system
#define   ELFOSABI_NETBSD        2 // NetBSD
#define   ELFOSABI_LINUX         3 // GNU/Linux
#define   ELFOSABI_HURD          4 // GNU/Hurd
#define   ELFOSABI_SOLARIS       6 // Solaris
#define   ELFOSABI_AIX           7 // AIX
#define   ELFOSABI_IRIX          8 // IRIX
#define   ELFOSABI_FREEBSD       9 // FreeBSD
#define   ELFOSABI_TRU64        10 // TRU64 UNIX
#define   ELFOSABI_MODESTO      11 // Novell Modesto
#define   ELFOSABI_OPENBSD      12 // OpenBSD
#define   ELFOSABI_OPENVMS      13 // OpenVMS
#define   ELFOSABI_NSK          14 // Hewlett-Packard Non-Stop Kernel
#define   ELFOSABI_AROS         15 // Amiga Research OS
#define   ELFOSABI_C6000_ELFABI 64 // Texas Instruments TMS320C6 bare-metal
#define   ELFOSABI_C6000_LINUX  65 // TI TMS320C6 MMU-less Linux platform
#define   ELFOSABI_ARM          97 // ARM
#define   ELFOSABI_CELLOSLV2   102 // PS3 lv2 OS
#define   ELFOSABI_NACL        123 // ChromeOS Native Client
#define   ELFOSABI_STANDALONE  255 // Standalone (embedded) application
  uint8 abiversion;          // ABI version
  uint8 pad[7];

  bool is_valid() const { return magic == ELF_MAGIC; }
  bool is_msb()   const { return bytesex == ELFDATA2MSB; }
  bool is_64()    const { return elf_class == ELFCLASS64; }
};

struct Elf32_Ehdr
{
  elf_ident_t e_ident;
  uint16  e_type;               // enum ET
  uint16  e_machine;            // enum EM
  uint32  e_version;            // enum EV
  uint32  e_entry;              // virtual start address
  uint32  e_phoff;              // off to program header table's (pht)
  uint32  e_shoff;              // off to section header table's (sht)
  uint32  e_flags;              // EF_machine_flag
  uint16  e_ehsize;             // header's size
  uint16  e_phentsize;          // size of pht element
  uint16  e_phnum;              // entry counter in pht
  uint16  e_shentsize;          // size of sht element
  uint16  e_shnum;              // entry count in sht
  uint16  e_shstrndx;           // sht index in name table
};


enum elf_ET
{
  ET_NONE = 0,    // No file type
  ET_REL  = 1,    // Relocatable file
  ET_EXEC = 2,    // Executable file
  ET_DYN  = 3,    // Share object file
  ET_CORE = 4,    // Core file
  ET_LOOS   = 0xfe00u,  // OS specific
  ET_HIOS   = 0xfeffu,  // OS specific
  ET_LOPROC = 0xff00u,  // Processor specific
  ET_HIPROC = 0xffffu   // Processor specific
};

enum elf_EM
{
  EM_NONE           = 0,   // No machine
  EM_M32            = 1,   // AT & T WE 32100
  EM_SPARC          = 2,   // Sparc
  EM_386            = 3,   // Intel 80386
  EM_68K            = 4,   // Motorola 68000
  EM_88K            = 5,   // Motorola 88000
  EM_486            = 6,
  // ATTENTION!!! in documentation present next values
  //  EM_860   = 6,   // Intel 80860
  //  EM_MIPS  = 7,    // MIPS RS3000
  // in linux RS3000 = 8, !!!
  // taken from linux
  EM_860            =  7,
  EM_MIPS           =  8,  // Mips 3000 (officialy, big-endian only)
  EM_S370           =  9,  // IBM System370
  EM_MIPS_RS3_BE    = 10,  // MIPS R3000 Big Endian
  //  EM_SPARC_64 = 11,    // SPARC v9
  EM_PARISC         = 15,  // HPPA
  EM_VPP550         = 17,  // Fujitsu VPP500
  EM_SPARC32PLUS    = 18,  // Sun's v8plus
  EM_I960           = 19,  // Intel 960
  EM_PPC            = 20,  // Power PC
  EM_PPC64          = 21,  // 64-bit PowerPC
  EM_S390           = 22,  // IBM S/390
  EM_SPU            = 23,  // Cell Broadband Engine Synergistic Processor Unit
  EM_CISCO7200      = 25,  // Cisco 7200 Series Router (MIPS)
  EM_CISCO3620      = 30,  // Cisco 3620/3640 Router (MIPS, IDT R4700)
  EM_V800           = 36,  // NEC V800 series
  EM_FR20           = 37,  // Fujitsu FR20
  EM_RH32           = 38,  // TRW RH32
  EM_MCORE          = 39,  // Motorola M*Core (May also be taken by Fujitsu MMA)
  EM_ARM            = 40,  // ARM
  EM_OLD_ALPHA      = 41,  // Digital Alpha
  EM_SH             = 42,  // Renesas (formerly Hitachi) / SuperH SH
  EM_SPARC64        = 43,  // Sparc v9 64-bit
  EM_TRICORE        = 44,  // Siemens Tricore embedded processor
  EM_ARC            = 45,  // ARC Cores
  EM_H8300          = 46,  // Renesas (formerly Hitachi) H8/300
  EM_H8300H         = 47,  // Renesas (formerly Hitachi) H8/300H
  EM_H8S            = 48,  // Renesas (formerly Hitachi) H8S
  EM_H8500          = 49,  // Renesas (formerly Hitachi) H8/500
  EM_IA64           = 50,  // Intel Itanium IA64
  EM_MIPS_X         = 51,  // Stanford MIPS-X
  EM_COLDFIRE       = 52,  // Motorola Coldfire
  EM_6812           = 53,  // Motorola MC68HC12
  EM_MMA            = 54,  // Fujitsu Multimedia Accelerator
  EM_PCP            = 55,  // Siemens PCP
  EM_NCPU           = 56,  // Sony nCPU embedded RISC processor
  EM_NDR1           = 57,  // Denso NDR1 microprocesspr
  EM_STARCORE       = 58,  // Motorola Star*Core processor
  EM_ME16           = 59,  // Toyota ME16 processor
  EM_ST100          = 60,  // STMicroelectronics ST100 processor
  EM_TINYJ          = 61,  // Advanced Logic Corp. TinyJ embedded processor
  EM_X86_64         = 62,  // Advanced Micro Devices X86-64 processor
  EM_PDSP           = 63,  // Sony DSP Processor
  EM_PDP10          = 64,  // DEC PDP-10
  EM_PDP11          = 65,  // DEC PDP-11
  EM_FX66           = 66,  // Siemens FX66 microcontroller
  EM_ST9            = 67,  // STMicroelectronics ST9+ 8/16 bit microcontroller
  EM_ST7            = 68,  // STMicroelectronics ST7 8-bit microcontroller
  EM_68HC16         = 69,  // Motorola MC68HC16
  EM_6811           = 70,  // Motorola MC68HC11
  EM_68HC08         = 71,  // Motorola MC68HC08
  EM_68HC05         = 72,  // Motorola MC68HC05
  EM_SVX            = 73,  // Silicon Graphics SVx
  EM_ST19           = 74,  // STMicroelectronics ST19 8-bit cpu
  EM_VAX            = 75,  // Digital VAX
  EM_CRIS           = 76,  // Axis Communications 32-bit embedded processor
  EM_JAVELIN        = 77,  // Infineon Technologies 32-bit embedded cpu
  EM_FIREPATH       = 78,  // Element 14 64-bit DSP processor
  EM_ZSP            = 79,  // LSI Logic's 16-bit DSP processor
  EM_MMIX           = 80,  // Donald Knuth's educational 64-bit processor
  EM_HUANY          = 81,  // Harvard's machine-independent format
  EM_PRISM          = 82,  // SiTera Prism
  EM_AVR            = 83,  // Atmel AVR 8-bit microcontroller
  EM_FR             = 84,  // Fujitsu FR Family
  EM_D10V           = 85,  // Mitsubishi D10V
  EM_D30V           = 86,  // Mitsubishi D30V
  EM_V850           = 87,  // NEC v850 (GNU compiler)

  EM_NECV850E       = 0x70FC, // ^
  EM_NECV850        = 0x70FF, // |
  EM_NECV850E2      = 0x71EA, // |
  EM_NECV850ES      = 0x73CE, // |
  EM_NECV850E2R1    = 0x73FD, // |This group is used by the Renesas CA850 toolchain
  EM_NECV850E2R2    = 0x73FE, // |
  EM_NECV850E2R3    = 0x73FF, // |
  EM_NECV850E2R4    = 0x7400, // |
  EM_NECV850E3V5    = 0x74FB, // v

  EM_CYGNUS_V850    = 0x9080,// V850 backend magic number. Written in the absense of an ABI.

  EM_M32R           = 88,  // Renesas M32R (formerly Mitsubishi M32R)
  EM_MN10300        = 89,  // Matsushita MN10300
  EM_MN10200        = 90,  // Matsushita MN10200
  EM_PJ             = 91,  // picoJava
  EM_OPENRISC       = 92,  // OpenRISC 32-bit embedded processor
  EM_ARCOMPACT      = 93,  // ARC Cores (ARCompact ISA)
  EM_XTENSA         = 94,  // Tensilica Xtensa Architecture
  EM_VIDEOCORE      = 95,  // Alphamosaic VideoCore processor
  EM_TMM_GPP        = 96,  // Thompson Multimedia General Purpose Processor
  EM_NS32K          = 97,  // National Semiconductor 32000 series
  EM_TPC            = 98,  // Tenor Network TPC processor
  EM_SNP1K          = 99,  // Trebia SNP 1000 processor
  EM_ST200          = 100, // STMicroelectronics ST200 microcontroller
  EM_IP2K           = 101, // Ubicom IP2022 micro controller
  EM_MAX            = 102, // MAX Processor
  EM_CR             = 103, // National Semiconductor CompactRISC
  EM_F2MC16         = 104, // Fujitsu F2MC16
  EM_MSP430         = 105, // TI msp430 micro controller
  EM_BLACKFIN       = 106, // ADI Blackfin
  EM_SE_C33         = 107, // S1C33 Family of Seiko Epson processors
  EM_SEP            = 108, // Sharp embedded microprocessor
  EM_ARCA           = 109, // Arca RISC Microprocessor
  EM_UNICORE        = 110, // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
  EM_EXCESS         = 111, // eXcess: 16/32/64-bit configurable embedded CPU
  EM_DXP            = 112, // Icera Semiconductor Inc. Deep Execution Processor
  EM_ALTERA_NIOS2   = 113, // Altera Nios II soft-core processor
  EM_CRX            = 114, // National Semiconductor CRX
  EM_XGATE          = 115, // Motorola XGATE embedded processor
  EM_C166           = 116, // Infineon C16x/XC16x processor
  EM_M16C           = 117, // Renesas M16C series microprocessors
  EM_DSPIC30F       = 118, // Microchip Technology dsPIC30F Digital Signal Controller
  EM_CE             = 119, // Freescale Communication Engine RISC core
  EM_M32C           = 120, // Renesas M32C series microprocessors
  EM_TSK3000        = 131, // Altium TSK3000 core
  EM_RS08           = 132, // Freescale RS08 embedded processor
  EM_SHARC          = 133, // Analog Devices SHARC family of 32-bit DSP processors
  EM_ECOG2          = 134, // Cyan Technology eCOG2 microprocessor
  EM_SCORE          = 135, // Sunplus Score
  EM_DSP24          = 136, // New Japan Radio (NJR) 24-bit DSP Processor
  EM_VIDEOCORE3     = 137, // Broadcom VideoCore III processor
  EM_LATTICEMICO32  = 138, // RISC processor for Lattice FPGA architecture
  EM_SE_C17         = 139, // Seiko Epson C17 family
  EM_TI_C6000       = 140, // Texas Instruments TMS320C6000 family
  EM_MMDSP_PLUS     = 160, // STMicroelectronics 64bit VLIW Data Signal Processor
  EM_CYPRESS_M8C    = 161, // Cypress M8C microprocessor
  EM_R32C           = 162, // Renesas R32C series microprocessors
  EM_TRIMEDIA       = 163, // NXP Semiconductors TriMedia architecture family
  EM_QDSP6          = 164, // QUALCOMM DSP6 Processor
  EM_8051           = 165, // Intel 8051 and variants
  EM_STXP7X         = 166, // STMicroelectronics STxP7x family
  EM_NDS32          = 167, // Andes Technology compact code size embedded RISC processor family
  EM_ECOG1          = 168, // Cyan Technology eCOG1X family
  EM_ECOG1X         = 168, // Cyan Technology eCOG1X family
  EM_MAXQ30         = 169, // Dallas Semiconductor MAXQ30 Core Micro-controllers
  EM_XIMO16         = 170, // New Japan Radio (NJR) 16-bit DSP Processor
  EM_MANIK          = 171, // M2000 Reconfigurable RISC Microprocessor
  EM_CRAYNV2        = 172, // Cray Inc. NV2 vector architecture
  EM_RX             = 173, // Renesas RX family
  EM_METAG          = 174, // Imagination Technologies META processor architecture
  EM_MCST_ELBRUS    = 175, // MCST Elbrus general purpose hardware architecture
  EM_ECOG16         = 176, // Cyan Technology eCOG16 family
  EM_CR16           = 177, // National Semiconductor CompactRISC 16-bit processor
  EM_ETPU           = 178, // Freescale Extended Time Processing Unit
  EM_SLE9X          = 179, // Infineon Technologies SLE9X core
  EM_L1OM           = 180, // Intel L1OM (Larrabee)
  EM_K1OM           = 181, // Intel K1OM
  EM_INTEL182       = 182, // Reserved by Intel
  EM_AARCH64        = 183, // ARM 64-bit architecture
  EM_ARM184         = 184, // Reserved by ARM
  EM_AVR32          = 185, // Atmel Corporation 32-bit microprocessor family
  EM_STM8           = 186, // STMicroeletronics STM8 8-bit microcontroller
  EM_TILE64         = 187, // Tilera TILE64 multicore architecture family
  EM_TILEPRO        = 188, // Tilera TILEPro multicore architecture family
  EM_MICROBLAZE     = 189, // Xilinx MicroBlaze 32-bit RISC soft processor core
  EM_CUDA           = 190, // NVIDIA CUDA architecture
  EM_TILEGX         = 191, // Tilera TILE-Gx multicore architecture family
  EM_CLOUDSHIELD    = 192, // CloudShield architecture family
  EM_COREA_1ST      = 193, // KIPO-KAIST Core-A 1st generation processor family
  EM_COREA_2ND      = 194, // KIPO-KAIST Core-A 2nd generation processor family
  EM_ARC_COMPACT2   = 195, // Synopsys ARCompact V2
  EM_OPEN8          = 196, // Open8 8-bit RISC soft processor core
  EM_RL78           = 197, // Renesas RL78 family
  EM_VIDEOCORE5     = 198, // Broadcom VideoCore V processor
  EM_78K0R          = 199, // Renesas 78K0R family
  EM_56800EX        = 200, // Freescale 56800EX Digital Signal Controller
  EM_BA1            = 201, // Beyond BA1 CPU architecture
  EM_BA2            = 202, // Beyond BA2 CPU architecture
  EM_XCORE          = 203, // XMOS xCORE processor family
  EM_MCHP_PIC       = 204, // Microchip 8-bit PIC(r)
        /* reserved 205-209 */
  EM_KM32           = 210, // KM211 KM32
  EM_KMX32          = 211, // KM211 KMX32
  EM_EMX16          = 212, // KM211 KMX16
  EM_EMX8           = 213, // KM211 KMX8
  EM_KVARC          = 214, // KM211 KVARC
  EM_CDP            = 215, // Paneve CDP
  EM_COGE           = 216, // Cognitive Smart Memory Processor
  EM_COOL           = 217, // Bluechip CoolEngine
  EM_NORC           = 218, // Nanoradio Optimized RISC
  EM_CSR_KALIMBA    = 219, // CSR Kalimba
  EM_Z80            = 220, // Zilog Z80
  EM_VISIUM         = 221, // Controls and Data Services VISIUMcore
  EM_FT32           = 222, // FTDI Chip FT32
  EM_MOXIE          = 223, // Moxie processor
  EM_AMDGPU         = 224, // AMD GPU
        /* reserved 225-242 */
  EM_RISCV          = 243, // RISC-V

  EM_NANOMIPS       = 249, // Imagination Technologies NanoMIPS

  EM_CYGNUS_POWERPC = 0x9025, // Cygnus PowerPC ELF backend
  EM_ALPHA          = 0x9026, // DEC Alpha
  EM_S390_OLD       = 0xa390 // old S/390 backend magic number. Written in the absence of an ABI.
};

enum elf_EV
{
  EV_NONE    = 0, // None version
  EV_CURRENT = 1  // Current version
  // in linux header
  // EV_NUM      = 2
};

// special section indexes
enum elh_SHN
{
  SHN_UNDEF     = 0,       // undefined/missing/...
  SHN_LORESERVE = 0xff00,
  SHN_LOPROC    = 0xff00,
  SHN_HIPROC    = 0xff1f,
  SHN_ABS       = 0xfff1,  // absolute value
  SHN_COMMON    = 0xfff2,  // common values (fortran/c)
  SHN_XINDEX    = 0xffff,  // the escape value
  SHN_HIRESERVE = 0xffff
};
//==========

struct Elf32_Shdr
{
  uint32 sh_name;      // index in string table
  uint32 sh_type;      // enum SHT
  uint32 sh_flags;     // enum SHF
  uint32 sh_addr;      // address in memory (or 0)
  uint32 sh_offset;    // offset in file
  uint32 sh_size;      // section size in bytes
  uint32 sh_link;      // index in symbol table
  uint32 sh_info;      // extra information
  uint32 sh_addralign; // 0 & 1 => no alignment
  uint32 sh_entsize;   // size symbol table or eq.
};


enum elf_SHT
{
  SHT_NULL      = 0,    // inactive - no assoc. section
  SHT_PROGBITS  = 1,    // internal program information
  SHT_SYMTAB    = 2,    // symbol table (static)
  SHT_STRTAB    = 3,    // string table
  SHT_RELA      = 4,    // relocation entries
  SHT_HASH      = 5,    // symbol hash table
  SHT_DYNAMIC   = 6,    // inf. for dynamic linking
  SHT_NOTE      = 7,    // additional info
  SHT_NOBITS    = 8,    // no placed in file
  SHT_REL       = 9,    // relocation entries without explicit address
  SHT_SHLIB     = 10,   // RESERVED
  SHT_DYNSYM    = 11,   // Dynamic Symbol Table
  SHT_COMDAT    = 12,   // COMDAT group directory -> SHT_HP_COMDAT */
  // abi 3
  SHT_INIT_ARRAY    = 14, // Array of ptrs to init functions
  SHT_FINI_ARRAY    = 15, // Array of ptrs to finish functions
  SHT_PREINIT_ARRAY = 16, // Array of ptrs to pre-init funcs
  SHT_GROUP         = 17, // Section contains a section group
  SHT_SYMTAB_SHNDX  = 18, // Indicies for SHN_XINDEX entries
  //  SHT_NUM       = 12,
  SHT_LOOS      = 0x60000000,
  SHT_HIOS      = 0x6FFFFFFF,
  SHT_LOPROC    = 0x70000000,
  SHT_HIPROC    = 0x7FFFFFFF,
  SHT_LOUSER    = 0x80000000,
  SHT_HIUSER    = 0xFFFFFFFF,

  // From binutils-2.27/elfcpp/elfcpp.h
  // The remaining values are not in the standard.
  // Incremental build data.
  SHT_GNU_INCREMENTAL_INPUTS  = 0x6FFF4700,
  SHT_GNU_INCREMENTAL_SYMTAB  = 0x6FFF4701,
  SHT_GNU_INCREMENTAL_RELOCS  = 0x6FFF4702,
  SHT_GNU_INCREMENTAL_GOT_PLT = 0x6FFF4703,
  SHT_GNU_ATTRIBUTES          = 0x6FFFFFF5, // Object attributes.
  SHT_GNU_HASH                = 0x6FFFFFF6, // GNU style dynamic hash table.
  SHT_GNU_LIBLIST             = 0x6FFFFFF7, // List of prelink dependencies.
  SHT_GNU_verdef              = 0x6FFFFFFD, // Versions defined by file.
  SHT_GNU_verneed             = 0x6FFFFFFE, // Versions needed by file.
  SHT_GNU_versym              = 0x6FFFFFFF, // Symbol versions.

  // http://docs.oracle.com/cd/E53394_01/html/E54813/chapter6-94076.html#OSLLGchapter6-73445
  SHT_SUNW_ancillary = 0x6FFFFFEE,
  SHT_SUNW_capchain  = 0x6FFFFFEF,
  SHT_SUNW_capinfo   = 0x6FFFFFF0,
  SHT_SUNW_symsort   = 0x6FFFFFF1,
  SHT_SUNW_tlssort   = 0x6FFFFFF2,
  SHT_SUNW_LDYNSYM   = 0x6FFFFFF3,
  SHT_SUNW_dof       = 0x6FFFFFF4,
  SHT_SUNW_cap       = 0x6FFFFFF5,
  SHT_SUNW_SIGNATURE = 0x6FFFFFF6,
  SHT_SUNW_ANNOTATE  = 0x6FFFFFF7,
  SHT_SUNW_DEBUGSTR  = 0x6FFFFFF8,
  SHT_SUNW_DEBUG     = 0x6FFFFFF9,
  SHT_SUNW_move      = 0x6FFFFFFA,
  SHT_SUNW_COMDAT    = 0x6FFFFFFB,
  SHT_SUNW_syminfo   = 0x6FFFFFFC,
  SHT_SUNW_verdef    = 0x6FFFFFFD,
  SHT_SUNW_verneed   = 0x6FFFFFFE,
  SHT_SUNW_versym    = 0x6FFFFFFF,

  // http://llvm.org/doxygen/namespacellvm_1_1ELF.html
  SHT_ANDROID_REL = 0x60000001,
  SHT_ANDROID_RELA = 0x60000002,
};

// section by index 0 ==
// { 0, SHT_NULL, 0, 0, 0, 0, SHN_UNDEF, 0, 0, 0 };

enum elf_SHF
{
  SHF_WRITE      = (1 << 0),    // writable data
  SHF_ALLOC      = (1 << 1),    // occupies memory
  SHF_EXECINSTR  = (1 << 2),    // machine instruction

  SHF_MERGE      = (1 << 4),    // can be merged
  SHF_STRINGS    = (1 << 5),    // contains nul-terminated strings
  SHF_INFO_LINK  = (1 << 6),    // sh_info contains SHT index
  SHF_LINK_ORDER = (1 << 7),    // preserve order after combining
  SHF_OS_NONCONFORMING = (1 << 8), // non-standard os specific handling required
  SHF_GROUP      = (1 << 9),    // section is memory of a group
  SHF_TLS        = (1 << 10),   // section holds thread-local data
  SHF_COMPRESSED = (1 << 11),   // section containing compressed data

  SHF_MASKOS    = 0x0ff00000,   // os specific
  SHF_MASKPROC  = 0xf0000000,   // processor specific
};

enum elf_GRP
{
  GRP_COMDAT   = 0x00000001,  // This is a COMDAT group.
  GRP_MASKOS   = 0x0ff00000,  // OS-specific flags
  GRP_MASKPROC = 0xf0000000,  // Processor-specific flags
};

// COMDAT selection criteria.
// (value of sh_info of a SHT_COMDAT section)
// ref: OS/2 Application Binary Interface for PowerPC (32-bit)
enum elf_COMDAT
{
  COMDAT_NONE = 0, // Invalid selection criteria.
  COMDAT_NOMATCH =1, // Only one instance of a SHT_COMDAT section of the
                     // given name is allowed.
  COMDAT_PICKANY =2, // Pick any instance of a SHT_COMDAT section of the
                     // given name.
  COMDAT_SAMESIZE =3, // Pick any instance of a SHT_COMDAT section of the
                     // given name but all instances of SHT_COMDAT
                     // sections of the given name must have the same size.
};

struct Elf32_Sym
{
  uint32 st_name;        // index in string table
  uint32 st_value;       // absolute value or addr
  uint32 st_size;        // 0-unknow or no, elsewere symbol size in bytes
  uchar  st_info;        // type and attribute (thee below)
  uchar  st_other;       // ==0
  uint16 st_shndx;       // index in section header table
};

#define ELF_ST_BIND(i)    ((i)>>4)
#define ELF_ST_TYPE(i)    ((i)&0xf)
#define ELF_ST_INFO(b,t)  (((b)<<4)+((t)&0xf))
/* This macro disassembles and assembles a symbol's visibility into
   the st_other field.  The STV_ defines specificy the actual visibility.  */
#define ELF_ST_VISIBILITY(v)            ((v) & 0x3)

enum elf_ST_BIND
{
  STB_LOCAL   = 0,
  STB_GLOBAL  = 1,
  STB_WEAK    = 2,
  STB_LOOS    = 10,              // OS-specific
  STB_GNU_UNIQUE = 10,           // Symbol is unique in namespace
  STB_HIOS    = 12,
  STB_LOPROC  = 13,              // processor-
  STB_HIPROC  = 15,              //           specific
  STB_INVALID = 254
};

enum elf_ST_TYPE
{
  STT_NOTYPE    = 0,
  STT_OBJECT  = 1,              // associated with data object
  STT_FUNC    = 2,              // associated with function or execut. code
  STT_SECTION = 3,
  STT_FILE    = 4,              // name of source file
  STT_COMMON  = 5,              // Uninitialized common section
  STT_TLS     = 6,              // TLS-data object
  STT_LOOS   = 10,              // OS-
  STT_HIOS   = 12,              //    specific
  STT_LOPROC = 13,              // processor-
  STT_HIPROC = 15,              //           specific
  STT_GNU_IFUNC = 10,           // Symbol is an indirect code object
};

enum elf_ST_VISIBILITY
{
  STV_DEFAULT    = 0,               /* Visibility is specified by binding type */
  STV_INTERNAL   = 1,               /* OS specific version of STV_HIDDEN */
  STV_HIDDEN     = 2,               /* Can only be seen inside currect component */
  STV_PROTECTED  = 3,               /* Treat as STB_LOCAL inside current component */
};

/* Special values for the st_other field in the symbol table.  These
   are used in an Irix 5 dynamic symbol table.  */
enum elf_ST_OTHER
{
  STO_DEFAULT             = STV_DEFAULT,
  STO_INTERNAL            = STV_INTERNAL,
  STO_HIDDEN              = STV_HIDDEN,
  STO_PROTECTED           = STV_PROTECTED,
/* This bit is used on Irix to indicate a symbol whose definition
   is optional - if, at final link time, it cannot be found, no
   error message should be produced.  */
  STO_OPTIONAL            = (1 << 2),
};

// relocation
struct Elf32_Rel
{
  uint32    r_offset;   // virtual address
  uint32    r_info;     // type of relocation
};

#define ELF32_R_SYM(i)    ((i)>>8)
#define ELF32_R_TYPE(i)   ((unsigned char)(i))
#define ELF32_R_INFO(s,t) (((s)<<8)+(unsigned char)(t))

struct Elf32_Rela
{
  uint32    r_offset;
  uint32    r_info;
  int32     r_addend;   // constant to compute
};

struct Elf32_Chdr
{
  uint32 ch_type;
  uint32 ch_size;
  uint32 ch_addralign;
};

//=================Loading & dynamic linking========================
// program header
struct Elf32_Phdr
{
  uint32    p_type;         // Segment type. see below
  uint32    p_offset;       // from beginning of file at 1 byte of segment resides
  uint32    p_vaddr;        // virtual addr of 1 byte
  uint32    p_paddr;        // reserved for system
  uint32    p_filesz;       // may be 0
  uint32    p_memsz;        // my be 0
  uint32    p_flags;        // for PT_LOAD access mask (PF_xxx)
  uint32    p_align;        // 0/1-no,
};

enum elf_SEGFLAGS
{
  PF_X          = (1 << 0),       // Segment is executable
  PF_W          = (1 << 1),       // Segment is writable
  PF_R          = (1 << 2),       // Segment is readable

  // PaX flags (for PT_PAX_FLAGS)
  PF_PAGEEXEC   = (1 << 4),       // Enable  PAGEEXEC
  PF_NOPAGEEXEC = (1 << 5),       // Disable PAGEEXEC
  PF_SEGMEXEC   = (1 << 6),       // Enable  SEGMEXEC
  PF_NOSEGMEXEC = (1 << 7),       // Disable SEGMEXEC
  PF_MPROTECT   = (1 << 8),       // Enable  MPROTECT
  PF_NOMPROTECT = (1 << 9),       // Disable MPROTECT
  PF_RANDEXEC   = (1 << 10),      // Enable  RANDEXEC
  PF_NORANDEXEC = (1 << 11),      // Disable RANDEXEC
  PF_EMUTRAMP   = (1 << 12),      // Enable  EMUTRAMP
  PF_NOEMUTRAMP = (1 << 13),      // Disable EMUTRAMP
  PF_RANDMMAP   = (1 << 14),      // Enable  RANDMMAP
  PF_NORANDMMAP = (1 << 15),      // Disable RANDMMAP

  PF_MASKOS     = 0x0FF00000,     // OS-specific reserved bits
  PF_MASKPROC   = 0xF0000000,     // Processor-specific reserved bits
};

enum elf_SEGTYPE
{
  PT_NULL    = 0,               // ignore entries in program table
  PT_LOAD    = 1,               // loadable segmen described in _filesz & _memsz
  PT_DYNAMIC = 2,               // dynamic linking information
  PT_INTERP  = 3,               // path name to interpreter (loadable)
  PT_NOTE    = 4,               // auxilarry information
  PT_SHLIB   = 5,               // reserved. Has no specified semantics
  PT_PHDR    = 6,               // location & size program header table
  PT_TLS     = 7,               // Thread local storage segment
  PT_LOOS    = 0x60000000,      // OS-
  PT_HIOS    = 0x6FFFFFFF,      //    specific
  PT_LOPROC  = 0x70000000,      // processor-
  PT_HIPROC  = 0x7FFFFFFF,      //    specific
  //
  PT_PAX_FLAGS    = (PT_LOOS + 0x5041580), // PaX flags

  // From binutils-2.27/elfcpp/elfcpp.h
  // The remaining values are not in the standard.
  PT_GNU_EH_FRAME = 0x6474E550, // Frame unwind information.
  PT_GNU_STACK    = 0x6474E551, // Stack flags.
  PT_GNU_RELRO    = 0x6474E552, // Read only after relocation.

  // http://docs.oracle.com/cd/E53394_01/html/E54813/chapter6-83432.html#OSLLGchapter6-69880
  PT_SUNW_UNWIND   = 0x6464E550,
  PT_SUNW_EH_FRAME = 0x6474E550,
  PT_SUNWBSS       = 0x6FFFFFFA,
  PT_SUNWSTACK     = 0x6FFFFFFB,
  PT_SUNWDTRACE    = 0x6FFFFFFC,
  PT_SUNWCAP       = 0x6FFFFFFD,
};

//=================Dynamic section===============================
struct Elf32_Dyn
{
  int32 d_tag;              // see below
  union
  {
    uint32 d_val;           // integer value with various interpretation
    uint32 d_ptr;           // programm virtual adress
  } d_un;
};

enum elf_DTAG
{
  DT_NULL     = 0,              // (-) end ofd _DYNAMIC array
  DT_NEEDED   = 1,              // (v) str-table offset name to needed library
  DT_PLTRELSZ = 2,              // (v) tot.size in bytes of relocation entries
  DT_PLTGOT   = 3,              // (p) see below
  DT_HASH     = 4,              // (p) addr. of symbol hash table
  DT_STRTAB   = 5,              // (p) addr of string table
  DT_SYMTAB   = 6,              // (p) addr of symbol table
  DT_RELA     = 7,              // (p) addr of relocation table
  DT_RELASZ   = 8,              // (v) size in bytes of DT_RELA table
  DT_RELAENT  = 9,              // (v) size in bytes of DT_RELA entry
  DT_STRSZ    = 10,             // (v) size in bytes of string table
  DT_SYMENT   = 11,             // (v) size in byte of symbol table entry
  DT_INIT     = 12,             // (p) addr. of initialization function
  DT_FINI     = 13,             // (p) addr. of termination function
  DT_SONAME   = 14,             // (v) offs in str.-table - name of shared object
  DT_RPATH    = 15,             // (v) offs in str-table - search patch
  DT_SYMBOLIC = 16,             // (-) start search of shared object
  DT_REL      = 17,             // (p) similar to DT_RELA
  DT_RELSZ    = 18,             // (v) tot.size in bytes of DT_REL
  DT_RELENT   = 19,             // (v) size in bytes of DT_REL entry
  DT_PLTREL   = 20,             // (v) type of relocation (DT_REL or DT_RELA)
  DT_DEBUG    = 21,             // (p) not specified
  DT_TEXTREL  = 22,             // (-) segment permisson
  DT_JMPREL   = 23,             // (p) addr of dlt procedure (if present)
  DT_BIND_NOW         = 24,
  DT_INIT_ARRAY       = 25,
  DT_FINI_ARRAY       = 26,
  DT_INIT_ARRAYSZ     = 27,
  DT_FINI_ARRAYSZ     = 28,
  DT_RUNPATH          = 29,
  DT_FLAGS            = 30,
#define DF_ORIGIN         0x01
#define DF_SYMBOLIC       0x02
#define DF_TEXTREL        0x04
#define DF_BIND_NOW       0x08
#define DF_STATIC_TLS     0x10
  DT_ENCODING         = 31,
  DT_PREINIT_ARRAY    = 32,
  DT_PREINIT_ARRAYSZ  = 33,
  DT_LOOS       = 0x60000000,  // OS-specific
  DT_HIOS       = 0x6FFFFFFF,  //

  // http://docs.oracle.com/cd/E53394_01/html/E54813/chapter6-42444.html#OSLLGchapter6-tbl-52
  DT_SUNW_AUXILIARY   = 0x6000000d,
  DT_SUNW_RTLDINF     = 0x6000000e,
  DT_SUNW_FILTER      = 0x6000000e,
  DT_SUNW_CAP         = 0x60000010,
  DT_SUNW_SYMTAB      = 0x60000011,
  DT_SUNW_SYMSZ       = 0x60000012,
  DT_SUNW_ENCODING    = 0x60000013,
  DT_SUNW_SORTENT     = 0x60000013,
  DT_SUNW_SYMSORT     = 0x60000014,
  DT_SUNW_SYMSORTSZ   = 0x60000015,
  DT_SUNW_TLSSORT     = 0x60000016,
  DT_SUNW_TLSSORTSZ   = 0x60000017,
  DT_SUNW_CAPINFO     = 0x60000018,
  DT_SUNW_STRPAD      = 0x60000019,
  DT_SUNW_CAPCHAIN    = 0x6000001a,
  DT_SUNW_LDMACH      = 0x6000001b,
  DT_SUNW_CAPCHAINENT = 0x6000001d,
  DT_SUNW_CAPCHAINSZ  = 0x6000001f,
  DT_SUNW_PARENT      = 0x60000021,
  DT_SUNW_ASLR        = 0x60000023,
  DT_SUNW_RELAX       = 0x60000025,
  DT_SUNW_NXHEAP      = 0x60000029,
  DT_SUNW_NXSTACK     = 0x6000002b,

  // https://github.com/amplab/ray-core/tree/master/src/tools/relocation_packer
  DT_ANDROID_REL    = 0x6000000f,
  DT_ANDROID_RELSZ  = 0x60000010,
  DT_ANDROID_RELA   = 0x60000011,
  DT_ANDROID_RELASZ = 0x60000012,

  // From binutils-2.27/elfcpp/elfcpp.h
  // Some of the values below are also present the Oracle documentation.
  // All of these types are supported both for GNU and Solaris.
  DT_VALRNGLO       = 0x6FFFFD00,
  DT_GNU_PRELINKED  = 0x6FFFFDF5,
  DT_GNU_CONFLICTSZ = 0x6FFFFDF6,
  DT_GNU_LIBLISTSZ  = 0x6FFFFDF7,
  DT_CHECKSUM       = 0x6FFFFDF8,
  DT_PLTPADSZ       = 0x6FFFFDF9,
  DT_MOVEENT        = 0x6FFFFDFA,
  DT_MOVESZ         = 0x6FFFFDFB,
  DT_FEATURE        = 0x6FFFFDFC,
#define DTF_1_PARINIT   0X00000001
#define DTF_1_CONFEXP   0X00000002
  DT_POSFLAG_1      = 0x6FFFFDFD,
#define DF_P1_LAZYLOAD  0x00000001
#define DF_P1_GROUPPERM 0x00000002
  DT_SYMINSZ        = 0x6FFFFDFE,
  DT_SYMINENT       = 0x6FFFFDFF,
  DT_VALRNGHI       = 0x6FFFFDFF,
  DT_ADDRRNGLO      = 0x6FFFFE00,
  DT_GNU_HASH       = 0x6FFFFEF5,  // GNU-style hash table.
  DT_TLSDESC_PLT    = 0x6FFFFEF6,
  DT_TLSDESC_GOT    = 0x6FFFFEF7,
  DT_GNU_CONFLICT   = 0x6FFFFEF8,  // Start of conflict section
  DT_GNU_LIBLIST    = 0x6FFFFEF9,
  DT_CONFIG         = 0x6FFFFEFA,
  DT_DEPAUDIT       = 0x6FFFFEFB,
  DT_AUDIT          = 0x6FFFFEFC,
  DT_PLTPAD         = 0x6FFFFEFD,
  DT_MOVETAB        = 0x6FFFFEFE,
  DT_SYMINFO        = 0x6FFFFEFF,
  DT_ADDRRNGHI      = 0x6FFFFEFF,
  DT_RELACOUNT      = 0x6FFFFFF9,
  DT_RELCOUNT       = 0x6FFFFFFA,
  DT_FLAGS_1        = 0x6FFFFFFB,
#define DF_1_NOW        0x00000001
#define DF_1_GLOBAL     0x00000002
#define DF_1_GROUP      0x00000004
#define DF_1_NODELETE   0x00000008
#define DF_1_LOADFLTR   0x00000010
#define DF_1_INITFIRST  0x00000020
#define DF_1_NOOPEN     0x00000040
#define DF_1_ORIGIN     0x00000080
#define DF_1_DIRECT     0x00000100
#define DF_1_TRANS      0x00000200
#define DF_1_INTERPOSE  0x00000400
#define DF_1_NODEFLIB   0x00000800
#define DF_1_NODUMP     0x00001000
#define DF_1_CONFALT    0x00002000
#define DF_1_ENDFILTEE  0x00004000
#define DF_1_DISPRELDNE 0x00008000
#define DF_1_DISPRELPND 0x00010000
#define DF_1_NODIRECT   0x00020000
#define DF_1_IGNMULDEF  0x00040000
#define DF_1_NOKSYMS    0x00080000
#define DF_1_NOHDR      0x00100000
#define DF_1_EDITED     0x00200000
#define DF_1_NORELOC    0x00400000
#define DF_1_SYMINTPOSE 0x00800000
#define DF_1_GLOBAUDIT  0x01000000
#define DF_1_SINGLETON  0x02000000
#define DF_1_STUB       0x04000000
#define DF_1_PIE        0x08000000
#define DF_1_KMOD       0x10000000
#define DF_1_WEAKFILTER 0x20000000
#define DF_1_NOCOMMON   0x40000000
  DT_VERDEF         = 0x6FFFFFFC,
  DT_VERDEFNUM      = 0x6FFFFFFD,
  DT_VERNEED        = 0x6FFFFFFE,
  DT_VERNEEDNUM     = 0x6FFFFFFF,
  DT_VERSYM         = 0x6FFFFFF0,

  //
  DT_LOPROC   = 0x70000000, // (?) processor-
  DT_HIPROC   = 0x7FFFFFFF, // (?)           specific

  //
  DT_AUXILIARY    = 0x7FFFFFFD,
  DT_USED         = 0x7FFFFFFE,
  DT_FILTER       = 0x7FFFFFFF,
};

//----------------------------------------------------------------------
// ELF Notes

enum
{
  NT_GNU_ABI_TAG = 1,
  NT_GNU_HWCAP = 2,
  NT_GNU_BUILD_ID = 3,
  NT_GNU_GOLD_VERSION = 4,
  NT_GNU_PROPERTY_TYPE_0 = 5,
};

#define NT_PRSTATUS         1
#define NT_FPREGSET         2
#define NT_PRPSINFO         3
#define NT_TASKSTRUCT       4
#define NT_AUXV             6
#define NT_PRXFPREG         0x46E62B7F
#define NT_PPC_VMX          0x100
#define NT_PPC_VSX          0x102
#define NT_PPC_TAR          0x103
#define NT_PPC_PPR          0x104
#define NT_PPC_DSCR         0x105
#define NT_PPC_EBB          0x106
#define NT_PPC_PMU          0x107
#define NT_PPC_TM_CGPR      0x108
#define NT_PPC_TM_CFPR      0x109
#define NT_PPC_TM_CVMX      0x10a
#define NT_PPC_TM_CVSX      0x10b
#define NT_PPC_TM_SPR       0x10c
#define NT_PPC_TM_CTAR      0x10d
#define NT_PPC_TM_CPPR      0x10e
#define NT_PPC_TM_CDSCR     0x10f
#define NT_386_TLS          0x200
#define NT_386_IOPERM       0x201
#define NT_X86_XSTATE       0x202
#define NT_S390_HIGH_GPRS   0x300
#define NT_S390_TIMER       0x301
#define NT_S390_TODCMP      0x302
#define NT_S390_TODPREG     0x303
#define NT_S390_CTRS        0x304
#define NT_S390_PREFIX      0x305
#define NT_S390_LAST_BREAK  0x306
#define NT_S390_SYSTEM_CALL 0x307
#define NT_S390_TDB         0x308
#define NT_S390_VXRS_LOW    0x309
#define NT_S390_VXRS_HIGH   0x30a
#define NT_S390_GS_CB       0x30b
#define NT_S390_GS_BC       0x30c
#define NT_ARM_VFP          0x400
#define NT_ARM_TLS          0x401
#define NT_ARM_HW_BREAK     0x402
#define NT_ARM_HW_WATCH     0x403
#define NT_ARM_SVE          0x405
#define NT_SIGINFO          0x53494749
#define NT_FILE             0x46494C45

#define NT_PSTATUS          10
#define NT_FPREGS           12
#define NT_PSINFO           13
#define NT_LWPSTATUS        16
#define NT_LWPSINFO         17
#define NT_WIN32PSTATUS     18

//===============================elf64 types=============================
struct Elf64_Ehdr
{
  elf_ident_t e_ident;
  uint16    e_type;
  uint16    e_machine;
  uint32    e_version;
  uint64    e_entry;          // Entry point virtual address
  uint64    e_phoff;          // Program header table file offset
  uint64    e_shoff;          // Section header table file offset
  uint32    e_flags;
  uint16    e_ehsize;
  uint16    e_phentsize;
  uint16    e_phnum;
  uint16    e_shentsize;
  uint16    e_shnum;
  uint16    e_shstrndx;
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Ehdr);

struct Elf64_Shdr
{
  uint32    sh_name;      // Section name, index in string tbl
  uint32    sh_type;      // Type of section
  uint64    sh_flags;     // Miscellaneous section attributes
  uint64    sh_addr;      // Section virtual addr at execution
  uint64    sh_offset;    // Section file offset
  uint64    sh_size;      // Size of section in bytes
  uint32    sh_link;      // Index of another section
  uint32    sh_info;      // Additional section information
  uint64    sh_addralign; // Section alignment
  uint64    sh_entsize;   // Entry size if section holds table
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Shdr);

//
struct Elf64_Sym
{
  uint32    st_name;    // Symbol name, index in string tbl
  uint8     st_info;    // Type and binding attributes
  uint8     st_other;   // No defined meaning, 0
  uint16    st_shndx;   // Associated section index
  uint64    st_value;   // Value of the symbol
  uint64    st_size;    // Associated symbol size
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Sym);

struct Elf64_Rel
{
  uint64    r_offset;  // Location at which to apply the action
  uint64    r_info;    // index and type of relocation
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Rel);

struct Elf64_Rela
{
  uint64    r_offset;    // Location at which to apply the action
  uint64    r_info;      // index and type of relocation
  int64     r_addend;    // Constant addend used to compute value
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Rela);

struct Elf64_Chdr
{
  uint32 ch_type;
  uint32 ch_reserved;
  uint64 ch_size;
  uint64 ch_addralign;
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Chdr);

/* Legal values for ch_type (compression algorithm).  */
#define ELFCOMPRESS_ZLIB        1          /* ZLIB/DEFLATE algorithm.  */
#define ELFCOMPRESS_LOOS        0x60000000 /* Start of OS-specific.  */
#define ELFCOMPRESS_HIOS        0x6FFFFFFF /* End of OS-specific.  */
#define ELFCOMPRESS_LOPROC      0x70000000 /* Start of processor-specific.  */
#define ELFCOMPRESS_HIPROC      0x7FFFFFFF /* End of processor-specific.  */

//#define ELF64_R_SYM(i)           ((i) >> 32)
//#define ELF64_R_TYPE(i)    ((i) & 0xffffffff)
//#define ELF64_R_INFO(s,t)  (((bfd_vma) (s) << 32) + (bfd_vma) (t))
#define ELF64_R_SYM(i)     uint32((i) >> 32)
#define ELF64_R_TYPE(i)    uint32(i)


struct Elf64_Phdr
{
  uint32    p_type;
  uint32    p_flags;
  uint64    p_offset;   // Segment file offset
  uint64    p_vaddr;    // Segment virtual address
  uint64    p_paddr;    // Segment physical address
  uint64    p_filesz;   // Segment size in file
  uint64    p_memsz;    // Segment size in memory
  uint64    p_align;    // Segment alignment, file & memory
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Phdr);

struct Elf64_Dyn
{
  uint64 d_tag;   // entry tag value
  uint64 d_un;
};
DECLARE_TYPE_AS_MOVABLE(Elf64_Dyn);

//=======================================================================
// Version information types

struct Elf_Verdef
{
  uint16 vd_version;
  uint16 vd_flags;
  uint16 vd_ndx;
  uint16 vd_cnt;
  uint32 vd_hash;
  uint32 vd_aux;
  uint32 vd_next;
};
DECLARE_TYPE_AS_MOVABLE(Elf_Verdef);

// Flags for vd_flags
#define VER_FLG_BASE    0x1
#define VER_FLG_WEAK    0x2
#define VER_FLG_INFO    0x4

struct Elf_Verdaux
{
  uint32 vda_name;
  uint32 vda_next;
};
DECLARE_TYPE_AS_MOVABLE(Elf_Verdaux);

struct Elf_Verneed
{
  uint16 vn_version;
  uint16 vn_cnt;
  uint32 vn_file;
  uint32 vn_aux;
  uint32 vn_next;
};
DECLARE_TYPE_AS_MOVABLE(Elf_Verneed);

struct Elf_Vernaux
{
  uint32 vna_hash;
  uint16 vna_flags;
  uint16 vna_other;
  uint32 vna_name;
  uint32 vna_next;
};
DECLARE_TYPE_AS_MOVABLE(Elf_Vernaux);

//=======================================================================
// Definitions for other modules

#define ELFNODE         "$ elfnode"       // value: Elf64_Ehdr
#define ELF_PHT_TAG     'p'               // supval(idx): Elf64_Phdr
#define ELF_SHT_TAG     's'               // supval(idx): Elf64_Shdr
#define TLSNODE         "$ tls"           // altval(0): the TLS template address + 1
                                          // altval(-1): size of the TLS template
                                          // see tlsinfo2_t::create_tls_template()
#define ATTRNODE        "$ attributes"    // hashval(vendorname) - nodeidx of netnode with attribute list
                                          // in that node:
                                          //   supval(tag): string value
                                          //   altval(tag): integer value + 1
                                          // Tag_compatibility uses both
                                          // Tag_also_compatible_with (for 'aeabi') stores sub-tag number in default altval
                                          //   and its value in supval('c') or altval('c')
#define ELFSEGMMAPPINGS "$ elfsegmmap"    // Holds a list of mappings for segments, conceptually of the form:
                                          // (wanted_start_ea, wanted_size, mapped_start_ea)
                                          // Note: Only the segments whose mapped EA is *not* the EA that the
                                          // binary file advertises for that segment will be present in
                                          // this netnode, not all segments.
                                          // This netnode should be iterated on using altfirst/altnext.
                                          //
                                          // idx: wanted_start_ea
                                          // altval(idx): mapped_start_ea
                                          // altval(idx, 's'): wanted_size

#define ATTR_VENDOR_EABI "aeabi"
#define ATTR_VENDOR_GNU  "gnu"
#define ATTR_VENDOR_ARM  "ARM"

#pragma pack(pop)
#endif // __ELFBASE_H__
