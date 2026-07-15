
#ifndef __ELFR_RISCV_H__
#define __ELFR_RISCV_H__

// Section types
enum
{
  SHT_RISCV_ATTRIBUTES = 0x70000003,  // Object file compatibility attributes
};

// RISC-V attribute tags
// Generic tags (same as ARM ELF attributes)
enum
{
  Tag_RISCV_NULL             = 0,
  Tag_RISCV_File             = 1,   // <uint32: byte-size> <attribute>*
  Tag_RISCV_Section          = 2,   // <uint32: byte-size> <section number>* 0 <attribute>*
  Tag_RISCV_Symbol           = 3,   // <uint32: byte-size> <symbol number>* 0 <attribute>*
  Tag_RISCV_stack_align      = 4,   // uleb128
  Tag_RISCV_arch             = 5,   // NTBS (null-terminated string)
  Tag_RISCV_unaligned_access = 6,   // uleb128
  Tag_RISCV_priv_spec        = 8,   // uleb128 (deprecated)
  Tag_RISCV_priv_spec_minor  = 10,  // uleb128 (deprecated)
  Tag_RISCV_priv_spec_rev    = 12,  // uleb128 (deprecated)
  Tag_RISCV_atomic_abi       = 14,  // uleb128
  Tag_RISCV_x3_reg_usage     = 16,  // uleb128
};

// e_flags

// This bit is set when the binary targets the C ABI, which allows
// instructions to be aligned to 16-bit boundaries (the base RV32 and RV64
// ISAs only allow 32-bit instruction alignment).
#define EF_RISCV_RVC 0x0001
// These flags identify the floating point ABI in use for this ELF file.
// They store the largest floating-point type that ends up in registers as
// part of the ABI (but do not control if code generation is allowed to use
// floating-point internally). If none of the float ABI flags are set, the
// object is taken to use the soft-float ABI.
#define EF_RISCV_FLOAT_ABI_SOFT   0x0000
#define EF_RISCV_FLOAT_ABI_SINGLE 0x0002
#define EF_RISCV_FLOAT_ABI_DOUBLE 0x0004
#define EF_RISCV_FLOAT_ABI_QUAD   0x0006
// This macro is used as a mask to test for one of the above floating-point
// ABIs.
#define EF_RISCV_FLOAT_ABI        0x0006
// This bit is set when the binary targets the E ABI.
#define EF_RISCV_RVE 0x0008

// A  Addend field in the relocation entry associated with the symbol
// B  Base address of a shared object loaded into memory
// G  Offset of the symbol into the GOT (Global Offset Table)
// P  Position of the relocation
// S  Value of the symbol in the symbol table
// V  Value at the position of the relocation
// GP Value of __global_pointer$ symbol

enum elf_RTYPE_riscv: int
{
  R_RISCV_NONE = 0,
  R_RISCV_32 = 1,             //                      word32  S + A
  R_RISCV_64 = 2,             //                      word64  S + A
  R_RISCV_RELATIVE = 3,       //                      wordclass
                              //                              B+A
  R_RISCV_COPY = 4,           // Must be in exec not in shared lib
  R_RISCV_JUMP_SLOT = 5,      // Runtime relocation wordclass S
  R_RISCV_TLS_DTPMOD32 = 6,   // TLS relocation word32        S->TLSINDEX
  R_RISCV_TLS_DTPMOD64 = 7,   // TLS relocation word64        S->TLSINDEX
  R_RISCV_TLS_DTPREL32 = 8,   // TLS relocation word32
                              //                    S + A + TLS - TLS_TP_OFFSET
  R_RISCV_TLS_DTPREL64 = 9,   // TLS relocation word64
                              //                    S + A + TLS - TLS_TP_OFFSET
  R_RISCV_TLS_TPREL32 = 10,   // TLS relocation word32
                              //    S + A + TLS + S_TLS_OFFSET - TLS_DTV_OFFSET
  R_RISCV_TLS_TPREL64 = 11,   // TLS relocation word64
                              //    S + A + TLS + S_TLS_OFFSET - TLS_DTV_OFFSET
      // 12 - 15 not attributed
  R_RISCV_BRANCH = 16,        // PC-relative branch   B-Type  S + A - P
  R_RISCV_JAL = 17,           // PC-relative jump     J-Type  S + A - P
  R_RISCV_CALL = 18,          // PC-relative call     J-Type  S + A - P
                              // Macros call, tail
  R_RISCV_CALL_PLT = 19,      // PC-relative call     J-Type  S + A - P
                              // Macros call, tail (PIC)
  R_RISCV_GOT_HI20 = 20,      // PC-relative GOT ref  U-Type  G + A - P
                              // %got_pcrel_hi(symbol)
  R_RISCV_TLS_GOT_HI20 = 21,  // PC-relative TLS IE GOT offset
                              //                      U-Type    Macro la.tls.ie
  R_RISCV_TLS_GD_HI20 = 22,   // PC-relative TLS IE GOT offset
                              //                      U-Type    Macro la.tls.gd
  R_RISCV_PCREL_HI20 = 23,    // PC-relative reference HI 20
                              //                      U-Type  S + A - P
                              //                               %pcrel_hi(symbol)
  R_RISCV_PCREL_LO12_I = 24,  // PC-relative reference Low 12 i-type instruction
                              //                      I-Type  S + A - P
                              //           /!\   %pcrel_lo(address of %pcrel_hi)
  R_RISCV_PCREL_LO12_S = 25,  // PC-relative reference Low 12 s-type instruction
                              //                      S-Type  S + A - P
                              //           /!\   %pcrel_lo(address of %pcrel_hi)
  R_RISCV_HI20 = 26,          // Absolute address     U-Type  S + A  %hi(symbol)
  R_RISCV_LO12_I = 27,        // Absolute address     I-Type  S + A  %lo(symbol)
  R_RISCV_LO12_S = 28,        // Absolute address     S-Type  S + A  %lo(symbol)
  R_RISCV_TPREL_HI20 = 29,    // TLS LE thread offset U-Type   %tprel_hi(symbol)
  R_RISCV_TPREL_LO12_I = 30,  // TLS LE thread offset I-Type   %tprel_lo(symbol)
  R_RISCV_TPREL_LO12_S = 31,  // TLS LE thread offset S-Type   %tprel_lo(symbol)
  R_RISCV_TPREL_ADD = 32,     // TLS LE thread usage          %tprel_add(symbol)
  R_RISCV_ADD8 = 33,          // 8-bit label addition word8   V + S + A
  R_RISCV_ADD16 = 34,         // 16-bit label add     word16  V + S + A
  R_RISCV_ADD32 = 35,         // 32-bit label add     word32  V + S + A
  R_RISCV_ADD64 = 36,         // 64-bit label add     word64  V + S + A
  R_RISCV_SUB8 = 37,          // 8-bit label sub      word8   V - S - A
  R_RISCV_SUB16 = 38,         // 16-bit label sub     word16  V - S - A
  R_RISCV_SUB32 = 39,         // 32-bit label sub     word32  V - S - A
  R_RISCV_SUB64 = 40,         // 64-bit label sub     word64  V - S - A
  R_RISCV_GNU_VTINHERIT = 41, // GNU C++ vtable hierarchy
  R_RISCV_GNU_VTENTRY = 42,   // GNU C++ vtable member usage
  R_RISCV_ALIGN = 43,         // Alignment statement
  R_RISCV_RVC_BRANCH = 44,    // PC-relative branch offset
                              //                      CB-Type S + A - P
  R_RISCV_RVC_JUMP = 45,      // PC-relative jump offset
                              //                      CJ-Type S + A - P
  R_RISCV_RVC_LUI = 46,       // Absolute address     CI-Type S + A
  R_RISCV_GPREL_I = 47,       // GP-relative ref      I-Type  S + A - GP
  R_RISCV_GPREL_S = 48,       // GP-relative ref      S-Type  S + A - GP
  R_RISCV_TPREL_I = 49,       // TP-relative TLS LE load
                              //                      I-Type
  R_RISCV_TPREL_S = 50,       // TP-relative TLS LE store
                              //                      S-Type
  R_RISCV_RELAX = 51,         // Previous reloc can be relaxed
  R_RISCV_SUB6 = 52,          // Local label sub      word6   V - S - A
  R_RISCV_SET6 = 53,          // Local label assgmt   word6   S + A
  R_RISCV_SET8 = 54,          // Local label assgmt   word8   S + A
  R_RISCV_SET16 = 55,         // Local label assgmt   word16  S + A
  R_RISCV_SET32 = 56,         // Local label assgmt   word32  S + A
  R_RISCV_32_PCREL = 57,      // PC-relative ref      word32  S + A - P
  R_RISCV_IRELATIVE = 58,     // Runtime relocation   wordclass
                              //                           ifunc_resolver(B + A)
  // R_RISCV_PLT32 = 59       // Reserved 59
  R_RISCV_SET_ULEB128 = 60,
  R_RISCV_SUB_ULEB128 = 61,
      // 62 - 191 Reserved for future standard use
      // 192 - 255 Reserved for nonstandard ABI extensions
};

// patching GOT loading,
// discard auxiliary values in plt/got
// can present offset bypass segment
#define ELF_RPL_RISCV_DEFAULT (ELF_RPL_GL | ELF_DIS_OFFW | ELF_DIS_GPLT)

#endif // __ELFR_RISCV_H__
