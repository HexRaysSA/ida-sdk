/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *      ARM Image File Format
 *
 */

#ifndef __AIF_H__
#define __AIF_H__

//-------------------------------------------------------------------------
struct aif_header_t
{
  uint32 decompress_code;// BL or NOP if the image is not compressed.
  uint32 self_reloc_code;// BL or NOP if the image is not self-relocating.
  uint32 zero_init;      // (or DBGInit) BL or NOP if the image has none.
  uint32 entry_point;    // BL or EntryPoint offset
  uint32 program_exit;   // usually SWI instruction
  uint32 readonly_size;  // Includes header size if executable AIF;
                         // excludes header size if non-executable AIF
  uint32 readwrite_size; // Exact size (a multiple of 4 bytes).
  uint32 debug_size;     // Exact size (a multiple of 4 bytes).
  uint32 zero_init_size; // Exact size (a multiple of 4 bytes).
  uint32 debug_type;     // bitwise OR of the following:
#define AIF_DEBUG_NONE 0
#define AIF_DEBUG_LOW  1        // Low-level debugging data is present
#define AIF_DEBUG_SRC  2        // Source level (ASD) debugging data is present
  uint32 image_base;     // Address where the image (code) was linked.
  uint32 work_space;     // Minimum work space (in bytes) to be reserved by a
                         // self-moving relocatable image.
  uint32 address_mode;   // 26/32 + 3 flag bytes LS byte contains 26 or 32;
                         // bit 8 set when using a separate data base.
#define AIF_SEP_DATA 0x100      // if set, data_base is meaningful.
  uint32 data_base;      // Address where the image data was linked.
  uint32 reserved[2];    // Two reserved words (initially 0)
  uint32 debug_init;     // NOP if unused.
  uint32 zero_code[15];  // Zero-init code.
};

//-------------------------------------------------------------------------
#define ZERO_CODE1      \
                    0xE04EC00F, 0xE08FC00C, 0xE99C000F, \
        0xE24CC010, 0xE59C2030, 0xE3120C01, 0x159CC034, \
        0x008CC000, 0xE08CC001, 0xE3A00000, 0xE3530000, \
        0xD1A0F00E, 0xE48C0004, 0xE2533004, 0xEAFFFFFB

#define ZERO_CODE2      \
                    0xE04EC00F, 0xE08FC00C, 0xE99C0017, \
        0xE24CC010, 0xE08CC000, 0xE08CC001, 0xE3A00000, \
        0xE3A01000, 0xE3A02000, 0xE3A03000, 0xE3540000, \
        0xD1A0F00E, 0xE8AC000F, 0xE2544010, 0xEAFFFFFB,

#define NOP     0xE1A00000 // opcode of NOP instruction
#define BL      0xEB000000 // opcode of BL instruction
#define BLMASK  0xFF000000 // mask to check BL instruction

// is BL instruction opcode?
inline int is_bl(uint32 code) { return (code & BLMASK) == BL; }

//-------------------------------------------------------------------------
// Debug item codes:
#define AIF_DEB_SECT    1  // section
#define AIF_DEB_FDEF    2  // procedure/function definition
#define AIF_DEB_ENDP    3  // endproc
#define AIF_DEB_VAR     4  // variable
#define AIF_DEB_TYPE    5  // type
#define AIF_DEB_STRU    6  // struct
#define AIF_DEB_ARRAY   7  // array
#define AIF_DEB_RANGE   8  // subrange
#define AIF_DEB_SET     9  // set
#define AIF_DEB_FILE    10 // fileinfo
#define AIF_DEB_CENUM   11 // contiguous enumeration
#define AIF_DEB_DENUM   12 // discontiguous enumeration
#define AIF_DEB_FDCL    13 // procedure/function declaration
#define AIF_DEB_SCOPE   14 // begin naming scope
#define AIF_DEB_ENDS    15 // end naming scope
#define AIF_DEB_BITF    16 // bitfield
#define AIF_DEB_MACRO   17 // macro definition
#define AIF_DEB_ENDM    18 // macro undefinition
#define AIF_DEB_CLASS   19 // class
#define AIF_DEB_UNION   20 // union
#define AIF_DEB_FPMAP   32 // FP map fragment

//-------------------------------------------------------------------------
struct section_t
{
  uint32 code;          // Section code and length
  uchar lang;           // Language codes:
#define LANG_NONE    0  // Low-level debugging data only
#define LANG_C       1  // C source level debugging data
#define LANG_PASCAL  2  // Pascal source level debugging data
#define LANG_FORTRAN 3  // Fortran-77 source level debugging data
#define LANG_ASM     4  // ARM assembler line number data
  uchar flags;          // Format is unknown :(
  uchar reserved;
  uchar asdversion;     // ASD version.
#define ASD_VERSION  2
  uint32 codestart;     // Address of first instruction in this section,
                        // relocated by the linker.
  uint32 datastart;     // Address of start of static data for this section,
                        // relocated by the linker.
  uint32 codesize;      // Byte size of executable code in this section.
  uint32 datasize;      // Byte size of the static data in this section.
  uint32 fileinfo;      // Offset in the debugging area of the fileinfo item
                        // for this section (0 if no fileinfo item present).
                        // The fileinfo field is 0 if no source file
                        // information is present.
  uint32 debugsize;     // Total byte length of debug data for this section.
  uint32 name;          // ...or nsyms. String or integer. The name field
                        // contains the program name for Pascal and Fortran
                        // programs. For C programs it contains a name derived
                        // by the compiler from the root filename (notionally
                        // a module name). In each case, the name is similar
                        // to a variable name in the source language. For a
                        // low-level debugging section (language = 0), the
                        // field is treated as a four-byte integer giving the
                        // number of symbols following.
};

//-------------------------------------------------------------------------
// Debug symbol types:
struct dsym_t
{
  uint32 sym;   // Flags + byte offset in string table of symbol name.
#define ASD_SYMOFF   0x00FFFFFF
                // sym encodes an index into the string table in the 24 least
                // significant bits, and the following flag values in the
                // eight most significant bits:
#define ASD_ABSSYM   0x00000000 // if the symbol is absolute
#define ASD_GLOBSYM  0x01000000 // if the symbol is global
#define ASD_SYMMASK  0x06000000 // mask to determine the symbol type
#define ASD_TEXTSYM    0x02000000 // if the symbol names code
#define ASD_DATASYM    0x04000000 // if the symbol names data
#define ASD_ZINITSYM   0x06000000 // if the symbol names 0-initialized data
#define ASD_16BITSYM 0x10000000 // bit set if the symbol is a Thumb symbol
  uint32 value;  // the symbol's value.
  int is_text(void) { return (sym & ASD_SYMMASK) == ASD_TEXTSYM; }
  int is_data(void) { return (sym & ASD_SYMMASK) == ASD_DATASYM; }
  int is_bss(void)  { return (sym & ASD_SYMMASK) == ASD_ZINITSYM; }
};

/*
Several of the debugging data items (eg. procedure and variable) have a type
word field to identify their data type. This field contains
  in the most significant 24 bits, a code to identify a base
  in the least significant 8 bits, a pointer count:
    0 denotes the type itself
    1 denotes a pointer to the type
    2 denotes a pointer to a pointer

void 0
signed integers
  single byte 10
  halfword 11
  word 12
  double word 13
unsigned integers
  single byte 20
  halfword 21
  word 22
  double word 23
floating point
  float 30
  double 31
  int32 double 32
complex
  single complex 41
  double complex 42
functions
  function 100
*/

#endif
