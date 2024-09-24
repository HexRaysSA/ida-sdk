/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *      ARM Object File Loader
 *
 */

#ifndef __AOF_H__
#define __AOF_H__

//-------------------------------------------------------------------------
struct chunk_header_t
{
  uint32 ChunkFileId;
#define AOF_MAGIC       0xC3CBC6C5 // magic value of chunk file
#define AOF_MAGIC_B     0xC5C6CBC3 // magic value of chunk file (big endian)
  uint32 max_chunks;     // defines the number of the entries in the
                        // header, fixed when the file is created.
  uint32 num_chunks;    // defines how many chunks are currently used in
                        // the file, which can vary from 0 to maxChunks.
                        // It is redundant in that it can be found by scanning
                        // the entries.
};

//-------------------------------------------------------------------------
struct chunk_entry_t
{
  char chunkId[8];      // an 8-byte field identifying what data the chunk
                        // contains. Note that this is an 8-byte field, not
                        // a 2-word field, so it has the same byte order
                        // independent of endianness.
#define OBJ_HEAD "OBJ_HEAD" // AOF Header
#define OBJ_AREA "OBJ_AREA" // Areas
#define OBJ_IDFN "OBJ_IDFN" // Identification
#define OBJ_SYMT "OBJ_SYMT" // Symbol Table
#define OBJ_STRT "OBJ_STRT" // String Table
  uint32 file_offset;   // a one-word field defining the byte offset within
                        // the file of the start of the chunk. All chunks are
                        // word-aligned, so it must be divisible by four.
                        // A value of zero indicates that the chunk entry
                        // is unused.
  uint32 size;          // a one-word field defining the exact byte size
                        // of the chunk's contents (which need not be a
                        // multiple of four).
};

//-------------------------------------------------------------------------
struct aof_header_t
{
  uint32 obj_file_type; // the value 0xC5E2D080 marks the file as being in
                        // relocatable object format (the usual output of
                        // compilers and assemblers and the usual input to
                        // the linker). The endianness of the object code
                        // can be deduced from this value and must be
                        // identical to the endianness of the containing
                        // chunk file.
#define OBJ_FILE_TYPE_MAGIC 0xC5E2D080
  uint32 version;       // encodes the version of AOF with which the object
                        // file complies
                        // version 1.50 is denoted by decimal 150
                        // version 2.00 is denoted by decimal 200
                        // this version is denoted by decimal 310 (0x136)
  uint32 num_areas;     // Number of Areas
  uint32 num_syms;      // Number of Symbols
  uint32 entry_area;    // Entry Area Index. in the range 1 to Number of
                        // Areas, gives the 1-origin index in the following
                        // array of area headers of the area containing the
                        // entry point. The entry address is defined to be
                        // the base address of this area plus Entry Offset.
                        // A value of 0 for Entry Area Index signifies that
                        // no program entry address is defined by this AOF
                        // file.
  uint32 entry_offset;
};

//-------------------------------------------------------------------------
struct area_header_t
{
  uint32 name;          // Area name (offset into string table)
  uint32 flags;         // Attributes + Alignment
                        // The least significant eight bits of this word
                        // encode the alignment of the start of the area as a
                        // power of 2 and must have a value between 2 and 32.
#define AREA_ABS    0x00000100 // The absolute attribute: denotes that the
                               // area must be placed at its Base Address.
                               // This bit is not usually set by language
                               // processors.
#define AREA_CODE   0x00000200 // CODE (otherwise DATA)
#define AREA_COMMON 0x00000400 // The area is a common definition.
#define AREA_COMREF 0x00000800 // The area is a reference to a common block:
                               // preclude the area having initializing data
                               // (see AREA_BSS). In effect, AREA_COMREF
                               // implies AREA_BSS.
                               // If both bits AREA_COMMON and AREA_COMREF
                               // are set, bit AREA_COMREF is ignored.
#define AREA_BSS    0x00001000 // Zero-initialized: the area has no
                               // initializing data in this object file,
                               // and that the area contents are missing from
                               // the OBJ_AREA chunk.
#define AREA_RDONLY 0x00002000 // Readonly area
#define AREA_PIC    0x00004000 // The position independent (PI) area
#define AREA_DEBUG  0x00008000 // The debugging table.

        // CODE areas only:

#define AREA_32BIT  0x00010000 // 32-bit area (not 26bit)
#define AREA_REENTR 0x00020000 // The re-entrant area
#define AREA_EXTFP  0x00040000 // Extended floating-point instruction set
                               // is used in the area.
#define AREA_NOCHK  0x00080000 // No Software Stack Check
#define AREA_THUMB  0x00100000 // Thumb code area
#define AREA_HALFW  0x00200000 // Halfword instructions may be present
#define AREA_INTER  0x00400000 // Area has been compiled to be suitable for
                               // ARM/Thumb interworking.

        // DATA areas only:

#define AREA_BASED  0x00100000 // Based area
inline int get_based_reg() { return int(flags >> 24) & 15; }

#define AREA_SHARED 0x00200000 // Shared Library Stub Data

  uint32 size;          // Area Size. Gives the size of the area in bytes,
                        // which must be a multiple of 4. Unless the
                        // "Not Initialised" bit (bit 12) is set in the area
                        // attributes, there must be this number of bytes
                        // for this area in the OBJ_AREA chunk.
                        // If the "Not Initialised" bit is set, there must be
                        // no initializing bytes for this area in the
                        // OBJ_AREA chunk.
  uint32 num_relocs;    // Number of Relocations. Specifies the number of
                        // relocation directives which apply to this area
                        // (which is equivalent to the number of relocation
                        // records following the area's contents in the
                        // OBJ_AREA chunk.
  uint32 baseaddr;      // Base Address or 0. Is unused unless the area has
                        // the absolute attribute. In this case, the field
                        // records the base address of the area. In general,
                        // giving an area a base address prior to linking
                        // will cause problems for the linker and may prevent
                        // linking altogether, unless only a single object
                        // file is involved.
};

//-------------------------------------------------------------------------
// segment flag bits in IDA for ARM module:
// the bits are kept in netnode().altval(seg_start_ea)

#ifdef _NETNODE_HPP
#define SEGFL_NETNODE_NAME "$ arm segflags"
#define SEGFL_BREG      0x000F
#define SEGFL_PIC       0x0010
#define SEGFL_REENTR    0x0020
#define SEGFL_HALFW     0x0040
#define SEGFL_INTER     0x0080
#define SEGFL_COMDEF    0x0100
#define SEGFL_BASED     0x0200
#define SEGFL_ALIGN     0x7C00
#define SEGFL_SHIFT     10

inline void set_arm_segm_flags(ea_t ea, ushort flags)
{
  netnode n;
  n.create(SEGFL_NETNODE_NAME);
  n.altset_ea(ea, flags);
}

inline ushort get_arm_segm_flags(ea_t ea)
{
  return (ushort)netnode(SEGFL_NETNODE_NAME).altval_ea(ea);
}
#endif

//-------------------------------------------------------------------------
struct reloc_t
{
  uint32 offset;
  uint32 type;                  // Low 24bits are SID
  size_t sid(void) { return size_t(type & 0x00FFFFFF); }
#define RF_II 0x60000000      // if RF_FT == 11, then:
                              // 00 no constraint (the linker may modify as many contiguous instructions as it needs to)
                              // 01 the linker will modify at most 1 instruction
                              // 10 the linker will modify at most 2 instructions
                              // 11 the linker will modify at most 3 instructions
#define RF_B  0x10000000      // Based
#define RF_A  0x08000000      // 1: The subject field is relocated by the
                              //    value of the symbol of which SID is the
                              //    zero-origin index in the symbol table
                              //    chunk.
                              // 0: The subject field is relocated by the
                              //    base of the area of which SID is the
                              //    zero-origin index in the array of areas,
                              //    (or, equivalently, in the array of area
                              //    headers).
#define RF_R  0x04000000      // PC relative
#define RF_FT 0x03000000
#define RF_FT_BYTE 0x00000000 // 00 the field to be relocated is a byte
#define RF_FT_HALF 0x01000000 // 01 the field to be relocated is a halfword (two bytes)
#define RF_FT_WORD 0x02000000 // 10 the field to be relocated is a word (four bytes)
#define RF_FT_INSN 0x03000000 // 11 the field to be relocated is an instruction or instruction sequence
};

//-------------------------------------------------------------------------
struct sym_t
{
  uint32 name;          // Offset in the string table (in chunk OBJ_STRT) of
                        // the character string name of the symbol.
  uint32 flags;         // Attributes.
#define SF_DEF   0x00000001     //   Symbol is defined in this file
#define SF_PUB   0x00000002     //   Symbol has a global scope
#define SF_ABS   0x00000004     //   Absolute attribute
#define SF_ICASE 0x00000008     //   Case-insensitive attribute
#define SF_WEAK  0x00000010     //   Weak attribute
#define SF_STRNG 0x00000020     //   Strong attribute
#define SF_COMM  0x00000040     //   Common attribute
                                // Code symbols only:
#define SF_CDATA 0x00000100     //   Code area datum attribute
#define SF_FPREG 0x00000200     //   FP args in FP regs attribute
#define SF_LEAF  0x00000800     //   Simple leaf function attribute
#define SF_THUMB 0x00001000     //   Thumb symbol
  uint32 value;         // is meaningful only if the symbol is a defining
                        // occurrence (bit 0 of Attributes set), or a common
                        // symbol (bit 6 of Attributes set):
                        // - if the symbol is absolute (bits 0-2 of
                        //   Attributes set), this field contains the value
                        //   of the symbol
                        // - if the symbol is a common symbol (bit 6 of
                        //   Attributes set), this contains the byte length
                        //   of the referenced common area
                        // - otherwise, value is interpreted as an offset
                        //   from the base address of the area named by
                        //   Area Name, which must be an area defined in
                        //   this object file
  uint32 area;          // Area Name is meaningful only if the symbol is a
                        // non-absolute defining occurrence (bit 0 of
                        // Attributes set, bit 2 unset). In this case it
                        // gives the index into the string table for the name
                        // of the area in which the symbol is defined (which
                        // must be an area in this object file).
};

#endif
