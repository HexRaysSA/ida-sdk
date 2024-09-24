/*
 *      Interactive disassembler (IDA).
 *      Version 4.20
 *      Copyright (c) 2002 by Ilfak Guilfanov. (ig@datarescue.com)
 *      ALL RIGHTS RESERVED.
 *
 */

//
//      Intel OMF386
//

#ifndef INTELOMF_HPP
#define INTELOMF_HPP

#pragma pack(push, 1)

#define INTELOMF_MAGIC_BYTE     0xB0    // The first byte of the file
                                        // must have this value

//-----------------------------------------------------------------------
// Linkable Module Header
// A linkable object file contains one or more linkable modules
//-----------------------------------------------------------------------
struct lmh  /* linkable module header */
{
  uint32 tot_length;    /* total length of the module on disk in bytes */
  int16 num_segs;       /* number of SEGDEF sections in the module */
  int16 num_gates;      /* number of GATDEF sections in the module */
  int16 num_publics;    /* number of PUBDEF sections in the module */
  int16 num_externals;  /* number of EXTDEF sections in the module */
  char linked;          /* linked = 0, if the module was produced by a translator */
  char date[8];         /* the creation date, written in the form MM/DD/YY */
  char time[8];         /* the creation time, written in the form HH:MM:SS */
  char mod_name[41];    /* name of the module, the first char is the string's length */
  char creator[41];     /* the name of the program which created the module */
  char src_path[46];    /* the path to the source file which produced the module */
  char trans_id;        /* translator id, mainly for debugger */
  char trans_vers[4];   /* translator version (ASCII) */
  char OMF_vers;        /* OMF version */
};

//-----------------------------------------------------------------------
struct toc_p1      /* Table of contents for first partition */
{
  int32 SEGDEF_loc; /* all the following _loc represents location of the first byte */
  int32 SEGDEF_len; /* of the section in current module, unit is byte; */
  int32 GATDEF_loc; /* all the following _len represents the length of the section */
  int32 GATDEF_len; /* also the unit is byte. */
  int32 TYPDEF_loc;
  int32 TYPDEF_len;
  int32 PUBDEF_loc;
  int32 PUBDEF_len;
  int32 EXTDEF_loc;
  int32 EXTDEF_len;
  int32 TXTFIX_loc;
  int32 TXTFIX_len;
  int32 REGINT_loc;
  int32 REGINT_len;
  int32 next_partition;
  int32 reserved;
};

//-----------------------------------------------------------------------
struct segdef  /* segment definition */
{
  int16 attributes;   /* need to be separated into bits to get bitwise info(cf. [1]) */
  int32 slimit;       /* the length of the segment minus one, in bytes */
  int32 dlength;      /* the number of data bytes in the segment, only for dsc seg*/
  int32 speclength;   /* the total number of bytes in the segment */
  int16 ldt_position; /* the position in LDT that this segment must occupy */
  char align;       /* alignment requirements of the segment */
  char combine_name[41]; /* first char is the length of the string in byte,
                       rest is name */
};

//-----------------------------------------------------------------------
// The GATDEF section defines an entry for each gate occurring in the module.
// There is a 1-byte field in the data structure which is used to identify type
// of gate from call gate, task gate, interrupt gate or trap gate. (cf. [1])

struct gatdef     /* Gate definition */
{
  char privilege; /* privilege of gate */
  char present;
  char gate_type;
  int32 GA_offset; /* gate entry GA consists of GA_offset and GA_segment */
  int16 GA_segment;
};

//-----------------------------------------------------------------------
// The TYPDEF section serves two purposes: to allow Relocation and Linkage
// software to check the validity of sharing data across external linkages,
// and to provide type information to debuggers to interpret data correct.
// [2] provides storage size equivalence tables and lists the syntactical
// constructs for high level languages PL/M, PASCAL, FORTRAN and C.

struct leaf
{
  char type;   /* an 8-bit number defines the type of the leaf */
  union        /* following are different kind of leaves */
  {
    char *string;
    int16 num_2;
    int32 num_4;
    uint64 num_8;
    int64 s_8;
    int16 s_2;
    int32 s_4;
  } content;
  struct leaf *next; /* points to next leaf */
};

struct typdef     /* type definition */
{
  char linkage;   /* is TRUE, if for public-external linkage; is FALSE, if only for debug symbols. */
  int16 length;   /* the length in bytes of all the leaves in it */
  struct leaf leaves; /* all different leaves format */
};

//-----------------------------------------------------------------------
// PUBDEF section contains a list of public names with their general
// addresses for the public symbols. The 2-byte field type_IN specifies
// an internal name for a segment, gate, GDT selector or the special
// CONST$IN. This section serves to define symbols to be exported to
// other modules.

struct pubdef   /* public definition */
{
  int32 PUB_offset; /* gen addr consists of PUB_offset and PUB_segment */
  int16 PUB_segment;
  int16 type_IN; /* internal name for the type of the public of symbol */
  char wordcount; /* the total # of 16-bit entities of stacked parameters */
  char sym_name[256];
};

//-----------------------------------------------------------------------
// EXTDEF section lists all external symbols, which are then referenced
// elsewhere in the module by means of their internal name. The 2-byte
// field seg_IN specifies the segment that is assumed to contain the
// matching public symbol and the 2-byte value of type_IN defines the
// type of the external symbol. (cf. [1])

struct extdef    /* external definition */
{
  int16 seg_IN;  /* internal name of segment having matched public symbol */
  int16 type_IN; /* internal name for the type of the external symbol */
  char allocate; /* not zero, if R&L needs allocate space for external symbol*/
  union
  {
    int16 len_2;
    int32 len_4;
  } allocate_len; /* number of bytes needed allocated for the external symbol */
  char sym_name[256]; /* the 1st char is length , the rest are name of the symbol*/
};

//-----------------------------------------------------------------------
// text block contains binaries for code segment and data segment.
// These segments are relocatable. Other than that, all the SLD information
// is also implemented in this block by a translator under debug option.
// Segment MODULES in the text block is designed with the purpose of
// providing general information about the current module. Segment MBOLS
// provides entries for each symbol used in the module, including stack
// symbols, local symbols and symbols that are used as procedure or block
// start entries. Segment LINES consists of line offset values, each line
// offset is the byte offset of the start of a line in the code segment.
// Segment SRCLINES consists of line offsets of the source files.

struct mod       /* MODULES segment */
{
  int16 ldt_sel;      /* a selector into the GDT for an LDT which contains the segments in this module */
  int32 code_offset;  /* code segment GA consists of code_offset and code_IN */
  int16 code_IN;
  int32 types_offset; /* TYPES GA consists of types_offset and types_IN */
  int16 types_IN;
  int32 sym_offset;   /* MBOLS GA consists of sym_coffset and sym_IN */
  int16 sym_IN;
  int32 lines_offset; /* LINES GA consists of lines_offset and lines_IN */
  int16 lines_IN;
  int32 pub_offset;   /* PUBLICS GA consists of pub_offset and pub_IN */
  int16 pub_IN;
  int32 ext_offset;   /* EXTERNAL GA consists of ext_offset and ext_IN */
  int16 ext_IN;
  int32 src_offset;   /* SRCLINES GA consists of src_offset and src_IN */
  int16 src_IN;
  int16 first_line;   /* first line number */
  char kind;          /* 0 value for 286, 1 value for 386 format */
  char trans_id;      /* same as lmh */
  char trans_vers[4]; /* same as lmh */
  char *mod_name;     /* same as lmh */
};

struct blk          /* block start entry */
{
  int32 offset;     /* offset in code segment */
  int32 blk_len;    /* block length */
  char *blk_name;   /* block name, note that first byte is the length of string */
};

struct proc         /* procedure start entry */
{
  int32 offset;     /* offset in code segment */
  int16 type_IN;    /* internal name of the typdef associated with the proc */
  char kind;        /* specifying 16-bit or 32-bit */
  int32 ebp_offset; /* offset of return address from EBP */
  int32 proc_len;   /* procedure length */
  char *proc_name;  /* procedure name, as always, the 1st char is string length */
};

struct sbase        /* symbol base entry */
{
  int32 offset;
  int16 s_IN;
};

struct symbol       /* symbol entry */
{
  int32 offset;
  int16 type_IN;
  char *sym_name;
};

struct sym          /* MBOLS segment */
{
  char kind;        /* kind of entries */
  union
  {
    struct blk blk_start;  /* block start entry */
    struct proc prc_start; /* procedure start entry */
    struct sbase sym_base; /* symbol base entry */
    struct symbol s_ent;   /* symbol entry */
  } entry;
  struct sym *next;
};

struct line         /* LINES segment */
{
  int32 offset;
  struct lines *next;
};

struct src          /* SRCLINES segment */
{
  char *src_file;   /* source file name */
  int16 count;
  struct lines *src_line;
  struct srclines *next;
};

struct text             /* text block */
{
  int32 txt_offset;     /* gen addr consists of txt_offset and txt_IN */
  int16 txt_IN;         /* internal segment name */
  int32 length;         /* the length of the text content, in byte */
  union
  {
    char *code;         /* CODE segment */
    char *data;         /* DATA segment */
    struct mod modules; /* MODULES segment */
    struct sym symbols; /* MBOLS segment */
    struct line lines;  /* LINES segment */
    struct src srclines;/* SRCLINES segment */
  } segment;
};

//-----------------------------------------------------------------------
// block contains information that allows the binder or linker to resolve
// (fix up) and eventually relocate references between object modules.
// The attributes where_IN and where_offset in the following data structures
// make a generalized address specifying the target for the fixup. Similarly,
// the attributes what_IN and what_offset make a generalized address
// specifying the target to which the fixup is to be applied.

// There are four kinds of fixups for Intel linkable object modules.
// They are:
//      general fixup,
//      intra-segment fixup,
//      call fixup
//      addition fixup.
// The general fixup and the addition fixup have the same data structure,
// both provide general addresses for where_IN, where_offset, and what_IN,
// what_offset. The intra-segment fixup is equivalent to a general fixup
// with what_IN = where_IN, and the call fixup is also equivalent to a
// general fixup with what_offset = 0. (cf. [1])

struct gen        /* for general fixup */
{
  char kind;      /* specifying the kind of fixup */
  union
  {
    int16 num2;
    int32 num4;
  } where_offset; /* 2- or 4- byte where_offset */
  union
  {
    int16 num2;
    int32 num4;
  } what_offset;  /* 2- or 4- byte what_offset */
  int16 what_IN;  /* what_IN & what_offset specify the target for the fixup*/
  union fixups *next;
};

struct intra      /* for intra-segment fixup */
{
  char kind;      /* specifying the kind of fixup */
  union
  {
    int16 num2;
    int32 num4;
  } where_offset; /* 2- or 4- byte where_offset */
  union
  {
    int16 num2;
    int32 num4;
  } what_offset;  /* 2- or 4- byte what_offset */
  union fixups *next;
};

struct cal        /* for call fixup */
{
  char kind;      /* specifying the kind of fixup */
  union
  {
    int16 num2;
    int32 num4;
  } where_offset; /* 2- or 4- byte where-offset */
  int16 what_IN;
  union fixups *next;
};

struct ad         /* for addition fixup */
{
  char kind;      /* specifying the kind of fixup */
  union
  {
    int16 num2;
    int32 num4;
  } where_offset; /* specifying the target to which the fixup is to be applied */
  union
  {
    int16 num2;
    int32 num4;
  } what_offset;
  int16 what_IN;
  union fixups *next;
};

struct temp       /* for the text template in the iterated text block */
{
  int32 length;   /* the length, in bytes, of a single mem blk to be initialized */
  char *value;    /* the text or data to be used to initialize any single mem blk*/
};

struct iterat       /* for iterated text block */
{
  int32 it_offset;
  int16 it_segment; /* above two specify a gen addr to put 1st byte of the text */
  int32 it_count;   /* the # of times the text template is to be repeated */
  struct temp text; /* the text template */
};

struct fixup    /* fixup block */
{
  int16 where_IN; /* specifying the segment to which fixups should be applied*/
  int16 length;   /* the length in bytes of the fixups */
  union
  {
    struct gen general;  /* for general fixup */
    struct intra in_seg; /* for intra-segment fixup */
    struct cal call_fix; /* call fixup */
    struct ad addition;  /* addition fixup */
  } fixups;
};

//-----------------------------------------------------------------------
// The TXTFIX section consists of intermixed text block, fixup block and
// iterated text block. As one can see, it is the TXTFIX section that
// records the binaries for machine codes, initialized data and
// uninitialized data. TXTFIX section output by a translator under debug
// option will also contain SLD information.

struct txtfix           /* text, iterated text and fixup block */
{
  char blk_type;        /* 0 for text blk; 1 for fixup blk and 2 for iterated text blk */
  union
  {
    struct text text_blk; /* text block */
    struct fixup fixup_blk; /* fixup block */
    struct iterat it_text_blk; /* iterated text block */
  } block;
  struct txtfix *next;
};

// The file ends with a checksum byte

#pragma pack(pop)
#endif
