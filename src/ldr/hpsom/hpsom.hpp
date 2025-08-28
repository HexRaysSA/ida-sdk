/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#ifndef HPSOM_HPP
#define HPSOM_HPP

// The timestamp is a two-word structure as shown below. If unused, both fields are
// zero.

struct sys_clock
{
  uint secs;
  uint nanosecs;
  void swap(void);
};

struct header
{
  short system_id;              /* system id */
#define SYSTEM_10       0x20B   // PA-RISC 1.0
#define SYSTEM_11       0x210   // PA-RISC 1.1
#define SYSTEM_20       0x214   // PA-RISC 2.0
  short int a_magic;            /* magic number */
#define EXELIB_MAGIC   0x104    // Executable SOM Library
#define REL_MAGIC      0x106    // Relocatable SOM
#define EXE_MAGIC      0x107    // Non-sharable, executable SOM
#define SHREXE_MAGIC   0x108    // Sharable, executable SOM
#define SHREXELD_MAGIC 0x10B    // Sharable, demand-loadable executable SOM
#define DLL_MAGIC      0x10D    // Dynamic Load Library
#define SHLIB_MAGIC    0x10E    // Shared Library
#define RELLIB_MAGIC   0x619    // Relocatable SOM Library
  uint version_id;              /* a.out format version */
  struct sys_clock file_time;   /* timestamp */
  uint entry_space;             /* index of space containing entry point */
  uint entry_subspace;          /* subspace index of entry */
  uint entry_offset;            /* offset of entry point */
  uint aux_header_location;     /* file ptr to aux hdrs */
  uint aux_header_size;         /* sizeof aux hdrs */
  uint som_length;              /* length of object module */
  uint presumed_dp;             /* DP value assumed during compilation */
  uint space_location;          /* file ptr to space dict */
  uint space_total;             /* # of spaces */
  uint subspace_location;       /* file ptr to subsp dict */
  uint subspace_total;          /* # of subspaces */
  uint loader_fixup_location;   /* space reference array */
  uint loader_fixup_total;      /* # of space reference recs */
  uint space_strings_location;  /* file ptr to sp. strings */
  uint space_strings_size;      /* sizeof sp. strings */
  uint init_array_location;     /* location of init pointers */
  uint init_array_total;        /* # of init pointers */
  uint compiler_location;       /* file ptr to comp recs */
  uint compiler_total;          /* # of compiler recs */
  uint symbol_location;         /* file ptr to sym table */
  uint symbol_total;            /* # of symbols */
  uint fixup_request_location;  /* file ptr to fixups */
  uint fixup_request_total;     /* # of fixups */
  uint symbol_strings_location; /* file ptr to sym strings */
  uint symbol_strings_size;     /* sizeof sym strings */
  uint unloadable_sp_location;  /* file ptr to debug info */
  uint unloadable_sp_size;      /* size of debug info */
  uint checksum;                /* header checksum */
  void swap(void);
};


//--------------------------------------------------------------------------
// Auxiliary Headers
//
// The auxiliary headers are contained in a single contiguous area in the file, and
// are located by a pointer in the file header. Auxiliary headers are used for two
// purposes: to attach users' version and copyright strings to an object file, and
// to contain the information needed to load an executable program. In an
// executable program, the HP-UX auxiliary header must precede all other auxiliary
// headers.

struct aux_id
{
  unsigned char flags;
#define AUX_MANDATORY  0x10   /* linker must understand aux hdr info */
#define AUX_COPY       0x20   /* copy aux hdr without modification */
#define AUX_APPEND     0x40   /* merge multiple entries of same type */
#define AUX_IGNORE     0x80   /* ignore aux hdr if type unknown */

  bool mandatory(void) { return (flags & AUX_MANDATORY) != 0; }
  bool copy(void)      { return (flags & AUX_COPY     ) != 0; }
  bool append(void)    { return (flags & AUX_APPEND   ) != 0; }
  bool ignore(void)    { return (flags & AUX_IGNORE   ) != 0; }

  uchar reserved;
  ushort type;                /* aux hdr type */
  uint length;                /* sizeof rest of aux hdr */
  void swap(void);
};

/* Values for the aux_id.type field */
#define HPUX_AUX_ID            4
#define VERSION_AUX_ID         6
#define COPYRIGHT_AUX_ID       9
#define SHLIB_VERSION_AUX_ID  10

struct som_exec_auxhdr           /* HP-UX auxiliary header */
{
  struct   aux_id header_id;   /* aux header id */
  int32    exec_tsize;         /* text size */
  int32    exec_tmem;          /* start address of text */
  int32    exec_tfile;         /* file ptr to text */
  int32    exec_dsize;         /* data size */
  int32    exec_dmem;          /* start address of data */
  int32    exec_dfile;         /* file ptr to data */
  int32    exec_bsize;         /* bss size */
  int32    exec_entry;         /* address of entry point */
  int32    exec_flags;         /* loader flags */
  int32    exec_bfill;         /* bss initialization value */
  void swap(void);
};

/* Values for exec_flags */
#define TRAP_NIL_PTRS    01

struct user_string_aux_hdr       /* Version string auxiliary header */
{
  struct aux_id header_id;       /* aux header id */
  uint string_length;            /* strlen(user_string) */
  char user_string[1];           /* user-defined string */
  void swap(void);
};

struct copyright_aux_hdr         /* Copyright string auxiliary header */
{
  struct aux_id header_id;       /* aux header id */
  uint string_length;            /* strlen(user_string) */
  char copyright[1];             /* user-defined string */
  void swap(void);
};

struct shlib_version_aux_hdr
{
  struct aux_id header_id;       /* aux header id */
  short version;                 /* version number */
  void swap(void);
};

//--------------------------------------------------------------------------
// Space Dictionary
//
// The space dictionary consists of a sequence of space records
//
// The strings for the space names are contained in the space strings table, which
// is located by a pointer in the file header. Each entry in the space strings
// table is preceded by a 4-byte integer that defines the length of the string, and
// is terminated by one to five null characters to pad the string out to a word
// boundary. Indices to this table are relative to the start of the table, and
// point to the first byte of the string (not the preceding length word). The union
// defined above is used for all such string pointers; the character pointer is
// defined for programs that read the string table into memory and wish to relocate
// in-memory copies of space records.



union name_pt
{
//    char         *n_name;
    uint n_strx;
};

struct space_dictionary_record
{
  union name_pt name;               /* index to space name */

  unsigned char flags;
#define SPACE_IS_LOADABLE   0x80   /* space is loadable */
#define SPACE_IS_DEFINED    0x40   /* space is defined within file */
#define SPACE_IS_PRIVATE    0x20   /* space is not sharable */
#define SPACE_HAS_INTERM    0x10   /* contains intermediate code */
#define SPACE_IS_TSPEC      0x08   /* space is $thread_specific$ */
  bool is_loadable(void)           { return (flags & SPACE_IS_LOADABLE) != 0; }
  bool is_defined(void)            { return (flags & SPACE_IS_DEFINED ) != 0; }
  bool is_private(void)            { return (flags & SPACE_IS_PRIVATE ) != 0; }
  bool has_intermediate_code(void) { return (flags & SPACE_HAS_INTERM ) != 0; }
  bool is_tspecific(void)          { return (flags & SPACE_IS_TSPEC   ) != 0; }
  unsigned char reserved;
  unsigned char sort_key;           /* sort key for space */
  unsigned char reserved2;          /* reserved */

  int  space_number;                /* space index */
  int  subspace_index;              /* index to first subspace */
  uint subspace_quantity;           /* # of subspaces in space */
  int  loader_fix_index;            /* index into loader fixup array */
  uint loader_fix_quantity;         /* # of loader fixups in space */
  int  init_pointer_index;          /* index into init pointer array */
  uint init_pointer_quantity;       /* # of init ptrs */
  void swap(void);
};

//--------------------------------------------------------------------------
// Subspace Dictionary
//
// The subspace dictionary consists of a sequence of subspace records, as defined
// in <scnhdr.h>. Strings for subspace names are contained in the space strings
// table.

struct subspace_dictionary_record
{
  int space_index;                    /* index into space dictionary */

  unsigned char f1;
#define SUBS_F1_ACCESS  0xFE          /* access and priv levels of subsp */
#define SUBS_F1_MEMRES  0x01          /* lock in memory during exec */
  int  access_control_bits(void) { return (f1 & SUBS_F1_ACCESS) >> 1; }
  bool memory_resident(void)     { return (f1 & SUBS_F1_MEMRES) != 0; }

  unsigned char f2;
#define SUBS_F2_DUPCOM  0x80          /* duplicate data symbols allowed */
#define SUBS_F2_INICOM  0x40          /* initialized common block */
#define SUBS_F2_ISLOAD  0x20          /* subspace is loadable */
#define SUBS_F2_QUADR   0x18          /* quadrant in space subsp should reside in */
#define SUBS_F2_FROZEN  0x04          /* lock in memory when OS booted */
#define SUBS_F2_FIRST   0x02          /* must be first subspace */
#define SUBS_F2_CODE    0x01          /* subspace contains only code */
  bool dup_common(void)       { return (f2 & SUBS_F2_DUPCOM) != 0; }
  bool is_common(void)        { return (f2 & SUBS_F2_INICOM) != 0; }
  bool is_loadable(void)      { return (f2 & SUBS_F2_ISLOAD) != 0; }
  int  quadrant(void)         { return (f2 & SUBS_F2_QUADR ) >> 3; }
  bool initially_frozen(void) { return (f2 & SUBS_F2_FROZEN) != 0; }
  bool is_first(void)         { return (f2 & SUBS_F2_FIRST ) != 0; }
  bool code_only(void)        { return (f2 & SUBS_F2_CODE  ) != 0; }

  unsigned char sort_key;             /* subspace sort key */

  unsigned char f3;
#define SUBS_F3_REPINI  0x80          /* init values to be replicated to fill subsp len */
#define SUBS_F3_CONTIN  0x40          /* subspace is a continuation */
#define SUBS_F3_ISTSPC  0x20          /* subspace contains TLS */
  bool replicate_init(void)   { return (f3 & SUBS_F3_REPINI) != 0; }
  bool continuation(void)     { return (f3 & SUBS_F3_CONTIN) != 0; }
  bool is_tspecific(void)     { return (f3 & SUBS_F3_ISTSPC) != 0; }

  int  file_loc_init_value;           /* file location or init value */
  uint initialization_length;         /* length of initialization */
  uint subspace_start;                /* starting offset */
  uint subspace_length;               /* total subspace length */
  unsigned short reserved2;           /* reserved */
  unsigned short alignment;           /* alignment required */
  union name_pt name;                 /* index of subspace name */
  int fixup_request_index;            /* index to first fixup */
  uint fixup_request_quantity;        /* # of fixup requests */
  void swap(void);
};


//--------------------------------------------------------------------------
// Symbol Table
//
// The symbol table consists of a sequence of entries described by the structure
// shown below, from <syms.h>. Strings for symbol and qualifier names are contained
// in the symbol strings table, whose structure is identical with the space strings
// table.

struct symbol_dictionary_record
{
  unsigned char f1;
#define SYM_F1_HIDDEN  0x80           /* symbol not visible to loader */
#define SYM_F1_SECDEF  0x40           /* secondary def symbol */
#define SYM_F1_TYPE    0x3F           /* symbol type */
  bool hidden(void)        { return (f1 & SYM_F1_HIDDEN) != 0; }
  bool secondary_def(void) { return (f1 & SYM_F1_SECDEF) != 0; }
  int  symbol_type(void)   { return (f1 & SYM_F1_TYPE);        }

  unsigned char f2;
#define SYM_F2_SCOPE   0xF0           /* symbol value */
#define SYM_F2_CHKLVL  0x0E           /* type checking level */
#define SYM_F2_MSTQUL  0x01           /* qualifier required */
  int  symbol_scope(void)  { return (f2 & SYM_F2_SCOPE ) >> 4; }
  int  check_level(void)   { return (f2 & SYM_F2_CHKLVL) >> 1; }
  bool must_qualify(void)  { return (f2 & SYM_F2_MSTQUL) != 0; }

  unsigned short f3;
#define SYM_F3_FROZEN  0x8000         /* lock in memory when OS booted */
#define SYM_F3_MEMRES  0x4000         /* lock in memory during exec */
#define SYM_F3_ISCOM   0x2000         /* common block */
#define SYM_F3_DUPCOM  0x1000         /* duplicate data symbols allowed */
#define SYM_F3_XLEAST  0x0C00         /* MPE-only */
#define SYM_F3_ARGREL  0x03FF         /* parameter relocation bits */
  bool initially_frozen(void) { return (f3 & SYM_F3_FROZEN) != 0; }
  bool memory_resident(void)  { return (f3 & SYM_F3_MEMRES) != 0; }
  bool is_common(void)        { return (f3 & SYM_F3_ISCOM ) != 0; }
  bool dup_common(void)       { return (f3 & SYM_F3_DUPCOM) != 0; }
  int  xleast(void)           { return (f3 & SYM_F3_XLEAST) >>10; }
  int  arg_reloc(void)        { return (f3 & SYM_F3_ARGREL);      }

  union name_pt  name;              /* index to symbol name */
  union name_pt  qualifier_name;    /* index to qual name */
  uint   symbol_info;       /* subspace index */
  uint   symbol_value;      /* symbol value */
  void swap(void);
};

/* Values for symbol_type */
#define ST_NULL      0     /* unused symbol entry */
#define ST_ABSOLUTE  1     /* non-relocatable symbol */
#define ST_DATA      2     /* initialized data symbol */
#define ST_CODE      3     /* generic code symbol */
#define ST_PRI_PROG  4     /* program entry point */
#define ST_SEC_PROG  5     /* secondary prog entry point*/
#define ST_ENTRY     6     /* procedure entry point */
#define ST_STORAGE   7     /* storage request */
#define ST_STUB      8     /* MPE-only */
#define ST_MODULE    9     /* Pascal module name */
#define ST_SYM_EXT   10    /* symbol extension record */
#define ST_ARG_EXT   11    /* argument extension record */
#define ST_MILLICODE 12    /* millicode entry point */
#define ST_PLABEL    13    /* MPE-only */
#define ST_OCT_DIS   14    /* Used by OCT only--ptr to translated code */
#define ST_MILLI_EXT 15    /* address of external millicode */
#define ST_TSTORAGE  16    /* TLS common symbol */

/* Values for symbol_scope */
#define SS_UNSAT     0     /* unsatisfied reference */
#define SS_EXTERNAL  1     /* import request to external symbol */
#define SS_LOCAL     2     /* local symbol */
#define SS_UNIVERSAL 3     /* global symbol */

// The meaning of the symbol value depends on the symbol type. For the code symbols
// (generic code, program entry points, procedure and millicode entry points), the
// low-order two bits of the symbol value encode the execution privilege level,
// which is not used on HP-UX, but is generally set to 3. The symbol value with
// those bits masked out is the address of the symbol (which is always a multiple
// of 4). For data symbols, the symbol value is simply the address of the symbol.
// For thread local storage symbols (not commons), the symbol value is the thread
// local storage offset in a library or executable file, and is the size of the
// symbol if in a relocatable object file. For storage requests and thread local
// storage commons, the symbol value is the number of bytes requested; the linker
// allocates space for the largest request for each symbol in the $BSS$ or $TBSS$
// subspaces, unless a local or universal symbol is found for that symbol (in which
// case the storage request is treated like an unsatisfied reference).
//
// If a relocatable file is compiled with parameter type checking, extension
// records follow symbols that define and reference procedure entry points and
// global variables. The first extension record, the symbol extension record,
// defines the type of the return value or global variable, and (if a procedure or
// function) the number of parameters and the types of the first three parameters.
// If more parameter type descriptors are needed, one or more argument extension
// records follow, each containing four more descriptors. A check level of 0
// specifies no type checking; no extension records follow. A check level of 1 or
// more specifies checking of the return value or global variable type. A check
// level of 2 or more specifies checking of the number of parameters, and a check
// level of 3 specifies checking the types of each individual parameter. The linker
// performs the requested level of type checking between unsatisfied symbols and
// local or universal symbols as it resolves symbol references.

union arg_descriptor
{
  struct
  {
    uint reserved: 3;    /* reserved */
    uint packing: 1;     /* packing algorithm used */
    uint alignment: 4;   /* byte alignment */
    uint mode: 4;        /* type of descriptor and its use */
    uint structure: 4;   /* structure of symbol */
    uint hash: 1;        /* set if arg_type is hashed */
    int  arg_type: 15;   /* data type */
  }  arg_desc;
  uint word;
};

struct symbol_extension_record
{
  uint type: 8;                /* always ST_SYM_EXT */
  uint max_num_args: 8;        /* max # of parameters */
  uint min_num_args: 8;        /* min # of parameters */
  uint num_args: 8;            /* actual # of parameters */
  union arg_descriptor symbol_desc;       /* symbol type desc. */
  union arg_descriptor argument_desc[3];  /* first 3 parameters */
};

struct argument_desc_array
{
  uint type: 8;                /* always ST_ARG_EXT */
  uint reserved: 24;           /* reserved */
  union arg_descriptor argument_desc[4];  /* next 4 parameters */
};

// The alignment field in arg_descriptor indicates the minimum alignment of the
// data, where a value of n represents 2^n byte alignment. The values for the mode,
// structure, and arg_type (when the data type is not hashed) fields in
// arg_descriptor are given in the following table.
//
// Value mode structure arg_type
// 0 any any any
// 1 value parm scalar void
// 2 reference parm array signed byte
// 3 value-result struct unsigned byte
// 4 name pointer signed short
// 5 variable int32 ptr unsigned short
// 6 function return C string signed int32
// 7 procedure Pascal string unsigned int32
// 8 int32 ref parm procedure signed dbl word
// 9  function unsigned dbl word
// 10  label short real
// 11   real
// 12   int32 real
// 13   short complex
// 14   complex
// 15   int32 complex
// 16   packed decimal
// 17   struct/array
//
//
// For procedure entry points, the parameter relocation bits define the locations
// of the formal parameters and the return value. Normally, the first four words of
// the parameter list are passed in general registers (r26-r23) instead of on the
// stack, and the return value is returned in r29. Floating-point parameters in
// this range are passed instead in floating-point registers (fr4-fr7) and a
// floating-point value is returned in fr4. The parameter relocation bits consist
// of five pairs of bits that describe the first four words of the parameter list
// and the return value. The leftmost pair of bits describes the first parameter
// word, and the rightmost pair of bits describes the return value. The meanings of
// these bits are shown in the following table.
//
// Bits Meaning
// 00 No parameter or return value
// 01 Parameter or return value in general register
// 10 Parameter or return value in floating-point register
// 11 Double-precision floating-point value
//
//
// For double-precision floating-point parameters, the odd-numbered parameter word
// should be marked 11 and the even-numbered parameter word should be marked 10.
// Double-precision return values are simply marked 11.
//
// Every procedure call is tagged with a similar set of bits (see "Relocation
// Information" below), so that the linker can match each call with the
// expectations of the procedure entry point. If the call and entry point mismatch,
// the linker creates a stub that relocates the parameters and return value as
// appropriate.


//--------------------------------------------------------------------------
// DL header
//
// The DL header appears in every shared library and in incomplete executables (program
// files linked with shared libraries--may contain unsatisfied symbols which will be satis-fied
// at run time by the dynamic loader). It is assumed to be at offset 0 in the $TEXT$
// space. It defines fields used by the dynamic loader and various other tools when attach-ing
// the shared libraries at run time. The header contains information on the location of
// the export and import lists, the module table, the linkage tables, as well as the sizes of
// the tables.


struct dl_header
{
  int hdr_version;       /* header version number */
#define OLD_HDR_VERSION  89060912  // prior to 10.0
#define HDR_VERSION      93092112
  int ltptr_value;       /* data offset of LT pointer (R19) */
  int shlib_list_loc;    /* text offset of shlib list */
  int shlib_list_count;  /* count of items in shlib list */
  int import_list_loc;   /* text offset of import list */
  int import_list_count; /* count of items in import list */
  int hash_table_loc;    /* text offset of export hash table */
  int hash_table_size;   /* count of slots in export hash table */
  int export_list_loc;   /* text offset of export list */
  int export_list_count; /* count of items in export list */
  int string_table_loc;  /* text offset of string table */
  int string_table_size; /* length in bytes of string table */
  int dreloc_loc;        /* text offset of dynamic reloc records */
  int dreloc_count;      /* number of dynamic relocation records */
  int dlt_loc;           /* data offset of data linkage table */
  int plt_loc;           /* data offset of procedure linkage table */
  int dlt_count;         /* number of dlt entries in linkage table */
  int plt_count;         /* number of plt entries in linkage table */
  short highwater_mark;  /* highest version number seen in lib or in shlib list*/
  short flags;           /* various flags */
#define ELAB_DEFINED         1 /* an elaborator has been defined for this library */
#define INIT_DEFINED         2 /* an initializer has been defined for this library */
#define SHLIB_PATH_ENABLE    4 /* allow search of SHLIB_PATH at runtime */
#define EMBED_PATH_ENABLE    8 /*allow search of embed path at runtime*/
#define SHLIB_PATH_FIRST    16 /* search SHLIB_PATH first */
#define SEARCH_ALL_STORS    32 /* search all shlibs to satisfy STOR import */
#define SHLIB_INTERNAL_NAME 64 /*shlib has an internal name, for library-level versioning support*/
  int export_ext_loc;    /* text offset of export extension tbl */
  int module_loc;        /* text offset of module table*/
  int module_count;      /* number of module entries */
  int elaborator;        /* import index of elaborator */
  int initializer;       /* import index of initializer */
  int embedded_path;     /* index into string table for search path. index must be > 0 to be valid */
  int initializer_count; /* count of items in initializer import list*/
  int tdsize;            /* size of the TSD area */
  int fastbind_list_loc; /* text-relative offset of fastbind info */
  void swap(void);
};

// Import entry

struct import_entry     // parallel with DLT followed by PLT
{
  int name;                     /* offset in string table */
  short reserved2;              /* unused */
  unsigned char type;           /* symbol type */
  unsigned char flags;
#define IMP_ENTRY_BYPASS 0x80   /* address of code symbol not taken in shlib */
#define IMP_ENTRY_TPREL  0x40   /* new field*/
  bool bypassable(void)     { return (flags & IMP_ENTRY_BYPASS) != 0; }
  bool is_tp_relative(void) { return (flags & IMP_ENTRY_TPREL ) != 0; }
  void swap(void);
};

// Export entry

struct misc_info
{
  short version;               /* months since January, 1990 */
  ushort flags;
#define MISC_INFO_RELOC 0x3FF  /* parameter relocation bits (5*2) */
  uint arg_reloc(void) { return flags & MISC_INFO_RELOC; }
  void swap(void);
};

struct export_entry
{
  int next;                /* index of next export entry in hash chain */
  int name;                /* offset within string table */
  int value;               /* offset of symbol (subject to relocation) */
  union
  {
    int size;              /* storage request area size in bytes */
    struct misc_info misc; /* version, etc. N/A to storage requests */
  } info;
  unsigned char type;      /* symbol type */
  unsigned char flags;
#define EXP_ENTRY_TPREL  0x80   /* TLS export*/
  bool is_tp_relative(void) { return (flags & EXP_ENTRY_TPREL ) != 0; }
  short module_index;      /* index of module defining this symbol */
  void swap(void);
};

#endif // ifndef HPSOM_HPP
