#ifndef _H_SYMS
#define _H_SYMS

#include <../ldr/coff/storclas.h>
#pragma pack(push, 1)

#define SYMNMLEN        8       /* Number of characters in a symbol name */
#define FILNMLEN        14      /* Number of characters in a file name */
#define DIMNUM          4       /* Number of array dimensions in auxiliary entry */

struct coff_sym_t // here for efd(di) and ldr/dbg
{
  union
  {
    char _n_name[SYMNMLEN];     /* old COFF version */
    struct
    {
      int32 _n_zeroes;          /* new == 0 */
      int32 _n_offset;          /* offset into string table */
    } _n_n;
//    char *_n_nptr[2];         /* allows for overlaying */
  } _n;
  uint32 n_value;               /* value of symbol */
  uint16 n_scnum;               /* section number */
  uint16 n_type;                /* type and derived type */
  uchar n_sclass;               /* storage class */
  uchar n_numaux;               /* number of aux. entries */
};

struct coff_sym64_t
{
  uint64  n_value64;  /* value of symbol */
  uint32  n_offset64; /* offset into string table */
  uint16  n_scnum;    /* section number */
  union
  {
    unsigned short _n_type;   /* type and derived type */
    struct
    {
      unsigned char _n_lang;  /* source language id */
      unsigned char _n_cpu; /* cputype id   */
    } _n_lc;
  } _n_tylc;
  char   n_sclass;  /* storage class */
  char   n_numaux;  /* number of aux. entries */
};

#define IDA_SYM_SZ    (SYMNMLEN + 8 + 4 + 2 + 2*1)

struct ida_sym_t // internal, translated form
{
  union
  {
    char _n_name[SYMNMLEN];     /* old for short name (<=8) */
    struct
    {
      int32 _n_zeroes;          /* for long name == 0 */
      int32 _n_offset;          /* offset into string table */
    } _n_n;
  } _n;
  uint64  n_value;              /* value of symbol */
  uint32  n_scnum;              /* section number */
  uint16  n_type;               /* type and derived type */
  uchar   n_sclass;             /* storage class */
  uchar   n_numaux;             /* number of aux. entries */
};

DECLARE_TYPE_AS_MOVABLE(ida_sym_t);

#define COFF_SYM_SZ   (SYMNMLEN + 4 + 2*2 + 2*1)
#define COFF_SYM64_SZ (8 + 4 + 2 + 2 + 2*1)
#define n_name          _n._n_name
#define n_nptr          _n._n_nptr[1]
#define n_zeroes        _n._n_n._n_zeroes
#define n_offset        _n._n_n._n_offset

/*
 * Relocatable symbols have a section number of the
 * section in which they are defined. Otherwise, section
 * numbers have the following meanings:
 */
#define N_UNDEF 0          // undefined symbol
#define N_ABS   uint16(-1) // value of symbol is absolute
#define N_DEBUG uint16(-2) // special debugging symbol -- value of symbol is meaningless
#define N_TV    uint16(-3) // indicates symbol needs transfer vector (preload)
#define P_TV    uint16(-4) // indicates symbol needs transfer vector (postload)

/*
 * The fundamental type of a symbol packed into the low
 * 4 bits of the word.
 */

#if 0
#define _EF     ".ef"
#endif

/*
 * Type of a symbol, in low N bits of the word
 */
#define T_NULL          0
#define T_VOID          1       /* function argument (only used by compiler) */
#define T_CHAR          2       /* character            */
#define T_SHORT         3       /* short integer        */
#define T_INT           4       /* integer              */
#define T_LONG          5       /* long integer         */
#define T_FLOAT         6       /* floating point       */
#define T_DOUBLE        7       /* double word          */
#define T_STRUCT        8       /* structure            */
#define T_UNION         9       /* union                */
#define T_ENUM          10      /* enumeration          */
#define T_MOE           11      /* member of enumeration*/
#define T_UCHAR         12      /* unsigned character   */
#define T_USHORT        13      /* unsigned short       */
#define T_UINT          14      /* unsigned integer     */
#define T_ULONG         15      /* unsigned long        */
#define T_LNGDBL        16      /* long double          */

/*
 * derived types, in n_type
*/
#define DT_NON          (0)     /* no derived type */
#define DT_PTR          (1)     /* pointer */
#define DT_FCN          (2)     /* function */
#define DT_ARY          (3)     /* array */

/*
 *      type packing constants
 */

#define IDA_N_BTMASK        017
#define IDA_N_TMASK         060
#define IDA_N_TMASK1        0300
#define IDA_N_TMASK2        0360
#define IDA_N_BTSHFT        4
#define IDA_N_TSHIFT        2

//--------------------------------------------------------------------------
        /*   Basic Type of  x   */

#define IDA_BTYPE(x)  ((x) & IDA_N_BTMASK)

        /*   Is  x  a  pointer ?   */

#define IDA_ISPTR(x)  (((x) & IDA_N_TMASK) == (DT_PTR << IDA_N_BTSHFT))

        /*   Is  x  a  function ?  */

#define IDA_ISFCN(x)  (((x) & IDA_N_TMASK) == (DT_FCN << IDA_N_BTSHFT))

        /*   Is  x  an  array ?   */

#define IDA_ISARY(x)  (((x) & IDA_N_TMASK) == (DT_ARY << IDA_N_BTSHFT))

        /* Is x a structure, union, or enumeration TAG? */

#define IDA_ISTAG(x)  ((x)==C_STRTAG || (x)==C_UNTAG || (x)==C_ENTAG)

#define IDA_INCREF(x) ((((x)&~IDA_N_BTMASK)<<IDA_N_TSHIFT)|(DT_PTR<<IDA_N_BTSHFT)|(x&IDA_N_BTMASK))

#define IDA_DECREF(x) ((((x)>>IDA_N_TSHIFT)&~IDA_N_BTMASK)|((x)&IDA_N_BTMASK))

/*************************************************************************
 *
 *      AUXILIARY ENTRY FORMAT
 *
 *************************************************************************/

typedef union auxent
{
  struct
  {
    int32 x_tagndx;             /* str, un, or enum tag indx */
#define x_exptr x_tagndx        /* exception table offset */
    union
    {
      struct
      {
        uint16 x_lnno;          /* declaration line number */
        uint16 x_size;          /* str, union, array size */
      } x_lnsz;
      int32 x_fsize;            /* size of function */
    } x_misc;
    union
    {
      struct
      {                  /* if ISFCN, tag, or .bb */
        int32 x_lnnoptr;        /* ptr to fcn line # */
        int32 x_endndx;         /* entry ndx past block end */
      } x_fcn;
      struct
      {                  /* if ISARY, up to 4 dimen. */
        uint16 x_dimen[DIMNUM];
      } x_ary;
    } x_fcnary;
    uint16 x_tvndx;             /* tv index */
  } x_sym;

  struct
  {
    struct
    {
      struct
      {
        int x_lnno;
      } x_lnsz;
    } x_misc;
    char pad[13];
    char x_auxtype;
  } x_sym64;

  union
  {
    char x_fname[FILNMLEN];
    struct
    {
      uint32 x_zeroes;
      uint32 x_offset;
    } _x;
  } x_file;

  struct
  {
    int32  x_scnlen;            /* section length */
    uint16 x_nreloc;            /* number of relocation entries */
    uint16 x_nlinno;            /* number of line numbers */
    uint32 x_chksum;            /* checksumm for comdat's */
    uint16 x_asscnt;            /* section number to associate with */
    uchar  x_select;            /* comdat selection type */
#define SSEL_NODUPL   1 // no duplicate
#define SSEL_ANY      2 // select any
#define SSEL_SIZE     3
#define SSEL_EXACT    4 // by checksumm
#define SSEL_ASSOC    5 // associative
#define SSEL_LARGEST  6
#define SSEL_NEWEST   7
    uchar  __align__;           /* for COFF+ only */
    uint16 x_asscnt_hi;         /* for COFF+ only - hi part of x_asscnt */
  } x_scn; // always <= sizeof(SYMENT) :)

  struct
  {
    int32 x_tvfill;             /* tv fill value */
    uint16 x_tvlen;             /* length of .tv */
    uint16 x_tvran[2];          /* tv range */
  } x_tv;                       /* info about .tv section (in auxent of symbol .tv)) */

  /******************************************
   * RS/6000-specific auxent - last auxent for every external symbol
   ******************************************/
  struct
  {
    int32 x_scnlen;             /* csect length */
    int32 x_parmhash;           /* parm type hash index */
    uint16 x_snhash;            /* sect num with parm hash */
    uchar x_smtyp;              /* symbol align and type */
                                        /* 0-4 - Log 2 of alignment */
                                        /* 5-7 - symbol type */
#define SMTYP_ALIGN(x)  ((x) >> 3)      /* log2 of alignment */
#define SMTYP_SMTYP(x)  ((x) & 0x7)     /* symbol type */
/* Symbol type values:  */
#define XTY_ER  0               /* External reference */
#define XTY_SD  1               /* Csect definition */
#define XTY_LD  2               /* Label definition */
#define XTY_CM  3               /* .BSS */
#define XTY_EM  4               /* Error message */
#define XTY_US  5               /* "Reserved for internal use" */
    uchar x_smclas;             /* storage mapping class */
#define XMC_PR  0               /* Read-only program code */
#define XMC_RO  1               /* Read-only constant */
#define XMC_DB  2               /* Read-only debug dictionary table */
#define XMC_TC  3               /* Read-write general TOC entry */
#define XMC_UA  4               /* Read-write unclassified */
#define XMC_RW  5               /* Read-write data */
#define XMC_GL  6               /* Read-only global linkage */
#define XMC_XO  7               /* Read-only extended operation */
#define XMC_SV  8               /* Read-only supervisor call */
#define XMC_BS  9               /* Read-write BSS */
#define XMC_DS  10              /* Read-write descriptor csect */
#define XMC_UC  11              /* Read-write unnamed Fortran common */
#define XMC_TI  12              /* Read-only traceback index csect */
#define XMC_TB  13              /* Read-only traceback table csect */
/*              14      ??? */
#define XMC_TC0 15              /* Read-write TOC anchor */
#define XMC_TD  16              /* Read-write data in TOC */
    int32 x_stab;               /* dbx stab info index */
    uint16 x_snstab;            /* sect num with dbx stab */
  } x_csect;                    /* csect definition information */\

/* XCOFF64 _csect */
  struct
  {
    uint32 x_scnlen_lo;
    int32  x_parmhash;
    uint16 x_snhash;
    uchar  x_smtyp;
    uchar  x_smclas;
#define XMC_SV64 17
#define XMC_SV2364 18
    int32  x_scnlen_hi;
    char   pad;
    char   x_auxtype;
  } x_csect64;

  /******************************************
   *  I960-specific *2nd* aux. entry formats
   ******************************************/
  struct
  {
#define x_stdindx x_stindx      /* This is a very old typo that keeps getting propagated. */
    int32 x_stindx;             /* sys. table entry */
  } x_sc;                       /* system call entry */

  struct
  {
    uint32 x_balntry;           /* BAL entry point */
  } x_bal;                      /* BAL-callable function */

} AUXENT;

/*      Defines for "special" symbols */

#if vax
#define _ETEXT  "_etext"
#define _EDATA  "_edata"
#define _END    "_end"
#else
#define _ETEXT  "etext"
#define _EDATA  "edata"
#define _END    "end"
#endif

#define _START  "_start"

//================================================================================
//      ECOFF symbols
//================================================================================

#define estNil          0       /* Nuthin' special */
#define estGlobal       1       /* external symbol */
#define estStatic       2       /* static */
#define estParam        3       /* procedure argument */
#define estLocal        4       /* local variable */
#define estLabel        5       /* label */
#define estProc         6       /*     "      "  Procedure */
#define estBlock        7       /* beginnning of block */
#define estEnd          8       /* end (of anything) */
#define estMember       9       /* member (of anything  - struct/union/enum */
#define estTypedef      10      /* type definition */
#define estFile         11      /* file name */
#define estRegReloc     12      /* register relocation */
#define estForward      13      /* forwarding address */
#define estStaticProc   14      /* load time only static procs */
#define estConstant     15      /* const */
#define estStaParam     16      /* Fortran static parameters */
    /* These new symbol types have been recently added to SGI machines. */
#define estStruct       26      /* Beginning of block defining a struct type */
#define estUnion        27      /* Beginning of block defining a union type */
#define estEnum         28      /* Beginning of block defining an enum type */
#define estIndirect     34      /* Indirect type specification */
    /* Pseudo-symbols - internal to debugger */
#define estStr          60      /* string */
#define estNumber       61      /* pure number (ie. 4 NOR 2+2) */
#define estExpr         62      /* 2+2 vs. 4 */
#define estType         63      /* post-coersion SER */
#define estMax          64

#define escNil          0
#define escText         1       /* text symbol */
#define escData         2       /* initialized data symbol */
#define escBss          3       /* un-initialized data symbol */
#define escRegister     4       /* value of symbol is register number */
#define escAbs          5       /* value of symbol is absolute */
#define escUndefined    6       /* who knows? */
#define escCdbLocal     7       /* variable's value is IN se->va.?? */
#define escBits         8       /* this is a bit field */
#define escCdbSystem    9       /* variable's value is IN CDB's address space */
#define escDbx          9       /* overlap dbx internal use */
#define escRegImage     10      /* register value saved on stack */
#define escInfo         11      /* symbol contains debugger information */
#define escUserStruct   12      /* address in struct user for current process */
#define escSData        13      /* load time only small data */
#define escSBss         14      /* load time only small common */
#define escRData        15      /* load time only read only data */
#define escVar          16      /* Var parameter (fortran,pascal) */
#define escCommon       17      /* common variable */
#define escSCommon      18      /* small common */
#define escVarRegister  19      /* Var parameter in a register */
#define escVariant      20      /* Variant record */
#define escSUndefined   21      /* small undefined(external) data */
#define escInit         22      /* .init section symbol */
#define escBasedVar     23      /* Fortran or PL/1 ptr based var */
#define escXData        24      /* exception handling data */
#define escPData        25      /* Procedure section */
#define escFini         26      /* .fini section */
#define escRConst       27      /* .rconst section */
#define escMax          32

struct ecoff_hdr
{
  uint16 magic;
#define ECOFF_SYM_MAGIC 0x1992
  uint16 vstamp;
  uint32  ilineMax;
  uint32  idnMax;
  uint32  ipdMax;
  uint32  isymMax;
  uint32  ioptMax;
  uint32  iauxMax;
  uint32  issMax;
  uint32  issExtMax;
  uint32  ifdMax;
  uint32  crfd;
  uint32  iextMax;
  uint64 cbLine;
  uint64 cbLineOffset;
  uint64 cbDnOffset;
  uint64 cbPdOffset;
  uint64 cbSymOffset;
  uint64 cbOptOffset;
  uint64 cbAuxOffset;
  uint64 cbSsOffset;
  uint64 cbSsExtOffset;
  uint64 cbFdOffset;
  uint64 cbRfdOffset;
  uint64 cbExtOffset;
};

struct ecoff_fdr
{
  uint64 f_adr;
  uint64 f_cbLineOffset;
  uint64 f_cbLine;
  uint64 f_cbSs;
  uint32 f_rss;
  uint32 f_issBase;
  uint32 f_isymBase;
  uint32 f_csym;
  uint32 f_ilineBase;
  uint32 f_cline;
  uint32 f_ioptBase;
  uint32 f_copt;
  uint32 f_ipdFirst;
  uint32 f_cpd;
  uint32 f_iauxBase;
  uint32 f_caux;
  uint32 f_rfdBase;
  uint32 f_crfd;
  uchar f_bits1;
  uchar f_bits2[3];
  uchar f_padding[4];
};

/* Procedure descriptor external record */

struct ecoff_pdr
{
  uint64 adr;
  uint64 cbLineOffset;
  uint32 isym;
  uint32 iline;
  uint32 regmask;
  uint32 regoffset;
  uint32 iopt;
  uint32 fregmask;
  uint32 fregoffset;
  uint32 frameoffset;
  uint32 lnLow;
  uint32 lnHigh;
  uchar gp_prologue;
  uchar bits1;
  uchar bits2;
  uchar localoff;
  uint16 framereg;
  uint16 pcreg;
};

/* Line numbers */

struct ecoff_line
{
  uint32 l_line;
};

/* Symbol external record */

#define SYM_BITS1_ST_BIG                0xFC
#define SYM_BITS1_ST_SH_BIG             2
#define SYM_BITS1_ST_LITTLE             0x3F
#define SYM_BITS1_ST_SH_LITTLE          0

#define SYM_BITS1_SC_BIG                0x03
#define SYM_BITS1_SC_SH_LEFT_BIG        3
#define SYM_BITS1_SC_LITTLE             0xC0
#define SYM_BITS1_SC_SH_LITTLE          6

#define SYM_BITS2_SC_BIG                0xE0
#define SYM_BITS2_SC_SH_BIG             5
#define SYM_BITS2_SC_LITTLE             0x07
#define SYM_BITS2_SC_SH_LEFT_LITTLE     2

#define SYM_BITS2_RESERVED_BIG          0x10
#define SYM_BITS2_RESERVED_LITTLE       0x08

#define SYM_BITS2_INDEX_BIG             0x0F
#define SYM_BITS2_INDEX_SH_LEFT_BIG     16
#define SYM_BITS2_INDEX_LITTLE          0xF0
#define SYM_BITS2_INDEX_SH_LITTLE       4

#define SYM_BITS3_INDEX_SH_LEFT_BIG     8
#define SYM_BITS3_INDEX_SH_LEFT_LITTLE  4

#define SYM_BITS4_INDEX_SH_LEFT_BIG     0
#define SYM_BITS4_INDEX_SH_LEFT_LITTLE  12

struct ecoff_sym
{
  uint64 s_value;
  uint32 s_iss;
  uchar s_bits1;
  uchar s_bits2;
  uchar s_bits3;
  uchar s_bits4;
  uchar st(bool mf)
  {
    return mf
         ? ((s_bits1 & SYM_BITS1_ST_BIG   ) >> SYM_BITS1_ST_SH_BIG)
         : ((s_bits1 & SYM_BITS1_ST_LITTLE) >> SYM_BITS1_ST_SH_LITTLE);
  }
  uchar sc(bool mf)
  {
    return mf
         ? (((s_bits1 & SYM_BITS1_SC_BIG   ) << SYM_BITS1_SC_SH_LEFT_BIG)
          | ((s_bits2 & SYM_BITS2_SC_BIG   ) >> SYM_BITS2_SC_SH_BIG))
         : (((s_bits1 & SYM_BITS1_SC_LITTLE) >> SYM_BITS1_SC_SH_LITTLE)
          | ((s_bits2 & SYM_BITS2_SC_LITTLE) << SYM_BITS2_SC_SH_LEFT_LITTLE));
  }
  uint32 index(bool mf)
  {
    return mf
         ? (((s_bits2 & SYM_BITS2_INDEX_BIG) << SYM_BITS2_INDEX_SH_LEFT_BIG)
          | (s_bits3 << SYM_BITS3_INDEX_SH_LEFT_BIG)
          | (s_bits4 << SYM_BITS4_INDEX_SH_LEFT_BIG))
         : (((s_bits2 & SYM_BITS2_INDEX_LITTLE) >> SYM_BITS2_INDEX_SH_LITTLE)
          | (s_bits3 << SYM_BITS3_INDEX_SH_LEFT_LITTLE)
          | (s_bits4 << SYM_BITS4_INDEX_SH_LEFT_LITTLE));
  }
};

/* The auxiliary type information is the same on all known ECOFF
   targets.  The internal forms are
   defined in coff/sym.h, which was originally donated by MIPS
   Computer Systems.  */

/* Type information external record */

struct ecoff_tir
{
  uchar t_bits1;
  uchar t_tq45;
  uchar t_tq01;
  uchar t_tq23;
  bool fBitfield(bool mf) { return (t_bits1 & (mf ? 0x80 : 0x01)) != 0; }
  bool continued(bool mf) { return (t_bits1 & (mf ? 0x40 : 0x02)) != 0; }
  uchar bt(bool mf)   { return mf ? (t_bits1 & 0x3F) >> 0 : (t_bits1 & 0xFC) >> 2; }
  uchar tq4(bool mf)  { return mf ? (t_tq45 & 0xF0) >> 4 : (t_tq45 & 0x0F) >> 0; }
  uchar tq5(bool mf)  { return mf ? (t_tq45 & 0x0F) >> 0 : (t_tq45 & 0xF0) >> 4; }
  uchar tq0(bool mf)  { return mf ? (t_tq01 & 0xF0) >> 4 : (t_tq01 & 0x0F) >> 0; }
  uchar tq1(bool mf)  { return mf ? (t_tq01 & 0x0F) >> 0 : (t_tq01 & 0xF0) >> 4; }
  uchar tq2(bool mf)  { return mf ? (t_tq23 & 0xF0) >> 4 : (t_tq23 & 0x0F) >> 0; }
  uchar tq3(bool mf)  { return mf ? (t_tq23 & 0x0F) >> 0 : (t_tq23 & 0xF0) >> 4; }
};

/* Relative symbol external record */

struct ecoff_rndx
{
  uchar r_bits[4];
  uint16 rfd(bool mf)
  {
    return mf
         ? (r_bits[0] << 4) | ((r_bits[1] & 0xF0) >> 4)
         : (r_bits[0] << 0) | ((r_bits[1] & 0x0F) << 8);
  }
  uint32 index(bool mf)
  {
    return mf
         ? ((r_bits[1] & 0x0F) << 16)
         | (r_bits[2] << 8)
         | (r_bits[3] << 0)
         : ((r_bits[1] & 0xF0) >> 4)
         | (r_bits[2] << 4)
         | (r_bits[3] << 12);
  }
};

/* Auxiliary symbol information external record */

union ecoff_aux
{
  ecoff_tir  a_ti;
  ecoff_rndx a_rndx;
  uint32 a_dnLow;
  uint32 a_dnHigh;
  uint32 a_isym;
  uint32 a_iss;
  uint32 a_width;
  uint32 a_count;
};

/* External symbol external record */

struct ecoff_ext
{
  ecoff_sym es_asym;
  uchar es_bits1;
  uchar es_bits2[3];
  uint32 es_ifd;
};

/* Dense numbers external record */

struct ecoff_dnr
{
  uint32 d_rfd;
  uint32 d_index;
};

/* Relative file descriptor */

struct ecoff_rfd
{
  uint32 rfd;
};

/* Optimizer symbol external record */

struct ecoff_opt
{
  uchar o_bits1;
  uchar o_bits2;
  uchar o_bits3;
  uchar o_bits4;
  ecoff_rndx o_rndx;
  uint32 o_offset;
  uchar ot(void) { return o_bits1; }
  uint32 value(bool mf)
  {
    return mf
         ? ((uint32(o_bits2) << 16)
          | (uint32(o_bits3) <<  8)
          | (uint32(o_bits4) <<  0))
         : ((uint32(o_bits2) <<  0)
          | (uint32(o_bits3) <<  8)
          | (uint32(o_bits4) << 16));
  }
};

//---------------------------------------------------------------------------
//      MIPS symbolic information
//---------------------------------------------------------------------------

struct mips_ecoff_hdr
{
  uint16 magic;
#define MIPS_SYM_MAGIC 0x7002
  uint16 vstamp;
  uint32 ilineMax;
  uint32 cbLine;
  uint32 cbLineOffset;
  uint32 idnMax;
  uint32 cbDnOffset;
  uint32 ipdMax;
  uint32 cbPdOffset;
  uint32 isymMax;
  uint32 cbSymOffset;
  uint32 ioptMax;
  uint32 cbOptOffset;
  uint32 iauxMax;
  uint32 cbAuxOffset;
  uint32 issMax;
  uint32 cbSsOffset;
  uint32 issExtMax;
  uint32 cbSsExtOffset;
  uint32 ifdMax;
  uint32 cbFdOffset;
  uint32 crfd;
  uint32 cbRfdOffset;
  uint32 iextMax;
  uint32 cbExtOffset;
};

struct mips_ecoff_fdr
{
  uint32 f_adr;
  uint32 f_rss;
  uint32 f_issBase;
  uint32 f_cbSs;
  uint32 f_isymBase;
  uint32 f_csym;
  uint32 f_ilineBase;
  uint32 f_cline;
  uint32 f_ioptBase;
  uint32 f_copt;
  uint16 f_ipdFirst;
  uint16 f_cpd;
  uint32 f_iauxBase;
  uint32 f_caux;
  uint32 f_rfdBase;
  uint32 f_crfd;
  uchar f_bits1;
  uchar f_bits2[3];
  uint32 f_cbLineOffset;
  uint32 f_cbLine;
};

/* Procedure descriptor external record */

struct mips_ecoff_pdr
{
  uint32 adr;
  uint32 isym;
  uint32 iline;
  uint32 regmask;
  uint32 regoffset;
  uint32 iopt;
  uint32 fregmask;
  uint32 fregoffset;
  uint32 frameoffset;
  uint16 framereg;
  uint16 pcreg;
  uint32 lnLow;
  uint32 lnHigh;
  uint32 cbLineOffset;
};

/* Line numbers */

struct mips_ecoff_line
{
  uint32 l_line;
};

/* Symbol external record */

struct mips_ecoff_sym
{
  uint32 s_iss;
  uint32 s_value;
  uchar s_bits1;
  uchar s_bits2;
  uchar s_bits3;
  uchar s_bits4;
  uchar st(bool mf)
  {
    return mf
         ? ((s_bits1 & SYM_BITS1_ST_BIG   ) >> SYM_BITS1_ST_SH_BIG)
         : ((s_bits1 & SYM_BITS1_ST_LITTLE) >> SYM_BITS1_ST_SH_LITTLE);
  }
  uchar sc(bool mf)
  {
    return mf
         ? (((s_bits1 & SYM_BITS1_SC_BIG   ) << SYM_BITS1_SC_SH_LEFT_BIG)
          | ((s_bits2 & SYM_BITS2_SC_BIG   ) >> SYM_BITS2_SC_SH_BIG))
         : (((s_bits1 & SYM_BITS1_SC_LITTLE) >> SYM_BITS1_SC_SH_LITTLE)
          | ((s_bits2 & SYM_BITS2_SC_LITTLE) << SYM_BITS2_SC_SH_LEFT_LITTLE));
  }
  uint32 index(bool mf)
  {
    return mf
         ? (((s_bits2 & SYM_BITS2_INDEX_BIG) << SYM_BITS2_INDEX_SH_LEFT_BIG)
          | (s_bits3 << SYM_BITS3_INDEX_SH_LEFT_BIG)
          | (s_bits4 << SYM_BITS4_INDEX_SH_LEFT_BIG))
         : (((s_bits2 & SYM_BITS2_INDEX_LITTLE) >> SYM_BITS2_INDEX_SH_LITTLE)
          | (s_bits3 << SYM_BITS3_INDEX_SH_LEFT_LITTLE)
          | (s_bits4 << SYM_BITS4_INDEX_SH_LEFT_LITTLE));
  }
};

#define mips_ecoff_aux  ecoff_aux

/* External symbol external record */

struct mips_ecoff_ext
{
  uchar es_bits1;
  uchar es_bits2;
  uint16 es_ifd;
  mips_ecoff_sym es_asym;
};

#define mips_ecoff_dnr ecoff_dnr
#define mips_ecoff_rfd ecoff_rfd
#define mips_ecoff_opt ecoff_opt

/* segment information */
struct ic_seginfo_t
{
  const ida_sym_t *sym = nullptr; // comdat symbol
  ea_t start = BADADDR;           // segment start address, BADADDR - not loaded
  adiff_t delta = 0;              // difference between the loaded address
                                  // and address in the file
  ea_t paddr = 0;                 // s_paddr from the segment descriptor
};
DECLARE_TYPE_AS_MOVABLE(ic_seginfo_t);
struct ic_seginfos_t : public qvector<ic_seginfo_t> {};

//----------------------------------------------------------------------
inline bool is_arm_switcher(const char *name)
{
  return strncmp(name, "$CODE", 5) == 0
      && (name[5] == '1' || name[5] == '3')
      && (name[6] == '6' || name[6] == '2')
      && name[7] == '\0';
}

struct i960_sym_t;
struct coff_sym_ex_t;
struct ida_filhdr_t;
struct ida_scnhdr_t;

//----------------------------------------------------------------------
class ida_syms_t
{
  struct coff_vars_t &ctx;
  qstring str_table; // standard COFF string table (includes size in first 4 bytes)
  qstring dtable; // XCOFF debug table (does not include size)

  void from_coff960(const i960_sym_t    *pc, uint nsyms, bool coff_hdr_mf);
  void from_bigcoff(const coff_sym_ex_t *pc, uint nsyms, bool coff_hdr_mf);
  void from_xcoff64(const coff_sym64_t  *pc, uint nsyms, bool coff_hdr_mf);
  void from_coffsym(const coff_sym_t    *pc, uint nsyms, bool coff_hdr_mf);
public:
  qvector<ida_sym_t> symtab;

  ida_syms_t(coff_vars_t &_ctx) : ctx(_ctx) {}
  bool str_table_from_file(linput_t *li, bool coff_hdr_mf);
  bool str_table_from_mem(const void *buf, size_t bufsize, bool coff_hdr_mf);
  bool load_from_file(
        linput_t *li,
        const ida_filhdr_t &fh,
        bool coff_hdr_mf);
  bool load_from_mem(const void *symbuf, size_t bufsize, uint32 nsyms, bool coff_hdr_mf);
#if !defined(COMPILE_DBG_LOADER)
  void load_xcoff_debug_table(linput_t *li, const qvector<ida_scnhdr_t> &sechdrs);
#endif
  const ida_sym_t *load_external_coff_symbols(linput_t *li, ida_filhdr_t &hf, bool mf);

  void qclear()
  {
    str_table.qclear();
    dtable.qclear();
    symtab.qclear();
  }

  void copy_from_str_table(char *buf, size_t bufsz, uint32 off, bool use_dtable = false) const;
  const char *get_segment_name(const char *name, size_t fixlen, char *buffer, size_t bufsize, uint32 f_magic) const;
  bool getaux(uint symidx, AUXENT &aux, uint &n_aux) const;
  char *getname(uint symidx, char *buf, size_t bufsize) const;
};

#pragma pack(pop)
#endif /* _H_SYMS */
