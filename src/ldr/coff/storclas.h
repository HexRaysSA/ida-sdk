#ifndef _H_STCLASS
#define _H_STCLASS

/*********************************************************************
 *
 *      COFF Extended Object File Format:
 *              storclass.h
 *      Derived from AT&T UNIX System V Release 2.0 COFF
 *
 *      Structure similar to original COFF
 *
 *********************************************************************/

/*
 *      STORAGE CLASSES
 */

/* This used to be defined as -1, but now n_sclass is unsigned.  */
#define C_EFCN          0xff    /* physical end of function     */
#define C_NULL          0
#define C_AUTO          1       /* automatic variable           */
#define C_EXT           2       /* external symbol              */
#define C_STAT          3       /* static                       */
#define C_REG           4       /* register variable            */
#define C_EXTDEF        5       /* external definition          */
#define C_LABEL         6       /* label                        */
#define C_ULABEL        7       /* undefined label              */
#define C_MOS           8       /* member of structure          */
#define C_ARG           9       /* function argument            */
#define C_STRTAG        10      /* structure tag                */
#define C_MOU           11      /* member of union              */
#define C_UNTAG         12      /* union tag                    */
#define C_TPDEF         13      /* type definition              */
#define C_USTATIC       14      /* undefined static             */
#define C_ENTAG         15      /* enumeration tag              */
#define C_MOE           16      /* member of enumeration        */
#define C_REGPARM       17      /* register parameter           */
#define C_FIELD         18      /* bit field                    */
#define C_AUTOARG       19      /* auto argument                */
#define C_LASTENT       20      /* dummy entry (end of block)   */
#define C_BLOCK         100     /* ".bb" or ".eb"               */
#define C_FCN           101     /* ".bf" or ".ef"               */
#define C_EOS           102     /* end of structure             */
#define C_FILE          103     /* file name                    */
#define C_LINE          104     /* line # reformatted as symbol table entry */
#define C_ALIAS         105     /* duplicate tag                */
#define C_HIDDEN        106     /* ext symbol in dmert public lib */

/* New storage classes for WINDOWS_NT   */
#define C_SECTION       104     /* section name */
#define C_NT_WEAK       105     /* weak external */

 /* New storage classes for 80960 */

/* C_LEAFPROC is obsolete.  Use C_LEAFEXT or C_LEAFSTAT */
#define C_LEAFPROC      108     /* Leaf procedure, "call" via BAL */

#define C_SCALL         107     /* Procedure reachable via system call */
#define C_LEAFEXT       108     /* External leaf */
#define C_LEAFSTAT      113     /* Static leaf */
#define C_OPTVAR        109     /* Optimized variable           */
#define C_DEFINE        110     /* Preprocessor #define         */
#define C_PRAGMA        111     /* Advice to compiler or linker */
#define C_SEGMENT       112     /* 80960 segment name           */

  /* Storage classes for m88k */
#define C_SHADOW        107     /* shadow symbol                */
#define C_VERSION       108     /* coff version symbol          */

 /* New storage classes for RS/6000 */
#define C_HIDEXT        107     /* Un-named external symbol */
#define C_BINCL         108     /* Marks beginning of include file */
#define C_EINCL         109     /* Marks ending of include file */
#define C_WEAKEXT       111     /* Weak external symbol */

/* Storage classes for MS Windows */

#define IMAGE_SYM_CLASS_TOKEN 107

#include <../ldr/coff/dbxstcla.h>

#endif /* _H_STCLASS */
