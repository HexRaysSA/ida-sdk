/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* bos420 src/bos/usr/include/ar.h                                        */
/*                                                                        */
/* Licensed Materials - Property of IBM                                   */
/*                                                                        */
/* (C) COPYRIGHT International Business Machines Corp. 1989,1995          */
/* All Rights Reserved                                                    */
/*                                                                        */
/* US Government Users Restricted Rights - Use, duplication or            */
/* disclosure restricted by GSA ADP Schedule Contract with IBM Corp.      */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */
/* @(#)25       1.8  src/bos/usr/include/ar.h, cmdar, bos420, 9613T 6/16/90 00:07:48 */
/* ar.h 5.1 - 86/12/09 - 06:03:39 */
#ifndef _H_AR
#define _H_AR
#pragma pack(push, 1)
/*
 * COMPONENT_NAME: CMDAR
 *
 * FUNCTIONS: none
 *
 * ORIGINS: 27, 3
 *
 * (C) COPYRIGHT International Business Machines Corp. 1989
 * All Rights Reserved
 * Licensed Materials - Property of IBM
 *
 * US Government Users Restricted Rights - Use, duplication or
 * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
 */

/*              AIX INDEXED ARCHIVE FORMAT
*
*       ARCHIVE File Organization:
*        _____________________________________________
*       |__________FIXED HEADER "fl_hdr"______________|
*  +--- |                                             |
*  |    |__________ARCHIVE_FILE_MEMBER_1______________|
*  +--> |                                             |
*       |       Archive Member Header "ar_hdr"        |
*  +--- |.............................................| <--+
*  |    |               Member Contents               |    |
*  |    |_____________________________________________|    |
*  |    |________ARCHIVE_FILE_MEMBER_2________________|    |
*  +--> |                                             | ---+
*       |       Archive Member Header "ar_hdr"        |
*  +--- |.............................................| <--+
*  |    |               Member Contents               |    |
*  |    |_____________________________________________|    |
*  |    |       .               .               .     |    |
*  .    |       .               .               .     |    .
*  .    |       .               .               .     |    .
*  .    |_____________________________________________|    .
*  |    |________ARCHIVE_FILE_MEMBER_n-1______________|    |
*  +--> |                                             | ---+
*       |       Archive Member Header "ar_hdr"        |
*  +--- |.............................................| <--+
*  |    |       Member Contents                       |    |
*  |    |       (Member Table, always present)        |    |
*  |    |_____________________________________________|    |
*  |    |_____________________________________________|    |
*  |    |________ARCHIVE_FILE_MEMBER_n________________|    |
*  |    |                                             |    |
*  +--> |       Archive Member Header "ar_hdr"        | ---+
*       |.............................................|
*       |       Member Contents                       |
*       |       (Global Symbol Table if present)      |
*       |_____________________________________________|
*
*/

#define AIAMAG    "<aiaff>\n"
#define AIAMAGBIG "<bigaf>\n"
#define SAIAMAG 8
#define AIAFMAG "`\n"

struct fl_hdr               /* archive fixed length header */
{
  char  fl_magic[SAIAMAG];  /* Archive magic string */
  char  fl_memoff[20];      /*Offset to member table */
  char  fl_gstoff[20];      /*Offset to global symbol table */
  char  fl_gst64off[20];    /*Offset global symbol table for 64-bit objects */
  char  fl_fstmoff[20];     /*Offset to first archive member */
  char  fl_lstmoff[20];     /*Offset to last archive member */
  char  fl_freeoff[20];     /*Offset to first mem on free list */
};

struct aix_ar_hdr                /* archive file member header - printable ascii */
{
  char ar_size[20];     /* File member size - decimal */
  char ar_nxtmem[20];   /* Next member offset-decimal */
  char ar_prvmem[20];   /* Previous member offset-dec */
  char ar_date[12];     /* File member date-decimal */
  char ar_uid[12];      /* File member userid-decimal */
  char ar_gid[12];      /* File member group id-decimal */
  char ar_mode[12];     /* File member mode-octal */
  char ar_namlen[4];    /* File member name length-dec */
#if 0
  union
  {
    char    ar_name[2];     /* variable length member name */
    char    ar_fmag[2];     /* AIAFMAG - string to end header */
  } _ar_name;               /*      and variable length name */
#endif
};

struct fl_hdr_small       /* archive fixed length header (prior to Version 4.3) */
{
  char    fl_magic[SAIAMAG];      /* Archive file magic string */
  char    fl_memoff[12];          /* Offset to member table */
  char    fl_gstoff[12];          /* Offset to global symbol table */
  char    fl_fstmoff[12];         /* Offset to first archive member */
  char    fl_lstmoff[12];         /* Offset to last archive member */
  char    fl_freeoff[12];         /* Offset to first mem on free list */
};

struct aix_ar_hdr_small             /* archive file member header - printable ascii */
{
  char    ar_size[12];    /* file member size - decimal */
  char    ar_nxtmem[12];  /* pointer to next member -  decimal */
  char    ar_prvmem[12];  /* pointer to previous member -  decimal */
  char    ar_date[12];    /* file member date - decimal */
  char    ar_uid[12];     /* file member user id - decimal */
  char    ar_gid[12];     /* file member group id - decimal */
  char    ar_mode[12];    /* file member mode - octal */
  char    ar_namlen[4];   /* file member name length - decimal */
#if 0
  union
  {
    char    ar_name[2];     /* variable length member name */
    char    ar_fmag[2];     /* AIAFMAG - string to end header */
  } _ar_name;               /*      and variable length name */
#endif
};
/*
*       Note:   'ar_namlen' contains the length of the member name which
*               may be up to 255 chars.  The character string containing
*               the name begins at '_ar_name.ar_name'.  The terminating
*               string AIAFMAG, is only cosmetic. File member contents begin
*               at the first even byte boundary past 'header position +
*               sizeof(struct ar_hdr) + ar_namlen',  and continue for
*               'ar_size' bytes.
*/

#pragma pack(pop)
#endif /* _H_AR */
