/*
        GEOS.H
        by Marcus Groeber 1992-95
        Include file for the PC/GEOS file format

        20.06.00: Modified by Ilfak Guilfanov <ig@datarescue.com>
*/


#if !defined(_GEOS_H)
#define _GEOS_H

#pragma pack(push, 1)

#define GEOS_TOKENLEN 4
struct GEOStoken
{                                       /*** ID for file types/icons */
  char str[GEOS_TOKENLEN];              // 4 byte string
  ushort num;                           // additional id number (?)
};

struct GEOSprotocol
{                                       /*** Protocol/version number */
  ushort vers;                          // protocol
  ushort rev;                           // sub revision
};

struct GEOSrelease
{                                       /*** "Release" */
  ushort versmaj,versmin;               // "release" x.y
  ushort revmaj,revmin;                 // value "a-b" behind "release"
};

/******************************************************************************
 *               GEOS standard file header (all file types)                   *
 ******************************************************************************/
#define GEOS_LONGNAME 36                // length of filename
#define GEOS_INFO     100               // length of user file info

#define GEOS_ID 0x53CF45C7              // GEOS file identification "magic"

struct GEOSheader
{                                       /*** Standard-Dateikof */
  int32 ID;                             // GEOS id magic: C7 45 CF 53
  ushort fclass;                        // 00=applciation, 01=VM file
  ushort flags;                         // flags ??? (always seen 0000h)
  GEOSrelease release;                  // "release"
  GEOSprotocol protocol;                // protocol/version
  GEOStoken token;                      // file type/icon
  GEOStoken appl;                       // "token" of creator application
  char name[GEOS_LONGNAME];             // long filename
  char info[GEOS_INFO];                 // user file info
  char _copyright[24];                  // original files: Copyright notice
};

/******************************************************************************
 *                         GEOS program files ("geodes")                      *
 ******************************************************************************/
#define GEOS_FNAME 8                    // Length of internale filename/ext
#define GEOS_FEXT  4

struct GEOSappheader
{                                     /*** Additional geode file header */
  ushort _attr;                       // attribute (see below)
#define GA_PROCESS                      0x8000
#define GA_LIBRARY                      0x4000
#define GA_DRIVER                       0x2000
#define GA_KEEP_FILE_OPEN               0x1000
#define GA_SYSTEM                       0x0800
#define GA_MULTI_LAUNCHABLE             0x0400
#define GA_APPLICATION                  0x0200
#define GA_DRIVER_INITIALIZED           0x0100
#define GA_LIBRARY_INITIALIZED          0x0080
#define GA_GEODE_INITIALIZED            0x0040
#define GA_USES_COPROC                  0x0020
#define GA_REQUIRES_COPROC              0x0010
#define GA_HAS_GENERAL_CONSUMER_MODE    0x0008
#define GA_ENTRY_POINTS_IN_C            0x0004
  ushort _type;                       // program type (see below)
  GEOSprotocol kernelprot;            // expected kernel protocoll
  ushort resourceCount;               // number of segments
  ushort importLibraryCount;          // number of included libraries
  ushort exportEntryCount;            // number of exported locations
  ushort stacksize;                   // default stack size (or udataSize)
  ushort classptr_ofs;                // if application: segment/offset of ???
  ushort classptr_seg;
  ushort tokenres_item;               // if application: segment/item of
  ushort tokenres_seg;                //   ressource with application token
                        char _x21[2];

// GEOS2 header start here:

  ushort attr;                        // attribute
  ushort type;                        // program type: 01=application
                                      //               02=library
                                      //               03=device driver
  GEOSrelease release;                // "release"
  GEOSprotocol protocol;              // protocol/version
  ushort timestamp;                   // time stamp (SWAT uniqueness)
  char name[GEOS_FNAME],ext[GEOS_FEXT]; // internal filename/ext (blank padded)
  GEOStoken token;                    // file type/icon
                        char _x3[2];
  ushort startofs;                    // if driver: entry location
  ushort startseg;                    //              "     "
  ushort initofs;                     // if library: init location (?)
  ushort initseg;                     //               "      "
                        char _x33[2];
  ushort numexp;                      // number of exports
  ushort numlib;                      // number of included libraries
                        char _x4[2];
  ushort numseg;                      // Number of program segments
                        char _x5[6];
};

struct GEOSexplist
{                                     /*** Base type of "exported" array */
  ushort ofs;                         // Routine entry location
  ushort seg;                         //    "      "      "
};

struct GEOSliblist
{                                     /*** Base typ of library array */
  char name[GEOS_FNAME];              // library name
  ushort type;                        // library type: 2000h=driver
                                      //               4000h=library
  GEOSprotocol protocol;              // required lib protocol/version
};

typedef ushort GEOSseglen;            /*** Base type of segment size array */
typedef int32 GEOSsegpos;             /*** Base type of segment loc array */
typedef ushort GEOSsegfix;            /*** Base type of fixup tab size ary */
typedef ushort GEOSsegflags;          /*** Base type of flag array:
                                               xxxx xxxx xxxx xxxxb
                                      */

#define HF_ZERO_INIT        0x8000
#define HF_LOCK             0x4000
#define HF_NO_ERR           0x2000
#define HF_UI               0x1000
#define HF_READ_ONLY        0x0800
#define HF_OBJECT_RESOURCE  0x0400
#define HF_CODE             0x0200
#define HF_CONFORMING       0x0100
#define HF_FIXED            0x0080
#define HF_SHARABLE         0x0040
#define HF_DISCARDABLE      0x0020
#define HF_SWAPABLE         0x0010
#define HF_LMEM             0x0008
#define HF_DEBUG            0x0004
#define HF_DISCARDED        0x0002
#define HF_SWAPPED          0x0001

struct GEOSfixup
{                                     /*** Base typ of segment fixup table */
  ushort type;                        // Type of fixup:
                                      //   xxxxh
                                      //   +|||
                                      //   | |0 = 16/16 pointer to routine #
                                      //   | |1 = 16    offset to routine #
                                      //   | |2 = 16    segment of routine #
                                      //   | |3 = 16    segment
                                      //   | |4 = 16/16 pointer (seg,ofs!)
                                      //   | 0 = kernel
                                      //   | 1 = library
                                      //   | 2 = program
                                      //   xx = if library: library ord #
  ushort ofs;                         // Offset relative to segment
};


#pragma pack(pop)

#endif
