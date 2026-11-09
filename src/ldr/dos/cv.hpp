/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 */

#ifndef __CV_HPP
#define __CV_HPP
#pragma pack(push, 1)

//----------------------------------------------------------------------
//              Codeview debug data
//----------------------------------------------------------------------
#define CV_NB00 "NB00"  // Not supported.
#define CV_NB01 "NB01"  // Not supported.
#define CV_NB02 "NB02"  // CodeView 3
#define CV_NB03 "NB03"  // Not supported.
#define CV_NB04 "NB04"  // Not supported.
#define CV_NB05 "NB05"  // Emitted by LINK, version 5.20 and later linkers for
                        // a file before it has been packed.
#define CV_NB06 "NB06"  // Not supported.
#define CV_NB07 "NB07"  // Used for Quick C for Windows 1.0 only.
#define CV_NB08 "NB08"  // Used by Microsoft CodeView debugger, versions 4.00
                        // through 4.05, for a file after it has been packed.
                        // Microsoft CodeView, version 4.00 through 4.05 will
                        // not process a file that does not have this
                        // signature.
#define CV_NB09 "NB09"  // Used by Microsoft CodeView, version 4.10 for a file
                        // after it has been packed. Microsoft CodeView 4.10
                        // will not process a file that does not have this
                        // signature.
#define CV_NB10 "NB10"  // The signature for an executable with the debug
                        // information stored in a separate PDB file. Corresponds
                        // with the formats set forth in NB09 or NB11.
#define CV_NB11 "NB11"  // The signature for Visual C++ 5.0 debug information that
                        // has been packed and bonded to the executable. This
                        // includes all 32-bit type indices.


//----------------------------------------------------------------------
bool inline is_codeview_magic(const char *data)
{
  return strncmp(data,CV_NB02,4) == 0
      || strncmp(data,CV_NB05,4) == 0
      || strncmp(data,CV_NB08,4) == 0
      || strncmp(data,CV_NB09,4) == 0
      || strncmp(data,CV_NB11,4) == 0;
}

#define CV_SIGNATURE 0x00000001 // flags should be equal to this
#define CV_SIGNATUR2 0x00000002 // NB11: flags should be equal to this

#define sstModule      0x120
#define sstTypes       0x121
#define sstPublic      0x122
#define sstPublicSym   0x123
#define sstSymbols     0x124
#define sstAlignSym    0x125
#define sstSrcLnSeg    0x126
#define sstSrcModule   0x127
#define sstLibraries   0x128
#define sstGlobalSym   0x129
#define sstGlobalPub   0x12a
#define sstGlobalTypes 0x12b
#define sstMPC         0x12c
#define sstSegMap      0x12d
#define sstSegName     0x12e
#define sstPreComp     0x12f
//#define unused       0x130
#define sstNames       0x130  // in tds ONLY
#define sstBrowse      0x131  // in tds ONLY
#define sstOffsetMap16 0x131
#define sstOffsetMap32 0x132
#define sstFileIndex   0x133
#define sstStaticSym   0x134

struct cv_dir_header_t
{
  uint16  cbDirHeader;  // Length of directory header.
  uint16  cbDirEntry;   // Length of each directory entry.
  uint32  cDir;         // Number of directory entries.
  uint32  lfoNextDir;   // Offset from lfaBase of next directory. This field
                        // is currently unused, but is intended for use by
                        // the incremental linker to point to the next
                        // directory containing Symbol and Type OMF
                        // information from an incremental link.
                        // TDS: 0
  uint32  flags;        // Flags describing directory and subsection tables.
                        // No values have been defined for this field.
                        // TDS: 0
};

struct cv_dir_entry_t
{
  uint16 subsection;    // Subdirectory index. See the table below for a
                        // listing of the valid subsection indices.
  uint16 iMod;          // Module index. This number is 1 based and zero (0)
                        // is never a valid index. The index 0xffff is
                        // reserved for tables that are not associated
                        // with a specific module. These tables include
                        // sstLibraries, sstGlobalSym, sstGlobalPub,
                        // and sstGlobalTypes.
                        // TDS: 0-value used for sstGlobal... & sstNames
  uint32 lfo;           // Offset from the base address lfaBase.
                        // TDS: offset from start of tds
  uint32 cb;            // Number of bytes in subsection.
};

//----------------------------------------------------------------------
//
//      Type information
//
// 11           reserved
//
// 10 - 8       mode
//    0 -
//    1 - near*
//    2 - far*
//    3 - huge*
//    4 - near32*
//    5 - far32*
//    6 - near64*
//    7 - *??*
//
// 7 - 4        type
//   0 -
//   1 - int
//   2 - uint
//   3 - bool
//   4 - real
//   5 - complex
//   ...
// 0xF - CVuse
//
// 3            reserved
//
// 2 - 0        size
// if ( !type ) {
//   0 -
//   1 - ABS
//   2 - Segment
//   3 - void
//   4 - BasicCurr
//   5 - NearBasicCurr
//   6 - FarBasicCurr
//   7 - CV3x
// }
// if ( type == 6 ) {
//   0 - Bit
//   1 - PasChar
//   2 - UndefExternal
//   3 - void
//   4 - BasicCurr
//   5 - NearBasicCurr
//   6 - FarBasicCurr
//   7 - CV3x
// }
// if ( type == 7 ) {
//   0 - char
//   1 - wchar
//   2 - rint16
//   3 - ruint16
//   4 - rint32
//   5 - ruint32
//   6 - rint64
//   7 - ruint64
// }
//

// Special Types
#define CV_T_NOTYPE     0x0000 // Uncharacterized type (no type)
#define CV_T_ABS        0x0001 // Absolute symbol
#define CV_T_SEGMENT    0x0002 // Segment type
#define CV_T_VOID       0x0003 // Void
#define CV_T_PVOID      0x0103 // Near pointer to void
#define CV_T_PFVOID     0x0203 // Far pointer to void
#define CV_T_PHVOID     0x0303 // Huge pointer to void
#define CV_T_32PVOID    0x0403 // 32-bit near pointer to void
#define CV_T_32PFVOID   0x0503 // 32-bit far pointer to void
#define CV_T_CURRENCY   0x0004 // Basic 8-byte currency value
#define CV_T_NBASICSTR  0x0005 // Near Basic string
#define CV_T_FBASICSTR  0x0006 // Far Basic string
#define CV_T_NOTTRANS   0x0007 // Untranslated type record from Microsoft symbol format
#define CV_T_BIT        0x0060 // Bit
#define CV_T_PASCHAR    0x0061 // Pascal CHAR
// Character Types
#define CV_T_CHAR       0x0010 // 8-bit signed
#define CV_T_UCHAR      0x0020 // 8-bit unsigned
#define CV_T_PCHAR      0x0110 // Near pointer to 8-bit signed
#define CV_T_PUCHAR     0x0120 // Near pointer to 8-bit unsigned
#define CV_T_PFCHAR     0x0210 // Far pointer to 8-bit signed
#define CV_T_PFUCHAR    0x0220 // Far pointer to 8-bit unsigned
#define CV_T_PHCHAR     0x0310 // Huge pointer to 8-bit signed
#define CV_T_PHUCHAR    0x0320 // Huge pointer to 8-bit unsigned
#define CV_T_32PCHAR    0x0410 // 16:32 near pointer to 8-bit signed
#define CV_T_32PUCHAR   0x0420 // 16:32 near pointer to 8-bit unsigned
#define CV_T_32PFCHAR   0x0510 // 16:32 far pointer to 8-bit signed
#define CV_T_32PFUCHAR  0x0520 // 16:32 far pointer to 8-bit unsigned
// Real Character Types
#define CV_T_RCHAR      0x0070 // Real char
#define CV_T_PRCHAR     0x0170 // Near pointer to a real char
#define CV_T_PFRCHAR    0x0270 // Far pointer to a real char
#define CV_T_PHRCHAR    0x0370 // Huge pointer to a real char
#define CV_T_32PRCHAR   0x0470 // 16:32 near pointer to a real char
#define CV_T_32PFRCHAR  0x0570 // 16:32 far pointer to a real char
// Wide Character Types
#define CV_T_WCHAR      0x0071 // Wide char
#define CV_T_PWCHAR     0x0171 // Near pointer to a wide char
#define CV_T_PFWCHAR    0x0271 // Far pointer to a wide char
#define CV_T_PHWCHAR    0x0371 // Huge pointer to a wide char
#define CV_T_32PWCHAR   0x0471 // 16:32 near pointer to a wide char
#define CV_T_32PFWCHAR  0x0571 // 16:32 far pointer to a wide char
// Real 16-bit Integer Types
#define CV_T_INT2       0x0072 // Real 16-bit signed int
#define CV_T_UINT2      0x0073 // Real 16-bit unsigned int
#define CV_T_PINT2      0x0172 // Near pointer to 16-bit signed int
#define CV_T_PUINT2     0x0173 // Near pointer to 16-bit unsigned int
#define CV_T_PFINT2     0x0272 // Far pointer to 16-bit signed int
#define CV_T_PFUINT2    0x0273 // Far pointer to 16-bit unsigned int
#define CV_T_PHINT2     0x0372 // Huge pointer to 16-bit signed int
#define CV_T_PHUINT2    0x0373 // Huge pointer to 16-bit unsigned int
#define CV_T_32PINT2    0x0472 // 16:32 near pointer to 16-bit signed int
#define CV_T_32PUINT2   0x0473 // 16:32 near pointer to 16-bit unsigned int
#define CV_T_32PFINT2   0x0572 // 16:32 far pointer to 16-bit signed int
#define CV_T_32PFUINT2  0x0573 // 16:32 far pointer to 16-bit unsigned int
// 16-bit Short Types
#define CV_T_SHORT      0x0011 // 16-bit signed
#define CV_T_USHORT     0x0021 // 16-bit unsigned
#define CV_T_PSHORT     0x0111 // Near pointer to 16-bit signed
#define CV_T_PUSHORT    0x0121 // Near pointer to 16-bit unsigned
#define CV_T_PFSHORT    0x0211 // Far pointer to 16-bit signed
#define CV_T_PFUSHORT   0x0221 // Far pointer to 16-bit unsigned
#define CV_T_PHSHORT    0x0311 // Huge pointer to 16-bit signed
#define CV_T_PHUSHORT   0x0321 // Huge pointer to 16-bit unsigned
#define CV_T_32PSHORT   0x0411 // 16:32 near pointer to 16-bit signed
#define CV_T_32PUSHORT  0x0421 // 16:32 near pointer to 16-bit unsigned
#define CV_T_32PFSHORT  0x0511 // 16:32 far pointer to 16-bit signed
#define CV_T_32PFUSHORT 0x0521 // 16:32 far pointer to 16-bit unsigned
// Real 32-bit Integer Types
#define CV_T_INT4       0x0074 // Real 32-bit signed int
#define CV_T_UINT4      0x0075 // Real 32-bit unsigned int
#define CV_T_PINT4      0x0174 // Near pointer to 32-bit signed int
#define CV_T_PUINT4     0x0175 // Near pointer to 32-bit unsigned int
#define CV_T_PFINT4     0x0274 // Far pointer to 32-bit signed int
#define CV_T_PFUINT4    0x0275 // Far pointer to 32-bit unsigned int
#define CV_T_PHINT4     0x0374 // Huge pointer to 32-bit signed int
#define CV_T_PHUINT4    0x0375 // Huge pointer to 32-bit unsigned int
#define CV_T_32PINT4    0x0474 // 16:32 near pointer to 32-bit signed int
#define CV_T_32PUINT4   0x0475 // 16:32 near pointer to 32-bit unsigned int
#define CV_T_32PFINT4   0x0574 // 16:32 far pointer to 32-bit signed int
#define CV_T_32PFUINT4  0x0575 // 16:32 far pointer to 32-bit unsigned int
// 32-bit Long Types
#define CV_T_LONG       0x0012 // 32-bit signed
#define CV_T_ULONG      0x0022 // 32-bit unsigned
#define CV_T_PLONG      0x0112 // Near pointer to 32-bit signed
#define CV_T_PULONG     0x0122 // Near pointer to 32-bit unsigned
#define CV_T_PFLONG     0x0212 // Far pointer to 32-bit signed
#define CV_T_PFULONG    0x0222 // Far pointer to 32-bit unsigned
#define CV_T_PHLONG     0x0312 // Huge pointer to 32-bit signed
#define CV_T_PHULONG    0x0322 // Huge pointer to 32-bit unsigned
#define CV_T_32PLONG    0x0412 // 16:32 near pointer to 32-bit signed
#define CV_T_32PULONG   0x0422 // 16:32 near pointer to 32-bit unsigned
#define CV_T_32PFLONG   0x0512 // 16:32 far pointer to 32-bit signed
#define CV_T_32PFULONG  0x0522 // 16:32 far pointer to 32-bit unsigned
// Real 64-bit int Types
#define CV_T_INT8       0x0076 // 64-bit signed int
#define CV_T_UINT8      0x0077 // 64-bit unsigned int
#define CV_T_PINT8      0x0176 // Near pointer to 64-bit signed int
#define CV_T_PUINT8     0x0177 // Near pointer to 64-bit unsigned int
#define CV_T_PFINT8     0x0276 // Far pointer to 64-bit signed int
#define CV_T_PFUINT8    0x0277 // Far pointer to 64-bit unsigned int
#define CV_T_PHINT8     0x0376 // Huge pointer to 64-bit signed int
#define CV_T_PHUINT8    0x0377 // Huge pointer to 64-bit unsigned int
#define CV_T_32PINT8    0x0476 // 16:32 near pointer to 64-bit signed int
#define CV_T_32PUINT8   0x0477 // 16:32 near pointer to 64-bit unsigned int
#define CV_T_32PFINT8   0x0576 // 16:32 far pointer to 64-bit signed int
#define CV_T_32PFUINT8  0x0577 // 16:32 far pointer to 64-bit unsigned int
// 64-bit Integral Types
#define CV_T_QUAD       0x0013 // 64-bit signed
#define CV_T_UQUAD      0x0023 // 64-bit unsigned
#define CV_T_PQUAD      0x0113 // Near pointer to 64-bit signed
#define CV_T_PUQUAD     0x0123 // Near pointer to 64-bit unsigned
#define CV_T_PFQUAD     0x0213 // Far pointer to 64-bit signed
#define CV_T_PFUQUAD    0x0223 // Far pointer to 64-bit unsigned
#define CV_T_PHQUAD     0x0313 // Huge pointer to 64-bit signed
#define CV_T_PHUQUAD    0x0323 // Huge pointer to 64-bit unsigned
#define CV_T_32PQUAD    0x0413 // 16:32 near pointer to 64-bit signed
#define CV_T_32PUQUAD   0x0423 // 16:32 near pointer to 64-bit unsigned
#define CV_T_32PFQUAD   0x0513 // 16:32 far pointer to 64-bit signed
#define CV_T_32PFUQUAD  0x0523 // 16:32 far pointer to 64-bit unsigned
// 32-bit Real Types
#define CV_T_REAL32     0x0040 // 32-bit real
#define CV_T_PREAL32    0x0140 // Near pointer to 32-bit real
#define CV_T_PFREAL32   0x0240 // Far pointer to 32-bit real
#define CV_T_PHREAL32   0x0340 // Huge pointer to 32-bit real
#define CV_T_32PREAL32  0x0440 // 16:32 near pointer to 32-bit real
#define CV_T_32PFREAL32 0x0540 // 16:32 far pointer to 32-bit real
// 48-bit Real Types
#define CV_T_REAL48     0x0044 // 48-bit real
#define CV_T_PREAL48    0x0144 // Near pointer to 48-bit real
#define CV_T_PFREAL48   0x0244 // Far pointer to 48-bit real
#define CV_T_PHREAL48   0x0344 // Huge pointer to 48-bit real
#define CV_T_32PREAL48  0x0444 // 16:32 near pointer to 48-bit real
#define CV_T_32PFREAL48 0x0544 // 16:32 far pointer to 48-bit real
// 64-bit Real Types
#define CV_T_REAL64     0x0041 // 64-bit real
#define CV_T_PREAL64    0x0141 // Near pointer to 64-bit real
#define CV_T_PFREAL64   0x0241 // Far pointer to 64-bit real
#define CV_T_PHREAL64   0x0341 // Huge pointer to 64-bit real
#define CV_T_32PREAL64  0x0441 // 16:32 near pointer to 64-bit real
#define CV_T_32PFREAL64 0x0541 // 16:32 far pointer to 64-bit real
// 80-bit Real Types
#define CV_T_REAL80     0x0042 // 80-bit real
#define CV_T_PREAL80    0x0142 // Near pointer to 80-bit real
#define CV_T_PFREAL80   0x0242 // Far pointer to 80-bit real
#define CV_T_PHREAL80   0x0342 // Huge pointer to 80-bit real
#define CV_T_32PREAL80  0x0442 // 16:32 near pointer to 80-bit real
#define CV_T_32PFREAL80 0x0542 // 16:32 far pointer to 80-bit real
// 128-bit Real Types
#define CV_T_REAL128    0x0043 // 128-bit real
#define CV_T_PREAL128   0x0143 // Near pointer to 128-bit real
#define CV_T_PFREAL128  0x0243 // Far pointer to 128-bit real
#define CV_T_PHREAL128  0x0343 // Huge pointer to 128-bit real
#define CV_T_32PREAL128 0x0443 // 16:32 near pointer to 128-bit real
#define CV_T_32PFREAL128 0x0543 // 16:32 far pointer to 128-bit real
// 32-bit Complex Types
#define CV_T_CPLX32     0x0050 // 32-bit complex
#define CV_T_PCPLX32    0x0150 // Near pointer to 32-bit complex
#define CV_T_PFCPLX32   0x0250 // Far pointer to 32-bit complex
#define CV_T_PHCPLX32   0x0350 // Huge pointer to 32-bit complex
#define CV_T_32PCPLX32  0x0450 // 16:32 near pointer to 32-bit complex
#define CV_T_32PFCPLX32 0x0550 // 16:32 far pointer to 32-bit complex
// 64-bit Complex Types
#define CV_T_CPLX64     0x0051 // 64-bit complex
#define CV_T_PCPLX64    0x0151 // Near pointer to 64-bit complex
#define CV_T_PFCPLX64   0x0251 // Far pointer to 64-bit complex
#define CV_T_PHCPLX64   0x0351 // Huge pointer to 64-bit complex
#define CV_T_32PCPLX64  0x0451 // 16:32 near pointer to 64-bit complex
#define CV_T_32PFCPLX64 0x0551 // 16:32 far pointer to 64-bit complex
// 80-bit Complex Types
#define CV_T_CPLX80     0x0052 // 80-bit complex
#define CV_T_PCPLX80    0x0152 // Near pointer to 80-bit complex
#define CV_T_PFCPLX80   0x0252 // Far pointer to 80-bit complex
#define CV_T_PHCPLX80   0x0352 // Huge pointer to 80-bit complex
#define CV_T_32PCPLX80  0x0452 // 16:32 near pointer to 80-bit complex
#define CV_T_32PFCPLX80 0x0552 // 16:32 far pointer to 80-bit complex
// 128-bit Complex Types
#define CV_T_CPLX128    0x0053 // 128-bit complex
#define CV_T_PCPLX128   0x0153 // Near pointer to 128-bit complex
#define CV_T_PFCPLX128  0x0253 // Far pointer to 128-bit complex
#define CV_T_PHCPLX128  0x0353 // Huge pointer to 128-bit real
#define CV_T_32PCPLX128 0x0453 // 16:32 near pointer to 128-bit complex
#define CV_T_32PFCPLX128 0x0553 // 16:32 far pointer to 128-bit complex
// Boolean Types
#define CV_T_BOOL08     0x0030 // 8-bit Boolean
#define CV_T_BOOL16     0x0031 // 16-bit Boolean
#define CV_T_BOOL32     0x0032 // 32-bit Boolean
#define CV_T_BOOL64     0x0033 // 64-bit Boolean
#define CV_T_PBOOL08    0x0130 // Near pointer to 8-bit Boolean
#define CV_T_PBOOL16    0x0131 // Near pointer to 16-bit Boolean
#define CV_T_PBOOL32    0x0132 // Near pointer to 32-bit Boolean
#define CV_T_PBOOL64    0x0133 // Near pointer to 64-bit Boolean
#define CV_T_PFBOOL08   0x0230 // Far pointer to 8-bit Boolean
#define CV_T_PFBOOL16   0x0231 // Far pointer to 16-bit Boolean
#define CV_T_PFBOOL32   0x0232 // Far pointer to 32-bit Boolean
#define CV_T_PFBOOL64   0x0233 // Far pointer to 64-bit Boolean
#define CV_T_PHBOOL08   0x0330 // Huge pointer to 8-bit Boolean
#define CV_T_PHBOOL16   0x0331 // Huge pointer to 16-bit Boolean
#define CV_T_PHBOOL32   0x0332 // Huge pointer to 32-bit Boolean
#define CV_T_PHBOOL64   0x0333 // Huge pointer to 64-bit Boolean
#define CV_T_32PBOOL08  0x0430 // 16:32 near pointer to 8-bit Boolean
#define CV_T_32PBOOL16  0x0431 // 16:32 near pointer to 16-bit Boolean
#define CV_T_32PBOOL32  0x0432 // 16:32 near pointer to 32-bit Boolean
#define CV_T_32PBOOL64  0x0433 // 16:32 near pointer to 64-bit Boolean
#define CV_T_32PFBOOL08 0x0530 // 16:32 far pointer to 8-bit Boolean
#define CV_T_32PFBOOL16 0x0531 // 16:32 far pointer to 16-bit Boolean
#define CV_T_32PFBOOL32 0x0532 // 16:32 far pointer to 32-bit Boolean
#define CV_T_32PFBOOL64 0x0533 // 16:32 far pointer to 64-bit Boolean


//----------------------------------------------------------------------
#define CV_FIRST_NONPRIM  0x1000

//----------------------------------------------------------------------
// Leaf indices for type records that can be referenced from symbols
// are the following:

#define LF_MODIFIER     0x0001
#define LF_POINTER      0x0002
#define LF_ARRAY        0x0003
#define LF_CLASS        0x0004
#define LF_STRUCTURE    0x0005
#define LF_UNION        0x0006
#define LF_ENUM         0x0007
#define LF_PROCEDURE    0x0008
#define LF_MFUNCTION    0x0009
#define LF_VTSHAPE      0x000A
#define LF_COBOL0       0x000B
#define LF_COBOL1       0x000C
#define LF_BARRAY       0x000D
#define LF_LABEL        0x000E
#define LF_NULL         0x000F      // LF_OEM
#define LF_NOTTRAN      0x0010
#define LF_DIMARRAY     0x0011
#define LF_VFTPATH      0x0012
#define LF_PRECOMP      0x0013
#define LF_ENDPRECOMP   0x0014
#define LF_OEM          0x0015      // LF_OEM2
#define LF_Reserved     0x0016

// Borland specific
#define BLF_SET          0x030
#define BLF_SUBRANGE     0x031
#define BLF_PARRAY       0x032
#define BLF_PSTRING      0x033
#define BLF_CLOSURE      0x034
#define BLF_PROPERTY     0x035
#define BLF_LSTRING      0x036
#define BLF_VARIANT      0x037
#define BLF_CLASSREF     0x038
#define BLF_WIDESTRING   0x039

#define BLF_UNRESEXT    0x00EF

// Leaf indices for type records that can be referenced from other type
// records are the following:

#define LF_SKIP         0x0200
#define LF_ARGLIST      0x0201
#define LF_DEFARG       0x0202
#define LF_LIST         0x0203
#define LF_FIELDLIST    0x0204
#define LF_DERIVED      0x0205
#define LF_BITFIELD     0x0206
#define LF_METHODLIST   0x0207
#define LF_DIMCONU      0x0208
#define LF_DIMCONLU     0x0209
#define LF_DIMVARU      0x020A
#define LF_DIMVARLU     0x020B
#define LF_REFSYM       0x020C

// Leaf indices for fields of complex lists are the following:

#define LF_BCLASS       0x0400
#define LF_VBCLASS      0x0401
#define LF_IVBCLASS     0x0402
#define LF_ENUMERATE    0x0403
#define LF_FRIENDFCN    0x0404
#define LF_INDEX        0x0405
#define LF_MEMBER       0x0406
#define LF_STMEMBER     0x0407
#define LF_METHOD       0x0408
#define LF_NESTTYPE     0x0409
#define LF_VFUNCTAB     0x040A
#define LF_FRIENDCLS    0x040B
#define LF_ONEMETHOD    0x040C
#define LF_VFUNCOFF     0x040D

// Leaf indices for numeric fields of symbols and type records
// are the following:

#define LF_NUMERIC      0x8000
#define LF_CHAR         0x8000
#define LF_SHORT        0x8001
#define LF_USHORT       0x8002
#define LF_LONG         0x8003
#define LF_ULONG        0x8004
#define LF_REAL32       0x8005
#define LF_REAL64       0x8006
#define LF_REAL80       0x8007
#define LF_REAL128      0x8008
#define LF_QUADWORD     0x8009
#define LF_UQUADWORD    0x800A
#define LF_REAL48       0x800B
#define LF_COMPLEX32    0x800C
#define LF_COMPLEX64    0x800D
#define LF_COMPLEX80    0x800E
#define LF_COMPLEX128   0x800F
#define LF_VARSTRING    0x8010          // ushort len followed by char[len]
#define LF_PAD0         0xF0
#define LF_PAD1         0xF1
#define LF_PAD2         0xF2
#define LF_PAD3         0xF3
#define LF_PAD4         0xF4
#define LF_PAD5         0xF5
#define LF_PAD6         0xF6
#define LF_PAD7         0xF7
#define LF_PAD8         0xF8
#define LF_PAD9         0xF9
#define LF_PAD10        0xFA
#define LF_PAD11        0xFB
#define LF_PAD12        0xFC
#define LF_PAD13        0xFD
#define LF_PAD14        0xFE
#define LF_PAD15        0xFF

// new leaf types for NB11

#define NLF_MODIFIER     0x1001
#define NLF_POINTER      0x1002
#define NLF_ARRAY        0x1003
#define NLF_CLASS        0x1004
#define NLF_STRUCTURE    0x1005
#define NLF_UNION        0x1006
#define NLF_ENUM         0x1007
#define NLF_PROCEDURE    0x1008
#define NLF_MFUNCTION    0x1009
#define NLF_VTSHAPE      0x000a
#define NLF_COBOL0       0x100a
#define NLF_COBOL1       0x000c
#define NLF_BARRAY       0x100b
#define NLF_DIMARRAY     0x100c
#define NLF_VFTPATH      0x100d
#define NLF_PRECOMP      0x100e
#define NLF_OEM          0x100f
#define NLF_ALIAS        0x1010     // MLF_extender
#define NLF_OEM2         0x1011     // MLF_extender
#define NLF_TYPESERVER   0x0016
#define NLF_SKIP         0x1200
#define NLF_ARGLIST      0x1201
#define NLF_DEFARG       0x1202
#define NLF_FIELDLIST    0x1203
#define NLF_DERIVED      0x1204
#define NLF_BITFIELD     0x1205
#define NLF_METHODLIST   0x1206
#define NLF_DIMCONU      0x1207
#define NLF_DIMCONLU     0x1208
#define NLF_DIMVARU      0x1209
#define NLF_DIMVARLU     0x120a
#define NLF_BCLASS       0x1400
#define NLF_VBCLASS      0x1401
#define NLF_IVBCLASS     0x1402
#define NLF_FRIENDFCN    0x1403
#define NLF_INDEX        0x1404
#define NLF_MEMBER       0x1405
#define NLF_STMEMBER     0x1406
#define NLF_METHOD       0x1407
#define NLF_NESTTYPE     0x1408
#define NLF_VFUNCTAB     0x1409
#define NLF_FRIENDCLS    0x140a
#define NLF_ONEMETHOD    0x140b
#define NLF_VFUNCOFF     0x140c
#define NLF_NESTTYPEEX   0x140d
#define NLF_MEMBERMODIFY 0x140e
#define NLF_MANAGED      0x140f       // MLF_extender

// new leaf types for vc7
#define MLF_TYPESERVER   0x1501
#define MLF_ENUMERATE    0x1502
#define MLF_ARRAY        0x1503
#define MLF_CLASS        0x1504
#define MLF_STRUCTURE    0x1505
#define MLF_UNION        0x1506
#define MLF_ENUM         0x1507
#define MLF_DIMARRAY     0x1508
#define MLF_PRECOMP      0x1509
#define MLF_ALIAS        0x150a
#define MLF_DEFARG       0x150b
#define MLF_FRIENDFCN    0x150c
#define MLF_MEMBER       0x150d
#define MLF_STMEMBER     0x150e
#define MLF_METHOD       0x150f
#define MLF_NESTTYPE     0x1510
#define MLF_ONEMETHOD    0x1511
#define MLF_NESTTYPEEX   0x1512   // unus?
#define MLF_MEMBERMODIFY 0x1513   // unus?
#define MLF_MANAGED      0x1514
#define MLF_TYPESERVER2  0x1515


// Member Attribute Field
// Several of the type records below reference a field attribute bit field.
// This bit field has the following format:
struct member_attr_t
{
  unsigned access:2;    // Specifies the access protection of the item
                // 0 No access protection
                // 1 Private
                // 2 Protected
                // 3 Public
  unsigned mprop :3;    // Specifies the properties for methods
                // 0 Vanilla method
                // 1 Virtual method
                // 2 Static method
                // 3 Friend method
                // 4 Introducing virtual method
                // 5 Pure virtual method
                // 6 Pure introducing virtual method
                // 7 Reserved
  unsigned pseudo :1;   // True if the method is never instantiated by the compiler
  unsigned noinherit:1; // True if the class cannot be inherited
  unsigned noconstruct:1;// True if the class cannot be constructed
  unsigned reserved :8;
};

//----------------------------------------------------------------------
struct leaf_t
{
  ushort type;
  void *value;
  void print(void);
  void print(char *buf, size_t bufsize);
  bool get_value(idc_value_t *v);
};

//----------------------------------------------------------------------
// LF_POINTER bits:

inline unsigned get_ptrtype(ushort attr) { return (attr >> 0) & 0x1F; }
#define PTRTYPE_NEAR    0  // Near
#define PTRTYPE_FAR     1  // Far
#define PTRTYPE_HUGE    2  // Huge
#define PTRTYPE_SEG     3  // Based on segment
#define PTRTYPE_VAL     4  // Based on value
#define PTRTYPE_VALSEG  5  // Based on segment of value
#define PTRTYPE_SYM     6  // Based on address of symbol
#define PTRTYPE_SYMSEG  7  // Based on segment of symbol address
#define PTRTYPE_TYPE    8  // Based on type
#define PTRTYPE_SELF    9  // Based on self
#define PTRTYPE_NEAR32  10 // Near 32-bit pointer
#define PTRTYPE_FAR32   11 // Far 32-bit pointer

inline unsigned get_ptrmode(ushort attr) { return (attr >> 5) & 0x07; }
#define PTRMODE_PTR  0  // Pointer
#define PTRMODE_REF  1  // Reference
#define PTRMODE_MEM  2  // Pointer to data member
#define PTRMODE_MET  3  // Pointer to method

#define LFTP_ISFLAT     0x0010  // True if 16:32 pointer
#define LFTP_VOLATILE   0x0020  // True if pointer is volatile
#define LFTP_CONST      0x0040  // True if pointer is const
#define LFTP_UNALIGNED  0x0080  // True if pointer is unaligned

//----------------------------------------------------------------------
// Class/structure type property bits
#define LF_CLS_PACKED   0x0001  // Structure is packed
#define LF_CLS_CTOR     0x0002  // Class has constructors and/or destructors
#define LF_CLS_OVEROPS  0x0004  // Class has overloaded operators
#define LF_CLS_ISNESTED 0x0008  // Class is a nested class
#define LF_CLS_CNESTED  0x0010  // Class contains nested classes
#define LF_CLS_OPASSIGN 0x0020  // Class has overloaded assignment
#define LF_CLS_OPCAST   0x0040  // Class has casting methods
#define LF_CLS_FWDREF   0x0080  // Class/structure is a forward (incomplete) reference
#define LF_CLS_SCOPED   0x0100  // This is a scoped definition

//----------------------------------------------------------------------
// LF_MODIFIER atribute bits
#define LFTM_CONST     0x0001
#define LFTM_VOLATILE  0x0002
#define LFTM_UNALIGNED 0x0004

//----------------------------------------------------------------------
// Symbol record types
#define S_COMPILE       0x0001 // Compile flags symbol
#define S_REGISTER      0x0002 // Register variable
#define S_CONSTANT      0x0003 // Constant symbol
#define S_UDT           0x0004 // User-defined Type
#define S_SSEARCH       0x0005 // Start search
#define S_END           0x0006 // End block, procedure, with, or thunk
#define S_SKIP          0x0007 // Skip - Reserve symbol space
#define S_CVRESERVE     0x0008 // Reserved for internal use by the Microsoft debugger
#define S_OBJNAME       0x0009 // Specify name of object file
#define S_ENDARG        0x000a // Specify end of arguments in function symbols
#define S_COBOLUDT      0x000b // Microfocus COBOL user-defined type
#define S_MANYREG       0x000c // Many register symbol
#define S_RETURN        0x000d // Function return description
#define S_ENTRYTHIS     0x000e // Description of this pointer at entry

// Borland specific
#define BS_GPROCREF     0x0020  // global procedure forward reference
#define BS_GDATAREF     0x0021  // global data -"-
#define BS_EDATA        0x0022  // OBJ only - force GDATAREF creation
#define BS_EPROC        0x0023  // OBJ - mangled name for tasm-pass
#define BS_USES         0x0024  // refernce to module
#define BS_NAMESPACE    0x0025
#define BS_USING        0x0026
#define BS_PCONSTANT    0x0027

#define S_BPREL16       0x0100 // BP relative 16:16
#define S_LDATA16       0x0101 // Local data 16:16
#define S_GDATA16       0x0102 // Global data 16:16
#define S_PUB16         0x0103 // Public symbol 16:16
#define S_LPROC16       0x0104 // Local procedure start 16:16
#define S_GPROC16       0x0105 // Global procedure start 16:16
#define S_THUNK16       0x0106 // Thunk start 16:16
#define S_BLOCK16       0x0107 // Block start 16:16
#define S_WITH16        0x0108 // With start 16:16
#define S_LABEL16       0x0109 // Code label 16:16
#define S_CEXMODEL16    0x010a // Change execution model 16:16
#define S_VFTPATH16     0x010b // Virtual function table path descriptor 16:16
#define S_REGREL16      0x010c // Specify 16:16 offset relative to arbitrary register

// Borland specific
#define BS_ENTRY16      0x0110
#define BS_OPTVAR16     0x0111  // variable line rangle for REGISTER/BPREL
#define BS_PROCRET16    0x0112  // epilogue indicator
#define BS_SAVEREGS16   0x0113

#define S_BPREL32       0x0200 // BP relative 16:32
#define S_LDATA32       0x0201 // Local data 16:32
#define S_GDATA32       0x0202 // Global data 16:32
#define S_PUB32         0x0203 // Public symbol 16:32
#define S_LPROC32       0x0204 // Local procedure start 16:32
#define S_GPROC32       0x0205 // Global procedure start 16:32
#define S_THUNK32       0x0206 // Thunk start 16:32
#define S_BLOCK32       0x0207 // Block start 16:32
#define S_WITH32        0x0208 // With start 16:32
#define S_LABEL32       0x0209 // Code label 16:32
#define S_CEXMODEL32    0x020a // Change execution model 16:32
#define S_VFTPATH32     0x020b // Virtual function table path descriptor 16:32
#define S_REGREL32      0x020c // 16:32 offset relative to arbitrary register
#define S_LTHREAD32     0x020d // Local Thread Storage data
#define S_GTHREAD32     0x020e // Global Thread Storage data

#define S_SLINK32       0x020f        // MS_extender

// Borland specific
#define BS_ENTRY32      0x0210
#define BS_OPTVAR32     0x0211
#define BS_PROCRET32    0x0212
#define BS_SAVEREGS32   0x0213
#define BS_SLINK        0x0230

#define S_LPROCMIPS     0x0300 // Local procedure start MIPS
#define S_GPROCMIPS     0x0301 // Global procedure start MIPS

#define S_PROCREF       0x0400 // Reference to a procedure
#define S_DATAREF       0x0401 // Reference to data
#define S_ALIGN         0x0402 // Page align symbols

// new symbol types from NB11:

#define NS_REGISTER     0x1001 // Register variable
#define NS_CONSTANT     0x1002 // Constant symbol
#define NS_UDT          0x1003 // User-defined type
#define NS_COBOLUDT     0x1004 // Microfocus COBOL user-defined type
#define NS_MANYREG      0x1005 // Many register symbol
#define NS_BPREL32      0x1006 // BP relative 16:32
#define NS_LDATA32      0x1007 // Local data 16:32
#define NS_GDATA32      0x1008 // Global data 16:32
#define NS_PUB32        0x1009 // Public symbol 16:32
#define NS_LPROC32      0x100a // Local procedure start 16:32
#define NS_GPROC32      0x100b // Global procedure start 16:32
#define NS_VFTTABLE32   0x100c // Virtual function table path descriptor 16:32
#define NS_REGREL32     0x100d // 16:32 offset relative to arbitrary register
#define NS_LTHREAD32    0x100e // Local Thread Storage data
#define NS_GTHREAD32    0x100f // Global Thread Storage data
#define NS_LPROCMIPS    0x1010 // Local procedure start MIPS
#define NS_GPROCMIPS    0x1011 // Global procedure start MIPS

// Undocumented symbols:

#define NS_FRAMEPROC    0x1012          // MS_extender
#define NS_COMPILE2     0x1013 // start - as S_COMPILE, then ms-flags
#define NS_MANYREG2     0x1014          // MS_extender
#define NS_LPROCIA64    0x1015          // MS_extender
#define NS_LOCALSLOT    0x1017          // MS_extender
#define NS_PARAMSLOT    0x1018          // MS_extender
#define NS_ANNOTATION   0x1019          // MS_extender
#define NS_GMANPROC     0x101a          // MS_extender
#define NS_LMANPROC     0x101b          // MS_extender
#define NS_RESERVED1    0x101c          // MS_extender
#define NS_RESERVED2    0x101d          // MS_extender
#define NS_RESERVED3    0x101e          // MS_extender
#define NS_RESERVED4    0x101f          // MS_extender
#define NS_LMANDATA     0x1020          // MS_extender
#define NS_GMANDATA     0x1021          // MS_extender
#define NS_MANFRAMEREL  0x1022          // MS_extender
#define NS_MANREGISTER  0x1023          // MS_extender
#define NS_MANSLOT      0x1024          // MS_extender
#define NS_MANMANYREG   0x1025          // MS_extender
#define NS_MANREGREL    0x1026          // MS_extender
#define NS_MANMANYREG2  0x1027          // MS_extender
#define NS_MANTYPEREF   0x1028          // MS_extender
#define NS_UNAMESPACE   0x1029          // MS_extender

// new symbol types from vc7
#define MS_OBJNAME      0x1101 // Specify name of object file
#define MS_THUNK32      0x1102 // Thunk start 16:32
#define MS_BLOCK32      0x1103 // Block start 16:32
#define MS_WITH32       0x1104 // With start 16:32
#define MS_LABEL32      0x1105 // Code label 16:32
#define MS_REGISTER     0x1106 // Register variable
#define MS_CONSTANT     0x1107 // Constant symbol
#define MS_UDT          0x1108  // User-defined type
#define MS_COBOLUDT     0x1109  // Microfocus COBOL user-defined type
#define MS_MANYREG      0x110a  // Many register symbol
#define MS_BPREL32      0x110b  // BP relative 16:32
#define MS_LDATA32      0x110c  // Local data 16:32
#define MS_GDATA32      0x110d  // Global data 16:32
#define MS_PUB32        0x110e  // Public symbol 16:32
#define MS_LPROC32      0x110f  // Local procedure start 16:32
#define MS_GPROC32      0x1110  // Global procedure start 16:32
#define MS_REGREL32     0x1111  // 16:32 offset relative to arbitrary register
#define MS_LTHREAD32    0x1112  // Local Thread Storage data
#define MS_GTHREAD32    0x1113  // Global Thread Storage data
#define MS_LPROCMIPS    0x1114  // Local procedure start MIPS
#define MS_GPROCMIPS    0x1115  // Global procedure start MIPS
#define MS_COMPILE2     0x1116  // compilator information
#define MS_MANYREG2     0x1117
#define MS_LPROCIA64    0x1118
#define MS_GPROCIA64    0x1119
#define MS_LOCALSLOT    0x111a
#define MS_PARAMSLOT    0x111b
#define MS_LMANDATA     0x111c
#define MS_GMANDATA     0x111d
#define MS_MANFRAMEREL  0x111e
#define MS_MANREGISTER  0x111f
#define MS_MANSLOT      0x1120
#define MS_MANMANYREG   0x1121
#define MS_MANREGREL    0x1122
#define MS_MANMANYREG2  0x1123

#define MS_UNAMESPACE   0x1124
#define MS_PROCREF      0x1125  // Reference to a procedure
#define MS_DATAREF      0x1126  // Reference to data
#define MS_LPROCREF     0x1127  // Reference to a procedure
#define MS_ANNOTATIONREF 0x1128
#define MS_TOKENREF     0x1129
#define MS_GMANPROC     0x112a
#define MS_LMANPROC     0x112b
#define MS_TRAMPOLINE   0x112c
#define MS_MANCONSTANT  0x112d
#define MS_ATTRFRAMEREL 0x112e
#define MS_ATTRREGISTER 0x112f
#define MS_ATTREGREL    0x1130
#define MS_ATTMANYREG   0x1131
#define MS_SEPCODE      0x1132
#define MS_UNKNOWN      0x1133

//----------------------------------------------------------------------
// S_COMPILE machine types
#define CV_CPU_I8080            0x00
#define CV_CPU_I8086            0x01
#define CV_CPU_I80286           0x02
#define CV_CPU_I80386           0x03
#define CV_CPU_I80486           0x04
#define CV_CPU_PENTIUM          0x05
#define CV_CPU_PENTIUM_PRO      0x06
#define CV_CPU_R4000            0x10
#define CV_CPU_MIPS_FUTURE1     0x11
#define CV_CPU_MIPS_FUTURE2     0x12
#define CV_CPU_MC68000          0x20
#define CV_CPU_MC68010          0x21
#define CV_CPU_MC68020          0x22
#define CV_CPU_MC68030          0x23
#define CV_CPU_MC68040          0x24
#define CV_CPU_ALPHA            0x30
#define CV_CPU_PPC601           0x40
#define CV_CPU_PPC603           0x41
#define CV_CPU_PPC604           0x42
#define CV_CPU_PPC620           0x43

// S_COMPILER language types

#define CV_LANG_C         0
#define CV_LANG_CPP       1
#define CV_LANG_FORTRAN   2
#define CV_LANG_MASM      3
#define CV_LANG_PASCAL    4
#define CV_LANG_BASIC     5
#define CV_LANG_COBOL     6
#define CV_LANG_LINKER    7

// S_COMPILER model bits

#define CV_COMPILE_PCODE        0x0001          // Pcode is present
#define CV_COMPILE_FPREC        0x0006          // Float precision (1-ANSI)
#define CV_COMPILE_FPACK        0x0018          // Float package:
#define CV_COMPILE_FP_HW        0
#define CV_COMPILE_FP_EMU       1
#define CV_COMPILE_FP_ALT       2
#define CV_COMPILE_AMBDATA      0x00E0          // Data model
#define CV_COMPILE_AMBCODE      0x0700          // Code model
#define CV_COMPILE_MODE32       0x0800          // 32bit application
#define CV_COMPILE_MODEL_NEAR   0
#define CV_COMPILE_MODEL_FAR    1
#define CV_COMPILE_MODEL_HUGE   2
// borland specific
#define BCV_COMPILE_CHSIGN      0x1000          // 'char' is signed

//----------------------------------------------------------------------
// S_THUNK types
#define CV_THUNK16_NOTYPE       0
#define CV_THUNK16_ADJUSTOR     1
#define CV_THUNK16_VCALL        2
#define CV_THUNK16_PCODE        3

//----------------------------------------------------------------------
// Procedure attribute bits
#define CV_PROC16_FPO   0x0001  // function has frame pointer omitted.
#define CV_PROC16_INTR  0x0002  // function is interrupt routine.
#define CV_PROC16_FAR   0x0004  // function performs far return.
#define CV_PROC16_NORET 0x0008  // function never returns.

//----------------------------------------------------------------------
// S_RETURN flag bits
#define CV_RETURN_CSTYLE        0x0001  // push varargs right to left
#define CV_RETURN_RSCLEAN       0x0002  // returnee stack cleanup

// S_RETURN styles

#define CV_RETURN_VOID          0x00    // void return
#define CV_RETURN_DATA          0x01    // return value is in the registers specified in data
#define CV_RETURN_CNEAR         0x02    // indirect caller-allocated near
#define CV_RETURN_CFAR          0x03    // indirect caller-allocated far
#define CV_RETURN_RNEAR         0x04    // indirect returnee-allocated near
#define CV_RETURN_RFAR          0x05    // indirect returnee-allocated far

//----------------------------------------------------------------------
// Segment descriptor
struct cv_seg_desc_t
{
  uint16 flags;
#define CV_SEG_READ     0x0001
#define CV_SEG_WRITE    0x0002
#define CV_SEG_EXEC     0x0004
#define CV_SEG_32BIT    0x0008
#define CV_SEG_SEL      0x0100
#define CV_SEG_ABS      0x0200
#define CV_SEG_GROUP    0x1000
  uint16 ovl;           // Logical overlay number.
  uint16 group;         // Group index into the descriptor array. The group
                        // index must either be 0 or cSegLog <= group < cSeg.
  uint16 frame;         // This value has the following different meanings
                        // depending upon the values of fAbs and fSel in the
                        // flags bit array and ovl:
//  abs  sel  ovl  description
//   0    0    0   frame is added to PSP+0x10 if not a .com file
//   0    0    0   frame is added to PSP if it is a .com file
//   0    0   !=0  frame is added to currnet overlay base
//   1    0    x   frame is absolute address
//   1    0    x   frame is contains a selector
  uint16 iSegName;      // Byte index of the segment or group name in the
                        // sstSegName table. A value of 0xffff indicates that
                        // there is no name.
  uint16 iClassName;    // Byte index of the class name in the sstSegName
                        // table. A value of 0xffff indicates that there is
                        // no name.
  uint32 offset;        // Byte offset of the logical segment within the
                        // specified physical segment. If fGroup is set in
                        // flags, offset is the offset of the group in
                        // the physical segment. Currently all groups define
                        // physical segments, so offset will be zero for
                        // groups.
  uint32 cbseg;         // Byte count of the logical segment or group.
};

//----------------------------------------------------------------------
// sstModule descriptions
struct cv_module_t
{
  uint16 seg;           // 1-based segment index that this structure describes
  uint16 oFlags;        // OBJ: padding for alignment. for future use
                        // TDS: // 1-code, 0-data (0xFF00 ulink:skip)
  uint32 offset;        // offset in segment where code starts
  uint32 cbSeg;         // number of byte in segment
};

// ---------------------------------------------------------------------------
struct bad_cv_t
{
};

// ---------------------------------------------------------------------------
template <typename T>
static const T *data_alias_at(const void *data, size_t size, size_t off, uint32 count = 1)
{
  if ( sizeof(T) != 1 && !is_mul_ok<uint32>(count, (uint32) sizeof(T)) )
    throw bad_cv_t();
  const char *cdata = (const char *) data;
  const char *cend = cdata + size;
  const char *ptr = cdata + off;
  const char *end = ptr + count * sizeof(T);
  if ( end > cend
    || ptr < cdata
    || ptr > end
    || (count > 0 && ptr == end) )
  {
    throw bad_cv_t();
  }
  return (const T*)ptr;
}

// ---------------------------------------------------------------------------
struct cv_data_t
{
  cv_data_t(const void *_data, size_t _size, bool _iswide)
    : data(_data), size(_size), iswide(_iswide) {}

  uint32 offset_in_data(const void *ptr) const
  {
    const uchar *p = (const uchar *) ptr;
    const uchar *d = (const uchar *) data;
    if ( p < d || p > (d + size) )
      throw bad_cv_t();
    return p - d;
  }

  const void *data;
  size_t size;
  bool iswide;
};

// ---------------------------------------------------------------------------
template <typename T>
static const T *data_alias_at(const cv_data_t &cvdata, size_t off, uint32 count = 1)
{
  return data_alias_at<T>(cvdata.data, cvdata.size, off, count);
}

// ---------------------------------------------------------------------------
struct cv_stream_t
{
  const cv_data_t &cvdata;
  const uchar     *start;
  const uchar     *ptr;
  const uchar     *end;

  cv_stream_t(const cv_data_t &_cvdata, const void *_ptr, size_t _size)
    : cvdata(_cvdata)
  {
    start = (uchar *)_ptr;
    ptr = start;
    end = start + _size;
    QASSERT(30473, start <= end);
  }

  uchar get_uchar()
  {
    ensure_left(1);
    return *ptr++;
  }

  ushort get_ushort()
  {
    ensure_left(2);
    uint16 x = *(uint16*) ptr;
    ptr += sizeof(uint16);
    return x;
  }

  uint32 get_ulong()
  {
    ensure_left(4);
    uint32 x = *(uint32*) ptr;
    ptr += sizeof(uint32);
    return x;
  }

  uint32 get_wd(bool is32)
  {
    return is32 ? get_ulong() : get_ushort();
  }

  int get_leaf(leaf_t &leaf)
  {
    leaf.type = get_ushort();
    if ( leaf.type < LF_NUMERIC )
    {
      leaf.value = &leaf.type;
      return 1;
    }
    leaf.value = (void *)ptr;
    uint32 toskip = 0;
    switch ( leaf.type )
    {
      case LF_CHAR:       toskip = 1;       break;
      case LF_SHORT:      toskip = 2;       break;
      case LF_USHORT:     toskip = 2;       break;
      case LF_LONG:       toskip = 4;       break;
      case LF_ULONG:      toskip = 4;       break;
      case LF_REAL32:     toskip = 4;       break;
      case LF_REAL64:     toskip = 8;       break;
      case LF_REAL80:     toskip = 10;      break;
      case LF_REAL128:    toskip = 16;      break;
      case LF_QUADWORD:   toskip = 8;       break;
      case LF_UQUADWORD:  toskip = 8;       break;
      case LF_REAL48:     toskip = 6;       break;
      case LF_COMPLEX32:  toskip = 8;       break;
      case LF_COMPLEX64:  toskip = 16;      break;
      case LF_COMPLEX80:  toskip = 20;      break;
      case LF_COMPLEX128: toskip = 32;      break;
      case LF_VARSTRING:  toskip = get_ushort(); break;
      default:
        return 0;
    }
    skip(toskip);
    return 1;
  }


  char *get_name(char *buf, size_t bufsize)
  {
    ensure_left(1);
    size_t len = *ptr++;
    if ( len >= bufsize )
      len = bufsize - 1;
    len = qmin(len, bytes_left());
    ensure_left(len);
    memcpy(buf, ptr, len);
    buf[len] = '\0';
    ptr += len;
    return buf;
  }

  cv_stream_t get_substream_for_symbol(uint16 *type)
  {
    uint16 len  = get_ushort() - 2;
    uint16 t    = get_ushort();
    if ( type != nullptr )
      *type = t;
    ensure_left(len);
    cv_stream_t sym_stream(cvdata, ptr, len);
    skip(len);
    return sym_stream;
  }

  cv_stream_t get_substream_from_start(uint32 offset)
  {
    const uchar *p = data_alias_at<uchar>(start, end-start, offset);
    return cv_stream_t(cvdata, p, end-p);
  }

  void skip(uint32 elsize, uint32 elcount)
  {
    if ( !is_mul_ok<uint32>(elcount, elsize) )
      throw bad_cv_t();
    skip(elcount * elsize);
  }

  void skip(uint32 n)
  {
    ensure_left(n);
    ptr += n;
  }

  void rewind(uint32 n)
  {
    if ( (ptr - start) < n )
      throw bad_cv_t();
    ptr -= n;
  }

  uint32 bytes_left()
  {
    if ( ptr > end )
      return 0;
    return end - ptr;
  }

  void narrow(const uchar *new_end)
  {
    if ( new_end == nullptr || new_end > end || new_end < ptr )
      throw bad_cv_t();
    end = new_end;
  }

  void ensure_left(uint32 n)
  {
    const uchar *p = ptr + n;
    if ( p > end || p < ptr )
      throw bad_cv_t();
  }
};

// //----------------------------------------------------------------------
// inline uchar get_uchar(const uchar *&ptr) {
//   return *ptr++;
// }

// //----------------------------------------------------------------------
// inline ushort get_ushort(const uchar *&ptr)
// {
//   uint16 x = *(uint16 *)ptr;
//   ptr += sizeof(uint16);
//   return x;
// }

// //----------------------------------------------------------------------
// inline uint32 get_ulong(const uchar *&ptr)
// {
//   uint32 x = *(uint32 *)ptr;
//   ptr += sizeof(uint32);
//   return x;
// }

// NB02 (CodeView3) format desctription
// Most of info taken from Watcom's hll.h

//  subsection type constants

enum cv3_sst
{
  cv3_sstModule = 0x101,  // Basic info. about object module
  cv3_sstModules = cv3_sstModule, /* misnomer. */
  cv3_sstPublics,         // Public symbols
  cv3_sstTypes,           // Type information
  cv3_sstSymbols,         // Symbol Data
  cv3_sstSrcLines,        // Source line information
  cv3_sstLibraries,       // Names of all library files used
  cv3_sstImports,         // Symbols for DLL fixups
  cv3_sstCompacted,       // Compacted types section
  cv3_sstSrcLnSeg,        // Same as source lines, contains segment
  cv3_sstHLLSrc = 0x10B
};

/* CV3 debug directory entry. */
struct cv3_dir_entry
{
  uint16 subsection;             /* The subsection type, cv3_sst. */
  uint16 iMod;                   /* The module index. (1 based) */
  uint32 lfo;                    /* The offset of the subsection (NBxx relative). */
  uint16 cb;                     /* The size of the subsection. */
};

/* CV3 16-bit segment info. */
struct cv3_seginfo_16
{
  uint16 Seg;
  uint16 offset;
  uint16 cbSeg;
};

/* CV3 32-bit segment info. */
struct cv3_seginfo_32
{
  uint16 Seg;
  uint32 offset;
  uint32 cbSeg;
};

struct cv3_module_16
{
  cv3_seginfo_16 SegInfo;        /* The segment info for the first [code] segment. */
  uint16         ovlNumber;      /* The overlay number. */
  uint16         iLib;           /* The index of the library to which we belong. */
  uint8          cSeg;           /* The number of segment info pieces (includes SegInfo). */
  uint8          reserved;
  uint8          name_len;       /* The name length. */
//  char           name[1];
//  cv3_seginfo_16 arnsg[];
};

struct cv3_module_32
{
  cv3_seginfo_32 SegInfo;        /* The segment info for the first [code] segment. */
  uint16         ovlNumber;      /* The overlay number. */
  uint16         iLib;           /* The index of the library to which we belong. */
  uint8          cSeg;           /* The number of segment info pieces (includes SegInfo). */
  uint8          reserved;
  uint8          name_len;       /* The name length. */
//  char           name[1];
//  cv3_seginfo_32 arnsg[];
};

/* CV3 16-bit public symbol record. */
struct cv3_public_16
{
  uint16 offset;
  uint16 seg;
  uint16 type;
  uint8  name_len;
//  char        name[1];
};

/* CV3 32-bit public symbol record. */
struct cv3_public_32
{
  uint32 offset;
  uint16 seg;
  uint16 type;
  uint8  name_len;
//  char        name[];
};

struct cv_linnum_seg
{
//  char      name[1];
  uint16 seg;
  uint16 cPair;
//    line_offset_parms[1];
};

/* obsolete */
struct cv_srcln_off_16
{
  uint16     line;
  uint16     offset;
};

/* CV3 16-bit line number entry. (cv3_sstSrcLnSeg & cv3_sstSrcLines) */
struct cv3_linnum_entry_16
{
  uint16 line;
  uint16 offset;
};

/* CV3 32-bit line number entry. (cv3_sstSrcLnSeg) */
struct cv3_linnum_entry_32
{
  uint16 line;
  uint32 offset;
};

#pragma pack(pop)
#endif // define __CV_HPP
