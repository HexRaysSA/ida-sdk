/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

//
//      PEF file format (Mac OS, Be OS)
//

#ifndef PEF_HPP
#define PEF_HPP
#pragma pack(push, 1)

//-----------------------------------------------------------------------
#if __MF__
#define mfshort(x)      (x)
#define lfshort(x)      swap16(x)
#define mflong(x)       (x)
#define lflong(x)       swap32(x)
#else
#define mfshort(x)      swap16(x)
#define lfshort(x)      (x)
#define mflong(x)       swap32(x)
#define lflong(x)       (x)
#endif

typedef int16 sint16;
typedef int32 sint32;

//-----------------------------------------------------------------------
struct pef_t
{
  char tag1[4];                 // Designates Apply-defined format
#define PEF_TAG_1 "Joy!"

  char tag2[4];                 // Type of container
#define PEF_TAG_2 "peff"

  char architecture[4];         // Target architecture
#define PEF_ARCH_PPC  "pwpc"
#define PEF_ARCH_68K  "m68k"

  uint32 formatVersion;         // Version of PEF
#define PEF_VERSION 1

  uint32 dateTimeStamp;         // Number of seconds from January 1, 1904

  uint32 oldDefVersion;
  uint32 oldImpVersion;
  uint32 currentVersion;

  uint16 sectionCount;          // Total number of sections
  uint16 instSectionCount;      // Number of instantiated sections

  uint32 reservedA;             // Should be 0
};

//-----------------------------------------------------------------------
struct pef_section_t
{
  sint32 nameOffset;            // Offset from the start of the section
                                // name table
                                // No name is -1
  uint32 defaultAddress;        // Preferred address for section
  uint32 totalSize;             // Total size of section in memory
  uint32 unpackedSize;          // Initialized size of section in memory
  uint32 packedSize;            // Size of section in file
  uint32 containerOffset;       // Offset from the beginning of the file
  uint8 sectionKind;            // Type of section:
#define PEF_SEC_CODE    0       //   Code segment
#define PEF_SEC_DATA    1       //   Unpacked data segment
#define PEF_SEC_PDATA   2       //   Pattern initialized data segment
#define PEF_SEC_CONST   3       //   Read only data
#define PEF_SEC_LOADER  4       //   Loader section
#define PEF_SEC_DEBUG   5       //   Reserved for future use
#define PEF_SEC_EDATA   6       //   Executable data segment
#define PEF_SEC_EXCEPT  7       //   Reserved for future use
#define PEF_SEC_TRACEB  8       //   Reserved for future use
  uint8 shareKind;              // Section share properties
#define PEF_SH_PROCESS 1        //   Shared within process
#define PEF_SH_GLOBAL  4        //   Shared between all processes
#define PEF_SH_PROTECT 5        //   Shared between all processes but protected
  uint8 alignment;              // Section alignment as power of 2
                                // (here we have an exponent)
  uint8 reservedA;              // Should be 0
};

//-----------------------------------------------------------------------
struct pef_loader_t
{
  sint32 mainSection;           // Number of section with "main" symbol (-1 - none)
  uint32 mainOffset;            // Offset to "main" symbol
  sint32 initSection;           // Number of section with initialization transition vector (-1 - none)
  uint32 initOffset;            // Offset to initialization transition vector
  sint32 termSection;           // Number of section with termination transition vector (-1 - none)
  uint32 termOffset;            // Offset to termination transition vector
  uint32 importLibraryCount;    // Number of imported libraries
  uint32 totalImportedSymbolCount;
  uint32 relocSectionCount;
  uint32 relocInstrOffset;
  uint32 loaderStringsOffset;
  uint32 exportHashOffset;
  uint32 exportHashTablePower;
  uint32 exportedSymbolCount;
};

//-----------------------------------------------------------------------
struct pef_library_t            // Imported Library
{
  uint32 nameOffset;            // Offset from beginning of loader string table
  uint32 oldImpVersion;
  uint32 currentVersion;
  uint32 importedSymbolCount;
  uint32 firstImportedSymbol;
  uint8 options;
#define PEF_LIB_INIT  0x80      // Non-default init order of library
#define PEF_LIB_WEAK  0x40      // Weak library
  uint8  reservedA;
  uint16 reservedB;
};

//-----------------------------------------------------------------------
// Imported symbol classes

#define kPEFCodeSymbol  0       // a code address
#define kPEFDataSymbol  1       // a data address
#define kPEFTVectSymbol 2       // a standard procedure pointer
#define kPEFTOCSymbol   3       // a direct data area (TOC) symbol
#define kPEFGlueSymbol  4       // a linker-inserted glue symbol

#define kPEFWeak        0x80    // Weak symbol mask

//-----------------------------------------------------------------------
// Relocation Header
struct pef_reloc_header_t
{
  uint16 sectionIndex;
  uint16 reservedA;
  uint32 relocCount;
  uint32 firstRelocOffset;
};

//-----------------------------------------------------------------------
// Relocation Instructions

enum
{
  kPEFRelocBySectDWithSkip= 0x00,/* binary: 00xxxxx */

  kPEFRelocBySectC     = 0x20,  /* binary: 0100000 */
  kPEFRelocBySectD     = 0x21,  /* binary: 0100001 */
  kPEFRelocTVector12   = 0x22,  /* binary: 0100010 */
  kPEFRelocTVector8    = 0x23,  /* binary: 0100011 */
  kPEFRelocVTable8     = 0x24,  /* binary: 0100100 */
  kPEFRelocImportRun   = 0x25,  /* binary: 0100101 */

  kPEFRelocSmByImport  = 0x30,  /* binary: 0110000 */
  kPEFRelocSmSetSectC  = 0x31,  /* binary: 0110001 */
  kPEFRelocSmSetSectD  = 0x32,  /* binary: 0110010 */
  kPEFRelocSmBySection = 0x33,  /* binary: 0110011 */

  kPEFRelocIncrPosition= 0x40,  /* binary: 1000xxx */
  kPEFRelocSmRepeat    = 0x48,  /* binary: 1001xxx */

  kPEFRelocSetPosition = 0x50,  /* binary: 101000x */
  kPEFRelocLgByImport  = 0x52,  /* binary: 101001x */
  kPEFRelocLgRepeat    = 0x58,  /* binary: 101100x */
  kPEFRelocLgSetOrBySection= 0x5A,/* binary: 101101x */
};

//-----------------------------------------------------------------------
// Exported Symbols
struct pef_export_t
{
  uint32 classAndName;
  uint32 symbolValue;
  sint16 sectionIndex;
};

#pragma pack(pop)
#endif // PEF_HPP
