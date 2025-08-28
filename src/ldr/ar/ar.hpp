/* So far this is correct for BSDish archives.  Don't forget that
   files must begin on an even byte boundary. */

#ifndef __AR_H__
#define __AR_H__
#pragma pack(push, 1)

/* Note that the usual '\n' in magic strings may translate to different
   characters, as allowed by ANSI.  '\012' has a fixed value, and remains
   compatible with existing BSDish archives. */

#define ARMAG  "!<arch>\012"    /* For COFF and a.out archives */
#define ARMAGB "!<bout>\012"    /* For b.out archives */
#define ARMAGE "!<elf_>\012"    /* For ELF archives */
#define SARMAG 8
#define ARFMAG "`\012"

/* The ar_date field of the armap (__.SYMDEF) member of an archive
   must be greater than the modified date of the entire file, or
   BSD-derived linkers complain.  We originally write the ar_date with
   this offset from the real file's mod-time.  After finishing the
   file, we rewrite ar_date if it's not still greater than the mod date.  */

#define ARMAP_TIME_OFFSET       60

struct ar_hdr
{
  char ar_name[16];             /* name of this member */
  char ar_date[12];             /* file mtime */
  char ar_uid[6];               /* owner uid; printed as decimal */
  char ar_gid[6];               /* owner gid; printed as decimal */
  char ar_mode[8];              /* file mode, printed as octal   */
  char ar_size[10];             /* file size, printed as decimal */
  char ar_fmag[2];              /* should contain ARFMAG */
};

#define AR_EFMT1    "#1/"       /* extended format #1: BSD/Apple archives */

// ig. get all module names from ar

int process_ar(
        char *libfile,    /* return 0 - ok */
        int (*_callback)(
          void *ud,
          int32 offset,
          int method,
          uint32 csize,
          uint32 ucsize,
          uint32 attributes,
          const char *filename),
        void *ud);

// The first linker member has the following format. This information appears after the
// header:
//
// Offset Size Field Description
// 0      4   Number of Symbols Unsigned long containing the number of symbols indexed.
//            This number is stored in big-endian format. Each object-file member
//            typically defines one or more external symbols.
// 4     4*n  Offsets Array of file offsets to archive member headers, in which n is
//            equal to Number of Symbols. Each number in the array is an unsigned long
//            stored in big-endian format. For each symbol named in the String Table,
//            the corresponding element in the Offsets array gives the location of the
//            archive member that contains the symbol.
// *      *   String Table Series of null-terminated strings that name all the symbols
//            in the directory. Each string begins immediately after the null character
//            in the previous string. The number of strings must be equal to the value
//            of the Number of Symbols fields.
//
// -----------------------------
// The second linker member has the name '\' as does the first linker member. Although
// both the linker members provide a directory of symbols and archive members that contain
// them, the second linker member is used in preference to the first by all current
// linkers. The second linker member includes symbol names in lexical order, which enables
// faster searching by name.
//
// The first second member has the following format. This information appears after the
// header:
//
// Offset Size Field Description
// 0      4    Number of Members Unsigned long containing the number of archive members.
// 4      4*m  Offsets Array of file offsets to archive member headers, arranged in
//             ascending order. Each offset is an unsigned long. The number m is equal
//             to the value of the Number of Members field.
// *      4    Number of Symbols Unsigned long containing the number of symbols indexed.
//             Each object-file member typically defines one or more external symbols.
// *      2*n  Indices Array of 1-based indices (unsigned short) which map symbol names
//             to archive member offsets. The number n is equal to Number of Symbols.
//             For each symbol named in the String Table, the corresponding element in
//             the Indices array gives an index into the Offsets array. The Offsets
//             array, in turn, gives the location of the archive member that contains
//             the symbol.
// *      *    String Table Series of null-terminated strings that name all the symbols
//             in the directory. Each string begins immediately after the null byte in
//             the previous string. The number of strings must be equal to the value of
//             the Number of Symbols fields. This table lists all the symbol names in
//             ascending lexical order.
//
// //-----------------------------
// The name of the longnames member is '\\'. The longnames member is a series of
// strings of archive member names. A name appears here only when there is insufficient
// room in the Name field (16 bytes). The longnames member can be empty, though its
// header must appear.
//
// The strings are null-terminated. Each string begins immediately after the null byte
// in the previous string.
//

bool is_ar_file(linput_t *li, qoff64_t offset, bool include_aix);

#pragma pack(pop)
#endif /* __AR_H__ */

