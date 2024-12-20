/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Routines and data structures for working with library signatures (e.g. FLIRT).
 */
#ifndef __LIBFUNC_HPP
#define __LIBFUNC_HPP
#pragma pack(push, 1)
struct idasgn_header_t
{
  char magic[6];                // 'IDASGN'
#define SIGN_HEADER_MAGIC  "IDASGN"
  uchar version;                // currently 7 (see fix_version() below)
#define SIGN_HEADER_VERSION 10
  uchar processor_id;           // idp id
  uint32 file_formats;          // allowed file formats (filetype_t)
  uint16 ostype;                // operation system type (bit field)
#define OSTYPE_MSDOS 0x0001
#define OSTYPE_WIN   0x0002
#define OSTYPE_OS2   0x0004
#define OSTYPE_NETW  0x0008
#define OSTYPE_UNIX  0x0010
#define OSTYPE_OTHER 0x0020
  uint16 apptype;               // application type:
#define APPT_CONSOLE 0x0001     //   console
#define APPT_GRAPHIC 0x0002     //   graphics
#define APPT_PROGRAM 0x0004     //   EXE
#define APPT_LIBRARY 0x0008     //   DLL
#define APPT_DRIVER  0x0010     //   DRIVER
#define APPT_1THREAD 0x0020     //   Singlethread
#define APPT_MTHREAD 0x0040     //   Multithread
#define APPT_16BIT   0x0080     //   16 bit application
#define APPT_32BIT   0x0100     //   32 bit application
#define APPT_64BIT   0x0200     //   64 bit application
                                //
                                // Idea: check library date and exe date
                                //
  uint16 flags;                 // signature file flags
#define LS_STARTUP      0x0001  // has startup entry as first module
#define LS_CTYPE        0x0002  // has ctype
#define LS_CTYPE2       0x0004  // ctype element is 2 bytes
#define LS_CTYPE_ALT    0x0008  // alternative ctype checksum present
#define LS_ZIP          0x0010  // compressed signature
#define LS_CTYPE_3V     0x0020  // 3rd variant of ctype checksum present
  uint16 number_of_modules_v5;
  uint16 ctype_crc;
  char   ctype_name[12];
  uchar libname_length;
  uint16 ctype_crc_alt;         // added in version 5
  uint32 number_of_modules;     // added in version 6
  uint16 pattern_length;
  uint16 ctype_crc_3v;          // added in version 10

  void fix_version(FILE *infp);
};
#pragma pack(pop)

/// Get idasgn header by a short signature name.
/// \param out_header buffer for the signature file header
/// \param out_libname buffer for the name of the library
/// \param name  short name of a signature
/// \return true in case of success

idaman bool ida_export get_idasgn_header_by_short_name(idasgn_header_t *out_header, qstring *out_libname, const char *name);

/// Get idasgn full path by a short signature name.
/// \param out_fullpath buffer for the signature file full path
/// \param name  short name of a signature
/// \return true in case of success

idaman bool ida_export get_idasgn_path_by_short_name(qstring *out_fullpath, const char *name);
#endif
