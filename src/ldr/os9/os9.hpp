/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 *      This file describes two different formats:
 *              - OS9 object files
 *              - FLEX STX files
 *
 */


#ifndef _OS9_HPP
#define _OS9_HPP
#pragma pack(push, 1)
//----------------------------------------------------------------------
//
//      OS9 object code files have the following header at the start:
//
struct os9_header_t
{
  ushort magic;         // $00   2  Sync Bytes (always $87CD)
#define OS9_MAGIC 0x87CD
  ushort size;          // $02   2  Module Size (bytes)
  ushort name;          // $04   2  Module Name Offset
  uchar  type_lang;     // $06   1  Type/Language
#define OS9_TYPE     0xF0  //       Type
#define OS9_TYPE_ILL 0x00  //         this one is illegal
#define OS9_TYPE_PRG 0x10  //         Program module
#define OS9_TYPE_SUB 0x20  //         Subroutine module
#define OS9_TYPE_MUL 0x30  //         Multi-Module (for future use)
#define OS9_TYPE_DAT 0x40  //         Data module
//#define OS9_$50-$B0 User defined
#define OS9_TYPE_SYS 0xC0  //         OS-9 System Module
#define OS9_TYPE_FIL 0xD0  //         OS-9 File Manager Module
#define OS9_TYPE_DRV 0xE0  //         OS-9 Device Driver Module
#define OS9_TYPE_DDM 0xF0  //         OS-9 Device Descriptor Module

#define OS9_LANG     0x0F  //       Language
#define OS9_LANG_DAT 0x00  //         Data (not executable)
#define OS9_LANG_OBJ 0x01  //         6809 object code <- this is the only one to disassemble
#define OS9_LANG_BAS 0x02  //         BASIC09 I-Code
#define OS9_LANG_PAS 0x03  //         PASCAL P-Code
#define OS9_LANG_C   0x04  //         C I-Code
#define OS9_LANG_CBL 0x05  //         COBOL I-Code
#define OS9_LANG_FTN 0x06  //         FORTRAN I-Code
  uchar  attrib;        // $07   1  Attrib/Revision
#define OS9_REVSN    0x0F  //         Module revision
                           //         The higher the number the more current
                           //         the revision. When modules are loaded by
                           //         the OS, if there is already module loaded
                           //         with the same name, type, language, etc.
                           //         the one with the highest revision will be used.
#define OS9_SHARED   0x80  //         The module is reentrant and sharable
  uchar  parity;        // $08   1  header parity byte
                        //          It is the ones complement of the vertical
                        //          parity (exclusive OR) of the previous
                        //          eight bytes.
  ushort start;         // $09   2  Execution Offset
  ushort storage;       // $0B   2  Permenant Storage Requirements
                        // $0D      Module Body
};

//----------------------------------------------------------------------
// Flex files have the following format:
// 0x02 0xYY 0xYY 0xZZ ...........
//    where 0xYY is a 16 bit address, and 0xZZ is the byte count (0x00-0xFF).
//    The reason for this is that the user could assign a program to be
//    loaded and executed from anywhere in memory. So each executable file
//    had the loading info in the file.
// 0x16 0xYY 0xYY
//    The starting address of the program was specified in the binary files
//    with a 0x16 0xYY 0xYY record. The 0xYY was the transfer address to be
//    JMP'ed to when the program finished loading. This is the way FLEX and
//    SK*DOS worked for the 6800, 6809 and 68K.

#pragma pack(pop)
#endif // define _OS9_HPP
