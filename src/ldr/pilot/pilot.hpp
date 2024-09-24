/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 */

#ifndef __PILOT_H
#define __PILOT_H
#pragma pack(push, 1)

#include <time.h>

#define PRC_68K "PalmPilot program file (68K)"
#define PRC_ARM "PalmPilot program file (ARM)"

// Regular resources:

#define PILOT_RSC_CODE  0x65646F63 // "code\0\0\0\1" program code
#define PILOT_RSC_PREF  0x66657270 // "pref\0\0\0\0" preferences (not used yet)
#define PILOT_RSC_DATA  0x61746164 // "data\0\0\0\0" image of global data
#define PILOT_RSC_LIBR  0x7262696C // "libr" SysLib-type shared library code
#define PILOT_RSC_GLIB  0x62694C47 // "GLib" PRC-Tools GLib-type shared library code
#define PILOT_RSC_RLOC  0x636F6C72 // "rloc" PRC-Tools and Multilink relocations
#define PILOT_RSC_ARMC  0x434D5241 // "ARMC" ARM native code
#define PILOT_RSC_ARMCL 0x636D7261 // "armc" ARM native code

// UI resources:

#define PILOT_RSC_MBAR   0x5241424D // "MBAR" Menu bar
#define PILOT_RSC_MENU   0x554E454D // "MENU" Menu options
#define PILOT_RSC_ICON   0x4E494174 // "tAIN" Application icon name
#define PILOT_RSC_AIB    0x42494174 // "tAIB" Application icon bitmap
#define PILOT_RSC_AIS    0x53494174 // "tAIS" Application information string
#define PILOT_RSC_ALERT  0x746C6154 // "Talt" Alert
#define PILOT_RSC_BITMAP 0x706D6254 // "Tbmp" Bitmap
#define PILOT_RSC_BUTTON 0x4E544274 // "tBTN" Button
#define PILOT_RSC_CHECK  0x58424374 // "tCBX" Check box
#define PILOT_RSC_FBM    0x4D424674 // "tFBM" Form bitmap
#define PILOT_RSC_FIELD  0x444C4674 // "tFLD" Field
#define PILOT_RSC_FORM   0x4D524674 // "tFRM" Form
#define PILOT_RSC_GADGET 0x54444774 // "tGDT" Gadget
#define PILOT_RSC_GRAFF  0x49534774 // "tGSI" Graffiti Shift
#define PILOT_RSC_LABEL  0x4C424C74 // "tLBL" Label
#define PILOT_RSC_LIST   0x54534C74 // "tLST" List box
#define PILOT_RSC_PUSH   0x4E425074 // "tPBN" Push button
#define PILOT_RSC_POPUPL 0x4C555074 // "tPUL" Popup list
#define PILOT_RSC_POPUPT 0x54555074 // "tPUT" Popup trigger
#define PILOT_RSC_REPEAT 0x50455274 // "tREP" Repeating control
#define PILOT_RSC_SELECT 0x544C5374 // "tSLT" Selector trigger
#define PILOT_RSC_STRING 0x52545374 // "tSTR" String
#define PILOT_RSC_TABLE  0x4C425474 // "tTBL" Table
#define PILOT_RSC_TITLE  0x4C545474 // "tTTL" Title
#define PILOT_RSC_VER    0x72657674 // "tver" Version number string


typedef uchar Byte;
typedef ushort Word;
typedef uint32 DWord;
typedef DWord LocalID;

//
//      Header of PRC file:
//

struct DatabaseHdrType
{
  Byte name[32];                        // name of database
#define PILOT_CREATOR_PILA 0x616C6950   // "Pila"
  Word attributes;                      // database attributes
#define dmHdrAttrResDB          0x0001  // Resource database
#define dmHdrAttrReadOnly       0x0002  // Read Only database
#define dmHdrAttrAppInfoDirty   0x0004  // Set if Application Info block is dirty
                                        // Optionally supported by an App's conduit
#define dmHdrAttrBackup         0x0008  // Set if database should be backed up to PC if
                                        // no app-specific synchronization conduit has
                                        // been supplied.
#define dmHdrAttrOpen           0x8000  // Database not closed properly
  Word version;                         // version of database
  DWord creationDate;                  // creation date of database
  DWord modificationDate;              // latest modification date
  DWord lastBackupDate;                // latest backup date
  DWord modificationNumber;             // modification number of database
  LocalID appInfoID;                    // application specific info
  LocalID sortInfoID;                   // app specific sorting info
  DWord type;                           // database type
#define PILOT_TYPE_APPL 0x6C707061      // "appl"
  DWord id;                             // program id
  DWord uniqueIDSeed;                   // used to generate unique IDs.
                                        //      Note that only the low order
                                        //      3 bytes of this is used (in
                                        //      RecordEntryType.uniqueID).
                                        //      We are keeping 4 bytes for
                                        //      alignment purposes.
 LocalID nextRecordListID;              // local chunkID of next list
 Word    numRecords;                    // number of records in this list
};

//
//      Each resource has the following entry:
//
struct ResourceMapEntry
{
  uint32 fcType;
  ushort id;
  uint32 ulOffset;
};


// Pilot bitmap format (also format of icon)
struct pilot_bitmap_t
{
  ushort cx;
  ushort cy;
  ushort cbRow;
  ushort ff;
  ushort ausUnk[4];
};


/*
 * code0000[long 0] nBytesAboveA5
 * code0000[long 1] nBytesBelowA5
 */
struct code0000_t
{
  uint32 nBytesAboveA5;
  uint32 nBytesBelowA5;
};

// pref0000

struct pref0000_t
{
  ushort flags;
#define sysAppLaunchFlagNewThread  0x0001
#define sysAppLaunchFlagNewStack   0x0002
#define sysAppLaunchFlagNewGlobals 0x0004
#define sysAppLaunchFlagUIApp      0x0008
#define sysAppLaunchFlagSubCall    0x0010
  uint32 stack_size;
  uint32 heap_size;
};

#pragma pack(pop)
#endif // __PILOT_H
