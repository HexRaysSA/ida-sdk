/*
        GEOS2.H
        by Marcus Groeber 1993-94
        Include file for the PC/GEOS 2 file format

        20.06.00: Modified by Ilfak Guilfanov <ig@datarescue.com>
*/

#ifndef GEOS2_H
#define GEOS2_H

#include "geos.h"

#pragma pack(push, 1)

/*
 *  Packed time and date structures; bitfield order is compiler dependant.
 */
struct PackedFileDate
{
  ushort d:5;
  ushort m:4;
  ushort y:7;
};

struct PackedFileTime
{
  ushort s_2:5;
  ushort m:6;
  ushort h:5;
};

/******************************************************************************
 *               GEOS standard file header (all file types)                   *
 ******************************************************************************/
#define GEOS2_ID 0x53C145C7             // GEOS2 file identification "magic"

struct GEOS2header
{                                       /*** GEOS2 standard header */
  int32 ID;                             // GEOS2 id magic: C7 45 CF 53
  char name[GEOS_LONGNAME];             // long filename
  ushort fclass;                        // geos filetype, see SDK docs
                                        // 1-executable
  ushort flags;                         // attributes
  GEOSrelease release;                  // "release"
  GEOSprotocol protocol;                // protocol/version
  GEOStoken token;                      // file type/icon
  GEOStoken appl;                       // "token" of creator application
  char info[GEOS_INFO];                 // user file info
  char _copyright[24];                  // original files: Copyright notice
  char _x[8];
  PackedFileDate create_date;
  PackedFileTime create_time;           // creation date/time in DOS format
  char password[8];                     // password, encrypted as hex string
  char _x2[44];                         // not yet decoded
};

#pragma pack(pop)

#endif // define GEOS2_H
