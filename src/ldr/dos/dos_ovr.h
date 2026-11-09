/*
 *      Interactive disassembler (IDA).
 *      Version 3.00
 *      Copyright (c) 1990-94 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _DOS_OVR_H_
#define _DOS_OVR_H_

// the following structures are 1-byte aligned (!)
#pragma pack(push,1)

struct fbov_t
{
  ushort fb;
#define FB_MAGIC 0x4246
  ushort ov;
#define OV_MAGIC 0x564F
  uint32 ovrsize;
  uint32 exeinfo;
  int32 segnum;
};

struct seginfo_t
{
  ushort seg;
  ushort maxoff;                // FFFF - unknown
  ushort flags;
#define SI_COD  0x0001
#define SI_OVR  0x0002
#define SI_DAT  0x0004
  ushort minoff;
};

struct stub_t
{
  uchar CDh;            // 0
  uchar intnum;         // 1
  ushort memswap;       // 2
  int32 fileoff;        // 4
  ushort codesize;      // 8
  ushort relsize;       // 10
  ushort nentries;      // 12
  ushort prevstub;      // 14
#define STUBUNK_SIZE            (0x20-0x10)
  uchar unknown[STUBUNK_SIZE];
};

struct ovrentry_t
{
  ushort int3f;
  ushort off;
  char segc;
};

CASSERT(sizeof(ovrentry_t) == 5);

struct ms_entry
{
  uchar   CDh;
  uchar   intnum;   // normally 3Fh
  ushort  ovr_index;
  ushort  entry_off;
};

bool pos_read(linput_t *fp, uint32 pos, void *buf, size_t size);
int  CheckCtrlBrk(void);
void add_segm_by_selector(sel_t base, const char *sclass);
extern const char e_exe[];
//
enum o_type { ovr_noexe, ovr_pascal, ovr_cpp, ovr_ms };

o_type PrepareOverlayType(linput_t *fp, exehdr *E);
linput_t *CheckExternOverlays(void);
sel_t  LoadCppOverlays(linput_t *fp);
sel_t  LoadMsOverlays(linput_t *fp, bool PossibleDynamic);
void   LoadPascalOverlays(linput_t *fp);

NORETURN void errstruct(void);

#pragma pack(pop)

#endif
