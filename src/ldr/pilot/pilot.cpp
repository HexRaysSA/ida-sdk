/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 */

#include "../idaldr.h"
#include <expr.hpp>
#include "pilot.hpp"

#include "common.cpp"
//------------------------------------------------------------------------
static void describe_all(DatabaseHdrType &h)
{
  create_filename_cmt();
  add_pgm_cmt("Version     : %04X", h.version);
  add_pgm_cmt("DatabaseType: %4.4s", (char*)&h.type);
  add_pgm_cmt("\n appl \"%s\", '%4.4s'", h.name, (char*)&h.id);
}

//------------------------------------------------------------------------
//
// Structure of the DATA 0 resource:
//
// +--------------------------------------------+
// | long:   offset of CODE 1 xrefs?            |- -+
// +--------------------------------------------+   |
// | char[]: Initialized near data (below A5)   |   |
// +--------------------------------------------+   |
// | char[]: Uninitialized near data (below A5) |   |
// +--------------------------------------------+   |
// | char[]: Initialized far data (above A5)    |   |
// +--------------------------------------------+   |
// | char[]: DATA 0 xrefs                       |   |
// +--------------------------------------------+   |
// | char[]: CODE 1 xrefs                       |<--+
// +--------------------------------------------+
//

static uchar *apply_relocs(uchar *packed, size_t &packlen, ea_t relocbase, ea_t targetbase, bool code=false)
{
  if ( packlen < 4 )
  {
BADDATA:
    warning("Bad packed data");
    return nullptr;
  }
  uint32 nrelocs = swap32(*(uint32*)packed);
  packed += 4;
  packlen -= 4;
  ea_t offset = relocbase;
  fixup_data_t fd(FIXUP_OFF32);
  if ( code )
    fd.set_sel(getseg(targetbase));
  //msg("%d relocations\n", nrelocs);
  for ( uint i=0; i < nrelocs; i++ )
  {
    if ( packlen < 1 )
      goto BADDATA;
    uchar c = *packed;
    if ( c&0x80 )
    {
      // signed 8-bit delta
      offset += char(c<<1);
      packed++;
      packlen--;
    }
    else if ( c&0x40 )
    {
      if ( packlen < 2 )
        goto BADDATA;
      // 15-bit unsigned(?) delta
      // comment in PalmOS_Startup.cpp says "unsigned" but they cast it to a signed short...
      uint32 o1 = swap16(*(ushort*)packed);
      packed  += 2;
      packlen -= 2;
      offset  += short(o1<<2) >> 1;
    }
    else
    {
      if ( packlen < 4 )
        goto BADDATA;
      // direct signed 31-bit offset
      offset = relocbase+(int32(swap32(*(int32*)packed)<<2)>>1);
      packed += 4;
      packlen -= 4;
    }
    for ( int j=0; j < 4; j++ )
      if ( !is_loaded(offset+j) )
        put_byte(offset+j, 0);
    fd.off = get_dword(offset);
    if ( code )
    {
      fd.set(offset);
      auto_make_proc(targetbase+fd.off);
      if ( get_word(offset-2) == 0x4EF9 ) // jump opcode?
        auto_make_proc(offset-2);
    }
    else
    {
      fd.set_base(targetbase);
      fd.set(offset);
    }
//  msg("Relocation %d at %08X: %08X -> %08X\n", i, offset-relocbase, fd.off, targetbase+fd.off);
  }
  return packed;
}

//------------------------------------------------------------------------
// unpack rle data from the buffer packed at file position fpos to ea cea
// return new position in the buffer and update cea
static uchar *unpack_rle(uchar *packed, size_t &packlen, ea_t &cea, qoff64_t fpos)
{
  const uchar *packed_sav = packed;
  while ( 1 )
  {
    if ( packlen < 1 )
    {
BADDATA:
      warning("Bad packed data");
      return nullptr;
    }
    uchar buf[256];
    buf[0] = '\0'; // shutup lint
    uchar cnt = *packed++;
    packlen--;
    if ( cnt == 0 )
      break;
    if ( cnt & 0x80 )
    {
      cnt = (cnt & 0x7F) + 1;
      if ( packlen < cnt )
        goto BADDATA;
      mem2base(packed, cea, cea+cnt, fpos+(packed-packed_sav));
      packed += cnt;
      packlen -= cnt;
      cea += cnt;
      continue;
    }
    if ( cnt & 0x40 )
    {
      cnt = (cnt & 0x3F) + 1;
      memset(buf, 0, cnt);
    }
    else if ( cnt & 0x20 )
    {
      if ( packlen < 1 )
        goto BADDATA;
      cnt = (cnt & 0x1F) + 2;
      memset(buf, *packed++, cnt);
      packlen--;
    }
    else if ( cnt & 0x10 )
    {
      cnt = (cnt & 0x0F) + 1;
      memset(buf, 0xFF, cnt);
    }
    else if ( cnt == 1 )
    {
      if ( packlen < 2 )
        goto BADDATA;
      buf[0] = 0x00;
      buf[1] = 0x00;
      buf[2] = 0x00;
      buf[3] = 0x00;
      buf[4] = 0xFF;
      buf[5] = 0xFF;
      buf[6] = *packed++;
      buf[7] = *packed++;
      packlen -= 2;
      cnt = 8;
    }
    else if ( cnt == 2 )
    {
      if ( packlen < 3 )
        goto BADDATA;
      buf[0] = 0x00;
      buf[1] = 0x00;
      buf[2] = 0x00;
      buf[3] = 0x00;
      buf[4] = 0xFF;
      buf[5] = *packed++;
      buf[6] = *packed++;
      buf[7] = *packed++;
      cnt = 8;
      packlen -= 3;
    }
    else if ( cnt == 3 )
    {
      if ( packlen < 3 )
        goto BADDATA;
      buf[0] = 0xA9;
      buf[1] = 0xF0;
      buf[2] = 0x00;
      buf[3] = 0x00;
      buf[4] = *packed++;
      buf[5] = *packed++;
      buf[6] = 0x00;
      buf[7] = *packed++;
      cnt = 8;
      packlen -= 3;
    }
    else if ( cnt == 4 )
    {
      if ( packlen < 4 )
        goto BADDATA;
      buf[0] = 0xA9;
      buf[1] = 0xF0;
      buf[2] = 0x00;
      buf[3] = *packed++;
      buf[4] = *packed++;
      buf[5] = *packed++;
      buf[6] = 0x00;
      buf[7] = *packed++;
      cnt = 8;
      packlen -= 4;
    }
    mem2base(buf, cea, cea+cnt, -1);
    cea += cnt;
  }
  return packed;
}

//------------------------------------------------------------------------
static size_t unpack_data0000(
        linput_t *li,
        qoff64_t fpos,
        size_t size,
        ea_t ea,
        const code0000_t &code0000,
        ea_t code1ea,
        ea_t &a5)
{
  if ( size < 4 )
  {
BADDATA:
    warning("Bad packed data");
    return 0;
  }
  bytevec_t packed_buf;
  packed_buf.resize(size);
  uchar *packed = packed_buf.begin();
  qlseek(li, fpos);
  lread(li, packed, size);
  size_t usize = code0000.nBytesAboveA5 + code0000.nBytesBelowA5; // total data size
  enable_flags(ea, ea+usize, STT_CUR);

  packed += sizeof(uint32);      // skip initializers size
  size -= sizeof(uint32);

  a5 = ea+code0000.nBytesBelowA5;
  ea_t cea;
  for ( int i=0; i < 3; i++ )
  {
    if ( size < 4 )
      goto BADDATA;
    int32 offset = swap32(*(uint32*)packed); // offset from A5
    packed += sizeof(uint32);
    size -= sizeof(uint32);
    cea = a5 + offset;
    if ( cea < ea )
    {
      // can happen when code 0 resource is not present (e.g. prc-tools GLib-type shared libs)
      if ( i != 0 )
        loader_failure("Error while decompressing data 0");
      cea = ea;
      a5 = ea - offset;
    }
    if ( size > 0 )
    {
      packed = unpack_rle(packed, size, cea, fpos+(packed-packed_buf.begin()));
      if ( packed == nullptr )
        return 0;
    }
    if ( usize < cea-ea )
      usize = size_t(cea-ea);
  }

  if ( a5 > ea + usize - 1 )
  {
    // allocate one extra byte for A5
    enable_flags(ea+usize, ea+usize+1, STT_CUR);
    usize++;
  }
  create_byte(a5, 1);
  if ( a5 != ea )
    add_pgm_cmt("A5 register does not point to the start of the data segment\n"
                "The file should not be recompiled using Pila\n");
  set_name(a5, "A5BASE", SN_NOCHECK|SN_AUTO);
  set_cmt(a5, "A5 points here", false);
  // TODO: find undefined bytes and set them to zero
  // this is done by Palm OS loader and some programs depend on it

  // process relocations
  if ( size > 0 )
  {
    // a5 to a5
    // msg("Relocations: data to data\n");
    packed = apply_relocs(packed, size, a5, a5);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  if ( size > 0 )
  {
    // a5 to code
    // msg("Relocations: data to code1\n");
    packed = apply_relocs(packed, size, a5, code1ea, true);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  return usize;
}

//------------------------------------------------------------------------
// CodeWarrior A4 data layout:
//
// 0..3:     0x00000000
// 4..7:     size of "above A4" region
// 8..11:    size of "below A4" region
// 12..N-1:  compressed "below A4" data
// N..N+3:   size of "near above A4" region
// N+4..O-1: compressed "near above A4" data
// O..O+3:   size of "far above A4" region
// O+4..P-1: compressed "far above A4" data
// then the relocations:
// 1) A4 -> A4
// 2) A4 -> A5
// 3) A4 -> code0001
// 4) A5 -> A4

static size_t unpack_data0001(
        linput_t *li,
        qoff64_t fpos,
        size_t size,
        ea_t ea,
        ea_t a5,
        ea_t code1ea,
        ea_t &a4)
{
  if ( size < 3 * sizeof(uint32) )
  {
BADDATA:
    warning("Bad packed data");
    return 0;
  }
  bytevec_t packed_buf;
  packed_buf.resize(size);
  uchar *packed = packed_buf.begin();
  qlseek(li, fpos);
  lread(li, packed, size);
  packed += sizeof(uint32);      // skip the 0
  size -= sizeof(uint32);

  int32 above = swap32(*(int32*)packed);
  packed += sizeof(int32);
  size -= sizeof(uint32);
  int32 below = swap32(*(int32*)packed);
  packed += sizeof(int32);
  size -= sizeof(uint32);
  size_t usize = above - below; // unpacked size
  if ( below & 1 )
    usize++;

  ea_t cea = ea;
  a4 = ea-below;
  if ( below & 1 )
    a4++;
  enable_flags(ea, ea+usize, STT_CUR);
  create_byte(a4, 1);
  set_name(a4, "A4BASE", SN_NOCHECK|SN_AUTO);
  set_cmt(a4, "A4 points here", 0);

  // unpack below a4
  packed = unpack_rle(packed, size, cea, fpos+(packed-packed_buf.begin()));
  if ( packed == nullptr )
    return 0;

  // unpack near above a4
  if ( size < sizeof(int32) )
    goto BADDATA;
  cea = a4 + swap32(*(int32*)packed);
  packed += sizeof(int32);
  size -= sizeof(uint32);
  packed = unpack_rle(packed, size, cea, fpos+(packed-packed_buf.begin()));
  if ( packed == nullptr )
    return 0;

  // unpack far above a4
  if ( size < sizeof(int32) )
    goto BADDATA;
  cea = a4 + swap32(*(int32*)packed);
  packed += sizeof(int32);
  size -= sizeof(uint32);
  packed = unpack_rle(packed, size, cea, fpos+(packed-packed_buf.begin()));
  if ( packed == nullptr )
    return 0;

  cea -= ea;
  if ( usize < cea )
    usize = (size_t)cea;

  // process relocations
  if ( size > 0 )
  {
    // a4 to a4
    // msg("Relocations: a4 to a4\n");
    packed = apply_relocs(packed, size, a4, a4);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  if ( size > 0 )
  {
    // a4 to a5
    // msg("Relocations: a4 to a5\n");
    packed = apply_relocs(packed, size, a4, a5);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  if ( size > 0 )
  {
    // a4 to code1
    // msg("Relocations: a4 to code1\n");
    packed = apply_relocs(packed, size, a4, code1ea, true);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  if ( size > 0 )
  {
    // a5 to a4
    // msg("Relocations: a5 to a4\n");
    packed = apply_relocs(packed, size, a5, a4);
    if ( packed == nullptr )
      return 0;
    // packed = (uchar*)__Relocate__((Int8*)packed, 0, 0);
  }
  return usize;
}

//------------------------------------------------------------------------
void fix_jumptables(ea_t ea1, ea_t /*ea2*/, sel_t sel, ea_t a5, ea_t a4)
{
  // msg("Fixing additional code segment at %08X\n", ea1);
  // from PalmOS_Startup.cpp
  /*
  struct SegmentHeader {  // the structure of a segment header
    short   jtsoffset;                      // A5 relative offset of this segments jump table (short version)
    short   jtentries;                      // number of entries in this segments jump table
    int32    jtloffset;                     // A5 relative offset of this segments jump table (long version)
    int32    xrefoffset;                    // offset of xref data in this CODE resource
    char    code[];                           // the code
  };
  struct JumpTableEntry { // the structure of a jumptable entry
    short   jumpinstruction;        // instruction: jmp routine
    int32    jumpaddress;           // absolute or relative address of rountine
  };*/

  short jtsoffset = get_word(ea1);
  int32 jtloffset = get_dword(ea1+4);
  if ( jtsoffset != jtloffset )
  {
    // msg("Doesn't look like a CodeWarrior code segment\n");
    return;
  }
  // find the jumptable
  ea_t jt_start;
  if ( a4 != BADADDR && get_word(a4+jtloffset) == 0x4EF9 ) // jmp opcode
  {
    jt_start = a4+jtloffset;
    create_word(ea1, 2);
    create_dword(ea1+4, 4);
    op_offset(ea1, 0, REF_OFF16|REFINFO_SIGNEDOP, BADADDR, a4);
    op_offset(ea1+4, 0, REF_OFF32|REFINFO_SIGNEDOP, BADADDR, a4);
  }
  else if ( get_word(a5+jtloffset) == 0x4EF9 ) // jmp opcode
  {
    jt_start = a5 + jtloffset;
    create_word(ea1, 2);
    create_dword(ea1+4, 4);
    op_offset(ea1, 0, REF_OFF16|REFINFO_SIGNEDOP, BADADDR, a5);
    op_offset(ea1+4, 0, REF_OFF32|REFINFO_SIGNEDOP, BADADDR, a5);
  }
  else
  {
    // msg("Could not find the jump table!\n");
    return;
  }

  create_word(ea1+2, 2);
  create_dword(ea1+8, 4);
  op_offset(ea1+8, 0, REF_OFF32, BADADDR, ea1);
  set_cmt(ea1, "Short jump table offset", 0);
  set_cmt(ea1+2, "Number of jump table entries", 0);
  set_cmt(ea1+4, "Long jump table offset", 0);
  set_cmt(ea1+8, "Offset to xref data", 0);

  fixup_data_t fd(FIXUP_OFF32);
  fd.sel = sel;
  ea_t jt_addr=jt_start;
  short   jtentries = get_word(ea1+2);
  while ( jtentries-- )
  {
    fd.off = get_dword(jt_addr+2);
    fd.set(jt_addr+2);
    // a little heuristic: does the jump point to code?
    if ( get_word(ea1+fd.off) == 0x4E56   // link a6, x
      || get_word(ea1+fd.off) == 0x06AF ) // addi.l x, 4(sp)
    {
      auto_make_proc(ea1+fd.off);
      auto_make_proc(jt_addr);
    }
    jt_addr+=6;
  }
  // TODO: hide the table?
  // add_hidden_range(jt_start, jt_addr, "Jumptable for segment NNN", "", "", 0);
}

//------------------------------------------------------------------------
void doCodeOffset(ea_t ea, ea_t base)
{
  create_dword(ea, 4);
  uint32 off = get_dword(ea);
  op_offset(ea, 0, REF_OFF32, BADADDR, base, off&1);
  ea_t target = base+off;
  if ( off&1 )// last bit set: offset to thumb code
  {
    target &= (~1); // remove last bit
    // set_sreg_at_next_code(target, BADADDR, str2reg("T"), 1);
    split_sreg_range(target, str2reg("T"), 1, SR_auto, true);
  }
  auto_make_proc(target);
}

//------------------------------------------------------------------------
void fixArmCW(ea_t start_ea, ea_t end_ea)
{
  // check for codewarrior relocation info
  /*
  typedef struct PnoHeaderType {
    00 UInt32 startupCode[8];       // changes based on the instruction count in startup code
    20 UInt32 pnoMain;         // offset to ARMletMain routine
    24 UInt32 signature;       // special PNO signature value
    28 UInt32 dataStart;       // offset to start of initialized data
    2C UInt32 roDataStart;     // offset to start of read-only initialized data
    30 UInt32 bssStart;        // offset to start of uninitialized data
    34 UInt32 bssEnd;          // offset to end of uninitialized data
    38 UInt32 codeRelocsStart; // offset to start of data-to-code relocation list
    3C UInt32 codeRelocsEnd;   // offset to end of data-to-code relocation list
    40 UInt32 dataRelocsStart; // offset to start of data-to-data relocation list
    44 UInt32 dataRelocsEnd;   // offset to end of data-to-data relocation list
    48 UInt32 altEntryCode[8];      // changes based on the instruction count in alternate entry code
    68
  } PnoHeaderType;
  */
  const char *const comments[] =
  {
    "offset to ARMletMain routine",
    "special PNO signature value",
    "offset to start of initialized data",
    "offset to start of read-only initialized data",
    "offset to start of uninitialized data",
    "offset to end of uninitialized data",
    "offset to start of data-to-code relocation list",
    "offset to end of data-to-code relocation list",
    "offset to start of data-to-data relocation list",
    "offset to end of data-to-data relocation list",
  };

  if ( end_ea-start_ea < 0x68 )
    return;
  for ( int i=0x20; i < 0x48; i+=4 )
  {
    create_dword(start_ea+i, 4);
    if ( i == 0x24 )
      op_chr(start_ea+i, 0);
    else
      op_offset(start_ea+i, 0, REF_OFF32, BADADDR, start_ea);
    set_cmt(start_ea+i, comments[(i-0x20)/4], 0);
  }
  auto_make_proc(start_ea);
  auto_make_proc(start_ea+0x48);
  doCodeOffset(start_ea+0x20, start_ea);

  // do relocs
  ea_t cur = start_ea+get_dword(start_ea+0x38);
  ea_t end = start_ea+get_dword(start_ea+0x3C);
  for ( ; cur < end; cur+=4 )
  {
    create_dword(cur, 4);
    op_offset(cur, 0, REF_OFF32, BADADDR, start_ea);
    doCodeOffset(start_ea+get_dword(cur), start_ea);
  }
  cur = start_ea+get_dword(start_ea+0x40);
  end = start_ea+get_dword(start_ea+0x44);
  for ( ; cur < end; cur+=4 )
  {
    create_dword(cur, 4);
    op_offset(cur, 0, REF_OFF32, BADADDR, start_ea);
    ea_t o = start_ea+get_dword(cur);
    create_dword(o, 4);
    op_offset(o, 0, REF_OFF32, BADADDR, start_ea);
  }
}

//------------------------------------------------------------------------
// check for 'cdwr' signature
bool isCWseg(linput_t *li, uint32 offset)
{
  qlseek(li, offset + 0x24);
  uchar sig[4];
  qlread(li, sig, 4);
  return sig[0] == 'r'
      && sig[1] == 'w'
      && sig[2] == 'd'
      && sig[3] == 'c';
}

//------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort neflags, const char * fileformatname)
{
  int i;
  bool armCode = strcmp(fileformatname, PRC_ARM) == 0;
  bool manualMode = (neflags & NEF_MAN) != 0; // don't do any extra processing if set
  sel_t dgroup = BADSEL;

  inf_set_app_bitness(32);
  set_processor_type(armCode ? "ARM" : "68K", SETPROC_LOADER);
  set_target_assembler(armCode ? 0 : 2); // Generic ARM assembler/PalmPilot assembler Pila
  DatabaseHdrType h;
  lread(li, &h, sizeof(h));
  swap_prc(h);

  qvector<ResourceMapEntry> re;
  re.resize(h.numRecords);
  lread(li, re.begin(), sizeof(ResourceMapEntry) * h.numRecords);
  for ( i=0; i < h.numRecords; i++ )
    swap_resource_map_entry(re[i]);

  code0000_t code0000 = { 0, 0 };
  if ( !armCode )
  {
    // sortResources(re, h.numRecords);
    // determine the bss size
    for ( i=0; i < h.numRecords; i++ )
    {
      if ( re[i].fcType == PILOT_RSC_CODE && re[i].id == 0 ) // code0000
      {
        qlseek(li, re[i].ulOffset);
        lread(li, &code0000, sizeof(code0000));
        swap_code0000(&code0000);
        break;
      }
    }
  }

  ea_t a5 = BADADDR, a4 = BADADDR, code1ea = BADADDR;
  ea_t datastart = BADADDR;

  // load the segments
  for ( i=0; i < h.numRecords; i++ )
  {
    // don't load known UI resources when asked not to
    if ( !(NEF_RSCS & neflags) && isKnownResource(re[i].fcType) )
      continue;
    // skip ARM chunks in 68K mode
    if ( !armCode && (re[i].fcType == PILOT_RSC_ARMC || re[i].fcType == PILOT_RSC_ARMCL) )
      continue;

    uint64 size;
    if ( i == (h.numRecords-1) )
      size = qlsize(li);
    else
      size = re[i+1].ulOffset;
    if ( size < re[i].ulOffset )
      loader_failure("Invalid file structure");
    size -= re[i].ulOffset;
    ea_t ea1 = (inf_get_max_ea() + 0xF) & ~0xF;
    ea_t ea2 = ea1 + size;

    char segname[10];
    qsnprintf(segname, sizeof(segname), "%4.4s%04X", (char*)&re[i].fcType, re[i].id);
    const char *sclass = "RSC";

    if ( armCode )
    {
      // load only ARM segments in ARM mode
      if ( re[i].fcType != PILOT_RSC_ARMC && re[i].fcType != PILOT_RSC_ARMCL )
        continue;

      bool bCodeWarrior = isCWseg(li, re[i].ulOffset);

      ea_t start_ea=ea1;
      file2base(li, re[i].ulOffset, ea1, ea2, FILEREG_PATCHABLE);
      int sel = i+1;
      if ( bCodeWarrior && !manualMode )
      {
        // load all sequential chunks as one segment
        while ( i < h.numRecords-1 && re[i].fcType == re[i+1].fcType && re[i].id + 1 == re[i+1].id && !isCWseg(li, re[i+1].ulOffset) )
        {
          i++;
          if ( i == (h.numRecords-1) )
            size = qlsize(li);
          else
            size = re[i+1].ulOffset;
          if ( size < re[i].ulOffset )
            loader_failure("Invalid file structure");
          size -= re[i].ulOffset;
          ea1 = ea2; // TODO: check if pnoloader.c does alignment
          ea2 = ea1 + size;
          file2base(li, re[i].ulOffset, ea1, ea2, FILEREG_PATCHABLE);
        }
      }
      set_selector(sel, start_ea >> 4);
      if ( !add_segm(sel, start_ea, ea2, segname, CLASS_CODE, ADDSEG_SPARSE) )
        loader_failure();

      // set DS for the segment to itself
      set_default_sreg_value(get_segm_by_sel(sel), str2reg("DS"), sel);
      if ( bCodeWarrior )
        fixArmCW(start_ea, ea2);
      continue;
    }

    if ( re[i].fcType == PILOT_RSC_CODE )
    {
      if ( re[i].id == 0 && !manualMode )
        continue;  // skip code0000 resource
      sclass = CLASS_CODE;
      if ( re[i].id == 1 )
      {
        inf_set_start_cs(i + 1);
        inf_set_start_ip(0);
        code1ea = ea1;
      }
    }
    else if ( re[i].fcType == PILOT_RSC_LIBR || re[i].fcType == PILOT_RSC_GLIB )
    {
      sclass = CLASS_CODE;
      if ( re[i].id == 0 )
      {
        inf_set_start_cs(i + 1);
        inf_set_start_ip(0);
        code1ea = ea1;
      }
    }

    // check if we need to decompress stuff
    if ( re[i].fcType == PILOT_RSC_DATA && re[i].id == 0 )
    {
      sclass = CLASS_DATA;
      dgroup = i + 1;
      size_t usize = unpack_data0000(li, re[i].ulOffset, size, ea1, code0000, code1ea, a5);
      ea2 = ea1 + usize;
      datastart = ea1;
    }
    else if ( re[i].fcType == PILOT_RSC_DATA && re[i].id == 1 && !manualMode )
    {
      sclass = CLASS_DATA;
      size_t usize = unpack_data0001(li, re[i].ulOffset, size, ea1, a5, code1ea, a4);
      ea2 = ea1 + usize;
    }
    else
    {
      // otherwise just load it as-is
      file2base(li, re[i].ulOffset, ea1, ea2, FILEREG_PATCHABLE);
    }

    {
      segment_t s;
      s.start_ea = ea1;
      s.end_ea = ea2;
      s.sel = i+1;
      s.bitness = 1;    // 32bit
      set_selector(i+1, ea1 >> 4);
      if ( !add_segm_ex(&s, segname, sclass, ADDSEG_FILLGAP|ADDSEG_OR_DIE|ADDSEG_SPARSE) )
        loader_failure();
    }
  }

  if ( !manualMode && !armCode )
  {
    // check if first dword is 1; if so, skip it
    if ( get_dword(code1ea) == 1 )
    {
      // codewarrior startup
      static const uchar pattern[] =
      {
        0x00, 0x00, 0x00, 0x01,              // dc.l 1
        0x48, 0x7A, 0x00, 0x04,              // pea  $A
        0x06, 0x97, 0xFF, 0xFF, 0xFF, 0xFF,  // addi.l  #(__Startup__-$A), (sp)
        0x4E, 0x75,                          // rts
      };
      if ( equal_bytes(code1ea, pattern, SKIP_FF_MASK, sizeof(pattern), BIN_SEARCH_CASE) )
      {
        plan_to_apply_idasgn("cwpalm.sig");
      }
      create_dword(code1ea, 4);
      inf_set_start_ip(4);
    }
    // is main code segment GLib?
    if ( inf_get_start_cs() > 0
      && re[int(inf_get_start_cs()-1)].fcType == PILOT_RSC_GLIB
      && a4 == BADADDR
      && datastart != BADADDR )
    {
      // GLib's a4 points at the start of data segment
      a4 = datastart;
      create_byte(a4, 1);
      set_name(a4, "A4BASE", SN_NOCHECK|SN_AUTO);
      set_cmt(a4, "A4 points here", 0);
    }
    // check for CodeWarrior's jumptables in additional code segments and fix them up
    for ( i=0; i < h.numRecords; i++ )
    {
      if ( re[i].fcType == PILOT_RSC_CODE && re[i].id > 1 )
      {
        segment_t *seg = get_segm_by_sel(i+1);
        if ( seg != nullptr )
          fix_jumptables(seg->start_ea, seg->end_ea, i+1, a5, a4);
      }
    }
    // TODO: handle prc-tools and multilink's 'rloc' segments
  }

  if ( dgroup != BADSEL )
    set_default_dataseg(dgroup);  // input: selector
  describe_all(h);
  exec_system_script("pilot.idc");
}

//--------------------------------------------------------------------------
// it is impossible to use ph.id,
// the processor module is not loaded yet
inline bool is_arm_specified(void)
{
  return strnieq(inf_get_procname().c_str(), "ARM", 3);
}

inline bool is_68k_specified(void)
{
  char pname[IDAINFO_PROCNAME_SIZE];
  inf_get_procname(pname, sizeof(pname));
  return strnieq(pname, "68K", 3)
      || strnieq(pname, "68000", 5)
      || strnieq(pname, "68010", 5)
      || strnieq(pname, "68020", 5)
      || strnieq(pname, "68030", 5)
      || strnieq(pname, "68040", 5)
      || strnieq(pname, "68330", 5)
      || strnieq(pname, "68882", 5)
      || strnieq(pname, "68851", 5)
      || strnieq(pname, "ColdFire", 8);
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  static int n = 0;
  int k = is_prc_file(li);
  if ( k == 0 )
    return 0;
  int ftype = 0;
  if ( n == 1 )
  {
    if ( k == 2 ) // has ARM segments?
    {
      *fileformatname = PRC_ARM;
      *processor      = "ARM";
      ftype = f_PRC;
      if ( is_arm_specified() )
        ftype |= ACCEPT_FIRST;
    }
  }
  else
  {
    n++;
    *fileformatname = PRC_68K;
    *processor      = "68K";
    ftype = f_PRC|ACCEPT_CONTINUE;
    if ( is_68k_specified() )
      ftype |= ACCEPT_FIRST;
  }
  return ftype;
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  nullptr,
//      take care of a moved segment (fix up relocations, for example)
  nullptr,
  nullptr,
};
