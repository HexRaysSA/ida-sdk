/*
 *      Interactive disassembler (IDA).
 *      Version 4.20
 *      Copyright (c) 2002 by Ilfak Guilfanov. (ig@datarescue.com)
 *      ALL RIGHTS RESERVED.
 *
 *      Intel OMF386
 *
 */


#include "../idaldr.h"
#include "intelomf.hpp"
#include "common.cpp"

static lmh h;
static ea_t xea;
static sel_t dsel = BADSEL;
//--------------------------------------------------------------------------
static void create32(
        sel_t sel,
        ea_t start_ea,
        ea_t end_ea,
        const char *name,
        const char *sclass)
{
  set_selector(sel, 0);

  segment_t s;
  s.sel     = sel;
  s.start_ea = start_ea;
  s.end_ea   = end_ea;
  s.align   = saRelByte;
  s.comb    = sclass != nullptr && streq(sclass, "STACK") ? scStack : scPub;
  s.bitness = 1; // 32-bit

  if ( !add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE) )
    loader_failure();
}

//-----------------------------------------------------------------------
static void show_segdefs(linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 )
    return;
  qlseek(li, offset);
  int n = 0;
  for ( int i=0; i < length; )
  {
    if ( qltell(li) >= qlsize(li) )
BAD_FILE:
      loader_failure("Corrupted segmentation info");
    segdef s;
    const int size = offsetof(segdef, combine_name);
    lread(li, &s, size);
    int nlen = read_pstring(li, s.combine_name, sizeof(s.combine_name));
    i += size + 1 + nlen;
    n++;

    const char *sname = s.combine_name;
    const char *sclas = sname;
    if ( strnicmp(sname, "CODE", 4) == 0 )
      sclas = "CODE";
    if ( strnicmp(sname, "DATA", 4) == 0 )
      sclas = "DATA";
    if ( strnicmp(sname, "CONST", 5) == 0 )
      sclas = "CONST";
    if ( stricmp(sname, "STACK") == 0 )
      sclas = "STACK";
    if ( strchr(sname, ':') != nullptr )
      continue;

    int segsize = s.slimit + 1;
    if ( segsize < 0 || qltell(li) >= qlsize(li) )
      goto BAD_FILE;

    if ( strcmp(sname, "DATA") == 0 )
      dsel = n;
    set_selector(n, 0);
    ea_t ea = find_free_chunk(inf_get_max_ea(), segsize, (1<<s.align)-1);
    create32(n, ea, ea+segsize, sname, sclas);
  }
}

//-----------------------------------------------------------------------
static ea_t getsea(ushort i)
{
  segment_t *s = get_segm_by_sel(i & 0xFF);
  return s ? s->start_ea : BADADDR;
}

//-----------------------------------------------------------------------
static void show_pubdefs(const ea_helper_t &eah, linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 )
    return;
  qlseek(li, offset);
  for ( int i=0; i < length; )
  {
    pubdef p;
    const int size = offsetof(pubdef, sym_name);
    if ( qlread(li, &p, size) != size )
      loader_failure("Corrupted pubdefs");
    int nlen = read_pstring(li, p.sym_name, sizeof(p.sym_name));
    i += size + 1 + nlen;

    ea_t sea = getsea(p.PUB_segment);
    if ( sea != BADADDR )
    {
      sea = eah.trunc_uval(sea + p.PUB_offset);
      add_entry(sea, sea, p.sym_name, segtype(sea) == SEG_CODE, AEF_IDBENC);
    }
  }
}

//-----------------------------------------------------------------------
static void show_extdefs(const ea_helper_t &eah, linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 )
    return;
  qlseek(li, offset);

  uchar ss = inf_is_64bit() ? 8 : 4;
  inf_set_specsegs(ss);
  int16 segsize = ss * h.num_externals;
  if ( !is_mul_ok(uint16(ss), uint16(h.num_externals))
    || segsize < 0
    || segsize < h.num_externals )
  {
BAD_EXTDEFS:
    loader_failure("Corrupted extdefs");
  }
  sel_t sel = h.num_segs+1;
  set_selector(sel, 0);
  xea = find_free_chunk(inf_get_max_ea(), segsize, 15);
  create32(sel, xea, xea+segsize, "XTRN", "XTRN");

  int n = 0;
  for ( int i=0; i < length; )
  {
    extdef p;
    const int size = offsetof(extdef, allocate_len);
    if ( qlread(li, &p, size) != size )
      goto BAD_EXTDEFS;
    p.allocate_len.len_4 = 0;
    if ( p.allocate != 0 )
    {
      ask_for_feedback("extdef.allocate\n");
      lread(li, &p.allocate_len.len_4, sizeof(p.allocate_len.len_4));
    }
    int nlen = read_pstring(li, p.sym_name, sizeof(p.sym_name));
    i += size + 1 + nlen;

    ea_t a = eah.trunc_uval(xea + 4 * n++);
    set_name(a, p.sym_name, SN_IDBENC);
    if ( p.allocate )
      put_dword(a, p.allocate_len.len_4);
  }
}

//-----------------------------------------------------------------------
static void read_text(const ea_helper_t &eah, linput_t *li)
{
  text txt;
  const int size = offsetof(text, segment);
  if ( qlread(li, &txt, size) != size || txt.length < 0 )
    loader_failure("Corrupted text data");
  if ( txt.length != 0 )
  {
    qoff64_t fptr = qltell(li);
    ea_t sea = getsea(txt.txt_IN);
    if ( sea != BADADDR )
    {
      ea_t start = eah.trunc_uval(sea + txt.txt_offset);
      ea_t end   = eah.trunc_uval(start + txt.length);
      uint64 fsize = qlsize(li);
      segment_t *s = getseg(start);
      if ( start < sea
        || end < start
        || fptr > fsize
        || fsize-fptr < txt.length
        || s == nullptr
        || s->end_ea < end )
      {
        loader_failure("Corrupted text data");
      }
      if ( change_storage_type(start, end, STT_VA) != eOk )
        INTERR(20060);
      file2base(li, fptr, start, end, FILEREG_PATCHABLE);
    }
    qlseek(li, fptr+txt.length);
  }
}

//-----------------------------------------------------------------------
static void read_fixup(const ea_helper_t &eah, linput_t *li)
{
  fixup fix;
  const int size = offsetof(fixup, fixups);
  if ( qlread(li, &fix, size) != size || fix.length < 0 )
    loader_failure("Corrupted fixups");
  qoff64_t fptr = qltell(li);
  ea_t sea = getsea(fix.where_IN);
  if ( sea != BADADDR )
  {
    validate_array_count(li, &fix.length, 1, "Fixup count");
    uchar *b = (uchar *)qalloc(fix.length);
    if ( b == nullptr )
      nomem("read_fixup");
    lread(li, b, fix.length);

//    show_hex(b, fix.length, "\nFIXUP SEG %04X, %04X BYTES, KIND %02X\n",
//                  fix.where_IN,
//                  fix.length,
//                  b[0]);

    const uchar *ptr = b;
    const uchar *end = b + fix.length;
    while ( ptr < end )
    {
      uint32 where_offset = 0;
      uint32 what_offset = 0;
      ushort what_in = 9;
      bool selfrel = false;
      bool isfar = false;
      fixup_data_t fd(FIXUP_OFF32);
      switch ( *ptr++ )
      {
        case 0x2C:      // GEN
          isfar = true;
          ask_for_feedback("Untested relocation type");
        case 0x24:      // GEN
          where_offset = readdw(ptr, false);
          what_offset = readdw(ptr, false);
          what_in = (ushort)readdw(ptr, false);
          break;
        case 0x2D:
          isfar = true;
        case 0x25:      // INTRA
          where_offset = readdw(ptr, false);
          what_offset = readdw(ptr, false);
          what_in = fix.where_IN;
          break;
        case 0x2A:      // CALL
          where_offset = readdw(ptr, false);
          what_offset = 0;
          what_in = (ushort)readdw(ptr, false);
          selfrel = true;
          break;
        case 0x2E:      // OFF32?
          isfar = true;
        case 0x26:
          where_offset = readdw(ptr, false);
          what_offset = 0;
          what_in = (ushort)readdw(ptr, false);
          break;
        default:
          ask_for_feedback("Unknown relocation type %02X", ptr[-1]);
          add_pgm_cmt("!!! Unknown relocation type %02X", ptr[-1]);
          break;
      }
      ea_t source = eah.trunc_uval(sea + where_offset);
      ea_t target = BADADDR;
      switch ( what_in >> 12 )
      {
        case 0x02:      // segments
          target = getsea(what_in);
          break;
        case 0x06:      // externs
          target = eah.trunc_uval(xea + 4 * ((what_in & 0xFFF) - 1));
          fd.set_extdef();
          break;
        default:
          ask_for_feedback("Unknown relocation target %04X", what_in);
          add_pgm_cmt("!!! Unknown relocation target %04X", what_in);
          break;
      }
      fd.set_target_sel();
      if ( !fd.is_extdef() )
      {
        target = eah.trunc_uval(target + what_offset);
        what_offset = 0;
      }
      fd.off = eah.trunc_uval(target - fd.get_base());
      fd.displacement = what_offset;
      target = eah.trunc_uval(target + what_offset);
      if ( selfrel )
        target = eah.trunc_uval(target - source - 4);
      fd.set(source);
      put_dword(source, target);
      if ( isfar )
      {
        fd.set_type_and_flags(FIXUP_SEG16);
        fd.set(eah.trunc_uval(source+4));
        put_word(eah.trunc_uval(source+4), fd.sel);
      }
    }
    qfree(b);
  }
  qlseek(li, fptr + fix.length);
}

//-----------------------------------------------------------------------
static void read_iterat(const ea_helper_t &eah, linput_t *li)
{
  iterat itr;
  const int size = offsetof(iterat, text) + offsetof(temp, value);
  lread(li, &itr, size);
  itr.text.value = nullptr;
  if ( itr.text.length != 0 )
  {
    if ( itr.text.length < 0 || itr.it_count < 0 )
BAD_FILE:
      loader_failure("Corrupted iterated data");
    qoff64_t fptr = qltell(li);
    ea_t sea = getsea(itr.it_segment);
    if ( sea != BADADDR )
    {
      uint64 fsize = qlsize(li);
      ea_t start = eah.trunc_uval(sea + itr.it_offset);
      segment_t *s = getseg(start);
      if ( start < sea
        || fptr > fsize
        || fsize-fptr < itr.text.length
        || !is_mul_ok(uint32(itr.text.length), uint32(itr.it_count))
        || s == nullptr )
      {
        goto BAD_FILE;
      }
      uint32 total = itr.text.length * itr.it_count;
      ea_t final_end = eah.trunc_uval(start + total);
      if ( final_end < start || final_end > s->end_ea )
        goto BAD_FILE;
      if ( change_storage_type(start, final_end, STT_VA) != eOk )
        INTERR(20061);
      for ( int i=0; i < itr.it_count; i++ )
      {
        ea_t end = eah.trunc_uval(start + itr.text.length);
        file2base(li, fptr, start, end, FILEREG_PATCHABLE);
        start = end;
      }
    }
    qlseek(li, fptr+itr.text.length);
  }
}

//-----------------------------------------------------------------------
static void show_txtfixs(const ea_helper_t &eah, linput_t *li, uint32 offset, uint32 length)
{
  if ( offset == 0 || length == 0 )
    return;
  uint64 fsize = qlsize(li);
  uint64 eoff = offset + length;
  if ( eoff < offset || offset > fsize || eoff > fsize )
    loader_failure("Corrupted fixups");
  qlseek(li, offset);
  while ( qltell(li) < eoff )
  {
    char type;
    lread(li, &type, sizeof(type));
    switch ( type )
    {
      case 0:
        read_text(eah, li);
        break;
      case 1:
        read_fixup(eah, li);
        break;
      case 2:
        read_iterat(eah, li);
        break;
      default:
        ask_for_feedback("txtfix.blk_type == %d!\n", type);
        return;
    }
  }
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  if ( is_intelomf_file(li) )
  {
    *fileformatname = "Intel OMF386";
    *processor      = "metapc";
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  set_processor_type("metapc", SETPROC_LOADER);
  inf_set_app_bitness(32);

  qlseek(li, 1);
  lread(li, &h, sizeof(h));

  toc_p1 toc;
  lread(li, &toc, sizeof(toc));

  const ea_helper_t &eah = EAH;
  // we add one to skip the magic byte
  show_segdefs(li, toc.SEGDEF_loc+1, toc.SEGDEF_len);
  show_pubdefs(eah, li, toc.PUBDEF_loc+1, toc.PUBDEF_len);
  show_extdefs(eah, li, toc.EXTDEF_loc+1, toc.EXTDEF_len);
  show_txtfixs(eah, li, toc.TXTFIX_loc+1, toc.TXTFIX_len);

  if ( dsel != BADSEL )
    set_default_dataseg(dsel);
  add_pgm_cmt("Module: %*.*s", h.mod_name[0], uchar(h.mod_name[0]), &h.mod_name[1]);
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                   // loader flags
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
  nullptr,
  nullptr,
};
