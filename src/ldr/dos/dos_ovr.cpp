/*
 *  This Loader Module is written by Ilfak Guilfanov and
 *                        rewriten by Yury Haron
 *
 */
/*
  L O A D E R  pard of MS-DOS file format's (overlayed EXE)
*/

#include "../idaldr.h"
#include <exehdr.h>
#include <typeinf.hpp>
#include "dos_ovr.h"

static const char *const stub_class    = "STUBSEG";
static const char *const stub_name_fmt = "stub%03d";
static const char *const ovr_class     = "OVERLAY";
static const char *const ovr_name_fmt  = "ovr%03d";

static uint32 ovr_off = 0;

//------------------------------------------------------------------------
o_type PrepareOverlayType(linput_t *li, exehdr *E)
{
  uint32 flen = qlsize(li);
  uint32 base = E->HdrSize * 16;
  uint32 loadend = base + E->CalcEXE_Length();
  uint32 fbovoff;
  fbov_t fbov;

  ovr_off = 0;

  for ( fbovoff = (loadend + 0xF) & ~0xF; ; fbovoff += 0x10 )
  {
    if ( pos_read(li, fbovoff, &fbov, sizeof(fbov)) )
      break;
    if ( fbov.fb != FB_MAGIC )
      break;
    if ( fbov.ov == OV_MAGIC )
    {
      ovr_off = fbovoff;
      return (fbov.exeinfo > loadend
           || fbov.ovrsize > (flen - fbovoff)
           || fbov.segnum <= 0)
           ? ovr_pascal
           : ovr_cpp;
    }
  }

  exehdr e1;
  fbovoff = (loadend + 511) & ~511;
  flen -= fbovoff;
  if ( !pos_read(li, fbovoff, &e1, sizeof(e1))
    && e1.exe_ident == EXE_ID  // only MZ !
    && flen >= (base = e1.HdrSize*16)
    && e1.TablOff + (e1.ReloCnt*4) <= (flen -= base)
    && e1.CalcEXE_Length() <= flen )
  {
    ovr_off = fbovoff;
    return ovr_ms;
  }
  return ovr_noexe;
}

//------------------------------------------------------------------------
static bool isStubPascal(ea_t ea)
{
  return get_word(ea) == 0x3FCD            // int 3F
      && (int32)get_dword(ea+4) > 0         // fileoff
      && get_word(ea+8) != 0               // codesize
      && (short)get_word(ea+10) >= 0       // relsize (assume max 32k)
      && (short)get_word(ea+12) > 0        // nentries
      && (short)get_word(ea+12) < (0x7FFF / sizeof(ovrentry_t)) // nentries
      && is_mapped(to_ea(inf_get_baseaddr() + get_word(ea+14), 0)); // prevstub
}

//------------------------------------------------------------------------
linput_t *CheckExternOverlays(void)
{
  char buf[MAXSTR];
  const char *p;
  if ( get_input_file_path(buf, sizeof(buf)) <= 0
    || (p=strrchr(buf, '.')) == nullptr
    || stricmp(++p, e_exe) != 0 )
  {
    return nullptr;
  }

  for ( segment_t *s = get_first_seg(); s != nullptr; s = get_next_seg(s->start_ea) )
  {
    ea_t ea = s->start_ea;
    if ( isStubPascal(ea) )
    {
      switch ( ask_yn(ASKBTN_NO,
                      "This file contains reference to Pascal-stype overlays\n"
                      "Do you want to load it?") )
      {

        case ASKBTN_NO:
          return nullptr;
        case ASKBTN_CANCEL:
          loader_failure();
        default:  // Yes
          break;
      }
      while ( true )
      {
        p = ask_file(false,
                     set_file_ext(buf, sizeof(buf), buf, "ovr"),
                     "Please enter pascal overlays file");
        CheckCtrlBrk();
        if ( p == nullptr )
          return nullptr;

        linput_t *li = open_linput(p, false);
        if ( li != nullptr )
          return li;
        warning("Pascal style overlays file '%s' is not found", p);
      }
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------
static void removeBytes(void)
{
  ea_t ea = inf_get_omin_ea();

  msg("Deleting bytes which do not belong to any segment...\n");
  for ( int i = 0; ; ++i )
  {
    if ( ea >= inf_get_omax_ea() )
      break;

    segment_t *sptr = getnseg(i);

    if ( ea < sptr->start_ea )
    {
      show_addr(ea);
      deb(IDA_DEBUG_LDR,
          "Deleting bytes at %a..%a (they do not belong to any segment)...\n",
          ea,
          sptr->start_ea);
      if ( disable_flags(ea,sptr->start_ea) )
      {
        warning("Maximal number of segments is reached, some bytes are out of segments");
        return;
      }
      CheckCtrlBrk();
    }
    ea = sptr->end_ea;
  }
}

//------------------------------------------------------
static void describeStub(ea_t stubEA)
{
  static const char stubSname[] = "_stub_descr";
  static tid_t id = 0;

  if ( id == 0
    && (id=get_named_type_tid(stubSname)) == BADADDR )
  {
    qstring decl;
    decl.sprnt(
          "struct %s\n"
          "{\n"
          "  char int_code[2] __tabform(,8);     ///< Overlay manager interrupt\n"
          "  __int16 memswap;                    ///< Runtime memory swap address\n"
          "  __int32 fileoff;                    ///< Offset in the file to the code\n"
          "  __int16 codesize;                   ///< Code size\n"
          "  __int16 relsize;                    ///< Relocation area size\n"
          "  __int16 nentries __udec;            ///< Number of overlay entries\n"
          "  __int16 prevstub __segm;            ///< Previous stub\n"
          "  char workarea[%d] __tabform(,8);\n"
          "};",
          stubSname,
          STUBUNK_SIZE);
    parse_decls(nullptr, decl.c_str(), msg, HTI_DCL);
    set_type_choosable(nullptr, get_type_ordinal(nullptr, stubSname), false);
    id = get_named_type_tid(stubSname);
  }

  ushort tmp = get_word(stubEA + offsetof(stub_t, prevstub));
  if ( tmp != 0 )
    put_word(stubEA + offsetof(stub_t, prevstub), uint16(tmp + inf_get_baseaddr()));

  tmp = get_word(stubEA + offsetof(stub_t, nentries));

  if ( id != BADNODE )
  {
    del_items(stubEA, DELIT_EXPAND, sizeof(stub_t));
    create_struct(stubEA, sizeof(stub_t), id);
  }

  stubEA += sizeof(stub_t);

  if ( tmp != 0 )
  {
    do
    {
      auto_make_proc(stubEA);
      stubEA += 5;
      CheckCtrlBrk();
    } while ( --tmp );
  }
}

//------------------------------------------------------------------------
static void load_overlay(
        linput_t *li,
        uint32 exeinfo,
        ea_t stubEA,
        segment_t *s,
        qoff64_t fboff)
{
  ea_t entEA = stubEA + sizeof(stub_t);
  stub_t stub;

  if ( get_bytes(&stub, sizeof(stub), stubEA) != sizeof(stub) )
    errstruct();
  msg("Overlay stub at %a, code at %a...\n", stubEA, s->start_ea);
  if ( stub.CDh != 0xCD )
    errstruct();   // bad stub

  // i now load overlay code:
  bool waszero = false;
  if ( !stub.codesize ) // IDA  doesn't allow 0 length segments
  {
    ++stub.codesize;
    waszero = true;
  }
  s->end_ea = s->start_ea + stub.codesize;
  file2base(li, fboff+stub.fileoff, s->start_ea, s->end_ea,
            fboff == 0
          ? FILEREG_NOTPATCHABLE
          : FILEREG_PATCHABLE);
  if ( waszero )
  {
    s->type = SEG_NULL;
    stub.codesize = 0;
  }

  uint i;
  for ( i = 0; i < stub.nentries; ++i )
  {
    show_addr(entEA);
    put_byte(entEA, 0xEA);     // jmp far
    ushort offset = get_word(entEA+2);
    put_word(entEA+1, offset); // offset
    put_word(entEA+3, s->sel); // selector
    auto_make_proc(to_ea(sel2para(s->sel), offset));
    entEA += sizeof(ovrentry_t);
    CheckCtrlBrk();
  }

  qoff64_t fpos = fboff + stub.fileoff + stub.codesize;
  qlseek(li, fpos);

  fixup_data_t fd(FIXUP_SEG16);

  uint relcnt = stub.relsize / 2;
  validate_array_count(li, &relcnt, sizeof(ushort), "Relocation count", fpos);
  if ( relcnt != 0 )
  {
    ushort *relb = qalloc_array<ushort>(relcnt);
    if ( !relb )
      nomem("overlay relocation table");

    lread(li, relb, sizeof(ushort)*relcnt);
    int32 pos = qltell(li); // must??

    ushort *relc = relb;
    do
    {
      if ( *relc > stub.codesize )
        errstruct();

      ea_t xEA = s->start_ea + *relc++;
      show_addr(xEA);
      ushort relseg = get_word(xEA);
      if ( exeinfo != 0 )
      {
        seginfo_t si;

        if ( pos_read(li, exeinfo + relseg, &si, sizeof(si)) )
          errstruct();
        relseg = si.seg;
      }

      fd.sel = relseg + inf_get_baseaddr();
      fd.set(xEA);
      put_word(xEA, ushort(fd.sel));
      CheckCtrlBrk();
    } while ( --relcnt );
    qfree(relb);
    qlseek(li, pos);
  }
}

//------------------------------------------------------------------------
static void add_seg16(ea_t ea)
{
  segment_t s;
  s.sel     = ea >> 4;
  s.start_ea = ea;
  s.end_ea   = BADADDR;
  s.align   = saRelByte;
  s.comb    = scPub;
  add_segm_ex(&s, nullptr, nullptr, ADDSEG_NOSREG | ADDSEG_SPARSE);
}

//------------------------------------------------------------------------
static sel_t AdjustStub(ea_t ea) // returns prev stub
{
  segment_t *seg = getseg(ea);

  if ( seg == nullptr || ea != seg->start_ea )
    add_seg16(ea);

  ushort nentries = get_word(ea+12);
  uint32 segsize = sizeof(stub_t) + nentries * sizeof(ovrentry_t);
  seg = getseg(ea);
  if ( seg == nullptr )
    return BADSEL;

  asize_t realsize = seg->end_ea - seg->start_ea;
  if ( segsize > realsize )
    return BADSEL;      // this stub is bad

  if ( segsize != realsize )
  {
    ea_t next = seg->start_ea + segsize;

    set_segm_end(seg->start_ea, next, 0);
    next += 0xF;
    next &= ~0xF;
    if ( is_mapped(next) )
    {
      segment_t *s = getseg(next);
      if ( s == nullptr )
        add_seg16(next);
    }
  }
  return get_word(ea + 14);
}

//------------------------------------------------------------------------
void LoadPascalOverlays(linput_t *li)
{
  // AdjustPascalOverlay
  ea_t minea = inf_get_min_ea();
  ea_t maxea = inf_get_max_ea();
  for ( ea_t ea = minea; ea < maxea; )
  {
    ea &= ~0xF;
    if ( isStubPascal(ea) )
    {
      AdjustStub(ea);
      segment_t *s = getseg(ea);
      if ( s != nullptr )
      {
        ea = s->end_ea;
        ea += 0xF;
        CheckCtrlBrk();
        continue;
      }
    }
    ea += 0x10;
  }
  //-
  ea_t ea;
  int i = 0;
  for ( segment_t *s0 = get_first_seg(); s0 != nullptr; s0 = get_next_seg(ea), ++i )
  {
    ea = s0->start_ea;

    if ( get_byte(ea) != 0xCD || get_byte(ea+1) != 0x3F )
      continue;
    set_segm_class(s0, stub_class);
    char sname[32];
    qsnprintf(sname, sizeof(sname), stub_name_fmt, i);
    set_segm_name(s0, sname);

    segment_t s;
    s.comb = scPub;
    s.align = saRelPara;
    s.start_ea = (inf_get_max_ea() + 0xF) & ~0xF;
    s.sel = setup_selector(s.start_ea >> 4);
    // 04.06.99 ig: what is exeinfo and why it is passed as 0 here?
    load_overlay(li, 0/*???*/, ea, &s, ovr_off); // i
    qsnprintf(sname, sizeof(sname), ovr_name_fmt, i);
    if ( !add_segm_ex(&s, sname, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();
    describeStub(ea);
    CheckCtrlBrk();
  }
  removeBytes();
}

//------------------------------------------------------------------------
static ea_t CppInfoBase(fbov_t *fbov)
{
  seginfo_t si;
  ea_t siEA = get_fileregion_ea(fbov->exeinfo);

  if ( siEA == BADADDR
    || get_bytes(&si, sizeof(si), siEA) != sizeof(si) )
  {
    errstruct();
  }

  if ( (si.flags & SI_OVR) && si.seg ) // possible truncation
  {
    ushort lseg = si.seg;

    msg("Probbly the input file was truncated by 'unp -h'. Searching the base...\n");
    do
    {
      if ( si.seg > lseg )
        errstruct();
      lseg = si.seg;

      if ( siEA < inf_get_omin_ea()+sizeof(si)
        || get_bytes(&si, sizeof(si), siEA -= sizeof(si)) != sizeof(si) )
      {
        errstruct();
      }
      fbov->exeinfo -= sizeof(si);
      CheckCtrlBrk();
    } while ( si.seg );
    add_pgm_cmt("Real (before unp -h) EXEinfo=%08X", fbov->exeinfo);
  }
  return siEA;
}

//------------------------------------------------------------------------
sel_t LoadCppOverlays(linput_t *li)
{
  fbov_t fbov;
  sel_t  dseg = BADSEL;

  if ( pos_read(li, ovr_off, &fbov, sizeof(fbov)) )
    errstruct();
  add_pgm_cmt("Overlays: base=%08X, size=%08X, EXEinfo=%08X",
              ovr_off, fbov.ovrsize, fbov.exeinfo);
  ovr_off += sizeof(fbov_t);

  if ( fbov.segnum == 0 )
    errstruct();

  ea_t    siEA = CppInfoBase(&fbov);
  ushort  lseg = 0;
  for ( int32 i = 0; i < fbov.segnum; ++i )
  {
    seginfo_t si;

    if ( get_bytes(&si, sizeof(si), siEA) != sizeof(si) )
      errstruct();
    siEA += sizeof(si);

    if ( si.maxoff == 0xFFFF )
      continue;  // skip EXEINFO & OVRDATA
    if ( si.maxoff <= si.minoff )
      continue;
    if ( si.seg < lseg )
      errstruct();
    lseg = si.seg;

    si.seg += (ushort)inf_get_baseaddr();

    const char *sclass = nullptr;
    segment_t s;      // i initialize segment_t with 0s
    s.align  = saRelByte;
    s.comb   = scPub;
    if ( si.seg == inf_get_start_ss() )
    {
      sclass = CLASS_STACK;
      s.type = SEG_DATA;
      s.comb = scStack;
    }
    if ( si.flags & SI_COD )
    {
      sclass = CLASS_CODE;
      s.type = SEG_CODE;
    }
    if ( si.flags & SI_DAT )
    {
      sclass = CLASS_BSS;
      s.type = SEG_DATA;
      dseg   = si.seg;
    }
    s.name = 0;
    if ( si.flags & SI_OVR )
    {
      s.align = saRelPara;
      s.start_ea = (inf_get_max_ea() + 0xF) & ~0xF;
      s.sel = setup_selector(s.start_ea >> 4);
      // i end_ea is set in load_overlay()
      load_overlay(li, fbov.exeinfo, to_ea(si.seg, 0), &s, ovr_off);
      if ( s.type != SEG_NULL )
        s.type = SEG_CODE;
      char sname[32];
      qsnprintf(sname, sizeof(sname), ovr_name_fmt, i);
      if ( !add_segm_ex(&s, sname, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
        loader_failure();
      s.name = 0;
      s.type = SEG_NORM;        // undefined segment type
      sclass = stub_class;
    }
    s.sel      = si.seg;
    s.start_ea = to_ea(s.sel, si.minoff);
    s.end_ea   = to_ea(s.sel, si.maxoff);
    if ( !add_segm_ex(&s, nullptr, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();
    if ( si.flags & SI_OVR )
    {
      describeStub(s.start_ea);
      char sname[32];
      qsnprintf(sname, sizeof(sname), stub_name_fmt, i);
      set_segm_name(&s, sname);
    }
    CheckCtrlBrk();
  }
  removeBytes();
  return dseg;
}

//------------------------------------------------------------------------
//+
//------------------------------------------------------------------------
static netnode msnode;

struct modsc_t
{
  uint32 bpos;
  uint32 size;
  ushort Toff;
  ushort Hsiz;
  ushort Rcnt;
  ushort Mpara;
};

static ea_t ref_off_EA;
static ea_t ref_ind_EA;
static uint ref_oi_cnt;

//------------------------------------------------------------------------
static uint CreateMsOverlaysTable(linput_t *li, bool *PossibleDynamic)
{
  modsc_t o;
  uint    Count = 0;
  uint32  flen = qlsize(li);

  o.bpos = ovr_off;
  msnode.create();
  msg("Searching for the overlays in the file...\n");
  while ( o.bpos + sizeof(exehdr) < flen )
  {
    exehdr  E;
    uint32  delta;

    if ( pos_read(li, o.bpos, &E, sizeof(E)) )
      errstruct();

    o.size = E.CalcEXE_Length();
    delta = (uint32)(o.Hsiz = E.HdrSize) * 16;
    o.Toff = E.TablOff;
    o.Rcnt = E.ReloCnt;
    o.Mpara = (ushort)((o.size + 0xF) >> 4);

    uint32 ost = flen - o.bpos;
    if ( E.exe_ident != EXE_ID   // only MZ !
      || ost < delta
      || (uint32)o.Toff + (E.ReloCnt*4) > (ost -= delta)
      || o.size > ost )
    {
      return Count;
    }
    CheckCtrlBrk();

    msnode.supset(++Count, &o, sizeof(o));
    ovr_off = o.bpos + delta + o.size;
    uint32 d2 = align_up(ovr_off, 512);
    if ( o.bpos == d2 )
    {
      warning("Too small overflay size %u, stopped processing them", delta+o.size);
      break;
    }
    o.bpos = d2;
    if ( E.Overlay != Count )
      *PossibleDynamic = false;
  }
  ovr_off = 0;
  return Count;
}

//------------------------------------------------------------------------
static void LoadMsOvrData(linput_t *li, uint Count, bool Dynamic)
{
  fixup_data_t fd(FIXUP_SEG16);
  for ( uint i = 1; i <= Count; ++i )
  {
    modsc_t o;

    // skip dropped overlays
    if ( msnode.supval(i, &o, sizeof(o)) != sizeof(o) )
      continue;

    segment_t s;
    s.comb    = scPub;
    s.align   = saRelPara;
    s.start_ea = (inf_get_max_ea() + 0xF) & ~0xF;
    s.sel = setup_selector(s.start_ea >> 4);
    msnode.altset(i, s.sel);
    s.end_ea = s.start_ea + ((uint32)o.Mpara << 4);
    file2base(li,
              o.bpos + o.Hsiz*16LL,
              s.start_ea,
              s.start_ea + o.size,
              FILEREG_PATCHABLE);
    char sname[32];
    qsnprintf(sname, sizeof(sname), ovr_name_fmt, i);
    if ( !add_segm_ex(&s, sname, ovr_class, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure();

    qlseek(li, o.bpos + o.Toff);

    for ( uint j = o.Rcnt; j; --j )
    {
      ushort buf[2];

      lread(li, buf, sizeof(buf));

// ATTENTION!!! if Dynamic (ms-autopositioning) segment part of relocation
//              address == pseudodata segment  to load (from data in ovr!)
//              We should checked it but don't have any testcase
      ea_t xEA = Dynamic
               ? s.start_ea + buf[0]
               : s.start_ea + to_ea(buf[1], buf[0]);

      if ( xEA >= s.end_ea )
        errstruct();

      show_addr(xEA);

      ushort ubs = ushort(get_word(xEA) + inf_get_baseaddr());
      put_word(xEA, ubs);
      fd.sel = ubs;
      fd.set(xEA);
      add_segm_by_selector(ubs, CLASS_CODE);
      CheckCtrlBrk();
    }
  }
}

//------------------------------------------------------------------------
static sel_t SearchMsOvrTable(uint *Cnt)
{
  modsc_t dsc;
  if ( msnode.supval(1, &dsc, sizeof(dsc)) != sizeof(dsc) )
  {
interr:
    error("Internal error");
  }

  uint32 src[2] = { 0, dsc.bpos };
  ea_t dstea, sea, ea = inf_get_min_ea();
  uint AddSkip, Count = *Cnt;
  uint i, j;  // watcom ...
  segment_t *s;

  msg("Searching the overlay reference data table...\n");
  while ( ea + sizeof(src) < inf_get_max_ea()
       && (sea = bin_search(ea,
                            inf_get_max_ea(),
                            (uchar *)src,
                            nullptr,
                            sizeof(src),
                            BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK | BIN_SEARCH_FORWARD)) != BADADDR )
  {
    ea = sea + sizeof(uint32);
    s = getseg(ea);
    if ( s == nullptr
      || ea - s->start_ea < sizeof(uint32)*(Count+1)
      || ea + (2*sizeof(uint32) * Count) > s->end_ea )
    {
nextfndadd:
      ea += sizeof(uint32);
nextfnd:
      continue;
    }

    AddSkip = 0;
    for ( i = 2; i <= Count + AddSkip; ++i )
    {
      ea += sizeof(uint32);
      uint32 pos = get_dword(ea);

      if ( pos == 0 )
      {
        ++AddSkip;
        if ( ea + (2*sizeof(uint32) * (Count+AddSkip-i)) > s->end_ea )
          goto nextfnd;
      }
      else
      {
        if ( msnode.supval(i - AddSkip, &dsc, sizeof(dsc)) != sizeof(dsc) )
          goto interr;
        if ( pos != dsc.bpos )
          goto nextfndadd;
      }
    }
    goto found;
  }
badtable:
  ref_oi_cnt = (uint)-1;
  return BADSEL;

found:
  if ( AddSkip )
  {
    ea = sea + sizeof(uint32);
    for ( i = 2; i <= Count; ++i )
    {
      if ( !get_dword(ea += sizeof(uint32)) )
      {
        if ( !AddSkip )
          goto interr;
        --AddSkip;
        for ( j = Count; j >= i; --j )
        {
          if ( msnode.supval(j, &dsc, sizeof(dsc)) != sizeof(dsc) )
            goto interr;
          msnode.supset(j+1, &dsc, sizeof(dsc));
        }
        msnode.supdel(i);
        ++Count;
        CheckCtrlBrk();
      }
    }
    if ( AddSkip )
      goto interr;
  }

  //msg("Found disk blocks table\n");
  ea = sea - ((Count-1) * sizeof(ushort)) - 1;  // -1 -- unification
  do
  {
    ea = bin_search(s->start_ea,
                    ea+1,
                    (uchar *)src,
                    nullptr,
                    sizeof(ushort),
                    BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK | BIN_SEARCH_BACKWARD);
    if ( ea == BADADDR )
      goto badtable;
  } while ( (sea - ea) % sizeof(ushort) );

  ref_oi_cnt = (sea - ea) / sizeof(ushort);
  if ( ref_oi_cnt <= 1 )
    goto badtable;
  ref_ind_EA = ea;

  //msg("Check all tables...\n");
  j = Count;
  while ( (ea += sizeof(ushort)) < sea )
  {
    i = get_word(ea);
    if ( i > j )
    {
      if ( j == *Cnt )
        goto badtable;
      j = i;
    }
  }
  if ( (i = j - Count) != 0 )
  {
    AddSkip = i;
    do
    {
      if ( get_dword(sea - sizeof(uint32)) )
        break;
      if ( (ref_oi_cnt -= 2) <= 1 )
        goto badtable;
      sea -= sizeof(uint32);
    } while ( --i );
    AddSkip -= i;
    for ( j = Count; j; --j )
    {
      if ( msnode.supval(j, &dsc, sizeof(dsc)) != sizeof(dsc) )
        msnode.supdel(j + AddSkip);
      else
        msnode.supset(j + AddSkip, &dsc, sizeof(dsc));
    }
    do
    {
      msnode.supdel(++j);
    }
    while ( j < AddSkip );
    Count += AddSkip;
    CheckCtrlBrk();
    if ( i )
    {
      ea = sea + Count*sizeof(uint32);
      Count += i;
      do
      {
        if ( get_dword(ea += sizeof(uint32)) )
          goto badtable;
      }
      while ( --i );
    }
  }

  dstea = sea;

  ea = ref_ind_EA - (ref_oi_cnt*sizeof(ushort));
  if ( get_prev_fixup_ea(ea+1) != ea )
    ask_for_feedback("Absent relocation at start of offset table");

  ref_off_EA = ea;

  sea = ref_ind_EA;
  AddSkip = 0;  // added 07.04.2015 (bmpcad)
  for ( i = 1; i < ref_oi_cnt; ++i )
  {
    ea  += sizeof(ushort);
    sea += sizeof(ushort);

    uint rsz;
    j = get_word(sea);
    if ( !j )
    {
      if ( i <= Count )
        goto badofftb;
      ++AddSkip;
      continue;
    }

    rsz = get_word(ea);

    if ( msnode.supval(j, &dsc, sizeof(dsc)) != sizeof(dsc) )
    {
      if ( rsz )
        goto badofftb;
      msg("An overlay index %u in the table of indexes points to a missing overlay\n", i);
    }
    else if ( rsz >= dsc.size )
    {
badofftb:
      ask_for_feedback("Incompatible offset table");
      AddSkip = 0;
      break;
    }
  }

  sea = dstea + (Count+1+AddSkip)*sizeof(uint32);
  for ( i = 1; i <= Count; ++i )
  {
    sea += sizeof(uint32);
    uint32 dt = get_dword(sea);

    if ( msnode.supval(i, &dsc, sizeof(dsc)) != sizeof(dsc) )
    {
      if ( dt )
      {
badmemtb:
        ask_for_feedback("Incompatible mem-size table");
      }
      continue;
    }

    if ( !dt )
    {
      ask_for_feedback("Zero overlay memory size in description table");
      goto badtable;
    }

    if ( dt < dsc.Mpara || dt >= 0x1000 )
      goto badmemtb;

    // Possiblee needed for segment with unitialized data at top, but not sampled...
    if ( dt > dsc.Mpara )
    {
      dsc.Mpara = (ushort)dt;
      msnode.supset(i, &dsc, sizeof(dsc));
    }
  }

  for ( i = 0; i < AddSkip; i++ )
  {
    sea += sizeof(uint32);
    if ( get_dword(sea) != 0 )
    {
      ask_for_feedback("Incompatible extension in overlay tables");
      break;
    }
  }

  msg("All tables OK\n");
  create_word(ref_off_EA, i = (ref_oi_cnt - AddSkip)*sizeof(ushort));
  force_name(ref_off_EA, "ovr_off_tbl");
  create_word(ref_ind_EA, i);
  force_name(ref_ind_EA, "ovr_index_tbl");
  *Cnt = Count;
  i = (Count + 1) * sizeof(uint32);
  create_dword(dstea, i);
  force_name(dstea, "ovr_start_tbl");
  dstea += i + (AddSkip * sizeof(uint32));
  create_dword(dstea, i);
  force_name(dstea, "ovr_memsiz_tbl");
  return s->sel;
}

//------------------------------------------------------------------------
static segment_t *MsOvrStubSeg(uint *stub_cnt, ea_t r_top, sel_t dseg)
{
  msg("Searching for the stub segment...\n");
  int count = get_segm_qty();
  for ( int i = 0; i < count; ++i )
  {
    segment_t *seg = getnseg(i);
    if ( seg->sel == dseg )
      continue;
    ea_t ea = seg->start_ea;
    uchar buf[3*sizeof(ushort)];

    if ( ea >= r_top )
      break;

    if ( get_bytes(buf, sizeof(buf), ea) != sizeof(buf) )
      continue;
    if ( *(uint32 *)buf || *(ushort *)&buf[sizeof(uint32)] )
      continue;

    uint  cnt = 0;
    uchar frs = (uchar)-1;
    while ( (ea += sizeof(buf)) < seg->end_ea - sizeof(buf) )
    {
      if ( (frs = get_byte(ea)) != 0xCD || get_byte(ea+1) != 0x3F )
        break;
      ushort ind = get_word(ea + sizeof(ushort));
      if ( !ind || ind > ref_oi_cnt )
        break;
      ++cnt;
      CheckCtrlBrk();
    }
    if ( !frs && cnt >= ref_oi_cnt )
    {
      *stub_cnt = cnt;
      return seg;
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------
static void CreateMsStubProc(segment_t *s, uint stub_cnt)
{
  ea_t ea = s->start_ea;

  set_segm_name(s, "STUB");
  set_segm_class(s, CLASS_CODE);
  create_byte(ea, 3*sizeof(ushort));
  ea += 3*sizeof(ushort);
  msg("Patching the overlay stub-segment...\n");
  for ( uint ind, i = 0; i < stub_cnt; ++i, ea += 3*sizeof(ushort) )
  {
    ind = get_word(ea+2);
    if ( ind != 0 )
    {
      if ( ind >= ref_oi_cnt )
      {
badref:
        ask_for_feedback("Illegal reference in overlay call interrupt");
        continue;
      }

      ind *= sizeof(ushort);
      uint off = (uint)get_word(ea+4) + get_word(ref_off_EA + ind);
      ind = get_word(ref_ind_EA + ind); // overlay number
      ushort sel = (ushort)msnode.altval(ind);
      modsc_t o;
      if ( msnode.supval(ind, &o, sizeof(o)) != sizeof(o) )
        goto badref;
      if ( off >= o.size )
        goto badref;

      show_addr(ea);
      put_byte(ea, 0xEA);   // jmp far
      put_word(ea+1, off);  // offset
      put_word(ea+3, sel);  // selector
      put_byte(ea+5, 0x90); // NOP -> for autoanalisis
      auto_make_proc(ea);
      auto_make_proc(to_ea(sel2para(sel), off));
      CheckCtrlBrk();
    }
  }
  create_align(ea, s->end_ea - ea, 0);
}

//------------------------------------------------------------------------
sel_t LoadMsOverlays(linput_t *li, bool PossibleDynamic)
{
  sel_t dseg = BADSEL;
  uint Cnt = CreateMsOverlaysTable(li, &PossibleDynamic);

  if ( ovr_off )
    warning("File has extra information\n"
            "\3Loading 0x%X bytes, total file size 0x%" FMT_64 "X",
            ovr_off, qlsize(li));

  if ( Cnt )
  {
    dseg = SearchMsOvrTable(&Cnt);
    if ( dseg != BADSEL )
      PossibleDynamic = false;
    else if ( !PossibleDynamic )
      ask_for_feedback("Cannot find the overlay call data table");

    ea_t r_top = inf_get_max_ea();
    LoadMsOvrData(li, Cnt, PossibleDynamic);

    if ( ref_oi_cnt != (uint)-1 )
    {
      uint stub_cnt;
      segment_t *s = MsOvrStubSeg(&stub_cnt, r_top, dseg);

      if ( s != nullptr )
        CreateMsStubProc(s, stub_cnt);
      else
        ask_for_feedback("The overlay-manager segment not found");
    }
  }
  msnode.kill();
  return dseg;
}
