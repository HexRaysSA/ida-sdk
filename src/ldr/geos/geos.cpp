/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "../idaldr.h"
#include "geos2.h"
#include "common.cpp"
#include <typeinf.hpp>

//--------------------------------------------------------------------------
static int create_seg(
        ea_t base,
        ea_t start,
        ea_t end,
        const char *name,
        const char *sclass)
{
  if ( start != BADADDR && end < start )
    return 0;
  segment_t s;
  s.sel     = setup_selector(base);
  s.start_ea = start;
  s.end_ea   = end;
  s.align   = saRelByte;
  s.comb    = (sclass != nullptr && strcmp(sclass,"STACK") == 0) ? scStack : scPub;
  s.bitness = 0;
  return add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE);
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  union
  {
    GEOSheader h1;
    GEOS2header h2;
  } h;
  qlseek(li, 0);
  if ( qlread(li, &h, sizeof(h)) != sizeof(h) )
    return 0;

  qoff64_t apppos;
  int version;
  if ( h.h1.ID == GEOS_ID && h.h1.fclass == 0 )
  {
    apppos = 0xC8;
    version = 1;
  }
  else if ( h.h2.ID == GEOS2_ID && h.h2.fclass == 1 )
  {
    apppos = sizeof(GEOS2header);
    version = 2;
  }
  else
  {
    return 0;
  }

  GEOSappheader ah;
  qlseek(li, apppos, SEEK_SET);
  if ( qlread(li, &ah, sizeof(ah)) != sizeof(ah) )
    return 0;
  const char *stype;
  switch ( ah.type )
  {
    case 1:  stype = "Application"; break;
    case 2:  stype = "Library";     break;
    case 3:  stype = "Driver";      break;
    default: stype = "Unknown type";break;
  }
  fileformatname->sprnt("GEOS%d %s", version, stype);
  *processor = "metapc";
  return 1;
}

//--------------------------------------------------------------------------
static ea_t get_segea(const GEOSappheader &ah, const uint32 *segea, uint16 s, uint16 off=0)
{
  if ( s >= ah.numseg )
  {
    ask_for_feedback("Bad segment number %d", s);
    return BADADDR;
  }
  return segea[s] == uint32(BADADDR) ? BADADDR : (segea[s]+off);
}

//--------------------------------------------------------------------------
static netnode get_node(const GEOSappheader &ah, const netnode *modnode, uint16 libn)
{
  if ( libn >= ah.numlib )
  {
    ask_for_feedback("Bad library number %d", libn);
    return BADNODE;
  }
  return modnode[libn];
}

//--------------------------------------------------------------------------
static void declare_class(ea_t ea, const char *entryname)
{
  static const char class_name[] = "ClassStruct";
  tinfo_t tif;
  tif.get_named_type(nullptr, class_name);
  if ( !tif.present() )
  {
    parse_decls(
          nullptr,
          "enum __bitmask ClassFlags : char"
          "{"
            "CLASSF_HAS_DEFAULT = 0x1,"
            "CLASSF_MASTER_CLASS = 0x2,"
            "CLASSF_VARIANT_CLASS = 0x4,"
            "CLASSF_DISCARD_ON_SAVE = 0x8,"
            "CLASSF_NEVER_SAVED = 0x10,"
            "CLASSF_HAS_RELOC = 0x20,"
            "CLASSF_C_HANDLERS = 0x40,"
          "};"
          "struct ClassStruct"
          "{"
            "void far *superClass __offset(OFF32);"
            "int masterOffset;"
            "int methodCount __udec;"
            "int instanceSize __udec;"
            "int vdRelocTable;"
            "int relocTable;"
            "ClassFlags flags;"
            "char masterMethods;"
          "};",
          msg,
          HTI_DCL);
    tif.get_named_type(nullptr, class_name);
  }
  if ( !tif.present() )
    return;
  asize_t size = tif.get_size();
  create_struct(ea, size, tif.get_tid());

  segment_t *s = getseg(ea);
  if ( s == nullptr )
    return;
  int count = get_word(ea+6);
//  bool c_handlers = get_byte(ea+14) & (1<<6);
  ea += size;
  if ( ea+2*count >= s->end_ea )
    return;
  ea_t messages = ea;
  create_word(ea, count*2);
  op_dec(ea, 0);
  ea += 2*count;
  if ( ea+4*count > s->end_ea )
    return;
  create_dword(ea, count*4);
  op_plain_offset(ea, 0, 0);
  for ( int i=0; i < count; i++ )
  {
    ea_t idx = ea + 4*i;
    ea_t pea = to_ea(get_word(idx+2), get_word(idx));
    auto_make_proc(pea);
    char name[MAXSTR];
    qsnprintf(name, sizeof(name), "%s_%u", entryname, get_word(messages+2*i));
    add_entry(pea, pea, name, true, AEF_IDBENC);
  }
// commented out because it doesn't work properly
// see geoplan.geo, entry number 1 for example
//  if ( c_handlers )
//    declare_parameter_types(ea+count*4, count);
}

//--------------------------------------------------------------------------
static void describe_app(const GEOSappheader &ah, const uint32 *segea)
{
  char buf[MAXSTR];
  char *end = buf + sizeof(buf);
  char *ptr = buf + qsnprintf(buf, sizeof(buf), "Pgm attrs   :");
  if ( ah.attr & GA_PROCESS                   ) APPEND(ptr, end, " GA_PROCESS");
  if ( ah.attr & GA_LIBRARY                   ) APPEND(ptr, end, " GA_LIBRARY");
  if ( ah.attr & GA_DRIVER                    ) APPEND(ptr, end, " GA_DRIVER");
  if ( ah.attr & GA_KEEP_FILE_OPEN            ) APPEND(ptr, end, " GA_KEEP_FILE_OPEN");
  if ( ah.attr & GA_SYSTEM                    ) APPEND(ptr, end, " GA_SYSTEM");
  if ( ah.attr & GA_MULTI_LAUNCHABLE          ) APPEND(ptr, end, " GA_MULTI_LAUNCHABLE");
  if ( ah.attr & GA_APPLICATION               ) APPEND(ptr, end, " GA_APPLICATION");
  if ( ah.attr & GA_DRIVER_INITIALIZED        ) APPEND(ptr, end, " GA_DRIVER_INITIALIZED");
  if ( ah.attr & GA_LIBRARY_INITIALIZED       ) APPEND(ptr, end, " GA_LIBRARY_INITIALIZED");
  if ( ah.attr & GA_GEODE_INITIALIZED         ) APPEND(ptr, end, " GA_GEODE_INITIALIZED");
  if ( ah.attr & GA_USES_COPROC               ) APPEND(ptr, end, " GA_USES_COPROC");
  if ( ah.attr & GA_REQUIRES_COPROC           ) APPEND(ptr, end, " GA_REQUIRES_COPROC");
  if ( ah.attr & GA_HAS_GENERAL_CONSUMER_MODE ) APPEND(ptr, end, " GA_HAS_GENERAL_CONSUMER_MODE");
  if ( ah.attr & GA_ENTRY_POINTS_IN_C         ) APPEND(ptr, end, " GA_ENTRY_POINTS_IN_C");
  add_pgm_cmt("%s", buf);

  if ( ah.attr & GA_PROCESS )
  {
    ea_t entry = get_segea(ah, segea, ah.classptr_seg, ah.classptr_ofs);
    set_name(entry, "ProcessClass", SN_NOCHECK|SN_NOWARN);
    declare_class(entry, "ProcessClass");
//    inf_set_start_cs(get_segea(ah,segea,ah.classptr_seg) >> 4);
//    inf_set_start_ip (ah.classptr_ofs);
         entry = get_segea(ah, segea, ah.tokenres_seg, ah.tokenres_item);
    set_name(entry, "ApplicationObject");
    add_pgm_cmt("ProcessClass: %d:%04X", ah.classptr_seg, ah.classptr_ofs);
    add_pgm_cmt("App object  : %d:%04X", ah.tokenres_seg, ah.tokenres_item);
  }
  if ( ah.attr & GA_LIBRARY && ah.initseg != 0 )
  {
    inf_set_start_cs(get_segea(ah, segea, ah.initseg) >> 4);
    inf_set_start_ip(ah.initofs);
    add_pgm_cmt("Library init: %d:%04X", ah.initseg, ah.initofs);
  }
  if ( ah.attr & GA_DRIVER && ah.startseg != 0 )
  {
    ea_t entry = get_segea(ah, segea, ah.startseg, ah.startofs);
    set_name(entry, "DriverTable");
//    inf_set_start_cs(get_segea(ah, segea, ah.startseg) >> 4);
//    inf_set_start_ip (ah.startofs);
    add_pgm_cmt("Driver Table: %d:%04X", ah.startseg, ah.startofs);
//      add_jmplist(ah.startseg,ah.startofs,4,4);
                                  // Add entry point as "jmplist"
  }
}

//--------------------------------------------------------------------------
static void bad_lib_reloc(int i, uint16 off)
{
  ask_for_feedback("Strange library relocation at %d:%04X", i, off);
}

//--------------------------------------------------------------------------
static void create_fixup(ea_t ea, fixup_data_t &fd, ea_t target)
{
  segment_t *s = getseg(target);
  if ( s != nullptr )
  {
    fd.sel = s->sel;
    fd.off = target - get_segm_base(s);
  }
  else
  {
    fd.sel = sel_t(target >> 4);
    fd.off = target & 0xF;
  }
  fd.displacement = 0;
  fd.set(ea);
  if ( fd.get_type() == FIXUP_PTR16 )
  {
    put_word(ea, fd.off);
    put_word(ea+2, fd.sel);
  }
  else if ( fd.get_type() == FIXUP_OFF16 )
  {
    put_word(ea, fd.off);
  }
  else              // SEG16
  {
    put_word(ea, fd.sel);
  }
}

//--------------------------------------------------------------------------
static void apply_relocations(
        linput_t *li,
        const GEOSappheader &ah,
        const netnode *modnode,
        const uint16 *seglen,
        const int32 *segpos,
        const uint16 *segfix,
        const uint32 *segea)
{
  // apply relocation information
  for ( int i=0; i < ah.numseg; i++ )
  {
    if ( segfix[i] == 0 )
      continue;
    GEOSfixup *fix = (GEOSfixup *)qalloc(segfix[i]);
    if ( fix == nullptr )
      nomem("fix");
    qlseek(li, segpos[i]+((seglen[i]+0xF)&~0xF));
    lread(li, fix, segfix[i]);
    int n = segfix[i]/sizeof(GEOSfixup);
    sel_t oldsel = BADSEL;
    sel_t oldoff = BADSEL;
    ea_t oldea = BADADDR;
    for ( int j=0; j < n; j++ )
    {
      ea_t ea = get_segea(ah, segea, (uint16)i, fix[j].ofs);
      int ftype = fix[j].type & 0xF0;
      if ( ftype != 0x10 && ftype != 0x20 )
        ask_for_feedback("Unknown fixup type %02X", ftype);
      netnode libnode = BADNODE;
      if ( ftype == 0x10 )
        libnode = get_node(ah, modnode, fix[j].type>>8);
      uint16 w1 = get_word(ea);
      ea_t target = BADADDR;
      fixup_data_t fd(FIXUP_SEG16);
      switch ( fix[j].type & 0x0F )
      {
        case 0x0: case 0x4:
          fd.set_type_and_flags(FIXUP_PTR16);
          if ( ftype == 0x20 )  // program
          {
            target = get_segea(ah, segea, w1, get_word(ea+2));
          }
          else                  // library
          {
            target = node2ea(libnode.altval(w1+1));
            fd.set_extdef();
          }
          break;
        case 0x1:               // off
          if ( ftype == 0x20 )  // program
          {
            ask_for_feedback("Program offset relocation encountered");
            continue;
          }
          oldoff = w1;
          if ( oldsel != BADSEL )
          {
LIB_PTR:
            target = node2ea(libnode.altval(oldoff+1));
            if ( oldea == ea+2 )
            {
              fd.set_type_and_flags(FIXUP_PTR16, FIXUPF_EXTDEF);
            }
            else
            {
              fd.set_type_and_flags(FIXUP_SEG16, FIXUPF_EXTDEF);
              create_fixup(oldea, fd, target);
              fd.set_type_and_flags(FIXUP_OFF16, FIXUPF_EXTDEF);
            }
            oldsel = BADSEL;
            oldoff = BADSEL;
            oldea  = BADSEL;
            break;
          }
          oldea = ea;
          continue;
        case 0x2: case 0x3:
          if ( ftype == 0x20 )  // program
          {
            target = get_segea(ah, segea, w1);
          }
          else
          {
            oldsel = w1;
            if ( oldoff != BADSEL )
            {
              ea_t tmp = ea;
              ea = oldea;
              oldea = tmp;
              goto LIB_PTR;
            }
            oldea = ea;
            continue;
          }
          break;
        default:
          ask_for_feedback("Unknown relocation type %02X", fix[j].type);
      }
      create_fixup(ea, fd, target);
    }
    qfree(fix);
  }
}

//--------------------------------------------------------------------------
static void find_imports_in_relocations(
        linput_t *li,
        const GEOSappheader &ah,
        const netnode *modnode,
        const uint16 *seglen,
        const int32 *segpos,
        const uint16 *segfix)
{
  for ( int i=0; i < ah.numseg; i++ )
  {
    if ( segfix[i] == 0 )
      continue;
    GEOSfixup *fix = (GEOSfixup *)qalloc(segfix[i]);
    if ( fix == nullptr )
      nomem("fix");
    qlseek(li, segpos[i]+((seglen[i]+0xF)&~0xF));
    lread(li, fix, segfix[i]);
// i don't understand why this should be done
// besides, if we uncomment it, the library fixups are
// not handled properly
//    if ( fix[0].ofs == 0 )
//      fix[0].ofs = 0xFFFF;
    int num = segfix[i]/sizeof(GEOSfixup);
    sel_t oldseg = BADSEL;
    sel_t oldoff = BADSEL;
    sel_t oldlib = BADSEL;
    for ( int j=0; j < num; j++ )
    {
      if ( fix[j].ofs == 0xFFFF )
        continue;
      if ( (fix[j].type & 0xF0) != 0x10 )
        continue;     // only library!
      int libn = fix[j].type>>8;
      if ( libn >= ah.numlib )
      {
        ask_for_feedback("Illegal library number in relocations");
        continue;
      }
      netnode n = modnode[libn];
      uint16 ofs = fix[j].ofs;
      qlseek(li, segpos[i]+ofs);
      uint16 w1;
      lread(li, &w1, sizeof(w1));
      switch ( fix[j].type & 0x0F )
      {
        case 0x0: case 0x4:                     // exported entry
          n.altset(w1+1, 1);
          oldseg = BADSEL;
          oldoff = BADSEL;
          oldlib = BADSEL;
          break;
        case 0x1:                               // off
          if ( oldseg != BADSEL )
          {
            if ( libn != oldlib || oldseg != w1 )
              bad_lib_reloc(i, ofs);
            n.altset(w1+1, 1);
            oldseg = BADSEL;
            break;
          }
          oldoff = w1;
          oldlib = libn;
          break;
        case 0x2: case 0x3:                     // seg #
          if ( oldoff != BADSEL )
          {
            if ( libn != oldlib || oldoff != w1 )
              bad_lib_reloc(i, ofs);
            n.altset(w1+1, 1);
            oldoff = BADSEL;
            break;
          }
          oldseg = w1;
          oldlib = libn;
          break;
        default:
          ask_for_feedback("Unknown relocation type %02X", fix[j].type);
      }
    }
    if ( oldseg != BADSEL && oldoff != BADSEL )
      ask_for_feedback("Some library relocations are strange");
    qfree(fix);
  }
}

//--------------------------------------------------------------------------
static void create_extern_segments(
        const GEOSappheader &ah,
        const GEOSliblist *lib,
        const netnode *modnodes)
{
  inf_set_specsegs(4);
  for ( int i=0; i < ah.numlib; i++ )
  {
    char libname[8+1];
    qstrncpy(libname, lib[i].name, sizeof(libname));
    trim(libname);
    netnode modnode = modnodes[i];
    uval_t x;
    int nimps = 0;
    for ( x=modnode.altfirst(); x != BADNODE; x=modnode.altnext(x) )
      nimps++;
    if ( nimps == 0 )
      continue;

    ea_t ea = find_free_chunk(inf_get_max_ea(), nimps*4, 15);
    ea_t end = ea + nimps*4;
    create_seg(ea>>4, ea, end, libname, "XTRN");
    for ( x=modnode.altfirst(); x != BADNODE; x=modnode.altnext(x),ea+=4 )
    {
      modnode.altdel(x);
      char buf[MAXSTR];
      qsnprintf(buf, sizeof(buf), "%s_%u", libname, uint16(x)-1);
      put_dword(ea, 0xCB);
      create_insn(ea);
      force_name(ea, buf, SN_IDBENC);
      set_import_ordinal(modnode, ea, x);
    }
    import_module(libname, nullptr /*windir*/, modnode, nullptr, "geos");
  }
}

//--------------------------------------------------------------------------
static void create_exports(
        const GEOSappheader &ah,
        const GEOSexplist *explist,
        const uint32 *segea,
        const char *modname)
{
  int i;
  netnode modnode;
  modnode.create();
  for ( i=0; i < ah.numexp; i++ )
  {
    ea_t ea = get_segea(ah, segea, explist[i].seg, explist[i].ofs);
    add_extra_cmt(ea, true, "Exported entry %d", i);
    set_import_ordinal(modnode, ea, i + 1);
  }
  import_module(modname, nullptr /*windir*/, modnode, nullptr, "geos");
  for ( i=0; i < ah.numexp; i++ )
  {
    ea_t ea = get_segea(ah, segea, explist[i].seg, explist[i].ofs);
    if ( ea != BADADDR )
    {
      qstring name;
      if ( get_name(&name, ea, GN_NOT_DUMMY) <= 0 )
        name.sprnt("%s_%d", modname, i);
      bool makecode = segtype(ea) == SEG_CODE;
      add_entry(i, ea, name.begin(), makecode, AEF_IDBENC);
      if ( !makecode )
        declare_class(ea, name.begin());
    }
  }
}

//--------------------------------------------------------------------------
void load_application(linput_t *li, int32 fpos, int32 fdelta)
{
  GEOSappheader ah;

  qlseek(li, fpos);
  lread(li, &ah, sizeof(ah));

  // build our name
  char modname[sizeof(ah.name)+1];
  qstrncpy(modname, ah.name, sizeof(ah.name));
  trim(modname);

  // read in library information
  GEOSliblist *lib = nullptr;
  netnode *modnode = nullptr;
  validate_array_count(li, &ah.numlib, sizeof(GEOSliblist), "The library count");
  if ( ah.numlib != 0 )
  {
    lib = qalloc_array<GEOSliblist>(ah.numlib);
    if ( lib == nullptr )
      nomem("libs");
    lread(li, lib, ah.numlib*sizeof(GEOSliblist));
    modnode = qalloc_array<netnode>(ah.numlib);
    if ( modnode == nullptr )
      nomem("libnode");
    for ( int i=0; i < ah.numlib; i++ )
    {
      char libname[8+1];
      qstrncpy(libname, lib[i].name, sizeof(libname));
      trim(libname);
      char buf[20];
      qsnprintf(buf, sizeof(buf), "$lib %.8s", libname);
      modnode[i].create(buf);
    }
  }

  // read in export information
  GEOSexplist *explist = nullptr;
  validate_array_count(li, &ah.numexp, sizeof(GEOSexplist), "Number of exports");
  if ( ah.numexp != 0 )
  {
    explist = qalloc_array<GEOSexplist>(ah.numexp);
    if ( explist == nullptr )
      nomem("exp");
    lread(li, explist, ah.numexp*sizeof(GEOSexplist));
  }

  // read in segment information
  void *segd = nullptr;
  uint16 *seglen = nullptr;
  int32 *segpos = nullptr;
  uint16 *segfix = nullptr;
  uint16 *segflg;
  sel_t ds_sel = BADSEL;
  uint32 *segea = nullptr;
  validate_array_count(li, &ah.numseg, 14, "Number of segments");
  if ( ah.numseg != 0 )
  {
    if ( !is_mul_ok<ushort>(ah.numseg, 14) )
NOMEM:
      nomem("geos_segments");
    segd = qalloc(ah.numseg*14);
    if ( segd == nullptr )
      goto NOMEM;
    lread(li, segd, ah.numseg*10);
    seglen = (uint16 *)segd;
    segpos = (int32  *)(seglen + ah.numseg);
    segfix = (uint16 *)(segpos + ah.numseg);
    segflg = (uint16 *)(segfix + ah.numseg);
    segea  = (uint32 *)(segflg + ah.numseg);
    ea_t ea = to_ea(inf_get_baseaddr(), 0);
    for ( int i=0; i < ah.numseg; i++ )
    {
      uint16 f = segflg[i];
      segpos[i] += fdelta;

      segea[i] = uint32(BADADDR);
      if ( seglen[i] == 0 )
        continue;
      size_t bss_size = 0;
      // if this is the data segment, increase its size by stacksize.
      // i'm not aware of a reliable way to find it, so use heuristics
      bool found_data_segment = false;
      if ( ds_sel == BADSEL
        && (f & (HF_READ_ONLY|HF_SHARABLE|HF_CODE)) == 0
        && (f & HF_FIXED) != 0 )
      {
        found_data_segment = true;
        bss_size = ah.stacksize;
      }
      ea = find_free_chunk(ea, bss_size + seglen[i], 15);
      ea_t endea = ea + seglen[i] + bss_size;
      if ( (f & HF_ZERO_INIT) == 0 )
        file2base(li, segpos[i], ea, endea - bss_size, FILEREG_PATCHABLE);
      create_seg(ea>>4, ea, endea, nullptr, (f & HF_CODE) ? "CODE" : "DATA");

      if ( found_data_segment )
        ds_sel = find_selector(ea>>4);

      char buf[MAXSTR];
      char *end = buf + sizeof(buf);
      char *ptr = buf + qsnprintf(buf, sizeof(buf), "Segm attrs  :");
      if ( f & HF_ZERO_INIT       ) APPEND(ptr, end, " ZEROINIT");
      if ( f & HF_LOCK            ) APPEND(ptr, end, " LOCK");
      if ( f & HF_NO_ERR          ) APPEND(ptr, end, " NO_ERR");
      if ( f & HF_UI              ) APPEND(ptr, end, " UI");
      if ( f & HF_READ_ONLY       ) APPEND(ptr, end, " RONLY");
      if ( f & HF_OBJECT_RESOURCE ) APPEND(ptr, end, " OBJ_RES");
      if ( f & HF_CODE            ) APPEND(ptr, end, " CODE");
      if ( f & HF_CONFORMING      ) APPEND(ptr, end, " CONFORMING");
      if ( f & HF_FIXED           ) APPEND(ptr, end, " FIXED");
      if ( f & HF_SHARABLE        ) APPEND(ptr, end, " SHARABLE");
      if ( f & HF_DISCARDABLE     ) APPEND(ptr, end, " DISCARDABLE");
      if ( f & HF_SWAPABLE        ) APPEND(ptr, end, " SWAPABLE");
      if ( f & HF_LMEM            ) APPEND(ptr, end, " LMEM");
      if ( f & HF_DEBUG           ) APPEND(ptr, end, " DEBUG");
      if ( f & HF_DISCARDED       ) APPEND(ptr, end, " DISCARDED");
      if ( f & HF_SWAPPED         ) APPEND(ptr, end, " SWAPPED");
      add_extra_cmt(ea, true, "%s", buf);

      segea[i] = (uint32)ea;
      ea = endea;
    }
  }

  find_imports_in_relocations(li, ah, modnode, seglen, segpos, segfix);
  create_extern_segments(ah, lib, modnode);
  set_default_dataseg(ds_sel);

  if ( !qgetenv("IDA_NORELOC") )
    apply_relocations(li, ah, modnode, seglen, segpos, segfix, segea);

  create_exports(ah, explist, segea, modname);

  describe_app(ah, segea);
  qfree(lib);
  qfree(modnode);
  qfree(explist);
  qfree(segd);
}

//--------------------------------------------------------------------------
static void show_geos1(GEOSheader &h)
{
  char buf[MAXSTR];
  add_pgm_cmt("Name        : %s", geos2ibm(buf, h.name, sizeof(h.name)));
  add_pgm_cmt("Token       : %s", token2str(buf, sizeof(buf), h.token));
  add_pgm_cmt("Creator     : %s", token2str(buf, sizeof(buf), h.appl));
  add_pgm_cmt("Release     : %u.%u.%u.%u",
                          h.release.versmaj,
                          h.release.versmin,
                          h.release.revmaj,
                          h.release.revmin);
  add_pgm_cmt("Protocol    : %u.%03u",
                          h.protocol.vers,
                          h.protocol.rev);
  add_pgm_cmt("Flags       : %04X", h.flags);
  add_pgm_cmt("User info   : %s", geos2ibm(buf, h.info, sizeof(h.info)));
  add_pgm_cmt("Copyright   : %s", geos2ibm(buf, h._copyright, sizeof(h._copyright)));
}

//--------------------------------------------------------------------------
static void show_geos2(GEOS2header &h)
{
  char buf[MAXSTR];
  add_pgm_cmt("Name        : %s", geos2ibm(buf, h.name, sizeof(h.name)));
  add_pgm_cmt("Token       : %s", token2str(buf, sizeof(buf), h.token));
  add_pgm_cmt("Creator     : %s", token2str(buf, sizeof(buf), h.appl));
  add_pgm_cmt("Release     : %u.%u.%u.%u",
                          h.release.versmaj,
                          h.release.versmin,
                          h.release.revmaj,
                          h.release.revmin);
  add_pgm_cmt("Protocol    : %u.%03u",
                          h.protocol.vers,
                          h.protocol.rev);
  add_pgm_cmt("Flags       : %04X", h.flags);
  add_pgm_cmt("Password    : %.*s", int(sizeof(h.password)), h.password);
  add_pgm_cmt("User info   : %s", geos2ibm(buf, h.info, sizeof(h.info)));
  add_pgm_cmt("Copyright   : %s", geos2ibm(buf, h._copyright, sizeof(h._copyright)));
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, uint16 /*neflag*/, const char * /*fileformatname*/)
{
  // 16bit only
  inf_set_app_bitness(16);

  set_processor_type("metapc", SETPROC_LOADER);

  union
  {
    GEOSheader h1;
    GEOS2header h2;
  } h;
  qlseek(li, 0);
  lread(li, &h, sizeof(h));

  int32 apppos;
  int32 fdelta;
  if ( h.h1.ID == GEOS_ID )
  {
    apppos = 0xC8;
    fdelta = 0;
  }
  else
  {
    apppos = sizeof(GEOS2header);
    fdelta = apppos;
  }

  load_application(li, apppos, fdelta);

  create_filename_cmt();
  if ( h.h1.ID == GEOS_ID )
    show_geos1(h.h1);
  else
    show_geos2(h.h2);

  inf_set_cc_cm(inf_get_cc_cm() | C_PC_LARGE);
  add_til("geos", ADDTIL_DEFAULT);
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
