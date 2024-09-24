/*
 *      Decompiler project
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Display microcode objects in text form (for debugging)
 *
 *      This file is published as part of the Hex-Rays SDK just to
 *      show how the internal representation of the microcode is
 *      converted into text. It is not supposed to be compilable.
 */

#include "allmicro.h"
#include <err.h>

//#define _DUMP_FLOWCHART
//#define _DUMP_STKPNTS

const char *const rasm_keywords[] =
{
#define QW(x) #x
#include "rasmkeys.cpp"
#undef QW
};
CASSERT(qnumber(rasm_keywords) == m_max+30);
const size_t rasm_keyword_count = qnumber(rasm_keywords);

GCC_DIAG_OFF(nonnull)

//-------------------------------------------------------------------------
typedef std::deque<qstring> strlist;
struct mblock_dumper_t : public vd_printer_t
{
  strlist lines;
  int nline = 0;
  int serial = 0;
  AS_PRINTF(3, 4) int print(int indent, const char *format, ...) override
  {
    qstring buf;
    if ( indent > 0 )
      buf.fill(0, ' ', indent);
    va_list va;
    va_start(va, format);
    buf.cat_vsprnt(format, va);
    va_end(va);
    size_t len = tag_remove(&buf);
    lines.push_back(buf);
    return len;
  }
};

struct showmic_vars_t
{
  mblock_dumper_t md;
  qstring dumpdir;
  int oldn = 0;
  int dumpnum = 0;
  qstring buffers[10] = { nullptr, };
  int lastbuf = 0;

  void get_dump_file_name(char *buf, size_t bufsize, int serial);
};

DEFINE_HEXVARS_ALLOC_FREE(showmic_vars);


//--------------------------------------------------------------------------
// make sure that all debugging functions are included in the executable
//-------------------------------------------------------------------------
qstring *debug_getbuf()
{
  hexrays_vars_t *hv = GET_MODULE_DATA(hexrays_vars_t);
  return hv->debug_getbuf();
}

//-------------------------------------------------------------------------
qstring *hexrays_vars_t::debug_getbuf()
{
  qstring *ptr = &showmic_vars->buffers[showmic_vars->lastbuf];
  if ( ++showmic_vars->lastbuf == 10 )
    showmic_vars->lastbuf = 0;
  ptr->qclear();
  return ptr;
}

#define _DEFINE_DSTR(class, x)      \
const char *class::dstr() const \
{                                   \
  qstring *buf = debug_getbuf();    \
  print(buf);                       \
  x                                 \
  return buf->c_str();              \
}

#define DEFINE_DSTR(class) _DEFINE_DSTR(class,; )
#define DEFINE_DSTR_NOTAG(class) _DEFINE_DSTR(class, tag_remove(buf); )

// See c.cpp for references to dstr() functions
DEFINE_DSTR(bitset_t)
DEFINE_DSTR(rlist_t)
DEFINE_DSTR(ivl_t)
DEFINE_DSTR(vivl_t)
DEFINE_DSTR(ivlset_t)
DEFINE_DSTR(mlist_t)
DEFINE_DSTR(lattice_t)
DEFINE_DSTR(ivl64_t)
DEFINE_DSTR(ivlset64_t)
DEFINE_DSTR(valrng_t)
DEFINE_DSTR(valranges_t)
DEFINE_DSTR(chain_t)
DEFINE_DSTR(block_chains_t)
DEFINE_DSTR(mcases_t)
DEFINE_DSTR(edgevec_t)
DEFINE_DSTR(fnumber_t)
DEFINE_DSTR(gva_attrs_t)
DEFINE_DSTR(gva_fields_t)
DEFINE_DSTR_NOTAG(mop_t)
DEFINE_DSTR_NOTAG(mcallarg_t)
DEFINE_DSTR_NOTAG(mcallinfo_t)
DEFINE_DSTR_NOTAG(minsn_t)
DEFINE_DSTR_NOTAG(ctree_item_t)

#ifdef _MSC_VER
#  pragma comment(linker, "/include:refs_for_linker")
#endif

#if defined(TESTABLE_BUILD) && defined(_DEBUG)
void dgr(citem_t *item)
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  hv.gfunc->body.dump_graph(item, 0);
}
#endif

//-------------------------------------------------------------------------
#ifdef __EA64__
static ea_t align_badaddr(const hexrays_vars_t &hv, ea_t ea)
{
  // represent BADADDR as 0xffffffff if ida64 is running with a 32bit binary
  return ea == BADADDR ? hv.eah().mask : ea;
}
static ea_t align_badaddr(ea_t ea)
{
  return ea == BADADDR
       ? align_badaddr(*GET_MODULE_DATA(hexrays_vars_t), ea)
       : ea;
}
#else
static ea_t align_badaddr(const hexrays_vars_t &, ea_t ea)
{
  return ea;
}
static ea_t align_badaddr(ea_t ea)
{
  return ea;
}
#endif

//-------------------------------------------------------------------------
template<> const char *intvec_t::dstr() const   //lint !e1763 contains deep modification
{
  qstring *buf = debug_getbuf();
  print_vector(buf, *this);
  return buf->c_str();
}

//lint -esym(714,refs_for_linker) not referenced
//lint -e{413} Likely use of null pointer
extern "C" void refs_for_linker()
{
GCC_DIAG_OFF(nonnull)
#define CALL_DSTR(type) ((type*)0)->dstr()
  CALL_DSTR(intvec_t);
  CALL_DSTR(bitset_t);
  CALL_DSTR(rlist_t);
  CALL_DSTR(ivl_t);
  CALL_DSTR(ivlset_t);
  CALL_DSTR(mlist_t);
  CALL_DSTR(lattice_t);
  CALL_DSTR(ivl64_t);
  CALL_DSTR(valrng_t);
  CALL_DSTR(valranges_t);
  CALL_DSTR(chain_t);
  CALL_DSTR(block_chains_t);
  CALL_DSTR(tinfo_t);
  CALL_DSTR(mcases_t);
  CALL_DSTR(citem_t);
  CALL_DSTR(cexpr_t);
  CALL_DSTR(cinsn_t);
  CALL_DSTR(lvar_t);
  CALL_DSTR(mop_t);
  CALL_DSTR(mcallarg_t);
  CALL_DSTR(edgevec_t);
  CALL_DSTR(argloc_t);
  CALL_DSTR(vdloc_t);
  dstr((tinfo_t*)0);
  ((mba_t*)0)->dump_lvars();
  ((mba_t*)0)->dump();
  ((mblock_t*)0)->dump();
  ((cfunc_t*)0)->dump();
  dump_insns(nullptr, nullptr);
#if defined(TESTABLE_BUILD) && defined(_DEBUG)
  dgr(0);
  ((simple_graph_t*)0)->wingraph32(false, "");
#endif
GCC_DIAG_ON(nonnull)
}

//--------------------------------------------------------------------------
// used for debugging only
const char *anch(uval_t x)
{
  ctree_anchor_t ca;
  ca.value = x;
  if ( !ca.is_valid_anchor() )
    return "BAD_ANCHOR";

  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  qstring *out = hv.debug_getbuf();
  if ( ca.is_citem_anchor() )
  {
    citem_t *item = hv.gfunc->get_citem_by_anchor(ca);
    if ( ca.is_blkcmt_anchor() )
      out->cat_sprnt("BLKCMT for citem %p:", item);
    if ( item != nullptr )
      item->print1(out, hv.gfunc);
    tag_remove(out);
  }
  else if ( ca.is_lvar_anchor() )
  {
    lvar_t *v = hv.gfunc->get_lvar_by_anchor(ca);
    *out = hv.gmba->print_lvar(v);
    tag_remove(out);
  }
  else if ( ca.is_itp_anchor() )
  {
    int idx = ca.get_index();
    out->sprnt("ITP %d", idx);
  }
  return out->c_str();
}

//--------------------------------------------------------------------------
const char *lvar_t::dstr() const
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  qstring *buf = hv.debug_getbuf();
  *buf = hv.gmba->print_lvar(this, true);
  return buf->c_str();
}

//--------------------------------------------------------------------------
const char *cexpr_t::dstr() const
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  qstring *buf = hv.debug_getbuf();
  print1(buf, hv.gfunc);
  tag_remove(buf);
  return buf->c_str();
}

//--------------------------------------------------------------------------
const char *cinsn_t::dstr() const
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  qstring *buf = hv.debug_getbuf();
  print1(buf, hv.gfunc);
  tag_remove(buf);
  return buf->c_str();
}

//--------------------------------------------------------------------------
const char *citem_t::dstr() const
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  qstring *buf = hv.debug_getbuf();
  print1(buf, hv.gfunc);
  tag_remove(buf);
  return buf->c_str();
}

//--------------------------------------------------------------------------
const char *dstr(const type_t *type)
{
  tinfo_t tif;
  if ( tif.deserialize(nullptr, &type) )
    return tif.dstr();
  return "?";
}

//--------------------------------------------------------------------------
//lint -e{413} Likely use of null pointer
const char *dstr(const tinfo_t *tif)
{
  return tif->dstr();
}

//--------------------------------------------------------------------------
const char *argloc_t::dstr() const
{
  char bbb[MAXSTR];
  if ( print_argloc(bbb, sizeof(bbb), *this) == 0 )
    return "?";
  qstring *buf = debug_getbuf();
  *buf = bbb;
  return buf->c_str();
}

//--------------------------------------------------------------------------
const char *vdloc_t::dstr(int width) const
{
  qstring *buf = debug_getbuf();
  print_vdloc(MVM, buf, *this, width);
  if ( buf->empty() )
    return "?";
  return buf->c_str();
}

//-------------------------------------------------------------------------
const char *lvar_locator_t::dstr() const
{
  const mvm_t &mvm = MVM;
  qstring *buf = debug_getbuf();
  print_vdloc(mvm, buf, location, slotsize(mvm));
  if ( buf->empty() )
    buf->append('?');
  buf->cat_sprnt(" defea=%a", align_badaddr(mvm.hv, defea));
  return buf->c_str();
}

//-------------------------------------------------------------------------
qstring print_lvinf(const mvm_t &mvm, const lvar_saved_info_t &lsi)
{
  qstring buf;

  if ( !lsi.type.empty() )
    vd_print_type(&buf, lsi.type, lsi.name.begin());
  else if ( !lsi.name.empty() )
    buf.append(lsi.name);

  buf.append("; // ");
  { // lvar_locator_t
    qstring tmp;
    lsi.ll.location.format_vdloc(mvm, &tmp, slotsize(mvm), 0);
    if ( tmp.empty() )
      tmp.append('?');
    tmp.cat_sprnt(" defea=%a", align_badaddr(mvm.hv, lsi.ll.defea));
    buf.append(tmp);
  }

  static const char *const bits[] =
  {
    " KEEP",
    " SPLIT",
    " NOPTR",
    " NOMAP",
    " UNUSED",
  };
  for ( size_t j=0; j < qnumber(bits); j++ )
    if ( (lsi.flags & (1<<j)) != 0 )
      buf.append(bits[j]);

  if ( !lsi.cmt.empty() )
  {
    buf.append(" CMT=");
    buf.append(lsi.cmt);
  }

  return buf;
}

//-------------------------------------------------------------------------
void dump_lvar_settings(ea_t entry_ea, const lvar_uservec_t &lvinf)
{
#ifdef TESTABLE_BUILD
  const mvm_t &mvm = MVM;
  msg("USER LVAR INFO FOR %a. STKOFF_DELTA %a. %s\n",
      entry_ea,
      lvinf.stkoff_delta,
      (lvinf.ulv_flags & ULV_PRECISE_DEFEA) != 0 ? "PRECISE_DEFEA" : "");
  for ( int i=0; i < lvinf.lvvec.size(); i++ )
  {
    const lvar_saved_info_t &lsi = lvinf.lvvec[i];
    qstring buf = print_lvinf(mvm, lsi);
    msg("%d. %s\n", i, buf.c_str());
  }

  const lvar_mapping_t &m = lvinf.lmaps;
  for ( lvar_mapping_t::const_iterator p=m.begin(); p != m.end(); ++p )
    msg("MAP {%s} -> {%s}\n", p->first.dstr(), p->second.dstr());
#else
  qnotused(entry_ea);
  qnotused(lvinf);
#endif
}

//-------------------------------------------------------------------------
void get_preciser_text(qstring *out, item_preciser_t itp)
{
  const char *ptr = nullptr;
  switch ( itp )
  {
    case ITP_EMPTY:   ptr = "empty";    break;
    case ITP_ELSE:    ptr = "else";     break;
    case ITP_DO:      ptr = "do";       break;
    case ITP_ASM:     ptr = "asm";      break;
    case ITP_SEMI:    ptr = ";";        break;
    case ITP_CURLY1:  ptr = "{";        break;
    case ITP_CURLY2:  ptr = "}";        break;
    case ITP_BRACE1:  ptr = "(";        break;
    case ITP_BRACE2:  ptr = ")";        break;
    case ITP_BLOCK1:  ptr = "/*pre*/";  break;
    case ITP_BLOCK2:  ptr = "/*post*/"; break;
    case ITP_COLON:   ptr = ":";        break;
    case ITP_TRY:     ptr = "try";      break;
    default:
      break;
  }
  if ( ptr != nullptr )
  {
    out->append(ptr);
  }
  else if ( itp >= ITP_ARG1 && itp <= ITP_ARG64 )
  {
    out->cat_sprnt("ARG%d", itp-ITP_ARG1+1);
  }
  else if ( (itp & ITP_CASE) != 0 )
  {
    int32 caseval = get_case_value(itp);
    out->cat_sprnt("case_%X", caseval);
  }
  else
  {
    out->cat_sprnt("%X", itp);
  }
}

//--------------------------------------------------------------------------
void ctree_item_t::print(qstring *out) const
{
  const char *ptr = nullptr;
  switch ( citype )
  {
    case VDI_NONE:
      ptr = "(none)";
      break;
    case VDI_EXPR:
      {
        if ( e->ea != BADADDR )
          out->sprnt("%a", e->ea);
        if ( e->op == cot_num )
          out->cat_sprnt("(%d)", e->n->nf.opnum);
        out->append(": ");
        it->print1(out, nullptr);
      }
      break;
    case VDI_LVAR:
      {
        hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
        if ( hv.gmba != nullptr )
          *out = hv.gmba->print_lvar(l);
      }
      break;
    case VDI_FUNC:
      ptr = "(func)";
      break;
    case VDI_TAIL:
      out->sprnt("cmt %a ", align_badaddr(loc.ea));
      get_preciser_text(out, loc.itp);
      break;
    default:
      ptr = "?";
      break;
  }
  if ( ptr != nullptr )
    *out = ptr;
}

//-------------------------------------------------------------------------
void mblock_t::print(vd_printer_t &vp) const
{
  mba_t *saved = hv.gmba;
  hv.gmba = mba;
  int n = 0;
  int shins_flags = mba->calc_shins_flags();
  for ( minsn_t *m=head; m != nullptr; m=m->next )
  {
    qstring buf;
    m->print(&buf, shins_flags);
    vp.print(0, "%d.%2d %s\n", serial, n++, buf.c_str());
  }
  hv.gmba = saved;
}

//-------------------------------------------------------------------------
#if 0
static void remove_unimportant_details(const char *p, char *buf, size_t bufsize)
{
  p = skip_spaces(p);
  while ( qisdigit(*p) )
    p++;
  p = skip_spaces(p);
  if ( *p == ':' )
    p++;
  p = skip_spaces(p);
  while ( qisdigit(*p) )
    p++;
  p = skip_spaces(p);
  const char *e = strchr(p, ';');
  if ( e == nullptr )
    e = tail(p);
  size_t len = e - p;
  if ( len >= bufsize )
    len = bufsize - 1;
  memcpy(buf, p, len);
  buf[len] = '\0';
  trim(buf);
}

static bool verify_rasm(const char *path)
{
  struct ida_local mbl_tester_t : public mbl_saver_t
  {
    int save(const mba_t *ba, const char * /*label*/, const char * /*checker_func*/)
    {
      // serialize-deserialize
      bytevec_t s;
      ba->serialize(s);
      mba_t *ba2 = mba_t::deserialize(&s[0], s.size());

      // compare deserialization result with the initial dump
      char outfile[QMAXPATH];
      for ( mblock_t *b=ba2->blocks; b != nullptr; b=b->nextb )
      {
        b->verify();
        mblock_dumper_t md2;
        md2.nline = 0;
        md2.serial = 0;
        b->print(md2);
        // save it into a file
        if ( !dumpdir.empty() )
        {
          qmakepath(outfile, sizeof(outfile), dumpdir.begin(), "rasm.dmp", nullptr);
          FILE *fp = fopenWT(outfile);
          for ( int i=0; i < md2.lines.size(); i++ )
            qfprintf(fp, "%s\n", md2.lines[i].c_str());
          qfclose(fp);
        }
        // compare results
        int n1 = md.lines.size() - oldn;
        int n2 = md2.lines.size();
        for ( int i=0; i < qmin(n1, n2); i++ )
        {
          char s1[MAXSTR];
          char s2[MAXSTR];
          remove_unimportant_details(md.lines[i+oldn].c_str(), s1, sizeof(s1));
          remove_unimportant_details(md2.lines[i].c_str(), s2, sizeof(s2));
          if ( strcmp(s1, s2) != 0 )
          {
            error("line %d mismatch\n"
                  "%s\n"
                  "%s\n",
                  i+1,
                  s1, s2);
          }
        }
        if ( n1 != n2 )
          error("md lines mismatch %d %d", n1, n2);
      }
      delete ba2;
      return 0;
    }
  };

  vd_printer_t vp;
  mbl_tester_t mt;
  return parse_mcode_file(path, vp, mt) == 0;
}
#endif

//-------------------------------------------------------------------------
void showmic_vars_t::get_dump_file_name(char *buf, size_t bufsize, int serial)
{
  qsnprintf(buf, bufsize,
            "%s%cb%05dd%03d.dmp",
            dumpdir.begin(), DIRCHAR, dumpnum++, serial);
}

//-------------------------------------------------------------------------
void mblock_t::vdump_block(const char *title, va_list va) const
{
  showmic_vars_t &sv = *hv.showmic_vars;
  if ( under_debugger
    && !empty()
    && !sv.dumpdir.empty()
    && ((mba->get_mba_flags() & MBA_PREOPT) != 0 || strneq(title, "debug", 5)) )
  {
    mblock_dumper_t &md = sv.md;
    char path[QMAXPATH];
    sv.get_dump_file_name(path, sizeof(path), serial);

    strlist oldlines;
    oldlines.swap(md.lines);
    md.nline = 0;
    md.serial = serial;
    hv.gmba = mba;
    print(md);

    // find the first different line
    int n = qmin(md.lines.size(), oldlines.size());
    int i;
    for ( i=0; i < n; i++ )
      if ( md.lines[i] != oldlines[i] )
        break;
    if ( i == n )
      i = sv.oldn;
    i -= i % 20;

    FILE *fp = fopenWT(path);
    if ( fp == nullptr )
    {
      msg("%s: %s\n", path, qstrerror(-1));
    }
    else
    {
      if ( sv.oldn != i )
      {
        sv.oldn = i;
        qfprintf(fp, "; block %d: scrolling to %d\n\n", serial, i);
        for ( int j=i; j < oldlines.size(); j++ )
          qfprintf(fp, "%s", oldlines[j].c_str());
        qfclose(fp);
        char *p = strrchr(path, '.');
        qstrncpy(p, "a.dmp", path+sizeof(path)-p);    //-V575 The potential null pointer is passed into function
        fp = fopenWT(path);
      }

      qfprintf(fp, "pattern block_%d 0x%a; ", serial, align_badaddr(hv, start));
      qvfprintf(fp, title, va);
      qfprintf(fp, "\n\n");

      while ( i < md.lines.size() )
        qfputs(md.lines[i++].c_str(), fp);

      qfprintf(fp, "\nendp\n");
      qfclose(fp);
    }
    eavec_t seen_calls;
    verify(&seen_calls);
  } //lint !e593 custodial pointer possibly not freed nor returned
}

//-------------------------------------------------------------------------
void mblock_t::dump() const
{
  dump_block("debugger");
}

//-------------------------------------------------------------------------
void mba_t::dump_lvars() const
{
  int idx = 0;
  vd_printer_t vp;
  for ( lvars_t::const_iterator p=vars.begin(); p != vars.end(); ++p,++idx )
  {
    vp.print(0, "%3d: ", idx);
    print_lvar(p, 0, vp);
  }
}

//-------------------------------------------------------------------------
void dump_insns(const minsn_t *i1, const minsn_t *i2)
{
  int i = 0;
  while ( i1 != nullptr )
  {
    msg("%d: %s\n", i++, i1->dstr());
    if ( i1 == i2 )
      break;
    i1 = i1->next;
  }
}

//-------------------------------------------------------------------------
void mba_t::dump() const
{
  dump_mba(false, "debugger");
}

//-------------------------------------------------------------------------
void mba_t::print(vd_printer_t &vp) const
{
  mba_t *saved = hv.gmba;
  hv.gmba = CONST_CAST(mba_t *)(this);

  microplace_t mp;
  linearray_t la(CONST_CAST(mba_t*)(this));
  la.set_place(&mp);
  while ( true )
  {
    const qstring *line = la.down();
    if ( line == nullptr )
      break;
    vp.print(0, "%s\n", line->c_str());
  }

  hv.gmba = saved;
}

//-------------------------------------------------------------------------
void mba_t::vdump_mba(bool do_verify, const char *title, va_list va) const
{
  showmic_vars_t &sv = *hv.showmic_vars;
  if ( under_debugger && !sv.dumpdir.empty() )
  {
    char path[QMAXPATH];
    sv.get_dump_file_name(path, sizeof(path), -1);
    FILE *outfp = fopenWT(path);
    if ( outfp == nullptr )
    {
      msg("Cannot open output file %s\n", path);
      return;
    }

    qvfprintf(outfp, title, va);
    qfprintf(outfp, "\n");

    file_printer_t fpr(outfp);
    print(fpr);
    qfclose(outfp);
  }
  if ( do_verify )
    verify(false);
}

//-------------------------------------------------------------------------
void mba_t::init_dump() const
{
  if ( !under_debugger )
    return;

  showmic_vars_t &sv = *hv.showmic_vars;
  sv.dumpnum = 0;
  if ( qgetenv("IDA_DUMPDIR", &sv.dumpdir) && !sv.dumpdir.empty() )
  {
    const char *dir = sv.dumpdir.begin();
    qmkdir(dir, 0777);
    qffblk64_t fb;
    char path[QMAXPATH];
    qmakepath(path, sizeof(path), dir, "*.dmp", nullptr);
    for ( int code = qfindfirst(path, &fb, 0);
          code == 0;
          code = qfindnext(&fb) )
    {
      qmakepath(path, sizeof(path), dir, fb.ff_name, nullptr);
      qunlink(path);
    }
  }
}

//-------------------------------------------------------------------------
void mba_t::init_ivl_names()
{
  std_ivls[MMIDX_GLBLOW].whole = "GLBLOW";
  std_ivls[MMIDX_GLBLOW].part = nullptr;
  std_ivls[MMIDX_LVARS].whole = "LVARS";
  std_ivls[MMIDX_LVARS].part = "sp";
  std_ivls[MMIDX_RETADDR].whole = "RET";
  std_ivls[MMIDX_RETADDR].part = "retaddr";
  std_ivls[MMIDX_SHADOW].whole = "SHADOW";
  std_ivls[MMIDX_SHADOW].part = "shadow";
  std_ivls[MMIDX_ARGS].whole = "ARGS";
  std_ivls[MMIDX_ARGS].part = "arg";
  std_ivls[MMIDX_GLBHIGH].whole = "GLBHIGH";
  std_ivls[MMIDX_GLBHIGH].part = nullptr;
}

//-------------------------------------------------------------------------
static void append_name(qstring *out, const char *name)
{
  bool badname = false;
  for ( const char *p=name; *p; p++ )
  {
    if ( !qisalnum(*p) && *p != '_' )
    {
      badname = true;
      break;
    }
  }
  if ( badname )
    out->append('"');
  out->append(name);
  if ( badname )
    out->append('"');
}

//-------------------------------------------------------------------------
static void print_number(qstring *out, uint64 n, bool with_sharp)
{
  if ( with_sharp )
    out->append('#');

  int64 value = n;
  const uint64 signbit = left_shift(uint64(1), sizeof(uint64)*8-1);
  if ( value < 0 && value != signbit )
  {
    out->append('-');
    value = -value;
  }

  // print small numbers as decimal
  out->cat_sprnt(uint64(value) < 10 ? "%" FMT_64 "d" : "0x%" FMT_64 "X", value);
}

//-------------------------------------------------------------------------
GCC_DIAG_OFF(format-nonliteral);
static void make_expr(qstring *out, const minsn_t *m, int shins_flags)
{
  qstring ql;
  qstring qr;
  m->l.print(&ql, shins_flags);
  m->r.print(&qr, shins_flags);
  const char *lbuf = ql.c_str();
  const char *rbuf = qr.c_str();
  const char *fmt = nullptr;
  switch ( m->opcode )
  {
    default:
      out->cat_sprnt("?%s?", rasm_keywords[m->opcode]);
      break;
    case m_xds:
    case m_xdu:
    case m_low:
    case m_high:
    case m_fneg:
    case m_f2i:
    case m_f2u:
    case m_i2f:
    case m_u2f:
    case m_f2f:
      out->cat_sprnt("%s.%d(%s)", rasm_keywords[m->opcode], m->d.size, lbuf);
      break;
    case m_ldx:
      out->cat_sprnt("[%s:%s]%s.%d", lbuf, rbuf, m->is_fpinsn() ? "f" : "", m->d.size);
      if ( (shins_flags & SHINS_LDXEA) != 0 && m->ea != BADADDR )
        out->cat_sprnt(COLSTR("@%a", SCOLOR_AUTOCMT), align_badaddr(m->ea));
      break;
    case m_ldc:
    case m_mov:   fmt = "mov(%s)";      break;
    case m_neg:   fmt = "-(%s)";        break;
    case m_setz:  fmt = m->is_fpinsn() ? "(%s ==f %s)" : "(%s == %s)";  break;
    case m_setnz: fmt = m->is_fpinsn() ? "(%s !=f %s)" : "(%s != %s)";  break;
    case m_setae: fmt = m->is_fpinsn() ? "(%s >=f %s)" : "(%s >=u %s)"; break;
    case m_setbe: fmt = m->is_fpinsn() ? "(%s <=f %s)" : "(%s <=u %s)"; break;
    case m_setb:  fmt = m->is_fpinsn() ? "(%s <f %s)"  : "(%s <u %s)";  break;
    case m_seta:  fmt = m->is_fpinsn() ? "(%s >f %s)"  : "(%s >u %s)";  break;
    case m_setp:  fmt = m->is_fpinsn() ? "(%s <> %s)"  : "(%s ?p %s)";  break;
    case m_sets:  fmt = "SF(%s)";       break;
    case m_setg:  fmt = "(%s >s %s)";   break;
    case m_setge: fmt = "(%s >=s %s)";  break;
    case m_setl:  fmt = "(%s <s %s)";   break;
    case m_setle: fmt = "(%s <=s %s)";  break;
    case m_seto:  fmt = "OF(%s-%s)";    break;
    case m_lnot:  fmt = "lnot(%s)";     break;
    case m_bnot:  fmt = "bnot(%s)";     break;
    case m_add:   fmt = "(%s+%s)";      break;
    case m_sub:   fmt = "(%s-%s)";      break;
    case m_mul:   fmt = "(%s*%s)";      break;
    case m_udiv:  fmt = "(%s /u %s)";   break;
    case m_sdiv:  fmt = "(%s /s %s)";   break;
    case m_umod:  fmt = "(%s %%u %s)";  break;
    case m_smod:  fmt = "(%s %%s %s)";  break;
    case m_or:    fmt = "(%s | %s)";    break;
    case m_and:   fmt = "(%s & %s)";    break;
    case m_xor:   fmt = "(%s ^ %s)";    break;
    case m_cfshl: fmt = "CF(%s << %s)"; break;
    case m_cfshr: fmt = "CF(%s >> %s)"; break;
    case m_shl:   fmt = "(%s <<l %s)";  break;
    case m_shr:   fmt = "(%s >>l %s)";  break;
    case m_sar:   fmt = "(%s >>a %s)";  break;
    case m_cfadd: fmt = "CF(%s+%s)";    break;
    case m_ofadd: fmt = "OF(%s+%s)";    break;
    case m_fadd:  fmt = "(%s +f %s)";   break;
    case m_fsub:  fmt = "(%s -f %s)";   break;
    case m_fmul:  fmt = "(%s *f %s)";   break;
    case m_fdiv:  fmt = "(%s /f %s)";   break;
    case m_call:
      out->cat_sprnt("%s %s%s", rasm_keywords[m->opcode], lbuf, rbuf);
      m->d.print(out, shins_flags);
      break;
    case m_icall:
      out->cat_sprnt("%s %s,%s", rasm_keywords[m->opcode], lbuf, rbuf);
      m->d.print(out, shins_flags);
      break;
  }
  if ( fmt != nullptr )
    out->cat_sprnt(fmt, lbuf, rbuf);
}
GCC_DIAG_ON(format-nonliteral);

//-------------------------------------------------------------------------
static void print_type(qstring *out, const tinfo_t &type, const qstring &name)
{
  qstring tb;
  vd_print_type(&tb, type, name.begin());
  append_name(out, tb.c_str());
}

//-------------------------------------------------------------------------
void mcallarg_t::print(qstring *out, int shins_flags) const
{
  print_type(out, type, name);
  out->append(' ');
  mop_t::print(out, shins_flags);
}

//-------------------------------------------------------------------------
void mcallinfo_t::print(qstring *out, int size, int shins_flags) const
{
  const char *ccname = "?";
  switch ( get_cc(cc) )
  {
    case CM_CC_INVALID : ccname = "inv";  break; // this value is invalid
    case CM_CC_UNKNOWN : ccname = "unk";  break; // unknown calling convention
    case CM_CC_VOIDARG : ccname = "void"; break; // function without arguments
    case CM_CC_CDECL   : ccname = "cdecl";break; // stack
    case CM_CC_ELLIPSIS: ccname = "...";  break; // cdecl + ellipsis
    case CM_CC_STDCALL : ccname = "std";  break; // stack, purged
    case CM_CC_PASCAL  : ccname = "pas";  break; // stack, purged, reverse order of args
    case CM_CC_FASTCALL: ccname = "fast"; break; // stack, first args are in regs (compiler-dependent)
    case CM_CC_THISCALL: ccname = "this"; break; // stack, first arg is in reg (compiler-dependent)
    case CM_CC_SWIFT   : ccname = "swft"; break; // special case for compiler specific
    case CM_CC_SPOILED : ccname = "!spl"; break;
    case CM_CC_GOLANG  : ccname = "go";   break;
    case CM_CC_RESERVE3: ccname = "rsv3"; break;
    case CM_CC_SPECIALE: ccname = "spce"; break;
    case CM_CC_SPECIALP: ccname = "spcp"; break;
    case CM_CC_SPECIAL : ccname = "spec"; break;  // locations of all arguments and the return
  }
  out->append('<');
  if ( get_cc(cc) != CM_CC_VOIDARG )
  {
    out->append(ccname);
    out->append(':');
    int n = args.size();
    for ( int i=0; i < n; i++ )
    {
      if ( i != 0 )
        out->append(',');
      if ( args[i].empty() )
        out->cat_sprnt("?");
      else
        args[i].print(out, shins_flags);
    }
  }
  out->append('>');
  if ( !retregs.empty() )
  {
    out->cat_sprnt(" => ");
    print_type(out, return_type, "");
    out->append(' ');
    for ( int i=0; i < retregs.size(); i++ )
    {
      if ( i != 0 )
        out->append(':');
      retregs[i].print(out);
    }
  }
  else if ( size != -1 )
  {
    out->cat_sprnt(".%d", size);
  }
}

//-------------------------------------------------------------------------
void mcases_t::print(qstring *out) const
{
  out->append('{');
  for ( int i=0; i < size(); i++ )
  {
    if ( i > 0 )
      out->append(", ");
    const svalvec_t &v = values[i];
    if ( v.empty() )
    {
      out->append("def");
    }
    else
    {
      for ( int j=0; j < v.size(); j++ )
      {
        if ( j != 0 )
          out->append(',');
        print_number(out, v[j], false);
      }
    }
    out->cat_sprnt(" => %d", targets[i]);
  }
  out->append('}');
}

//-------------------------------------------------------------------------
void mop_t::print(qstring *out, int shins_flags) const
{
  int s2 = size;
  color_t color = '\0';
  switch ( t )
  {
    case mop_z:         // none
      break;
    case mop_b:         // micro basic block (mblock_t)
      tag_on(out, color=COLOR_MACRO);
      out->cat_sprnt("@%d", b);
      break;
    case mop_v:         // global variable
      tag_on(out, color=COLOR_DNAME);
      {
        out->append('$');
        ea_t head = get_item_head(g);
        if ( !has_any_name(get_flags(head)) )
          set_dummy_name(BADADDR, head);
        qstring name;
        if ( get_name(&name, head) > 0 )
        {
          append_name(out, name.begin());
          if ( g != head )
            out->cat_sprnt("@%" FMT_EA "u", g - head);
        }
        else
        {
          out->cat_sprnt("0x%a", align_badaddr(g));
        }
      }
      break;
    case mop_d:         // result of another instruction
      s2 = NOSIZE;
      tag_on(out, color=VD_COLOR_KEYWORD);
      make_expr(out, d, shins_flags);
      break;
    case mop_n:         // immediate
      tag_on(out, color=VD_COLOR_NUMBER);
      print_number(out, nnn->value, true);
      if ( nnn->ea != BADADDR && (shins_flags & SHINS_NUMADDR) != 0 )
      {
        tag_off(out, color);
        tag_on(out, color=COLOR_AUTOCMT);
        out->cat_sprnt("@%a", align_badaddr(nnn->ea));
      }
      break;
    case mop_r:         // register
      tag_on(out, color=VD_COLOR_REG);
      {
        qstring tmp;
        get_mreg_name(MVM, &tmp, r, size);
        out->append(tmp.c_str());
      }
      break;
    case mop_S:         // stack variable
      tag_on(out, color=COLOR_DREFTAIL); // olive
      {
        uval_t off;
        out->append('%');
        udm_t stkvar;
        ssize_t stkvar_idx = get_stkvar(&stkvar, &off);
        if ( stkvar_idx != -1 )
        {
          append_name(out, stkvar.name.c_str());
          sval_t delta = off - stkvar.offset/8;
          if ( delta != 0 )
            out->cat_sprnt("@%" FMT_EA "d", delta);
        }
        else
        {
          out->cat_sprnt("0x%a", uval_t(s->off));
        }
      }
      break;
    case mop_f:
      tag_on(out, color=VD_COLOR_SYMBOL);
      f->print(out, s2, shins_flags);
      s2 = NOSIZE;
      break;
    case mop_l: // local c variable
      {
        bool varok = false;
        color = l->mba != nullptr ? VD_COLOR_IMPORT : VD_COLOR_ERROR;
        tag_on(out, color);
        if ( l->mba != nullptr && l->idx < l->mba->vars.size() )
        {
          const lvar_t &v = l->var();
          if ( !v.name.empty() )
          {
            append_name(out, v.name.begin());
            varok = true;
          }
        }
        if ( !varok )
          out->cat_sprnt("?%d", l->idx);
        if ( l->off != 0 )
          out->cat_sprnt("@%" FMT_EA "d", l->off);
      }
      break;
    case mop_a:
      tag_on(out, color=VD_COLOR_SYMBOL);
      out->append('&');
      out->append('(');
      a->print(out, shins_flags);
      out->append(')');
      if ( a->insize != NOSIZE || a->outsize != NOSIZE )
      {
        out->append('<');
        if ( a->insize != NOSIZE )
          out->cat_sprnt("%d", a->insize);
        out->append('/');
        if ( a->outsize != NOSIZE )
          out->cat_sprnt("%d", a->outsize);
        out->append('>');
      }
      break;
    case mop_h:
      tag_on(out, color=COLOR_CODNAME);
      out->cat_sprnt("!%s", helper);
      break;
    case mop_c:
      tag_on(out, color=VD_COLOR_SYMBOL);
      c->print(out);
      break;
    case mop_fn:
      tag_on(out, color=VD_COLOR_FPNUM);
      out->append('#');
      out->append('(');
      fpc->print(out);
      out->append(')');
      break;
    case mop_p:
      tag_on(out, color=VD_COLOR_SYMBOL);
      out->append(":(");
      pair->hop.print(out, shins_flags);
      out->append(',');
      pair->lop.print(out, shins_flags);
      out->append(')');
      s2 = NOSIZE;
      break;
    case mop_sc:
      tag_on(out, color=VD_COLOR_SYMBOL);
      out->append("@<");
      if ( !scif->type.empty() )
        print_type(out, scif->type, "");
      else
        out->append("\"\"");
      out->append(' ');
      print_vdloc(scif->mba->mvm, out, *scif, size);
      out->append('>');
      break;
    case mop_str:
      tag_on(out, color=VD_COLOR_STRING);
      out->append('"');
      out->append(cstr);
      out->append('"');
      break;
    default:
      if ( under_debugger )
        out->append("ILLEGAL_MOP");
      else
        INTERR(50581);
  }
  if ( s2 != NOSIZE )
    out->cat_sprnt(".%d", s2);
  if ( color != '\0' )
    tag_off(out, color);
  if ( (shins_flags & SHINS_VALNUM) != 0 && valnum != 0 )
  {
    tag_on(out, COLOR_AUTOCMT);
    out->cat_sprnt("{%d}", valnum);
    tag_off(out, COLOR_AUTOCMT);
  }
}

//-------------------------------------------------------------------------
void mba_t::print_insn_usedef(qstring *out, const minsn_t &insn) const
{
  mlist_t yu = blocks->build_use_list(insn, MAY_ACCESS);
  mlist_t tu = blocks->build_use_list(insn, MUST_ACCESS);
  qstring buf1;
  qstring buf2;
  tu.print(&buf1);
  if ( yu == tu )
  {
    out->cat_sprnt("u=%-10s", buf1.c_str());
  }
  else
  {
    yu.sub(tu);
    yu.print(&buf2);
    out->cat_sprnt("u=%s%s(%s)", buf1.c_str(), tu.empty() ? "" : ",", buf2.c_str());
  }
  mlist_t yd = blocks->build_def_list(insn, MAY_ACCESS);
  if ( !yd.empty() )
  {
    mlist_t td = blocks->build_def_list(insn, MUST_ACCESS);
    buf1.qclear();
    td.print(&buf1);
    out->cat_sprnt(" d=%s", buf1.c_str());
    if ( yd != td )
    {
      if ( !td.empty() )
      {
        out->append(',');
        yd.sub(td);
      }
      buf2.qclear();
      yd.print(&buf2);
      out->cat_sprnt("(%s)", buf2.c_str());
      mlist_t pd = yd;
      pd.sub(blocks->build_def_list(insn, MAY_ACCESS | EXCLUDE_PASS_REGS));
      if ( !pd.empty() )
      {
        out->append(',');
        buf2.qclear();
        pd.print(&buf2);
        out->cat_sprnt("pass=%s", buf2.c_str());
      }
    }
  }
}

//--------------------------------------------------------------------------
static void add_spaces(qstring *buf, ssize_t len)
{
  if ( len > 0 )
  {
    len -= tag_strlen(buf->c_str());
    if ( len > 0 )
      buf->fill(buf->length(), ' ', len);
  }
}

//-------------------------------------------------------------------------
//lint -esym(773,DIAG_NAME) expression-like macro 'DIAG_NAME' not parenthesized
#ifdef __MAC__
#define DIAG_NAME tautological-undefined-compare
#elif defined(__GNUC__) && __GNUC__ >= 6
#define DIAG_NAME nonnull-compare
#endif
#ifdef DIAG_NAME
GCC_DIAG_OFF(DIAG_NAME);
#endif
void minsn_t::print(qstring *out, int shins_flags) const
{
  if ( this == nullptr ) //lint !e3417 this is never null //-V704
  {
    out->append("(null)");
    return;
  }

  if ( is_optional()     ) out->append(KEYCOL("opt") " ");
  if ( is_persistent()   ) out->append(KEYCOL("keep") " ");
  if ( is_wild_match()   ) out->append(KEYCOL("many") " ");
  if ( is_cleaning_pop() ) out->append(KEYCOL("sideft") " ");

  const char *mnem = (opcode < 0 || opcode >= m_max) ? "???" : rasm_keywords[opcode];   //lint !e685 //-V560 A part is always false
  size_t len = strlen(mnem);
  tag_on(out, VD_COLOR_KEYWORD);
  out->append(mnem);
  if ( is_fpinsn() && !is_mcode_fpu(opcode) )
  {
    out->append(".fpu");
    len += 4;
  }
  tag_off(out, VD_COLOR_KEYWORD);

  // align instruction mnemonics
  do
    out->append(' ');
  while ( ++len < 7 );

  // output operands
  if ( opcode == m_call && d.is_arglist() )
  {
    l.print(out, shins_flags);
    out->append(' ');
    d.print(out, shins_flags);
  }
  else
  {
    qstring tmp;
    bool comma = false;
    for ( int i=0; i < 3; i++ )
    {
      switch ( i )
      {
        case 0:
          l.print(&tmp, shins_flags);
          break;
        case 1:
          r.print(&tmp, shins_flags);
          break;
        case 2:
          d.print(&tmp, shins_flags);
          break;
      }
      if ( !tmp.empty() )
      {
        if ( comma )
          out->append(SYMCOL(",") " ");
        out->append(tmp);
        tmp.qclear();
        comma = true;
      }
    }
  }
  if ( (shins_flags & SHINS_SHORT) == 0 )
  {
    add_spaces(out, 30);
    tag_on(out, COLOR_AUTOCMT);
    out->cat_sprnt(" ; %a ", align_badaddr(ea));
    if ( is_inverted_jx()   ) out->append("inverted_jx ");
    if ( is_ignlowsrc()     ) out->append("ignlowsrc ");
    if ( !is_propagatable() ) out->append("dontprop ");
    if ( is_combined()      ) out->append("combined ");
    if ( was_unpaired()     ) out->append("unpaired ");
    if ( is_farcall()       ) out->append("farcall ");
    if ( is_cleaning_pop()  ) out->append("popecx ");
    if ( is_extstx()        ) out->append("extstx ");
    if ( is_tailcall()      ) out->append("tailcall ");
    if ( is_assert()        ) out->append("assert ");
    if ( is_multimov()      ) out->append("multimov ");
    if ( !is_combinable()   ) out->append("not_combinable ");
    if ( was_noret_icall()  ) out->append("was_noret_icall ");
    if ( is_mbarrier()      ) out->append("mbarrier ");
    if ( was_unmerged()     ) out->append("unmerged ");
    int split = get_split_size();
    if ( split != 0 )
      out->cat_sprnt("split%d ", split);
    if ( l.is_udt() || r.is_udt() || d.is_udt() )
    {
      char buf[10]; // "udt(lrd) "
                    //  123456789
      char *ptr = qstpncpy(buf, "udt(", sizeof(buf));
      if ( l.is_udt() )
        *ptr++ = 'l';
      if ( r.is_udt() )
        *ptr++ = 'r';
      if ( d.is_udt() )
        *ptr++ = 'd';
      *ptr++ = ')';
      *ptr++ = ' ';
      *ptr++ = '\0';
      out->append(buf);
    }
    if ( !is_fpinsn()
      && (l.probably_floating()
       || r.probably_floating()
       || d.probably_floating()) )
    {
      char buf[12]; // "float(lrd) "
                    //  123456789012
      char *ptr = qstpncpy(buf, "float(", sizeof(buf));
      if ( l.probably_floating() )
        *ptr++ = 'l';
      if ( r.probably_floating() )
        *ptr++ = 'r';
      if ( d.probably_floating() )
        *ptr++ = 'd';
      *ptr++ = ')';
      *ptr++ = ' ';
      *ptr++ = '\0';
      out->append(buf);
    }
    if ( l.is_lowaddr() || r.is_lowaddr() || d.is_lowaddr() )
    {
      char buf[14]; // "lowaddr(lrd) "
                    //  12345678901234
      char *ptr = qstpncpy(buf, "lowaddr(", sizeof(buf));
      if ( l.is_lowaddr() )
        *ptr++ = 'l';
      if ( r.is_lowaddr() )
        *ptr++ = 'r';
      if ( d.is_lowaddr() )
        *ptr++ = 'd';
      *ptr++ = ')';
      *ptr++ = ' ';
      *ptr++ = '\0';
      out->append(buf);
    }
    hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
    if ( hv.gmba != nullptr )
      hv.gmba->print_insn_usedef(out, *this);
    tag_off(out, COLOR_AUTOCMT);
  }
}
#ifdef DIAG_NAME
GCC_DIAG_ON(DIAG_NAME);
#endif

//-------------------------------------------------------------------------
int minsn_t::print(vd_printer_t &vp, int shins_flags) const
{
  qstring buf;
  print(&buf, shins_flags);
  return vp.print(0, "%s", buf.c_str());
}

//-------------------------------------------------------------------------
//lint -esym(528, print_vector_element) not referenced
static void print_vector_element(qstring *out, const edge_t &e)
{
  out->cat_sprnt("(%d,%d)", e.src, e.dst);
}

//-------------------------------------------------------------------------
void edgevec_t::print(qstring *out) const
{
  print_vector(out, *this);
}

//-------------------------------------------------------------------------
static const char *print_block_type(mblock_type_t type)
{
  static const char *const names[] =
  {
    "NONE",
    "STOP",
    "0WAY",
    "1WAY",
    "2WAY",
    "NWAY",
    "XTRN",
  };
  if ( type > 0 && type < qnumber(names) )
    return names[type];
  return COLSTR("????", SCOLOR_ERROR);
}

//--------------------------------------------------------------------------
template <class T>
static void print_list(qstrvec_t *vec, const char *header, const T &must, T may)
{
  if ( !may.empty() )
  {
    qstring buf;
    try
    {
      must.print(&buf);
      if ( may != must )
      {
        may.sub(must);
        if ( !must.empty() )
          buf.append(',');
        buf.append('(');
        may.print(&buf);
        buf.append(')');
      }
    }
    catch ( const vd_failure_t &ve )
    {
      buf = ve.hf.desc();
    }
    vec->push_back().sprnt(COLSTR("; %s: %s", SCOLOR_RPTCMT), header, buf.c_str());
  }
}

//--------------------------------------------------------------------------
template <class T>
static void print_list(qstrvec_t *vec, const char *header, const T &lst)
{
  if ( !lst.empty() )
  {
    qstring lstr;
    lst.print(&lstr);
    vec->push_back().sprnt(COLSTR("; %s: %s", SCOLOR_RPTCMT), header, lstr.c_str());
  }
}

//-------------------------------------------------------------------------
static qstring print_ea_with_orig(const mba_t *mba, ea_t ea)
{
  qstring s;
  ea = align_badaddr(mba->hv, ea);
  ea_t orig_ea = mba->map_fict_ea(ea);
  if ( orig_ea != ea )
    s.sprnt("%a(%a)", ea, orig_ea);
  else
    s.sprnt("%a", ea);
  return s;
}

//-------------------------------------------------------------------------
void mblock_t::print_block_header(qstrvec_t *vec) const
{
  qstring buf;
  if ( serial == 0 )
  { // describe the entire microcode
    buf.sprnt(COLSTR("; STKD=%a MINREF=%a/END=%a ARGS: OFF=%a/MINREF=%a/END=%a/SHADOW=%x", SCOLOR_RPTCMT),
        uval_t(mba->tmpstk_size), // delta to convert ida_stkoff to vd_stkoff
        uval_t(mba->minstkref),
        uval_t(mba->stacksize),
        uval_t(mba->inargoff),
        uval_t(mba->minargref),
        uval_t(mba->fullsize),
        mba->shadow_args);
    vec->push_back().swap(buf);
    if ( mba->procinf != nullptr )
    {
      const intvec_t &sregs = mba->procinf->sregs;
      if ( !sregs.empty() )
      {
        buf.append(SCOLOR_ON SCOLOR_RPTCMT "; SAVEDREGS: ");
        for ( int i=0; i < sregs.size(); i++ )
        {
          if ( i != 0 )
            buf.append(',');
          rlist_t(sregs[i], mba->slotsize()).print(&buf);
        }
        buf.append(SCOLOR_OFF SCOLOR_RPTCMT);
        vec->push_back().swap(buf);
      }
    }
  }
  buf.sprnt(SCOLOR_ON SCOLOR_RPTCMT
            "; %s-BLOCK %d%s%s%s%s%s%s%s%s%s%s",
            print_block_type(type),
            serial,
            (flags & MBL_DSLOT) != 0 ? " DSLOT" : "",
            (flags & MBL_NORET) != 0 ? " NORET" : "",
            (flags & MBL_PROP)  != 0 ? " PROP" : "",
            (flags & MBL_COMB)  != 0 ? " COMB" : "",
            (flags & MBL_PUSH)  != 0 ? " PUSH" : "",
            (flags & MBL_TCAL)  != 0 ? " TAILCALL" : "",
            (flags & MBL_FAKE)  != 0 ? " FAKE" : "",
            (flags & MBL_KEEP)  != 0 ? " KEEP" : "",
            (flags & MBL_INLINED)  != 0 ? " INLINED" : "",
            (flags & MBL_EXTFRAME) != 0 ? " EXTFRAME" : "");
            // print? MBL_GOTO MBL_DMT64 MBL_DEAD MBL_BACKPROP
  if ( npred() != 0 )
  {
    buf.append(" INBOUNDS:");
    for ( int i=0; i < npred(); i++ )
      buf.cat_sprnt(" %d", pred(i));
  }
  if ( nsucc() != 0 )
  {
    buf.append(" OUTBOUNDS:");
    for ( int i=0; i < nsucc(); i++ )
      buf.cat_sprnt(" %d", succ(i));
  }
  buf.cat_sprnt(" [START=%s END=%s] MINREFS: STK=%a/ARG=%a, MAXBSP: %a" SCOLOR_OFF SCOLOR_RPTCMT,
                print_ea_with_orig(mba, start).c_str(),
                print_ea_with_orig(mba, end).c_str(),
                uval_t(minbstkref),
                uval_t(minbargref),
                uval_t(maxbsp));
  if ( (flags & MBL_EXTFRAME) != 0 )
  {
    const subframe_t &sf = mba->subframes[subframe_idx];
    buf.cat_sprnt(" SUBFRAME #%" FMT_Z " %a..%a/MINSTKREF=%a",
                subframe_idx,
                uval_t(sf.bottom),
                uval_t(sf.top()),
                uval_t(local_minstkref));
  }
  vec->push_back().swap(buf);
  // display the lists
  if ( lists_ready() )
  {
    print_list(vec, "USE", mustbuse, maybuse);
    print_list(vec, "DEF", mustbdef, maybdef);
    print_list(vec, "DNU", dnu);
  }
  else
  {
    vec->push_back(COLSTR("; USE-DEF LISTS ARE NOT READY", SCOLOR_RPTCMT));
  }
  // display value ranges
  if ( !valranges.empty() && !valranges.all_values() )
  {
    qstring vrstr;
    valranges.print(&vrstr);
    vec->push_back().sprnt(
            COLSTR("; VALRANGES: %s", SCOLOR_RPTCMT),
            vrstr.c_str());
  }
}

//-------------------------------------------------------------------------
static int print_decimal_number(qstring *out, int bit, int, void *)
{
  out->cat_sprnt("%d", bit);
  return 1;
}

//-------------------------------------------------------------------------
void bitset_t::print(
        qstring *out,
        int (*get_bit_name)(
          qstring *out,
          int bit,
          int width,
          void *ud),
        void *ud) const
{
  int delayed = -1;
  bool first = true;
  if ( bitmap != nullptr )
  {
    if ( get_bit_name == nullptr )
      get_bit_name = print_decimal_number;
    for ( size_t i=0; i <= high; i++ )
    {
      mbitmap_t bit = mbitmap_t(1) << (i & bitset_align);
      if ( i != high && (bitmap[i/bitset_width] & bit) != 0 )
      {
        if ( delayed == -1 )
          delayed = i;
      }
      else
      {
        if ( delayed != -1 )              // delayed..(i-1)
        {
          if ( !first )
            out->append(',');
          first = false;
          size_t s = i - delayed;
          while ( true )
          {
            qstring name;
            int d = get_bit_name(&name, delayed, s, ud);
            delayed += d;
            s -= d;
            out->cat_sprnt("%s.%d", name.c_str(), d);
            if ( d == 0 || s == 0 )
              break;
            out->append(',');
          }
          delayed = -1;
        }
      }
    }
  }
}

//-------------------------------------------------------------------------
inline void print_size(qstring *out, ea_t ea1, ea_t ea2, const ivl_t &ivl)
{
  asize_t s = ea2 - ea1;
  if ( ea2 == ivl.end() )
    out->cat_sprnt("..");
  else if ( s <= 12 )
    out->cat_sprnt(".%a", s);
  else
    out->cat_sprnt("..%a", ea2-ivl.off);
}

//-------------------------------------------------------------------------
void ivl_t::print(qstring *out) const
{
  if ( *this == allmem )
  {
    out->append("ALLMEM");
    return;
  }

#ifndef TEST
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  if ( hv.gmba != nullptr )
  {
    uval_t ea1 = off;
    uval_t ea2 = off + size;
    const char *comma = "";
    int numivls = qnumber(hv.gmba->std_ivls);
    for ( int i=0; i < numivls; i++ )
    {
      const ivl_with_name_t &n = hv.gmba->std_ivls[i];
      if ( ea1 >= n.ivl.end() )
        continue;
      if ( ea1 < n.ivl.off )
      {
        ea_t s2 = qmin(ea2, n.ivl.off);
        if ( ea1 < s2 )
        {
          out->cat_sprnt("%s%a", comma, ea1);
          print_size(out, ea1, s2, ivl_t(0, BADADDR));
          ea1 = s2;
          comma = ",";
        }
      }
      if ( ea2 <= n.ivl.off )
        break;
      if ( ea1 == n.ivl.off && ea2 >= n.ivl.end() )
      {
        out->cat_sprnt("%s%s", comma, n.whole);
        ea1 = n.ivl.end();
        comma = ",";
      }
      else if ( i >= numivls-1 || hv.gmba->std_ivls[i+1].ivl.off >= ea1 )
      {
        ea_t s2 = n.ivl.end();
        if ( s2 > ea2 )
          s2 = ea2;
        if ( n.part != nullptr && ea1 < s2 )
        {
          out->cat_sprnt("%s%s+%a", comma, n.part, ea1-n.ivl.off);
          print_size(out, ea1, s2, n.ivl);
          ea1 = s2;
          comma = ",";
        }
      }
    }
    if ( ea1 < ea2 )
    {
      out->cat_sprnt("%s%a", comma, ea1);
      print_size(out, ea1, ea2, ivl_t(0, BADADDR));
    }
    return;
  }
#endif
  out->cat_sprnt("%a.%a", off, size);
}

//-------------------------------------------------------------------------
void ivlset_t::print(qstring *out) const
{
  for ( const_iterator p=begin(); p != end(); ++p )
  {
    if ( p != begin() )
      out->append(',');
    p->print(out);
  }
}

//-------------------------------------------------------------------------
void ivlset64_t::print(qstring *out) const
{
  for ( const_iterator p=begin(); p != end(); ++p )
  {
    if ( p != begin() )
      out->append(',');
    p->print(out);
  }
}

//-------------------------------------------------------------------------
void vivl_t::print(qstring *vout) const
{
  if ( defined() )
    make_list(GMBA, size).print(vout);
}

//-------------------------------------------------------------------------
void mlist_t::print(qstring *out) const
{
  reg.print(out);
  if ( !mem.empty() )
  {
    if ( !reg.empty() )
      out->append(',');
    mem.print(out);
  }
}

//-------------------------------------------------------------------------
void lattice_t::print(qstring *out) const
{
  bitset_t::print(out);
  out->cat_sprnt(",%d", maxbits);
}

//-------------------------------------------------------------------------
inline void print_vector_element(qstring *vout, const range_t &v)
{
  vout->cat_sprnt("%a..%a", v.start_ea, v.end_ea);
}

//-------------------------------------------------------------------------
void mba_ranges_t::print(qstring *vout) const
{
  bool append_curly = false;
  if ( !is_snippet() )
  {
    vout->cat_sprnt("%a", pfn->start_ea);
    if ( !ranges.empty() )
    {
      vout->append("+outline{");
      append_curly = true;
    }
  }
  print_vector(vout, ranges);
  if ( append_curly )
    vout->append('}');
}

//-------------------------------------------------------------------------
// dump stack change points.
// nonfunc is a pointer to make it easier to use this function from the debugger
void mba_t::dump_stkpnts(const char *header, const ivlset_t *nonfunc) const
{
#ifdef _DUMP_STKPNTS
  if ( under_debugger )
  {
    size_t n = stkpnts.size();
    qstring rangestr;
    mbr.print(&rangestr);
    msg("STKPNTS for %s (%s; %" FMT_Z " entries); "
        "stacksize=0x%" FMT_EA "X tmpstk=0x%" FMT_EA "X",
        rangestr.c_str(), header, n, stacksize, tmpstk_size);
    ::dump_stkpnts(this, stkpnts, nullptr, nonfunc);
  }
#else
  qnotused(header);
  qnotused(nonfunc);
#endif
}

//-------------------------------------------------------------------------
void dump_stkpnts(const mba_t *mba, const stkpnts_t &stkpnts, const char *header, const ivlset_t *nonfunc)
{
  if ( header != nullptr )
    msg("%s\n", header);
  size_t n = stkpnts.size();
  for ( size_t i=0; i < n; i++ )
  {
    const stkpnt_t &sp = stkpnts[i];
    char sign = ' ';
    sval_t spd = sp.spd;
    if ( spd < 0 )
    {
      sign = '-';
      spd = -spd;
    }
    const char *dc = "";
    if ( nonfunc != nullptr )
    {
      bool is_delta = nonfunc->contains(sp.ea);
      dc = is_delta ? " delta" : " cumulative";
    }
    msg("  %s: %c%" FMT_EA "X%s\n",
        print_ea_with_orig(mba, sp.ea).c_str(),
        sign, spd, dc);
  }
}

//-------------------------------------------------------------------------
void dump_flowchart(const qflow_chart_t &fc)
{
#ifdef _DUMP_FLOWCHART
  if ( under_debugger )
  {
    for ( size_t i=0; i < fc.size(); i++ )
    {
      qstring s;
      const qbasic_block_t &bb = fc.blocks[i];
      s.sprnt("%" FMT_Z ". %a..%a", i, bb.start_ea, bb.end_ea);
      int ns = bb.succ.size();
      if ( ns > 0 )
      {
        s.append(" =>");
        for ( int j=0; j < ns; j++ )
          s.cat_sprnt(" %d", bb.succ[j]);
      }
      msg("%s\n", s.c_str());
    }
  }
#else
  qnotused(fc);
#endif
}

//-------------------------------------------------------------------------
static void print_valrange_key(
        qstring *out,
        const mvm_t &mvm,
        const valrange_key_t &key,
        int size)
{
  switch ( key.t )
  {
    case mop_S:
      out->cat_sprnt("%%0x%a", uval_t(key.reg));
      break;
    case mop_r:
      {
        qstring rs;
        get_mreg_name(mvm, &rs, key.reg, size);
        out->append(rs);
      }
      break;
    default:
      break;
  }
  out->cat_sprnt(".%d", size);
}

//-------------------------------------------------------------------------
void valranges_t::print(qstring *out) const
{
  size_t l = out->length();
  if ( empty() )
  {
    out->append("none");
    return;
  }
  for ( map_t::const_iterator p = known.begin(); p != known.end(); ++p )
  {
    if ( out->length() > l )
      out->append(", ");
    print_valrange_key(out, mba->mvm, p->first, p->second.get_size());
    out->append(':');
    p->second.print(out);
  }
}
