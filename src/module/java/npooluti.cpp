#include "java.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include "npooluti.hpp"
#include "oututil.hpp"

#ifndef NCPS
#define NCPS 0x110000
#endif

//-----------------------------------------------------------------------
NORETURN void errtrunc(void)
{
  loader_failure("Premature end of file");
}

//-----------------------------------------------------------------------
GCC_DIAG_OFF(format-nonliteral);
void java_t::load_msg(const char *format, ...)
{ // this procedure prepares saving load-time message to base
  char str[MAXSTR];
  va_list va;

  ++errload;
  va_start(va, format);
  int cnt = qvsnprintf(str, sizeof(str), format, va);
  va_end(va);
  msg("%s", str);
  for ( int i = cnt; i; )
  {
    if ( str[--i] <= ' ' ) // remove cr's
      continue;
    if ( ++i > MAXSPECSIZE )
    {
      i = MAXSPECSIZE;
      memcpy(&str[MAXSPECSIZE-3], "...", 3);
    }

    netnode temp;
    uval_t j;
    if ( !curClass.msgNode )
    {
      temp.create();
      curClass.msgNode = temp;
      j = 0;
    }
    else
    {
      temp = curClass.msgNode;
      j    = temp.altval(0);
    }
    temp.supset(j, str, i);
    temp.altset(0, j+1);
    break;
  }
}
GCC_DIAG_ON(format-nonliteral);

//-----------------------------------------------------------------------
const char *java_t::mk_diag(attr_parent_kind_t apk, char str[128]) const
{
  static const char *const diag[] = { "Code in method", "Field", "Method" };
  str[0] = '\0';
  if ( apk < attr_parent_kind_class_file )
    qsnprintf(str,
              126,
              " for %s#%u", diag[uchar(apk)],
              apk == attr_parent_kind_field ? curField.id.Number : curSeg.id.Number);
  return str;
}

//-----------------------------------------------------------------------
void java_t::BadRef(ea_t ea, const char *to, ushort id, attr_parent_kind_t apk)
{
  if ( ea != BADADDR )
    remember_problem(PR_DISASM, ea);

  char diastr[128];
  load_msg("Illegal %s reference (%u)%s\n", to, id, mk_diag(apk, diastr));
}

//-----------------------------------------------------------------------
void java_t::mark_access(ea_t ea, ushort acc) const
{
  char str[60];

  str[0] = 0;  // for module
  if ( acc )
    qsnprintf(str, sizeof(str), "Illegal access bits (0x%X)", acc);
  mark_and_comment(ea, str);
}

//-------------------------------------------------------------------------
static const char *_constant_strings[CONSTANT_LAST+1] =
{
  // 0
  "<UNKNOWN>",
  "Utf8",
  "Unicode",
  "Integer",
  "Float",
  // 5
  "Long",
  "Double",
  "Class",
  "String",
  "Fieldref",
  // 10
  "Methodref",
  "InterfaceMethodref",
  "NameAndType",
  "<UNUSED_13>",
  "<UNUSED_14>",
  // 15
  "MethodHandle",
  "MethodType",
  "<UNUSED_17>",
  "InvokeDynamic",
};
const char *constant_type_to_str(uchar ctype)
{
  if ( ctype > CONSTANT_LAST )
    ctype = 0;
  return _constant_strings[ctype];
}

//-------------------------------------------------------------------------
void java_t::print_constant(
        qstrvec_t *out,
        const const_desc_t &cd,
        ushort index,
        bool strip_tags) const
{
  size_t anchor = out->size();

  op_t x;
  memset(&x, 0, sizeof(x));
  copy_const_to_opnd(x, cd);
  x.ref = 0; // as flag
  x.cp_type = cd.type;
  x.cp_ind = index;
  if ( x.cp_type == CONSTANT_Class )
    x.addr_shorts.high = (cd.flag & HAS_CLSNAME) != 0 ? fmt_fullname : fmt_ClassName;
  out_java_t *ctx = (out_java_t *) create_outctx(BADADDR);
  ctx->init_lines_array(out, 1000);
  ctx->init_prompted_output();
  ctx->OutConstant(x, /*include_descriptor=*/ true);
  ctx->flush_outbuf();

  if ( strip_tags )
  {
    for ( ; anchor < out->size(); ++anchor )
      tag_remove(&out->at(anchor));
  }

  delete ctx;
}

//-----------------------------------------------------------------------
void *myAlloc(uint size)
{
  void *p = qalloc(size);
  if ( p == nullptr )
    nomem("JavaLoader");
  return p;
}

//-----------------------------------------------------------------------
uchar *java_t::sm_realloc(uint size)
{
  if ( size > curClass.maxSMsize )
  {
    curClass.maxSMsize = size;
    qfree(smBuf);
    smBuf = (uchar*)myAlloc(size+1);
  }
  return smBuf;
}

//-----------------------------------------------------------------------
uchar *java_t::annotation_realloc(uint size)
{
  if ( size > curClass.maxAnnSz )
  {
    curClass.maxAnnSz = size;
    qfree(annBuf);
    annBuf = (uchar*)myAlloc(size+1);
  }
  return annBuf;
}

//-----------------------------------------------------------------------
// visible for converter only
ushort *java_t::append_tmp_buffer(uint size)
{
  if ( (ushort)size > curClass.maxStrSz )
  {
    curClass.maxStrSz = (ushort)size;
    qfree(tsPtr);
    tsPtr = (ushort*)myAlloc(size*sizeof(ushort)*2+sizeof(ushort));
  }
  return tsPtr;
}

//-----------------------------------------------------------------------
bool java_t::getblob(uval_t ind, void *p, uval_t sz)
{
  if ( (ushort)sz > curClass.maxStrSz )
    return false;

  sz *= 2;
  size_t ts = (size_t)sz + 1;
  return ConstantNode.getblob(p, &ts, ind, BLOB_TAG) && (uint32)ts == sz;
}

//-------------------------------------------------------------------------
bool java_t::getstr(qstring *out, ushort index)
{
  bool ok = is_valid_string_index(index);
  if ( ok )
  {
  //   || !getblob(ind2, p2 = p1 + (size_t)siz1, siz2) )
  // uval_t i1 = ConstantNode.altval(ind1);
    uint32 raw_idx = (uint32)index << 16;
    nodeidx_t sz = ushort(ConstantNode.altval(raw_idx));
    ok = sz > 0;
    if ( ok )
    {
      qvector<ushort> raw;
      raw.resize(sz, 0);
      msg("Reading %u bytes\n", uint32(sz));
      ok = getblob(raw_idx, raw.begin(), sz);
      if ( ok )
        out->append((const char *) raw.begin(), sz);
    }
  }
  return ok;
}

//----------------------------------------------------------------------
NORETURN static void readerr(void)
{
  loader_failure("Input file read error");
}

//-----------------------------------------------------------------------
ushort java_t::read2(void)
{
  ushort data;
  if ( FileSize < 2 )
    errtrunc();
  FileSize -= 2;
  if ( fread2bytes(myFile, &data, 1) != 0 )
    readerr();
  return data;
}

//-----------------------------------------------------------------------
uint32 java_t::read4(void)
{
  uint32 data;
  if ( FileSize < 4 )
    errtrunc();
  FileSize -= 4;
  if ( fread4bytes(myFile, &data, 1) != 0 )
    readerr();
  return data;
}

//-----------------------------------------------------------------------
uchar java_t::read1(void)
{
  uchar data;
  if ( !FileSize )
    errtrunc();
  --FileSize;
  if ( qfread(myFile, &data, 1) != 1 )
    readerr();
  return data;
}

//-----------------------------------------------------------------------
void java_t::readData(void *data, uint32 size)
{
  if ( FileSize < size )
    errtrunc();
  FileSize -= size;
  if ( qfread(myFile, data, size) != size )
    readerr();
}

//-----------------------------------------------------------------------
void java_t::skipData(uint32 size)
{
  if ( FileSize < size )
    errtrunc();
  FileSize -= size;
  qfseek(myFile, size, SEEK_CUR);
}

//-----------------------------------------------------------------------
uchar java_t::set_parent_object(void)
{
  if ( curClass.super.Name )
  {
    static const char object[] = "java.lang.Object";
    if ( fmtName(curClass.super.Name, tmpbuf, sizeof(tmpbuf), fmt_fullname)
      && memcmp(tmpbuf, object, sizeof(object)) == 0 )
    {
      curClass.extflg |= XFL_C_SUPEROBJ;
      return 1;
    }
  }
  return 0;
}

//-----------------------------------------------------------------------
const uchar *java_t::get_annotation(uval_t node, uint *plen)
{
  netnode temp(node);
  size_t len = (size_t)temp.altval(0);
  if ( len && len <= curClass.maxAnnSz )
  {
    *plen = (uint)len;
    ++len;
    if ( temp.getblob(annBuf, &len, 0, BLOB_TAG) && len == *plen )
      return annBuf;
  }
  return nullptr;
}

//-----------------------------------------------------------------------
bool java_t::sm_getinfo(const insn_t &insn, SMinfo *pinf)
{ // call ONLY when curSeg.smNode != 0
  sm_info_t smr;
  ea_t ea;

  switch ( sm_node )
  {
    case smn_aa_not_finished:
      goto noinfo;

    case smn_ok:
      sm_node = smn_no_use;
      SMnode = curSeg.smNode;
      {
        size_t cnt = (size_t)SMnode.altval(-1);
        if ( cnt < 2 || cnt > curClass.maxSMsize )
          goto destroyed;
        SMsize = (uint32)cnt;
        ++cnt;
        if ( !SMnode.getblob(smBuf, &cnt, 0, BLOB_TAG) || cnt != SMsize )
          goto destroyed;
      }
    default:
      break;
  }

  ea = pinf->ea;
  if ( ea == BADADDR )
    ea = insn.ea - 1;
  ea = SMnode.supnext(ea);
  if ( ea == BADNODE )
    goto noinfo;
  if ( get_item_head(ea) != insn.ea )
    goto noinfo;
  if ( SMnode.supval(ea, &smr, sizeof(smr)) != sizeof(smr) )
    goto destroyed;
  if ( smr.noff >= 2 && smr.eoff > smr.noff && smr.eoff <= SMsize )
  {
    pinf->ea = ea;
    pinf->pb = smBuf + smr.noff;
    pinf->pe = smBuf + smr.eoff;
    pinf->fcnt = smr.fcnt;
    return true;
  }

destroyed:
  DESTROYED("sm_getinfo");

noinfo:
  return false;
}

//-----------------------------------------------------------------------
static const char special_sym[] =
{
  j_field_dlm,                    // classname (dot) ==> special point
  j_clspath_dlm,                  // classname path (slash)
  j_parm_list_start, j_parm_list_end,              // function (for methods)
  0
};

//-------------------------------------------------------------------------
void op_NameChars(namechar_op_t op)
{
  switch ( op )
  {
    case ncop_disable:
      for ( size_t i = 0; i < qnumber(special_sym); ++i )
        set_cp_validity(UCDR_NAME, special_sym[i], BADCP, false);
      break;
    case ncop_enable:
      for ( size_t i = 0; i < qnumber(special_sym); ++i )
        set_cp_validity(UCDR_NAME, special_sym[i]);
      break;
    case ncop_enable_without_parens:
      for ( size_t i = 0; i < 2; ++i )
        set_cp_validity(UCDR_NAME, special_sym[i]);
      break;
    default: INTERR(10267);
  }
}

//-----------------------------------------------------------------------
void make_NameChars(bool on_load)
{
  static const char special_char[] =
  {
    '$', '_',                       // MUST present (historical/special)
    j_sign, j_endsign,              // special case for <init>, <clinit> :(
  };

  set_cp_validity(UCDR_NAME, 0, NCPS, false);
  // in names accepted ONLY english chars (temporary?)
  set_cp_validity(UCDR_NAME, 'A', 'Z'+1);
  set_cp_validity(UCDR_NAME, 'a', 'z'+1);
  set_cp_validity(UCDR_NAME, '0', '9'+1);
  for ( size_t i = 0; i < qnumber(special_char); ++i )
    set_cp_validity(UCDR_NAME, special_char[i]);
  // fill national character's
  set_cp_validity(UCDR_NAME, '\\'); // is valid for unicode escape sequnce only (special work)
  // class/method path/call chars
  op_NameChars(on_load ? ncop_enable : ncop_enable_without_parens); // for oldbase convertation
}

//----------------------------------------------------------------------
segment_t *java_t::getMySeg(ea_t ea, segment_t *seg)
{
  segment_t *s = seg != nullptr ? seg : getseg(ea);

  if ( s == nullptr )
    goto compat_err;

  if ( curSeg.start_ea != s->start_ea )
  {
    if ( sm_node > smn_ok )
      sm_node = smn_ok;
    if ( !s->orgbase )
    {
      if ( s->type != SEG_IMP && s->type != SEG_XTRN )
        goto compat_err;
      curSeg.start_ea = s->start_ea;
    }
    else
    {
      if ( ClassNode.supval(s->orgbase, &curSeg, sizeof(curSeg) ) != sizeof(curSeg) )
        DESTROYED("getMySeg");
      if ( 0-s->orgbase != curSeg.id.Number
        || s->start_ea != (s->type == SEG_BSS ? curSeg.DataBase : curSeg.start_ea) )
      {
compat_err:
        UNCOMPAT("getMySeg");
      }
    }
  }
  return s;
}

//-----------------------------------------------------------------------
// visible for converter only
GCC_DIAG_OFF(format-nonliteral);
void out_java_t::trunc_name(uint num, uchar type)
{
  static const char fnam[]   = "...(Field_%u)";
  static const char metnam[] = "...(Method_%u)";
  static const char locnam[] = "...(locvar_%u)";
  static const char xtrn[]   = "...(extern_%u)";
  static const char clsnam[] = "...";
  static const char *const add_nam[5] = { xtrn, fnam, metnam, locnam, clsnam };

  enableExt_NameChar();
  size_t s = (sizeof(metnam) - 2 + 5 + 1);
  size_t inplen = outbuf.length();
  outbuf.resize(inplen - s);
  outbuf.cat_sprnt(add_nam[type], num);
}
GCC_DIAG_ON(format-nonliteral);

//-----------------------------------------------------------------------
int java_t::CmpString(ushort index1, ushort index2)
{
  DEB_ASSERT((!index1 || !index2), "cs-ind");
  if ( index1 != index2 )
  {
    size_t i;
    uval_t ind1 = (uint32)index1 << 16;
    uval_t ind2 = (uint32)index2 << 16;

    uval_t sz = ConstantNode.altval(ind1);
    if ( sz == 0 || (i=(size_t)ConstantNode.altval(ind2)) == 0 )
    {
BADIDB:
      DESTROYED("CmpString");
    }

    if ( sz != i )
    {
diff:
      return 1;
    }

    i = (ushort)i;
    if ( i == 0 )
      return -1;

    sz = i;
    i *= sizeof(ushort);
    uchar *p1 = (uchar *)tsPtr, *p2 = p1 + i;
    if ( !getblob(ind1, p1, sz) || !getblob(ind2, p2, sz) )
      goto BADIDB;
    if ( memcmp(p1, p2, i) != 0 )
      goto diff;
  }
  return 0;
}

//-----------------------------------------------------------------------
int java_t::cmpDscrString(ushort index1, uchar met, ushort index2, uchar self)
{
  uval_t siz1, siz2;
  ushort *p1, *p2;

  uval_t ind1 = (uint32)index1 << 16;
  uval_t ind2 = (uint32)index2 << 16;
  uval_t i1 = ConstantNode.altval(ind1);
  uval_t i2 = ConstantNode.altval(ind2);
  if ( i1 == 0
    || i2 == 0
    || (siz1 = (ushort)i1) == 0
    || (siz2 = (ushort)i2) == 0
    || !getblob(ind1, p1 = tsPtr, siz1)
    || !getblob(ind2, p2 = p1 + (size_t)siz1, siz2) )
  {
    goto int_err;
  }

  if ( met )
  {
#define _MCR  ((_OP_ONECLS | _OP_VALPOS) << 16)
    if ( (i1 & _MCR) != _MCR )
      goto diff;
#undef _MCR
    i1 = ConstantNode.altval(ind1+1);
    if ( !i1 || (int32)(siz1 -= i1) <= 0 )
      goto int_err;  // never signature
    p1 += (size_t)i1;
  }

  if ( self && !(i1 & (_OP_NODSCR << 16)) )
  {
    while ( *p1 == j_array )
    {
      if ( !--siz1 )
        goto int_err;
      ++p1;
    }
  }

  if ( (i1 ^ i2) & (_OP_NODSCR << 16) )
  {
    if ( i2 & (_OP_NODSCR << 16) )
    {
      if ( *p1 == j_class && p1[(size_t)siz1-1] == j_endclass )
      {
        ++p1;
        if ( (int)(siz1 -= 2) <= 0 )
          goto int_err;
      }
    }
    else
    {
      if ( *p2 == j_class && p2[(size_t)siz2-1] == j_endclass )
      {
        ++p2;
        if ( (int)(siz2 -= 2) <= 0 )
          goto int_err;
      }
    }
  }

  if ( siz1 != siz2 || memcmp(p1, p2, (size_t)siz1 * sizeof(ushort)) != 0 )
    goto diff;
  return 0;
int_err:
  INTERNAL("cmpDscrString");
diff:
  return 1;
}

//-----------------------------------------------------------------------
ushort java_t::xtrnDscrSearch(ushort name, uchar met)
{
  const_desc_t cr;

  if ( curClass.This.Dscr
    && !cmpDscrString(name, met, curClass.This.Name, 1) )
  {
    return 0xFFFF;
  }

  for ( ushort j = curClass.xtrnLQE; j; j = (ushort)(XtrnNode.altval(j) >> 16) )
  {
    if ( ConstantNode.supval(j, &cr, sizeof(cr)) != sizeof(cr)
      || cr.type != CONSTANT_Class
      || (j = cr.ref_ip) == 0 )
    {
      INTERNAL("xtrnDscrSearch");
    }
    if ( !cmpDscrString(name, met, cr._name, 0) )
      return j;
  }
  return 0;
}

//-----------------------------------------------------------------------
void java_t::mark_strange_name(ea_t ea) const
{
  mark_and_comment(ea, "Strange name");
}

//-----------------------------------------------------------------------
void java_t::xtrnSet(
        uint cin,
        const_desc_t *co,
        uint xip,
        char *str,
        size_t strsize,
        bool full,
        uchar rmod)
{
  ea_t ea = curClass.xtrnEA + xip;

  if ( !(rmod & 4) )
  {
    co->ref_ip = (ushort)xip;
    StoreOpis(cin, *co);
    uval_t rfa = cin;
    if ( full )
    {
      rfa |= ((uval_t)curClass.xtrnLQE << 16);
      curClass.xtrnLQE = (ushort)cin;
    }
    XtrnNode.altset(xip, rfa);
    create_byte(ea, 1);
  }

  uint js = MAXNAMELEN - 1;
  out_java_t *p_ctx = (out_java_t *)create_outctx(BADADDR);
  name_chk = 0;
  if ( full ) // fmt_fullname
  {
    uni_chk = 0;
    if ( p_ctx->fmtString(*this, co->_name, js, fmt_fullname) )
    {
      endcls = MAXNAMELEN;
trnc:
      p_ctx->trunc_name(xip);
      p_ctx->outbuf.resize(MAXNAMELEN-1);
    }
    else
    {
      endcls = (uint)strlen(p_ctx->outbuf.c_str());
    }
    clunic = uni_chk;
  }
  else
  {
    uni_chk = clunic;
    if ( endcls >= MAXNAMELEN - 2 )
    {
      p_ctx->outbuf.resize(MAXNAMELEN-1);
      name_chk = 0;   // no mark here
      goto trnc;
    }
    p_ctx->outbuf.resize(p_ctx->outbuf.length() + (endcls + 1));
    p_ctx->outbuf[endcls] = '.';
    js -= (endcls + 1);
    if ( p_ctx->fmtString(*this, co->_subnam, js, fmt_UnqualifiedName) )
      goto trnc;
  }
  qstrncpy(str, p_ctx->outbuf.c_str(), strsize);
  delete p_ctx;
  if ( rmod & 1 )
  {
    // enableExt_NameChar();
    force_name(ea, convert_clsname(str));
    hide_name(ea);
    // disableExt_NameChar();
  }
  if ( (char)uni_chk > 0 && (rmod & 2) )
    ConstantNode.charset(ea, uni_chk, UR_TAG);
  uni_chk = (uchar)-1;
  if ( name_chk && !(rmod & 4) )
    mark_strange_name(ea);
}

//-----------------------------------------------------------------------
void java_t::SetName(ushort name, ea_t ea, ushort access_mode, uval_t number, uchar rmod)
{
  uni_chk = name_chk = 0;
  fmt_t fmt = number || curSeg.id.Number ? fmt_UnqualifiedName : fmt_fullname;
  out_java_t *p_ctx = (out_java_t *)create_outctx(BADADDR);
  if ( p_ctx->fmtString(*this, name, sizeof(tmpbuf) - 1, fmt) )
  {
    if ( !number )
      p_ctx->trunc_name(curSeg.id.Number, uchar(3 + !curSeg.id.Number));
    else if ( number <= (uval_t)curClass.FieldCnt )
      p_ctx->trunc_name((uint)number, 1);
    else
      p_ctx->trunc_name((uint)number - curClass.FieldCnt, 2);
  }
  qstrncpy(tmpbuf, p_ctx->outbuf.c_str(), sizeof(tmpbuf));
  delete p_ctx;
  convert_clsname(tmpbuf);

  if ( rmod & 1 )
  {
    switch ( access_mode & ACC_ACCESS_MASK )
    {
      case ACC_PUBLIC:
        if ( rmod & 4 )
          del_global_name(ea);
        add_entry(number, ea, tmpbuf, 0);
        break;
      case 0:
        if ( rmod & 4 )
          del_global_name(ea);
        add_entry(ea, ea, tmpbuf, 0);
        break;
      default:
        force_name(ea, tmpbuf);
        break;
    }
  }
  // disableExt_NameChar();
  if ( (char)uni_chk > 0 && (rmod & 2) )
    ConstantNode.charset(ea, uni_chk, UR_TAG);
  uni_chk = (uchar)-1;
  if ( name_chk && !(rmod & 4) )
    mark_strange_name(ea);
}

//-----------------------------------------------------------------------
// as procedure for rename_unichars
void java_t::set_lv_name(ushort name, ea_t ea, uchar rmod)
{
  uni_chk = name_chk = 0;
  if ( fmtName(name, tmpbuf, sizeof(tmpbuf), fmt_UnqualifiedName) )
  {
    if ( rmod & 1 )
      force_name(ea, tmpbuf);
    hide_name(ea);
    if ( (char)uni_chk > 0 && (rmod & 2) )
      ConstantNode.charset(ea, uni_chk, UR_TAG);
    if ( name_chk && !(rmod & 4) )
      mark_strange_name(ea);
  }
  uni_chk = (uchar)-1;
}

//--------------------------------------------------------------------------
void java_t::rename_uninames(int32 mode)
{
  nodeidx_t id = ConstantNode.charfirst(UR_TAG);
  if ( id != BADNODE )
  {
    char str[MAXNAMELEN];  // for imports

    show_wait_box("HIDECANCEL\nRenaming labels with national characters");

    ushort lcls = 0;  // for imports
    uchar rmod = 7;  // rename+save (+renamemode)
    switch ( mode )
    {
      case 0:   // change table but renaming not needed (recreate records only)
        rmod = 2; // save only
        break;
      case -1:  // change processor flag only
        rmod = 5; // rename only
        // no break
      default:  // change table and renaming needed
        break;
    }
    do
    {
      adiff_t dif;
      ea_t ea = id;
      uchar type = ConstantNode.charval(ea, UR_TAG);
      show_addr(ea);
      if ( !type || type > 3 )
        goto BADIDB;
      if ( !(type & 2) && mode == -1 )
        continue;
      switch ( getMySeg(ea)->type )
      {
        default:
BADIDB:
          DESTROYED("rename_uninames");

        case SEG_BSS:
          if ( !curSeg.varNode
            || (dif = ea - curSeg.DataBase) < 0
            || dif >= curSeg.DataSize
            || is_align(get_flags(ea)) )
          {
            goto BADIDB;
          }
          {
            netnode tmp(curSeg.varNode);
            LocVar lv;
            if ( tmp.supval((nodeidx_t)dif, &lv, sizeof(lv)) != sizeof(lv) )
              goto BADIDB;
            set_lv_name(lv.var.Name, ea, rmod);
          }
          break;

        case SEG_CODE:
          if ( ea != curSeg.start_ea )
            goto BADIDB;
          SetName(curSeg.id.name, ea, curSeg.id.access,
                  curClass.FieldCnt + curSeg.id.Number, rmod);
          break;

        case SEG_IMP: // class/fields
          dif = ea - curClass.start_ea;
          if ( dif < 0 )
            goto BADIDB;
          if ( !dif ) // class
          {
            ushort sv = curSeg.id.Number;
            curSeg.id.Number = 0;
            SetName(curClass.This.Name, ea, curClass.AccessFlag, 0, rmod);
            curSeg.id.Number = sv;
            break;
          }
          if ( dif > curClass.FieldCnt )
            goto BADIDB;
          if ( ClassNode.supval((nodeidx_t)dif, &curField, sizeof(curField) ) != sizeof(curField) )
            goto BADIDB;
          SetName(curField.id.name, ea, curField.id.access, (int)dif, rmod);
          break;

        case SEG_XTRN:
          dif = ea - curClass.xtrnEA;
          if ( dif <= 0 || dif > curClass.xtrnCnt )
            goto BADIDB;
          {
            uchar cmod = rmod;
            const_desc_t co;
            {
              uint j = (uint)XtrnNode.altval((nodeidx_t)dif);
              if ( j == 0 )
                goto BADIDB;
              if ( !LoadOpis(lm_normal, (ushort)j, 0, &co) )
                goto BADIDB;
            }
            switch ( co.type )
            {
              default:
                goto BADIDB;

              case CONSTANT_Fieldref:
              case CONSTANT_InterfaceMethodref:
              case CONSTANT_Methodref:
                if ( co._name != lcls )
                {
                  cmod = 4; // set internal static variables only
LCLASS:
                  lcls = co._name;
                  xtrnSet(-1, &co, (uint)dif, str, sizeof(str), true, cmod);
                  if ( co.type == CONSTANT_Class )
                    break;
                }
                xtrnSet(-1, &co, (uint)dif, str, sizeof(str), false, rmod);
                break;
              case CONSTANT_Class:
                goto LCLASS;
            }
          }
          break;
      }
    }
    while ( (id = ConstantNode.charnext(id, UR_TAG)) != BADNODE );
    hide_wait_box();
  }
}

//-----------------------------------------------------------------------
void java_t::xtrnRef(ea_t ea, const const_desc_t &opis) const
{
  if ( (loadMode & MLD_EXTREF) && opis.ref_ip )
  {
    ea_t target = opis.ref_ip == 0xFFFF
                ? curClass.start_ea
                : curClass.xtrnEA + opis.ref_ip;
    add_dref(ea, target, dr_I);
  }
}

//-----------------------------------------------------------------------
void java_t::xtrnRef_dscr(ea_t ea, const_desc_t *opis, uchar met)
{
  if ( !met )
  {
    if ( !(loadMode & MLD_VARREF) )
      return;
    if ( (opis->flag & (HAS_CLSNAME | HAS_TYPEDSCR)) == HAS_CLSNAME )
      return;
  }
  else if ( !(loadMode & MLD_METHREF) )
  {
    return;
  }

  const_desc_t cr(*opis);
  opis = &cr;
  opis->ref_ip = xtrnDscrSearch(opis->_name, met);
  xtrnRef(ea, *opis);
}

//-----------------------------------------------------------------------
void java_t::deltry(uint bg, uint ic, uint ui, const const_desc_t &pco)
{
  for ( uint i = bg; (ushort)i <= curClass.xtrnCnt; i++ )
  {
    uint j = (uint)XtrnNode.altval(i, '0');
    if ( j == 0 )
      continue;
    const_desc_t co;
    ConstantNode.supval(j, &co, sizeof(co));
    if ( co.type   != pco.type
      || co.flag   != pco.flag
      || co.ref_ip != (ushort)ic
      || CmpString(co._subnam, pco._subnam)
      || CmpString(co._dscr, pco._dscr) )
    {
      continue;
    }
    co.ref_ip = (ushort)ui;
    StoreOpis(j, co);
    XtrnNode.altdel(i, '0');
  }
}

//-----------------------------------------------------------------------
GCC_DIAG_OFF(format-nonliteral);
segment_t *java_t::_add_seg(int caller)
{
  static const char *const _cls[4] = { "xtrn",   "met_",    "_var",    "head" };
  static const char *const fm[4]   = { "import", "met%03u", "var%03u", "_Class" };

  uval_t size;
  uchar type;

  switch ( caller )
  {
    default:
      INTERNAL("_add_seg");

    case 1:   // method
      curSeg.start_ea = start_ea;
      // fallthrough
    case -1:  // code
      start_ea = curSeg.start_ea;
      type = SEG_CODE;
      size = curSeg.CodeSize;
      break;

    case 2:  // data
      curSeg.DataBase = start_ea;
      size = curSeg.DataSize;
      type = SEG_BSS;
      break;

    case 3: // class
      curClass.start_ea = start_ea;
      size = curClass.FieldCnt + 1;
      type = SEG_IMP;
      break;

    case 0: // header
      curClass.xtrnEA = start_ea = to_ea(inf_get_baseaddr(), 0);
      if ( !curClass.xtrnCnt )
        return nullptr;
      size = curClass.xtrnCnt;
      type = SEG_XTRN;
      break;
  }
  ea_t top = start_ea + size;
  ea_t end = (top + (0xF + 1)) & ~0xF;
  if ( top < start_ea )
    loader_failure("Our of addressing space");

  segment_t *S;
  if ( caller < 0 )
  {
    S = getseg(start_ea);
    if ( S == nullptr || !set_segm_end(curSeg.start_ea, end, SEGMOD_KILL) )
      qexit(1);
    qoff64_t pos = qftell(myFile);
    linput_t *li = make_linput(myFile);
    file2base(li, pos, start_ea, top, FILEREG_PATCHABLE);
    unmake_linput(li);
    qfseek(myFile, pos + curSeg.CodeSize, SEEK_SET);
  }
  else
  {
    sel_t sel;
    if ( start_ea > 0x100000 )
    {
      sel = cursel++;
      set_selector(sel, start_ea>>4);
    }
    else
    {
      sel = (ushort)(start_ea >> 4);
    }
    if ( !add_segm(sel, start_ea, end, nullptr, _cls[caller]) )
      qexit(1);
    S = getseg(start_ea);
    S->orgbase = 0-(uval_t)curSeg.id.Number;
    S->type = type;
    if ( caller != 1 )
      S->set_hidden_segtype(true);  // no out comment of segment type
    char sname[32];
    qsnprintf(sname, sizeof(sname), fm[caller], curSeg.id.Number);
    set_segm_name(S, sname);
    if ( caller <= 1 )
      goto end_create;  // method/header
    for ( uval_t i = 0; start_ea < top; start_ea++, i++ ) // data & class
    {
      create_byte(start_ea, 1);
      if ( caller == 2 ) // data
      {
        char str[MAXNAMELEN];
        qsnprintf(str, sizeof(str), "met%03u_slot%03" FMT_EA "u", curSeg.id.Number, i);
        if ( force_name(start_ea, str) )
          make_name_auto(start_ea);
        else
          hide_name(start_ea);
      }
    }
  }

  create_byte(top, end - top);  // !header && !method
end_create:
  start_ea = end;
  return S;
}
GCC_DIAG_ON(format-nonliteral);

//-----------------------------------------------------------------------
void java_t::resizeLocVars(void) const
{
  netnode temp(curSeg.varNode);
  int slot = curSeg.DataSize;

  for ( int32 cur, prev = 1; --slot >= 0; prev = cur )
  {
    cur = (int32)temp.altval(slot);
    if ( cur < 0 && !prev )
    {
      del_items(curSeg.DataBase + slot+1, DELIT_SIMPLE);
      create_word(curSeg.DataBase + slot, 2);
    }
  }
}

//-----------------------------------------------------------------------
const char *java_t::CopyAttrToFile(const char *astr, uint32 size, ushort id)
{
  if ( FileSize < size )
    errtrunc();  // here for alloc diagnostic

  char fname[QMAXPATH];
  qstrncpy(fname, get_path(PATH_TYPE_CMD), sizeof(fname));
  char *ptr = (char *)get_file_ext(fname);
  if ( ptr == nullptr )
  {
    ptr = &fname[strlen(fname)];
    *ptr++ = '.';
  }

  uint32 sz = uint32(ptr - fname);

  uval_t *pnode = nullptr;
  if ( astr[0] == ' ' ) // SourceDebugExtension
  {
    if ( sz > sizeof(fname)-sizeof("SDE.utf8") )
    {
too_long:
      return "PathName too long";
    }
    memcpy(ptr, "SDE.utf8", sizeof("SDE.utf8"));
  }
  else
  {
    if ( sz > (sizeof(fname)-30) )
      goto too_long;

    switch ( (uchar)astr[0] )
    {
      default:  // ARQ_FILE:
        pnode = &curClass.genNode;
        break;
      case attr_parent_kind_field:
        ptr += qsnprintf(ptr, 30, "fld%03u_", curField.id.Number);
        pnode = &curField.genNode;
        break;
      case attr_parent_kind_code:
      case attr_parent_kind_method:
        pnode = &curSeg.genNodes[astr[0] == attr_parent_kind_code];
        ptr += qsnprintf(ptr, 30, "%smet%03u.",
                         astr[0] == attr_parent_kind_code ? "code_" : "",
                         curSeg.id.Number);
        break;
    }

    uchar err = 0;
    for ( sz = 1; ptr < &fname[sizeof(fname) - sizeof(".attr")]; sz++ ) //lint !e440
    {
      uchar c = astr[sz];
      switch ( c )
      {
        case 0:
          goto full_copy;
        default:
          if ( c > CHP_MIN && c < CHP_MAX )
          {
            *ptr++ = c;
            break;
          }
          // no break
        case '/':
        case '\\':
        case '>':
        case '<':
        case '?':
        case '*':
        case '=':
          err = 1;
          break;
      }
    }
    ptr[-1] = '!';  // as marker of truncated name
full_copy:
    memcpy(ptr, ".attr", sizeof(".attr"));
    if ( err )
      msg("Convert unprintable filename for attribute '%s'\n", &astr[1]);
  }
  ptr = fname;
  while ( (ptr=strchr(ptr, '\\')) != nullptr )
    *ptr = '/';

  ptr = (char *)myAlloc(size + 1); // +1 for zero_size extension!
  readData(ptr, size);

  FILE *f = qfopen(fname, "wb");
  if ( f == nullptr )
  {
    qfree(ptr);
    return "Can't create file for storing";
  }

  uchar err = 0;
  if ( qfwrite(f, ptr, size) != size )
    ++err;
  qfree(ptr);
  if ( qfclose(f) && !err )
  {
    qunlink(fname);
    return "Error writing";
  }
  if ( pnode )
  {
    netnode temp;
    uint32 pos = 0;
    if ( *pnode )
    {
      temp = *pnode;
    }
    else
    {
      temp.create();
      *pnode = temp;
      pos = (uint32)temp.altval(0);
    }
    ++pos;
    temp.altset(pos, id);
    temp.supset(pos, fname, strlen(fname));
    temp.altset(0, pos);
  }
  return nullptr;
}

//-----------------------------------------------------------------------
bool java_t::fmtName(ushort index, char *buf, size_t bufsize, fmt_t fmt)
{
  out_java_t *p_ctx = (out_java_t *)create_outctx(BADADDR);
  int i = p_ctx->fmtString(*this, index, bufsize-1, fmt);
  qstrncpy(buf, p_ctx->outbuf.c_str(), bufsize);
  delete p_ctx;
  return !i && buf[0];
}

//--------------------------------------------------------------------------
//  Procedures for "press Enter on any name"
int java_t::is_locvar_name(const insn_t &insn, const char *name)
{
  LocVar lv;
  uint32 idx = (uint32)insn.Op1.addr;

  if ( insn.Op1.type == o_mem )
  {
    if ( insn.Op1.ref )
      goto bad;
  }
  else if ( insn.Op1.type == o_void )
  {
    if ( (char)insn.Op1.ref < 0 || (int32)(idx -= (uint32)curSeg.DataBase) < 0 )
      goto bad;
  }

  if ( netnode(curSeg.varNode).supval(idx, &lv, sizeof(lv)) == sizeof(lv)
    && fmtName(lv.var.Name, tmpbuf, sizeof(tmpbuf), fmt_UnqualifiedName)
    && streq(name, tmpbuf) )
  {
    return idx;
  }
bad:
  return -1;
}

//-------------------------------------------------------------------------
static bool is_get_ref_addr_visible_cp(wchar32_t cp)
{
  return cp == j_field_dlm || cp == j_clspath_dlm || is_visible_cp(cp);
}

//--------------------------------------------------------------------------
ea_t java_t::get_ref_addr(ea_t ea, const char *name, size_t pos)
{
  const size_t name_len = qstrlen(name);
  if ( name_len <= pos || getseg(ea) == nullptr )
  {
NOT_FOUND:
    return BADADDR;
  }

  uchar clv = getMySeg(ea)->type;
  switch ( clv ) // also set curSeg
  {
    case SEG_XTRN:
      if ( !jasmin() )
        goto NOT_FOUND; // short form. Can't search by text
      // no break
    default:
      break;
    case SEG_CODE:
      if ( strstrpos(name, ash.cmnt) <= pos )
        clv |= 0x80;  // flag for 'modified autocomment' (see make_locvar_cmt)
      break;
  }

  ssize_t r = pos;
  if ( !is_get_ref_addr_visible_cp(uchar(name[r])) )
    goto NOT_FOUND;

  while ( r > 0 && is_get_ref_addr_visible_cp(uchar(name[r-1])) )
    --r;
  ssize_t start = r;
  for ( r = pos+1; name[r]; r++ )
    if ( !is_get_ref_addr_visible_cp(uchar(name[r])) )
      break;
  if ( name[r] == '\\' && !name[r+1] )
    goto NOT_FOUND; //\\+++ not work with prompt?
  char buf[MAXSTR*2];
  // msg("name: \"%s\", start: %" FMT_Z ", r: %" FMT_Z ", pos: %" FMT_Z "\n", name, start, r, pos);
  size_t nbytes = qmin(r, name_len - start);
  nbytes = qmin(nbytes, sizeof(buf) - 1);
  memcpy(buf, &name[start], nbytes);
  buf[nbytes] = '\0';
  switch ( clv & ~0x80 )
  {
    case SEG_CODE:
    case SEG_BSS:
      r = check_special_label(buf, r);
      if ( r >= 0 )
        return curSeg.start_ea + r;
      // no break
    default:
      break;
  }
  insn_t insn;
  decode_insn(&insn, ea);
  if ( (clv&0x80) && curSeg.varNode && (start = is_locvar_name(insn, buf)) >= 0 )
    return curSeg.DataBase + start;
// append(new)
  ea_t rea = get_name_ea(BADADDR, convert_clsname(buf));
  if ( rea == BADADDR && jasmin() && (clv&~0x80) == SEG_CODE ) // fieldnames
  {
    char *p = strrchr(buf, j_field_dlm);
    if ( p )
    {
      *p++ = '\0';
      if ( get_name_ea(BADADDR, buf) == curClass.start_ea )
        rea = get_name_ea(BADADDR, p);
    }
  }
  return rea;
}

//-----------------------------------------------------------------------
// for IDF_SHOWBADSTR (index my be not string :)
bool java_t::is_valid_string_index(ushort index) const
{
  return index > 0
      && index <= curClass.maxCPindex
      && ConstantNode.altval(((uint32)index) << 16);
}

//-----------------------------------------------------------------------
/*           signatures encoding
 *
 *     methodOrFieldSignature ::= type
 *     classSignature         ::= [ typeparams ] supertype { interfacetype }
 *
 *     type       ::= ... | classtype | methodtype | typevar
 *     classtype  ::= classsig { '.' classsig }
 *     classig    ::= 'L' name [typeargs] ';'
 *     methodtype ::= [ typeparams ] '(' { type } ')' type
 *     typevar    ::= 'T' name ';'
 *     typeargs   ::= '<' type { type } '>'
 *     typeparams ::= '<' typeparam { typeparam } '>'
 *     typeparam  ::= name ':' type
*/

//-------------------------------------------------------------------------
int out_java_t::fmtString(java_t &pm, ushort index, ssize_t size, fmt_t mode, _PRMPT_ putproc)
{
  ushort *tp = nullptr;

  if ( size < 0 )
FMTSTR_INTERR:
    INTERNAL("fmtString");

  if ( !index )
BADIDB:
    DESTROYED("fmtString");

  uint32 strind = ((uint32)index) << 16;
  uint32 ostsz = uint32(pm.ConstantNode.altval(strind));
  if ( ostsz == 0 )
    goto BADIDB;
  CASSERT(offsetof(_STROP_, size) == 0 && sizeof(((_STROP_ *)0)->size) == sizeof(ushort));
  if ( !(pm.uni_chk & 1) && (ostsz & (_OP_UNICHARS<<16)) )
    ++pm.uni_chk;  // rename unicode
  if ( ostsz & (_OP_BADFIRST<<16) )
    pm.name_chk = 1;
  if ( mode & FMT_ENC_RESERVED ) // support jasmin reserved words
  {
    CASSERT((fmt_fullname+1) == fmt_UnqualifiedName && (fmt_UnqualifiedName+1 ) == fmt__ENDENUM);
    mode = (fmt_t)(mode ^ FMT_ENC_RESERVED);
    if ( mode < fmt_fullname )
      goto FMTSTR_INTERR;
    if ( (ostsz & (_OP_JSMRES_ << 16)) && (pm.idpflags & IDM_OUTASM) )
      mode = fmt_string_single_quotes;
  }
  ostsz = (ushort)ostsz;
  if ( ostsz != 0 && !pm.getblob(strind, tp = pm.tsPtr, ostsz) )
    goto BADIDB;

  uint32 off_ReturnType = 0;
  uint32 off_ThrowsSignature_and_TypeSignature = 0;
  if ( fmt_expects_call_descriptor(mode) ) // method part out
  {
    off_ReturnType = (uint32)pm.ConstantNode.altval(strind+1); // offset to return type
    off_ThrowsSignature_and_TypeSignature = (uint32)pm.ConstantNode.altval(strind+2); // lng of <...:...> + throw off
  }

  return pm.format_utf16_string(tp, ostsz, off_ReturnType, off_ThrowsSignature_and_TypeSignature, size, mode, this, putproc);
}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
// this function is called only from the loader
uchar java_t::LoadUtf8(ushort index, const_desc_t *co)
{
  _STROP_ _opstr;
  uint32 Flags = 0;
  uint32 ind = ((uint32)index) << 16;
  uchar result = 0, is_sde = 0, unicode = 0;
  uint size;

  if ( index == (ushort)-1 ) // SourceDebugExtension
  {
    CASSERT(offsetof(_STROP_, size) == 0 && sizeof(_opstr.size) == sizeof(ushort));
    *(uint32*)&_opstr = (ushort)(size_t)co;
    co = nullptr;
    is_sde = 1;
  }
  else
  {
    _opstr.flags = _OP_UTF8_;
    _opstr.size  = read2();
  }
  size = _opstr.size;
  if ( size != 0 )
  {
    ushort *po = append_tmp_buffer(size);
    union
    {
      ushort cw;
      uchar cs;
    };
    uchar c;
    do
    {
      --size;
      cw = (uchar)read1();
      if ( cw == 0 || cs >= 0xf0 )
        goto errcoding;
      if ( (char)cs < 0 )
      {
        if ( !size )
          goto errchar;
        --size;
        --_opstr.size;
        c = cs;
        cs &= 0x1F;
        cw <<= 6;
        {
          uchar c2 = read1();
          if ( (c2 & 0xC0) != 0x80 )
            goto errchar;
          cs |= (c2 & 0x3F);
        }
        if ( (c & 0xE0) != 0xC0 )
        {
          if ( !size
            || (c & 0xF0) != 0xE0
            || ((c = read1()) & 0xC0) != 0x80 )
          {
errchar:
            if ( is_sde )
              goto done;
            loader_failure("Illegal byte in CONSTANT_Utf8 (%u)", index);
          }
          --size;
          --_opstr.size;
          cw <<= 6;
          cs |= (c & 0x3F);
          if ( cw < 0x800 )
            goto errcoding;
        }
        else if ( cw < 0x80 && cs )
        {
errcoding:
          if ( is_sde )
            goto done;
          loader_failure("Illegal symbol encoding in CONSTANT_Utf8 (%u)", index);
        }
      } // end encoding
      *po++ = cw;
      if ( !is_sde )
      {
        if ( cw >= CHP_MAX )
        {
          if ( !javaIdent(cw) )
            goto extchar;
          unicode = 1;
        }
        else if ( cs <= CHP_MIN )
        {
extchar:
          Flags |= _OP_EXTSYM_;
          unicode = (uchar)-1;
        }
      }
    }
    while ( size );

    if ( !is_sde
      && _opstr.size == 1
      && (loadMode & MLD_STRIP)
      && (cw >= 0x80 || get_base_typename(cs) == nullptr) )
    {
// Symantec error (strip) #3
       char str[16];
       uchar *ps = (uchar *)str;

       _opstr.size = (ushort)qsnprintf(str, sizeof(str), "_?_%04X", cw);
       po = append_tmp_buffer(_opstr.size);
       do
         *po++ = *ps++;
       while ( *ps );
       Flags |= _OP_NODSCR | _OP_NOSIGN;
       co->flag = HAS_CLSNAME | HAS_FLDNAME;
       unicode = 0;   // PARANOYA
    }
    result = !Flags;
    ConstantNode.setblob(tsPtr, (uchar *)po - (uchar *)tsPtr, ind, BLOB_TAG);
  }
  if ( !is_sde )
  {
    if ( unicode == 1 )
      Flags |= _OP_UNICHARS;
    _opstr.flags |= (ushort)Flags;
    co->_Sopstr = *(int32 *)&_opstr;
  }
  ConstantNode.altset(ind, *(uint32 *)&_opstr);
done:
  return result;
}

//-----------------------------------------------------------------------
void java_t::parse_const_desc(ushort index, const_desc_t *co)
{
// all nexts used only here (for parsing)
#define _op_PARAM_    0x00010000  // start paramlist '('
#define _op_PAREND_   0x00020000  // last char is end of paramlist ')'
#define _op_RETTYPE_  0x00040000  // have valid position for call return type
#define _op_FRSPRM_   0x00080000  // not first descriptor (parameter)
#define _op_CLSBEG_   0x00100000  // begin 'L...;' detected
#define _op_TYPBEG_   0x00200000  // begin 'T...;' (signtype) detected
#define _op_NAME_     0x00400000  // non empty class/typeref-name
#define _op_ARRAY_    0x00800000  // previous char is '['
// next needed for 'complex' classnames
#define _op_ISARRAY_  0x01000000  // have any '[' in name
#define _op_PRIMSIG_  0x02000000  // <...:...> signature presnt
#define _op_INPRSIG_  0x04000000  // currently parse <...:...> signature
#define _op_MUSTNAM_  0x08000000  // part must be name (before ':')

#define _op_isTAG_   (_op_CLSBEG_ | _op_NAME_ | _op_TYPBEG_)

  uint Flags = 0;
  uint size = co->_Ssize;
  uint32 off_ReturnType = 0;
  uint32 off_ThrowsSignature_and_TypeSignature = 0;
  ushort *po = tsPtr; // ATT: call ONLY after LoadUtf8, size!=0
  uchar sgnlev = 0, prim = 0, *pprim = nullptr;
  uchar cs;  // for prev

  if ( *po == j_sign ) // check <...:...> signature and <init>/<clinit>
  {
    while ( ++off_ReturnType < size )
    {
      if ( !javaIdent(po[off_ReturnType]) )
      {
        if ( off_ReturnType != 1 )
        {
          size -= off_ReturnType+1;  // +1 => balance for while, or align for <init>
          switch ( po[off_ReturnType] )
          {
            case j_tag:
              if ( size < 7 )
                break; // Lx;>Lx; or Lx;>( )V => only_string
              Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR
                     | _op_PRIMSIG_ | _op_INPRSIG_;
              po += off_ReturnType;
              off_ReturnType &= 0;
              ++sgnlev;
              goto accept_tag;

            case j_endsign:
              if ( !size ) // <init>/<clinit>
              {
                Flags |= _OP_NODSCR | _OP_NOSIGN;
                goto SET_FLAGS;
              }
              // no break
            default:
              break;  // only_string
          } // switch
        } // off_ReturnType != 1
        break;
      } // special_char
    }
    goto only_string;
  } // first '<'

  if ( *po == j_parm_list_start ) // check method descriptor/signature
  {
to_func:
    if ( --size < 2 )
      goto only_string; // )V
    ++po;
    Flags |= _op_PARAM_;
  }
  else
  {
    pprim = &prim;
  }
  do
  {
    --size;
    cs = 0;   // as flag (for wide characters)
    CASSERT(CHP_MAX < 0x100);
    if ( *po < CHP_MAX )
      cs = (uchar)*po;  // for 'L', 'T'...
    if ( javaIdent(*po, pprim) ) // letter/digit/$_
    {
      if ( pprim )
      {
        if ( !prim )
          Flags |= _OP_BADFIRST;
        pprim = nullptr;
      }
      goto norm_char;
    }
    pprim = nullptr; // for speed
    if ( cs <= CHP_MIN )
      goto only_string; // also >= CHP_MAX

    if ( Flags & _op_MUSTNAM_ ) // only in <...:...> signature (formal name)
    {
      if ( cs != j_tag )
        goto only_string;
      Flags &= ~_op_MUSTNAM_;
      if ( size < 7 )
        goto only_string; // Lx;>Lx; or Lx;>()V
accept_tag:
      if ( po[1] == j_tag )
      {  // iface
        --size;
        ++po;
      }
      goto only_tag;
    }
    switch ( cs ) // validate special chars
    {
      case j_parm_list_end: // always can be present in in name
        if ( sgnlev )
          goto only_string;
        if ( (Flags & (_op_PARAM_ | _op_ARRAY_ | _op_isTAG_)) != _op_PARAM_ )
          goto only_string;
        Flags ^= (_op_PARAM_ | _op_PAREND_);
        continue;

      case j_array: // class name can be full qualified array :(
        if ( !sgnlev && !(Flags & (_op_isTAG_ | _OP_NOSIGN)) )
        {
          Flags |= _OP_FULLNM;
          break;
        }
        // no break
      default:
        goto only_string;

      case j_clspath_dlm: // '/'
      case j_field_dlm:   // '.'
        Flags |= _OP_FULLNM;
        continue;

      case j_sign:
        if ( size < 3  // *>;
          || (Flags & (_op_NAME_ | _OP_NOSIGN)) != _op_NAME_
          || ++sgnlev >= 30 )
        {
          goto only_string;
        }
        CASSERT((int32)(2 << 30) < 0); // "fmtString check method"
        Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR;
        Flags &= ~_op_isTAG_;
        --size;
        switch ( *++po )
        {
          case j_wild:
            if ( *++po != j_endsign )
              goto only_string;
            --size;
            goto end_signW;

          case j_wild_s:
          case j_wild_e:
            goto only_tag;

          default:
            goto skipped_only_tag;
        }

      case j_endsign:
        if ( !size || !sgnlev )
          goto only_string;
end_signW:
        // end of <...:...> signature must resolve in endclass
        if ( !--sgnlev && (Flags & _op_INPRSIG_) )
          goto only_string;
        if ( *++po != j_endclass )
          goto only_string;
        --size;
        Flags |= _op_NAME_; // restore
        // no break
      case j_endclass:
        if ( (Flags & (_op_NAME_ | _op_PAREND_ | _op_ARRAY_)) != _op_NAME_ )
          goto only_string;

        if ( !size && (Flags & (_op_CLSBEG_ | _OP_NOSIGN)) == _op_CLSBEG_ )
          Flags |= _OP_ONECLS;
        Flags &= ~_op_isTAG_;

        if ( sgnlev == 1 && (Flags & _op_INPRSIG_) ) // parse <...:...>
        {
          if ( size < 4 )
            goto only_string;  // >Lx; or >( )V
          switch ( po[1] )
          {
            default:
              Flags |= _op_MUSTNAM_;  // next substitution
              continue;
            case j_tag:
              goto only_string;
            case j_endsign: // end of <...:...>
              break;
          }
          ++po;   // skip ';'
          --size; // balance next '>'
          sgnlev = 0;
          Flags &= ~_op_INPRSIG_;
          if ( po[1] != j_parm_list_start )
            goto only_tag; // superclass{ifaces}
          ++po;   // skip '>' (go=> before do-while)
          off_ThrowsSignature_and_TypeSignature = (uint32)(po - tsPtr);
          goto to_func;
        } // end resolve end of <...:...>

        if ( sgnlev )
        {
          if ( po[1] == j_endsign )
            continue;
          if ( size > 2 )
            goto only_tag; // Lx;
          goto only_string;
        }
        Flags |= _OP_FULLNM;
        // class name can be full qualified array :(
        if ( (Flags&(_op_ISARRAY_|_op_PARAM_|_op_RETTYPE_)) != _op_ISARRAY_ )
        {
          if ( Flags & _OP_NOSIGN )
            goto only_string;  // speed only
          Flags |= _OP_NOFNM;
        }
        if ( Flags & (_op_RETTYPE_ | _op_PRIMSIG_) )
        {
          Flags &= ~_op_FRSPRM_;
          if ( Flags & _op_RETTYPE_ )
            goto check_throw;
        }
        continue;
    } // switch ( specchar ) FULLNM
norm_char:
    if ( Flags & (_OP_NOSIGN | _op_MUSTNAM_ | _op_NAME_) )
      continue;

    if ( Flags & _op_isTAG_ )
    {
      Flags |= _op_NAME_;
      continue;
    }
    if ( sgnlev )
      continue;

    if ( Flags & _op_PAREND_ )
    {
      off_ReturnType = (uint32)(po - tsPtr);
      Flags &= ~(_op_PAREND_ | _op_FRSPRM_);
      Flags |= _op_RETTYPE_;
      if ( cs == j_void_ret )
        goto check_throw;
    }

// chkdscr
    if ( (Flags & (_op_PARAM_ | _op_FRSPRM_)) == _op_FRSPRM_ )
      goto nodscsg;

    if ( cs == j_array )
    {
      Flags |= _op_ARRAY_ | _op_ISARRAY_;
      continue;
    }

    Flags = (Flags & ~_op_ARRAY_) | _op_FRSPRM_;
    switch ( cs )
    {
      case j_class:   // 'L'
        Flags |= _op_CLSBEG_;
        continue;
      case j_typeref: // 'T'
        Flags |= _op_TYPBEG_;
        continue;
      default:
        break;
    }
    if ( !cs || get_base_typename(cs) == nullptr )
    {
nodscsg:
      if ( Flags & (_OP_FULLNM | _op_RETTYPE_) )
        goto only_string;
      Flags |= _OP_NODSCR | _OP_NOSIGN;
    }
    else if ( Flags & _op_RETTYPE_ )
    {
check_throw:
      if ( !size )
        break;
      if ( size < 4 || po[1] != j_throw )
        goto only_string; // ^Lx;
      Flags |= _OP_FULLNM | _OP_NOFNM | _OP_NODSCR;
      ++po;   // skip rettype/previous-';'
      --size;
      if ( off_ThrowsSignature_and_TypeSignature < 0x10000 )
        off_ThrowsSignature_and_TypeSignature |= ((uint32)(po - tsPtr) << 16);
only_tag:
      --size;
      ++po;
skipped_only_tag:
      switch ( *po )
      {
        default:
          goto only_string;
        case j_class: // never set CLSBEG (no ONECLS)
        case j_typeref:
          Flags |= _op_TYPBEG_;
          break;
      }
    }
  }
  while ( ++po, size );

  if ( (Flags & (_op_PARAM_ | _op_PAREND_ | _op_ARRAY_)) || sgnlev )
  {
only_string:
    Flags |= (_OP_NODSCR | _OP_NOSIGN | _OP_NOFNM | _OP_FULLNM);
  }
  else
  {
    if ( Flags & (_op_CLSBEG_ | _op_TYPBEG_) )
    {
      Flags |= _OP_NODSCR | _OP_NOSIGN;
    }
    else if ( !(Flags & _OP_NOSIGN) )
    {
      if ( off_ReturnType )
      {
        Flags |= _OP_VALPOS;
        if ( off_ThrowsSignature_and_TypeSignature )
          Flags |= _OP_METSIGN;
      }
      else if ( off_ThrowsSignature_and_TypeSignature )
      {
        Flags |= _OP_CLSSIGN;
      }
    }
    // check for reserved words
    if ( !(Flags & _OP_NOWORD) )
      ResW_validate((uint32 *)&Flags, po);
  }
  if ( (ushort)Flags )
  {
SET_FLAGS:  // <init>/<cinit>/V nor reserved :)
    uint32 ind = ((uint32)index) << 16;
    co->_Sflags |= (ushort)Flags;
    ConstantNode.altset(ind, co->_Sopstr);
    CASSERT(_OP_VALPOS < 0x10000u);
    if ( Flags & _OP_VALPOS )
    {
      ConstantNode.altset(ind+1, off_ReturnType);
      if ( Flags & _OP_METSIGN )
        ConstantNode.altset(ind+2, off_ThrowsSignature_and_TypeSignature);
      if ( !(Flags & _OP_NODSCR) )
        co->flag |= HAS_CALLDSCR;
      return;
    }
  }

  cs = 0;
  if ( !(Flags & _OP_NODSCR) )
    cs |= HAS_TYPEDSCR;
  if ( !(Flags & _OP_NOFNM) )
    cs |= HAS_CLSNAME;
  if ( !(Flags & _OP_FULLNM) )
    cs |= HAS_FLDNAME;
  co->flag |= cs;
}

//--------------------------------------------------------------------------
//---------------------------------------------------------------------------
// generated by JDK1.5 (checked with beta of 1.6) -- previously version have
// some 'skipped' letters(?). See 'addonces\jvunigen.cpp' (and move headers)
uchar javaIdent(ushort v, uchar *isStart)
{
  static const uchar cpchtb[256] =
  {
     2,  3,  4,  5,  6,  7,  8,  9,  0, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21,  3, 22, 23, 24, 25,  0,  0,  0, 26, 27, 28,
    29, 30,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    31, 32,  0,  0,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, 33,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3, 34,
     3,  3,  3,  3, 35,  0,  0,  0,  0,  0,  0,  0,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
     3,  3,  3,  3,  3,  3,  3, 36,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  3, 37, 38,  3, 39, 40, 41 };

  static const uchar idxtb[42][32] =
  {
    {   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1 },
    {   0,  0,  0,  0,  1,  0,192,215, 38, 26, 26, 49, 38, 26, 26, 86,
        0,  0,  0,  0,  2,  3,111,  3, 26, 26,110, 26, 26, 26,110, 26 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26 },
    {  26, 26, 26, 26, 26, 26,110,  0,  0,  0, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 26, 26, 28, 26, 37,  0, 40, 83,  0,  0 },
    { 192,192,192,192,192,192,192,192,192,192,192,222,192,192,  0,  3,
       83,  4, 26, 26, 65, 26, 26, 26, 26,110, 26, 26, 26, 26, 71, 55 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      155,  5, 26, 26, 26, 26, 26, 26, 26,110, 26, 26, 26, 26, 96, 37 },
    {  26, 26,  0,  0,  0,  0, 38, 26, 26, 26,110, 97, 38, 26, 26, 26,
       26,  0,217,192,193,192,192,194,195,  0, 26, 26, 26, 86, 86,  0 },
    {   0,  0,224,  0, 38, 26, 26, 86, 26,154,192,228,192,156,157, 26,
       26, 26, 26, 26, 26, 26, 26, 26, 26, 26,158,196,159,160,192,191 },
    {   0,  0,190, 26, 26, 26,192,192,192,163,  0,  0,  0,  0,  0,  0,
       26, 26, 26, 26,164,192,165,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    { 166, 26, 26, 26, 26, 26, 26,189,192,224,168, 26,169,192,  0,  0,
      170, 63,  6, 26, 26, 32,  7,189,196,197,237,  8,169,192, 55,  0 },
    { 170, 49,  6, 26, 26, 32,  9,171,198,197,  0, 10,216,192,172,  0,
      170, 71, 65, 26, 26, 32, 11,189,199,200,100,  0,169,192, 97,  0 },
    { 170, 63,  6, 26, 26, 32, 11,189,201,197,216,  8,173,192, 97,  0,
      188, 74, 75, 12,108, 74, 71,173,202,203,237,  0,237,192,  0, 97 },
    { 170, 76, 32, 26, 26, 32, 30,173,204,203,219,  0,173,192,  0,  0,
      175, 76, 32, 26, 26, 32, 30,189,204,203,219, 83,173,192,  0,  0 },
    { 175, 76, 32, 26, 26, 32, 26,173,205,203,237,  0,173,192,  0,  0,
      175, 26,110,  5, 26, 26, 65, 90,110,206,207,192,  0,  0,208,  0 },
    {  38, 26, 26, 26, 26, 26,187,177,178,238,192,215,  0,  0,  0,  0,
       13, 14, 98, 38, 15, 47,187,179, 79,224,192,186,  0,  0,  0,  0 },
    { 100,  0,  0,215,192,215,221,209, 26, 38, 26, 26, 26, 86,217,192,
      204, 55,192,217,192,192,192,210,211,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 65,185,202,215,192,215,164,215,  0,  0,  0,  0,
        0,  0,  0,  0, 26, 26, 26, 26, 96,  0, 26, 26, 26, 26, 26,100 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 16, 26, 26, 26, 26,
       26, 26, 26, 26, 86, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 37 },
    { 110, 26, 26, 26, 26, 26, 26, 26,110, 75,110, 75, 26, 26, 26, 26,
      110, 75, 26, 26, 26,110, 75,110, 75,110,110, 26, 26,110, 26, 26 },
    {  26,110, 75,110, 26, 26, 26, 26,110, 26, 26, 86,  0,217,215,  0,
        0,  0,  0,  0, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 40,  0 },
    {  38, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 63,110,  0,
       38, 26, 26, 86, 26, 26, 26, 26, 26, 26, 26, 26, 26, 74,100,  0 },
    {  26, 76,182,  0, 26, 26,182,  0, 26, 26,183,  0, 26, 76,184,  0,
       26, 26, 26, 26, 26, 26,181,192,192,192,180,176,192,215,  0,  0 },
    {   0,212,192,215, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,  0,
       26, 26, 26, 26, 26,174,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 40,192,241,192,241,216,192, 26, 26, 26, 96, 40,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 55,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 55, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 37 },
    {  26, 26, 96, 96, 26, 26, 26, 26, 96, 96, 26, 17, 26, 26, 26, 96,
       26, 26, 26, 26, 26, 26, 76, 79, 18, 40, 41, 55, 26, 40, 18, 40 },
    {   0,  0,  0,  0,  0,  0,  0,109,100,  0,  1,  0,  0,  0, 97,109,
        0,  0,  0,  0, 26, 26, 37,  0,  0,  0,192,210,213,214,  0,  0 },
    {  78,  5, 90, 19, 20, 21, 65, 22, 33, 37,  0,  0, 26, 26, 26, 26,
       55,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  33,  0,  0,  0, 38,167, 19, 40, 38, 26, 26, 26, 26, 26, 26, 26,
       26, 26,110,162, 38, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26 },
    {  33, 26, 26, 26, 26, 40, 38, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26,110,  0,  0, 26, 26, 26,  0,  0,  0,  0,  0,  0,  0, 26, 26 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 96,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 96,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 40,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 55,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    {  26, 26, 26, 26, 26, 96, 26, 26, 26, 26, 26, 26, 26, 86,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    { 110,  0, 23,161, 26, 32,110, 79, 24, 26, 26, 26, 26, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 37,  0,  0,  0, 23, 26, 26, 26, 26, 26 },
    {  26, 26, 26, 26, 26, 26, 26, 96,  0,  0, 26, 26, 26, 26, 26, 26,
       26, 26,  5, 26, 26, 26, 26, 26, 26,  0,  0,  0,  0,  0, 26, 40 },
    { 192,192,  0,  0,241,  0,108,  0,  0, 33,  0,  0,  0, 97, 76, 26,
       26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 40 },
    {   1,  0,192,215, 38, 26, 26, 49, 38, 26, 26, 86, 33, 26, 26, 26,
       26, 26, 26, 26, 26, 26, 26,110,  5,  5,  5,104, 25,  0,  0,  0 }
  };

  static const uchar bittb[124] =
  {
    0x00, 0x10, 0x3C, 0x04, 0xD7, 0xFC, 0xF9, 0xC5, 0xB0, 0x6D, 0x5E, 0xED,
    0xD6, 0x96, 0x25, 0xAE, 0x83, 0xAA, 0xDC, 0x3E, 0x50, 0xBD, 0xE3, 0xF8,
    0xDB, 0x63, 0xFF, 0x7B, 0xC3, 0xFF, 0xEF, 0xFF, 0xFD, 0xE0, 0xE6, 0xE7,
    0xFF, 0x03, 0xFE, 0xFF, 0x1F, 0xCF, 0xEE, 0xD3, 0x1F, 0xC3, 0x03, 0xEC,
    0x38, 0x87, 0xFF, 0x3B, 0x8F, 0xCF, 0x1F, 0x0F, 0x0D, 0xF6, 0x33, 0xFF,
    0xEC, 0xF3, 0xFF, 0x9F, 0xFF, 0xFB, 0xBB, 0x16, 0x9F, 0x39, 0x87, 0xBF,
    0x3B, 0x8F, 0xC7, 0x3D, 0xDF, 0xCF, 0x84, 0x5F, 0x0C, 0xC2, 0x1F, 0x40,
    0x38, 0xE2, 0x07, 0x03, 0xC0, 0xFE, 0x2F, 0x60, 0xC0, 0xA0, 0xE0, 0xE0,
    0x3F, 0x02, 0xF0, 0x03, 0x01, 0x03, 0xE0, 0x03, 0x1C, 0x03, 0x01, 0xE0,
    0x18, 0x80, 0x7F, 0x20, 0x80, 0x0F, 0x03, 0x03, 0x01, 0x06, 0x30, 0x0D,
    0xE8, 0x23, 0xFD, 0x9C
  };

  uint ind = idxtb[cpchtb[v >> 8]][(((uchar)v) >> 3) & 31];
  uchar bit = uchar(1 << (v & 7));

  if ( !(bittb[ind & 0x7F] & bit) )
    return 0;
  if ( isStart )
    *isStart = (!(ind & 0x80)
            || (!(ind & 0x40) && (bittb[ind - 68] & bit)));
  return 1;
}

