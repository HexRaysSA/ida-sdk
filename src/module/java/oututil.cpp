#include "java.hpp"
#include "oututil.hpp"

//--------------------------------------------------------------------------
// returns number of positions advanced
int out_java_t::out_commented(const char *p, color_t color)
{
  if ( color != COLOR_NONE )
    out_tagon(color);
  size_t inplen = outbuf.length();
  out_printf("%s %s", ash.cmnt, p);
  int npos = outbuf.length() - inplen;
  if ( color != COLOR_NONE )
    out_tagoff(color);
  return npos;
}

//----------------------------------------------------------------------
bool out_java_t::change_line(bool main)
{
  bool overflow = false;
  if ( pm().g_bufinited )
  {
    pm().outcnt = 0;
    uchar sv = inf_get_indent();
    inf_set_indent((uchar)pm().curpos);
    overflow = flush_buf(outbuf.c_str(), main ? -1 : pm().curpos);
    inf_set_indent(sv);
    // for autocomment with call fmtName
    outbuf.qclear();
    outbuf.reserve(pm().g_bufsize);
  }
  return overflow;
}

//----------------------------------------------------------------------
size_t out_java_t::putLine(java_t &pm)
{
  color_t color = COLOR_NONE;

  if ( pm.g_bufinited )
  {
    const char *p = strrchr(outbuf.c_str(), COLOR_ON);
    if ( p != nullptr && p[1] && strchr(p+2, COLOR_OFF) == nullptr )   // second - PARANOYA
    {
      color = (color_t)*(p + 1);
      out_tagoff(color);
    }
  }
  out_symbol('\\');
  if ( change_line(pm.curpos != 0 && !pm.no_prim) )
    return 0;
  pm.curpos = 0;
  if ( color != COLOR_NONE )
    out_tagon(color);
  pm.ref_pos = outbuf.length();
  return pm.maxpos;
}

//----------------------------------------------------------------------
bool out_java_t::checkLine(size_t size)
{
  if ( !pm().g_bufinited )
    return true;
  if ( pm().maxpos - pm().curpos > pm().outcnt + size )
    return true;
  return putLine(pm()) != 0;
}

//----------------------------------------------------------------------
bool out_java_t::chkOutLine(const char *str, size_t len)
{
  if ( !checkLine(len) )
    return true;
  pm().outcnt += len;
  out_line(str);
  return false;
}

//----------------------------------------------------------------------
bool out_java_t::chkOutKeyword(const char *str, uint len)
{
  if ( !checkLine(len) )
    return true;
  OutKeyword(str, len);
  return false;
}

//----------------------------------------------------------------------
bool out_java_t::chkOutSymbol(char c)
{
  if ( !checkLine(1) )
    return true;
  ++pm().outcnt;
  out_symbol(c);
  return false;
}

//----------------------------------------------------------------------
bool out_java_t::chkOutChar(char c)
{
  if ( !checkLine(1) )
    return true;
  ++pm().outcnt;
  out_char(c);
  return false;
}

//----------------------------------------------------------------------
bool out_java_t::chkOutSymSpace(char c)
{
  if ( !checkLine(2) )
    return true;
  out_symbol(c);
  out_char(' ');
  pm().outcnt += 2;
  return false;
}

//----------------------------------------------------------------------
uchar out_java_t::putShort(ushort value, uchar wsym)
{
  size_t inplen = outbuf.length();

  out_tagon(COLOR_ERROR);
  if ( wsym )
    out_char(wsym);
  out_btoa(value,
#ifdef __debug__
                debugmode ? 16 :
#endif
                10);
  out_tagoff(COLOR_ERROR);

  char tmpstr[32];
  size_t curlen = outbuf.length();
  size_t len = curlen - inplen;
  qstrncpy(tmpstr, &outbuf[inplen], qmin(len+1, sizeof(tmpstr)));
  outbuf.resize(inplen);
  return chkOutLine(tmpstr, tag_strlen(tmpstr));
}

//----------------------------------------------------------------------
char out_java_t::outName(ea_t from, int n, ea_t ea, uval_t off, uchar *rbad)
{
  qstring qbuf;

  if ( get_name_expr(&qbuf, from, n, ea + off, off) <= 0 )
  {
    remember_problem(PR_NONAME, insn.ea);
    return 0;
  }
  if ( chkOutLine(qbuf.begin(), tag_strlen(qbuf.begin())) )
  {
    *rbad = 1;
    return 0;
  }
  return 1;
}

//---------------------------------------------------------------------------
uchar out_java_t::putVal(const op_t &x, uchar mode, uchar warn)
{
  size_t inplen = outbuf.length();

  {
    flags64_t saved = F;
    F = 0;
    out_value(x, mode);
    F = saved;
  }

  char str[MAXSTR];
  size_t curlen = outbuf.length();
  size_t len = curlen - inplen;
  qstrncpy(str, &outbuf[inplen], qmin(len+1, sizeof(str)));
  outbuf.resize(inplen);

  if ( warn )
    out_tagon(COLOR_ERROR);

  if ( warn )
  {
    qstring qstr;
    len = tag_remove(&qstr, str);
    qstrncpy(str, qstr.c_str(), sizeof(str));
  }
  else
  {
    len = tag_strlen(str);
  }

  if ( chkOutLine(str, len) )
    return 0;

  if ( warn )
    out_tagoff(COLOR_ERROR);
  return 1;
}

//----------------------------------------------------------------------
CASSERT(MIN_ARG_SIZE >= 2 && MIN_ARG_SIZE < 30);

uchar out_java_t::OutUtf8(ushort index, fmt_t mode, color_t color)
{
  size_t size = (pm().maxpos - pm().curpos) - pm().outcnt;

  if ( (int)size <= MIN_ARG_SIZE )
  {
    DEB_ASSERT(((int)size < 0), "OutUtf8");
    size = putLine(pm());
    if ( size == 0 )
      return 1;
  }

  if ( color != COLOR_NONE )
    out_tagon(color);
  pm().ref_pos = outbuf.length();
  struct ida_local lambda_t
  {
    static size_t call_putLine(java_t &pm, out_java_t *oj)
    {
      return oj->putLine(pm);
    }
  };
  if ( fmtString(pm(), index, size, mode, lambda_t::call_putLine) < 0 )
    return 1;
  pm().outcnt += outbuf.length() - pm().ref_pos;
  if ( color != COLOR_NONE )
    out_tagoff(color);
  return 0;
}

//---------------------------------------------------------------------------
uchar out_java_t::out_index(ushort index, fmt_t mode, color_t color, uchar as_index)
{
  if ( as_index )
  {
    if ( !(pm().idpflags & (IDM_BADIDXSTR | IDM_OUTASM))   // no store in file
      || !pm().is_valid_string_index(index) )
    {
      return putShort(index);
    }
    color = COLOR_ERROR;
    mode = fmt_string;
  }
  return OutUtf8(index, mode, color);
}

//--------------------------------------------------------------------------
uchar out_java_t::out_alt_ind(uint32 val)
{
  if ( (ushort)val )
    return OutUtf8((ushort)val, fmt_fullname, COLOR_IMPNAME);
  return putShort((ushort)(val >> 16));
}

//--------------------------------------------------------------------------
// special label format/scan procedures
//--------------------------------------------------------------------------
void out_java_t::out_method_label(uchar is_end)
{
  set_gen_cmt(true);
  set_gen_xrefs(true);
  gen_printf(0, COLSTR("met%03u_%s%s", SCOLOR_CODNAME), pm().curSeg.id.Number,
              is_end ? "end" : "begin", COLSTR(":", SCOLOR_SYMBOL));
}

//---------------------------------------------------------------------------
char out_java_t::putMethodLabel(ushort off)
{
  char str[32];
  int len = qsnprintf(str, sizeof(str), "met%03u_%s", pm().curSeg.id.Number,
                      off ? "end" : "begin");

  if ( !checkLine(len) )
    return 1;
  out_tagon(COLOR_CODNAME);
  outLine(str, len);
  out_tagoff(COLOR_CODNAME);
  return 0;
}

//--------------------------------------------------------------------------
// procedure for get_ref_addr
ssize_t java_t::check_special_label(const char *buf, size_t len) const
{
  if ( len >= sizeof("met000_end")-1
    && (*(uint32*)buf & 0xFFFFFF) == ('m'|('e'<<8)|('t'<<16)) )
  {

    switch ( *(uint32*)&buf[len -= 4] )
    {
      case ('_'|('e'<<8)|('n'<<16)|('d'<<24)):
        break;
      case ('e'|('g'<<8)|('i'<<16)|('n'<<24)):
        if ( len >= sizeof("met000_begin")-1 - 4
          && *(ushort*)&buf[len -= 2] == ('_'|('b'<<8)) )
        {
          break;
        }
        // no break
      default:
        len |= -1; // as flag
        break;
    }
    if ( len <= sizeof("met00000")-1 )
    {
      size_t off = curSeg.CodeSize;
      if ( buf[len+1] == 'b' )
        off = 0;
      size_t n = 0;
      size_t j = sizeof("met")-1;
      while ( true )
      {
        if ( !qisdigit((uchar)buf[j]) )
          break;
        n = n*10 + (buf[j] - '0');
        if ( ++j == len )
        {
          if ( n >= 0x10000 || (ushort)n != curSeg.id.Number )
            break;
          return off;
        }
      }
    }
  }
  return -1;
}

//--------------------------------------------------------------------------
// end of special-label procedures
//----------------------------------------------------------------------
uchar out_java_t::outOffName(ushort off)
{
  if ( !off || off == pm().curSeg.CodeSize )
    return putMethodLabel(off);
  if ( off < pm().curSeg.CodeSize )
  {
    uchar err = 0;
    if ( outName(pm().curSeg.start_ea + pm().curSeg.CodeSize, 0,
                 pm().curSeg.start_ea, off, &err) )
      return 0; // good
    if ( err )
      return 1; // bad
  }
  return putShort(off, 0);
}

//----------------------------------------------------------------------
bool out_java_t::block_begin(uchar off)
{
  return flush_buf(COLSTR("{", SCOLOR_SYMBOL), off);
}

//----------------------------------------------------------------------
bool out_java_t::block_end(uint32 off)
{
  return flush_buf(COLSTR("}", SCOLOR_SYMBOL), off);
}

//----------------------------------------------------------------------
bool out_java_t::block_close(uint32 off, const char *name)
{
  if ( !jasmin() )
    return block_end(off);
  return gen_printf(off, COLSTR(".end %s", SCOLOR_KEYWORD), name);
}

//----------------------------------------------------------------------
bool out_java_t::close_comment(void)
{
  return flush_buf(COLSTR("*/", SCOLOR_AUTOCMT), 0);
}

//---------------------------------------------------------------------------
uchar out_java_t::out_nodelist(uval_t nodeid, uchar pos, const char *pref)
{
  netnode node(nodeid);
  uval_t cnt = node.altval(0);
  if ( cnt == 0 )
    DESTROYED("out::nodelist");

  uval_t off = 0;
  if ( pref ) // jasmin
  {
    if ( change_line() )
    {
bad:
      return 0;
    }
    off = strlen(pref);
  }

  uint i = 0;
  while ( true )
  {
    if ( pref ) // jasmin (single directive per line)
    {
      pm().curpos = pos;
      out_keyword(pref);
      pm().outcnt = off;
    }
    else if ( i && chkOutSymSpace(',') )
    {
      goto bad; // prompted list
    }
    if ( out_alt_ind((uint32)node.altval(++i)) )
      goto bad;
    if ( i >= cnt )
      return 1;
    if ( pref && change_line() )
      goto bad; // jasmin
  }
}

//----------------------------------------------------------------------
void out_java_t::init_prompted_output(uchar pos)
{
  pm().maxpos = inf_get_margin();
//  if ( maxpos < 32 )
//    maxpos = 32;
//  if ( maxpos > MAXSTR - 4 )
//    maxpos = MAXSTR - 4;

#ifdef __debug__
  if ( debugmode == -1
    && inf.show_line_pref() && inf_get_margin() == 77 && !inf.bin_prefix_size )
  {
    maxpos -= gl_psize;
  }
#endif
  pm().g_bufsize = (MAXSTR*2) - STR_PRESERVED;
  pm().g_bufinited = true;
  outbuf.qclear();
  outbuf.reserve(pm().g_bufsize);
  pm().curpos = pos;
  pm().outcnt = 0;
}

//----------------------------------------------------------------------
void out_java_t::term_prompted_output(void)
{
  outbuf.qclear();
  pm().g_bufinited = false;
  pm().g_bufsize = 0;
  pm().maxpos = 0;
  pm().curpos = -1;
}

//----------------------------------------------------------------------
uchar out_java_t::OutConstant(const op_t &_x, bool include_descriptor)
{
  op_t x = _x;
  fmt_t fmt = fmt_FieldDescriptor;
  color_t color;

  insn_t cur_insn;
  decode_insn(&cur_insn, insn_ea);
  switch ( (uchar)x.cp_type )
  {
    default:
      warning("OC: bad constant type %u", (uchar)x.cp_type);
      break;

    case CONSTANT_Long:
      x.dtype = dt_qword;
      goto outNum;
    case CONSTANT_Double:
      x.dtype = dt_double;
      goto outNum;
    case CONSTANT_Integer:
      x.dtype = dt_dword;
      goto outNum;
    case CONSTANT_Float:
      x.dtype = dt_float;
outNum:
      if ( putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
        break;
badconst:
      return 0;

    case CONSTANT_Utf8:
      if ( OutUtf8(x.cp_ind, fmt_string, COLOR_STRING) )
        goto badconst;
      break;

    case CONSTANT_String:
      if ( OutUtf8(x._name, fmt_string, COLOR_STRING) )
        goto badconst;
      break;

    case CONSTANT_NameAndType:
nameandtype:
      if ( OutUtf8(x._class, fmt_fullname)
        || OutUtf8(x._name, fmt_fullname) )
      {
        goto badconst;
      }
      break;

    case CONSTANT_InvokeDynamic:
      {
        const_desc_t invdyn;
        if ( pm().ConstantNode.supval(x.cp_ind, &invdyn, sizeof(invdyn)) != sizeof(invdyn) )
          goto badconst;
        // Retrieve NameAndType
        const_desc_t nat;
        if ( pm().ConstantNode.supval(invdyn._name, &nat, sizeof(nat)) != sizeof(nat) )
          goto badconst;
        memset(&x, 0, sizeof(x));
        pm().copy_const_to_opnd(x, nat);
        x.ref = 0;
        x.cp_type = nat.type;
        x.cp_ind = invdyn._name;
        goto nameandtype;
      }
      break;

    case CONSTANT_MethodHandle:
      {
        const_desc_t tmp;
        if ( pm().ConstantNode.supval(x._mhr_index, &tmp, sizeof(tmp)) != sizeof(tmp) )
          goto badconst;
        op_t tmpop;
        memset(&tmpop, 0, sizeof(tmpop));
        pm().copy_const_to_opnd(tmpop, tmp);
        tmpop.ref = 0; // as flag
        tmpop.cp_type = tmp.type;
        tmpop.cp_ind = x._mhr_index;
        OutConstant(tmpop, include_descriptor);
      }
      break;

    case CONSTANT_MethodType:
      if ( OutUtf8(x._mtd_index, fmt_fullname, COLOR_KEYWORD) )
        goto badconst;
      break;

    case CONSTANT_Class:
      CASSERT((fmt_ClassName_or_Array+1) == fmt_ClassName && (fmt_ClassName+1) == fmt_fullname);
      {
        fmt_t f2 = (fmt_t )x.addr_shorts.high;
        color_t c2 = f2 < fmt_ClassName_or_Array || f2 > fmt_fullname ? COLOR_KEYWORD
                   : cur_insn.xtrn_ip == 0xFFFF ? COLOR_DNAME : COLOR_IMPNAME;

        if ( OutUtf8(x._name, f2, c2) )
          goto badconst;
      }
      break;

    case CONSTANT_InterfaceMethodref:
    case CONSTANT_Methodref:
      fmt = fmt_method_ReturnType;
      // fallthrough
    case CONSTANT_Fieldref:
#ifdef VIEW_WITHOUT_TYPE
      if ( include_descriptor )
#endif
        if ( !jasmin() && OutUtf8(x._dscr, fmt, COLOR_KEYWORD) )
          goto badconst;
      color = x._class == pm().curClass.This.Dscr ? COLOR_DNAME : COLOR_IMPNAME;
      out_tagon(color);
      if ( jasmin() || (color == COLOR_IMPNAME && !include_descriptor) ) // other class
      {
        if ( OutUtf8(x._name, fmt_ClassName) || chkOutDot() )
          goto badconst;
      }
      if ( OutUtf8(x._subnam, fmt_UnqualifiedName) )
        goto badconst; // Field
      out_tagoff(color);
      if ( jasmin() )
      {
        if ( fmt == fmt_method_ReturnType )
          fmt = fmt_FieldDescriptor_nospace; // no space at end
        else if ( chkOutSpace() )
          goto badconst;
      }
      else
      {
        if ( fmt != fmt_method_ReturnType )
          break;
        fmt = fmt_method_TypeSignature;
      }
      if ( OutUtf8(x._dscr, fmt, COLOR_KEYWORD) )
        goto badconst;
      break;
  }
  return 1;
}

//--------------------------------------------------------------------------
// FIXME: there should be a better way of suppressing borders in disassembly
void out_java_t::myBorder(void)
{
  gen_empty_line();
  if ( pm().user_limiter )
  {
    inf_set_limiter(LMT_THIN);
    gen_border_line(false);
  }
  inf_set_limiter(0);  // do not output border between method & vars :(
}

//--------------------------------------------------------------------------
uchar out_java_t::out_problems(char str[MAXSTR], const char *prefix)
{
  if ( pm().curClass.extflg & XFL_C_ERRLOAD )
  {
    myBorder();
    gen_printf(DEFAULT_INDENT,
                COLSTR("%s This class has had loading time problem(s)", SCOLOR_ERROR),
                prefix);
    if ( pm().curClass.msgNode )
    {
      gen_empty_line();
      if ( pm().print_loader_messages(str, prefix, this) == -1 )
        return 1;
    }
    myBorder();
  }
  return 0;
}

//--------------------------------------------------------------------------
uchar out_java_t::putScope(ushort scope, uint32 doff)
{
  if ( !scope || scope == pm().curSeg.CodeSize )
    return putMethodLabel(scope);

  if ( scope < pm().curSeg.CodeSize )
  {
    uchar err = 0;
    if ( outName(pm().curSeg.DataBase + doff, 0, pm().curSeg.start_ea, scope, &err) )
      return 0;
    if ( err )
      return 1;
  }

  return putShort(scope, 0);
}

//----------------------------------------------------------------------
size_t out_java_t::debLine(java_t &)
{
  out_char('"');
  out_tagoff(COLOR_STRING);
  if ( change_line() )
    return 0;
  return putDeb(1);
}

//----------------------------------------------------------------------
void out_java_t::OutKeyword(const char *str, size_t len)
{
  pm().outcnt += len;
  out_keyword(str);
}

//----------------------------------------------------------------------
void out_java_t::outLine(const char *str, uint len)
{
  pm().outcnt += len;
  out_line(str);
}

//----------------------------------------------------------------------
uchar out_java_t::chkOutDot(void)
{
  return chkOutChar('.');
}

//----------------------------------------------------------------------
void out_java_t::OutSpace(void)
{
  ++pm().outcnt;
  out_char(' ');
}

//----------------------------------------------------------------------
uchar out_java_t::chkOutSpace(void)
{
  return chkOutChar(' ');
}

//--------------------------------------------------------------------------
size_t out_java_t::putDeb(uchar next)
{
  OUT_KEYWORD(".debug ");
  out_tagon(COLOR_STRING);
  if ( next )
    out_char('"');
  return pm().maxpos - pm().outcnt;
}

//----------------------------------------------------------------------
bool out_java_t::out_operand(const op_t &x)
{
  int outf;
  uchar warn = 0;

  switch ( x.type )
  {
    case o_near:
      if ( x.ref )
      {
        ++warn;
      }
      else
      {
        if ( outName(insn.ea + x.offb, x.n, pm().curSeg.start_ea, x.addr, &warn) )
          break;
        if ( warn )
          goto badop;
      }
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32, warn) )
        break;
      // no break
    case o_void:
badop:
      return false;

    case o_imm:
      if ( x.ref == 2 )
        ++warn;
      outf = OOFW_IMM | OOF_NUMBER | (x.ref ? OOFS_NOSIGN : OOF_SIGNED);
      if ( putVal(x, outf, warn) )
        break;
      goto badop;

    case o_mem:
      if ( jasmin() )
        goto putidcv_num;
      if ( x.ref )
      {
putAddr:
        ++warn;
      }
      else
      {
        if ( outName(insn.ea + x.offb, x.n, pm().curSeg.DataBase, x.addr, &warn) )
          break;
        if ( warn )
          goto badop;
      }
putidcv_num:
      if ( putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16, warn) )
        break;
      goto badop;

    case o_cpool:
      if ( !x.cp_ind )
      {
        OUT_KEYWORD("NULL");
      }
      else
      {
        if ( x.ref )
          goto putAddr;
        if ( !OutConstant(x) )
          goto badop;
      }
      break;

    case o_array:
      if ( !x.ref )
      {
        uchar btype = 0;
        switch ( uchar(x.cp_type) )
        {
          case T_BOOLEAN: btype = j_bool; break;
          case T_CHAR: btype = j_char; break;
          case T_FLOAT: btype = j_float; break;
          case T_DOUBLE: btype = j_double; break;
          case T_BYTE: btype = j_byte; break;
          case T_SHORT: btype = j_short; break;
          case T_INT: btype = j_int; break;
          case T_LONG: btype = j_long; break;
        }
        const TXS *tname = get_base_typename(btype);
        if ( tname == 0 || chkOutKeyword(tname->str, tname->size) )
          goto badop;
      }
      else
      {
        static const char tt_bogust[] = "BOGUST_TYPE-";

        if ( !checkLine(sizeof(tt_bogust) + 2) )
          goto badop;
        out_tagon(COLOR_ERROR);
        size_t inplen = outbuf.length();
        out_printf("%c%s%u", WARN_SYM, tt_bogust, (uchar)x.cp_type);
        pm().outcnt += outbuf.length() - inplen;
        out_tagoff(COLOR_ERROR);
      }
      break;

    default:
      warning("out: %a: bad optype %d", insn.ip, x.type);
      break;
  }
  return true;
}

//--------------------------------------------------------------------------
void java_t::java_footer(outctx_t &ctx)
{
  if ( !jasmin() )
  {
    out_java_t *p = (out_java_t *)&ctx;
    p->block_end(0);
  }
}
