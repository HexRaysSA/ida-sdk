/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "java.hpp"
#include "oututil.hpp"
#include "npooluti.hpp"
//lint -esym(666,qnumber) expression with side effects

// support for jasmin reserved word's
#define QS(f) (fmt_t)(f | FMT_ENC_RESERVED)

DECLARE_OUT_FUNCS(out_java_t)

//----------------------------------------------------------------------
bool out_java_t::out_sm_end(void)
{
  return block_close(4, "stack");
}

//----------------------------------------------------------------------
bool out_java_t::out_deprecated(uchar pos)
{
  return flush_buf(COLSTR(".deprecated", SCOLOR_KEYWORD), pos);
}

//----------------------------------------------------------------------
//lint -e719 too many arguments for format
// no idea why lint complains, everything looks corrrect
bool out_java_t::out_sm_start(int same)
{
  char samestr[80];

  samestr[0] = 0;
  if ( same >= 0 )
  {
    char tmp[32];
    tmp[0] = '\0';
    if ( same )
      qsnprintf(tmp, sizeof(tmp), COLSTR(" %d", SCOLOR_NUMBER), same);
    qsnprintf(samestr, sizeof(samestr), " use%s locals", tmp);
  }

  if ( jasmin() )
    return gen_printf(4, COLSTR(".stack%s", SCOLOR_KEYWORD), samestr);

  return gen_printf(4,
                    COLSTR("%s %s StackMap%s", SCOLOR_AUTOCMT),
                    COLSTR("{", SCOLOR_SYMBOL),
                    ash.cmnt, samestr);
}

//----------------------------------------------------------------------
bool out_java_t::out_stackmap(const SMinfo *pinf)
{
  static char const *const verif[ITEM_BADOBJECT] =
  {
    "Top", "Integer", "Float", "Double", "Long", "Null", "UninitializedThis",
    "Object ", "Unititialized "
  };
  static char const *const kwd[3] = { "locals", "stack", nullptr };

  union
  {
    const uchar   *p1;
    const ushort  *p2;
  };

  char const *const *stage;
  uchar rectype;
  uint vcnt;

  p1 = pinf->pb;
  rectype = SMT_FULL_FRAME;
  if ( pm().SMF_mode )
    rectype = *p1++; // >=JDK6
  if ( rectype >= SMT_SAME_FRM_S1 )
    ++p2;  // skip offset
  if ( (rectype < SMT_SAME_FRM_S1 && rectype > SMT_SAME_FRM_S1_max) )
    goto BADIDB;
  if ( p1 > pinf->pe )
    goto BADIDB;

  {
    int hdr = -1;

    if ( rectype != SMT_FULL_FRAME )
    {
      ++hdr;  // 0 -- without args
      if ( rectype >= SMT_CHOP_FRM_S0_min && rectype <= SMT_CHOP_FRM_S0_max )
      {
        hdr = SMT_SAME_FRM_S0 - rectype;
        if ( (uint)hdr > pinf->fcnt )
          goto BADIDB;
        hdr = pinf->fcnt - hdr;
        if ( hdr == 0 )
          --hdr;  // nocopy
      }
    }
    if ( out_sm_start(hdr) )
      goto STOP_NOW;
  }

  if ( pinf->ea != insn.ea )
    if ( gen_printf(6, COLSTR("%s %u", SCOLOR_ERROR),
                    COLSTR("offset", SCOLOR_KEYWORD),
                    (uint)(pinf->ea - pm().curSeg.start_ea)) )
      goto STOP_NOW;


  if ( rectype <= SMT_SAME_FRM_S0_max )
    goto done_block;
  stage = &kwd[1];
  vcnt  = 1;
  if ( rectype > SMT_SAME_FRM_S1 )
  {
    if ( rectype <= SMT_SAME_FRM_S0 )
      goto done_block;
    --stage;
    if ( rectype != SMT_FULL_FRAME )
    {
      vcnt = rectype - SMT_SAME_FRM_S0;
    }
    else
    {
repeat_stage:
      vcnt = *p2++;
      if ( p1 > pinf->pe )
        goto BADIDB;
    }
  }
  if ( vcnt != 0 )
  {
    do
    {
      uchar tag = *p1++;
      if ( p1 > pinf->pe || tag > ITEM_CURCLASS )
        goto BADIDB;
      pm().curpos = 6;
      out_tagon(COLOR_KEYWORD);
      size_t inplen = outbuf.length();
      out_printf("%s %s", *stage,
                   verif[tag < ITEM_BADOBJECT ? SM_ITEM(tag) : ITEM_Object]);
      pm().outcnt = outbuf.length() - inplen;
      out_tagoff(COLOR_KEYWORD);
      CASSERT((ITEM_Object+1) == ITEM_Uninitialized
           && (ITEM_Uninitialized+1) == ITEM_BADOBJECT
           && (ITEM_BADOBJECT+1) == ITEM_CURCLASS);
      if ( tag >= ITEM_Object )
      {
        ushort var = *p2++;
        if ( p1 > pinf->pe )
          goto BADIDB;
        switch ( tag )
        {
          case ITEM_BADOBJECT:
            if ( putShort(var) )
              goto STOP_NOW;
            break;
          case ITEM_CURCLASS:
          case ITEM_Object:
            if ( OutUtf8(var,
                         QS(fmt_fullname),
                         tag == ITEM_Object ? COLOR_IMPNAME : COLOR_DNAME) )
              goto STOP_NOW;
            break;
          case ITEM_Uninitialized:
            if ( outOffName(var) )
              goto STOP_NOW;
            break;
        }
      }
      if ( change_line() )
        goto STOP_NOW;
    }
    while ( --vcnt );
  }
  if ( rectype == SMT_FULL_FRAME && *++stage )
    goto repeat_stage;
done_block:
  if ( p1 == pinf->pe )
    return out_sm_end();
BADIDB:
  DESTROYED("out_stackmap");
STOP_NOW:
  return true;
}

//----------------------------------------------------------------------
uchar out_java_t::OutModes(uint32 mode)
#define OA_THIS   0
#define OA_FIELD  1
#define OA_METHOD 2
#define OA_NEST   4 // in this case low BYTE == OA_NEST, hi word == access
{
  static const TXS fn[] =
  {
    TXS_DECLARE("public "),
    TXS_DECLARE("private "),
    TXS_DECLARE("protected "),
    TXS_DECLARE("static "),
    TXS_DECLARE("final "),
    TXS_DECLARE("synchronized "), // "super "   (file)
    TXS_DECLARE("volatile "),     // "bridge "  (method)
    TXS_DECLARE("transient "),    // "varargs " (method)
    TXS_DECLARE("native "),
    TXS_EMPTY(),  // "interface " // special output mode
    TXS_DECLARE("abstract "),
    TXS_DECLARE("fpstrict "),     // float-ing-point FP-stricted
    TXS_DECLARE("synthetic "),    // create by compiler (not present in source)
    TXS_DECLARE("annotation "),
    TXS_DECLARE("enum ")          // class or it superclass is enum
  };

  static const TXS ex[2] =
  {
    TXS_DECLARE("bridge "),
    TXS_DECLARE("varargs ")
  };

  static const TXS kwd[4] =
  {
    TXS_DECLARE(".class "),
    TXS_DECLARE(".field "),
    TXS_DECLARE(".method "),
    TXS_DECLARE(".interface ")
  };

  ushort access_mode;
  uchar off = 2, flg;
  int kwdo;

  switch ( mode )
  {
    case OA_FIELD:
      flg = pm().curField.id.extflg;
      access_mode = pm().curField.id.access & ACC_FIELD_MASK;
      break;
    case OA_METHOD:
      flg = pm().curSeg.id.extflg;
      access_mode = pm().curSeg.id.access & ACC_METHOD_MASK;
      break;
    case OA_THIS:
      flg = pm().curClass.extflg;
      access_mode = pm().curClass.AccessFlag & ACC_THIS_MASK;
      off = 0;
      break;
    default:  // OA_NEST
      flg = 0;
      access_mode = (ushort)(mode >> 16);
      break;
  }

  kwdo = mode & 3;
  if ( kwdo == 0 && (access_mode & ACC_INTERFACE) )
    kwdo += 3;

  if ( !jasmin() && (flg & XFL_DEPRECATED) )
  {
    out_commented("@Deprecated", COLOR_AUTOCMT);
    if ( change_line() )
    {
BADIDB:
      return 1;
    }
    pm().curpos = off;
  }

  if ( mode >= OA_NEST && !jasmin() )
  {
    pm().outcnt += out_commented("{Inner}: ");
  }
  else
  {
    out_tagon(COLOR_KEYWORD);
    uint rc = 0;
    if ( jasmin() )
    {
      if ( mode >= OA_NEST )
      {
        OUT_STR(".inner ");
        ++rc;
      }
      outLine(&kwd[kwdo].str[rc], kwd[kwdo].size-rc);
    }
  }
  for ( uint m, v = access_mode & ((1 << qnumber(fn)) - 1), i = 0;
        (m = (1<<i)) <= v;
        i++ ) //lint !e440 for clause irregularity
  {
    if ( (v & m) == 0 )
      continue;

    const TXS *pfn = &fn[i];

    switch ( m )
    {
      case ACC_SUPER:
        if ( !(mode & 3) )
          continue; // OA_THIS, OA_NEST: 'super' is deprecated;
      default:
        break;
      case ACC_BRIDGE:
      case ACC_VARARGS:
        if ( (uchar)mode == OA_METHOD )
          pfn = &ex[m == ACC_VARARGS];
        break;
    }
    if ( !pfn->size )
      continue; // special case
    if ( chkOutLine(pfn->str, pfn->size) )
      goto BADIDB;
  }
  switch ( mode )
  {
    default:  // OA_NEST, OA_THIS
      if ( !jasmin()
        && chkOutLine(&kwd[kwdo].str[1], kwd[kwdo].size-1) )
      {
        goto BADIDB;
      }
      if ( (uchar)mode != OA_THIS && !jasmin() )
        break;
      // no break
    case OA_FIELD:
    case OA_METHOD:
      out_tagoff(COLOR_KEYWORD);
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
uchar out_java_t::sign_out(ushort utsign, char mode)
{
  fmt_t fmt = fmt_string;

  if ( !jasmin() )
  {
    out_tagon(COLOR_AUTOCMT);
    pm().outcnt += out_commented("User type: ");
    fmt = fmt_FieldDescriptor_nospace; // for field/locvar
    if ( mode )
    {
      fmt = fmt_method_FormalTypeParameters;
      if ( mode > 0 )
        fmt = fmt_ClassSignature;  // defer for check ONLY
    }
  }
  else
  {
    static const TXS sgn = TXS_DECLARE(".signature ");
    out_tagon(COLOR_KEYWORD);
    if ( chkOutLine(sgn.str + !mode, sgn.size - !mode) )
      goto BADIDB;
  }
  if ( OutUtf8(utsign, fmt) )
  {
BADIDB:
    return 1;
  }
  if ( fmt == fmt_method_FormalTypeParameters )
  {
    if ( OutUtf8(utsign, fmt_method_ReturnType)
      || chkOutSpace()
      || OutUtf8(utsign, fmt_method_TypeSignature)
      || OutUtf8(utsign, fmt_method_ThrowsSignature) )
    {
      goto BADIDB;
    }
  }
  out_tagoff(jasmin() ? COLOR_KEYWORD : COLOR_AUTOCMT);
  if ( mode || !jasmin() )
    return change_line();
  return chkOutSpace();
}

//----------------------------------------------------------------------
void out_java_t::out_switch(void)
{
  op_t x;
  x.n     = 0;
  x.flags = OF_SHOW;
  x.dtype = dt_dword;
  x.type  = o_imm;

  if ( !jasmin() && block_begin(4) )
    return;

  uchar nwarns = 0;
  uval_t count;
  ea_t addr;
  for ( addr = insn.Op2.addr, count = insn.Op3.value; count; addr += 4, count-- )
  {
    pm().curpos = 8;
    if ( insn.itype == j_lookupswitch )
    {
      x.value = get_dword(pm().curSeg.start_ea + addr); // pairs
      addr += 4;
      if ( !putVal(x, OOFW_IMM | OOF_NUMBER | OOF_SIGNED | OOFW_32, 0)
        || chkOutSpace()
        || chkOutSymSpace(':') )
      {
        return;
      }
      if ( !checkLine(1 + 8 - ((pm().outcnt + 1) % 8)) )
        return;
      int idx = pm().outcnt & 7;
      if ( idx != 0 )
      {
        static const char seven_spaces[] = "       ";
        out_line(&seven_spaces[idx-1]);
      }
    }
    x.value = pm().trunc_uval(insn.ip + get_dword(pm().curSeg.start_ea + addr));
    if ( x.value >= pm().curSeg.CodeSize )
    {
      ++nwarns;
    }
    else
    {
      if ( outName(pm().curSeg.start_ea + addr, x.n, pm().curSeg.start_ea, x.value, &nwarns) )
        goto doneswitch;
      if ( nwarns )
        return;
    }
    if ( !putVal(x, OOFW_IMM | OOF_NUMBER | OOFS_NOSIGN | OOFW_32, nwarns) )
      return;
doneswitch:
    if ( change_line() )
      return;
  }
  pm().curpos = 6;
  OUT_KEYWORD("default ");
  if ( chkOutSymSpace(':') || !out_operand(insn.Op3) || change_line() )
    return;
  if ( !jasmin() )
    block_end(4);
}

//----------------------------------------------------------------------
void out_java_t::out_proc_mnem(void)
{
  static const char *const addonce[] = { "", "_w", "_quick", "2_quick", "_quick_w" };
  out_mnem(2, addonce[uchar(insn.wid)]);
}

//----------------------------------------------------------------------
void out_java_t::out_insn(void)
{
  pm().getMySeg(insn.ea); // set curSeg (for special strings)
  set_gen_xrefs(false);

  if ( pm().curSeg.smNode && !(pm().idpflags & IDF_HIDESM) )
  {
    SMinfo smi;
    smi.ea = BADADDR;
    if ( pm().sm_getinfo(insn, &smi) )
    {
      init_prompted_output(4);
      do
        if ( out_stackmap(&smi) )
          goto STOP_NOW;
      while ( pm().sm_getinfo(insn, &smi) );
    }
  }

  init_prompted_output(4);
  out_mnemonic();
  pm().outcnt = tag_strlen(outbuf.c_str());

  if ( insn.Op1.type != o_void )
  {
    if ( !out_one_operand(0) )
      goto STOP_NOW;
  }
  else
  {
    if ( (char)insn.Op1.ref > 0 )
    {
      qstring nbuf;
      if ( get_visible_name(&nbuf, insn.Op1.addr) > 0 )
        pm().outcnt += out_commented(nbuf.begin(), COLOR_REGCMT);
    }
  }

  if ( insn.Op2.type != o_void )
  {
    if ( chkOutSpace() )
      goto STOP_NOW;
    if ( insn.itype == j_tableswitch && !jasmin() )
    {
      if ( CHK_OUT_KEYWORD("to ") )
        goto STOP_NOW;
    }
    if ( !out_one_operand(1) )
      goto STOP_NOW;
  }

  if ( insn.Op3.type != o_void && !insn.swit ) // ! lookupswitch/tablesswitch
  {
    if ( chkOutSpace() || !out_one_operand(2) )
      goto STOP_NOW;
  }

  set_gen_xrefs(true);
  set_gen_cmt(true);
  if ( !change_line(true) )
  {
    if ( insn.swit & 2 )
      out_switch();  // normal tableswitch/lookupswitch
  }
STOP_NOW:
  term_prompted_output();
}

//--------------------------------------------------------------------------
bool out_java_t::close_annotation(uint32 pos)
{
  return block_close(pos, "annotation");
}

//--------------------------------------------------------------------------
const ushort *out_java_t::annotation(const ushort *p, uint *plen, uint pos)
{
  if ( *plen < sizeof(ushort) )
    return nullptr;
  *plen -= sizeof(ushort);
  uint pairs = *p++;
  if ( pairs != 0 )
  {
    do
    {
      pm().curpos = pos;
      if ( *plen < sizeof(ushort) )
        return nullptr;
      *plen -= sizeof(ushort);
      p = annotation_element(p+1, plen, pos, *p);
      if ( p == nullptr )
        break;
      if ( change_line() )
        goto STOP_NOW;
    }
    while ( --pairs );
  }
  return p;

STOP_NOW:
  *plen = (uint)-1;
  return nullptr;
}

//--------------------------------------------------------------------------
const ushort *out_java_t::annotation_element(
        const ushort *p,
        uint *plen,
        uint pos,
        ushort name)
{
  uchar tag = 0, type = 0;
  ushort val, prev = 0;
  int alev = 0;
  color_t ecol = COLOR_IMPNAME;
  const TXS *pt;
  const_desc_t co;

  op_t x;
  x.flags = 0;  // output flags, will be used by out_value()
  x.n = 0;      // operand number, will be used by out_value()
  do // array-values-loop
  {
arentry:
    if ( *plen < sizeof(uchar)+sizeof(ushort) )
      goto BADIDB;
    *plen -= sizeof(uchar)+sizeof(ushort);
    if ( alev > 0 && tag != *(uchar*)p )
      goto BADIDB;
    tag = *(uchar *)p;
    p = (ushort*)((uchar*)p+1);
    val = *p++;
    if ( tag == j_array )
    {
      if ( !*plen || (alev= val) == 0 || (tag= *(uchar*)p) == j_array )
        goto BADIDB;
      alev = -alev;
      goto arentry;
    }

    if ( alev > 0 ) // not first array element
    {
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( prev != val )
            goto BADIDB;
        default:
          break;
      }
      if ( !jasmin() )
      {
        if ( chkOutSymSpace(',') )
          goto STOP_NOW;
      }
      else if ( tag != j_annotation )
      {
        if ( chkOutSpace() )
          goto STOP_NOW;
      }
      else
      {
        if ( change_line() )
          goto STOP_NOW;
        pm().curpos = pos;
      }
      goto do_value;
    }

    switch ( tag )
    {
      default:
        goto BADIDB;

      case j_annotation:
      case j_enumconst:
        if ( val == pm().curClass.This.Dscr )
          ecol = COLOR_DNAME;
        prev = val;
        // no break
      case j_class_ret:
      case j_string:
        break;

      case j_float:
        type    = CONSTANT_Float;
        x.dtype = dt_float;
        break;
      case j_long:
        type    = CONSTANT_Long;
        x.dtype = dt_qword;
        break;
      case j_double:
        type    = CONSTANT_Double;
        x.dtype = dt_double;
        break;
      case j_bool:
      case j_byte:
      case j_char:
        x.dtype = dt_byte;
        goto do_int;
      case j_short:
        x.dtype = dt_word;
        goto do_int;
      case j_int:
        x.dtype = dt_dword;
do_int:
        type = CONSTANT_Integer;
        break;
    }

    if ( jasmin() )
    {
      if ( name )
      {
        if ( OutUtf8(name, fmt_UnqualifiedName, COLOR_DNAME) || chkOutSpace() )
          goto STOP_NOW;
      }
      out_tagon(COLOR_KEYWORD);
      if ( alev )
      {
        if ( !checkLine(2) )
          goto STOP_NOW;
        out_char(j_array);
      }
      if ( chkOutChar(tag) )
        goto STOP_NOW;
      out_tagoff(COLOR_KEYWORD);
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( chkOutSpace() || OutUtf8(val, fmt_FieldDescriptor_nospace, ecol) )
            goto STOP_NOW;
        default:
          break;
      }
    }
    else
    { // jasmin
      static const TXS doptype[] =
      {
        TXS_DECLARE("String"),
        TXS_DECLARE("Enum"),
        TXS_DECLARE("Class"),
        TXS_DECLARE("Annotation")
      };
      pt = doptype;
      switch ( tag )
      {
        case j_annotation:
          ++pt;
          // no break
        case j_class_ret:
          ++pt;
          // no break
        case j_enumconst:
          ++pt;
          // no break
        case j_string:
          break;

        default:
          pt = get_base_typename(tag);
          if ( pt == nullptr )
            goto BADIDB;
          break;
      }
      if ( chkOutKeyword(pt->str, pt->size) )
        goto STOP_NOW;
      switch ( tag )
      {
        case j_enumconst:
        case j_annotation:
          if ( chkOutSpace() || OutUtf8(val, fmt_FieldDescriptor_nospace, ecol) )
            goto STOP_NOW;
        default:
          break;
      }
      if ( alev && CHK_OUT_KEYWORD("[]") )
        goto STOP_NOW;
      if ( name != 0 )
      {
        if ( chkOutSpace() || OutUtf8(name, fmt_UnqualifiedName, COLOR_DNAME) )
          goto STOP_NOW;
      }
    } // jasmin
    alev = -alev;  // 0 = 0
/*
    if ( chkOutSpace(insn) )
      goto STOP_NOW;
    if ( (name || jasmin()) && chkOutSymSpace(insn, '=') )
      goto STOP_NOW;
*/
    if ( chkOutSpace() || chkOutSymSpace('=') )
      goto STOP_NOW;
do_value:
    switch ( tag )
    {
      case j_annotation:
        if ( jasmin() )
        {
          if ( CHK_OUT_KEYWORD(".annotation") )
            goto STOP_NOW;
        }
        else
        {
          if ( chkOutSymbol('{') )
            goto STOP_NOW;
        }
        if ( change_line() )
          goto STOP_NOW;
        p = annotation(p, plen, pos+2);
        if ( p == nullptr )
          goto done;
        pm().curpos = pos;
        if ( jasmin() )
        {
          out_line(COLSTR(".end annotation", SCOLOR_KEYWORD));
        }
        else
        {
          out_symbol('}');
          ++pm().outcnt;
        }
        continue;

      case j_class_ret:
        if ( !OutUtf8(val, fmt_FieldDescriptor_nospace, // without space
                      val == pm().curClass.This.Dscr ? COLOR_DNAME : COLOR_IMPNAME) )
          continue;
STOP_NOW:
        *plen = (uint)-1;
BADIDB:
        return nullptr;

      case j_enumconst:
        if ( *plen < sizeof(ushort) )
          goto BADIDB;
        *plen -= sizeof(ushort);
        if ( OutUtf8(*p++, fmt_UnqualifiedName, ecol) )
          goto STOP_NOW;
        continue;

      case j_string:
        if ( OutUtf8(val, fmt_string, COLOR_STRING) )
          goto STOP_NOW;
        continue;

      default:
        break;
    }
    if ( !pm().LoadOpis(lm_normal, val, type, &co) )
      goto BADIDB;
    if ( !jasmin() )
    {
      switch ( tag )
      {
        case j_bool:
          {
            static const TXS bt[2] =
            {
              TXS_DECLARE("true"),
              TXS_DECLARE("false")
            };
            pt = &bt[!co.value];
            if ( chkOutKeyword(pt->str, pt->size) )
              goto STOP_NOW;
          }
          continue;

        case j_char:
          if ( co.value < ' ' || co.value >= 0x80 )
            break;
          if ( !checkLine(3) )
            goto STOP_NOW;
          out_printf(COLSTR("'%c'", SCOLOR_CHAR), char(co.value));
          pm().outcnt += 3;
          continue;

        default:
          break;
      }
    }
    pm().copy_const_to_opnd(x, co);
    if ( !putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
      goto STOP_NOW;
  }
  while ( alev && --alev );
done:
  return p;
}

//--------------------------------------------------------------------------
uchar out_java_t::annotation_loop(const uval_t *pnodes, uint nodecnt)
{
  uchar result = 1;
  uint32 pos = pm().curpos;

  if ( gen_empty_line() )
    goto STOP_NOW;

  for ( uint n = 0; n < nodecnt; n++ )
  {
    if ( pnodes[n] )
    {
      static char const *const jnames[5] =
      {
        "visible", "invisible", "default", "visibleparam", "invisibleparam"
      };
      static char const *const lnames[5] =
      {
        "RuntimeVisible", "RuntimeInvisible",
        "Default",
        "RuntimeVisibleParameter", "RuntimeInvisibleParameter"
      };
      char hdr[MAXSTR];
      uint hdrpos, hdrlen, len;
      const ushort *p = (ushort*)pm().get_annotation(pnodes[n], &len);
      if ( p == nullptr )
        goto BADIDB;

      if ( jasmin() )
      {
        hdrpos = qsnprintf(hdr, sizeof(hdr),
                           COLSTR(".annotation %s", SCOLOR_KEYWORD),
                           jnames[n]);
      }
      else
      {
        hdrpos = qsnprintf(hdr, sizeof(hdr),
                           COLSTR("%sAnnotation", SCOLOR_KEYWORD),
                           lnames[n]);
      }

      if ( n == 2 ) // defalut
      {
        if ( !jasmin() )
          qstrncpy(&hdr[hdrpos], COLSTR(" {", SCOLOR_SYMBOL), sizeof(hdr)-hdrpos);
        if ( flush_buf(hdr, pos) )
          goto STOP_NOW;
        pm().curpos = pos + 2;
        p = annotation_element(p, &len, pos+2, 0);
        if ( p == nullptr )
        {
checkans:
          if ( len == (uint)-1 )
            goto STOP_NOW;
          goto BADIDB;
        }
        if ( len )
          goto BADIDB;
        if ( change_line() || close_annotation(pos) )
          goto STOP_NOW;
        continue;
      }
      int nump = 0, ip = 1;
      uchar present = 0;
      if ( n > 2 ) // parameters
      {
        --len;
        nump = *(uchar*)p;
        if ( nump == 0 )
          goto BADIDB;
        p = (ushort*)((uchar*)p+1);
        if ( !jasmin() )
          hdrpos += qsnprintf(&hdr[hdrpos], sizeof(hdr)-hdrpos,
                              COLSTR(" for parameter", SCOLOR_KEYWORD));
      }
      hdr[hdrpos++] = ' ';
      hdr[hdrpos] = '\0';
      do // parameters loop
      {
        if ( len < sizeof(ushort) )
          goto BADIDB;
        len -= sizeof(ushort);
        uint cnt = *p++;
        if ( !cnt )
        {
          if ( !nump )
            goto BADIDB;
          continue;
        }
        if ( nump )
          qsnprintf(&hdr[hdrpos], sizeof(hdr) - hdrpos, COLSTR("%d ", SCOLOR_NUMBER), ip);
        present = 1;
        hdrlen = (uint32)tag_strlen(hdr);
        do // annotations loop
        {
          if ( len < sizeof(ushort) )
            goto BADIDB;
          len -= sizeof(ushort);
          pm().curpos = pos;
          out_line(hdr);
          pm().outcnt = hdrlen;
          if ( OutUtf8(*p, jasmin() ? fmt_FieldDescriptor_nospace : fmt_FieldDescriptor) )
            goto STOP_NOW;
          if ( !jasmin() )
            out_symbol('{');
          if ( change_line() )
            goto STOP_NOW;
          p = annotation(p+1, &len, pos+2);
          if ( p == nullptr )
            goto checkans;
          if ( close_annotation(pos) )
            goto STOP_NOW;
        }
        while ( --cnt );
      }
      while ( ++ip <= nump );
      if ( nump && !present )
        goto BADIDB;
      if ( len )
        goto BADIDB;
    }
  } // loop of annotation types
  result = 0;
STOP_NOW:
  return result;

BADIDB:
  DESTROYED("annotation");
}

//--------------------------------------------------------------------------
void out_java_t::java_header(void)
{
  char str[MAXSTR*2];

  if ( !jasmin() )
    flush_buf(COLSTR("/*", SCOLOR_AUTOCMT), 0);
  const char *prefix = jasmin() ? ash.cmnt : "";

#ifdef __debug__
  gen_printf(0, COLSTR("%sDisassembler mode: %s", SCOLOR_AUTOCMT),
              prefix, debugmode ? "DEBUG" : "Normal");
#endif
  gen_printf(0,
             COLSTR("%sJava Virtual Machine (JDK 1.%u)", SCOLOR_AUTOCMT),
             prefix, pm().curClass.JDKsubver);
  {
    char sv = inf_get_indent();
    inf_set_indent(0);
    if ( !jasmin() )
    {
      gen_printf(-1,
                 COLSTR("%sClassFile version: %u.%u", SCOLOR_AUTOCMT),
                 prefix, pm().curClass.MajVers, pm().curClass.MinVers);
    }
    else
    {
      if ( out_problems(str, prefix) )
        return;
      gen_empty_line();
      gen_printf(-1, COLSTR("%s %u.%u", SCOLOR_NUMBER),
                 COLSTR(".bytecode", SCOLOR_KEYWORD),
                 pm().curClass.MajVers, pm().curClass.MinVers);
    }
    inf_set_indent(sv);
  }

  if ( pm().curClass.SourceName )
  {
    init_prompted_output();
    if ( jasmin() )
    {
      OUT_KEYWORD(".source ");
      out_tagon(COLOR_STRING);
    }
    else
    {
      out_tagon(COLOR_AUTOCMT);
      OUT_STR("Source File      : ");
    }
    uchar stp;
    {
      uint32 save = pm().idpflags;
      pm().idpflags = (pm().idpflags & ~IDF_AUTOSTR) | IDF_ENCODING;  // PARANOYA
      stp = OutUtf8(pm().curClass.SourceName, fmt_string);
      pm().idpflags = save;
    }
    if ( !stp )
      out_tagoff(jasmin() ? COLOR_STRING : COLOR_AUTOCMT);
    if ( stp || flush_outbuf(0) )
      return;
  }
  else
  {
    gen_empty_line();
  }

  //
  {
    nodeidx_t bmnidx = bootstrap_methods_get_node(/*assert=*/ false, /*can_create=*/ true);
    if ( bmnidx != BADNODE )
    {
      const nodeidx_t bmcnt = bootstrap_methods_get_count();
      if ( bmcnt > 0 )
      {
        gen_printf(0, COLSTR("%sBootstrapMethods : %u", SCOLOR_AUTOCMT),
                   prefix, uint(bmcnt));
        for ( nodeidx_t bmidx = 0; bmidx < bmcnt; ++bmidx )
        {
          bootstrap_method_def_t bmd;
          const char *bmerr = "error retrieving data";
          bool bmok = bootstrap_methods_get_method(&bmd, bmidx);
          if ( bmok )
          {
            bmok = bmd.method_ref != 0 && bmd.method_ref <= pm().curClass.maxCPindex;
            if ( bmok )
            {
              const_desc_t tmp;
              bmok = pm().ConstantNode.supval(bmd.method_ref, &tmp, sizeof(tmp)) == sizeof(tmp);
              if ( bmok )
              {
                bmok = tmp.type == CONSTANT_MethodHandle;
                if ( bmok )
                {
                  const_desc_t method_handle;
                  bmok = pm().ConstantNode.supval(bmd.method_ref, &method_handle, sizeof(method_handle)) == sizeof(method_handle);
                  if ( bmok )
                  {
                    // qstring buf;
                    // buf.sprnt("MethodHandle{kind=%u, index=%u}",
                    //           method_handle._mhr_kind, method_handle._mhr_index);
                    // flush_buf(buf.c_str());
                    switch ( method_handle._mhr_kind )
                    {
                      case JVM_REF_getField:
                      case JVM_REF_getStatic:
                      case JVM_REF_putField:
                      case JVM_REF_putStatic:
                        // points at CONSTANT_Fieldref
                        //   (fallthrough)
                      case JVM_REF_invokeVirtual:
                      case JVM_REF_invokeStatic:
                      case JVM_REF_invokeSpecial:
                      case JVM_REF_newInvokeSpecial:
                        // points at CONSTANT_Methodref
                        {
                          qstrvec_t lines;
                          pm().print_constant(&lines, method_handle, bmd.method_ref);
                          if ( lines.empty() )
                            lines.push_back("<failed printing method handle>");
                          for ( ssize_t lidx = 0; lidx < lines.size(); ++lidx )
                            gen_printf(0, "%s", lines[lidx].c_str());
                          flush_outbuf();
                          for ( size_t argidx = 0, argcnt = bmd.args.size(); argidx < argcnt; ++argidx )
                          {
                            const_desc_t arg;
                            const ushort argcid = bmd.args[argidx];
                            if ( pm().ConstantNode.supval(argcid, &arg, sizeof(arg)) == sizeof(arg) )
                            {
                              lines.qclear();
                              pm().print_constant(&lines, arg, argcid, /*strip_tags=*/ true);
                              if ( lines.empty() )
                                lines.push_back("<failed printing constant>");
                              for ( size_t lidx = 0; lidx < lines.size(); ++lidx )
                                gen_printf(0, "Argument #%" FMT_Z ": %s", argidx, lines[lidx].c_str());
                            }
                            else
                            {
                              gen_printf(0, COLSTR("Error retrieving argument #%" FMT_Z, SCOLOR_ERROR), argidx);
                            }
                            flush_outbuf();
                          }
                        }
                        break;
                      case JVM_REF_invokeInterface:
                        // points at CONSTANT_InterfaceMethodref
                        bmok = false;
                        break;
                    }
                  }
                  else
                  {
                    bmerr = "Couldn't retrieve method handle";
                  }
                }
                else
                {
                  bmerr = "Bad constant type";
                }
              }
              else
              {
                bmerr = "Corrupted data";
              }
            }
            else
            {
              bmerr = "Bad constant pool index";
            }
          }
          if ( !bmok )
            gen_printf(0, COLSTR("Error retrieving bootstrap method %u (%s)", SCOLOR_ERROR),
                       uint(bmcnt), bmerr);
        }
      }
    }
  }

  if ( !jasmin() )
  {
    if ( out_problems(str, prefix) )
      return;
    close_comment();
  }
  myBorder();
}

//--------------------------------------------------------------------------
void idaapi java_header(outctx_t &ctx)
{
  out_java_t *p_ctx = (out_java_t *)&ctx;
  p_ctx->java_header();
}

//--------------------------------------------------------------------------
uchar out_java_t::enclose_out(void)
{
  if ( !jasmin() )
  {
    out_tagon(COLOR_AUTOCMT);
    size_t inplen = outbuf.length();
    out_printf("%sEnclosing %s: ", ash.cmnt,
                 pm().curClass.encMethod ? "method" : "class");
    pm().outcnt += outbuf.length() - inplen;
  }
  else
  {
    OUT_KEYWORD(".enclosing method ");
  }
  if ( !pm().curClass.encMethod )
  {
    if ( OutUtf8(pm().curClass.encClass, QS(fmt_fullname)) )
      return 1;
  }
  else
  {
    const_desc_t op;

    if ( !pm().LoadOpis(lm_normal, pm().curClass.encMethod, CONSTANT_NameAndType, &op) )
      DESTROYED("out::enclose");
    if ( (!jasmin() && OutUtf8(op._name, fmt_method_ReturnType))
      || OutUtf8(pm().curClass.encClass, fmt_fullname)
      || chkOutChar(jasmin() ? '/' : '.')
      || OutUtf8(op._class, fmt_UnqualifiedName)
      || OutUtf8(op._name, jasmin() ? fmt_FieldDescriptor : fmt_method_TypeSignature) )
    {
      return 1;
    }
  }
  if ( !jasmin() )
    out_tagoff(COLOR_AUTOCMT);
  pm().curpos = 0;
  return change_line();
}

//--------------------------------------------------------------------------
// output the method return type
uchar out_java_t::out_seg_type(fmt_t fmt)
{
  return out_index(pm().curSeg.id.dscr,
                   fmt,
                   COLOR_KEYWORD,
                   pm().curSeg.id.extflg & EFL_TYPE);
}

//--------------------------------------------------------------------------
// output the field type
uchar out_java_t::out_field_type(void)
{
  return out_index(pm().curField.id.dscr,
                   fmt_FieldDescriptor,
                   COLOR_KEYWORD,
                   pm().curField.id.extflg & EFL_TYPE);
}

//----------------------------------------------------------------------
uchar out_java_t::out_includes(uval_t node, uchar pos)
{
  netnode temp(node);
  uint32 len, vid, cnt = (uint32)temp.altval(0);
  color_t color = jasmin() ? COLOR_KEYWORD : COLOR_AUTOCMT;
  char fnm[qmin(QMAXPATH,MAXSPECSIZE)+4];

  if ( !cnt )
    goto BADIDB;
  fnm[0] = '"';
  do
  {
    pm().curpos = pos;

    len = (uint32)temp.supstr(cnt, &fnm[1], sizeof(fnm)-3);
    if ( !len )
      goto BADIDB;
    fnm[++len] = '"';
    fnm[++len] = '\0';
    char *pf = fnm;
    if ( pm().idpflags & IDF_NOPATH )
    {
      pf = strrchr(pf, '/');
      if ( pf != nullptr )
      {
        ++pf;
      }
      else
      {
#ifndef __UNIX__
        pf = &fnm[1+1];
        if ( *pf != ':' )
          --pf;
#else
        pf = &fnm[1];
#endif
      }
      *--pf = '"';
      len -= uint32(pf - fnm);
    }
    vid = (uint32)temp.altval(cnt);
    if ( vid == 0 || vid > pm().curClass.maxCPindex )
      goto BADIDB;
    out_tagon(color);
    if ( jasmin() )
      OUT_STR(".attribute ");
    else
      pm().outcnt = out_commented("GenericAttribute ");
    if ( OutUtf8((ushort)vid, fmt_UnqualifiedName)
      || chkOutSpace()
      || chkOutLine(pf, len) )
    {
      goto STOP_NOW;
    }
    out_tagoff(color);
    if ( change_line() )
      goto STOP_NOW;
  }
  while ( --cnt );
  return 0;

BADIDB:
  DESTROYED("out_includes");
STOP_NOW:
  return 1;
}

//----------------------------------------------------------------------
void out_java_t::java_segstart(segment_t *)
{
  ea_t ea = insn_ea;

  init_prompted_output(2);

  set_gen_cmt(true);
  switch ( pm().getMySeg(ea)->type ) // also set curSeg
  {
    case SEG_CODE:
      {
        func_t *pfn = get_func(ea);
        if ( pfn != nullptr )
        {
          qstring qbuf;
          if ( get_func_cmt(&qbuf, pfn, false) > 0
            || get_func_cmt(&qbuf, pfn, true) > 0 )
          {
            if ( gen_block_cmt(qbuf.c_str(), COLOR_REGCMT) )
              break;
          }
        }
      }
      pm().no_prim = true;
      if ( OutModes(OA_METHOD) )
        break;
      if ( !(pm().curSeg.id.extflg & EFL_TYPE)
        && !jasmin()
        && out_seg_type(fmt_method_ReturnType) )
      {
        break;
      }
      if ( out_index(pm().curSeg.id.name, fmt_UnqualifiedName, COLOR_CNAME,  // Method Name
                     pm().curSeg.id.extflg & EFL_NAME) )
        break;
      if ( pm().curSeg.id.extflg & EFL_TYPE )
      {
        if ( chkOutSpace() )
          break;
        goto do_dscid;
      }
      if ( jasmin() )
      {
do_dscid:
        if ( out_seg_type(fmt_FieldDescriptor) )
          break;
      }
      else if ( OutUtf8(pm().curSeg.id.dscr, fmt_method_TypeSignature, COLOR_KEYWORD) )
      {
        break;
      }
      if ( pm().curSeg.thrNode )
      {
        const char *p = ".throws ";
        if ( !jasmin() )
        {
          if ( CHK_OUT_KEYWORD(" throws ") )
            break;
          p = nullptr;
        }
        if ( !out_nodelist(pm().curSeg.thrNode, 2, p) )
          break;
      }
      if ( change_line() )
        break;
      if ( pm().curSeg.id.utsign )
      {
        pm().curpos = 2;
        if ( sign_out(pm().curSeg.id.utsign, -1) )
          break;
      }
      if ( jasmin() && (pm().curSeg.id.extflg & XFL_DEPRECATED) )
      {
        if ( out_deprecated(2) )
          break;
      }
      if ( pm().curSeg.genNodes[0] && out_includes(pm().curSeg.genNodes[0], 2) )
        break;

      if ( pm().curSeg.stacks )
      {
        int over = gen_printf(2,
                       jasmin() ? COLSTR(".limit stack %u", SCOLOR_ASMDIR) :
                                  COLSTR("max_stack %u", SCOLOR_ASMDIR),
                       pm().curSeg.stacks);
        if ( over )
          break;
      }

      if ( pm().curSeg.DataSize )
      {
        int over = gen_printf(2,
                       jasmin() ? COLSTR(".limit locals %u", SCOLOR_ASMDIR) :
                                  COLSTR("max_locals %u", SCOLOR_ASMDIR),
                       pm().curSeg.DataSize);
        if ( over )
          break;
      }
      if ( (pm().curSeg.id.extflg & XFL_M_EMPTYSM) && (out_sm_start(-1) || out_sm_end()) )
        break;

      if ( pm().curSeg.id.extflg & XFL_M_LABSTART )
        out_method_label(0);
      if ( !jasmin() )
        block_begin(2);
      break;

    case SEG_IMP:
      pm().curpos = 0;
      if ( OutModes(OA_THIS) )
        break;
      if ( out_index(pm().curClass.This.Name, QS(fmt_fullname), COLOR_DNAME,
                     (uchar)!pm().curClass.This.Dscr) )
        break;

      if ( jasmin() )
      {
        if ( !pm().curClass.super.Ref )
          goto nosuper;
        if ( change_line(true) )
          break;
        OUT_KEYWORD(".super ");
      }
      else
      {
        uchar sskip = 0;
        if ( !pm().curClass.super.Ref )
          goto check_imps;
        if ( (pm().curClass.AccessFlag & ACC_INTERFACE)
          && (pm().curClass.extflg & XFL_C_SUPEROBJ) )
        {
check_imps:
          if ( !pm().curClass.impNode )
            goto noparents;
          sskip = 1;
        }

        if ( CHK_OUT_KEYWORD(" extends ") )
          break;
        if ( sskip )
          goto nosuper;
      }
      if ( out_alt_ind(pm().curClass.super.Ref) )
        break;
nosuper:
      if ( pm().curClass.impNode )
      {
        const char *p = ".implements ";
        if ( !jasmin() )
        {
          if ( pm().curClass.AccessFlag & ACC_INTERFACE )
          {
            if ( pm().curClass.super.Ref
              && !(pm().curClass.extflg&XFL_C_SUPEROBJ)
              && chkOutSymSpace(',') )
            {
              break;
            }
          }
          else if ( CHK_OUT_KEYWORD(" implements ") )
          {
            break;
          }
          p = nullptr;
        }
        if ( !out_nodelist(pm().curClass.impNode, 0, p) )
          break;
      }
noparents:
      if ( change_line(!jasmin()) )
        break;
      if ( pm().curClass.utsign && sign_out(pm().curClass.utsign, 1) )
        break;
      if ( pm().curClass.encClass && enclose_out() )
        break;
      if ( jasmin() && (pm().curClass.extflg & XFL_DEPRECATED) )
      {
        if ( out_deprecated(0) )
          break;
      }
      if ( pm().curClass.genNode != 0 && out_includes(pm().curClass.genNode, 0) )
        break;
      struct ida_local lambda_t
      {
        static size_t call_debLine(java_t &pm, out_java_t *oj)
        {
          return oj->debLine(pm);
        }
      };
      if ( (pm().curClass.extflg & XFL_C_DEBEXT)
        && fmtString(pm(), (ushort)-1, putDeb(0), fmt_debug, lambda_t::call_debLine) >= 0 )
      {
        out_tagoff(COLOR_STRING);
        change_line();
      }
      break;

    case SEG_XTRN:
    case SEG_BSS:
      if ( !jasmin() )
        flush_buf(COLSTR("/*", SCOLOR_AUTOCMT), 0);
    default:
      break;
  }
  term_prompted_output();
  pm().no_prim = false;
}

//----------------------------------------------------------------------
void idaapi java_segstart(outctx_t &ctx, segment_t *seg)
{
  out_java_t *p_ctx = (out_java_t *)&ctx;
  p_ctx->java_segstart(seg);
}

//--------------------------------------------------------------------------
void out_java_t::java_segend(segment_t *seg)
{
  init_prompted_output(4);
  uchar t = pm().getMySeg(BADADDR, seg)->type; // also set curSeg
  switch ( t )
  {
    case SEG_CODE:
      clr_gen_label(); // for empty method's
      if ( pm().curSeg.id.extflg & XFL_M_LABEND )
        out_method_label(1);
      if ( pm().curSeg.excNode )
      {
        netnode enode(pm().curSeg.excNode);
        uint j = (uint32)enode.altval(0);
        if ( j == 0 )
          DESTROYED("out::segend");

        if ( !jasmin() )
          flush_buf(COLSTR("/*", SCOLOR_AUTOCMT), 0); /*"*///  makedep BUG!!!
        else
          gen_empty_line();
        uint i = 0;
        do
        {
          Exception ex;
          if ( enode.supval(++i, &ex, sizeof(ex)) != sizeof(ex) )
            DESTROYED("out::except");

          pm().curpos = 4; // for loop with large lines
          if ( !jasmin() )
          {
            OUT_KEYWORD("try");
          }
          else
          {
            OUT_KEYWORD(".catch ");
            CASSERT(offsetof(Exception, filter.Ref)  == offsetof(Exception, filter.Name)
                 && offsetof(Exception, filter.Dscr) == offsetof(Exception, filter.Name) + 2);
            if ( !ex.filter.Ref )
              OUT_KEYWORD("all");
            else if ( out_alt_ind(ex.filter.Ref) )
              goto STOP_NOW;
          }
          {
            static const TXS kw[3] =
            {
              TXS_DECLARE(" from "),
              TXS_DECLARE(" to "),
              TXS_DECLARE(" using ")
            };
            int n = 0;
            do
            {
              if ( n == 2 && !jasmin() )
              {
                if ( ex.filter.Ref )
                {
                  if ( CHK_OUT_KEYWORD(" catch")
                    || chkOutSymbol('(')
                    || out_alt_ind(ex.filter.Ref)
                    || chkOutSymbol(')') )
                  {
                    goto STOP_NOW;
                  }
                }
                else
                {
                  if ( CHK_OUT_KEYWORD(" finally") )
                    goto STOP_NOW;
                }
                if ( CHK_OUT_KEYWORD(" handler ") )
                  goto STOP_NOW;
              }
              else
              {
                if ( chkOutKeyword(kw[n].str, kw[n].size) )
                  goto STOP_NOW;
              }
              CASSERT(offsetof(Exception,end_pc)-offsetof(Exception,start_pc) == sizeof(ushort)
                   && offsetof(Exception,handler_pc)-offsetof(Exception,end_pc) == sizeof(ushort));
              ushort off = 0;
              switch ( n )
              {
                case 0: off = ex.start_pc;   break;
                case 1: off = ex.end_pc;     break;
                case 2: off = ex.handler_pc; break;
              }
              if ( outOffName(off) )
                goto STOP_NOW;
            }
            while ( ++n < 3 );
          }
          if ( change_line() )
            goto STOP_NOW;
        }
        while ( i < j );
        if ( !jasmin() )
          close_comment();
        else
          gen_empty_line();
      }
      if ( pm().curSeg.genNodes[1] && out_includes(pm().curSeg.genNodes[1], 2) )
        goto STOP_NOW;
      if ( pm().curSeg.DataSize )
        goto STOP_NOW;
close_method:
      for ( int i = 0; i < qnumber(pm().curSeg.annNodes); i++ )
      {
        if ( pm().curSeg.annNodes[i] )
        {
          if ( annotation_loop(pm().curSeg.annNodes, qnumber(pm().curSeg.annNodes)) )
            goto STOP_NOW;
          gen_empty_line();
          break;
        }
      }
      block_close(2, "method");
      break;

//    case SEG_IMP:
    default:  // PARANOYA
      break;

    case SEG_XTRN:
    case SEG_BSS:
      if ( !jasmin() )
        close_comment();
      if ( t == SEG_BSS )
        goto close_method;
      break;
  }
  myBorder();
STOP_NOW:
  term_prompted_output();
}

//--------------------------------------------------------------------------
void idaapi java_segend(outctx_t &ctx, segment_t *seg)
{
  out_java_t *p_ctx = (out_java_t *)&ctx;
  p_ctx->java_segend(seg);
}

//----------------------------------------------------------------------
static void check_float_const(ea_t ea, void *m, char len)
{
  if ( !has_cmt(get_flags(ea)) && j_realcvt(m, nullptr, (uchar)len) != REAL_ERROR_OK )
  {
    char cmt[2+5*5+2], *p = cmt;

    *p++ = '0';
    *p++ = 'x';
    do
      p += qsnprintf(p, 5, "%04X", ((ushort *)m)[uchar(len)]);
    while ( --len >= 0 );
    remember_problem(PR_ATTN, ea);
    append_cmt(ea, cmt, false);
  }
}

//--------------------------------------------------------------------------
void out_java_t::java_data(bool /*analyze_only*/)
{
  char nbuf[MAXSTR];
  qstring name;
  op_t x;
  uint32 off;
  uint32 lvc;
  ea_t ea = insn_ea;

  init_prompted_output();
  char stype = pm().getMySeg(ea)->type; // also set curSeg
  ea_t ip = ea - pm().curSeg.start_ea;
  asize_t sz = get_item_size(ea) - 1;
  switch ( stype )
  {
    case SEG_CODE:
      if ( ip >= pm().curSeg.CodeSize )
        goto STOP_NOW;
      if ( get_name(nullptr, ea) > 0 )
        flush_buf(" ");  // for string delimeter
      if ( sz != 0 )
      {
illcall:
        out_line(COLSTR("!!!_UNSUPPORTED_OUTPUT_MODE_!!!", SCOLOR_ERROR));
      }
      else
      {
        pm().curpos = 2;
        uchar c = get_byte(ea);
        out_printf(COLSTR("%3u %s 0x%02X", SCOLOR_ERROR),
                     c, ash.cmnt, c);
      }
    default:
      break;

    case SEG_BSS:
      if ( is_align(F) )
      {
        clr_gen_label();
        set_gen_cmt(false);
        set_gen_xrefs(false);
        goto STOP_NOW;
      }
      lvc = 0;  // unification
      off = uint32(ea - pm().curSeg.DataBase);
      if ( (uint32)off >= (uint32)pm().curSeg.DataSize )
      {
        off = (uint32)-1;
      }
      else if ( pm().curSeg.varNode
             && (lvc = (uint32)netnode(pm().curSeg.varNode).altval(off)) != 0 )
      {
        if ( (int32)lvc < 0 )
        {
          lvc = -(int32)lvc;
          if ( sz )  // can be byte for 'overloaded' variables :(
          {
            if ( --sz )
              goto BADIDB; // must be word
          }
        }
        if ( (lvc % sizeof(LocVar)) || lvc >= sizeof(nbuf) )
          goto BADIDB;
      }
      if ( jasmin() )
        out_line(ash.cmnt, COLOR_AUTOCMT);
      clr_gen_label();
      if ( off == (uint32)-1 )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      if ( get_visible_name(&name, ea) > 0 )
        out_printf(COLSTR("%s", SCOLOR_AUTOCMT), name.begin());
      if ( lvc == 0 )
        break;
      set_gen_cmt(true);
      set_gen_xrefs(true);
      if ( change_line(true) )
        goto STOP_NOW;
      if ( netnode(pm().curSeg.varNode).supval(off, nbuf, lvc+1) != lvc )
        goto BADIDB;
      lvc /= sizeof(LocVar);
      for ( LocVar *plv = (LocVar*)nbuf; ; plv++ )
      {
        if ( jasmin() )
        {
          pm().curpos = 4;
          OUT_KEYWORD(".var ");
          out_tagon(COLOR_NUMBER);
          size_t inplen = outbuf.length();
          out_printf("%u", off);
          pm().outcnt += outbuf.length() - inplen;
          out_tagoff(COLOR_NUMBER);
          OUT_KEYWORD(" is ");
        }
        else
        {
          if ( plv->utsign && sign_out(plv->utsign, 0) )
            break;
          if ( OutUtf8(plv->var.Dscr, fmt_FieldDescriptor, COLOR_KEYWORD) )
            break;
          if ( chkOutSpace() )
            break;
        }
        if ( OutUtf8(plv->var.Name, QS(fmt_UnqualifiedName), COLOR_DNAME) )
          break;
        if ( chkOutSpace() )
          break;
        if ( jasmin() )
        {
          if ( OutUtf8(plv->var.Dscr, fmt_FieldDescriptor, COLOR_KEYWORD) )
            break;
          if ( plv->utsign && sign_out(plv->utsign, 0) )
            break;
          if ( CHK_OUT_KEYWORD("from ") )
            break;
        }
        else
        {
          out_tagon(COLOR_AUTOCMT);
          if ( !out_commented("Scope: ") )
            break;
        }
        if ( putScope(plv->ScopeBeg, off) )
          break;
        if ( jasmin() )
        {
          if ( CHK_OUT_KEYWORD(" to ") )
            break;
        }
        else
        {
          if ( CHK_OUT_STR(" / ") )
            break;
        }
        if ( putScope(plv->ScopeTop, off) )
          break;
        if ( !jasmin() )
          out_tagoff(COLOR_AUTOCMT);
        if ( change_line(pm().curpos != 0) || !--lvc )
          break;
      }
      goto STOP_NOW;

    case SEG_XTRN:
      if ( ip > (uint32)pm().curClass.xtrnCnt )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      if ( !ip )
      {
        gen_printf(0, COLSTR("%s Importing prototypes", SCOLOR_AUTOCMT),
                    jasmin() ? ash.cmnt : "");
        break; // equivalence - gen_empty_line(); with comment
      }

      if ( jasmin() )
      {
        out_printf(COLSTR("%s", SCOLOR_AUTOCMT), ash.cmnt);
        pm().outcnt = strlen(ash.cmnt);
      }
      clr_gen_label();
      set_gen_cmt(false);
      set_gen_xrefs(false);
      {
        const_desc_t co;
        {
          uint j = (uint32)pm().XtrnNode.altval(ip);
          if ( j == 0 )
            goto BADIDB;
          if ( !pm().LoadOpis(lm_normal, (ushort)j, 0, &co) )
            goto BADIDB;
        }
        pm().copy_const_to_opnd(x, co); // name / class & dscr / subnam
        x.ref = 0;  // as flag
        x.cp_type = co.type;
        switch ( x.cp_type )
        {
          default:
            goto BADIDB;

          case CONSTANT_Class:
            if ( !jasmin() )
            {
              outbuf.qclear();
              pm().outcnt = 0;
            }
            {
              static const TXS imp = TXS_DECLARE(".import ");
              int of = !jasmin();
              OutKeyword(imp.str+of, imp.size-of);
            }

            if ( !(co.flag & (HAS_TYPEDSCR | HAS_CLSNAME)) )
              goto do_idx_out;
            x.addr_shorts.high = (co.flag & HAS_CLSNAME) != 0
                               ? fmt_fullname
                               : fmt_ClassName;
            goto no_space_check;

          case CONSTANT_Fieldref:
            if ( (co.flag & NORM_FIELD) != NORM_FIELD )
              goto do_idx;
            break;
          case CONSTANT_InterfaceMethodref:
          case CONSTANT_Methodref:
            if ( (co.flag & NORM_METOD) != NORM_METOD )
            {
do_idx:
              ++x.ref;
            }
            break;
        }
      }
      if ( CHK_OUT_STR("  ") )
        goto STOP_NOW;
      if ( x.ref )
      {
do_idx_out:
        x.n = 2;
        if ( !putVal(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16, 1) )
          goto STOP_NOW;
      }
      else
      {
no_space_check:
        if ( !OutConstant(x, /*include_descriptor=*/ true) )
          goto STOP_NOW;
      }
//      if ( x.cp_type == CONSTANT_Class && !jasmin() )
//        out_line(".*", COLOR_SYMBOL);
      break;

    case SEG_IMP:
      if ( ip > (uint32)pm().curClass.FieldCnt )
        goto STOP_NOW;
      if ( sz )
        goto illcall;
      clr_gen_label();
      set_gen_cmt(false);
      set_gen_xrefs(false);
      if ( !ip )
      {
        if ( pm().curClass.annNodes[0] | pm().curClass.annNodes[1] )
        {
          if ( annotation_loop(pm().curClass.annNodes, qnumber(pm().curClass.annNodes)) )
            goto STOP_NOW;
        }
        if ( !jasmin() )
          block_begin(0);
        else
          gen_empty_line();

        if ( pm().curClass.innerNode )
        {
          netnode inode(pm().curClass.innerNode);
          uint j = (uint32)inode.altval(0);
          if ( j == 0 )
            goto BADIDB;
          color_t ci = jasmin() ? COLOR_IMPNAME : COLOR_NONE;
          uint i = 0;
          do
          {
            InnerClass ic;
            if ( inode.supval(++i, &ic, sizeof(ic)) != sizeof(ic) )
              goto BADIDB;
            pm().curpos = 2;
            if ( !jasmin() )
              out_tagon(COLOR_AUTOCMT);
            if ( OutModes((((uint32)ic.access) << 16) | OA_NEST) )
              break;
            if ( ic.name )
            {
              if ( OutUtf8(ic.name, fmt_UnqualifiedName, ci) )
                break;
            }
            else if ( !jasmin() && CHK_OUT_STR("{anonymous}") )
            {
              break;
            }
            if ( ic.inner )
            {
              if ( jasmin() )
              {
                if ( CHK_OUT_KEYWORD(" inner ") )
                  break;
              }
              else if ( CHK_OUT_STR(" {is}: ") )
              {
                break;
              }
              if ( OutUtf8(ic.inner, fmt_fullname, ci) )
                break;
            }
            if ( ic.outer )
            {
              if ( jasmin() )
              {
                if ( CHK_OUT_KEYWORD(" outer ") )
                  break;
              }
              else if ( CHK_OUT_STR(" {from}: ") )
              {
                break;
              }
              color_t co = ci;
              if ( co != COLOR_NONE && ic.outer == pm().curClass.This.Name )
                co = COLOR_DNAME;
              if ( OutUtf8(ic.outer, fmt_fullname, co) )
                break;
            }
            if ( !jasmin() )
              out_tagoff(COLOR_AUTOCMT);
            if ( change_line() )
              break;
          }
          while ( i < j );
          if ( pm().curClass.FieldCnt )
            gen_empty_line();
        }
        goto STOP_NOW;
      } // first entry (zero offset)

      if ( pm().ClassNode.supval(ip, &pm().curField, sizeof(pm().curField)) != sizeof(pm().curField) )
        goto BADIDB;
      pm().curpos = 2;
      if ( !jasmin() && pm().curField.id.utsign )
      {
        if ( sign_out(pm().curField.id.utsign, 0) )
          goto STOP_NOW;
        pm().curpos = 2;
      }
      if ( OutModes(OA_FIELD) )
        goto STOP_NOW;
      if ( !jasmin() && out_field_type() )
        goto STOP_NOW;
      if ( out_index(pm().curField.id.name, QS(fmt_UnqualifiedName), COLOR_DNAME, pm().curField.id.extflg & EFL_NAME) )
        goto STOP_NOW;
      if ( chkOutSpace() )
        goto STOP_NOW;
      if ( jasmin() && out_field_type() )
        goto STOP_NOW;

      if ( pm().curField.valNode )
      {
        netnode vnode(pm().curField.valNode);

        uint valcnt = (uint32)vnode.altval(0);
        if ( valcnt == 0 )
          goto BADIDB;
        x.n = 0;
        x.flags = OF_SHOW;
        x.type = o_imm;

        if ( chkOutSymSpace('=') )
          goto STOP_NOW;
        for ( uint i = 1; ; i++ )
        {
          uchar flen;

          const_desc_t co;
          if ( vnode.supval(i, &co, sizeof(co)) != sizeof(co) )
          {
            ip = netnode(pm().curField.valNode).altval(i);
            if ( ushort(ip) != 0xFFFF )
              goto BADIDB;
            if ( putShort(ushort(ip >> 16)) )
              goto STOP_NOW;
          }
          else
          {
            switch ( co.type )
            {
              case CONSTANT_Long:
                x.dtype = dt_qword;
                pm().copy_const_to_opnd(x, co);
                flen = 3;
                goto chk_flt;
              case CONSTANT_Double:
                x.dtype = dt_double;
                check_float_const(ea, &co.value, 3);
                pm().copy_const_to_opnd(x, co);
                goto one_w;
              case CONSTANT_Float:
                x.dtype = dt_float;
                x.value = co.value;
                flen = 1;
chk_flt:
                check_float_const(ea, &x.value, flen);
                goto one_w;
              case CONSTANT_Integer:
                x.dtype = dt_dword;
                x.value = co.value;
one_w:
                if ( !putVal(x, OOF_NUMBER | OOF_SIGNED | OOFW_IMM, 0) )
                  goto STOP_NOW;
                break;

              case CONSTANT_String:
                if ( !checkLine(2) )
                  goto STOP_NOW;
                if ( OutUtf8(co._name, fmt_string, COLOR_STRING) )
                  goto STOP_NOW;
                break;

              default:
                UNCOMPAT("out::data");
            }
          }

          if ( i >= valcnt )
            break;
          if ( chkOutSymSpace(',') )
            goto STOP_NOW;
        } // for(...) (value)
      } // if ( valNode )
      set_gen_cmt(true);
      set_gen_xrefs(true);
      if ( !change_line(pm().curpos != 0) )
      {
        uchar addonce = 0;

        if ( jasmin() )
        {
          if ( pm().curField.id.utsign )
          {
            pm().curpos = 4;
            if ( sign_out(pm().curField.id.utsign, -1) )
              goto STOP_NOW;
            addonce = 1;
          }
          if ( pm().curField.id.extflg & XFL_DEPRECATED )
          {
            if ( out_deprecated(4) )
              goto STOP_NOW;
            addonce = 1;
          }
        }

        if ( pm().curField.genNode | pm().curField.annNodes[0] | pm().curField.annNodes[1] )
        {
          addonce = 1;
          if ( !jasmin() )
            block_begin(2);
        }

        if ( pm().curField.genNode && out_includes(pm().curField.genNode, 4) )
          goto STOP_NOW;

        if ( pm().curField.annNodes[0] | pm().curField.annNodes[1] )
        {
          pm().curpos = 4; // prompted output (prefer to new syntax)
          if ( annotation_loop(pm().curField.annNodes, qnumber(pm().curField.annNodes)) )
            goto STOP_NOW;
        }
        if ( addonce )
          block_close(2, "field");
      }
      goto STOP_NOW;
  }

  set_gen_cmt(true);
  set_gen_xrefs(true);
  change_line(pm().curpos != 0);
STOP_NOW:
  term_prompted_output();
  return;

BADIDB:
  DESTROYED("out::data");
}

//--------------------------------------------------------------------------
void idaapi java_data(outctx_t &ctx, bool analyze_only)
{
  out_java_t *p_ctx = (out_java_t *)&ctx;
  p_ctx->java_data(analyze_only);
}
