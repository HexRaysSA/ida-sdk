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
#include <loader.hpp>
#include <diskio.hpp>
#include <segregs.hpp>
#include "npooluti.hpp"
#include "oututil.hpp"

#define _CUR_IDP_VER IDP_JDK16

static const char constant_pool[] = "$ Constant Pool ~";

//-------------------------------------------------------------------------
nodeidx_t bootstrap_methods_get_node(bool assert, bool can_create)
{
  // if ( curClass.bmNode != 0 )
  //   return curClass.bmNode;
  netnode n("$ BootstrapMethods ~");
  if ( can_create && !netnode_exist(n) )
    n.create("$ BootstrapMethods ~");
  if ( assert )
    QASSERT(10333, netnode_exist(n));
  return n;
}

//-------------------------------------------------------------------------
nodeidx_t bootstrap_methods_get_count()
{
  return netnode(bootstrap_methods_get_node()).altval(0);
}

//-------------------------------------------------------------------------
void bootstrap_methods_set_count(nodeidx_t cnt)
{
  netnode(bootstrap_methods_get_node()).altset(0, cnt);
}

//-------------------------------------------------------------------------
bool bootstrap_methods_get_method(
        bootstrap_method_def_t *out,
        nodeidx_t idx)
{
  netnode n = bootstrap_methods_get_node();
  bytevec_t blob;
  if ( n.getblob(&blob, idx, stag) < 2 )
    return false;
  const uchar *p = blob.begin();
  out->method_ref = *(ushort *) p;
  p += sizeof(ushort);
  const size_t nargs = size_t(blob.end() - p) / sizeof(ushort);
  out->args.resize(nargs);
  if ( nargs > 0 )
    memcpy(out->args.begin(), p, nargs * sizeof(ushort));
  return true;
}

//-------------------------------------------------------------------------
static bool bootstrap_methods_set_method(
        const bootstrap_method_def_t &bmd,
        nodeidx_t idx)
{
  netnode n = bootstrap_methods_get_node();
  bytevec_t blob;
  blob.append(&bmd.method_ref, sizeof(bmd.method_ref));
  if ( !bmd.args.empty() )
    blob.append(bmd.args.begin(), bmd.args.size() * sizeof(ushort));
  return n.setblob(blob.begin(), blob.size(), idx, stag);
}

//-----------------------------------------------------------------------
void java_t::database_loaded(const char *file)
{
  int i, v;
  ssize_t size;

  if ( file == nullptr ) // load old file
  {
    if ( ConstantNode.create(constant_pool) )
      goto BADIDB;

    i = sizeof(curClass);
    v = (int)ConstantNode.altval(CNA_VERSION);
    switch ( v )
    {
      default:
        error("Very old database format. Cannot convert it");

      case IDP_JDK15:
        error("Intermediate (developer) database format. Cannot convert it.");

      case IDP_JDK12:
        i -= sizeof(curClass) - offsetof(ClassInfo, MajVers);
        // no break
      case _CUR_IDP_VER:  // IDP_JDK16
        break;
    }

    if ( i != (int)ConstantNode.supval(CNS_CLASS, nullptr, (size_t)-1) )
      goto BADIDB;
    size = ConstantNode.supval(CNS_CLASS, &curClass, sizeof(curClass));
    if ( size < (int32)offsetof(ClassInfo, MajVers) || !curClass.ClassNode )
      goto BADIDB;
    if ( curClass.xtrnNode )
    {
      if ( !curClass.xtrnCnt )
        goto BADIDB;
      XtrnNode = curClass.xtrnNode;
    }
    else if ( curClass.xtrnCnt )
    {
      goto BADIDB;
    }
    ClassNode = curClass.ClassNode;

    if ( v != IDP_JDK12 ) // current JDK format
    {
      if ( curClass.MajVers < JDK_MIN_MAJOR )
        goto BADIDB;
      if ( curClass.MajVers > JDK_MAX_MAJOR )
        goto BADIDB;
      if ( curClass.MajVers == JDK_MIN_MAJOR ) // JDK1.0/1.1
      {
        if ( curClass.JDKsubver != (curClass.MinVers >= JDK_1_1_MINOR) )
          goto BADIDB;
      }
      else
      {
        if ( curClass.MinVers )
          goto BADIDB;
        if ( curClass.MajVers - (JDK_MIN_MAJOR-1) != curClass.JDKsubver )
          goto BADIDB;
      }
    }

    make_NameChars(/*on_load=*/ false);  // initialize and set enableExr_NameChar for upgrade
    if ( v != _CUR_IDP_VER )
    {
      ResW_init();  // prepare RW-find
      v = upgrade_db_format(v, ConstantNode);
      if ( v == 0 )
      {
BADIDB:
        DESTROYED("database_loaded");
      }
      QASSERT(10134, v == _CUR_IDP_VER);
      ConstantNode.supset(CNS_CLASS, &curClass, sizeof(curClass));
      ConstantNode.altset(CNA_VERSION, _CUR_IDP_VER);
    }
    else
    {
      v = curClass.maxStrSz;
      if ( v != 0 )
        tsPtr = (ushort*)myAlloc(sizeof(ushort)*(v+1));
      v = curClass.maxSMsize;
      if ( v != 0 )
        smBuf = (uchar*)myAlloc(v+1);
      v = curClass.maxAnnSz;
      if ( v != 0 )
        annBuf = (uchar*)myAlloc(v+1);
      idpflags = (ushort)ConstantNode.altval(CNA_IDPFLAGS);
      user_limiter = (uchar)ConstantNode.altval(CNA_LIMITER);

      if ( !ResW_oldbase() )
        goto BADIDB;
    }
    // disableExt_NameChar();  // set standart extension
    if ( curClass.extflg & XFL_C_DONE )
      sm_node = smn_ok;
    if ( curClass.MajVers >= JDK_SMF_MAJOR_MIN )
      SMF_mode = 1;
  }
  else
  {  // new base
    if ( !ConstantNode )
      INTERNAL("ConstantNode");

    char str[MAXSPECSIZE];
    char *ps = str;
    i = qstrlen((char *) file);
    if ( i >= sizeof(str) )
    {
      ps = (char *) file + i - (sizeof(str) - 3);
      for ( i = sizeof(str) - 1 - 3; i; i-- )
        if ( *--ps == '/' )
          break;
      if ( i == 0 )
        error("notify: illegal file name parameter");
      file = ps;
      memcpy(str, "...", 3);
      ps = &str[3];
    }
    memcpy(ps, file, i);
    if ( ps != str )
      i += 3;
    ConstantNode.supset(CNS_SOURCE, str, i);
    user_limiter = inf_get_limiter();
    ConstantNode.altset(CNA_LIMITER, user_limiter);
  }
  inf_set_limiter(0);
}


//-------------------------------------------------------------------------
void java_t::dump_floating_constants(
        const char *problem,
        const char *what,
        const intvec_t &ks)
{
  const size_t kss = ks.size();
  if ( kss > 0 )
  {
    static const char *const emc = "Number of %s CONSTANT_%s: %" FMT_Z "\n";
    load_msg(emc, problem, what, kss);
    for ( size_t i = 0; i < kss; ++i )
    {
      qstrvec_t lines;

      const_desc_t cd;
      ushort cid = ks[i];
      if ( ConstantNode.supval(cid, &cd, sizeof(cd)) == sizeof(cd) )
      {
        print_constant(&lines, cd, cid);
        if ( lines.empty() )
          lines.push_back("<failed printing constant>");
      }
      else
      {
        cd.type = 0;
        lines.push_back("<failed retrieving constant>");
      }
      for ( size_t lidx = 0, lcnt = lines.size(); lidx < lcnt; ++lidx )
      {
        char sfxbuf[MAXSTR];
        if ( lcnt > 1 )
          qsnprintf(sfxbuf, sizeof(sfxbuf), ".%" FMT_Z, lidx);
        else
          sfxbuf[0] = '\0';
        load_msg("  #%" FMT_Z "%s, index=%d, type=%s: %s",
                 i, sfxbuf, cid, constant_type_to_str(cd.type),
                 lines[lidx].c_str());
      }
    }
  }
}

//-----------------------------------------------------------------------
bool java_t::LoadOpis(load_mode_t load_mode, ushort index, uchar _op, const_desc_t *p)
{
  const uchar op = _op;
#define LoadAnyString(lmod, index)  LoadOpis(lmod, index, CONSTANT_Utf8, nullptr)
  const_desc_t tmp;
  if ( p == nullptr )
    p = &tmp;

  if ( !index
    || index > curClass.maxCPindex
    || ConstantNode.supval(index, p, sizeof(*p)) != sizeof(*p) )
  {
    return false;
  }

  if ( load_mode == lm_lenient || load_mode == lm_no_set_ref )
    return true;

  if ( !p->is_referenced() )
  {
    p->mark_referenced();
    StoreOpis(index, *p);
  }
  CASSERT(MAX_CONSTANT_TYPE < 0x20);
  if ( op < 0x20 )
    return op == 0 || op == p->type;

#define LoadNamedClass(lmod, index, p) LoadOpis(lmod, index, uchar(-1), p)
  if ( op == uchar(-1) )
    return p->type == CONSTANT_Class && (p->flag & HAS_CLSNAME);

  if ( p->type != CONSTANT_Utf8 )
    return false;

#define OP_TYPE_MASK 0x1F
#define OP_CHECK_SHIFT 5

  const uchar _type = op & OP_TYPE_MASK;
  const uchar _check = op >> OP_CHECK_SHIFT;
  switch ( _type )
  {
    default:
      INTERNAL("LoadOpis");
    case 0:
    case CONSTANT_Utf8:
      break;
  }
  {
    static const uchar chk[8] =
    {
      0x00,    // align

#define CheckAnyDscr(lmod, index, p)    LoadOpis(lmod, index, (1 << OP_CHECK_SHIFT), p)
      (HAS_TYPEDSCR | HAS_CALLDSCR),

#define CheckFieldDscr(lmod, index, p)  LoadOpis(lmod, index, (2 << OP_CHECK_SHIFT), p)
#define LoadFieldDscr(lmod, index, p)   LoadOpis(lmod, index, (2 << OP_CHECK_SHIFT) | CONSTANT_Utf8, p)
      HAS_TYPEDSCR,

#define CheckFieldName(lmod, index, p)  LoadOpis(lmod, index, (3 << OP_CHECK_SHIFT), p)
#define LoadFieldName(lmod, index)      LoadOpis(lmod, index, (3 << OP_CHECK_SHIFT) | CONSTANT_Utf8, nullptr)
      HAS_FLDNAME,

//#define Check...(lmod, index, p)      LoadOpis(lmod, index, (4 << OP_CHECK_SHIFT), p)
      0x00,

#define CheckClass(lmod, index, p)      LoadOpis(lmod, index, (5 << OP_CHECK_SHIFT), p)
      (HAS_TYPEDSCR | HAS_CLSNAME),

#define CheckCallDscr(lmod, index, p)   LoadOpis(lmod, index, (6 << OP_CHECK_SHIFT), p)
#define LoadCallDscr(lmod, index)       LoadOpis(lmod, index, (6 << OP_CHECK_SHIFT) | CONSTANT_Utf8, nullptr)
      HAS_CALLDSCR,

#define CheckClassName(lmod, index, p)  LoadOpis(lmod, index, (7 << OP_CHECK_SHIFT), p)
      HAS_CLSNAME
    };

    if ( p->flag & chk[_check] )
      return true;
  }

  if ( _type != 0 )
    return false;

  if ( load_mode == lm_need_cr )
    msg("\n");
  load_msg("Illegal reference type to Utf8#%u\n", index);
  return lm_need_cr >= 2;  // true when load_constants_pool, false after
}

//-----------------------------------------------------------------------
// for annotation
bool java_t::isSingleClass(ushort val)
{
  const_desc_t co;

  return LoadFieldDscr(lm_normal, val, &co)
      && (co._Sflags & (_OP_VALPOS | _OP_ONECLS)) == _OP_ONECLS;
}

//-----------------------------------------------------------------------
uchar java_t::attribute_type_from_str(ushort index, attr_parent_kind_t apk, char str[MAX_ATTR_NMSZ])
{
  static const char *const name[] =
  {
#define attr_LineNumberTable                       0 // 0x000001: code
        "LineNumberTable",
#define attr_LocalVariableTable                    1 // 0x000002: code
        "LocalVariableTable",
#define attr_LocalVariableTypeTable                2 // 0x000004: code
        "LocalVariableTypeTable",
#define attr_StackMap                              3 // 0x000008: code (J2ME CLDC)
        "StackMap",
#define attr_StackMapTable                         4 // 0x000010: code (>=JDK1.6)
        "StackMapTable",
#define attr_CODE_TOP  5

#define attr_ConstantValue                         5 // 0x000020: fld
        "ConstantValue",
#define attr_FLD_TOP   6

#define attr_Code                                  6 // 0x000040: met
        "Code",
#define attr_Exceptions                            7 // 0x000080: met
        "Exceptions",
#define attr_RuntimeVisibleParameterAnnotations    8 // 0x000100: met
        "RuntimeVisibleParameterAnnotations",
#define attr_RuntimeInvisibleParameterAnnotations  9 // 0x000200: met
        "RuntimeInvisibleParameterAnnotations",
#define attr_AnnotationDefault                    10 // 0x000400: met
        "AnnotationDefault",
#define attr_MET_TOP   11

#define attr_SourceFile                           11 // 0x000800: file
        "SourceFile",
#define attr_InnerClasses                         12 // 0x001000: file
        "InnerClasses",
#define attr_EnclosingMethod                      13 // 0x002000: file
        "EnclosingMethod",
#define attr_SourceDebugExtension                 14 // 0x004000: file
        "SourceDebugExtension",
#define attr_BootstrapMethods                     15 // 0x008000: file
        "BootstrapMethods",
#define attr_FILE_TOP  16

#define attr_Signature                            16 // 0x010000: all !code
        "Signature",
#define attr_Synthetic                            17 // 0x020000: all !code
        "Synthetic",
#define attr_Deprecated                           18 // 0x040000: all !code
        "Deprecated",
#define attr_RuntimeVisibleAnnotations            19 // 0x080000: all !code
        "RuntimeVisibleAnnotations",
#define attr_RuntimeInvisibleAnnotations          20 // 0x100000: all !code
        "RuntimeInvisibleAnnotations",
// next field for check pool ONLY (must be in last position)
#define attr_LocalVariables                       21 // 0x200000: obsolete
        "LocalVariables"
#define attr_CHECK_MASK   0x3FFFFF
      };
#define attr_UNKNOWN     32
#define attr_TRUNCATED   33
#define attr_NONAME      34
//#if sizeof("RuntimeInvisibleParameterAnnotations") > MAX_ATTR_NMSZ
//#error
//#endif

  str[0] = '\0';
  if ( !LoadFieldName(lm_normal, index) )
    return attr_NONAME;
  if ( !fmtName(index, str, MAX_ATTR_NMSZ, fmt_UnqualifiedName) )
    return attr_TRUNCATED;

  uchar i = 0, top = (uchar)(qnumber(name) - 1);
  switch ( apk )
  {
    case attr_parent_kind_code:
      top = attr_CODE_TOP;
      break;
    case attr_parent_kind_field:
      i   = attr_CODE_TOP;
      top = attr_FLD_TOP;
      break;
    case attr_parent_kind_method:
      i   = attr_FLD_TOP;
      top = attr_MET_TOP;
      break;
    case attr_parent_kind_class_file:
      i   = attr_MET_TOP;
      top = attr_FILE_TOP;
      break;
    default:
//    case ARQ_CHECK:
      ++top;
      break;
  }

repeat:
  do
  {
    if ( !strcmp(name[i], str) )
      return i;
  } while ( ++i < top );
  if ( apk != attr_parent_kind_code && i < (uchar)(qnumber(name)-1) )
  {
    i = attr_FILE_TOP;
    top = (uchar)(qnumber(name) - 1);
    goto repeat;
  }
  return attr_UNKNOWN;
}

//-------------------------------------------------------------------------
static NORETURN void badref_loader_failure(ushort i, ushort k)
{
  loader_failure("Bad reference (from %u to %u) in constant pool", i, k);
}

//-----------------------------------------------------------------------
uint java_t::load_constants_pool(void)
{
  ushort k;
  uint ui = 0;
  const_desc_t cd;

  // prepare jasmin reserved word checking
  ResW_init();

  msg("\nLoading constant pool...");
  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    memset(&cd, 0, sizeof(cd));
    cd.type = read1();
    switch ( cd.type )
    {
      case CONSTANT_Long:
      case CONSTANT_Double:
        cd.value2 = read4();
        // fallthrough
      case CONSTANT_Integer:
      case CONSTANT_Float:
        cd.value = read4();
        break;

      case CONSTANT_NameAndType:
      case CONSTANT_Fieldref:
      case CONSTANT_Methodref:
      case CONSTANT_InterfaceMethodref:
        k = read2();
        if ( k == 0 || k > curClass.maxCPindex )
        {
badindex:
          loader_failure("Bad record in constant pool.\n"
                         "Record %u have reference to %u\n"
                         "(maxnum %u, file offset after the read is 0x%" FMT_64 "X)",
                         i, k, curClass.maxCPindex, qftell(myFile));
        }
        cd._class = k;     // _subnam for name & type
        // fallthrough. Yes, we will let 'name_and_type_index' be read by the CONSTANT_String block below...
      case CONSTANT_Class:
        cd.ref_ip = 0;
        // fallthrough
      case CONSTANT_String:
        k = read2();
        if ( k == 0 || k > curClass.maxCPindex )
          goto badindex;
        cd._name = k;      // _dscr for name & type
        break;

      case CONSTANT_Unicode:
        loader_failure("File contains CONSTANT_Unicode, which was removed from "
                       "the standard in 1996, and is not supported by IDA");

      case CONSTANT_Utf8:
        cd._name = (ushort)i;  // for xtrnRef_dscr
        if ( LoadUtf8((ushort)i, &cd) )
          parse_const_desc((ushort)i, &cd);
        break;

      case CONSTANT_MethodHandle:
        cd._mhr_kind = read1();
        cd._mhr_index = read2();
        break;

      case CONSTANT_MethodType:
        k = read2(); // descriptor_index
        if ( k == 0 || k > curClass.maxCPindex )
          goto badindex;
        cd._mtd_index = k;
        break;

      case CONSTANT_InvokeDynamic:
        {
          cd._bmidx = read2(); // bootstrap_method_attr_index
          k = read2(); // name_and_type_index
          if ( k == 0 || k > curClass.maxCPindex )
            goto badindex;
          cd._name = k;
        }
        break;

      default:
        loader_failure("Bad constant type 0x%x (%u)", cd.type, i);
    }  // end switch
    StoreOpis(i, cd);
    if ( cd.type == CONSTANT_Long || cd.type == CONSTANT_Double )
    {
      if ( curClass.maxCPindex == (ushort)i )
        loader_failure("Premature end of constant pool");
      ++i;
    }
  } // end for
  ResW_free();  // free mem - this set not needed later

  msg("checking...");
  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    const_desc_t cr;
    ConstantNode.supval(i, &cd, sizeof(cd));
    switch ( cd.type )
    {
      case CONSTANT_String:
        if ( !LoadAnyString(lm_need_cr, cd._name) )
          badref_loader_failure(i, cd._name);
        continue;

      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;

      case CONSTANT_NameAndType:
        if ( !CheckFieldName(lm_need_cr, cd._class, &cr) )
          badref_loader_failure(i, cd._class);
        cd.flag |= ((cr.flag & HAS_FLDNAME) << SUB_SHIFT);
        if ( !CheckAnyDscr(lm_need_cr, cd._name, &cr) )
          badref_loader_failure(i, cd._name);
        cd.flag |= ((cr.flag<<SUB_SHIFT) & (SUB_TYPEDSCR | SUB_CALLDSCR));
        break;

      case CONSTANT_Class:
        if ( !CheckClass(lm_need_cr, cd._name, &cr) )
          badref_loader_failure(i, cd._name);
        cd.flag |= (cr.flag & (HAS_FLDNAME | HAS_TYPEDSCR | HAS_CLSNAME));
        cd._dscr = cd._subnam = 0;
        break;
    } // end switch
    StoreOpis(i, cd);
    if ( (loadMode & MLD_EXTREF)
      && cd.type == CONSTANT_Class
      && (cd.flag & HAS_CLSNAME) )
    {
      ushort j;

      for ( j = 1; j <= curClass.xtrnCnt; j++ )
      {
        uint32 rfc = (uint32)XtrnNode.altval(j);
        if ( !CmpString(cd._name, (ushort)rfc) )
        {
          cd._subnam = (ushort)(rfc >> 16);
          goto found;
        }
      }
      XtrnNode.altset(j, (i << 16) | cd._name);
      ++curClass.xtrnCnt;
      cd._subnam = (ushort)i;
found:
      StoreOpis(i, cd);
    }
  }  // end for
  if ( loadMode & MLD_EXTREF )
    XtrnNode.altdel();  // delete all

  msg("referencing...");
  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    const_desc_t cr;
    uint32 sav;

    ConstantNode.supval(i, &cd, sizeof(cd));
    switch ( cd.type )
    {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;

      case CONSTANT_Class:
        continue;

      case CONSTANT_InterfaceMethodref:
      case CONSTANT_Fieldref:
      case CONSTANT_Methodref:
        if ( !LoadOpis(lm_need_cr, cd._class, CONSTANT_Class, &cr) )
          badref_loader_failure(i, cd._class);
//\\VALID nullptr ??? go twos if any... (reorder cur ind to null)
        cd.flag |= (cr.flag & HAS_CLSNAME);
        k = cd._name;
        sav = errload;
        cd.ref_ip = cr._subnam;
        CheckClassName(lm_need_cr, cd._name = cr._name, nullptr); //lint !e530 likely using an uninitialized value
        if ( !LoadOpis(lm_need_cr, k, CONSTANT_NameAndType, &cr) )
        {
          badref_loader_failure(i, k);
        }
        cd._dscr   = cr._name;
        cd._subnam = cr._class;
        cd.flag |=(cr.flag & (SUB_FLDNAME | SUB_TYPEDSCR | SUB_CALLDSCR));
        if ( cd.type != CONSTANT_Fieldref )
          CheckCallDscr(lm_need_cr, cd._dscr, nullptr);
        else
          CheckFieldDscr(lm_need_cr, cd._dscr, nullptr);
        if ( !LoadFieldName(lm_need_cr, cd._subnam) )
          --sav;
        if ( (loadMode & MLD_EXTREF) && errload == sav )
        {
          XtrnNode.altset(++ui, i, '0');
          ++curClass.xtrnCnt;
        }
        else
        {
          cd.ref_ip = 0;
        }
        break;

      case CONSTANT_MethodHandle:
        if ( !LoadOpis(lm_need_cr, cd._mhr_index, 0, &cr) )
          badref_loader_failure(i, cd._mhr_index);
        break;

      case CONSTANT_MethodType:
        if ( !LoadOpis(lm_need_cr, cd._mtd_index, CONSTANT_Utf8, &cr) )
          badref_loader_failure(i, cd._mtd_index);
        break;

      case CONSTANT_InvokeDynamic:
        // We can resolve the name_and_type_index, right away but the
        // bootstrap_method_attr_index, will have to wait after the
        // BootstrapMethods array has been loaded (in load_attributes())
        if ( !LoadOpis(lm_need_cr, cd._name, CONSTANT_NameAndType, &cr) )
          badref_loader_failure(i, cd._mtd_index);
        break;
    } // end switch
    StoreOpis(i, cd);
  }  // end for

  msg("complete\n");

  // { // debug
  //   intvec_t tmp;
  //   FOR_EACH_CONSTANT_POOL_INDEX(i)
  //     tmp.push_back(i);
  //   dump_floating_constants(
  //           "NO PROBLEM",
  //           "NOTHING",
  //           tmp);
  // }

  return ui;
}

//-----------------------------------------------------------------------
void java_t::setPoolReference(void)
{
  char str[MAXNAMELEN];
  const_desc_t co;
  uint ic, ii, ui = 0;

  msg("Sorting external references...");
  for ( uint i = 1; (ushort)i <= curClass.xtrnCnt; i++ )
  {
    uint j = (uint)XtrnNode.altval(i, '0');
    if ( j == 0 )
      continue;
    show_addr(curClass.xtrnCnt - (ushort)i);
    ConstantNode.supval(j, &co, sizeof(co));
    if ( co._class == curClass.This.Dscr )
    {
      co.ref_ip = 0;
      StoreOpis(j, co);
      continue;
    }
    const_desc_t cr;
    ConstantNode.supval(ic = co.ref_ip, &cr, sizeof(cr));
    xtrnSet(ic, &cr, ++ui, str, sizeof(str), true);
    xtrnSet(j, &co, ++ui, str, sizeof(str), false);
    deltry(ii = i + 1, ic, ui, co);
    for ( ; (ushort)ii <= curClass.xtrnCnt; ii++ )
    {
      j = (uint)XtrnNode.altval(ii, '0');
      if ( j == 0 )
        continue;
      ConstantNode.supval(j, &cr, sizeof(cr));
      if ( cr.ref_ip != (ushort)ic )
        continue;
      xtrnSet(j, &cr, ++ui, str, sizeof(str), false);
      XtrnNode.altdel(ii, '0');
      deltry(ii + 1, ic, ui, co);
    }
  }
  XtrnNode.altdel_all('0');

  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    ConstantNode.supval(i, &co, sizeof(co));
    switch ( co.type )
    {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        break;
      case CONSTANT_Class:
        if ( co._subnam == (ushort)i
          && (ushort)i != curClass.This.Dscr
          && !co.ref_ip )
        {
          xtrnSet(i, &co, ++ui, str, sizeof(str), true);
        }
        break;
    }
  }

  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    ConstantNode.supval(i, &co, sizeof(co));
    switch ( co.type )
    {
      case CONSTANT_Long:
      case CONSTANT_Double:
        ++i;
      default:
        continue;
      case CONSTANT_Class:
        break;
    }
    if ( co._subnam && co._subnam != (ushort)i )
    {
      const_desc_t tmp;
      ConstantNode.supval(co._subnam, &tmp, sizeof(tmp));
      co.ref_ip = tmp.ref_ip;
      StoreOpis(i, co);
    }
  }

  curClass.xtrnCnt = (ushort)ui;
  if ( curClass.xtrnCnt != 0 )
  {
    set_segm_end(curClass.xtrnEA, curClass.xtrnEA + curClass.xtrnCnt + 1, SEGMOD_KILL);
    create_byte(curClass.xtrnEA, 1);
  }
  else
  {
    XtrnNode.kill();
    curClass.xtrnNode = 0;
    del_segm(curClass.xtrnEA, SEGMOD_KILL);
    curClass.xtrnEA = 0;
  }
  msg("OK\n");
}

//-----------------------------------------------------------------------
void java_t::CheckPoolReference(bool insns_created)
{
  char str[MAX_ATTR_NMSZ];
  const_desc_t co;
  intvec_t k1s;
  intvec_t k2s;
  intvec_t k3s;
  uint mask = attr_CHECK_MASK;

  msg("Checking references, %s creating instructions...\n", insns_created ? "after" : "before");
  FOR_EACH_CONSTANT_POOL_INDEX(i)
  {
    ConstantNode.supval(i, &co, sizeof(co));
    if ( co.type == CONSTANT_Long || co.type == CONSTANT_Double )
      ++i;
    if ( co.is_referenced() )
      continue;
    switch ( co.type )
    {
      case CONSTANT_Utf8:
        if ( !insns_created )
        {
          uchar j;

          k2s.push_back(i);
          CASSERT((1 << (attr_LocalVariables+1)) - 1 == attr_CHECK_MASK);
          if ( (co.flag & HAS_FLDNAME)
            && mask
            && (j = attribute_type_from_str((ushort)i, attr_parent_kind_CHECK, str)) <= attr_LocalVariables
            && (mask & (1 << j)) )
          {
            mask ^= (1 << j);
          }
          else if ( co._Ssize )
          {
            k3s.push_back(i); // unnotify empty
          }
        }
        break;

      case CONSTANT_NameAndType:
        if ( !insns_created )
          k1s.push_back(i);
        break;

      case CONSTANT_Class:
        if ( insns_created )
        {
          k2s.push_back(i);
          if ( !(co.flag & HAS_CLSNAME) )
            k3s.push_back(i);
        }
        break;

      default:
        if ( insns_created )
          k1s.push_back(i);
        break;
    } // switch
  } // for

  if ( !k1s.empty() )
  {
    dump_floating_constants(
            "unused",
            insns_created ? "(any except Class/Type/String)" : "NameAndType",
            k1s);
  }
  if ( !k2s.empty() )
  {
    if ( !k3s.empty() )
    {
      dump_floating_constants(
              insns_created ? "unnamed" : "unreferenced",
              insns_created ? "Class" : "Utf8",
              k3s);
      for ( size_t i = 0, n = k3s.size(); i < n; ++i )
        k2s.del(k3s[i]);
    }
    if ( !k2s.empty() )
      dump_floating_constants("unused", insns_created ? "Class" : "Utf8", k2s);
  }
}

//-----------------------------------------------------------------------
void java_t::ValidateStoreLocVar(ushort slot, LocVar & lv)
{
  netnode temp;
  uint32 cnt, id;
  bool dble;
  LocVar vals[(qmin(MAXSTR, MAXSPECSIZE)/sizeof(LocVar))];
  const char *txt = "Invalid declaration";

  lv.ScopeTop = (ushort)(id = (uint32)lv.ScopeBeg + lv.ScopeTop);

  if ( slot >= curSeg.DataSize || id > curSeg.CodeSize )
    goto BADDECL;

  dble = false;
  if ( curSeg.varNode )
  {
    temp = curSeg.varNode;
    cnt = (uint32)temp.altval(slot);
    if ( cnt != 0 )
    {
      if ( (int32)cnt < 0 )
      {
        cnt = -(int32)cnt;
        dble = true;
      }
      if ( (cnt % sizeof(LocVar))
        || cnt >= sizeof(vals)
        || temp.supval(slot, vals, cnt+1) != cnt )
      {
        goto interr;
      }
      cnt /= sizeof(LocVar);
    }
  }
  else
  {
    temp.create();
    curSeg.varNode = temp;
    cnt = 0;
  }

  if ( !lv.utsign ) // base declaration
  {
    const_desc_t opis;

    CASSERT(offsetof(LocVar, utsign)+sizeof(lv.utsign) == sizeof(LocVar));
    //lint -esym(645, vals) Symbol may not have been initialized
    for ( id = 0; id < cnt; id++ ) // skip full duplication
      if ( memcmp(&lv, &vals[id], offsetof(LocVar, utsign)) == 0 )
        return;

    if ( !LoadFieldName(lm_normal, lv.var.Name) )
      goto BADDECL;
    if ( !LoadFieldDscr(lm_normal, lv.var.Dscr, &opis) )
      goto BADDECL;

    CASSERT(offsetof(const_desc_t, _Sflags) - offsetof(const_desc_t, _Ssize) == 2);
    if ( !dble && opis._Sopstr == (1 | (_OP_UTF8_ << 16)) )
    {
      uchar tmp[sizeof(ushort)+1];
      if ( ConstantNode.supval((uint32)lv.var.Dscr << 16, tmp, sizeof(tmp),
                             BLOB_TAG) != sizeof(ushort) )
        goto interr;
      switch ( tmp[0] )
      {
        case j_double:
        case j_long:
          dble = true;
          if ( slot+1 == curSeg.DataSize )
            goto BADDECL;
        default:
          break;
      }
    }

    txt = "Too many variants";
    if ( cnt == qnumber(vals)-1 )
      goto BADDECL;

    if ( !lv.ScopeBeg )
      curSeg.id.extflg |= XFL_M_LABSTART; // special label at entry
    if ( lv.ScopeTop == curSeg.CodeSize )
      curSeg.id.extflg |= XFL_M_LABEND;   // special label at end

    {
      ea_t dea = curSeg.DataBase + slot;
      add_dref(dea, curSeg.start_ea + lv.ScopeBeg, dr_I);
      add_dref(dea, curSeg.start_ea + lv.ScopeTop, dr_I);
    }
    xtrnRef_dscr(curSeg.start_ea + lv.ScopeBeg, &opis);
    if ( !cnt )
      set_lv_name(lv.var.Name, curSeg.DataBase + slot,
                  (loadMode & MLD_LOCVAR) ? 3 : 0);  // if not rename_on_load ONLY mark
    vals[cnt++] = lv;
  }
  else
  {  // signature declaration
    CASSERT(offsetof(LocVar, var.Dscr)+sizeof(lv.var.Dscr)+sizeof(lv.utsign) == sizeof(LocVar));
    for ( id = 0; id < cnt; id++ )
      if ( memcmp(&lv, &vals[id], offsetof(LocVar, var.Dscr)) == 0 )
      {
        if ( !vals[id].utsign )
        {
          if ( !CheckSignature(lv.utsign, attr_parent_kind_code) )
            goto BADDECL;
          vals[id].utsign = lv.utsign;
          goto store;
        }
        if ( vals[id].utsign == lv.utsign )
          return;
        txt = "Different signature";
        goto BADDECL;
      }
    txt = "Signature without type";
    goto BADDECL;
  }
store:
  cnt *= sizeof(LocVar);
  temp.supset(slot, vals, cnt);
  if ( !lv.utsign )
  {
    if ( dble )
      cnt = -(int32)cnt;
    temp.altset(slot, cnt);
  }
  return;

BADDECL:
  load_msg("%s LocVar#%u Method#%u (name#%u dsc#%u sgn#%u scope:%u-%u)\n",
           txt, slot, curSeg.id.Number,
           lv.var.Name, lv.var.Dscr, lv.utsign, lv.ScopeBeg, lv.ScopeTop);
  return;

interr:
  INTERNAL("StoreLocVar");
}

//-----------------------------------------------------------------------
inline void java_t::BadRefFile(const char *to, ushort id)
{
  BadRef(BADADDR, to, id, attr_parent_kind_class_file);
}

//-----------------------------------------------------------------------
uchar *java_t::annotation(uchar *p, uint32 *psize)
{
  if ( *psize < 2 )
  {
bad:
    return nullptr;
  }
  *psize -= 2;
  uint pairs= read2();
  *(ushort *)p = (ushort)pairs;
  p += sizeof(ushort);
  if ( pairs )
  {
    do
    {
      if ( *psize < 2 )
        goto bad;
      *psize -= 2;
      ushort id = read2();
      if ( !LoadFieldName(lm_normal, id) )
        goto bad;
      *(ushort *)p = id;
      p = annot_elm(p+sizeof(ushort), psize);
      if ( p == nullptr )
        goto bad;
    }
    while ( --pairs );
  }
  return p;
}

//---------------------------------------------------------------------------
uchar *java_t::annot_elm(uchar *ptr, uint32 *psize, uchar is_array)
{
  if ( *psize < 1+2 )
  {
bad:
    return nullptr;
  }
  *psize -= 1+2;
  union
  {
    uchar *p1;
    ushort *p2;
  };
  p1 = ptr;
  uchar tag  = read1();
  ushort val = read2();
  *p1++ = tag;
  *p2++ = val;
  switch ( tag )
  {
    case j_annotation:
      if ( isSingleClass(val)
        && (p1 = annotation(p1, psize)) != nullptr )
      {
        goto done;
      }
    default:
      goto bad;

    case j_array:
      if ( val && !is_array ) // multidimensional array is not valid (javac )
      {
        uchar *ps = p1;
        tag = 0;
        do
        {
          p1 = annot_elm(p1, psize, 1);
          if ( p1 == nullptr )
            goto bad;
          if ( !tag )
          {
            if ( val == 1 )
              break;
            tag = *ps;
            ps = p1;
          }
          else if ( tag != (uchar)-1 )
          {
            if ( tag != *ps )
              goto bad;
            tag = (uchar)-1;
          }
        }
        while ( --val );
        goto done;
      }
      goto bad;

    case j_enumconst:
      if ( LoadFieldDscr(lm_normal, val, nullptr) )
      {
        if ( *psize < 2 )
          goto bad;
        *psize -= 2;
        *p2++ = val = read2();
        if ( LoadFieldName(lm_normal, val) )
          goto done;
      }
      goto bad;

    case j_class_ret:
      if ( isSingleClass(val) )
        goto done;
      goto bad; //### in 'classfile.pdf' j_void_ret also remebemered?

    case j_string:
      tag = CONSTANT_Utf8;
      break;
    case j_float:
      tag = CONSTANT_Float;
      break;
    case j_long:
      tag = CONSTANT_Long;
      break;
    case j_double:
      tag = CONSTANT_Double;
      break;
    case j_int:
    case j_byte:
    case j_char:
    case j_short:
    case j_bool:
      tag = CONSTANT_Integer;
      break;
  }
  if ( !LoadOpis(lm_normal, val, tag, nullptr) )
    goto bad;
done:
  return p1;
}

//-----------------------------------------------------------------------
bool java_t::sm_chkargs(uchar **pptr, uint32 *pDopSize, ushort cnt)
{
  union
  {
    uchar   *p1;
    ushort  *p2;
  };
  p1 = *pptr;
  uint32 dopsize = *pDopSize;
  bool result = false;

  do
  {
    if ( !dopsize )
      goto declerr_w;
    --dopsize;
    uchar tag = read1();
    if ( tag > ITEM_Uninitialized )
      goto declerr_w;
    *p1++ = tag;
    CASSERT(ITEM_Object+1 == ITEM_Uninitialized);
    if ( tag >= ITEM_Object )
    {
      if ( dopsize < 2 )
        goto declerr_w;
      dopsize -= 2;
      ushort var = read2();
      if ( tag == ITEM_Object )
      {
        const_desc_t opis;
        if ( var == curClass.This.Dscr )
        {
          var = curClass.This.Name;
          p1[-1] = ITEM_CURCLASS;
        }
        else if ( LoadNamedClass(lm_normal, var, &opis) )
        {
          var = opis._name;
        }
        else
        {
          p1[-1] = ITEM_BADOBJECT;
        }
      }
      else
      { // Uninitialized (offset to new instruction)
        if ( !var )
          curSeg.id.extflg |= XFL_M_LABSTART; // PARANOYA
        else if ( var >= curSeg.CodeSize )
          goto declerr_w;
      }
      *p2++ = var;
    }
  }
  while ( --cnt );
  result = true;
  *pptr = p1;
declerr_w:
  *pDopSize = dopsize;
  return result;
}

//-----------------------------------------------------------------------
int java_t::sm_load(ushort declcnt, uint32 *pDopSize)
{
  union
  {
    uchar  *p1;
    ushort *p2;
  };
  sm_info_t smr;
  uint32 dopsize = *pDopSize;
  netnode temp(curSeg.smNode);
  int result = 0;
  uint prevoff = (uint)-1;

  p1 = sm_realloc(dopsize);
  dopsize -= 2;     // skip READED counter
  *p2++ = declcnt;  // counter
  smr.noff = (uint32)(p1 - smBuf);
  smr.fcnt = 0;
  do
  {
    ea_t refea;
    uint nxcnt;
    uchar rectype = SMT_FULL_FRAME;
    if ( SMF_mode )  // >=JDK6
    {
      if ( !dopsize )
        goto declerr_w;
      --dopsize;
      rectype = read1();
      *p1++ = rectype;
    }
    {
      uint off;
      if ( rectype < SMT_SAME_FRM_S1 )
      {
        if ( rectype > SMT_SAME_FRM_S1_max )
          goto declerr_w; // reserved
        off = rectype;
        if ( rectype >= SMT_SAME_FRM_S1_min )
          off -= SMT_SAME_FRM_S1_min;
      }
      else
      {
        if ( dopsize < 2 )
          goto declerr_w;
        dopsize -= 2;
        off = read2();
        *p2++ = (ushort)off;
      }
      if ( SMF_mode )
        off += (prevoff + 1);  // >=JDK6
      if ( (uint32)off >= curSeg.CodeSize )
        goto declerr_w;
      prevoff = off;
      refea = curSeg.start_ea + off;
    }
    if ( temp.supval(refea, nullptr, 0) != -1 ) // for CLDC only
    {
      --result;
      goto declerr_w;
    }
    nxcnt = smr.fcnt;
    if ( rectype == SMT_FULL_FRAME )
    {
      for ( int pass = 0; pass < 2; pass++ )
      {
        ushort cnt;

        if ( dopsize < 2 )
          goto declerr_w;
        dopsize -= 2;
        *p2++ = cnt = read2(); // number of locals / number of stacks
        if ( !pass )
          nxcnt = cnt;
        if ( cnt && !sm_chkargs(&p1, &dopsize, cnt) )
          goto declerr_w;
      }
    }
    else if ( rectype > SMT_SAME_FRM_S0 )
    {
      rectype -= SMT_SAME_FRM_S0;
      if ( !sm_chkargs(&p1, &dopsize, rectype) )
        goto declerr_w;
      nxcnt += rectype;
    }
    else if ( rectype >= SMT_SAME_FRM_S1 )
    {
      rectype = (uchar)SMT_SAME_FRM_S0 - rectype;
      nxcnt -= rectype;
      if ( int(nxcnt) < 0 )
        goto declerr_w;
      if ( rectype == 4 /*i.e., was: SMT_SAME_FRM_S1 */ )
      {
        // same_locals_1_stack_item_frame_extended
        // http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.7.4
        if ( !sm_chkargs(&p1, &dopsize, 1) )
          goto declerr_w;
      }
    }
    else if ( rectype >= SMT_SAME_FRM_S1_min )
    {
      if ( !sm_chkargs(&p1, &dopsize, 1) )
        goto declerr_w;
    }
    smr.eoff = (uint32)(p1 - smBuf);
    temp.supset(refea, &smr, sizeof(smr));
    smr.noff = smr.eoff;
    smr.fcnt = nxcnt;
  }
  while ( --declcnt );
//
  temp.altset(-1, smr.noff);
  temp.setblob(smBuf, smr.noff, 0, BLOB_TAG);
  ++result;
declerr_w:
  *pDopSize = dopsize;
  return result;
}

//-------------------------------------------------------------------------
NORETURN void java_t::loader_failure_bad_attr_decl_size(attr_parent_kind_t apk) const
{
  char diastr[128];
  loader_failure("Illegal declaration size%s", mk_diag(apk, diastr));
}

//-----------------------------------------------------------------------
void java_t::load_attributes(attr_parent_kind_t apk)
{
  char atrs[MAX_ATTR_NMSZ+2], diastr[128];
  // ushort k;
  uint i, j, r;
  netnode temp;
  uval_t *pann;
  uchar eflg, lvtb = 0, lntb = 0, fatal = (loadMode & MLD_FORCE) == 0;
  const_desc_t opis;
  opis._name = 0;  // for vc

  j = read2();
  for ( i = 0; i < j; i++ )
  {
    if ( savesize >= 0 && (savesize -= 6) < 0 )
      loader_failure_bad_attr_decl_size(apk);
    const ushort attribute_name_index = read2();
    uint attribute_length = read4();
    if ( savesize >= 0 )
    {
      if ( (uint)savesize < attribute_length )
        loader_failure_bad_attr_decl_size(apk);
      savesize -= attribute_length;
    }
    eflg = 0;  // flag(additional attributes/locvars/annotation/stackmap)
    atrs[0] = ' ';  // for additinal attibutes (mark SourceDebugExtension)
    switch ( attribute_type_from_str(attribute_name_index, apk, &atrs[1]) )
    {
      case attr_SourceDebugExtension:
        if ( sde )
          goto duplerr_w;
        ++sde;
        if ( attribute_length < 0x10000 )
        {
          if ( attribute_length == 0 )
          {
            deb(IDA_DEBUG_LDR,
                "Ignore zero length SourceDebugExtension attribute\n");
            break;
          }
          qoff64_t pos = qftell(myFile), ssz = FileSize;
          if ( LoadUtf8((ushort)-1, (const_desc_t*)(size_t)attribute_length) )
          {
            curClass.extflg |= XFL_C_DEBEXT;
            break;
          }
          qfseek(myFile, pos, SEEK_SET);
          FileSize = ssz;
        }
        if ( ask_yn(ASKBTN_YES,
                    "HIDECANCEL\n"
                    "SourceDebugExtension attribute have a non standard encoding\n"
                    "or large size and cannot be represented in assembler.\n\n"
                    "\3Do you want to store it in external file?") > ASKBTN_NO )
          goto attr2file;
        goto skipAttr;

      case attr_BootstrapMethods:
        {
          if ( bootstrap_methods_get_node(/*assert=*/ false) != BADNODE )
            loader_failure("Duplicate 'BootstrapMethods' attribute definition");
          bootstrap_methods_get_node(/*assert=*/ true, /*can_create=*/ true);
          if ( attribute_length < 2 )
            goto declerr_w;
          const ushort num_bootstrap_methods = read2();
          bootstrap_methods_set_count(num_bootstrap_methods);
          attribute_length -= 2;
          const qoff64_t end = qftell(myFile) + attribute_length;
          for ( ushort bmidx = 0; bmidx < num_bootstrap_methods; ++bmidx )
          {
            if ( qftell(myFile) >= end )
              goto declerr_w;
            const ushort bootstrap_method_ref = read2();

            if ( qftell(myFile) >= end )
              goto declerr_w;
            const ushort num_bootstrap_arguments = read2();

            bootstrap_method_def_t mdef;
            mdef.method_ref = bootstrap_method_ref;
            for ( ushort baidx = 0; baidx < num_bootstrap_arguments; ++baidx )
            {
              if ( qftell(myFile) >= end )
                goto declerr_w;
              const ushort bootstrap_argument = read2();
              mdef.args.push_back(bootstrap_argument);
            }

            bootstrap_methods_set_method(mdef, bmidx);
          }

          // Now that all bootstrap methods are loaded, try and resolve
          // the constant pool's references to it
          FOR_EACH_CONSTANT_POOL_INDEX(cpidx)
          {
            const_desc_t cd;
            cd.type = 0;
            ConstantNode.supval(cpidx, &cd, sizeof(cd));
            if ( cd.type == CONSTANT_InvokeDynamic )
            {
              bootstrap_method_def_t mdef;
              if ( bootstrap_methods_get_method(&mdef, cd._bmidx) )
                LoadOpis(lm_normal, mdef.method_ref, CONSTANT_MethodHandle, nullptr);
            }
          }
        }
        break;

      case attr_UNKNOWN:
        atrs[0] = uchar(apk);
        if ( loadMode & MLD_EXTATR )
        {
attr2file:
          const char *p = CopyAttrToFile(atrs, attribute_length, attribute_name_index);
          if ( p == nullptr )
            break;
          loader_failure("%s %sattribute '%s'%s",
                         p,
                         atrs[0] == ' ' ? "" : "additional ",
                         &atrs[1],
                         mk_diag(apk, diastr));
        }
        if ( idpflags & IDM_REQUNK )
        {
          idpflags &= ~IDM_REQUNK;
          if ( ask_yn(ASKBTN_YES,
                      "HIDECANCEL\n"
                      "File contains unknown attribute(s).\n"
                      "Do you want store it in external files?\n\n") > ASKBTN_NO )
          {
            loadMode |= MLD_EXTATR;
            goto attr2file;
          }
        }
        eflg = 1;
        goto unkAttr;
      case attr_NONAME:
        qsnprintf(atrs, sizeof(atrs), "(with index %u)", attribute_name_index);
        goto notify;
      case attr_TRUNCATED:
        qstrncat(atrs, "...", sizeof(atrs));
unkAttr:
        atrs[0] = '"';
        qstrncat(atrs, "\"", sizeof(atrs));
notify:
MSC_DIAG_OFF(4191)
        if ( eflg && !(idpflags & IDM_WARNUNK) )
          msg(
            "Ignore%s %s attribute (size %u)%s\n",
            (uchar)atrs[0] == ' ' ? "" : " unknown",
            atrs, attribute_length, mk_diag(apk, diastr));
        else
          load_msg(
            "Ignore%s %s attribute (size %u)%s\n",
            (uchar)atrs[0] == ' ' ? "" : " unknown",
            atrs, attribute_length, mk_diag(apk, diastr));
MSC_DIAG_ON(4191)
skipAttr:
        if ( attribute_length )
        {
real_skipAttr:
          skipData(attribute_length);
        }
        break;

      case attr_ConstantValue:
        {
          ushort constantvalue_index;
          if ( attribute_length != 2 || !LoadOpis(lm_normal, constantvalue_index = read2(), 0, &opis) )
          {
          declerr:
            ++fatal;
          declerr_w:
            load_msg("Illegal declaration of %s%s\n",
                     &atrs[1], mk_diag(apk, diastr));
            goto skipAttr;
          }

          temp = curField.valNode;
          if ( !temp )
          {
            temp.create();
            curField.valNode = temp;
            r = 0;
          }
          else
          {
            r = (uint)temp.altval(0);
          }
          switch ( opis.type )
          {
            case CONSTANT_Integer:
            case CONSTANT_Long:
            case CONSTANT_Float:
            case CONSTANT_Double:
            case CONSTANT_String:
              temp.supset(++r, &opis, sizeof(opis));
              break;
            default:
              BadRef(curClass.start_ea + curField.id.Number, "value", constantvalue_index, apk);
              temp.altset(++r, (((uint32) constantvalue_index) << 16) | 0xFFFF);
              break;
          }
          temp.altset(0, r);
        }
        break;

      case attr_Code:
        if ( curSeg.CodeSize )
        {
// duplerr:
          ++fatal;
duplerr_w:
          if ( fatal )
            loader_failure("Duplicate %s attribute declaration%s", &atrs[1], mk_diag(apk, diastr));
          else
            load_msg("Duplicate %s attribute declaration%s", &atrs[1], mk_diag(apk, diastr));
          goto skipAttr;
        }
        r = curClass.JDKsubver ? 12 : 8;
        if ( attribute_length < r )
          goto declerr;
        attribute_length -= r;
        r -= 8;
        curSeg.stacks = r ? read2() : read1();
        curSeg.DataSize = r ? read2() : read1();     // max_locals
        curSeg.CodeSize = r ? read4() : read2();
        if ( curSeg.CodeSize != 0 )
        {
          if ( attribute_length < curSeg.CodeSize )
            goto declerr;
          attribute_length -= curSeg.CodeSize;
          if ( FileSize < curSeg.CodeSize )
            errtrunc();
          FileSize -= curSeg.CodeSize;
          {
            segment_t *S = _add_seg(-1);  // expand size
            if ( curSeg.DataSize )
              set_default_sreg_value(S, rVds, _add_seg(2)->sel); // create data segment
          }
        }

        {
          const ushort exception_table_length = read2();
          if ( exception_table_length != 0 ) // except. table
          {
            if ( !curSeg.CodeSize )
              goto declerr;

            r = ((uint32) exception_table_length) * (2*4);
            if ( attribute_length < r )
              goto declerr;
            attribute_length -= r;
            temp.create();
            curSeg.excNode = temp;
            temp.altset(0, exception_table_length);
            ea_t ea = curSeg.start_ea + curSeg.CodeSize;
            r = 1;
            uchar err = 0;
            do
            {
              Exception exc;

              exc.start_pc    = read2();
              exc.end_pc      = read2();
              exc.handler_pc  = read2();

              exc.filter.Ref &= 0;  // for 'finally'
              exc.filter.Dscr = read2();
              if ( exc.filter.Dscr != 0 )
              {
                if ( !LoadNamedClass(lm_normal, exc.filter.Dscr, &opis) )
                {
                  BadRef(ea, ".catch", exc.filter.Dscr, apk);
                }
                else
                {
                  exc.filter.Name = opis._name;
                  xtrnRef(ea, opis);
                }
              }
              temp.supset(r++, &exc, sizeof(exc));
              err |= set_exception_xref(&curSeg, exc, ea); // as procedure for base converter
            }
            while ( (ushort)r <= exception_table_length );
            if ( err )
            {
              remember_problem(PR_ILLADDR, ea);
              load_msg("Invalid address(es) in .catch%s\n",
                       mk_diag(apk, diastr));
            }
          }
        }// exception table

        savesize = attribute_length;
        load_attributes(attr_parent_kind_code);  // Additional attr
        savesize = -1;
        break;

      case attr_Exceptions:
        if ( curSeg.thrNode )
          goto duplerr_w;
        if ( attribute_length < (2+2) || (attribute_length % 2) )
          goto declerr_w;
        attribute_length -= 2;
        if ( (attribute_length / 2) != (uint32)read2() )
          goto declerr_w;
        attribute_length /= 2;
        temp.create();
        curSeg.thrNode = temp;
        r = 0;
        do
        {
          const ushort exception_index = read2();
          if ( exception_index == 0 )
          {
            load_msg("Ignore zero exception index%s\n", mk_diag(apk, diastr));
          }
          else
          {
            uint32 refd = (uint32)exception_index << 16;
            if ( !LoadNamedClass(lm_normal, exception_index, &opis) )
            {
              BadRef(curSeg.start_ea, ".throws", exception_index, apk);
            }
            else
            {
              refd |= opis._name;
              xtrnRef(curSeg.start_ea, opis);
            }
            temp.altset(++r, refd);
          }
        }
        while ( --attribute_length );
        temp.altset(0, r);
        break;

      case attr_LineNumberTable:
        if ( lntb )
          goto duplerr_w;
        ++lntb;
        r = attribute_length - 2;
        if ( attribute_length < 2 || (r % 4) )
          goto declerr_w;
        attribute_length -= 2;
        if ( (r /= 4) != (uint32)read2() )
          goto declerr_w;
        if ( attribute_length == 0 )
        {
// Symantec error (strip) #1
          deb(IDA_DEBUG_LDR,
              "Stripped declaration of LineNumber table%s\n",
              mk_diag(apk, diastr));
        }
        while ( r-- )
        {
          const ushort start_pc = read2();
          const ushort line_number = read2();
          if ( uint32(start_pc) < curSeg.CodeSize )
            set_source_linnum(curSeg.start_ea + start_pc, line_number);
          else
            load_msg("Illegal address (%u) of source line %u%s\n", start_pc,
                     line_number, mk_diag(apk, diastr));
        }
        break;

      case attr_LocalVariableTypeTable:
        if ( !(lvtb & 1) ) // ATT: my be can before LocalVariableTable?
        {
          if ( fatal )
            loader_failure("%s before LocalVariableTable%s", atrs, mk_diag(apk, diastr));
          else
            load_msg("%s before LocalVariableTable%s", atrs, mk_diag(apk, diastr));
          goto skipAttr;
        }
        ++eflg; // 2 <= 1 + 1
        // no break
      case attr_LocalVariableTable:
        ++eflg; // 1
        if ( lvtb & eflg )
          goto duplerr_w;
        lvtb |= eflg;
        --eflg; // unification (0/1)
        r = attribute_length - 2;
        if ( attribute_length < 2 || (r % 10) )
          goto declerr_w;
        attribute_length -= 2;
        if ( (r /= 10) != (uint32)read2() )
          goto declerr_w;
        while ( r-- )
        {
          LocVar lv;

          lv.ScopeBeg = read2();  // start_pc
          lv.ScopeTop = read2();  // length
          lv.var.Name = read2();  // name_index
          CASSERT(offsetof(LocVar,utsign) == offsetof(LocVar,var.Dscr)+sizeof(lv.var.Dscr)
               && sizeof(lv.var.Dscr)*2 == sizeof(uint32));
          *(uint32 *)&lv.var.Dscr &= 0;
          if ( eflg == 0 )  // LocalVariableTable/LocalVariableTypeTable
            lv.var.Dscr = read2(); // descriptor_index
          else
            lv.utsign = read2(); // descriptor_index
          const ushort index = read2();   // index
          if ( !eflg )   // normal table
          {
            if ( index == 0 && !lv.var.Name && !lv.ScopeBeg && lv.ScopeTop <= 1 )
            {
// Symantec error (strip) #2
              deb(IDA_DEBUG_LDR,
                  "Stripped declaration of local variables%s\n",
                  mk_diag(apk, diastr));
              continue;
            }
            if ( (short)lv.ScopeBeg == -1 )
            {
// Microsoft VisualJ++ error (purge?)
              LoadAnyString(lm_normal, lv.var.Name);
              LoadAnyString(lm_normal, lv.var.Dscr);
              deb(IDA_DEBUG_LDR,
                  "Purged declaration of LocVar#%u%s\n", index,
                  mk_diag(apk, diastr));
              continue;
            }
          }
          ValidateStoreLocVar(index, lv);
        } // while
        break;

      case attr_SourceFile:
        {
          if ( attribute_length != 2 )
            goto declerr_w;
          const ushort sourcefile_index = read2();
          if ( LoadAnyString(lm_normal, sourcefile_index) )
            curClass.SourceName = sourcefile_index;
          else
            BadRef(BADADDR, "source file name", sourcefile_index, apk);
        }
        break;

      case attr_InnerClasses:
        r = attribute_length - 2;
        if ( attribute_length < 2 || (r % 8) )
          goto declerr_w;
        attribute_length -= 2;
        if ( (r /= 8) != (uint32)read2() )
          goto declerr_w;
        if ( !r )
        {
          deb(IDA_DEBUG_LDR, "Stripped declaration of InnerClasses\n");
          break;
        }
        attribute_length = r;
        {
          ushort flags = 0;
          while ( attribute_length-- )
          {
            InnerClass ic;

            *(uchar *)&flags = 0;
            ic.inner = read2(); // inner_class_info_index
            if ( ic.inner && !LoadNamedClass(lm_normal, ic.inner, &opis) )
              flags |= 0x101;
            else
              ic.inner = opis._name;
            ic.outer = read2(); // outer_class_info_index
            if ( ic.outer && !LoadNamedClass(lm_normal, ic.outer, &opis) )
              flags |= 0x101;
            else
              ic.outer = opis._name;
            ic.name = read2(); // inner_class_name_index
            if ( ic.name && !LoadFieldName(lm_normal, ic.name) )
              flags |= 0x101;
            ic.access = read2(); // inner_class_access_flags
            r = ic.access & ACC_ACCESS_MASK;
            if ( !is_pow2(r) )
              flags |= 0x101;
            if ( uchar(flags) == 0 )
            {
              temp = curClass.innerNode;
              if ( !temp )
              {
                temp.create();
                curClass.innerNode = temp;
                r = 0;
              }
              else
              {
                r = (uint)temp.altval(0);
              }
              temp.supset(++r, &ic, sizeof(ic));
              temp.altset(0, r);
            }
          }
          if ( flags != 0 )
            load_msg("Error declaration(s) in Inner Classes\n");
        }
        break;

      case attr_EnclosingMethod:
        if ( curClass.encClass )
          goto duplerr_w;
        if ( attribute_length != 4 )
          goto declerr_w;
        curClass.encClass = LoadNamedClass(lm_normal, read2(), &opis)
                          ? opis._name
                          : 0xFFFF;
        {
          const ushort method_index = read2();
          if ( curClass.encClass == 0xFFFF )
          {
bad_encl:
            msg("Invalid EnclosingMethod description\n");
          }
          else if ( method_index != 0 )
          {
            if ( !LoadOpis(lm_normal, method_index, CONSTANT_NameAndType, &opis)
              || !(opis.flag & SUB_FLDNAME)
              || !LoadCallDscr(lm_normal, opis._name) )
            {
              goto bad_encl;
            }
            curClass.encMethod = method_index;
          }
        }
        break;

      case attr_Synthetic:
        if ( attribute_length != 0 )
          goto declerr_w;
        switch ( apk )
        {
          default:  // attr_parent_kind_code
            goto declerr_w; // paranoya
          case attr_parent_kind_field:
            curField.id.access |= ACC_SYNTHETIC;
            break;
          case attr_parent_kind_method:
            curSeg.id.access |= ACC_SYNTHETIC;
            break;
          case attr_parent_kind_class_file:
            curClass.AccessFlag |= ACC_SYNTHETIC;
            break;
        }
        break;

      case attr_Deprecated:
        if ( attribute_length != 0 )
          goto declerr_w;
        switch ( apk )
        {
          default:  // attr_parent_kind_code
            goto declerr_w; // paranoya
          case attr_parent_kind_field:
            curField.id.extflg |= XFL_DEPRECATED;
            break;
          case attr_parent_kind_method:
            curSeg.id.extflg |= XFL_DEPRECATED;
            break;
          case attr_parent_kind_class_file:
            curClass.extflg |= XFL_DEPRECATED;
            break;
        }
        break;

      case attr_Signature:
        if ( attribute_length != 2 || apk == attr_parent_kind_code )
          goto declerr_w;
        {
          const ushort signature_index = read2();
          if ( CheckSignature(signature_index, apk) )
          {
            switch ( apk )
            {
              case attr_parent_kind_field:
                curField.id.utsign = signature_index;
                break;
              case attr_parent_kind_method:
                curSeg.id.utsign = signature_index;
                break;
              case attr_parent_kind_class_file:
                curClass.utsign = signature_index;
                break;
              default: break;
            }
          }
        }
        break;

      case attr_StackMapTable:
        ++eflg;
        // fallthrough
      case attr_StackMap:
        if ( !eflg != (curClass.JDKsubver < 6) )
        {
          if ( fatal )
            loader_failure("JDK1.%u incompatible with attribute%s%s", curClass.JDKsubver, atrs, mk_diag(apk, diastr));
          else
            load_msg("JDK1.%u incompatible with attribute%s%s", curClass.JDKsubver, atrs, mk_diag(apk, diastr));
          goto skipAttr;
        }
        if ( curSeg.smNode )
          goto duplerr_w;
        if ( attribute_length < 2 )
          goto declerr_w;
        {
          const ushort number_of_entries = read2();
          if ( number_of_entries == 0 )
          {
            attribute_length -= 2;
            curSeg.smNode = BADNODE;
            deb(IDA_DEBUG_LDR,
                "Empty%s attribute%s\n", atrs, mk_diag(apk, diastr));
            curSeg.id.extflg |= XFL_M_EMPTYSM;
          }
          else
          {
            temp.create();
            curSeg.smNode = temp;
            r = sm_load(number_of_entries, &attribute_length);
            if ( int(r) <= 0 )
            {
              temp.kill();
              curSeg.smNode = BADNODE;
              if ( !r )
                goto declerr_w;
              if ( fatal )
                loader_failure("Inconsistent declaration of %s%s", &atrs[1], mk_diag(apk, diastr));
              else
                load_msg("Inconsistent declaration of %s%s", &atrs[1], mk_diag(apk, diastr));
              goto skipAttr;    //-V779 Unreachable code detected
            }
          }
        }
skip_excess:
        if ( attribute_length )
        {
          deb(IDA_DEBUG_LDR,
              "Excess %u bytes in%s attribute%s\n", attribute_length, atrs,
              mk_diag(apk, diastr));
          goto real_skipAttr;
        }
        break;

      case attr_AnnotationDefault:
        pann = &curSeg.annNodes[2];
        eflg = 4; // as flag
        goto do_annot1;
      case attr_RuntimeInvisibleParameterAnnotations:
        ++eflg;
        // no break
      case attr_RuntimeVisibleParameterAnnotations:
        pann = &curSeg.annNodes[3];
        eflg |= 2;  // flag of secondary loop
do_annot1:
        if ( apk != attr_parent_kind_method )
          goto declerr_w;  // paranoya
        goto do_annot;
      case attr_RuntimeInvisibleAnnotations:
        ++eflg;
        // no break
      case attr_RuntimeVisibleAnnotations:
        switch ( apk )
        {
          default:  // attr_parent_kind_code
            goto declerr_w; // paranoya
          case attr_parent_kind_class_file:
            pann = curClass.annNodes;
            break;
          case attr_parent_kind_field:
            pann = curField.annNodes;
            break;
          case attr_parent_kind_method:
            pann = curSeg.annNodes;
            break;
        }
do_annot:
        if ( eflg & 1 )
          ++pann;  // invisible
        if ( *pann )
          goto duplerr_w;
        temp.create();
        *pann = temp;
        if ( attribute_length == 0 )
          goto declerr_w;
        {
          uchar *p = annotation_realloc(attribute_length);
          r = 1;  // no paramsloop
          if ( eflg & 2 ) // Parameters
          {
            r = read1();
            *p++ = (uchar)r;
            --attribute_length;
            if ( !r )
              goto annot_err;
          }
          if ( eflg & 4 ) // defalut
          {
            p = annot_elm(p, &attribute_length);
            if ( p != nullptr )
              goto annot_done;
annot_err:
            temp.kill();
            *pann = (uval_t)-1; // as flag for duplicates
            goto declerr_w;
          }
          do // loop for Parameters
          {
            if ( attribute_length < 2 )
              goto annot_err;
            uint cnt = read2();
            attribute_length -= 2;
            *(ushort *)p = (ushort)cnt;
            p += sizeof(ushort);
            if ( !cnt )
            {
              if ( !(eflg & 2) )
                goto annot_err; // no parameters
              continue;
            }
            eflg |= 8;  // flag for parameters
            do
            {
              if ( attribute_length < 2 )
                goto annot_err;
              attribute_length -= 2;
              ushort id = read2();
              if ( !isSingleClass(id) )
                goto annot_err;
              *(ushort*)p = id;
              p = annotation(p + sizeof(ushort), &attribute_length);
              if ( p == nullptr )
                goto annot_err;
            }
            while ( --cnt );
          }
          while ( --r );  // parameters loop
          if ( eflg == 2 )
            goto annot_err; // empty Parameters annotation
annot_done:
          r = (uint)(p - annBuf);
        } // local variable block
        temp.setblob(annBuf, r, 0, BLOB_TAG);
        temp.altset(0, r);
        goto skip_excess;

      default:
        INTERNAL("load_attributes");
    }  // switch
  }  // for
}

//-----------------------------------------------------------------------
uchar java_t::CheckSignature(ushort index, attr_parent_kind_t apk)
{
  char diastr[128];
  const_desc_t opis;

  if ( !LoadOpis(lm_normal, index, CONSTANT_Utf8, &opis) )
  {
bad:
    if ( apk != attr_parent_kind_code ) // not debug variable
      load_msg("Invalid signature (#%u)%s\n", index, mk_diag(apk, diastr));
    return 0;
  }

  CASSERT(HAS_TYPEDSCR < 0x100 && HAS_CALLDSCR < 0x100);    //-V590 expression is excessive
  if ( !((uchar)opis.flag & ((apk == attr_parent_kind_method ) ? HAS_CALLDSCR : HAS_TYPEDSCR)) )
  {
    if ( !opis._Ssize )
      goto bad; // PARANOYA
    if ( opis._Sflags & (_OP_EXTSYM_ | _OP_NOSIGN) )
      goto bad;
    opis._Sflags &= (_OP_VALPOS | _OP_METSIGN | _OP_CLSSIGN);
    switch ( apk )
    {
      case attr_parent_kind_method:
        if ( (opis._Sflags &= ~_OP_METSIGN) != _OP_VALPOS )
          goto bad;
        break;
      case attr_parent_kind_class_file:
        opis._Sflags &= ~_OP_CLSSIGN;
        // no break
      default:  // FIELD & .var
        if ( opis._Sflags )
          goto bad;
        break;
    }
  }
  return 1;
}

//-----------------------------------------------------------------------
//
// This function should read the input file (it is opened in binary mode)
// analyze it and:
//      - loading segment and offset are in inf.BaseAddr &
//      - load it into the database using file2base(),mem2base()
//        or allocate addresses by enable_flags() and fill them
//        with values using putByte(), putWord(), putLong()
//      - (if createsegs) create segments using
//          add_segm(segment_t *,const char *name,const char *sclass,int flags)
//        or
//          add_segm(uint short,ea_t,ea_t,char *,char *)
//        see segment.hpp for explanations
//      - set up inf_get_start_ip(),startCS to the starting address
//      - set up inf_get_min_ea(),inf_get_max_ea()
//
//
void java_t::loader(FILE *fp, bool manual)
{
  ushort j;
  const_desc_t opis;

  memset(&curClass, 0, sizeof(curClass));
  qfseek(fp, 0, SEEK_SET);   // rewind
  FileSize = qfsize(fp);
  myFile = fp;
  enableExt_NameChar();

  if ( read4() != MAGICNUMBER )
    error("Illegal magic number");

  curClass.MinVers = read2();
  curClass.MajVers = read2();

  if ( curClass.MajVers <= JDK_MIN_MAJOR )
  {
    if ( curClass.MajVers < JDK_MIN_MAJOR )
      goto BAD_VERSION;
    curClass.JDKsubver = (uchar)(curClass.MinVers >= JDK_1_1_MINOR);
  }
  else if ( curClass.MajVers > JDK_MAX_MAJOR || curClass.MinVers )
  {
BAD_VERSION:
    loader_failure("Unsupported file format (version %u.%u)",
                   curClass.MajVers, curClass.MinVers);
  }
  else
  {
    curClass.JDKsubver = (uchar)(curClass.MajVers - (JDK_MIN_MAJOR-1));
  }

  if ( curClass.MajVers >= JDK_SMF_MAJOR_MIN )
  {
    SMF_mode = 1;
  }
  else if ( curClass.JDKsubver <= 1 )
  {
    switch ( curClass.MinVers )
    {
      default:
        ask_for_feedback(
           "Class file with version %u.%u (JDK1.%u?) is not tested!",
           curClass.MajVers, curClass.MinVers, curClass.JDKsubver);
        // no break
      case JDK_1_02_MINOR:
      case JDK_1_1_MINOR:
        break;
    }
  }
//--
  curClass.maxCPindex = read2();
  if ( curClass.maxCPindex <= 2 )
    loader_failure("Empty constant pool");
  loadMode = loadDialog(manual);
  ConstantNode.create(constant_pool);
  --curClass.maxCPindex;  // last valid number
  XtrnNode.create();
  make_NameChars(/*on_load=*/ true);  // initialize and set 'load extension'
  const uint nconstants = load_constants_pool();
  if ( !_add_seg(0) )
  {
    XtrnNode.kill();
  }
  else
  {
    curClass.xtrnCnt  = ushort(nconstants);
    curClass.xtrnNode = XtrnNode;
  }
//--
  curClass.AccessFlag = read2();
  if ( curClass.AccessFlag & ~ACC_THIS_MASK )
    load_msg("Illegal class access bits (0x%X)\n", curClass.AccessFlag);
  curClass.This.Dscr = read2();
  if ( LoadNamedClass(lm_normal, curClass.This.Dscr, &opis) )
  {
    curClass.This.Name = opis._name;
  }
  else
  {
    BadRefFile("'this' class", curClass.This.Dscr);
    CASSERT(offsetof(ClassInfo, This.Ref)+2 == offsetof(ClassInfo, This.Dscr)
         && offsetof(ClassInfo, This.Ref)   == offsetof(ClassInfo, This.Name));
    curClass.This.Ref >>= 16;
//    curClass.This.Name = curClass.This.Dscr;
//    curClass.This.Dscr = 0;
  }
//--
  if ( curClass.xtrnNode )
    setPoolReference();
  curClass.super.Dscr = read2();
  uint i = read2();                    // interface counter
  i *= 2;
  if ( FileSize < i )
    errtrunc();
  qfseek(fp, i, SEEK_CUR);
  curClass.FieldCnt = read2();
  qfseek(fp, -2 - qoff64_t(i), SEEK_CUR);
  _add_seg(3);          // class segment
  enableExt_NameChar();
  if ( curClass.This.Dscr )
  {
    curSeg.id.Number = 0;
    SetName(curClass.This.Name, curClass.start_ea, curClass.AccessFlag, 0);
    hide_name(curClass.start_ea);
  }

  if ( curClass.super.Ref )
  {
    if ( !LoadNamedClass(lm_normal, curClass.super.Dscr, &opis) )
    {
      BadRefFile("parent class", curClass.super.Dscr);
    }
    else
    {
      curClass.super.Name = opis._name;
      xtrnRef(curClass.start_ea, opis);
    }
  }
//--
  if ( (i /= 2) != 0 ) // InterfaceCount
  {
    netnode temp;
    uint r = 0;

    do
    {
      j = read2();
      if ( j == 0 )
      {
        load_msg("Ignore zero interface index\n");
        continue;
      }
      if ( !r )
        temp.create();

      uint32 refd = (uint32)j << 16;
      if ( !LoadNamedClass(lm_normal, j, &opis) )
      {
        BadRefFile("interface", j);
      }
      else
      {
        xtrnRef(curClass.start_ea, opis);
        refd |= opis._name;
      }
      temp.altset(++r, refd);
    }
    while ( --i );
    if ( r )
    {
      temp.altset(0, r);
      curClass.impNode = temp;
    }
  }
//---
  ClassNode.create();
  curClass.ClassNode = ClassNode;
  qfseek(fp, 2, SEEK_CUR);
  if ( errload )
  {
    int f = (curClass.AccessFlag & ~ACC_THIS_MASK) ? curClass.AccessFlag : 0;
    mark_access(curClass.start_ea, f);
  }
//---
  for ( i = 1; (ushort)i <= curClass.FieldCnt; i++ )
  {
    memset(&curField, 0, sizeof(curField));
    curField.id.Number = (ushort)i;
    curField.id.access = read2();
    j = curField.id.access & ACC_ACCESS_MASK;
    if ( (curField.id.access & ~ACC_FIELD_MASK) || !is_pow2(j) )
    {
      load_msg("Illegal Field#%u Attribute 0x%04x\n", i, curField.id.access);
//      curField.id.extflg |= EFL_ACCESS;
      mark_access(curClass.start_ea + i, curField.id.access);
    }

    curField.id.name = read2();
    if ( !CheckFieldName(lm_normal, curField.id.name, nullptr) )
      curField.id.extflg |= EFL_NAME;

    curField.id.dscr = read2();
    if ( !CheckFieldDscr(lm_normal, curField.id.dscr, &opis) )
      curField.id.extflg |= EFL_TYPE;
    else
      xtrnRef_dscr(curClass.start_ea + curField.id.Number, &opis);
    if ( curField.id.extflg & EFL_NAMETYPE )
      load_msg("Illegal NameAndType of field %u\n", i);
    load_attributes(attr_parent_kind_field);
    for ( int n = 0; n < qnumber(curField.annNodes); n++ )
      if ( curField.annNodes[n] == (uval_t)-1 )
        ++curField.annNodes[n];
    ClassNode.supset(i, &curField, sizeof(curField));
    if ( !(curField.id.extflg & EFL_NAME) )
      SetName(curField.id.name, curClass.start_ea + i, curField.id.access, i);
  }
//--
  curClass.MethodCnt = read2();
  for ( i = 1; i <= curClass.MethodCnt; i++ )
  {
    memset(&curSeg, 0, sizeof(curSeg));
    curSeg.id.Number = (ushort)i;
    curSeg.id.access = read2();
    j = curSeg.id.access & ACC_ACCESS_MASK;
    if ( !(j & ~ACC_METHOD_MASK) && is_pow2(j) )
      j = 0;
    else
      load_msg("Illegal Method#%u Attribute 0x%04x\n", i, curSeg.id.access);
//      curSeg.id.extflg |= EFL_ACCESS;

    _add_seg(1);  // create code segment // this for strnRef_dscr
    curSeg.id.name = read2();
    if ( !CheckFieldName(lm_normal, curSeg.id.name, nullptr) )
      curSeg.id.extflg |= EFL_NAME;

    curSeg.id.dscr = read2();
    if ( !CheckCallDscr(lm_normal, curSeg.id.dscr, &opis) )
      curSeg.id.extflg |= EFL_TYPE;
    else
      xtrnRef_dscr(curSeg.start_ea, &opis, 1);
    if ( curSeg.id.extflg & EFL_NAMETYPE )
      load_msg("Illegal NameAndType of method %u\n", i);
//    if ( curSeg.id.extflg & EFL_ACCESS )
    if ( j )
      mark_access(curSeg.start_ea, curSeg.id.access);
    load_attributes(attr_parent_kind_method);
    if ( curSeg.smNode == BADNODE )
      curSeg.smNode = 0; // remove 'flagged' value
    for ( int n = 0; n < qnumber(curSeg.annNodes); n++ )
      if ( curSeg.annNodes[n] == (uval_t)-1 )
        ++curSeg.annNodes[n];
    if ( curSeg.varNode )
      resizeLocVars();
    if ( curSeg.thrNode )
    {
      netnode tnode(curSeg.thrNode);
      if ( !tnode.altval(0) )
      {
        tnode.kill();
        curSeg.thrNode = 0;
      }
    }
    ClassNode.supset(-(int)i, &curSeg, sizeof(curSeg));
  }
//--
  load_attributes(attr_parent_kind_class_file); // Source File
  for ( int n = 0; n < qnumber(curClass.annNodes); n++ )
    if ( curClass.annNodes[n] == (uval_t)-1 )
      ++curClass.annNodes[n];
  myFile = nullptr;
  if ( curClass.encClass == 0xFFFF )
    ++curClass.encClass;  // unification in out
  if ( FileSize )
    warning("This file has extra information (pos=0x%" FMT_64 "x)", qftell(fp));
//---
  CheckPoolReference(0);
  endLoad_NameChar(); // set 'standart extension'
  if ( !set_parent_object() && (curClass.AccessFlag & ACC_INTERFACE) )
  {
    load_msg("This is interface, but superclass is not java.lang.Object!\n");
    mark_and_comment(curClass.start_ea, "Interface have nonstandart parent");
  }
  if ( curClass.impNode && !curClass.super.Ref )
  {
    load_msg("This have implements without superclass!\n");
    mark_and_comment(curClass.start_ea, "Empty supperclass not for Object");
  }
  if ( errload )
    curClass.extflg |= XFL_C_ERRLOAD;
  ConstantNode.supset(CNS_CLASS, &curClass, sizeof(curClass));   // load end!
//--
  debugmode = 1; // full pass...
  for ( i = 1; i <= curClass.MethodCnt; i++ )
  {
    msg("Analysing method %u...\n", i);
    ClassNode.supval(-(int)i, &curSeg, sizeof(curSeg));
    ea_t ea = curSeg.start_ea;
    show_addr(ea);
    ea_t end = ea + curSeg.CodeSize;
    segment_t *s = getseg(ea);
    if ( s == nullptr || end < ea || end > s->end_ea )
      loader_failure("Bad method %u code size 0x%X", i, curSeg.CodeSize);
    if ( !curSeg.CodeSize )
    {
      create_byte(ea, 0x10);
    }
    else
    {
      do
      {
        int sz = create_insn(ea);
        if ( sz == 0 )
          ++sz;
        ea += sz;
      }
      while ( ea < end );
    }
    if ( (curSeg.id.extflg & EFL_NAME) == 0 )
      SetName(curSeg.id.name, curSeg.start_ea, curSeg.id.access,
                                              curClass.FieldCnt + i);
    add_func(curSeg.start_ea, end + 1);
  }
  debugmode = 0;  // all references setting...
  CheckPoolReference(1);
  ConstantNode.altset(CNA_VERSION, _CUR_IDP_VER);
  ResW_newbase();
  create_filename_cmt();
}
