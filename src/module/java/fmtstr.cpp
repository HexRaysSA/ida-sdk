
#include <pro.h>

#include "java.hpp"
#include "oututil.hpp"
#include "upgrade.hpp"

#ifdef TEST_FMTSTR
//-------------------------------------------------------------------------
AS_PRINTF(2, 0) void out_java_t::out_vprintf(
        const char *format,
        va_list va)
{
  outbuf.cat_vsprnt(format, va);
}

//-------------------------------------------------------------------------
void out_java_t::out_char(char c)
{
  outbuf.append(c);
}

//-------------------------------------------------------------------------
void out_java_t::out_line(const char *str)
{
  outbuf.append(str);
}
#endif

//-------------------------------------------------------------------------
//
//-----------------------------------------------------------------------
inline bool is_class_or_typeref(wchar32_t cp)
{
  return cp == j_class || cp == j_typeref;
}

//-------------------------------------------------------------------------
const TXS tp_decl[] =
{
  TXS_DECLARE("void"), // ATTENTION: only for fmtStr
  TXS_DECLARE("byte"),
  TXS_DECLARE("char"),
  TXS_DECLARE("double"),
  TXS_DECLARE("float"),
  TXS_DECLARE("int"),
  TXS_DECLARE("long"),
  TXS_DECLARE("short"),
  TXS_DECLARE("boolean")
};

//-----------------------------------------------------------------------
// BaseType:
// B
// C
// D
// F
// I
// J
// S
// Z
// ...to which we'll add the support for V=void
const TXS *get_base_typename(uchar tag, bool or_void)
{
  switch ( tag )
  {
    case j_void_ret: return or_void ? &tp_decl[0] : nullptr;

    case j_byte: return &tp_decl[1];
    case j_char: return &tp_decl[2];
    case j_double: return &tp_decl[3];
    case j_float: return &tp_decl[4];
    case j_int: return &tp_decl[5];
    case j_long: return &tp_decl[6];
    case j_short: return &tp_decl[7];
    case j_bool: return &tp_decl[8];
    default: return nullptr;
  }
}

//-----------------------------------------------------------------------
#ifndef TEST_FMTSTR
// #define DUMP_FORMATTED 1
#ifdef DUMP_FORMATTED
static const char *const _fmt_strings[] =
{
  "debug",
  "string",
  "quoted",
  "dscr",
  "prefsgn",
  "retdscr",
  "paramstr",
  "throws",
  "clssign",
  "signature",
  "cast",
  "classname",
  "fullname",
  "name",
};
static const char *fmt_to_string(fmt_t mode)
{
  mode = fmt_t(int(mode) & ~FMT_ENC_RESERVED);
  if ( mode > fmt_UnqualifiedName )
    return "<UNKNOWN>";
  return _fmt_strings[mode];
}
#endif
#endif // TEST_FMTSTR


//-------------------------------------------------------------------------
struct format_helper_t
{
  java_t &pm;
  const ushort *tp;
  uint32 nutf16;
  int strcnt;
  ssize_t size;
  const uint32 off_ReturnType;
  const uint32 off_ThrowsSignature_and_TypeSignature;
  out_java_t *oj;
  _PRMPT_ *putproc;
  fmt_t mode;
#ifdef DUMP_FORMATTED
  qstring header;
  qwstring input;
  qstring utf8_input;
  qstring collected;
#endif

  format_helper_t(
          java_t &_pm,
          const ushort *_tp,
          uint32 _nutf16,
          uint32 _off_ReturnType,
          uint32 _off_ThrowsSignature_and_TypeSignature,
          ssize_t _size,
          fmt_t _mode,
          out_java_t *_oj,
          _PRMPT_ _putproc);

  int format();

private:
  bool parse_ClassSignature();
  bool parse_FormalTypeParameters();
  bool parse_FormalTypeParameter();
  bool parse_SuperclassSignature();
  bool parse_SuperinterfaceSignature();
  bool parse_Identifier();
  bool parse_ClassBound();
  bool parse_InterfaceBound();
  bool parse_FieldTypeSignature();
  bool parse_ClassTypeSignature();
  bool parse_ArrayTypeSignature();
  bool parse_TypeVariableSignature();
  bool parse_SimpleClassTypeSignature();
  bool parse_ClassTypeSignatureSuffix();
  bool parse_TypeSignature();
  bool parse_TypeArgument();
  bool parse_TypeArguments();
  bool parse_TypeArguments_opt();
  bool parse_BaseType();
  bool parse_ReturnType();
  bool parse_ThrowsSignature();
  bool parse_MethodParams();
  bool parse_FieldType();
  bool parse_ArrayType();
  bool parse_ObjectType();
  bool parse_UnqualifiedName();
  bool parse_FieldDescriptor();
  bool parse_MethodDescriptor();
  bool parse_ReturnDescriptor();
  bool parse_ParameterDescriptor();

  bool is_BaseType(wchar16_t v) const;
#define PCD_TYPE_ARGUMENTS_ALLOWED      0x1 // '<' and '>' are allowed
#define PCD_EXPECT_SIGNATURE_BOUNDARIES 0x2 // expects 'L' and ';'
  bool parse_class_desc(uint32 flags);

  bool ensure_remaining(ssize_t needed);
  wchar16_t lookahead_utf16() const;
  bool discard_utf16_expect(wchar16_t expected);
  bool consume_utf16_expect(wchar16_t expected);
  bool next_cp(wchar32_t *out);
  void maybe_report(bool failure=false) const;
  bool out_cp(wchar32_t cp);
  bool out_param_sep() { return out_line(", ", 2); }
  bool out_array_dim() { return out_line("[]", 2); }
  bool out_line(const char *s, size_t len);
  bool out_escaped_char(uchar cs);
  bool out_utf16_escaped_halfword(wchar16_t hw);
  bool out_unicode_escaped_cp(wchar32_t cp);
  bool out_octal_char(uchar cs);
  enum sfx_type_t
  {
    sfxt_extends = 0,
    sfxt_super,
    sfxt_implements,
    sfxt_throws,
  };
  bool out_sfx(sfx_type_t sfxt);

  void _out_byte_to_ctx(uchar cs);
  void _out_line_to_ctx(const char *utf8);
  void _badidb(const char *from) const;
};

//-------------------------------------------------------------------------
format_helper_t::format_helper_t(
        java_t &_pm,
        const ushort *_tp,
        uint32 _nutf16,
        uint32 _off_ReturnType,
        uint32 _off_ThrowsSignature_and_TypeSignature,
        ssize_t _size,
        fmt_t _mode,
        out_java_t *_oj,
        _PRMPT_ _putproc)
  : pm(_pm),
    tp(_tp),
    nutf16(_nutf16),
    strcnt(0),
    size(_size),
    off_ReturnType(_off_ReturnType),
    off_ThrowsSignature_and_TypeSignature(_off_ThrowsSignature_and_TypeSignature),
    oj(_oj),
    putproc(_putproc),
    mode(_mode)
{
#ifdef DUMP_FORMATTED
  header.sprnt("nutf16=%u, ", _nutf16);
  header.cat_sprnt("posit=%u, ", _off_ReturnType);
  header.cat_sprnt("possgn=%u, ", _off_ThrowsSignature_and_TypeSignature);
  header.cat_sprnt("mode=%u (%s)", _mode, fmt_to_string(_mode));
  if ( nutf16 > 0 )
  {
    input.resize(_nutf16);
    memcpy(input.begin(), tp, nutf16 * sizeof(ushort));
  }
  utf16_utf8(&utf8_input, (const wchar16_t *) tp, nutf16);
#endif
}

#define BADIDB() _badidb(__FUNCTION__)

#define CHECKED(Expr)                           \
  do                                            \
  {                                             \
    if ( !(Expr) )                              \
      return false;                             \
  } while ( false )

//-------------------------------------------------------------------------
// ClassSignature:
// FormalTypeParameters opt SuperclassSignature SuperinterfaceSignature*
bool format_helper_t::parse_ClassSignature()
{
  if ( lookahead_utf16() == j_sign )
    CHECKED(parse_FormalTypeParameters());
  CHECKED(out_sfx(sfxt_extends));
  CHECKED(parse_SuperclassSignature());
  for ( uint32 impl_cnt = 0; lookahead_utf16() == j_class; ++impl_cnt )
  {
    if ( impl_cnt == 0 )
      CHECKED(out_sfx(sfxt_implements));
    else
      CHECKED(out_param_sep());
    CHECKED(parse_SuperinterfaceSignature());
  }
  return true;
}

//-------------------------------------------------------------------------
// FormalTypeParameters:
// < FormalTypeParameter+ >
bool format_helper_t::parse_FormalTypeParameters()
{
  CHECKED(consume_utf16_expect(j_sign));
  for ( uint32 cnt = 0; ; ++cnt )
  {
    if ( cnt++ > 0 )
      CHECKED(out_param_sep());
    CHECKED(parse_FormalTypeParameter());
    if ( lookahead_utf16() == j_endsign )
      break;
  }
  CHECKED(consume_utf16_expect(j_endsign));
  return true;
}

//-------------------------------------------------------------------------
// FormalTypeParameter:
// Identifier ClassBound InterfaceBound*
bool format_helper_t::parse_FormalTypeParameter()
{
  CHECKED(parse_Identifier());
  CHECKED(parse_ClassBound());
  while ( nutf16 > 0 )
  {
    if ( lookahead_utf16() != j_tag )
      break;
    CHECKED(parse_InterfaceBound());
  }
  return true;
}

//-------------------------------------------------------------------------
// SuperclassSignature:
// ClassTypeSignature
bool format_helper_t::parse_SuperclassSignature()
{
  CHECKED(parse_ClassTypeSignature());
  return true;
}

//-------------------------------------------------------------------------
// SuperinterfaceSignature:
// ClassTypeSignature
bool format_helper_t::parse_SuperinterfaceSignature()
{
  CHECKED(parse_ClassTypeSignature());
  return true;
}

//-------------------------------------------------------------------------
// In the following, the terminal symbol Identifier is used to denote the name of a type, field, local
// variable, parameter, method, or type variable, as generated by a Java compiler. Such a name must
// not contain any of the ASCII characters . ; [ / < > : (that is, the characters forbidden in method
// names (4.2.2) and also colon) but may contain characters that must not appear in an identifier in
// the Java programming language (JLS 3.8).
bool format_helper_t::parse_Identifier()
{
  while ( nutf16 > 0 )
  {
    wchar16_t la = lookahead_utf16();
    switch ( la )
    {
      case j_field_dlm:
      case j_endclass:
      case j_array:
      case j_clspath_dlm:
      case j_sign:
      case j_endsign:
      case j_tag:
        return true;
    }
    wchar32_t cp;
    if ( next_cp(&cp) && is_cp_graphical(cp) )
      CHECKED(out_cp(cp));
    else
      CHECKED(out_unicode_escaped_cp(cp)); // partial codepoint, broken surrogate, ...
  }
  return true;
}

//-------------------------------------------------------------------------
// ClassBound:
// : FieldTypeSignatureopt
bool format_helper_t::parse_ClassBound()
{
  CHECKED(discard_utf16_expect(j_tag));
  if ( lookahead_utf16() != j_tag )
  {
    CHECKED(out_sfx(sfxt_extends));
    CHECKED(parse_FieldTypeSignature());
  }
  return true;
}

//-------------------------------------------------------------------------
// InterfaceBound:
// : FieldTypeSignature
bool format_helper_t::parse_InterfaceBound()
{
  CHECKED(discard_utf16_expect(j_tag));
  CHECKED(out_sfx(sfxt_implements));
  CHECKED(parse_FieldTypeSignature());
  return true;
}

//-------------------------------------------------------------------------
// FieldTypeSignature:
// ClassTypeSignature
// ArrayTypeSignature
// TypeVariableSignature
bool format_helper_t::parse_FieldTypeSignature()
{
  wchar16_t la = lookahead_utf16();
  switch ( la )
  {
    case j_class:
      CHECKED(parse_ClassTypeSignature());
      break;
    case j_array:
      CHECKED(parse_ArrayTypeSignature());
      break;
    case j_typeref:
      CHECKED(parse_TypeVariableSignature());
      break;
    case 0:
    default:
      return false;
  }
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_ClassTypeSignature()
{
  return parse_class_desc(PCD_TYPE_ARGUMENTS_ALLOWED|PCD_EXPECT_SIGNATURE_BOUNDARIES);
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_ArrayTypeSignature()
{
  CHECKED(discard_utf16_expect(j_array));
  CHECKED(parse_TypeSignature());
  CHECKED(out_array_dim());
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_TypeVariableSignature()
{
  CHECKED(discard_utf16_expect(j_typeref));
  CHECKED(parse_Identifier());
  CHECKED(discard_utf16_expect(j_endclass));
  return true;
}

//-------------------------------------------------------------------------
// SimpleClassTypeSignature:
// Identifier TypeArgumentsopt
bool format_helper_t::parse_SimpleClassTypeSignature()
{
  CHECKED(parse_Identifier());
  CHECKED(parse_TypeArguments_opt());
  return true;
}

//-------------------------------------------------------------------------
// ClassTypeSignatureSuffix:
// . SimpleClassTypeSignature
bool format_helper_t::parse_ClassTypeSignatureSuffix()
{
  CHECKED(consume_utf16_expect(j_field_dlm));
  CHECKED(parse_SimpleClassTypeSignature());
  return true;
}

//-------------------------------------------------------------------------
// TypeSignature:
// FieldTypeSignature
// BaseType
bool format_helper_t::parse_TypeSignature()
{
  wchar16_t la = lookahead_utf16();
  if ( is_BaseType(la) )
    CHECKED(parse_BaseType());
  else
    CHECKED(parse_FieldTypeSignature());
  return true;
}

//-------------------------------------------------------------------------
// TypeArgument:
// WildcardIndicator opt FieldTypeSignature
// *
bool format_helper_t::parse_TypeArgument()
{
  wchar16_t la = lookahead_utf16();
  switch ( la )
  {
    case j_wild:
      CHECKED(discard_utf16_expect(la));
      CHECKED(out_cp('?'));
      break;
    case j_wild_e:
    case j_wild_s:
      CHECKED(discard_utf16_expect(la));
      CHECKED(out_cp('?'));
      CHECKED(out_sfx(la == j_wild_s ? sfxt_super : sfxt_extends));
      // fallthrough
    default:
      CHECKED(parse_FieldTypeSignature());
      break;
  }
  return true;
}

//-------------------------------------------------------------------------
// TypeArguments:
// < TypeArgument+ >
bool format_helper_t::parse_TypeArguments()
{
  CHECKED(consume_utf16_expect(j_sign));
  uint32 cnt = 0;
  do
  {
    if ( cnt++ > 0 )
      CHECKED(out_param_sep());
    CHECKED(parse_TypeArgument());
  } while ( lookahead_utf16() != j_endsign );
  CHECKED(consume_utf16_expect(j_endsign));
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_TypeArguments_opt()
{
  if ( lookahead_utf16() == j_sign )
    CHECKED(parse_TypeArguments());
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_BaseType()
{
  wchar32_t cp;
  CHECKED(next_cp(&cp));
  if ( cp >= 0x10000 )
    return false;
  const TXS *tname = get_base_typename(cp, /*or_void=*/ false);
  if ( tname == nullptr )
    return false;
  CHECKED(out_line(tname->str, tname->size));
  return true;
}

//-------------------------------------------------------------------------
// ReturnType:
// TypeSignature
// VoidDescriptor
bool format_helper_t::parse_ReturnType()
{
  if ( lookahead_utf16() == j_void_ret )
  {
    const TXS *tname = get_base_typename(j_void_ret, /*or_void=*/ true);
    CHECKED(out_line(tname->str, tname->size));
    CHECKED(discard_utf16_expect(j_void_ret));
  }
  else
  {
    CHECKED(parse_TypeSignature());
  }
  return true;
}

//-------------------------------------------------------------------------
// ThrowsSignature:
// ^ ClassTypeSignature
// ^ TypeVariableSignature
bool format_helper_t::parse_ThrowsSignature()
{
  for ( uint32 cnt = 0; nutf16 > 0; ++cnt )
  {
    CHECKED(discard_utf16_expect(j_throw));
    if ( cnt == 0 )
      CHECKED(out_sfx(sfxt_throws));
    else
      CHECKED(out_param_sep());
    if ( lookahead_utf16() == j_class )
      CHECKED(parse_ClassTypeSignature());
    else
      CHECKED(parse_TypeVariableSignature());
  }
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_MethodParams()
{
  CHECKED(consume_utf16_expect(j_parm_list_start));
  for ( uint32 cnt = 0; nutf16 > 0 && lookahead_utf16() != j_parm_list_end; ++cnt )
  {
    if ( cnt > 0 )
      CHECKED(out_param_sep());
    CHECKED(parse_TypeSignature());
  }
  CHECKED(consume_utf16_expect(j_parm_list_end));
  return true;
}

//-------------------------------------------------------------------------
// FieldType:
// BaseType
// ObjectType
// ArrayType
bool format_helper_t::parse_FieldType()
{
  const wchar16_t la = lookahead_utf16();
  switch ( la )
  {
    case j_class:
      CHECKED(parse_ObjectType());
      break;
    case j_array:
      CHECKED(parse_ArrayType());
      break;
    default:
      if ( !is_BaseType(la) )
        return false;
      CHECKED(parse_BaseType());
      break;
  }
  return true;
}

//-------------------------------------------------------------------------
// ArrayType:
// [ ComponentType
//
// where:
// ComponentType:
// FieldType
bool format_helper_t::parse_ArrayType()
{
  CHECKED(discard_utf16_expect(j_array));
  CHECKED(parse_FieldType());
  CHECKED(out_array_dim());
  return true;
}

//-------------------------------------------------------------------------
// ObjectType:
// L ClassName ;
//
// where: "The ClassName represents a binary class or interface name encoded in internal form (4.2.1)."
bool format_helper_t::parse_ObjectType()
{
  return parse_class_desc(PCD_TYPE_ARGUMENTS_ALLOWED|PCD_EXPECT_SIGNATURE_BOUNDARIES);
}

//-------------------------------------------------------------------------
// Names of methods, fields, and local variables are stored as unqualified
// names. An unqualified name must not contain any of the ASCII
// characters . ; [ / (that is, period or semicolon or left square bracket
// or forward slash). Method names are further constrained so that,
// with the exception of the special method names <init> and <clinit>
// (2.9), they must not contain the ASCII characters < or > (that is,
// left angle bracket or right angle bracket).
bool format_helper_t::parse_UnqualifiedName()
{
  while ( nutf16 > 0 )
  {
    wchar32_t cp;
    if ( next_cp(&cp) && is_cp_graphical(cp) )
    {
      switch ( cp )
      {
        case j_field_dlm:
        case j_endclass:
        case j_array:
        case j_clspath_dlm:
          return false;
        default:
          CHECKED(out_cp(cp));
      }
    }
    else
    {
      CHECKED(out_unicode_escaped_cp(cp)); // partial codepoint, broken surrogate, ...
    }
  }
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_FieldDescriptor()
{
  return parse_FieldType();
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_MethodDescriptor()
{
  CHECKED(consume_utf16_expect(j_parm_list_start));
  for ( uint32 cnt = 0; lookahead_utf16() != j_parm_list_end; ++cnt )
  {
    if ( cnt > 0 )
      CHECKED(out_param_sep());
    CHECKED(parse_ParameterDescriptor());
  }
  CHECKED(consume_utf16_expect(j_parm_list_end));
  CHECKED(parse_ReturnDescriptor());
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_ReturnDescriptor()
{
  if ( lookahead_utf16() == j_void_ret )
  {
    const TXS *tname = get_base_typename(j_void_ret, /*or_void=*/ true);
    CHECKED(out_line(tname->str, tname->size));
    CHECKED(discard_utf16_expect(j_void_ret));
  }
  else
  {
    CHECKED(parse_FieldType());
  }
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::parse_ParameterDescriptor()
{
  return parse_FieldType();
}

//-------------------------------------------------------------------------
bool format_helper_t::is_BaseType(wchar16_t v) const
{
  return v < 0x100 && get_base_typename(v, /*or_void=*/ false);
}

//-------------------------------------------------------------------------
// ClassTypeSignature:
// L PackageSpecifier opt SimpleClassTypeSignature ClassTypeSignatureSuffix* ;
//
// where:
// PackageSpecifier:
// Identifier / PackageSpecifier*
//
// and:
// SimpleClassTypeSignature:
// Identifier TypeArgumentsopt
//
// and:
// TypeArguments:
// < TypeArgument+ >
//
// Note that there is some ambiguity wrt the optional 'PackageSpecifier':
// it's impossible to know whether what we are parsing is the identifier
// of a PackageSpecifier, or that of a SimpleClassTypeSignature.
//
//
// Must also support binary class/interface names:
//
// 4.2.1. Binary Class and Interface Names
//
// Class and interface names that appear in class file structures
// are always represented in a fully qualified form known as binary
// names (JLS 13.1). Such names are always represented as CONSTANT_Utf8_info
// structures (4.4.7) and thus may be drawn, where not further constrained,
// from the entire Unicode codespace.
// Class and interface names are referenced from those
// CONSTANT_NameAndType_info structures (4.4.6) which have such names as
// part of their descriptor (4.3), and from all CONSTANT_Class_info
// structures (4.4.1).
//
// For historical reasons, the syntax of binary names that appear in
// class file structures differs from the syntax of binary names documented
// in JLS 13.1. In this internal form, the ASCII periods (.) that normally
// separate the identifiers which make up the binary name are replaced
// by ASCII forward slashes (/). The identifiers themselves must be
// unqualified names (4.2.2).
//
// For example, the normal binary name of class Thread is java.lang.Thread.
// In the internal form used in descriptors in the class file format, a
// reference to the name of class Thread is implemented using a
// CONSTANT_Utf8_info structure representing the string java/lang/Thread.
bool format_helper_t::parse_class_desc(uint32 flags)
{
  const bool type_arguments_allowed = (flags & PCD_TYPE_ARGUMENTS_ALLOWED) != 0;
  const bool expect_signature_boundaries = (flags & PCD_EXPECT_SIGNATURE_BOUNDARIES) != 0;
  if ( expect_signature_boundaries )
    CHECKED(discard_utf16_expect(j_class));
  bool reached_suffix = false;
  while ( !reached_suffix )
  {
    CHECKED(parse_Identifier());
    wchar16_t la = lookahead_utf16();
    switch ( la )
    {
      case j_clspath_dlm:
        CHECKED(out_cp('.'));
        CHECKED(discard_utf16_expect(j_clspath_dlm));
        break;
      case j_sign:
        if ( type_arguments_allowed )
        {
          CHECKED(parse_TypeArguments());
          goto parse_class_desc_ok;
        }
        else
        {
          return false;
        }
      case j_field_dlm:
        reached_suffix = true;
        break;
      case j_endclass:
        goto parse_class_desc_ok;
      default:
        if ( la == 0 && !expect_signature_boundaries )
          goto parse_class_desc_ok;
        return false;
    }
  }

  // If we are here, it means we reached 'ClassTypeSignatureSuffix*'
  while ( true )
  {
    wchar16_t la = lookahead_utf16();
    if ( la == j_endclass )
      goto parse_class_desc_ok;
    if ( la == j_field_dlm )
      CHECKED(parse_ClassTypeSignatureSuffix());
    else
      return false; // unexpected codepoint
  }

parse_class_desc_ok:
  if ( expect_signature_boundaries )
    CHECKED(discard_utf16_expect(j_endclass));
  return true;
}

#undef CHECKED

//-------------------------------------------------------------------------
int format_helper_t::format()
{
  bool ok = false;
  if ( mode == fmt_ClassSignature )
  {
    switch ( lookahead_utf16() )
    {
      case j_class:
        ok = parse_ClassTypeSignature();
        break;
      case j_sign:
        ok = parse_ClassSignature();
        break;
      default:
        break;
    }
  }
  else if ( mode == fmt_method_FormalTypeParameters
         || mode == fmt_method_TypeSignature
         || mode == fmt_method_ReturnType
         || mode == fmt_method_ThrowsSignature )
  {
    // MethodTypeSignature:
    // FormalTypeParameters opt (TypeSignature*) ReturnType ThrowsSignature*
    if ( !off_ReturnType || off_ReturnType >= nutf16 || tp[off_ReturnType-1] != j_parm_list_end )
      BADIDB();

    ushort off_TypeSignature = ushort(off_ThrowsSignature_and_TypeSignature);
    ushort off_ThrowsSignature = off_ThrowsSignature_and_TypeSignature >> 16;
    if ( off_ThrowsSignature_and_TypeSignature > 0 )
    {
      if ( off_TypeSignature >= off_ReturnType
        || tp[off_TypeSignature] != j_parm_list_start )
      {
        BADIDB();
      }
      if ( off_ThrowsSignature > 0 )
      {
        if ( off_ThrowsSignature <= off_ReturnType
          || off_ThrowsSignature >= nutf16
          || tp[off_ThrowsSignature] != j_throw )
        {
          BADIDB();
        }
      }
    }
    switch ( mode )
    {
      case fmt_method_FormalTypeParameters:
        if ( off_TypeSignature == 0 )
          return 0;
        if ( *tp != j_sign )
          BADIDB();
        nutf16 = off_TypeSignature;
        ok = parse_FormalTypeParameters();
        break;
      case fmt_method_TypeSignature:
        nutf16 = off_ReturnType - off_TypeSignature;
        tp += off_TypeSignature;
        ok = parse_MethodParams();
        break;
      case fmt_method_ReturnType:
        if ( off_ThrowsSignature > 0 )
          nutf16 = off_ThrowsSignature;
        nutf16 -= off_ReturnType;
        tp += off_ReturnType;
        ok = parse_ReturnType();
        break;
      case fmt_method_ThrowsSignature:
        if ( off_ThrowsSignature == 0 )
          return 0;
        nutf16 -= off_ThrowsSignature;
        tp += off_ThrowsSignature;
        ok = parse_ThrowsSignature();
        break;

      default: INTERR(10332);
    }
    if ( ok && mode != fmt_method_TypeSignature )
      ok = out_cp(' ');
  }
  else if ( mode == fmt_FieldDescriptor_nospace )
  {
    switch ( lookahead_utf16() )
    {
      case j_class:
        ok = parse_ClassTypeSignature();
        break;
      case j_sign:
        ok = parse_ClassSignature();
        break;
      case j_parm_list_start:
        ok = parse_MethodDescriptor();
        break;
      default:
        ok = parse_TypeSignature();
        break;
    }
  }
  else if ( mode == fmt_FieldDescriptor )
  {
    ok = parse_FieldDescriptor() && out_cp(' ');
  }
  else if ( mode == fmt_fullname )
  {
    switch ( lookahead_utf16() )
    {
      case j_parm_list_start:
        ok = parse_MethodDescriptor();
        break;
      case j_class:
        ok = parse_ClassTypeSignature();
        break;
      case j_array:
        ok = parse_ArrayType();
        break;
      default:
        ok = parse_class_desc(0);
        break;
    }
  }
  else if ( mode == fmt_ClassName
         || mode == fmt_ClassName_or_Array )
  {
    ok = lookahead_utf16() == j_array
       ? parse_ArrayType()
       : parse_class_desc(0);
  }
  else if ( mode == fmt_UnqualifiedName )
  {
    ok = parse_UnqualifiedName();
  }
  else if ( mode == fmt_debug || mode == fmt_string || mode == fmt_string_single_quotes )
  {
    uchar quotation = '"';
    switch ( mode )
    {
      case fmt_debug:
        if ( !pm.is_multiline_debug() )
          mode = fmt_string;  // optimize
        break;
      case fmt_string:
        if ( pm.is_fmt_string_as_fmt_debug() )
          mode = fmt_debug;
        break;
      case fmt_string_single_quotes:
        quotation = '\'';
        break;
      default:
        break;
    }
    ok = out_cp(quotation);
    while ( ok && nutf16 > 0 )
    {
      wchar32_t cp;
      if ( !next_cp(&cp) )
      {
        ok = out_unicode_escaped_cp(cp); // partial codepoint, broken surrogate, ...
      }
      else
      {
        if ( cp >= 0x100 )
        {
          if ( !is_cp_graphical(cp) )
            ok = out_unicode_escaped_cp(cp);
          else
            ok = out_cp(cp);
          continue;
        }
        else if ( cp >= CHP_MAX )
        {
          ok = out_octal_char(cp);
          continue;
        }
        else if ( cp >= ' ' )
        {
          if ( cp == '\\' || cp == '"' )
            ok = out_escaped_char(cp);
          else
            ok = out_cp(cp);
          continue;
        }
        else if ( cp < 0xD )
        {
          if ( cp < 8 || cp == 0xB )
            goto checkdig;
          {
            static const char casc[(0xD-8)+1] = { 'b', 't', 'n', '?', 'f', 'r' };
            cp = casc[cp-8];    //lint !e676 possibly indexing before the beginning of an allocation
            if ( cp == 'n'
              && mode == fmt_debug
              && nutf16
              && size > 2 )
            {
              size = 2;
            }
          }
          ok = out_escaped_char(cp);
          continue;
        }
checkdig:
        if ( nutf16 > 0 && *tp <= '7' && *tp >= '0' )
        {
          ok = out_octal_char(cp);
        }
        else
        {
          if ( cp <= 7 )
          {
            ok = out_escaped_char(cp + '0');
          }
          else
          {
            char _buf[MAXSTR];
            int _buflen = qsnprintf(_buf, sizeof(_buf), "\\%o", cp);
            ok = out_line(_buf, _buflen);
          }
        }
      }
    }
    if ( ok )
      ok = out_cp(quotation);
  }
  maybe_report(/*failure=*/ !ok);
  return strcnt;
}

//-------------------------------------------------------------------------
bool format_helper_t::ensure_remaining(ssize_t needed)
{
  if ( size < needed )
  {
    size = putproc(pm, oj);
    if ( size == 0 )
      return false;
    else
      ++strcnt;
  }
  size -= needed;
  return true;
}

//-------------------------------------------------------------------------
wchar16_t format_helper_t::lookahead_utf16() const
{
  return nutf16 > 0 ? *tp : 0;
}

//-------------------------------------------------------------------------
bool format_helper_t::discard_utf16_expect(wchar16_t expected)
{
  if ( nutf16 == 0 || *tp != expected )
    return false;
  --nutf16;
  ++tp;
  return true;
}

//-------------------------------------------------------------------------
bool format_helper_t::consume_utf16_expect(wchar16_t expected)
{
  bool rc = discard_utf16_expect(expected);
  if ( rc )
    out_cp(expected);
  return rc;
}

//-------------------------------------------------------------------------
bool format_helper_t::next_cp(wchar32_t *out)
{
  bool ok = true;
  wchar32_t cp = *tp++;
  --nutf16;
  if ( is_tail_surrogate(cp) )
  {
    ok = false;
  }
  else if ( is_lead_surrogate(cp) )
  {
    ok = nutf16 > 0;
    if ( ok )
    {
      wchar16_t lookahead = *tp;
      ok = is_tail_surrogate(lookahead);
      if ( ok )
      {
        cp = utf16_surrogates_to_cp(cp, lookahead);
        ++tp;
        --nutf16;
      }
    }
  }
  *out = cp;
  return ok;
}

//-------------------------------------------------------------------------
void format_helper_t::maybe_report(bool failure) const
{
#ifdef DUMP_FORMATTED
  if ( collected != utf8_input && !utf8_input.empty() )
  {
    qstring notag_collected;
    tag_remove(&notag_collected, collected);
    if ( under_debugger && failure )
      BPT;
    msg("\n#%s %s", failure ? "FAILING_INPUT" : "FMTSTRING", header.c_str());

    qstring utf8_input_user, notag_collected_user;
    qstr2user(&utf8_input_user, utf8_input);
    qstr2user(&notag_collected_user, notag_collected);
    qstring serialized_input;
    for ( size_t i = 0, n = input.length(); i < n; ++i )
    {
      ushort cw = input[i];
      if ( cw >= ' ' && cw < 0x7f && qisprint(char(cw)) && cw != '\\' )
        serialized_input.append(char(cw));
      else
        serialized_input.cat_sprnt("\\u%04X", cw);
    }
    msg("#\x01%s\x01%s\x01%s\n",
        utf8_input_user.c_str(),
        serialized_input.c_str(),
        notag_collected_user.c_str());
  }
#else
  qnotused(failure);
#endif // DUMP_FORMATTED
}

//-------------------------------------------------------------------------
bool format_helper_t::out_cp(wchar32_t cp)
{
  char utf8[MAX_UTF8_SEQ_LEN];
  ssize_t nbytes = put_utf8_char(utf8, cp);
  if ( nbytes < 0 )
    nbytes = put_utf8_char(utf8, CP_REPLCHAR);
  if ( nbytes < 0 ) // PARANOYA
    utf8[0] = '\0';
  bool ok = ensure_remaining(1);
  if ( ok )
    _out_line_to_ctx(utf8);
  return ok;
}

//-------------------------------------------------------------------------
bool format_helper_t::out_line(const char *s, size_t len)
{
  bool ok = ensure_remaining(len);
  if ( ok )
    _out_line_to_ctx(s);
  return ok;
}

//-------------------------------------------------------------------------
bool format_helper_t::out_escaped_char(uchar cs)
{
  bool ok = ensure_remaining(2);
  if ( ok )
  {
    _out_byte_to_ctx('\\');
    _out_byte_to_ctx(cs);
  }
  return ok;
}

//-------------------------------------------------------------------------
bool format_helper_t::out_utf16_escaped_halfword(wchar16_t hw)
{
  char buf[32];
  int buflen = qsnprintf(buf, sizeof(buf), "\\u%04X", hw);
  bool ok = ensure_remaining(buflen);
  if ( ok )
    _out_line_to_ctx(buf);
  return ok;
}

//-------------------------------------------------------------------------
bool format_helper_t::out_unicode_escaped_cp(wchar32_t cp)
{
  if ( cp < 0x10000 )
  {
    return out_utf16_escaped_halfword(cp);
  }
  else
  {
    wchar16_t leading = 0xD800 + (((cp - 0x10000) >> 10) & 0x3FF);
    wchar16_t tailing = 0xDC00 + (cp & 0x3FF);
    return out_utf16_escaped_halfword(leading)
        && out_utf16_escaped_halfword(tailing);
  }
}

//-------------------------------------------------------------------------
bool format_helper_t::out_octal_char(uchar cs)
{
  char buf[32];
  int buflen = qsnprintf(buf, sizeof(buf), "\\%.3o", cs);
  bool ok = ensure_remaining(buflen);
  if ( ok )
    _out_line_to_ctx(buf);
  return ok;
}

//-------------------------------------------------------------------------
bool format_helper_t::out_sfx(sfx_type_t sfxt)
{
  static const TXS sfx[4] =
    {
      TXS_DECLARE(" extends "),
      TXS_DECLARE(" super "),
      TXS_DECLARE(" implements "),
      TXS_DECLARE(" throws ")
  };

  bool ok = ensure_remaining(sfx[sfxt].size);
  if ( ok )
    _out_line_to_ctx(sfx[sfxt].str);
  return ok;
}

//-------------------------------------------------------------------------
void format_helper_t::_out_byte_to_ctx(uchar cs)
{
  oj->out_char(cs);
#ifdef DUMP_FORMATTED
  collected.append(cs);
#endif
}

//-------------------------------------------------------------------------
void format_helper_t::_out_line_to_ctx(const char *utf8)
{
  oj->out_line(utf8);
#ifdef DUMP_FORMATTED
  collected.append(utf8);
#endif
}

//-------------------------------------------------------------------------
void format_helper_t::_badidb(const char *from) const     //lint !e715 not referenced
{
  qnotused(from);
  DESTROYED(from);
}

//-------------------------------------------------------------------------
int java_t::format_utf16_string(
        const ushort *tp,
        uint32 nutf16,
        uint32 off_ReturnType,
        uint32 off_ThrowsSignature_and_TypeSignature,
        ssize_t size,
        fmt_t mode,
        out_java_t *oj,
        _PRMPT_ putproc)
{
  format_helper_t helper(*this, tp, nutf16, off_ReturnType, off_ThrowsSignature_and_TypeSignature, size, mode, oj, putproc);
  return helper.format();
}
