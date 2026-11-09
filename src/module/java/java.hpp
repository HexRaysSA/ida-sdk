//#define __debug__

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

#ifndef _JAVA_HPP
#define _JAVA_HPP

#define VIEW_WITHOUT_TYPE // no show return/filed type in command if !jasmin()

#include <pro.h>
#include "../idaidp.hpp"
#include <fpro.h>
#include <ieee.h>

#include "classfil.hpp"
#include "ins.hpp"
struct java_t;

//----------------------------------------------------------------------
struct TXS
{
  const char *str;
  uchar size;
};
#define TXS_DECLARE(p) { p, (uchar)(sizeof(p)-1) }
#define TXS_EMPTY()    { nullptr, 0 }


#pragma pack(1)
//----------------------------------------------------------------------
// Redefine temporary names
//
#define wid         segpref
#define xtrn_ip     auxpref

#define swit        Op1.specflag2
#define ref         specflag1
#define _name       value_shorts.low
#define _class      value_shorts.high
#define _bmidx      value_shorts.high
#define _mhr_kind   value_shorts.low  // MethodHandle reference_kind
#define _mhr_index  value_shorts.high // MethodHandle reference_index
#define _mtd_index  value_shorts.low  // MethodType descriptor_index
#define _dscr       addr_shorts.low
#define _subnam     addr_shorts.high
#define cp_ind      specval_shorts.low
#define cp_type     specval_shorts.high
// nexts for Utf8 (on load) and _Ssize used in MAP only
#define _Ssize      addr_shorts.low
#define _Sflags     addr_shorts.high
#define _Sopstr     value2

// command aliases
#define o_cpool     o_idpspec0
#define o_array     o_idpspec1

//----------------------------------------------------------------------
struct const_desc_t
{
  uchar type;         // CONSTANT_type
  uchar flag;
#define _REF          0x01   // has reference
#define HAS_FLDNAME   0x02   // Utf8 is valid Field/Variable Name
#define HAS_TYPEDSCR  0x04   // Utf8 is valid Descriptor
#define HAS_CALLDSCR  0x08   // Utf8 is valid Descriptor for Method
#define HAS_CLSNAME   0x10   // Utf8 is valid as Class Name (Not FLD!)
#define SUB_FLDNAME   0x20
#define SUB_TYPEDSCR  0x40
#define SUB_CALLDSCR  0x80
#define SUB_SHIFT 4
  CASSERT((HAS_FLDNAME  << SUB_SHIFT) == SUB_FLDNAME
       && (HAS_TYPEDSCR << SUB_SHIFT) == SUB_TYPEDSCR
       && (HAS_CALLDSCR << SUB_SHIFT) == SUB_CALLDSCR);

  bool is_referenced() const { return (flag & _REF) != 0; }
  void mark_referenced() { flag |= _REF; }

#define NORM_FIELD (HAS_CLSNAME | SUB_FLDNAME | SUB_TYPEDSCR)
#define NORM_METOD (HAS_CLSNAME | SUB_FLDNAME | SUB_CALLDSCR)

  ushort ref_ip;      // in xtrn-segment...
  union
  {
    uint32 value;     // low part of # value
    struct
    {
      ushort low;     // BegInd Utf8 (name)
      ushort high;    // index to _Class
    } value_shorts;   // unification
  };
  union
  {
    uint32 value2;    // hi part of # value
    struct
    {
      ushort low;     // TypeName
      ushort high;    // Descriptor
    } addr_shorts;
  };
};

union Object
{ // in IDP_JDK12 format was in reverse order!
  struct
  {
    ushort Name;      // index to name
    ushort Dscr;      // index to descriptor
  };
  uint32 Ref;         // used in out
};

struct _FMid_
{
  ushort name;           // index to name
  ushort dscr;           // index to descriptor
  ushort access;         // access flag
// Number not needed for search/out
  ushort Number;         // Number of current Field or Method
  uchar  extflg;         // for ERROR diagnostic and other flags
#define EFL_NAME    1
#define EFL_TYPE    2
#define EFL_NAMETYPE  (EFL_NAME | EFL_TYPE)
//#define _OLD_EFL_ACCESS  4
#define EFL__MASK (EFL_NAME | EFL_TYPE | 4)  // for check on conversion
// next constant added in JDK15 store-format
// java-2 store format only
#define XFL_DEPRECATED  0x04
#define XFL_UNICODENAME 0x08            // name contain unicode character
#define XFL_M_LABSTART  0x10            // for METHOD set label at entry
#define XFL_C_SUPEROBJ  0x10            // for THIS - parent(.super) == Object
#define XFL_M_LABEND    0x20            // for METHOD set label at exit
#define XFL_C_DEBEXT    0x20            // for THIS - have stored SourceDebugExtension
#define XFL_M_EMPTYSM   0x40            // for METHOD - have empty StackMap
#define XFL_C_ERRLOAD   0x40            // for THIS - have loadtime problems
#define XFL_C_DONE      0x80            // analisys pass complete
// next fields added in JDK15 store-format
  uchar  _UNUSED_ALING;  // = 0
  ushort utsign;         // index to signature attribute
};

struct FieldInfo
{
  _FMid_ id;             // for search procedure
  uval_t valNode;        // init value's node
// next fields added in JDK15 store-format
  uval_t annNodes[2];    // nodes for Vis/Invis annotation
  uval_t genNode;        // list of stored generic attributes

  void clear_jdk15_fields()
  {
    annNodes[0] = 0;
    annNodes[1] = 0;
    genNode = 0;
  }
};

struct SegInfo
{
  _FMid_ id;             // for search procedure
  uint32 CodeSize;       // CODE size
  ea_t   start_ea;        // EA of Code (checker & slb)
  ea_t   DataBase;       // EA of loc variable segment
  ushort DataSize;       // max locals (DATA size)
  ushort stacks;         // stack size
  uval_t excNode;        // Node for exception table
  uval_t thrNode;        // Node for throws  (fmt change!)
// next fields added in JDK15 store-format
  uval_t varNode;        // LocVar descriptors
  uval_t smNode;         // StackMap descriptors
  // Visible, Invisible, VisibleParam, InvisibleParam, Default
  uval_t annNodes[5];    // nodes for all types of annotations
  uval_t genNodes[2];    // list of stored generic attributes + code

  void clear_jdk15_fields()
  {
    varNode = 0;
    smNode = 0;
    annNodes[0] = 0;
    annNodes[1] = 0;
    annNodes[2] = 0;
    annNodes[3] = 0;
    annNodes[4] = 0;
    genNodes[0] = 0;
    genNodes[1] = 0;
  }
};

struct ClassInfo
{
  ushort maxCPindex;     // max valid index in ConstantPool
  ushort MinVers;        //-> of file
  Object This;           // class name/descriptor
  Object super;          // .super class (parent)
  ushort AccessFlag;     // access flags
  ushort FieldCnt;       // Field Declaration Counter
  uval_t ClassNode;      // Field (>0) & Method (<0) (0?)
  ushort MethodCnt;      // Method's Segment fot this Class
  ushort SourceName;     // Index of Utf8 Source File Name
  uval_t impNode;        // Node for Interfaces (fmt change!)
  ea_t   start_ea;       // for SearchFM
  uint32 maxSMsize;      // optimize memory allocation (StackMap)
                         // ATT: JDK15 - previous errload
  ea_t   xtrnEA;         // beg header segment
  uval_t xtrnNode;       // node for xtrn Segment
  ushort xtrnCnt;        // header size
  ushort xtrnLQE;
// next fields added in JDK15 store-format
  ushort MajVers;        // -> of file
  uchar  extflg;         // XFL_.... consts
  uchar  JDKsubver;      // for speed/size ONLY
  uval_t innerNode;      // Node for Inner classes
  ushort encClass;       // EnclosingMethod class
  ushort encMethod;      // EnclosingMethod NameAndType
  uval_t msgNode;        // node for store loading messages
  ushort utsign;         // signature attribute index
  ushort maxStrSz;       // optimize memory allocation (string)
  uval_t annNodes[2];    // nodes for Visible/Invisible
  uint32 maxAnnSz;       // optimize memory allocation (annotation)
  uval_t genNode;        // list of stored generic attributes
};

#define FOR_EACH_CONSTANT_POOL_INDEX(Binding) for ( ushort Binding = 1; Binding <= curClass.maxCPindex; ++Binding )


struct Exception
{
  ushort start_pc;
  ushort end_pc;
  ushort handler_pc;
  Object filter;
};

struct LocVar
{
  ushort ScopeBeg;       // scope start
  ushort ScopeTop;       // scope end
  Object var;            // name & descriptor
  ushort utsign;         // signature attribute index
};

struct InnerClass
{
  ushort inner;
  ushort outer;
  ushort name;
  ushort access;
};

//------------------------------------------------------------------------
enum sm_node_t
{
  smn_aa_not_finished = -1,
  smn_ok = 0,
  smn_no_use = 1,
};
#define CNS_SOURCE    -2
#define CNS_CLASS     0
//>0 - opis[i]
//>=0x10000 - string blobs
#define CNA_VERSION   -1
#define CNA_KWRDVER   -2
#define CNA_IDPFLAGS  -3 // idpflags value
#define CNA_LIMITER   -4 // user_limiter state
//>=0x10000 - string info
#define UR_TAG  'r'

//------------------------------------------------------------------------
// !DO NOT CHANGE ORDER!
enum fmt_t
{
  fmt_debug = 0,  // as fmt_string, but have prompting
  fmt_string,     // string as text
  fmt_string_single_quotes,
  fmt_FieldDescriptor,

  // MethodTypeSignature:
  // FormalTypeParameters opt (TypeSignature*) ReturnType ThrowsSignature*
  //  ^
  fmt_method_FormalTypeParameters,

  // MethodTypeSignature:
  // FormalTypeParameters opt (TypeSignature*) ReturnType ThrowsSignature*
  //                                           ^
  fmt_method_ReturnType,

  // MethodTypeSignature:
  // FormalTypeParameters opt (TypeSignature*) ReturnType ThrowsSignature*
  //                          ^
  fmt_method_TypeSignature,

  // MethodTypeSignature:
  // FormalTypeParameters opt (TypeSignature*) ReturnType ThrowsSignature*
  //                                                      ^
  fmt_method_ThrowsSignature,

  fmt_ClassSignature,    // class signature (start width <...:...>)
  fmt_FieldDescriptor_nospace,  // signature (==dscr, without space)
  fmt_ClassName_or_Array,       // if have '[' desriptor, else fieldname
  fmt_ClassName,  // extract class from descriptor
  fmt_fullname,   // full qualified name
  fmt_UnqualifiedName,
  fmt__ENDENUM
 };
#define FMT_ENC_RESERVED  (uchar)0x80

//-------------------------------------------------------------------------
inline bool fmt_expects_call_descriptor(fmt_t fmt)
{
  return fmt >= fmt_method_FormalTypeParameters && fmt <= fmt_ClassSignature;
}

//-------------------------------------------------------------------------
struct SMinfo // for sm_getinfo
{
  const uchar *pb;
  const uchar *pe;
  uint fcnt;
  ea_t ea;
};

enum load_mode_t
{
  lm_lenient = -1, // don't call remember_problem()
  lm_no_set_ref = 0, // no set reference
  lm_normal = 1, // Normal mode
  lm_need_cr = 2, // needed CR
};
ea_t        extract_name_ea(
        char buf[MAXSTR],
        const char *name,
        int pos,
        uchar clv);
const TXS *get_base_typename(uchar tag, bool or_void=false);

#if defined(__debug__) || defined(TEST_FMTSTR)
NORETURN extern void _destroyed(const char *from);
NORETURN extern void _faterr(uchar mode, const char *from);
#define UNCOMPAT(p)   _faterr(1, p)
#define INTERNAL(p)   _faterr(0, p)
#define DESTROYED(p)  _destroyed(p)
#else
NORETURN extern void _destroyed(void);
NORETURN extern void _faterr(uchar mode);
#define UNCOMPAT(p)   _faterr(1)
#define INTERNAL(p)   _faterr(0)
#define DESTROYED(p)  _destroyed()
#endif

uchar javaIdent(ushort v, uchar *isStart = nullptr);

// information record of StackMap
struct sm_info_t
{
  uint32 noff;   // start offset in blob
  uint32 eoff;   // end offset in blob
  uint fcnt;     // locals at entry
};

//------------------------------------------------------------------------
#ifdef __debug__
#define DEB_ASSERT(cond, text)   if ( cond ) error(text)
#else
#define DEB_ASSERT(cond, text)
#endif

//------------------------------------------------------------------------
enum j_registers { Rvars=0, Roptop, Rframe, rVcs, rVds };

//------------------------------------------------------------------------
void  idaapi java_header(outctx_t &ctx);

void  idaapi java_segstart(outctx_t &ctx, segment_t *seg);
void  idaapi java_segend(outctx_t &ctx, segment_t *seg);

fpvalue_error_t idaapi j_realcvt(void *m, fpvalue_t *e, ushort swt);

void  idaapi java_data(outctx_t &ctx, bool analyze_only);

int   cmp_operands(op_t &op1, op_t &op2);
bool  idaapi can_have_type(const op_t &op);
void copy_const_to_opnd(op_t &x, const const_desc_t &co);


//----------------------------------------------------------------------
#define UAS_JASMIN   0x0001     // is jasmin assembler?

//------------------------------------------------------------------------
#define MLD_EXTREF    0x01
#define MLD_VARREF    0x02  // if present EXTREF must be present
#define MLD_METHREF   0x04  // if present VARREF must be present

#define MLD_EXTATR    0x08  // store additional attributes to file(s)
#define MLD_LOCVAR    0x10  // Rename local variables
#define MLD_STRIP     0x20  // Semantic error names show
#define MLD_FORCE     0x40  // Ignore 'additional error' on load

#define MLD__DEFAULT  ((MLD_EXTREF|MLD_VARREF) /* | MLD_LOCVAR */)


//------------------------------------------------------------------------
#define IDF_MULTDEB       0x0001    // multiline debug
#define IDF_HIDESM        0x0002    // hide stackmap
#define IDF_AUTOSTR       0x0004    // fmt_string as fmt_debug (next string at \n)
#define IDF_CONVERT       0x0008    // convert (to jasmin) when write asm file
#define IDF_ENCODING      0x0010    // enable unicode-encoding (also see map)
#define IDF_NOPATH        0x0020    // .attribute's filename without path

// not stored (in base) flags
#define IDM_BADIDXSTR 0x00010000    // show invalid indexes as string's

// ... and used loader only
#define IDM_REQUNK    0x20000000    // make request of ;unknown attribute'
#define IDM_WARNUNK   0x40000000    // 'unknown attribute' produced warnings
// ... in module, but temporary
#define IDM_OUTASM    0x80000000    // currently write asm file

#define IDM__REQMASK  ((~(IDM_REQUNK | IDM_WARNUNK | IDM_OUTASM)) >> 16)

// curent modes
#define IDFM__DEFAULT ((IDF_MULTDEB|IDF_CONVERT|IDF_ENCODING) | IDM_WARNUNK)

#pragma pack()

//------------------------------------------------------------------
enum CIC_param
{
  C_4byte = 0,
  C_8byte,
  C_Field,
  C_Method,
  C_Interface,
  C_Class,
  C_Type,
  C_TypeName,
  C_CallSite,
};

enum attr_parent_kind_t
{
  attr_parent_kind_code = 0,
  attr_parent_kind_field,
  attr_parent_kind_method,
  attr_parent_kind_class_file,
  attr_parent_kind_CHECK,
};

class out_java_t;
typedef size_t _PRMPT_(java_t &pm, out_java_t *oj);
#define MAX_ATTR_NMSZ  128

//------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct java_t);

struct java_t : public procmod_t
{
  idb_listener_t idb_listener = idb_listener_t(*this);
  int start_asm_list = 0;
  uint32 idpflags = IDFM__DEFAULT;
#ifdef TEST_FMTSTR
  inline bool jasmin(void) const { return false; }
  inline bool is_multiline_debug(void) const { return true; } // true by default, it seems
  inline bool is_fmt_string_as_fmt_debug(void) const { return false; } // false by default, it seems
#else
  inline bool jasmin(void) const { return (ash.uflag & UAS_JASMIN) != 0; }
  inline bool is_multiline_debug(void) const { return (idpflags & IDF_MULTDEB) != 0; }
  inline bool is_fmt_string_as_fmt_debug(void) const { return (idpflags & IDF_AUTOSTR) != 0; }
#endif
  bool mode_changed = false;
  bool displayed_nl = false;

  bool g_bufinited = false;
  uint32 g_bufsize = 0;
  uint32 maxpos = 0;
  uint32 curpos = 0;
  uchar user_limiter = 0;
  // next fields are only for out
  bool no_prim = false;
  size_t outcnt = 0;
  size_t ref_pos = 0;
  uint32 Feature = 0;
  // Normally static buffers of MAX_NODENAME_SIZE are forbidden but since
  // 'tmp_name' is defined only in the java module, it is acceptable. To avoid
  // warnings we define JAVA_BUFSIZE:
#define JAVA_BUFSIZE MAX_NODENAME_SIZE
  char tmp_name[JAVA_BUFSIZE];

  // map.cpp vars
  char rfmt[23] = "                %5u=> ";
  char ind_fmt[8] = "%s=%-5u";
  char lft_fmt[16] = "%08lX %5u%c %s ";

  // npool.cpp vars
  int32 savesize = -1;
  uchar sde = 0;

  // npooluti.cpp vars
  ClassInfo   curClass;
  SegInfo     curSeg;
  FieldInfo   curField;
  FILE        *myFile = nullptr;
  netnode     ClassNode;
  netnode     XtrnNode;
  netnode     ConstantNode;
  char        debugmode = 0;
  uchar       SMF_mode = 0;
  // only for npool
  uchar       loadMode = 0;
  uint32      errload = 0;
  ushort      *tsPtr = nullptr;
  uchar       *smBuf = nullptr;
  uchar       *annBuf = nullptr;
  uint32      FileSize = 0;
  sm_node_t sm_node = smn_aa_not_finished;
  uchar uni_chk = (uchar)-1;  // unicode 'renaming' support
  uchar name_chk = 0;
  char tmpbuf[JAVA_BUFSIZE];  // see comment for TMP_NAME
  netnode SMnode;
  uint32 SMsize = 0;
  uint endcls = 0;
  uchar clunic = 0;     // for unicode renaming
  ea_t start_ea = 0;
  ushort cursel = 1;
  // jasmin reserved word support
  std::set<qstring> ResW;

  java_t()
  {
    memset(&curClass, 0, sizeof(curClass));
    memset(&curSeg, 0, sizeof(curSeg));
    memset(&curField, 0, sizeof(curField));
    memset(tmp_name, 0, sizeof(tmp_name));
    memset(tmpbuf, 0, sizeof(tmpbuf));
  }

  inline void StoreOpis(uint index, const const_desc_t &opis)
  {
    ConstantNode.supset(index, &opis, sizeof(opis));
  }

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  void sm_validate(const SegInfo *si);

  uchar loadDialog(bool manual);
  int32 gen_map_file(FILE *fp);
  char *convert_clsname(char *buf) const;
  void database_loaded(const char *file);
  void make_new_name(ushort name, ushort subnam, uchar mode, uint ip);
  int upgrade_db_format(int ver, netnode constnode);
  void coagulate_unused_data(const SegInfo *ps);

  void java_footer(outctx_t &ctx);

  void load_attributes(attr_parent_kind_t apk);
  void loader(FILE *fp, bool manual);
  ea_t get_ref_addr(ea_t ea, const char *name, size_t pos);
  void TouchArg(const insn_t &insn, const op_t &x, bool isload);
  uval_t SearchFM(ushort name, ushort dscr, char *naprN);
  void mark_and_comment(ea_t ea, const char *cmt) const;
  int emu(const insn_t &insn);

  int format_utf16_string(
        const ushort *_tp,
        uint32 ostsz,
        uint32 off_ReturnType,
        uint32 off_ThrowsSignature_and_TypeSignature,
        ssize_t size,
        fmt_t mode,
        out_java_t *oj,
        _PRMPT_ putproc);
  void xtrnSet(
        uint cin,
        const_desc_t *co,
        uint xip,
        char *str,
        size_t strsize,
        bool full,
        uchar rmod=3);
  void rename_uninames(int32 mode);
  void setPoolReference(void);
  void SetName(ushort name, ea_t ea, ushort access, uval_t number, uchar rmod=3);
  int refput(ushort index);
  bool fmtName(ushort index, char *buf, size_t bufsize, fmt_t fmt);
  uchar set_parent_object(void);
  uchar attribute_type_from_str(ushort index, attr_parent_kind_t apk, char str[MAX_ATTR_NMSZ]);
  void CheckPoolReference(bool insns_created);
  void set_lv_name(ushort name, ea_t ea, uchar rmod);
  int is_locvar_name(const insn_t &insn, const char *name);
  void ValidateStoreLocVar(ushort slot, LocVar & lv);
  void dump_floating_constants(
        const char *problem,
        const char *what,
        const intvec_t &ks);
  ssize_t check_special_label(const char *buf, size_t len) const;
  bool LoadOpis(load_mode_t load_mode, ushort index, uchar _op, const_desc_t *p);
  void load_msg(const char *format, ...);
  bool isSingleClass(ushort val);
  const char *mk_diag(attr_parent_kind_t apk, char str[128]) const;
  uint load_constants_pool(void);
  inline void BadRefFile(const char *to, ushort id);
  void BadRef(ea_t ea, const char *to, ushort id, attr_parent_kind_t apk);
  void mark_access(ea_t ea, ushort acc) const;
  uchar *sm_realloc(uint size);
  uchar *annotation_realloc(uint size);
  ushort *append_tmp_buffer(uint size);
  bool getblob(uval_t ind, void *p, uval_t sz);
  bool getstr(qstring *out, ushort index);
  ushort read2(void);
  uint32 read4(void);
  uchar read1(void);
  void readData(void *data, uint32 size);
  void skipData(uint32 size);
  const uchar *get_annotation(uval_t node, uint *plen);
  bool sm_getinfo(const insn_t &insn, SMinfo *pinf);
  uchar *annot_elm(uchar *ptr, uint32 *psize, uchar is_array=0);
  uchar *annotation(uchar *p, uint32 *psize);
  segment_t *getMySeg(ea_t ea, segment_t *seg = nullptr);
  bool sm_chkargs(uchar **pptr, uint32 *pDopSize, ushort cnt);
  int sm_load(ushort declcnt, uint32 *pDopSize);
  NORETURN void loader_failure_bad_attr_decl_size(attr_parent_kind_t apk) const;
  int CmpString(ushort index1, ushort index2);
  int cmpDscrString(ushort index1, uchar met, ushort index2, uchar self);
  ushort xtrnDscrSearch(ushort name, uchar met);
  void mark_strange_name(ea_t ea) const;
  void xtrnRef(ea_t ea, const const_desc_t &opis) const;
  void xtrnRef_dscr(ea_t ea, const_desc_t *opis, uchar met=0);
  void deltry(uint bg, uint ic, uint ui, const const_desc_t &pco);
  segment_t *_add_seg(int caller);
  void resizeLocVars(void) const;
  const char *CopyAttrToFile(const char *astr, uint32 size, ushort id);
  inline int strstrpos(const char *s1, const char *s2)
  {
    s2 = strstr(s1, s2);
    return s2 == nullptr ? -1 : s2 - s1;
  }
  bool is_valid_string_index(ushort index) const;
  uchar LoadUtf8(ushort index, const_desc_t *co);
  void parse_const_desc(ushort index, const_desc_t *co);
  uchar CheckSignature(ushort index, attr_parent_kind_t apk);

  void ResW_init(void);
  void ResW_newbase(void);
  uchar ResW_oldbase(void);
  void ResW_validate(uint32 *Flags, const ushort *pend);
  uint32 upgrade_ResW(uint32 opstr);
  void ResW_free(void);

  size_t make_locvar_cmt(qstring *buf, const insn_t &insn);
  int32 print_loader_messages(char str[MAXSTR], const char *cmt, outctx_t *ctx);

  void copy_const_to_opnd(op_t &x, const const_desc_t &co) const;
  int LoadIndex(insn_t &insn);
  int ConstLoad(insn_t &insn, CIC_param ctype);
  int ana(insn_t *_insn);

  void print_constant(
        qstrvec_t *out,
        const const_desc_t &cd,
        ushort index,
        bool strip_tags=false) const;
};
extern int data_id;
#endif

