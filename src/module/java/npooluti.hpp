#ifndef _NPOOLUTI_HPP_
#define _NPOOLUTI_HPP_
#include "upgrade.hpp"

const char *constant_type_to_str(uchar ctype);
void *myAlloc(uint size);

NORETURN void errtrunc(void);

//-------------------------------------------------------------------------
struct bootstrap_method_def_t
{
  ushort method_ref;
  qvector<ushort> args;

  bootstrap_method_def_t() : method_ref(0) {}
};

nodeidx_t bootstrap_methods_get_node(bool assert=true, bool can_create=false);
nodeidx_t bootstrap_methods_get_count();
void bootstrap_methods_set_count(nodeidx_t cnt);
bool bootstrap_methods_get_method(
        bootstrap_method_def_t *out,
        nodeidx_t idx);

//-----------------------------------------------------------------------------
void make_NameChars(bool on_load);

enum namechar_op_t
{
  ncop_disable,
  ncop_enable,
  ncop_enable_without_parens,
};

//-------------------------------------------------------------------------
void op_NameChars(namechar_op_t op);

//------------------
static void inline endLoad_NameChar(void)
{
  op_NameChars(ncop_enable_without_parens);     // end load base (remove '()')
}

//------------------
static void inline enableExt_NameChar(void)
{
  op_NameChars(ncop_enable);  //j_field_dlm;  // (for searches)
}

//------------------
static void inline disableExt_NameChar(void)
{
  op_NameChars(ncop_disable);
}

//-----------------------------------------------------------------------
struct _STROP_
{
  ushort size;
  ushort flags;
};

// new flags at VER15
#define _OP_NOSIGN    0x0001  // not signature (always +_OP_NODSCR)
#define _OP_METSIGN   0x0002  // method signature: <:>(...)ret
#define _OP_CLSSIGN   0x0004  // class signature:  <:>super{iface}
//#define _OP_          0x0008
//#define _OP_          0x0010
#define _OP_JSMRES_   0x0020  // name reserved in jasmin (asm support)
// end of new flags
#define _OP_ONECLS    0x0040  // descriptor has class reference
#define _OP_FULLNM    0x0080  // field have '.', '/' or [ => no FM name
#define _OP_NOFNM     0x0100  // can only descriptor. Not name
#define _OP_VALPOS    0x0200  // has posit for call descriptor
#define _OP_NODSCR    0x0400  // not descriptor
//#define _OP_NULL_     0x0800  // has simbols 0
//#define _OP_NAT0_     0x1000  // has simbols disabled in Xlat-table
//#define _OP_WIDE_     0x2000  // has simbols >= 0x100
#define _OP_BADFIRST  0x1000  // first char in string is badStart for ident
#define _OP_UNICHARS  0x2000  // have valid unicode characters
#define _OP_UTF8_     0x4000  //  Utf8 String
#define _OP_EXTSYM_   0x8000    // contain (!qisprint(english) && !isJavaIdent())
// ver12 bits
// #define _OP_UNICODE_  0x8000  //  Unicode String  (removed? from standard)
// for jasmin reserved words checking
#define _OP_NOWORD  uint32(0xFFFF & ~(_OP_NOSIGN|_OP_ONECLS|_OP_NODSCR|_OP_UTF8_))

// low bits used as temporary in VER12
         // _OP_NULL_ | _OP_NAT0_ | _OP_WIDE_

CASSERT((UPG12_EXTMASK >> 16) == 0x7000
     && (UPG12_CLRMASK >> 16) == 0xF03F
     && (UPG12_BADMASK >> 16) == 0x8000
     && (UPG12_EXTSET  >> 16) == _OP_EXTSYM_);

//-----------------------------------------------------------------------------
#endif
