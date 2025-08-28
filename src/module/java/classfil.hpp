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

#ifndef _CLASSFIL_HPP_
#define _CLASSFIL_HPP_
//
// Java File definition
//
#define MAGICNUMBER     0xCAFEBABE    // magic number

// Oracle's Java Virtual Machine implementation in JDK release 1.0.2
// supports class file format versions 45.0 through 45.3 inclusive. JDK
// releases 1.1.* support class file format versions in the range 45.0
// through 45.65535 inclusive. For k >= 2, JDK release 1.k supports class
// file format versions in the range 45.0 through 44+k.0 inclusive.

#define JDK_1_02_MINOR     2     // (45.2) JDK1.0
#define JDK_1_1_MINOR      3     // (45.3) JDK1.1
#define JDK_MIN_MAJOR     45     // JDK1.0/JDK1.1
#define JDK_MAX_MAJOR     (44+11)// JDK1.11(JDK11): Java11?
//
// access_flags
//
#define ACC_PUBLIC        0x0001  // Visible to everyone
#define ACC_PRIVATE       0x0002  // Visible only to the defning
#define ACC_PROTECTED     0x0004  // Visible to subclasses
#define ACC_STATIC        0x0008  // Variable or method is static Method
#define ACC_FINAL         0x0010  // No further subclassing, overriding, or
                                  // assignment after initialization
#define ACC_SYNCHRONIZED  0x0020  // Wrap use in monitor lock
#define ACC_SUPER         0x0020  // invoke by the 'invokespecial' (deprecated)
#define ACC_VOLATILE      0x0040  // Can't cache (field)
#define ACC_BRIDGE        0x0040  // Bridge method (java5) (generate by compiler)
#define ACC_TRANSIENT     0x0080  // Not to be written or read by
                                  // a persistent object manager (field)
#define ACC_VARARGS       0x0080  // Method with variable number of arguments
                                  // (java5)
#define ACC_NATIVE        0x0100  // Implemented in a language otherthan Java
#define ACC_INTERFACE     0x0200  // Is an interface
#define ACC_ABSTRACT      0x0400  // No body provided
#define ACC_STRICT        0x0800  // Delcared strictfp (floating-point mode
                                  // is FP-strict) (method)
#define ACC_SYNTHETIC     0x1000  // Generate by compiler (no present in source)
                                  // (java2)
#define ACC_ANNOTATION    0x2000  // only with INTERFACE (annotated) (java5)
#define ACC_ENUM          0x4000  // Class or BaseClass is enum (java5)
/* jdk1.5
ACC_BRIDGE, ACC_VARARGS, ACC_STRICT, ACC_SYNTHETIC, ACC_ANNOTATION, ACC_ENUM
*/
//
#define ACC_ACCESS_MASK (ACC_PUBLIC | ACC_PROTECTED | ACC_PRIVATE)
#define _ACC_ALLTP      (ACC_ACCESS_MASK | ACC_STATIC | ACC_FINAL \
                       | ACC_SYNTHETIC)

#define ACC_THIS_MASK   (ACC_PUBLIC | ACC_FINAL | ACC_SUPER | ACC_INTERFACE \
                       | ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION \
                       | ACC_ENUM)
#define ACC_NESTED_MASK (_ACC_ALLTP | ACC_INTERFACE | ACC_ABSTRACT \
                       | ACC_ANNOTATION | ACC_ENUM)
#define ACC_FIELD_MASK  (_ACC_ALLTP | ACC_VOLATILE | ACC_TRANSIENT | ACC_ENUM)
#define ACC_METHOD_MASK (_ACC_ALLTP | ACC_SYNCHRONIZED | ACC_BRIDGE \
                       | ACC_VARARGS | ACC_NATIVE | ACC_ABSTRACT    \
                       | ACC_STRICT)

//-----------------------------------
// base type
//
#define j_byte          'B'     // signed byte
#define j_char          'C'     // unicode character
#define j_double        'D'     // double precision IEEE float
#define j_float         'F'     // single precision IEEE foat
#define j_int           'I'     // integer
#define j_long          'J'     // long integer
#define j_class         'L'     // <fullclassname>;
                                // ... an object of the given class
#define j_endclass        ';'     // tag for end of classname
#define j_parm_list_start '('     // start of function parameters
#define j_parm_list_end   ')'     // end of function parameters
#define j_short           'S'     // signed short
#define j_bool            'Z'     // boolean true or false
#define j_array           '['     // <length><field sig> ... array
#define j_void_ret        'V'     // return no value
//----------- make as mnemonic in new version
#define j_field_dlm     '.'     // use as field delimiter
#define j_clspath_dlm   '/'     // use as classpath delimeter
//#define j_legacy_dlm    '$'     // mechanically generated & legacy systems
//----------- jdk1.5
// signatures
#define j_typeref       'T'     // TypeVariable signature
#define j_throw         '^'     // ThrowsSignature start
#define j_wild          '*'     // wildcard(unknown) <?>
#define j_wild_e        '+'     // wildcard(extends) <+name>
#define j_wild_s        '-'     // wildcard(super)   <-name>
// type  declaration syntax: <name:typesign>
// iface declaration syntax: <name:typesign:ifacesign>
// super declaration syntax:
#define j_sign          '<'     // formal type parameter start
#define j_endsign       '>'     // formal type parameter end
#define j_tag           ':'     // delimeter

// annotation tags
// possible const types is: B, C, D, F, I, J, S, Z, [
// additional annotation tag types
#define j_string        's'     // constant string
#define j_enumconst     'e'     // enum (type + name)
#define j_class_ret     'c'     // return type descriptor
#define j_annotation    '@'     // nested annotation

//-----------------------------------------------------
// Constant Pool
//
#define CONSTANT_Asciz                 1  // jdk1.1
#define CONSTANT_Utf8                  1  // jdk1.x
#define CONSTANT_Unicode               2  // unused if jdk >= 1.0 (45.2)
#define CONSTANT_Integer               3
#define CONSTANT_Float                 4
#define CONSTANT_Long                  5
#define CONSTANT_Double                6
#define CONSTANT_Class                 7
#define CONSTANT_String                8
#define CONSTANT_Fieldref              9
#define CONSTANT_Methodref            10
#define CONSTANT_InterfaceMethodref   11
#define CONSTANT_NameAndType          12
#define MAX_CONSTANT_TYPE     12 // Check in Loader flag
// JDK1.7 (JSR 292) -- dynamic for multiLanguage (python, ruby, etc)
#define CONSTANT_MethodHandle         15
#define CONSTANT_MethodType           16
// JDK 1.8
#define CONSTANT_InvokeDynamic        18
#define CONSTANT_LAST CONSTANT_InvokeDynamic

// JVM_CONSTANT_MethodHandle subtypes
#define JVM_REF_getField          1
#define JVM_REF_getStatic         2
#define JVM_REF_putField          3
#define JVM_REF_putStatic         4
#define JVM_REF_invokeVirtual     5
#define JVM_REF_invokeStatic      6
#define JVM_REF_invokeSpecial     7
#define JVM_REF_newInvokeSpecial  8
#define JVM_REF_invokeInterface   9

//-------------------------------------------------------
// Array Type (newarray)
//
#define T_BOOLEAN       4
#define T_CHAR          5
#define T_FLOAT         6
#define T_DOUBLE        7
#define T_BYTE          8
#define T_SHORT         9
#define T_INT           10
#define T_LONG          11

//--------------------------------------------------------
// StackMapTable records
#define JDK_SMF_MAJOR_MIN     50  // minimal version (previous: CLDC)
// offset for record 0 == offset, else previous_offset + offset + 1;
#define SMT_SAME_FRM_S0_min    0  // off_dt=type, loc=prev, stack=empty
#define SMT_SAME_FRM_S0_max   63
#define SMT_SAME_FRM_S1_min   64  // off_dt=type-min, loc=prev, stack=1
#define SMT_SAME_FRM_S1_max  127  //   [ + verinf[1] ]
#define SMT_reserved_min     128
#define SMT_reserved_max     246
#define SMT_SAME_FRM_S1      247  // loc=prev, stack=1 [ + off_d, verinf[1] ]
#define SMT_CHOP_FRM_S0_min  248  // stack=empty, loc=prev-((max+1)-type)
#define SMT_CHOP_FRM_S0_max  250  //   [ + off_dt ]
#define SMT_SAME_FRM_S0      251  // stack=empty, loca=prev [ + off_dt ]
#define SMT_APPE_FRM_S0_min  252  // stack=empty, loc+=prev+(type-(min-1))
#define SMT_APPE_FRM_S0_max  254  //  [ + off_dt, { verinf[n] } ]
#define SMT_FULL_FRAME       255  // see below
/*
struct sm_full
{
  u1 type;       // for JDK16 or higher
  u2 off_dt;     // for StackMap - off
  u2 nloc;
  verinf locs[nlocks];
  u2 nstk;
  verinf stks[nstk];
};
*/
// Initial stack map frame: off=0, stack is free, max_locals, max_stack;

// StackMap types
enum SM_ITEM // u1
{
  ITEM_Bogus = 0,   // unused (unknown type -- can't used directly)
  ITEM_Integer,
  ITEM_Float,
  ITEM_Double,
  ITEM_Long,
  ITEM_Null,
  ITEM_UnitializedThis,
  ITEM_Object,          // +pool_index
  ITEM_Uninitialized,   // +offset (u2)
  // additional for out
  ITEM_BADOBJECT,
  ITEM_CURCLASS
};

#endif
