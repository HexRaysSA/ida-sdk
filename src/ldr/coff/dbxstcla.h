#ifndef _H_DBXSTCLASS
#define _H_DBXSTCLASS
/*
 *      XCOFF STORAGE CLASSES AND STABSTRINGS DESIGNED SPECIFICALLY FOR DBX
 */
#define DBXMASK         0x80

#define C_GSYM          0x80    // Global variable.
#define C_LSYM          0x81    // Automatic variable allocated on stack.
#define C_PSYM          0x82    // Argument to subroutine allocated on stack.
#define C_RSYM          0x83    // Register variable.
#define C_RPSYM         0x84    // Argument to function or procedure stored in the register.
#define C_STSYM         0x85    // Statically allocated symbol.
#define C_TCSYM         0x86
#define C_BCOMM         0x87    // Beginning of common block.
#define C_ECOML         0x88    // Local member of common block.
#define C_ECOMM         0x89    // End of common block.
#define C_DECL          0x8c    // Declaration of object.
#define C_ENTRY         0x8d    // Alternate entry.
#define C_FUN           0x8e    // Function or procedure.
#define C_BSTAT         0x8f    // Beginning of static block.
#define C_ESTAT         0x90    // End of static block.

#define TP_ARRAY \
{\
  "int:t-1=r-1;-2147483648;2147483647",\
  "char:t-2=@s8;r-2;0;255",\
  "short:t-3=@s16;r-3;-32768;32767",\
  "long:t-4=-1",\
  "unsigned char:t-5=@s8;r-5;0;255",\
  "signed char:t-6=@s8;r-6;-128;127",\
  "unsigned short:t-7=@s16;r-7;0;65535",\
  "unsigned int:t-8=r-8;0;4294967295",\
  "unsigned:t-9=-8",\
  "unsigned long:t-10=-8",\
  "void:t-11=r-11;0;0",\
  "float:t-12=g-12;4",\
  "double:t-13=g-12;8",\
  "long double:t-14=g-12;10",\
  "integer:t-15=-1",\
  "boolean:t-16=efalse:0,true:1,",\
  "shortreal:t-17=g-12;4",\
  "real:t-18=g-12;8",\
  "stringptr:t-19=N-19",\
  "character:t-20=@s8;r-20;0;255",\
  "logical*1:t-21=@s8;r-21;0;255",\
  "logical*2:t-22=@s16;r-22;0;65535",\
  "logical*4:t-23=r-23;0;4294967295",\
  "logical:t-24=-23",\
  "complex:t-25=c-25;8",\
  "double complex:t-26=c-25;16",\
  "integer*1:t-27=-6",\
  "integer*2:t-28=-3",\
  "integer*4:t-29=-1",\
  "wchar:t-30=@s16;r-30;0;65535" \
}

#define TP_INT          (-1)
#define TP_CHAR         (-2)
#define TP_SHORT        (-3)
#define TP_LONG         (-4)
#define TP_UCHAR        (-5)
#define TP_SCHAR        (-6)
#define TP_USHORT       (-7)
#define TP_UINT         (-8)
#define TP_UNSIGNED     (-9)
#define TP_ULONG        (-10)
#define TP_VOID         (-11)
#define TP_FLOAT        (-12)
#define TP_DOUBLE       (-13)
#define TP_LDOUBLE      (-14)
#define TP_PASINT       (-15)
#define TP_BOOL         (-16)
#define TP_SHRTREAL     (-17)
#define TP_REAL         (-18)
#define TP_STRNGPTR     (-19)
#define TP_FCHAR        (-20)
#define TP_LOGICAL1     (-21)
#define TP_LOGICAL2     (-22)
#define TP_LOGICAL4     (-23)
#define TP_LOGICAL      (-24)
#define TP_COMPLEX      (-25)
#define TP_DCOMPLEX     (-26)
#define TP_INTEGER1     (-27)
#define TP_INTEGER2     (-28)
#define TP_INTEGER4     (-29)
#define TP_WCHAR        (-30)

#define TP_NTYPES       30

#endif /* _H_DBXSTCLASS */
