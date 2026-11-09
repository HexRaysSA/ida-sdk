// Borland-compatible Microsoft.Net definitions
// Only the most important headers are declared
//
// The second half of the file contains the structures saved in the
// database

#ifndef __MYCOR_H
#define __MYCOR_H
#pragma pack(push, 1)

#ifdef __NT__
typedef wchar_t wchar;
#else
typedef wchar16_t wchar;
#endif

#ifndef _WINDOWS_         // define some MS Windows symbols if <windows.h> is not included

#define __int8 char
#ifdef __GNUC__
#define __cdecl
#define __stdcall
#endif

typedef int32 HRESULT;
#define S_OK 0
#define S_FALSE (!S_OK)
#define E_FAIL 0x80004005
#define SEVERITY_SUCCESS          0
#define SEVERITY_ERROR            1
#define FACILITY_URT              19
#define MAKE_HRESULT(sev,fac,code) \
    ((HRESULT) (((uint32)(sev)<<31) | ((uint32)(fac)<<16) | ((uint32)(code))) )
#define EMAKEHR(val)              MAKE_HRESULT(SEVERITY_ERROR, FACILITY_URT, val)
#define SMAKEHR(val)              MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_URT, val)
#define META_E_BAD_SIGNATURE      EMAKEHR(0x1192) // Bad binary signature
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#undef UNALIGNED
#define UNALIGNED

typedef uchar BYTE;
typedef short SHORT;
typedef ushort USHORT;
typedef ushort WORD;
typedef uint32 ULONG;
typedef uint ULONG32;
typedef uint32 DWORD;
typedef uint64 DWORD64;
typedef void *LPVOID;
typedef bool BOOL;
typedef int32 LONG;
typedef uint32 ULONG;
typedef int64 LONGLONG;
typedef uint64 ULONGLONG;
typedef wchar *LPWSTR;
typedef const void *UVCP_CONSTANT;
typedef ULONG &LPCWSTR;
typedef float FLOAT;
typedef double DOUBLE;
typedef uint32 SCODE;
typedef void *BSTR; // http://msdn.microsoft.com/en-us/library/windows/desktop/ms221069(v=vs.85).aspx
typedef void *PVOID;
typedef int INT;
typedef uint UINT;
typedef char CHAR;
typedef DOUBLE DATE;

class IUnknown;

struct OSINFO
{
  DWORD   dwOSPlatformId;
  DWORD   dwOSMajorVersion;
  DWORD   dwOSMinorVersion;
};

struct ASSEMBLYMETADATA
{
  USHORT  usMajorVersion;
  USHORT  usMinorVersion;
  USHORT  usBuildNumber;
  USHORT  usRevisionNumber;
  LPWSTR  szLocale;
  ULONG   cbLocale;
  DWORD   *rdwProcessor;
  ULONG   ulProcessor;
  OSINFO  *rOS;
  ULONG   ulOS;
};

struct GUID
{
  uint32 Data1;
  ushort Data2;
  ushort Data3;
  uchar  Data4[8];
};

struct IMAGE_DATA_DIRECTORY
{
  uint32 VirtualAddress;
  uint32 Size;
};

// http://msdn.microsoft.com/en-us/library/windows/desktop/ms221061(v=vs.85).aspx
typedef struct tagDEC
{
  USHORT wReserved;
  union
  {
    struct
    {
      BYTE scale;
      BYTE sign;
    };
    USHORT signscale;
  };
  ULONG Hi32;
  union
  {
    struct
    {
      ULONG Lo32;
      ULONG Mid32;
    };
    ULONGLONG Lo64;
  };
} DECIMAL;


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms221223(v=vs.85).aspx
typedef union tagCY
{
  struct
  {
    unsigned long Lo;
    long          Hi;
  };
  LONGLONG int64;
} CY, CURRENCY;


typedef struct tagSAFEARRAYBOUND
{
  ULONG cElements;
  LONG  lLbound;
} SAFEARRAYBOUND, *LPSAFEARRAYBOUND;


// http://msdn.microsoft.com/en-us/library/9ec8025b-4763-4526-ab45-390c5d8b3b1e(VS.85)
typedef struct tagSAFEARRAY
{
  USHORT         cDims;
  USHORT         fFeatures;
  ULONG          cbElements;
  ULONG          cLocks;
  PVOID          pvData;
  SAFEARRAYBOUND rgsabound[1];
} SAFEARRAY, *LPSAFEARRAY;


// http://msdn.microsoft.com/en-us/library/windows/desktop/ms221627(v=vs.85).aspx
typedef unsigned short VARTYPE;
typedef uint16 VARIANT_BOOL;
typedef uint16 _VARIANT_BOOL;
struct IRecordInfo;
typedef struct tagVARIANT
{
  union
  {
    struct
    {
      VARTYPE vt;
      WORD    wReserved1;
      WORD    wReserved2;
      WORD    wReserved3;
      union
      {
        LONGLONG            llVal;
        LONG                lVal;
        BYTE                bVal;
        SHORT               iVal;
        FLOAT               fltVal;
        DOUBLE              dblVal;
        VARIANT_BOOL        boolVal;
        /* _VARIANT_BOOL       bool; */
        SCODE               scode;
        CY                  cyVal;
        DATE                date;
        BSTR                bstrVal;
        IUnknown            *punkVal;
        /* IDispatch           *pdispVal; */
        SAFEARRAY           *parray;
        BYTE                *pbVal;
        SHORT               *piVal;
        LONG                *plVal;
        LONGLONG            *pllVal;
        FLOAT               *pfltVal;
        DOUBLE              *pdblVal;
        VARIANT_BOOL        *pboolVal;
        /* _VARIANT_BOOL       *pbool; */
        SCODE               *pscode;
        CY                  *pcyVal;
        DATE                *pdate;
        BSTR                *pbstrVal;
        /* IUnknown            **ppunkVal; */
        /* IDispatch           **ppdispVal; */
        SAFEARRAY           **pparray;
        /* VARIANT             *pvarVal; */
        PVOID               byref;
        CHAR                cVal;
        USHORT              uiVal;
        ULONG               ulVal;
        ULONGLONG           ullVal;
        INT                 intVal;
        UINT                uintVal;
        DECIMAL             *pdecVal;
        CHAR                *pcVal;
        USHORT              *puiVal;
        ULONG               *pulVal;
        ULONGLONG           *pullVal;
        INT                 *pintVal;
        UINT                *puintVal;
        struct /*__tagBRECORD*/
        {
          PVOID       pvRecord;
          IRecordInfo *pRecInfo;
        } /* __VARIANT_NAME_4*/;
      } /* __VARIANT_NAME_3*/;
    } /* __VARIANT_NAME_2*/;
    DECIMAL decVal;
  };
} VARIANT, *LPVARIANT, VARIANTARG, *LPVARIANTARG;

#define VT_EMPTY 0x0000
#define VT_NULL 0x0001
#define VT_I2 0x0002
#define VT_I4 0x0003
#define VT_R4 0x0004
#define VT_R8 0x0005
#define VT_CY 0x0006
#define VT_DATE 0x0007
#define VT_BSTR 0x0008
#define VT_DISPATCH 0x0009
#define VT_ERROR 0x000A
#define VT_BOOL 0x000B
#define VT_VARIANT 0x000C
#define VT_UNKNOWN 0x000D
#define VT_DECIMAL 0x000E
#define VT_I1 0x0010
#define VT_UI1 0x0011
#define VT_UI2 0x0012
#define VT_UI4 0x0013
#define VT_I8 0x0014
#define VT_UI8 0x0015
#define VT_INT 0x0016
#define VT_UINT 0x0017
#define VT_VOID 0x0018
#define VT_HRESULT 0x0019
#define VT_PTR 0x001A
#define VT_SAFEARRAY 0x001B
#define VT_CARRAY 0x001C
#define VT_USERDEFINED 0x001D
#define VT_LPSTR 0x001E
#define VT_LPWSTR 0x001F
#define VT_RECORD 0x0024
#define VT_INT_PTR 0x0025
#define VT_UINT_PTR 0x0026
#define VT_ARRAY 0x2000
#define VT_BYREF 0x4000



#define VariantInit(v_ptr) (v_ptr)->vt = VT_EMPTY

inline HRESULT VariantClear(VARIANTARG *pVar)
{
  memset(pVar, 0, sizeof(VARIANT));
  return S_OK;
}


#define HRESULT_CODE(hr) ((hr) & 0xFFFF)
#define SCODE_CODE(sc)   ((sc) & 0xFFFF)


#define CLDB_S_TRUNCATION SMAKEHR(0x1106)
#define CLDB_E_TRUNCATION EMAKEHR(0x1106)


#endif // __UNIX__

#include "corhdr.h"
#include "cor.h"

//--------------------------------------------------------------------
//      what            netnode tag
#define CLITAG_MDA      0       // the assembly mda is here at index 0
#define CLITAG_MTK      1       // the scope mtk is here at index 0
#define CLITAG_STRUCT   'a'     // the structure itself is saved here
#define CLITAG_NAME     'b'     // char *name (deprecated for strings, see CLITAG_STRING)
                                // saved as blob
#define CLITAG_VALUE    'c'     // void *pval
#define CLITAG_SIG      'd'     // PCOR_SIGNATURE[]
#define CLITAG_OTHER    'e'     // mdToken others[]
//#define CLITAG_TITLE    'f'     // assembly title
//#define CLITAG_DESCR    'g'     // assembly description
//#define CLITAG_ALIAS    'h'     // assembly alias
#define CLITAG_PUBKEY   'i'     // public key blob
#define CLITAG_PINV     'k'     // pinvoke_info_t
#define CLITAG_PNAME    'l'     // name of pinvoke method
#define CLITAG_LAYOUT   'm'     // layout_info_t
#define CLITAG_OFFSETS  'n'     // COR_FIELD_OFFSET[]
#define CLITAG_CUST     'o'     // custom attribute blob
#define CLITAG_TOKEN    'p'     // ea: method, field, property, event token is here
#define CLITAG_CLASS    'q'     // ea: typedef token
#define CLITAG_STRING   'r'     // ea: address of string's bytes in .strings segment
#define CLITAG_CLASSEND 's'     // ea: typedef token
#define CLITAG_TRY      't'     // ea: try block start/cor_exception_info_t
#define CLITAG_BEND     'u'     // ea: block end
#define CLITAG_HASH     'v'     // hash
#define CLITAG_FRVA     'x'     // field rva
#define CLITAG_EXCEPTION 128    // exception blocks: several indexes

// enumeration blobs
// global enumerations have index 0
#define CLITAG_PARAMS      'A'
#define CLITAG_FIELDS      'B'
#define CLITAG_METHODS     'C'
#define CLITAG_EVENTS      'D'
#define CLITAG_PROPERTIES  'E'
#define CLITAG_INTERFACES  'F'
#define CLITAG_TYPEDEFS    'G'
#define CLITAG_TYPEREFS    'H'
#define CLITAG_TYPESPECS   'I'
#define CLITAG_USERSTRINGS 'J'
#define CLITAG_CUSTATTRS   'K'
#define CLITAG_MODULEREFS  'L'
#define CLITAG_MEMBERREFS  'M'  // 'N' shouldn't be used (as well as 'V')


struct param_info_t      // +name +value
{
  mdToken method;
  ULONG n;
  ULONG flags;
  DWORD deftype;
};

struct field_info_t      // +name +sig +value
{
  mdToken owner;
  ULONG flags;
  DWORD deftype;
  ea_t ea;
};

struct method_info_t     // +name +sig +params
{
  mdToken owner;
  DWORD flags;
  ULONG rva;            // ea later
  DWORD implflags;
  mdToken lvars;
  uint32 maxstack;
  uint32 methodflags;
};

struct pinvoke_info_t   // +pname
{
  DWORD mappingflags;
  mdToken dlltok;
};

struct property_info_t   // +name +sig +other_tokens +value
{
  mdToken owner;
  ULONG flags;
  DWORD deftype;
  mdToken setter, getter;
//  mdToken backing;    disappeared in Beta2
  ea_t ea;
};

struct event_info_t   // +name +other_tokens
{
  mdToken owner;
  ULONG flags;
  mdToken type;
  mdToken addon, removeon, fire;
  ea_t ea;
};

struct interfaceimpl_info_t
{
  mdToken inttok;
};

struct typedef_info_t    // +name +fields +methods +layout +offsets
{
  DWORD flags;
  mdToken super;
};

struct layout_info_t
{
  DWORD packsize;
  ULONG classsize;
  ULONG noffsets;
};

struct typeref_info_t    // +name
{
  mdToken scope;
};

struct moduleref_info_t  // +name
{
};

struct memberref_info_t  // +name +sig
{
  mdToken owner;
};

struct typespec_info_t   // +sig
{
};

struct userstring_info_t // +name
{
};

struct custattr_info_t   // +blob
{
  mdToken owner;
  mdToken type;
};

struct assembly_info_t   // +name +orig +title +desc +alias
{
  ULONG  hash;
  DWORD  flags;
  USHORT usMajorVersion;
  USHORT usMinorVersion;
  USHORT usRevisionNumber;
  USHORT usBuildNumber;
};

struct assemblyref_info_t   // +name +orig +hash
{
  DWORD  flags;
//  mdToken exeloc;
  USHORT usMajorVersion;
  USHORT usMinorVersion;
  USHORT usRevisionNumber;
  USHORT usBuildNumber;
};

struct file_info_t         // +name +hash
{
  DWORD flags;
};

struct comtype_info_t      // +name +descr
{
  ULONG flags;
  mdToken impl, type, exeloc;
};

struct cor_module_info_t     // +name
{
  mdToken mtk;
  GUID mid;
};

struct cor_exception_info_t
{
  ULONG flags;
  ULONG param;
};

struct longname_director_t
{
  char zero;
  uval_t node;
};
CASSERT(sizeof(longname_director_t) == 1 + sizeof(uval_t));

//------------------------------------------------------------------------
ea_t get_free_address(void);
void expand(ea_t ea);
void define_class(mdToken, const char *name, ea_t ea1, ea_t ea2);
mdToken define_method(mdToken method, const char *name, method_info_t &b, ea_t *ea);
void supset(ea_t idx, const void *body, int size, char tag);
ssize_t supstr(ea_t idx, char *buf, size_t bufsize, char tag);
void altset(ea_t idx, ea_t val, char tag);
void setblob(ea_t idx, const void *body, int size, char tag);
void save_name(ea_t idx, const qstring &name);
qstring retrieve_name(ea_t idx);
uint32 get_constant_element_type_raw_size(CorElementType type, uint32 chars);

bool load_metadata(const void *metadata, size_t metasize);

#pragma pack(pop)
#endif // define __MYCOR_H
