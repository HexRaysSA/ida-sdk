// Basic MS Windows types for non-Windows builds

#ifndef __WINTYPES_H
#define __WINTYPES_H
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
#define E_ABORT 0x80004004
#define SEVERITY_SUCCESS          0
#define SEVERITY_ERROR            1
#define MAKE_HRESULT(sev,fac,code) \
    ((HRESULT) (((uint32)(sev)<<31) | ((uint32)(fac)<<16) | ((uint32)(code))) )
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

struct GUID
{
  uint32 Data1;
  ushort Data2;
  ushort Data3;
  uchar  Data4[8];
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

#endif // _WINDOWS_

#pragma pack(pop)
#endif // define __WINTYPES_H
