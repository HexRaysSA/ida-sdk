// Compatibility stubs for old Windows versions.
//
// When building with /MT (static CRT), the modern MSVC CRT calls several
// Vista+ kernel32 APIs that don't exist on older Windows. We intercept the
// __imp__ symbols (via crt_oldwin_compat_stubs.asm) and redirect to these
// stubs, which try the real API at runtime and fall back to an older
// equivalent if unavailable.
//
// This allows compiling with the current MSVC toolset while producing
// binaries that run on older Windows versions but still use native APIs
// when available.

#ifdef __XPCOMPAT__

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#pragma warning(disable: 4273) // inconsistent dll linkage

//--------------------------------------------------------------------------
// InitializeCriticalSectionEx (Vista+)
// Fallback: InitializeCriticalSectionAndSpinCount (ignores dwFlags)

typedef BOOL (WINAPI *InitializeCriticalSectionEx_t)(LPCRITICAL_SECTION, DWORD, DWORD);

extern "C" BOOL WINAPI CompatInitializeCriticalSectionEx(
        LPCRITICAL_SECTION cs,
        DWORD spinCount,
        DWORD dwFlags)
{
  static InitializeCriticalSectionEx_t pfn = (InitializeCriticalSectionEx_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "InitializeCriticalSectionEx");
  if ( pfn != nullptr )
    return pfn(cs, spinCount, dwFlags);
  return InitializeCriticalSectionAndSpinCount(cs, spinCount);
}

//--------------------------------------------------------------------------
// Fiber Local Storage (Vista+)
// Fallback: Thread Local Storage (ignores FLS callback)

typedef DWORD (WINAPI *FlsAlloc_t)(PFLS_CALLBACK_FUNCTION);
typedef BOOL (WINAPI *FlsFree_t)(DWORD);
typedef PVOID (WINAPI *FlsGetValue_t)(DWORD);
typedef BOOL (WINAPI *FlsSetValue_t)(DWORD, PVOID);

extern "C" DWORD WINAPI CompatFlsAlloc(PFLS_CALLBACK_FUNCTION cb)
{
  static FlsAlloc_t pfn = (FlsAlloc_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "FlsAlloc");
  if ( pfn != nullptr )
    return pfn(cb);
  return TlsAlloc();
}

extern "C" BOOL WINAPI CompatFlsFree(DWORD idx)
{
  static FlsFree_t pfn = (FlsFree_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "FlsFree");
  if ( pfn != nullptr )
    return pfn(idx);
  return TlsFree(idx);
}

extern "C" PVOID WINAPI CompatFlsGetValue(DWORD idx)
{
  static FlsGetValue_t pfn = (FlsGetValue_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "FlsGetValue");
  if ( pfn != nullptr )
    return pfn(idx);
  return TlsGetValue(idx);
}

extern "C" BOOL WINAPI CompatFlsSetValue(DWORD idx, PVOID data)
{
  static FlsSetValue_t pfn = (FlsSetValue_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "FlsSetValue");
  if ( pfn != nullptr )
    return pfn(idx, data);
  return TlsSetValue(idx, data);
}

//--------------------------------------------------------------------------
// DecodePointer / EncodePointer (XP SP2+)
// Fallback: identity (no-op encoding)

typedef PVOID (WINAPI *DecodePointer_t)(PVOID);
typedef PVOID (WINAPI *EncodePointer_t)(PVOID);

extern "C" PVOID WINAPI CompatDecodePointer(PVOID Ptr)
{
  static DecodePointer_t pfn = (DecodePointer_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "DecodePointer");
  if ( pfn != nullptr )
    return pfn(Ptr);
  return Ptr;
}

extern "C" PVOID WINAPI CompatEncodePointer(PVOID Ptr)
{
  static EncodePointer_t pfn = (EncodePointer_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "EncodePointer");
  if ( pfn != nullptr )
    return pfn(Ptr);
  return Ptr;
}

//--------------------------------------------------------------------------
// InitializeSListHead (XP SP2+)
// Fallback: zero the header

typedef void (WINAPI *InitializeSListHead_t)(PSLIST_HEADER);

extern "C" void WINAPI CompatInitializeSListHead(PSLIST_HEADER ListHead)
{
  static InitializeSListHead_t pfn = (InitializeSListHead_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "InitializeSListHead");
  if ( pfn != nullptr )
    return pfn(ListHead);
  ListHead->Alignment = 0;
}

//--------------------------------------------------------------------------
// GetModuleHandleExW (XP SP1+)
// Fallback: GetModuleHandleW (ignores flags and ref-counting)

typedef BOOL (WINAPI *GetModuleHandleExW_t)(DWORD, LPCWSTR, HMODULE *);

extern "C" BOOL WINAPI CompatGetModuleHandleExW(
        DWORD dwFlags,
        LPCWSTR lpModuleName,
        HMODULE *phModule)
{
  static GetModuleHandleExW_t pfn = (GetModuleHandleExW_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "GetModuleHandleExW");
  if ( pfn != nullptr )
    return pfn(dwFlags, lpModuleName, phModule);
  if ( phModule == nullptr )
    return FALSE;
  HMODULE h = GetModuleHandleW(
        (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) ? nullptr : lpModuleName);
  *phModule = h;
  return h != nullptr;
}

//--------------------------------------------------------------------------
// SetFilePointerEx (XP SP1+)
// Fallback: SetFilePointer with 64-bit split

typedef BOOL (WINAPI *SetFilePointerEx_t)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);

extern "C" BOOL WINAPI CompatSetFilePointerEx(
        HANDLE hFile,
        LARGE_INTEGER liDistanceToMove,
        PLARGE_INTEGER lpNewFilePointer,
        DWORD dwMoveMethod)
{
  static SetFilePointerEx_t pfn = (SetFilePointerEx_t)
      GetProcAddress(GetModuleHandleA("kernel32"), "SetFilePointerEx");
  if ( pfn != nullptr )
    return pfn(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
  LONG high = liDistanceToMove.HighPart;
  DWORD low = SetFilePointer(hFile, liDistanceToMove.LowPart, &high, dwMoveMethod);
  if ( low == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR )
    return FALSE;
  if ( lpNewFilePointer != nullptr )
  {
    lpNewFilePointer->LowPart = low;
    lpNewFilePointer->HighPart = high;
  }
  return TRUE;
}

//--------------------------------------------------------------------------
// WSAPoll (Vista+)
// Fallback: select()

#define COMPAT_POLLIN   0x0100
#define COMPAT_POLLOUT  0x0010
#define COMPAT_POLLERR  0x0001
struct compat_pollfd
{
  SOCKET fd;
  SHORT events;
  SHORT revents;
};

typedef int (WSAAPI *WSAPoll_t)(compat_pollfd *, unsigned long, int);

static int WSAAPI FallbackWSAPoll(
        compat_pollfd *fds,
        unsigned long nfds,
        int timeout_ms)
{
  fd_set read_fds, write_fds, except_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_ZERO(&except_fds);
  for ( unsigned long i = 0; i < nfds; i++ )
  {
    if ( fds[i].events & COMPAT_POLLIN )
      FD_SET(fds[i].fd, &read_fds);
    if ( fds[i].events & COMPAT_POLLOUT )
      FD_SET(fds[i].fd, &write_fds);
    FD_SET(fds[i].fd, &except_fds);
  }
  struct timeval tv;
  struct timeval *ptv = nullptr;
  if ( timeout_ms >= 0 )
  {
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ptv = &tv;
  }
  // on Windows the first parameter to select() is ignored
  int result = ::select(0, &read_fds, &write_fds, &except_fds, ptv);
  if ( result == SOCKET_ERROR )
    return -1;
  int count = 0;
  for ( unsigned long i = 0; i < nfds; i++ )
  {
    fds[i].revents = 0;
    if ( FD_ISSET(fds[i].fd, &read_fds) )
      fds[i].revents |= COMPAT_POLLIN;
    if ( FD_ISSET(fds[i].fd, &write_fds) )
      fds[i].revents |= COMPAT_POLLOUT;
    if ( FD_ISSET(fds[i].fd, &except_fds) )
      fds[i].revents |= COMPAT_POLLERR;
    if ( fds[i].revents != 0 )
      count++;
  }
  return count;
}

extern "C" int WSAAPI CompatWSAPoll(
        compat_pollfd *fds,
        unsigned long nfds,
        int timeout_ms)
{
  static WSAPoll_t pfn = (WSAPoll_t)
      GetProcAddress(GetModuleHandleA("ws2_32"), "WSAPoll");
  if ( pfn != nullptr )
    return pfn(fds, nfds, timeout_ms);
  return FallbackWSAPoll(fds, nfds, timeout_ms);
}

//--------------------------------------------------------------------------
// RegDeleteTreeA (Vista+)
// Fallback: SHDeleteKeyA from shlwapi.dll (Win2000+)

typedef LSTATUS (APIENTRY *RegDeleteTreeA_t)(HKEY, LPCSTR);

extern "C" LSTATUS APIENTRY CompatRegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey)
{
  static RegDeleteTreeA_t pfn = (RegDeleteTreeA_t)
      GetProcAddress(GetModuleHandleA("advapi32"), "RegDeleteTreeA");
  if ( pfn != nullptr )
    return pfn(hKey, lpSubKey);
  return SHDeleteKeyA(hKey, lpSubKey);
}

#endif // __XPCOMPAT__
