/*
 *      Interactive disassembler (IDA).
 *      ALL RIGHTS RESERVED.
 *      Copyright (c) 1990-2024 Hex-Rays
 *
 *
 *      This file defines the functions prototypes that are exported by bochsys.dll
 *
 *
 */

#ifndef __BOCHSYS_DLL__
#define __BOCHSYS_DLL__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define BX_CALLCONV WINAPI

typedef wchar_t wchar16_t;
//CASSERT(sizeof(wchar16_t) == 2);

//--------------------------------------------------------------------------
// These functions are similar to MS Windows functions. Please refer
// to the SDK documentation for more information on how to use them.
extern FARPROC        WINAPI BxGetProcAddress(HMODULE hMod, LPCSTR ProcName);
extern HMODULE        WINAPI BxGetModuleHandleA(LPCSTR ModuleFileName);
extern DWORD          WINAPI BxGetModuleFileNameA(HINSTANCE hModule, LPCSTR lpFilename, DWORD nSize);
extern DWORD          WINAPI BxGetModuleFileNameW(HINSTANCE hModule, LPWSTR lpFilename, DWORD nSize);
extern HMODULE        WINAPI BxLoadLibraryA(LPCTSTR lpFileName);
extern LPVOID         WINAPI BxVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
extern BOOL           WINAPI BxVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
extern DWORD          WINAPI BxExitProcess(DWORD);
extern DWORD          WINAPI BxGetTickCount(VOID);
extern BOOL           WINAPI BxVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
extern DWORD          WINAPI BxWin32SetLastError(DWORD ErrorCode);
extern DWORD          WINAPI BxWin32GetLastError(VOID);
extern LPCSTR         WINAPI BxWin32GetCommandLineA(VOID);
extern LPWSTR         WINAPI BxWin32GetCommandLineW(VOID);
extern LPCSTR         WINAPI BxWin32GetEnvironmentStringsA(VOID);
extern LPWSTR         WINAPI BxWin32GetEnvironmentStringsW(VOID);
extern LPVOID         WINAPI BxWin32TlsGetValue(DWORD dwTlsIndex);
extern BOOL           WINAPI BxWin32TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);
extern BOOL           WINAPI BxWin32TlsFree(DWORD dwTlsIndex);
extern DWORD          WINAPI BxWin32TlsAlloc(VOID);
extern DWORD          WINAPI BxWin32FlsAlloc(VOID);
extern char *         WINAPI BxStrCpyA(char *Dst, char *Src);
extern wchar16_t *    WINAPI BxStrCpyW(wchar16_t *Dst, wchar16_t *Src);
extern char *         WINAPI BxStrCatA(char *Dst, char *Src);
extern wchar16_t *    WINAPI BxStrCatW(wchar16_t *Dst, wchar16_t *Src);

//--------------------------------------------------------------------------
// Installs an exception handler. Only one exception handler
// can be installed at one time. You need to uninstall one
// before reinstalling another.
// These two functions will return non-zero on success.
typedef DWORD (*PEXCEPTION_HANDLER)(PEXCEPTION_RECORD, struct _EXCEPTION_REGISTRATION_RECORD *, PCONTEXT,struct _EXCEPTION_REGISTRATION_RECORD **);

extern DWORD   WINAPI BxInstallSEH(PEXCEPTION_HANDLER Handler);
extern DWORD   WINAPI BxUninstallSEH();

#endif
