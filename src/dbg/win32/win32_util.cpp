#include <windows.h>
#include <pro.h>
#include "winbase_debmod.h"
#include "win32_util.hpp"

#ifndef __X86__
typedef BOOL WINAPI IsWow64Process_t(HANDLE, PBOOL);
static IsWow64Process_t *_IsWow64Process = nullptr;
#endif

//--------------------------------------------------------------------------
//lint -esym(818,handle) could be pointer to const
wow64_state_t check_wow64_handle(HANDLE handle)
{
#ifdef __X86__
  qnotused(handle);
#else
  if ( _IsWow64Process == nullptr )
  {
    HMODULE k32 = GetModuleHandle(kernel32_dll);
    *(FARPROC*)&_IsWow64Process = GetProcAddress(k32, TEXT("IsWow64Process"));
    if ( _IsWow64Process == nullptr )
      return WOW64_NONE; // unknown
  }
  BOOL bIsWow64 = FALSE;
  if ( _IsWow64Process(handle, &bIsWow64) && bIsWow64 != 0 )
    return WOW64_YES;
#endif
  return WOW64_NO;
}

//--------------------------------------------------------------------------
wow64_state_t check_wow64_pid(int pid)
{
  wow64_state_t r = WOW64_BAD; // assume pid is bad
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if ( h != nullptr )
  {
    r = check_wow64_handle(h);
    CloseHandle(h);
  }
  return r;
}

//--------------------------------------------------------------------------
MSC_DIAG_OFF(4996) // GetVersionEx was declared deprecated
win_version_t::win_version_t()
{
  OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVersionInfo);
  ver_ok = GetVersionEx(&OSVersionInfo) != 0;   //lint !e2586 is deprecated
#ifdef __X86__
  is_64bit_os = false;
  if ( OSVersionInfo.dwMajorVersion > 5
    || OSVersionInfo.dwMajorVersion == 5 && OSVersionInfo.dwMinorVersion >= 1 )
  {
    is_64bit_os = check_wow64_handle(GetCurrentProcess()) > 0;
  }
#endif
}
MSC_DIAG_ON(4996)

//--------------------------------------------------------------------------
win_tool_help_t::win_tool_help_t()
{
  use_debug_break = qgetenv("IDA_DEBUGBREAKPROCESS");
  HMODULE kern_handle = GetModuleHandle(kernel32_dll);
  *(FARPROC*)&_DebugActiveProcessStop = GetProcAddress(kern_handle, TEXT("DebugActiveProcessStop"));
  *(FARPROC*)&_DebugBreakProcess      = GetProcAddress(kern_handle, TEXT("DebugBreakProcess"));

  // find the needed functions
  *(FARPROC*)&_CreateToolhelp32Snapshot = GetProcAddress(kern_handle, TEXT("CreateToolhelp32Snapshot"));
  *(FARPROC*)&_Process32First           = GetProcAddress(kern_handle, TEXT("Process32First"));
  *(FARPROC*)&_Process32Next            = GetProcAddress(kern_handle, TEXT("Process32Next"));
  *(FARPROC*)&_Module32First            = GetProcAddress(kern_handle, TEXT("Module32First"));
  *(FARPROC*)&_Module32Next             = GetProcAddress(kern_handle, TEXT("Module32Next"));

  inited = _CreateToolhelp32Snapshot != nullptr
        && _Process32First != nullptr
        && _Process32Next != nullptr
        && _Module32First != nullptr
        && _Module32Next != nullptr;
}
