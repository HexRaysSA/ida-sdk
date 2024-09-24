//
// Wrapper for Windows ToolHelp library: enumerate processes/modules
//
// PSAPI.DLL:                                 NT, 2K, XP/2K3
// KERNEL32.DLL (ToolHelp functions): 9X, ME,     2K, XP/2K3
//? add NT support

#ifndef __TOOLHELP_HPP__
#define __TOOLHELP_HPP__

#ifdef __NT__

#include <windows.h>
#include <Tlhelp32.h>

#include <dbghelp.h>

#include <segment.hpp>

#ifdef UNICODE
#define LookupPrivilegeValue_Name "LookupPrivilegeValueW"
#else
#define LookupPrivilegeValue_Name "LookupPrivilegeValueA"
#endif

#ifndef TH32CS_SNAPNOHEAPS
#  define TH32CS_SNAPNOHEAPS    0x0
#endif

//--------------------------------------------------------------------------
enum wow64_state_t
{
  WOW64_NONE = -2, // unknown yet
  WOW64_BAD = -1,
  WOW64_NO = 0,
  WOW64_YES = 1,
};

wow64_state_t check_wow64_handle(HANDLE handle);
wow64_state_t check_wow64_pid(int pid);

//--------------------------------------------------------------------------
class win_version_t
{
public:
  win_version_t();
  const OSVERSIONINFO &get_info() const { return OSVersionInfo; }
  bool ok() { return ver_ok; }
  bool is_NT()
  {
    return ok() && OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT;
  }
  bool is_strictly_xp()  // Is strictly XP (32bit)?
  {
    return ok()
        && is_NT()
        && OSVersionInfo.dwMajorVersion == 5
        && OSVersionInfo.dwMinorVersion == 1;
  }
  bool is_DW32()
  {
    return ok() && OSVersionInfo.dwPlatformId == 3;
  }
  bool is_2K()           // Is at least Win2K?
  {
    return ok() && OSVersionInfo.dwMajorVersion >= 5;
  }
  bool is_64bitOS()
  {
#ifndef __X86__
    return true;
#else
    return is_64bit_os;
#endif
  }

  //--------------------------------------------------------------------------
  // GetProcessDEPPolicy() is broken for Win8, Win8.1, Win10:
  // always set *lpPermanent == CL register, if not permanently policy.
  // https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/05683d76-3c8a-49de-91e3-9d7ab8492f39/getprocessdeppolicy-does-not-set-the-correct-value-to-lppermanent?forum=windowscompatibility
  bool is_GetProcessDEPPolicy_broken()
  {
    return ok()
        && ((OSVersionInfo.dwMajorVersion == 10 && OSVersionInfo.dwMinorVersion == 0)   // Windows 10
         || (OSVersionInfo.dwMajorVersion ==  6 && OSVersionInfo.dwMinorVersion == 3)   // Windows 8.1
         || (OSVersionInfo.dwMajorVersion ==  6 && OSVersionInfo.dwMinorVersion == 2)); // Windows 8
  }

private:
  OSVERSIONINFO OSVersionInfo;
  bool ver_ok;
#ifdef __X86__
  bool is_64bit_os;
#endif
};

//--------------------------------------------------------------------------
//-V:win_tool_help_t:730 Not all members of a class are initialized inside the constructor
class win_tool_help_t
{
public:
  win_tool_help_t();
  bool ok() { return inited; }
  bool use_debug_break_process();
  bool debug_break_process(HANDLE process_handle);
  bool use_debug_detach_process();
  bool debug_detach_process(pid_t pid);

private:
  // function prototypes
  typedef HANDLE WINAPI CreateToolhelp32Snapshot_t(DWORD dwFlags, DWORD th32ProcessID);
  typedef BOOL   WINAPI Process32First_t(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
  typedef BOOL   WINAPI Process32Next_t(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
  typedef BOOL   WINAPI Module32First_t(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
  typedef BOOL   WINAPI Module32Next_t(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
  typedef BOOL   WINAPI DebugActiveProcessStop_t(DWORD dwProcessID);
  typedef BOOL   WINAPI DebugBreakProcess_t(HANDLE Process);
  typedef BOOL   WINAPI CloseToolhelp32Snapshot_t(HANDLE hSnapshot);

  // functions pointers
  CreateToolhelp32Snapshot_t *_CreateToolhelp32Snapshot;
  Process32First_t           *_Process32First;
  Process32Next_t            *_Process32Next;
  Module32First_t            *_Module32First;
  Module32Next_t             *_Module32Next;
  DebugActiveProcessStop_t   *_DebugActiveProcessStop;
  DebugBreakProcess_t        *_DebugBreakProcess;

  bool inited;
  bool use_debug_break;

  friend class toolhelp_snapshot_t;
  friend class process_snapshot_t;
  friend class module_snapshot_t;
};

//--------------------------------------------------------------------------
class toolhelp_snapshot_t
{
public:
  inline toolhelp_snapshot_t(win_tool_help_t *tool);
  inline ~toolhelp_snapshot_t();
  inline bool ok();
  inline bool open(uint32 flags, pid_t pid);
  inline void close();
  inline uint32 last_err();
protected:
  bool seterr();        // always returns 'false' for convenience
  win_tool_help_t *t;
  HANDLE h;
  uint32 last_error;
};

//--------------------------------------------------------------------------
class process_snapshot_t: public toolhelp_snapshot_t
{
public:
  inline process_snapshot_t(win_tool_help_t *tool);
  inline bool first(uint32 flags, LPPROCESSENTRY32 lppe);
  inline bool next(LPPROCESSENTRY32 lppe);
};

//--------------------------------------------------------------------------
class module_snapshot_t: public toolhelp_snapshot_t
{
public:
  inline module_snapshot_t(win_tool_help_t *tool);
  inline bool first(uint32 flags, pid_t pid, LPMODULEENTRY32 lpme);
  inline bool next(LPMODULEENTRY32 lpme);
};

//--------------------------------------------------------------------------
inline bool win_tool_help_t::use_debug_break_process()
{
  return use_debug_break && _DebugBreakProcess != nullptr;
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::debug_break_process(HANDLE process_handle)
{
  return process_handle != INVALID_HANDLE_VALUE && _DebugBreakProcess(process_handle);
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::use_debug_detach_process()
{
  return _DebugActiveProcessStop != nullptr;
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::debug_detach_process(pid_t pid)
{
  return _DebugActiveProcessStop != nullptr && _DebugActiveProcessStop(pid);
}

//--------------------------------------------------------------------------
inline process_snapshot_t::process_snapshot_t(win_tool_help_t *tool)
  : toolhelp_snapshot_t(tool)
{
}

//--------------------------------------------------------------------------
inline bool process_snapshot_t::first(uint32 flags, LPPROCESSENTRY32 lppe)
{
  open(TH32CS_SNAPPROCESS | flags, 0);
  lppe->dwSize = sizeof(PROCESSENTRY32);
  if ( ok() && t->_Process32First(h, lppe) )
  {
    // ignore "System Process" (ID==0)
    return lppe->th32ProcessID != 0 || next(lppe);
  }
  return seterr();
}

//--------------------------------------------------------------------------
inline bool process_snapshot_t::next(LPPROCESSENTRY32 lppe)
{
  while ( ok() )
  {
    if ( !t->_Process32Next(h, lppe) )
      break;
    // ignore "System Process" (ID==0)
    if ( lppe->th32ProcessID != 0 )
      return true;
  }
  return seterr();
}

//--------------------------------------------------------------------------
inline module_snapshot_t::module_snapshot_t(win_tool_help_t *tool)
  : toolhelp_snapshot_t(tool)
{
}

//--------------------------------------------------------------------------
inline bool module_snapshot_t::first(uint32 flags, pid_t pid, LPMODULEENTRY32 lpme)
{
  wow64_state_t state = check_wow64_pid(pid);
  flags |= state == WOW64_YES ? TH32CS_SNAPMODULE32 : 0;
  if ( !open(TH32CS_SNAPMODULE | flags, pid) )
    return false;
  lpme->dwSize = sizeof(MODULEENTRY32);
  if ( t->_Module32First(h, lpme) )
    return true;
  return seterr();
}

//--------------------------------------------------------------------------
inline bool module_snapshot_t::next(LPMODULEENTRY32 lpme)
{
  if ( ok() )
    return false;
  if ( t->_Module32Next(h, lpme) )
    return true;
  seterr();
  return false;
}

//--------------------------------------------------------------------------
inline toolhelp_snapshot_t::toolhelp_snapshot_t(win_tool_help_t *tool)
  : t(tool), h(INVALID_HANDLE_VALUE), last_error(0)
{
}

//--------------------------------------------------------------------------
inline toolhelp_snapshot_t::~toolhelp_snapshot_t()
{
  close();
}

//--------------------------------------------------------------------------
inline bool toolhelp_snapshot_t::ok()
{
  return h != INVALID_HANDLE_VALUE;
}

//--------------------------------------------------------------------------
// // always returns 'false' for convenience
inline bool toolhelp_snapshot_t::seterr()
{
  last_error = GetLastError();
  return false;
}

//--------------------------------------------------------------------------
// // always returns 'false' for convenience
inline uint32 toolhelp_snapshot_t::last_err()
{
  return last_error;
}

//--------------------------------------------------------------------------
inline bool toolhelp_snapshot_t::open(uint32 flags, pid_t pid)
{
  if ( !t->ok() )
    return false;
  close();
  for ( int cnt=0; cnt < 5; cnt++ )
  {
    h = t->_CreateToolhelp32Snapshot(flags, pid);
    if ( h != INVALID_HANDLE_VALUE )
      return true;
    seterr();
    // MSDN: If the function fails with ERROR_BAD_LENGTH, retry
    //       the function until it succeeds.
    if ( last_err() != ERROR_BAD_LENGTH
      || (flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) == 0 )
    {
      break;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
inline void toolhelp_snapshot_t::close()
{
  if ( t->ok() && h != INVALID_HANDLE_VALUE )
    CloseHandle(h);
}

//--------------------------------------------------------------------------
// convert Windows protection modes to IDA protection modes
inline uchar win_prot_to_ida_perm(DWORD protection)
{
  uchar perm = 0;

  if ( protection & PAGE_READONLY )
    perm |= SEGPERM_READ;
  if ( protection & PAGE_READWRITE )
    perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_WRITECOPY )
    perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_EXECUTE )
    perm |= SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READ )
    perm |= SEGPERM_READ | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READWRITE )
    perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_WRITECOPY )
    perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;

  return perm;
}

#endif // __NT__
#endif // __TOOLHELP_HPP__
