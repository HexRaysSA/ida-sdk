//
//
//      This file contains win32 specific implementations of win32_debmod class
//
//

#include <diskio.hpp>
#include "win32_rpc.h"
#include "win32_undoc.h"

#include "dbg_pe_hlp.cpp"

struct impfunc_t
{
  const char *name;
  void *fptr;
};
#define IMPFUNC(x) { TEXT(#x), &x }

//lint -esym(843,ntdll) -esym(844,ntdll) could be const
static HMODULE ntdll = nullptr;
static NtSystemDebugControl_t  *NtSystemDebugControl;
static NtLoadDriver_t          *NtLoadDriver;
static NtUnloadDriver_t        *NtUnloadDriver;
static RtlAdjustPrivilege_t    *RtlAdjustPrivilege;
static NtCreateFile_t          *NtCreateFile;
static NtDeviceIoControlFile_t *NtDeviceIoControlFile;

static const impfunc_t ntfuncs[] =
{
  IMPFUNC(NtSystemDebugControl),
  IMPFUNC(NtLoadDriver),
  IMPFUNC(NtUnloadDriver),
  IMPFUNC(RtlAdjustPrivilege),
  IMPFUNC(NtCreateFile),
  IMPFUNC(NtDeviceIoControlFile),
};

// To read MSRs, we use a local kernel debugger driver provided by Microsoft.
//lint -esym(843,DriverHandle,DriverPath,DriverName) could be const
//lint -esym(844,DriverHandle) could be pointing to const
static HANDLE DriverHandle = nullptr;
static UNICODE_STRING DriverPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\kldbgdrv");
static UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"\\Device\\kldbgdrv");

//--------------------------------------------------------------------------
// PE COMMON HELPER FUNCTIONS
#define lread myread     // since we can't use loader_failure()
inline void myread(linput_t *li, void *buf, size_t size)
{
  int bytes_read = qlread(li, buf, size);
  if ( bytes_read != size )
  {
    int saved_code = errno;
    const char *errmsg = qerrstr();
    uint64 pos = qltell(li) - bytes_read;
    static const char *const format =
      "Read error: %s\n"
      "(file position 0x%" FMT_64 "X, wanted 0x%" FMT_Z "X bytes, read 0x%X)";

    error(format,
      saved_code ? errmsg : "read past end of file",
      pos,
      size,
      bytes_read);
  }
}

#include "../../ldr/pe/common.cpp"

#define GetMappedFileName_Name "GetMappedFileNameW"
#define GetModuleFileNameEx_Name "GetModuleFileNameExW"

// function prototypes
typedef DWORD (WINAPI *GetMappedFileName_t)(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI *GetModuleFileNameEx_t)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

// functions pointers
//lint -esym(843,_GetMappedFileName,_GetModuleFileNameEx) could be const
static GetMappedFileName_t _GetMappedFileName = nullptr;
static GetModuleFileNameEx_t _GetModuleFileNameEx = nullptr;

// dynamic linking information for PSAPI functions
//lint -esym(843,hPSAPI) -esym(844,hPSAPI) could be const
static HMODULE hPSAPI = nullptr;

// dw32 support
//lint -esym(843,system_teb_size) could be const
static DWORD system_teb_size = MEMORY_PAGE_SIZE;

//--------------------------------------------------------------------------
LPVOID win32_debmod_t::correct_exe_image_base(LPVOID base)
{
  return base;
}

//--------------------------------------------------------------------------
eanat_t win32_debmod_t::s0tops(eanat_t ea)
{
  return ea;
}

//--------------------------------------------------------------------------
eanat_t win32_debmod_t::pstos0(eanat_t ea)
{
  return ea;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::prepare_to_stop_process(debug_event_t *, const threads_t &)
{
  return true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::disable_hwbpts()
{
  for ( page_bpts_t::iterator p = page_bpts.begin(); p != page_bpts.end(); ++p )
    dbg_enable_page_bpt(p, false);
  return true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::enable_hwbpts()
{
  for ( page_bpts_t::iterator p = page_bpts.begin(); p != page_bpts.end(); ++p )
    dbg_enable_page_bpt(p, true);
  return true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::may_write(ea_t /*ea*/)
{
  return true;
}

//--------------------------------------------------------------------------
int win32_debmod_t::describe_stack_segment(
        thid_t tid,
        images_t &thr_ranges,
        images_t &cls_ranges,
        const _NT_TIB &tib,
        const char *pref)       // "x64" for x64 part of wow64 processes
{
  int cnt = 1;
  char name[MAXSTR];
  asize_t size = ptr_to_ea(tib.StackBase) - ptr_to_ea(tib.StackLimit);
  qsnprintf(name, sizeof(name), "%sStack[%08X]", pref, tid);
  image_info_t ii_stack(this, ptr_to_ea(tib.StackLimit), size, name);
  thr_ranges.insert(std::make_pair(ii_stack.base, ii_stack));
  ii_stack.name = "STACK";
  cls_ranges.insert(std::make_pair(ii_stack.base, ii_stack));
  // verify a Stack PAGE_GUARD page exists
  ea_t ea_guard = ii_stack.base - MEMORY_PAGE_SIZE;
  MEMORY_BASIC_INFORMATION MemoryBasicInformation;
  if ( VirtualQueryEx(process_handle, (LPCVOID)(size_t)ea_guard,
                &MemoryBasicInformation, sizeof(MemoryBasicInformation)) )
  {
    if ( MemoryBasicInformation.Protect & PAGE_GUARD ) // a Stack PAGE_GUARD exists
    {
      qsnprintf(name, sizeof(name), "%sStack_PAGE_GUARD[%08X]", pref, tid);
      image_info_t ii_guard(this, ea_guard, MEMORY_PAGE_SIZE, name);
      thr_ranges.insert(std::make_pair(ii_guard.base, ii_guard));
      ii_guard.name = "STACK";
      cls_ranges.insert(std::make_pair(ii_guard.base, ii_guard));
      cnt++;
    }
  }
  return cnt;
}

//--------------------------------------------------------------------------
int win32_debmod_t::add_thread_ranges(
        thid_t tid,
        images_t &thr_ranges,
        images_t &cls_ranges)
{
  thread_info_t *ti = threads.get(tid);
  if ( ti == nullptr )
    return 0;

  // This structure is specific to NT, but stack related records are Win9X compatible
  _NT_TIB tib;
  ea_t ea_tib = ptr_to_ea(ti->lpThreadLocalBase);
  if ( _read_memory(ea_tib, &tib, sizeof(tib)) != sizeof(tib) ) // read the TIB
    return 0;

  // additional test: we verify that TIB->Self contains the TIB's linear address
  if ( ptr_to_ea(tib.Self) != ea_tib )
    return false;

  // add TIB range
  char name[MAXSTR];
  qsnprintf(name, sizeof(name), "TIB[%08X]", tid);
  // we suppose the whole page is reserved for the TIB
  image_info_t ii_tib(this, ea_tib, system_teb_size, name);
  thr_ranges.insert(std::make_pair(ii_tib.base, ii_tib));

  int cnt = 0;
  const char *pref = "";
  if ( check_wow64_process() == WOW64_YES )
  {
    // Note: This works for Windows versions <= 8.1
    // The offset of the 32-bit TEB address within the 64-bit TEB is 0.
    // This can be used to directly access the 32-bit TEB of a WOW64 thread
    ea_t wow64_tib_ea = *(uint32*)&tib;
    struct _NT_TIB32
    {
      DWORD ExceptionList;
      DWORD StackBase;
      DWORD StackLimit;
      DWORD SubSystemTib;
      DWORD FiberData;
      DWORD ArbitraryUserPointer;
      DWORD Self;
    };
    _NT_TIB32 tib32;
    if ( _read_memory(wow64_tib_ea, &tib32, sizeof(tib32)) == sizeof(tib32) )
    {
      _NT_TIB tib2;
      tib2.StackBase = (PVOID)(eanat_t)tib32.StackBase;
      tib2.StackLimit = (PVOID)(eanat_t)tib32.StackLimit;
      cnt += describe_stack_segment(tid, thr_ranges, cls_ranges, tib2, pref);
    }
    pref = "x64";
  }

  // add stack range
  cnt += describe_stack_segment(tid, thr_ranges, cls_ranges, tib, pref);
  return cnt;
}

//--------------------------------------------------------------------------
// Get PE header
// In: ea=DLL imagebase, nh=buffer to keep the answer
//     child==true:ea is an address in the child process
//     child==false:ea is an address in the the debugger itself
// Returns: offset to the headers, BADADDR means failure
ea_t win32_debmod_t::get_pe_header(eanat_t ea, peheader_t *nh)
{
  uint32 offset = 0;
  uint32 magic;
  if ( _read_memory(ea, &magic, sizeof(magic)) != sizeof(magic) )
    return BADADDR;
  if ( ushort(magic) == MC2('M','Z') )
  {
    if ( _read_memory(ea+PE_PTROFF, &offset, sizeof(offset)) != sizeof(offset) )
      return BADADDR;
  }
  peheader64_t pe64;
  if ( _read_memory(ea+offset, &pe64, sizeof(pe64)) != sizeof(pe64) )
    return BADADDR;
  if ( !pe64_to_pe(*nh, pe64, true, true) )
    return BADADDR;
  if ( nh->signature != PEEXE_ID )
    return BADADDR;
  return offset;
}

//--------------------------------------------------------------------------
// calculate dll image size
// since we could not find anything nice, we just look
// at the beginning of the DLL module in the memory and extract
// correct value from the file header
uint32 win32_debmod_t::calc_imagesize(eanat_t base)
{
  peheader_t nh;
  ea_t peoff = get_pe_header(base, &nh);
  if ( peoff == BADADDR )
    return 0;
  return nh.imagesize;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::create_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        bool is_gui,
        bool hide_window,
        PROCESS_INFORMATION *ProcessInformation)
{
  linput_t *li = open_linput(path, false);
  if ( li == nullptr )
    return false;
  pe_loader_t pl;
  pl.read_header(li, true);
  close_linput(li);

#ifndef __EA64__
  if ( pl.pe.is_pe_plus() )
  {
    dwarning("AUTOHIDE NONE\nPlease use ida64 to debug 64-bit applications");
    SetLastError(ERROR_NOT_SUPPORTED);
    return false;
  }
#endif

#ifdef __X86__
  if ( pl.pe.is_pe_plus() )
  {
    static const char server_name[] = "win64_remote64.exe";
    if ( ask_yn(ASKBTN_YES,
                "AUTOHIDE REGISTRY\nHIDECANCEL\n"
                "Debugging 64-bit applications is only possible with the %s server.\n"
                "Launch it now?",
                server_name) == ASKBTN_YES )
    {
      do
      {
        // Switch to the remote win32 debugger
        if ( !load_debugger("win32_stub", true) )
        {
          warning("Failed to switch to the remote windows debugger!");
          break;
        }

        // Form the server path
        char server_exe[QMAXPATH];
        qmakepath(server_exe, sizeof(server_exe), idadir(nullptr), server_name, nullptr);

        // Try to launch the server
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if ( hide_window )
        {
          si.dwFlags |= STARTF_USESHOWWINDOW;
          si.wShowWindow = SW_HIDE; /* SW_FORCEMINIMIZE ? */
        }
        if ( !::CreateProcess(server_exe, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi) )
        {
          warning("Failed to run the 64-bit remote server!");
          break;
        }

        // Set the remote debugging options: localhost
        set_remote_debugger("localhost", "", -1);

        // Notify the user
        info("Debugging server has been started, please try debugging the program again.");
      } while ( false );
    }
    SetLastError(ERROR_NOT_SUPPORTED);
    return false;
  }
#endif // __X86__

  // Empty directory means our directory
  if ( startdir != nullptr && startdir[0] == '\0' )
    startdir = nullptr;

  // Args passed as empty string?
  if ( args != nullptr && args[0] == '\0' )
    args = nullptr;

  launch_process_params_t lpp;
  lpp.flags |= LP_TRACE | LP_PATH_WITH_ARGS;
  if ( !is_gui )
    lpp.flags |= LP_NEW_CONSOLE;
  if ( hide_window )
    lpp.flags |= LP_HIDE_WINDOW;

  lpp.path = path;
  lpp.args = args;
  lpp.startdir = startdir;
  lpp.info = ProcessInformation;

  qstring envs_str;
  if ( envs != nullptr )
  {
    if ( !envs->merge )
      lpp.flags |= LP_REPLACE_ENV;

    form_envs(&envs_str, envs);
  }
  lpp.env = envs_str.begin();

  qstring errbuf;
  if ( launch_process(lpp, &errbuf) == nullptr )
  {
    dwarning("AUTOHIDE NONE\n%s", errbuf.c_str());
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
void term_win32_subsystem(void)
{
  if ( hPSAPI != nullptr )
  {
    FreeLibrary(hPSAPI);
    hPSAPI = nullptr;
  }
  if ( DriverHandle != nullptr )
  {
    CloseHandle(DriverHandle);
    DriverHandle = nullptr;
    NtUnloadDriver(&DriverPath);
  }
}

//--------------------------------------------------------------------------
void init_win32_subsystem(void)
{
  ntdll = GetModuleHandle(TEXT("ntdll.dll"));
  if ( ntdll != nullptr )
  {
    for ( int i=0; i < qnumber(ntfuncs); i++ )
      *(FARPROC*)ntfuncs[i].fptr = GetProcAddress(ntdll, ntfuncs[i].name);
  }

  // load the library
  hPSAPI = LoadLibrary(TEXT("psapi.dll"));
  if ( hPSAPI != nullptr )
  {
    // find the needed functions
    *(FARPROC*)&_GetMappedFileName = GetProcAddress(hPSAPI, TEXT(GetMappedFileName_Name));
    *(FARPROC*)&_GetModuleFileNameEx = GetProcAddress(hPSAPI, TEXT(GetModuleFileNameEx_Name));
    if ( _GetMappedFileName == nullptr )
    {
      FreeLibrary(hPSAPI);
      hPSAPI = nullptr;
    }
  }
}

//--------------------------------------------------------------------------
bool win32_debmod_t::can_access(ea_t addr)
{
  char dummy;
  return access_memory(addr, &dummy, 1, false, false) == 1;
}

//--------------------------------------------------------------------------
// return the address of all names exported by a DLL in 'ni'
// if 'exported_name' is given, only the address of this exported name will be returned in 'ni'
bool win32_debmod_t::get_pe_exports_from_path(
        const char *path,
        linput_t *li,
        ea_t imagebase,
        name_info_t &ni,
        const char *exported_name) const
{
  // prepare nice name prefix for exported functions names
  char prefix[MAXSTR];
  qstrncpy(prefix, qbasename(path), sizeof(prefix));
  char *ptr = strrchr(prefix, '.');
  if ( ptr != nullptr )
    *ptr = '\0';
  qstrlwr(prefix);

  pe_loader_t pl;
  if ( !pl.read_header(li) )
    return false;

  struct export_reader_t : public pe_export_visitor_t
  {
    const ea_helper_t &_eah;
    const char *prefix;
    ea_t imagebase;
    name_info_t &ni;
    const char *exported_name;
    export_reader_t(const ea_helper_t &_eh, const char *pfx, ea_t base, name_info_t &_ni, const char *exname)
      : _eah(_eh), prefix(pfx), imagebase(base), ni(_ni), exported_name(exname) {}
    int idaapi visit_export(uint32 rva, uint32 ord, const char *name, const char *)
    {
      ea_t fulladdr = trunc_uval(imagebase + rva);
      if ( exported_name != nullptr )
      {
        if ( strcmp(exported_name, name) == 0 )
        {
          ni.addrs.push_back(fulladdr);
          return 1;
        }
      }
      else
      {
        qstring n2;
        if ( name[0] == '\0' )
          n2.sprnt("%s_%u", prefix, ord);
        else
          n2.sprnt("%s_%s", prefix, name);
        ni.addrs.push_back(fulladdr);
        ni.names.push_back(n2.extract());
      }
      return 0;
    }

    DEFINE_EA_HELPER_FUNCS(_eah)
  };
  export_reader_t er(eah(), prefix, imagebase, ni, exported_name);
  return pl.process_exports(li, er) >= 0;
}

//--------------------------------------------------------------------------
// return the address of all names exported by a DLL in 'ni'
// if 'exported_name' is given, only the address of this exported name will be returned in 'ni'
bool win32_debmod_t::get_dll_exports(
        const images_t &loaded_dlls,
        ea_t imagebase,
        name_info_t &ni,
        const char *exported_name)
{
  char prefix[MAXSTR];
  images_t::const_iterator p = loaded_dlls.find(imagebase);
  if ( p == loaded_dlls.end() )
  {
    dwarning("get_dll_exports: can't find dll name for imagebase %a", imagebase);
    return false;
  }
  char dname[MAXSTR];
  const char *dllname = p->second.name.c_str();
  qstrncpy(dname, dllname, sizeof(dname));
  if ( !is_64bit_app() )
    replace_system32(dname, MAXSTR);
  linput_t *li = open_linput(dname, false);
  if ( li == nullptr )
  {
    // sysWOW64: ntdll32.dll does not exist but there is a file called ntdll.dll
    if ( stricmp(qbasename(dllname), "ntdll32.dll") != 0 )
      return false;
    if ( qisabspath(dllname) )
    {
      qstrncpy(prefix, dllname, sizeof(prefix));
      char *fname = qbasename(prefix);
      qstrncpy(fname, "ntdll.dll", sizeof(prefix)-(fname-prefix));
      dllname = prefix;
    }
    else
    {
#ifdef __X86__
      // TODO: On X86 there might by file redirection active on a X64 host
      // Therefore we will load on such system always 32 bit DLL, as we can
      // access 64 bit one without disabling the redirection
      dllname = "C:\\Windows\\System32\\ntdll.dll";
#else
#ifndef __EA64__
      dllname = "C:\\Windows\\SysWOW64\\ntdll.dll";
#else
      dllname = is_64bit_app() ? "C:\\Windows\\System32\\ntdll.dll" : "C:\\Windows\\SysWOW64\\ntdll.dll";
#endif
#endif
    }
    li = open_linput(dllname, false);
    if ( li == nullptr )
      return false;
  }

  bool ok = get_pe_exports_from_path(dllname, li, imagebase, ni, exported_name);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
// get name from export directory in PE image in debugged process
bool win32_debmod_t::get_pe_export_name_from_process(
        eanat_t imagebase,
        char *name,
        size_t namesize)
{
  peheader_t pe;
  ea_t peoff = get_pe_header(imagebase, &pe);
  if ( peoff != BADADDR && pe.expdir.rva != 0 )
  {
    eanat_t ea = imagebase + pe.expdir.rva;
    peexpdir_t expdir;
    if ( _read_memory(ea, &expdir, sizeof(expdir)) == sizeof(expdir) )
    {
      ea = imagebase + expdir.dllname;
      name[0] = '\0';
      _read_memory(ea, name, namesize);  // don't check the return code because
      // we might have read more than necessary
      if ( name[0] != '\0' )
        return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// Read/write a model specific register using the driver provided by WinDbg.
// The following requirements are imposed by this code:
//      - debugger module should be run with admin privileges
//      - System must be loaded with /debug switch (use bcdedit.exe to turn it on)
//      - Windbg local kernel debugging should be used at least once
// This code is based on a sample kindly provided by Alex Ionescu.
int win32_debmod_t::kldbgdrv_access_msr(SYSDBG_MSR *msr, bool write)
{
  NTSTATUS code;
  IO_STATUS_BLOCK IoStatusBlock;
  if ( DriverHandle == nullptr )
  {
    //
    // Acquire 'load driver' privilege
    //
    BOOLEAN Old;
    code = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &Old);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to acquire 'load driver' privilege, please run as admin!\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // And need this for the driver to accept our commands
    // Additionally, system must be booted in /DEBUG mode
    //
    code = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &Old);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to acquire 'debug' privilege, is system booted in /debug mode?\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // Now load the driver
    //
    code = NtLoadDriver(&DriverPath);
    if ( FAILED(code) && code != STATUS_IMAGE_ALREADY_LOADED )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to load 'kldbgdrv', please use local kernel debugging at least once!\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // Open a handle to it
    //
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &DriverName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    code = NtCreateFile(&DriverHandle,
                        GENERIC_READ | GENERIC_WRITE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        nullptr,
                        FILE_ATTRIBUTE_NORMAL,
                        0,
                        FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE,
                        nullptr,
                        0);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to open 'kldbgdrv'\n"
               "Error: %s\n", winerr(code));
      return code;
    }
  }

  //
  // Package the input parameters into the private structure
  //
  KLDD_DATA_DEBUG_CONTROL KldDebugCommand;
  KldDebugCommand.Command = write ? SysDbgWriteMsr : SysDbgReadMsr;
  KldDebugCommand.InputBuffer = msr;
  KldDebugCommand.InputBufferLength = sizeof(*msr);

  //
  // Send the request -- output isn't packaged, just specify directly the buffer
  //
  code = NtDeviceIoControlFile(DriverHandle,
                               nullptr,
                               nullptr,
                               nullptr,
                               &IoStatusBlock,
                               KLDD_CODE_DEBUG_CONTROL,
                               &KldDebugCommand,
                               sizeof(KldDebugCommand),
                               msr,
                               sizeof(*msr));
  if ( FAILED(code) )
  {
    dwarning("AUTOHIDE NONE\n"
             "Failed to access model specific register, is system booted in /debug mode?\n"
             "Error: %s\n", winerr(code));
    return code;
  }

  // all ok!
  return code;
}

//--------------------------------------------------------------------------
int win32_debmod_t::rdmsr(int reg, uint64 *value)
{
  SYSDBG_MSR msr;
  msr.reg = reg;
  msr.value = 0; // shut up the compiler

  NTSTATUS code;
  if ( NtSystemDebugControl == nullptr )
    code = STATUS_NOT_IMPLEMENTED;
  else
    code = NtSystemDebugControl(SysDbgReadMsr, &msr, sizeof(msr), &msr, sizeof(msr), 0);

  // if failed to read it with SystemDebugControl, try the driver
  if ( FAILED(code) )
    code = kldbgdrv_access_msr(&msr, false);

  if ( SUCCEEDED(code) )
    *value = msr.value;
  return code;
}

//--------------------------------------------------------------------------
int win32_debmod_t::wrmsr(int reg, uint64 value)
{
  SYSDBG_MSR msr;
  msr.reg = reg;
  msr.value = value;

  NTSTATUS code;
  if ( NtSystemDebugControl == nullptr )
    code = STATUS_NOT_IMPLEMENTED;
  else
    code = NtSystemDebugControl(SysDbgWriteMsr, &msr, sizeof(msr), nullptr, 0, 0);

  // if failed to write it with SystemDebugControl, try the driver
  if ( FAILED(code) )
    code = kldbgdrv_access_msr(&msr, true);

  return code;
}
