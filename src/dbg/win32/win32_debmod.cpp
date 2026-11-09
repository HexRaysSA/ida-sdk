#include <windows.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <dbg.hpp>
#include <prodir.h>
#include <exehdr.h>
#include <kernwin.hpp>
#include <segment.hpp>
#include "win32_debmod.h"

//-------------------------------------------------------------------------
struct machine_thread_state_t
{
  ea_t __eax;
  ea_t __ebx;
  ea_t __ecx;
  ea_t __edx;
  ea_t __edi;
  ea_t __esi;
  ea_t __ebp;
  ea_t __esp;
  ea_t __eip;
#ifndef __X86__
  ea_t __r8;
  ea_t __r9;
  ea_t __r10;
  ea_t __r11;
  ea_t __r12;
  ea_t __r13;
  ea_t __r14;
  ea_t __r15;
#endif
  ea_t __eflags;
  ea_t __ss;
  ea_t __cs;
  ea_t __ds;
  ea_t __es;
  ea_t __fs;
  ea_t __gs;
};

//-------------------------------------------------------------------------
#define MMX_FPU_REG_DATA_SIZE 10
//lint -e754 local struct member '' not referenced
struct mmx_fpu_reg_t
{
  char __data[MMX_FPU_REG_DATA_SIZE];
  char __rsv[6];
};
CASSERT(sizeof(mmx_fpu_reg_t) == 16);

//-------------------------------------------------------------------------
struct xmm_reg_t
{
  char __data[16];
};
CASSERT(sizeof(xmm_reg_t) == 16);
//lint +e754

//-------------------------------------------------------------------------
struct machine_float_state_t
{
  mmx_fpu_reg_t __fpu_stmm[8];
  xmm_reg_t  __fpu_xmm[16];
  xmm_reg_t  __fpu_ymmh[16];

  uint32 __fpu_mxcsr;
  uint32 __fpu_fcw;
  uint32 __fpu_fsw;
  uint32 __fpu_ftw;
};

//--------------------------------------------------------------------------
struct regctx_t : public regctx_base_t
{
  win32_debmod_t &debmod;
  context_holder_t ctxh;
  machine_thread_state_t cpu;
  machine_float_state_t fpu;

  regctx_t(dynamic_register_set_t &_idaregs, win32_debmod_t &_debmod);
  virtual bool init() override;
  virtual bool load() override;
  virtual bool store() override;
};

//--------------------------------------------------------------------------
regctx_t::regctx_t(dynamic_register_set_t &_idaregs, win32_debmod_t &_debmod)
  : regctx_base_t(_idaregs), debmod(_debmod)
{
  memset(&cpu, 0, sizeof(cpu));
  memset(&fpu, 0, sizeof(fpu));

  idaregs.set_regclasses(x86_register_classes);
}

//--------------------------------------------------------------------------
//lint -esym(1762,regctx_t::init) could be made const
bool regctx_t::init()
{
  return (clsmask & X86_RC_ALL) != 0;
}

//--------------------------------------------------------------------------
bool regctx_t::load()
{
  return init() && debmod.get_thread_state(&ctxh, &cpu, &fpu, tid, clsmask);
}

//--------------------------------------------------------------------------
bool regctx_t::store()
{
  return debmod.set_thread_state(cpu, fpu, ctxh, tid, clsmask);
}

//--------------------------------------------------------------------------

#ifndef TH32CS_SNAPNOHEAPS
  #define TH32CS_SNAPNOHEAPS    0x0
#endif
#include "win32_debmod_impl.cpp"

typedef HANDLE WINAPI OpenThread_t(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
static OpenThread_t *_OpenThread = nullptr;
typedef HRESULT WINAPI GetThreadDescription_t(HANDLE hThread, PWSTR *threadDescription);
static GetThreadDescription_t *_GetThreadDescription = nullptr;

#ifndef __X86__
typedef BOOL WINAPI Wow64GetThreadContext_t(HANDLE hThread, PWOW64_CONTEXT lpContext);
typedef BOOL WINAPI Wow64SetThreadContext_t(HANDLE hThread, const WOW64_CONTEXT *lpContext);
typedef BOOL WINAPI Wow64GetThreadSelectorEntry_t(HANDLE hThread, DWORD dwSelector, PWOW64_LDT_ENTRY lpSelectorEntry);
static Wow64GetThreadContext_t *_Wow64GetThreadContext = nullptr;
static Wow64SetThreadContext_t *_Wow64SetThreadContext = nullptr;
static Wow64GetThreadSelectorEntry_t *_Wow64GetThreadSelectorEntry = nullptr;
#endif

// Older SDKs (such as the one used for the ..._opt_s debug servers)
// requires these defines
#ifndef XSTATE_MASK_AVX
#  define XSTATE_MASK_AVX (XSTATE_MASK_GSSE)
#endif // XSTATE_MASK_AVX
#ifndef XSTATE_AVX
#  define XSTATE_AVX (XSTATE_GSSE)
#endif // XSTATE_AVX

#define CONTEXT_XSTATE_BIT 0x40

// https://docs.microsoft.com/en-us/windows/desktop/debug/working-with-xstate-context
// The definition of CONTEXT_XSTATE changed across SDKs. On older SDKs, where it would
// have another value, it wasn't usable anyway, so it's safe to undefine & re-define it.
#ifdef CONTEXT_XSTATE
#  if ((CONTEXT_XSTATE & CONTEXT_XSTATE_BIT) == 0)
#    undef CONTEXT_XSTATE
#    if defined(_M_X64)
#      define CONTEXT_XSTATE (0x00100040)
#    else
#      define CONTEXT_XSTATE (0x00010040)
#    endif
#  endif
#endif


//--------------------------------------------------------------------------
static int calc_ctxflags(int clsmask)
{
  int ctxflags = CONTEXT_CONTROL|CONTEXT_INTEGER;
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
    ctxflags |= CONTEXT_SEGMENTS;
  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
    ctxflags |= CONTEXT_FLOATING_POINT;
  if ( (clsmask & X86_RC_XMM) != 0 )
#ifndef __X86__
    ctxflags |= CONTEXT_FLOATING_POINT;
#else
    ctxflags |= CONTEXT_EXTENDED_REGISTERS;
#endif
  if ( (clsmask & X86_RC_YMM) != 0 )
#ifndef __X86__
    ctxflags |= CONTEXT_XSTATE|CONTEXT_FLOATING_POINT;
#else
    ctxflags |= CONTEXT_XSTATE|CONTEXT_EXTENDED_REGISTERS;
#endif
  return ctxflags;
}

//--------------------------------------------------------------------------
// assertions that ensure that the conversion between CONTEXT and WOW64_CONTEXT
// is correct
#ifdef __X86__
CASSERT(sizeof(FLOATING_SAVE_AREA) == 112);
CASSERT(CONTEXT_CONTROL                   == 0x10001);
CASSERT(CONTEXT_INTEGER                   == 0x10002);
CASSERT(CONTEXT_SEGMENTS                  == 0x10004);
CASSERT(CONTEXT_FLOATING_POINT            == 0x10008);
CASSERT(CONTEXT_DEBUG_REGISTERS           == 0x10010);
CASSERT(CONTEXT_EXTENDED_REGISTERS        == 0x10020);
#else
CASSERT(sizeof(WOW64_FLOATING_SAVE_AREA) == 112);
CASSERT(sizeof(XSAVE_FORMAT) == WOW64_MAXIMUM_SUPPORTED_EXTENSION);
CASSERT(WOW64_CONTEXT_CONTROL             == 0x10001);
CASSERT(WOW64_CONTEXT_INTEGER             == 0x10002);
CASSERT(WOW64_CONTEXT_SEGMENTS            == 0x10004);
CASSERT(WOW64_CONTEXT_FLOATING_POINT      == 0x10008);
CASSERT(WOW64_CONTEXT_DEBUG_REGISTERS     == 0x10010);
CASSERT(WOW64_CONTEXT_EXTENDED_REGISTERS  == 0x10020);
#endif

#ifndef __X86__
//--------------------------------------------------------------------------
inline int ctxflags_to_wow64(int ctxflags)
{
  if ( (ctxflags & CONTEXT_FLOATING_POINT) != 0 )
    ctxflags |= WOW64_CONTEXT_EXTENDED_REGISTERS;
  // XSTATE in WOW64 is handled in a separate context
  bool requires_xstate = (ctxflags & CONTEXT_XSTATE) == CONTEXT_XSTATE;
  if ( requires_xstate )
    ctxflags |= WOW64_CONTEXT_FLOATING_POINT;
  ctxflags &= ~CONTEXT_XSTATE_BIT;
  ctxflags &= ~CONTEXT_AMD64;
  ctxflags |= WOW64_CONTEXT_i386;
  return ctxflags; // see CASSERTs anout CONTEXT_... bits above
}

//-------------------------------------------------------------------------
static void WOW64_CONTEXT_to_CONTEXT(
        CONTEXT *out,
        const WOW64_CONTEXT &wow64ctx,
        int clsmask,
        PCONTEXT xstate_ctx,
        const context_helper_t &helper)
{
  out->ContextFlags = calc_ctxflags(clsmask);

  if ( xstate_ctx != nullptr && helper.xstate_helpers_loaded() )
    helper.pfnCopyContext(out, CONTEXT_XSTATE, xstate_ctx);

  out->Dr0 = wow64ctx.Dr0;
  out->Dr1 = wow64ctx.Dr1;
  out->Dr2 = wow64ctx.Dr2;
  out->Dr3 = wow64ctx.Dr3;
  out->Dr6 = wow64ctx.Dr6;
  out->Dr7 = wow64ctx.Dr7;

  out->SegGs = wow64ctx.SegGs;
  out->SegFs = wow64ctx.SegFs;
  out->SegEs = wow64ctx.SegEs;
  out->SegDs = wow64ctx.SegDs;

  out->Rdi = wow64ctx.Edi;
  out->Rsi = wow64ctx.Esi;
  out->Rbx = wow64ctx.Ebx;
  out->Rdx = wow64ctx.Edx;
  out->Rcx = wow64ctx.Ecx;
  out->Rax = wow64ctx.Eax;

  out->Rbp    = wow64ctx.Ebp;
  out->SegCs  = wow64ctx.SegCs;
  out->EFlags = wow64ctx.EFlags;
  out->SegSs  = wow64ctx.SegSs;
  out->Rip    = wow64ctx.Eip;
  out->Rsp    = wow64ctx.Esp;

  if ( (wow64ctx.ContextFlags & WOW64_CONTEXT_EXTENDED_REGISTERS) != 0 )
  {
    memcpy(&out->FltSave, wow64ctx.ExtendedRegisters, sizeof(out->FltSave));
  }
  else if ( (wow64ctx.ContextFlags & WOW64_CONTEXT_FLOATING_POINT) != 0 )
  {
    out->FltSave.ControlWord   = wow64ctx.FloatSave.ControlWord;
    out->FltSave.StatusWord    = wow64ctx.FloatSave.StatusWord;
    out->FltSave.TagWord       = wow64ctx.FloatSave.TagWord;
    out->FltSave.ErrorOffset   = wow64ctx.FloatSave.ErrorOffset;
    out->FltSave.ErrorSelector = wow64ctx.FloatSave.ErrorSelector;
    out->FltSave.DataOffset    = wow64ctx.FloatSave.DataOffset;
    out->FltSave.DataSelector  = wow64ctx.FloatSave.DataSelector;
    memset(out->FltSave.FloatRegisters, 0, sizeof(out->FltSave.FloatRegisters));
    for ( int i=0; i < 8; i++ )
      memcpy(&out->FltSave.FloatRegisters[i], &wow64ctx.FloatSave.RegisterArea[i*10], 10);
  }
}

//--------------------------------------------------------------------------
static void CONTEXT_to_WOW64_CONTEXT(
        WOW64_CONTEXT *out,
        CONTEXT &ctx,
        PCONTEXT xstate_ctx,
        int clsmask,
        const context_helper_t &helper)
{
  int cflags = calc_ctxflags(clsmask);
  int wflags = ctxflags_to_wow64(cflags);
  out->ContextFlags = wflags;

  if ( xstate_ctx != nullptr && helper.xstate_helpers_loaded() )
    helper.pfnCopyContext(xstate_ctx, CONTEXT_XSTATE, &ctx);

  out->Dr0 = ctx.Dr0;
  out->Dr1 = ctx.Dr1;
  out->Dr2 = ctx.Dr2;
  out->Dr3 = ctx.Dr3;
  out->Dr6 = ctx.Dr6;
  out->Dr7 = ctx.Dr7;

  out->SegGs = ctx.SegGs;
  out->SegFs = ctx.SegFs;
  out->SegEs = ctx.SegEs;
  out->SegDs = ctx.SegDs;

  out->Edi = ctx.Rdi;
  out->Esi = ctx.Rsi;
  out->Ebx = ctx.Rbx;
  out->Edx = ctx.Rdx;
  out->Ecx = ctx.Rcx;
  out->Eax = ctx.Rax;

  out->Ebp    = ctx.Rbp;
  out->SegCs  = ctx.SegCs;
  out->EFlags = ctx.EFlags;
  out->SegSs  = ctx.SegSs;
  out->Eip    = ctx.Rip;
  out->Esp    = ctx.Rsp;

  if ( (wflags & WOW64_CONTEXT_FLOATING_POINT) != 0 )
  {
    out->FloatSave.ControlWord   = ctx.FltSave.ControlWord;
    out->FloatSave.StatusWord    = ctx.FltSave.StatusWord;
    out->FloatSave.TagWord       = ctx.FltSave.TagWord;
    out->FloatSave.ErrorOffset   = ctx.FltSave.ErrorOffset;
    out->FloatSave.ErrorSelector = ctx.FltSave.ErrorSelector;
    out->FloatSave.DataOffset    = ctx.FltSave.DataOffset;
    out->FloatSave.DataSelector  = ctx.FltSave.DataSelector;
    for ( int i=0; i < 8; i++ )
      memcpy(&out->FloatSave.RegisterArea[i*10], &ctx.FltSave.FloatRegisters[i], 10);
  }
  if ( (wflags & WOW64_CONTEXT_EXTENDED_REGISTERS) != 0 )
    memcpy(out->ExtendedRegisters, &ctx.FltSave, sizeof(ctx.FltSave));
}

#define Eip Rip
#endif

//-------------------------------------------------------------------------
// https://docs.microsoft.com/en-us/windows/desktop/debug/working-with-xstate-context
bool context_helper_t::create_context(context_holder_t *out, int *_ctxflags)
{
  out->buffer.qclear();
  out->buffer.clear();
  int ctxsz = sizeof(CONTEXT);
#define CONTEXT_REQUIRES_XSTATE() ((*_ctxflags & CONTEXT_XSTATE_BIT) == CONTEXT_XSTATE_BIT)
  if ( CONTEXT_REQUIRES_XSTATE() && !get_xstate_context_size(&ctxsz) )
    *_ctxflags &= ~CONTEXT_XSTATE_BIT;
  out->buffer.resize(ctxsz);
  if ( CONTEXT_REQUIRES_XSTATE() )
  {
    if ( pfnInitializeContext(
                 out->buffer.begin(),
                 *_ctxflags,
                 &out->ptr,
                 (DWORD *) &ctxsz) == FALSE )
    {
      return false;
    }

    if ( pfnSetXStateFeaturesMask(out->ptr, XSTATE_MASK_AVX) == FALSE )
      return false;
  }
  else
  {
    out->ptr = (PCONTEXT) out->buffer.begin();
    out->ptr->ContextFlags = *_ctxflags;
  }
  return true;
}

//-------------------------------------------------------------------------
bool context_helper_t::get_xstate_context_size(int *out_ctxsz)
{
  if ( xstate_context_size < 0 )
  {
    xstate_context_size = 0;
    const char *error = nullptr;

    HINSTANCE h = GetModuleHandle(kernel32_dll);
    *(FARPROC*) &pfnGetEnabledXStateFeatures = GetProcAddress(h, "GetEnabledXStateFeatures");
    *(FARPROC*) &pfnInitializeContext = GetProcAddress(h, "InitializeContext");
    *(FARPROC*) &pfnGetXStateFeaturesMask = GetProcAddress(h, "GetXStateFeaturesMask");
    *(FARPROC*) &pfnLocateXStateFeature = GetProcAddress(h, "LocateXStateFeature");
    *(FARPROC*) &pfnSetXStateFeaturesMask = GetProcAddress(h, "SetXStateFeaturesMask");
    *(FARPROC*) &pfnCopyContext = GetProcAddress(h, "CopyContext");

    if ( pfnGetEnabledXStateFeatures != nullptr
      && pfnInitializeContext != nullptr
      && pfnGetXStateFeaturesMask != nullptr
      && pfnLocateXStateFeature != nullptr
      && pfnSetXStateFeaturesMask != nullptr
      && pfnCopyContext != nullptr )
    {
      DWORD64 feature_mask;
      feature_mask = pfnGetEnabledXStateFeatures();
      if ( (feature_mask & XSTATE_MASK_AVX) != 0 )
      {
        DWORD context_size = 0;
        BOOL success = pfnInitializeContext(
                nullptr,
                CONTEXT_ALL | CONTEXT_XSTATE,
                nullptr,
                &context_size);

        if ( (success != FALSE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER) )
          error = "InitializeContext failed";
        else
          xstate_context_size = context_size;
      }
      else
      {
        error = "AVX feature not enabled";
      }
    }
    else
    {
      error = "Couldn't retrieve AVX functions";
    }

    if ( error != nullptr )
      msg("%s\n", error);
  }
  int ctxsz = xstate_context_size;
  bool ok = ctxsz > 0;
  if ( ok )
    *out_ctxsz = ctxsz;
  return ok;
}

//-------------------------------------------------------------------------
void context_helper_t::clear()
{
  memset(this, 0, sizeof(*this));
  xstate_context_size = -1;
}

//--------------------------------------------------------------------------
// Macro to test the DBG_FLAG_DONT_DISTURB flag
#if 0
#define NODISTURB_ASSERT(x) QASSERT(x)
#else
#define NODISTURB_ASSERT(x)
#endif

static int g_code = 0;

//--------------------------------------------------------------------------
void win32_debmod_t::check_thread(bool must_be_main_thread) const
{
  // remote debugger uses only one thread
  if ( rpc != nullptr )
    return;

  // someone turned off debthread?
  if ( (debugger_flags & DBG_FLAG_DEBTHREAD) == 0 )
    return;

  // local debugger uses 2 threads and we must be in the correct one
  QASSERT(30191, is_main_thread() == must_be_main_thread);
}

//--------------------------------------------------------------------------
static int utf16_to_utf8(char *buf, size_t bufsize, LPCWSTR unicode)
{
  qstring res;
  utf16_utf8(&res, unicode);
  qstrncpy(buf, res.c_str(), bufsize);
  size_t n = res.length();
  if ( n > bufsize )
    n = bufsize;
  return (int)n;
}

//--------------------------------------------------------------------------
// try to locate full path of a dll name without full path
// for example, toolhelp.dll -> c:\windows\toolhelp.dll
static bool find_full_path(char *fname, size_t fnamesize, const char *process_path)
{
  if ( fname[0] != '\0' && !qisabspath(fname) )
  {
    char path[QMAXPATH];
    char dir[QMAXPATH];
    // check system directory
    GetSystemDirectory(dir, sizeof(dir));
    qmakepath(path, sizeof(path), dir, fname, nullptr);
    if ( qfileexist(path) )
    {
FOUND:
      qstrncpy(fname, path, fnamesize);
      return true;
    }
    // check current process directory
    if ( process_path[0] != '\0' && !qisabspath(process_path) )
    {
      qdirname(dir, sizeof(dir), process_path);
      qmakepath(path, sizeof(path), dir, fname, nullptr);
      if ( qfileexist(path) )
        goto FOUND;
    }
    // check current directory
    if ( GetCurrentDirectory(sizeof(dir), dir) != 0 )
    {
      qmakepath(path, sizeof(path), dir, fname, nullptr);
      if ( qfileexist(path) )
        goto FOUND;
    }
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::access_memory(eanat_t ea, void *buffer, ssize_t size, bool do_write, bool suspend)
{
  if ( process_handle == INVALID_HANDLE_VALUE )
    return -1;

  NODISTURB_ASSERT(in_event != nullptr || exiting);

  // stop all threads before accessing its memory
  if ( suspend )
    suspend_all_threads();

  ea = s0tops(ea);
  void *addr = (void *)ea;

  DWORD_PTR size_access = 0;
  const DWORD BADPROT = DWORD(-1);
  DWORD oldprotect = BADPROT;
  bool ok;

  while ( true )
  {
    // try to access the memory

    ok = do_write
       ? WriteProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0// address of number of bytes accessed
       : ReadProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0;// address of number of bytes accessed

    // if we have changed the page protection, revert it
    if ( oldprotect != BADPROT )
    {
      if ( !VirtualProtectEx(
              process_handle,     // handle of the process whose memory is accessed
              addr,               // address to start access
              (DWORD)size,        // number of bytes to access
              oldprotect,
              &oldprotect) )
      {
        deberr("VirtualProtectEx2(%p)", addr);
      }
      break; // do not attempt more than once
    }

    // bail out after a successful read/write
    if ( ok )
      break;

    // bail out if it is not about "not enough access rights"
    // *or* ERROR_PARTIAL_COPY as, sometimes we may read/write
    // *only* parts of memory because of page breakpoints
    int code = GetLastError();
    if ( code != ERROR_NOACCESS && code != ERROR_PARTIAL_COPY )
    {
      deberr("%sProcessMemory(%p)", do_write ? "Write" : "Read", ea);
      break;
    }

    if ( code != ERROR_PARTIAL_COPY )
      size_access = 0; // size_access may be spoiled after failed ReadProcessMemory

    // check if the address is valid
    MEMORY_BASIC_INFORMATION meminfo;
    if ( !VirtualQueryEx(process_handle,    // handle of process
                         addr,              // address of region
                         &meminfo,          // address of information buffer
                         sizeof(meminfo)) ) // size of buffer
    {
      size_access = 0;
      break;
    }

    // allow the desired access on the page
    if ( !VirtualProtectEx(
      process_handle,     // handle of the process whose memory is accessed
      addr,               // address to start access
      (DWORD)size,        // number of bytes to access
      do_write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ,
      &oldprotect) )
    {
      deberr("VirtualProtectEx1(%08p, size=%d for %s)", ea, int(size), do_write ? "write" : "read");
      break;
    }
  }

  if ( do_write && ok )
    FlushInstructionCache(
      process_handle,      // handle to process with cache to flush
      addr,                // pointer to region to flush
      (DWORD)size);        // length of region to flush

  if ( suspend )
    resume_all_threads();
  return size_access;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_read_memory(eanat_t ea, void *buffer, size_t size, bool suspend)
{
  return access_memory(ea, buffer, size, false, suspend);
}

ssize_t idaapi win32_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring * /*errbuf*/)
{
  check_thread(false);
  return _read_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
// Make sure that the thread is suspended
// by calling SuspendThread twice
// If raw=true then SuspendThread() API will be called and we return directly
// without doing any further logic
static void _sure_suspend_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;

  int count = SuspendThread(h);
  if ( raw )
    return;

  if ( count != -1 )
    ti.suspend_count++;

  count = SuspendThread(h);
  if ( count != -1 )
    ti.suspend_count++;
}

//--------------------------------------------------------------------------
// Resume thread by calling ResumeThread as many times as required
// Note: this function just reverts the actions of sure_suspend_thread
// If the thread was already suspended before calling sure_suspend_thread
// then it will stay in the suspended state
// If raw=true then ResumeThread() will be called and we return directly
// without doing any further logic
static void _sure_resume_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;
  if ( raw )
  {
    ResumeThread(h);
    return;
  }

  while ( ti.suspend_count > 0 )
  {
    ResumeThread(h);
    ti.suspend_count--;
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_suspend_thread(p->second, raw);
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_resume_thread(p->second, raw);
}

//--------------------------------------------------------------------------
static int get_thread_suspend_count(HANDLE hThread)
{
  DWORD dwSuspendCount = SuspendThread(hThread);
  ResumeThread(hThread);
  return dwSuspendCount;
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_running_threads(threadvec_t &suspended)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t t = p->second;
    t.suspend_count = get_thread_suspend_count(t.hThread);
    if ( t.suspend_count == 0 )
    {
      _sure_suspend_thread(t);
      suspended.push_back(t);
    }
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_suspended_threads(threadvec_t suspended) const
{
  threadvec_t::iterator p;
  for ( p = suspended.begin(); p != suspended.end(); ++p )
    _sure_resume_thread(*p);
}

//--------------------------------------------------------------------------
size_t win32_debmod_t::add_dll(image_info_t &ii)
{
  dlls.insert(std::make_pair(ii.base, ii));
  dlls_to_import.insert(ii.base);
  return (size_t)ii.imagesize;
}

//--------------------------------------------------------------------------
// is modname already present in the loaded module list?
bool win32_debmod_t::module_present(const char *modname)
{
  // host process is not added to dlls, so check it first
  if ( process_path == modname )
    return true;

  // check DLLs which we already know about
  for ( const auto &p : dlls )
  {
    const image_info_t &ii = p.second;
    if ( ii.name == modname )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// iterate all modules of the specified process
// until the callback returns != 0
int win32_debmod_t::for_each_module(DWORD _pid, module_cb_t module_cb, void *ud)
{
  int code = 0;

  module_snapshot_t msnap(get_tool_help());
  MODULEENTRY32 me;
  for ( bool ok = msnap.first(TH32CS_SNAPNOHEAPS, _pid, &me); ok; ok = msnap.next(&me) )
  {
    code = module_cb(this, &me, ud);
    if ( code != 0 )
      break;
  }
  return code;
}

//--------------------------------------------------------------------------
// callback: get info about the main module of the debugger process
//lint -e{818}
int win32_debmod_t::get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud)
{
  win32_debmod_t *_this = (win32_debmod_t *)sess;
  // if the module name doesn't correspond to the process name,
  // we continue to iterate
  char buf[QMAXPATH];
  tchar_utf8(buf, me32->szModule, sizeof(buf));
  if ( !_this->process_path.empty() && stricmp(buf, qbasename(_this->process_path.c_str())) != 0 )
    return 0;

  // ok, this module corresponds to our debugged process
  modinfo_t &dmi = *(modinfo_t *)ud;
  dmi.name = _this->process_path;
  dmi.base = _this->ptr_to_ea(me32->modBaseAddr);
  dmi.size = _this->trunc_uval(me32->modBaseSize);
  return 1; // we stop to iterate
}

//--------------------------------------------------------------------------
// Return module information on the currently debugged process
void win32_debmod_t::get_debugged_module_info(modinfo_t *dmi)
{
  dmi->name[0]   = '\0';
  dmi->base      = BADADDR;
  dmi->size      = 0;
  dmi->rebase_to = BADADDR;
  for_each_module(pid, get_dmi_cb, dmi);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_stopped_at_debug_event(
        import_infos_t *,
        bool dlls_added,
        thread_name_vec_t *thr_names)
{
  if ( dlls_added )
  {
    check_thread(true);
    // we will take advantage of this event to import information
    // about the exported functions from the loaded dlls and the
    // binary itself
    name_info_t &ni = *get_debug_names();
    if ( !binary_to_import.name.empty() )
    {
      const char *bin_path = binary_to_import.name.c_str();
      linput_t *li = open_linput(bin_path, false);
      if ( li != nullptr )
      {
        get_pe_exports_from_path(bin_path, li, binary_to_import.base, ni);
        close_linput(li);
      }
      binary_to_import.name.clear();
    }

    for ( easet_t::iterator p = dlls_to_import.begin(); p != dlls_to_import.end(); )
    {
      get_dll_exports(dlls, *p, ni);
      p = dlls_to_import.erase(p);
    }
  }

  if ( thr_names != nullptr )
    update_thread_names(thr_names);
}

//--------------------------------------------------------------------------
static void update_thread_description(thread_info_t &ti)
{
  if ( _GetThreadDescription == nullptr )
    return;

  PWSTR data;
  HRESULT hr = _GetThreadDescription(ti.hThread, &data);
  if ( SUCCEEDED(hr) )
  {
    int data_sz = wcslen(data) * 2;   // size in bytes
    qstring newname;
    if ( convert_encoding(
                    (bytevec_t*)&newname,
                    ENC_UTF16LE, ENC_UTF8,
                    (const uchar *)data,
                    data_sz) > 0 )
    {
      if ( newname != ti.name )
      {
        ti.name = newname.c_str();  // newname over allocated
        ti.set_new_name();
      }
    }
    LocalFree(data);
  }
}

//--------------------------------------------------------------------------
void win32_debmod_t::update_thread_names(thread_name_vec_t *thr_names)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    update_thread_description(ti);
    if ( ti.is_new_name() )
    {
      thread_name_t &tn = thr_names->push_back();
      tn.tid = ti.tid;
      tn.name = ti.name;
      ti.clr_new_name();
    }
  }
}

//--------------------------------------------------------------------------
// return the address of an exported name
ea_t win32_debmod_t::get_dll_export(
        const images_t &_dlls,
        ea_t imagebase,
        const char *exported_name)
{
  ea_t ret = BADADDR;

  name_info_t ni;
  if ( get_dll_exports(_dlls, imagebase, ni, exported_name) && !ni.addrs.empty() )
    ret = ni.addrs[0];
  return ret;
}

//--------------------------------------------------------------------------
win32_debmod_t::win32_debmod_t()
  : expecting_debug_break(0), stop_at_ntdll_bpts(false)
{
  fake_suspend_event = false;

  pid = -1;

  // Reset handles
  process_handle  = INVALID_HANDLE_VALUE;
  thread_handle   = INVALID_HANDLE_VALUE;
  redirin_handle  = INVALID_HANDLE_VALUE;
  redirout_handle = INVALID_HANDLE_VALUE;

  attach_evid = INVALID_HANDLE_VALUE;
  attach_status = as_none;

  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile = INVALID_HANDLE_VALUE;  // hFile
  cpdi.hProcess = INVALID_HANDLE_VALUE;  // hProcess
  cpdi.hThread = INVALID_HANDLE_VALUE;  // hThread

  winxp_step_thread = 0;
  memset(&in_event, 0, sizeof(in_event));
  exiting = false;
  pause_requested = false;

  broken_event_handle = nullptr;
  // we don't set platform name here because it will be inherited
  // from winbase_debmod_t

  binary_to_import.base = BADADDR;
  binary_to_import.size = 0;
  binary_to_import.rebase_to = BADADDR;
}

//--------------------------------------------------------------------------
#define qoffsetof2(s, f) (qoffsetof(regctx_t, s) + qoffsetof(decltype(regctx_t::s), f))
#define offset_size(s, f) qoffsetof2(s, f), sizeof(decltype(regctx_t::s)::f)

//--------------------------------------------------------------------------
static void clear_ival(const regctx_t * /*ctx*/, regval_t *value, void * /*user_data*/)
{
  value->ival = 0;
}

//--------------------------------------------------------------------------
static void nop_write(regctx_t * /*ctx*/, const regval_t * /*value*/, void * /*user_data*/)
{
}

//--------------------------------------------------------------------------
static void ymm_read(const regctx_t *ctx, regval_t *value, void *user_data)
{
  size_t ymm_reg_idx = size_t(user_data);
  const uint128 *ptrl = (uint128 *) &ctx->fpu.__fpu_xmm[0];
  const uint128 *ptrh = (uint128 *) &ctx->fpu.__fpu_ymmh[0];
  uint8_t ymm[32];
  *(uint128 *) &ymm[ 0] = ptrl[ymm_reg_idx];
  *(uint128 *) &ymm[16] = ptrh[ymm_reg_idx];
  value->set_bytes(ymm, sizeof(ymm));
}

//--------------------------------------------------------------------------
static void ymm_write(regctx_t *ctx, const regval_t *value, void *user_data)
{
  size_t ymm_reg_idx = size_t(user_data);
  const uint8_t *ymm = (const uint8_t *) value->get_data();
  uint128 *ptrl = (uint128 *) &ctx->fpu.__fpu_xmm[0];
  uint128 *ptrh = (uint128 *) &ctx->fpu.__fpu_ymmh[0];
  ptrl[ymm_reg_idx] = *(uint128 *) &ymm[ 0];
  ptrh[ymm_reg_idx] = *(uint128 *) &ymm[16];
}

//-------------------------------------------------------------------------
void win32_debmod_t::init_reg_ctx()
{
  // Populate register context
  // order of registers corresponds to register_x86_t / register_x86_x86_t
  reg_ctx = new regctx_t(idaregs, *this);

  // ST*
  size_t offset = qoffsetof2(fpu, __fpu_stmm);
  for ( size_t i = R_ST0; i <= R_ST7; i++, offset += 16 )
    reg_ctx->add_fval(x86_registers[i], offset, 10);

  // FPU control
  reg_ctx->add_ival(x86_registers[R_CTRL], offset_size(fpu, __fpu_fcw));
  reg_ctx->add_ival(x86_registers[R_STAT], offset_size(fpu, __fpu_fsw));
  reg_ctx->add_ival(x86_registers[R_TAGS], offset_size(fpu, __fpu_ftw));

  cs_idx = reg_ctx->add_ival(x86_registers[R_CS], offset_size(cpu, __cs));
  if ( is64 )
  {
    ds_idx = reg_ctx->add_func(x86_registers[R_DS], clear_ival, nop_write);
    es_idx = reg_ctx->add_func(x86_registers[R_ES], clear_ival, nop_write);
  }
  else
  {
    ds_idx = reg_ctx->add_ival(x86_registers[R_DS], offset_size(cpu, __ds));
    es_idx = reg_ctx->add_ival(x86_registers[R_ES], offset_size(cpu, __es));
  }
  fs_idx = reg_ctx->add_ival(x86_registers[R_FS], offset_size(cpu, __fs));
  gs_idx = reg_ctx->add_ival(x86_registers[R_GS], offset_size(cpu, __gs));
  if ( is64 )
    ss_idx = reg_ctx->add_func(x86_registers[R_SS], clear_ival, nop_write);
  else
    ss_idx = reg_ctx->add_ival(x86_registers[R_SS], offset_size(cpu, __ss));

#ifdef __EA64__
  if ( is64 )
  {
    reg_ctx->add_ival(r_rax, offset_size(cpu, __eax));
    reg_ctx->add_ival(r_rbx, offset_size(cpu, __ebx));
    reg_ctx->add_ival(r_rcx, offset_size(cpu, __ecx));
    reg_ctx->add_ival(r_rdx, offset_size(cpu, __edx));
    reg_ctx->add_ival(r_rsi, offset_size(cpu, __esi));
    reg_ctx->add_ival(r_rdi, offset_size(cpu, __edi));
    reg_ctx->add_ival(r_rbp, offset_size(cpu, __ebp));
    sp_idx = reg_ctx->add_ival(r_rsp, offset_size(cpu, __esp));
    pc_idx = reg_ctx->add_ival(r_rip, offset_size(cpu, __eip));
    reg_ctx->add_ival(r_r8, offset_size(cpu, __r8));
    reg_ctx->add_ival(r_r9, offset_size(cpu, __r9));
    reg_ctx->add_ival(r_r10, offset_size(cpu, __r10));
    reg_ctx->add_ival(r_r11, offset_size(cpu, __r11));
    reg_ctx->add_ival(r_r12, offset_size(cpu, __r12));
    reg_ctx->add_ival(r_r13, offset_size(cpu, __r13));
    reg_ctx->add_ival(r_r14, offset_size(cpu, __r14));
    reg_ctx->add_ival(r_r15, offset_size(cpu, __r15));
  }
  else
#endif
  {
    reg_ctx->add_ival(r_eax, offset_size(cpu, __eax));
    reg_ctx->add_ival(r_ebx, offset_size(cpu, __ebx));
    reg_ctx->add_ival(r_ecx, offset_size(cpu, __ecx));
    reg_ctx->add_ival(r_edx, offset_size(cpu, __edx));
    reg_ctx->add_ival(r_esi, offset_size(cpu, __esi));
    reg_ctx->add_ival(r_edi, offset_size(cpu, __edi));
    reg_ctx->add_ival(r_ebp, offset_size(cpu, __ebp));
    sp_idx = reg_ctx->add_ival(r_esp, offset_size(cpu, __esp));
    pc_idx = reg_ctx->add_ival(r_eip, offset_size(cpu, __eip));
  }
  sr_idx = reg_ctx->add_ival(x86_registers[R_EFLAGS], offset_size(cpu, __eflags));

  // XMM*
  offset = qoffsetof2(fpu, __fpu_xmm);
  for ( size_t i = R_XMM0; i <= R_LAST_XMM; i++, offset += 16 )
  {
#ifdef __EA64__
    if ( !is64 && i >= R_XMM8 )
      break;
#endif
    reg_ctx->add_data(x86_registers[i], offset, 16);
  }
  reg_ctx->add_ival(x86_registers[R_MXCSR], offset_size(fpu, __fpu_mxcsr));

  // MMX*
  offset = qoffsetof2(fpu, __fpu_stmm);
  for ( size_t i = R_MMX0; i <= R_MMX7; i++, offset += 16 )
    reg_ctx->add_data(x86_registers[i], offset, 8);

  // YMM*
  for ( size_t i = R_YMM0; i <= R_LAST_YMM; i++ )
  {
#ifdef __EA64__
    if ( !is64 && i >= R_YMM8 )
      break;
#endif
    reg_ctx->add_func(x86_registers[i], ymm_read, ymm_write, (void *) (i - R_YMM0));
  }
}

//--------------------------------------------------------------------------
#ifndef __X86__
#  define FloatSave FltSave       // FIXME: use XMM save area!
#  define RegisterArea FloatRegisters
#  define FPUREG_ENTRY_SIZE  16
#  define XMMREG_PTR   ((uchar *)&ctx.Xmm0)
#  define XMMREG_MXCSR (ctx.FltSave.MxCsr)
#else
#  define FltSave FloatSave
#  define XMMREG_PTR ((uchar *)&ctx.ExtendedRegisters[0xA0])
#  define XMMREG_MXCSR (*(uint32 *)&ctx.ExtendedRegisters[0x18])
#  define FPUREG_ENTRY_SIZE  10
#endif

#define FPUREG_PTR        ((uchar *)ctx.FloatSave.RegisterArea)

//-------------------------------------------------------------------------
bool win32_debmod_t::get_thread_state(
        context_holder_t *out_ctxh,
        machine_thread_state_t *out_regs,
        machine_float_state_t *out_floats,
        thid_t tid,
        int clsmask)
{
  thread_info_t *ti = threads.get(tid);
  if ( ti == nullptr || !ti->read_context(out_ctxh, clsmask) )
    return false;
  CONTEXT &ctx = *out_ctxh->ptr;
  memset(out_regs, 0, sizeof(*out_regs));
  memset(out_floats, 0, sizeof(*out_floats));

  // if ( (clsmask & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
#ifdef __X86__
    out_regs->__eax    = ctx.Eax;
    out_regs->__ebx    = ctx.Ebx;
    out_regs->__ecx    = ctx.Ecx;
    out_regs->__edx    = ctx.Edx;
    out_regs->__edi    = ctx.Edi;
    out_regs->__esi    = ctx.Esi;
    out_regs->__ebp    = ctx.Ebp;
    out_regs->__esp    = ctx.Esp;
    out_regs->__eip    = ctx.Eip;
    out_regs->__eflags = ctx.EFlags;
    out_regs->__cs     = ctx.SegCs;
    out_regs->__fs     = ctx.SegFs;
    out_regs->__gs     = ctx.SegGs;
    out_regs->__ss     = ctx.SegSs;
    out_regs->__ds     = ctx.SegDs;
    out_regs->__es     = ctx.SegEs;
#else
    out_regs->__eax    = ctx.Rax;
    out_regs->__ebx    = ctx.Rbx;
    out_regs->__ecx    = ctx.Rcx;
    out_regs->__edx    = ctx.Rdx;
    out_regs->__edi    = ctx.Rdi;
    out_regs->__esi    = ctx.Rsi;
    out_regs->__ebp    = ctx.Rbp;
    out_regs->__esp    = ctx.Rsp;
    out_regs->__eip    = ctx.Rip;
    out_regs->__r8     = ctx.R8;
    out_regs->__r9     = ctx.R9;
    out_regs->__r10    = ctx.R10;
    out_regs->__r11    = ctx.R11;
    out_regs->__r12    = ctx.R12;
    out_regs->__r13    = ctx.R13;
    out_regs->__r14    = ctx.R14;
    out_regs->__r15    = ctx.R15;
    out_regs->__eflags = ctx.EFlags;
    out_regs->__cs     = ctx.SegCs;
    out_regs->__fs     = ctx.SegFs;
    out_regs->__gs     = ctx.SegGs;
    out_regs->__ss     = ctx.SegSs;
    out_regs->__ds     = ctx.SegDs;
    out_regs->__es     = ctx.SegEs;
#endif
  }

  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      out_floats->__fpu_fcw = ctx.FltSave.ControlWord;
      out_floats->__fpu_fsw = ctx.FltSave.StatusWord;
      out_floats->__fpu_ftw = ctx.FltSave.TagWord;
    }

    const uchar *vptr = (const uchar *) FPUREG_PTR;
    for ( int i = 0; i < 8; ++i, vptr += FPUREG_ENTRY_SIZE )
      memcpy(&out_floats->__fpu_stmm[i], vptr, MMX_FPU_REG_DATA_SIZE);
  }

  if ( (clsmask & (X86_RC_XMM|X86_RC_YMM)) != 0 )
  {
    const uchar *xptr = XMMREG_PTR;
    memcpy(&out_floats->__fpu_xmm[0], xptr, (R_MXCSR - R_XMM0) * sizeof(xmm_reg_t));
    out_floats->__fpu_mxcsr = XMMREG_MXCSR;
  }

  if ( (clsmask & X86_RC_YMM) != 0
    && context_helper.xstate_helpers_loaded()
    && context_helper.pfnSetXStateFeaturesMask(&ctx, XSTATE_MASK_AVX) != FALSE )
  {
    DWORD xmm_blob_length = 0;
    PM128A Xmm = (PM128A) context_helper.pfnLocateXStateFeature(
            &ctx,
            XSTATE_LEGACY_SSE,
            &xmm_blob_length);
    PM128A Ymm = (PM128A) context_helper.pfnLocateXStateFeature(
            &ctx,
            XSTATE_AVX,
            nullptr);
    CASSERT(sizeof(Ymm[0]) == sizeof(xmm_reg_t));
    const int nxmm_regs = xmm_blob_length / sizeof(Xmm[0]);
    const int nymm_regs = qmin(nxmm_regs, 16);
    memcpy(&out_floats->__fpu_ymmh[0], Ymm, nymm_regs * sizeof(xmm_reg_t));
  }

  return true;
}

//-------------------------------------------------------------------------
bool win32_debmod_t::set_thread_state(
        const machine_thread_state_t &state,
        const machine_float_state_t &floats,
        const context_holder_t &ctxh,
        thid_t tid,
        int clsmask)
{
  thread_info_t *ti = threads.get(tid);
  if ( ti == nullptr )
    return false;

  CONTEXT &ctx = *ctxh.ptr;

  // if ( (clsmask & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
#ifdef __X86__
    ctx.Eax = state.__eax;
    ctx.Ebx = state.__ebx;
    ctx.Ecx = state.__ecx;
    ctx.Edx = state.__edx;
    ctx.Edi = state.__edi;
    ctx.Esi = state.__esi;
    ctx.Ebp = state.__ebp;
    ctx.Esp = state.__esp;
    ctx.Eip = state.__eip;
    ctx.EFlags = state.__eflags;
    ctx.SegCs = state.__cs;
    ctx.SegFs = state.__fs;
    ctx.SegGs = state.__gs;
    ctx.SegSs = state.__ss;
    ctx.SegDs = state.__ds;
    ctx.SegEs = state.__es;
#else
    ctx.Rax = state.__eax;
    ctx.Rbx = state.__ebx;
    ctx.Rcx = state.__ecx;
    ctx.Rdx = state.__edx;
    ctx.Rdi = state.__edi;
    ctx.Rsi = state.__esi;
    ctx.Rbp = state.__ebp;
    ctx.Rsp = state.__esp;
    ctx.Rip = state.__eip;
    ctx.R8 = state.__r8;
    ctx.R9 = state.__r9;
    ctx.R10 = state.__r10;
    ctx.R11 = state.__r11;
    ctx.R12 = state.__r12;
    ctx.R13 = state.__r13;
    ctx.R14 = state.__r14;
    ctx.R15 = state.__r15;
    ctx.EFlags = state.__eflags;
    ctx.SegCs = state.__cs;
    ctx.SegFs = state.__fs;
    ctx.SegGs = state.__gs;
    ctx.SegSs = state.__ss;
    ctx.SegDs = state.__ds;
    ctx.SegEs = state.__es;
#endif
  }

  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      ctx.FloatSave.ControlWord = floats.__fpu_fcw;
      ctx.FloatSave.StatusWord = floats.__fpu_fsw;
      ctx.FloatSave.TagWord = floats.__fpu_ftw;
    }

    uchar *vptr = (uchar *) FPUREG_PTR;
    for ( int i = 0; i < 8; ++i, vptr += FPUREG_ENTRY_SIZE )
      memcpy(vptr, &floats.__fpu_stmm[i], MMX_FPU_REG_DATA_SIZE);
  }

  if ( (clsmask & (X86_RC_XMM|X86_RC_YMM)) != 0 )
  {
    uchar *xptr = XMMREG_PTR;
    memcpy(xptr, &floats.__fpu_xmm[0], (R_MXCSR - R_XMM0) * sizeof(xmm_reg_t));
    XMMREG_MXCSR = floats.__fpu_mxcsr;
  }

  if ( (clsmask & X86_RC_YMM) != 0
    && context_helper.xstate_helpers_loaded()
    && context_helper.pfnSetXStateFeaturesMask(&ctx, XSTATE_MASK_AVX) != FALSE )
  {
    DWORD xmm_blob_length = 0;
    PM128A Xmm = (PM128A) context_helper.pfnLocateXStateFeature(
            &ctx,
            XSTATE_LEGACY_SSE,
            &xmm_blob_length);
    PM128A Ymm = (PM128A) context_helper.pfnLocateXStateFeature(
            &ctx,
            XSTATE_AVX,
            nullptr);
    CASSERT(sizeof(Ymm[0]) == sizeof(xmm_reg_t));
    const int nxmm_regs = xmm_blob_length / sizeof(Xmm[0]);
    const int nymm_regs = qmin(nxmm_regs, 16);
    memcpy(Ymm, &floats.__fpu_ymmh[0], nymm_regs * sizeof(xmm_reg_t));
  }

  return ti->write_context(clsmask, ctx);
}

//----------------------------------------------------------------------
// return the handle associated with a thread id from the threads list
HANDLE win32_debmod_t::get_thread_handle(thid_t tid)
{
  thread_info_t *tinfo = threads.get(tid);
  return tinfo == nullptr ? INVALID_HANDLE_VALUE : tinfo->hThread;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    set_hwbpts(p->second.hThread);
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  check_thread(false);
  if ( orig_bytes != nullptr )
  {
    bool ok = false;
    bpts.erase(ea);
    suspend_all_threads();
    // write the old value only if our bpt is still present
    if ( !has_bpt_at(ea) )
    {
      if ( !exiting )
        dmsg("%a: breakpoint vanished from memory\n", ea);
      ok = true;
    }
    else
    {
      ok = _write_memory(ea, orig_bytes, len) == len;
    }
    resume_all_threads();
    return ok;
  }

  // try to delete a page bpt first
  if ( del_page_bpt(ea, type) )
    return true;
  return del_hwbpt(ea, type);
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_write_memory(eanat_t ea, const void *buffer, size_t size, bool suspend)
{
  if ( !may_write(ea) )
    return -1;
  return access_memory(ea, (void *)buffer, size, true, suspend);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_term(void)
{
  check_thread(true);
  cleanup();
  for ( size_t i = 0; i < pdb_remote_sessions.size(); ++i )
    close_pdb_remote_session(pdb_remote_sessions[i]);
  inherited::dbg_term();
}

//--------------------------------------------------------------------------
bool win32_debmod_t::has_bpt_at(ea_t ea)
{
  uchar bytes[8];
  int size = bpt_code.size();
  return _read_memory(ea, bytes, size) == size
      && memcmp(bytes, bpt_code.begin(), size) == 0;
}

//--------------------------------------------------------------------------
// 2-ok(pagebpt), 1-ok, 0-failed, -2-read failed
int idaapi win32_debmod_t::dbg_add_bpt(
        bytevec_t *orig_bytes,
        bpttype_t type,
        ea_t ea,
        int len)
{
  check_thread(false);
  if ( type == BPT_SOFT )
  {
    if ( len <= 0 )
      len = bpt_code.size();
    if ( orig_bytes != nullptr && read_bpt_orgbytes(orig_bytes, ea, len) < 0 )
      return -2;
    debmod_bpt_t dbpt(ea, len);
    if ( !dbg_read_memory(ea, dbpt.saved, len, nullptr) )
      return -2;
    int size = bpt_code.size();
    if ( dbg_write_memory(ea, bpt_code.begin(), size, nullptr) != size )
      return 0;
    bpts[ea] = dbpt;
    return 1;
  }

  // try, first, to add a real hw breakpoint
  // if it fails, add a memory range type bpt
  // reason: the user may try to insert a 5th
  // correct hw bpt, however, it isn't possible
  // so, instead, we add a page breakpoint
  int ret = 0;
  if ( check_x86_hwbpt(type, ea, len) == BPT_OK )
    ret = add_hwbpt(type, ea, len);

  if ( !ret )
    ret = dbg_add_page_bpt(type, ea, len);
  return ret;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_get_memory_info(meminfo_vec_t &ranges, qstring * /*errbuf*/)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr);

  images.clear();
  thread_ranges.clear();
  class_ranges.clear();
  for ( threads_t::iterator t=threads.begin(); t != threads.end(); ++t )
    add_thread_ranges(t->first, thread_ranges, class_ranges);

  if ( process_handle != INVALID_HANDLE_VALUE )
  {
    for ( ea_t ea=0; !like_badaddr(ea); )
    {
      memory_info_t meminf;
      ea = get_region_info(ea, &meminf);
      if ( !like_badaddr(ea) && !like_badaddr(meminf.start_ea) )
        ranges.push_back(meminf);
    }
    enable_page_bpts(true);
  }

  if ( same_as_oldmemcfg(ranges) )
    return DRC_NOCHG;

  save_oldmemcfg(ranges);
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_suspend(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr);
  int count = SuspendThread(get_thread_handle(tid));
  if ( count == -1 )
    deberr("SuspendThread(%08X)", tid);

  if ( debug_debugger )
    debdeb("SuspendThread(%08X) -> %d\n", tid, count);

  return count != -1 ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_continue(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr);
  int count = ResumeThread(get_thread_handle(tid));
  if ( count == -1 )
    deberr("ResumeThread(%08X)", tid);

  if ( debug_debugger )
    debdeb("ResumeThread(%08X) -> %d\n", tid, count);

  return count != -1 ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
bool thread_info_t::read_context(
        context_holder_t *out,
        int clsmask)
{
  // if ( (flags & clsmask) == clsmask )
  //   return true;

  int ctxflags = calc_ctxflags(clsmask);
  if ( !debmod->context_helper.create_context(out, &ctxflags) )
    return false;

  PCONTEXT ctx = out->ptr;
#ifndef __X86__
  if ( is_wow64() && _Wow64GetThreadContext != nullptr )
  {
    WOW64_CONTEXT wow64ctx;
    wow64ctx.ContextFlags = ctxflags_to_wow64(ctxflags);
    if ( !_Wow64GetThreadContext(hThread, &wow64ctx) )
      return false;
    context_holder_t xstate_ctx;
    if ( (clsmask & X86_RC_YMM) != 0 )
    {
      int xstate_ctxflags = CONTEXT_XSTATE;
      if ( !debmod->context_helper.create_context(&xstate_ctx, &xstate_ctxflags) )
        return false;
      if ( !GetThreadContext(hThread, xstate_ctx.ptr) )
        return false;
    }
    WOW64_CONTEXT_to_CONTEXT(
            ctx,
            wow64ctx,
            clsmask,
            xstate_ctx.ptr,
            debmod->context_helper);
  }
  else
#endif
  {
    ctx->ContextFlags = ctxflags;
    if ( !GetThreadContext(hThread, ctx) )
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be const ref
bool thread_info_t::write_context(int clsmask, CONTEXT &ctx)
{
#ifndef __X86__
  if ( is_wow64() && _Wow64SetThreadContext != nullptr )
  {
    context_holder_t xstate_ctx;
    if ( (clsmask & X86_RC_YMM) != 0 )
    {
      int xstate_ctxflags = CONTEXT_XSTATE;
      if ( !debmod->context_helper.create_context(&xstate_ctx, &xstate_ctxflags) )
        return false;
    }
    WOW64_CONTEXT wow64ctx;
    CONTEXT_to_WOW64_CONTEXT(
            &wow64ctx,
            ctx,
            xstate_ctx.ptr,
            clsmask,
            debmod->context_helper);
    if ( xstate_ctx.ptr != nullptr )
    {
      if ( SetThreadContext(hThread, xstate_ctx.ptr) == 0 )
        return false;
    }
    if ( _Wow64SetThreadContext(hThread, &wow64ctx) == 0 )
      return false;
    return true;
  }
#else
  qnotused(clsmask);
#endif
  return SetThreadContext(hThread, &ctx) != 0;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_prepare_to_pause_process(qstring * /*errbuf*/)
{
  check_thread(false);
  bool ok = true;
  win_tool_help_t *wth = get_tool_help();
  if ( wth->use_debug_break_process() ) // only possible on XP/2K3 or higher
  {
    ok = wth->debug_break_process(process_handle);
    if ( !stop_at_ntdll_bpts )
      expecting_debug_break = ok;
  }
  else if ( threads.empty() )
  {
    ok = false;
  }
  else
  {
    suspend_all_threads();
    for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    {
      thread_info_t &ti = p->second;
      context_holder_t ctxh;
      if ( !ti.read_context(&ctxh, X86_RC_GENERAL) )
      {
        ok = false;
        continue;
      }
      // we have a problem: it is possible that eip points past a temporary breakpoint
      // that will be removed and replaced by the original instruction opcode.
      // if we set a new breakpoint now, it will be at the second byte of the
      // instruction and will lead to a crash.
      eanat_t ip = ctxh.ptr->Eip;
      if ( bpts.find(ip-bpt_code.size()) != bpts.end() )
        continue; // yes, there is a breakpoint just before us. it was just hit
                  // but hopefully not processed yet
      if ( !set_thread_bpt(ti, trunc_uval(ip)) )
        ok = false;
    }
    // send WM_NULL to the main thread, hopefully it will wake up the application
    thread_info_t &ti = threads.begin()->second;
    PostThreadMessageA(ti.tid, WM_NULL, 0, 0);
    resume_all_threads();
  }
  pause_requested = true;
  return ok ? DRC_OK : DRC_FAILED;
}

//----------------------------------------------------------------------
// return the name associated with an existing image in IMGS list
// containing a particular range
const char *win32_debmod_t::get_range_name(
        const images_t &imgs,
        const range_t *range) const
{
  for ( images_t::const_iterator p=imgs.begin(); p != imgs.end(); ++p )
  {
    const image_info_t &img = p->second;
    ea_t ea1 = trunc_uval(img.base);
    ea_t ea2 = trunc_uval(ea1 + img.imagesize);
    range_t b = range_t(ea1, ea2);
    b.intersect(*range);
    if ( !b.empty() )
      return img.name.c_str();
  }
  return nullptr;
}

//--------------------------------------------------------------------------
void win32_debmod_t::restore_original_bytes(ea_t ea, bool really_restore)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  QASSERT(1488, p != thread_bpts.end());
  if ( --p->second.count == 0 )
  {
    uchar *obytes = p->second.orig_bytes;
    if ( really_restore )
    {
      int size = bpt_code.size();
      if ( _write_memory(ea, obytes, size) != size )
        INTERR(1489);
    }
    thread_bpts.erase(p);
  }
}

//--------------------------------------------------------------------------
// returns: 0-error,1-ok,2-already had bpt, just increased the counter
int win32_debmod_t::save_original_bytes(ea_t ea)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  if ( p == thread_bpts.end() )
  {
    internal_bpt_info_t ibi;
    ibi.count = 1;
    int size = bpt_code.size();
    if ( _read_memory(ea, ibi.orig_bytes, size) != size )
      return 0;
    thread_bpts.insert(std::make_pair(ea, ibi));
    return 1;
  }
  else
  {
    p->second.count++;
    return 2;
  }
}

//--------------------------------------------------------------------------
bool win32_debmod_t::del_thread_bpt(thread_info_t &ti, ea_t ea)
{
  if ( like_badaddr(ti.bpt_ea) )
    return false;

  if ( ti.bpt_ea == ea )
  {
    context_holder_t ctxh;
    if ( !ti.read_context(&ctxh, X86_RC_GENERAL) )
      return false;
    ctxh.ptr->Eip = ti.bpt_ea; // reset EIP
    ctxh.ptr->ContextFlags = CONTEXT_CONTROL;
    if ( !ti.write_context(X86_RC_GENERAL, *ctxh.ptr) )
      deberr("del_thread_bpt: SetThreadContext");
  }

  // restore old insn if necessary
  restore_original_bytes(ti.bpt_ea);
  ti.bpt_ea = BADADDR;
  return true;
}

//--------------------------------------------------------------------------
// delete all thread breakpoints
// returns true if a breakpoint at which we stopped was removed
bool win32_debmod_t::del_thread_bpts(ea_t ea)
{
  bool found = false;
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    found |= del_thread_bpt(p->second, ea);
  return found;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::set_thread_bpt(thread_info_t &ti, ea_t ea)
{
  // delete old thread bpt if any existed before
  del_thread_bpt(ti, BADADDR);

  ti.bpt_ea = ea;
  int code = save_original_bytes(ti.bpt_ea);
  if ( code )
  {
    if ( code == 2 ) // already have a bpt?
      return true;   // yes, then everything ok
    int size = bpt_code.size();
    code = _write_memory(ti.bpt_ea, bpt_code.begin(), size);
    if ( code > 0 )
    {
      if ( code == size )
        return true;
      // failed to write, forget the original byte
      restore_original_bytes(ti.bpt_ea, false);
    }
  }
  debdeb("%a: set_thread_bpt() failed to pause thread %d\n", ti.bpt_ea, ti.tid);
  ti.bpt_ea = BADADDR;
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::add_thread(const CREATE_THREAD_DEBUG_INFO &thr_info, thid_t tid)
{
  wow64_state_t w = check_wow64_process();
  thread_info_t ti(this, thr_info, tid, w);
  threads.insert(std::make_pair(tid, ti));
}

//--------------------------------------------------------------------------
gdecode_t win32_debmod_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  if ( events.retrieve(event) )
    return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;

  DEBUG_EVENT DebugEvent;
  // we have to wait infinitely if we just try to attach to a running process
  if ( attach_status == as_attaching )
    timeout_ms = INFINITE;
  if ( !WaitForDebugEvent(&DebugEvent, timeout_ms) )
  {
    // no event occurred
    if ( attach_status == as_detaching ) // if we were requested to detach,
    {                                    // we generate a fake detach event
      event->set_eid(PROCESS_DETACHED);
      return GDE_ONE_EVENT;
    }
    // else, we don't return an event
    return GDE_NO_EVENT;
  }

  if ( attach_status == as_attaching )
  {
    if ( DebugEvent.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT )
      return GDE_ERROR;
    // fill in starting information for the just attached process (we couldn't do it from CreateProcess() return values !)
    process_path   = "";
    pid            = DebugEvent.dwProcessId;
    attach_status  = as_breakpoint;
  }

  if ( debug_debugger )
    show_debug_event(DebugEvent);

  // ignore events coming from other child processes
  if ( DebugEvent.dwProcessId != pid )
  {
    debdeb("ignore: pid %x != %x\n", DebugEvent.dwProcessId, pid);
    bool handled = DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
      && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
       || DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT);

    if ( !ContinueDebugEvent(DebugEvent.dwProcessId,
      DebugEvent.dwThreadId,
      handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED) )
    {
      deberr("ContinueDebugEvent");
    }
    return GDE_NO_EVENT;
  }

  event->pid = DebugEvent.dwProcessId;
  event->tid = DebugEvent.dwThreadId;
  event->handled = true;

  gdecode_t gdecode = GDE_ONE_EVENT;
  switch ( DebugEvent.dwDebugEventCode )
  {
    case EXCEPTION_DEBUG_EVENT:
      {
        EXCEPTION_RECORD &er = DebugEvent.u.Exception.ExceptionRecord;
        // remove temporary breakpoints if any
        bool was_thread_bpt = del_thread_bpts(ptr_to_ea(er.ExceptionAddress));
        bool firsttime = DebugEvent.u.Exception.dwFirstChance != 0;
        gdecode = handle_exception(event, er, was_thread_bpt, firsttime);
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      {
        // add this thread to our list
        add_thread(DebugEvent.u.CreateThread, event->tid);
        event->set_info(THREAD_STARTED);
        event->ea = ptr_to_ea(DebugEvent.u.CreateThread.lpStartAddress);
        // set hardware breakpoints if any
        set_hwbpts(DebugEvent.u.CreateThread.hThread);
      }
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      {
        // save information for later
        cpdi = DebugEvent.u.CreateProcessInfo;
        cpdi.lpBaseOfImage = correct_exe_image_base(cpdi.lpBaseOfImage);
        if ( process_handle != INVALID_HANDLE_VALUE && process_handle != cpdi.hProcess )
          myCloseHandle(process_handle); // already have an open handle
        process_handle = cpdi.hProcess;
        // since we do not use the file handle, close it immediately, in order
        // not to hinder the apps that want to open it themselves, exclusively. see pc_win32_open_myself.pe
        myCloseHandle(cpdi.hFile);

        create_start_event(event);
        curproc.insert(std::make_pair(event->modinfo().base, image_info_t(this, event->modinfo())));

        // add record about the main thread into the list
        CREATE_THREAD_DEBUG_INFO ctdi;
        ctdi.hThread           = cpdi.hThread;
        ctdi.lpThreadLocalBase = cpdi.lpThreadLocalBase;
        ctdi.lpStartAddress    = cpdi.lpStartAddress;
        add_thread(ctdi, DebugEvent.dwThreadId);

        // set hardware breakpoints if any
        set_hwbpts(cpdi.hThread);

        // test hardware breakpoints:
        // add_hwbpt(HWBPT_WRITE, 0x0012FF68, 4);
        if ( highdlls.empty() && winver.is_DW32() ) // dw32 specific
        {
          HINSTANCE h = GetModuleHandle(kernel32_dll);
          eanat_t addr = eanat_t(h);
          uint32 size = calc_imagesize(addr);
          highdlls.add(addr, size);
        }
        break;
      }

    case EXIT_THREAD_DEBUG_EVENT:
      {
        threads.erase(event->tid);
        event->set_exit_code(THREAD_EXITED, DebugEvent.u.ExitThread.dwExitCode);
        // invalidate corresponding handles
        HANDLE h = get_thread_handle(event->tid);
        if ( h == thread_handle )
          thread_handle = INVALID_HANDLE_VALUE;
        if ( h == cpdi.hThread )
          cpdi.hThread = INVALID_HANDLE_VALUE;
        break;
      }

    case EXIT_PROCESS_DEBUG_EVENT:
      event->set_exit_code(PROCESS_EXITED, DebugEvent.u.ExitProcess.dwExitCode);
      exiting = true;
      break;

    case LOAD_DLL_DEBUG_EVENT:
      {
        const LOAD_DLL_DEBUG_INFO &dil = DebugEvent.u.LoadDll;
        eanat_t addr = eanat_t(dil.lpBaseOfDll);
        modinfo_t &mi_ll = event->set_modinfo(LIB_LOADED);
        event->ea = trunc_uval(addr);
        mi_ll.base = event->ea;
        mi_ll.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp

        char full_name[MAXSTR];
        full_name[0] = '\0';
        bool ok = get_filename_for(full_name,
                                   sizeof(full_name),
                                   eanat_t(dil.lpImageName),
                                   dil.fUnicode != 0,
                                   addr);
        // Win 7 may send a bogus DLL load event for the main module
        // ignore event if this module has already been mapped
        if ( !ok || module_present(full_name) )
        {
          debdeb("%p: bogus DLL load event, skippping\n", addr);
          goto SILENTLY_RESUME;
        }
        mi_ll.name = full_name;
        uint32 size = calc_imagesize(addr);
        mi_ll.size = size;

        // does the address fit into ea_t?
        HANDLE ntdll_handle = dil.hFile;
        if ( highdlls.add_high_module(addr, size, ntdll_handle) )
        {
          debdeb("%p: 64bit DLL loaded into high addresses has been detected\n",
                 addr);
          goto SILENTLY_RESUME;
        }

        // hFile: When the debugger is finished with this file, it should close the handle using the CloseHandle function.
        // We don't use the handle, so close it immediately
        myCloseHandle(DebugEvent.u.LoadDll.hFile);
        DebugEvent.u.LoadDll.hFile = nullptr;

        // we defer the import of the dll until the moment when ida stops
        // at a debug event. we do so to avoid unnecessary imports because
        // the dll might get unloaded before ida stops.
        image_info_t di(this, dil, size, full_name);
        add_dll(di);
        // determine the attach breakpoint if needed
        size_t max_ntdlls = check_wow64_process() == WOW64_YES ? 2 : 1;
        if ( highdlls.count_ntdlls() < max_ntdlls )
        {
          if ( is_ntdll_name(full_name) )
            highdlls.add_ntdll(addr, size);
          if ( attach_status == as_none && !stop_at_ntdll_bpts )
            expecting_debug_break = highdlls.count_ntdlls();
        }
        break;
      }

SILENTLY_RESUME:
      // do not report this event to ida
      event->handled = true;
      dbg_continue_after_event(event);
      return GDE_NO_EVENT;

    case UNLOAD_DLL_DEBUG_EVENT:
      event->set_info(LIB_UNLOADED);
      {
        eanat_t addr = eanat_t(DebugEvent.u.UnloadDll.lpBaseOfDll);
        range_t range(addr, addr+MEMORY_PAGE_SIZE); // we assume DLL image is at least a PAGE size
        const char *name = get_range_name(dlls, &range);
        if ( name != nullptr )
          event->info() = name;
        else
          event->info().clear();

        // remove ntdll from the list
        HANDLE ntdll_handle;
        if ( highdlls.del_high_module(&ntdll_handle, addr) )
        {
          myCloseHandle(ntdll_handle);
          goto SILENTLY_RESUME;
        }

        // close the associated DLL handle
        images_t::iterator p = dlls.find(addr);
        if ( p != dlls.end() )
        {
          myCloseHandle(p->second.dll_info.hFile);
          // Remove it from the list of dlls to import
          // (in the case it was never imported)
          dlls_to_import.erase(p->first);
          dlls.erase(p);
        }
        else
        {
          debdeb("Could not find dll to unload (base=%a)\n", ptr_to_ea(DebugEvent.u.UnloadDll.lpBaseOfDll));
        }
      }
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      {
        char buf[MAXSTR];
        get_debug_string(DebugEvent, buf, sizeof(buf));
        event->set_info(INFORMATION) = buf;
      }
      break;

    case RIP_EVENT:
      debdeb("RIP_EVENT (system debugging error)");
      break;

    default:
      debdeb("UNKNOWN_EVENT %d", DebugEvent.dwDebugEventCode);
      event->handled = false;      // don't handle it
      break;
  }

  if ( gdecode > GDE_NO_EVENT && attach_status == as_breakpoint && event->eid() == EXCEPTION )
  { // exception while attaching. apparently things went wrong
    // pretend that we attached successfully
    events.enqueue(*event, IN_BACK);
    create_attach_event(event, true);
    attach_status = as_none;
  }
  return gdecode;
}

//--------------------------------------------------------------------------
gdecode_t idaapi win32_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  gdecode_t gdecode = get_debug_event(event, timeout_ms);
  if ( gdecode >= GDE_ONE_EVENT )
  {
    last_event = *event;
    in_event = &last_event;
    pause_requested = false;
  }
  return gdecode;
}


//--------------------------------------------------------------------------
bool win32_debmod_t::get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize)
{
  buf[0] = '\0';
  size_t nullsize = ev.u.DebugString.fUnicode ? sizeof(wchar_t) : 1;
  size_t msize = qmin(ev.u.DebugString.nDebugStringLength, bufsize-nullsize);
  ea_t ea = ptr_to_ea(ev.u.DebugString.lpDebugStringData);
  ssize_t rsize = _read_memory(ea, buf, msize);
  if ( rsize == msize )
  {
    buf[rsize] = '\0';
    if ( ev.u.DebugString.fUnicode )
    {
      *(wchar_t*)(buf + rsize) = 0;
      utf16_to_utf8(buf, bufsize, (LPCWSTR)buf);
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::cleanup()
{
  myCloseHandle(redirin_handle);
  myCloseHandle(redirout_handle);
  myCloseHandle(thread_handle);
  myCloseHandle(process_handle);

  // Close handles of remaining DLLs
  for ( images_t::iterator p=dlls.begin(); p != dlls.end(); ++p )
    myCloseHandle(p->second.dll_info.hFile);

  pid = -1;
  highdlls.clear();
  stop_at_ntdll_bpts = qgetenv("IDA_SYSTEMBREAKPOINT");
  expecting_debug_break = 0;
  in_event = nullptr;
  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile = INVALID_HANDLE_VALUE;
  cpdi.hProcess = INVALID_HANDLE_VALUE;
  cpdi.hThread = INVALID_HANDLE_VALUE;
  attach_status = as_none;
  attach_evid = INVALID_HANDLE_VALUE;

  old_ranges.clear();
  threads.clear();
  thread_bpts.clear();
  bpts.clear();
  curproc.clear();
  dlls.clear();
  dlls_to_import.clear();
  images.clear();
  thread_ranges.clear();
  class_ranges.clear();
  context_helper.clear();
  inherited::cleanup();
}

#define DRVBUFSIZE 512

//--------------------------------------------------------------------------
// Translate path with device name to drive letters.
// e.g. \Device\HarddiskVolume4\Windows\System32\ntdll.dll -> C:\Windows\System32\ntdll.dll
static bool translate_nt_path(qstring *out, LPCWSTR pszFilename)
{
  // get a list of all drive letters
  WCHAR szTemp[DRVBUFSIZE];
  if ( GetLogicalDriveStringsW(qnumber(szTemp)-1, szTemp) )
  {
    WCHAR szName[MAX_PATH];
    WCHAR szDrive[3] = L" :";
    BOOL bFound = FALSE;
    WCHAR *p = szTemp;

    do
    {
      // Copy the drive letter to the template string
      *szDrive = *p;

      // Look up device name for this drive
      DWORD uNameLen = QueryDosDeviceW(szDrive, szName, qnumber(szName) - 1);
      if ( uNameLen != 0 )
      {
        // for some reason return value is 2 chars longer, so get the actual length
        uNameLen = wcslen(szName);
        // do we have a match at the start of filename?
        bFound = _wcsnicmp(pszFilename, szName, uNameLen) == 0
              && pszFilename[uNameLen] == L'\\';

        if ( bFound )
        {
          // Reconstruct filename
          // by replacing device path with DOS path (drive)
          qstring path;
          utf16_utf8(out, szDrive);
          utf16_utf8(&path, pszFilename + uNameLen);
          out->append(path);
          return true;
        }
      }

      // Go to the next nullptr character.
      while ( *p++ )
        ;
    }
    while ( !bFound && *p ); // end of string
  }
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::get_filename_for(
        char *buf,
        size_t bufsize,
        eanat_t image_name_ea,
        bool use_unicode,
        eanat_t image_base)
{
  buf[0] = '\0';
  // if we have address of file name in the process image from the debug API, try to use it
  //   remark: depending on the OS, NTDLL.DLL can return an empty string or only the DLL name!
  if ( image_name_ea != 0 )
  {
    if ( get_filename_from_process(image_name_ea, use_unicode, buf, bufsize) )
    {
      if ( qisabspath(buf) )
        return true;
    }
  }

  // various fallbacks
  // first try GetMappedFileName
  if ( _GetMappedFileName != nullptr )
  {
    wchar16_t tbuf[MAXSTR];
    HMODULE hmod = (HMODULE)(size_t)image_base;
    if ( _GetMappedFileName(process_handle, hmod, tbuf, qnumber(tbuf)) )
    {
      qstring tmp;
      if ( translate_nt_path(&tmp, tbuf) )
      {
        qstrncpy(buf, tmp.c_str(), bufsize);
        return true;
      }
    }
  }

  // then try GetModuleFileNameEx
  if ( _GetModuleFileNameEx != nullptr )
  {
    wchar16_t tbuf[MAXSTR];
    HMODULE hmod = (HMODULE)(size_t)image_base;
    if ( _GetModuleFileNameEx(process_handle, hmod, tbuf, qnumber(tbuf)) )
    {
      qstring tmp;
      utf16_utf8(&tmp, tbuf);
      qstrncpy(buf, tmp.c_str(), bufsize);
      return true;
    }
  }

  // last: we try to get DLL name by looking at the export name from
  //   the export directory in PE image in debugged process.
  // this is the least reliable way since this string may not match the actual dll filename
  get_pe_export_name_from_process(image_base, buf, bufsize);

  // for dlls without path, try to find it
  find_full_path(buf, bufsize, process_path.c_str());

  // convert possible short path to long path
  qffblk64_t fb;
  if ( qfindfirst(buf, &fb, 0) == 0 )
  {
    char *fptr = qbasename(buf);
    qstrncpy(fptr, fb.ff_name, bufsize-(fptr-buf));
  }
  return buf[0] != '\0';
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_detach_process()
{
  check_thread(false);
  if ( in_event != nullptr )
    dbg_continue_after_event(in_event);
  BOOL ret = get_tool_help()->debug_detach_process(pid);
  if ( ret )
  {
    attach_status = as_detaching;
    exiting = true;
  }
  return ret ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_init(uint32_t *flags2, qstring * /*errbuf*/)
{
  check_thread(true);

  cleanup();

  if ( flags2 != nullptr )
    *flags2 = g_code;

  return DRC_OK;
}

//--------------------------------------------------------------------------
image_info_t::image_info_t(win32_debmod_t *ses)
  : sess(ses), base(BADADDR), imagesize(0)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(
        win32_debmod_t *ses,
        ea_t _base,
        uint32 _imagesize,
        const qstring &_name)
  : sess(ses), base(_base), imagesize(_imagesize), name(_name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(
        win32_debmod_t *ses,
        const LOAD_DLL_DEBUG_INFO &i,
        uint32 _imagesize,
        const char *_name)
  : sess(ses), name(_name), dll_info(i)
{
  base = ses->ptr_to_ea(i.lpBaseOfDll);
  imagesize = _imagesize;
}

image_info_t::image_info_t(win32_debmod_t *ses, const modinfo_t &m)
  : sess(ses), base(m.base), imagesize(m.size), name(m.name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

//--------------------------------------------------------------------------
// get (path+)name from debugged process
// lpFileName - pointer to pointer to the file name
// use_unicode - true if the filename is in unicode
bool win32_debmod_t::get_filename_from_process(
        eanat_t name_ea,
        bool use_unicode,
        char *buf,
        size_t bufsize)
{
  buf[0] = '\0';
  if ( name_ea == 0 )
    return false;
  eanat_t dll_addr;
  if ( _read_memory(name_ea, &dll_addr, sizeof(dll_addr)) != sizeof(dll_addr) )
    return false;
  if ( dll_addr == 0 )
    return false;
  name_ea = dll_addr;
  if ( _read_memory(name_ea, buf, bufsize) != bufsize )
    return false;
  if ( use_unicode )
    utf16_to_utf8(buf, bufsize, (LPCWSTR)buf);
  return true;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_region_info(ea_t ea, memory_info_t *mi)
{
  // okay to keep static, they won't change between clients
  static DWORD_PTR totalVirtual = 0;
  static DWORD granularity = 0;

  if ( totalVirtual == 0 )
  {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    totalVirtual = (DWORD_PTR)si.lpMaximumApplicationAddress;
  }

  void *addr = (void *)(size_t)ea;
  MEMORY_BASIC_INFORMATION meminfo;
  while ( !VirtualQueryEx(process_handle,    // handle of process
                          addr,              // address of region
                          &meminfo,          // address of information buffer
                          sizeof(meminfo)) ) // size of buffer
  {
    // On Windows CE VirtualQueryEx can fail when called with addr == 0,
    // so try to call it again with the next page (and end loop after 2d
    // iteration to prevent scanning of huge number of pages)
    // It's possible VirtualQueryEx fails on Windows CE not only for zero
    // address: perhaps we shouldn't limit the number of iterations and return
    // to using of a separate variable 'first' (as in win32_debmod.cpp#34)
    if ( ea != 0 || ea >= totalVirtual )
      return BADADDR;
    // try to find next valid page
    ea += granularity;
    addr = (void *)(size_t)ea;
  }

  eanat_t startea = (eanat_t)meminfo.BaseAddress;
  eanat_t endea = startea + meminfo.RegionSize;
  if ( endea <= startea  // overflow/empty?
#if !defined(__X86__)
    || endea >= eah().mask  // crossed 4GB boundary
#endif
    )
  {
    if ( endea == startea )
    {
      // ignore empty sections ...
      mi->start_ea = BADADDR;
      mi->end_ea   = BADADDR;
      return trunc_uval(endea + 1);
    }
    // signal end of enumeration
    endea = BADADDR;
  }

//  debdeb("VirtualQueryEx(%a): base = %a, end = %a, protect=0x%x, allocprotect=0x%x, state=0x%x\n", ea, startea, endea, meminfo.Protect, meminfo.AllocationProtect, meminfo.State);

  // hide the page bpts in this memory region from ida
  uint32 prot = meminfo.Protect;
  if ( mask_page_bpts(trunc_uval(startea), trunc_uval(endea), &prot) )
  {
    debdeb("   masked protect=0x%x\n", prot);
    meminfo.Protect = prot;
  }

  if ( (meminfo.State & (MEM_FREE|MEM_RESERVE)) == MEM_FREE // if the range isn't interesting for/accessible by IDA
    || (meminfo.Protect & PAGE_NOACCESS) != 0 )
  { // we simply return an invalid range, and a pointer to the next (eventual) range
    mi->start_ea = BADADDR;
    mi->end_ea   = BADADDR;
    return trunc_uval(endea);
  }

  mi->start_ea = trunc_uval(startea);
  mi->end_ea   = trunc_uval(endea);
#ifdef __EA64__
  // we may be running a 32bit process in wow64 with ida64
  mi->bitness = check_wow64_process() > 0 ? 1 : 2;
#else
  mi->bitness = 1; // 32bit
#endif

  // convert Windows protection modes to IDA protection modes
  mi->perm = win_prot_to_ida_perm(meminfo.Protect);

  // try to associate a segment name to the memory range
  const char *ptr;
  if ( (ptr=get_range_name(curproc,       mi)) != nullptr   // first try with the current process
    || (ptr=get_range_name(dlls,          mi)) != nullptr   // then try in DLLs
    || (ptr=get_range_name(images,        mi)) != nullptr   // then try in previous images ranges
    || (ptr=get_range_name(thread_ranges, mi)) != nullptr ) // and finally in thread ranges
  {
    // return the filename without the file path
    mi->name = qbasename(ptr);
  }
  else
  {
    char buf[MAXSTR];
    buf[0] = '\0';
    // check for a mapped filename
    get_filename_for(buf, sizeof(buf), 0, false, mi->start_ea);
    if ( buf[0] != '\0' )
    {
      mi->name = qbasename(buf);
    }
    // if we found nothing, check if the segment is a PE file header,
    // and we try to locate a name in it
    else if ( get_pe_export_name_from_process(mi->start_ea, buf, sizeof(buf)) )
    { // we insert it in the image ranges list
      uint32 size = calc_imagesize(mi->start_ea);
      image_info_t ii(this, mi->start_ea, size, buf);
      images.insert(std::make_pair(ii.base, ii));
      mi->name = buf;
    }
  }

  // try to associate a segment class name to the memory range
  mi->sclass = get_range_name(class_ranges, mi);
  return trunc_uval(endea);
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_attach_process(pid_t _pid, int event_id, int /*flags*/, qstring * /*errbuf*/)
{
  check_thread(false);
#ifndef __EA64__
  int addrsize = get_process_addrsize(_pid);
  if ( addrsize > 4 )
  {
    dwarning("AUTOHIDE NONE\nPlease use ida64 to debug 64-bit applications");
    SetLastError(ERROR_NOT_SUPPORTED);
    return DRC_FAILED;
  }
#endif
  if ( !DebugActiveProcess(_pid) )
  {
    deberr("DebugActiveProcess %08lX", _pid);
    return DRC_FAILED;
  }

  if ( !handle_process_start(_pid) )
    return DRC_FAILED;

  attach_status = as_attaching;
  attach_evid = (HANDLE)(INT_PTR)(event_id);
  exiting = false;
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring * /*errbuf*/)
{
  check_thread(false);
  // input file specified in the database does not exist
  if ( input_path[0] != '\0' && !qfileexist(input_path) )
  {
    dwarning("AUTOHIDE NONE\nInput file is missing: %s", input_path);
    return DRC_NOFILE;
  }

  input_file_path = input_path;
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;

  char fullpath[QMAXPATH];
  if ( !qfileexist(path) )
  {
    if ( qisabspath(path) || !search_path(fullpath, sizeof(fullpath), path, false) )
    {
      dwarning("AUTOHIDE NONE\nCannot find application file '%s'", path);
      return DRC_NETERR;
    }
    path = fullpath;
  }

  drc_t drc = DRC_OK;
  if ( !check_input_file_crc32(input_file_crc32) )
    drc = DRC_CRC;

  exiting = false;

  // Build a full command line
  qstring args_buffer; // this vector must survive until create_process()
  if ( args != nullptr && args[0] != '\0' )
  {
    args_buffer += '"';
    args_buffer += path;
    args_buffer += '"';
    args_buffer += ' ';
    args_buffer += args;
    args = args_buffer.c_str();
  }

  PROCESS_INFORMATION ProcessInformation;
  bool is_gui = (flags & DBG_PROC_IS_GUI) != 0;
  bool hide_window = (flags & DBG_HIDE_WINDOW) != 0;
  if ( !create_process(path, args, envs, startdir, is_gui, hide_window, &ProcessInformation) )
    return DRC_FAILED;

  pid            = ProcessInformation.dwProcessId;
  process_handle = ProcessInformation.hProcess;
  thread_handle  = ProcessInformation.hThread;
  process_path   = path;

  if ( !handle_process_start(pid) )
    return DRC_NETERR;

  return drc;
}

//--------------------------------------------------------------------------
//lint -esym(1762,win32_debmod_t::myCloseHandle) could be made const
bool win32_debmod_t::myCloseHandle(HANDLE &h)
{
  bool ok = true;
  if ( h != INVALID_HANDLE_VALUE && h != nullptr )
  {
    DWORD code;
    __try
    {
      ok = CloseHandle(h) != 0;
      if ( !ok )
        deberr("CloseHandle(%08X)", h);
    }
    __except ( code=GetExceptionCode() )
    {
      debdeb("CloseHandle(%08X) exception code %08X\n", h, code);
      ok = false;
    }
    h = INVALID_HANDLE_VALUE;
  }
  return ok;
}

//--------------------------------------------------------------------------
void win32_debmod_t::install_callgate_workaround(thread_info_t *ti, const debug_event_t *event)
{
  // add a breakpoint after the call statement
  ea_t bpt = event->ea + 7;
  ti->callgate_ea = bpt;
  if ( !set_thread_bpt(*ti, bpt) )
    INTERR(637); // how can it be?
}

//--------------------------------------------------------------------------
// we do not use 'firsttime' argument anymore. we could use it to distinguish
// the first chance and the second chance but it is more logical to
// behave consistently.
gdecode_t win32_debmod_t::handle_exception(
        debug_event_t *event,
        const EXCEPTION_RECORD &er,
        bool was_thread_bpt,
        bool /*firsttime*/)
{
  int code = er.ExceptionCode;
  const exception_info_t *ei = find_exception(code);

  eanat_t addr = eanat_t(er.ExceptionAddress);
  excinfo_t &exc = event->set_exception();
  event->ea = trunc_uval(addr);
  exc.code = code;
  exc.can_cont = (er.ExceptionFlags == 0);
  exc.ea = BADADDR;
  event->handled = false;

  if ( exiting && ei == nullptr )
  {
    event->set_exit_code(PROCESS_EXITED, -1);
    return GDE_ONE_EVENT;
  }

  bool suspend = true;

  // we don't expect callgate breakpoints anymore
  ea_t was_callgate_ea = BADADDR;
  thread_info_t *ti = threads.get(event->tid);
  if ( ti != nullptr )
  {
    was_callgate_ea = ti->callgate_ea;
    ti->callgate_ea = BADADDR;
  }

  if ( ei != nullptr )
  {
    event->handled = ei->handle();
    // if the user asked to suspend the process, do not resume
    if ( !was_thread_bpt )
      suspend = ei->break_on() || pause_requested;
  }
  if ( !suspend )
    suspend = should_suspend_at_exception(event, ei);
  exc.info.qclear();
  int elc_flags = 0;
  switch ( uint32(code) )
  {
    case EXCEPTION_BREAKPOINT:
    case STATUS_WX86_BREAKPOINT:
      if ( was_thread_bpt )
      {
        QASSERT(638, ti != nullptr);

        // is installed the workaround for the 'freely running after syscall' problem?
        if ( was_callgate_ea == event->ea )
          event->set_eid(STEP);
        else
          event->set_eid(PROCESS_SUSPENDED);
        break;
      }
      if ( attach_status == as_breakpoint ) // the process was successfully suspended after an attachement
      {
        create_attach_event(event, true);
        break;
      }
      if ( expecting_debug_break > 0
        && highdlls.has(addr)
        && get_kernel_bpt_ea(event->ea, event->tid) == BADADDR ) // not user-defined bpt
      {
        --expecting_debug_break;
        debdeb("%a: resuming after DbgBreakPoint(), expecting bpts: %d\n", event->ea, expecting_debug_break);
        event->handled = true;
        dbg_continue_after_event(event);
        return GDE_NO_EVENT;
      }
      // is this a breakpoint set by ida?
      {
        ea_t kea = get_kernel_bpt_ea(event->ea, event->tid);
        if ( kea != BADADDR )
        {
          bptaddr_t &bpta = event->set_bpt();
          bpta.hea = BADADDR; // no referenced address (only for hardware breakpoint)
          bpta.kea = kea == event->ea ? BADADDR : kea;
          event->handled = true;
        }
      }
      break;
    case EXCEPTION_SINGLE_STEP:
    case STATUS_WX86_SINGLE_STEP:
      {
        bool is_stepping = ti != nullptr && ti->is_tracing();
        // if this happened because of a hardware breakpoint
        // find out which one caused it
        if ( !check_for_hwbpt(event, is_stepping) )
        {
          // if we have not asked for single step, do not convert it to STEP
          if ( is_stepping )
          {
            event->set_eid(STEP);   // Single-step breakpoint
            event->handled = true;
            ti->clr_tracing();
            break;
          }
        }
      }
      break;
    case EXCEPTION_ACCESS_VIOLATION:
      {
        ea_t exc_ea = trunc_uval(er.ExceptionInformation[1]); // virtual address of the inaccessible data.
        exc.ea = exc_ea;
        // is this a page bpt?
        page_bpts_t::iterator p = find_page_bpt(exc_ea);
        if ( p == page_bpts.end() )
        {
          exc_ea = event->ea;
          p = find_page_bpt(exc_ea);
        }
        if ( p != page_bpts.end() )
        {
          // since on access violation the system does not update anything
          // there is no need to reset eip when handling lowcnd below.
          elc_flags |= ELC_KEEP_EIP;
          ea_t exc_eip = ptr_to_ea(er.ExceptionAddress);
          if ( !should_fire_page_bpt(p, exc_ea, er.ExceptionInformation[0],
                                     exc_eip, dep_policy) )
          { // Silently step over the page breakpoint
            if ( ti != nullptr && ti->is_tracing() )
              elc_flags |= ELC_KEEP_SUSP;
            lowcnd_t lc;
            const pagebpt_data_t &bpt = p->second;
            lc.ea = bpt.ea;
            lc.type = bpt.type;
            lc.size = bpt.user_len;
            if ( !handling_lowcnds.has(bpt.ea)
              && handle_lowcnd(&lc, event, elc_flags) )
            {
              if ( (elc_flags & ELC_KEEP_SUSP) != 0 )
              { // if we were tracing, report a STEP event
                event->set_eid(STEP);
                event->handled = true;
                ti->clr_tracing();
                return GDE_ONE_EVENT;
              }
              return GDE_NO_EVENT;
            }
            // failed to step over, return the exception
          }
          else
          {
            bptaddr_t &bpta = event->set_bpt();
            bpta.hea = exc_ea;
            bpta.kea = BADADDR;
            event->handled = true;
            break;
          }
        }
        if ( ei != nullptr && event->eid() == EXCEPTION )
        {
          int einfo = er.ExceptionInformation[0];
          const char *verb = einfo == EXCEPTION_EXECUTE_FAULT ? "executed"
                           : einfo == EXCEPTION_WRITE_FAULT   ? "written"
                           :                                    "read";
          exc.info.sprnt(ei->desc.c_str(), event->ea, exc.ea, verb);
        }
      }
      break;
#define EXCEPTION_BCC_FATAL  0xEEFFACE
#define EXCEPTION_BCC_NORMAL 0xEEDFAE6
    case EXCEPTION_BCC_FATAL:
    case EXCEPTION_BCC_NORMAL:
      if ( er.NumberParameters == 5
        && er.ExceptionInformation[0] == 2 // these numbers are highly hypothetic
        && er.ExceptionInformation[1] == 3 )
      {
        EXCEPTION_RECORD r2;
        if ( dbg_read_memory(er.ExceptionInformation[3], &r2, sizeof(r2), nullptr) == sizeof(r2) )
          return handle_exception(event, r2, false, false);
      }
      break;
#define MS_VC_EXCEPTION 0x406D1388
    case MS_VC_EXCEPTION:
      // SetThreadName
      // https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
      if ( er.ExceptionInformation[0] == 0x1000
        && er.ExceptionInformation[3] == 0x00 )
      {
        qstring name;
        name.resize(MAXSTR);
        ea_t nameaddr = er.ExceptionInformation[1];
        if ( dbg_read_memory(nameaddr, name.begin(), name.length(), nullptr) > 0 )
        {
          thid_t tid = er.ExceptionInformation[2];
          msg("Thread %d is named '%s'\n", tid, name.c_str());
          thread_info_t *tin = threads.get(tid);
          if ( tin != nullptr )
          {
            tin->name = name.c_str();
            tin->set_new_name();
          }
          event->handled = true;
        }
      }
      break;
  }
  if ( !pause_requested && evaluate_and_handle_lowcnd(event, elc_flags) )
    return GDE_NO_EVENT;

  if ( event->eid() == EXCEPTION )
  {
    if ( ei == nullptr )
    {
      exc.info.sprnt("unknown exception code %X", code);
    }
    else if ( exc.info.empty() )
    {
      exc.info.sprnt(ei->desc.c_str(), event->ea,
                     ea_t(er.ExceptionInformation[0]),
                     ea_t(er.ExceptionInformation[1]));
    }
    if ( !suspend )
    {
      log_exception(event, ei);
      // if a single step was scheduled by the user
      if ( ti != nullptr && ti->is_tracing() )
      {
        clear_tbit(*ti);
        if ( event->handled )
        {
          // since we mask the exception, we generate a STEP event
          event->set_eid(STEP);
          return GDE_ONE_EVENT; // got an event
        }
      }
      dbg_continue_after_event(event);
      return GDE_NO_EVENT;
    }
  }
  return GDE_ONE_EVENT;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::check_for_hwbpt(debug_event_t *event, bool is_stepping)
{
  ea_t ea = is_hwbpt_triggered(event->tid, is_stepping);
  if ( ea != BADADDR )
  {
    bptaddr_t &addr = event->set_bpt();
    addr.hea = ea;
    addr.kea = BADADDR;
    event->handled = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_attach_event(debug_event_t *event, bool attached)
{
  event->set_modinfo(PROCESS_ATTACHED);
  event->handled = true;
  if ( attached )
    attach_status = as_attached;
  else
    attach_status = as_attaching;
  if ( attach_evid != INVALID_HANDLE_VALUE )
  {
    SetEvent(attach_evid);
    attach_evid = INVALID_HANDLE_VALUE;
  }
  modinfo_t &mi_ps = event->modinfo();
  get_debugged_module_info(&mi_ps);

  binary_to_import = mi_ps;
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_start_event(debug_event_t *event)
{
  modinfo_t &mi_ps = event->set_modinfo(PROCESS_STARTED);
  ea_t base = ptr_to_ea(cpdi.lpBaseOfImage);

  process_snapshot_t psnap(get_tool_help());
  PROCESSENTRY32 pe32;
  for ( bool ok = psnap.first(TH32CS_SNAPNOHEAPS, &pe32); ok; ok = psnap.next(&pe32) )
  {
    if ( pe32.th32ProcessID == event->pid )
    {
      char exefile[QMAXPATH];
      tchar_utf8(exefile, pe32.szExeFile, sizeof(exefile));
      if ( !qisabspath(exefile) )
      {
        char abspath[QMAXPATH];
        get_filename_for(abspath,
                         sizeof(abspath),
                         /*image_name_ea=*/ 0,
                         /*use_unicode=*/ false, // irrelevant
                         base);
        if ( abspath[0] != '\0' )
          qstrncpy(exefile, abspath, sizeof(exefile));
      }
      if ( process_path.empty() || qisabspath(exefile) )
        process_path = exefile;
      break;
    }
  }
  mi_ps.name = process_path;
  mi_ps.base = base;
  mi_ps.size = calc_imagesize(base);
  mi_ps.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp

  binary_to_import = mi_ps;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_kernel_bpt_ea(ea_t ea, thid_t tid)
{
  if ( is_ida_bpt(ea, tid) )
    return ea;
  return BADADDR;
}


ssize_t idaapi win32_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring * /*errbuf*/)
{
  check_thread(false);
  return _write_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_get_sreg_base(
        ea_t *pea,
        thid_t tid,
        int sreg_value,
        qstring * /*errbuf*/)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr);
  HANDLE h = get_thread_handle(tid);
  if ( h == INVALID_HANDLE_VALUE )
    return DRC_FAILED;

#ifndef __X86__

  thread_info_t *ti = threads.get(tid);
  context_holder_t ctxh;
  if ( ti != nullptr && ti->read_context(&ctxh, X86_RC_SEGMENTS) )
  {
    // is this a TLS base register? (FS for wow64 and GS for x64)
    if ( sreg_value == ctxh.ptr->SegGs && !ti->is_wow64()
      || sreg_value == ctxh.ptr->SegFs && ti->is_wow64() )
    {
      // lpThreadLocalBase is the native (X64) TEB, or GS base
      if ( sreg_value == ctxh.ptr->SegGs )
        *pea = ptr_to_ea(ti->lpThreadLocalBase);
      else
      {
        // fs base is the WoW64 TEB
        // pointer to it is the first field in the native TEB
        LPVOID tib32;
        if ( _read_memory(ptr_to_ea(ti->lpThreadLocalBase), &tib32, sizeof(tib32)) != sizeof(tib32) )
          return DRC_FAILED;
        *pea = ptr_to_ea(tib32);
      }
      return DRC_OK;
    }
    else if ( ti->is_wow64() )
    {
      WOW64_LDT_ENTRY se;
      if ( !_Wow64GetThreadSelectorEntry(h, sreg_value, &se) )
      {
        if ( GetLastError() == ERROR_NOT_SUPPORTED )
        {
          // in x64 all selectors except fs/gs are 0-based
          *pea = 0;
          return DRC_OK;
        }
        deberr("GetThreadSelectorEntry");
        return DRC_FAILED;
      }
     *pea = (se.HighWord.Bytes.BaseHi << 24)
          | (se.HighWord.Bytes.BaseMid << 16)
          | se.BaseLow;
     return DRC_OK;
    }
  }
#endif  // __X64__
  // the below code works for non-x64
  LDT_ENTRY se;
  if ( !GetThreadSelectorEntry(h, sreg_value, &se) )
  {
    if ( GetLastError() == ERROR_NOT_SUPPORTED )
    {
      *pea = 0;
      return DRC_OK;
    }
    deberr("GetThreadSelectorEntry");
    return DRC_FAILED;
  }

  *pea = (se.HighWord.Bytes.BaseHi << 24)
       | (se.HighWord.Bytes.BaseMid << 16)
       | se.BaseLow;
  return DRC_OK;
}

//-------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_write_register(
        thid_t tid,
        int reg_idx,
        const regval_t *value,
        qstring * /*errbuf*/)
{
  check_thread(false);
  if ( value == nullptr )
    return DRC_FAILED;

  NODISTURB_ASSERT(in_event != nullptr);

  reg_ctx->setup(tid);
  reg_ctx->setup_reg(reg_idx);
  if ( !reg_ctx->load() )
    return DRC_FAILED;

  if ( !reg_ctx->patch(reg_idx, value) )
    return DRC_FAILED;

  if ( !reg_ctx->store() )
    return DRC_FAILED;

  return DRC_OK;
}

//--------------------------------------------------------------------------
bool idaapi win32_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values)
{
  if ( values == nullptr )
    return false;

  reg_ctx->setup(tid);
  for ( size_t i = 0; i < count; i++ )
    reg_ctx->setup_reg(start + i);
  if ( !reg_ctx->load() )
    return false;

  for ( size_t i = 0; i < count; i++, values++ )
    if ( !reg_ctx->patch(start + i, values) )
      return false;

  if ( !reg_ctx->store() )
    return false;

  return true;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_read_registers(
        thid_t tid,
        int clsmask,
        regval_t *values,
        qstring * /*errbuf*/)
{
  check_thread(false);
  if ( values == nullptr )
    return DRC_FAILED;

  reg_ctx->setup(tid, clsmask);
  if ( !reg_ctx->load() )
    return DRC_FAILED;

  reg_ctx->read_all(values);

  return DRC_OK;
}

//--------------------------------------------------------------------------
bool thread_info_t::toggle_tbit(bool set_tbit)
{
  context_holder_t ctxh;
  if ( !read_context(&ctxh, X86_RC_GENERAL) )
    return false;

  bool ok = true;
  CASSERT(EFLAGS_TRAP_FLAG == 0x100); // so we can shift set_tbit << 8
  if ( (ctxh.ptr->EFlags & EFLAGS_TRAP_FLAG) != (set_tbit << 8) )   //lint !e647 possible truncation before conversion from 'int' to 'unsigned long'
  {
    QASSERT(30117, (ctxh.ptr->ContextFlags & CONTEXT_CONTROL) != 0);
    ctxh.ptr->EFlags |= EFLAGS_TRAP_FLAG;
    ctxh.ptr->ContextFlags = CONTEXT_CONTROL;
    ok = write_context(X86_RC_GENERAL, *ctxh.ptr);
    if ( ok )
      setflag(flags, THR_TRACING, set_tbit);
    else
      debmod->deberr("%d: SetThreadContext failed", tid);
  }
  return ok;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return DRC_FAILED; // not supported

  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr);
  thread_info_t *ti = threads.get(tid);
  if ( ti == nullptr )
    return DRC_FAILED;

  bool ok = ti->toggle_tbit(true);
  if ( !ok )
    deberr("%d: (set_step) SetThreadContext failed", tid);
  return ok ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::clear_tbit(thread_info_t &ti)
{
  NODISTURB_ASSERT(in_event != nullptr);
  bool ok = ti.toggle_tbit(false);
  if ( !ok )
    deberr("%d: (clr_step) SetThreadContext failed", ti.tid);
  return ok;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != nullptr || exiting);

  if ( event == nullptr )
    return DRC_FAILED;

  if ( events.empty() )
  {
    bool done = false;
    if ( !done )    //-V547 '!done' is always true
    {
      // check if we need to install the workaround for single stepping over callgates
      thread_info_t *ti = threads.get(event->tid);
      if ( ti != nullptr && ti->is_tracing() )
      {
        if ( check_for_call_large(event, process_handle) )
          install_callgate_workaround(ti, event);
      }

      int flag = event->handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
      if ( !ContinueDebugEvent(event->pid, event->tid, flag) )
      {
        deberr("ContinueDebugEvent");
        return DRC_FAILED;
      }
      debdeb("ContinueDebugEvent: handled=%s\n", event->handled ? "yes" : "no");
      if ( event->eid() == PROCESS_EXITED )
      {
        // from WaitForDebugEvent help page:
        //  If the system previously reported an EXIT_PROCESS_DEBUG_EVENT debugging event,
        //  the system closes the handles to the process and thread when the debugger calls the ContinueDebugEvent function.
        // => we don't close these handles to avoid error messages
        cpdi.hProcess = INVALID_HANDLE_VALUE;
        cpdi.hThread  = INVALID_HANDLE_VALUE;
        process_handle= INVALID_HANDLE_VALUE;
        thread_handle = INVALID_HANDLE_VALUE;
        cleanup();
      }
    }
  }
  in_event = nullptr;
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_exit_process(qstring * /*errbuf*/)
{
  check_thread(false);
  // WindowsCE sometimes reports failure but terminates the application.
  // We ignore the return value.
  bool check_termination_code = prepare_to_stop_process(in_event, threads);
  bool terminated = TerminateProcess(process_handle, -1) != 0;
  if ( !terminated && check_termination_code )
  {
    deberr("TerminateProcess");
    return DRC_FAILED;
  }
  exiting = true;

  if ( in_event != nullptr && dbg_continue_after_event(in_event) != DRC_OK )
  {
    deberr("continue_after_event");
    return DRC_FAILED;
  }
  return DRC_OK;
}


//--------------------------------------------------------------------------
void win32_debmod_t::show_exception_record(const EXCEPTION_RECORD &er, int level)
{
  char name[MAXSTR];
  get_exception_name(er.ExceptionCode, name, sizeof(name));
  if ( level > 0 )
    dmsg("%*c", level, ' ');
  dmsg("%s: fl=%X adr=%a #prm=%d\n",
    name,
    er.ExceptionFlags,
    ptr_to_ea(er.ExceptionAddress),
    er.NumberParameters);
  if ( er.NumberParameters > 0 )
  {
    dmsg("%*c", level+2, ' ');
    int n = qmin(er.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
    for ( int i=0; i < n; i++ )
      dmsg("%s0x%a", i == 0 ? "" : " ", ea_t(er.ExceptionInformation[i]));
    dmsg("\n");
  }
  if ( er.ExceptionRecord != nullptr )
    show_exception_record(*er.ExceptionRecord, level+2);
}

//--------------------------------------------------------------------------
void win32_debmod_t::show_debug_event(const DEBUG_EVENT &ev)
{
  if ( !debug_debugger )
    return;
  dmsg("[%u %d] ", ev.dwProcessId, ev.dwThreadId);
  switch ( ev.dwDebugEventCode )
  {
    case EXCEPTION_DEBUG_EVENT:
      {
        const EXCEPTION_RECORD &er = ev.u.Exception.ExceptionRecord;
        dmsg("EXCEPTION: ea=%p first: %d", // no \n intentionally
          er.ExceptionAddress, ev.u.Exception.dwFirstChance);
        show_exception_record(er);
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      dmsg("CREATE_THREAD: hThread=%X LocalBase=%p Entry=%p\n",
        ev.u.CreateThread.hThread,
        ev.u.CreateThread.lpThreadLocalBase,
        ev.u.CreateThread.lpStartAddress);
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      {
        const CREATE_PROCESS_DEBUG_INFO &cpinf = ev.u.CreateProcessInfo;
        char path[QMAXPATH];
        if ( process_handle == INVALID_HANDLE_VALUE )
          process_handle = cpinf.hProcess;
        get_filename_for(
          path,
          sizeof(path),
          eanat_t(cpinf.lpImageName),
          cpinf.fUnicode != 0,
          eanat_t(cpinf.lpBaseOfImage));
        dmsg("CREATE_PROCESS: hFile=%X hProcess=%X hThread=%X "
          "base=%p\n dbgoff=%X dbgsiz=%X tlbase=%p start=%p name=%p '%s' \n",
          cpinf.hFile, cpinf.hProcess, cpinf.hThread, cpinf.lpBaseOfImage,
          cpinf.dwDebugInfoFileOffset, cpinf.nDebugInfoSize, cpinf.lpThreadLocalBase,
          cpinf.lpStartAddress, cpinf.lpImageName, path);
      }
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      dmsg("EXIT_THREAD: code=%d\n", ev.u.ExitThread.dwExitCode);
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      dmsg("EXIT_PROCESS: code=%d\n", ev.u.ExitProcess.dwExitCode);
      break;

    case LOAD_DLL_DEBUG_EVENT:
      {
        char path[QMAXPATH];
        const LOAD_DLL_DEBUG_INFO &di = ev.u.LoadDll;
        get_filename_for(
          path,
          sizeof(path),
          eanat_t(di.lpImageName),
          di.fUnicode != 0,
          eanat_t(di.lpBaseOfDll));
        dmsg("LOAD_DLL: h=%X base=%p dbgoff=%X dbgsiz=%X name=%X '%s'\n",
          di.hFile, di.lpBaseOfDll, di.dwDebugInfoFileOffset, di.nDebugInfoSize,
          di.lpImageName, path);
      }
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      dmsg("UNLOAD_DLL: base=%p\n", ev.u.UnloadDll.lpBaseOfDll);
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      {
        char buf[MAXSTR];
        get_debug_string(ev, buf, sizeof(buf));
        dmsg("OUTPUT_DEBUG_STRING: str=\"%s\"\n", buf);
      }
      break;

    case RIP_EVENT:
      dmsg("RIP_EVENT (system debugging error)\n");
      break;

    default:
      dmsg("UNKNOWN_DEBUG_EVENT %d\n", ev.dwDebugEventCode);
      break;
  }
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_freeze_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_suspend_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_thaw_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_resume_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi win32_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  bool ret = false;
  if ( restore_broken_breakpoints() )
  {
    // create the required event for synchronization; we use it
    // to notify when the process was successfully detached
    broken_event_handle = CreateEvent(nullptr, false, false, nullptr);

    if ( broken_event_handle != nullptr )
    {
      int code = WAIT_TIMEOUT;
      while ( code == WAIT_TIMEOUT )
        code = WaitForSingleObject(broken_event_handle, 100);

      if ( code == WAIT_OBJECT_0 )
      {
        suspend_running_threads(_suspended_threads);
        if ( dbg_detach_process() == DRC_OK )
          SetEvent(broken_event_handle);
      }
    }
  }

  return ret;
}

//--------------------------------------------------------------------------
// Continuing from a broken connection in win32 debugger consist in the
// following step (if we're talking about a single threaded server):
//
//  1 - Notify the other thread that we want to reuse that connection
//  2 - Wait for the previous thread to notify that finished his work
//  3 - Reattach to the process and reopen thread's handles as, for a
//      reason, the handles we have are invalid (why?).
//  4 - Resume the threads we suspended before.
//
bool idaapi win32_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(_pid);

  QASSERT(676, broken_event_handle != nullptr);

  // notify the broken thread we want to reuse the connection
  SetEvent(broken_event_handle);

  // and wait for the notification for a maximum of 15 seconds
  // as we don't want to wait forever (INFINITE) because the
  // other thread may fail
  int code = WaitForSingleObject(broken_event_handle, 15000);
  if ( code != WAIT_OBJECT_0 )
  {
    msg("Error restoring broken connection");
    return false;
  }

  if ( dbg_attach_process(_pid, -1, 0, nullptr) == DRC_OK && reopen_threads() )
  {
    resume_suspended_threads(_suspended_threads);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::reopen_threads(void)
{
  if ( _OpenThread == nullptr )
    return false;

  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    HANDLE hThread;
    hThread = _OpenThread(THREAD_ALL_ACCESS, true, p->second.tid);
    if ( hThread != nullptr )
      p->second.hThread = hThread;
    else
      deberr("OpenThread");
    p->second.suspend_count = get_thread_suspend_count(hThread);
  }
  return true;
}

//--------------------------------------------------------------------------
static bool enable_privilege(LPCTSTR privilege, bool enable);
static bool g_subsys_inited = false;
static bool g_got_debpriv = false;

bool init_subsystem()
{
  if ( g_subsys_inited )
    return true;

  if ( !win32_debmod_t::winver.ok() )
    return false;

  win_tool_help_t *wth = win32_debmod_t::get_tool_help();
  if ( wth->ok() )
    g_code |= DBG_HAS_GET_PROCESSES;

  // DebugActiveProcessStop() is only available on XP/2K3
  if ( wth->use_debug_detach_process() )
    g_code |= DBG_HAS_DETACH_PROCESS;

  g_got_debpriv = enable_privilege(SE_DEBUG_NAME, true);
  if ( !g_got_debpriv )
    msg("Cannot set debug privilege: %s.\n"
        "Debugging of processes owned by another account won't be possible.\n",
        winerr(GetLastError()));

  win32_debmod_t::reuse_broken_connections = true;
  init_win32_subsystem();

  HINSTANCE h = GetModuleHandle(kernel32_dll);
  *(FARPROC*)&_OpenThread = GetProcAddress(h, TEXT("OpenThread"));
  *(FARPROC*)&_GetThreadDescription = GetProcAddress(h, TEXT("GetThreadDescription"));

#ifndef __X86__
  *(FARPROC*)&_Wow64GetThreadContext = GetProcAddress(h, TEXT("Wow64GetThreadContext"));
  *(FARPROC*)&_Wow64SetThreadContext = GetProcAddress(h, TEXT("Wow64SetThreadContext"));
  *(FARPROC*)&_Wow64GetThreadSelectorEntry = GetProcAddress(h, TEXT("Wow64GetThreadSelectorEntry"));
#endif

  g_subsys_inited = g_code != 0;
  return g_subsys_inited;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  if ( !g_subsys_inited )
    return true;

  g_subsys_inited = false;

  if ( g_got_debpriv )
  {
    enable_privilege(SE_DEBUG_NAME, false);
    g_got_debpriv = false;
  }

  term_win32_subsystem();
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session(void *)
{
  return new win32_debmod_t();
}

//--------------------------------------------------------------------------
//
//      DEBUG PRIVILEGE
//
//--------------------------------------------------------------------------
// dynamic linking information for Advapi functions
static HMODULE hAdvapi32 = nullptr;
// function prototypes
typedef BOOL (WINAPI *OpenProcessToken_t)(
        HANDLE ProcessHandle,
        DWORD DesiredAccess,
        PHANDLE TokenHandle);
typedef BOOL (WINAPI *LookupPrivilegeValue_t)(
        LPCTSTR lpSystemName,
        LPCTSTR lpName,
        PLUID lpLuid);
typedef BOOL (WINAPI *AdjustTokenPrivileges_t)(
        HANDLE TokenHandle,
        BOOL DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD ReturnLength);

// Function pointers
static OpenProcessToken_t      _OpenProcessToken      = nullptr;
static LookupPrivilegeValue_t  _LookupPrivilegeValue  = nullptr;
static AdjustTokenPrivileges_t _AdjustTokenPrivileges = nullptr;

//--------------------------------------------------------------------------
static void term_advapi32(void)
{
  if ( hAdvapi32 != nullptr )
  {
    DWORD code = GetLastError();
    FreeLibrary(hAdvapi32);
    SetLastError(code);
    hAdvapi32 = nullptr;
  }
}

//--------------------------------------------------------------------------
static bool init_advapi32(void)
{
  // load the library
  hAdvapi32 = LoadLibrary(TEXT("advapi32.dll"));
  if ( hAdvapi32 == nullptr )
    return false;

  // find the needed functions
  *(FARPROC*)&_OpenProcessToken       = GetProcAddress(hAdvapi32, TEXT("OpenProcessToken"));
  *(FARPROC*)&_LookupPrivilegeValue   = GetProcAddress(hAdvapi32, TEXT(LookupPrivilegeValue_Name));
  *(FARPROC*)&_AdjustTokenPrivileges  = GetProcAddress(hAdvapi32, TEXT("AdjustTokenPrivileges"));

  bool ok = _OpenProcessToken      != nullptr
         && _LookupPrivilegeValue  != nullptr
         && _AdjustTokenPrivileges != nullptr;
  if ( !ok )
    term_advapi32();
  return ok;
}


//--------------------------------------------------------------------------
// based on code from:
// http://support.microsoft.com/support/kb/articles/Q131/0/65.asp
static bool enable_privilege(LPCTSTR privilege, bool enable)
{
  if ( !win32_debmod_t::winver.is_NT() ) // no privileges on 9X/ME
    return true;

  bool ok = false;
  if ( init_advapi32() )
  {
    HANDLE hToken;
    DWORD tokens = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    if ( _OpenProcessToken(GetCurrentProcess(), tokens, &hToken) )
    {
      LUID luid;
      if ( _LookupPrivilegeValue(nullptr, privilege, &luid) )
      {
        TOKEN_PRIVILEGES tp;
        memset(&tp, 0, sizeof(tp));
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        ok = _AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE;
      }
      CloseHandle(hToken);
    }
    term_advapi32();
  }
  return ok;
}
