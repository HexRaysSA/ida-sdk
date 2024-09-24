#include <windows.h>
#include <ida.hpp>
#include "winbase_debmod.h"

#ifndef __X86__
#define IDA_ADDRESS_SIZE 8
#else
#define IDA_ADDRESS_SIZE 4
#endif

const TCHAR kernel32_dll[] = TEXT("kernel32.dll");

typedef BOOL WINAPI GetProcessDEPPolicy_t(HANDLE hProcess, LPDWORD lpFlags, PBOOL lpPermanent);
static GetProcessDEPPolicy_t *_GetProcessDEPPolicy = nullptr;

typedef dep_policy_t WINAPI GetSystemDEPPolicy_t(void);
static GetSystemDEPPolicy_t *_GetSystemDEPPolicy = nullptr;

//--------------------------------------------------------------------------
winbase_debmod_t::winbase_debmod_t(void): highdlls(eah())
{
  HMODULE k32 = GetModuleHandle(kernel32_dll);

  if ( _GetProcessDEPPolicy == nullptr )
    *(FARPROC*)&_GetProcessDEPPolicy = GetProcAddress(k32, TEXT("GetProcessDEPPolicy"));

  if ( _GetSystemDEPPolicy == nullptr )
    *(FARPROC*)&_GetSystemDEPPolicy = GetProcAddress(k32, TEXT("GetSystemDEPPolicy"));

  if ( _GetSystemDEPPolicy != nullptr )
    dep_policy = _GetSystemDEPPolicy();

  win_tool_help = nullptr;
  set_platform("win32");
}

//--------------------------------------------------------------------------
// Prepare new page protections for a breakpoint of BPTTYPE.
// Use INPUT as starting page protections.
// Return false in the case of failure.
bool winbase_debmod_t::remove_page_protections(
        DWORD *p_input,
        bpttype_t bpttype,
        dep_policy_t dpolicy,
        HANDLE proc_handle)
{
  // If PAGE_GUARD is already set, do not change anything, it is already ok
  DWORD input = *p_input;
  if ( (input & PAGE_GUARD) != 0 )
    return false;

  // Convert between Unix permissions and Win32 page protections using this array:
  static const uchar win32_page_protections[] =
  {
    PAGE_NOACCESS,          // 000
    PAGE_READONLY,          // 001
    0xFF,                   // 010 WRITE_ONLY does not exist on win32
    PAGE_READWRITE,         // 011
    PAGE_EXECUTE,           // 100
    PAGE_EXECUTE_READ,      // 101
    0xFF,                   // 110 EXECUTE_WRITE does not exist on win32
    PAGE_EXECUTE_READWRITE, // 111
  };
  uchar unix;
  // convert ..COPY page protections into their non-copy counterparts
  // this is the best thing we can do with them because they are automatically
  // converted by the system upon a write access
  if ( (input & PAGE_WRITECOPY) != 0 )
  {
    unix = 3; // rw
  }
  else if ( (input & PAGE_EXECUTE_WRITECOPY) != 0 )
  {
    unix = 7; // rwx
  }
  else
  {
    for ( unix=0; unix < 8; unix++ )
    {
      uchar p = win32_page_protections[unix];
      if ( p != 0xFF && (input & p) != 0 )
        break;
    }
  }
  QASSERT(622, unix < 8);

  // convert bpttype into unix permissions
  int del = 0;
  if ( (bpttype & BPT_READ) != 0 )
    del |= 1;
  if ( (bpttype & BPT_WRITE) != 0 )
    del |= 2;
  if ( (bpttype & BPT_EXEC) != 0 )
  {
    del |= 4;
    // if DEP is disabled for this process then a program can
    // happily execute code in a read only area so we need to
    // remove *all* privileges, unfortunately
    if ( dpolicy != dp_always_on )
    {
      // on XP, GetProcessDEPPolicy returns DEP policy for current process (i.e. the debugger)
      // so we can't use it
      // assume that DEP is disabled by default
      DWORD flags = 0;
      BOOL permanent = 0;
      if ( _GetProcessDEPPolicy == nullptr
        || winver.is_strictly_xp()
        || winver.is_GetProcessDEPPolicy_broken()
        || _GetProcessDEPPolicy(proc_handle, &flags, &permanent) )
      {
        // flags == 0: DEP is disabled for the specified process.
        //
        // Remarks: if permanent == 0 and global DEP policy is OptIn
        // flags may be equal to 1 *but* having DEP disabled because,
        // in case the process called SetProcessDEPPolicy the
        // permanent argument would be 1, it seems to be a bug in the
        // documentation
        if ( (dpolicy == dp_opt_in && permanent == 0) || flags == 0 )
          del |= 1;
      }
    }
  }

  // Remove the access types to trigger on
  unix &= ~del;

  // Handle WRITE_ONLY and EXECUTE_WRITE cases because win32 does not have them.
  // We use stricter page permissions for them. This means that there will
  // be more useless exceptions but we cannot do much about it.
  if ( unix == 2 || unix == 6 )
    unix = 0; // use PAGE_NOACCESS instead of WRITE_ONLY or EXECUTE_WRITE

  uchar perm = win32_page_protections[unix];
  *p_input = (input & ~0xFF) | perm;
  return true;
}

//--------------------------------------------------------------------------
bool idaapi winbase_debmod_t::dbg_enable_page_bpt(
        page_bpts_t::iterator p,
        bool enable)
{
  pagebpt_data_t &bpt = p->second;
  if ( (bpt.old_prot != 0) == enable )
    return false; // already the desired state

  debdeb("dbg_enable_page_bpt(%s): page_ea=%a, old_prot=0x%x, new_prot=0x%x\n", enable ? "true" : "false", bpt.page_ea, bpt.old_prot, bpt.new_prot);

  DWORD old;
  DWORD prot = enable ? bpt.new_prot : bpt.old_prot;
  if ( !VirtualProtectEx(process_handle, (void*)(size_t)bpt.page_ea,
                         bpt.real_len, prot, &old) )
  {
    deberr("VirtualProtectEx");
    // if the page disappeared while disabling a bpt, do not complain,
    // silently return success
    if ( enable )
      return false;
    old = 0;
  }

  debdeb("    success! old=0x%x\n", old);

  bpt.old_prot = enable ? old : 0;
  return true;
}

//--------------------------------------------------------------------------
// Should we generate a BREAKPOINT event because of page bpt?
//lint -e{1746} could be made const reference
bool should_fire_page_bpt(
        page_bpts_t::iterator p,
        ea_t ea,
        DWORD failed_access_type,
        ea_t pc,
        dep_policy_t dep_policy)
{
  const pagebpt_data_t &bpt = p->second;
  if ( !interval::contains(bpt.ea, bpt.user_len, ea) )
    return false; // not in the user-defined interval

  int bit;
  switch ( failed_access_type )
  {
    default:
      INTERR(623);    //-V796 no break
    case EXCEPTION_READ_FAULT: // failed READ access
      // depending on the DEP policy we mark this access also
      // to be triggered in case of EXEC breakpoints
      bit = BPT_READ;
      if ( dep_policy != dp_always_on && bpt.type == BPT_EXEC && pc == ea )
        bit |= BPT_EXEC;
      break;
    case EXCEPTION_WRITE_FAULT: // failed WRITE access
      bit = BPT_WRITE;
      break;
    case EXCEPTION_EXECUTE_FAULT: // failed EXECUTE access
      bit = BPT_EXEC;
      break;
  }
  return (bpt.type & bit) != 0;
}

//--------------------------------------------------------------------------
// returns 0-failure, 2-success
int idaapi winbase_debmod_t::dbg_add_page_bpt(
        bpttype_t type,
        ea_t ea,
        int size)
{
  // only one page breakpoint per page is permitted
  page_bpts_t::iterator p = find_page_bpt(ea, size);
  if ( p != page_bpts.end() )
    return 0; // another page bpt exists

  // Find out the current page protections
  MEMORY_BASIC_INFORMATION meminfo;
  ea_t page_ea = calc_page_base(ea);
  if ( !VirtualQueryEx(process_handle, (void *)(size_t)page_ea,
                       &meminfo, sizeof(meminfo)) )
  {
    deberr("VirtualQueryEx");
    return 0;
  }

  // Make sure the page is loaded
  if ( (meminfo.State & MEM_FREE) != 0 )
  {
    deberr("%a: the page has not been allocated", page_ea);
    return 0;
  }

  // According to MSDN documentation for VirtualQueryEx
  // (...)
  //    AllocationProtect
  //      The memory protection option when the region was initially allocated. This member can be
  //      one of the memory protection constants or 0 if the caller does not have access.
  //
  // Unfortunately, there is no more information about why it my happen so, for now, I'm just
  // returning an error.
  if ( meminfo.Protect == 0 )
  {
    deberr("%a: the page cannot be accessed", page_ea);
    return 0;
  }

  // Calculate new page protections
  int aligned_len = align_up((ea-page_ea)+size, MEMORY_PAGE_SIZE);
  int real_len = 0;
  DWORD prot = meminfo.Protect;
  if ( remove_page_protections(&prot, type, dep_policy, process_handle) )
  { // We have to set new protections
    real_len = aligned_len;
  }

  // Remember the new breakpoint
  p = page_bpts.insert(std::make_pair(page_ea, pagebpt_data_t())).first;
  pagebpt_data_t &bpt = p->second;
  bpt.ea          = ea;
  bpt.user_len    = size;
  bpt.page_ea     = page_ea;
  bpt.aligned_len = aligned_len;
  bpt.real_len    = real_len;
  bpt.old_prot    = 0;
  bpt.new_prot    = prot;
  bpt.type        = type;

  // for PAGE_GUARD pages, no need to change the permissions, everything is fine already
  if ( real_len == 0 )
  {
    bpt.old_prot = meminfo.Protect;
    return 2;
  }

  return dbg_enable_page_bpt(p, true) ? 2 : 0;
}

//--------------------------------------------------------------------------
// returns true if changed *protect (in other words, if we have to mask
// the real page protections and return the original one)
bool winbase_debmod_t::mask_page_bpts(
        ea_t startea,
        ea_t endea,
        uint32 *protect)
{
  // if we have page breakpoints, what we return must be changed to show the
  // real segment privileges, instead of the new ones we applied for the bpt
  int newprot = 0;
  page_bpts_t::iterator p = page_bpts.begin();
  while ( p != page_bpts.end() )
  {
    pagebpt_data_t &pbd = p->second;
    if ( pbd.page_ea + pbd.real_len > startea )
    {
      if ( pbd.page_ea >= endea )
        break;
      if ( pbd.old_prot != 0 )
      { // bpt has been written to the process memory
        if ( *protect == pbd.new_prot )
        { // return the old protection, before setting the page bpt
          newprot = pbd.old_prot;
        }
        else
        {
          debdeb("mask_page_bpts: app changed our page protection for %a (expected: 0x%x, actual: 0x%x)\n", pbd.page_ea, pbd.new_prot, *protect);
          // page protection has been changed by the application
          DWORD prot = *protect;
          if ( prot == PAGE_WRITECOPY && pbd.new_prot == PAGE_READWRITE
            || prot == PAGE_EXECUTE_WRITECOPY && pbd.new_prot == PAGE_EXECUTE_READWRITE )
          {
            // in some cases OS may restore WRITECOPY protection; do nothing in such cases since it works the same way for breakpoint purposes
            debdeb("   ignoring changes to WRITECOPY protection\n");
          }
          else if ( remove_page_protections(&prot, pbd.type, dep_policy, process_handle) )
          {
            pbd.new_prot = prot;
            pbd.old_prot = 0; // mark our bpt as non-written
            debdeb("   will re-set protection to 0x%x\n", pbd.new_prot);
          }
        }
      }
    }
    ++p;
  }
  if ( newprot != 0 )
  {
    *protect = newprot;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Page breakpoints modify the page protections to induce access violations.
// We must hide the modified page protections from IDA and report the original
// page protections.
// Second, the application may render a page bpt inactive by changing its page protections.
// In this case we must report to IDA the new page protections and also reactivate
// the page breakpoint.
void winbase_debmod_t::verify_page_protections(
        meminfo_vec_t *areas,
        const win32_prots_t &prots)
{
  QASSERT(624, areas->size() == prots.size());
  if ( page_bpts.empty() )
    return;

  for ( int i = 0; i < areas->size(); i++ )
  {
    uint32 prot = prots[i];
    memory_info_t &a = areas->at(i);
    if ( mask_page_bpts(a.start_ea, a.end_ea, &prot) )
      a.perm = win_prot_to_ida_perm(prot);
  }

  // reactivate all disabled page bpts, if any
  enable_page_bpts(true);
}

//--------------------------------------------------------------------------
#ifndef __X86__
wow64_state_t winbase_debmod_t::check_wow64_process()
{
  if ( is_wow64 == WOW64_NONE )
  {
    is_wow64 = check_wow64_handle(process_handle);
    if ( is_wow64 > 0 )
      dmsg("WOW64 process has been detected (pid=%d)\n", pid);
  }
  return is_wow64;
}
#endif

//--------------------------------------------------------------------------
bool highdll_vec_t::has(eanat_t addr) const
{
  for ( int i = 0; i < size(); ++i )
    if ( (*this)[i].has(addr) )
      return true;
  return false;
}

//--------------------------------------------------------------------------
bool highdll_vec_t::add(eanat_t addr, size_t sz, HANDLE h)
{
  if ( has(addr) )
    return false;

  // check removed: on new win10 we can have above 4GB:
  // ntdll.dll, wow64.dll, wow64win.dll
  // QASSERT(1491, size() < 2);
  highdll_range_t &r = push_back();
  r.start = addr;
  r.end = addr + sz;
  r.handle = h;
  return true;
}

//--------------------------------------------------------------------------
bool highdll_vec_t::add_high_module(
        eanat_t addr,
        size_t sz,
        HANDLE h)
{
  if ( trunc_uval(addr) == addr )
    return false;
  add(addr, sz, h);   //-V779 unreachable code
  return true;
}

//--------------------------------------------------------------------------
bool highdll_vec_t::del_high_module(HANDLE *h, eanat_t addr)
{
  for ( int i = 0; i < size(); ++i )
  {
    const highdll_range_t &r = (*this)[i];
    if ( r.start == addr )
    {
      if ( h != nullptr )
        *h = r.handle;
      erase(begin() + i);
      return trunc_uval(addr) != addr;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
void idaapi winbase_debmod_t::dbg_term(void)
{
  is_wow64 = WOW64_NONE;
  delete win_tool_help;
  win_tool_help = nullptr;
  cleanup_hwbpts();
}

//-------------------------------------------------------------------------
bool winbase_debmod_t::handle_process_start(pid_t _pid)
{
  set_addr_size(get_process_addrsize(_pid));
  is64 = is_64bit_app();

  init_dynamic_regs();
  return true;
}

//-------------------------------------------------------------------------
void winbase_debmod_t::cleanup(void)
{
  inherited::cleanup();
  is64 = false;
}

//--------------------------------------------------------------------------
// Check if we need to install a temporary breakpoint to workaround the
// 'freely running after syscall' problem. Exactly, the problem is the
// following: after single stepping over a "jmp far ptr" instruction in
// wow64cpu.dll for a 32bits process under a 64bits OS (Win7), the trap flag
// is lost. Probably, it's a bug in wow64cpu!CpuReturnFromSimulatedCode.
//
// So, if we find an instruction like "call large dword fs:XX" we add a
// temporary breakpoint at the next instruction and re-enable tracing
// when the breakpoint is reached.
bool winbase_debmod_t::check_for_call_large(
        const debug_event_t *event,
        HANDLE handle)
{
  if ( check_wow64_handle(handle) <= 0 )
    return false;
  uchar buf[3];
  if ( dbg_read_memory(event->ea, buf, 3, nullptr) == 3 )
  {
    // is it the call large instruction?
    if ( memcmp(buf, "\x64\xFF\x15", 3) == 0 )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi winbase_debmod_t::get_process_bitness(int _pid)
{
  if ( _pid != -1 && _pid != GetCurrentProcessId() )
  {
    if ( !winver.is_64bitOS() )
      return 4;
    switch ( check_wow64_pid(_pid) )
    {
      case WOW64_BAD: return 0; // bad process id
      case WOW64_YES: return 4; // wow64 process, 32bit
      case WOW64_NO:  return 8; // regular 64bit process
      default: break;
    }
  }
  return IDA_ADDRESS_SIZE;
}

//--------------------------------------------------------------------------
static const char *str_bitness(int addrsize)
{
  switch ( addrsize )
  {
    case 8:
      return "[64]";
    case 4:
      return "[32]";
    default:
      return "[x]";
  }
}

//--------------------------------------------------------------------------
// this function may correct pinfo->addrsize
bool winbase_debmod_t::get_process_path(
        ext_process_info_t *pinfo,
        char *buf,
        size_t bufsize)
{
  module_snapshot_t msnap(get_tool_help());
  MODULEENTRY32 me;
  if ( !msnap.first(TH32CS_SNAPMODULE, pinfo->pid, &me) )
  {
    if ( msnap.last_err() == ERROR_PARTIAL_COPY && pinfo->addrsize == 0 )
    {
      // MSDN: If the specified process is a 64-bit process and the caller is a
      //       32-bit process, error code is ERROR_PARTIAL_COPY
      pinfo->addrsize = 8;
    }
    qstrncpy(buf, pinfo->name.c_str(), bufsize);
    return false;
  }
  else
  {
    tchar_utf8(buf, me.szExePath, bufsize);
    return true;
  }
}

//--------------------------------------------------------------------------
win_tool_help_t *winbase_debmod_t::get_tool_help()
{
  if ( win_tool_help == nullptr )
    win_tool_help = new win_tool_help_t;
  return win_tool_help;
}

//-------------------------------------------------------------------------
int winbase_debmod_t::get_process_addrsize(pid_t _pid)
{
  int addrsize = get_process_bitness(_pid);
  return addrsize != 0 ? addrsize : IDA_ADDRESS_SIZE;
}

//--------------------------------------------------------------------------
//lint -e{1762} could be made const [in fact it cannot be made const in x64 mode]
bool winbase_debmod_t::is_ntdll_name(const char *path)
{
  const char *base_name = qbasename(path);
  const char *ntdll_name = winver.is_NT()
                         ? "ntdll.dll"      // NT
                         : "kernel32.dll";  // 9X/Me and KERNEL32.DLL
  if ( strieq(base_name, ntdll_name) )
    return true;
#ifndef __X86__
  if ( winver.is_NT()
    && check_wow64_process() == WOW64_YES
    && strieq(base_name, "ntdll32.dll") )
  {
    return true;
  }
#endif
  return false;
}

//--------------------------------------------------------------------------
//lint -esym(1762,winbase_debmod_t::build_process_ext_name) could be made const
void winbase_debmod_t::build_process_ext_name(ext_process_info_t *pinfo)
{
  char fullname[MAXSTR];
  if ( get_process_path(pinfo, fullname, sizeof(fullname))
    && pinfo->addrsize == 0 )
  {
    // the WOW64 is optional on R2 x64 server
    pinfo->addrsize = IDA_ADDRESS_SIZE;
  }
  pinfo->ext_name = str_bitness(pinfo->addrsize);
  if ( !pinfo->ext_name.empty() )
    pinfo->ext_name += ' ';
  pinfo->ext_name += fullname;
}

//--------------------------------------------------------------------------
int idaapi winbase_debmod_t::get_process_list(procvec_t *list, qstring *)
{
  int mypid = GetCurrentProcessId();
  list->clear();

  process_snapshot_t psnap(get_tool_help());
  PROCESSENTRY32 pe32;
  for ( bool ok = psnap.first(TH32CS_SNAPNOHEAPS, &pe32); ok; ok = psnap.next(&pe32) )
  {
    if ( pe32.th32ProcessID != mypid )
    {
      int addrsize = get_process_bitness(pe32.th32ProcessID);
#ifndef __EA64__
      if ( addrsize > 4 )
        continue; // skip 64bit processes, we cannot debug them because ea_t is 32bit
#endif
      ext_process_info_t pinfo;
      pinfo.pid = pe32.th32ProcessID;
      pinfo.addrsize = addrsize;
      tchar_utf8(&pinfo.name, pe32.szExeFile);
      build_process_ext_name(&pinfo);
      list->push_back(pinfo);
    }
  }
  return list->size();
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
bool idaapi winbase_debmod_t::get_exec_fname(int _pid, char *buf, size_t bufsize)
{
  ext_process_info_t pinfo;
  pinfo.pid = _pid;
  pinfo.name.qclear();
  return get_process_path(&pinfo, buf, bufsize);
}

//--------------------------------------------------------------------------
win_tool_help_t *winbase_debmod_t::win_tool_help = nullptr;
win_version_t winbase_debmod_t::winver;
