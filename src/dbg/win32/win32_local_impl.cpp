#ifndef __NT__
#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
#define CONTROL_C_EXIT                      STATUS_CONTROL_C_EXIT
#define DBG_CONTROL_C                    0x40010005
#define DBG_CONTROL_BREAK                0x40010008
#define STATUS_GUARD_PAGE_VIOLATION      0x80000001
#define STATUS_DATATYPE_MISALIGNMENT     0x80000002
#define STATUS_BREAKPOINT                0x80000003
#define STATUS_SINGLE_STEP               0x80000004
#define STATUS_ACCESS_VIOLATION          0xC0000005
#define STATUS_IN_PAGE_ERROR             0xC0000006
#define STATUS_INVALID_HANDLE            0xC0000008
#define STATUS_NO_MEMORY                 0xC0000017
#define STATUS_ILLEGAL_INSTRUCTION       0xC000001D
#define STATUS_NONCONTINUABLE_EXCEPTION  0xC0000025
#define STATUS_INVALID_DISPOSITION       0xC0000026
#define STATUS_ARRAY_BOUNDS_EXCEEDED     0xC000008C
#define STATUS_FLOAT_DENORMAL_OPERAND    0xC000008D
#define STATUS_FLOAT_DIVIDE_BY_ZERO      0xC000008E
#define STATUS_FLOAT_INEXACT_RESULT      0xC000008F
#define STATUS_FLOAT_INVALID_OPERATION   0xC0000090
#define STATUS_FLOAT_OVERFLOW            0xC0000091
#define STATUS_FLOAT_STACK_CHECK         0xC0000092
#define STATUS_FLOAT_UNDERFLOW           0xC0000093
#define STATUS_INTEGER_DIVIDE_BY_ZERO    0xC0000094
#define STATUS_INTEGER_OVERFLOW          0xC0000095
#define STATUS_PRIVILEGED_INSTRUCTION    0xC0000096
#define STATUS_STACK_OVERFLOW            0xC00000FD
#define STATUS_CONTROL_C_EXIT            0xC000013A
#define STATUS_FLOAT_MULTIPLE_FAULTS     0xC00002B4
#define STATUS_FLOAT_MULTIPLE_TRAPS      0xC00002B5
#define STATUS_REG_NAT_CONSUMPTION       0xC00002C9
#define SUCCEEDED(x) (x >= 0)
#define FAILED(x) (x < 0)
#endif

#include <expr.hpp>
#include <loader.hpp>
#include "../ldr/pe/pe.h"
#include "../plugins/pdb/pdb.hpp"
#include "win32_rpc.h"
#include "dbg_rpc_hlp.h"

//--------------------------------------------------------------------------
static const char idc_win32_rdmsr_args[] = { VT_LONG, 0 };
static error_t idaapi idc_win32_rdmsr(idc_value_t *argv, idc_value_t *res)
{
  uint64 value = 0; // shut up the compiler
  uval_t reg = argv[0].num;
#ifdef RPC_CLIENT
  void *out = nullptr;
  ssize_t outsize;
  int code = g_dbgmod.send_ioctl(WIN32_IOCTL_RDMSR, &reg, sizeof(reg), &out, &outsize);
  if ( SUCCEEDED(code) && outsize == sizeof(value) )
    value = *(uint64*)out;
  qfree(out);
#else
  int code = g_dbgmod.rdmsr(reg, &value);
#endif
  if ( FAILED(code) )
  {
    res->num = code;
    return set_qerrno(eExecThrow); // read error, raise exception
  }
  res->set_int64(value);
  return eOk;
}

//--------------------------------------------------------------------------
static const char idc_win32_wrmsr_args[] = { VT_LONG, VT_INT64, 0 };
static error_t idaapi idc_win32_wrmsr(idc_value_t *argv, idc_value_t *res)
{
  win32_wrmsr_t msr;
  msr.reg = argv[0].num;
  msr.value = argv[1].i64;
#ifdef RPC_CLIENT
  res->num = g_dbgmod.send_ioctl(WIN32_IOCTL_WRMSR, &msr, sizeof(msr), nullptr, nullptr);
#else
  res->num = g_dbgmod.wrmsr(msr.reg, msr.value);
#endif
  return eOk;
}

//--------------------------------------------------------------------------
// Installs or uninstalls debugger specific idc functions
static bool register_idc_funcs(bool reg)
{
  static const ext_idcfunc_t idcfuncs[] =
  {
    { IDC_READ_MSR,  idc_win32_rdmsr, idc_win32_rdmsr_args, nullptr, 0, 0 },
    { IDC_WRITE_MSR, idc_win32_wrmsr, idc_win32_wrmsr_args, nullptr, 0, 0 },
  };
  return add_idc_funcs(idcfuncs, qnumber(idcfuncs), reg);
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  netnode penode(PE_NODE);
  ea_t currentbase = new_base;
  ea_t imagebase = ea_t(penode.altval(PE_ALT_IMAGEBASE)); // loading address (usually pe.imagebase)

  if ( imagebase == 0 )
  {
    if ( !is_miniidb() )
      warning("AUTOHIDE DATABASE\n"
              "IDA could not automatically determine if the program should be\n"
              "rebased in the database because the database format is too old and\n"
              "doesn't contain enough information.\n"
              "Create a new database if you want automated rebasing to work properly.\n"
              "Note you can always manually rebase the program by using the\n"
              "Edit, Segments, Rebase program command.");
  }
  else if ( imagebase != currentbase )
  {
    rebase_or_warn(imagebase, currentbase);
  }
}

//--------------------------------------------------------------------------
bool read_pe_header(peheader_t *pe)
{
  netnode penode(PE_NODE);
  return penode.valobj(pe, sizeof(peheader_t)) > 0;
}

//--------------------------------------------------------------------------
// Initialize Win32 debugger plugin
static bool win32_init_plugin(void)
{
  // Remote debugger? Then nothing to initialize locally
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif
  if ( !netnode::inited() || is_miniidb() || inf_is_snapshot() )
  {
#ifndef __NT__
    // local debugger is available if we are running under Windows
    // for other systems only the remote debugger is available
    if ( !debugger.is_remote() )
      return false;
#endif
  }
  else
  {
    if ( inf_get_filetype() != f_PE )
      return false; // only PE files

    processor_t &ph = PH;
    if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
      return false;

    // find out the pe header
    peheader_t pe;
    if ( !read_pe_header(&pe) )
      return false;

    // debug only gui, console, or unknown applications
    if ( pe.subsys != PES_WINGUI    // Windows GUI
      && pe.subsys != PES_WINCHAR   // Windows Character
      && pe.subsys != PES_UNKNOWN ) // Unknown
    {
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
inline void win32_term_plugin(void)
{
#ifndef RPC_CLIENT
  term_subsystem();
#endif
}

//----------------------------------------------------------------------------
struct pdb_remote_session_t;
void close_pdb_remote_session(pdb_remote_session_t *)
{
}

#ifndef HAVE_PLUGIN_COMMENTS
//--------------------------------------------------------------------------
static const char comment[] = "Userland win32 debugger plugin";
#endif
