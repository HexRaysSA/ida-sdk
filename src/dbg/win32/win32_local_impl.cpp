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
#include "../dbg_win.hpp"
#include "../plugins/pdb/pdb.hpp"
#include "win32_rpc.h"
#include "dbg_rpc_hlp.h"

//--------------------------------------------------------------------------
// Initialize Win32 debugger plugin
static bool win32_init_plugin(debugger_t *_debugger)
{
  qnotused(_debugger);
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
    if ( !_debugger->is_remote() )
      return false;
#endif
    return true;
  }
  return is_windows_binary(PH);
}

//----------------------------------------------------------------------------
struct pdb_remote_session_t;
void close_pdb_remote_session(pdb_remote_session_t *)
{
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland win32 debugger plugin";
