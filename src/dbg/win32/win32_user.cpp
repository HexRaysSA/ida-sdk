/*
This is main source code for the local win32 debugger module
*/
//lint -e528 not referenced

static const char wanted_name[] = "Local Windows debugger";

#define DEBUGGER_NAME  "win32"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#define DEBUGGER_FLAGS (DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_DEBTHREAD    \
                      | DBG_FLAG_ANYSIZE_HWBPT\
                      | DBG_FLAG_ADD_ENVS     \
                      | DBG_FLAG_MERGE_ENVS)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objidl.h>

#include <fpro.h>
#include <ua.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <dbg.hpp>
#include "dbg_plugmod.hpp"
#include "win32_debmod.h"
#include "w32sehch.h"
#include "pc_regs.hpp"
#include "deb_pc.hpp"

#include "common_stub_impl.cpp"
#include "win32_local_impl.cpp"

struct dbg_plugmod_t : public dbg_plugmod_user_t
{
  virtual ~dbg_plugmod_t() override;

  win32_debmod_t g_dbgmod;
  virtual debmod_t &get_debmod() override { return g_dbgmod; }

  win32_cfg_t cfg;

  //--------------------------------------------------------------------------
  bool init_plugin()
  {
    bool ok = win32_init_plugin(&debugger);
    if ( ok )
    {
      debugger.flags |= DBG_HAS_APPCALL;
      debugger.filetype = f_PE;
    }
    return ok;
  }

  void term_plugin()
  {
    term_subsystem();
  }
};
win32_debmod_t &get_win32_debmod() { return *static_cast<win32_debmod_t *>(&get_debmod()); }
win32_cfg_t &get_win32_cfg() { return get_dbg_plugmod()->cfg; }

//--------------------------------------------------------------------------
static const char idc_win32_rdmsr_args[] = { VT_LONG, 0 };
static error_t idaapi idc_win32_rdmsr(idc_value_t *argv, idc_value_t *res)
{
  uint64 value = 0; // shut up the compiler
  uval_t reg = argv[0].num;
  int code = get_win32_debmod().rdmsr(reg, &value);
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
  res->num = get_win32_debmod().wrmsr(msr.reg, msr.value);
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

#include "common_local_impl.cpp"
#include "win32_server_stub.cpp"
