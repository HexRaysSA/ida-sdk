#ifndef __PC_DEBUGGER_MODULE__
#define __PC_DEBUGGER_MODULE__

#ifdef __NT__
#  include <windows.h>
#endif

#include "pc_regs.hpp"
#include "deb_pc.hpp"
#include "debmod.h"

class pc_debmod_t: public debmod_t
{
  typedef debmod_t inherited;
protected:
  // Hardware breakpoints
  ea_t hwbpt_ea[MAX_BPT];
  bpttype_t hwbpt_type[MAX_BPT];
  uint32 dr6;
  uint32 dr7;

  int sr_idx;
  int fs_idx;
  int gs_idx;
  int cs_idx;
  int ds_idx;
  int es_idx;
  int ss_idx;

public:
  pc_debmod_t();
  void fix_registers();
  void cleanup_hwbpts();
  virtual bool refresh_hwbpts() newapi { return false; }
  int find_hwbpt_slot(ea_t ea, bpttype_t type) const;
  bool del_hwbpt(ea_t ea, bpttype_t type);
  bool add_hwbpt(bpttype_t type, ea_t ea, int len);
  static const char *get_local_platform();
#ifdef __NT__
  virtual bool set_hwbpts(HANDLE hThread) newapi;
  ea_t is_hwbpt_triggered(thid_t id, bool is_stepping);
  virtual HANDLE get_thread_handle(thid_t /*tid*/) newapi { return INVALID_HANDLE_VALUE; }
#endif
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) override;
  virtual int finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &stk) override;
  virtual ea_t calc_appcall_stack(const regvals_t &regvals) override;
  virtual bool should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea) override;
  virtual bool preprocess_appcall_cleanup(thid_t tid, call_context_t &ctx) override;
  virtual int get_regidx(const char *regname, int *clsmask) override;
  void read_fpu_registers(regval_t *values, int clsmask, const void *fptr, size_t step) const;
};

#endif
