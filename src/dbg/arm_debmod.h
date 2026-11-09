#ifndef __ARM_DEBMOD__
#define __ARM_DEBMOD__

#include "arm_regs.hpp"
#include "deb_arm.hpp"
#include "debmod.h"

//--------------------------------------------------------------------------
struct arm_hwbpt_info_t
{
  bpttype_t type; // BPT_...
  ea_t addr;      // target address
  ea_t ctrl;      // control value

  arm_hwbpt_info_t(void) { clear(); }

  void clear(void)
  {
    type = BPT_DEFAULT;
    addr = BADADDR;
    ctrl = 0;
  }
};

//--------------------------------------------------------------------------
class arm_debmod_t : public debmod_t
{
  typedef debmod_t inherited;

protected:
  int hwbpt_count;
  int watch_count;

  arm_hwbpt_info_t hwbpt_slots[ARM_MAX_HWBPTS];
  arm_hwbpt_info_t watch_slots[ARM_MAX_WATCHPOINTS];

  int lr_idx;
  int sr_idx;

public:
  arm_debmod_t(void);

  void fix_registers();
  void reset_hwbpts(void);
  void cleanup_hwbpts(void);

  int getn_hwbpts_supported(void);
  int getn_watchpoints_supported(void);

  int find_hwbpt_slot(int *slot, ea_t ea);
  int find_watchpoint_slot(int *slot, ea_t ea);

  bool add_hwbpt(bpttype_t type, ea_t ea, int len);
  bool del_hwbpt(ea_t ea, bpttype_t type);

  // subclasses must implement these functions to properly support hardware breakpoints/watchpoints
  virtual int _getn_hwbpts_supported(void) newapi { return -1; }
  virtual int _getn_watchpoints_supported(void) newapi { return -1; }
  virtual ea_t get_hwbpt_ctrl_bits(bpttype_t, ea_t, int) newapi { return 0; }
  virtual ea_t get_watchpoint_ctrl_bits(bpttype_t, ea_t, int) newapi { return 0; }
  virtual bool refresh_hwbpts(void) newapi { return false; }

  // overridden base class functions
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) override;
  virtual int finalize_appcall_stack(call_context_t &ctx, regval_map_t &regs, bytevec_t &stk) override;

  virtual int get_regidx(const char *regname, int *clsmask) override;
  virtual void adjust_swbpt(ea_t *p_ea, int *p_len) override;

protected:
#ifdef ENABLE_LOWCNDS
  virtual drc_t dbg_perform_single_step(debug_event_t *dev, const insn_t &insn) override;
#endif
};

bool is_32bit_thumb_insn(uint16 code);

#endif
