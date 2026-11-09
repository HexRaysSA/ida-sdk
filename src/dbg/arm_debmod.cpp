#include <pro.h>
#include <nalt.hpp>
#include "arm_debmod.h"

#ifdef ENABLE_LOWCNDS
inline bool has_armv5(void) { return true; }
static arm_debmod_t *ssmod; // pointer to the current debugger module
#endif

//-------------------------------------------------------------------------
inline bool is_arm64_ea(ea_t ea)
{
  qnotused(ea);
#if defined(__EA64__)
  return true;
#else
  return false;
#endif
}


//--------------------------------------------------------------------------
arm_debmod_t::arm_debmod_t(void)
{
  static const uchar bpt[] = ARM_BPT_CODE;
  bpt_code.append(bpt, sizeof(bpt));

  set_platform("linux");
  fix_registers();

  reset_hwbpts();
}

//--------------------------------------------------------------------------
void arm_debmod_t::fix_registers()
{
  bool is64 = is_64bit_app();
  sp_idx = armreg_to_idx(R_SP, is64);
  pc_idx = armreg_to_idx(R_PC, is64);
  lr_idx = armreg_to_idx(R_LR, is64);
  sr_idx = armreg_to_idx(R_PSR, is64);
}

//--------------------------------------------------------------------------
int arm_debmod_t::getn_hwbpts_supported(void)
{
  if ( hwbpt_count < 0 )
  {
    // unknown, ask the subclass how many hwbpts are supported
    hwbpt_count = _getn_hwbpts_supported();
    if ( hwbpt_count < 0 )
      hwbpt_count = 0;
    else
      hwbpt_count = qmin(hwbpt_count, ARM_MAX_HWBPTS);
  }
  return hwbpt_count;
}

//--------------------------------------------------------------------------
int arm_debmod_t::getn_watchpoints_supported(void)
{
  if ( watch_count < 0 )
  {
    // unknown, ask the subclass how many watchpoints are supported
    watch_count = _getn_watchpoints_supported();
    if ( watch_count < 0 )
      watch_count = 0;
    else
      watch_count = qmin(watch_count, ARM_MAX_WATCHPOINTS);
  }
  return watch_count;
}

//--------------------------------------------------------------------------
int arm_debmod_t::find_hwbpt_slot(int *out, ea_t ea)
{
  int slot = -1;
  for ( int i = 0, n = getn_hwbpts_supported(); i < n; i++ )
  {
    if ( hwbpt_slots[i].addr == ea )
      return BPT_BAD_ADDR; // duplicate

    if ( hwbpt_slots[i].addr == BADADDR && slot < 0 )
      slot = i;
  }

  if ( slot < 0 )
    return BPT_TOO_MANY;

  if ( out != nullptr )
    *out = slot;

  return BPT_OK;
}

//--------------------------------------------------------------------------
int arm_debmod_t::find_watchpoint_slot(int *out, ea_t ea)
{
  int slot = -1;
  for ( int i = 0, n = getn_watchpoints_supported(); i < n; i++ )
  {
    if ( watch_slots[i].addr == ea )
      return BPT_BAD_ADDR; // duplicate

    if ( watch_slots[i].addr == BADADDR && slot < 0 )
      slot = i;
  }

  if ( slot < 0 )
    return BPT_TOO_MANY;

  if ( out != nullptr )
    *out = slot;

  return BPT_OK;
}

//--------------------------------------------------------------------------
int idaapi arm_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int /*len*/)
{
  switch ( type )
  {
    case BPT_SOFT:
      break;

    case BPT_EXEC:
      {
        if ( getn_hwbpts_supported() <= 0 )
          return BPT_BAD_TYPE;

        int code = find_hwbpt_slot(nullptr, ea);
        if ( code != BPT_OK )
          return code;
      }
      break;

    default:
      {
        if ( getn_watchpoints_supported() <= 0 )
          return BPT_BAD_TYPE;

        int code = find_watchpoint_slot(nullptr, ea);
        if ( code != BPT_OK )
          return code;
      }
      break;
  }

  return BPT_OK;
}

//--------------------------------------------------------------------------
bool arm_debmod_t::add_hwbpt(bpttype_t type, ea_t ea, int len)
{
  int slot;
  bool ok = false;
  switch ( type )
  {
    case BPT_EXEC:
      if ( find_hwbpt_slot(&slot, ea) == BPT_OK )
      {
        hwbpt_slots[slot].type = type;
        hwbpt_slots[slot].addr = ea;
        hwbpt_slots[slot].ctrl = get_hwbpt_ctrl_bits(type, ea, len);
        ok = true;
      }
      break;
    default:
      if ( find_watchpoint_slot(&slot, ea) == BPT_OK )
      {
        watch_slots[slot].type = type;
        watch_slots[slot].addr = ea;
        watch_slots[slot].ctrl = get_watchpoint_ctrl_bits(type, ea, len);
        ok = true;
      }
      break;
  }
  return ok && refresh_hwbpts();
}

//--------------------------------------------------------------------------
bool arm_debmod_t::del_hwbpt(ea_t ea, bpttype_t type)
{
  bool ok = false;
  switch ( type )
  {
    case BPT_EXEC:
      for ( int i = 0, n = getn_hwbpts_supported(); i < n; i++ )
      {
        if ( hwbpt_slots[i].addr == ea )
        {
          hwbpt_slots[i].clear();
          ok = true;
          break;
        }
      }
      break;
    default:
      for ( int i = 0, n = getn_watchpoints_supported(); i < n; i++ )
      {
        if ( watch_slots[i].addr == ea )
        {
          watch_slots[i].clear();
          ok = true;
          break;
        }
      }
      break;
  }
  return ok && refresh_hwbpts();
}

//--------------------------------------------------------------------------
void arm_debmod_t::reset_hwbpts(void)
{
  hwbpt_count = -1;
  watch_count = -1;

  for ( size_t i = 0; i < ARM_MAX_HWBPTS; i++ )
    hwbpt_slots[i].clear();

  for ( size_t i = 0; i < ARM_MAX_WATCHPOINTS; i++ )
    watch_slots[i].clear();
}

//--------------------------------------------------------------------------
void arm_debmod_t::cleanup_hwbpts(void)
{
  reset_hwbpts();
  refresh_hwbpts();
}

//--------------------------------------------------------------------------
int arm_debmod_t::finalize_appcall_stack(
        call_context_t &ctx,
        regval_map_t &regs,
        bytevec_t &/*stk*/)
{
  regs[lr_idx].ival = ctx.ctrl_ea;
  // return addrsize as the adjustment factor to add to sp
  // we do not need the return address, that's why we ignore the first 4
  // bytes of the prepared stack image
  return get_addr_size();
}

//--------------------------------------------------------------------------
int arm_debmod_t::get_regidx(const char *regname, int *clsmask)
{
  return arm_get_regidx(clsmask, regname, is_64bit_app());
}

#ifdef ENABLE_LOWCNDS
//--------------------------------------------------------------------------
static const regval_t &idaapi arm_getreg(const char *name, const regval_t *regvals)
{
  int idx = ssmod->get_regidx(name, nullptr);
  QASSERT(30182, idx >= 0 && idx < ssmod->nregs());
  return regvals[idx];
}

//--------------------------------------------------------------------------
static uint32 idaapi arm_get_long(ea_t ea)
{
  uint32 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v), nullptr);
  return v;
}

//--------------------------------------------------------------------------
static uint16 idaapi arm_get_word(ea_t ea)
{
  uint16 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v), nullptr);
  return v;
}

//--------------------------------------------------------------------------
static uint8 idaapi arm_get_byte(ea_t ea)
{
  uint8 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v), nullptr);
  return v;
}

//----------------------------------------------------------------------
// stripped down version of get_dtype_size()
static size_t idaapi arm_get_dtype_size(op_dtype_t dtype)
{
  switch ( dtype )
  {
    case dt_byte:    return 1;          // 8 bit
    case dt_word:
    case dt_half:    return 2;          // 16 bit
    case dt_dword:
    case dt_float:   return 4;          // 4 byte
    case dt_qword:
    case dt_double:  return 8;          // 8 byte
    default:         return 0;
  }
}

//--------------------------------------------------------------------------
// since arm does not have a single step facility, we have to emulate it
// with a temporary breakpoint.
drc_t arm_debmod_t::dbg_perform_single_step(debug_event_t *dev, const insn_t &insn)
{
  // read register values
  regvals_t values;
  values.resize(nregs());
  drc_t drc = dbg_read_registers(dev->tid, ARM_RC_GENERAL, values.begin(), nullptr);
  if ( drc <= DRC_NONE )
    return drc;

  static const opinfo_helpers_t oh =
  {
    arm_getreg,
    arm_get_byte,
    arm_get_word,
    arm_get_long,
    arm_get_dtype_size,
    nullptr,               // has_insn_cf_chg not needed
  };

  // calculate the address of the next executed instruction
  lock_begin();
  ssmod = this;
  ea_t next = calc_next_exec_insn(insn, values.begin(), oh, false); // TODO pass is_mprofile parameter
  ssmod = nullptr;
  lock_end();

  // BADADDR means that the execution flow is linear
  if ( next == BADADDR )
  {
    next = insn.ea + insn.size;
    if ( (values[sr_idx].ival & BIT5) != 0 ) // thumb?
      next |= 1;
  }

  // safety check: self jumping instruction cannot be single stepped
  if ( (next & ~1) == insn.ea )
    return DRC_FAILED;

  // add a breakpoint there
  update_bpt_info_t ubi;
  ubi.ea = next;
  ubi.type = BPT_SOFT;
  ubi.code = 0;
  int nbpts;
  drc = dbg_update_bpts(&nbpts, &ubi, 1, 0, nullptr);
  if ( drc != DRC_OK || nbpts == 0 )
    return drc != DRC_OK ? drc : DRC_FAILED;

  drc = resume_app_and_get_event(dev);

  // clean up: delete the temporary breakpoint
  ubi.ea &= ~1; // del_bpt requires an even address
  drc_t drc2 = dbg_update_bpts(&nbpts, &ubi, 0, 1, nullptr);
  if ( drc2 != DRC_OK || nbpts == 0 )
  {
    msg("%a: failed to remove single step bpt?!\n", ubi.ea);
    drc = drc2 != DRC_OK ? drc2 : DRC_FAILED;
  }
  // the caller expects to see STEP after us:
  if ( drc == DRC_OK )
    dev->set_eid(STEP);
  return drc;
}

#endif // ENABLE_LOWCNDS

//--------------------------------------------------------------------------
void arm_debmod_t::adjust_swbpt(ea_t *p_ea, int *p_len)
{
  ea_t &ea = *p_ea;
  if ( (ea & 1) != 0 ) // T bit is set, use a thumb breakpoint
  {
    ea--;
    *p_len = 2;
  }
}
