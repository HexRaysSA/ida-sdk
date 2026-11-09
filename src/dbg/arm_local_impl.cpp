#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <segregs.hpp>
#include <segment.hpp>

#include "deb_arm.hpp"

#include "arm_regs.cpp"

//--------------------------------------------------------------------------
int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  switch ( type )
  {
    case BPT_SOFT:
      if ( (ea & 1) != 0 )
        return BPT_BAD_ADDR;
      break;

    case BPT_EXEC:
      if ( (ea & 3) != 0 )
        return BPT_BAD_ALIGN;
      break;

    default:
      if ( (ea & 7) != 0 )
        return BPT_BAD_ALIGN;
      if ( len < 1 || len > 8 )
        return BPT_BAD_LEN;
      break;
  }

  return BPT_OK;
}

//--------------------------------------------------------------------------
// if bit0 is set, ensure that thumb mode
// if bit0 is clear, ensure that arm mode
static void handle_arm_thumb_modes(ea_t ea)
{
  bool should_be_thumb = (ea & 1) != 0;
  bool is_thumb = processor_t::get_code16_mode(ea);
  if ( should_be_thumb != is_thumb )
    processor_t::set_code16_mode(ea, should_be_thumb);
}

//--------------------------------------------------------------------------
static easet_t pending_addresses;

static ssize_t idaapi dbg_callback(void *, int code, va_list)
{
  // we apply thumb/arm switches when the process is suspended.
  // it is quite late (normally we should do it as soon as the corresponding
  // segment is created) but i did not manage to make it work.
  // in the segm_added event the addresses are not enabled yet,
  // so switching modes fails.
  if ( code == dbg_suspend_process && !pending_addresses.empty() )
  {
    for ( easet_t::iterator p=pending_addresses.begin();
          p != pending_addresses.end();
          ++p )
    {
      handle_arm_thumb_modes(*p);
    }
    pending_addresses.clear();
  }
  return 0;
}

//--------------------------------------------------------------------------
// For ARM processors the low bit means 1-thumb, 0-arm mode.
// The following function goes over the address list and sets the mode
// in IDA database according to bit0. It also resets bit0 for all addresses.
void set_arm_thumb_modes(ea_t *addrs, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    ea_t ea = addrs[i];
    segment_t *s = getseg(ea);
    if ( s == nullptr )
      pending_addresses.insert(ea);
    else
      handle_arm_thumb_modes(ea);

    addrs[i] = ea & ~1;
  }
}

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
  hook_to_notification_point(HT_DBG, dbg_callback);
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
  unhook_from_notification_point(HT_DBG, dbg_callback);
  pending_addresses.clear();
}
