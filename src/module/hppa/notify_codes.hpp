
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */
#pragma once

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the PPC module in the ph.notify() function
namespace hppa_module_t
{
  enum event_codes_t
  {
    ev_dummy = processor_t::ev_loader, // was used before
    ev_is_psw_w,   // W-bit in PSW is set
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline bool is_psw_w()
  {
    return processor_t::notify(idp_ev(ev_is_psw_w)) == 1;
  }
}
