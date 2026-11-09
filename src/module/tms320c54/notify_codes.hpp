/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __TMS320C54_NOTIFY_CODES_HPP
#define __TMS320C54_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the TMS320C54 module in the ph.notify() function
namespace tms320c54_module_t
{
  enum event_codes_t
  {
    ev_set_dataseg = processor_t::ev_loader + 2,
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline void set_dataseg(ea_t ea)
  {
    processor_t::notify(idp_ev(ev_set_dataseg), ea);
  }
}

#endif // __TMS320C54_NOTIFY_CODES_HPP
