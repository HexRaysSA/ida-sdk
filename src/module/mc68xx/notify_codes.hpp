/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __MC68XX_NOTIFY_CODES_HPP
#define __MC68XX_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the MC68XX module in the ph.notify() function
namespace mc68xx_module_t
{
  enum event_codes_t
  {
    ev_notify_flex_format = processor_t::ev_loader,
                          // tell the module that the file has FLEX format
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline void notify_flex_format()
  {
    processor_t::notify(idp_ev(ev_notify_flex_format));
  }
}

#endif // __MC68XX_NOTIFY_CODES_HPP
