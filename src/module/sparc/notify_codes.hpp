/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __SPARC_NOTIFY_CODES_HPP
#define __SPARC_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the SPARC module in the ph.notify() function
namespace sparc_module_t
{
  enum event_codes_t
  {
    ev_load_symbols = processor_t::ev_loader,
    ev_set_v8,
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline void load_symbols(const char *fname)
  {
    processor_t::notify(idp_ev(ev_load_symbols), fname);
  }

  inline void set_v8(bool is_v8)
  {
    processor_t::notify(idp_ev(ev_set_v8), is_v8);
  }
}

#endif // __SPARC_NOTIFY_CODES_HPP
