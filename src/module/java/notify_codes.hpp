/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __JAVA_NOTIFY_CODES_HPP
#define __JAVA_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the JAVA module in the ph.notify() function
namespace java_module_t
{
  enum event_codes_t
  {
    ev_load_file = processor_t::ev_loader,
                          // load input file (see also function loader())
                          // in: linput_t *li
                          //     bool manual
                          // Returns: 0-ok, otherwise-failed
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline bool load_file(linput_t *li, bool manual)
  {
    return processor_t::notify(idp_ev(ev_load_file), li, manual) == 0;
  }
}

#endif // __JAVA_NOTIFY_CODES_HPP
