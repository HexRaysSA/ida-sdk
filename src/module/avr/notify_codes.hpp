/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __AVR_NOTIFY_CODES_HPP
#define __AVR_NOTIFY_CODES_HPP

#include <idp.hpp>

//----------------------------------------------------------------------
// The following events are supported by the AVR module in the ph.notify() function
namespace avr_module_t
{
  enum event_codes_t
  {
    ev_set_machine_type = processor_t::ev_loader,
                          // elf-loader 'set machine type' and file type
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  inline void set_machine_type(int subarch, bool image_file)
  {
    processor_t::notify(idp_ev(ev_set_machine_type), subarch, image_file);
  }
}

#endif // __AVR_NOTIFY_CODES_HPP
