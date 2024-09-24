/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __PPC_NOTIFY_CODES_HPP
#define __PPC_NOTIFY_CODES_HPP

#include <idp.hpp>

struct pushinfo_t;
//----------------------------------------------------------------------
// The following events are supported by the PPC module in the ph.notify() function
namespace ppc_module_t
{
  enum event_codes_t
  {
    ev_dummy = processor_t::ev_loader, // was used before
    ev_set_toc,
    // obsolete, use processor_t::set_code16_mode()
    ev_set_vle_mode,
    ev_restore_pushinfo,  // Restore function prolog info from the database
                          // in: pushinfo_t *pi
                          //     ea_t func_start
                          // Returns: 1-ok, otherwise-failed
    ev_save_pushinfo,     // Save function prolog info to the database
                          // in: ea_t func_start
                          //     const pushinfo_t *pi
                          // Returns: 1-ok, otherwise-failed
    // obsolete, use processor_t::get_code16_mode()
    ev_get_vle_mode,
    ev_set_sda_base,
    ev_get_sda_base,
    ev_get_toc,
    ev_is_gnu_mcount_nc,  // Is __gnu_mcount_nc function?
                          // in: ea_t ea
                          // Returns: 1-yes, -1-no
    ev_set_func_toc,      // Set TOC for a function.
                          // in: ea_t func_start_ea
                          //     ea_t toc_ea
    ev_get_fix_gnu_vleadreloc_bug,
                          // Get config var PPC_FIX_GNU_VLEADRELOC_BUG.
                          // Used by ELF-loader PPC submodule.
                          // Returns: 1-yes, -1-no

    ev_get_abi,           // returns ABI, \ref abi_type_t

    ev_get_func_toc,      // Fet TOC for a function.
                          // out: ea_t *toc_ea
                          // in:  ea_t func_start_ea

    ev_serialize_pushinfo, // Save function prolog info to the buffer
                           // in: bytevec_t *buf
                           //     ea_t func_start
                           //     const pushinfo_t *pi
                           //     int flags (reserved)
                           // Returns: 1-ok, otherwise-failed
    ev_deserialize_pushinfo,
                           // Restore function prolog info from the buffer
                           // in: pushinfo_t *pi
                           //     memory_deserializer_t *buf
                           //     ea_t func_start
                           //     int flags (reserved)
                           // Returns: 1-ok, otherwise-failed
  };

  inline processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  // set TOC / SDA2_BASE (gpr2)
  inline void set_toc(ea_t toc_ea, adiff_t displ = 0)
  {
    QASSERT(10230, PH.id == PLFM_PPC);
    processor_t::notify(idp_ev(ev_set_toc), toc_ea, displ);
  }

  // get TOC/SDA2_BASE (gpr2)
  inline ea_t get_toc()
  {
    QASSERT(10241, PH.id == PLFM_PPC);
    ea_t toc_ea = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_toc), &toc_ea);
    return toc_ea;
  }

  inline bool restore_pushinfo(pushinfo_t *pi, ea_t func_start)
  {
    return processor_t::notify(idp_ev(ev_restore_pushinfo), pi, func_start) == 1;
  }

  inline bool save_pushinfo(ea_t func_start, const pushinfo_t &pi)
  {
    return processor_t::notify(idp_ev(ev_save_pushinfo), func_start, &pi) == 1;
  }

  inline bool is_gnu_mcount_nc(ea_t ea)
  {
    return processor_t::notify(idp_ev(ev_is_gnu_mcount_nc), ea) == 1;
  }

  inline bool get_fix_gnu_vleadreloc_bug()
  {
    return processor_t::notify(idp_ev(ev_get_fix_gnu_vleadreloc_bug)) == 1;
  }

  inline int get_abi()
  {
    return processor_t::notify(idp_ev(ev_get_abi));
  }

  inline void set_sda_base(ea_t sda_base)
  {
    QASSERT(10239, PH.id == PLFM_PPC);
    processor_t::notify(idp_ev(ev_set_sda_base), sda_base);
  }

  // get SDA base (gpr13)
  inline ea_t get_sda_base()
  {
    QASSERT(10240, PH.id == PLFM_PPC);
    ea_t sda_base = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_sda_base), &sda_base);
    return sda_base;
  }

  // set TOC for a function (gpr2)
  inline void set_func_toc(ea_t func_ea, ea_t toc_ea)
  {
    QASSERT(10247, PH.id == PLFM_PPC);
    processor_t::notify(idp_ev(ev_set_func_toc), func_ea, toc_ea);
  }

  // get TOC for a function (gpr2)
  inline ea_t get_func_toc(ea_t func_ea)
  {
    QASSERT(10265, PH.id == PLFM_PPC);
    ea_t toc_ea = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_func_toc), &toc_ea, func_ea);
    return toc_ea;
  }

  inline bool serialize_pushinfo(
          bytevec_t *buf,
          ea_t func_start,
          const pushinfo_t &pi,
          int flags = 0)
  {
    return processor_t::notify(idp_ev(ev_serialize_pushinfo),
                     buf,
                     func_start,
                     &pi,
                     flags) == 1;
  }

  inline bool deserialize_pushinfo(
          pushinfo_t *pi,
          memory_deserializer_t *buf,
          ea_t func_start,
          int flags = 0)
  {
    return processor_t::notify(idp_ev(ev_deserialize_pushinfo),
                     pi,
                     buf,
                     func_start,
                     flags) == 1;
  }
}

#endif // __PPC_NOTIFY_CODES_HPP
