/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __ARM_NOTIFY_CODES_HPP
#define __ARM_NOTIFY_CODES_HPP

struct pushinfo_t;
struct arm_arch_t;
//----------------------------------------------------------------------
// The following events are supported by the ARM module in the ph.notify() function
namespace arm_module_t
{
  enum event_codes_t
  {
    // obsolete, use processor_t::set_code16_mode()
    ev_set_thumb_mode = processor_t::ev_loader,
    ev_set_arm_mode,
    // obsolete, use processor_t::get_code16_mode()
    ev_get_thumb_mode,
    ev_restore_pushinfo,   // Restore function prolog info from the database
                           // in: pushinfo_t *pi
                           //     ea_t func_start
                           // Returns: 1-ok, otherwise-failed
    ev_save_pushinfo,      // Save function prolog info to the database
                           // in: ea_t func_start
                           //     const pushinfo_t *pi
                           // Returns: 1-ok, otherwise-failed
    ev_is_push_insn,       // Is push instruction?
                           // in: uint32 *reglist
                           //     const insn_t* insn
                           // Returns: 1-yes, -1-no
    ev_is_pop_insn,        // Is pop instruction?
                           // in: uint32 *reglist
                           //     const insn_t* insn
                           //     bool allow_ldmed
                           // Returns: 1-yes, -1-no
    ev_is_gnu_mcount_nc,   // Is __gnu_mcount_nc function?
                           // in: ea_t ea
                           // Returns: 1-yes, -1-no
    ev_is_special_func,    // Is special function?
                           // in: ea_t ea
                           // Returns: special_func_t
    ev_get_arch_settings,  // in: arm_arch_t *arch to be filled in
                           // size_t strucsize;(init to sizeof(arm_arch_t)
                           // Returns: 1-ok, otherwise-failed
    ev_get_fptr_info,      // Get frame pointer info for given function
                           // in: ushort *reg (out) FP register number
                           //     ea_t *addr (out) address where the fp register is set
                           //     ea_t func_start
                           // Returns: 1-ok, 0-no FP register
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

  inline bool restore_pushinfo(pushinfo_t *pi, ea_t func_start)
  {
    return processor_t::notify(idp_ev(ev_restore_pushinfo), pi, func_start) == 1;
  }

  inline bool save_pushinfo(ea_t func_start, const pushinfo_t &pi)
  {
    return processor_t::notify(idp_ev(ev_save_pushinfo), func_start, &pi) == 1;
  }

  inline bool is_push_insn(uint32 *reglist, const insn_t &insn)
  {
    return processor_t::notify(idp_ev(ev_is_push_insn), reglist, &insn) == 1;
  }

  inline bool is_pop_insn(uint32 *reglist, const insn_t &insn, bool allow_ldmed)
  {
    return processor_t::notify(idp_ev(ev_is_pop_insn), reglist, &insn, allow_ldmed) == 1;
  }

  inline bool is_gnu_mcount_nc(ea_t ea)
  {
    return processor_t::notify(idp_ev(ev_is_gnu_mcount_nc), ea) == 1;
  }

  inline int is_special_func(ea_t ea)
  {
    return processor_t::notify(idp_ev(ev_is_special_func), ea);
  }

  inline bool get_arch_settings(arm_arch_t *arch)
  {
    return processor_t::notify(idp_ev(ev_get_arch_settings), arch) == 1;
  }

  inline bool get_fptr_info(ushort *reg, ea_t *addr, ea_t func_start)
  {
    return processor_t::notify(idp_ev(ev_get_fptr_info), reg, addr, func_start) == 1;
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

#endif // __NOTIFY_CODES_HPP
