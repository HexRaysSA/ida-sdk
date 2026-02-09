/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#pragma once

#include <idp.hpp>
#include "necv850.hpp"
#include "../spcfuncs.hpp"

//-------------------------------------------------------------------------
// The following events are supported by the NEC850 module in the
// ph.notify() function
namespace nec850_module_t
{
  enum reg_usage_t
  {
    FIXED = 1,    // the register has a fixed value at the entire program,
                  // a callee does not change this register
    CALLEE_SAVED, // the register does not change after a call,
                  // but we do not know its value
    FREE,         // the register is used as temporary
  };

  enum event_codes_t
  {
    ev_get_gp_register = processor_t::ev_loader,
                            // Get usage of the GP register
                            // \return  reg_usage_t
    ev_get_gp_ea,           // Get GP at the given address
                            // \param[out] ea_t the GP value
                            // \param[in]  ea_t the address
    ev_set_gp_register,     // Set usage of the GP register
                            // \param[in]  reg_usage_t the usage
                            // \param[in]  ea_t        the fixed GP value
                            //                         (only for FIXED)
    ev_get_tp_register,     // Get usage of the TP register
                            // \return  reg_usage_t
    ev_get_tp_ea,           // Get TP at the given address
                            // \param[out] ea_t the TP value
                            // \param[in]  ea_t the address
    ev_set_tp_register,     // Set usage of the TP register
                            // \param[in]  reg_usage_t the usage
                            // \param[in]  ea_t        the fixed TP value
                            //                         (only for FIXED)
    ev_get_ep_register,     // Get usage of the EP register
                            // \return  reg_usage_t
    ev_get_ep_ea,           // Get EP at the given address
                            // \param[out] ea_t the EP value
                            // \param[in]  ea_t the address
    ev_set_ep_register,     // Set usage of the EP register
                            // \param[in]  reg_usage_t the usage
                            // \param[in]  ea_t        the fixed EP value
                            //                         (only for FIXED)
    ev_get_r2_register,     // Get usage of the R2 register
                            // \return  reg_usage_t (not FIXED)
    ev_set_r2_register,     // Set usage of the R2 register
                            // \param[in]  reg_usage_t the usage

    ev_restore_pushinfo,   // Restore function prolog info from the database
                           // in: pushinfo_t *pi
                           //     ea_t func_start
                           // Returns: 1-ok, otherwise-failed
    ev_save_pushinfo,      // Save function prolog info to the database
                           // in: ea_t func_start
                           //     const pushinfo_t *pi
                           // Returns: 1-ok, otherwise-failed
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

    ev_is_special_func_call,
                           // Is a call of a special function?
                           // in: const insn_t *insn
                           // Returns: special_func_t
  };

  constexpr processor_t::event_t idp_ev(event_codes_t ev)
  {
    return processor_t::event_t(ev);
  }

  // get usage of the GP register
  inline reg_usage_t get_gp_register()
  {
    QASSERT(10523, PH.id == PLFM_NEC_V850X);
    return reg_usage_t(processor_t::notify(idp_ev(ev_get_gp_register)));
  }

  // get GP at the given address
  inline ea_t get_gp_ea(ea_t ea)
  {
    QASSERT(10524, PH.id == PLFM_NEC_V850X);
    ea_t gpval = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_gp_ea), &gpval, ea);
    return gpval;
  }

  // set usage of the GP register
  inline void set_gp_register(reg_usage_t usage, ea_t fixed_value = BADADDR)
  {
    QASSERT(10530, PH.id == PLFM_NEC_V850X);
    processor_t::notify(idp_ev(ev_set_gp_register), usage, fixed_value);
  }

  // get usage of the TP register
  inline reg_usage_t get_tp_register()
  {
    QASSERT(10525, PH.id == PLFM_NEC_V850X);
    return reg_usage_t(processor_t::notify(idp_ev(ev_get_tp_register)));
  }

  // get TP at the given address
  inline ea_t get_tp_ea(ea_t ea)
  {
    QASSERT(10526, PH.id == PLFM_NEC_V850X);
    ea_t tpval = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_tp_ea), &tpval, ea);
    return tpval;
  }

  // set usage of the TP register
  inline void set_tp_register(reg_usage_t usage, ea_t fixed_value = BADADDR)
  {
    QASSERT(10531, PH.id == PLFM_NEC_V850X);
    processor_t::notify(idp_ev(ev_set_tp_register), usage, fixed_value);
  }

  // get usage of the EP register
  inline reg_usage_t get_ep_register()
  {
    QASSERT(10527, PH.id == PLFM_NEC_V850X);
    return reg_usage_t(processor_t::notify(idp_ev(ev_get_ep_register)));
  }

  // get EP at the given address
  inline ea_t get_ep_ea(ea_t ea)
  {
    QASSERT(10528, PH.id == PLFM_NEC_V850X);
    ea_t epval = BADADDR;  // just in case
    processor_t::notify(idp_ev(ev_get_ep_ea), &epval, ea);
    return epval;
  }

  // set usage of the EP register
  inline void set_ep_register(reg_usage_t usage, ea_t fixed_value = BADADDR)
  {
    QASSERT(10532, PH.id == PLFM_NEC_V850X);
    processor_t::notify(idp_ev(ev_set_ep_register), usage, fixed_value);
  }

  // get usage of the R2 register
  inline reg_usage_t get_r2_register()
  {
    QASSERT(0, PH.id == PLFM_NEC_V850X);
    return reg_usage_t(processor_t::notify(idp_ev(ev_get_r2_register)));
  }

  // set usage of the R2 register
  inline void set_r2_register(reg_usage_t usage)
  {
    QASSERT(0, PH.id == PLFM_NEC_V850X);
    processor_t::notify(idp_ev(ev_set_r2_register), usage);
  }

  inline bool restore_pushinfo(pushinfo_t *pi, ea_t func_start)
  {
    return processor_t::notify(idp_ev(ev_restore_pushinfo), pi, func_start) == 1;
  }

  inline bool save_pushinfo(ea_t func_start, const pushinfo_t &pi)
  {
    return processor_t::notify(idp_ev(ev_save_pushinfo), func_start, &pi) == 1;
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

  inline special_func_t is_special_func_call(const insn_t &insn)
  {
    auto res = processor_t::notify(idp_ev(ev_is_special_func_call), &insn);
    return special_func_t(res);
  }
}
