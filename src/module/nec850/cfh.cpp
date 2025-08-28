/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2025 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#include <fixup.hpp>
#include <bytes.hpp>
#include "necv850.hpp"

//--------------------------------------------------------------------------
#include "../cfh_ha16.cpp"  // for ha16_calc_reference_data()

// simple format
static void idaapi nec850_ha16_get_format(qstring *format)
{
  *format = COLSTR("HIGHW1", SCOLOR_KEYWORD)
            COLSTR("(", SCOLOR_SYMBOL)
            "%s"
            COLSTR(")", SCOLOR_SYMBOL);
}

// this structure is similar to ref_ha16 but it uses custom callback
// get_format
static const custom_refinfo_handler_t nec850_ref_ha16 =
{
  sizeof(custom_refinfo_handler_t),
  "HIGHA16",
  "high adjusted 16 bits of 32-bit offset",
  0,                        // properties (currently 0)
  nullptr,                  // gen_expr
  ha16_calc_reference_data, // calc_reference_data
  nec850_ha16_get_format,   // get_format
};

//--------------------------------------------------------------------------
void nec850_t::init_custom_refs()
{
  cfh_ha16 = ::cfh_ha16;
  cfh_ha16_id = register_custom_fixup(&cfh_ha16);
  ref_ha16_id = register_custom_refinfo(&nec850_ref_ha16) | REFINFO_CUSTOM;
  cfh_ha16.reftype = ref_ha16_id;
}

//--------------------------------------------------------------------------
void nec850_t::term_custom_refs()
{
  cfh_ha16.reftype = REFINFO_CUSTOM;
  unregister_custom_refinfo(ref_ha16_id);
  unregister_custom_fixup(cfh_ha16_id);
}

