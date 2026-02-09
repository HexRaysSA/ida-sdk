/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2026 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "necv850.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//-------------------------------------------------------------------------
#define MERGE_POINTER(idx, name) \
  IDI_ALTENTRY(idx, atag, sizeof(ea_t), 0, nullptr, name)

static const idbattr_info_t idbattr_info[] =
{
  MERGE_POINTER(nec850_t::CTBP_EA_IDX, "analysis.callt_base_pointer"),
  MERGE_POINTER(nec850_t::GP_EA_IDX,   "analysis.global_pointer"),
  MERGE_POINTER(nec850_t::TP_EA_IDX,   "analysis.text_pointer"),
  {
    "analysis.element_pointer",         // name: gpval
    nec850_t::EP_EA_IDX,                // altval idx
    sizeof(ea_t),                       // width
    0,                                  // bitmask
    atag,                               // tag
    nullptr,                            // vmap
    nullptr,                            // individual_node
    IDI_ALTVAL                          // idi_flags: altval
  | IDI_EA_HEX                          // default representation
  | IDI_INC                             // stored value is incremented
  | IDI_MAP_VAL,                        // apply ea2node() to value
  },
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idbattr_info)
