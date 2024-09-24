/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "pdp.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

#define MERGE_OVR_FIELD(altval, field, name)  IDI_ALTENTRY(altval, atag, sizeof(pdp_ml_t::field), uint32(-1), nullptr, name)
//

static const idbattr_info_t idpopts_info[] =
{
  MERGE_OVR_FIELD(n_asect, asect_top, "asect section top"),
  MERGE_OVR_FIELD(n_ovrbeg, ovrcallbeg, "overlay table begin"),
  MERGE_OVR_FIELD(n_ovrend, ovrcallend, "overlay table end"),
  MERGE_OVR_FIELD(n_ovrbas, ovrtbl_base, "overlay table base"),
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
