/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality for the PC module.

*/

#include "arc.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//--------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name, valmap) \
        IDI_ALTENTRY(-1, atag, sizeof(uint16), mask, valmap, name)

static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(ARC_SIMPLIFY,    "analysis.simplify_instructions", nullptr),
  MERGE_IDPFLAGS(ARC_INLINECONST, "analysis.inline_constant_loads", nullptr),
  MERGE_IDPFLAGS(ARC_TRACKREGS,   "analysis.track_registers",       nullptr),
  IDI_DEVICE_ENTRY,
};

//--------------------------------------------------------------------------
static merge_node_info_t merge_node_info[] =
{
  MNI_STDENTRY(CALLEE_TAG,   NDS_MAP_VAL|NDS_IS_EA, "Callee address for indirect call"),
  MNI_STDENTRY(DXREF_TAG,    NDS_MAP_VAL|NDS_IS_EA, "Resolved address for complex calculation"),
  MNI_STDENTRY(DSLOT_TAG,    0,                     "Delay slot kind"),
};

//--------------------------------------------------------------------------
DEFINE_STD_PROCMOD_HANDLER(idpopts_info, merge_node_info)
