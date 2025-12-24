/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2025 Hex-Rays SA <support@hex-rays.com>
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
  MERGE_POINTER(nec850_t::GP_EA_IDX,   "analysis.global_pointer"),
  MERGE_POINTER(nec850_t::CTBP_EA_IDX, "analysis.callt_base_pointer"),
  MERGE_POINTER(nec850_t::TP_EA_IDX,   "analysis.text_pointer"),
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idbattr_info)
