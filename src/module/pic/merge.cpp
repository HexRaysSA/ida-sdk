/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "pic.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

#define MERGE_IDPFLAGS(mask, name)  IDI_ALTENTRY(-1, atag, sizeof(pic_t::idpflags), mask, nullptr, name)
static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_SIMPLIFY, "analysis.simplify_instructions"),
  IDI_ALTENTRY(0, atag, sizeof(pic_t::dataseg), 0, nullptr, "data_segment_address"),
  IDI_DEVICE_ENTRY,
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
