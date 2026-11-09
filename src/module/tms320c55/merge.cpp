/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "tms320c55.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

#define MERGE_IDPFLAGS(mask, name)  IDI_ALTENTRY(-1, atag, sizeof(tms320c55_t::idpflags), mask, nullptr, name)
static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(TMS320C55_IO, "Use I/O definitions"),
  MERGE_IDPFLAGS(TMS320C55_MMR, "Detect memory mapped registers"),
  IDI_DEVICE_ENTRY,
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
