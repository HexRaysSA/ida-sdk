/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "st9.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

#define MERGE_IDPFLAGS(mask, name)  IDI_ALTENTRY(-1, atag, sizeof(st9_t::idpflags), mask, nullptr, name)
static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_GR_DEC, "analysis.decimal_format_of_register"),
  MERGE_IDPFLAGS(IDP_GR_HEX, "analysis.hexadecimal_format_of_register"),
  MERGE_IDPFLAGS(IDP_GR_BIN, "analysis.binary_format_of_register"),
  IDI_DEVICE_ENTRY,
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
