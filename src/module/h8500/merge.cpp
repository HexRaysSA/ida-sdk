/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "h8500.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//-------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name) \
  IDI_ALTENTRY(-1, atag, sizeof(h8500_t::idpflags), mask, nullptr, name)

static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_SAMESIZE, "analysis.same_size_insns"),
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
