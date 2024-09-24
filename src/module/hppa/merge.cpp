/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "hppa.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//-------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name) \
  IDI_ALTENTRY(-1, atag, sizeof(hppa_t::idpflags), mask, nullptr, name)

static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_SIMPLIFY, "analysis.simplify"    ),
  MERGE_IDPFLAGS(IDP_MNEMONIC, "analysis.mnemonic"    ),
  MERGE_IDPFLAGS(IDP_PSW_W,    "analysis.w_bit_in_psw"),
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
