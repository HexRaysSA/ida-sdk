/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "uunp.hpp"
#include <mergemod.hpp>

//-------------------------------------------------------------------------
static const idbattr_info_t plgopts_info[] =
{
  IDI_ALTENTRY(0, atag, sizeof(ea_t), 0, nullptr, "original_entrypoint"),
  IDI_ALTENTRY(1, atag, sizeof(ea_t), 0, nullptr, "code_start_address"),
  IDI_ALTENTRY(2, atag, sizeof(ea_t), 0, nullptr, "code_end_address"),
  IDI_ALTENTRY(3, atag, sizeof(ea_t), 0, nullptr, "iat_start_addres"),
  IDI_ALTENTRY(4, atag, sizeof(ea_t), 0, nullptr, "iat_end_address"),
};

SIMPLE_MODDATA_DIFF_HELPER(helper, "uunp", UUNP_NODE_NAME, plgopts_info);

//--------------------------------------------------------------------------
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS("Uunp", MH_TERSE);
  create_std_modmerge_handlers(mhp, data_id, helper);
}

