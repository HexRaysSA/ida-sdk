/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      This example shows how to merge data stored in netnodes.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <mergemod.hpp>
#include "mex.hpp"

//-------------------------------------------------------------------------
// 1. Data common for entire database (e.g. the options).

// This example shows how to merge the data from database.
// We will describe the items to merge and pass the description
// to create_std_modmerge_handlers(), which will do all the work for us.

//-------------------------------------------------------------------------
// We will use the convenience macro IDI_ALTENTRY to describe values in database.

static const idbattr_info_t idpopts_info[] =
{
  // Describe both flags
  IDI_ALTENTRY(MEX_OPTION_FLAGS_IDX, atag, sizeof(mex_ctx_t::flags), MEX_FLAGS_0, nullptr, "MEX flag 0"),
  IDI_ALTENTRY(MEX_OPTION_FLAGS_IDX, atag, sizeof(mex_ctx_t::flags), MEX_FLAGS_1, nullptr, "MEX flag 1"),
  // Describe ident
  IDI_SUPSTR(MEX_OPTION_IDENT_IDX, stag, "MEX ident"),
};

// The descriptions are ready. Now create an instance of the standard helper
// class to be passed to the kernel, and the kernel will take care of organizing
// the merge process for them.
SIMPLE_MODDATA_DIFF_HELPER(
        modmerger_helper,       // helper instance name
        "Sample merge data",    // label: prefix for the attribute names, e.g. "Sample merge data.MEX flag 0"
        MEX_NODE_NAME,          // netnode name for idpopts_info and merge_node_info
        idpopts_info);          // field descriptions

//-------------------------------------------------------------------------
// 2. Data specific to a particular address.
// We describe how the data is stored in a netnode.
static const merge_node_info_t merge_node_info[] =
{
  {
    "Function marks",       // label of the merge handler, e.g. "Plugins/Merge example 1/Function marks"
    ea_tag,                 // netnode tag
    NDS_MAP_IDX|NDS_IS_STR, // netnode value descriptors and modificators, see \ref nds_flags_t
    nullptr
  },
};

//-------------------------------------------------------------------------
// Now we should combine together in function create_merge_handlers.
// This function will be called on processor_t::ev_create_merge_handlers event.
// As a result, two merge handlers with labels
//   "Plugins/Merge example 1/Database attributes"
//   "Plugins/Merge example 1/Function marks"
// will be created.
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS(
        "Merge example " MEX_NUMBER, // Label of the merge handler
        0);
  create_std_modmerge_handlers(
        mhp,
        data_id,
        modmerger_helper,
        merge_node_info,        // Description of netnode data
        qnumber(merge_node_info));
}
