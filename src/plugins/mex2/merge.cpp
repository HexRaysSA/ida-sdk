/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      This example shows how to merge data stored in the fields of the plugin context.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <mergemod.hpp>
#include "../mex1/mex.hpp"

//-------------------------------------------------------------------------
// 1. Data common for entire database (e.g. the options).

// This example shows how to merge the data that is kept in the plugin memory,
// as fields of the plugin context structure (mex_ctx_t in our case).
// We will describe the items to merge and pass the description
// to the helper that is used by create_std_modmerge_handlers(),
// which will do all the work for us.

//-------------------------------------------------------------------------
// We will use the convenience macro IDI_FLDENTRY to describe fields of mex_ctx_t.
// Let us define a macro to simplify its usage:

// Description of mex_ctx_t::flags
#define MEX_FLAG(mask, name) IDI_FLDENTRY(mex_ctx_t, flags, mask, nullptr, name)

static const idbattr_info_t idpopts_info[] =
{
  // Describe both flags
  MEX_FLAG(MEX_FLAGS_0, "MEX flag 0"),
  MEX_FLAG(MEX_FLAGS_1, "MEX flag 1"),
  // Describe ident
  IDI_FLDQSTR(mex_ctx_t, ident, "MEX ident"),
};

// In our case we have to define a subclass of moddata_diff_helper_t() that
// keeps descriptions of the fields and will save the merge result. Only our
// plugin knows how it saves its data, this is why the kernel cannot do it for us.
struct mex_plugin_merge_helper_t : public moddata_diff_helper_t
{
  mex_plugin_merge_helper_t()
    : moddata_diff_helper_t(
        "Sample merge data", // prefix for the attribute names, e.g. "Sample merge data.MEX flag 0",
        MEX_NODE_NAME,       // netnode name for idpopts_info and merge_node_info
        idpopts_info,        // field descriptions
        qnumber(idpopts_info))
  {
  }

  // This optional function is called when merging of the plugin data starts.
  virtual void merge_starting(diff_source_idx_t, void *module_data) override
  {
    mex_ctx_t &ctx = *(mex_ctx_t *)module_data;
    // restore_from_idb() may be skipped if the plugin always keeps its
    // memory state in sync with the database. We included this call in the
    // example just as a reminder that before merging data it must be
    // read from the database.
    ctx.restore_from_idb();
  }

  // This function is called at the end of merging of the plugin data.
  virtual void merge_ending(diff_source_idx_t, void *module_data) override
  {
    // Options have been merged as mex_ctx_t fields, now we save them.
    mex_ctx_t &ctx = *(mex_ctx_t *)module_data;
    // Saving data to the database is mandatory and only the plugin
    // can do it because only the plugin knows how the data is stored
    // in the database.
    ctx.save_to_idb();
  }
};

// The helper class mex_plugin_merge_helper_t is ready. We will pass an instance
// of the helper class to the kernel, and the kernel will take care of
// organizing the merge process for the plugin options.
static mex_plugin_merge_helper_t modmerger_helper;

//-------------------------------------------------------------------------
// 2. Data specific to a particular address.
// We describe how the data is stored in a netnode.
static const merge_node_info_t merge_node_info[] =
{
  {
    "Function marks",       // label of the merge handler, e.g. "Plugins/Merge example 2/Function marks"
    ea_tag,                 // netnode tag
    NDS_MAP_IDX|NDS_IS_STR, // netnode value descriptors and modificators, see \ref nds_flags_t
    nullptr
  },
};

//-------------------------------------------------------------------------
// Now we should combine together in function create_merge_handlers.
// This function will be called on processor_t::ev_create_merge_handlers event.
// As a result, two merge handlers with labels
//   "Plugins/Merge example 2/Database attributes"
//   "Plugins/Merge example 2/Function marks"
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
