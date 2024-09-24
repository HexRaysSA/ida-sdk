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
#include "mex.hpp"

//-------------------------------------------------------------------------
// 1. Data common for entire database (e.g. the options).

// This example shows how to merge the data from database.
// We will describe the items to merge and pass the description
// to the helper that is used by create_std_modmerge_handlers(),
// which will do all the work for us.

//-------------------------------------------------------------------------
static const idbattr_info_t idpopts_info[] =
{
  // Describe both flags
  { "Options blob", 0, 0, 0, MEX_BLOB_TAG, nullptr, nullptr, IDI_BLOB|IDI_BYTEARRAY, 0 },
};

// In our case we have to define a subclass of moddata_diff_helper_t() that
// keeps descriptions of the fields and will save the merge result. Only our
// plugin knows how it saves its data, this is why the kernel cannot do it for us.
struct mex_plugin_merge_helper_t : public moddata_diff_helper_t
{
  mex_plugin_merge_helper_t()
    : moddata_diff_helper_t(
        "Sample merge data", // prefix for the attribute names, e.g. "Sample merge data.Options blob",
        MEX_NODE_NAME,       // netnode name for idpopts_info and merge_node_info
        idpopts_info,        // field descriptions
        qnumber(idpopts_info))
  {
    // By default there is no detail pane,
    // reset MH_UI_NODETAILS to turn on detail pane
    additional_mh_flags &= MH_UI_NODETAILS;
  }

  // This method is called when there is a need to display details for module option
  void print_diffpos_details(qstrvec_t *out, const idbattr_info_t &fi) override
  {
    if ( fi.tag == MEX_BLOB_TAG )
    { // load blob, unpack it and format details
      netnode options(MEX_NODE_NAME);
      bytevec_t packed;
      if ( exist(options) && options.getblob(&packed, 0, MEX_BLOB_TAG) > 0 )
      {
        memory_deserializer_t d(packed);
        ushort flags = d.unpack_dw();
        qstring ident;
        d.unpack_str(&ident);
        out->push_back().sprnt("Flags : 0x%X", flags);
        out->push_back().sprnt("Ident : %s", ident.c_str());
      }
    }
  }
};

// The helper class mex_plugin_merge_helper_t is ready. We will pass an instance
// of the helper class to the kernel, and the kernel will take care of
// organizing the merge process for the plugin options.
static mex_plugin_merge_helper_t modmerger_helper;

//-------------------------------------------------------------------------
// Now we should combine together in function create_merge_handlers.
// This function will be called on processor_t::ev_create_merge_handlers event.
// As a result, merge handler with label
//   "Plugins/Merge example 4/Database attributes"
// will be created.
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS(
        "Merge example " MEX_NUMBER,  // Label of the merge handler
        MH_UI_COLONNAME               // Create multi-column chooser, split diffpos names using ':'
      | MH_UI_DP_SHORTNAME            // Use only attribute name in detail pane
      | MH_UI_COMPLEX);               // Do not show diffpos details in merge chooser column
  create_std_modmerge_handlers(
        mhp,
        data_id,
        modmerger_helper);
}
