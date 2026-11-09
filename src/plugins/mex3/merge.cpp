/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      This example uses the mex1 example and improves the user-interface for it.
 *
 *      IDA Teams uses a chooser to display the merge conflicts.
 *      To fill the chooser columns IDA Teams uses the following methods from diff_source_t type:
 *        * print_diffpos_name()
 *        * print_diffpos_details()
 *      and UI hints from merge_handler_params_t type:
 *        * ui_has_details()
 *        * ui_complex_details()
 *        * ui_complex_name()
 *
 *      In general, chooser columns are filled as following:
 *        columns.clear()
 *        NAME = print_diffpos_name()
 *        if ui_complex_name()
 *        then
 *          columns.add(split NAME by ui_split_char())
 *        else
 *          columns[0] = NAME
 *        if not ui_complex_details()
 *        then
 *          columns.add(print_diffpos_details())
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <mergemod.hpp>
#include "../mex1/mex.hpp"

//-------------------------------------------------------------------------
// 1. Data common for entire database (e.g. the options).

// This example shows how to merge the data from database.
// We will describe the items to merge and pass the description
// to the helper that is used by create_std_modmerge_handlers(),
// which will do all the work for us.

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

// Define default helper class instance for the merge handler
// (see mergemod.hpp for details)
SIMPLE_MODDATA_DIFF_HELPER(
        modmerger_helper,       // helper instance name
        "Sample merge data",    // label: prefix for the attribute names
        MEX_NODE_NAME,          // netnode name for idpopts_info and merge_node_info
        idpopts_info);          // field descriptions

// Merge handler created from idbattr_info_t with the MH_UI_NODETAILS UI hint.
// Its linear_diff_source_t::get_diffpos_name() method returns NAME constructed as following:
//   * prefix if any, f.e. "Sample merge data", concatenated with "."
//   * add item name, f.e. "MEX flag 0"
//   * add ": "
//   * add item value
// You might have noticed this when checking the mex1 and mex2 examples
//
// In this case we can improve UI look if add MH_UI_COLONNAME UI hint to merge_handler_params_t.

//-------------------------------------------------------------------------
// 2. Data specific to a particular address.
//
// To improve UI look for this merge handler we can create a subclass of merge_node_helper_t type.
struct mex_merge_node_helper_t : public merge_node_helper_t
{
  static merge_node_helper_t *instance(merge_data_t &, int)
  {
    return new mex_merge_node_helper_t();
  }
  // is called from print_diffpos_name()
  qstring print_entry_name(uchar tag, nodeidx_t ndx, void * /*module_data*/) const override
  {
    // if you need access to plugin data use:
    // mex_ctx_t *pd = static_cast<mex_ctx_t *>(module_data);
    if ( tag != ea_tag )
      return "";
    // get item value
    ea_t ea = node2ea(ndx);
    netnode eanode(MEX_NODE_NAME);
    qstring mark;
    eanode.supstr_ea(&mark, ea, ea_tag);
    // prepare NAME
    qstring ea_nice_name;
    get_ea_diffpos_name(&ea_nice_name, ea);
    qstring name;
    name.sprnt("%s,%s", ea_nice_name.c_str(), mark.c_str());
    return name;
  }
  // column headers for chooser
  void get_column_headers(qstrvec_t *headers, uchar tag, void * /*module_data*/) const override
  {
    if ( tag == ea_tag )
    {
      headers->push_back("Address");
      headers->push_back("Mark");
    }
  }

};

static const merge_node_info_t merge_node_info[] =
{
  { "Function marks", ea_tag, NDS_MAP_IDX|NDS_IS_STR, mex_merge_node_helper_t::instance },
};

//-------------------------------------------------------------------------
// Now we should combine together in function create_merge_handlers.
// This function will be called on processor_t::ev_create_merge_handlers event.
// As a result, two merge handlers with labels
//   "Plugins/Merge example 3/Database attributes"
//   "Plugins/Merge example 3/Function marks"
// will be created.
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS(
        "Merge example " MEX_NUMBER, // Label of the merge handler
        MH_UI_COLONNAME);            // Create multi-column chooser, split diffpos names using ':'

  // create merge handler for idbattr_info_t, it will use MH_UI_COLONNAME.
  // MH_UI_COLONNAME will ensure that the diffpos names will be split by ':'
  // and displayed as separate columns in a chooser. Multi-column choosers
  // are easier to work with for the user.
  create_std_modmerge_handlers(mhp, data_id, modmerger_helper);

  // create merge handlers for merge_node_info_t, it will use MH_UI_NODETAILS.
  mhp.mh_flags = MH_UI_COMMANAME  // Create multi-column chooser, split diffpos names using ','
               | MH_UI_NODETAILS; // do not display the detail pane
  create_nodeval_merge_handlers(
        nullptr,
        mhp,
        data_id,
        MEX_NODE_NAME,
        merge_node_info,
        qnumber(merge_node_info));
}
