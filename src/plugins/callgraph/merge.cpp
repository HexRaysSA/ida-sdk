/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "callgraph.h"
#include <mergemod.hpp>

//-------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name) \
  IDI_FLDENTRY(plugin_ctx_t, fg_opts.flags, mask, nullptr, name)
#define MERGE_OPTION(fld, name) \
  IDI_FLDENTRY(plugin_ctx_t, fg_opts.fld, 0, nullptr, name)

//-------------------------------------------------------------------------
static const idbattr_info_t plgopts_info[] =
{
  MERGE_IDPFLAGS(FWO_SHOWSTRING, "show_string_references"),
  MERGE_IDPFLAGS(FWO_SKIPLIB,    "skip_library_functions"),
  MERGE_IDPFLAGS(FWO_CALLEE_RECURSE_UNLIM, "unlimited_callees_recursion"),

  MERGE_OPTION(callees_recurse_limit, "callees_recurse_limit"),
  MERGE_OPTION(callers_recurse_limit, "callers_recurse_limit"),
  MERGE_OPTION(max_nodes,             "max_nodes"),
};

//--------------------------------------------------------------------------
struct plg_procmod_diff_helper_t : public moddata_diff_helper_t
{
  plg_procmod_diff_helper_t()
    : moddata_diff_helper_t(
        "Callgraph",
        PROCMOD_NODE_NAME,
        plgopts_info, qnumber(plgopts_info))
  {
  }

  // all options are merged as structure fields,
  // so we should sync them with IDB
  virtual void merge_starting(
        diff_source_idx_t,
        void *module_data) override
  {
    plugin_ctx_t &plg = *(plugin_ctx_t *)module_data;
    plg.load_options();
  }

  virtual void merge_ending(
        diff_source_idx_t,
        void *module_data) override
  {
    plugin_ctx_t &plg = *(plugin_ctx_t *)module_data;
    plg.save_options();
  }
};

static plg_procmod_diff_helper_t plg_procmod_helper;

//--------------------------------------------------------------------------
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS("Callgraph", MH_TERSE);
  create_std_modmerge_handlers(mhp, data_id, plg_procmod_helper);
}

