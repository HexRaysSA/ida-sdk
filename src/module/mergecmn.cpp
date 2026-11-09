/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.
        Various helper definitions for processor modules.

*/

#include <mergemod.hpp>

// PROCMOD_NAME is the name of the processor module name (e.g. "arm").
// PROCMODE_T is the name of the module specific data structure.
// usually PROCMODE_NAME is defined and we derive PROCMODE_T from it, but it
//
// PROCMOD_NAME is used as a prefix for the 'idpoptions' names.
// example: arm.analysis.simplify_instructions
// where arm is PROCMOD_NAME, and in the idbattr_info_t array there is "analysis.simplify_instructions"
//
#ifndef PROCMOD_T
#define APPEND_SUFF(name, suff)  name ## suff
#define TAPPEND_SUFF(name, suff) APPEND_SUFF(name, suff)
#define PROCMOD_T                TAPPEND_SUFF(PROCMOD_NAME, _t)
#define PROCMOD_HELPER_T         TAPPEND_SUFF(PROCMOD_NAME, _moddiff_helper_t)
#endif

// Also, PROCMOD_NODE_NAME should be defined: it is the name of the module netnode

// The standard module parameters for merging.
// The 'insert_after' argument is alwats MERGE_KIND_INF for processor modules
// because in this case the kernel puts the merge handler for idpoptions
// immediately after
// Global settings/Processor specific/
// For example:
// Global settings/Processor specific/pc.state.gnulnx_til_loaded: true
// The address-dependent merge handlers are put at the end of the
// list inside the "Processor specific/" folder. Example:
// Processor specific/Pushinfo/08048492
// Processor specific/Pushinfo/080484D0
//
#define DEFINE_MERGE_HANDLER_PARAMS(insert_after)                \
  merge_handler_params_t mhp(                                    \
        md,                                                      \
        "Processor specific",                                    \
        MERGE_KIND_NONE,            /* allocate a merge kind */  \
        insert_after,               /* insert after what? */     \
        MH_TERSE                    /* terse debug output; */    \
       |MH_LISTEN)                  /* listen to merge events */

//--------------------------------------------------------------------------
// A helper definition for the 'device' attribute. Most module need only
// this definition, and nothing else:
static const idbattr_info_t idbattr_device_name[] =
{
  IDI_DEVICE_ENTRY,
};

//--------------------------------------------------------------------------
// A local convenience macro for the definitions below
#define _PROCMOD_DIFF_HELPER(class_name, name, idbattrs)                     \
  MODDATA_DIFF_HELPER(class_name, name,                                      \
                      QSTRINGIZE(PROCMOD_NAME), PROCMOD_NODE_NAME, idbattrs)

//--------------------------------------------------------------------------
// A macro for std_moddata_diff_helper_t, see mergemod.hpp
// std_moddata_diff_helper_t requires the processor module to have the
// load_from_idb() method, which will be called at the end of merging.
// This macro is useful for merging the data stored in netnodes (not the fields
// of the processor specific data structure).
#define STD_PROCMOD_DIFF_HELPER(name, idbattrs)                              \
  using PROCMOD_HELPER_T = std_moddata_diff_helper_t<PROCMOD_T>;             \
  _PROCMOD_DIFF_HELPER(PROCMOD_HELPER_T, name, idbattrs)

//--------------------------------------------------------------------------
// This macro uses moddata_diff_helper_t, does not require any method definitions.
// It is more simpler that the previous macro and should be used when the module
// does not have `idpoptions` except DEVICE, but has some ea-specific data.
// An example of such module: tms320c6.
#define SIMPLE_PROCMOD_DIFF_HELPER(name, idbattrs)                           \
  _PROCMOD_DIFF_HELPER(moddata_diff_helper_t, name, idbattrs)

//--------------------------------------------------------------------------
/// Create and register a merge handler for internal processor module fields
/// param idbattrs descriptions of the fields
///
/// This macro should be used when the module has only idpoptions and no
/// address-dependent data.
#define DEFINE_SIMPLE_PROCMOD_HANDLER(idbattrs)                              \
  void create_std_procmod_handlers(merge_data_t &md)                         \
  {                                                                          \
    DEFINE_MERGE_HANDLER_PARAMS(MERGE_KIND_INF);                             \
    STD_PROCMOD_DIFF_HELPER(helper, idbattrs);                               \
    return create_std_modmerge_handlers(mhp, data_id, helper);               \
  }

//--------------------------------------------------------------------------
/// Create and register a merge handler for internal processor module fields
/// and node values
/// param idbattrs descriptions of the module fields
/// param merge_node_info descriptions of node values
///
/// The most commonly used macro, when both idpoptions and address-dependent
/// data are present.
#define DEFINE_STD_PROCMOD_HANDLER(idbattrs, merge_node_info)                \
  void create_std_procmod_handlers(merge_data_t &md)                         \
  {                                                                          \
    DEFINE_MERGE_HANDLER_PARAMS(MERGE_KIND_INF);                             \
    STD_PROCMOD_DIFF_HELPER(helper, idbattrs);                               \
    return create_std_modmerge_handlers(mhp, data_id, helper,                \
                    merge_node_info, qnumber(merge_node_info));              \
  }

//--------------------------------------------------------------------------
/// The following functions can be useful in the helper class methods.
/// See examples in the SDK.
//--------------------------------------------------------------------------
inline void get_merging_func_name(qstring *out, ea_t func_ea, bool with_addr=false)
{
  if ( get_name(out, func_ea) <= 0 )
    out->sprnt("func<%a>", func_ea);
  else if ( with_addr )
    out->cat_sprnt(" at %a", func_ea);
}

//--------------------------------------------------------------------------
/// print string representation of flag values according to map bit=>name
inline qstring build_flags_info(uint64 flags, const idbattr_valmap_t *map, int n)
{
  qstring str_flags;
  for ( int i = 0; i < n; ++i )
    if ( (flags & map[i].value) != 0 )
      str_flags.cat_sprnt(" %s", map[i].valname);
  return str_flags;
}
