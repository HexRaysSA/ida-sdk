/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2025 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "tms6.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//-------------------------------------------------------------------------
struct tms6_merge_node_helper_t : public merge_node_helper_t
{
  tms6_merge_node_helper_t() {}

  static merge_node_helper_t *instance(merge_data_t &, int)
  {
    return new tms6_merge_node_helper_t();
  }

  qstring print_entry_name(
        uchar tag,
        nodeidx_t ndx,
        void *module_data) const override
  {
    tms6_t *pm = static_cast<tms6_t *>(module_data);
    switch ( tag )
    {
      case stag:
        return print_tgtinfo_name(*pm, ndx);
      default:
        return "";
    }
  }

  qstring print_tgtinfo_name(const tms6_t &pm, nodeidx_t ndx) const
  {
    tgtinfo_t tgt;
    if ( !tgt.restore_from_idb(pm, node2ea(ndx)) )
      return "";
    qstring name = tgt.get_type_name();
    if ( tgt.has_target() )
      name.cat_sprnt(":%a", tgt.target);
    return name;
  }
};

//-------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name)  IDI_ALTENTRY(-1, atag, sizeof(tms6_t::idpflags), mask, nullptr, name)
static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_SCALE_OFFSETS, "analysis.scale_offsets"),
  IDI_DEVICE_ENTRY,
  };

//-------------------------------------------------------------------------
static merge_node_info_t merge_node_info[] =
{
  MNI_ENTRY(stag,
            NDS_SUPVAL|NDS_UI_ND,
            "call/branch info",
            tms6_merge_node_helper_t::instance),
};

//--------------------------------------------------------------------------
DEFINE_STD_PROCMOD_HANDLER(idpopts_info, merge_node_info)
