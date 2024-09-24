/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality for the PC module.

*/

#include "avr.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//--------------------------------------------------------------------------
static const idbattr_info_t idpopts_info[] =
{
  { "analysis.ROM_segment_start",        /* helper.altset(-1, ea2node(ea)) */ \
    size_t(-1),                          /* altval index                   */ \
    sizeof(ea_t),                        /* width                          */ \
    0,                                   /* bitmask                        */ \
    atag,                                /* tag (for node values only)     */ \
    nullptr,                             /* vmap                           */ \
    nullptr,                             /* individual_node                */ \
    IDI_ALTVAL|IDI_SCALAR|IDI_MAP_VAL }, /* flags                          */

  IDI_DEVICE_ENTRY,
};

//--------------------------------------------------------------------------
static merge_node_info_t merge_node_info[] =
{
  MNI_STDENTRY(atag,        0,        "Entry point"),
  MNI_STDENTRY(ELF_AVR_TAG, NDS_VAL8, "ELF reloc flag"),
};

//--------------------------------------------------------------------------
DEFINE_STD_PROCMOD_HANDLER(idpopts_info, merge_node_info)
