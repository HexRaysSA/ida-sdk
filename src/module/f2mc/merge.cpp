/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "f2mc.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//--------------------------------------------------------------------------
#define MERGE_FIELD(mask, name) \
  { name,                              /* field name */ \
    size_t(-1),                        /* altval index */ \
    sizeof(f2mc_t::idpflags),          /* width */ \
    mask,                              /* bitmask */ \
    atag,                              /* tag (for node values only) */ \
    nullptr,                           /* idbattr_valmap */ \
    nullptr,                           /* individual_node */ \
    IDI_ALTVAL|IDI_SCALAR }            /* flags: altval */
static const idbattr_info_t idpopts_info[] =
{
  MERGE_FIELD(F2MC_MACRO, "Use macro instructions"),
  IDI_DEVICE_ENTRY
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
