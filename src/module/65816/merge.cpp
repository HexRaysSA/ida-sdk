/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "m65816.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//--------------------------------------------------------------------------
#define MERGE_HASH(name, mask, flag) \
  IDI_HASHENTRY(name, 'H', 0, mask, flag, nullptr, "loader." name)

static const idbattr_info_t idpopts_info[] =
{
  IDI_DEVICE_ENTRY,
  MERGE_HASH("rom_size",      0, IDI_ALTVAL),
  MERGE_HASH("ram_size",      0, IDI_ALTVAL),
  MERGE_HASH("header_offset", 0, IDI_ALTVAL),

  MERGE_HASH("type",          0, IDI_SUPVAL|IDI_CSTR),
  MERGE_HASH("region",        0, IDI_SUPVAL|IDI_CSTR),
  MERGE_HASH("mapper",        0, IDI_SUPVAL|IDI_CSTR),
  MERGE_HASH("dsp1_mapper",   0, IDI_SUPVAL|IDI_CSTR),

  MERGE_HASH("firmware_appended", 1, IDI_ALTVAL),
  MERGE_HASH("has_bsx_slot",      1, IDI_ALTVAL),
  MERGE_HASH("has_superfx",       1, IDI_ALTVAL),
  MERGE_HASH("has_sa1",           1, IDI_ALTVAL),
  MERGE_HASH("has_sharprtc",      1, IDI_ALTVAL),
  MERGE_HASH("has_epsonrtc",      1, IDI_ALTVAL),
  MERGE_HASH("has_sdd1",          1, IDI_ALTVAL),
  MERGE_HASH("has_spc7110",       1, IDI_ALTVAL),
  MERGE_HASH("has_cx4",           1, IDI_ALTVAL),
  MERGE_HASH("has_dsp1",          1, IDI_ALTVAL),
  MERGE_HASH("has_dsp2",          1, IDI_ALTVAL),
  MERGE_HASH("has_dsp3",          1, IDI_ALTVAL),
  MERGE_HASH("has_dsp4",          1, IDI_ALTVAL),
  MERGE_HASH("has_obc1",          1, IDI_ALTVAL),
  MERGE_HASH("has_st010",         1, IDI_ALTVAL),
  MERGE_HASH("has_st011",         1, IDI_ALTVAL),
  MERGE_HASH("has_st018",         1, IDI_ALTVAL),
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)
