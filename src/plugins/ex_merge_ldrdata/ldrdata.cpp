/*
        Interactive disassembler (IDA).
        Copyright (c) 1990-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Example: Merge data created by loaders.

        This is an example how to implement the merging of loader data
        based on the IDA Pro loaders implementation.
        Do not install this plugin, it will not have any effect.
        The same may be used for debugger data or another plugin.

*/
#include <pro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <exehdr.h>
#include <diskio.hpp>
#include <mergemod.hpp>
#include "../../ldr/pe/pe.h"
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"
#include "../../ldr/aof/aof.h"
static int data_id;

//==========================================================================
// PE_NODE
// ../../ldr/pe/pe.h:1003
//--------------------------------------------------------------------------
static const idbattr_info_t penode_idpopts_info[] =
{
  // netnode value() -> peheader_t
  { "PE_header",          0,                 sizeof(peheader_t),      0, 0,             nullptr, nullptr, IDI_VALOBJ|IDI_BYTEARRAY, 0 },
  // altval() -> translated fpos of debuginfo
  { "dbginfo_fpos",       PE_ALT_DBG_FPOS,   sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> loading address (usually pe.imagebase)
  { "loading_address",    PE_ALT_IMAGEBASE,  sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> offset of PE header
  { "PE_header_offset",   PE_ALT_PEHDR_OFF,  sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> neflags
  { "NE_flags",           PE_ALT_NEFLAGS,    sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> tds already loaded(1) or invalid(-1)
  { "TDS_loaded",         PE_ALT_TDS_LOADED, sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> if POSIX(x86) imports from PSXDLL netnode
  { "POSIX_x86_imported", PE_ALT_PSXDLL,     sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> overlay rva (if present)
  { "overlay_RVA",        PE_ALT_OVRVA,      sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // altval() -> overlay size (if present)
  { "overlay_size",       PE_ALT_OVRSZ,      sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // supstr() -> pdb file name
  { "PDB_filename",       PE_SUPSTR_PDBNM,   0,                       0, stag,          nullptr, nullptr, IDI_SUPVAL|IDI_CSTR,      0 },
  // altval() -> uses Native API
  { "use_Native_API",     PE_ALT_NTAPI,      sizeof(ea_t),            0, atag,          nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR,    0 },
  // blob(0, PE_NODE_RELOC)  -> relocation info
  { "relocation_info",    0,                 0,                       0, PE_NODE_RELOC, nullptr, nullptr, IDI_BLOB|IDI_BYTEARRAY,   0 },
  // blob(0, RSDS_TAG)  -> rsds_t structure
  { "RSDS",               0,                 sizeof(rsds_t),          0, RSDS_TAG,      nullptr, nullptr, IDI_BLOB|IDI_BYTEARRAY,   0 },
  // blob(0, NB10_TAG)  -> cv_info_pdb20_t structure
  { "NB10",               0,                 sizeof(cv_info_pdb20_t), 0, NB10_TAG,      nullptr, nullptr, IDI_BLOB|IDI_BYTEARRAY,   0 },
  // blob(0, UTDS_TAG)  -> rsds_t structure
  { "UTDS",               0,                 sizeof(rsds_t),          0, UTDS_TAG,      nullptr, nullptr, IDI_BLOB|IDI_BYTEARRAY,   0 },
};
SIMPLE_MODDATA_DIFF_HELPER(penode_plugin_helper, "penode", PE_NODE, penode_idpopts_info);

//--------------------------------------------------------------------------
static merge_node_info_t penode_merge_node_info[] =
{
  // altval(segnum) -> s->start_ea
  { "pe_segment_start_ea", atag, NDS_IS_EA, nullptr },
  // supval(segnum) -> pesection_t
  { "segment_pesection", stag, NDS_SUPVAL, nullptr },
};

//==========================================================================
// ELFNODE
// ../../ldr/elf/elfbase.h:991
//--------------------------------------------------------------------------
static const idbattr_info_t elfnode_idpopts_info[] =
{
  // netnode value() -> Elf64_Ehdr
  { "ELF_header", 0, sizeof(elf_ehdr_t), 0, 0, nullptr, nullptr, IDI_VALOBJ|IDI_BYTEARRAY },
};
SIMPLE_MODDATA_DIFF_HELPER(elfnode_plugin_helper, "elfnode", ELFNODE, elfnode_idpopts_info);

//--------------------------------------------------------------------------
static merge_node_info_t elfnode_merge_node_info[] =
{
  // supval(idx): elf_shdr_t
  { "elf_section_headers", ELF_SHT_TAG, NDS_SUPVAL, nullptr },
  // supval(idx): elf_phdr_t
  { "elf_segment_headers", ELF_PHT_TAG, NDS_SUPVAL, nullptr },
};

//==========================================================================
// TLSNODE
// ../../ldr/elf/elfbase.h:994
//--------------------------------------------------------------------------
static const idbattr_info_t tlsnode_idpopts_info[] =
{
  // altval(0): the TLS template address + 1
  { "start_address_of_the_TLS_template", 0, sizeof(ea_t), 0, atag, nullptr, nullptr, IDI_ALTVAL|IDI_SCALAR|IDI_INC },
  // altval(-1): size of the TLS template
  IDI_ALTENTRY(-1, atag, sizeof(ea_t), 0, nullptr, "size_of_the_TLS_template"),
};
SIMPLE_MODDATA_DIFF_HELPER(tlsnode_plugin_helper, "tlsnode", TLSNODE, tlsnode_idpopts_info);

//==========================================================================
// segment flag bits in IDA Pro for ARM module
//--------------------------------------------------------------------------
struct armsegfl_merge_node_helper_t : public merge_node_helper_t
{
  armsegfl_merge_node_helper_t() {}

public:
  static merge_node_helper_t *instance(merge_data_t &, int)
  {
    return new armsegfl_merge_node_helper_t();
  }
  qstring print_entry_name(uchar, nodeidx_t ndx, void *) const override
  {
    ushort sflags = get_arm_segm_flags(node2ea(ndx));
    qstring buf;
    buf.append((sflags & SEGFL_COMDEF) != 0 ? "COMDEF " : "COMMON ");
    if ( (sflags & SEGFL_BASED) != 0 )
      buf.cat_sprnt("BASED %d ", sflags & SEGFL_BREG);
    if ( (sflags & SEGFL_PIC) != 0 )
      buf.append("PIC ");
    if ( (sflags & SEGFL_REENTR) != 0 )
      buf.append("REENTRANT ");
    if ( (sflags & SEGFL_HALFW) != 0 )
      buf.append("HALFWORD ");
    if ( (sflags & SEGFL_INTER) != 0 )
      buf.append("INTERWORK ");
    int align = (sflags & SEGFL_ALIGN) >> SEGFL_SHIFT;
    buf.cat_sprnt("ALIGN=%d", align);
    return buf;
  }
};

// ../../ldr/aof/aof.h:154
static merge_node_info_t armsegfl_merge_node_info[] =
{
  // the bits are kept in netnode().altval(seg_start_ea)
  { "arm_segment_flags", atag, NDS_MAP_IDX|NDS_UI_ND, armsegfl_merge_node_helper_t::instance },
};

//==========================================================================
void create_merge_handlers(merge_data_t &md)
{
  merge_handler_params_t mhp =
  {
    md,
    "Plugins/Loader/PE file",
    MERGE_KIND_NONE,
    MERGE_KIND_END,   // insert to the end of handler list
    MH_TERSE,
  };
  create_std_modmerge_handlers(mhp, data_id, penode_plugin_helper, penode_merge_node_info, qnumber(penode_merge_node_info));

  mhp.label = "Plugins/Loader/ELF file";
  create_std_modmerge_handlers(mhp, data_id, elfnode_plugin_helper, elfnode_merge_node_info, qnumber(elfnode_merge_node_info));

  mhp.label = "Plugins/Loader/TLS";
  create_std_modmerge_handlers(mhp, data_id, tlsnode_plugin_helper);

  mhp.label = "Plugins/Loader/ARM segment flags";
  create_nodeval_merge_handlers(
        nullptr,
        mhp,
        data_id,
        SEGFL_NETNODE_NAME,
        armsegfl_merge_node_info,
        qnumber(armsegfl_merge_node_info));
}

//==========================================================================
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  plugin_ctx_t()
  {
    hook_event_listener(HT_IDP, this);
  }

  ~plugin_ctx_t()
  {
    clr_module_data(data_id);
  }

  virtual bool idaapi run(size_t) override
  {
    return true;
  }

  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override
  {
    switch ( code )
    {
      case processor_t::ev_create_merge_handlers:
        {
          merge_data_t *md = va_arg(va, merge_data_t *);
          create_merge_handlers(*md);
        }
        break;
    }
    return 0;  // event is not processed
  }
};

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  auto plugmod = new plugin_ctx_t;
  set_module_data(&data_id, plugmod);
  return plugmod;
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Example: Merge data created by loaders";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_HIDE | PLUGIN_MULTI, // plugin flags
  init,                 // initialize
  nullptr,              // terminate. this pointer may be nullptr.
  nullptr,              // invoke plugin
  wanted_name,          // long comment about the plugin
  wanted_name,          // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
