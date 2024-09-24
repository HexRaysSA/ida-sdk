/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _MERGE_HPP
#define _MERGE_HPP

#include <functional>
#include <queue>
#include <nalt.hpp>
#include <diff3.hpp>

/*! \file merge.hpp

  \brief Merge functionality.

        NOTE: this functionality is available in IDA Teams (not IDA Pro)

        There are 3 databases involved in merging: base_idb, local_db, and remote_idb.
         - base_idb: the common base ancestor of 'local_db' and 'remote_db'.
                  in the UI this database is located in the middle.
         - local_idb: local database that will contain the result of the merging.
                  in the UI this database is located on the left.
         - remote_idb: remote database that will merge into local_idb. It may reside
                  locally on the current computer, despite its name.
                  in the UI this database is located on the right.
        base_idb and remote_idb are opened for reading only.
        base_idb may be absent, in this case a 2-way merging is performed.

        Conflicts can be resolved automatically or interactively.
        The automatic resolving scores the conflicting blocks and takes the better one.
        The interactive resolving displays the full rendered contents side by
        side, and expects the user to select the better side for each conflict.

        Since IDB files contain various kinds of information, there are many
        merging phases. The entire list can be found in merge.cpp. Below are
        just some selected examples:
          - merge global database settings (inf and other global vars)
          - merge segmentation and changes to the database bytes
          - merge various lists: exports, imports, loaded tils, etc
          - merge names, functions, function frames
          - merge debugger settings, breakpoints
          - merge struct/enum views
          - merge local type libraries
          - merge the disassembly items (i.e. the segment contents)
            this includes operand types, code/data separation, etc
          - merge plugin specific info like decompiler types, dwarf mappings, etc

        To unify UI elements of each merge phase, we use merger views:
          - A view that consists of 2 or 3 panes: left (local_idb) and right (remote_idb).
            The common base is in the middle, if present.
          - Rendering of the panes depends on the phase, different phases
            show different contents.
          - The conflicts are highlighted by a colored background. Also,
            the detail pane can be consulted for additional info.
          - The user can select a conflict (or a bunch of conflicts) and say
            "use this block".
          - The user can browse the panes as he wishes. He will not be forced
            to handle conflicts in any particular order. However, once he
            finishes working with a merge handler and proceeds to the next one,
            he cannot go back.
          - Scrolling the left pane will synchronously scroll the right pane
            and vice versa.
          - There are the navigation commands like "go to the prev/next conflict"
          - The number of remaining conflicts to resolve is printed in the
            "Progress" chooser.
          - The user may manually modify local database inside the merger view.
            For that he may use the regular hotkeys. However, editing the database
            may lead to new conflicts, so we better restrict the available actions
            to some reasonable minimum. Currently, this is not implemented.

        IDA works in a new "merge" mode during merging. In this mode most
        events are not generated. We forbid them to reduce the risk that a rogue
        third-party plugin that is not aware of the "merge" mode would spoil something.

        For example, normally renaming a function causes a cascade of events
        and may lead to other database modifications. Some of them may be
        desired, some - not. Since there are some undesired events, it is
        better to stop generating them. However, some events are required to
        render the disassembly listing. For example, ev_ana_insn, av_out_insn.
        This is why some events are still generated in the "merge" mode.

        To let processor modules and plugins merge their data, we introduce
        a new event: ev_create_merge_handlers. It is generated immediately after
        opening all three idbs. The interested modules should react to this
        event by creating new merge handlers, if they need them.

        While the kernel can create arbitrary merge handlers, modules
        can create only the standard ones returned by:

          create_nodeval_merge_handler()
          create_nodeval_merge_handlers()
          create_std_modmerge_handlers()

        We do not document merge_handler_t because once a merge handler is
        created, it is used exclusively by the kernel.

        See mergemod.hpp for more information about the merge mode for modules.
*/

#ifdef switch_dbctx
  #define ui_switch_dbctx_guard switch_dbctx
  #undef switch_dbctx
#endif

//------------------------------------------------------------------------
/// Kinds of merge handlers.
enum merge_kind_t ENUM_SIZE(uint32)
{
  MERGE_KIND_NETNODE,           ///< netnode (no merging, to be used in idbunits)
  MERGE_KIND_AUTOQ,             ///< auto queues
  MERGE_KIND_INF,               ///< merge the inf variable (global settings)
  MERGE_KIND_ENCODINGS,         ///< merge encodings
  MERGE_KIND_ENCODINGS2,        ///< merge default encodings
  MERGE_KIND_SCRIPTS2,          ///< merge scripts common info
  MERGE_KIND_SCRIPTS,           ///< merge scripts
  MERGE_KIND_CUSTDATA,          ///< merge custom data type and formats
  MERGE_KIND_ENUMS,             ///< merge enums
  MERGE_KIND_STRUCTS,           ///< merge structs (globally: add/delete structs entirely)
  MERGE_KIND_TILS,              ///< merge type libraries
  MERGE_KIND_TINFO,             ///< merge tinfo
  MERGE_KIND_STRMEM,            ///< merge struct members
  MERGE_KIND_UDTMEM,            ///< merge UDT members (local types)
  MERGE_KIND_GHSTRCMT,          ///< merge ghost structure comment
  MERGE_KIND_STRMEMCMT,         ///< merge member comments for ghost struc
  MERGE_KIND_SELECTORS,         ///< merge selectors
  MERGE_KIND_STT,               ///< merge flag storage types
  MERGE_KIND_SEGMENTS,          ///< merge segments
  MERGE_KIND_SEGGRPS,           ///< merge segment groups
  MERGE_KIND_SEGREGS,           ///< merge segment registers
  MERGE_KIND_ORPHANS,           ///< merge orphan bytes
  MERGE_KIND_BYTEVAL,           ///< merge byte values
  MERGE_KIND_FIXUPS,            ///< merge fixups
  MERGE_KIND_MAPPING,           ///< merge manual memory mapping
  MERGE_KIND_EXPORTS,           ///< merge exports
  MERGE_KIND_IMPORTS,           ///< merge imports
  MERGE_KIND_PATCHES,           ///< merge patched bytes
  MERGE_KIND_FLAGS,             ///< merge flags64_t
  MERGE_KIND_EXTRACMT,          ///< merge extra next or prev lines
  MERGE_KIND_AFLAGS_EA,         ///< merge aflags for mapped EA
  MERGE_KIND_IGNOREMICRO,       ///< IM ("$ ignore micro") flags
  MERGE_KIND_FILEREGIONS,       ///< merge fileregions
  MERGE_KIND_HIDDENRANGES,      ///< merge hidden ranges
  MERGE_KIND_SOURCEFILES,       ///< merge source files ranges
  MERGE_KIND_FUNC,              ///< merge func info
  MERGE_KIND_FRAMEMGR,          ///< merge frames (globally: add/delete frames entirely)
  MERGE_KIND_FRAME,             ///< merge function frame info (frame members)
  MERGE_KIND_STKPNTS,           ///< merge SP change points
  MERGE_KIND_FLOWS,             ///< merge flows
  MERGE_KIND_CREFS,             ///< merge crefs
  MERGE_KIND_DREFS,             ///< merge drefs
  MERGE_KIND_BPTS,              ///< merge breakpoints
  MERGE_KIND_WATCHPOINTS,       ///< merge watchpoints
  MERGE_KIND_BOOKMARKS,         ///< merge bookmarks
  MERGE_KIND_TRYBLKS,           ///< merge try blocks
  MERGE_KIND_DIRTREE,           ///< merge std dirtrees
  MERGE_KIND_VFTABLES,          ///< merge vftables
  MERGE_KIND_SIGNATURES,        ///< signatures
  MERGE_KIND_PROBLEMS,          ///< problems
  MERGE_KIND_UI,                ///< UI
  MERGE_KIND_DEKSTOPS,          ///< dekstops
  MERGE_KIND_NOTEPAD,           ///< notepad
  MERGE_KIND_LOADER,            ///< loader data
  MERGE_KIND_DEBUGGER,          ///< debugger data
  MERGE_KIND_DBG_MEMREGS,       ///< manual memory regions (debugger)
  MERGE_KIND_LUMINA,            ///< lumina function metadata
  MERGE_KIND_LAST,              ///< last predefined merge handler type.
                                ///< please note that there can be more merge handler types,
                                ///< registered by plugins and processor modules.
  MERGE_KIND_END = merge_kind_t(-2),
                                ///< insert to the end of handler list,
                                ///< valid for merge_handler_params_t::insert_after
  MERGE_KIND_NONE = merge_kind_t(-1)
};

//------------------------------------------------------------------------
class merge_handler_t;
class merge_data_t;
using merge_handlers_t = qvector<merge_handler_t *>;
//--------------------------------------------------------------------------
/// Return TRUE if IDA is running in diff mode (MERGE_POLICY_MDIFF/MERGE_POLICY_VDIFF)
idaman bool ida_export is_diff_merge_mode();

//--------------------------------------------------------------------------
/// class to contain public info about the merge process
class merge_data_t
{
public:
  /// several items can be grouped into a block. It is more natural to
  /// consider all items in a block as a whole (e.g. IT-blocks in ARM).
  /// This class can be used to detect a block containing an instruction
  /// and to setup internal block-specific data before updating of an item
  /// that is a parts of a block
  struct item_block_locator_t
  {
    /// get block address (address of first item in the block) by address of item
    /// this function returns item address if it does not belong to any block
    virtual ea_t get_block_head(merge_data_t &md, diff_source_idx_t idx, ea_t item_head) = 0;

    /// setup block-specific info before region updating, return FALSE if
    /// nothing was changed
    virtual bool setup_blocks(
        merge_data_t &md,
        diff_source_idx_t from,
        diff_source_idx_t to,
        const diff_range_t &region) = 0;

    virtual ~item_block_locator_t() {}
  };

  class merge_mappers_t &mappers;

  int dbctx_ids[3] = { -1, -1, -1 };  ///< local, remote, base ids
  int nbases = 0;                     ///< number of database participating in merge process,
                                      ///< maybe 2 or 3
  merge_handlers_t ev_handlers;       ///< event handlers
  item_block_locator_t *item_block_locator = nullptr;
  merge_handler_t *last_udt_related_merger = nullptr;

  merge_data_t();
  virtual ~merge_data_t();
  merge_data_t(const merge_data_t &) = delete;
  void operator=(const merge_data_t &) = delete;

  void set_dbctx_ids(int local, int remote, int base)
  {
    dbctx_ids[LOCAL_IDX] = local;
    dbctx_ids[REMOTE_IDX] = remote;
    dbctx_ids[BASE_IDX] = base;
    nbases = base != -1 ? 3 : 2;
  }

  int local_id()  const { return dbctx_ids[LOCAL_IDX]; }
  int remote_id() const { return dbctx_ids[REMOTE_IDX]; }
  int base_id()   const { return dbctx_ids[BASE_IDX]; }

  void add_event_handler(merge_handler_t *handler) { ev_handlers.push_back(handler); }
  void remove_event_handler(merge_handler_t *handler) { ev_handlers.del(handler); }

  ea_t get_block_head(diff_source_idx_t idx, ea_t item_head)
  {
    return item_block_locator == nullptr
         ? item_head
         : item_block_locator->get_block_head(*this, idx, item_head);
  }
  bool setup_blocks(diff_source_idx_t dst_idx, diff_source_idx_t src_idx, const diff_range_t &region)
  {
    return item_block_locator != nullptr
        && item_block_locator->setup_blocks(*this, dst_idx, src_idx, region);
  }

  // make these functions virtual to be available from plugins

  /// check that node exists in any of databases
  virtual bool has_existing_node(const char *nodename) const;

  /// map IDs of structures, enumerations and their members
  /// \param[out] tid     item ID in TO database
  /// \param      ea      item ID to find counterpart
  /// \param      from    source database index, \ref diff_source_idx_t
  /// \param      to      destination database index, \ref diff_source_idx_t
  /// \param      strict  raise interr if could not map
  /// \return success
  virtual bool map_privrange_id(
        tid_t *tid,
        ea_t ea,
        diff_source_idx_t from,
        diff_source_idx_t to,
        bool strict=true);

  /// migrate type,
  /// replaces type references into FROM database to references into TO database
  /// \param[inout] tif     type to migrate, will be cleared in case of fail
  /// \param        from    source database index, \ref diff_source_idx_t
  /// \param        to      destination database index, \ref diff_source_idx_t
  /// \param        strict  raise interr if could not map
  /// \return success
  virtual bool map_tinfo(
        tinfo_t *tif,
        diff_source_idx_t from,
        diff_source_idx_t to,
        bool strict=true);

  /// compare types from two databases
  /// \param tif1      type
  /// \param diffidx1  database index, \ref diff_source_idx_t
  /// \param tif2      type
  /// \param diffidx2  database index, \ref diff_source_idx_t
  /// \return -1, 0, 1
  virtual int compare_merging_tifs(
        const tinfo_t &tif1,
        diff_source_idx_t diffidx1,
        const tinfo_t &tif2,
        diff_source_idx_t diffidx2) const;
};

//------------------------------------------------------------------------
/// Merge handler parameters.
/// They describe the handler label, its kind (which is usually automatically
/// allocated by IDA), and various flags.
/// The MH_UI_... flags describe how the merge differences will be displayed to the user.
/// By default they are displayed as a list (using a chooser), and a detail pane
/// at the bottom.
/// Currently the chooser columns are automatically determined based on the diffpos
/// name. A diffpos name is a textual representation of an object that we compare
/// during merging. For example, if 2 IDBs have different imagebases, then the user
/// would see diffpos names like the following:
///     addresses.imagebase: 0x8048000
///     addresses.imagebase: 0xA000000
/// Specifying MH_UI_COLONNAME would cause IDA to create a 2-column chooser for
/// this merge handler.
struct merge_handler_params_t
{
  merge_data_t &md;
  qstring label;
  merge_kind_t kind;            ///< merge handler kind \ref merge_kind_t
  merge_kind_t insert_after;    ///< desired position inside 'handlers' \ref merge_kind_t
  uint32 mh_flags;
#define MH_LISTEN           0x00000001 ///< merge handler will receive merge events
#define MH_TERSE            0x00000002 ///< do not display equal lines in the merge results table
#define MH_UI_NODETAILS     0x00000100 ///< ida will not show the diffpos details
#define MH_UI_COMPLEX       0x00000200 ///< diffpos details won't be displayed in the diffpos chooser
#define MH_UI_DP_NOLINEDIFF 0x00000400 ///< Detail pane: do not show differences inside the line
#define MH_UI_DP_SHORTNAME  0x00000800 ///< Detail pane: use the first part of a complex diffpos name as the tree node name
#define MH_UI_INDENT        0x00001000 ///< preserve indent for diffpos name in diffpos chooser
#define MH_UI_SPLITNAME     0x00800000 ///< ida will split the diffpos name by 7-bit ASCII char
                                       ///< to create chooser columns
#define MH_UI_CHAR_MASK     0x007F0000 ///< 7-bit ASCII split character
#define MH_UI_DEF_CHAR(v)   ((((v) & 0x7F) << 16) | MH_UI_SPLITNAME)
                                       ///< define split char
#ifndef SWIG
#define MH_UI_COMMANAME     MH_UI_DEF_CHAR(',')
#else
#define MH_UI_COMMANAME     0x00AC0000
#endif
                                       ///< ida will split the diffpos name by ',' to create chooser columns
#ifndef SWIG
#define MH_UI_COLONNAME     MH_UI_DEF_CHAR(':')
#else
#define MH_UI_COLONNAME     0x00BA0000
#endif
                                       ///< ida will split the diffpos name by ':' to create chooser columns
#define MH_DUMMY            0x80000000 ///< dummy entry - just to fill an array slot

  merge_handler_params_t(
        merge_data_t &_md,
        const qstring &_label,
        merge_kind_t _kind,
        merge_kind_t _insert_after,
        uint32 _mh_flags)
    : md(_md),
      label(_label),
      kind(_kind),
      insert_after(_insert_after),
      mh_flags(_mh_flags)
  {}

  /// Should IDA display the diffpos detail pane?
  static bool ui_has_details(uint32 _mh_flags)      { return (_mh_flags & MH_UI_NODETAILS) == 0; }
  bool ui_has_details() const                       { return ui_has_details(mh_flags); }

  /// Do not display the diffpos details in the chooser.
  /// For example, the MERGE_KIND_SCRIPTS handler puts the script body as the
  /// diffpos detail. It would not be great to show them as part of the chooser.
  static bool ui_complex_details(uint32 _mh_flags)  { return (_mh_flags & MH_UI_COMPLEX) != 0; }
  bool ui_complex_details() const                   { return ui_complex_details(mh_flags); }

  /// It customary to create long diffpos names having many components that
  /// are separated by any 7-bit ASCII character (besides of '\0').
  /// In this case it is possible to instruct IDA to use this separator
  /// to create a multi-column chooser.
  /// For example the MERGE_KIND_ENUMS handler has the following diffpos name:
  /// enum_1,enum_2
  /// If MH_UI_COMMANAME is specified, IDA will create 2 columns for these names.
  static bool ui_complex_name(uint32 _mh_flags)     { return (_mh_flags & MH_UI_SPLITNAME) != 0; }
  bool ui_complex_name() const                      { return ui_complex_name(mh_flags); }
  static char ui_split_char(uint32 _mh_flags)       { return (_mh_flags >> 16) & 0x7F; }
  char ui_split_char() const                        { return ui_split_char(mh_flags); }
  static qstring ui_split_str(uint32 _mh_flags)     { return qstring(1, ui_split_char(_mh_flags)); }
  qstring ui_split_str() const                      { return ui_split_str(mh_flags); }

  /// The detail pane shows the diffpos details for the current diffpos range
  /// as a tree-like view. In this pane the diffpos names are used as tree node
  /// names and the diffpos details as their children.
  /// Sometimes, for complex diffpos names, the first part of the name
  /// looks better than the entire name.
  /// For example, the MERGE_KIND_SEGMENTS handler has the following diffpos name:
  /// <range>,<segm1>,<segm2>,<segm3>
  /// if MH_UI_DP_SHORTNAME is specified, IDA will use <range> as a tree node name
  static bool ui_dp_shortname(uint32 _mh_flags)     { return (_mh_flags & MH_UI_DP_SHORTNAME) != 0; }
  bool ui_dp_shortname() const                      { return ui_dp_shortname(mh_flags); }

  /// In detail pane IDA shows difference between diffpos details.
  /// IDA marks added or deleted detail by color.
  /// In the modified detail the changes are marked.
  /// Use this UI hint if you do not want to show the differences inside detail.
  static bool ui_linediff(uint32 _mh_flags)         { return (_mh_flags & MH_UI_DP_NOLINEDIFF) == 0; }
  bool ui_linediff() const                          { return ui_linediff(mh_flags); }

  /// In the ordinary situation the spaces from the both sides of diffpos name are trimmed.
  /// Use this UI hint to preserve the leading spaces.
  static bool ui_indent(uint32 _mh_flags)           { return (_mh_flags & MH_UI_INDENT) != 0; }
  bool ui_indent() const                            { return ui_indent(mh_flags); }
};

//------------------------------------------------------------------------

/// helper class for module data diff source
struct moddata_diff_helper_t
{
  const char *module_name = nullptr;      ///< will be used as a prefix for field desc
  const char *netnode_name = nullptr;     ///< name of netnode with module data attributes
  const idbattr_info_t *fields = nullptr; ///< module data attribute descriptions
  size_t nfields = 0;                     ///< number of descriptions
  uint32 additional_mh_flags = MH_UI_NODETAILS;
                                          ///< additional merge handler flags

  moddata_diff_helper_t(
        const char *_module_name,
        const char *_netnode_name,
        const idbattr_info_t *_fields,
        size_t _nfields)
    : module_name(_module_name),
      netnode_name(_netnode_name),
      fields(_fields),
      nfields(_nfields)
  {
  }
  virtual ~moddata_diff_helper_t() {}

  virtual void merge_starting(diff_source_idx_t /*diffidx*/, void * /*module_data*/) {}
  virtual void merge_ending(diff_source_idx_t /*diffidx*/, void * /*module_data*/) {}
  virtual void *get_struc_ptr(merge_data_t &/*md*/, diff_source_idx_t /*diffidx*/, const idbattr_info_t &/*fi*/) { INTERR(2048); }
  virtual void print_diffpos_details(qstrvec_t * /*out*/, const idbattr_info_t &/*fi*/) {}
  virtual bool val2str(qstring * /*out*/, const idbattr_info_t &/*fi*/, uint64 /*value*/) { return false; }
  virtual bool str2val(uint64 * /*out*/, const idbattr_info_t &/*fi*/, const char * /*strvals*/) { return false; }
};
/// netnode value modificators (to be used in nodeval_diff_source, see below)
enum nds_flags_t
{
  NDS_IS_BOOL     = 0x0001,   ///< boolean value
  NDS_IS_EA       = 0x0002,   ///< EA value
  NDS_IS_RELATIVE = 0x0004,   ///< value is relative to index (stored as delta)
  NDS_IS_STR      = 0x0008,   ///< string value
  NDS_SUPVAL      = 0x0010,   ///< stored as netnode supvals (not scalar)
  NDS_BLOB        = 0x0020,   ///< stored as netnode blobs
  NDS_EV_RANGE    = 0x0040,   ///< enable default handling of mev_modified_ranges, mev_deleting_segm
  NDS_EV_FUNC     = 0x0080,   ///< enable default handling of mev_added_func/mev_deleting_func
  NDS_MAP_IDX     = 0x0100,   ///< apply ea2node() to index (==NETMAP_IDX)
  NDS_MAP_VAL     = 0x0200,   ///< apply ea2node() to value. Along with NDS_INC
                              ///< it gives effect of NETMAP_VAL, examples:
                              ///<   altval_ea : NDS_MAP_IDX
                              ///<   charval   : NDS_VAL8
                              ///<   charval_ea: NDS_MAP_IDX|NDS_VAL8
                              ///<   eaget     : NDS_MAP_IDX|NDS_MAP_VAL|NDS_INC
  NDS_VAL8        = 0x1000,   ///< use 8-bit values (==NETMAP_V8)
  NDS_INC         = 0x2000,   ///< stored value is incremented (scalars only)
  NDS_UI_ND       = 0x4000,   ///< UI: no need to show diffpos detail pane, \ref MH_UI_NODETAILS,
                              ///<     make sense if \ref merge_node_helper_t is used
};

//--------------------------------------------------------------------------
/// abstract adapter to provide access to non-standard netnode array entries
struct merge_node_helper_t
{
  virtual ~merge_node_helper_t() {}

  /// print the name of the specified entry
  /// (to be used in print_diffpos_name)
  virtual qstring print_entry_name(uchar /*tag*/, nodeidx_t /*ndx*/, void * /*module_data*/) const { return qstring(); }

  /// print the details of the specified entry
  /// usually contains multiple lines, one for each attribute or detail.
  /// (to be used in print_diffpos_details)
  virtual void print_entry_details(qstrvec_t * /*out*/, uchar /*tag*/, nodeidx_t /*ndx*/, void * /*module_data*/) const {}

  /// get column headers for chooser
  /// (to be used in linear_diff_source_t::get_column_headers)
  virtual void get_column_headers(qstrvec_t * /*headers*/, uchar /*tag*/, void * /*module_data*/) const {}

  /// filter: check if we should perform merging for given record
  virtual bool is_mergeable(uchar /*tag*/, nodeidx_t /*ndx*/) const { return true; }

  /// return netnode to be used as source. If this function returns BADNODE
  /// netnode will be created using netnode name passed to create_nodeval_diff_source
  virtual netnode get_netnode() const { return BADNODE; }

  /// map scalar/string/buffered value
  virtual void map_scalar(
        nodeidx_t * /*scalar_value*/,
        void * /*module_data*/,
        diff_source_idx_t /*from*/,
        diff_source_idx_t /*to*/) const
  {
  }
  virtual void map_string(
        qstring * /*string_value*/,
        void * /*module_data*/,
        diff_source_idx_t /*from*/,
        diff_source_idx_t /*to*/) const
  {
  }
  virtual void map_value(
        bytevec_t * /*value*/,
        void * /*module_data*/,
        diff_source_idx_t /*from*/,
        diff_source_idx_t /*to*/) const
  {
  }

  /// notify helper that some data was changed in the database and internal
  /// structures (e.g. caches) should be refreshed
  virtual void refresh(uchar /*tag*/, void * /*module_data*/) {}

  /// return name of netnode to be used in logging. If this function returns nullptr
  /// netnode name and tag passed to create_nodeval_diff_source will be used
  virtual const char *get_logname() const { return nullptr; }

  /// can be used by derived classes
  static void append_eavec(qstring *s, const char *prefix, const eavec_t &eas)
  {
    s->append(prefix);
    s->append(" [");
    if ( !eas.empty() )
    {
      for ( const auto ea : eas )
        s->cat_sprnt("%a,", ea);
      s->remove_last();
    }
    s->append(']');
  }
};
typedef merge_node_helper_t *merge_node_helper_creator_t(merge_data_t &md, int dbctx_id);
using merge_node_hlpfunc_creator_t = std::function<merge_node_helper_creator_t>;

//--------------------------------------------------------------------------
/// field descriptor used to organize merging of a netnode array
struct merge_node_info_t
{
  const char *name; ///< name of the array (label)
  uchar tag;        ///< a tag used to access values in the netnode
  uint32 nds_flags; ///< node value attributes (a combination of \ref nds_flags_t)
  merge_node_helper_creator_t *nhc;
                    ///< a factory to create instances of \ref merge_node_helper_t
};
DECLARE_TYPE_AS_MOVABLE(merge_node_info_t);
struct merge_node_info2_t
{
  const char *name; ///< name of the array (label)
  uchar tag;        ///< a tag used to access values in the netnode
  uint32 nds_flags; ///< node value attributes (a combination of \ref nds_flags_t)
  merge_node_helper_t *node_helper;
                    ///< merge handler creation helper, foreign owner
};
DECLARE_TYPE_AS_MOVABLE(merge_node_info2_t);

/// Create a merge handler for netnode scalar/string values
/// \param mhp merging parameters
/// \param label handler short name (to be be appended to mhp.label)
/// \param moddata_id module data ID (to be passed to get_module_data)
/// \param nodename netnode name
/// \param tag a tag used to access values in the netnode
/// \param nds_flags netnode value attributes (a combination of \ref nds_flags_t)
/// \param nhc a factory to create instances of \ref merge_node_helper_t
/// \param skip_empty_nodes do not create handler in case of empty netnode
/// \return diff source object (normally should be attahced to a merge handler)
idaman merge_handler_t *ida_export create_nodeval_merge_handler(
        const merge_handler_params_t &mhp,
        const char *label,
        int moddata_id,
        const char *nodename,
        uchar tag,
        uint32 nds_flags,
        merge_node_hlpfunc_creator_t nhc = nullptr,
        bool skip_empty_nodes = true);
idaman merge_handler_t *ida_export create_nodeval_merge_handler2(
        const merge_handler_params_t &mhp,
        const char *label,
        int moddata_id,
        const char *nodename,
        uchar tag,
        uint32 nds_flags,
        merge_node_helper_t *node_helper = nullptr,    // owned by the caller
        bool skip_empty_nodes = true);

/// Create a serie of merge handlers for netnode scalar/string values
/// (call create_nodeval_merge_handler() for each member of VALDESC)
/// \param out [out] created handlers will be placed here
/// \param mhp merging parameters
/// \param moddata_id module data ID (to be passed to get_module_data)
/// \param nodename netnode name
/// \param valdesc array of handler descriptions
/// \param nvals number of members in VALDESC
/// \param skip_empty_nodes do not create handlers for empty netnodes
/// \return diff source object (normally should be attahced to a merge handler)
idaman void ida_export create_nodeval_merge_handlers(
        merge_handlers_t *out,
        const merge_handler_params_t &mhp,
        int moddata_id,
        const char *nodename,
        const merge_node_info_t *valdesc,
        size_t nvals,
        bool skip_empty_nodes = true);
idaman void ida_export create_nodeval_merge_handlers2(
        merge_handlers_t *out,
        const merge_handler_params_t &mhp,
        int moddata_id,
        const char *nodename,
        const merge_node_info2_t *valdesc,
        size_t nvals,
        bool skip_empty_nodes = true);

//------------------------------------------------------------------------
// macros for convenience to be used in modules:

/// idbattr_info_t entry for scalar structure field
#define IDI_FLDENTRY(struc, field, mask, valmap, name)                  \
  { name,                              /* field description          */ \
    qoffsetof(struc, field),           /* offset                     */ \
    sizeof(struc::field),              /* width                      */ \
    mask,                              /* bitmask                    */ \
    0,                                 /* tag (for node values only) */ \
    valmap,                            /* vmap                       */ \
    nullptr,                           /* individual_node            */ \
    IDI_STRUCFLD|IDI_SCALAR }          /* flags                      */

/// idbattr_info_t entry for qstring structure field
#define IDI_FLDQSTR(struc, field, name) \
  { name, qoffsetof(struc, field), 0, 0, 0, nullptr, nullptr, IDI_STRUCFLD|IDI_QSTRING }

/// idbattr_info_t entry for scalar node altval
#define IDI_ALTENTRY(altidx, tag, width, mask, valmap, name)            \
  { name,                              /* field description          */ \
    uintptr_t(altidx),                 /* altval index               */ \
    width,                             /* width                      */ \
    mask,                              /* bitmask                    */ \
    tag,                               /* tag (for node values only) */ \
    valmap,                            /* vmap                       */ \
    nullptr,                           /* individual_node            */ \
    IDI_ALTVAL|IDI_SCALAR }            /* flags                      */

/// idbattr_info_t entry for named node hash entry
#define IDI_HASHENTRY(hashname, tag, width, mask, flag, valmap, name)   \
  { name,                              /* field description          */ \
    uintptr_t(hashname),               /* hash name                  */ \
    width,                             /* width                      */ \
    mask,                              /* bitmask                    */ \
    tag,                               /* tag (for node values only) */ \
    valmap,                            /* vmap                       */ \
    nullptr,                           /* individual_node            */ \
    IDI_HASH|(flag) }                  /* flags                      */

/// idbattr_info_t entry for node supstr
#define IDI_SUPSTR(altidx, tag, name) \
  { name, uintptr_t(altidx), 0, 0, tag, nullptr, nullptr, IDI_SUPVAL|IDI_CSTR }

/// standard idbattr_info_t entry for 'device' (to be used in processor modules)
#define IDI_DEVICE_ENTRY IDI_SUPSTR(-1, stag, "device")

/// merge_node_info_t entry for node value
#define MNI_ENTRY(tag, flags, name, helper) \
  { name, tag, NDS_MAP_IDX|NDS_EV_RANGE|(flags), helper }

/// merge_node_info_t entry to be used inside functions only
#define MNI_FUNCENTRY(tag, flags, name) \
  MNI_ENTRY(tag, NDS_EV_FUNC|(flags), name, nullptr)

/// merge_node_info_t entry for node with default representation (no helper)
#define MNI_STDENTRY(tag, flags, name) MNI_ENTRY(tag, flags, name, nullptr)
//------------------------------------------------------------------------
idaman void ida_export destroy_moddata_merge_handlers(int data_id);

#ifdef ui_switch_dbctx_guard
  #define switch_dbctx ui_switch_dbctx_guard
#endif

//------------------------------------------------------------------------
/// Get nice name for EA diffpos
/// \param      ea  diffpos
/// \param[out] out nice name
/// \note \see get_nice_colored_name
idaman ssize_t ida_export get_ea_diffpos_name(qstring *out, ea_t ea);
#endif // _MERGE_HPP
