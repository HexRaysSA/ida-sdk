#pragma once

#include <string_view>

#include <pro.h>
#include <range.hpp>
#include <loader.hpp>

/*! \file dscu.h

  \brief Apple Dyld Shared Cache (DSC) API

  A DSC:

  * is essentially, a large collection of `dylib` files (AKA _images_),
    packed together in an Apple-custom format
  * those are used to limit the amount of overhead at program launch-time,
    by having a lot of the relocations/resolutions heavylifting already
    addressed
  * in addition to _images_, the DSC-producing tooling creates specific
    regions whose purpose is to "link" the various images together.
    Those regions are known as "branch mappings" (older caches used
    "branch islands".)
  * occasionally, you will also find some GOT's (and possibly
    "unknown regions") in the address space of a DSC
  * DSC's can grow very large in size, and will then be split
    into multiple _files_ (e.g., iPhone 16 DSC's have north of 80 files)

  All-in-all a DSC is an unusual beast, in the sense that hardly makes
  sense to load it all in an IDA database: you would end up with a
  a set of mostly-unrelated libraries.

  Instead, an iterative approach is preferable: load whatever part
  of the DSC you need, when you need it.

  This API provides exactly that.

  # Key concepts/entities

  * images: the `dylib` files, packed in the DSC
  * unknown regions: portions of the address space that ARE covered
        by the DSC's mappings, but are not referred to by any of the
        known entities. The address space is not missing -- it's our
        understanding of the content that has a gap.
  * branch islands/branch mappings: stubs, that help stitch
        together calls between images
  * files: the file(s) that compose the DSC. When a DSC is composed
        of multiple files, the one that is used as the entrypoint,
        is called the "toplevel" file.

  # Secondary concepts/entities

  * file mappings: (to not be confused with branch mappings!) internal,
        high-level representation of "portions" of a file. Typically
        files have somewhere between 1...5 mappings
  * `region_info_t`: a "range": either a section of an image, or a branch
        mapping, GOT, unknown region... Typically, an image will have dozens of
        regions. See below for more info

  # API

  Keeping the above concepts in mind, navigating the API should
  be pretty straightforward: it's kept simple on-purpose.

  A couple notes:

  * Use `get_dscu_svc()` to retrieve the API interface,
  * Initially, the DSC loader will only load the DSC header,
  * Additional images/regions can be loaded through the API,
    as needed.

*/


//-------------------------------------------------------------------------
struct dscu_svc_t;
struct dscu_ctx_t;

//-------------------------------------------------------------------------
class dscu_req_t
{
  friend dscu_ctx_t;

protected:
  enum code_t
  {
    drc_unknown = 10,
    drc_create_layout,
    drc_get_dscu_svc,

#ifdef TESTABLE_BUILD
    drc_load_cancellation_req = 100,
#endif
  };

private:
  code_t code = drc_unknown;

protected:
  dscu_req_t(code_t _code)
    : code(_code) {}

  bool _perform()
  {
    return load_and_run_plugin("dscu", size_t(this));
  }
};

//-------------------------------------------------------------------------
class dscu_create_layout_req_t : public dscu_req_t
{
  friend dscu_ctx_t;

  bytevec_t uuid;
  qstring path;
  int image_index = -1;

public:
  dscu_create_layout_req_t(
          const bytevec_t &_uuid,
          const qstring &_path,
          int _image_index)
    : dscu_req_t(drc_create_layout)
  {
    uuid = _uuid;
    path = _path;
    image_index = _image_index;
  }

  bool perform()
  {
    return _perform();
  }
};

//-------------------------------------------------------------------------
class dscu_svc_req_t : public dscu_req_t
{
  friend dscu_ctx_t;

  dscu_svc_t *ds = nullptr;

public:
  dscu_svc_req_t()
    : dscu_req_t(drc_get_dscu_svc) {}

  dscu_svc_t *perform()
  {
    _perform();
    return ds;
  }
};

//-------------------------------------------------------------------------
/// Retrieve the "shared cache services".
///
/// The returned instance is shared, and must not be deleted.
/// Furthermore, the following situations will cause this
/// function to return a `nullptr`:
///
/// * we are currently not operating on a shared cache
/// * `dscu_bootstrap` wasn't called (by the loader)
/// * an error occurs
///
/// \return the services instance, or nullptr
inline dscu_svc_t *get_dscu_svc()
{
  return dscu_svc_req_t().perform();
};

//-------------------------------------------------------------------------
/// Available region types. See the region_info_t documentation for more info.
enum region_type_t : uint32
{
  rt_invalid = uint32(-1), ///< Invalid
  rt_image_entity = 0,   ///< A subset of an image (segment, section, ...)
  rt_island = 1,         ///< A branch island
  rt_header = 2,         ///< The dyld header
  rt_mapping = 3,        ///< A subcache branch mapping
  rt_unknown = 4,        ///< A covered cache region whose content we don't (yet) identify
  rt_got = 5,            ///< A Global Offset Table
  rt_cache_data = 6,     ///< Cache-wide named data (e.g. a linkedit subcache mapping)
};

//-------------------------------------------------------------------------
/// An "intermediate" partioning of file(s) participating in the DSC
struct mapping_coords_t
{
  int16 file_index;    /// the toplevel/subcache to which `mapping_index` applies. `0` means toplevel file
  int16 mapping_index; /// the mapping # inside that file

  bool operator==(const mapping_coords_t &r) const
  {
    return file_index == r.file_index
        && mapping_index == r.mapping_index;
  }
  bool operator!=(const mapping_coords_t &r) const
  {
    return !(*this == r);
  }

  inline bool valid() const { return file_index >= 0 && mapping_index >= 0; }

  static mapping_coords_t make_invalid()
  {
    mapping_coords_t c;
    c.file_index = int16(-1);
    c.mapping_index = int16(-1);
    return c;
  }
};
CASSERT(sizeof(mapping_coords_t) == sizeof(int));
DECLARE_TYPE_AS_MOVABLE(mapping_coords_t);
typedef qvector<mapping_coords_t> mapping_coords_vec_t;

//-----------------------------------------------------------------------------
/// Address ranges that can be loaded into the database.
///
/// Regions have the following properties:
///
/// * regions that don't belong to an image (i.e., islands, mappings,
///   unknown regions, GOTs), can be loaded individually
/// * regions belonging to an image, can _not_ be loaded individually: they have/
///   relationships with one another, and loading them individually would prevent
///   the right scaffolding/plumbing to be put into place
/// * regions belonging to an image, have contiguous _indexes_. However,
/// * regions belonging to an image, do *not* need to have contiguous address ranges.
/// * in fact, they can even be spread across the entire cache's address range
/// * (that is why retrieving the "range" of an image, makes no sense: even though
///   its _image_ in the DSC file is contiguous, its individual segments/sections
///   can go anywhere. Thus, we operate at a `rt_image_entity`-level, and there's
///   no `rt_image`.)
struct region_info_t
{
  ea_t start = BADADDR;            /// Coordinates in address space
  asize_t size = 0;                /// Size in bytes

  region_type_t type = rt_invalid; /// Region type

  /// image number or branch island number
  union
  {
    int image_index = -1;          /// for `rt_image`
    int branch_island_number;      /// for `rt_island`
  };

  char name[40] = { 0 };           /// region name (e.g., `__text`). Not unique


  void swap(region_info_t &r)
  {
    qswap(start, r.start);
    qswap(size, r.size);
    qswap(type, r.type);
    qswap(image_index, r.image_index);
    qswap(name, r.name);
  }

  range_t get_range() const { return range_t(start, start+size); }

  bool operator==(const region_info_t &r) const
  {
    return start == r.start
        && size == r.size
        && type == r.type
        && image_index == r.image_index
        && streq(name, r.name);
  }
  bool operator!=(const region_info_t &r) const { return !(*this == r); }
};
CASSERT(sizeof(region_info_t) == 64);
DECLARE_TYPE_AS_MOVABLE(region_info_t);
typedef qvector<region_info_t> region_info_vec_t;

//-------------------------------------------------------------------------
/// Resolution of a single address into the cache layout: the region
/// it lives in, the mapping that backs it, and the offset within that
/// mapping's on-disk file.
struct address_info_t
{
  region_info_t region;                                            ///< Region containing the address (type=rt_invalid if not found)
  mapping_coords_t mapping = mapping_coords_t::make_invalid();     ///< Mapping that backs the address
  uint64 file_offset = 0;                                          ///< Offset within the on-disk file backing #mapping

  bool valid() const { return mapping.valid(); }
};
DECLARE_TYPE_AS_MOVABLE(address_info_t);

//-------------------------------------------------------------------------
typedef std::set<int> dyldlib_set_t;

//-------------------------------------------------------------------------
/// A load request, offering the ability to be populated from
/// previously-retrieved `region_info_t`, and that will be treated
/// atomically.
struct dscu_load_request_t
{
  intvec_t images;                ///< image indexes
  intvec_t islands;               ///< branch island numbers
  eavec_t mappings;               ///< branch mappings
  eavec_t gots;                   ///< global offset table ranges
  eavec_t unknown_regions;        ///< unknown-region ranges (covered, but unidentified)
  eavec_t cache_data;             ///< cache-wide data ranges (e.g. linkedit subcache mappings)

#define DLRF_UNDO_ON_FAILURE   0x1                          ///< failure to satisfy any part of the request, will revert everything
#define DLRF_CREATE_UNDO_POINT (0x2 | DLRF_UNDO_ON_FAILURE) ///< should the request create a new undo point (or rely on the last created one and undo to that.)
#define DLRF_SILENT            0x4                          ///< don't emit `loader_finished` notification
#define DLRF_ASK_CONFIRMATION  0x8                          ///< ask the user's confirmation before performing the load
#define DLRF_DEFAULT           (DLRF_CREATE_UNDO_POINT)     ///< default set of flags for DSC load requests

  uint32 flags = 0;

  dscu_load_request_t(uint32 _flags=DLRF_DEFAULT) : flags(_flags) {}

  void add_region(const region_info_t &ri)
  {
    switch ( ri.type )
    {
      case rt_image_entity:
        // Regions belonging to images, need to cause a full image load
        images.add_unique(ri.image_index);
        break;

      case rt_island:
        islands.add_unique(ri.branch_island_number);
        break;

      case rt_mapping:
        mappings.add_unique(ri.start);
        break;

      case rt_header:
        // ?
        break;

      case rt_got:
        gots.add_unique(ri.start);
        break;

      case rt_unknown:
        unknown_regions.add_unique(ri.start);
        break;

      case rt_cache_data:
        cache_data.add_unique(ri.start);
        break;

      default:
        TB_INTERR_OR_RETURN(0);
    }
  }

  void add_regions(const region_info_vec_t &ris)
  {
    for ( const auto &ri : ris )
      add_region(ri);
  }

  void clear()
  {
    images.clear();
    islands.clear();
    mappings.clear();
    gots.clear();
    unknown_regions.clear();
    cache_data.clear();
    flags = DLRF_DEFAULT;
  }

  bool empty() const
  {
    return images.empty()
        && islands.empty()
        && mappings.empty()
        && gots.empty()
        && unknown_regions.empty()
        && cache_data.empty();
  }
};

//-------------------------------------------------------------------------
/// A symbol match produced by dscu_svc_t::find_symbol() / query_symbols().
struct symbol_match_t
{
  std::string_view symbol;  ///< Matching symbol name; the view is valid for the lifetime of the dscu_svc_t.
  ea_t ea = BADADDR;        ///< Address of the symbol.
  int image_index = -1;     ///< Owning image index, or -1 if the symbol came from the cache's local symbol table (.symbols).

  bool operator==(const symbol_match_t &r) const
  {
    return ea == r.ea && image_index == r.image_index && symbol == r.symbol;
  }
  bool operator!=(const symbol_match_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(symbol_match_t);
typedef qvector<symbol_match_t> symbol_match_vec_t;

//-------------------------------------------------------------------------
/// A string-literal match produced by dscu_svc_t::find_string().
struct string_match_t
{
  ea_t ea = BADADDR;        ///< Mapped address; BADADDR for non-image hits
  int image_index = -1;     ///< Owning image index, or -1 if the hit
                            ///< came from a non-image blob (.symbols,
                            ///< branch mappings, other adjacent files).
  size_t file_index = 0;    ///< When image_index == -1: the file the hit
                            ///< lives in (see get_file_name()).
  uint64 file_offset = 0;   ///< Offset within that file (when image_index == -1)
  qstring context;          ///< Bytes around the match, for display

  bool operator==(const string_match_t &r) const
  {
    return ea == r.ea
        && image_index == r.image_index
        && file_index == r.file_index
        && file_offset == r.file_offset
        && context == r.context;
  }
  bool operator!=(const string_match_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(string_match_t);
typedef qvector<string_match_t> string_match_vec_t;

//-------------------------------------------------------------------------
class shared_cache_toplevel_file_t;

//-------------------------------------------------------------------------
/// Report on one "load command" entry found in an external file
struct dependency_match_entry_t
{
  qstring image_name;                    ///< The image name
  int image_index = -1;                  ///< The image index in this DSC (-1 if not found)
  uint32 load_command_type = uint32(-1); ///< Load command type. One of ACH_LC_*

  bool operator==(const dependency_match_entry_t &r) const
  {
    return image_name == r.image_name
        && image_index == r.image_index
        && load_command_type == r.load_command_type;
  }
  bool operator!=(const dependency_match_entry_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(dependency_match_entry_t);
typedef qvector<dependency_match_entry_t> dependency_match_entry_vec_t;

//-------------------------------------------------------------------------
/// The result of a dscu_svc_t::match_dependencies operation.
struct dependency_match_result_t : public dependency_match_entry_vec_t
{
};

//-------------------------------------------------------------------------
/// IDA's DSC API interface
///
/// Use get_dscu_svc() to retrieve an implementation.
struct dscu_svc_t
{
  virtual ~dscu_svc_t() {}

  /// Return the parsed toplevel shared cache file.
  virtual std::shared_ptr<shared_cache_toplevel_file_t> get_toplevel() const = 0;

  /// Retrieve the path to the dyld_shared_cache file on disk.
  /// \param[out] out  receives the path
  /// \return true on success
  virtual bool get_input_file_path(qstring *out) const = 0;

  /// Return the cumulative ASLR slide applied to the cache.
  virtual adiff_t get_dyld_slide() const = 0;

  /// Apply an additional slide delta and reload the cache.
  /// \param delta  slide increment (added to the current slide)
  virtual void update_dyld_slide(adiff_t delta) = 0;

  /// \name Files (toplevel + subcaches)
  //@{

  /// Retrieve the names of all cache files (toplevel + subcaches).
  /// \param[out] out  receives the file names
  virtual void get_files_names(qstrvec_t *out) const = 0;

  /// Get the on-disk file name for the given file index.
  /// \param[out] out         receives the file name
  /// \param      file_index  index into the files list
  /// \return true on success
  virtual bool get_file_name(qstring *out, size_t file_index) const = 0;

  /// Look up a file index by name.
  /// \param file_name  on-disk file name
  /// \return the file index, or size_t(-1) on failure
  virtual size_t get_file_index(const char *file_name) const = 0;

  /// Return all mapping coordinates for the given cache file.
  /// \param[out] out        receives the mapping coordinates
  /// \param      file_name  on-disk file name
  /// \return true on success
  virtual bool get_file_mappings(mapping_coords_vec_t *out, const char *file_name) const = 0;

  //@}

  /// \name Mappings
  //@{

  /// Return the address range covered by a mapping.
  /// \param[out] out      receives the range
  /// \param      mapping  mapping coordinates (file_index, mapping_index)
  /// \return true on success
  virtual bool get_mapping_range(range_t *out, mapping_coords_t mapping) const = 0;

  /// Resolve \p ea into the cache layout: the region it lives in,
  /// the mapping that backs it, and the offset within that mapping's
  /// on-disk file.
  /// \param ea  effective address to look up
  /// \return the resolved info; #address_info_t::valid() is false
  ///         when \p ea isn't backed by any mapping.
  virtual address_info_t locate_address(ea_t ea) const = 0;

  //@}

  /// \name Regions
  //@{

  /// Retrieve region info by index.
  /// \param[out] ri            receives the region info
  /// \param      region_index  index into the global region list
  /// \param      full          when false, only lightweight fields
  ///                           (start, size, type, image_index) are filled
  /// \return true on success
  virtual bool get_region(region_info_t *ri, size_t region_index, bool full=true) const = 0;

  /// Find the region containing \p ea, optionally returning its index.
  /// \param[out] ri                receives the region info
  /// \param      ea                effective address to look up
  /// \param[out] out_region_index  if not nullptr, receives the region index
  /// \param      full              see #get_region()
  /// \return true on success
  virtual bool get_region_by_ea(
        region_info_t *ri,
        ea_t ea,
        size_t *out_region_index=nullptr,
        bool full=true) const = 0;

  /// Retrieve a batch of regions.
  /// \param[out] vout            receives the region infos
  /// \param      region_indexes  if nullptr, all regions are returned;
  ///                             otherwise only the specified ones
  /// \param      full            see #get_region()
  virtual void get_regions(
        region_info_vec_t *vout,
        const sizevec_t *region_indexes=nullptr,
        bool full=true) const = 0;

  //@}

  /// \name Images
  /// Methods accepting \p image_index return early (false, #BADADDR,
  /// make_invalid(), ...) when the index is < 0, so callers that pass
  /// the result of get_image_index() don't need to check it themselves.
  /// Each virtual has a convenience inline overload taking a
  /// \p image_name that does the lookup automatically.
  //@{

  /// Return the number of images in the cache.
  virtual int get_images_count() const = 0;

  /// Retrieve the full paths of all images in the cache.
  /// \param[out] out  receives the image names
  virtual void get_images_names(qstrvec_t *out) const = 0;

  /// Look up an image index by full path.
  /// \param image_name  full image path (e.g., "/usr/lib/libSystem.B.dylib")
  /// \return the image index, or -1 on failure
  virtual int get_image_index(const char *image_name) const = 0;

  /// Retrieve the full path of an image.
  /// \param[out] out          receives the image path
  /// \param      image_index  image index
  /// \return true on success
  virtual bool get_image_name(qstring *out, int image_index) const = 0;

  /// Like get_image_name(), but returns only the filename component
  /// (everything after the last '/').
  /// \param[out] out          receives the filename
  /// \param      image_index  image index
  /// \return true on success
  bool get_image_filename(qstring *out, int image_index) const
  {
    bool ok = get_image_name(out, image_index);
    if ( ok )
    {
      const size_t pos = out->rfind('/');
      ok = pos != qstring::npos;
      if ( ok )
      {
        qstring tmp(out->c_str() + pos + 1, out->length() - pos - 1);
        out->swap(tmp);
      }
    }
    return ok;
  }

  /// Return the mapping coordinates for an image.
  /// \param image_index  image index
  /// \return the mapping coordinates, or make_invalid() if not found
  virtual mapping_coords_t get_image_mapping(int image_index) const = 0;
  inline mapping_coords_t get_image_mapping(const char *image_name) const { return get_image_mapping(get_image_index(image_name)); }

  /// Check whether an image has been loaded into the database.
  /// \param image_index  image index
  virtual bool is_image_loaded(int image_index) const = 0;
  inline bool is_image_loaded(const char *image_name) const { return is_image_loaded(get_image_index(image_name)); }

  /// Return the on-disk cache file name that contains the image.
  /// \param[out] out          receives the file name
  /// \param      image_index  image index
  /// \return true on success
  virtual bool get_image_file_name(qstring *out, int image_index) const = 0;
  inline bool get_image_file_name(qstring *out, const char *image_name) const { return get_image_file_name(out, get_image_index(image_name)); }

  /// Retrieve all regions belonging to an image.
  /// \param[out] out          receives the region infos
  /// \param      image_index  image index
  /// \param      full         see #get_region()
  /// \return true on success
  virtual bool get_image_regions(region_info_vec_t *out, int image_index, bool full=true) const = 0;
  inline bool get_image_regions(region_info_vec_t *out, const char *image_name, bool full=true) const { return get_image_regions(out, get_image_index(image_name), full); }

  /// Retrieve the region indexes (into the global region list) for an image.
  /// \param[out] out          receives the region indexes
  /// \param      image_index  image index
  /// \return true on success
  virtual bool get_image_regions_indexes(sizevec_t *out, int image_index) const = 0;
  inline bool get_image_regions_indexes(sizevec_t *out, const char *image_name) const { return get_image_regions_indexes(out, get_image_index(image_name)); }

  /// Collect transitive dependencies of an image.
  /// The image itself is included in the output.
  /// \param[out] out          receives the dependent image indexes
  /// \param      image_index  image index
  /// \param      depth        recursion depth: 1 = direct only, -1 = unlimited
  /// \return true on success
  virtual bool get_image_dependencies(intvec_t *out, int image_index, int depth=1) const = 0;
  inline bool get_image_dependencies(intvec_t *out, const char *image_name, int depth=1) const { return get_image_dependencies(out, get_image_index(image_name), depth); }

  /// Return the start address of the image's Mach-O header in the cache.
  /// \param image_index  image index
  /// \return the address, or #BADADDR on failure
  virtual ea_t get_image_address(int image_index) const = 0;

  /// Return the total size of all regions that compose this image.
  /// \param image_index  image index
  /// \return the total size in bytes, or 0 on failure
  virtual uint64 get_image_total_size(int image_index) const = 0;
  inline uint64 get_image_total_size(const char *image_name) const { return get_image_total_size(get_image_index(image_name)); }

  /// Return the file index of the cache file that contains the image.
  /// \param image_index  image index
  /// \return the file index, or size_t(-1) on failure
  virtual size_t get_image_file_index(int image_index) const = 0;
  inline size_t get_image_file_index(const char *image_name) const { return get_image_file_index(get_image_index(image_name)); }

  /// Like get_image_dependencies(), but for multiple images at once.
  /// \param[out] out              receives the union of all dependencies
  /// \param      images_indexes   image indexes to query
  /// \param      depth            recursion depth: 1 = direct only, -1 = unlimited
  /// \return true on success
  virtual bool get_images_dependencies(intvec_t *out, const intvec_t &images_indexes, int depth=1) const = 0;

  //@}

  /// \name Islands
  //@{

  /// Check whether a branch island has been loaded into the database.
  /// \param island_index  island index
  virtual bool is_island_loaded(int island_index) const = 0;

  //@}

  /// \name Loading
  //@{

  /// Load a Mach-O image from the shared cache into the database.
  /// Creates segments, applies fixups, imports symbols, and triggers
  /// auto-analysis on the loaded ranges.
  /// \param image_index  image index (silently ignored if < 0)
  /// \param flags a combination of DLRF_ flags
  /// \return success
  virtual bool load_image(int image_index, uint32 flags=DLRF_DEFAULT) = 0;

  /// Load a branch island from the shared cache into the database.
  /// \param island_index  island index (silently ignored if < 0)
  /// \param flags a combination of DLRF_ flags
  /// \return success
  virtual bool load_island(int island_index, uint32 flags=DLRF_DEFAULT) = 0;

  /// Load a branch mapping (__stubs) region into the database.
  /// \param ea  start address of the mapping region
  /// \param flags a combination of DLRF_ flags
  /// \return success
  virtual bool load_branch_mapping(ea_t ea, uint32 flags=DLRF_DEFAULT) = 0;

  /// Check whether a branch mapping has been loaded.
  /// \param mapping_addr  start address of the mapping region
  virtual bool is_mapping_loaded(ea_t mapping_addr) const = 0;

  /// Load a GOT region into the database.
  /// Reads bytes from the cache file, creates a segment, untags
  /// pointers, and symbolicates entries from the export tables.
  /// \param ea  start address of the GOT region
  /// \param flags a combination of DLRF_ flags
  /// \return success
  virtual bool load_got(ea_t ea, uint32 flags=DLRF_DEFAULT) = 0;

  /// Check whether a GOT region has been loaded.
  /// \param got_addr  start address of the GOT region
  virtual bool is_got_loaded(ea_t got_addr) const = 0;

  /// Load an unknown region (a covered-but-unidentified range of a mapping)
  /// into the database. Reads bytes from the cache file, creates a segment,
  /// and untags pointers if the region is non-executable.
  /// \param ea  start address of the unknown region
  /// \param flags a combination of DLRF_ flags
  /// \return success
  virtual bool load_unknown_region(ea_t ea, uint32 flags=DLRF_DEFAULT) = 0;

  /// Check whether an unknown region has been loaded.
  /// \param ea  start address of the unknown region
  virtual bool is_unknown_region_loaded(ea_t ea) const = 0;

  /// Load a cache-wide data region (e.g. a `.dyldlinkedit` subcache
  /// mapping) into the database. Reads bytes from the cache file and
  /// creates a segment covering the whole region.
  /// \param ea     start address of the cache_data region
  /// \param flags  a combination of DLRF_ flags
  /// \return success
  virtual bool load_cache_data(ea_t ea, uint32 flags=DLRF_DEFAULT) = 0;

  /// Check whether a cache-wide data region has been loaded.
  /// \param cache_data_addr  start address of the region
  virtual bool is_cache_data_loaded(ea_t cache_data_addr) const = 0;

  /// Load all regions described by the request (images, islands,
  /// mappings, GOTs, unknown_regions, cache_data) in a single batch.
  /// \param regions  the load request
  /// \return true on success
  virtual bool load_regions(const dscu_load_request_t &regions) = 0;

  /// Return the number of times load_regions() has been invoked
  /// successfully.
  virtual int get_load_regions_requests_count() const = 0;

  //@}

  /// \name Misc
  //@{

  /// Return the type of the region at \p region_index.
  /// \param region_index  index into the global region list
  /// \return the region type, or #rt_invalid on failure
  virtual region_type_t get_region_type(size_t region_index) const = 0;

  /// Find symbols from the cache's local symbol table that fall
  /// within \p range.
  /// \param[out] out    receives the matches. `image_index` is always
  ///                    -1 since this call only queries the cache's
  ///                    local (.symbols) table.
  /// \param      range  address range to query
  /// \return true if at least one symbol was found
  virtual bool query_symbols(
        symbol_match_vec_t *out,
        const range_t &range) const = 0;

  /// Look up a single address in the local symbol table.
  /// \param ea  effective address
  /// \return the symbol name, or empty view if not found.
  ///         the returned view is valid for the lifetime of this dscu_svc_t.
  virtual std::string_view query_symbol(ea_t ea) const = 0;

  /// Look up an address in the per-image export tables.
  /// Exports are loaded lazily on first access for each image.
  /// \param ea  effective address
  /// \return the exported symbol name, or empty view if not found.
  ///         the returned view is valid for the lifetime of this dscu_svc_t.
  virtual std::string_view query_exported_symbol(ea_t ea) const = 0;

  /*! \defgroup fsf Find symbol flags
  */
  ///@{
#define FSF_LOADED_IMAGES_ONLY 0x1 ///< Skip export tables of images that have not been loaded yet
#define FSF_CASE_INSENSITIVE   0x2 ///< Match \p needle case-insensitively
  //@}

  /// Find all symbols whose name contains \p needle, searching the
  /// cache's local symbol table and each image's export table.
  /// Matching is a plain substring match, case-sensitive by default
  /// (see \ref FSF_CASE_INSENSITIVE).
  /// \param[out] out        receives (symbol, ea, image_index) matches.
  ///                        image_index is -1 when the match comes from
  ///                        the cache's local symbol table (.symbols).
  /// \param      needle     substring to match (must be non-empty)
  /// \param      flags      combination of FSF_* bits
  /// \param      max_count  stop accumulating once this many matches
  ///                        have been collected; default is unlimited
  /// \return true if at least one symbol was found
  virtual bool find_symbol(
        symbol_match_vec_t *out,
        const char *needle,
        uint32 flags=0,
        size_t max_count=size_t(-1)) const = 0;

  /*! \defgroup fssf Find string flags
  */
  ///@{
#define FSSF_SCOPE_IMAGES               0x00 ///< Limit scanning to images
#define FSSF_SCOPE_FILES                0x01 ///< Scan entire files
#define FSSF_SCOPE_MASK                 0x01 ///< Scope mask

#define FSSF_IMAGES_SCOPE_DATA_SECTIONS 0x00 ///< When `FSSF_SCOPE_IMAGES`, limit scanning to data sections
#define FSSF_IMAGES_SCOPE_ALL           0x02 ///< When `FSSF_SCOPE_IMAGES`, scan all sections
#define FSSF_IMAGES_SCOPE_MASK          0x02 ///< Images scope mask

#define FSSF_FILES_INCLUDE_SYMBOLS      0x04 ///< When scanning files, include the .symbols pool
#define FSSF_FILES_INCLUDE_BRANCH_MAPPINGS 0x08 ///< When scanning files, include branch mapping files
#define FSSF_FILES_INCLUDE_OTHER        0x10 ///< When scanning files, include other adjacent files

#define FSSF_CASE_INSENSITIVE           0x20 ///< Match \p needle case-insensitively
  //@}

  /// Find all occurrences of \p needle in the cache's byte content.
  /// Matching is a plain substring match against UTF-8 bytes.
  /// \param[out] out        receives (ea, image_index, file_index, file_offset, context) matches
  /// \param      needle     substring to match (must be non-empty)
  /// \param      flags      combination of FSSF_* bits
  /// \param      max_count  stop scanning once this many matches have
  ///                        been collected; default is unlimited
  /// \return true if at least one match was found
  virtual bool find_string(
        string_match_vec_t *out,
        const char *needle,
        uint32 flags=0,
        size_t max_count=size_t(-1)) const = 0;

  /// Whether this cache has a `.symbols` sidecar file.
  virtual bool has_local_symbols() const = 0;

  enum depmatch_code_t
  {
    dmc_ok = 0,            ///< Match succeeded
    dmc_bad_file,          ///< File either not present or not a Mach-O file
    dmc_cpu_mismatch,      ///< CPU architecture doesn't match the shared cache's (see MDF_ALLOW_CPU_MISMATCH)
    dmc_platform_mismatch, ///< Platform doesn't match the shared cache's (see MDF_ALLOW_PLATFORM_MISMATCH)
    dmc_failed,            ///< Failed to satisfy the request, for misc. reasons
  };

  /*! \defgroup mdf Match dependencies flags
  */
  ///@{
#define MDF_ALLOW_CPU_MISMATCH      0x1 ///< Perform match operation despite the CPU architecture of the external file & the DSC not matching
#define MDF_ALLOW_PLATFORM_MISMATCH 0x2 ///< Perform match operation despite the platform of the external file & the DSC not matching
  //@}

  /// Parse the Mach-O file's load commands, and match
  /// the image dependencies to this DSC.
  ///
  /// \param[out] out result of the match operation
  /// \param path Mach-O file path
  /// \param flags combination of MDF_* bits
  /// \return result code
  virtual depmatch_code_t match_dependencies(
        dependency_match_result_t *out,
        const char *path,
        uint32 flags=0) const = 0;

  /*! \defgroup dlf Dump flags
  */
  ///@{
#define DLF_VALIDATE             (1 << 0)                    ///< Perform validation of persisted layout information
#define DLF_VALIDATE_HARD        (DLF_VALIDATE | (1 << 1))   ///< Do a lot more validating (time-consuming)
#define DLF_TOPLEVEL_INPUT_PATH  (1 << 2)                    ///< Dump the DSC's (toplevel) input path
#define DLF_TOPLEVEL_DETAILS     (1 << 3)                    ///< Dump some additional details about the toplevel file
#define DLF_TOPLEVEL             (DLF_TOPLEVEL_INPUT_PATH | DLF_TOPLEVEL_DETAILS) ///< Alias
#define DLF_FILES                (1 << 4)                    ///< Dump information about files composing this DSC
#define DLF_MAPPINGS             (1 << 5)                    ///< Dump information about high-level mappings described in files composing this DSC
#define DLF_IMAGES               (1 << 6)                    ///< Dump information about images (i.e., libraries) found in this DSC
#define DLF_IMAGES_DEPENDENCIES  (DLF_IMAGES | (1 << 7))     ///< Dump information about each image's dependencies
#define DLF_IMAGES_REGIONS       (DLF_IMAGES | (1 << 8))     ///< Dump information about each image's known regions
#define DLF_ISLANDS              (1 << 9)                    ///< Dump information about branch islands
#define DLF_ISLANDS_REGIONS      (DLF_ISLANDS | (1 << 10))   ///< Dump information about each branch island's known regions
#define DLF_GOTS                 (1 << 11)                   ///< Dump information about known GOT's in this DSC
#define DLF_UNKNOWN_REGIONS      (1 << 12)                   ///< Dump information about the unknown (covered but unidentified) regions of this DSC
#define DLF_CACHE_DATA           (1 << 13)                   ///< Dump information about known cache-wide data regions

#define DLF_ALL 0xFFFFFFFF
  //@}

  /// Dump the full cache layout to the output window.
  /// Use #DLF_VALIDATE flags to also run consistency checks.
  ///
  /// \param flags combination of DLF_* bits
  virtual void dump_layout(uint32 flags=DLF_ALL) const = 0;

};

