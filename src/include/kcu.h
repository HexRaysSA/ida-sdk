#pragma once

#include <pro.h>
#include <range.hpp>
#include <loader.hpp>
#include <kcu_minimal.h> // kc_type_t

/*! \file kcu.h

  \brief Apple KernelCache (KC) API

  An Apple kernelcache (a.k.a. KernelCollection) is the XNU kernel plus a
  collection of kernel extensions (KEXTs) packed together into a single
  Mach-O file. Modern caches use the MH_FILESET format, where each KEXT and
  the kernel itself is a self-contained subfile (LC_FILESET_ENTRY); older
  caches embed the KEXTs in __PRELINK_TEXT / __kmod_start sections.

  As with the dyld shared cache (see dscu.h), it rarely makes sense to load
  an entire fileset kernelcache into a single IDA database -- you usually
  care about a few KEXTs. This API lets you enumerate the KEXTs and load
  the ones you need, when you need them.

  # Key concepts

  * KEXT: a kernel extension subfile of the cache (the kernel,
    "com.apple.kernel", is itself one such subfile in a boot KernelCollection)
  * KernelCollection type: boot / system (pageable) / auxiliary -- a cache
    can link against another (e.g. an aux KC links the boot KC), which
    matters when resolving cross-collection symbol references

  # API

  * Use `get_kcu_svc()` to retrieve the API interface,
  * The mach-o loader hands a kernelcache to this plugin, which loads it: by
    default the kernel, with the KEXTs on demand (see kcu.cfg for the modes),
  * Additional KEXTs can be loaded through the API as needed.

*/

//-------------------------------------------------------------------------
struct kcu_svc_t;
struct kcu_ctx_t;

//-------------------------------------------------------------------------
class kcu_req_t
{
  friend kcu_ctx_t;

protected:
  enum code_t
  {
    krc_unknown = 10,
    krc_load_kcache, // loader -> plugin: load this kernelcache (internal)
    krc_get_kcu_svc,
  };

private:
  code_t code = krc_unknown;

protected:
  kcu_req_t(code_t _code)
    : code(_code) {}

  bool _perform()
  {
    return load_and_run_plugin("kcu", size_t(this));
  }
};

//-------------------------------------------------------------------------
/// What the kcu plugin resolved from its configuration (kcu.cfg) for this
/// database. Ask for it alongside the services, when you need to treat a
/// kernelcache the way the plugin does.
struct kcu_config_t
{
  /// how the segments of a kernelcache are named; see kcu.cfg for the syntax
  qstring segname_format;
};
DECLARE_TYPE_AS_MOVABLE(kcu_config_t);

//-------------------------------------------------------------------------
class kcu_svc_req_t : public kcu_req_t
{
  friend kcu_ctx_t;

  kcu_svc_t *ks = nullptr;
  kcu_config_t *cfg = nullptr; // filled if the caller asked for it

public:
  kcu_svc_req_t(kcu_config_t *_cfg=nullptr)
    : kcu_req_t(krc_get_kcu_svc), cfg(_cfg) {}

  kcu_svc_t *perform()
  {
    _perform();
    return ks;
  }
};

//-------------------------------------------------------------------------
/// Retrieve the "kernelcache services".
///
/// The returned instance is shared, and must not be deleted.
/// Returns nullptr if we are not operating on a kernelcache, if the loader
/// did not bootstrap the kcu plugin, or on error.
///
/// \param cfg  if given, also receives the plugin's configuration
/// \return the services instance, or nullptr
inline kcu_svc_t *get_kcu_svc(kcu_config_t *cfg=nullptr)
{
  return kcu_svc_req_t(cfg).perform();
}

//-------------------------------------------------------------------------
/// Kind of a region in the kernelcache address space.
///
/// A fileset kernelcache groups segments into type/permission regions across
/// all subfiles, so a KEXT's segments are scattered; a region is the unit
/// that maps an address back to its owning KEXT.
enum kcu_region_type_t
{
  krt_invalid,       ///< no/invalid region
  krt_header,        ///< the fileset mach header
  krt_kext_header,   ///< a KEXT's mach-o header (kext is set)
  krt_kext_section,  ///< a section belonging to a KEXT (kext is set)
  krt_linkedit,      ///< the collection-wide shared __LINKEDIT (no owning KEXT)
  krt_unknown,       ///< covered but not (yet) identified
};

//-------------------------------------------------------------------------
/// Name of a region type, i.e. its enumerator (e.g. "krt_header").
inline const char *kcu_region_type_name(kcu_region_type_t type)
{
  switch ( type )
  {
    case krt_invalid:      return "krt_invalid";
    case krt_header:       return "krt_header";
    case krt_kext_header:  return "krt_kext_header";
    case krt_kext_section: return "krt_kext_section";
    case krt_linkedit:     return "krt_linkedit";
    case krt_unknown:      return "krt_unknown";
  }
  return "?";
}

//-------------------------------------------------------------------------
/// A KEXT across the collection set: top nibble = the collection's kind
/// (kc_type_t), low 28 bits = KEXT index within that collection.
struct kext_coords_t
{
  static constexpr uint32 KC_SHIFT = 28;             ///< where the collection nibble sits
  static constexpr uint32 INDEX_MASK = 0x0FFFFFFF;   ///< what is left for the index
  /// a real collection never fills the nibble, so 0xF marks "no KEXT": that
  /// is how BADKEXT (all ones) reads, and what ::kc_none packs down to
  static constexpr uint32 KC_NONE = 0xF;

  uint32 packed = 0xFFFFFFFF; ///< both coordinates as one value (BADKEXT = all ones)

  kext_coords_t() {}
  /// \param kc  the collection; ::kc_none yields an invalid coordinate
  /// \param i   KEXT index within it
  kext_coords_t(kc_type_t kc, uint32 i) { set(kc, i); }

  /// the collection this KEXT belongs to, or ::kc_none if the coordinate
  /// names none
  kc_type_t get_kc() const
  {
    const uint32 nibble = packed >> KC_SHIFT;
    return nibble == KC_NONE ? kc_none : kc_type_t(nibble);
  }
  /// KEXT index within its collection
  uint32 get_index() const { return packed & INDEX_MASK; }
  /// set both coordinates at once
  void set(kc_type_t kc, uint32 i)
  {
    packed = (uint32(kc) << KC_SHIFT) | (i & INDEX_MASK);
  }

  bool is_valid() const { return get_kc() != kc_none; }
  bool operator==(const kext_coords_t &r) const { return packed == r.packed; }
  bool operator!=(const kext_coords_t &r) const { return packed != r.packed; }
};
CASSERT(sizeof(kext_coords_t) == 4);
DECLARE_TYPE_AS_MOVABLE(kext_coords_t);
typedef qvector<kext_coords_t> kext_coords_vec_t;

#define BADKEXT kext_coords_t()

//-------------------------------------------------------------------------
/// A contiguous range in the kernelcache with a type and (for KEXT
/// sections) the owning KEXT (cf. dscu region_info_t).
struct kcu_region_info_t
{
  ea_t start = BADADDR;                  ///< start address
  asize_t size = 0;                      ///< size in bytes
  kcu_region_type_t type = krt_invalid;  ///< region kind
  kext_coords_t kext;                    ///< owning KEXT, or BADKEXT
  qstring segname;                       ///< Mach-O segment, empty if none
  qstring sectname;                      ///< Mach-O section, empty if none

  void swap(kcu_region_info_t &r)
  {
    qswap(start, r.start);
    qswap(size, r.size);
    qswap(type, r.type);
    qswap(kext, r.kext);
    segname.swap(r.segname);
    sectname.swap(r.sectname);
  }

  range_t get_range() const { return range_t(start, start + size); }

  bool operator==(const kcu_region_info_t &r) const
  {
    return start == r.start
        && size == r.size
        && type == r.type
        && kext == r.kext
        && segname == r.segname
        && sectname == r.sectname;
  }
  bool operator!=(const kcu_region_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(kcu_region_info_t);
typedef qvector<kcu_region_info_t> kcu_region_info_vec_t;

//-------------------------------------------------------------------------
/// A KernelCollection linked from this one (e.g. a system KC's boot KC).
struct kcu_linked_kc_info_t
{
  kc_type_t kc = kc_boot;  ///< which collection this is
  bool loaded = false;     ///< is it mapped into the database?
  ea_t base = BADADDR;     ///< its lowest mapped address, or BADADDR
  bytevec_t uuid;          ///< LC_UUID, as the linking collection records it
  qstring path;            ///< where it was found on disk, if it was

  bool operator==(const kcu_linked_kc_info_t &r) const
  {
    return kc == r.kc
        && loaded == r.loaded
        && base == r.base
        && uuid == r.uuid
        && path == r.path;
  }
  bool operator!=(const kcu_linked_kc_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(kcu_linked_kc_info_t);
typedef qvector<kcu_linked_kc_info_t> kcu_linked_kc_info_vec_t;

//-------------------------------------------------------------------------
/// A location holding a pointer into a linked KC that is not (yet) mapped.
struct kcu_extref_t
{
  ea_t ea = BADADDR;      ///< where the pointer is
  kc_type_t kc = kc_boot; ///< the collection the pointer targets
  uint64 offset = 0;         ///< target offset within that collection

  bool operator==(const kcu_extref_t &r) const
  {
    return ea == r.ea && kc == r.kc && offset == r.offset;
  }
  bool operator!=(const kcu_extref_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(kcu_extref_t);
typedef qvector<kcu_extref_t> kcu_extref_vec_t;

//-------------------------------------------------------------------------
/// The kernelcache services interface.
struct kcu_svc_t
{
  virtual ~kcu_svc_t() {}

  /// \name Collections
  //@{

  /// number of collections in the region map: the loaded cache, plus any
  /// harvested linked collection
  virtual size_t get_kcs_count() const = 0;

  /// the type of the collection containing the given address, or kc_none
  /// if the address belongs to no known region
  virtual kc_type_t get_kc_by_ea(ea_t ea) const = 0;

  /// number of KEXTs in the given collection
  virtual size_t get_kc_kexts_count(kc_type_t kc) const = 0;

  /// names of the KEXTs (bundle ids) in the given collection, indexed by the
  /// low 28 bits of a kext_coords_t for that collection
  virtual void get_kc_kexts_names(qstrvec_t *out, kc_type_t kc) const = 0;

  //@}

  /// \name KEXTs
  /// Methods accepting a \p kext return early (false, 0, an empty vector,
  /// ...) when the coordinate names no KEXT of this cache, so a caller that
  /// passes the result of get_kext_coords() need not check it first.
  /// Each of them has a convenience overload taking a bundle id, which does
  /// that lookup itself.
  //@{

  /// identifier of the KEXT with the given bundle id, or BADKEXT.
  /// Searches every mounted KC file (bundle ids are unique across the set).
  virtual kext_coords_t get_kext_coords(const char *name) const = 0;

  /// bundle id of the given KEXT
  virtual bool get_kext_name(qstring *out, kext_coords_t kext) const = 0;

  /// regions belonging to the given KEXT: its sections, plus its header
  /// (cf. dscu's get_image_regions).
  /// \param[out] out   receives the region infos
  /// \param      kext  the KEXT to describe
  /// \param      full  when false, the region names are not populated (cheaper)
  virtual bool get_kext_regions(kcu_region_info_vec_t *out, kext_coords_t kext, bool full=true) const = 0;
  inline bool get_kext_regions(kcu_region_info_vec_t *out, const char *kext_name, bool full=true) const { return get_kext_regions(out, get_kext_coords(kext_name), full); }

  /// indexes of the regions belonging to the given KEXT (cf. dscu's
  /// get_image_regions_indexes). Cheaper than get_kext_regions() when only
  /// the indexes are needed; feed them to get_regions().
  virtual bool get_kext_region_indexes(sizevec_t *out, kext_coords_t kext) const = 0;
  inline bool get_kext_region_indexes(sizevec_t *out, const char *kext_name) const { return get_kext_region_indexes(out, get_kext_coords(kext_name)); }

  /// total mapped size of a KEXT = the sum of its (scattered) regions
  /// (cf. dscu's get_image_total_size).
  virtual asize_t get_kext_total_size(kext_coords_t kext) const = 0;
  inline asize_t get_kext_total_size(const char *kext_name) const { return get_kext_total_size(get_kext_coords(kext_name)); }

  /// identifier of the KEXT covering the given address, or BADKEXT
  virtual kext_coords_t get_kext_by_ea(ea_t ea) const = 0;

  //@}

  /// \name Regions
  //@{

  /// total number of regions in the layout
  virtual size_t get_regions_count() const = 0;

  /// the region at the given index.
  /// \param[out] out           receives the region info
  /// \param      region_index  0..get_regions_count()-1
  /// \param      full          when false, the region name is not populated
  ///                           (cheaper)
  virtual bool get_region(kcu_region_info_t *out, size_t region_index, bool full=true) const = 0;

  /// the region covering the given address (false if none).
  /// \param[out] out               receives the region info
  /// \param      ea                effective address to look up
  /// \param[out] out_region_index  if not nullptr, receives the region index
  /// \param      full              see #get_region()
  virtual bool get_region_by_ea(
        kcu_region_info_t *out,
        ea_t ea,
        size_t *out_region_index=nullptr,
        bool full=true) const = 0;

  /// retrieve a batch of regions.
  /// \param[out] vout            receives the region infos
  /// \param      region_indexes  if nullptr, all regions are returned;
  ///                             otherwise only the specified ones
  /// \param      full            see #get_region()
  virtual void get_regions(
        kcu_region_info_vec_t *vout,
        const sizevec_t *region_indexes=nullptr,
        bool full=true) const = 0;

  //@}

  /// \name Loading
  //@{

  /// load the given KEXTs into the database, then reconstruct once over the
  /// whole set.
  /// \param kexts  the KEXTs to load
  /// \param flags  reserved, pass 0
  virtual bool load_kexts(const kext_coords_vec_t &kexts, uint32 flags=0) = 0;

  /// load a single KEXT into the database
  /// \param kext   the KEXT to load
  /// \param flags  reserved, pass 0
  bool load_kext(kext_coords_t kext, uint32 flags=0)
  {
    kext_coords_vec_t v;
    v.push_back(kext);
    return load_kexts(v, flags);
  }
  inline bool load_kext(const char *kext_name, uint32 flags=0) { return load_kext(get_kext_coords(kext_name), flags); }

  /// is the given KEXT mapped into the database?
  virtual bool is_kext_loaded(kext_coords_t kext) const = 0;
  inline bool is_kext_loaded(const char *kext_name) const { return is_kext_loaded(get_kext_coords(kext_name)); }

  /// map the collection-wide shared __LINKEDIT region into the database
  /// (a single owner-less region, cf. krt_linkedit). Returns true if it is
  /// (or is now) mapped.
  virtual bool load_linkedit() = 0;

  /// Return the number of KEXTs load_kexts() has mapped successfully,
  /// including the on-demand loads navigation triggers
  /// (cf. dscu's get_load_regions_requests_count).
  virtual int get_load_kexts_requests_count() const = 0;

  //@}

  /// \name Linked collections
  //@{

  /// the KernelCollections linked from this one (boot/system). Empty if this
  /// cache is self-contained.
  virtual void get_linked_kcs(kcu_linked_kc_info_vec_t *vout) const = 0;

  /// total number of recorded external references (cross-KC pointers into a
  /// linked KC that is not yet mapped).
  virtual size_t get_extrefs_count() const = 0;

  /// if \p ea holds a cross-KC pointer, report which linked KC it targets and
  /// the target offset within it. Returns false if \p ea is not an extref.
  virtual bool get_extref(kcu_extref_t *out, ea_t ea) const = 0;

  /// all recorded external references.
  virtual void get_extrefs(kcu_extref_vec_t *vout) const = 0;

  //@}

  /// \name Misc
  //@{

  /// dump the cache layout to the output window (for diagnostics)
  /// \param flags  reserved, pass 0
  virtual void dump_layout(uint32 flags=0) const = 0;

  //@}
};
