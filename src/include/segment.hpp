/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _SEGMENT_HPP
#define _SEGMENT_HPP

#include <ida.hpp>
#include <range.hpp>            // segments are range of addresses
                                // with characteristics

/*! \file segment.hpp

  \brief Functions that deal with segments.

  IDA requires that all program addresses belong to segments
  (each address must belong to exactly one segment).
  The situation when an address doesn't belong to any segment
  is allowed as a temporary situation only when the user changes program
  segmentation. Bytes outside a segment can't be converted to
  instructions, have names, comments, etc.
  Each segment has its start address, ending address and represents
  a contiguous range of addresses. There might be unused holes between
  segments.

  Each segment has its unique segment selector. This selector is used
  to distinguish the segment from other segments. For 16-bit programs
  the selector is equal to the segment base paragraph. For 32-bit
  programs there is special array to translate the selectors to
  the segment base paragraphs. A selector is a 32/64 bit value.

  The segment base paragraph determines the offsets in the segment.
  If the start address of the segment == (base << 4) then the first
  offset in the segment will be 0. The start address should be
  higher or equal to (base << 4).
  We will call the offsets in the segment 'virtual addresses'.
  So, the virtual address of the first byte of the segment is

          (start address of segment - segment base linear address)

  For IBM PC, the virtual address corresponds to the offset part of the address.
  For other processors (Z80, for example), virtual addresses correspond
  to Z80 addresses and linear addresses are used only internally.
  For MS Windows programs the segment base paragraph is 0 and therefore
  the segment virtual addresses are equal to linear addresses.
*/

/// \defgroup seg Segments
/// \copybrief segment.hpp


/// Maximum number of segment registers is 16 (see segregs.hpp)
#define SREG_NUM 16


//-------------------------------------------------------------------------
//      D E F I N I T O N   O F   S E G M E N T   S T R U C T U R E
//-------------------------------------------------------------------------
/// \defgroup seg_info Segment information (copy-based API)
/// New API that returns copies of segment data using segment start_ea as handle.
/// This API provides better encapsulation than the pointer-based API.
/// \ingroup seg
///@{

/// \defgroup SFL_ Segment flags
/// \ingroup seg_t
/// Used by segment_t::flags
///@{
/// IDP dependent field (IBM PC: if set, ORG directive is not commented out)
#define SFL_COMORG      0x01
/// Orgbase is present? (IDP dependent field)
#define SFL_OBOK        0x02
/// Is the segment hidden?
#define SFL_HIDDEN      0x04
/// Is the segment created for the debugger?
/// Such segments are temporary and do not have permanent flags.
#define SFL_DEBUG       0x08
/// Is the segment created by the loader?
#define SFL_LOADER      0x10
/// Hide segment type (do not print it in the listing)
#define SFL_HIDETYPE    0x20
/// Header segment (do not create offsets to it in the disassembly)
#define SFL_HEADER    0x40
///@}

/// \defgroup SEG_ Segment types
/// \ingroup seg_t
/// Used by segment_t::type
///@{
#define SEG_NORM    0   ///< unknown type, no assumptions
#define SEG_XTRN    1   ///< * segment with 'extern' definitions.
                        ///<   no instructions are allowed
#define SEG_CODE    2   ///< code segment
#define SEG_DATA    3   ///< data segment
#define SEG_IMP     4   ///< java: implementation segment
#define SEG_GRP     6   ///< * group of segments
#define SEG_NULL    7   ///< zero-length segment
#define SEG_UNDF    8   ///< undefined segment type (not used)
#define SEG_BSS     9   ///< uninitialized segment
#define SEG_ABSSYM 10   ///< * segment with definitions of absolute symbols
#define SEG_COMM   11   ///< * segment with communal definitions
#define SEG_IMEM   12   ///< internal processor memory & sfr (8051)
#define SEG_MAX_SEGTYPE_CODE SEG_IMEM ///< maximum value segment type can take
///@}

/// \defgroup SEGPERM_ Segment permissions
/// \ingroup seg_t
/// Used by segment_t::perm
///@{
#define SEGPERM_EXEC  1 ///< Execute
#define SEGPERM_WRITE 2 ///< Write
#define SEGPERM_READ  4 ///< Read
#define SEGPERM_MAXVAL (SEGPERM_EXEC + SEGPERM_WRITE + SEGPERM_READ) ///< Execute + Write + Read
///@}

/// \defgroup sa_ Segment alignment codes
/// \ingroup seg_t
/// Used by segment_t::align
///@{
#define saAbs           0 ///< Absolute segment.
#define saRelByte       1 ///< Relocatable, byte aligned.
#define saRelWord       2 ///< Relocatable, word (2-byte) aligned.
#define saRelPara       3 ///< Relocatable, paragraph (16-byte) aligned.
#define saRelPage       4 ///< Relocatable, aligned on 256-byte boundary
#define saRelDble       5 ///< Relocatable, aligned on a double word (4-byte)
                          ///< boundary.
#define saRel4K         6 ///< This value is used by the PharLap OMF for page (4K)
                          ///< alignment. It is not supported by LINK.
#define saGroup         7 ///< Segment group
#define saRel32Bytes    8 ///< 32 bytes
#define saRel64Bytes    9 ///< 64 bytes
#define saRelQword     10 ///< 8 bytes
#define saRel128Bytes  11 ///< 128 bytes
#define saRel512Bytes  12 ///< 512 bytes
#define saRel1024Bytes 13 ///< 1024 bytes
#define saRel2048Bytes 14 ///< 2048 bytes
#define saRel_MAX_ALIGN_CODE saRel2048Bytes
///@}

/// \defgroup sc_ Segment combination codes
/// \ingroup seg_t
/// Used by segment_t::comb
///@{
#define scPriv     0    ///< Private. Do not combine with any other program
                        ///< segment.
#define scGroup    1    ///< Segment group
#define scPub      2    ///< Public. Combine by appending at an offset that meets
                        ///< the alignment requirement.
#define scPub2     4    ///< As defined by Microsoft, same as C=2 (public).
#define scStack    5    ///< Stack. Combine as for C=2. This combine type forces
                        ///< byte alignment.
#define scCommon   6    ///< Common. Combine by overlay using maximum size.
#define scPub3     7    ///< As defined by Microsoft, same as C=2 (public).
#define sc_MAX_COMB_CODE    scPub3
///@}

#define SEG_MAX_BITNESS_CODE 2 ///< Maximum segment bitness value

/// Macro to declare common segment_info_t related functions
class segment_info_t;
#define DECLARE_SEGMENT_HELPERS(decl)\
decl bool ida_export segment_info_t__visible_name(const segment_info_t *_this, qstring *); \

DECLARE_SEGMENT_HELPERS(idaman)

/// Describes a program segment
/// Call set_segment_info() to apply modifications to the database.
class segment_info_t : public range_t
{
public:
  /// Default constructor - initializes defsr to BADSEL
  segment_info_t() { memset(defsr_, -1, sizeof(defsr_)); }

  /// Is the segment info valid?
  bool is_valid() const { return !empty(); }

  /// Check if a string field was populated by get_segment_info().
  /// \param gsi_flags  combination of \ref GSI_ flags to check
  /// \return true if all specified fields are available
  bool has(int gsi_flags) const { return (filled_ & gsi_flags) == gsi_flags; }

  /// A segment always has a name. If you hadn't specified a name,
  /// the kernel will assign it "seg###" name where ### is segment number.
  /// The new name is validated (see validate_name).
  /// \note Call get_segment_info() with GSI_NAME flag to populate this field.
  const char *get_name() const { return qname_.c_str(); }
  bool visible_name(qstring *out) const { return segment_info_t__visible_name(this, out); }
  void set_name(const char *v) { qname_ = v; updated_ |= SI_NAME; }

  /// Segment class is arbitrary text (max 8 characters)
  /// If segment type is #SEG_NORM and segment class is one of predefined
  /// names, then segment type is changed to:
  ///   - "CODE"  -> #SEG_CODE
  ///   - "DATA"  -> #SEG_DATA
  ///   - "STACK" -> #SEG_BSS
  ///   - "BSS"   -> #SEG_BSS
  ///   - if "UNK" then segment type is reset to #SEG_NORM.
  /// \note Call get_segment_info() with GSI_SCLASS flag to populate this field.
  const char *get_sclass() const { return qsclass_.c_str(); }
  void set_sclass(const char *v) { qsclass_ = v; updated_ |= SI_SCLASS; }

  /// This field is IDP dependent.
  /// you may keep your information about the segment here
  uval_t get_orgbase() const { return orgbase_; }
  void set_orgbase(uval_t v) { orgbase_ = v; updated_ |= SI_ORGBASE; }

  /// Segment alignment \ref sa_
  uchar get_align() const { return align_; }
  void set_align(uchar v) { align_ = v; updated_ |= SI_ALIGN; }

  /// Segment combination \ref sc_
  uchar get_comb() const { return comb_; }
  void set_comb(uchar v) { comb_ = v; updated_ |= SI_COMB; }

  /// Segment permissions \ref SEGPERM_
  uchar get_perm() const { return perm_; }
  void set_perm(uchar v) { perm_ = v; updated_ |= SI_PERM; }

  /// Addressing mode (0=16bit, 1=32bit, 2=64bit)
  uchar get_bitness() const { return bitness_; }
  void set_bitness(uchar v) { bitness_ = v; updated_ |= SI_BITNESS; }

  /// Is a 16-bit segment?
  bool is_16bit() const { return bitness_ == 0; }
  /// Is a 32-bit segment?
  bool is_32bit() const { return bitness_ == 1; }
  /// Is a 64-bit segment?
  bool is_64bit() const { return bitness_ == 2; }
  /// Get number of address bits
  int abits() const { return 1 << (bitness_ + 4); }
  /// Get number of address bytes
  int abytes() const { return abits() / 8; }

  /// Segment flags \ref SFL_
  ushort get_flags() const { return flags_; }
  void set_flags(ushort v) { flags_ = v; updated_ |= SI_FLAGS; }

  /// \name Segment flag: ORG directive
  /// See #SFL_COMORG
  ///@{
  bool comorg() const { return (flags_ & SFL_COMORG) != 0; }
  void set_comorg(bool v=true) { setflag(flags_, SFL_COMORG, v); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: orgbase
  /// See #SFL_OBOK
  ///@{
  bool ob_ok() const { return (flags_ & SFL_OBOK) != 0; }
  void set_ob_ok(bool v=true) { setflag(flags_, SFL_OBOK, v); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: hidden
  /// See #SFL_HIDDEN
  ///@{
  bool is_visible_segm() const { return (flags_ & SFL_HIDDEN) == 0; }
  bool is_finally_visible_segm() const { return (inf_get_cmtflg() & SCF_SHHID_SEGM) != 0 || is_visible_segm(); }
  void set_visible_segm(bool visible=true) { setflag(flags_, SFL_HIDDEN, !visible); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: debugger segment
  /// See #SFL_DEBUG
  ///@{
  bool is_debugger_segm() const { return (flags_ & SFL_DEBUG) != 0; }
  void set_debugger_segm(bool debseg=true) { setflag(flags_, SFL_DEBUG, debseg); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: loader segment
  /// See #SFL_LOADER
  ///@{
  bool is_loader_segm() const { return (flags_ & SFL_LOADER) != 0; }
  void set_loader_segm(bool ldrseg=true) { setflag(flags_, SFL_LOADER, ldrseg); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: hide segment type
  /// See #SFL_HIDETYPE
  ///@{
  bool is_hidden_segtype() const { return (flags_ & SFL_HIDETYPE) != 0; }
  void set_hidden_segtype(bool hide=true) { setflag(flags_, SFL_HIDETYPE, hide); updated_ |= SI_FLAGS; }
  ///@}

  /// \name Segment flag: header segment
  /// See #SFL_HEADER
  ///@{
  bool is_header_segm() const { return (flags_ & SFL_HEADER) != 0; }
  void set_header_segm(bool on=true) { setflag(flags_, SFL_HEADER, on); updated_ |= SI_FLAGS; }
  ///@}

  /// Ephemeral segments are not analyzed automatically
  /// (no flirt, no functions unless required, etc).
  /// Most likely these segments will be destroyed at the end of the
  /// debugging session unless the user changes their status.
  bool is_ephemeral_segm() const
    { return (flags_ & (SFL_DEBUG|SFL_LOADER)) == SFL_DEBUG; }

  /// Segment selector - should be unique.
  /// You can't change this field after creating the segment.
  /// Exception: 16-bit OMF files may have several
  /// segments with the same selector, but this is not
  /// good (no way to denote a segment exactly)
  /// so it should be fixed in the future.
  sel_t get_sel() const { return sel_; }
  void set_sel(sel_t v) { sel_ = v; updated_ |= SI_SEL; }

  /// Get segment base paragraph.
  inline ea_t para() const;

  /// Get segment base linear address.
  ea_t base() const { return to_ea(para(), 0); }

  /// Get default segment register value.
  /// \param sr_idx  segment register index (0..SREG_NUM-1)
  /// \return segment register value, or BADSEL if sr_idx is out of range
  /// \note first element of this array keeps information
  ///       about value of \ph{reg_first_sreg}
  sel_t get_defsr(int sr_idx) const { return (sr_idx >= 0 && sr_idx < SREG_NUM) ? defsr_[sr_idx] : BADSEL; }
  void set_defsr(int sr_idx, sel_t v) { if ( sr_idx >= 0 && sr_idx < SREG_NUM ) { defsr_[sr_idx] = v; updated_ |= si_defsr(sr_idx); } }

  /// Segment type \ref SEG_
  /// The kernel treats different segment types differently.
  /// Segments marked with '*' contain no instructions
  /// or data and are not declared as 'segments' in
  /// the disassembly.
  uchar get_type() const { return type_; }
  void set_type(uchar v) { type_ = v; updated_ |= SI_TYPE; }

  /// The segment color
  bgcolor_t get_color() const { return color_; }
  void set_color(bgcolor_t v) { color_ = v; updated_ |= SI_COLOR; }

  /// Regular segment comment
  /// \note Call get_segment_info() with GSI_CMT_REG flag to populate this field.
  const char *get_cmt_reg() const { return cmt_reg_.c_str(); }
  void set_cmt_reg(const char *v) { cmt_reg_ = v; updated_ |= SI_CMT_REG; }

  /// Repeatable segment comment
  /// \note Call get_segment_info() with GSI_CMT_RPT flag to populate this field.
  const char *get_cmt_rpt() const { return cmt_rpt_.c_str(); }
  void set_cmt_rpt(const char *v) { cmt_rpt_ = v; updated_ |= SI_CMT_RPT; }
  ///@}

private:
  static constexpr int SI_VERSION = 1;

  uint64 updated_ = 0;        ///< bitmask of modified fields (SI_*)
  int filled_ = 0;            ///< bitmask of populated string fields (GSI_*)
  qstring qname_;             ///< segment name
  qstring qsclass_;           ///< segment class
  qstring cmt_reg_;           ///< regular segment comment
  qstring cmt_rpt_;           ///< repeatable segment comment
  uval_t orgbase_ = 0;        ///< IDP dependent field
  uchar align_ = 0;           ///< Segment alignment \ref sa_
  uchar comb_ = 0;            ///< Segment combination \ref sc_
  uchar perm_ = 0;            ///< Segment permissions \ref SEGPERM_
  uchar bitness_ = 0;         ///< Addressing mode (0=16bit, 1=32bit, 2=64bit)
  ushort flags_ = 0;          ///< Segment flags \ref SFL_
  sel_t sel_ = 0;             ///< segment selector
  sel_t defsr_[SREG_NUM];     ///< default segment register values
  uchar type_ = SEG_NORM;     ///< segment type (see \ref SEG_)
  bgcolor_t color_ = DEFCOLOR;///< the segment color
  uchar version_ = SI_VERSION;   ///< version of segment_info_t

  DECLARE_SEGMENT_HELPERS(friend)
  friend struct kdata_t;

  /// \defgroup SI_ Segment info field bitmasks
  /// Used by set_segment_info() to track which fields to update
  ///@{
  enum
  {
    SI_SEL        = 0x00000001,  ///< Update sel field
    SI_ORGBASE    = 0x00000002,  ///< Update orgbase field
    SI_FLAGS      = 0x00000004,  ///< Update flags field
    SI_TYPE       = 0x00000008,  ///< Update type field
    SI_PERM       = 0x00000010,  ///< Update perm field
    SI_BITNESS    = 0x00000020,  ///< Update bitness field
    SI_ALIGN      = 0x00000040,  ///< Update align field
    SI_COMB       = 0x00000080,  ///< Update comb field
    SI_COLOR      = 0x00000100,  ///< Update color field
    SI_NAME       = 0x00000200,  ///< Update name field
    SI_SCLASS     = 0x00000400,  ///< Update sclass field
    SI_CMT_REG    = 0x00000800,  ///< Update regular comment (bit 11)
    SI_CMT_RPT    = 0x00001000,  ///< Update repeatable comment (bit 12)
    SI_DEFSR_FIRST= 0x00002000,  ///< First bit for defsr updates (bit 13)
    SI_ALL_FIELDS = 0x00001FFF,  ///< All non-defsr fields (bits 0-12)
    SI_ALL_DEFSR  = 0x1FFFE000,  ///< All defsr fields (bits 13-28 for regs 0-15)
    SI_ALL        = 0x1FFFFFFF,  ///< Update all modifiable fields
  };
  /// Get the SI_ flag for a specific segment register
  static uint64 si_defsr(int rg) { return SI_DEFSR_FIRST << rg; }
  ///@}
};

///@} seg_info

//-------------------------------------------------------------------------
// INTERNAL
/// \defgroup seg_t Segment structure
/// Definition of ::segment_t and related functions
/// \ingroup seg
///@{

/// Describes a program segment
class segment_t : public range_t
{
public:
  uval_t name = 0;      ///< use get/set_segm_name() functions
  uval_t sclass = 0;    ///< use get/set_segm_class() functions
  uval_t orgbase = 0;   ///< this field is IDP dependent.
                        ///< you may keep your information about
                        ///< the segment here

  uchar align = 0;      ///< \ref sa_
  uchar comb = 0;       ///< \ref sc_
  uchar perm = 0;       ///< \ref SEGPERM_ (0 means no information)
  uchar bitness = 0;    ///< Number of bits in the segment addressing
                        ///<   - 0: 16 bits
                        ///<   - 1: 32 bits
                        ///<   - 2: 64 bits
  /// Is a 16-bit segment?
  bool is_16bit() const { return bitness == 0; }
  /// Is a 32-bit segment?
  bool is_32bit() const { return bitness == 1; }
  /// Is a 64-bit segment?
  bool is_64bit() const { return bitness == 2; }
  /// Get number of address bits
  int  abits() const { return 1<<(bitness+4); }
  /// Get number of address bytes
  int  abytes() const { return abits() / 8; }

/// \defgroup SFL_ Segment flags
/// \ingroup seg_t
/// Used by segment_t::flags

  ushort flags = 0;     ///< \ref SFL_
  /// \name Segment flag: ORG directive
  /// See #SFL_COMORG
  ///@{
  bool comorg() const { return (flags & SFL_COMORG) != 0; }
  void set_comorg() { flags |= SFL_COMORG; }
  void clr_comorg() { flags &= ~SFL_COMORG; }
  ///@}
  /// \name Segment flag: orgbase
  /// See #SFL_OBOK
  ///@{
  bool ob_ok() const { return (flags & SFL_OBOK) != 0; }
  void set_ob_ok() { flags |= SFL_OBOK; }
  void clr_ob_ok() { flags &= ~SFL_OBOK; }
  ///@}
  /// \name Segment flag: hidden
  /// See #SFL_HIDDEN
  ///@{
  bool is_visible_segm() const { return (flags & SFL_HIDDEN) == 0; }
  void set_visible_segm(bool visible) { setflag(flags, SFL_HIDDEN, !visible); }
  ///@}
  /// \name Segment flag: debugger segment
  /// See #SFL_DEBUG
  ///@{
  bool is_debugger_segm() const { return (flags & SFL_DEBUG) != 0; }
  // use ::change_segment_status() to change the segment state during debugging
  void set_debugger_segm(bool debseg) { setflag(flags, SFL_DEBUG, debseg); }
  ///@}
  /// \name Segment flag: loader segment
  /// See #SFL_LOADER
  ///@{
  bool is_loader_segm() const { return (flags & SFL_LOADER) != 0; }
  void set_loader_segm(bool ldrseg) { setflag(flags, SFL_LOADER, ldrseg); }
  ///@}
  /// \name Segment flag: hide segment type
  /// See #SFL_HIDETYPE
  ///@{
  bool is_hidden_segtype() const { return (flags & SFL_HIDETYPE) != 0; }
  void set_hidden_segtype(bool hide) { setflag(flags, SFL_HIDETYPE, hide); }
  ///@}
  /// \name Segment flag: header segment
  /// See #SFL_HEADER
  ///@{
  bool is_header_segm() const { return (flags & SFL_HEADER) != 0; }
  void set_header_segm(bool on) { setflag(flags, SFL_HEADER, on); }
  ///@}

  /// Ephemeral segments are not analyzed automatically
  /// (no flirt, no functions unless required, etc).
  /// Most likely these segments will be destroyed at the end of the
  /// debugging session unless the user changes their status.
  bool is_ephemeral_segm() const
    { return (flags & (SFL_DEBUG|SFL_LOADER)) == SFL_DEBUG; }

  sel_t sel = 0;        ///< segment selector - should be unique. You can't
                        ///< change this field after creating the segment.
                        ///< Exception: 16-bit OMF files may have several
                        ///< segments with the same selector, but this is not
                        ///< good (no way to denote a segment exactly)
                        ///< so it should be fixed in the future.

  sel_t defsr[SREG_NUM];///< default segment register values.
                        ///< first element of this array keeps information
                        ///< about value of \ph{reg_first_sreg}

  uchar type = SEG_NORM;///< segment type (see \ref SEG_).
                        ///< The kernel treats different segment types differently.
                        ///< Segments marked with '*' contain no instructions
                        ///< or data and are not declared as 'segments' in
                        ///< the disassembly.

 bgcolor_t color = DEFCOLOR; ///< the segment color

  /// Update segment information. You must call this function after modification
  /// of segment characteristics. Note that not all fields of segment structure
  /// may be modified directly, there are special functions to modify some fields.
  /// \return success
  inline bool update();

  /// Constructor
  segment_t()
  {
    memset(defsr, -1, sizeof(defsr)); // BADSEL
  }

#ifndef SWIG
  DECLARE_COMPARISONS(segment_t);
#endif
}; // total 192 bytes

#ifdef __EA64__
CASSERT(sizeof(segment_t) == 192);
#endif

/// See #SFL_HIDDEN
inline bool is_visible_segm(segment_t *s) { return s != nullptr && s->is_visible_segm(); }
/// See #SFL_HIDDEN, #SCF_SHHID_SEGM
inline bool is_finally_visible_segm(segment_t *s)
{
  return (inf_get_cmtflg() & SCF_SHHID_SEGM) != 0 || is_visible_segm(s);
}
/// See #SFL_HIDDEN
/// \deprecated Use segment_info_t::set_visible_segm() or set_visible_segment() for safer access.
idaman DEPRECATED void ida_export set_visible_segm(segment_t *s, bool visible);

/// Set segment visibility by address.
/// \param ea       any address within the segment
/// \param visible  true to make visible, false to hide

idaman void ida_export set_visible_segment(ea_t ea, bool visible);


/// Has segment a special type?
/// (#SEG_XTRN, #SEG_GRP, #SEG_ABSSYM, #SEG_COMM)

idaman bool ida_export is_spec_segm(uchar seg_type);


/// Does the address belong to a segment with a special type?
/// (#SEG_XTRN, #SEG_GRP, #SEG_ABSSYM, #SEG_COMM)
/// \param ea  linear address

idaman bool ida_export is_spec_ea(ea_t ea);


/// Lock segment pointer
/// \deprecated Use lock_segment_by_ea() for safer access.
/// Locked pointers are guaranteed to remain valid until they are unlocked.
/// Ranges with locked pointers cannot be deleted or moved.

idaman DEPRECATED void ida_export lock_segm(const segment_t *segm, bool lock);

/// Lock segment by address.
/// Locked segments cannot be deleted or moved.
/// \param ea    any address within the segment
/// \param lock  true to lock, false to unlock

idaman void ida_export lock_segment_by_ea(ea_t ea, bool lock);

/// Helper class to lock a segment pointer so it stays valid
/// \deprecated Use lock_segment_ea instead.
class DEPRECATED lock_segment
{
  ea_t ea = BADADDR;
public:
  lock_segment(const segment_t *segm)
  {
    if ( segm != nullptr )
    {
      ea = segm->start_ea;
      lock_segment_by_ea(ea, true);
    }
  }
  ~lock_segment()
  {
    if ( ea != BADADDR )
      lock_segment_by_ea(ea, false);
  }
};

/// Helper class to lock a segment by address so it stays valid
class lock_segment_ea
{
  ea_t seg_ea;
public:
  lock_segment_ea(ea_t ea) : seg_ea(ea)
  {
    lock_segment_by_ea(seg_ea, true);
  }
  ~lock_segment_ea()
  {
    lock_segment_by_ea(seg_ea, false);
  }
};

/// Is a segment pointer locked?
/// \deprecated Use is_segment_locked() for safer access.
idaman DEPRECATED bool ida_export is_segm_locked(const segment_t *segm);

/// Is segment locked by address?
/// \param ea  any address within the segment
/// \return true if the segment is locked

idaman bool ida_export is_segment_locked(ea_t ea);

///@} seg_t

//-------------------------------------------------------------------------
//      S E G M E N T   S E L E C T O R S
//
/// \defgroup seg_sel Segment selectors
/// \ingroup seg
/// The kernel maintains a table to translate selector values to
/// segment base paragraphs. A Paragraph is a 16byte quantity.
/// This table and translation is necessary because IBM PC uses
/// 16-bit selectors in instructions but segments may reside anywhere
/// in the linear addressing space. For example, if a segment with
/// selector 5 resides at 0x400000, we need to have selector translation
///         5 -> 0x400000.
/// For 16-bit programs the selector translation table is usually empty,
/// selector values are equal to segment base paragraphs.
///@{
//-------------------------------------------------------------------------

/// Get description of selector (0..get_selector_qty()-1)

idaman bool ida_export getn_selector(sel_t *sel, ea_t *base, int n);


/// Get number of defined selectors

idaman size_t ida_export get_selector_qty();


/// Allocate a selector for a segment if necessary.
/// You must call this function before calling add_segm_ex().
/// add_segm() calls this function itself, so you don't need to
/// allocate a selector.
/// This function will allocate a selector if 'segbase' requires more than
/// 16 bits and the current processor is IBM PC.
/// Otherwise it will return the segbase value.
/// \param segbase  a new segment base paragraph
/// \return the allocated selector number

idaman sel_t ida_export setup_selector(ea_t segbase);


/// Allocate a selector for a segment unconditionally.
/// You must call this function before calling add_segm_ex().
/// add_segm() calls this function itself, so you don't need to
/// allocate a selector.
/// This function will allocate a new free selector and setup its mapping
/// using find_free_selector() and set_selector() functions.
/// \param segbase  a new segment base paragraph
/// \return the allocated selector number

idaman sel_t ida_export allocate_selector(ea_t segbase);


/// Find first unused selector.
/// \return a number >= 1

idaman sel_t ida_export find_free_selector();


/// Set mapping of selector to a paragraph.
/// You should call this function _before_ creating a segment
/// which uses the selector, otherwise the creation of the segment will fail.
/// \param selector   number of selector to map
///                     - if selector == #BADSEL, then return 0 (fail)
///                     - if the selector has had a mapping, old mapping is destroyed
///                     - if the selector number is equal to paragraph value, then the mapping is
///                       destroyed because we don't need to keep trivial mappings.
/// \param paragraph  paragraph to map selector
/// \retval 1  ok
/// \retval 0  failure (bad selector or too many mappings)

idaman int ida_export set_selector(sel_t selector, ea_t paragraph);


/// Delete mapping of a selector.
/// Be wary of deleting selectors that are being used in the program, this
/// can make a mess in the segments.
/// \param selector   number of selector to remove from the translation table

idaman void ida_export del_selector(sel_t selector);


/// Get mapping of a selector.
/// \param selector   number of selector to translate
/// \return paragraph the specified selector is mapped to.
///          if there is no mapping, returns 'selector'.

idaman ea_t ida_export sel2para(sel_t selector);


/// Get mapping of a selector as a linear address.
/// \param selector  number of selector to translate to linear address
/// \return linear address the specified selector is mapped to.
///          if there is no mapping, returns to_ea(selector,0);

inline ea_t idaapi sel2ea(sel_t selector)
{
  if ( selector == BADSEL )
    return BADADDR;
  return to_ea(sel2para(selector), 0);
}


/// Find a selector that has mapping to the specified paragraph.
/// \param base  paragraph to search in the translation table
/// \return selector value or base

idaman sel_t ida_export find_selector(ea_t base);


/// Enumerate all selectors from the translation table.
/// This function calls 'func' for each selector in the translation table.
/// If 'func' returns non-zero code, enumeration is stopped and this code
/// is returned.
/// \param func  callback function
///                - sel:  selector number
///                - para: selector mapping
/// \return 0 or code returned by 'func'.

idaman int ida_export enumerate_selectors(int (idaapi *func)(sel_t sel,ea_t para));


/// Enumerate all segments with the specified selector.
/// This function will call the callback function 'func' for each
/// segment that has the specified selector. Enumeration starts
/// from the last segment and stops at the first segment (reverse order).
/// If the callback function 'func' returns a value != #BADADDR, the
/// enumeration is stopped and this value is returned to the caller.
/// \param selector  segments that have this selector are enumerated
/// \param func      callback function
///                    - s:  pointer to segment structure
///                    - ud: user data
/// \param ud        pointer to user data. this pointer will be passed
///                  to the callback function
/// \return #BADADDR or the value returned by the callback function 'func'

idaman ea_t ida_export enumerate_segments_with_selector(
        sel_t selector,
        ea_t (idaapi *func)(segment_t *s, void *ud),
        void *ud=nullptr);


/// Get pointer to segment structure.
/// \deprecated Use get_segment_ea_by_sel() for safer access.
/// This function finds a segment by its selector. If there are several
/// segments with the same selectors, the last one will be returned.
/// \param selector  a segment with the specified selector will be returned
/// \return pointer to segment or nullptr

idaman DEPRECATED segment_t *ida_export get_segm_by_sel(sel_t selector);

/// Get segment start address by its selector.
/// This function finds a segment by its selector. If there are several
/// segments with the same selectors, the last one will be returned.
/// \param selector  selector value to search for
/// \return segment start_ea, or BADADDR if not found

idaman ea_t ida_export get_segment_ea_by_sel(sel_t selector);

///@} seg_sel

//-------------------------------------------------------------------------
//      S E G M E N T   M A N I P U L A T I O N   F U N C T I O N S
//-------------------------------------------------------------------------
/// \defgroup seg_man Segment manipulation functions
/// Add/Delete/Modify segments
/// \ingroup seg
///@{

/// Add a new segment.
/// \deprecated Use add_segment_ex() for safer access without pointer lifetime issues.
/// If a segment already exists at the specified range of addresses,
/// this segment will be truncated. Instructions and data in the old
/// segment will be deleted if the new segment has another addressing
/// mode or another segment base address.
/// \param s       pointer to filled segment structure.
///                segment selector should have proper mapping (see set_selector()).
///                  - if s.start_ea==#BADADDR then s.start_ea <- get_segm_base(&s)
///                  - if s.end_ea==#BADADDR, then a segment up to the next segment
///                    will be created (if the next segment doesn't exist, then
///                    1 byte segment will be created).
///                  - if the s.end_ea < s.start_ea, then fail.
///                  - if s.end_ea is too high and the new segment would overlap
///                    the next segment, s.end_ea is adjusted properly.
/// \param name    name of new segment. may be nullptr.
///                if specified, the segment is immediately renamed
/// \param sclass  class of the segment. may be nullptr.
///                if specified, the segment class is immediately changed
/// \param flags   \ref ADDSEG_
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed
/// The specified default segment register values may be modified by processor
/// modules (see ev_creating_segm). Also, if the default data segment value is
/// BADSEL, it will be changed to the selector of the newly created segment.
/// This ensures that the data segment is always correctly set, which is a good
/// default for most processors.

idaman DEPRECATED bool ida_export add_segm_ex(
        segment_t *NONNULL s,
        const char *name,
        const char *sclass,
        int flags);

/// Add a new segment using segment_info_t.
/// If a segment already exists at the specified range of addresses,
/// this segment will be truncated. Instructions and data in the old
/// segment will be deleted if the new segment has another addressing
/// mode or another segment base address.
/// The segment name and class and comments are taken from the segment_info_t structure.
/// \param si     segment_info_t structure containing segment properties.
///               Required fields: start_ea, end_ea, sel (or use setup_selector()).
///               Optional fields: name, sclass, comments,
///               align, comb, bitness, type, perm, flags, orgbase, defsr, color.
///               segment selector should have proper mapping (see set_selector()).
///                 - if s.start_ea==#BADADDR then s.start_ea <- get_segm_base(&s)
///                 - if s.end_ea==#BADADDR, then a segment up to the next segment
///                   will be created (if the next segment doesn't exist, then
///                   1 byte segment will be created).
///                 - if the s.end_ea < s.start_ea, then fail.
///                 - if s.end_ea is too high and the new segment would overlap
///                   the next segment, s.end_ea is adjusted properly.
/// \param flags  \ref ADDSEG_
/// \retval true  segment was created successfully
/// \retval false failed, a warning message is displayed
/// The specified default segment register values may be modified by processor
/// modules (see ev_creating_segment). Also, if the default data segment value is
/// BADSEL, it will be changed to the selector of the newly created segment.
/// This ensures that the data segment is always correctly set, which is a good
/// default for most processors.

idaman bool ida_export add_segment_ex(segment_info_t *si, int flags);

/// \defgroup ADDSEG_ Add segment flags
/// Passed as 'flags' parameter to add_segm_ex()
///@{
#define ADDSEG_NOSREG     0x0001  ///< set all default segment register values to #BADSEL
                                  ///< (undefine all default segment registers)
#define ADDSEG_OR_DIE     0x0002  ///< qexit() if can't add a segment
#define ADDSEG_NOTRUNC    0x0004  ///< don't truncate the new segment at the beginning of the next segment if they overlap.
                                  ///< destroy/truncate old segments instead.
#define ADDSEG_QUIET      0x0008  ///< silent mode, no "Adding segment..." in the messages window
#define ADDSEG_FILLGAP    0x0010  ///< fill gap between new segment and previous one.
                                  ///< i.e. if such a gap exists, and this gap is less
                                  ///< than 64K, then fill the gap by extending the
                                  ///< previous segment and adding .align directive
                                  ///< to it. This way we avoid gaps between segments.
                                  ///< too many gaps lead to a virtual array failure.
                                  ///< it cannot hold more than ~1000 gaps.
#define ADDSEG_SPARSE     0x0020  ///< use sparse storage method for the new ranges
                                  ///< of the created segment. please note that the
                                  ///< ranges that were already enabled before
                                  ///< creating the segment will not change their
                                  ///< storage type.
#define ADDSEG_NOAA       0x0040  ///< do not mark new segment for auto-analysis
#define ADDSEG_IDBENC     0x0080  ///< 'name' and 'sclass' are given in the IDB encoding;
                                  ///< non-ASCII bytes will be decoded accordingly
#define ADDSEG_KEEP_TYPE  0x0100  ///< do not set segment type according to segment class
///@}


/// Add a new segment, second form.
/// Segment alignment is set to #saRelByte.
/// Segment combination is "public" or "stack" (if segment class is "STACK").
/// Addressing mode of segment is taken as default (16-bit or 32-bit).
/// Default segment registers are set to #BADSEL.
/// If a segment already exists at the specified range of addresses,
/// this segment will be truncated. Instructions and data in the old
/// segment will be deleted if the new segment has another addressing
/// mode or another segment base address.
/// \param para    segment base paragraph.
///                if paragraph can't fit in 16-bit, then a new selector is
///                allocated and mapped to the paragraph.
/// \param start   start address of the segment.
///                if start==#BADADDR then start <- to_ea(para,0).
/// \param end     end address of the segment. end address should be higher than
///                start address. For emulate empty segments, use #SEG_NULL segment
///                type. If the end address is lower than start address, then fail.
///                If end==#BADADDR, then a segment up to the next segment
///                will be created (if the next segment doesn't exist, then
///                1 byte segment will be created).
///                If 'end' is too high and the new segment would overlap
///                the next segment, 'end' is adjusted properly.
/// \param name    name of new segment. may be nullptr
/// \param sclass  class of the segment. may be nullptr.
///                type of the new segment is modified if class is one of
///                predefined names:
///                 - "CODE"  -> #SEG_CODE
///                 - "DATA"  -> #SEG_DATA
///                 - "CONST" -> #SEG_DATA
///                 - "STACK" -> #SEG_BSS
///                 - "BSS"   -> #SEG_BSS
///                 - "XTRN"  -> #SEG_XTRN
///                 - "COMM"  -> #SEG_COMM
///                 - "ABS"   -> #SEG_ABSSYM
/// \param flags   \ref ADDSEG_
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed

idaman bool ida_export add_segm(
        ea_t para,
        ea_t start,
        ea_t end,
        const char *name,
        const char *sclass,
        int flags=0);


/// Delete a segment.
/// \param ea     any address belonging to the segment
/// \param flags  \ref SEGMOD_
/// \retval 1  ok
/// \retval 0  failed, no segment at 'ea'.

idaman bool ida_export del_segm(ea_t ea, int flags);

/// \defgroup SEGMOD_ Segment modification flags
/// Used by functions in \ref seg_man
///@{
#define SEGMOD_KILL    0x0001 ///< disable addresses if segment gets shrinked or deleted
#define SEGMOD_KEEP    0x0002 ///< keep information (code & data, etc)
#define SEGMOD_SILENT  0x0004 ///< be silent
#define SEGMOD_KEEP0   0x0008 ///< flag for internal use, don't set
#define SEGMOD_KEEPSEL 0x0010 ///< do not try to delete unused selector
#define SEGMOD_NOMOVE  0x0020 ///< don't move info from the start of segment to the new start address
                              ///< (for set_segm_start())
#define SEGMOD_SPARSE  0x0040 ///< use sparse storage if extending the segment
                              ///< (for set_segm_start(), set_segm_end())
///@}


/// Get number of segments

idaman int ida_export get_segm_qty();


/// Get pointer to segment by linear address.
/// \deprecated Use get_segment_info() for safer access without pointer lifetime issues.
/// \param ea  linear address belonging to the segment
/// \return nullptr or pointer to segment structure

idaman DEPRECATED segment_t *ida_export getseg(ea_t ea);

/// \defgroup GSI_ Get segment info flags
/// Flags for get_segment_info() to request additional string fields.
/// By default, only fields present in segment_t are filled.
///@{
#define GSI_NAME     0x0001  ///< Fill segment name string
#define GSI_SCLASS   0x0002  ///< Fill segment class string
#define GSI_CMT_REG  0x0004  ///< Fill regular comment string
#define GSI_CMT_RPT  0x0008  ///< Fill repeatable comment string
#define GSI_COMMENTS (GSI_CMT_REG|GSI_CMT_RPT) ///< Fill both comments
#define GSI_ALL      (GSI_NAME|GSI_SCLASS|GSI_COMMENTS) ///< Fill all string fields
#define GSI_UPDATED  0x0100  ///< Mark name and/or class strings as updated
///@}

/// Fill segment_info_t structure for segment at the specified address.
/// By default, only fields present in segment_t are filled.
/// Use GSI_* flags to request additional string fields (name, class, comments).
/// \param out    output structure to fill (can be nullptr)
/// \param ea     linear address belonging to the segment
/// \param flags  combination of \ref GSI_ flags (default: 0)
/// \return true if segment found, false otherwise

idaman bool ida_export get_segment_info(segment_info_t *out, ea_t ea, int flags=0);


/// Apply segment_info_t modifications to the database.
/// Uses start_ea as the segment handle.
/// \param si  segment_info_t with modifications (set via set_* methods)
/// \return true on success, false if segment not found

idaman bool ida_export set_segment_info(segment_info_t *si);


/// Get segment start address.
/// \param ea     linear address belonging to the segment
/// \return segment start_ea, or BADADDR if not found

idaman ea_t ida_export get_segment_ea(ea_t ea);


/// Get pointer to segment by its number.
/// \deprecated Use get_segment_info_by_num() for safer access.
/// \warning Obsoleted because it can slow down the debugger (it has to refresh the whole
/// memory segmentation to calculate the correct answer)
/// \param n  segment number in the range (0..get_segm_qty()-1)
/// \return nullptr or pointer to segment structure

idaman DEPRECATED segment_t *ida_export getnseg(int n);

/// Fill segment_info_t structure for segment by its number.
/// By default, only fields present in segment_t are filled.
/// Use GSI_* flags to request additional string fields (name, class, comments).
/// \param out    output structure to fill (can be nullptr)
/// \param n      segment number (0..get_segm_qty()-1)
/// \param flags  combination of \ref GSI_ flags (default: 0)
/// \return true if segment found, false otherwise

idaman bool ida_export get_segment_info_by_num(segment_info_t *out, int n, int flags=0);


/// Get number of segment by address.
/// \param ea  linear address belonging to the segment
/// \return -1 if no segment occupies the specified address.
///         otherwise returns number of the specified segment (0..get_segm_qty()-1)
idaman int ida_export get_segm_num(ea_t ea);


/// Get pointer to the next segment.
/// \deprecated Use get_next_segment_ea() for safer access.
idaman DEPRECATED segment_t *ida_export get_next_seg(ea_t ea);

/// Get start address of the next segment.
/// \param seg_ea  linear address belonging to the segment
/// \return start_ea of next segment, or BADADDR if no more segments

idaman ea_t ida_export get_next_segment_ea(ea_t seg_ea);


/// Get pointer to the previous segment.
/// \deprecated Use get_prev_segment_ea() for safer access.
idaman DEPRECATED segment_t *ida_export get_prev_seg(ea_t ea);

/// Get start address of the previous segment.
/// \param seg_ea  linear address belonging to the segment
/// \return start_ea of previous segment, or BADADDR if no more segments

idaman ea_t ida_export get_prev_segment_ea(ea_t seg_ea);


/// Get pointer to the first segment.
/// \deprecated Use get_first_segment_ea() for safer access.
idaman DEPRECATED segment_t *ida_export get_first_seg();

/// Get start address of the first segment.
/// The returned address can be used as a handle for other segment_* functions.
/// \return segment start_ea, or BADADDR if no segments exist

idaman ea_t ida_export get_first_segment_ea();


/// Get pointer to the last segment.
/// \deprecated Use get_last_segment_ea() for safer access.
idaman DEPRECATED segment_t *ida_export get_last_seg();

/// Get start address of the last segment.
/// \return segment start_ea, or BADADDR if no segments exist

idaman ea_t ida_export get_last_segment_ea();


/// Get pointer to segment by its name.
/// \deprecated Use get_segment_ea_by_name() for safer access.
/// If there are several segments with the same name, returns the first of them.
/// \param name  segment name. may be nullptr.
/// \return nullptr or pointer to segment structure

idaman DEPRECATED segment_t *ida_export get_segm_by_name(const char *name);

/// Get segment start address by its name.
/// If there are several segments with the same name, returns the first of them.
/// \param name  segment name (may be nullptr)
/// \return segment start_ea, or BADADDR if not found

idaman ea_t ida_export get_segment_ea_by_name(const char *name);

///@} seg_man

//-------------------------------------------------------------------------
/// \defgroup seg_mod Segment modification
/// \ingroup seg
///@{

/// Set segment end address.
/// The next segment is shrinked to allow expansion of the specified segment.
/// The kernel might even delete the next segment if necessary.
/// The kernel will ask the user for a permission to destroy instructions
/// or data going out of segment scope if such instructions exist.
/// \param ea      any address belonging to the segment
/// \param newend  new end address of the segment
/// \param flags   \ref SEGMOD_
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed

idaman bool ida_export set_segm_end(ea_t ea, ea_t newend, int flags);


/// Set segment start address.
/// The previous segment is trimmed to allow expansion of the specified segment.
/// The kernel might even delete the previous segment if necessary.
/// The kernel will ask the user for a permission to destroy instructions
/// or data going out of segment scope if such instructions exist.
/// \param ea        any address belonging to the segment
/// \param newstart  new start address of the segment
///                  note that segment start address should be higher than
///                  segment base linear address.
/// \param flags     \ref SEGMOD_
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed

idaman bool ida_export set_segm_start(ea_t ea, ea_t newstart, int flags);


/// Move segment start.
/// The main difference between this function and set_segm_start() is
/// that this function may expand the previous segment while set_segm_start()
/// never does it. So, this function allows to change bounds of two segments
/// simultaneously. If the previous segment and the specified segment
/// have the same addressing mode and segment base, then instructions
/// and data are not destroyed - they simply move from one segment
/// to another. Otherwise all instructions/data which migrate
/// from one segment to another are destroyed.
/// \note this function never disables addresses.
/// \param ea        any address belonging to the segment
/// \param newstart  new start address of the segment
///                  note that segment start address should be higher than
///                  segment base linear address.
/// \param mode      policy for destroying defined items
///                    -  0: if it is necessary to destroy defined items,
///                          display a dialog box and ask confirmation
///                    -  1: if it is necessary to destroy defined items,
///                          just destroy them without asking the user
///                    - -1: if it is necessary to destroy defined items,
///                          don't destroy them (i.e. function will fail)
///                    - -2: don't destroy defined items (function will succeed)
/// \retval 1  ok
/// \retval 0  failed, a warning message is displayed

idaman bool ida_export move_segm_start(ea_t ea, ea_t newstart, int mode);


/// \defgroup MOVE_SEGM_ Move segment result codes
/// Return values for move_segm() add rebase_program()
///@{
enum move_segm_code_t
{
  MOVE_SEGM_OK          =  0,  ///< all ok
  MOVE_SEGM_PARAM       = -1,  ///< The specified segment does not exist
  MOVE_SEGM_ROOM        = -2,  ///< Not enough free room at the target address
  MOVE_SEGM_IDP         = -3,  ///< IDP module forbids moving the segment
  MOVE_SEGM_CHUNK       = -4,  ///< Too many chunks are defined, can't move
  MOVE_SEGM_LOADER      = -5,  ///< The segment has been moved but the loader complained
  MOVE_SEGM_ODD         = -6,  ///< Cannot move segments by an odd number of bytes
  MOVE_SEGM_ORPHAN      = -7,  ///< Orphan bytes hinder segment movement
  MOVE_SEGM_DEBUG       = -8,  ///< Debugger segments cannot be moved
  MOVE_SEGM_SOURCEFILES = -9,  ///< Source files ranges of addresses hinder segment movement
  MOVE_SEGM_MAPPING     = -10, ///< Memory mapping ranges of addresses hinder segment movement
  MOVE_SEGM_INVAL       = -11, ///< Invalid argument (delta/target does not fit the address space)
};
///@}


/// Return string describing error MOVE_SEGM_... code
idaman const char *ida_export move_segm_strerror(move_segm_code_t code);


/// This function moves all information to the new address.
/// \deprecated Use move_segment() for safer access.
/// It fixes up address sensitive information in the kernel.
/// The total effect is equal to reloading the segment to the target address.
/// For the file format dependent address sensitive information, loader_t::move_segm is called.
/// Also IDB notification event idb_event::segm_moved is called.
/// \param s      segment to move
/// \param to     new segment start address
/// \param flags  \ref MSF_
/// \return       \ref MOVE_SEGM_

idaman DEPRECATED move_segm_code_t ida_export move_segm(segment_t *s, ea_t to, int flags=0);

/// Move segment to a new address.
/// It fixes up address sensitive information in the kernel.
/// The total effect is equal to reloading the segment to the target address.
/// For the file format dependent address sensitive information, loader_t::move_segm is called.
/// Also IDB notification event idb_event::segm_moved is called.
/// \param seg_ea any address within the segment to move
/// \param to     new segment start address
/// \param flags  \ref MSF_
/// \return       \ref MOVE_SEGM_

idaman move_segm_code_t ida_export move_segment(ea_t seg_ea, ea_t to, int flags=0);

/// \defgroup MSF_ Move segment flags
/// Passed as 'flags' parameter to move_segm() and rebase_program()
///@{
#define MSF_SILENT    0x0001    ///< don't display a "please wait" box on the screen
#define MSF_NOFIX     0x0002    ///< don't call the loader to fix relocations
#define MSF_LDKEEP    0x0004    ///< keep the loader in the memory (optimization)
#define MSF_FIXONCE   0x0008    ///< call loader only once with the special calling method.
                                ///< valid for rebase_program(). see loader_t::move_segm.
#define MSF_PRIORITY  0x0020    ///< loader segments will overwrite any existing debugger segments when moved.
                                ///< valid for move_segm()
#define MSF_NETNODES  0x0080    ///< move netnodes instead of changing inf.netdelta (this is slower);
                                ///< valid for rebase_program()
///@}

/// Rebase the whole program by 'delta' bytes.
/// \param delta  number of bytes to move the program
/// \param flags  \ref MSF_
///               it is recommended to use #MSF_FIXONCE so that the loader takes
///               care of global variables it stored in the database
/// \return \ref MOVE_SEGM_

idaman move_segm_code_t ida_export rebase_program(adiff_t delta, int flags);


/// Convert a debugger segment to a regular segment and vice versa.
/// \deprecated Use change_segment_status_by_ea() for safer access.
/// When converting debug->regular, the memory contents will be copied
/// to the database.
/// \param s            segment to modify
/// \param is_deb_segm  new status of the segment
/// \return \ref CSS_

idaman DEPRECATED int ida_export change_segment_status(segment_t *s, bool is_deb_segm);

/// Convert a debugger segment to a regular segment and vice versa by address.
/// When converting debug->regular, the memory contents will be copied
/// to the database.
/// \param ea           any address within the segment
/// \param is_deb_segm  new status of the segment
/// \return \ref CSS_

idaman int ida_export change_segment_status_by_ea(ea_t ea, bool is_deb_segm);

/// \defgroup CSS_ Change segment status result codes
/// Return values for change_segment_status()
///@{
#define CSS_OK       0          ///< ok
#define CSS_NODBG   -1          ///< debugger is not running
#define CSS_NORANGE -2          ///< could not find corresponding memory range
#define CSS_NOMEM   -3          ///< not enough memory (might be because the segment
                                ///< is too big)
#define CSS_BREAK   -4          ///< memory reading process stopped by user
///@}


/// \defgroup SNAP_ Snapshot types
/// Specifies which segments should be included in the snapshot.
/// Used by take_memory_snapshot
///@{
#define SNAP_ALL_SEG        0       ///< Take a snapshot of all segments
#define SNAP_LOAD_SEG       1       ///< Take a snapshot of loader segments
#define SNAP_CUR_SEG        2       ///< Take a snapshot of current segment
///@}

/// Take a memory snapshot of the running process.
/// \param type specifies which snapshot we want (see SNAP_ Snapshot types)
/// \return success

idaman bool ida_export take_memory_snapshot(int type);

/// Is the database a miniidb created by the debugger?
/// \return true if the database contains no segments
/// or only debugger segments

idaman bool ida_export is_miniidb();


/// Internal function
/// \deprecated Use set_segment_base() for safer access.

idaman DEPRECATED bool ida_export set_segm_base(segment_t *s, ea_t newbase);

/// Set segment base.
/// Internal function.
/// \param seg_ea   any address within the segment
/// \param newbase  new base linear address
/// \return success

idaman bool ida_export set_segment_base_ea(ea_t seg_ea, ea_t newbase);

///@} seg_man

//-------------------------------------------------------------------------
//      S E G M E N T   G R O U P S
//-------------------------------------------------------------------------
/// \defgroup seg_grp Segment groups
/// \ingroup seg
///@{


/// Create a new group of segments (used OMF files).
/// \param grp  selector of group segment (segment type is #SEG_GRP)
///             You should create an 'empty' (1 byte) group segment
///             It won't contain anything and will be used to
///             redirect references to the group of segments to the
///             common selector.
/// \param sel  common selector of all segments belonging to the segment
///             You should create all segments within the group with the
///             same selector value.
/// \retval 1   ok
/// \retval 0   too many groups (see #MAX_GROUPS)

idaman int ida_export set_group_selector(sel_t grp, sel_t sel);

#define MAX_GROUPS      8   ///< max number of segment groups


/// Get common selector for a group of segments.
/// \param grpsel  selector of group segment
/// \return common selector of the group or 'grpsel' if no such group is found

idaman sel_t ida_export get_group_selector(sel_t grpsel);

///@} seg_grp

//-------------------------------------------------------------------------
//      S E G M E N T   T R A N S L A T I O N S
///
/// \defgroup seg_trans Segment translations
/// \ingroup seg
///
/// Used to represent overlayed memory banks.
/// Segment translations are used to redirect access to overlayed segments
/// so that the correct overlay is accessed. Each segment has its own
/// translation list. For example, suppose we have
/// four segments:
///   <pre>
///     A               1000-2000
///     B               1000-2000
///       C             2000-3000
///       D             2000-3000
///   </pre>
/// A and B occupy the same virtual addresses. The same with C and D.
/// Segment A works with segment C, segment B works with segment D.
///
/// So all references from A to 2000-3000 should go to C. For this
/// we add translation C for segment A. The same with B,D: add
/// translation D for segment B. Also, we need to specify the correct
/// segment to be accessed from C, thus we add translation A for segment C.
/// And we add translation B for segment D.
///
/// After this, all references to virtual addresses 2000-3000 made from A
/// go to segment C (even if segment A would be large and occupy 1000-3000)
/// So, we need the following translations:
///   <pre>
///     A:      C
///     B:      D
///     C:      A
///     D:      B
///  </pre>
/// With translations, the segments may reside at any linear addresses,
/// all references will pass  through the translation mechanism and go to the
/// correct segment.
///
/// Segment translation works only for code segments (see map_code_ea())
///@{
//-------------------------------------------------------------------------

/// Add segment translation.
/// \param segstart   start address of the segment to add translation to
/// \param mappedseg  start address of the overlayed segment
/// \retval 1  ok
/// \retval 0  too many translations or bad segstart

idaman bool ida_export add_segment_translation(ea_t segstart, ea_t mappedseg);

#define MAX_SEGM_TRANSLATIONS   64      ///< max number of segment translations


/// Set new translation list.
/// \param segstart  start address of the segment to add translation to
/// \param transmap  vector of segment start addresses for the translation list.
///                  If transmap is empty, the translation list is deleted.
/// \retval 1  ok
/// \retval 0  too many translations or bad segstart

idaman bool ida_export set_segment_translations(ea_t segstart, const eavec_t &transmap);


/// Delete the translation list
/// \param segstart  start address of the segment to delete translation list

idaman void ida_export del_segment_translations(ea_t segstart);


/// Get segment translation list.
/// \param transmap  vector of segment start addresses for the translation list
/// \param segstart  start address of the segment to get information about
/// \return  -1 if no translation list or bad segstart.
///          otherwise returns size of translation list.

idaman ssize_t ida_export get_segment_translations(eavec_t *transmap, ea_t segstart);
///@} seg_trans

//-------------------------------------------------------------------------
//      S E G M E N T   C O M M E N T S
//
/// \defgroup seg_cmt Segment comments
/// \ingroup seg
///
/// Segment comments are rarely used yet.
/// The user may define a segment comment by pressing ':'
/// while standing on the segment name at the segment start.
///
/// The main advantage of segment comments compared to anterior
/// lines (see lines.hpp) is that they are attached to a segment,
/// not to an address and they will move with the start of segment
/// if the segment boundaries change.
///
/// You may set segment comments in your LDR module to describe
/// characteristics of a segment in comments.
///
/// Repeatable segment comments are not used at all, because I don't
/// know where they should be repeated.
///@{
//-------------------------------------------------------------------------

/// Get segment comment.
/// \deprecated Use segment_info_t::get_cmt_reg() or segment_info_t::get_cmt_rpt() or get_segment_cmt_by_ea().
/// \param buf         buffer for the comment
/// \param s           pointer to segment structure
/// \param repeatable  0: get regular comment.
///                    1: get repeatable comment.
/// \return size of comment or -1

idaman DEPRECATED ssize_t ida_export get_segment_cmt(qstring *buf, const segment_t *s, bool repeatable);

/// Get segment comment by address.
/// \param buf         buffer for the comment
/// \param ea          any address within the segment
/// \param repeatable  0: get regular comment.
///                    1: get repeatable comment.
/// \return size of comment or -1 if no segment at ea

idaman ssize_t ida_export get_segment_cmt_by_ea(qstring *buf, ea_t ea, bool repeatable);


/// Set segment comment.
/// \deprecated Use segment_info_t::set_cmt_reg() or segment_info_t::set_cmt_rpt() and set_segment_info() or set_segment_cmt_by_ea().
/// \param s           pointer to segment structure
/// \param cmt         comment string, may be multiline (with '\n').
///                    maximal size is 4096 bytes.
///                    Use empty str ("") to delete comment
/// \param repeatable  0: set regular comment.
///                    1: set repeatable comment.
///

idaman DEPRECATED void ida_export set_segment_cmt(const segment_t *s, const char *cmt, bool repeatable);

/// Set segment comment by address.
/// \param ea          any address within the segment
/// \param cmt         comment string, may be multiline (with '\n').
///                    maximal size is 4096 bytes.
///                    Use empty str ("") to delete comment
/// \param repeatable  0: set regular comment.
///                    1: set repeatable comment.

idaman void ida_export set_segment_cmt_by_ea(ea_t ea, const char *cmt, bool repeatable);


/// Generate segment footer line as a comment line.
/// \deprecated Use std_out_segment_footer() for safer access.
/// This function may be used in IDP modules to generate segment footer
/// if the target assembler doesn't have 'ends' directive.

idaman DEPRECATED void ida_export std_out_segm_footer(struct outctx_t &ctx, segment_t *seg);

/// Generate segment footer line as a comment line by address.
/// This function may be used in IDP modules to generate segment footer
/// if the target assembler doesn't have 'ends' directive.
/// \param ctx     output context
/// \param seg_ea  any address within the segment

idaman void ida_export std_out_segment_footer(struct outctx_t &ctx, ea_t seg_ea);

///@} seg_cmt

//-------------------------------------------------------------------------
//      S E G M E N T   N A M E S
//-------------------------------------------------------------------------
/// \defgroup seg_name Segment names
/// \ingroup seg
/// Various ways to retrieve the name of a segment
///@{

/// Rename segment.
/// The new name is validated (see validate_name).
/// A segment always has a name. If you hadn't specified a name,
/// the kernel will assign it "seg###" name where ### is segment number.
/// \deprecated Use segment_info_t::set_name() and set_segment_info() or set_segment_name().
/// \param s       pointer to segment (may be nullptr)
/// \param name    new segment name
/// \param flags   ADDSEG_IDBENC or 0
/// \retval 1  ok, name is good and segment is renamed
/// \retval 0  failure, name is bad or segment is nullptr

idaman DEPRECATED int ida_export set_segm_name(
        segment_t *s,
        const char *name,
        int flags=0);

/// Rename segment by address.
/// The new name is validated (see validate_name).
/// A segment always has a name. If you hadn't specified a name,
/// the kernel will assign it "seg###" name where ### is segment number.
/// \param ea      any address within the segment
/// \param name    new segment name
/// \param flags   ADDSEG_IDBENC or 0
/// \retval 1  ok, name is good and segment is renamed
/// \retval 0  failure, name is bad or no segment at ea

idaman int ida_export set_segment_name(ea_t ea, const char *name, int flags=0);


/// Get true segment name by pointer to segment.
/// \deprecated Use get_segment_info() and segment_info_t::get_name() or get_segment_name().
/// \param buf      output buffer. cannot be nullptr
/// \param s        pointer to segment
/// \param flags    0-return name as is; 1-substitute bad symbols with _
///                 1 corresponds to GN_VISIBLE
/// \return size of segment name (-1 if s==nullptr)

idaman DEPRECATED ssize_t ida_export get_segm_name(qstring *buf, const segment_t *s, int flags=0);

/// Get segment name by address.
/// \param buf      output buffer. cannot be nullptr
/// \param ea       any address within the segment
/// \param flags    0-return name as is; 1-substitute bad symbols with _
///                 1 corresponds to GN_VISIBLE
/// \return size of segment name (-1 if no segment at ea)

idaman ssize_t ida_export get_segment_name(qstring *buf, ea_t ea, int flags=0);


/// Get segment name by pointer to segment.
/// \deprecated Use get_segment_name() with GN_VISIBLE flag.
/// \param buf      output buffer. cannot be nullptr
/// \param s        pointer to segment
/// \return size of segment name (-1 if s==nullptr)

DEPRECATED inline ssize_t idaapi get_visible_segm_name(qstring *buf, const segment_t *s)
{
  return s != nullptr ? get_segment_name(buf, s->start_ea, 1) : -1;
}


/// Get colored segment name expression in the form (segname + displacement).
/// \param buf      output buffer to hold segment expression
/// \param from     linear address of instruction operand or data referring to
///                 the name. This address will be used to get fixup information,
///                 so it should point to exact position of operand in the
///                 instruction.
/// \param sel      value to convert to segment expression
/// \return size of segment expression or -1

ssize_t get_segm_expr(qstring *buf, ea_t from, sel_t sel);

///@} seg_name

//-------------------------------------------------------------------------
//      S E G M E N T   C L A S S E S   A N D   T Y P E S
//-------------------------------------------------------------------------
/// \defgroup seg_type Segment classes and types
/// \ingroup seg
/// See \ref SEG_
///@{

/// Get segment class.
/// Segment class is arbitrary text (max 8 characters).
/// \deprecated Use get_segment_info() and segment_info_t::get_sclass() or get_segment_class().
/// \param buf      output buffer. cannot be nullptr.
/// \param s        pointer to segment
/// \return size of segment class (-1 if s==nullptr or bufsize<=0)

idaman DEPRECATED ssize_t ida_export get_segm_class(qstring *buf, const segment_t *s);

/// Get segment class by address.
/// Segment class is arbitrary text (max 8 characters).
/// \param buf      output buffer. cannot be nullptr.
/// \param ea       any address within the segment
/// \return size of segment class (-1 if no segment at ea)

idaman ssize_t ida_export get_segment_class(qstring *buf, ea_t ea);


/// Set segment class.
/// \deprecated Use segment_info_t::set_sclass() and set_segment_info() or set_segment_class().
/// \param s       pointer to segment (may be nullptr)
/// \param sclass  segment class (may be nullptr).
///                If segment type is #SEG_NORM and segment class is one of predefined
///                names, then segment type is changed to:
///                  - "CODE"  -> #SEG_CODE
///                  - "DATA"  -> #SEG_DATA
///                  - "STACK" -> #SEG_BSS
///                  - "BSS"   -> #SEG_BSS
///                  - if "UNK" then segment type is reset to #SEG_NORM.
/// \param flags   \ref ADDSEG_
/// \retval 1  ok, name is good and segment is renamed
/// \retval 0  failure, name is nullptr or bad or segment is nullptr

idaman DEPRECATED int ida_export set_segm_class(segment_t *s, const char *sclass, int flags=0);

/// Set segment class by address.
/// \param ea      any address within the segment
/// \param sclass  segment class (may be nullptr).
///                If segment type is #SEG_NORM and segment class is one of predefined
///                names, then segment type is changed to:
///                  - "CODE"  -> #SEG_CODE
///                  - "DATA"  -> #SEG_DATA
///                  - "STACK" -> #SEG_BSS
///                  - "BSS"   -> #SEG_BSS
///                  - if "UNK" then segment type is reset to #SEG_NORM.
/// \param flags   \ref ADDSEG_
/// \retval 1  ok, class is good and segment class is changed
/// \retval 0  failure, class is nullptr or bad or no segment at ea

idaman int ida_export set_segment_class(ea_t ea, const char *sclass, int flags=0);


/// Get segment type.
/// \param ea  any linear address within the segment
/// \return \ref SEG_, #SEG_UNDF if no segment found at 'ea'

idaman uchar ida_export segtype(ea_t ea);

///@} seg_type

//-------------------------------------------------------------------------
//      S E G M E N T   A L I G N M E N T   A N D   C O M B I N A T I O N
//-------------------------------------------------------------------------
/// \defgroup seg_align Segment alignment and combination
/// \ingroup seg
///@{

/// Get text representation of segment alignment code.
/// \return text digestable by IBM PC assembler.

idaman const char *ida_export get_segment_alignment(uchar align);


/// Get text representation of segment combination code.
/// \return text digestable by IBM PC assembler.

idaman const char *ida_export get_segment_combination(uchar comb);

///@} seg_align

//-------------------------------------------------------------------------
//      S E G M E N T   A D D R E S S I N G
//-------------------------------------------------------------------------
/// \defgroup seg_addr Segment addressing
/// \ingroup seg
///@{

/// Get segment base paragraph.
/// \deprecated Use segment_info_t::para() or get_segment_para() for safer access.
/// Segment base paragraph may be converted to segment base linear address
/// using to_ea() function.
/// In fact, to_ea(get_segm_para(s), 0) == get_segm_base(s).
/// \param s  pointer to segment
/// \return 0 if s == nullptr,
///          the segment base paragraph

idaman DEPRECATED ea_t ida_export get_segm_para(const segment_t *s);

/// Get segment base paragraph by address.
/// Segment base paragraph may be converted to segment base linear address
/// using to_ea() function.
/// \param ea  any linear address within the segment
/// \return 0 if no segment at ea, otherwise the segment base paragraph

idaman ea_t ida_export get_segment_para(ea_t ea);


/// Get segment base linear address.
/// \deprecated Use segment_info_t::base() or get_segment_base() for safer access.
/// Segment base linear address is used to calculate virtual addresses.
/// The virtual address of the first byte of the segment will be
///      (start address of segment - segment base linear address)
/// \param s  pointer to segment
/// \return 0 if s == nullptr,
///          otherwise segment base linear address

idaman DEPRECATED ea_t ida_export get_segm_base(const segment_t *s);

/// Get segment base linear address by address.
/// Segment base linear address is used to calculate virtual addresses.
/// The virtual address of the first byte of the segment will be
///      (start address of segment - segment base linear address)
/// \param ea  any linear address within the segment
/// \return 0 if no segment at ea, otherwise segment base linear address

idaman ea_t ida_export get_segment_base(ea_t ea);


/// Change segment addressing mode (16, 32, 64 bits).
/// You must use this function to change segment addressing, never change
/// the 'bitness' field directly.
/// This function will delete all instructions, comments and names in the segment
/// \deprecated Use segment_info_t::set_bitness() and set_segment_info() or set_segment_addressing().
/// \param s        pointer to segment
/// \param bitness  new addressing mode of segment
///                   - 2: 64-bit segment
///                   - 1: 32-bit segment
///                   - 0: 16-bit segment
/// \return success

idaman DEPRECATED bool ida_export set_segm_addressing(segment_t *s, size_t bitness);

/// Change segment addressing mode (16, 32, 64 bits) by address.
/// You must use this function to change segment addressing, never change
/// the 'bitness' field directly.
/// This function will delete all instructions, comments and names in the segment
/// \param ea       any address within the segment
/// \param bitness  new addressing mode of segment
///                   - 2: 64-bit segment
///                   - 1: 32-bit segment
///                   - 0: 16-bit segment
/// \return success

idaman bool ida_export set_segment_addressing(ea_t ea, size_t bitness);


/// Check two addresses belong to one segment.
/// \param ea1  linear address
/// \param ea2  linear address
/// \return true if two addresses belong to one segment or
///              they both are not belong to any segment

idaman bool ida_export is_same_segment(ea_t ea1, ea_t ea2);


ea_t segment_info_t::para() const { return sel2para(sel_); }
///@} seg_addr

//-----------------------------------------------------------------------

/// Does the address belong to a debug segment?

inline bool is_debugger_segm(ea_t ea)
{
  segment_info_t si;
  return get_segment_info(&si, ea) && si.is_debugger_segm();
}

/// Does the address belong to an ephemeral segment?

inline bool is_ephemeral_segm(ea_t ea)
{
  segment_info_t si;
  return get_segment_info(&si, ea) && si.is_ephemeral_segm();
}

//-------------------------------------------------------------------------
idaman ea_t ida_export correct_address(ea_t ea, ea_t from, ea_t to, ea_t size, bool skip_check=false);

//-------------------------------------------------------------------------
idaman bool ida_export update_segm(segment_t *s);

inline bool segment_t::update()
{
  return update_segm(this);
}

/// Truncate and sign extend a delta depending on the segment
/// \deprecated Use adjust_segment_diff() for safer access.
idaman DEPRECATED adiff_t ida_export segm_adjust_diff(const segment_t *s, adiff_t delta);

/// Truncate and sign extend a delta depending on the segment by address.
/// \param seg_ea any address within the segment
/// \param delta  delta to adjust
/// \return adjusted delta (0 if no segment at seg_ea)
idaman adiff_t ida_export adjust_segment_diff(ea_t seg_ea, adiff_t delta);

/// Truncate an address depending on the segment
/// \deprecated Use adjust_segment_ea() for safer access.
idaman DEPRECATED ea_t ida_export segm_adjust_ea(const segment_t *s, ea_t ea);

/// Truncate an address depending on the segment by address.
/// \param seg_ea any address within the segment (used to determine bitness)
/// \param ea     address to adjust
/// \return adjusted address (ea if no segment at seg_ea)
idaman ea_t ida_export adjust_segment_ea(ea_t seg_ea, ea_t ea);

#endif // _SEGMENT_HPP
