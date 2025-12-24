
#ifndef LUMINA_HPP
#define LUMINA_HPP

#include <pro.h>
#include <md5.h>
#include <network.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>


enum pattern_type_t
{
  PAT_TYPE_UNKNOWN = 0,
  PAT_TYPE_MD5,
};

enum lumina_op_res_t
{
  PDRES_BADPTN = -3,
  PDRES_NOT_FOUND = -2,
  PDRES_ERROR = -1,
  PDRES_OK = 0,
  PDRES_ADDED,
};

/// \defgroup PMF_ flags for the push_md operation
///@{
/// Conflict resolution mode
#define PMF_PUSH_MODE_MASK 0xF
#define PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT 0x0
#define PMF_PUSH_OVERRIDE                        0x1
#define PMF_PUSH_DO_NOT_OVERRIDE                 0x2
#define PMF_PUSH_MERGE                           0x3
///@}

enum user_op_t
{
  UOT_ADD = 0,
  UOT_EDIT,
  UOT_DEL,
};

enum generic_sort_type_t
{
  GST_NONE = 0,
  GST_NAME,
};

enum dump_md_sort_type_t
{
  DMD_SORT_NONE = 0,
  DMD_SORT_HASH,
};

/// \defgroup UF_ bits for the lumina_users_t::features
///@{
#define UF_IS_ADMIN        0x1
#define UF_CAN_DEL_HISTORY 0x2
///@}

/// \defgroup URF_ bits for the show_users_result packet
///@{
#define URF_IGNORE_LICID 0x1
///@}


#define BOPF_DETAILS             0x2
#define BOPF_CHRONOLOGICAL_ORDER 0x4
#define BOPF_LAST_FUNC_RECORD    0x8
#define BOPF_FIELD_LICENSE_NAME      0x001000
#define BOPF_FIELD_LICENSE_EMAIL     0x002000
#define BOPF_FIELD_LICENSE_ID        0x004000
#define BOPF_SHOW_FIELD_INPUT_HASH   0x010000
#define BOPF_SHOW_FIELD_INPUT_PATH   0x020000
#define BOPF_SHOW_FIELD_IDB_PATH     0x040000
#define BOPF_SHOW_FIELD_CALCREL_HASH 0x080000
#define BOPF_SHOW_FIELD_FUNC_EA      0x100000
#define BOPF_SHOW_FIELD_FUNC_ID      0x200000
#define BOPF_SHOW_FIELD_USERNAME     0x400000
#define BOPF_SHOW_FIELD_ALL (BOPF_SHOW_FIELD_INPUT_HASH|BOPF_SHOW_FIELD_INPUT_PATH|BOPF_SHOW_FIELD_IDB_PATH|BOPF_SHOW_FIELD_CALCREL_HASH|BOPF_SHOW_FIELD_FUNC_EA|BOPF_SHOW_FIELD_FUNC_ID|BOPF_SHOW_FIELD_USERNAME|BOPF_FIELD_LICENSE_NAME|BOPF_FIELD_LICENSE_EMAIL|BOPF_FIELD_LICENSE_ID)
#define BOPF_PUSHES_FIELD_ALL (BOPF_FIELD_LICENSE_NAME|BOPF_FIELD_LICENSE_EMAIL|BOPF_FIELD_LICENSE_ID)

#define STF_DETAILS 0x1

#define DEFAULT_TLM_FLUSH_TIMEOUT (60 * 1000)
#define DEFAULT_TLM_FLUSH_EVCNT 64

#define LUMINA_GET_POP_DEFAULT_NRESULTS 10

//-------------------------------------------------------------------------
enum well_known_fail_code_t
{
  WKFC_INTERRUPTED = 0xDEADBEEF
};

//-------------------------------------------------------------------------
enum mdkey_t
{
  MDK_NONE         =  0,
  MDK_TYPE         =  1, // type_source + type [ + '\0' + fields ]
  MDK_VD_ELAPSED   =  2, // how long it took to decompile (int64 seconds)
  MDK_FCMT         =  3, // function comment
  MDK_FRPTCMT      =  4, // function repeatable comment
  MDK_CMTS         =  5, // instruction regular comments
  MDK_RPTCMTS      =  6, // instruction repeatable comments
  MDK_EXTRACMTS    =  7, // anterior/posterior comments
  MDK_USER_STKPNTS =  8, // user-defined stackpoints
  MDK_FRAME_DESC   =  9, // frame description + stack variables
  MDK_OPS          = 10, // operand representation
  MDK_OPS_EX       = 11, // extended operand representation

  MDK_LAST,
};

const char *mdkey2str(mdkey_t key);
mdkey_t str2mdkey(const char *str);

//-------------------------------------------------------------------------
#ifdef __EA64__
typedef ea_t ea64_t;
#else
typedef uint64 ea64_t;
#endif


//-------------------------------------------------------------------------
enum mdkey_format_t
{
  MDKF_NONE = 0,
  MDKF_STR,
  MDKF_TYPE,
  MDKF_INT64,
  MDKF_UINT64,
  MDKF_DCSTRLIST,  // list of: [fchunk+]delta+zero-terminated-string
  MDKF_DSVALLIST,  // list of: [fchunk+]delta+sval
  MDKF_FRAME_DESC,
  MDKF_NLSTRLIST,  // list of: \n-separated-string
  MDKF_DOPSLIST,   // list of: [fchunk+]delta+opnum+oprepr
};

mdkey_format_t get_mdkey_preferred_format(mdkey_t key);

//-------------------------------------------------------------------------
struct insn_site_t
{
  uint32 fchunk_nr = -1;
  uint32 fchunk_off = -1;
  ea_t toea(const func_t *pfn) const
  {
    QASSERT(1777, pfn != nullptr);
    const range_t *r = fchunk_nr == 0             ? pfn
                     : fchunk_nr-1 < pfn->tailqty ? &pfn->tails[fchunk_nr-1]
                     :                              nullptr;
    return r != nullptr && fchunk_off < r->size()
         ? r->start_ea + fchunk_off
         : BADADDR;
  }
};

//-------------------------------------------------------------------------
struct insn_cmt_t : public insn_site_t
{
  qstring cmt;
};
DECLARE_TYPE_AS_MOVABLE(insn_cmt_t);
typedef qvector<insn_cmt_t> insn_cmts_t;

//-------------------------------------------------------------------------
struct user_stkpnt_t : public insn_site_t
{
  int64 delta = 0;
};
DECLARE_TYPE_AS_MOVABLE(user_stkpnt_t);
typedef qvector<user_stkpnt_t> user_stkpnts_t;

//-------------------------------------------------------------------------
struct extra_cmt_t : public insn_site_t
{
  // Both in 'prev' and 'next', possible multiple comments are joined together using '\n'
  qstring prev;
  qstring next;
};
DECLARE_TYPE_AS_MOVABLE(extra_cmt_t);
typedef qvector<extra_cmt_t> extra_cmts_t;

//-------------------------------------------------------------------------
// Used to store flags + possible minimal opinfo_t
// representation for operands & frame members.
struct oprepr_t
{
  oprepr_t() { memset(this, 0, sizeof(*this)); }

  flags64_t flags;
  opinfo_t opinfo;
};

//-------------------------------------------------------------------------
struct insn_ops_repr_t : public insn_site_t
{
  insn_ops_repr_t() { memset(this, 0, sizeof(*this)); }

  flags64_t flags;
  opinfo_t ops[8];
};
DECLARE_TYPE_AS_MOVABLE(insn_ops_repr_t);
typedef qvector<insn_ops_repr_t> insn_ops_reprs_t;

//-------------------------------------------------------------------------
// Metadata is very versatile. It is stored as a sequence of
// [key][len][bytes], [key][len][bytes], [...]
class metadata_t : public bytevec_t
{
public:
  metadata_t(const void *buf=nullptr, size_t sz=0) { if ( buf != nullptr ) append(buf, sz); }

  void add(mdkey_t key, const void *buf, size_t bufsize);
  void add(mdkey_t key, const bytevec_t &buf) { add(key, buf.begin(), buf.size()); }
  void add_str(mdkey_t key, const qstring &value) { add(key, value.c_str(), value.length()); }
  void add_uint64(mdkey_t key, uint64 value);
  void add_insn_cmts(const insn_cmts_t &insn_cmts, bool repeatable);
  void add_extra_cmts(const extra_cmts_t &extra_cmts);
  void add_stkpnts(const user_stkpnts_t &stkpnts);
  void add_insn_opreprs(const insn_ops_reprs_t &opreprs);

  const uchar *find(mdkey_t key, const uchar **pend=nullptr) const;
};

//-------------------------------------------------------------------------
class metadata_creator_t
{
  metadata_t &md;
public:
  metadata_creator_t(metadata_t *_md) : md(*_md) {}

  virtual void add(mdkey_t key, const void *buf, size_t bufsize);
  virtual void add_uint64(mdkey_t key, uint64 value);
  virtual const uchar *find(mdkey_t key, const uchar **pend=nullptr) const;

  void add_str(mdkey_t key, const qstring &value) { add(key, value.c_str(), value.length()); }
};

//-------------------------------------------------------------------------
class metadata_iterator_t
{
  const metadata_t &md;
  const uchar *ptr;
  const uchar *end;
public:
  const uchar *data = nullptr;
  size_t size = 0;
  mdkey_t key = MDK_NONE;

  metadata_iterator_t(const metadata_t &_md)
    : md(_md), ptr(md.begin()), end(md.end())
  {
  }
  bool next(void)
  {
    key = mdkey_t(unpack_dd(&ptr, end));
    if ( key == MDK_NONE )
      return false;
    data = (uchar *)unpack_buf_inplace(&ptr, end);
    if ( data == nullptr )
      return false;
    size = ptr - data;
    return true;
  }
  const uchar *data_end() const { return ptr; } // valid after next()
};

//-------------------------------------------------------------------------
inline const uchar *metadata_t::find(mdkey_t key, const uchar **pend) const
{
  metadata_iterator_t p(*this);
  while ( p.next() )
  {
    if ( p.key == key )
    {
      if ( pend != nullptr )
        *pend = p.data_end();
      return p.data;
    }
  }
  return nullptr;
}

//-------------------------------------------------------------------------
typedef void idaapi metadata_appender_t(metadata_creator_t &mcr, const func_t *pfn);

//-------------------------------------------------------------------------
struct md5_t;
struct func_md_t;
struct frame_mem_t;
struct frame_desc_t;
struct func_info_t;
class lumina_client_t;

//-------------------------------------------------------------------------
idaman rpc_packet_data_t *ida_export new_packet(uchar code, const uchar *ptr=nullptr, size_t len=0, int version=-1);

enum lumina_feature_t
{
  LFEAT_PRIMARY_MD,
  LFEAT_DEC,
  LFEAT_TLM,
  LFEAT_SECONDARY_MD,
};

//-------------------------------------------------------------------------

idaman asize_t ida_export calc_func_metadata(
        md5_t *out_hash,     // can be nullptr
        func_info_t *out_fi, // can be nullptr
        const func_t *pfn,
        metadata_appender_t *append_metadata=nullptr);

struct md_type_parts_t
{
  bool userti = false;
  qtype type;
  qtype fields;

  bool operator==(const md_type_parts_t &r) const
  {
    return userti == r.userti && type == r.type && fields == r.fields;
  }
  bool operator!=(const md_type_parts_t &r) const
  {
    return !(*this == r);
  }
};
idaman void ida_export extract_type_from_metadata(
        md_type_parts_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_insn_cmts_from_metadata(
        insn_cmts_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_extra_cmts_from_metadata(
        extra_cmts_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_user_stkpnts_from_metadata(
        user_stkpnts_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_frame_desc_from_metadata(
        frame_desc_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_insn_opreprs_from_metadata(
        insn_ops_reprs_t *out,
        const uchar *ptr,
        const uchar *end);
idaman void ida_export extract_insn_opreprs_from_metadata_ex(
        insn_ops_reprs_t *out,
        const uchar *ptr,
        const uchar *end);

void close_server_connection();
void close_server_connection2(lumina_feature_t feature);
void close_server_connections();

idaman lumina_client_t *ida_export get_server_connection();
idaman lumina_client_t *ida_export get_server_connection2(int flags);

#define GCSF_NO_CONNECT 0x80000000
#define GSCF_FEAT_MASK  (~GCSF_NO_CONNECT)

/// \defgroup AMDF_ flags for \ref apply_metadata()
///@{
#define AMDF_UPGRADE  0x0 ///< apply kvps that seem to be of higher
                          ///< "quality" than what's currently in the IDB
#define AMDF_FORCE    0x1 ///< apply kvps regardless of what's currently
                          ///< in the IDB, possibly removing some attributes
                          ///< currently present (e.g., name, or prototype
                          ///< could be lost)
///@}


idaman void ida_export apply_metadata(ea_t ea, const func_info_t &fi, uint32 flags=AMDF_UPGRADE);
idaman uint32 ida_export score_metadata(const func_info_t &fi);
idaman bool ida_export backup_metadata(ea_t ea);
idaman bool ida_export revert_metadata(ea_t ea);
idaman bool ida_export has_backup_metadata(ea_t ea);

struct func_md_diff_handler_t
{
  virtual ~func_md_diff_handler_t() {}

  virtual void on_score_changed(uint32 l, uint32 r)
  {
    qnotused(l);
    qnotused(r);
  }

  virtual void on_name_changed(
        const qstring *l,
        const qstring *r)
  {
    qnotused(l);
    qnotused(r);
  }

  virtual void on_proto_changed(
        const md_type_parts_t &l,
        const md_type_parts_t &r)
  {
    qnotused(l);
    qnotused(r);
  }

  virtual void on_function_comment_changed(
        const qstring *l,
        const qstring *r,
        bool rep)
  {
    qnotused(l);
    qnotused(r);
    qnotused(rep);
  }

  virtual void on_comment_changed(
        uint32 fchunk_nr,
        uint32 fchunk_off,
        const qstring *l,
        const qstring *r,
        bool rep)
  {
    qnotused(fchunk_nr);
    qnotused(fchunk_off);
    qnotused(l);
    qnotused(r);
    qnotused(rep);
  }

  virtual void on_extra_comment_changed(
        uint32 fchunk_nr,
        uint32 fchunk_off,
        const qstring *l,
        const qstring *r,
        bool is_prev)
  {
    qnotused(fchunk_nr);
    qnotused(fchunk_off);
    qnotused(l);
    qnotused(r);
    qnotused(is_prev);
  }

  virtual void on_user_stkpnt_changed(
        uint32 fchunk_nr,
        uint32 fchunk_off,
        const int64 *l,
        const int64 *r)
  {
    qnotused(fchunk_nr);
    qnotused(fchunk_off);
    qnotused(l);
    qnotused(r);
  }

  virtual void on_frame_member_changed(
        uint32 offset,
        const frame_mem_t *l,
        const frame_mem_t *r)
  {
    qnotused(offset);
    qnotused(l);
    qnotused(r);
  }

  virtual void on_insn_ops_repr_changed(
        uint32 fchunk_nr,
        uint32 fchunk_off,
        const insn_ops_repr_t *l,
        const insn_ops_repr_t *r)
  {
    qnotused(fchunk_nr);
    qnotused(fchunk_off);
    qnotused(l);
    qnotused(r);
  }
};

#define DMOF_COMPUTE_AND_DIFF_SCORE 0x1

idaman bool ida_export diff_metadata(
        func_md_diff_handler_t &handler,
        const func_info_t &left,
        const func_info_t &right,
        uint32 flags=0);




// <PROTOCOL>

#define PROTOCOL_VERSION 6


//
// Serializable/deserializable utilities
//
#ifndef NO_UTILS


//---------------------------------------------------------------------------
typedef qvector<lumina_op_res_t> lumina_op_res_vec_t;

//---------------------------------------------------------------------------
typedef qvector<mdkey_t> mdkey_vec_t;

//---------------------------------------------------------------------------
typedef qvector<ea64_t> ea64vec_t;

//---------------------------------------------------------------------------
struct pattern_id_t
{
  pattern_type_t type;
  bytevec_t data;
  pattern_id_t(pattern_type_t __type=PAT_TYPE_UNKNOWN, const bytevec_t &__data=bytevec_t())
    : type(__type), data(__data) {}

  void swap(pattern_id_t &other)
  {
    qswap(type, other.type);
    data.swap(other.data);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(pattern_id_t);

//---------------------------------------------------------------------------
typedef qvector<pattern_id_t> pattern_ids_t;

//---------------------------------------------------------------------------
struct func_info_base_t
{
  qstring name;
  metadata_t metadata;
  func_info_base_t(const char *__name=nullptr, const metadata_t &__metadata=metadata_t())
    : name(__name), metadata(__metadata) {}

  void swap(func_info_base_t &other)
  {
    name.swap(other.name);
    metadata.swap(other.metadata);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(func_info_base_t);

//---------------------------------------------------------------------------
typedef qvector<func_info_base_t> func_info_base_vec_t;

//---------------------------------------------------------------------------
struct func_info_t
{
  qstring name;
  uint32 size;
  metadata_t metadata;
  func_info_t(const char *__name=nullptr, uint32 __size=0, const metadata_t &__metadata=metadata_t())
    : name(__name), size(__size), metadata(__metadata) {}

  void swap(func_info_t &other)
  {
    name.swap(other.name);
    qswap(size, other.size);
    metadata.swap(other.metadata);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(func_info_t);

//---------------------------------------------------------------------------
typedef qvector<func_info_t> func_info_vec_t;

//---------------------------------------------------------------------------
typedef qvector<md5_t> md5_vec_t;

//---------------------------------------------------------------------------
struct input_file_t
{
  qstring path;
  md5_t md5;
  input_file_t(const char *__path=nullptr, const md5_t &__md5=md5_t())
    : path(__path), md5(__md5) {}

  void swap(input_file_t &other)
  {
    path.swap(other.path);
    md5.swap(other.md5);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(input_file_t);

//---------------------------------------------------------------------------
struct func_info_and_frequency_t : public func_info_t
{
  uint32 frequency;
  func_info_and_frequency_t(uint32 __frequency=0)
    : func_info_t(), frequency(__frequency) {}

  void swap(func_info_and_frequency_t &other)
  {
    func_info_t::swap((func_info_t &) other);
    qswap(frequency, other.frequency);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(func_info_and_frequency_t);

//---------------------------------------------------------------------------
typedef qvector<func_info_and_frequency_t> func_info_and_frequency_vec_t;

//---------------------------------------------------------------------------
struct func_info_and_pattern_t : public func_info_t
{
  pattern_id_t pattern_id;
  func_info_and_pattern_t(const pattern_id_t &__pattern_id=pattern_id_t())
    : func_info_t(), pattern_id(__pattern_id) {}

  void swap(func_info_and_pattern_t &other)
  {
    func_info_t::swap((func_info_t &) other);
    pattern_id.swap(other.pattern_id);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(func_info_and_pattern_t);

//---------------------------------------------------------------------------
typedef qvector<func_info_and_pattern_t> func_info_and_pattern_vec_t;

//---------------------------------------------------------------------------
struct func_info_pattern_and_frequency_t : public func_info_and_pattern_t
{
  uint32 frequency;
  func_info_pattern_and_frequency_t(uint32 __frequency=0)
    : func_info_and_pattern_t(), frequency(__frequency) {}

  void swap(func_info_pattern_and_frequency_t &other)
  {
    func_info_and_pattern_t::swap((func_info_and_pattern_t &) other);
    qswap(frequency, other.frequency);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(func_info_pattern_and_frequency_t);

//---------------------------------------------------------------------------
typedef qvector<func_info_pattern_and_frequency_t> func_info_pattern_and_frequency_vec_t;

//---------------------------------------------------------------------------
struct pop_fun_t : public func_info_pattern_and_frequency_t
{
  qstring hostname;
  input_file_t input;
  ea64_t ea64;
  pop_fun_t(const char *__hostname=nullptr, const input_file_t &__input=input_file_t(), ea64_t __ea64=ea64_t(-1))
    : func_info_pattern_and_frequency_t(), hostname(__hostname), input(__input), ea64(__ea64) {}

  void swap(pop_fun_t &other)
  {
    func_info_pattern_and_frequency_t::swap((func_info_pattern_and_frequency_t &) other);
    hostname.swap(other.hostname);
    input.swap(other.input);
    qswap(ea64, other.ea64);
  }
  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(pop_fun_t);

//---------------------------------------------------------------------------
typedef qvector<pop_fun_t> pop_fun_vec_t;

//---------------------------------------------------------------------------
struct serialized_tinfo
{
  qtype type;
  qtype fields;
  serialized_tinfo(const type_t *__type=nullptr, const type_t *__fields=nullptr)
    : type(__type), fields(__fields) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
  bool empty() const;
};
DECLARE_TYPE_AS_MOVABLE(serialized_tinfo);

//---------------------------------------------------------------------------
struct frame_mem_t
{
  qstring name;
  serialized_tinfo type;
  qstring cmt;
  qstring rptcmt;
  ea64_t offset;
  oprepr_t info;
  asize_t nbytes;
  frame_mem_t(const char *__name=nullptr, const serialized_tinfo &__type=serialized_tinfo(), const char *__cmt=nullptr, const char *__rptcmt=nullptr, ea64_t __offset=ea64_t(-1), const oprepr_t &__info=oprepr_t(), asize_t __nbytes=asize_t(-1))
    : name(__name), type(__type), cmt(__cmt), rptcmt(__rptcmt), offset(__offset), info(__info), nbytes(__nbytes) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(frame_mem_t);

//---------------------------------------------------------------------------
typedef qvector<frame_mem_t> frame_mems_t;

//---------------------------------------------------------------------------
struct frame_desc_t
{
  sval_t frsize;
  asize_t argsize;
  ushort frregs;
  frame_mems_t members;
  frame_desc_t(sval_t __frsize=0, asize_t __argsize=asize_t(-1), ushort __frregs=0, const frame_mems_t &__members=frame_mems_t())
    : frsize(__frsize), argsize(__argsize), frregs(__frregs), members(__members) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(frame_desc_t);

//---------------------------------------------------------------------------
struct skipped_func_t
{
  pattern_id_t pattern_id;
  uint32 count;
  skipped_func_t(const pattern_id_t &__pattern_id=pattern_id_t(), uint32 __count=0)
    : pattern_id(__pattern_id), count(__count) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(skipped_func_t);

//---------------------------------------------------------------------------
typedef qvector<skipped_func_t> skipped_funcs_t;

//---------------------------------------------------------------------------
struct user_license_info_t
{
  qstring id;
  qstring name;
  qstring email;
  user_license_info_t(const char *__id=nullptr, const char *__name=nullptr, const char *__email=nullptr)
    : id(__id), name(__name), email(__email) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(user_license_info_t);

//---------------------------------------------------------------------------
typedef qvector<utc_timestamp_t> utc_timestamp_vec_t;

//---------------------------------------------------------------------------
struct lumina_user_t
{
  user_license_info_t license_info;
  qstring name;
  int karma;
  utc_timestamp_t last_active;
  uint32 features;
  lumina_user_t(const user_license_info_t &__license_info=user_license_info_t(), const char *__name=nullptr, int __karma=0, utc_timestamp_t __last_active=0, uint32 __features=0)
    : license_info(__license_info), name(__name), karma(__karma), last_active(__last_active), features(__features) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
  bool is_admin() const { return (features & UF_IS_ADMIN) != 0; }
  void set_is_admin(bool v=true) { setflag(features, UF_IS_ADMIN, v); }
  bool can_del_history() const { return (features & UF_CAN_DEL_HISTORY) != 0; }
  void set_can_del_history(bool v=true) { setflag(features, UF_CAN_DEL_HISTORY, v); }
};
DECLARE_TYPE_AS_MOVABLE(lumina_user_t);

//---------------------------------------------------------------------------
typedef qvector<lumina_user_t> lumina_users_t;

//---------------------------------------------------------------------------
struct peer_conn_t
{
  uint32 session_id;
  qstring peer_name;
  lumina_user_t user;
  utc_timestamp_t established;
  peer_conn_t(uint32 __session_id=0, const char *__peer_name=nullptr, const lumina_user_t &__user=lumina_user_t(), utc_timestamp_t __established=0)
    : session_id(__session_id), peer_name(__peer_name), user(__user), established(__established) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(peer_conn_t);

//---------------------------------------------------------------------------
typedef qvector<qstring> qstrvec_t;

//---------------------------------------------------------------------------
struct lumina_server_info_t
{
  qstring macaddr;
  qstring verstr;
  utc_timestamp_t start_time;
  utc_timestamp_t current_time;
  lumina_server_info_t(const char *__macaddr=nullptr, const char *__verstr=nullptr, utc_timestamp_t __start_time=0, utc_timestamp_t __current_time=0)
    : macaddr(__macaddr), verstr(__verstr), start_time(__start_time), current_time(__current_time) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(lumina_server_info_t);

//---------------------------------------------------------------------------
struct lumina_info_t
{
  peer_conn_t client;
  lumina_server_info_t server;
  lumina_info_t(const peer_conn_t &__client=peer_conn_t(), const lumina_server_info_t &__server=lumina_server_info_t())
    : client(__client), server(__server) {}

  void serialize(bytevec_t *out, int version) const;
  bool deserialize(const uchar **ptr, size_t len, int version);
};
DECLARE_TYPE_AS_MOVABLE(lumina_info_t);

#endif // !UTILS

//
// Packet types
//
#ifndef NO_RPC_PACKETS_LIST

enum lumina_rpc_packet_t
{
  PKT_RPC_OK = 10,
  PKT_RPC_FAIL,
  PKT_RPC_NOTIFY,
  PKT_HELO,
  PKT_PULL_MD,
  PKT_PULL_MD_RESULT,
  PKT_PUSH_MD,
  PKT_PUSH_MD_RESULT,
  PKT_GET_POP,
  PKT_GET_POP_RESULT,
  __UNUSED_20 = 20,
  __UNUSED_21 = 21,
  __UNUSED_22 = 22,
  __UNUSED_23 = 23,
  __UNUSED_24 = 24,
  __UNUSED_25 = 25,
  __UNUSED_26 = 26,
  __UNUSED_27 = 27,
  __UNUSED_28 = 28,
  __UNUSED_29 = 29,
  __UNUSED_30 = 30,
  __UNUSED_31 = 31,
  __UNUSED_32 = 32,
  __UNUSED_33 = 33,
  __UNUSED_34 = 34,
  __UNUSED_35 = 35,
  __UNUSED_36 = 36,
  __UNUSED_37 = 37,
  __UNUSED_38 = 38,
  __UNUSED_39 = 39,
  __UNUSED_40 = 40,
  __UNUSED_41 = 41,
  __UNUSED_42 = 42,
  PKT_GET_LUMINA_INFO,
  PKT_GET_LUMINA_INFO_RESULT,
  __UNUSED_45 = 45,
  __UNUSED_46 = 46,
  __UNUSED_47 = 47,
  __UNUSED_48 = 48,
  PKT_HELO_RESULT,
};

//---------------------------------------------------------------------------
inline uchar get_lumina_rpc_packet_t_index_from_base(lumina_rpc_packet_t code) { return code - 10; }

#endif // !RPC_PACKETS_LIST


//
// Packet definitions
//
#ifndef NO_RPC_PACKETS


//---------------------------------------------------------------------------
struct pkt_rpc_ok_t : public rpc_packet_data_t
{
  pkt_rpc_ok_t()
    : rpc_packet_data_t(PKT_RPC_OK) {}

  virtual ~pkt_rpc_ok_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_rpc_fail_t : public rpc_packet_data_t
{
  int result;
  qstring error;
  pkt_rpc_fail_t(int __result=0, const char *__error=nullptr)
    : rpc_packet_data_t(PKT_RPC_FAIL), result(__result), error(__error) {}

  virtual ~pkt_rpc_fail_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_rpc_notify_t : public rpc_packet_data_t
{
  rpc_notification_type_t type;
  qstring text;
  pkt_rpc_notify_t(rpc_notification_type_t __type=rnt_unknown, const char *__text=nullptr)
    : rpc_packet_data_t(PKT_RPC_NOTIFY), type(__type), text(__text) {}

  virtual ~pkt_rpc_notify_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_helo_t : public rpc_packet_data_t
{
  int client_version;
  bytevec_t key;
  uchar license_id[6];
  bool record_conv;
  qstring username;
  qstring password;
  pkt_helo_t(int __client_version=0, const bytevec_t &__key=bytevec_t(), bool __record_conv=false, const char *__username=nullptr, const char *__password=nullptr)
    : rpc_packet_data_t(PKT_HELO), client_version(__client_version), key(__key), record_conv(__record_conv), username(__username), password(__password)
  {
    memset(license_id, 0, sizeof(license_id));
  }

  virtual ~pkt_helo_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_pull_md_t : public rpc_packet_data_t
{
  uint32 flags;
  mdkey_vec_t keys;
  pattern_ids_t pattern_ids;
  pkt_pull_md_t(uint32 __flags=0, const mdkey_vec_t &__keys=mdkey_vec_t(), const pattern_ids_t &__pattern_ids=pattern_ids_t())
    : rpc_packet_data_t(PKT_PULL_MD), flags(__flags), keys(__keys), pattern_ids(__pattern_ids) {}

  virtual ~pkt_pull_md_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_pull_md_result_t : public rpc_packet_data_t
{
  lumina_op_res_vec_t codes;
  func_info_and_frequency_vec_t results;
  pkt_pull_md_result_t(const lumina_op_res_vec_t &__codes=lumina_op_res_vec_t(), const func_info_and_frequency_vec_t &__results=func_info_and_frequency_vec_t())
    : rpc_packet_data_t(PKT_PULL_MD_RESULT), codes(__codes), results(__results) {}

  virtual ~pkt_pull_md_result_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_push_md_t : public rpc_packet_data_t
{
  uint32 flags;
  qstring idb;
  input_file_t input;
  qstring hostname;
  func_info_and_pattern_vec_t contents;
  ea64vec_t ea64s;
  pkt_push_md_t(uint32 __flags=0, const char *__idb=nullptr, const input_file_t &__input=input_file_t(), const char *__hostname=nullptr, const func_info_and_pattern_vec_t &__contents=func_info_and_pattern_vec_t(), const ea64vec_t &__ea64s=ea64vec_t())
    : rpc_packet_data_t(PKT_PUSH_MD), flags(__flags), idb(__idb), input(__input), hostname(__hostname), contents(__contents), ea64s(__ea64s) {}

  virtual ~pkt_push_md_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_push_md_result_t : public rpc_packet_data_t
{
  lumina_op_res_vec_t codes;
  pkt_push_md_result_t(const lumina_op_res_vec_t &__codes=lumina_op_res_vec_t())
    : rpc_packet_data_t(PKT_PUSH_MD_RESULT), codes(__codes) {}

  virtual ~pkt_push_md_result_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_get_pop_t : public rpc_packet_data_t
{
  uint32 nresults;
  pkt_get_pop_t(uint32 __nresults=LUMINA_GET_POP_DEFAULT_NRESULTS)
    : rpc_packet_data_t(PKT_GET_POP), nresults(__nresults) {}

  virtual ~pkt_get_pop_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_get_pop_result_t : public rpc_packet_data_t
{
  pop_fun_vec_t results;
  pkt_get_pop_result_t(const pop_fun_vec_t &__results=pop_fun_vec_t())
    : rpc_packet_data_t(PKT_GET_POP_RESULT), results(__results) {}

  virtual ~pkt_get_pop_result_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_get_lumina_info_t : public rpc_packet_data_t
{
  pkt_get_lumina_info_t()
    : rpc_packet_data_t(PKT_GET_LUMINA_INFO) {}

  virtual ~pkt_get_lumina_info_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_get_lumina_info_result_t : public rpc_packet_data_t
{
  lumina_info_t info;
  pkt_get_lumina_info_result_t(const lumina_info_t &__info=lumina_info_t())
    : rpc_packet_data_t(PKT_GET_LUMINA_INFO_RESULT), info(__info) {}

  virtual ~pkt_get_lumina_info_result_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
struct pkt_helo_result_t : public rpc_packet_data_t
{
  lumina_user_t user;
  pkt_helo_result_t(const lumina_user_t &__user=lumina_user_t())
    : rpc_packet_data_t(PKT_HELO_RESULT), user(__user) {}

  virtual ~pkt_helo_result_t();
  virtual void serialize(bytevec_t *out, int version) const override;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) override;
};

//---------------------------------------------------------------------------
extern const rpc_packet_type_desc_t lumina_rpc_packet_t_descs[40];

#endif // !RPC_PACKETS

// </PROTOCOL>

//-------------------------------------------------------------------------
// If 'eas' is empty, then 'min_func_size' will be used
// to figure out what functions should be reported.
struct push_md_opts_t
{
  eavec_t eas;
  size_t min_func_size;
  push_md_opts_t(size_t mfs=size_t(-1)) : min_func_size(mfs) {}
};

//-------------------------------------------------------------------------
struct push_md_result_t
{
  eavec_t eas;
  lumina_op_res_vec_t codes;
  func_info_and_pattern_vec_t contents;
};

//-------------------------------------------------------------------------
class lumina_client_t : public generic_client_t
{
  lumina_feature_t feature;
  lumina_user_t user;   // takes value after HELO

public:
  lumina_client_t(lumina_feature_t _feature, idarpc_stream_t *_irs);
  ~lumina_client_t();

  virtual void set_pattern_id_md5(pattern_id_t *out, const md5_t &md5) const newapi;
  virtual bool is_pattern_id(const pattern_id_t &pid, const md5_t &md5) const newapi;

  bool send_helo(
        const bytevec_t &key_data,
        const uchar license_id[6],
        qstring *errbuf,
        const char *username,
        const char *password);
  virtual pkt_pull_md_result_t *pull_md(
        pattern_ids_t &pattern_ids, // will be destroyed
        qstring *errbuf,
        uint32 pull_md_flags=0) newapi;
  virtual pkt_pull_md_result_t *pull_md(
        eavec_t *funcs,           // if empty, will be filled with interesting funcs
        qstring *errbuf,
        uint32 pull_md_flags=0) newapi;
#define PULL_MD_AUTO_APPLY 0x01       // automatically apply metadata
                                      // FIXME: this bit does not need to be sent
                                      // to the lumina server
#define PULL_MD_SEEN_FILE  0x02       // do not increase frequency count

  virtual bool push_md(
        push_md_result_t *result,
        const push_md_opts_t &opts,
        qstring *errbuf,
        metadata_appender_t *append_metadata=nullptr,
        uint32 flags=0) newapi;

  virtual pkt_get_pop_result_t *get_pop(
        qstring *errbuf,
        uint32 nresults=LUMINA_GET_POP_DEFAULT_NRESULTS) newapi;

  // unconditionally remove all metadata for FUNCS
  virtual bool del_history(qstring *errbuf, const eavec_t &funcs) newapi;

  bool can_del_history() const
  {
    return user.can_del_history();
  }

};


#endif // LUMINA_HPP
