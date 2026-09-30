
#ifndef LUMINA_HPP
#define LUMINA_HPP

/*! \file lumina.hpp

  \brief Lumina client API: metadata push/pull against a Lumina server.
*/

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
  /// \deprecated Use to_ea() for safer access.
  DEPRECATED ea_t toea(const func_t *pfn) const
  {
    QASSERT(1777, pfn != nullptr);
    return to_ea(pfn->start_ea);
  }
  ea_t to_ea(ea_t func_ea) const
  {
    if ( fchunk_nr == 0 )
    {
      func_entry_info_t fi;
      if ( !get_func_entry_info(&fi, func_ea) )
        return BADADDR;
      return fchunk_off < fi.size() ? fi.start_ea + fchunk_off : BADADDR;
    }
    rangevec_t tails;
    get_func_tails(&tails, func_ea);
    if ( fchunk_nr-1 >= tails.size() )
      return BADADDR;
    const range_t &r = tails[fchunk_nr-1];
    return fchunk_off < r.size() ? r.start_ea + fchunk_off : BADADDR;
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
typedef void idaapi metadata_appender_ea_t(metadata_creator_t &mcr, ea_t func_ea);

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

/// \deprecated Use calc_function_metadata() for safer access.
idaman DEPRECATED asize_t ida_export calc_func_metadata(
        md5_t *out_hash,     // can be nullptr
        func_info_t *out_fi, // can be nullptr
        const func_t *pfn,
        metadata_appender_t *append_metadata=nullptr);

idaman asize_t ida_export calc_function_metadata(
        md5_t *out_hash,     // can be nullptr
        func_info_t *out_fi, // can be nullptr
        ea_t func_ea,
        metadata_appender_ea_t *append_metadata=nullptr);

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




#include "lumina_protocol.hpp"

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
  friend struct ida_lumina_client_t;
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

  virtual bool obsolete_push_md(
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

  virtual bool push_md(
        push_md_result_t *result,
        const push_md_opts_t &opts,
        qstring *errbuf,
        metadata_appender_ea_t *append_metadata=nullptr,
        uint32 flags=0) newapi;

  bool can_del_history() const
  {
    return user.can_del_history();
  }


};


#endif // LUMINA_HPP
