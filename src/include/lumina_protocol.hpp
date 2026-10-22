/* --- This file is generated. Do not edit! --- */
#pragma once

/*! \file lumina_protocol.hpp

  \brief Lumina RPC protocol: packet and payload types.
*/

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
