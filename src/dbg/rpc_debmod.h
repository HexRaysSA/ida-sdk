#ifndef __RPC_DEBUGGER_MODULE__
#define __RPC_DEBUGGER_MODULE__

#define pack_ea DONT_USE_pack_ea_USE_pack_ea64_INSTEAD
#define unpack_ea DONT_USE_unpack_ea_USE_unpack_ea64_INSTEAD

#include "debmod.h"
#include "dbg_rpc_client.h"

//---------------------------------------------------------------------------
class rpc_debmod_t
  : public debmod_t,
    public dbg_rpc_client_t
{
  drc_t process_start_or_attach(bytevec_t &req, qstring *errbuf);

public:
  rpc_debmod_t(const char *default_platform = nullptr);
  virtual bool idaapi open_remote(const char *hostname, int port_number, const char *password, qstring *errbuf) newapi;
  drc_t close_remote();

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
  {
    return rpc_engine_t::send_ioctl(fn, buf, size, poutbuf, poutsize);
  }

  //--------------------------------------------------------------------------
  inline int getint(ushort code)
  {
    bytevec_t req = prepare_rpc_packet((uchar)code);
    return send_request_get_long_result(req);
  }
  drc_t get_drc_int(uchar code, int x)
  {
    bytevec_t req = prepare_rpc_packet(code);
    req.pack_dd(x);
    return send_request_get_drc_result(req, nullptr);
  }
  inline drc_t get_drc(ushort code, qstring *errbuf=nullptr)
  {
    bytevec_t req = prepare_rpc_packet((uchar)code);
    return send_request_get_drc_result(req, errbuf);
  }

  //
  virtual void idaapi dbg_set_debugging(bool _debug_debugger) override;
  virtual drc_t idaapi dbg_init(uint32_t *flags2, qstring *errbuf) override;
  virtual void idaapi dbg_term(void) override;
  virtual drc_t idaapi dbg_get_processes(procinfo_vec_t *procs, qstring *errbuf) override;
  virtual drc_t idaapi dbg_detach_process(void) override;
  virtual drc_t idaapi dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf) override;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms) override;
  virtual drc_t idaapi dbg_attach_process(pid_t process_id, int event_id, int flags, qstring *errbuf) override;
  virtual drc_t idaapi dbg_prepare_to_pause_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_exit_process(qstring *errbuf) override;
  virtual drc_t idaapi dbg_continue_after_event(const debug_event_t *event) override;
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty) override;
  virtual void idaapi dbg_stopped_at_debug_event(import_infos_t *infos, bool dlls_added, thread_name_vec_t *thr_names) override;
  virtual drc_t idaapi dbg_thread_suspend(thid_t thread_id) override;
  virtual drc_t idaapi dbg_thread_continue(thid_t thread_id) override;
  virtual drc_t idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) override;
  virtual drc_t idaapi dbg_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf) override;
  virtual drc_t idaapi dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value, qstring *errbuf) override;
  virtual drc_t idaapi dbg_get_memory_info(meminfo_vec_t &areas, qstring *errbuf) override;
  virtual int idaapi dbg_get_scattered_image(scattered_image_t &si, ea_t base) override;
  virtual bool idaapi dbg_get_image_uuid(bytevec_t *uuid, ea_t base) override;
  virtual ea_t idaapi dbg_get_segm_start(ea_t base, const qstring &segname) override;
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring *errbuf) override;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring *errbuf) override;
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) override;
  virtual int idaapi dbg_add_bpt(bytevec_t *orig_bytes, bpttype_t type, ea_t ea, int len) override;
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) override;
  virtual drc_t idaapi dbg_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel, qstring *errbuf) override;
  virtual drc_t idaapi dbg_update_lowcnds(int *nupdated, const lowcnd_t *lowcnds, int nlowcnds, qstring *errbuf) override;
  virtual drc_t idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea, qstring *errbuf) override;
  virtual int idaapi dbg_open_file(const char *file, uint64 *fsize, bool readonly) override;
  virtual void idaapi dbg_close_file(int fn) override;
  virtual ssize_t idaapi dbg_read_file(int fn, qoff64_t off, void *buf, size_t size) override;
  virtual ssize_t idaapi dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size) override;
  virtual int idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize) override;
  virtual int idaapi get_system_specific_errno(void) const override;
  virtual drc_t idaapi dbg_update_call_stack(thid_t, call_stack_t *) override;
  virtual ea_t idaapi dbg_appcall(
        ea_t func_ea,
        thid_t tid,
        int stkarg_nbytes,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags) override;
  virtual drc_t idaapi dbg_cleanup_appcall(thid_t tid) override;
  virtual int get_regidx(const char *, int *) override { INTERR(30116); }
  virtual int idaapi dbg_rexec(const char *cmdline) override;
  virtual drc_t idaapi dbg_bin_search(
        ea_t *ea,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring *errbuf) override;
};

#endif
