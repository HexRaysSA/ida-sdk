
#include <segment.hpp>
#include <err.h>
#include <network.hpp>

#include "rpc_debmod.h"
#include "dbg_rpc_hlp.h"

//-------------------------------------------------------------------------
inline drc_t unpack_drc(memory_deserializer_t &mmdsr)
{
  return drc_t(mmdsr.unpack_dd());
}

//--------------------------------------------------------------------------
rpc_debmod_t::rpc_debmod_t(const char *default_platform)
  : dbg_rpc_client_t(nullptr)
{
  for ( int i=0; i < debugger.nregisters; i++ )
  {
    const register_info_t &ri = debugger.regs(i);
    if ( (ri.flags & REGISTER_SP) != 0 )
      sp_idx = i;
    if ( (ri.flags & REGISTER_IP) != 0 )
      pc_idx = i;
  }
  bpt_code.append(debugger.bpt_bytes, debugger.bpt_size);
  rpc = this;

  set_platform(default_platform);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::handle_ioctl(    //-V524 equivalent to 'send_ioctl'
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return rpc_engine_t::send_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
inline int get_expected_addrsize(void)
{
  return inf_is_64bit() ? 8 : 4;
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::open_remote(
        const char *hostname,
        int port_number,
        const char *password,
        qstring *errbuf)
{
  if ( hostname[0] == '\0' )
  {
    if ( errbuf != nullptr )
      *errbuf = "Please specify the hostname in Debugger, Process options";
    return false;
  }

  rpc_packet_t *rp = nullptr;
  network_error = false;
  client_irs = irs_new();
  if ( !irs_init_client(client_irs, irs_client_opts_t(hostname, port_number)) )
  {
FAILURE:
    if ( rp != nullptr )
      qfree(rp);

    if ( errbuf != nullptr )
      *errbuf = irs_strerror(client_irs);
    irs_term(&client_irs);
    return false;
  }

  rp = recv_packet(RPC_OPEN);
  if ( rp == nullptr || rp->code != RPC_OPEN )  // is this an ida debugger server?
  {
    dbg_rpc_client_t::dwarning("ICON ERROR\nAUTOHIDE NONE\n"
                               "Bogus or irresponsive remote server");
    goto FAILURE;
  }

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int version            = mmdsr.unpack_dd();
  int remote_debugger_id = mmdsr.unpack_dd();
  int easize             = mmdsr.unpack_dd();
#ifdef __EA64__
  // in case of instant debugging we are able to low the IDA bitness
  if ( (!netnode::inited() || is_miniidb() )
    && easize != get_expected_addrsize() )
  {
    inf_set_app_bitness(easize * 8);
    set_addr_size(easize);
  }
#endif
#ifdef TESTABLE_BUILD
  msg("Remote debug server (sizeof ea=%d)\n", easize*8);
#endif
  qstring errstr;
  if ( version != IDD_INTERFACE_VERSION )
    errstr.sprnt("protocol version is %d, expected %d", version, IDD_INTERFACE_VERSION);
  else if ( remote_debugger_id != debugger.id )
    errstr.sprnt("debugger id is %d, expected %d (%s)", remote_debugger_id, debugger.id, debugger.name);
  else if ( easize < get_expected_addrsize() )
    errstr.sprnt("address size is %d bytes, expected at least %d", easize, get_expected_addrsize());
  if ( !errstr.empty() )
  {
    bytevec_t req = prepare_rpc_packet(RPC_OK);
    req.pack_dd(false);
    send_data(req);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Incompatible debugging server:\n"
            "%s", errstr.c_str());
    goto FAILURE;
  }
  qfree(rp);

  bytevec_t req = prepare_rpc_packet(RPC_OK);
  req.pack_dd(true);
  req.pack_str(password);
  send_data(req);

  rp = recv_packet(RPC_OPEN);
  if ( rp == nullptr || rp->code != RPC_OK )
    goto FAILURE;

  memory_deserializer_t mmdsr2(rp+1, rp->length);
  bool password_ok = mmdsr2.unpack_dd() != 0;
  if ( !password_ok )  // is this an ida debugger server?
  {
    warning("ICON ERROR\nAUTOHIDE NONE\n"
            "Bad password");
    goto FAILURE;
  }

  qfree(rp);
  logged_in = true;
  return true;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_add_bpt(bytevec_t *, bpttype_t, ea_t, int)
{
  INTERR(30114);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_del_bpt(bpttype_t, ea_t, const uchar *, int)
{
  INTERR(30115);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_update_lowcnds(
        int *nupdated,
        const lowcnd_t *lowcnds,
        int nlowcnds,
        qstring *errbuf)
{
  ea_t ea = 0;
  bytevec_t req = prepare_rpc_packet(RPC_UPDATE_LOWCNDS);
  req.pack_dd(nlowcnds);
  const lowcnd_t *lc = lowcnds;
  for ( int i=0; i < nlowcnds; i++, lc++ )
  {
    req.pack_ea64(lc->ea-ea); ea = lc->ea;
    req.pack_str(lc->cndbody);
    if ( !lc->cndbody.empty() )
    {
      req.pack_dd(lc->type);
      if ( lc->type != BPT_SOFT )
        req.pack_dd(lc->size);
      req.pack_db(lc->orgbytes.size());
      req.append(lc->orgbytes.begin(), lc->orgbytes.size());
      req.pack_ea64(lc->cmd.ea);
      if ( lc->cmd.ea != BADADDR )
        append_insn(req, lc->cmd);
    }
  }

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_UPDATE_LOWCNDS, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  int ret_nupdated = mmdsr.unpack_dd();
  if ( nupdated != nullptr )
    *nupdated = ret_nupdated;

  if ( errbuf != nullptr && drc != DRC_NONE )
    *errbuf = mmdsr.unpack_str();

  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_eval_lowcnd(thid_t tid, ea_t ea, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_EVAL_LOWCND);
  req.pack_dd(tid);
  req.pack_ea64(ea);
  return send_request_get_drc_result(req, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_update_bpts(
        int *nbpts,
        update_bpt_info_t *ubpts,
        int nadd,
        int ndel,
        qstring *errbuf)
{
  int skipped = 0;
  update_bpt_info_t *b;
  update_bpt_info_t *bend = ubpts + nadd;
  for ( b=ubpts; b != bend; b++ )
    if ( b->code != BPT_OK )
      skipped++;
  if ( skipped == nadd && ndel == 0 )
  {
    if ( nbpts != nullptr )
      *nbpts = 0;   // no bpts to update
    return DRC_OK;
  }

  bytevec_t req = prepare_rpc_packet(RPC_UPDATE_BPTS);
  req.pack_dd(nadd-skipped);
  req.pack_dd(ndel);
  ea_t ea = 0;
  for ( b=ubpts; b != bend; b++ )
  {
    if ( b->code == BPT_OK )
    {
      req.pack_ea64(b->ea-ea); ea = b->ea;
      req.pack_dd(b->size);
      req.pack_dd(b->type);
      req.pack_dd(b->pid);
      req.pack_dd(b->tid);
    }
  }

  ea = 0;
  bend += ndel;
  for ( ; b != bend; b++ )
  {
    req.pack_ea64(b->ea-ea); ea = b->ea;
    req.pack_db(b->orgbytes.size());
    req.append(b->orgbytes.begin(), b->orgbytes.size());
    req.pack_dd(b->type);
    req.pack_dd(b->pid);
    req.pack_dd(b->tid);
  }

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_UPDATE_BPTS, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  int ret_nbpts = mmdsr.unpack_dd();
  if ( nbpts != nullptr )
    *nbpts = ret_nbpts;
  bend = ubpts + nadd;
  for ( b=ubpts; b != bend; b++ )
  {
    if ( b->code == BPT_OK )
    {
      b->code = mmdsr.unpack_db();
      if ( b->code == BPT_OK && b->type == BPT_SOFT )
      {
        uchar len = mmdsr.unpack_db();
        b->orgbytes.resize(len);
        mmdsr.unpack_obj(b->orgbytes.begin(), len);
      }
    }
  }

  bend += ndel;
  for ( ; b != bend; b++ )
    b->code = mmdsr.unpack_db();

  if ( errbuf != nullptr && drc != DRC_NONE )
    *errbuf = mmdsr.unpack_str();
  return drc;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_thread_get_sreg_base(ea_t *ea, thid_t tid, int sreg_value, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SREG_BASE);
  req.pack_dd(tid);
  req.pack_dd(sreg_value);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_SREG_BASE, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  if ( drc == DRC_OK )
    *ea = mmdsr.unpack_ea64();
  else if ( errbuf != nullptr )
    *errbuf = mmdsr.unpack_str();

  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_set_exception_info(const exception_info_t *table, int qty)
{
  bytevec_t req = prepare_rpc_packet(RPC_SET_EXCEPTION_INFO);
  req.pack_dd(qty);
  append_exception_info(req, table, qty);

  qfree(send_request_and_receive_reply(RPC_SET_EXCEPTION_INFO, req));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_open_file(const char *file, uint64 *fsize, bool readonly)
{
  bytevec_t req = prepare_rpc_packet(RPC_OPEN_FILE);
  req.pack_str(file);
  req.pack_dd(readonly);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_OPEN_FILE, req);
  if ( rp == nullptr )
    return -1;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int fn = mmdsr.unpack_dd();
  if ( fn != -1 )
  {
    if ( fsize != nullptr && readonly )
      *fsize = mmdsr.unpack_dq();
  }
  else
  {
    errno = mmdsr.unpack_dd();
  }
  qfree(rp);
  return fn;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_close_file(int fn)
{
  bytevec_t req = prepare_rpc_packet(RPC_CLOSE_FILE);
  req.pack_dd(fn);

  qfree(send_request_and_receive_reply(RPC_CLOSE_FILE, req));
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_read_file(int fn, qoff64_t off, void *buf, size_t size)
{
  bytevec_t req = prepare_rpc_packet(RPC_READ_FILE);
  req.pack_dd(fn);
  req.pack_dq(off);
  req.pack_dd((uint32)size);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_READ_FILE, req);
  if ( rp == nullptr )
    return -1;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int32 rsize = mmdsr.unpack_dd();
  if ( size != rsize )
    errno = mmdsr.unpack_dd();

  if ( rsize > 0 )
  {
    QASSERT(1204, rsize <= size);
    mmdsr.unpack_obj(buf, rsize);
  }
  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_FILE);
  req.pack_dd(fn);
  req.pack_dq(off);
  req.pack_buf(buf, size);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_WRITE_FILE, req);
  if ( rp == nullptr )
    return -1;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int32 rsize = mmdsr.unpack_dd();
  if ( size != rsize )
    errno = mmdsr.unpack_dd();

  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  bytevec_t req = prepare_rpc_packet(RPC_ISOK_BPT);
  req.pack_dd(type);
  req.pack_ea64(ea);
  req.pack_dd(len+1);

  return send_request_get_long_result(req);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_init(uint32_t *_flags2, qstring *errbuf)
{
  has_pending_event = false;
  poll_debug_events = false;

  bytevec_t req = prepare_rpc_packet(RPC_INIT);
  req.pack_dd(debugger.flags);
  req.pack_dd(debug_debugger);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_INIT, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  uint32_t flags2 = mmdsr.unpack_dd();
  if ( _flags2 != nullptr )
    *_flags2 = flags2;
  if ( drc != DRC_OK && errbuf != nullptr )
    *errbuf = mmdsr.unpack_str();

  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_term(void)
{
  bytevec_t req = prepare_rpc_packet(RPC_TERM);

  qfree(send_request_and_receive_reply(RPC_TERM, req));
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_get_processes(procinfo_vec_t *procs, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_PROCESSES);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_PROCESSES, req);
  if ( rp == nullptr )
    return DRC_NETERR;
  memory_deserializer_t mmdsr(rp+1, rp->length);

  procs->qclear();
  drc_t drc = unpack_drc(mmdsr);
  if ( drc == DRC_OK )
    extract_process_info_vec(procs, mmdsr);
  else if ( errbuf != nullptr )
    *errbuf = mmdsr.unpack_str();

  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_detach_process(void)
{
  return get_drc(RPC_DETACH_PROCESS);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf)
{
  if ( inf_test_mode() )
    flags |= DBG_HIDE_WINDOW;
  bytevec_t req = prepare_rpc_packet(RPC_START_PROCESS);
  req.pack_str(path);
  req.pack_str(args);
  req.pack_str(startdir);
  req.pack_dd(flags);
  req.pack_str(input_path);
  req.pack_dd(input_file_crc32);

  if ( envs != nullptr )
  {
    req.pack_db(envs->merge);
    req.pack_dd(envs->size());
    for ( auto &env : *envs )
      req.pack_str(env.c_str());
  }
  else
  {
    req.pack_db(true);
    req.pack_dd(0);
  }


  return process_start_or_attach(req, errbuf);
}

//--------------------------------------------------------------------------
gdecode_t idaapi rpc_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  if ( has_pending_event )
  {
    verbev(("get_debug_event => has pending event, returning it\n"));
    *event = pending_event;
    has_pending_event = false;
    poll_debug_events = false;
    return GDE_ONE_EVENT;
  }

  gdecode_t result = GDE_NO_EVENT;
  if ( poll_debug_events )
  {
    // do we have something waiting?
    if ( irs_ready(client_irs, timeout_ms) > 0 )
    {
      verbev(("get_debug_event => remote has a packet for us\n"));
      // get the packet - it can RPC_EVENT or RPC_MSG/RPC_WARNING/RPC_ERROR
      bytevec_t empty;
      rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_DEBUG_EVENT, empty, PREQ_GET_EVENT);
      verbev(("get_debug_event => processed remote event, has=%d\n", has_pending_event));
      if ( rp != nullptr )
      {
        warning("rpc: event protocol error (rp=%p has_event=%d)", rp, has_pending_event);
        return GDE_ERROR;
      }
    }
  }
  else
  {
    verbev(("get_debug_event => first time, send GET_DEBUG_EVENT\n"));
    bytevec_t req = prepare_rpc_packet(RPC_GET_DEBUG_EVENT);
    req.pack_dd(timeout_ms);

    rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_DEBUG_EVENT, req);
    if ( rp == nullptr )
      return GDE_ERROR;
    memory_deserializer_t mmdsr(rp+1, rp->length);

    result = gdecode_t(mmdsr.unpack_dd());
    if ( result >= GDE_ONE_EVENT )
      extract_debug_event(event, mmdsr);
    else
      poll_debug_events = true;
    verbev(("get_debug_event => remote said %d, poll=%d now\n", result, poll_debug_events));
    qfree(rp);
  }
  return result;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_attach_process(pid_t _pid, int event_id, int flags, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_ATTACH_PROCESS);
  req.pack_dd(_pid);
  req.pack_dd(event_id);
  req.pack_dd(flags);
  return process_start_or_attach(req, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_prepare_to_pause_process(qstring *errbuf)
{
  return get_drc(RPC_PREPARE_TO_PAUSE_PROCESS, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_exit_process(qstring *errbuf)
{
  return get_drc(RPC_EXIT_PROCESS, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  bytevec_t req = prepare_rpc_packet(RPC_CONTINUE_AFTER_EVENT);
  append_debug_event(req, event);

  return send_request_get_drc_result(req, nullptr);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_stopped_at_debug_event(
        import_infos_t *,
        bool dlls_added,
        thread_name_vec_t *thr_names)
{
  bytevec_t req = prepare_rpc_packet(RPC_STOPPED_AT_DEBUG_EVENT);
  req.pack_db(dlls_added);
  bool ask_thr_names = thr_names != nullptr;
  req.pack_db(ask_thr_names);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_STOPPED_AT_DEBUG_EVENT, req);
  if ( rp == nullptr )
    return;

  if ( ask_thr_names )
  {
    memory_deserializer_t mmdsr(rp+1, rp->length);
    uint32 n = mmdsr.unpack_dd();
    thr_names->resize(n);
    for ( uint32 i=0; i < n; ++i )
    {
      thread_name_t &tn = (*thr_names)[i];
      tn.tid  = mmdsr.unpack_dd();
      tn.name = mmdsr.unpack_str();
    }
  }

  qfree(rp);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return get_drc_int(RPC_TH_SUSPEND, tid);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_thread_continue(thid_t tid)
{
  return get_drc_int(RPC_TH_CONTINUE, tid);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  bytevec_t req = prepare_rpc_packet(RPC_SET_RESUME_MODE);
  req.pack_dd(tid);
  req.pack_dd(resmod);

  return send_request_get_drc_result(req, nullptr);
}

//--------------------------------------------------------------------------
// prepare bitmap of registers belonging to the specified classes
// return size of the bitmap in bits (always the total number of registers)
static int calc_regmap(bytevec_t *regmap, int clsmask)
{
  int nregs = debugger.nregisters;
  regmap->resize((nregs+7)/8, 0);
  for ( int i=0; i < nregs; i++ )
    if ( (debugger.regs(i).register_class & clsmask) != 0 )
      regmap->set_bit(i);
  return nregs;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_read_registers(
        thid_t tid,
        int clsmask,
        regval_t *values,
        qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_READ_REGS);
  req.pack_dd(tid);
  req.pack_dd(clsmask);
  // append additional information about the class structure
  bytevec_t regmap;
  int n_regs = calc_regmap(&regmap, clsmask);
  req.pack_dd(n_regs);
  req.append(regmap.begin(), regmap.size());

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_READ_REGS, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  if ( drc == DRC_OK )
    unpack_regvals(values, n_regs, regmap.begin(), mmdsr);
  else if ( errbuf != nullptr )
    *errbuf = mmdsr.unpack_str();
  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_write_register(
        thid_t tid,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_REG);
  req.pack_dd(tid);
  req.pack_dd(reg_idx);
  append_regvals(req, value, 1, nullptr);

  return send_request_get_drc_result(req, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_get_memory_info(meminfo_vec_t &areas, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_MEMORY_INFO);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_MEMORY_INFO, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = drc_t(mmdsr.unpack_dd() + DRC_IDBSEG);
  if ( drc > DRC_NONE )
  {
    int n = mmdsr.unpack_dd();
    areas.resize(n);
    for ( int i=0; i < n; i++ )
      extract_memory_info(&areas[i], mmdsr);
  }
  else if ( errbuf != nullptr )
  {
    *errbuf = mmdsr.unpack_str();
  }
  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_get_scattered_image(scattered_image_t &si, ea_t base)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SCATTERED_IMAGE);
  req.pack_ea64(base);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_SCATTERED_IMAGE, req);
  if ( rp == nullptr )
    return false;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int result = mmdsr.unpack_dd() - 2;
  if ( result > 0 )
  {
    int n = mmdsr.unpack_dd();
    si.resize(n);
    for ( int i=0; i < n; i++ )
      extract_scattered_segm(&si[i], mmdsr);
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::dbg_get_image_uuid(bytevec_t *uuid, ea_t base)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_IMAGE_UUID);
  req.pack_ea64(base);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_IMAGE_UUID, req);
  if ( rp == nullptr )
    return false;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  bool result = mmdsr.unpack_dd() != 0;
  if ( result )
  {
    int n = mmdsr.unpack_dd();
    uuid->append(mmdsr.ptr, n);
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ea_t idaapi rpc_debmod_t::dbg_get_segm_start(ea_t base, const qstring &segname)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SEGM_START);
  req.pack_ea64(base);
  req.pack_str(segname.c_str());

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_GET_SEGM_START, req);
  if ( rp == nullptr )
    return false;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  ea_t result = mmdsr.unpack_ea64();
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_READ_MEMORY);
  req.pack_ea64(ea);
  req.pack_dd((uint32)size);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_READ_MEMORY, req);
  if ( rp == nullptr )
    return -1;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int result = mmdsr.unpack_dd();
  if ( result > 0 )
  {
    QASSERT(1205, result <= size);
    mmdsr.unpack_obj(buffer, result);
  }
  else if ( errbuf != nullptr )
  {
    *errbuf = mmdsr.unpack_str();
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_MEMORY);
  req.pack_ea64(ea);
  req.pack_buf(buffer, size);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_WRITE_MEMORY, req);
  if ( rp == nullptr )
    return -1;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int result = mmdsr.unpack_dd();
  if ( errbuf != nullptr && result <= 0 )
    *errbuf = mmdsr.unpack_str();
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_update_call_stack(thid_t tid, call_stack_t *trace)
{
  bytevec_t req = prepare_rpc_packet(RPC_UPDATE_CALL_STACK);
  req.pack_dd(tid);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_UPDATE_CALL_STACK, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  if ( drc == DRC_OK )
    extract_call_stack(trace, mmdsr);
  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
ea_t idaapi rpc_debmod_t::dbg_appcall(
        ea_t func_ea,
        thid_t tid,
        int stkarg_nbytes,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags)
{
  bytevec_t req = prepare_rpc_packet(RPC_APPCALL);
  req.pack_ea64(func_ea);
  req.pack_dd(tid);
  req.pack_dd(stkarg_nbytes);
  req.pack_dd(flags);
  regobjs_t *rr = (flags & APPCALL_MANUAL) == 0 ? retregs : nullptr;
  append_appcall(req, *regargs, *stkargs, rr);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_APPCALL, req);
  if ( rp == nullptr )
    return BADADDR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  ea_t sp = mmdsr.unpack_ea64();
  if ( sp == BADADDR )
  {
    if ( (flags & APPCALL_DEBEV) != 0 )
      extract_debug_event(event, mmdsr);
    if ( errbuf != nullptr )
      *errbuf = mmdsr.unpack_str();
  }
  else if ( (flags & APPCALL_MANUAL) == 0 )
  {
    if ( retregs != nullptr )
      extract_regobjs(retregs, true, mmdsr);
  }
  qfree(rp);
  return sp;
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_cleanup_appcall(thid_t tid)
{
  bytevec_t req = prepare_rpc_packet(RPC_CLEANUP_APPCALL);
  req.pack_dd(tid);
  return send_request_get_drc_result(req, nullptr);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_rexec(const char *cmdline)
{
  bytevec_t req = prepare_rpc_packet(RPC_REXEC);
  req.pack_str(cmdline);
  return send_request_get_long_result(req);
}

//--------------------------------------------------------------------------
drc_t idaapi rpc_debmod_t::dbg_bin_search(
        ea_t *pea,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring *errbuf)
{
  bytevec_t req = prepare_rpc_packet(RPC_BIN_SEARCH);
  req.pack_ea64(start_ea);
  req.pack_ea64(end_ea);
  // compiled_binpat_vec_t
  int sz = ptns.size();
  req.pack_dd(sz);
  for ( compiled_binpat_vec_t::const_iterator p=ptns.begin();
        p != ptns.end();
        ++p )
  { // compiled_binpat_t
    sz = p->bytes.size();
    req.pack_buf(p->bytes.begin(), sz);
    sz = p->mask.size();
    req.pack_buf(p->mask.begin(), sz);
    sz = p->strlits.size();
    req.pack_dd(sz);
    for ( int i=0; i < sz; ++i )
    {
      req.pack_ea64(p->strlits[i].start_ea);
      req.pack_ea64(p->strlits[i].end_ea);
    }
    req.pack_dd(p->encidx);
  }
  req.pack_dd(srch_flags);

  rpc_packet_t *rp = send_request_and_receive_reply(RPC_BIN_SEARCH, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  if ( drc == DRC_OK )
  {
    if ( pea != nullptr )
      *pea = mmdsr.unpack_ea64();
  }
  else if ( drc != DRC_FAILED )   // DRC_FAILED means not found
  {
    if ( errbuf != nullptr )
      *errbuf = mmdsr.unpack_str();
  }

  qfree(rp);
  return drc;
}

//--------------------------------------------------------------------------
drc_t rpc_debmod_t::close_remote()
{
  bytevec_t req = prepare_rpc_packet(RPC_OK);
  send_data(req);
  irs_term(&client_irs);
  network_error = false;
  return DRC_OK;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::get_system_specific_errno(void) const
{
  return irs_get_error(client_irs);
}

//-------------------------------------------------------------------------
drc_t rpc_debmod_t::process_start_or_attach(bytevec_t &req, qstring *errbuf)
{
  rpc_packet_t *rp = (rpc_packet_t *)req.begin();
  rp = send_request_and_receive_reply(rp->code, req);
  if ( rp == nullptr )
    return DRC_NETERR;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  drc_t drc = unpack_drc(mmdsr);
  if ( drc > DRC_NONE )
  {
    extract_debapp_attrs(&debapp_attrs, mmdsr);
    extract_dynamic_register_set(&idaregs, mmdsr);
  }
  else if ( errbuf != nullptr )
  {
    *errbuf = mmdsr.unpack_str();
  }
  qfree(rp);
  return drc;
}
