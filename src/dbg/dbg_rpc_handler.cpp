#include <limits.h>

#include <pro.h>
#include <typeinf.hpp>
#include <diskio.hpp>
#include <network.hpp>      // otherwise cannot compile win32_remote.bpr
#include <err.h>

#include "server.h"

//--------------------------------------------------------------------------
// another copy of this function (for local debugging) is defined in common_local_impl.cpp
int send_ioctl(
        rpc_engine_t *srv,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return srv->send_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
AS_PRINTF(3, 0) ssize_t dvmsg(int code, rpc_engine_t *rpc, const char *format, va_list va)
{
  if ( code == 0 )
    code = RPC_MSG;
  else if ( code > 0 )
    code = RPC_WARNING;
  else
    code = RPC_ERROR;

  bytevec_t req = prepare_rpc_packet((uchar)code);

  char buf[MAXSTR];
  qvsnprintf(buf, sizeof(buf), format, va);
  req.pack_str(buf);

  qfree(rpc->send_request_and_receive_reply((uchar)code, req));
  if ( code == RPC_ERROR )
    exit(1);
  return strlen(buf);
}

//--------------------------------------------------------------------------
void report_idc_error(rpc_engine_t *rpc, ea_t ea, error_t code, ssize_t errval, const char *errprm)
{
  if ( code == eOS )
  {
    dbg_rpc_handler_t *h = (dbg_rpc_handler_t *)rpc;
    errval = h->get_debugger_instance()->get_system_specific_errno();
  }

  bytevec_t req = prepare_rpc_packet(RPC_REPORT_IDC_ERROR);
  req.pack_ea64(ea);
  req.pack_dd(code);
  if ( (const char *)errval == errprm )
  {
    req.pack_db(1);
    req.pack_str(errprm);
  }
  else
  {
    req.pack_db(0);
    req.pack_ea64(errval);
  }
  qfree(rpc->send_request_and_receive_reply(RPC_REPORT_IDC_ERROR, req));
}

//--------------------------------------------------------------------------
debmod_t *dbg_rpc_handler_t::get_debugger_instance()
{
  return dbg_mod;   //lint !e1535 !e1536 exposes lower access member
}

//--------------------------------------------------------------------------
void dbg_rpc_handler_t::prepare_broken_connection(void)
{
  if ( debmod_t::reuse_broken_connections )
  {
    if ( !dbg_mod->dbg_prepare_broken_connection() )
      dmsg("Error preparing debugger server to handle a broken connection\n");
  }
}

//--------------------------------------------------------------------------
//                        dbg_rpc_handler_t
//--------------------------------------------------------------------------
dbg_rpc_handler_t::dbg_rpc_handler_t(
        idarpc_stream_t *_irs,
        dbgsrv_dispatcher_t *_dispatcher)
  : network_client_handler_t(_irs, /*_verbose=*/ false),
    dbg_rpc_engine_t(/*is_client=*/ false),
    dbg_mod(nullptr),
    dispatcher(_dispatcher)
{
  clear_channels(); //lint -esym(1566,dbg_rpc_handler_t::channels) not inited
  struct ida_local lambda_t
  {
    static int ioctl(rpc_engine_t *rpc, int fn, const void *buf, size_t size, void **out, ssize_t *outsz)
    {
      dbg_rpc_handler_t *serv = (dbg_rpc_handler_t *) rpc;
      memory_deserializer_t mmdsr(buf, size);
      if ( fn >= MIN_SERVER_IOCTL )
        return serv->handle_server_ioctl(fn, out, outsz, mmdsr);
      else
        return serv->get_debugger_instance()->handle_ioctl(fn, buf, size, out, outsz);
    }

    static progress_loop_ctrl_t recv_data_iter(bool, size_t, size_t, void *ud)
    {
      dbg_rpc_handler_t *eng = (dbg_rpc_handler_t *) ud;
      bool performed = false;
      int code = eng->on_recv_packet_progress(&performed);
      if ( performed )
        return code == 0 ? plc_skip_iter : plc_cancel;
      else
        return plc_proceed;
    }
  };

  set_ioctl_handler(lambda_t::ioctl);
  irs_set_progress_cb(irs, 100, lambda_t::recv_data_iter, this);
}

//--------------------------------------------------------------------------
dbg_rpc_handler_t::~dbg_rpc_handler_t()
{
  //lint -e(1506) Call to virtual function 'dbg_rpc_handler_t::get_broken_connection(void)' within a constructor or destructor
  if ( !get_broken_connection() )
    delete dbg_mod; // the connection is not broken, delete the debugger instance

  //lint -esym(1579,dbg_rpc_handler_t::dbg_mod) pointer member might have been freed by a separate function
  clear_channels();

  dispatcher = nullptr;
}

//------------------------------------------------------------------------
// Function safe against time slicing attack, comparing time depends only on str length
static bool password_matches(const char *str, const char *pass)
{
  if ( str == nullptr )
    return false;
  int str_length = strlen(str);
  int pass_length = strlen(pass);
  int res = str_length ^ pass_length;
  if ( pass_length != 0 )
  {
    for ( int i = 0; i < str_length; i++ )
      res |= (pass[i % pass_length] ^ str[i]);
  }
  return res == 0;
}

//-------------------------------------------------------------------------
bool dbg_rpc_handler_t::handle()
{
  bytevec_t req = prepare_rpc_packet(RPC_OPEN);
  req.pack_dd(IDD_INTERFACE_VERSION);
  req.pack_dd(DEBUGGER_ID);
  req.pack_dd(sizeof(ea_t));

  bool send_response = false;
  rpc_packet_t *rp = send_request_and_receive_reply(RPC_OPEN, req, 0);
  bool ok = rp != nullptr;
  if ( ok )
  {
    send_response = true;

    // Answer is after rpc_packet_t
    memory_deserializer_t mmdsr(rp+1, rp->length);
    ok = mmdsr.unpack_dd() != 0;
    if ( !ok )
    {
      lprintf("[%d] Incompatible IDA version\n", session_id);
      send_response = false;
    }
    else if ( !dispatcher->server_password.empty() )
    {
      const char *pass = mmdsr.unpack_str();
      if ( !password_matches(pass, dispatcher->server_password.c_str()) )
      {
        lprintf("[%d] Bad password\n", session_id);
        ok = false;
      }
    }
    logged_in = ok;

    qfree(rp);
  }
  else
  {
    lprintf("[%d] Could not establish the connection\n", session_id);
  }

  if ( send_response )
  {
    req = prepare_rpc_packet(RPC_OK);
    req.pack_dd(ok);
    send_data(req);

    // remove reception timeout on the server side
    recv_timeout = -1;
    logged_in = true;

    if ( ok )
    {
      // the main loop: handle client requests until it drops the connection
      // or sends us RPC_OK (see rpc_debmod_t::close_remote)
      bytevec_t empty;
      rpc_packet_t *packet = send_request_and_receive_reply(RPC_OPEN, empty);
      if ( packet != nullptr )
        qfree(packet);
    }
  }
  network_error = false;

  bool preserve_server = false;
  if ( get_broken_connection() )
  {
    lprintf("[%d] Broken connection (mode=%d)\n",
            session_id, dispatcher->on_broken_conn);
    if ( dispatcher->on_broken_conn == BCH_KEEP_DEBMOD )
    {
      term_irs();
      lprintf("[%d] Debugged session entered into sleeping mode\n", session_id);
      prepare_broken_connection();
      preserve_server = true;
    }
    else
    {
      if ( dispatcher->on_broken_conn == BCH_KILL_PROCESS )
      {
        int pid = get_debugger_instance()->pid;
        lprintf("[%d] Debugged process PID: %d\n", session_id, pid);
        if ( pid > 0 )
        {
          lprintf("[%d] Killing debugged process %d\n",
                  session_id, get_debugger_instance()->pid);
          int code = kill_process();
          if ( code != 0 )
            lprintf("[%d] Failed to kill process after %d seconds. Giving up\n",
                    session_id, code);
        }
      }
      goto TERM_DEBMOD;
    }
  }
  else
  {
TERM_DEBMOD:
    get_debugger_instance()->dbg_term();
    term_irs();
  }

  return !preserve_server;
}

//--------------------------------------------------------------------------
void dbg_rpc_handler_t::set_debugger_instance(debmod_t *instance)
{
  dbg_mod = instance;
  dbg_mod->rpc = this;
}

//--------------------------------------------------------------------------
#ifdef VERBOSE_ENABLED
static const char *bptcode2str(uint code)
{
  static const char *const strs[] =
  {
    "BPT_OK",
    "BPT_INTERNAL_ERR",
    "BPT_BAD_TYPE",
    "BPT_BAD_ALIGN",
    "BPT_BAD_ADDR",
    "BPT_BAD_LEN",
    "BPT_TOO_MANY",
    "BPT_READ_ERROR",
    "BPT_WRITE_ERROR",
    "BPT_SKIP",
    "BPT_PAGE_OK",
  };
  if ( code >= qnumber(strs) )
    return "?";
  return strs[code];
}
#endif

//--------------------------------------------------------------------------
int dbg_rpc_handler_t::rpc_update_bpts(bytevec_t &req, memory_deserializer_t &mmdsr)
{
  update_bpt_vec_t bpts;
  int nadd = mmdsr.unpack_dd();
  int ndel = mmdsr.unpack_dd();

  if ( nadd < 0 || ndel < 0 || INT_MAX - ndel < nadd )
  {
    req.pack_dd(0);
    verb(("update_bpts(nadd=%d, ndel=%d) => 0 (incorrect values)\n", nadd, ndel));
    return 0;
  }

  bpts.resize(nadd+ndel);
  ea_t ea = 0;
  update_bpt_vec_t::iterator b;
  update_bpt_vec_t::iterator bend = bpts.begin() + nadd;
  for ( b=bpts.begin(); b != bend; ++b )
  {
    b->code = BPT_OK;
    b->ea = ea + mmdsr.unpack_ea64(); ea = b->ea;
    b->size = mmdsr.unpack_dd();
    b->type = mmdsr.unpack_dd();
    b->pid  = mmdsr.unpack_dd();
    b->tid  = mmdsr.unpack_dd();
  }

  ea = 0;
  bend += ndel;
  for ( ; b != bend; ++b )
  {
    b->ea = ea + mmdsr.unpack_ea64(); ea = b->ea;
    uchar len = mmdsr.unpack_db();
    if ( len > 0 )
    {
      b->orgbytes.resize(len);
      mmdsr.unpack_obj(b->orgbytes.begin(), len);
    }
    b->type = mmdsr.unpack_dd();
    b->pid  = mmdsr.unpack_dd();
    b->tid  = mmdsr.unpack_dd();
  }

#ifdef VERBOSE_ENABLED
  for ( b=bpts.begin()+nadd; b != bend; ++b )
    verb(("del_bpt(ea=%a, type=%d orgbytes.size=%" FMT_Z " size=%d)\n",
          b->ea, b->type, b->orgbytes.size(), b->type != BPT_SOFT ? b->size : 0));
#endif

  int nbpts;
  qstring errbuf;
  drc_t drc = dbg_mod->dbg_update_bpts(&nbpts, bpts.begin(), nadd, ndel, &errbuf);

  bend = bpts.begin() + nadd;
#ifdef VERBOSE_ENABLED
  for ( b=bpts.begin(); b != bend; ++b )
    verb(("add_bpt(ea=%a type=%d len=%d) => %s\n", b->ea, b->type, b->size, bptcode2str(b->code)));
#endif

  req.pack_dd(drc);
  req.pack_dd(nbpts);
  for ( b=bpts.begin(); b != bend; ++b )
  {
    req.pack_db(b->code);
    if ( b->code == BPT_OK && b->type == BPT_SOFT )
    {
      req.pack_db(b->orgbytes.size());
      req.append(b->orgbytes.begin(), b->orgbytes.size());
    }
  }

  bend += ndel;
  for ( ; b != bend; ++b )
  {
    req.pack_db(b->code);
    verb(("del_bpt(ea=%a) => %s\n", b->ea, bptcode2str(b->code)));
  }

  if ( drc != DRC_OK )
    req.pack_str(errbuf);
  return drc;
}

//--------------------------------------------------------------------------
void dbg_rpc_handler_t::rpc_update_lowcnds(
        bytevec_t &req,
        memory_deserializer_t &mmdsr)
{
  ea_t ea = 0;
  lowcnd_vec_t lowcnds;
  int nlowcnds = mmdsr.unpack_dd();
  lowcnds.resize(nlowcnds);
  lowcnd_t *lc = lowcnds.begin();
  for ( int i=0; i < nlowcnds; i++, lc++ )
  {
    lc->compiled = false;
    lc->ea = ea + mmdsr.unpack_ea64(); ea = lc->ea;
    lc->cndbody = mmdsr.unpack_str();
    if ( !lc->cndbody.empty() )
    {
      lc->size = 0;
      lc->type = mmdsr.unpack_dd();
      if ( lc->type != BPT_SOFT )
        lc->size = mmdsr.unpack_dd();
      int norg = mmdsr.unpack_db();
      if ( norg > 0 )
      {
        lc->orgbytes.resize(norg);
        mmdsr.unpack_obj(lc->orgbytes.begin(), norg);
      }
      lc->cmd.ea = mmdsr.unpack_ea64();
      if ( lc->cmd.ea != BADADDR )
        extract_insn(&lc->cmd, mmdsr);
    }
    verb(("update_lowcnd(ea=%a cnd=%s)\n", ea, lc->cndbody.c_str()));
  }
  int nupdated;
  qstring errbuf;
  drc_t drc = dbg_mod->dbg_update_lowcnds(&nupdated, lowcnds.begin(), nlowcnds, &errbuf);
  verb(("  update_lowcnds => %d\n", drc));

  req.pack_dd(drc);
  req.pack_dd(nupdated);
  if ( drc != DRC_OK )
    req.pack_str(errbuf);
}

//--------------------------------------------------------------------------
bool dbg_rpc_handler_t::check_broken_connection(pid_t pid)
{
  bool result = false;
  dispatcher->clients_list->lock();
  client_handlers_list_t::storage_t::iterator p;
  for ( p = dispatcher->clients_list->storage.begin();
        p != dispatcher->clients_list->storage.end();
        ++p )
  {
    dbg_rpc_handler_t *h = (dbg_rpc_handler_t *) p->first;
    if ( h == this )
      continue;

    debmod_t *d = h->get_debugger_instance();
    if ( d->broken_connection && d->pid == pid && d->dbg_continue_broken_connection(pid) )
    {
      dbg_mod->dbg_term();
      delete dbg_mod;
      dbg_mod = d;
      result = true;
      verb(("reusing previously broken debugging session\n"));

#ifndef __SINGLE_THREADED_SERVER__
      qthread_t thr = p->second;

      // free thread
      if ( thr != nullptr )
        qthread_free(thr);
#endif

      h->term_irs();
      dispatcher->clients_list->storage.erase(p);
      delete h;

      d->broken_connection = false;
      break;
    }
  }
  dispatcher->clients_list->unlock();
  return result;
}

//-------------------------------------------------------------------------
int dbg_rpc_handler_t::handle_server_ioctl(
        int fn,
        void **out,
        ssize_t *outsz,
        memory_deserializer_t &mmdsr)
{
  int code = -1;
  verb(("handle_server_ioctl(fn=%d, bufsize=%" FMT_Z ").\n", fn, mmdsr.size()));
  return code;
}

//-------------------------------------------------------------------------
int dbg_rpc_handler_t::on_recv_packet_progress(bool *performed)
{
  *performed = poll_debug_events;
  return poll_debug_events ? poll_events(TIMEOUT) : 0;
}

//--------------------------------------------------------------------------
drc_t dbg_rpc_handler_t::rpc_attach_process(
        qstring *errbuf,
        memory_deserializer_t &mmdsr)
{
  pid_t pid    = mmdsr.unpack_dd();
  int event_id = mmdsr.unpack_dd();
  int flags    = mmdsr.unpack_dd();
  drc_t drc = check_broken_connection(pid)
            ? DRC_OK
            : dbg_mod->dbg_attach_process(pid, event_id, flags, errbuf);
  verb(("attach_process(pid=%d, evid=%d) => %d\n", pid, event_id, drc));
  return drc;
}

//-------------------------------------------------------------------------
void dbg_rpc_handler_t::append_start_or_attach(bytevec_t &req, drc_t drc, const qstring &errbuf) const
{
  req.pack_dd(drc);
  if ( drc > DRC_NONE )
  {
    debapp_attrs_t attrs;
    dbg_mod->dbg_get_debapp_attrs(&attrs);
    append_debapp_attrs(req, attrs);
    append_dynamic_register_set(req, dbg_mod->idaregs);
  }
  else
  {
    req.pack_str(errbuf);
  }
}

//-------------------------------------------------------------------------
void dbg_rpc_handler_t::shutdown_gracefully(int /*signum*/)
{
  debmod_t *d = get_debugger_instance();
  if ( d != nullptr )
    d->dbg_exit_process(nullptr); // kill the process instead of letting it run in wild
}

//--------------------------------------------------------------------------
// performs requests on behalf of a remote client
// client -> server
#ifdef __UNIX__
#  define IS_SUBPATH strneq
#else
#  define IS_SUBPATH strnieq
#endif
bytevec_t dbg_rpc_handler_t::on_send_request_interrupt(const rpc_packet_t *rp)
{
  // While the server is performing a request, it should not poll
  // for debugger events
  bool saved_poll_mode = poll_debug_events;
  poll_debug_events = false;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  bytevec_t req = prepare_rpc_packet(RPC_OK);
#if defined(__EXCEPTIONS) || defined(__NT__)
  try
#endif
  {
    switch ( rp->code )
    {
      case RPC_INIT:
        {
          dbg_mod->debugger_flags = mmdsr.unpack_dd();
          bool debug_debugger = mmdsr.unpack_dd() != 0;
          if ( debug_debugger )
            verbose = true;

          dbg_mod->dbg_set_debugging(debug_debugger);
          qstring errbuf;
          uint32_t flags2 = 0;
          drc_t drc = dbg_mod->dbg_init(&flags2, &errbuf);
          verb(("init(debug_debugger=%d) => %d (flags2=%d)\n", debug_debugger, drc, flags2));
          req.pack_dd(drc);
          req.pack_dd(flags2);
          if ( drc != DRC_OK )
            req.pack_str(errbuf);
        }
        break;

      case RPC_TERM:
        // Do not dbg_term() here, as it will be called
        // at the end of server.cpp's handle_single_session(),
        // right after this.
        // dbg_mod->dbg_term();
        // verb(("term()\n"));
        break;

      case RPC_GET_PROCESSES:
        {
          procinfo_vec_t procs;
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_get_processes(&procs, &errbuf);
          req.pack_dd(drc);
          if ( drc == DRC_OK )
            append_process_info_vec(req, &procs);
          else
            req.pack_str(errbuf);
          verb(("get_processes() => %d\n", drc));
        }
        break;

      case RPC_DETACH_PROCESS:
        {
          drc_t drc = dbg_mod->dbg_detach_process();
          req.pack_dd(drc);
          verb(("detach_process() => %d\n", drc));
        }
        break;

      case RPC_START_PROCESS:
        {
          const char *path  = mmdsr.unpack_str();
          const char *args  = mmdsr.unpack_str();
          const char *sdir  = mmdsr.unpack_str();
          int flags         = mmdsr.unpack_dd();
          const char *input = mmdsr.unpack_str();
          uint32 crc32      = mmdsr.unpack_dd();
          qstring errbuf;

          launch_env_t envs;
          envs.merge = mmdsr.unpack_db() != 0;
          int envs_size = mmdsr.unpack_dd();
          for ( int i = 0; i < envs_size && !mmdsr.empty(); ++i )
            mmdsr.unpack_str(&envs.push_back());

          drc_t drc = DRC_NOFILE;
          if ( path != nullptr && sdir != nullptr && input != nullptr ) // protect against malicious ida
          {
            drc = dbg_mod->dbg_start_process(path, args, &envs, sdir, flags, input, crc32, &errbuf);
            verb(("start_process(path=%s args=%s flags=%s%s%s\n"
              "              sdir=%s\n"
              "              input=%s crc32=%x) => %d\n",
              path, args,
              flags & DBG_PROC_IS_DLL ? " is_dll" : "",
              flags & DBG_PROC_IS_GUI ? " under_gui" : "",
              flags & DBG_HIDE_WINDOW ? " hide_window" : "",
              sdir,
              input, crc32,
              drc));
          }
          append_start_or_attach(req, drc, errbuf);
        }
        break;

      case RPC_GET_DEBUG_EVENT:
        {
          int timeout_ms = mmdsr.unpack_dd();
          gdecode_t result = GDE_NO_EVENT;
          if ( !has_pending_event )
            result = dbg_mod->dbg_get_debug_event(&ev, timeout_ms);
          req.pack_dd(result);
          if ( result >= GDE_ONE_EVENT )
          {
            append_debug_event(req, &ev);
            verb(("got event: %s\n", debug_event_str(&ev)));
          }
          else if ( !has_pending_event )
          {
            saved_poll_mode = true;
          }
          verbev(("get_debug_event(timeout=%d) => %d (has_pending=%d, willpoll=%d)\n", timeout_ms, result, has_pending_event, saved_poll_mode));
        }
        break;

      case RPC_ATTACH_PROCESS:
        {
          qstring errbuf;
          append_start_or_attach(req, rpc_attach_process(&errbuf, mmdsr), errbuf);
        }
        break;

      case RPC_PREPARE_TO_PAUSE_PROCESS:
        {
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_prepare_to_pause_process(&errbuf);
          verb(("prepare_to_pause_process() => %d\n", drc));
          req.pack_dd(drc);
          if ( drc < DRC_NONE )
            req.pack_str(errbuf);
        }
        break;

      case RPC_EXIT_PROCESS:
        {
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_exit_process(&errbuf);
          verb(("exit_process() => %d\n", drc));
          req.pack_dd(drc);
          if ( drc < DRC_NONE )
            req.pack_str(errbuf);
        }
        break;

      case RPC_CONTINUE_AFTER_EVENT:
        {
          extract_debug_event(&ev, mmdsr);
          drc_t drc = dbg_mod->dbg_continue_after_event(&ev);
          verb(("continue_after_event(...) => %d\n", drc));
          req.pack_dd(drc);
        }
        break;

      case RPC_STOPPED_AT_DEBUG_EVENT:
        {
          bool dlls_added    = mmdsr.unpack_db() != 0;
          bool ask_thr_names = mmdsr.unpack_db() != 0;
          import_infos_t infos;
          thread_name_vec_t thr_names;
          dbg_mod->dbg_stopped_at_debug_event(&infos, dlls_added, ask_thr_names ? &thr_names : nullptr);
          process_import_requests(infos);
          name_info_t *ni = dbg_mod->get_debug_names();
          int err = RPC_OK;
          if ( ni != nullptr )
          {
            err = send_debug_names_to_ida(ni->addrs.begin(), ni->names.begin(), (int)ni->addrs.size());
            dbg_mod->clear_debug_names();
          }
          if ( ask_thr_names )
          {
            uint32 n = thr_names.size();
            req.pack_dd(n);
            for ( int i=0; i < n; ++i )
            {
              thread_name_t &tn = thr_names[i];
              req.pack_dd(tn.tid);
              req.pack_str(tn.name);
            }
          }
        }
        break;

      case RPC_TH_SUSPEND:
        {
          thid_t tid = mmdsr.unpack_dd();
          drc_t drc = dbg_mod->dbg_thread_suspend(tid);
          verb(("thread_suspend(tid=%d) => %d\n", tid, drc));
          req.pack_dd(drc);
        }
        break;

      case RPC_TH_CONTINUE:
        {
          thid_t tid = mmdsr.unpack_dd();
          drc_t drc = dbg_mod->dbg_thread_continue(tid);
          verb(("thread_continue(tid=%d) => %d\n", tid, drc));
          req.pack_dd(drc);
        }
        break;

      case RPC_SET_RESUME_MODE:
        {
          thid_t tid = mmdsr.unpack_dd();
          resume_mode_t resmod = resume_mode_t(mmdsr.unpack_dd());
          drc_t drc = dbg_mod->dbg_set_resume_mode(tid, resmod);
          verb(("set_resume_mode(tid=%d, resmod=%d) => %d\n", tid, resmod, drc));
          req.pack_dd(drc);
        }
        break;

      case RPC_READ_REGS:
        {
          drc_t drc = DRC_NONE;
          qstring errbuf;
          bytevec_t regmap;
          regvals_t values;
          thid_t tid  = mmdsr.unpack_dd();
          int clsmask = mmdsr.unpack_dd();
          int nregs   = mmdsr.unpack_dd();
          int debmod_nregs = dbg_mod->nregs();
          if ( nregs <= 0 || nregs > debmod_nregs )
          {
            errbuf.sprnt("read_regs(tid=%d, mask=%x, nregs=%d) => 0 "
                         "(incorrect nregs, should be in range 0..%d)\n",
                         tid, clsmask, nregs, debmod_nregs);
          }
          else
          {
            regmap.resize((nregs+7)/8);
            mmdsr.unpack_obj(regmap.begin(), regmap.size());
            values.resize(debmod_nregs);
            drc = dbg_mod->dbg_read_registers(tid, clsmask, values.begin(), &errbuf);
            verb(("read_regs(tid=%d, mask=%x) => %d\n", tid, clsmask, drc));
          }
          req.pack_dd(drc);
          if ( drc == DRC_OK )
            append_regvals(req, values.begin(), nregs, regmap.begin());
          else
            req.pack_str(errbuf);
        }
        break;

      case RPC_WRITE_REG:
        {
          thid_t tid  = mmdsr.unpack_dd();
          int reg_idx = mmdsr.unpack_dd();
          regval_t value;
          unpack_regvals(&value, 1, nullptr, mmdsr);
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_write_register(tid, reg_idx, &value, &errbuf);
          verb(("write_reg(tid=%d) => %d\n", tid, drc));
          req.pack_dd(drc);
          if ( drc < DRC_NONE )
            req.pack_str(errbuf);
        }
        break;

      case RPC_GET_SREG_BASE:
        {
          thid_t tid     = mmdsr.unpack_dd();
          int sreg_value = mmdsr.unpack_dd();
          ea_t ea;
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_thread_get_sreg_base(&ea, tid, sreg_value, &errbuf);
          verb(("get_thread_sreg_base(tid=%d, %d) => %a\n", tid, sreg_value, drc == DRC_OK ? ea : BADADDR));
          req.pack_dd(drc);
          if ( drc == DRC_OK )
            req.pack_ea64(ea);
          else
            req.pack_str(errbuf);
        }
        break;

      case RPC_SET_EXCEPTION_INFO:
        {
          int qty = mmdsr.unpack_dd();
          exception_info_t *extable = extract_exception_info(qty, mmdsr);
          dbg_mod->dbg_set_exception_info(extable, qty);
          delete [] extable;
          verb(("set_exception_info(qty=%d)\n", qty));
        }
        break;

      case RPC_GET_MEMORY_INFO:
        {
          meminfo_vec_t areas;
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_get_memory_info(areas, &errbuf);
          int qty = areas.size();
          verb(("get_memory_info() => %d (qty=%d)\n", drc, qty));
          req.pack_dd(drc + (-DRC_IDBSEG));
          if ( drc == DRC_OK )
          {
            req.pack_dd(qty);
            for ( int i=0; i < qty; i++ )
              append_memory_info(req, &areas[i]);
          }
          else
          {
            req.pack_str(errbuf);
          }
        }
        break;

      case RPC_GET_SCATTERED_IMAGE:
        {
          ea_t base = mmdsr.unpack_ea64();
          scattered_image_t si;
          int result = dbg_mod->dbg_get_scattered_image(si, base);
          int qty = si.size();
          verb(("get_scattered_image(base=%a) => %d (qty=%d)\n", base, result, qty));
          req.pack_dd(result+2);
          if ( result > 0 )
          {
            req.pack_dd(qty);
            for ( int i=0; i < qty; i++ )
              append_scattered_segm(req, &si[i]);
          }
        }
        break;

      case RPC_GET_IMAGE_UUID:
        {
          ea_t base = mmdsr.unpack_ea64();
          bytevec_t uuid;
          bool result = dbg_mod->dbg_get_image_uuid(&uuid, base);
          int size = uuid.size();
          verb(("get_image_uuid(base=%a) => %d (size=%d)\n", base, result, size));
          req.pack_dd(result);
          if ( result )
            req.pack_buf(uuid.begin(), size);
        }
        break;

      case RPC_GET_SEGM_START:
        {
          ea_t base = mmdsr.unpack_ea64();
          const char *segname = mmdsr.unpack_str();
          ea_t result = dbg_mod->dbg_get_segm_start(base, segname);
          verb(("get_segm_start(base=%a, segname=%s) => %a\n", base, segname, result));
          req.pack_ea64(result);
        }
        break;

      case RPC_READ_MEMORY:
        {
          ea_t ea     = mmdsr.unpack_ea64();
          size_t size = mmdsr.unpack_dd();
          uchar *buf = new uchar[size];
          qstring errbuf;
          ssize_t result = dbg_mod->dbg_read_memory(ea, buf, size, &errbuf);
          verb(("read_memory(ea=%a size=%" FMT_Z ") => %" FMT_ZS, ea, size, result));
          if ( result > 0 && size == 1 )
            verb((" (0x%02X)\n", *buf));
          else
            verb(("\n"));
          req.pack_dd(uint32(result));
          if ( result > 0 )
            req.append(buf, result);
          else
            req.pack_str(errbuf);
          delete[] buf;
        }
        break;

      case RPC_WRITE_MEMORY:
        {
          ea_t ea     = mmdsr.unpack_ea64();
          size_t size = mmdsr.unpack_dd();
          uchar *buf = new uchar[size];
          mmdsr.unpack_obj(buf, size);
          qstring errbuf;
          ssize_t result = dbg_mod->dbg_write_memory(ea, buf, size, &errbuf);
          verb(("write_memory(ea=%a size=%" FMT_Z ") => %" FMT_ZS, ea, size, result));
          if ( result && size == 1 )
            verb((" (0x%02X)\n", *buf));
          else
            verb(("\n"));
          req.pack_dd(uint32(result));
          if ( result <= 0 )
            req.pack_str(errbuf);
          delete[] buf;
        }
        break;

      case RPC_ISOK_BPT:
        {
          bpttype_t type = mmdsr.unpack_dd();
          ea_t ea        = mmdsr.unpack_ea64();
          int len        = mmdsr.unpack_dd() - 1;
          int result = dbg_mod->dbg_is_ok_bpt(type, ea, len);
          verb(("isok_bpt(type=%d ea=%a len=%d) => %d\n", type, ea, len, result));
          req.pack_dd(result);
        }
        break;

      case RPC_UPDATE_BPTS:
        {
          int ret = rpc_update_bpts(req, mmdsr);
          if ( ret == 0 )
            verb(("rpc_update_bpts failed!\n"));
        }
        break;

      case RPC_UPDATE_LOWCNDS:
        rpc_update_lowcnds(req, mmdsr);
        break;

      case RPC_EVAL_LOWCND:
        {
          thid_t tid = mmdsr.unpack_dd();
          ea_t ea    = mmdsr.unpack_ea64();
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_eval_lowcnd(tid, ea, &errbuf);
          req.pack_dd(drc);
          if ( drc != DRC_OK )
            req.pack_str(errbuf);
          verb(("eval_lowcnd(tid=%d, ea=%a) => %d\n", tid, ea, drc));
        }
        break;

      case RPC_OPEN_FILE:
        {
          const char *path = mmdsr.unpack_str();
          bool readonly = mmdsr.unpack_dd() != 0;
          int64 fsize = 0;
          int fn = find_free_channel();
          if ( fn != -1 )
          {
            if ( readonly )
            {
              channels[fn] = fopenRB(path);
            }
            else
            {
              char dir[QMAXPATH];
              if ( qdirname(dir, sizeof(dir), path) && !qisdir(dir) )
              {
                char absdir[QMAXPATH];
                qmake_full_path(absdir, sizeof(absdir), dir);
                char cwd[QMAXPATH];
                qgetcwd(cwd, sizeof(cwd));
                if ( IS_SUBPATH(absdir, cwd, qstrlen(cwd)) )
                {
                  qstrvec_t subpaths;
                  while ( !qisdir(absdir) )
                  {
                    subpaths.insert(subpaths.begin(), absdir);
                    if ( !qdirname(absdir, sizeof(absdir), absdir) )
                      break;
                  }
                  for ( size_t i = 0, n = subpaths.size(); i < n; ++i )
                  {
                    const char *subdir = subpaths[i].c_str();
                    verb(("open_file() creating directory %s\n", subdir));
                    if ( qmkdir(subdir, 0777) != 0 )
                      break;
                  }
                }
              }
              channels[fn] = fopenWB(path);
            }
            if ( channels[fn] == nullptr )
              fn = -1;
            else if ( readonly )
              fsize = qfsize(channels[fn]);
          }
          verb(("open_file('%s', %d) => %d %" FMT_64 "d\n", path, readonly, fn, fsize));
          req.pack_dd(fn);
          if ( fn != -1 )
            req.pack_dq(fsize);
          else
            req.pack_dd(errno);
        }
        break;

      case RPC_CLOSE_FILE:
        {
          int fn = mmdsr.unpack_dd();
          if ( fn >= 0 && fn < qnumber(channels) )
          {
            FILE *fp = channels[fn];
            if ( fp != nullptr )
            {
#ifdef __UNIX__
              fchmod(fileno(fp), 0755); // set mode 0755 for unix applications
#endif
              qfclose(fp);
              channels[fn] = nullptr;
            }
          }
          verb(("close_file(%d)\n", fn));
        }
        break;

      case RPC_READ_FILE:
        {
          char *buf  = nullptr;
          int fn     = mmdsr.unpack_dd();
          int64 off  = mmdsr.unpack_dq();
          int32 size = mmdsr.unpack_dd();
          int32 s2 = 0;
          if ( size > 0 )
          {
            buf = new char[size];
            qfseek(channels[fn], off, SEEK_SET);
            s2 = qfread(channels[fn], buf, size);
          }
          req.pack_dd(s2);
          if ( size != s2 )
            req.pack_dd(errno);
          else
            req.append(buf, s2);
          delete[] buf;
          verb(("read_file(%d, 0x%" FMT_64 "X, %d) => %d\n", fn, off, size, s2));
        }
        break;

      case RPC_WRITE_FILE:
        {
          char *buf = nullptr;
          int fn      = mmdsr.unpack_dd();
          uint64 off  = mmdsr.unpack_dq();
          uint32 size = mmdsr.unpack_dd();
          if ( size > 0 )
          {
            buf = new char[size];
            mmdsr.unpack_obj(buf, size);
          }
          qfseek(channels[fn], off, SEEK_SET);
          uint32 s2 = buf == nullptr ? 0 : qfwrite(channels[fn], buf, size);
          req.pack_dd(size);
          if ( size != s2 )
            req.pack_dd(errno);
          delete [] buf;
          verb(("write_file(%d, 0x%" FMT_64 "X, %u) => %u\n", fn, off, size, s2));
        }
        break;

      case RPC_EVOK:
        req.clear();
        verbev(("got evok!\n"));
        break;

      case RPC_IOCTL:
        {
          int code = handle_ioctl_packet(req, mmdsr.ptr, mmdsr.end);
          if ( code != RPC_OK )
            req = prepare_rpc_packet((uchar)code);
        }
        break;

      case RPC_UPDATE_CALL_STACK:
        {
          call_stack_t trace;
          thid_t tid = mmdsr.unpack_dd();
          drc_t drc = dbg_mod->dbg_update_call_stack(tid, &trace);
          req.pack_dd(drc);
          if ( drc == DRC_OK )
            append_call_stack(req, trace);
        }
        break;

      case RPC_APPCALL:
        {
          ea_t func_ea      = mmdsr.unpack_ea64();
          thid_t tid        = mmdsr.unpack_dd();
          int stkarg_nbytes = mmdsr.unpack_dd();
          int flags         = mmdsr.unpack_dd();

          regobjs_t regargs, retregs;
          relobj_t stkargs;
          regobjs_t *rr = (flags & APPCALL_MANUAL) == 0 ? &retregs : nullptr;
          extract_appcall(&regargs, &stkargs, rr, mmdsr);

          qstring errbuf;
          debug_event_t event;
          ea_t sp = dbg_mod->dbg_appcall(func_ea, tid, stkarg_nbytes, &regargs, &stkargs,
                                          &retregs, &errbuf, &event, flags);
          req.pack_ea64(sp);
          if ( sp == BADADDR )
          {
            if ( (flags & APPCALL_DEBEV) != 0 )
              append_debug_event(req, &event);
            req.pack_str(errbuf);
          }
          else if ( (flags & APPCALL_MANUAL) == 0 )
          {
            append_regobjs(req, retregs, true);
          }
        }
        break;

      case RPC_CLEANUP_APPCALL:
        {
          thid_t tid = mmdsr.unpack_dd();
          drc_t drc = dbg_mod->dbg_cleanup_appcall(tid);
          req.pack_dd(drc);
        }
        break;

      case RPC_REXEC:
        {
          const char *cmdline = mmdsr.unpack_str();
          int code = dbg_mod->dbg_rexec(cmdline);
          req.pack_dd(code);
        }
        break;

      case RPC_BIN_SEARCH:
        {
          ea_t start_ea = mmdsr.unpack_ea64();
          ea_t end_ea   = mmdsr.unpack_ea64();
          int cnt       = mmdsr.unpack_dd();
          compiled_binpat_vec_t ptns;
          ptns.resize(cnt);
          for ( int i=0; i < cnt; ++i )
          {
            compiled_binpat_t &p = ptns[i];
            // bytes
            int sz = mmdsr.unpack_dd();
            if ( sz != 0 )
            {
              p.bytes.resize(sz);
              mmdsr.unpack_obj(p.bytes.begin(), sz);
            }
            // mask
            sz = mmdsr.unpack_dd();
            if ( sz != 0 )
            {
              p.mask.resize(sz);
              mmdsr.unpack_obj(p.mask.begin(), sz);
            }
            // strlits
            sz = mmdsr.unpack_dd();
            p.strlits.resize(sz);
            for ( int j=0; j < sz; ++j )
            {
              p.strlits[j].start_ea = mmdsr.unpack_ea64();
              p.strlits[j].end_ea   = mmdsr.unpack_ea64();
            }
            // encidx
            p.encidx = mmdsr.unpack_dd();
          }
          int srch_flags = mmdsr.unpack_dd();
          ea_t srch_ea;
          qstring errbuf;
          drc_t drc = dbg_mod->dbg_bin_search(&srch_ea, start_ea, end_ea, ptns, srch_flags, &errbuf);
          req.pack_dd(drc);
          if ( drc == DRC_OK )
            req.pack_ea64(srch_ea);
          else if ( drc != DRC_FAILED )   // DRC_FAILED means not found
            req.pack_str(errbuf);
        }
        break;

      default:
        req = prepare_rpc_packet(RPC_UNK);
        break;
    }
  }
#if defined(__EXCEPTIONS) || defined(__NT__)
  catch ( const std::bad_alloc & )
  {
    req = prepare_rpc_packet(RPC_MEM);
  }
#endif

  if ( saved_poll_mode )
    poll_debug_events = true;
  return req;
}

//--------------------------------------------------------------------------
// poll for events from the debugger module
int dbg_rpc_handler_t::poll_events(int timeout_ms)
{
  int code = 0;
  if ( !has_pending_event )
  {
    // immediately set poll_debug_events to false to avoid recursive calls.
    poll_debug_events = false;
    has_pending_event = dbg_mod->dbg_get_debug_event(&pending_event, timeout_ms) >= GDE_ONE_EVENT;
    if ( has_pending_event )
    {
      verbev(("got event, sending it, poll will be 0 now\n"));
      bytevec_t req = prepare_rpc_packet(RPC_EVENT);
      append_debug_event(req, &pending_event);
      code = send_data(req);
      has_pending_event = false;
    }
    else
    { // no event, continue to poll
      poll_debug_events = true;
    }
  }
  return code;
}

//--------------------------------------------------------------------------
// this function runs on the server side
// a dbg_rpc_client sends an RPC_SYNC request and the server must give the stub to the client
bool dbg_rpc_handler_t::rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name)
{
  bool ok = false;
  int32 crc32 = -1;
  linput_t *li = open_linput(server_stub_name, false);
  if ( li != nullptr )
  {
    crc32 = calc_file_crc32(li);
    close_linput(li);
  }

  bytevec_t stub = prepare_rpc_packet(RPC_SYNC_STUB);
  stub.pack_str(ida_stub_name);
  stub.pack_dd(crc32);
  rpc_packet_t *rp = send_request_and_receive_reply(RPC_SYNC_STUB, stub);

  if ( rp == nullptr )
    return ok;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  size_t size = unpack_dd(&answer, end);
  if ( size == 1 )
  {
    ok = true;
  }
  else if ( size != 0 )
  {
    FILE *fp = fopenWB(server_stub_name);
    if ( fp != nullptr )
    {
      ok = qfwrite(fp, answer, size) == size;
      dmsg("Updated kernel debugger stub: %s\n", ok ? "success" : "failed");
      qfclose(fp);
    }
    else
    {
      dwarning("Could not update the kernel debugger stub.\n%s", qerrstr());
    }
  }
  qfree(rp);

  return ok;
}

//--------------------------------------------------------------------------
//lint -e{818} 'addrs' could be declared as pointing to const
int dbg_rpc_handler_t::send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty)
{
  if ( qty == 0 )
    return RPC_OK;

  bytevec_t buf;

  // The overall size of debug names may be large.
  // This may lead to unwanted network timeouts.
  // On the other hand, the small packet size produces a lot of packets,
  // which can significantly increase the total response time for the request.
  // Example: with 1300 byte packets, attaching to a process using Corellium
  //          was taking 20 minutes, while with 1MB packets it takes 3 minutes
  const size_t SZPACKET = 1024*1024;

  while ( qty > 0 )
  {
    buf.qclear();

    ea_t old = 0;
    const char *optr = "";

    // Start appending names and EAs
    int i = 0;
    while ( i < qty )
    {
      adiff_t diff = *addrs - old;
      bool neg = diff < 0;
      if ( neg )
        diff = -diff;

      buf.pack_ea64(diff); // send address deltas
      buf.pack_dd(neg);

      old = *addrs;
      const char *nptr = *names;
      int len = 0;

      // do not send repeating prefixes of names
      while ( nptr[len] != '\0' && nptr[len] == optr[len] ) //lint !e690 wrong access
        len++;

      buf.pack_dd(len);
      buf.pack_str(nptr+len);
      optr = nptr;
      addrs++;
      names++;
      i++;

      if ( buf.size() > SZPACKET )
        break;
    }
    qty -= i;

    bytevec_t req = prepare_rpc_packet(RPC_SET_DEBUG_NAMES);
    req.pack_dd(i);
    req.append(buf.begin(), buf.size());

    // should return a qty as much as sent...if not probably network error!
    if ( i != send_request_get_long_result(req) )
      return RPC_UNK;
  }

  return RPC_OK;
}

//--------------------------------------------------------------------------
int dbg_rpc_handler_t::send_debug_event_to_ida(const debug_event_t *debev, int rqflags)
{
  bytevec_t req = prepare_rpc_packet(RPC_HANDLE_DEBUG_EVENT);
  append_debug_event(req, debev);
  req.pack_dd(rqflags);
  return send_request_get_long_result(req);
}

//--------------------------------------------------------------------------
void dbg_rpc_handler_t::process_import_requests(const import_infos_t &infos)
{
  // in an effort to avoid sending large amounts of symbol data over the network,
  // we attempt to import symbols for each dll on the client side.
  // if the client does not support such behavior, then we simply parse the symbols
  // on the server side and append to the list of debug names to send to IDA, as normal.
  for ( import_infos_t::const_iterator i = infos.begin(); i != infos.end(); ++i )
  {
    ea_t base = i->base;
    const char *path = i->path.c_str();
    const bytevec_t &uuid = i->uuid;

    bytevec_t req = prepare_rpc_packet(RPC_IMPORT_DLL);
    req.pack_ea64(base);
    req.pack_str(path);
    req.pack_buf(uuid.begin(), uuid.size());

    int code = send_request_get_long_result(req);
    if ( code < 0 )  // cancelled or network error
      return;
    if ( code != 0 ) // request failed, fall back to parsing symbols server-side
      dbg_mod->import_dll(*i);
  }
}

//--------------------------------------------------------------------------
bool dbg_rpc_handler_t::get_broken_connection(void)
{
  return get_debugger_instance()->broken_connection;
}

//--------------------------------------------------------------------------
void dbg_rpc_handler_t::set_broken_connection(void)
{
  get_debugger_instance()->broken_connection = true;
}

//-------------------------------------------------------------------------
int dbg_rpc_handler_t::kill_process(void)
{
  const int NSEC = 5;
  dbg_mod->dbg_exit_process(nullptr);

  // now, wait up to NSEC seconds until the process is gone
  qtime64_t wait_start = qtime64();
  qtime64_t wait_threshold = make_qtime64(
          get_secs(wait_start) + NSEC,
          get_usecs(wait_start));
  while ( qtime64() < wait_threshold )
  {
    gdecode_t result = dbg_mod->dbg_get_debug_event(&ev, 100);
    if ( result >= GDE_ONE_EVENT )
    {
      dbg_mod->dbg_continue_after_event(&ev);
      if ( ev.eid() == PROCESS_EXITED )
        return 0;
    }
  }
  return NSEC;
}

//--------------------------------------------------------------------------
int debmod_t::send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty)
{
  dbg_rpc_handler_t *s = (dbg_rpc_handler_t *)rpc;
  return s->send_debug_names_to_ida(addrs, names, qty);
}

//--------------------------------------------------------------------------
int debmod_t::send_debug_event_to_ida(const debug_event_t *ev, int rqflags)
{
  dbg_rpc_handler_t *s = (dbg_rpc_handler_t *)rpc;
  return s->send_debug_event_to_ida(ev, rqflags);
}
