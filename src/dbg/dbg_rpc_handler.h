#ifndef __DBG_RPC_HANDLER__
#define __DBG_RPC_HANDLER__

#include <network.hpp>

#include "dbg_rpc_engine.h"
#define MIN_SERVER_IOCTL 0x01000000

#include "debmod.h"

struct dbgsrv_dispatcher_t;

//-------------------------------------------------------------------------
class dbg_rpc_handler_t
  : public network_client_handler_t,
    public dbg_rpc_engine_t
{
public:
  dbg_rpc_handler_t(idarpc_stream_t *_irs, dbgsrv_dispatcher_t *_dispatcher);
  virtual ~dbg_rpc_handler_t();

  virtual bool handle() override;
  virtual void shutdown_gracefully(int signum) override;

private:
  debug_event_t ev;
  debug_event_t pending_event;
  debmod_t *dbg_mod;
  dbgsrv_dispatcher_t *dispatcher;
  DECLARE_UNCOPYABLE(dbg_rpc_handler_t);
  void append_start_or_attach(bytevec_t &req, drc_t drc, const qstring &errbuf) const;
  int poll_events(int timeout_ms);
  void extract_path_and_arch(
        const char **out_file_path,
        int *out_arch,
        int *out_is_be,
        memory_deserializer_t &mmdsr) const;
  int on_recv_packet_progress(bool *performed);

protected:
  void rpc_update_lowcnds(bytevec_t &rcmd, memory_deserializer_t &mmdsr);
  int rpc_update_bpts(bytevec_t &rcmd, memory_deserializer_t &mmdsr);
  drc_t rpc_attach_process(qstring *errbuf, memory_deserializer_t &mmdsr);
  bool check_broken_connection(pid_t pid);
  virtual int handle_server_ioctl(int fn, void **out, ssize_t *outsz, memory_deserializer_t &mmdsr) newapi;
  virtual bytevec_t on_send_request_interrupt(const rpc_packet_t *rp) override;

public:
  void set_debugger_instance(debmod_t *instance);
  debmod_t *get_debugger_instance();
  void prepare_broken_connection();
  bool rpc_sync_stub(const char *server_stub_name, const char *ida_stub_name);
  int send_debug_names_to_ida(ea_t *ea, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  void process_import_requests(const import_infos_t &infos);
  virtual idarpc_stream_t *get_irs() const override { return irs; }
  virtual bool get_broken_connection(void) override;
  virtual void set_broken_connection(void) override;
  int kill_process(void); // returns 0-ok, >0-failed, after that many seconds
};

// defined only in the single threaded version of the server:
extern dbg_rpc_handler_t *g_global_server;

#endif // __DBG_RPC_HANDLER__
