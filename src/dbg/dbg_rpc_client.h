#ifndef __RPC_CLIENT__
#define __RPC_CLIENT__

#include "dbg_rpc_engine.h"

class dbg_rpc_client_t: public dbg_rpc_engine_t
{
protected:
  debug_event_t pending_event;
  idarpc_stream_t *client_irs;
  bool verbose;

  struct send_request_data_t
  {
    uchar code;
    bool wait_dialog_displayed;

    send_request_data_t() { reset(); }
    void reset() { code = uchar(-1); wait_dialog_displayed = false; }
  };
  send_request_data_t send_request_data;

  void my_update_wait_dialog(const char *message, const rpc_packet_t *rp);

  virtual bytevec_t on_send_request_interrupt(const rpc_packet_t *rp) override;
  virtual void on_send_request_end(const rpc_packet_t *result) override;

public:
  dbg_rpc_client_t(idarpc_stream_t *irs);
  virtual ~dbg_rpc_client_t() {}

  virtual idarpc_stream_t *get_irs() const override { return client_irs; }
};

#endif
