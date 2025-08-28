#ifndef __DBG_RPC_ENGINE__
#define __DBG_RPC_ENGINE__

#include <pro.h>
#include <idd.hpp>
#include <network.hpp>

//-------------------------------------------------------------------------
class dbg_rpc_engine_t : public rpc_engine_t
{
public:
  bool has_pending_event;
  bool poll_debug_events;

  dbg_rpc_engine_t(bool _is_client);

#define PREQ_GET_EVENT  0x01
  rpc_packet_t *send_request_and_receive_reply(uchar pkt_code, bytevec_t &pkt, int flags);

  virtual rpc_packet_t *send_request_and_receive_reply(uchar pkt_code, bytevec_t &pkt) override
  {
    return send_request_and_receive_reply(pkt_code, pkt, 0);
  }

protected:
  int send_request_get_long_result(bytevec_t &pkt) { return _send_request_get_int_result(pkt, -1, nullptr); }
  drc_t send_request_get_drc_result(bytevec_t &pkt, qstring *errbuf) { return drc_t(_send_request_get_int_result(pkt, DRC_NETERR, errbuf)); }

  virtual bytevec_t on_send_request_interrupt(const rpc_packet_t *rp) = 0;
  virtual void on_send_request_end(const rpc_packet_t *result) newapi { qnotused(result); }

private:
  int _send_request_get_int_result(bytevec_t &pkt, int failure_code, qstring *errbuf);
};

#endif // __DBG_RPC_ENGINE__
