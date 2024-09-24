
#include <network.hpp>

#include "dbg_rpc_engine.h"

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
static const rpc_packet_type_desc_t dbg_rpc_packet_t_descs[] =
{
  { RPC_OK,                       "RPC_OK",                       nullptr },
  { RPC_UNK,                      "RPC_UNK",                      nullptr },
  { RPC_MEM,                      "RPC_MEM",                      nullptr },

  { RPC_OPEN,                     "RPC_OPEN",                     nullptr },
  { RPC_EVENT,                    "RPC_EVENT",                    nullptr },
  { RPC_EVOK,                     "RPC_EVOK",                     nullptr },
  { RPC_CANCELLED,                "RPC_CANCELLED",                nullptr },

  { RPC_INIT,                     "RPC_INIT",                     nullptr },
  { RPC_TERM,                     "RPC_TERM",                     nullptr },
  { RPC_GET_PROCESSES,            "RPC_GET_PROCESSES",            nullptr },
  { RPC_START_PROCESS,            "RPC_START_PROCESS",            nullptr },
  { RPC_EXIT_PROCESS,             "RPC_EXIT_PROCESS",             nullptr },
  { RPC_ATTACH_PROCESS,           "RPC_ATTACH_PROCESS",           nullptr },
  { RPC_DETACH_PROCESS,           "RPC_DETACH_PROCESS",           nullptr },
  { RPC_GET_DEBUG_EVENT,          "RPC_GET_DEBUG_EVENT",          nullptr },
  { RPC_PREPARE_TO_PAUSE_PROCESS, "RPC_PREPARE_TO_PAUSE_PROCESS", nullptr },
  { RPC_STOPPED_AT_DEBUG_EVENT,   "RPC_STOPPED_AT_DEBUG_EVENT",   nullptr },
  { RPC_CONTINUE_AFTER_EVENT,     "RPC_CONTINUE_AFTER_EVENT",     nullptr },
  { RPC_TH_SUSPEND,               "RPC_TH_SUSPEND",               nullptr },
  { RPC_TH_CONTINUE,              "RPC_TH_CONTINUE",              nullptr },
  { RPC_SET_RESUME_MODE,          "RPC_SET_RESUME_MODE",          nullptr },
  { RPC_GET_MEMORY_INFO,          "RPC_GET_MEMORY_INFO",          nullptr },
  { RPC_READ_MEMORY,              "RPC_READ_MEMORY",              nullptr },
  { RPC_WRITE_MEMORY,             "RPC_WRITE_MEMORY",             nullptr },
  { RPC_UPDATE_BPTS,              "RPC_UPDATE_BPTS",              nullptr },
  { RPC_UPDATE_LOWCNDS,           "RPC_UPDATE_LOWCNDS",           nullptr },
  { RPC_EVAL_LOWCND,              "RPC_EVAL_LOWCND",              nullptr },
  { RPC_ISOK_BPT,                 "RPC_ISOK_BPT",                 nullptr },
  { RPC_READ_REGS,                "RPC_READ_REGS",                nullptr },
  { RPC_WRITE_REG,                "RPC_WRITE_REG",                nullptr },
  { RPC_GET_SREG_BASE,            "RPC_GET_SREG_BASE",            nullptr },
  { RPC_SET_EXCEPTION_INFO,       "RPC_SET_EXCEPTION_INFO",       nullptr },

  { RPC_OPEN_FILE,                "RPC_OPEN_FILE",                nullptr },
  { RPC_CLOSE_FILE,               "RPC_CLOSE_FILE",               nullptr },
  { RPC_READ_FILE,                "RPC_READ_FILE",                nullptr },
  { RPC_WRITE_FILE,               "RPC_WRITE_FILE",               nullptr },
  { RPC_IOCTL,                    "RPC_IOCTL",                    nullptr },
  { RPC_UPDATE_CALL_STACK,        "RPC_UPDATE_CALL_STACK",        nullptr },
  { RPC_APPCALL,                  "RPC_APPCALL",                  nullptr },
  { RPC_CLEANUP_APPCALL,          "RPC_CLEANUP_APPCALL",          nullptr },
  { RPC_REXEC,                    "RPC_REXEC",                    nullptr },
  { RPC_GET_SCATTERED_IMAGE,      "RPC_GET_SCATTERED_IMAGE",      nullptr },
  { RPC_GET_IMAGE_UUID,           "RPC_GET_IMAGE_UUID",           nullptr },
  { RPC_GET_SEGM_START,           "RPC_GET_SEGM_START",           nullptr },
  { RPC_BIN_SEARCH,               "RPC_BIN_SEARCH",               nullptr },

  { RPC_SET_DEBUG_NAMES,          "RPC_SET_DEBUG_NAMES",          nullptr },
  { RPC_SYNC_STUB,                "RPC_SYNC_STUB",                nullptr },
  { RPC_ERROR,                    "RPC_ERROR",                    nullptr },
  { RPC_MSG,                      "RPC_MSG",                      nullptr },
  { RPC_WARNING,                  "RPC_WARNING",                  nullptr },
  { RPC_HANDLE_DEBUG_EVENT,       "RPC_HANDLE_DEBUG_EVENT",       nullptr },
  { RPC_REPORT_IDC_ERROR,         "RPC_REPORT_IDC_ERROR",         nullptr },
  { RPC_IMPORT_DLL,               "RPC_IMPORT_DLL",               nullptr },
};
#endif

//-------------------------------------------------------------------------
dbg_rpc_engine_t::dbg_rpc_engine_t(bool _is_client)
  : rpc_engine_t(_is_client),
    has_pending_event(false),
    poll_debug_events(false)
{
#ifdef TESTABLE_BUILD
  register_packet_type_descs(
        dbg_rpc_packet_t_descs,
        qnumber(dbg_rpc_packet_t_descs));
#endif
}

//--------------------------------------------------------------------------
// sends a request and waits for a reply
// may occasionally send another request based on the reply
rpc_packet_t *dbg_rpc_engine_t::send_request_and_receive_reply(
        uchar pkt_code,
        bytevec_t &req,
        int flags)
{
  bool displayed = false;
  rpc_packet_t *result = nullptr;

  while ( true )
  {
    if ( displayed && user_cancelled() )
      req = prepare_rpc_packet(RPC_CANCELLED);

    if ( !req.empty() )
    {
      int code = send_data(req);
      if ( code != 0 )
      {
        (is_client ? msg : lprintf)("%s\n", last_errstr.c_str());
        break;
      }
      if ( (flags & PREQ_GET_EVENT) != 0 )
        break;

      rpc_packet_t *reqp = (rpc_packet_t *)req.begin();
      if ( reqp->code == RPC_ERROR )
        qexit(1); // sent error packet, may die now
    }

    rpc_packet_t *rp = recv_packet(pkt_code);
    if ( rp == nullptr )
    {
      (is_client ? msg : lprintf)("%s\n", last_errstr.c_str());
      break;
    }

    switch ( rp->code )
    {
      case RPC_UNK:
        dwarning("rpc: remote did not understand our request");
        goto FAILURE;
      case RPC_MEM:
        dwarning("rpc: no remote memory");
        goto FAILURE;
      case RPC_CANCELLED:
        msg("rpc: user cancelled the operation\n");
        goto FAILURE;
      case RPC_OK:
        result = rp;
        goto END;
      default:
        // other replies are passed to the handler
        break;
    }

    if ( !logged_in )
    {
      lprintf("Exploit packet has been detected and ignored\n");
FAILURE:
      qfree(rp);
      break;
    }
    // handle actual command in the request
    // FIXME: use a better function name
    req = on_send_request_interrupt(rp);
    qfree(rp);
  }

END:
  on_send_request_end(result);

  return result;
}

//-------------------------------------------------------------------------
int dbg_rpc_engine_t::_send_request_get_int_result(
        bytevec_t &req,
        int failure_code,
        qstring *errbuf)
{
  rpc_packet_t *rp = (rpc_packet_t *)req.begin();
  rp = send_request_and_receive_reply(rp->code, req);
  if ( rp == nullptr )
    return failure_code;

  memory_deserializer_t mmdsr(rp+1, rp->length);
  int rc = mmdsr.unpack_dd();
  if ( rc < 0 && errbuf != nullptr )
    *errbuf = mmdsr.unpack_str();

  qfree(rp);
  return rc;
}
