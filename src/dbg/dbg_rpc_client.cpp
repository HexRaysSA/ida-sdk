
//  This file is included in the debugger stub that runs on the computer with IDA

#include <pro.h>
#include <name.hpp>
#include <diskio.hpp>
#include <idp.hpp>

#include "dbg_rpc_client.h"
#include "dbg_rpc_hlp.h"
#include "debmod.h"

//--------------------------------------------------------------------------
// check and send to the remote server the specified stub
// do it only if its crc does not match the specified crc
// this function runs on the local machine with ida interface
static uchar *sync_stub(const char *fname, uint32 crc, size_t *psize)
{
  bool complain = true;
  uchar *retval = nullptr;
  char path[QMAXPATH];
  if ( getsysfile(path, sizeof(path), fname, nullptr) != nullptr )
  {
    linput_t *li = open_linput(path, false);
    if ( li != nullptr )
    {
      int64 size = qlsize(li);
      if ( size > 0 )
      {
        bytevec_t buf;
        buf.resize(size);
        if ( qlread(li, buf.begin(), size) == size )
        {
          complain = false;
          if ( calc_crc32(0, buf.begin(), size) != crc )
          {
            *psize = size;
            retval = buf.extract();
          }
          else
          {
            msg("Kernel debugger stub is up to date...\n");
            *psize = 1;       // signal ok
          }
        }
      }
      close_linput(li);
    }
  }
  if ( complain )
    warning("AUTOHIDE NONE\nCould not find/read debugger stub %s", fname);
  return retval;
}

//--------------------------------------------------------------------------
dbg_rpc_client_t::dbg_rpc_client_t(idarpc_stream_t *_irs)
  : dbg_rpc_engine_t(/*is_client=*/ true),
    client_irs(_irs)
{
  pending_event.clear_all();
  verbose = false;
  recv_timeout = RECV_TIMEOUT_PERIOD;
}

//-------------------------------------------------------------------------
void dbg_rpc_client_t::my_update_wait_dialog(
        const char *message,
        const rpc_packet_t *rp)
{
  if ( send_request_data.wait_dialog_displayed )
  {
    if ( rp->code != send_request_data.code )
      replace_wait_box("%s", message);
  }
  else
  {
    show_wait_box("%s", message);
    send_request_data.wait_dialog_displayed = true;
  }
  send_request_data.code = rp->code;
}

//--------------------------------------------------------------------------
// requests received from the server.
// here the client handles certain server -> client requests
bytevec_t dbg_rpc_client_t::on_send_request_interrupt(const rpc_packet_t *rp)
{
  const ea_helper_t &eah = EAH;
  memory_deserializer_t mmdsr(rp+1, rp->length);
  bytevec_t req = prepare_rpc_packet(RPC_OK);

  switch ( rp->code )
  {
    // send_debug_names_to_ida() is thread safe
    case RPC_SET_DEBUG_NAMES:
      {
        my_update_wait_dialog("Downloading Symbols", rp);
        int qty = mmdsr.unpack_dd();
        ea_t *addrs  = OPERATOR_NEW(ea_t, qty);
        char **names = OPERATOR_NEW(char *, qty);
        qstring name;
        ea_t old = 0;
        for ( int i=0; i < qty; i++ )
        {
          adiff_t o2 = mmdsr.unpack_ea64();
          if ( mmdsr.unpack_dd() )
            o2 = -o2;
          old += o2;
          addrs[i] = eah.uval2ea(eah.trunc_uval(old));
          int oldlen = mmdsr.unpack_dd();
          QASSERT(1203, oldlen >= 0 && oldlen <= name.length());
          // keep the prefix
          name.resize(oldlen);
          if ( !mmdsr.unpack_str(&name) )
            INTERR(1294);
          names[i] = qstrdup(name.c_str());
        }
        int result = send_debug_names_to_ida(addrs, names, qty);
        verb(("set_debug_name(qty=%d) => %d\n", qty, result));
        req.pack_dd(result);
        for ( int i=0; i < qty; i++ )
          qfree(names[i]);
        delete [] addrs;
        delete [] names;
      }
      break;

    // import_dll() is thread safe
    case RPC_IMPORT_DLL:
      {
        my_update_wait_dialog("Importing DLLs", rp);
        ea_t base        = mmdsr.unpack_ea64();
        const char *path = mmdsr.unpack_str();
        int n            = mmdsr.unpack_dd();
        const void *bytes = mmdsr.unpack_obj_inplace(n);
        bytevec_t uuid(bytes, n);
        int result = import_dll(import_request_t(base, path, uuid));
        verb(("import_dll(base=%a, path=%s) => %d\n", base, path, result));
        req.pack_dd(result);
      }
      break;

    // send_debug_event_to_ida() is thread safe
    case RPC_HANDLE_DEBUG_EVENT:
      {
        debug_event_t ev;
        extract_debug_event(&ev, mmdsr);
        int rqflags = mmdsr.unpack_dd();
        int code = send_debug_event_to_ida(&ev, rqflags);
        req.pack_dd(code);
      }
      break;

    // sync_stub() is thread safe
    case RPC_SYNC_STUB:
      {
        const char *fname = mmdsr.unpack_str();
        uint32 crc        = mmdsr.unpack_dd();

        // security problem: the debugger server should not be able to
        // read an arbitrary file on the local computer. therefore we completely
        // ignore the file name and use a hardcoded name.
        qnotused(fname);
        fname = "ida_kdstub.dll";

        size_t size = 0;
        uchar *contents = sync_stub(fname, crc, &size);
        req.pack_dd((uint32)size);
        if ( contents != nullptr )
        {
          req.append(contents, size);
          qfree(contents);
        }
      }
      break;

    // msg/error/warning are thread safe
    case RPC_ERROR:
    case RPC_MSG:
    case RPC_WARNING:
      {
        const char *str = mmdsr.unpack_str();
        if ( *str != '\0' )
        {
          if ( rp->code == RPC_MSG )
            msg("%s", str);
          else if ( rp->code == RPC_ERROR )
            error("%s", str);
          else
            warning("%s", str);
        }
      }
      break;

    // no external functions are called
    case RPC_EVENT:
      {
        extract_debug_event(&pending_event, mmdsr);
        has_pending_event = true;
        req = prepare_rpc_packet(RPC_EVOK);
        verbev(("got event, storing it and sending RPC_EVOK\n"));
      }
      break;

    // i doubt that this code is used on the client side
    // ioctl_handler is nullptr
    case RPC_IOCTL:
      {
        int code = handle_ioctl_packet(req, mmdsr.ptr, mmdsr.end);
        if ( code != RPC_OK )
          return prepare_rpc_packet((uchar)code);
      }
      break;

    // report_idc_error() is thread safe
    case RPC_REPORT_IDC_ERROR:
      {
        ea_t ea = mmdsr.unpack_ea64();
        error_t code = mmdsr.unpack_dd();
        const char *errprm;
        ssize_t errval;
        if ( mmdsr.unpack_db() )
        {
          errprm = mmdsr.unpack_str();
          errval = (ssize_t)errprm;
        }
        else
        {
          errprm = nullptr;
          errval = mmdsr.unpack_ea64();
        }
        report_idc_error(nullptr, ea, code, errval, errprm);
      }
      break;

    default:
      return prepare_rpc_packet(RPC_UNK);
  }
  return req;
}

//-------------------------------------------------------------------------
void dbg_rpc_client_t::on_send_request_end(const rpc_packet_t *)
{
  if ( send_request_data.wait_dialog_displayed )
    hide_wait_box();
  send_request_data.reset();
}
