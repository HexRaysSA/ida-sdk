#ifndef SERVER_H
#define SERVER_H

#include <network.hpp>

#ifdef __NT__
//#  ifndef SIGHUP
//#    define SIGHUP 1
//#  endif
#  define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#else   // not NT, i.e. UNIX
#  if defined(__LINUX__)
#    if defined(__ARM__)
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_LINUX_USER
#    else
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#    endif
#  elif defined(__MAC__)
#    if defined(__ARM__)
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_MACOS_USER
#    else
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_MACOSX_USER
#    endif
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif // !__NT__

enum broken_conn_hndl_t
{
  BCH_DEFAULT,
  BCH_KEEP_DEBMOD,
  BCH_KILL_PROCESS,
};

struct dbgsrv_dispatcher_t : public base_dispatcher_t
{
  qstring server_password;
  bool broken_conns_supported;
  broken_conn_hndl_t on_broken_conn;

  dbgsrv_dispatcher_t(bool multi_threaded);

  virtual void collect_cliopts(cliopts_t *out) override;
  virtual network_client_handler_t *new_client_handler(idarpc_stream_t *irs) override;

  virtual void shutdown_gracefully(int signum) override;
};

#include "debmod.h"
#include "dbg_rpc_hlp.h"
#include "dbg_rpc_handler.h"

// // sizeof(ea_t)==8 and sizeof(size_t)==4 servers cannot be used to debug 64-bit
// // applications. but to debug 32-bit applications, simple 32-bit servers
// // are enough and can work with both 32-bit and 64-bit versions of ida.
// // so, there is no need to build sizeof(ea_t)==8 and sizeof(size_t)==4 servers
// #if defined(__EA64__) == defined(__X86__)
// #error "Mixed mode servers do not make sense, they should not be compiled"
// #endif

#endif
