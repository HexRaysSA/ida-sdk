/*
       IDA remote debugger server
*/

#ifdef _WIN32
// We use the deprecated inet_ntoa() function for Windows XP compatibility.
//lint -e750 local macro '' not referenced
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <pro.h>
#include <expr.hpp>
#include "server.h"

//--------------------------------------------------------------------------
// for debug servers app bitness is defined by size of ea_t
int get_default_app_addrsize()
{
  return sizeof(ea_t);
}
void update_idd_registers() {}

// Provide dummy versions for tinfo copy/clear. Debugger servers do not use them
#if !defined(__NT__)
void ida_export copy_tinfo_t(tinfo_t *, const tinfo_t &) {}
void ida_export clear_tinfo_t(tinfo_t *) {}
#endif

// We don't have a kernel. Provide envvar-based debug file directory retrieval.
#if defined(__LINUX__)
static bool _elf_debug_file_directory_resolved = false;
static qstring _elf_debug_file_directory;
idaman const char *ida_export get_elf_debug_file_directory()
{
  if ( !_elf_debug_file_directory_resolved )
  {
    if ( !qgetenv("DEBUG_FILE_DIRECTORY", &_elf_debug_file_directory) )
      qgetenv("ELF_DEBUG_FILE_DIRECTORY", &_elf_debug_file_directory);
    if ( _elf_debug_file_directory.empty() )
      _elf_debug_file_directory = "/usr/lib/debug";
    _elf_debug_file_directory_resolved = true;
  }
  return _elf_debug_file_directory.c_str();
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
static std::map<int,qstring> _pid_elf_debug_file_directories;
void set_elf_debug_file_directory_for_pid(int pid, const char *path)
{
  _pid_elf_debug_file_directories[pid] = path;
}

//-------------------------------------------------------------------------
const char *get_elf_debug_file_directory_for_pid(int pid)
{
  const char *found = nullptr;
  std::map<int,qstring>::const_iterator it = _pid_elf_debug_file_directories.find(pid);
  if ( it != _pid_elf_debug_file_directories.end() )
    found = it->second.begin();
  else
    found = get_elf_debug_file_directory();
  return found;
}
#endif
#endif

//lint -esym(714, dump_udt) not referenced
void dump_udt(const char *, const struct udt_type_data_t &) {}


//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
#ifdef __SINGLE_THREADED_SERVER__
dbgsrv_dispatcher_t dispatcher(false);

static bool init_lock(void) { return true; }
bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }
#else
dbgsrv_dispatcher_t dispatcher(true);

static qmutex_t g_mutex = nullptr;
static bool init_lock(void) { g_mutex = qmutex_create(); return g_mutex != nullptr; }
bool lock_begin(void) { return qmutex_lock(g_mutex); }
bool lock_end(void) { return qmutex_unlock(g_mutex); }
#endif

//--------------------------------------------------------------------------
dbg_rpc_handler_t *g_global_server = nullptr;

//--------------------------------------------------------------------------
// perform an action (func) on all debuggers
int for_all_debuggers(debmod_visitor_t &v)
{
  int code = 0;
  dispatcher.clients_list->lock();
  {
    client_handlers_list_t::storage_t::iterator it;
    for ( it = dispatcher.clients_list->storage.begin();
          it != dispatcher.clients_list->storage.end();
          ++it )
    {
      dbg_rpc_handler_t *h = (dbg_rpc_handler_t *) it->first;
      code = v.visit(h->get_debugger_instance());
      if ( code != 0 )
        break;
    }
  }
  dispatcher.clients_list->unlock();
  return code;
}

//-------------------------------------------------------------------------
dbgsrv_dispatcher_t::dbgsrv_dispatcher_t(bool multi_threaded)
  : base_dispatcher_t(multi_threaded),
    broken_conns_supported(false),
    on_broken_conn(BCH_DEFAULT)
{
  port_number = DEBUGGER_PORT_NUMBER;
  use_tls = false; // override network.hpp's default
}

//-------------------------------------------------------------------------
void dbgsrv_dispatcher_t::collect_cliopts(cliopts_t *out)
{
  struct ida_local ns_t
  {
    static void _set_dpassword(const char *value, void *ud)
    {
      ((dbgsrv_dispatcher_t *) ud)->server_password = value;
    }
    static void _set_broken_connections_keep_debmod(const char *, void *ud)
    {
      ((dbgsrv_dispatcher_t *) ud)->on_broken_conn = BCH_KEEP_DEBMOD;
    }
    static void _set_closing_session_kill_debuggee(const char *, void *ud)
    {
      ((dbgsrv_dispatcher_t *) ud)->on_broken_conn = BCH_KILL_PROCESS;
    }
  };

  static const cliopt_t cliopts[] =
  {
    { 'P', "password", "Password", ns_t::_set_dpassword, 1 },
  };
  // the following options are valid only if broken connections are supported
  static const cliopt_t bc_cliopts[] =
  {
    {
      'k',
      "on-broken-connection-keep-session",
      "Keep debugger session alive when connection breaks",
      ns_t::_set_broken_connections_keep_debmod,
      0,
    },
    {
      'K',
      "on-stop-kill-process",
      "Kill debuggee when closing session",
      ns_t::_set_closing_session_kill_debuggee,
      0,
    },
  };

  base_dispatcher_t::collect_cliopts(out);
  add_notls_cliopts(out);
  for ( size_t i = 0; i < qnumber(cliopts); ++i )
    out->push_back(cliopts[i]);

  if ( broken_conns_supported )
    for ( size_t i = 0; i < qnumber(bc_cliopts); ++i )
      out->push_back(bc_cliopts[i]);
}

//-------------------------------------------------------------------------
network_client_handler_t *dbgsrv_dispatcher_t::new_client_handler(idarpc_stream_t *_irs)
{
  dbg_rpc_handler_t *h = new dbg_rpc_handler_t(_irs, this);
  h->verbose = verbose;
  void *params = nullptr;
#if defined(__LINUX__) && defined(TESTABLE_BUILD)
  params = (void *) get_elf_debug_file_directory_for_pid; //lint !e611 cast between pointer to function type '' and pointer to object type 'void *'
#endif
  h->set_debugger_instance(create_debug_session(params));
  g_global_server = h;
  return h;
}

//-------------------------------------------------------------------------
void dbgsrv_dispatcher_t::shutdown_gracefully(int signum)
{
  base_dispatcher_t::shutdown_gracefully(signum);
  term_subsystem();
}


//--------------------------------------------------------------------------
// debugger remote server - TCP/IP mode
int NT_CDECL main(int argc, const char *argv[])
{
#ifdef ENABLE_LOWCNDS
  init_idc();
#endif

  // call the debugger module to initialize its subsystem once
  if ( !init_lock() || !init_subsystem() )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  qstring password;
  if ( qgetenv("IDA_DBGSRV_PASSWD", &password) )
    dispatcher.server_password = password;

  int ida_major = IDA_SDK_VERSION / 100;
#if (IDA_SDK_VERSION % 10) == 0
  int ida_minor = (IDA_SDK_VERSION % 100)/10;  // 740 -> 4
#else
  int ida_minor = IDA_SDK_VERSION % 100;       // 741 -> 41
#endif

  lprintf("IDA " SYSTEM SYSBITS " remote debug server(" __SERVER_TYPE__ ") "
          "v%d.%d.%d. Hex-Rays (c) 2004-2024\n",
           ida_major, ida_minor, IDD_INTERFACE_VERSION);

  dispatcher.broken_conns_supported = debmod_t::reuse_broken_connections;
  cliopts_t cliopts(lprintf);
  dispatcher.collect_cliopts(&cliopts);
  cliopts.apply(argc, argv, &dispatcher);
  dispatcher.install_signal_handlers();
  dispatcher.dispatch();
}
