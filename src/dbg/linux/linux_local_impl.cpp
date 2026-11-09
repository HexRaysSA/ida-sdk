#include <loader.hpp>

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  ea_t base = get_imagebase();
  if ( base != BADADDR && new_base != BADADDR && base != new_base )
    rebase_or_warn(base, new_base);
}

#ifdef HAVE_UPDATE_CALL_STACK
static bool g_must_save_cfg = false;
#define LIBUNWIND_EMPTY_MARKER "\x01"

//--------------------------------------------------------------------------
enum linuxopt_idx_t
{
  LINUX_OPT_LIWUNWIND_PATH, // path to a valid libunwind
};

//--------------------------------------------------------------------------
struct linux_cfgopt_t
{
  const char *name;         // parameter name
  char type;                // parameter type (IDPOPT_...)
  linuxopt_idx_t index;     // index in the altval array
  void *var;                // pointer to variable that will hold the value
  size_t size;
};

//--------------------------------------------------------------------------
static const linux_cfgopt_t g_cfgopts[] =
{
  { "LIBUNWIND_PATH", IDPOPT_STR, LINUX_OPT_LIWUNWIND_PATH, &g_dbgmod.libunwind_path, 0 },
};
CASSERT(IS_QSTRING(g_dbgmod.libunwind_path));

//--------------------------------------------------------------------------
static const linux_cfgopt_t *find_option(const char *name)
{
  for ( int i=0; i < qnumber(g_cfgopts); i++ )
    if ( strcmp(g_cfgopts[i].name, name) == 0 )
      return &g_cfgopts[i];
  return nullptr;
}

//--------------------------------------------------------------------------
static void load_linux_options()
{
  if ( !netnode::inited() )
    return;

  netnode node(LINUX_NODE);
  if ( !exist(node) )
  {
    g_dbgmod.libunwind_path = libunwind_pair_name[0].libx86_64_name;
#if defined(TESTABLE_BUILD) && defined(HAVE_UPDATE_CALL_STACK)
    // this is for kernel testing of pc_linux_sigmake
    qstring env;
    if ( qgetenv("IDA_DONTUSE_LIBUNWIND", &env) )
      g_dbgmod.libunwind_path.clear();
#endif
    return;
  }

  for ( int i = 0; i < qnumber(g_cfgopts); i++ )
  {
    const linux_cfgopt_t &opt = g_cfgopts[i];
    if ( opt.type == IDPOPT_STR )
      node.supstr((qstring *)opt.var, opt.index);
    else
      node.supval(opt.index, opt.var, opt.size);
  }
  if ( g_dbgmod.libunwind_path == LIBUNWIND_EMPTY_MARKER )
    g_dbgmod.libunwind_path.clear();
}

//--------------------------------------------------------------------------
static void save_linux_options()
{
  if ( !g_must_save_cfg || !netnode::inited() )
    return;

  if ( g_dbgmod.libunwind_path.empty() )
    g_dbgmod.libunwind_path = LIBUNWIND_EMPTY_MARKER;

  netnode node;
  node.create(LINUX_NODE);
  if ( node != BADNODE )
  {
    for ( int i = 0; i < qnumber(g_cfgopts); i++ )
    {
      const linux_cfgopt_t &opt = g_cfgopts[i];
      if ( opt.type == IDPOPT_STR )
        node.supset(opt.index, ((qstring *)opt.var)->c_str(), 0);
      else
        node.supset(opt.index, opt.var, opt.size);
    }
  }

  g_must_save_cfg = false;
}

//--------------------------------------------------------------------------
static ssize_t idaapi ui_callback(void *, int notification_code, va_list)
{
  if ( notification_code == ui_saving )
    save_linux_options();
  return 0;
}

//--------------------------------------------------------------------------
const char *idaapi set_linux_options(const char *keyword, int pri, int value_type, const void *value)
{
  // Load linux option with LINUX_NODE defined in user for local and in stub for remote
  if ( keyword == nullptr )
  {
    static const char form[] =
      "Linux debugger configuration\n"
      "<#Where is the libunwind leave empty if you don't want to use libunwind#Path to lib~u~nwind:q:" SMAXSTR ":60::>\n\n";

    qstring path = g_dbgmod.libunwind_path;
    while ( true )
    {
      if ( !ask_form(form, &path) )
        return IDPOPT_OK;
      if ( path.empty() )
        break;
      bool is_correct_libpath = false;
      for ( int i = 0; i < qnumber(libunwind_pair_name); i++ )
      {
        if ( path == libunwind_pair_name[i].libx86_64_name
          || qisabspath(path.c_str())
          && streq(libunwind_pair_name[i].libx86_64_name, qbasename(path.c_str())) )
        {
          is_correct_libpath = true;
          break;
        }
      }
      if ( is_correct_libpath )
      {
        break;
      }
      else
      {
        warning("AUTOHIDE NONE\n"
                "\"%s\" is not a valid path to libunwind-x86_64.so",
                path.c_str());
      }
    }
    g_dbgmod.libunwind_path = path;
    g_must_save_cfg = true;
  }
  else
  {
    if ( *keyword == '\0' )
    {
      load_linux_options();
      return IDPOPT_OK;
    }

    const linux_cfgopt_t *opt = find_option(keyword);
    if ( opt == nullptr )
      return IDPOPT_BADKEY;
    if ( opt->type != value_type )
      return IDPOPT_BADTYPE;

    if ( opt->type == IDPOPT_STR )
    {
      qstring *pvar = (qstring *)opt->var;
      *pvar = (char *)value;
    }

    if ( pri == IDPOPT_PRI_HIGH )
      g_must_save_cfg = true;
  }
  return IDPOPT_OK;
}
#endif // HAVE_UPDATE_CALL_STACK

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif

  bool ok = false;
  do
  {
    if ( !netnode::inited() || is_miniidb() || inf_is_snapshot() )
    {
#ifdef __LINUX__
      // local debugger is available if we are running under Linux
      return true;
#else
      // for other systems only the remote debugger is available
      if ( debugger.is_remote() )
        return true;
      break; // failed
#endif
    }

    if ( inf_get_filetype() != S_FILETYPE )
      break;
    processor_t &ph = PH;
    if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
      break;

    ok = true;
  } while ( false );
#ifndef RPC_CLIENT
  if ( !ok )
    term_subsystem();
#endif
#ifdef HAVE_UPDATE_CALL_STACK
  if ( ok )
    hook_to_notification_point(HT_UI, ui_callback);
#endif
  return ok;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
#ifndef RPC_CLIENT
  term_subsystem();
#endif
#ifdef HAVE_UPDATE_CALL_STACK
  unhook_from_notification_point(HT_UI, ui_callback);
  save_linux_options();
#endif
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland linux debugger plugin.";
