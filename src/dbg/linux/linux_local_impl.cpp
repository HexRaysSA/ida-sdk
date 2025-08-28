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
  size_t dm_offset;         // offset to value storage inside linux_dbgmod_t
  size_t size;
};

//--------------------------------------------------------------------------
static const linux_cfgopt_t g_cfgopts[] =
{
  { "LIBUNWIND_PATH", IDPOPT_STR, LINUX_OPT_LIWUNWIND_PATH, qoffsetof(LINUX_DEBMOD_T, libunwind_path), 0 },
};
CASSERT(IS_QSTRING(LINUX_DEBMOD_T::libunwind_path));

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
  auto &dbgmod = get_linux_debmod();
  if ( !exist(node) )
  {
    dbgmod.libunwind_path = stkunw_library_name();
#if defined(TESTABLE_BUILD) && defined(HAVE_UPDATE_CALL_STACK)
    // this is for kernel testing of pc_linux_sigmake
    qstring env;
    if ( qgetenv("IDA_DONTUSE_LIBUNWIND", &env) )
      dbgmod.libunwind_path.clear();
#endif
    return;
  }

  uchar *dm_start = (uchar *)&dbgmod;
  for ( const auto &opt : g_cfgopts )
  {
    uchar *fldptr = dm_start + opt.dm_offset;
    if ( opt.type == IDPOPT_STR )
      node.supstr((qstring *)fldptr, opt.index);
    else
      node.supval(opt.index, (uval_t *)fldptr, opt.size);
  }
  if ( dbgmod.libunwind_path == LIBUNWIND_EMPTY_MARKER )
    dbgmod.libunwind_path.clear();
}

//--------------------------------------------------------------------------
static void save_linux_options()
{
  auto &dbgmod = get_linux_debmod();
  if ( !dbgmod.g_must_save_cfg || !netnode::inited() )
    return;

  if ( dbgmod.libunwind_path.empty() )
    dbgmod.libunwind_path = LIBUNWIND_EMPTY_MARKER;

  netnode node;
  node.create(LINUX_NODE);
  if ( node != BADNODE )
  {
    uchar *dm_start = (uchar *)&dbgmod;
    for ( const auto &opt : g_cfgopts )
    {
      uchar *fldptr = dm_start + opt.dm_offset;
      if ( opt.type == IDPOPT_STR )
        node.supset(opt.index, ((qstring *)fldptr)->c_str(), 0);
      else
        node.supset(opt.index, (uval_t *)fldptr, opt.size);
    }
  }

  dbgmod.g_must_save_cfg = false;
}

//--------------------------------------------------------------------------
const char *idaapi set_linux_options(const char *keyword, int pri, int value_type, const void *value)
{
  auto &dbgmod = get_linux_debmod();
  // Load linux option with LINUX_NODE defined in user for local and in stub for remote
  if ( keyword == nullptr )
  {
    static const char form[] =
      "Linux debugger configuration\n"
      "<#Where is the libunwind leave empty if you don't want to use libunwind#Path to lib~u~nwind:q:" SMAXSTR ":60::>\n\n";

    qstring path = dbgmod.libunwind_path;
    while ( true )
    {
      if ( !ask_form(form, &path) )
        return IDPOPT_OK;
      if ( path.empty() )
        break;
      if ( stkunw_get_libraries(path.c_str()) != nullptr )
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
    dbgmod.libunwind_path = path;
    dbgmod.g_must_save_cfg = true;
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

    uchar *fldptr = (uchar *)&dbgmod + opt->dm_offset;
    if ( opt->type == IDPOPT_STR )
    {
      qstring *pvar = (qstring *)fldptr;
      *pvar = (char *)value;
    }

    if ( pri == IDPOPT_PRI_HIGH )
      dbgmod.g_must_save_cfg = true;
  }
  return IDPOPT_OK;
}
#else
inline void save_linux_options() {}
const char *idaapi set_linux_options(const char *, int, int, const void *) { return IDPOPT_OK; }
#endif // HAVE_UPDATE_CALL_STACK

//--------------------------------------------------------------------------
static bool init_linux_plugin(debugger_t *_debugger)
{
  qnotused(_debugger);
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
      if ( _debugger->is_remote() )
        return true;
      break; // failed
#endif
    }

    if ( inf_get_filetype() != f_ELF )
      break;
    processor_t &ph = PH;
    if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
      break;

    ok = true;
  } while ( false );
  return ok;
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland linux debugger plugin.";
