
/*
 * This utility is meant to be used to let IDA switch between
 * installed versions of Python3.
 *
 * See the documentation placed in 'opts.epilog', near the bottom
 * of this file.
 */

#ifdef __NT__
#  include <windows.h>
#endif

//lint -esym(1788, iinc) is referenced only by its constructor or destructor
//lint -e754 local struct member 'pylib_entries_t::path_history' not referenced
//lint -esym(750, EXIT_CODE_SPLIT_DEBUG_EXPAND_DT_NEEDED_ROOM_FAILED) local macro '' not referenced
//lint -esym(750, SOSFX) local macro '' not referenced

#include <pro.h>
#include <err.h>
#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include <network.hpp>
#include <parsejson.hpp>
#include <expr.hpp>

idcfuncs_t idc_func_table;

#define EXIT_CODE_FORCE_PATH_FAILED 110

#define EXIT_CODE_NO_INSTALLS 120
#define EXIT_CODE_APPLY_FAILED 121

#ifdef __LINUX__
#  define EXIT_CODE_SPLIT_DEBUG_EXPAND_DT_NEEDED_ROOM_FAILED 140
#endif

#ifdef __GNUC__ // gcc defines those macros, that are in our way
#  undef major
#  undef minor
#endif

//-------------------------------------------------------------------------
struct user_args_t
{
  qstring force_path;
  uint32 major_version = 3;
  uint32 minor_version = 8;
  bool verbose = false;
  bool dry_run = false;
  bool auto_apply = false;
  bool idalib = false;
#ifdef __UNIX__
  bool ignore_python_config = false;
#endif
};
static user_args_t args;

//-------------------------------------------------------------------------
static int out_ident = 0;
struct out_ident_inc_t
{
  out_ident_inc_t() { ++out_ident; }
  ~out_ident_inc_t() { --out_ident; }
};

//-------------------------------------------------------------------------
AS_PRINTF(1, 0) int vout(const char *format, va_list va)
{
  for ( int i = 0; i < out_ident; ++i )
    printf("    ");
  return vprintf(format, va);
}

//-------------------------------------------------------------------------
AS_PRINTF(1, 2) int out(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int rc = vout(format, va);
  va_end(va);
  return rc;
}

//-------------------------------------------------------------------------
AS_PRINTF(1, 2) int out_verb(const char *format, ...)
{
  int rc = 0;
  if ( args.verbose )
  {
    out("V: ");
    va_list va;
    va_start(va, format);
    rc = vout(format, va);
    va_end(va);
  }
  return rc;
}

//-------------------------------------------------------------------------
NORETURN AS_PRINTF(2, 3) void error(int exit_code, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vout(format, va);
  va_end(va);
  qexit(exit_code);
}


//-------------------------------------------------------------------------
struct pylib_version_t
{
  int major;
  int minor;
  int revision;
  qstring modifiers; //lint !e958 padding of 4 bytes needed to align member on a 8 byte boundary
  qstring raw;

  pylib_version_t(
          int _major=0,
          int _minor=0,
          int _revision=0,
          const char *_modifiers=nullptr,
          const char *_raw=nullptr)
    : major(_major),
      minor(_minor),
      revision(_revision),
      modifiers(_modifiers),
      raw(_raw) {}

  bool valid() const { return major > 0; }

  const char *str(qstring *out) const
  {
    out->sprnt("%d.%d.%d%s ('%s')",
               major, minor, revision,
               modifiers.c_str(), raw.c_str());
    return out->c_str();
  }

  DECLARE_COMPARISONS(pylib_version_t)
  {
    if ( major != r.major )
      return major - r.major;
    if ( minor != r.minor )
      return minor - r.minor;
    if ( revision != r.revision )
      return revision - r.revision;
    // when it comes to modifiers, we'll consider:
    //  - that a debug version is lesser than a non-debug one
    //  - that a version with more modifiers is "greater" than
    //    one with fewer modifiers.
    const int has_debug   = qstrstr(modifiers.c_str(), "d") != nullptr;
    const int r_has_debug = qstrstr(r.modifiers.c_str(), "d") != nullptr;
    if ( has_debug != r_has_debug )
      return r_has_debug - has_debug;
    return modifiers.length() - r.modifiers.length();
  }
};
DECLARE_TYPE_AS_MOVABLE(pylib_version_t);

//-------------------------------------------------------------------------
struct pylib_entry_t
{
  pylib_version_t version;
#ifdef __MAC__
  pylib_version_t compatibility_version; // only for OSX
#endif
#ifdef __NT__
  qstring display_name;
#endif
  qstrvec_t paths;
  bool preferred;

  pylib_entry_t(const pylib_version_t &_version)
    : version(_version), preferred(false) {}

  const char *str(qstring *out) const
  {
    qstring pbuf, vbuf;
    for ( auto const &p : paths )
    {
      if ( !pbuf.empty() )
        pbuf.append(", ", 2);
      pbuf.append(p);
    }
    out->sprnt("Version: %s; paths: %s", version.str(&vbuf), pbuf.c_str());
    if ( preferred )
      out->append(" (PREFERRED)");
    return out->c_str();
  }

  bool operator ==(const pylib_entry_t &r) const { return paths == r.paths; }
  bool operator !=(const pylib_entry_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(pylib_entry_t);
typedef qvector<pylib_entry_t> pylib_entry_vec_t;

//-------------------------------------------------------------------------
struct pylib_entries_t
{
  pylib_entry_vec_t entries;
  qstrvec_t path_history;

  pylib_entry_t *get_entry_for_version(const pylib_version_t &version)
  {
    for ( auto &e : entries )
      if ( e.version == version )
        return &e;
    return nullptr;
  }

  pylib_entry_t &add_entry(const pylib_version_t &version, const qstrvec_t &paths)
  {
    pylib_entry_t ne(version);
    ne.paths = paths;
    entries.push_back(ne);
    pylib_entry_t *e = &entries.back();
    return *e;
  }

  pylib_entry_t &add_entry(const pylib_version_t &version, const char *path)
  {
    qstrvec_t paths;
    paths.push_back(path);
    return add_entry(version, paths);
  }
};

#ifdef __UNIX__
static void set_preferred_pylib_version(pylib_entries_t *result);
#endif

//-------------------------------------------------------------------------
struct pyver_tool_t
{
  static bool reverse_compare_entries(
        const pylib_entry_t &e0,
        const pylib_entry_t &e1)
  {
    if ( e0.preferred )
      return true;
    if ( e1.preferred )
      return false;
    int rc = e0.version.compare(e1.version);
    if ( rc > 0 )
      return true;
    return false;
  }

  bool path_to_pylib_entry(
        pylib_entry_t *out,
        const char *path,
        qstring *errbuf) const
  {
    return do_path_to_pylib_entry(out, path, errbuf);
  }

  void find_python_libs(pylib_entries_t *result) const
  {
    do_find_python_libs(result);

#ifdef __UNIX__
    set_preferred_pylib_version(result);
#endif

    std::sort(result->entries.begin(), result->entries.end(), reverse_compare_entries);

    qstring buf;
    if ( args.verbose )
    {
      out_ident_inc_t iinc;
      for ( auto const &e : result->entries )
        out_verb("%s\n", e.str(&buf));
    }
  }

  bool apply_version(
        const pylib_entry_t &entry,
        qstring *errbuf) const
  {
    return do_apply_version(entry, errbuf);
  }

private:
  // These three need to be implemented in different
  // ways on __NT__, __LINUX__ and __MAC__

  // Look on the filesystem (or the registry on Windows)
  // for available Python3 installations.
  void do_find_python_libs(pylib_entries_t *out) const;

  // Given a path to a .so, .dll or .dylib, try and parse the
  // Python3 version and produce an entry with it.
  bool do_path_to_pylib_entry(pylib_entry_t *entry, const char *path, qstring *errbuf) const;

  // Do patch the idapython.[so|dylib] binary (or the
  // registry on Windows) so that they refer to the right
  // Python3 version.
  bool do_apply_version(const pylib_entry_t &entry, qstring *errbuf) const;
};

//-------------------------------------------------------------------------
// Accepts:
//   "3.7"
//   "3.7.1"
//   "3.7m"
//   "3.7.1dm"

//lint -esym(528, parse_python_version_str) not referenced
static bool parse_python_version_str(pylib_version_t *out, const char *raw)
{
  int major = 0;
  int minor = 0;
  int revision = 0;
  int nchars_read;

  const char *p = raw;

  if ( qsscanf(raw, "%d.%d%n", &major, &minor, &nchars_read) != 2 )
    return false;
  p += nchars_read;

  if ( p[0] == '.' && qisdigit(p[1]) )
  {
    if ( qsscanf(p, ".%d%n", &revision, &nchars_read) != 1 )
      return false;
    p += nchars_read;
  }

  *out = pylib_version_t(major, minor, revision, p, raw);
  return true;
}

#ifdef __UNIX__
//-------------------------------------------------------------------------
static bool extract_version_from_str(
        pylib_version_t *out,
        const char *p,
        const char *stem,
        const char *end_delimiter)
{
  const size_t stemlen = qstrlen(stem);
  if ( !strneq(p, stem, stemlen) )
    return false;
  p += stemlen;
  const char *p2 = qstrstr(p, end_delimiter);
  if ( p2 == nullptr )
    p2 = tail(p);
  size_t nbytes = p2 - p;
  char raw[MAXSTR];
  if ( nbytes > sizeof(raw) - 1 )
    nbytes = sizeof(raw) - 1;
  memmove(raw, p, nbytes);
  raw[nbytes] = '\0';
  parse_python_version_str(out, raw);
  return true;
}

//-------------------------------------------------------------------------
static void set_preferred_pylib_version(pylib_entries_t *result)
{
  // If python(3)-config exists, use it to determine the preferred version
  if ( args.ignore_python_config )
    return;

  const char *config_util = args.major_version == 3 ? "python3-config" : "python-config";
  qstring cmd;
  cmd.sprnt("%s --libs", config_util);

  qstring error;
  qstring verbuf;
  FILE *fp = popen(cmd.c_str(), "r");
  if ( fp != nullptr )
  {
    char outbuf[MAXSTR];
    /*ssize_t nread =*/ qfread(fp, outbuf, sizeof(outbuf));
    int rc = pclose(fp);
    if ( rc == 0 )
    {
      pylib_version_t version;
      const char *p = qstrstr(outbuf, "-lpython");
      if ( p != nullptr
        && extract_version_from_str(&version, p, "-lpython", " ") )
      {
#ifdef __MAC__
        // python3-config output on OSX will contain modifiers, i.e. "-lpython3.7m", but when detecting pylibs on OSX
        // we extract the python version from the LC_ID_DYLIB load command, which does not contain modifiers.
        // it seems safe to ignore the modifiers on OSX, they appear to be only used for compatibility purposes.
        version.modifiers.clear();
#endif
        out_verb("Preferred version, as reported by \"%s\": %s\n", cmd.c_str(), version.str(&verbuf));
        pylib_entry_t *e = result->get_entry_for_version(version);
        if ( e != nullptr )
          e->preferred = true;
        else
          error.sprnt("\"%s\" reports preferred "
                      "version \"%s\", but no corresponding library file "
                      "was found.\n", cmd.c_str(), version.str(&verbuf));
      }
      else
      {
        error.sprnt("Error parsing \"%s\" output", cmd.c_str());
      }
    }
    else
    {
      error.sprnt("Error calling \"%s\"", cmd.c_str());
    }
  }
  else
  {
    error.sprnt("\"%s\" is not available", config_util);
  }

  if ( !error.empty() )
    out_verb("%s. Cannot determine preferred version this way.\n",
             error.c_str());
}
#endif // __UNIX__

#if defined(__LINUX__) || defined(__MAC__)
#  ifdef __LINUX__
#    define SOSFX "so"
#  else
#    define SOSFX "dylib"
#  endif

#endif

//-------------------------------------------------------------------------
// Remove ANSI escape sequences (e.g., \x1b[36m...\x1b[39m) from a string
static void strip_ansi(qstring *s)
{
  while ( true )
  {
    size_t esc = s->find('\x1b');
    if ( esc == qstring::npos )
      break;
    size_t end = s->find('m', esc);
    if ( end == qstring::npos )
      break;
    s->remove(esc, end - esc + 1);
  }
}

//-------------------------------------------------------------------------
// Run a command and return its output as lines, with ANSI codes stripped.
// Returns non-zero on failure.
static int run_command(const char *cmd, qstrvec_t *lines, qstring *errbuf)
{
  out_verb("Running: \"%s\"\n", cmd);
#ifdef __NT__
  FILE *fp = _popen(cmd, "r");
#else
  FILE *fp = popen(cmd, "r");
#endif
  if ( fp == nullptr )
  {
    errbuf->sprnt("Command \"%s\" couldn't be run", cmd);
    return -1;
  }

  bytevec_t outbuf;
  uchar buf[MAXSTR];
  ssize_t nread;
  for ( ; ; )
  {
    nread = qfread(fp, buf, sizeof(buf));
    if ( nread > 0 )
      outbuf.append(buf, nread);
    else
      break;
  }

#ifdef __NT__
  int rc = _pclose(fp);
#else
  int rc = pclose(fp);
#endif
  if ( rc != 0 )
  {
    const char *out = outbuf.empty() ? "<empty>" : (const char *)outbuf.begin();
    errbuf->sprnt("Error calling \"%s\"; output is: %s", cmd, out);
    return rc;
  }

  // Split into lines and strip ANSI codes
  qstring all((const char *)outbuf.begin(), outbuf.size());
  all.split(lines, "\n", SSF_DROP_EMPTY);
  for ( auto &line : *lines )
    strip_ansi(&line);

  return 0;
}

//-------------------------------------------------------------------------
// Parse the output of "uv python list" and call process_install_dir
// for each unique cpython installation root found.
// Output format: "cpython-3.14.0-linux-x86_64-gnu  /path [-> target]"
//lint -esym(528, scan_uv_python_list) not referenced
template <typename F>
static void scan_uv_python_list(F process_install_dir)
{
  qstrvec_t lines;
  qstring errbuf;
  // Run from filesystem root so relative paths become absolute
#ifdef __NT__
  const char *cmd = "cmd /c \"cd \\ && uv --color never python list"
                    " --only-installed --all-versions 2>nul\"";
#else
  const char *cmd = "cd / && uv --color never python list"
                    " --only-installed --all-versions 2>/dev/null";
#endif
  if ( run_command(cmd, &lines, &errbuf) != 0 )
    return;

  qstrvec_t install_dirs;
  for ( const qstring &line : lines )
  {
    // Filter: only cpython, skip freethreaded builds (not supported)
    if ( !line.starts_with("cpython-") )
      continue;
    if ( line.find("+freethreaded") != qstring::npos )
      continue;

    // Extract path after the tag
    size_t path_start = line.find(' ');
    if ( path_start == qstring::npos )
      continue;
    while ( path_start < line.length() && qisspace(line[path_start]) )
      ++path_start;

    // Handle " -> target" symlink annotation (Unix only).
    // The target may be relative to the source's directory, so resolve it.
    qstring path;
    size_t arrow = line.find(" -> ", path_start);
    if ( arrow != qstring::npos )
    {
      qstring target = line.substr(arrow + 4);
      if ( qisabspath(target.c_str()) )
      {
        path = target;
      }
      else
      {
        // resolve relative target against the source path's directory
        qstring srcpath = line.substr(path_start, arrow - path_start);
        char srcdir[QMAXPATH];
        qdirname(srcdir, sizeof(srcdir), srcpath.c_str());
        char joined[QMAXPATH];
        qmakepath(joined, sizeof(joined), srcdir, target.c_str(), nullptr);
        qmake_full_path(joined, sizeof(joined), joined);
        path = joined;
      }
    }
    else
    {
      path = line.substr(path_start);
    }

    // Derive install root: up 2 levels on Unix (bin/python), 1 on Windows
    char install_dir[QMAXPATH];
    qdirname(install_dir, sizeof(install_dir), path.c_str());
#ifndef __NT__
    qdirname(install_dir, sizeof(install_dir), install_dir);
#endif

    if ( !install_dirs.has(install_dir) && qisdir(install_dir) )
    {
      out_verb("Found uv install dir: %s\n", install_dir);
      install_dirs.push_back(install_dir);
    }
  }

  for ( const qstring &dir : install_dirs )
    process_install_dir(dir.c_str());
}

//-------------------------------------------------------------------------
// Read ~/.conda/environments.txt and call process_env_dir
// for each conda environment root directory found.
// Conda maintains this file as a registry of all known environments.
const char *get_homedir(void); // diskio.hpp, internal

//lint -esym(528, scan_conda_envs) not referenced
template <typename F>
static void scan_conda_envs(F process_env_dir)
{
  char path[QMAXPATH];
#ifdef __NT__
  // on Windows, get_homedir() returns "My Documents" (CSIDL_PERSONAL),
  // but conda stores environments.txt under the user profile root
  if ( !get_special_folder(path, sizeof(path), CSIDL_PROFILE) )
    return;
#else
  qstrncpy(path, get_homedir(), sizeof(path));
#endif
  qmakepath(path, sizeof(path), path, ".conda", nullptr);
  qmakepath(path, sizeof(path), path, "environments.txt", nullptr);

  FILE *fp = qfopen(path, "r");
  if ( fp == nullptr )
    return;

  qstring env_dir;
  while ( qgetline(&env_dir, fp) >= 0 )
  {
    env_dir.trim2();
    if ( !env_dir.empty() && qisdir(env_dir.c_str()) )
    {
      out_verb("Found conda env: %s\n", env_dir.c_str());
      process_env_dir(env_dir.c_str());
    }
  }
  qfclose(fp);
}

//-------------------------------------------------------------------------
// Rewrite `path` to the user-facing IDA install dir for idalib, if it differs
// from the plain idadir() value. On macOS this maps ida.app/Contents/MacOS to
// the ida.app bundle root; on other platforms it's a no-op. Defined in the
// platform-specific idapyswitch_{linux,mac,win}.cpp file.
static void platform_normalize_install_dir(char *path, size_t bufsize);

//-------------------------------------------------------------------------
static bool get_current_install_dir(qstring *out, qstring *errbuf)
{
  const char *dir = idadir(nullptr);
  if ( dir == nullptr || dir[0] == '\0' )
  {
    errbuf->sprnt("couldn't determine IDA installation directory");
    return false;
  }

  char full[QMAXPATH];
  if ( qmake_full_path(full, sizeof(full), dir) == nullptr )
    qstrncpy(full, dir, sizeof(full));

  platform_normalize_install_dir(full, sizeof(full));

  *out = full;
  return true;
}

//-------------------------------------------------------------------------
static bool get_idalib_config_path(qstring *out, qstring *errbuf)
{
  const char *user_dir = get_user_idadir();
  if ( user_dir == nullptr || user_dir[0] == '\0' )
  {
    errbuf->sprnt("couldn't determine IDA user directory");
    return false;
  }

  if ( !qisdir(user_dir) && qmkdir(user_dir, 0777) != 0 && !qisdir(user_dir) )
  {
    errbuf->sprnt("couldn't create IDA user directory \"%s\": %s",
                  user_dir, winerr(errno));
    return false;
  }

  char path[QMAXPATH];
  qmakepath(path, sizeof(path), user_dir, "ida-config.json", nullptr);
  *out = path;
  return true;
}

//-------------------------------------------------------------------------
static bool load_or_create_idalib_config(
        jvalue_t *config,
        const char *path,
        qstring *errbuf)
{
  if ( !qfileexist(path) )
  {
    config->set_obj(new jobj_t);
    return true;
  }

  if ( parse_json_file(config, path, errbuf) != eOk )
    return false;

  if ( config->type() != JT_OBJ )
  {
    errbuf->sprnt("%s doesn't contain a JSON object", path);
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
static jobj_t &get_or_create_obj(jobj_t *parent, const char *key)
{
  jvalue_t *value = parent->get_value_or_new(key);
  if ( value->type() != JT_OBJ )
    value->set_obj(new jobj_t);
  return value->obj();
}

//-------------------------------------------------------------------------
// Write `config` to `path` atomically: write to a sibling .tmp file, then
// rename over the destination. This avoids leaving a truncated or partially
// written file visible to readers (e.g. the idapro Python package loading
// ida-config.json concurrently).
static bool write_json_file(
        const char *path,
        const jvalue_t &config,
        qstring *errbuf)
{
  qstring serialized;
  if ( !serialize_json(&serialized, config, SJF_PRETTY) )
  {
    errbuf->sprnt("couldn't serialize JSON");
    return false;
  }
  serialized.append('\n');

  qstring tmp_path;
  tmp_path.sprnt("%s.tmp", path);

  FILE *fp = qfopen(tmp_path.c_str(), "w");
  if ( fp == nullptr )
  {
    errbuf->sprnt("couldn't open %s for writing: %s",
                  tmp_path.c_str(), winerr(errno));
    return false;
  }
  bool ok = qfwrite(fp, serialized.c_str(), serialized.length())
         == ssize_t(serialized.length());
  if ( !ok )
    errbuf->sprnt("couldn't write %s: %s", tmp_path.c_str(), winerr(errno));
  qfclose(fp);

  if ( !ok || qrename(tmp_path.c_str(), path) != 0 )
  {
    if ( ok )
      errbuf->sprnt("couldn't rename %s to %s: %s",
                    tmp_path.c_str(), path, winerr(errno));
    qunlink(tmp_path.c_str());
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
static bool update_idalib_config(qstring *errbuf)
{
  if ( args.dry_run )
  {
    out_verb("Dry-run: not updating ida-config.json for idalib\n");
    return true;
  }

  qstring install_dir;
  if ( !get_current_install_dir(&install_dir, errbuf) )
    return false;

  qstring config_path;
  if ( !get_idalib_config_path(&config_path, errbuf) )
    return false;

  jvalue_t config;
  if ( !load_or_create_idalib_config(&config, config_path.c_str(), errbuf) )
    return false;

  jobj_t &root = config.obj();
  jobj_t &paths = get_or_create_obj(&root, "Paths");
  paths.put("ida-install-dir", install_dir);

  if ( !write_json_file(config_path.c_str(), config, errbuf) )
    return false;

  out_verb("Updated idalib configuration %s: %s\n",
           config_path.c_str(), install_dir.c_str());
  return true;
}

//-------------------------------------------------------------------------
static void update_idalib_config_or_warn(void)
{
  qstring errbuf;
  if ( !update_idalib_config(&errbuf) )
    out("Warning: failed to update ida-config.json for idalib: %s\n",
        errbuf.c_str());
}

#ifdef __LINUX__
#  include "idapyswitch_linux.cpp"
#else
#  ifdef __NT__
#    include "idapyswitch_win.cpp"
#  else
#    include "idapyswitch_mac.cpp"
#  endif
#endif

//-------------------------------------------------------------------------
static void set_verbose(const char *, void *) { args.verbose = true; }
static void set_auto_apply(const char *, void *) { args.auto_apply = true; }
static void set_dry_run(const char *, void *) { args.dry_run = true; }
static void set_force_path(const char *arg, void *) { args.force_path = arg; }
static void set_idalib(const char *, void *) { args.idalib = true; }
#ifdef __UNIX__
static void set_ignore_python_config(const char *, void *) { args.ignore_python_config = true; }
#endif

//-------------------------------------------------------------------------
static const cliopt_t _opts[] =
{
  { 'v', "verbose", "Verbose mode", set_verbose, 0 },
  { 'a', "auto-apply", "Run non-interactively; automatically apply the preferred version (if found)", set_auto_apply, 0 },
  { 'r', "dry-run", "Only report what would happen; don't do it", set_dry_run, 0 },
  { 's', "force-path",
#ifdef __LINUX__
    "Have IDAPython use the specified \"/path/to/libpython[...]so\" shared object",
#else
#  ifdef __NT__
    "Have IDAPython use the specified \"\\path\\to\\python3.dll\" DLL",
#  else
    "Have IDAPython use the specified \"/path/to/libpython[...]dylib\" dylib",
#  endif
#endif
    set_force_path,
    1
  },
  { 0, "idalib", nullptr, set_idalib, 0 },

#ifdef __UNIX__
  { 'k', "ignore-python-config", "Do not use python-config to find out the preferred version number", set_ignore_python_config, 0 },
#endif
};

//-------------------------------------------------------------------------
static const char usage_epilog[] =
  "Switch between available installations of Python3\n"
  "\n"
  "Because Python3 does not systematically install a single,\n"
  "always-available \"python3.dll\", \"libpython3.so\" or \"libpython3.dylib\",\n"
  "but rather allows for multiple versions of Python3 to be\n"
  "installed in parallel on a given system, many tools\n"
  "provide a way to switch between those versions.\n"
  "\n"
  "IDA is no exception, and this tool is one such Python3 'switcher'.\n"
  "Please note that the minimum supported version is Python 3.8.\n"
  "\n"
  "It can be run in 3 ways:\n"
  "\n"
  "  1) The default, interactive way\n"
  "  -------------------------------\n"
  "     > $ idapyswitch\n"
  "   will look on the filesystem for available Python3 installations,\n"
  "   present the user with a list of found versions (sorted according\n"
  "   to preferability), and let the user pick which one IDA should use.\n"
  "\n"
  "  2) The 'automatic' way\n"
  "  ----------------------\n"
  "     > $ idapyswitch --auto-apply\n"
  "   will look on the filesystem for available Python3 installations,\n"
  "   and automatically pick the one it deemed the most preferable.\n"
  "\n"
  "  3) The 'manual' way\n"
  "  -------------------\n"
#ifdef __NT__
  "     > $ idapyswitch --force-path C:\\Python38\\python3.dll\n"
#else
#  ifdef __LINUX__
  "     > $ idapyswitch --force-path /path/to/libpython3.8dm.so.1.2\n"
#  else
  "     > $ idapyswitch --force-path /path/to/Python.framework/Versions/3.8/Python\n"
#  endif
#endif
  "   will use the Python library that the user provided.\n"
  "   Please note that specifically the path to the library is needed.\n"
  "   Providing the path of the interpreter executable (python.exe/python3) will not work.\n"
  "\n"
  "Once a version is picked, this tool will place the path to the python library\n"
  "into the registry, so that IDA loads the correct one at runtime.\n"
#  ifdef __MAC__
  "    If you want to use a Python version installed via\n"
  "    Homebrew, note that locations may vary (brew info python).\n"
#  endif
  ;

//-------------------------------------------------------------------------
int main(int argc, const char **argv)
{
  cliopts_t opts(out);
  opts.epilog = usage_epilog;
  opts.add(_opts, qnumber(_opts));
  opts.apply(argc, argv);

  qstring errbuf;

  pyver_tool_t tool;

  if ( !args.force_path.empty() )
  {
    const char *path = args.force_path.c_str();
    pylib_version_t dummy_version;
    pylib_entry_t entry(dummy_version);
    if ( !tool.path_to_pylib_entry(&entry, path, &errbuf) )
    {
      error(EXIT_CODE_FORCE_PATH_FAILED,
            "Cannot determine python library version for \"%s\": %s\n",
            path, errbuf.c_str());
    }
    if ( !tool.apply_version(entry, &errbuf) )
    {
      qstring buf;
      error(EXIT_CODE_FORCE_PATH_FAILED,
            "Applying \"%s\" (extracted from path \"%s\") failed: %s\n",
            entry.str(&buf), path, errbuf.c_str());
    }
    if ( args.idalib )
      update_idalib_config_or_warn();
  }
  else
  {
    pylib_entries_t entries;
    tool.find_python_libs(&entries);

    const size_t nentries = entries.entries.size();
    if ( nentries > 0 )
    {
      qstring buf;
      const pylib_entry_t *preferred = nullptr;
      if ( args.auto_apply )
      {
        preferred = &entries.entries[0];
      }
      else
      {
        out("The following Python installations were found:\n");
        int numw = nentries >= 100 ? 3 : nentries >= 10 ? 2 : 1;
        int prefw = 0;
        int revw = 0;
        int raww = 0;
        for ( size_t i = 0; i < nentries; ++i )
        {
          const pylib_version_t &v = entries.entries[i].version;
          buf.sprnt("%d.%d", v.major, v.minor);
          if ( buf.length() > prefw )
            prefw = buf.length();
          buf.sprnt("%d%s", v.revision, v.modifiers.c_str());
          if ( buf.length() > revw )
            revw = buf.length();
          if ( v.raw.length() > raww )
            raww = v.raw.length();
        }
        for ( size_t i = 0; i < nentries; ++i )
        {
          out_ident_inc_t iinc;
          const pylib_entry_t &e = entries.entries[i];
          buf.sprnt("%d.%d", e.version.major, e.version.minor);
          qstring buf2;
          buf2.sprnt("%d%s", e.version.revision, e.version.modifiers.c_str());
          qstring buf3;
          buf3.sprnt("('%s')", e.version.raw.c_str());
          out("#%*" FMT_Z ": %*s.%-*s %-*s  (%s)\n",
              numw, i,
              prefw, buf.c_str(),
              revw, buf2.c_str(),
              raww + 4, buf3.c_str(),
              !e.paths.empty() ? e.paths[0].c_str() : "<unavailable path>");
        }

        size_t picked = size_t(-1);
        while ( picked >= nentries )
        {
          out("Please pick a number between 0 and %" FMT_Z " (default: 0)\n", nentries-1);
          char numbuf[MAXSTR];
          qfgets(numbuf, sizeof(numbuf), stdin);
          qstring qnumbuf(numbuf);
          qnumbuf.rtrim('\n');
          if ( qnumbuf.empty() )
            picked = 0;
          else
            picked = qatoll(qnumbuf.c_str());
        }
        preferred = &entries.entries[picked];
      }

      out("Applying version %s\n", preferred->version.str(&buf));
      if ( !tool.apply_version(*preferred, &errbuf) )
      {
        error(EXIT_CODE_APPLY_FAILED,
              "Apply failed: %s\n",
              errbuf.c_str());
      }
      if ( args.idalib )
        update_idalib_config_or_warn();
    }
    else
    {
      error(EXIT_CODE_NO_INSTALLS,
            "No suitable Python installations were found\n");
    }
  }

  return 0;
}
