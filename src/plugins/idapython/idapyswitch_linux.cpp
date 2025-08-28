#include "../../pro/registry.cpp"

#define IDA_ADDLIB_VALUE "Python3TargetDLL"


//-------------------------------------------------------------------------
static bool extract_version_from_libpython_filename(
        pylib_version_t *out,
        const char *p)
{
  return extract_version_from_str(out, p, "libpython", ".so");
}

//-------------------------------------------------------------------------
static int run_command(const char *_cmd, qstring *errbuf, bytevec_t *_outbuf = nullptr)
{
  qstring cmd(_cmd);
  if ( args.dry_run )
    cmd.insert("echo ");
  int rc = -1;
  out_verb("Running: \"%s\"\n", cmd.c_str());
  FILE *fp = popen(cmd.c_str(), "r");
  bytevec_t outbuf;
  if ( fp != nullptr )
  {
    uchar outs[MAXSTR];
    ssize_t nread;
    for ( ; ; )
    {
      nread = qfread(fp, outs, sizeof(outs));
      if ( nread > 0 )
        outbuf.append(outs, nread);
      else
        break;
    }
    rc = pclose(fp);
    if ( rc != 0 )
    {
      const char *out = outbuf.empty() ? "<empty>" : (const char *)outbuf.begin();
      errbuf->sprnt("Error calling \"%s\"; output is: %s", cmd.c_str(), out);
    }
    if ( _outbuf != nullptr )
      *_outbuf = outbuf;
  }
  else
  {
    errbuf->sprnt("Command \"%s\" couldn't be run", cmd.c_str());
  }
  return rc;
}

//---------------------------------------------------------------------------
static const char *getword(const char *ptr, qstring *word)
{
  while ( *ptr != '\0' && qisspace(*ptr) )
    ptr++;
  const char *start = ptr;
  while ( *ptr != '\0' && !qisspace(*ptr) )
    ptr++;
  if ( word != nullptr && ptr > start )
    *word = qstring(start, ptr-start);
  return ptr;
}

//-------------------------------------------------------------------------
// check that ldconfig library attributes match what we need
// examples:
// (libc6,x86-64)
// (libc6,AArch64)
// (libc6,x32)
// (libc6, OS ABI: Linux 3.2.0)
// (ELF)
static bool valid_attrs(const qstring &attrs)
{
  qstrvec_t vattr;
  attrs.split(&vattr, ",");
  if ( vattr.size() < 2 || vattr[0] != "(libc6" )
    return false;
#if defined(__ARM__)
  static const char my_arch[] = "AArch64";
#else
  static const char my_arch[] = "x86-64";
#endif
  return vattr[1].starts_with(my_arch);
}

//-------------------------------------------------------------------------
// simplified version of bytevec_t::qgetline() from pro/bytevec.cpp
static bool qgetline(const bytevec_t &bv, qstring *out, size_t *p_pos)
{
  size_t pos = *p_pos;
  if ( pos >= bv.size() )
    return false;

  size_t start = pos;
  size_t end = pos;
  while ( pos < bv.size() )
  {
    char c = bv.at(pos++);
    if ( c == '\n' )
      break;
    end = pos;
  }
  *out = qstring((char *)bv.begin() + start, end-start);
  *p_pos = pos;
  return true;
}

//-------------------------------------------------------------------------
void pyver_tool_t::do_find_python_libs(pylib_entries_t *result) const
{
  //
  // Find all libpython3*.so* known to ldconfig -p
  //  sample output:
  // 1199 libs found in cache `/etc/ld.so.cache'
  // <tab>libpython3.10.so.1.0 (libc6,x86-64) => /lib/x86_64-linux-gnu/libpython3.10.so.1.0
  // ....

  bytevec_t ldconfig;
  qstring errbuf;
  // where to find ldconfig
  static const char *paths[] =
  {
    "/sbin/ldconfig",   // default glibc path
    "/usr/bin/ldconfig",// Arch Linux
  };
  const char *p = nullptr;
  for ( int i = 0; i < qnumber(paths); i++ )
  {
    if ( qfileexist(paths[i]) )
    {
      p = paths[i];
      break;
    }
  }
  if ( p == nullptr )
    p = "ldconfig"; // hope it's in $PATH
  qstring cmd;
  cmd.sprnt("%s -p", p);
  if ( run_command(cmd.c_str(), &errbuf, &ldconfig) != 0 )
  {
    out_verb("error running ldconfig: %s\n",errbuf.c_str());
    return;
  }

  qstring buf;
  size_t pos = 0;
  while ( qgetline(ldconfig, &buf, &pos) )
  {
    const char *line = buf.c_str();
    if ( line[0] == '\t' )
    {
      qstring libname;
      getword(line+1, &libname);
      if ( libname.starts_with("libpython3.") )
      {
        out_verb("Matched line: \"%s\" (libname %s)\n", line+1, libname.c_str());
        qstring attrs;
        getword(line+1+libname.length(), &attrs);
        if ( valid_attrs(attrs) )
        {
          size_t ppath = buf.find(" => ");
          if ( ppath != qstring::npos )
          {
            qstring path = buf.substr(ppath + 4);
            out_verb("\t libpath: '%s')\n", path.c_str());
            pylib_version_t version;
            qstring verbuf;
            if ( extract_version_from_libpython_filename(&version, libname.c_str()) )
            {
              if ( version.major < args.major_version || version.minor < args.minor_version )
              {
                qstring verbuf;
                out_verb("Skipping %s: unsupported python version %s (%d.%d+ is required)",
                  path.c_str(), version.str(&verbuf), args.major_version, args.minor_version);
                continue;
              }
              const char *_binpath = path.c_str();
              out_verb("Found: \"%s\" (version: %s)\n", _binpath, version.str(&verbuf));
              // check for duplicate entries
              char buf[PATH_MAX];
              const char *binpath = realpath(_binpath, buf);
              if ( binpath == nullptr )
              {
                out_verb("Skipping %s: realpath() failed: %s\n", _binpath, winerr(errno));
                continue;
              }
              if ( result->path_history.find(binpath) != result->path_history.end() )
              {
                out_verb("Skipping %s: duplicate of %s\n", _binpath, binpath);
                continue;
              }
              result->path_history.push_back(binpath);
              result->add_entry(version, binpath);
            }
          }
        }
      }
    }
  }

  //
  // See if we already have one registered for IDA
  //
  qstring existing;
  if ( reg_read_string(&existing, IDA_ADDLIB_VALUE) )
  {
    out_verb("Previously used runtime: \"%s\"\n", existing.c_str());
    pylib_version_t version;
    qstring verbuf;
    const char *libname = qbasename(existing.c_str());
    if ( extract_version_from_libpython_filename(&version, libname) )
    {
      out("IDA previously used: \"%s\" (guessed version: %s). "
          "Making this the preferred version.\n",
          existing.c_str(), version.str(&verbuf));
      // do we have it in the list?
      bool found = false;
      for ( pylib_entry_t &e : result->entries )
      {
        if ( e.paths.has(existing) )
        {
          found = true;
          e.preferred = true;
        }
      }
      if ( !found )
      {
        // add a new one
        pylib_entry_t e(version);
        e.paths.push_back(existing);
        e.preferred = true;
        result->entries.push_back(e);
      }
    }
    else
    {
      out_verb("Ignoring path \"%s\"\n", existing.c_str());
    }
  }
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_path_to_pylib_entry(
        pylib_entry_t *entry,
        const char *path,
        qstring *errbuf) const
{
  const char *fname = qbasename(path);
  const bool ok = fname != nullptr && qfileexist(path);
  if ( ok )
  {
    extract_version_from_libpython_filename(&entry->version, fname);
    if ( entry->version.major < args.major_version || entry->version.minor < args.minor_version )
    {
      qstring verbuf;
      errbuf->sprnt("Unsupported python version %s (%d.%d+ is required)",
        entry->version.str(&verbuf), args.major_version, args.minor_version);
      return false;
    }
    entry->paths.push_back(path);
  }
  else
  {
    errbuf->sprnt("Couldn't parse file name \"%s\"", fname);
  }
  return ok;
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_apply_version(
        const pylib_entry_t &entry,
        qstring *errbuf) const
{
  qstring soname;
  for ( const auto &path : entry.paths )
  {
    const char *p = path.c_str();
    out_verb("Setting registry value %s to '%s'\n", IDA_ADDLIB_VALUE, p);
    reg_write_string(IDA_ADDLIB_VALUE, p);
    return true;
  }
  errbuf->sprnt("no paths present");
  return false;
}

