#include <elf.h>

#include "../../pro/registry.cpp"

#define IDA_ADDLIB_VALUE "Python3TargetDLL"

//-------------------------------------------------------------------------
static void platform_normalize_install_dir(char *, size_t)
{
}

//-------------------------------------------------------------------------
// Try to read the Py_Version constant from a libpython shared library
// without loading it. Py_Version is available starting from Python 3.11.
// Encoding: (major << 24) | (minor << 16) | (micro << 8) | (releaselevel << 4) | serial
static bool read_py_version_from_elf(
        int *major,
        int *minor,
        int *micro,
        const char *path)
{
  // reasonable upper bound for section table and string table sizes
  // to avoid allocating huge buffers on corrupt files
  static const size_t MAX_TABLE_SIZE = 64 * 1024 * 1024;

  FILE *fp = qfopen(path, "rb");
  if ( fp == nullptr )
    return false;

  bool ok = false;

  // get file size for offset validation
  qfseek(fp, 0, SEEK_END);
  uint64 fsize = qftell(fp);
  qfseek(fp, 0, SEEK_SET);

  // read and validate the ELF header
  Elf64_Ehdr ehdr;
  if ( qfread(fp, &ehdr, sizeof(ehdr)) != sizeof(ehdr)
    || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
    || ehdr.e_ident[EI_CLASS] != ELFCLASS64
    || ehdr.e_ident[EI_DATA] != ELFDATA2LSB
    || ehdr.e_shentsize != sizeof(Elf64_Shdr)
    || ehdr.e_shnum == 0 )
  {
    qfclose(fp);
    return false;
  }

  // validate section header table fits in the file
  size_t shnum = ehdr.e_shnum;
  uint64 shtab_size = shnum * sizeof(Elf64_Shdr);
  if ( ehdr.e_shoff >= fsize || shtab_size > fsize - ehdr.e_shoff )
  {
    qfclose(fp);
    return false;
  }

  // read section headers
  qvector<Elf64_Shdr> shdrs;
  shdrs.resize(shnum);
  qfseek(fp, ehdr.e_shoff, SEEK_SET);
  if ( qfread(fp, shdrs.begin(), shtab_size) != shtab_size )
  {
    qfclose(fp);
    return false;
  }

  // find .dynsym and its string table
  char *strings = nullptr;
  for ( size_t si = 0; si < shnum; ++si )
  {
    if ( shdrs[si].sh_type != SHT_DYNSYM )
      continue;

    const Elf64_Shdr &symtab = shdrs[si];

    // validate sh_link points to a valid section
    if ( symtab.sh_link >= shnum )
      break;
    const Elf64_Shdr &strtab = shdrs[symtab.sh_link];

    // validate sizes and offsets
    if ( symtab.sh_entsize != sizeof(Elf64_Sym) )
      break;
    if ( symtab.sh_size > MAX_TABLE_SIZE
      || strtab.sh_size > MAX_TABLE_SIZE
      || strtab.sh_size == 0 )
    {
      break;
    }
    if ( symtab.sh_offset >= fsize || symtab.sh_size > fsize - symtab.sh_offset
      || strtab.sh_offset >= fsize || strtab.sh_size > fsize - strtab.sh_offset )
    {
      break;
    }

    // read string table; ensure it is NUL-terminated
    char *strings = (char *)malloc(strtab.sh_size);
    if ( strings == nullptr )
      break;
    qfseek(fp, strtab.sh_offset, SEEK_SET);
    if ( qfread(fp, strings, strtab.sh_size) != strtab.sh_size )
      break;
    strings[strtab.sh_size - 1] = '\0';

    // read symbol table
    size_t nsyms = symtab.sh_size / sizeof(Elf64_Sym);
    qvector<Elf64_Sym> syms;
    syms.resize(nsyms);
    qfseek(fp, symtab.sh_offset, SEEK_SET);
    if ( qfread(fp, syms.begin(), nsyms * sizeof(Elf64_Sym)) != nsyms * sizeof(Elf64_Sym) )
      break;

    // find Py_Version
    for ( size_t j = 0; j < nsyms; ++j )
    {
      const Elf64_Sym &sym = syms[j];
      if ( sym.st_name >= strtab.sh_size )
        continue;
      if ( !streq(&strings[sym.st_name], "Py_Version") )
        continue;
      if ( sym.st_shndx == SHN_UNDEF || sym.st_shndx >= shnum )
        break;
      // validate that the symbol points within its section
      const Elf64_Shdr &dsec = shdrs[sym.st_shndx];
      if ( sym.st_value < dsec.sh_addr
        || sym.st_value - dsec.sh_addr + sizeof(uint64) > dsec.sh_size )
      {
        break;
      }
      // read the value from the file
      uint64 file_offset = dsec.sh_offset + (sym.st_value - dsec.sh_addr);
      if ( file_offset + sizeof(uint64) > fsize )
        break;
      uint64 val = 0;
      qfseek(fp, file_offset, SEEK_SET);
      if ( qfread(fp, &val, sizeof(val)) == sizeof(val) )
      {
        *major = (val >> 24) & 0xFF;
        *minor = (val >> 16) & 0xFF;
        *micro = (val >> 8) & 0xFF;
        ok = true;
      }
      break;
    }
    break;
  }

  free(strings);
  qfclose(fp);
  return ok;
}

//-------------------------------------------------------------------------
static bool extract_version_from_libpython_filename(
        pylib_version_t *out,
        const char *p)
{
  return extract_version_from_str(out, p, "libpython", ".so");
}

//-------------------------------------------------------------------------
// Extract version from a libpython shared library: parse the filename,
// then try to refine with the Py_Version ELF symbol (available in 3.11+).
static bool extract_libpython_version(
        pylib_version_t *out,
        const char *libpath)
{
  const char *libname = qbasename(libpath);
  if ( libname == nullptr
    || !qfileexist(libpath)
    || !extract_version_from_libpython_filename(out, libname) )
  {
    return false;
  }
  if ( out->major > 3 || (out->major == 3 && out->minor >= 11) )
  {
    int elf_major, elf_minor, elf_micro;
    if ( read_py_version_from_elf(&elf_major, &elf_minor, &elf_micro, libpath) )
    {
      out_verb("Py_Version from ELF: %d.%d.%d\n", elf_major, elf_minor, elf_micro);
      out->major = elf_major;
      out->minor = elf_minor;
      out->revision = elf_micro;
      out->raw.sprnt("%d.%d%s", elf_major, elf_minor, out->modifiers.c_str());
    }
  }
  return true;
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
// Helper to add a libpython path to results with version check and deduplication
static bool try_add_libpython(
        pylib_entries_t *result,
        const char *libpath)
{
  pylib_version_t version;
  if ( !extract_libpython_version(&version, libpath) )
    return false;

  if ( version.modifiers.find('t') != qstring::npos )
  {
    out_verb("Skipping %s: freethreaded python is not supported\n", libpath);
    return false;
  }

  if ( version.major != args.major_version || version.minor < args.minor_version )
  {
    qstring verbuf;
    out_verb("Skipping %s: unsupported python version %s (%d.%d+ is required)\n",
      libpath, version.str(&verbuf), args.major_version, args.minor_version);
    return false;
  }

  char realpathbuf[PATH_MAX];
  const char *resolved = realpath(libpath, realpathbuf);
  if ( resolved == nullptr )
  {
    out_verb("Skipping %s: realpath() failed: %s\n", libpath, winerr(errno));
    return false;
  }

  if ( result->path_history.find(resolved) != result->path_history.end() )
  {
    out_verb("Skipping %s: duplicate of %s\n", libpath, resolved);
    return false;
  }

  qstring verbuf;
  out_verb("Found: \"%s\" (version: %s)\n", resolved, version.str(&verbuf));
  result->path_history.push_back(resolved);
  result->add_entry(version, resolved);
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

  qstrvec_t lines;
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
  if ( run_command(cmd.c_str(), &lines, &errbuf) != 0 )
  {
    out_verb("error running ldconfig: %s\n", errbuf.c_str());
    return;
  }

  for ( const qstring &buf : lines )
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
            try_add_libpython(result, path.c_str());
          }
        }
      }
    }
  }

  //
  // Scan uv-managed Python installations
  //
  scan_uv_python_list([result](const char *version_dir)
  {
    char libdir[QMAXPATH];
    qmakepath(libdir, sizeof(libdir), version_dir, "lib", nullptr);
    if ( !qisdir(libdir) )
      return;

    char libpattern[QMAXPATH];
    qmakepath(libpattern, sizeof(libpattern), libdir, "libpython3*.so*", nullptr);

    qffblk64_t lib_fb;
    for ( int lib_code = qfindfirst(libpattern, &lib_fb, 0);
          lib_code == 0;
          lib_code = qfindnext(&lib_fb) )
    {
      char libpath[QMAXPATH];
      qmakepath(libpath, sizeof(libpath), libdir, lib_fb.ff_name, nullptr);
      try_add_libpython(result, libpath);
    }
    qfindclose(&lib_fb);
  });

  //
  // Scan conda-managed Python environments
  //
  scan_conda_envs([result](const char *env_dir)
  {
    char libdir[QMAXPATH];
    qmakepath(libdir, sizeof(libdir), env_dir, "lib", nullptr);
    if ( !qisdir(libdir) )
      return;

    char libpattern[QMAXPATH];
    qmakepath(libpattern, sizeof(libpattern), libdir, "libpython3*.so*", nullptr);

    qffblk64_t lib_fb;
    for ( int lib_code = qfindfirst(libpattern, &lib_fb, 0);
          lib_code == 0;
          lib_code = qfindnext(&lib_fb) )
    {
      char libpath[QMAXPATH];
      qmakepath(libpath, sizeof(libpath), libdir, lib_fb.ff_name, nullptr);
      try_add_libpython(result, libpath);
    }
    qfindclose(&lib_fb);
  });

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
    if ( qfileexist(existing.c_str())
      && extract_version_from_libpython_filename(&version, libname) )
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
  const bool ok = extract_libpython_version(&entry->version, path);
  if ( ok )
  {
    if ( entry->version.major != args.major_version || entry->version.minor < args.minor_version )
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
    errbuf->sprnt("Couldn't parse file name \"%s\"", path);
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

