//-------------------------------------------------------------------------
// Mimic GDB's debug file-seeking mechanism. Let:
//   PATH      be for-each components of the full DWARF_DEBUG_FILE_DIRECTORY.
//   BIN       be the full path to the binary file.
//   DLINK     the value of the section ".gnu_debuglink"
//   BLDID     build ID from note section GNU/3
//      BLDCAR the lowercase hex-formatted value of the first byte of BLDID
//      BLDCDR the lowercase hex-formatted value of the remaining bytes of BLDID
//
// 1) Look for file by build ID
//    foreach PATH in DWARF_DEBUG_FILE_DIRECTORY:
//        if $PATH/.build-id/$BLDCAR/$BLDCRD.debug exists and matches:
//            found!
// 2) If not found, look for file by debug link
//    if dir($BIN)/$DLINK exists and matches:
//        found!
//    if dir($BIN)/.debug/$DLINK exists and matches:
//        found!
//    foreach PATH in DWARF_DEBUG_FILE_DIRECTORY:
//        if $PATH/dir($BIN)/$DLINK exists and matches:
//            found!
class debug_info_file_visitor_t
{
public:
  char fullpath[MAXSTR];    // current path
  enum checkmethod_t
  {
    BUILDID,
    DEBUGLINK
  };

  // visit fullpath
  // returns 0 - continue to search
  virtual int visit_fullpath(checkmethod_t check_method)
  {
    int code = 0;
    if ( qfileexist(fullpath) )
    {
      code = 1;
      if ( check_method == DEBUGLINK )
        code = check_debuglink_crc32() ? 1 : 0;
    }
    return code;
  }

  int call_visit_fullpath(checkmethod_t check_method)
  {
    int code = visit_fullpath(check_method);
    debugout("debug_info_file_visitor_t::visit_fullpath(check_method=%s), fullpath=%s => %d\n",
             check_method == BUILDID ? "BUILDID" : "DEBUGLINK",
             fullpath,
             code);
    return code;
  }

  debug_info_file_visitor_t(
          const char *_glbl_deb_dirs,     // global debug directories
          bool from_envvar,               // taken from environment variable
          const char *_path_to_binary,    // binary's absolute file name
          const char *_debuglink,         // name of the separate debug info file
          uint32 _debuglink_crc32,        // CRC32 of the separate debug info file
          const char *_buildid)           // build ID
    : path_to_binary(_path_to_binary),
      debuglink(_debuglink),
      buildid(_buildid),
      debuglink_crc32(_debuglink_crc32)
  {
    fullpath[0] = '\0';
    const char *sep = from_envvar ? DELIMITER : ";";    //-V583
    char buf[QMAXPATH];
    qstrncpy(buf, _glbl_deb_dirs, sizeof(buf));
    char *saved_ptr;
    char *p = qstrtok(buf, sep, &saved_ptr);
    while ( p != nullptr )
    {
      glbl_deb_dirs.push_back(p);
      p = qstrtok(nullptr, sep, &saved_ptr);
    }
  }
  virtual ~debug_info_file_visitor_t() {}

  // accept visitor
  // stop searching if visitor returns non-zero,
  // returns visitor's result
  int accept(void)
  {
    int code = 0;

    // Look for file by build ID
    if ( !glbl_deb_dirs.empty() && buildid.length() > 2 )
    {
      // looks in the .build-id subdirectory of each one of the global debug directories
      // for a file named nn/nnnnnnnn.debug,
      // where nn are the first 2 hex characters of the build ID bit string,
      // and nnnnnnnn are the rest of the bit string
      qstring bid_car(buildid.substr(0, 2));
      qstring bid_cdr(buildid.substr(2));
      bid_cdr.append(".debug");

      for ( qstrvec_t::const_iterator p=glbl_deb_dirs.begin(); p != glbl_deb_dirs.end(); ++p )
      {
        qmakepath(fullpath, sizeof(fullpath), p->c_str(), ".build-id", bid_car.c_str(), bid_cdr.c_str(), nullptr);
        code = call_visit_fullpath(BUILDID);
        if ( code != 0 )
          goto END;
      }
    }

    // If not found, look for file by debug link
    if ( !debuglink.empty() )
    {
      char bindir[QMAXPATH];
      if ( qdirname(bindir, sizeof(bindir), path_to_binary.c_str()) )
      {
        // in the directory of the executable file
        qmakepath(fullpath, sizeof(fullpath), bindir, debuglink.c_str(), nullptr);
        code = call_visit_fullpath(DEBUGLINK);
        if ( code != 0 )
          goto END;

        // then in a subdirectory of that directory named .debug
        qmakepath(fullpath, sizeof(fullpath), bindir, ".debug", debuglink.c_str(), nullptr);
        code = call_visit_fullpath(DEBUGLINK);
        if ( code != 0 )
          goto END;

        // and finally under each one of the global debug directories,
        // in a subdirectory whose name is identical to the leading directories
        // of the executable's absolute file name
        for ( qstrvec_t::const_iterator p=glbl_deb_dirs.begin(); p != glbl_deb_dirs.end(); ++p )
        {
          qmakepath(fullpath, sizeof(fullpath), p->c_str(), bindir, debuglink.c_str(), nullptr);
          code = call_visit_fullpath(DEBUGLINK);
          if ( code != 0 )
            goto END;
        }
      }
    }

    END:
      return code;
  }

  // check debuglink file CRC32
  bool check_debuglink_crc32(void)
  {
    linput_t *li = open_linput(fullpath, false);
    uint32 crc32 = calc_file_crc32(li);
    close_linput(li);
    return debuglink_crc32 == crc32;
  }

private:
  qstrvec_t glbl_deb_dirs;
  const qstring path_to_binary;
  const qstring debuglink;
  const qstring buildid;
  uint32 debuglink_crc32;

  AS_PRINTF(2, 3) void debugout(const char *format, ...)
  {
    if ( (debug & LOOK_FOR_DEBUG_FILE_DEBUG_FLAG) != 0 )
    {
      va_list va;
      va_start(va, format);
      vmsg(format, va);
      va_end(va);
    }
  }
};
#undef DIFV_DEB
