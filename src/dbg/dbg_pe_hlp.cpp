#if defined(__NT__) && !defined(__X86__)
//--------------------------------------------------------------------------
static bool path_start_match(const char *s, const char *f)
{
  if ( f == nullptr || s == nullptr || *f == 0 || *s == 0 )
    return false;
  if ( s == f )
    return true;
  qstring t1(s);
  qstring t2(f);
  size_t l1 = t1.length();
  size_t l2 = t2.length();
  t1.replace("\\", "/");
  t2.replace("\\", "/");
  if ( t1[l1-1] == '/' )
    --l1;
  if ( t2[l2-1] == '/' )
    --l2;
  if ( l1 > l2
    || l1 < l2 && t2[l1] != '/' )
  {
    return false;
  }
  return memicmp(t1.c_str(), t2.c_str(), l1) == 0;
}

//--------------------------------------------------------------------------
static void replace_system32(char *path, size_t sz)
{
  char spath[MAXSTR];
  spath[0] = 0;
  GetSystemDirectoryA(spath, sizeof(spath));
  if ( spath[0] == 0 || !path_start_match(spath, path) )
    return;
  char wpath[MAXSTR];
  wpath[0] = 0;
  GetSystemWow64Directory(wpath, sizeof(wpath));
  if ( wpath[0] == 0 || path_start_match(wpath, spath) )
    return;
  size_t len = strlen(wpath);
  if ( wpath[len-1] == '/' || wpath[len-1] == '\\' )
    wpath[len-1] = 0;
  len = strlen(spath);
  if ( spath[len-1] == '/' || spath[len-1] == '\\' )
  {
    --len;
    path[len] = 0;
  }
  qstring n;
  n.sprnt("%s%s", wpath, &path[len]);
  qstrncpy(path, n.c_str(), sz);
}
#else
#define replace_system32(PATH, SZ) do {} while ( false )
#endif


