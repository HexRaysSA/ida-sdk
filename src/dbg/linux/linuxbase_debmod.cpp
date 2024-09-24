#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include "linuxbase_debmod.h"

//--------------------------------------------------------------------------
static inline const char *str_bitness(int bitness)
{
  switch ( bitness )
  {
    case 8:
      return "[64]";
    case 4:
      return "[32]";
    default:
      return "[x]";
  }
}

//--------------------------------------------------------------------------
static void build_process_ext_name(ext_process_info_t *pinfo)
{
  pinfo->ext_name = str_bitness(pinfo->addrsize);

  char buf[QMAXPATH];
  qsnprintf(buf, sizeof(buf), "/proc/%u/cmdline", pinfo->pid);

  FILE *cmdfp = qfopen(buf, "r");
  if ( cmdfp == nullptr )
  {
DEFEXT:
    pinfo->ext_name.append(" ");
    pinfo->ext_name.append(pinfo->name);
    return;
  }

  int size = qfread(cmdfp, buf, sizeof(buf));
  if ( size == 0 )
    goto DEFEXT;
  buf[size] = '\0';
  qfclose(cmdfp);

#ifdef __ANDROID__
  while ( size >= 0 && buf[size] == '\0' )
    size--;
  size++;
#endif

  // arguments are separated by '\0'
  for ( int i=0; i < size; )
  {
    const char *in = &buf[i];
    qstring arg = in;
    quote_cmdline_arg(&arg);
    pinfo->ext_name.append(" ");
    pinfo->ext_name.append(arg);

    i += strlen(in) + 1;
  }
}

//--------------------------------------------------------------------------
inline bool procps_get_exec_fname(
        int _pid,
        char *buf,
        size_t bufsize)
{
  char path[QMAXPATH];
  qsnprintf(path, sizeof(path), "/proc/%u/exe", _pid);
  int len = readlink(path, buf, bufsize-1);
  if ( len > 0 )
  {
    buf[len] = '\0';
    return true;
  }
  else
  {
    // ESXi keeps the real file name inside /proc/PID/exe (which is not a link)
    FILE *fp = qfopen(path, "r");
    if ( fp != nullptr )
    {
      len = qfread(fp, buf, bufsize);
      qfclose(fp);
      if ( len > 1 && len < bufsize && buf[0] == '/' ) // sanity check
      {
        buf[len] = '\0';
        return true;
      }
    }
  }
  buf[0] = '\0';
  return false;
}

//--------------------------------------------------------------------------
inline bool procps_get_ppid_comm(int *ppid, qstring *comm, int _pid)
{
  char path[QMAXPATH];
  qsnprintf(path, sizeof(path), "/proc/%u/stat", _pid);
  bool ok = false;
  FILE *fstat = qfopen(path, "r");
  if ( fstat != nullptr )
  {
    int spid;
    char sname[MAXSTR+1];
    char sstate;
    *ppid = 0;
    // (1) pid   %d The process ID
    // (2) comm  %s The filename of the executable, in parentheses
    //              Strings longer than TASK_COMM_LEN (16) characters
    //              (including the terminating null byte) are silently
    //              truncated
    // (3) state %c One of the following characters, indicating process state
    // (4) ppid  %d The PID of the parent of this process.
    ok = qfscanf(fstat, "%d %" SMAXSTR "s %c %d", &spid, sname, &sstate, ppid) == 4;
    if ( ok && comm != nullptr )
      *comm = sname;
    qfclose(fstat);
  }
  return ok;
}

//--------------------------------------------------------------------------
// Returns the file name associated with pid
bool idaapi linuxbase_debmod_t::get_exec_fname(
        int _pid,
        char *buf,
        size_t bufsize)
{
  if ( procps_get_exec_fname(_pid, buf, bufsize) )
    return true;

  // forked process may lack /proc/_PID/exe file and
  // /proc/_PID/cmdlines empty in such case
  int ppid;
  qstring comm;
  while ( procps_get_ppid_comm(&ppid, &comm, _pid) && ppid != 1 )
  {
    _pid = ppid;
    if ( procps_get_exec_fname(_pid, buf, bufsize) )
    {
#ifdef __ANDROID__
      memcpy(buf, comm.c_str(), bufsize);
#endif
      return true;
    }
  }

  buf[0] = '\0';
  return false;
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi linuxbase_debmod_t::get_process_bitness(int _pid)
{
  char fname[QMAXPATH];
  qsnprintf(fname, sizeof(fname), "/proc/%u/maps", _pid);
  FILE *mapfp = fopenRT(fname);
  if ( mapfp == nullptr )
    return 0;

  int bitness = 0;
  qstring line;
  while ( qgetline(&line, mapfp) >= 0 )
  {
    if ( line.empty() )
      continue;
    bitness = 4;
    ea_t ea1;
    ea_t ea2;
    if ( qsscanf(line.begin(), "%a-%a ", &ea1, &ea2) == 2 )
    {
      size_t pos = line.find('-');
      if ( pos != qstring::npos && pos > 8 )
      {
        bitness = 8;
        break;
      }
    }
  }
  qfclose(mapfp);
  return bitness;
}

//--------------------------------------------------------------------------
int idaapi linuxbase_debmod_t::get_process_list(procvec_t *list, qstring *)
{
  int mypid = getpid();
  list->clear();
  qffblk64_t fb;
  for ( int code = qfindfirst("/proc/*", &fb, FA_DIREC);
        code == 0;
        code = qfindnext(&fb) )
  {
    if ( !qisdigit(fb.ff_name[0]) )
      continue;
    ext_process_info_t pinfo;
    pinfo.pid = atoi(fb.ff_name);
    if ( pinfo.pid == mypid )
      continue;
    char buf[MAXSTR];
    if ( !get_exec_fname(pinfo.pid, buf, sizeof(buf)) )
      continue; // we skip the process because we cannot debug it anyway
    pinfo.name = buf;
    pinfo.addrsize = get_process_bitness(pinfo.pid);
    build_process_ext_name(&pinfo);
    list->push_back(pinfo);
  }
  return list->size();
}
