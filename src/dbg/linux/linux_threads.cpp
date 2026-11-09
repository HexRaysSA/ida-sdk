/*
*        Thread support for IDA debugger under Linux.
*
*  There are two approaches to handle threads:
*  1. PTRACE_O_TRACECLONE (since Linux 2.5.46)
*  2. libthread_db.so (the oldest one)
*
*  At first we are testing the PTRACE_O_TRACECLONE ability.
*  In case of success the approach 1. will be used.
*  Otherwise we will try the approach 2.
*
*  User is able to set IDA_USE_LIBTHREAD_DB environment variable to skip
*  the 1. approach.
*
*/

// debugging multi-threaded program
enum mt_state_t
{
  MT_UNKN,     // not detected yet
  MT_NONE,    // disabled
  MT_CLONE,   // PTRACE_O_TRACECLONE
  MT_LIB,     // libthread_db.so
};
static uint32 mt_state = MT_UNKN;

//-------------------------------------------------------------------
//#define TDEB     // debug threads
#ifdef TDEB
#define ddeb(x) _ddeb x
AS_PRINTF(1, 2) inline void _ddeb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}
#else
#define ddeb(x) (void)0
#endif

//==========================================================================
// thread_db
//==========================================================================

//-------------------------------------------------------------------
//#define MANUALLY_LOAD_THREAD_DB
#ifdef MANUALLY_LOAD_THREAD_DB
// On some systems libthread_db cannot be linked statically because only .so files exists.
// Also, linking it statically is probably a bad idea because it is closely
// tied to the thread implementation.
// Therefore we manually load libthread_db.so.

// Prototypes of functions we use from libthread_db.so:
typedef td_err_e td_init_t(void);
typedef td_err_e td_ta_delete_t(td_thragent_t *__ta);
typedef td_err_e td_ta_event_addr_t(const td_thragent_t *__ta, td_event_e __event, td_notify_t *__ptr);
typedef td_err_e td_ta_event_getmsg_t(const td_thragent_t *__ta, td_event_msg_t *__msg);
typedef td_err_e td_ta_map_lwp2thr_t(const td_thragent_t *__ta, lwpid_t __lwpid, td_thrhandle_t *__th);
typedef td_err_e td_ta_new_t(struct ps_prochandle *__ps, td_thragent_t **__ta);
typedef td_err_e td_ta_set_event_t(const td_thragent_t *__ta, td_thr_events_t *__event);
typedef td_err_e td_ta_thr_iter_t(const td_thragent_t *__ta, td_thr_iter_f *__callback, void *__cbdata_p, td_thr_state_e __state, int __ti_pri, sigset_t *__ti_sigmask_p, unsigned int __ti_user_flags);
typedef td_err_e td_thr_event_enable_t(const td_thrhandle_t *__th, int __event);
typedef td_err_e td_thr_get_info_t(const td_thrhandle_t *__th, td_thrinfo_t *__infop);
typedef td_err_e td_thr_setsigpending_t(const td_thrhandle_t *__th, unsigned char __n, const sigset_t *__ss);
typedef td_err_e td_thr_set_event_t(const td_thrhandle_t *__th, td_thr_events_t *__event);

// Pointers to imported functions:
static td_init_t              *p_td_init              = nullptr;
static td_ta_delete_t         *p_td_ta_delete         = nullptr;
static td_ta_event_addr_t     *p_td_ta_event_addr     = nullptr;
static td_ta_event_getmsg_t   *p_td_ta_event_getmsg   = nullptr;
static td_ta_map_lwp2thr_t    *p_td_ta_map_lwp2thr    = nullptr;
static td_ta_new_t            *p_td_ta_new            = nullptr;
static td_ta_set_event_t      *p_td_ta_set_event      = nullptr;
static td_ta_thr_iter_t       *p_td_ta_thr_iter       = nullptr;
static td_thr_event_enable_t  *p_td_thr_event_enable  = nullptr;
static td_thr_get_info_t      *p_td_thr_get_info      = nullptr;
static td_thr_setsigpending_t *p_td_thr_setsigpending = nullptr;
static td_thr_set_event_t     *p_td_thr_set_event     = nullptr;

struct symbol_resolve_info_t
{
  const char *name;
  void **ptr;
};
static symbol_resolve_info_t tdsyms[] =
{
  { "td_init",                (void**)&p_td_init              },
  { "td_ta_delete",           (void**)&p_td_ta_delete         },
  { "td_ta_event_addr",       (void**)&p_td_ta_event_addr     },
  { "td_ta_event_getmsg",     (void**)&p_td_ta_event_getmsg   },
  { "td_ta_map_lwp2thr",      (void**)&p_td_ta_map_lwp2thr    },
  { "td_ta_new",              (void**)&p_td_ta_new            },
  { "td_ta_set_event",        (void**)&p_td_ta_set_event      },
  { "td_ta_thr_iter",         (void**)&p_td_ta_thr_iter       },
  { "td_thr_event_enable",    (void**)&p_td_thr_event_enable  },
  { "td_thr_get_info",        (void**)&p_td_thr_get_info      },
  { "td_thr_setsigpending",   (void**)&p_td_thr_setsigpending },
  { "td_thr_set_event",       (void**)&p_td_thr_set_event     },
};

// These definitions make our source code the same:
#define td_init              p_td_init
#define td_ta_delete         p_td_ta_delete
#define td_ta_event_addr     p_td_ta_event_addr
#define td_ta_event_getmsg   p_td_ta_event_getmsg
#define td_ta_map_lwp2thr    p_td_ta_map_lwp2thr
#define td_ta_new            p_td_ta_new
#define td_ta_set_event      p_td_ta_set_event
#define td_ta_thr_iter       p_td_ta_thr_iter
#define td_thr_event_enable  p_td_thr_event_enable
#define td_thr_get_info      p_td_thr_get_info
#define td_thr_setsigpending p_td_thr_setsigpending
#define td_thr_set_event     p_td_thr_set_event

//--------------------------------------------------------------------------
static bool load_libthread_db_so(void)
{
  if ( p_td_init == nullptr )
  {
    const char *file = "libthread_db.so";
    void *lib = dlopen(file, RTLD_NOW);
    if ( lib == nullptr )
    {
      msg("dlopen(%s): %s\n", file, dlerror());
      return false;
    }
    for ( int i=0; i < qnumber(tdsyms); i++ )
    {
      *tdsyms[i].ptr = dlsym(lib, tdsyms[i].name);
      const char *err = dlerror();
      if ( err != nullptr )
      {
        msg("dlsym(%s.%s): %s\n", file, tdsyms[i].name, err);
        dlclose(lib);
        return false;
      }
    }
  }
  return true;
}
#else   // Automatic loading of libthread_db.so
inline bool load_libthread_db_so(void) { return true; }
#endif  // MANUALLY_LOAD_THREAD_DB

typedef std::map<qstring, ea_t> psnames_t;
static psnames_t psname_cache;

static bool tdb_inited = false;

//--------------------------------------------------------------------------
#define COMPLAIN_IF_FAILED(func, err)          \
  do                                           \
  {                                            \
    if ( err != TD_OK )                        \
      msg("%s: %s\n", func, tdb_strerr(err));  \
  }                                            \
  while ( 0 )

#define DIE_IF_FAILED(func, err)               \
  do                                           \
  {                                            \
    if ( err != TD_OK )                        \
      error("%s: %s\n", func, tdb_strerr(err));\
  }                                            \
  while ( 0 )

static const char *tdb_strerr(td_err_e err)
{
  static char buf[64];
  switch ( err )
  {
    case TD_OK:          return "ok";
    case TD_ERR:         return "generic error";
    case TD_NOTHR:       return "no thread to satisfy query";
    case TD_NOSV:        return "no sync handle to satisfy query";
    case TD_NOLWP:       return "no LWP to satisfy query";
    case TD_BADPH:       return "invalid process handle";
    case TD_BADTH:       return "invalid thread handle";
    case TD_BADSH:       return "invalid synchronization handle";
    case TD_BADTA:       return "invalid thread agent";
    case TD_BADKEY:      return "invalid key";
    case TD_NOMSG:       return "no event message for getmsg";
    case TD_NOFPREGS:    return "FPU register set not available";
    case TD_NOLIBTHREAD: return "application not linked with libpthread";
    case TD_NOEVENT:     return "requested event is not supported";
    case TD_NOCAPAB:     return "capability not available";
    case TD_DBERR:       return "debugger service failed";
    case TD_NOAPLIC:     return "operation not applicable to";
    case TD_NOTSD:       return "no thread-specific data for this thread";
    case TD_MALLOC:      return "malloc failed";
    case TD_PARTIALREG:  return "only part of register set was written/read";
    case TD_NOXREGS:     return "X register set not available for this thread";
#ifdef TD_TLSDEFER
    case TD_TLSDEFER:    return "thread has not yet allocated TLS for given module";
#endif
#ifdef TD_VERSION
    case TD_VERSION:     return "versions of libpthread and libthread_db do not match";
#endif
#ifdef TD_NOTLS
    case TD_NOTLS:       return "there is no TLS segment in the given module";
#endif
    default:
      qsnprintf(buf, sizeof(buf), "tdb error %d", err);
      return buf;
  }
}

//--------------------------------------------------------------------------
// Debug print functions
//{{{
#ifdef TDEB
static const char *tdb_event_name(int ev)
{
  static const char *const names[] =
  {
    "READY",       //  1
    "SLEEP",       //  2
    "SWITCHTO",    //  3
    "SWITCHFROM",  //  4
    "LOCK_TRY",    //  5
    "CATCHSIG",    //  6
    "IDLE",        //  7
    "CREATE",      //  8
    "DEATH",       //  9
    "PREEMPT",     // 10
    "PRI_INHERIT", // 11
    "REAP",        // 12
    "CONCURRENCY", // 13
    "TIMEOUT",     // 14
  };
  if ( ev > 0 && ev <= qnumber(names) )
    return names[ev-1];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", ev);
  return buf;
}

//--------------------------------------------------------------------------
static char *get_thr_events_str(const td_thr_events_t &set)
{
  static char buf[MAXSTR];
  char *ptr = buf;
  char *end = buf + sizeof(buf);
  for ( int i=TD_MIN_EVENT_NUM; i <= TD_MAX_EVENT_NUM; i++ )
  {
    if ( td_eventismember(&set, i) )
    {
      if ( ptr != buf )
        APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, tdb_event_name(i));
    }
  }
  return buf;
}

//--------------------------------------------------------------------------
static const char *get_sigset_str(const sigset_t &set)
{
  static char buf[MAXSTR];
  char *ptr = buf;
  char *end = buf + sizeof(buf);
  for ( int i=0; i <= 32; i++ )
  {
    if ( sigismember(CONST_CAST(sigset_t*)(&set), i) )
    {
      if ( ptr != buf )
        APPCHAR(ptr, end, ' ');
      ptr += qsnprintf(ptr, end-ptr, "%d", i);
    }
  }
  return buf;
}

//--------------------------------------------------------------------------
static const char *get_thread_state_name(td_thr_state_e state)
{
  static const char *const names[] =
  {
    "ANY_STATE",      //  0
    "UNKNOWN",        //  1
    "STOPPED",        //  2
    "RUN",            //  3
    "ACTIVE",         //  4
    "ZOMBIE",         //  5
    "SLEEP",          //  6
    "STOPPED_ASLEEP"  //  7
  };
  if ( state >= 0 && state < qnumber(names) )
    return names[state];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", state);
  return buf;
}

//--------------------------------------------------------------------------
static const char *get_thread_type_name(td_thr_type_e type)
{
  static const char *const names[] =
  {
    "ANY_STATE",      //  0
    "USER",           //  1
    "SYSTEM",         //  2
  };
  if ( type >= 0 && type < qnumber(names) )
    return names[type];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", type);
  return buf;
}

//--------------------------------------------------------------------------
static void display_thrinfo(const td_thrinfo_t &thi)
{
#ifdef __ANDROID__
  msg("  tid         : %lx\n", thi.ti_tid);
  msg("  kernel pid  : %d\n", thi.ti_lid); // lwpid_t
  msg("  state       : %s\n", get_thread_state_name(thi.ti_state));
#else
  size_t sigmask = *(size_t*)&thi.ti_sigmask;
  msg("  tid         : %lx\n", thi.ti_tid);
  msg("  tls         : %lx\n", (size_t)thi.ti_tls);
  msg("  entry       : %lx\n", (size_t)thi.ti_startfunc);
  msg("  stackbase   : %lx\n", (size_t)thi.ti_stkbase);
  msg("  stacksize   : %lx\n", thi.ti_stksize);
  msg("  state       : %s\n", get_thread_state_name(thi.ti_state));
  msg("  suspended   : %d\n", thi.ti_db_suspended);
  msg("  type        : %s\n", get_thread_type_name(thi.ti_type));
  msg("  priority    : %d\n", thi.ti_pri);
  msg("  kernel pid  : %d\n", thi.ti_lid); // lwpid_t
  msg("  signal mask : %lx\n", sigmask);
  msg("  traceme     : %d\n", thi.ti_traceme);
  msg("  pending sg  : %s\n", get_sigset_str(thi.ti_pending));
  msg("  enabled ev  : %s\n", get_thr_events_str(thi.ti_events));
#endif
}

//--------------------------------------------------------------------------
void linux_debmod_t::display_thrinfo(thid_t tid)
{
  msg("tid=%d\n", tid);
  td_thrhandle_t th;
  td_err_e err = td_ta_map_lwp2thr(ta, tid, &th);
  COMPLAIN_IF_FAILED("td_ta_map_lwp2thr2", err);

  if ( err == 0 )
  {
    td_thrinfo_t thi;
    memset(&thi, 0, sizeof(thi));
    err = td_thr_get_info(&th, &thi);
    COMPLAIN_IF_FAILED("td_thr_get_info2", err);

    if ( err == 0 )
      ::display_thrinfo(thi);
  }
}

//--------------------------------------------------------------------------
static int display_thread_cb(const td_thrhandle_t *th_p, void * /*data*/)
{
  td_thrinfo_t ti;
  td_err_e err = td_thr_get_info(th_p, &ti);
  DIE_IF_FAILED("td_thr_get_info", err);

  if ( ti.ti_state == TD_THR_UNKNOWN || ti.ti_state == TD_THR_ZOMBIE )
    return 0;

  display_thrinfo(ti);
  return 0;
}

void linux_debmod_t::display_all_threads()
{
  if ( ta != nullptr )
  {
    td_err_e err = td_ta_thr_iter(ta, display_thread_cb, nullptr,
                                  TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                                  TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    COMPLAIN_IF_FAILED("td_ta_thr_iter", err);
  }
}

#endif // end of debug print functions
//}}}

//--------------------------------------------------------------------------
// Helper functions for thread_db
// (it requires ps_... functions to be defined in the debugger)
//--------------------------------------------------------------------------
static linux_debmod_t *find_debugger(ps_prochandle *hproc)
{
#ifdef __ANDROID__ // android passes nullptr as hproc, do not use it
  qnotused(hproc);
  linux_debmod_t *d = (linux_debmod_t *)g_global_server->get_debugger_instance();
  return d;
#else
  struct ida_local find_debugger_t : public debmod_visitor_t
  {
    int pid;
    linux_debmod_t *found;
    find_debugger_t(int p) : pid(p), found(nullptr) {}
    virtual int visit(debmod_t *debmod) override
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      if ( ld->process_handle == pid )
      {
        found = ld;
        return 1; // stop
      }
      return 0; // continue
    }
  };
  find_debugger_t fd(hproc->pid);
  for_all_debuggers(fd);
//  msg("prochandle: %x, looking for the debugger, found: %x\n", hproc, fd.found);
  return fd.found;
#endif
}

//--------------------------------------------------------------------------
inline ea_t get_symbol_as_envvar(const char *name)
{
  qstring buf;
  return qgetenv(name, &buf) ? strtoull(buf.begin(), nullptr, 16) : BADADDR;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_pglobal_lookup(
        ps_prochandle *hproc,
        const char *obj,
        const char *name,
        psaddr_t *sym_addr)
{
  ea_t ea;
  // cache names for repeated requests. android, for example, requests the
  // same name again and again. without the cache, the name would be gone
  // from the pending name list and become unresolvable.
  psnames_t::iterator p = psname_cache.find(name);
  if ( p != psname_cache.end() )
  {
    ea = p->second;
  }
  else
  {
    linux_debmod_t *ld = find_debugger(hproc);
    if ( ld == nullptr )
      return PS_BADPID;

    ld->enum_names(obj); // update the name list

    ea = ld->find_pending_name(name);
    if ( ea == BADADDR )
    {
      if ( ld->nptl_base != BADADDR )
        ea = get_symbol_as_envvar(name);
      if ( ea == BADADDR )
      {
        if ( ld->nptl_base != BADADDR )
          msg("*WARNING* Failed to resolve name '%s' in libpthread shared object.\n"
              "          Support for multithread applications will be turned off.\n"
              "          We recommend you to analyze libpthread and provide the\n"
              "          missing symbol info as an environment variable:\n"
              "\n"
              "          export %s=####\n"
              "\n"
              "          where #### is the hexadecimal address of the symbol.\n"
              "          The full list of symbols is in syms_as_envvars.py\n",
              name, name);
        return PS_NOSYM;
      }
      ea += ld->nptl_base;
    }
#ifdef TDEB
    if ( streq(name, "nptl_version") )
    {
      char buf[8 + 1];
      buf[0] = '\0';
      ld->_read_memory(-1, ea, buf, 8, false);
      buf[8] = '\0';
      msg("nptl_version='%s'\n", buf);
    }
#endif
    psname_cache[name] = ea;
  }
  *sym_addr = psaddr_t(size_t(ea));
  ddeb(("ps_pglobal_lookup('%s') => %a\n", name, ea));
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman pid_t ps_getpid(ps_prochandle *hproc)
{
  return hproc->pid;
}

#ifdef __ANDROID__
#  ifndef __X86__
//--------------------------------------------------------------------------
idaman ps_err_e ps_get_thread_area(const struct ps_prochandle *, lwpid_t lwpid, int idx, void **base)
{
  struct iovec iovec;
  uint64_t reg;

  iovec.iov_base = &reg;
  iovec.iov_len = sizeof (reg);

  if ( ptrace(PTRACE_GETREGSET, lwpid, NT_ARM_TLS, &iovec) != 0 )
    return PS_ERR;

  /* IDX is the bias from the thread pointer to the beginning of the
     thread descriptor.  It has to be subtracted due to implementation
     quirks in libthread_db.  */
  *base = (void *) (reg - idx);

  return PS_OK;
}
#  endif

#else   // !__ANDROID__
//--------------------------------------------------------------------------
idaman ps_err_e ps_pdread(
        ps_prochandle *hproc,
        psaddr_t addr,
        void *buf,
        size_t size)
{
  ddeb(("ps_pdread(%" FMT_Z ", %ld)\n", size_t(addr), size));
  linux_debmod_t *ld = find_debugger(hproc);
  if ( ld == nullptr )
  {
    ddeb(("\t=> bad pid\n"));
    return PS_BADPID;
  }
  if ( ld->thread_handle == INVALID_HANDLE_VALUE
    || ld->_read_memory(ld->thread_handle, size_t(addr), buf, size, false) <= 0 )
  {
    ddeb(("\t=> read error (1)\n"));
    if ( ld->_read_memory(hproc->pid, size_t(addr), buf, size, false) <= 0 )
    {
      ddeb(("\t=> read error (2)\n"));
      return PS_ERR;
    }
  }
  ddeb(("\t=> read OK\n"));
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_pdwrite(
        ps_prochandle *hproc,
        psaddr_t addr,
        void *buf,
        size_t size)
{
  linux_debmod_t *ld = find_debugger(hproc);
  if ( ld == nullptr )
    return PS_BADPID;
  if ( ld->_write_memory(hproc->pid, size_t(addr), buf, size, false) <= 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lgetregs(ps_prochandle *, lwpid_t lwpid, prgregset_t gregset)
{
#if defined(__ARM__) && defined(__EA64__)
  iovec iov;
  iov.iov_base = gregset;
  iov.iov_len = sizeof(*gregset);

  if ( qptrace(PTRACE_GETREGSET, lwpid, (void*)NT_PRSTATUS, &iov) != 0 )
    return PS_ERR;
#else
  if ( qptrace(PTRACE_GETREGS, lwpid, 0, gregset) != 0 )
    return PS_ERR;
#endif
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lsetregs(ps_prochandle *, lwpid_t lwpid, const prgregset_t gregset)
{
#if defined(__ARM__) && defined(__EA64__)
  iovec iov;
  iov.iov_base = (void*)gregset;
  iov.iov_len = sizeof(*gregset);

  if ( qptrace(PTRACE_SETREGSET, lwpid, (void*)NT_PRSTATUS, &iov) != 0 )
    return PS_ERR;
#else
  if ( qptrace(PTRACE_SETREGS, lwpid, 0, (void*)gregset) != 0 )
    return PS_ERR;
#endif
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lgetfpregs(ps_prochandle *, lwpid_t lwpid, prfpregset_t *fpregset)
{
#if defined(__ARM__) && defined(__EA64__)
  iovec iov;
  iov.iov_base = fpregset;
  iov.iov_len = sizeof(*fpregset);

  if ( qptrace(PTRACE_GETREGSET, lwpid, (void*)NT_FPREGSET, &iov) != 0 )
    return PS_ERR;
#else
  if ( qptrace(PTRACE_GETFPREGS, lwpid, 0, fpregset) != 0 )
    return PS_ERR;
#endif
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lsetfpregs(ps_prochandle *, lwpid_t lwpid, const prfpregset_t *fpregset)
{
#if defined(__ARM__) && defined(__EA64__)
  iovec iov;
  iov.iov_base = (void*)fpregset;
  iov.iov_len = sizeof(*fpregset);

  if ( qptrace(PTRACE_SETREGSET, lwpid, (void*)NT_FPREGSET, &iov) != 0 )
    return PS_ERR;
#else
  if ( qptrace(PTRACE_SETFPREGS, lwpid, 0, (void*)fpregset) != 0 )
    return PS_ERR;
#endif
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_get_thread_area(const struct ps_prochandle *, lwpid_t lwpid, int idx, void **base)
{
  #ifndef PTRACE_GET_THREAD_AREA
    #ifdef __ARM__
      #define PTRACE_GET_THREAD_AREA __ptrace_request(22)
    #else
      #define PTRACE_GET_THREAD_AREA __ptrace_request(25)
    #endif
  #endif
  unsigned int desc[4];
  if ( qptrace(PTRACE_GET_THREAD_AREA, lwpid, (void *)size_t(idx), &desc) < 0 )
  {
#if !defined(__X86__) && !defined(__ARM__)
    // from <sys/reg.h>
    #define LINUX_FS 25
    #define LINUX_GS 26

    /* The following definitions come from prctl.h, but may be absent
       for certain configurations.  */
    #ifndef ARCH_GET_FS
    #define ARCH_SET_GS 0x1001
    #define ARCH_SET_FS 0x1002
    #define ARCH_GET_FS 0x1003
    #define ARCH_GET_GS 0x1004
    #endif

    switch ( idx )
    {
      case LINUX_FS:
        if ( ptrace(PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_FS) != 0 )
          return PS_ERR;
        break;
      case LINUX_GS:
        if ( ptrace(PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_GS) != 0 )
          return PS_ERR;
        break;
      default:
        return PS_BADADDR;
    }
#endif
    return PS_ERR;
  }

  *(int *)base = desc[1];

  return PS_OK;
}
#endif

//--------------------------------------------------------------------------
// High level interface for the rest of the debugger module
//--------------------------------------------------------------------------
void tdb_init(void)
{
  if ( !tdb_inited )
  {
    if ( !load_libthread_db_so() )
    {
      msg("DBG: thread support is not available\n");
    }
    else
    {
      td_err_e code = td_init();
      if ( code == TD_OK )
        tdb_inited = true;
      else
        msg("DBG: td_init error code %d\n", code);
    }
  }
}

//--------------------------------------------------------------------------
void tdb_term(void)
{
  // no way to uninitialize thread_db
}

//--------------------------------------------------------------------------
typedef qvector<td_thrinfo_t> td_thrinfovec_t;

//--------------------------------------------------------------------------
// check if there are pending messages from thread DB
void linux_debmod_t::tdb_handle_messages(int /*tid*/)
{
  if ( ta == nullptr )
    return;

  td_event_msg_t tmsg;
  td_thrinfo_t ti;
  td_err_e err;
#ifndef __ANDROID__
  while ( true )
#endif
  {
    err = td_ta_event_getmsg(ta, &tmsg);
    if ( err != TD_OK )
    {
      if ( err == TD_NOMSG )
        return;
      msg("Cannot get thread event message: %s\n", tdb_strerr(err));
      return;
    }

    err = td_thr_get_info(tmsg.th_p, &ti);
    COMPLAIN_IF_FAILED("td_thr_get_info", err);
    switch ( tmsg.event )
    {
      case TD_CREATE:
        if ( !thread_is_known(ti) )
        {
          if ( listen_thread_events(ti, tmsg.th_p) )
            attach_to_thread(ti);
        }
        break;

      case TD_DEATH:
        dead_thread(ti.ti_lid, DYING);
        break;

      default:
        msg("Spurious thread event %d.", tmsg.event);
    }
  }
}

//----------------------------------------------------------------------------
struct cbdata_t
{
  linux_debmod_t  *debmod;
  td_thrinfovec_t *threads_list;
};

//----------------------------------------------------------------------------
static int update_threads_cb(const td_thrhandle_t *th_p, void *data)
{
  cbdata_t *cbdata = (cbdata_t *) data;

  td_thrinfo_t ti;
  td_err_e err = td_thr_get_info(th_p, &ti);
  DIE_IF_FAILED("td_thr_get_info", err);

  if ( ti.ti_state != TD_THR_UNKNOWN && ti.ti_state != TD_THR_ZOMBIE )
  {
    if ( !cbdata->debmod->thread_is_known(ti) )
    {
      cbdata->debmod->listen_thread_events(ti, th_p);
      cbdata->threads_list->push_back(ti);
    }
  }
  return 0;
}

//----------------------------------------------------------------------------
bool linux_debmod_t::thread_is_known(const td_thrinfo_t &info) const
{
  return threads.find(info.ti_lid) != threads.end();
}

//--------------------------------------------------------------------------
bool linux_debmod_t::listen_thread_events(const td_thrinfo_t &info, const td_thrhandle_t *th_p)
{
#ifdef TDEB
  msg("thread %d is new\n", info.ti_lid);
  ::display_thrinfo(info);
#else
  qnotused(info);
#endif
  td_err_e err;
  td_thr_events_t thr_events;
  td_event_emptyset(&thr_events);
  td_event_addset(&thr_events, TD_CREATE);
  td_event_addset(&thr_events, TD_DEATH);
#ifndef __ANDROID__
  td_event_addset(&thr_events, TD_CATCHSIG);
#endif
  err = td_thr_set_event(th_p, &thr_events);
  DIE_IF_FAILED("td_thr_set_event", err);

  err = td_thr_event_enable(th_p, 1);
  COMPLAIN_IF_FAILED("td_thr_event_enable", err);
  if ( err != TD_OK )
  {
    ddeb(("%d: thread dead already? not adding to list.\n", info.ti_lid));
    return false;
  }

  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::attach_to_thread(const td_thrinfo_t &info)
{
#ifndef __ANDROID__
  ea_t ea = (ea_t) (size_t) info.ti_startfunc;
#else
  ea_t ea = BADADDR;
#endif

  attach_to_thread(info.ti_lid, ea);
}

//--------------------------------------------------------------------------
void linux_debmod_t::tdb_update_threads(void)
{
  if ( ta != nullptr )
  {
    td_thrinfovec_t newlist;
    cbdata_t cb_payload = { this, &newlist };

    td_err_e err = td_ta_thr_iter(ta, update_threads_cb, &cb_payload,
                                  TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                                  TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    COMPLAIN_IF_FAILED("td_ta_thr_iter", err);
    if ( err != TD_OK )
      return;

    // generate THREAD_STARTED events
    for ( int i=0; i < newlist.size(); i++ )
    {
      const td_thrinfo_t &info = newlist[i];
      // Main thread is already suspended; others not.
      if ( i != 0 )
        dbg_freeze_threads(info.ti_lid, false);
      attach_to_thread(newlist[i]);
    }
  }
}

//--------------------------------------------------------------------------
bool linux_debmod_t::tdb_enable_event(td_event_e event, internal_bpt *bp)
{
  td_notify_t notify;
  td_err_e err = td_ta_event_addr(ta, event, &notify);
  COMPLAIN_IF_FAILED("td_ta_event_addr", err);
  if ( err != TD_OK )
    return false;
  bool ok = add_internal_bp(*bp, size_t(notify.u.bptaddr));
  if ( !ok )
  {
    // Having the following cast inline in the 'dmsg' call causes
    // the __X86__=1 build on linux to report:
    //   linux_threads.cpp:851:86: warning: format '%a' expects argument of
    //   type 'double', but argument 3 has type 'size_t {aka unsigned int}'
    // ...which AFAICT is a bug in gcc.
    // Putting it on a separate line works fine, though.
    ea_t bptaddr = ea_t(size_t(notify.u.bptaddr));
    dmsg("%a: failed to add thread_db breakpoint\n", bptaddr);
    return false;
  }
  debdeb("%a: added BP for thread event %s\n", bp->bpt_addr, event == TD_CREATE ? "TD_CREATE" : "TD_DEATH");
  return true;
}

//--------------------------------------------------------------------------
// returns true: multithreaded application has been detected
bool linux_debmod_t::tdb_new(void)
{
  if ( ta == nullptr )
  {
    if ( !tdb_inited )
      return false; // no libthread_db

#ifdef __ANDROID__
    // wait until libc gets loaded. on android v4.2.2 there are 2 sets of pthread_...()
    // functions: in /system/bin/linker and in /system/lib/libc.so. The ones
    // from /system/bin/linker get resolved first but we have to use the ones
    // from /system/lib/libc.so
    bool libc_loaded = false;
    qstring custom_libc_path;
    qgetenv("IDA_LIBC_PATH", &custom_libc_path);
    for ( images_t::const_iterator p=dlls.begin(); p != dlls.end(); ++p )
    {
      const qstring &path = p->second.fname;
      if ( path == "/system/lib/libc.so"
        || path == "/system/lib64/libc.so"
        || !custom_libc_path.empty() && path == custom_libc_path )
      {
        libc_loaded = true;
        break;
      }
    }
    if ( !libc_loaded )
    {
      debdeb("DBG: /system/lib/libc.so is not loaded yet, use IDA_LIBC_PATH if necessary\n");
      return false;
    }
#endif

    debdeb("DBG: checking pid %d with thread_db\n", process_handle);
    prochandle.pid = process_handle;
    td_err_e err = td_ta_new(&prochandle, &ta);
    // the call might fail the first time if libc is not loaded yet
    // so don't show misleading message to the user
#ifdef TDEB
    COMPLAIN_IF_FAILED("td_ta_new", err);
#endif
    if ( err != TD_OK )
    {
      debdeb("DBG: td_ta_new: %s\n", tdb_strerr(err));
      ta = nullptr;
      return false;
    }

    td_thrhandle_t th;
    err = td_ta_map_lwp2thr(ta, process_handle, &th);
    COMPLAIN_IF_FAILED("td_ta_map_lwp2thr", err);
    if ( err != TD_OK )
      return false;

    err = td_thr_event_enable(&th, TD_CREATE);
    DIE_IF_FAILED("td_thr_event_enable(TD_CREATE)", err);
#ifndef __ANDROID__
    err = td_thr_event_enable(&th, TD_DEATH);
    DIE_IF_FAILED("td_thr_event_enable(TD_DEATH)", err);
#endif

    // set breakpoints for thread birth/death
    td_thr_events_t thr_events;
    td_event_emptyset(&thr_events);
    td_event_addset(&thr_events, TD_CREATE);
    td_event_addset(&thr_events, TD_DEATH);
    err = td_ta_set_event(ta, &thr_events);
    DIE_IF_FAILED("td_ta_set_event", err);

    tdb_enable_event(TD_CREATE, &birth_bpt);
#ifndef __ANDROID__
    tdb_enable_event(TD_DEATH, &death_bpt);
#endif
    debdeb("DBG: thread support has been enabled, birth_bpt=%a death_bpt=%a\n", birth_bpt.bpt_addr, death_bpt.bpt_addr);

    tdb_update_threads();
  }
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::tdb_delete(void)
{
  if ( ta != nullptr )
  {
    td_ta_delete(ta);
    ta = nullptr;
    psname_cache.clear();
  }
}

//==========================================================================
// PTRACE_O_TRACECLONE
//==========================================================================

//--------------------------------------------------------------------------
// This variable is a tri-state flag:
// -1 for unknown,
// 0  if PTRACE_O_TRACEFORK cannot be used,
// 1  if it can.
static int linux_supports_tracefork_flag = -1;

//--------------------------------------------------------------------------
static int linux_tracefork_grandchild(void *)
{
  _exit(0);
}

static int linux_tracefork_child(void)
{
  errno = 0;
  if ( qptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0 )
  {
    msg("PTRACE_O_TRACEFORK test: Cannot trace created process: %s\n", winerr(errno));
    _exit(127);
  }
  kill(getpid(), SIGSTOP);

  if ( fork() == 0 )
    linux_tracefork_grandchild(nullptr);

  _exit(0);
}

// Determine if PTRACE_O_TRACEFORK can be used to follow fork events. Make
// sure that we can enable the option, and that it had the desired effect.
static void linux_test_for_tracefork(void)
{
  linux_supports_tracefork_flag = 0;

  int child_pid = fork();
  if ( child_pid == 0 )
    linux_tracefork_child();

  if ( child_pid == -1 )
  {
    msg("clone: %s\n", winerr(errno));
    return;
  }

  int status;
  int ret = qwait(&status, child_pid, 0);
  if ( ret == -1 )
  {
    msg("waitpid: %s\n", winerr(errno));
    return;
  }
  else if ( ret != child_pid )
  {
    msg("linux_test_for_tracefork: waitpid: unexpected result %d\n", ret);
    return;
  }
  if ( !WIFSTOPPED(status) )
  {
    msg("linux_test_for_tracefork: waitpid: unexpected status %d\b", status);
    return;
  }

  ret = qptrace(PTRACE_SETOPTIONS, child_pid, nullptr, (void *)PTRACE_O_TRACEFORK);
  if ( ret != 0 )
  {
    ret = qptrace(PTRACE_KILL, child_pid, nullptr, nullptr);
    if ( ret != 0 )
    {
      msg("linux_test_for_tracefork: failed to kill child");
      return;
    }

    ret = qwait(&status, child_pid, 0);
    if ( ret != child_pid )
      msg("linux_test_for_tracefork: failed to wait for killed child");
    else if ( !WIFSIGNALED(status) )
      msg("linux_test_for_tracefork: unexpected wait status 0x%x from "
          "killed child", status);
    return;
  }

  ret = qptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
  if ( ret != 0 )
    msg("linux_test_for_tracefork: failed to resume child");

  ret = qwait(&status, child_pid, 0);
  if ( ret == child_pid
    && WIFSTOPPED(status)
    && status >> 16 == PTRACE_EVENT_FORK )
  {
    long second_pid = 0;
    ret = qptrace(PTRACE_GETEVENTMSG, child_pid, nullptr, &second_pid);
    if ( ret == 0 && second_pid != 0 )
    {
      int second_status;

      linux_supports_tracefork_flag = 1;
      qwait(&second_status, second_pid, 0);
      ret = qptrace(PTRACE_KILL, second_pid, nullptr, nullptr);
      if ( ret != 0 )
        msg("linux_test_for_tracefork: failed to kill second child");
       qwait(&status, second_pid, 0);
    }
  }
  else
  {
    msg("linux_test_for_tracefork: unexpected result from waitpid "
        "(%d, status 0x%x)", ret, status);
  }

  do
  {
    ret = qptrace(PTRACE_KILL, child_pid, nullptr, nullptr);
    if ( ret != 0 )
      msg("linux_test_for_tracefork: failed to kill child");
    qwait(&status, child_pid, 0);
  }
  while ( WIFSTOPPED(status) );
}

//--------------------------------------------------------------------------
// Return non-zero iff we have tracefork functionality available.
// This function also sets linux_supports_tracefork_flag.
static int linux_supports_tracefork(void)
{
  if ( linux_supports_tracefork_flag == -1 )
    linux_test_for_tracefork();
  return linux_supports_tracefork_flag;
}

//--------------------------------------------------------------------------
static void linux_enable_event_reporting(int pid)
{
  if ( linux_supports_tracefork() == 0 )
    return;

  qptrace(PTRACE_SETOPTIONS, pid, nullptr, (void *)PTRACE_O_TRACECLONE);
}

//--------------------------------------------------------------------------
// ported from GDB sources: linux_proc_attach_tgid_threads()
void linux_debmod_t::procfs_collect_threads(void)
{
  // TODO: if (linux_proc_get_tgid (pid) != pid) return;

  qstring pathname;
  pathname.sprnt("/proc/%d/task", process_handle);
  DIR *dir = opendir(pathname.c_str());
  if ( dir == nullptr )
  {
    msg("Could not open /proc/%d/task", process_handle);
    return;
  }

  /* Scan the task list for existing threads.  While we go through the
     threads, new threads may be spawned.  Cycle through the list of
     threads until we have done two iterations without finding new
     threads.  */
  for ( int iterations=0; iterations < 2; ++iterations )
  {
    bool new_threads_found = false;

    struct dirent *dp;
    while ( (dp = readdir(dir)) != nullptr )
    {
      /* Fetch one lwp.  */
      unsigned long lwp = strtoul(dp->d_name, nullptr, 10);
      if ( lwp != 0 )
      {
        debdeb("DBG: %d found %s thread\n", iterations, dp->d_name);
        if ( attach_collected_thread(lwp) )
        {
          new_threads_found = true;
          debdeb("DBG: %d collected %s thread\n", iterations, dp->d_name);
        }
      }
    }

    if ( new_threads_found )
    { /* Start over.  */
      iterations = -1;
    }
    rewinddir(dir);
  }

  closedir(dir);
}

//--------------------------------------------------------------------------
bool linux_debmod_t::attach_collected_thread(unsigned long lwp)
{
  thread_info_t *thif = get_thread(lwp);
  if ( thif != nullptr )
    return false;

  // Main thread is already suspended; others not.
  if ( lwp != process_handle )
    dbg_freeze_threads(lwp, false);
  // generate THREAD_STARTED event
  return attach_to_thread(lwp, BADADDR);
}

//--------------------------------------------------------------------------
void linux_debmod_t::handle_extended_wait(bool *handled, const chk_signal_info_t &csi)
{
  if ( handled != nullptr )
    *handled = false;

  // extended event guard
  int event = csi.status >> 16;
  if ( !WIFSTOPPED(csi.status)
    || WSTOPSIG(csi.status) != SIGTRAP
    || event == 0 )
  {
    return;
  }

  if ( event == PTRACE_EVENT_CLONE )
  {
    unsigned long new_pid;
    qptrace(PTRACE_GETEVENTMSG, csi.pid, nullptr, &new_pid);
    ddeb(("handle_extended_wait: PTRACE_EVENT_CLONE(signal_pid=%d, new_pid=%ld)\n", csi.pid, new_pid));

    linux_enable_event_reporting(new_pid);
    finish_attaching(new_pid, BADADDR, true);
    if ( handled != nullptr )
      *handled = true;
  }
}

//==========================================================================
// Common part
//==========================================================================

//--------------------------------------------------------------------------
void init_multithreading()
{
  bool skip_clone = qgetenv("IDA_USE_LIBTHREAD_DB", nullptr);
  if ( !skip_clone )
  {
    if ( linux_supports_tracefork() == 1 )
    {
      mt_state = MT_CLONE;
      return;
    }
  }
  tdb_init();
  if ( tdb_inited )
    mt_state = MT_LIB;
  else
    mt_state = MT_NONE;
}

//--------------------------------------------------------------------------
void term_multithreading()
{
  if ( mt_state == MT_LIB )
    tdb_term();
}

//--------------------------------------------------------------------------
bool linux_debmod_t::activate_multithreading()
{
  if ( mt_state == MT_UNKN )
    init_multithreading();
  if ( mt_state == MT_NONE )
  {
    debdeb("DBG: debugging of multi-threaded program is not available\n");
    return false;
  }

  bool ok;
  if ( mt_state == MT_CLONE )
  {
    debdeb("DBG: PTRACE_O_TRACECLONE ability detected, will be used in debugging multi-threaded program\n");
    linux_enable_event_reporting(process_handle);
    birth_bpt.bpt_addr = 0;
    death_bpt.bpt_addr = 0;

    if ( !threads_collected )
    {
      debdeb("DBG: collect threads\n");
      procfs_collect_threads();
      threads_collected = true;
    }
    ok = true;
  }
  else
  { // MT_LIB
    ok = tdb_new();
    debdeb("DBG: tdb_new returns %d\n", ok);
    if ( ok && ta != nullptr )
      debdeb("DBG: libthread_db.so will be used in debugging multi-threaded program\n");
  }

  return ok;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::attach_to_thread(int tid, ea_t ea)
{
  // attach to the thread and make it ready for debugging
  if ( qptrace(PTRACE_ATTACH, tid, 0, 0) != 0 )
  {
    dmsg("Attaching to %d thread: %s\n", tid, winerr(errno));
    if ( errno == EPERM || errno == ESRCH )
      return false;   // thread died prematurely
    INTERR(30197);
  }

  return finish_attaching(tid, ea, false);
}

//--------------------------------------------------------------------------
void linux_debmod_t::dead_thread(int tid, thstate_t state)
{
  threads_t::iterator p = threads.find(tid);
  if ( p != threads.end() )
  {
    ddeb(("thread %d died\n", tid));
    set_thread_state(p->second, state);
    debug_event_t ev;
    ev.set_exit_code(THREAD_EXITED, 0);   // ???
    ev.pid     = process_handle;
    ev.tid     = tid;
    ev.ea      = BADADDR;
    ev.handled = true;
    enqueue_event(ev, IN_BACK);
    if ( state == DEAD )
      del_thread(tid);
  }
  else
  {
    msg("unknown thread %d died\n", tid);
  }
}

//--------------------------------------------------------------------------
bool linux_debmod_t::finish_attaching(int tid, ea_t ea, bool use_ip)
{
  thread_info_t &ti = add_thread(tid);

  // If we haven't already seen the new PID stop, wait for it now
  if ( !seen_threads.del(tid) )
  {
    // The new child has a pending SIGSTOP.  We can't affect it until it
    // hits the SIGSTOP, but we're already attached
    int status;
    int tid2 = check_for_signal(&status, tid, -1);
    ddeb(("finish_attaching: tid2=%d status=%s\n", tid2, status_dstr(status)));
    if ( tid2 == -1 )
    {
      dmsg("Finish attaching to %d thread: %s\n", tid, winerr(errno));
      return false; // looks alike a "zombie"
    }
    if ( tid2 != tid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP )
    {
      get_thread(tid)->waiting_sigstop = true;
      if ( tid2 > 0 )
        store_pending_signal(tid2, status);
    }
  }

  debug_event_t ev;
  ev.set_info(THREAD_STARTED) = ti.name;
  ev.pid     = process_handle;
  ev.tid     = tid;
  ev.ea      = use_ip ? get_ip(ev.tid) : ea;
  ev.handled = true;
  enqueue_event(ev, IN_FRONT);
  return true;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::get_thread_name(qstring *thr_name, thid_t tid)
{
  qstring comm_file;
  comm_file.sprnt("/proc/%d/task/%d/comm", process_handle, tid);
  FILE *fp = fopenRT(comm_file.c_str());
  if ( fp == nullptr )
  {
    dmsg("%s: %s\n", comm_file.c_str(), winerr(errno));
    return false;
  }
  qgetline(thr_name, fp);   // return code is ignored, assumed empty thread name
  qfclose(fp);
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::update_thread_names(thread_name_vec_t *thr_names)
{
  // assert: thr_names != nullptr
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    qstring new_thr_name;
    if ( get_thread_name(&new_thr_name, ti.tid)
      && new_thr_name != ti.name )
    {
      ddeb(("Thread %d renamed from '%s' to '%s'\n", ti.tid, ti.name.c_str(), new_thr_name.c_str()));
      ti.name.swap(new_thr_name);
      thread_name_t &tn = thr_names->push_back();
      tn.tid = ti.tid;
      tn.name = ti.name;
    }
  }
}
