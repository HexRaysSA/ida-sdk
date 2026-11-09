/*
*  This is a userland linux debugger module
*
*  Functions unique for Linux
*
*  It can be compiled by gcc
*
*/

//#define LDEB            // enable debug print in this module

#include <sys/syscall.h>
#include <pthread.h>
#include <dirent.h>

#include <pro.h>
#include <prodir.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <network.hpp>

#include "symelf.hpp"
#include "linux_debmod.h"
#include "linux_rpc.h"

#ifdef __ANDROID__
#  include <elf.h>
#  include <sys/procfs.h>
#  include "android.hpp"
#  include "android.cpp"
#else
#  include <link.h>
#endif

#if defined(__ARM__) && defined(__EA64__)
#  include <asm/ptrace.h>
#endif

//--------------------------------------------------------------------------
// Load IDA register sets.
#ifdef __ARM__
#  include "arm_regs.hpp"
#  define arch_registers arm_registers
#else
#  include "pc_regs.hpp"
#  define arch_registers x86_registers
#endif

//--------------------------------------------------------------------------
// Define some ptrace() requests if they're not available.
#ifndef PTRACE_GETREGSET
#  define PTRACE_GETREGSET __ptrace_request(0x4204)
#  define PTRACE_SETREGSET __ptrace_request(0x4205)
#endif

#ifdef __HAVE_ARM_VFP__
#  ifndef PTRACE_GETVFPREGS
#    define PTRACE_GETVFPREGS __ptrace_request(27)
#    define PTRACE_SETVFPREGS __ptrace_request(28)
#  endif
#endif

#if !defined(__ARM__) && !defined(__X86__) && !defined(PTRACE_ARCH_PRCTL)
#  define PTRACE_ARCH_PRCTL __ptrace_request(30)
#endif

//--------------------------------------------------------------------------
// ARM breakpoint codes.
#ifdef __ARM__
static const uchar thumb16_bpt[] = { 0x10, 0xDE }; // UND #10
// we must use 32-bit breakpoints for 32bit instructions inside IT blocks (thumb mode)
// if we use a 16-bit breakpoint and the processor decides to skip it
// because the condition codes are not satisfied, we will end up skipping
// only half of the original 32-bit instruction
static const uchar thumb32_bpt[] = { 0xF0, 0xF7, 0x00, 0xA0 };
// This bit is combined with the software bpt size to indicate
// that 32bit bpt code should be used.
#define USE_THUMB32_BPT 0x80
static const uchar aarch64_bpt[] = AARCH64_BPT_CODE;
#endif

//--------------------------------------------------------------------------
#if defined(__HAVE_ARM_VFP__) && !defined(__ANDROID__)
struct user_vfp
{
  int64 fpregs[32];
  int32 fpscr;
};
#endif

//--------------------------------------------------------------------------
#ifdef __ARM__
#  if defined(__X86__)
#    define user_regs_struct user_regs
#    define PCREG uregs[15]
#  else // arm64
#    define user_regs_struct user_pt_regs
#    define LRREG_IDX 30
#  endif
#else // __ARM__
#  if defined(__X86__)
#    define SPREG esp
#    define PCREG eip
#    define XMM_STRUCT  x387
#    define TAGS_REG    twd
#    define INTEL_REG(reg) e##reg
#    define INTEL_SREG(reg) x##reg
#  else // x64
#    define SPREG rsp
#    define PCREG rip
#    define XMM_STRUCT  i387
#    define TAGS_REG    ftw
#    define INTEL_REG(reg) r##reg
#    define INTEL_SREG(reg) reg
#  endif
#endif

//--------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
typedef const char *per_pid_elf_dbgdir_resolver_t(int pid);
static per_pid_elf_dbgdir_resolver_t *per_pid_elf_dbgdir_resolver = nullptr;
#endif

//--------------------------------------------------------------------------
// ptrace() uses long as part of its API and we want to use that, so we
// tell lint to ignore it.
//lint -esym(970,long) use of modifier or type 'long' outside of a typedef

//--------------------------------------------------------------------------
linux_debmod_t::linux_debmod_t(void) :
  ta(nullptr),
  complained_shlib_bpt(false),
  process_handle(INVALID_HANDLE_VALUE),
  thread_handle(INVALID_HANDLE_VALUE),
  exited(false),
  mapfp(nullptr),
  npending_signals(0),
  may_run(false),
  requested_to_suspend(false),
  in_event(false),
  nptl_base(BADADDR)
{
  prochandle.pid = NO_PROCESS;
  set_platform("linux");
}

#ifdef LDEB
//--------------------------------------------------------------------------
const char *get_ptrace_name(__ptrace_request request)
{
  switch ( request )
  {
    case PTRACE_TRACEME:     return "PTRACE_TRACEME";     /* Indicate that the process making this request should be traced.
                                                             All signals received by this process can be intercepted by its
                                                             parent, and its parent can use the other `ptrace' requests.  */
    case PTRACE_PEEKTEXT:    return "PTRACE_PEEKTEXT";    /* Return the word in the process's text space at address ADDR.  */
    case PTRACE_PEEKDATA:    return "PTRACE_PEEKDATA";    /* Return the word in the process's data space at address ADDR.  */
    case PTRACE_PEEKUSER:    return "PTRACE_PEEKUSER";    /* Return the word in the process's user area at offset ADDR.  */
    case PTRACE_POKETEXT:    return "PTRACE_POKETEXT";    /* Write the word DATA into the process's text space at address ADDR.  */
    case PTRACE_POKEDATA:    return "PTRACE_POKEDATA";    /* Write the word DATA into the process's data space at address ADDR.  */
    case PTRACE_POKEUSER:    return "PTRACE_POKEUSER";    /* Write the word DATA into the process's user area at offset ADDR.  */
    case PTRACE_CONT:        return "PTRACE_CONT";        /* Continue the process.  */
    case PTRACE_KILL:        return "PTRACE_KILL";        /* Kill the process.  */
    case PTRACE_SINGLESTEP:  return "PTRACE_SINGLESTEP";  /* Single step the process. This is not supported on all machines.  */
#if !defined(__ARM__) || defined(__X86__)
    case PTRACE_GETREGS:     return "PTRACE_GETREGS";     /* Get all general purpose registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETREGS:     return "PTRACE_SETREGS";     /* Set all general purpose registers used by a processes. This is not supported on all machines.  */
    case PTRACE_GETFPREGS:   return "PTRACE_GETFPREGS";   /* Get all floating point registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETFPREGS:   return "PTRACE_SETFPREGS";   /* Set all floating point registers used by a processes. This is not supported on all machines.  */
#endif
    case PTRACE_ATTACH:      return "PTRACE_ATTACH";      /* Attach to a process that is already running. */
    case PTRACE_DETACH:      return "PTRACE_DETACH";      /* Detach from a process attached to with PTRACE_ATTACH.  */
#if !defined(__ARM__)
    case PTRACE_GETFPXREGS:  return "PTRACE_GETFPXREGS";  /* Get all extended floating point registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETFPXREGS:  return "PTRACE_SETFPXREGS";  /* Set all extended floating point registers used by a processes. This is not supported on all machines.  */
#endif
    case PTRACE_SYSCALL:     return "PTRACE_SYSCALL";     /* Continue and stop at the next (return from) syscall.  */
#if defined(__ARM__) && defined(__X86__)
    case PTRACE_GETVFPREGS:  return "PTRACE_GETVFPREGS";  /* Get all vfp registers used by a processes.  This is not supported on all machines.  */
    case PTRACE_SETVFPREGS:  return "PTRACE_SETVFPREGS";  /* Set all vfp registers used by a processes.  This is not supported on all machines.  */
#endif
    case PTRACE_SETOPTIONS:  return "PTRACE_SETOPTIONS";  /* Set ptrace filter options.  */
    case PTRACE_GETEVENTMSG: return "PTRACE_GETEVENTMSG"; /* Get last ptrace message.  */
    case PTRACE_GETSIGINFO:  return "PTRACE_GETSIGINFO";  /* Get siginfo for process.  */
    case PTRACE_SETSIGINFO:  return "PTRACE_SETSIGINFO";  /* Set new siginfo for process.  */
    case PTRACE_GETREGSET:   return "PTRACE_GETREGSET";   /* Get register content.  */
    case PTRACE_SETREGSET:   return "PTRACE_SETREGSET";   /* Set register content.  */
#ifdef PTRACE_SEIZE
    case PTRACE_SEIZE:       return "PTRACE_SEIZE";       /* Like PTRACE_ATTACH, but do not force tracee to trap and do not affect signal or group stop state.  */
    case PTRACE_INTERRUPT:   return "PTRACE_INTERRUPT";   /* Trap seized tracee.  */
    case PTRACE_LISTEN:      return "PTRACE_LISTEN";      /* Wait for next group event.  */
    case PTRACE_PEEKSIGINFO: return "PTRACE_PEEKSIGINFO"; /* Wait for next group event.  */
    case PTRACE_GETSIGMASK:  return "PTRACE_GETSIGMASK";  /* Wait for next group event.  */
    case PTRACE_SETSIGMASK:  return "PTRACE_SETSIGMASK";  /* Wait for next group event.  */
#endif
#if !defined(__ARM__) && !defined(__X86__)
    case PTRACE_ARCH_PRCTL:  return "PTRACE_ARCH_PRCTL";  //lint !e2444 case value is not in enumeration
#endif
    default:
      static char buf[MAXSTR];
      qsnprintf(buf, sizeof(buf), "%d", request);
      return buf;
  }
}
#endif

//--------------------------------------------------------------------------
// fixme: can we use peeksize_t instead?
static long qptrace(__ptrace_request request, pid_t pid, void *addr, void *data)
{
  long code = ptrace(request, pid, addr, data);
#ifdef LDEB
  if ( request != PTRACE_PEEKTEXT
    && request != PTRACE_PEEKUSER
    && (request != PTRACE_POKETEXT
     && request != PTRACE_POKEDATA
#if !defined(__ARM__) || defined(__X86__)
     && request != PTRACE_GETREGS
     && request != PTRACE_SETREGS
     && request != PTRACE_GETFPREGS
     && request != PTRACE_SETFPREGS
#endif
#if defined(__ARM__) && defined(__X86__)
     && request != PTRACE_GETVFPREGS
     && request != PTRACE_SETVFPREGS
#endif
#if !defined(__ARM__)
     && request != PTRACE_SETFPXREGS
     && request != PTRACE_GETFPXREGS
#endif
     || code != 0) )
  {
//    int saved_errno = errno;
//    msg("%s(%u, 0x%X, 0x%X) => 0x%X\n", get_ptrace_name(request), pid, addr, data, code);
//    errno = saved_errno;
  }
#endif
  return code;
}

//--------------------------------------------------------------------------
#ifdef LDEB
GCC_DIAG_OFF(format-nonliteral);
void linux_debmod_t::log(thid_t tid, const char *format, ...)
{
  if ( tid != -1 )
  {
    thread_info_t *thif = get_thread(tid);
    if ( thif == nullptr )
    {
      msg("    %d:       ** missing **\n", tid);
    }
    else
    {
      const char *name = "?";
      switch ( thif->state )
      {
        case RUNNING:        name = "RUN "; break;
        case STOPPED:        name = "STOP"; break;
        case DYING:          name = "DYIN"; break;
        case DEAD:           name = "DEAD"; break;
      }
      msg("    %d: %s %c%c S=%d U=%d ",
          thif->tid,
          name,
          thif->waiting_sigstop ? 'W' : ' ',
          thif->got_pending_status ? 'P' : ' ',
          thif->suspend_count,
          thif->user_suspend);
    }
  }
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}

static const char *strevent(int status)
{
  int event = status >> 16;
  if ( WIFSTOPPED(status)
    && WSTOPSIG(status) == SIGTRAP
    && event != 0 )
  {
    switch ( event )
    {
      case PTRACE_EVENT_FORK:
        return " event=PTRACE_EVENT_FORK";
      case PTRACE_EVENT_VFORK:
        return " event=PTRACE_EVENT_VFORK";
      case PTRACE_EVENT_CLONE:
        return " event=PTRACE_EVENT_CLONE";
      case PTRACE_EVENT_EXEC:
        return " event=PTRACE_EVENT_EXEC";
      case PTRACE_EVENT_VFORK_DONE:
        return " event=PTRACE_EVENT_VFORK_DONE";
      case PTRACE_EVENT_EXIT:
        return " event=PTRACE_EVENT_EXIT";
      default:
        return " UNKNOWN event";
    }
  }
  return "";
}

static char *status_dstr(int status)
{
  static char buf[80];
  if ( WIFSTOPPED(status) )
  {
    int sig = WSTOPSIG(status);
    ::qsnprintf(buf, sizeof(buf), "stopped(%s)%s", strsignal(sig), strevent(status));
  }
  else if ( WIFSIGNALED(status) )
  {
    int sig = WTERMSIG(status);
    ::qsnprintf(buf, sizeof(buf), "terminated(%s)", strsignal(sig));
  }
  else if ( WIFEXITED(status) )
  {
    int code = WEXITSTATUS(status);
    ::qsnprintf(buf, sizeof(buf), "exited(%d)", code);
  }
  else
  {
    ::qsnprintf(buf, sizeof(buf), "status=%x\n", status);
  }
  return buf;
}

static void ldeb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}
GCC_DIAG_OFF(format-nonliteral);

#else
//lint -estring(750,status_dstr, strevent) not referenced
#define log(tid, format, args...)
#define ldeb(format, args...) do {} while ( 0 )
#define status_dstr(status) "?"
#define strevent(status) ""
#endif

//--------------------------------------------------------------------------
static int qkill(int pid, int signo)
{
  ldeb("%d: sending signal %s\n", pid, signo == SIGSTOP ? "SIGSTOP"
                                     : signo == SIGKILL ? "SIGKILL" : "");
  int ret;
  errno = 0;
  static bool tkill_failed = false;
  if ( !tkill_failed )
  {
    ret = syscall(__NR_tkill, pid, signo);
    if ( ret != 0 && errno == ENOSYS )
    {
      errno = 0;
      tkill_failed = true;
    }
  }
  if ( tkill_failed )
    ret = kill(pid, signo);
  if ( ret != 0 )
    ldeb("  %s\n", strerror(errno));
  return ret;
}

//--------------------------------------------------------------------------
inline thread_info_t *linux_debmod_t::get_thread(thid_t tid)
{
  threads_t::iterator p = threads.find(tid);
  if ( p == threads.end() )
    return nullptr;
  return &p->second;
}

#define X86_XSTATE_SSE_SIZE 576
// #define X86_XSTATE_AVX_SIZE 832
// #define X86_XSTATE_BNDREGS_SIZE 1024
// #define X86_XSTATE_BNDCFG_SIZE 1088
// #define X86_XSTATE_AVX512_SIZE 2688
// #define X86_XSTATE_PKRU_SIZE 2696
#define X86_XSTATE_MAX_SIZE 2696

//-------------------------------------------------------------------------
static int _has_ptrace_getregset = -1;
static bool has_ptrace_getregset(thid_t tid)
{
  if ( _has_ptrace_getregset < 0 )
  {
#if defined(__ARM__)
    uint8_t xstateregs[sizeof(struct user_regs_struct)];
#   define _TEST_PTRACE_OP NT_PRSTATUS
#else
    uint8_t xstateregs[X86_XSTATE_SSE_SIZE];
#   define _TEST_PTRACE_OP NT_X86_XSTATE
#endif
    struct iovec iov;
    iov.iov_base = xstateregs;
    iov.iov_len = sizeof(xstateregs);
    _has_ptrace_getregset = qptrace(PTRACE_GETREGSET, tid, (void *) _TEST_PTRACE_OP, &iov) == 0;
#undef _TEST_PTRACE_OP
  }
  return _has_ptrace_getregset > 0;
}

//-------------------------------------------------------------------------
inline bool qptrace_get_regset(struct iovec *out, size_t what, thid_t tid)
{
  if ( !has_ptrace_getregset(tid) )
    return false;
  return qptrace(PTRACE_GETREGSET, tid, (void *) what, out) == 0;
}

//-------------------------------------------------------------------------
inline bool qptrace_get_regset(void *out, size_t outsz, size_t what, thid_t tid)
{
  struct iovec iov = { out, outsz };
  return qptrace_get_regset(&iov, what, tid);
}

//-------------------------------------------------------------------------
inline bool qptrace_set_regset(size_t what, thid_t tid, struct iovec &iov)
{
  // we'll assume that if a platform exposes 'PTRACE_GETREGSET'
  // it also exposes 'PTRACE_SETREGSET'.
  if ( !has_ptrace_getregset(tid) )
    return false;
  return qptrace(PTRACE_SETREGSET, tid, (void *) what, &iov) == 0;
}

//-------------------------------------------------------------------------
inline bool qptrace_set_regset(size_t what, thid_t tid, void *in, size_t insz)
{
  struct iovec iov = { in, insz };
  return qptrace_set_regset(what, tid, iov);
}

//--------------------------------------------------------------------------
#if defined(__ARM__) && !defined(__X86__)
inline bool qptrace_get_prstatus(struct user_regs_struct *regset, thid_t tid)
{
  return qptrace_get_regset(regset, sizeof(struct user_regs_struct), NT_PRSTATUS, tid);
}
#endif

//--------------------------------------------------------------------------
static ea_t get_ip(thid_t tid)
{
  ea_t ea;
#if defined(__ARM__) && !defined(__X86__)
  struct user_regs_struct regset;
  ea = qptrace_get_prstatus(&regset, tid) ? regset.pc : BADADDR;
#else
  const size_t pcreg_off = qoffsetof(user, regs) + qoffsetof(user_regs_struct, PCREG);
  // In case 64bit IDA (__EA64__=1) is debugging a 32bit process:
  //  - size of ea_t is 64 bit
  //  - qptrace() returns a 32bit long value
  // Here we cast the return value to unsigned long to prevent
  // extending of the sign bit when convert 32bit long value to 64bit ea_t
  ea = (unsigned long)qptrace(PTRACE_PEEKUSER, tid, (void *)pcreg_off, 0);
#endif
  return ea;
}

#include "linux_threads.cpp"

//--------------------------------------------------------------------------
#ifndef __ARM__
static unsigned long get_dr(thid_t tid, int idx)
{
  uchar *offset = (uchar *)qoffsetof(user, u_debugreg) + idx*sizeof(unsigned long int);
  unsigned long value = qptrace(PTRACE_PEEKUSER, tid, (void *)offset, 0);
  // msg("dr%d => %a\n", idx, value);
  return value;
}

//--------------------------------------------------------------------------
static bool set_dr(thid_t tid, int idx, ea_t ea)
{
  uchar *offset = (uchar *)qoffsetof(user, u_debugreg) + idx*sizeof(unsigned long int);

  if ( ea == BADADDR )
    ea = 0;   // linux does not accept too high values
  unsigned long value = ea;
  // msg("dr%d <= %a\n", idx, value);
  return qptrace(PTRACE_POKEUSER, tid, offset, (void *)value) == 0;
}
#endif

//--------------------------------------------------------------------------
bool linux_debmod_t::del_pending_event(event_id_t id, const char *module_name)
{
  for ( eventlist_t::iterator p=events.begin(); p != events.end(); ++p )
  {
    if ( p->eid() == id && p->modinfo().name == module_name )
    {
      events.erase(p);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
void linux_debmod_t::enqueue_event(const debug_event_t &ev, queue_pos_t pos)
{
  if ( ev.eid() != NO_EVENT )
  {
    events.enqueue(ev, pos);
    may_run = false;
    ldeb("enqueued event, may not run!\n");
  }
}

//--------------------------------------------------------------------------
static inline void resume_dying_thread(int tid, int)
{
  qptrace(PTRACE_CONT, tid, 0, (void *)0);
}

//--------------------------------------------------------------------------
// we got a signal that does not belong to our thread. find the target thread
// and store the signal there
void linux_debmod_t::store_pending_signal(int _pid, int status)
{
  struct ida_local linux_signal_storer_t : public debmod_visitor_t
  {
    int pid;
    int status;
    linux_signal_storer_t(int p, int s) : pid(p), status(s) {}
    virtual int visit(debmod_t *debmod) override
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      threads_t::iterator p = ld->threads.find(pid);
      if ( p != ld->threads.end() )
      {
        thread_info_t &ti = p->second;
        // normally we should not receive a new signal unless the process or the thread
        // exited. the exit signals may occur even if there is a pending signal.
        QASSERT(30185, !ti.got_pending_status || ld->exited || WIFEXITED(status));
        if ( ti.waiting_sigstop && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP )
        {
          ti.waiting_sigstop = false;
          ld->set_thread_state(ti, STOPPED);
        }
        else
        {
          ti.got_pending_status = true;
          ti.pending_status = status;
          ld->npending_signals++;
        }
        return 1; // stop
      }
      else
      {
        // we are handling an event from a thread we recently removed, ignore this
        if ( ld->deleted_threads.has(pid) )
        {
          // do not store the signal but resume the thread and let it finish
          resume_dying_thread(pid, status);
          return 1;
        }
      }

      return 0; // continue
    }
  };
  linux_signal_storer_t lss(_pid, status);
  if ( !for_all_debuggers(lss) ) // uses lock_begin(), lock_end() to protect common data
  {
    if ( WIFSTOPPED(status) )
    {
      // we can get SIGSTOP for the new-born lwp before the parent get it
      // store pid to mark that we should not wait for SIGSTOP anymore
      seen_threads.push_back(_pid);
    }
    else if ( !WIFSIGNALED(status) )
    {
      // maybe it comes from a zombie?
      // if we terminate the process, there might be some zombie threads remaining(?)
      msg("  %d: failed to store pending status %x, killing unknown thread\n", _pid, status);
      qptrace(PTRACE_KILL, _pid, 0, 0);
    }
  }
}

//--------------------------------------------------------------------------
inline bool is_bpt_status(int status)
{
  if ( !WIFSTOPPED(status) )
    return false;
  int sig = WSTOPSIG(status);
#ifdef __ARM__
  return sig == SIGTRAP || sig == SIGILL;
#else
  return sig == SIGTRAP;
#endif
}

//--------------------------------------------------------------------------
// check if there are any pending signals for our process
bool linux_debmod_t::retrieve_pending_signal(pid_t *p_pid, int *status)
{
  if ( npending_signals == 0 )
    return false;

  lock_begin();

  // try to stick to the same thread as before
  threads_t::iterator p = threads.find(last_event.tid);
  if ( p != threads.end() )
  {
    thread_info_t &ti = p->second;
    if ( !ti.got_pending_status || ti.user_suspend > 0 || ti.suspend_count > 0 )
      p = threads.end();
  }

  // find a thread with a signal.
  if ( p == threads.end() )
  {
    for ( int i=0; i < 3; i++ )
    {
      for ( p=threads.begin(); p != threads.end(); ++p )
      {
        thread_info_t &ti = p->second;
        if ( ti.user_suspend > 0 || ti.suspend_count > 0 )
          continue;
        if ( ti.got_pending_status )
        {
          // signal priorities: STEP, SIGTRAP, others
          if ( i == 0 )
          {
            if ( !ti.single_step )
              continue;
          }
          else if ( i == 1 )
          {
            if ( !is_bpt_status(ti.pending_status) )
              continue;
          }
          break;
        }
      }
    }
  }

  bool got_pending_signal = false;
  if ( p != threads.end() )
  {
    *p_pid = p->first;
    *status = p->second.pending_status;
    p->second.got_pending_status = false;
    got_pending_signal = true;
    npending_signals--;
    QASSERT(30186, npending_signals >= 0);
    ldeb("-------------------------------\n");
    log(p->first, "qwait (pending signal): %s (may_run=%d)\n", status_dstr(*status), may_run);
  }
  lock_end();
  return got_pending_signal;
}

//--------------------------------------------------------------------------
// read a zero terminated string. try to avoid reading unreadable memory
bool linux_debmod_t::read_asciiz(tid_t tid, ea_t ea, char *buf, size_t bufsize, bool suspend)
{
  while ( bufsize > 0 )
  {
    int pagerest = 4096 - (ea % 4096); // number of bytes remaining on the page
    int nread = qmin(pagerest, bufsize);
    if ( !suspend && nread > 128 )
      nread = 128;      // most paths are short, try to read only 128 bytes
    nread = _read_memory(tid, ea, buf, nread, suspend);
    if ( nread < 0 )
      return false; // failed

    // did we read a zero byte?
    for ( int i=0; i < nread; i++ )
      if ( buf[i] == '\0' )
        return true;

    ea  += nread;
    buf += nread;
    bufsize -= nread;
  }
  return true; // odd, we did not find any zero byte. should we report success?
}

//--------------------------------------------------------------------------
// may add/del threads!
bool linux_debmod_t::gen_library_events(int /*tid*/)
{
  int s = events.size();
  meminfo_vec_t miv;
  if ( get_memory_info(miv, false) == 1 )
    handle_dll_movements(miv);
  return events.size() != s;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::handle_hwbpt(debug_event_t *event)
{
#ifdef __ARM__
  qnotused(event);
#else

  uint32 dr6_value = get_dr(event->tid, 6);
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( dr6_value & (1<<i) )  // Hardware breakpoint 'i'
    {
      if ( hwbpt_ea[i] == get_dr(event->tid, i) )
      {
        bptaddr_t &addr = event->set_bpt();
        addr.hea = hwbpt_ea[i];
        addr.kea = BADADDR;
        set_dr(event->tid, 6, 0); // Clear the status bits
        return true;
      }
    }
  }
#endif
  return false;
}

//--------------------------------------------------------------------------
inline ea_t calc_bpt_event_ea(const debug_event_t *event)
{
#ifdef __ARM__
  if ( event->exc().code == SIGTRAP || event->exc().code == SIGILL )
    return event->ea;
#else
  if ( event->exc().code == SIGTRAP )
//  || event->exc().code == SIGSEGV ) // NB: there was a bug in linux 2.6.10 when int3 was reported as SIGSEGV instead of SIGTRAP
  {
    return event->ea - 1;               // x86 reports the address after the bpt
  }
#endif
  return BADADDR;
}

//--------------------------------------------------------------------------
inline void linux_debmod_t::set_thread_state(thread_info_t &ti, thstate_t state) const
{
  ti.state = state;
}

//--------------------------------------------------------------------------
static __inline void clear_tbit(thid_t tid)
{
#ifdef __ARM__
  qnotused(tid);
  return;
#else

  struct user_regs_struct regs;
  if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
  {
    msg("clear_tbit: error reading registers for thread %d\n", tid);
    return;
  }

  if ( (regs.eflags & 0x100) != 0 )
  {
    regs.eflags &= ~0x100;
    if ( qptrace(PTRACE_SETREGS, tid, 0, &regs) != 0 )
      msg("clear_tbit: error writting registers for thread %d\n", tid);
  }

#endif
}

//--------------------------------------------------------------------------
bool linux_debmod_t::check_for_new_events(chk_signal_info_t *csi, bool *event_prepared)
{
  if ( event_prepared != nullptr )
    *event_prepared = false;

  while ( true )
  {
    // even if we have pending events, check for new events first.
    // this improves multithreaded debugging experience because
    // we stick to the same thread (hopefully a new event arrives fast enough
    // if we are single stepping). if we first check pending events,
    // the user will be constantly switched from one thread to another.
    csi->pid = check_for_signal(&csi->status, -1, 0);
    if ( csi->pid <= 0 )
    { // no new events, do we have any pending events?
      if ( retrieve_pending_signal(&csi->pid, &csi->status) )
      {
        // check for extended event,
        // if any the debugger event can be prepared
        handle_extended_wait(event_prepared, *csi);
        break;
      }
      // if the timeout was zero, nothing else to do
      if ( csi->timeout_ms == 0 )
        return false;
      // ok, we will wait for new events for a while
      csi->pid = check_for_signal(&csi->status, -1, csi->timeout_ms);
      if ( csi->pid <= 0 )
        return false;
    }
    ldeb("-------------------------------\n");
    log(csi->pid, " => qwait: %s\n", status_dstr(csi->status));

    // check for extended event,
    // if any the debugger event can be prepared
    handle_extended_wait(event_prepared, *csi);

    if ( threads.find(csi->pid) != threads.end() )
      break;

    // when an application creates many short living threads we may receive events
    // from a thread we already removed so, do not store this pending signal, just
    // ignore it
    if ( !deleted_threads.has(csi->pid) )
    {
      // we are not interested in this pid
      log(csi->pid, "storing status %d\n", csi->status);
      store_pending_signal(csi->pid, csi->status);
    }
    else
    {
      // do not store the signal but resume the thread and let it finish
      resume_dying_thread(csi->pid, csi->status);
    }
    csi->timeout_ms = 0;
  }
  return true;
}

//--------------------------------------------------------------------------
// timeout in microseconds
// 0 - no timeout, return immediately
// -1 - wait forever
// returns: 1-ok, 0-failed
int linux_debmod_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  chk_signal_info_t csi(timeout_ms);

  // even if we have pending events, check for new events first.
  bool event_ready = false;
  if ( !check_for_new_events(&csi, &event_ready) )
    return false;

  pid_t tid = csi.pid;
  int status = csi.status;

  thread_info_t *thif = get_thread(tid);
  if ( thif == nullptr )
  {
    // not our thread?!
    debdeb("EVENT FOR UNKNOWN THREAD %d, IGNORED...\n", tid);
    size_t sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
    qptrace(PTRACE_CONT, tid, 0, (void*)(sig));
    return false;
  }
  QASSERT(30057, thif->state != STOPPED || exited || WIFEXITED(status) || WIFSIGNALED(status));

  event->tid = NO_EVENT; // start with empty event

  // if there was a pending event, it means that previously we did not resume
  // any threads, all of them are suspended
  set_thread_state(*thif, STOPPED);

  dbg_freeze_threads(NO_THREAD);
  may_run = false;

  // debugger event could be prepared during the check_for_new_events
  if ( event_ready )
    goto EVENT_READY; // report empty event to get called back immediately

  // dbg_freeze_threads may delete some threads and render our 'thif' pointer invalid
  thif = get_thread(tid);
  if ( thif == nullptr )
  {
    debdeb("thread %d disappeared after freezing?!...\n", tid);
    goto EVENT_READY; // report empty event to get called back immediately
  }

  event->pid = process_handle;
  event->tid = tid;
  if ( exited )
  {
    event->ea = BADADDR;
  }
  else if ( WIFSIGNALED(status) )
  {
    siginfo_t info;
    qptrace(PTRACE_GETSIGINFO, tid, nullptr, &info);
    event->ea = (ea_t)(size_t)info.si_addr;
  }
  else
  {
    event->ea = get_ip(event->tid);
  }
  event->handled = false;
  if ( WIFSTOPPED(status) )
  {
    ea_t proc_ip;
    bool suspend;
    const exception_info_t *ei;
    int code = WSTOPSIG(status);
    excinfo_t &exc = event->set_exception();
    exc.code     = code;
    exc.can_cont = true;
    exc.ea       = BADADDR;
    if ( code == SIGSTOP )
    {
      if ( thif->waiting_sigstop )
      {
        log(tid, "got pending SIGSTOP!\n");
        thif->waiting_sigstop = false;
        goto RESUME; // silently resume the application
      }
      // convert SIGSTOP into simple PROCESS_SUSPENDED, this will avoid
      // a dialog box about the signal. I'm not sure that this is a good thing
      // (probably better to report exceptions in the output windows rather than
      // in dialog boxes), so I'll comment it out for the moment.
      //event->eid = PROCESS_SUSPENDED;
    }

    ei = find_exception(code);
    if ( ei != nullptr )
    {
      exc.info.sprnt("got %s signal (%s)", ei->name.c_str(), ei->desc.c_str());
      suspend = should_suspend_at_exception(event, ei);
      if ( !suspend && ei->handle() )
        code = 0;               // mask the signal
    }
    else
    {
      exc.info.sprnt("got unknown signal #%d", code);
      suspend = true;
    }
    proc_ip = calc_bpt_event_ea(event); // if bpt, calc its address from event->ea
    if ( proc_ip != BADADDR )
    { // this looks like a bpt-related exception. it occurred either because
      // of our bpt either it was generated by the app.
      // by default, reset the code so we don't send any SIGTRAP signal to the debugged
      // process *except* in the case where the program generated the signal by
      // itself
      code = 0;
      if ( proc_ip == shlib_bpt.bpt_addr && shlib_bpt.bpt_addr != 0 )
      {
        log(tid, "got shlib bpt %a\n", proc_ip);
        // emulate return from function
        if ( !emulate_retn(tid) )
        {
          msg("%a: could not return from the shlib breakpoint!\n", proc_ip);
          return true;
        }
        if ( !gen_library_events(tid) ) // something has changed in shared libraries?
        { // no, nothing has changed
          log(tid, "nothing has changed in dlls\n");
RESUME:
          if ( !requested_to_suspend && !in_event )
          {
            ldeb("autoresuming\n");
//            QASSERT(30177, thif->state == STOPPED);
            resume_app(NO_THREAD);
            return false;
          }
          log(tid, "app may not run, keeping it suspended (%s)\n",
                        requested_to_suspend ? "requested_to_suspend" :
                        in_event ? "in_event" : "has_pending_events");
          event->set_eid(PROCESS_SUSPENDED);
          return true;
        }
        log(tid, "gen_library_events ok\n");
        event->set_eid(NO_EVENT);
      }
      else if ( (proc_ip == birth_bpt.bpt_addr && birth_bpt.bpt_addr != 0)
             || (proc_ip == death_bpt.bpt_addr && death_bpt.bpt_addr != 0) )
      {
        log(tid, "got thread bpt %a (%s)\n", proc_ip, proc_ip == birth_bpt.bpt_addr ? "birth" : "death");
        size_t s = events.size();
        thread_handle = tid; // for ps_pdread
        // NB! if we don't do this, some running threads can interfere with thread_db
        tdb_handle_messages(tid);
        // emulate return from function
        if ( !emulate_retn(tid) )
        {
          msg("%a: could not return from the thread breakpoint!\n", proc_ip);
          return true;
        }
        if ( s == events.size() )
        {
          log(tid, "resuming after thread_bpt\n");
          goto RESUME;
        }
        event->set_eid(NO_EVENT);
      }
      else
      {
        // according to the requirement of commdbg a LIB_LOADED event
        // should not be reported with the same thread/IP immediately after
        // a BPT-related event (see idd.hpp)
        // Here we put to the queue all already loaded (but not reported)
        // libraries to be sent _before_ BPT (do it only if ELF interpreter
        // is not yet loaded, otherwise LIB_LOADED events will be generated
        // by shlib_bpt and thus they cannot conflict with regular BPTs
        if ( interp.empty() )
        {
          gen_library_events(tid);
          thif = get_thread(tid);
        }
        if ( !handle_hwbpt(event) )
        {
          if ( bpts.find(proc_ip) != bpts.end()
            && !handling_lowcnds.has(proc_ip) )
          {
            bptaddr_t &bpta = event->set_bpt();
            bpta.hea = BADADDR;
            bpta.kea = BADADDR;
            event->ea = proc_ip;
          }
          else if ( thif != nullptr && thif->single_step )
          {
            event->set_eid(STEP);
          }
          else
          {
            // in case of unknown breakpoints (icebp, int3, etc...) we must remember the signal
            // unless it should be masked
            if ( ei == nullptr || !ei->handle() )
              code = event->exc().code;
          }
        }
      }
    }
    thif = get_thread(tid);
    if ( thif == nullptr )
      goto EVENT_READY; // report empty event to get called back immediately
    thif->child_signum = code;
    if ( !requested_to_suspend && evaluate_and_handle_lowcnd(event) )
      return false;
    if ( !suspend && event->eid() == EXCEPTION )
    {
      log_exception(event, ei);
      log(tid, "resuming after exception %d\n", code);
      goto RESUME;
    }
  }
  else
  {
    int exit_code;
    if ( WIFSIGNALED(status) )
    {
      int sig = WTERMSIG(status);
      debdeb("SIGNALED pid=%d tid=%d signal='%s'(%d) pc=%a\n", event->pid, event->tid, strsignal(sig), sig, event->ea);
      exit_code = sig;
    }
    else
    {
      exit_code = WEXITSTATUS(status);
    }
    if ( threads.size() <= 1 || thif->tid == process_handle )
    {
      event->set_exit_code(PROCESS_EXITED, exit_code);
      exited = true;
    }
    else
    {
      log(tid, "got a thread exit\n");
      event->clear();
      dead_thread(event->tid, DEAD);
    }
  }
EVENT_READY:
  log(tid, "low got event: %s, signum=%d\n", debug_event_str(event), thif->child_signum);
  thif = get_thread(event->tid);
  if ( thif != nullptr )
    thif->single_step = false;
  last_event = *event;
  return true;
}

//--------------------------------------------------------------------------
gdecode_t idaapi linux_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  QASSERT(30059, !in_event || exited);
  while ( true )
  {
    // are there any pending events?
    if ( !events.empty() )
    {
      // get the first event and return it
      *event = events.front();
      events.pop_front();
      if ( event->eid() == NO_EVENT )
        continue;
      log(-1, "GDE1(handling_lowcnds.size()=%" FMT_Z "): %s\n", handling_lowcnds.size(), debug_event_str(event));
      in_event = true;
      if ( handling_lowcnds.empty() )
      {
        ldeb("requested_to_suspend := 0\n");
        requested_to_suspend = false;
      }
      return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
    }

    debug_event_t ev;
    if ( !get_debug_event(&ev, timeout_ms) )
      break;
    enqueue_event(ev, IN_BACK);
  }
  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// R is running
// S is sleeping in an interruptible wait
// D is waiting in uninterruptible disk sleep
// Z is zombie
// T is traced or stopped (on a signal)
// W is paging
static char getstate(int tid)
{
  char buf[QMAXPATH];
  qsnprintf(buf, sizeof(buf), "/proc/%u/status", tid);
  FILE *fp = fopenRT(buf);
  qstring line;
  if ( fp == nullptr                 //-V501 identical sub-expressions
    || qgetline(&line, fp) < 0
    || qgetline(&line, fp) < 0 )
  {
    // no file or file read error (e.g. was deleted after successful fopenRT())
    return ' ';
  }
  char st;
  if ( qsscanf(line.c_str(), "State:  %c", &st) != 1 )
    INTERR(30060);
  qfclose(fp);
  return st;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::has_pending_events(void)
{
  if ( !events.empty() )
    return true;

  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.got_pending_status && ti.user_suspend == 0 && ti.suspend_count == 0 )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
int linux_debmod_t::dbg_freeze_threads(thid_t tid, bool exclude)
{
  ldeb("  freeze_threads(%s %d) handling_lowcnds.size()=%" FMT_Z "\n", exclude ? "exclude" : "only", tid, handling_lowcnds.size());
  // first send all threads the SIGSTOP signal, as fast as possible
  typedef qvector<thread_info_t *> queue_t;
  queue_t queue;
  qvector<thid_t> deadtids;
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) == exclude )
      continue;
    thread_info_t &ti = p->second;
    if ( ti.is_running() )
    {
      if ( qkill(ti.tid, SIGSTOP) != 0 )
      {
        // In some cases the thread may already be dead but we are not aware
        // of it (for example, if many threads died at once, the events
        // will be queued and not processed yet.
        if ( errno == ESRCH )
          deadtids.push_back(ti.tid);
        else
          dmsg("failed to send SIGSTOP to thread %d: %s\n", ti.tid, strerror(errno));
        continue;
      }
      queue.push_back(&ti);
      ti.waiting_sigstop = true;
    }
    ti.suspend_count++;
  }
  // then wait for the SIGSTOP signals to arrive
  while ( !queue.empty() )
  {
    int status = 0;
    int stid = check_for_signal(&status, -1, exited ? -1 : 0);
    if ( stid > 0 )
    {
      // if more signals are to arrive, enable the waiter
      for ( queue_t::iterator p=queue.begin(); p != queue.end(); ++p )
      {
        thread_info_t &ti = **p;
        if ( ti.tid == stid )
        {
          if ( WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP )
          {
            // suspended successfully
            ti.waiting_sigstop = false;
            set_thread_state(ti, STOPPED);
          }
          else
          { // got another signal, SIGSTOP will arrive later
            store_pending_signal(stid, status);
          }
          stid = -1;
          queue.erase(p);
          break;
        }
      }
    }
    if ( stid > 0 ) // got a signal for some other thread
      store_pending_signal(stid, status);
  }

  // clean up dead threads
  for ( int i=0; i < deadtids.size(); i++ )
    dead_thread(deadtids[i], DEAD);

#ifdef LDEB
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) != exclude )
    {
      thid_t tid2 = p->first;
      log(tid2, "suspendd (ip=%08a)\n", get_ip(tid2));
    }
  }
#endif
  return 1;
}

//--------------------------------------------------------------------------
int linux_debmod_t::dbg_thaw_threads(thid_t tid, bool exclude)
{
  int ok = 1;
  ldeb("  thaw_threads(%s %d), may_run=%d handlng_lowcnd.size()=%" FMT_Z " npending_signals=%d\n", exclude ? "exclude" : "only", tid, may_run, handling_lowcnds.size(), npending_signals);
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) == exclude )
      continue;

    thread_info_t &ti = p->second;
    log(ti.tid, "(ip=%08a) ", get_ip(ti.tid));

    if ( ti.is_running() )
    {
      QASSERT(30188, ti.suspend_count == 0);
      ldeb("already running\n");
      continue;
    }

    if ( ti.suspend_count > 0 && --ti.suspend_count > 0 )
    {
      ldeb("suspended\n");
      continue;
    }
    if ( ti.user_suspend > 0 )
    {
      ldeb("user suspended\n");
      continue;
    }

    if ( ti.got_pending_status )
    {
      ldeb("have pending signal\n");
      continue;
    }

    if ( (!may_run && ti.state != DYING) || exited )
    {
      ldeb("!may_run\n");
      continue;
    }

    if ( ti.state == STOPPED || ti.state == DYING )
    {
      __ptrace_request request = ti.single_step ? PTRACE_SINGLESTEP : PTRACE_CONT;
#ifdef LDEB
      char ostate = getstate(ti.tid);
#endif
      ldeb("really resuming\n");
      if ( qptrace(request, ti.tid, 0, (void *)(size_t)(ti.child_signum)) != 0 && ti.state != DYING )   //lint !e571 cast results in sign extension
      {
        ldeb("    !! failed to resume thread (error %d)\n", errno);
        if ( getstate(ti.tid) != 'Z' )
        {
          ok = 0;
          continue;
        }
        // we have a zombie thread
        // report its death
        dead_thread(ti.tid, DYING);
      }
      if ( ti.state == DYING )
      {
        set_thread_state(ti, DEAD);
      }
      else
      {
        QASSERT(30178, ti.state == STOPPED);    //-V547 is always true
        set_thread_state(ti, RUNNING);
      }
      ldeb("PTRACE_%s, signum=%d, old_state: '%c', new_state: '%c'\n", request == PTRACE_SINGLESTEP ? "SINGLESTEP" : "CONT", ti.child_signum, ostate, getstate(ti.tid));
    }
    else
    {
      ldeb("ti.state is not stopped or dying\n");
    }
  }
  return ok;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::suspend_all_threads(void)
{
  return dbg_freeze_threads(NO_THREAD);
}

//--------------------------------------------------------------------------
bool linux_debmod_t::resume_all_threads(void)
{
  return dbg_thaw_threads(NO_THREAD);
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( event == nullptr )
    return DRC_FAILED;

  int tid = event->tid;
  thread_info_t *t = get_thread(tid);
  if ( t == nullptr && event->eid() != THREAD_EXITED && !exited )
  {
    dwarning("could not find thread %d!\n", tid);
    return DRC_FAILED;
  }

  ldeb("continue after event %s%s\n", debug_event_str(event), has_pending_events() ? " (there are pending events)" : "");

  if ( t != nullptr )
  {
    if ( event->eid() != THREAD_STARTED
      && event->eid() != THREAD_EXITED
      && event->eid() != LIB_LOADED
      && event->eid() != LIB_UNLOADED
      && (event->eid() != EXCEPTION || event->handled) )
    {
      t->child_signum = 0;
    }

    if ( t->state == DYING )
    {
      // this thread is about to exit; resume it so it can do so
      t->suspend_count = 0;
      t->user_suspend = 0;
      dbg_thaw_threads(t->tid, false);
    }
    else if ( t->state == DEAD )
    {
      // remove from internal list
      del_thread(event->tid);
    }

    // ensure TF bit is not set (if we aren't single stepping) after a SIGTRAP
    // because TF bit may still be set
    if ( event->eid() == EXCEPTION && !t->single_step
      && event->exc().code == SIGTRAP && event->handled )
      clear_tbit(event->tid);
  }

  in_event = false;
  return resume_app(NO_THREAD) ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
// if tid is specified, resume only it.
bool linux_debmod_t::resume_app(thid_t tid)
{
  may_run = !handling_lowcnds.empty() || !has_pending_events();
  if ( !removed_bpts.empty() && npending_signals == 0 && handling_lowcnds.empty() )
  {
    for ( easet_t::iterator p=removed_bpts.begin(); p != removed_bpts.end(); ++p )
      bpts.erase(*p);
    removed_bpts.clear();
  }

  return tid == NO_THREAD
       ? resume_all_threads()
       : dbg_thaw_threads(tid, false);
}

//--------------------------------------------------------------------------
// PTRACE_PEEKTEXT / PTRACE_POKETEXT operate on unsigned long values! (i.e. 4 bytes on x86 and 8 bytes on x64)
typedef unsigned long peeksize_t;
#define PEEKSIZE sizeof(peeksize_t)

//--------------------------------------------------------------------------
int linux_debmod_t::_read_memory(int tid, ea_t ea, void *buffer, int size, bool suspend)
{
  if ( exited || process_handle == INVALID_HANDLE_VALUE )
    return 0;

  // stop all threads before accessing the process memory
  if ( suspend )
    suspend_all_threads();

  if ( tid == -1 )
    tid = process_handle;

  int read_size = 0;
  bool tried_mem = false;
  bool tried_peek = false;
  // don't use memory for short reads
  if ( size > 3 * PEEKSIZE )
  {
TRY_MEMFILE:
#ifndef __ANDROID__
    char filename[64];
    qsnprintf (filename, sizeof(filename), "/proc/%d/mem", tid);
    int fd = open(filename, O_RDONLY | O_LARGEFILE);
    if ( fd != -1 )
    {
      read_size = pread64(fd, buffer, size, ea);
      close(fd);
    }
    // msg("%d: pread64 %d:%a:%d => %d\n", tid, fd, ea, size, read_size);

#ifdef LDEB
    if ( read_size < size )
      perror("read_memory: pread64 failed");
#endif
#endif
    tried_mem = true;
  }

  if ( read_size != size && !tried_peek )
  {
    uchar *ptr = (uchar *)buffer;
    read_size = 0;
    tried_peek = true;
    while ( read_size < size )
    {
      const int shift = ea & (PEEKSIZE-1);
      int nbytes = shift == 0 ? PEEKSIZE : PEEKSIZE - shift;
      if ( nbytes > (size - read_size) )
        nbytes = size - read_size;
      errno = 0;
      unsigned long v = qptrace(PTRACE_PEEKTEXT, tid, (void *)(size_t)(ea-shift), 0);
      if ( errno != 0 )
      {
        ldeb("PEEKTEXT %d:%a => %s\n", tid, ea-shift, strerror(errno));
        break;
      }
      else
      {
        //msg("PEEKTEXT %d:%a => OK\n", tid, ea-shift);
      }
      if ( nbytes == PEEKSIZE )
      {
        *(unsigned long*)ptr = v;   //lint !e433 !e415 allocated area not large enough for pointer
      }
      else
      {
        v >>= (shift*8);
        for ( int i=0; i < nbytes; i++ )
        {
          ptr[i] = uchar(v);
          v >>= 8;
        }
      }
      ptr  += nbytes;
      ea   += nbytes;
      read_size += nbytes;
    }
  }

  // sometimes PEEKTEXT fails but memfile succeeds... so try both
  if ( read_size < size && !tried_mem )
    goto TRY_MEMFILE;

  if ( suspend )
    resume_all_threads();
  // msg("READ MEMORY (%d): %d\n", tid, read_size);
  return read_size > 0 ? read_size : 0;
}

//--------------------------------------------------------------------------
int linux_debmod_t::_write_memory(int tid, ea_t ea, const void *buffer, int size, bool suspend)
{
  if ( exited || process_handle == INVALID_HANDLE_VALUE )
    return 0;

#ifndef LDEB
  if ( debug_debugger )
#endif
  {
    show_hex(buffer, size, "WRITE MEMORY %a %d bytes:\n", ea, size);
  }

  // stop all threads before accessing the process memory
  if ( suspend )
    suspend_all_threads();


  if ( tid == -1 )
    tid = process_handle;

  int ok = size;
  const uchar *ptr = (const uchar *)buffer;
  errno = 0;

  while ( size > 0 )
  {
    const int shift = ea & (PEEKSIZE-1);
    int nbytes = shift == 0 ? PEEKSIZE : PEEKSIZE - shift;
    if ( nbytes > size )
      nbytes = size;
    unsigned long word;
    memcpy(&word, ptr, qmin(sizeof(word), nbytes)); // use memcpy() to read unaligned bytes
    if ( nbytes != PEEKSIZE )
    {
      unsigned long old = qptrace(PTRACE_PEEKTEXT, tid, (void *)(size_t)(ea-shift), 0);
      if ( errno != 0 )
      {
        ok = 0;
        break;
      }
      unsigned long mask = ~0;
      mask >>= ((PEEKSIZE - nbytes)*8);
      mask <<= (shift*8);
      word <<= (shift*8);
      word &= mask;
      word |= old & ~mask;
    }
    errno = 0;
    qptrace(PTRACE_POKETEXT, process_handle, (void *)(size_t)(ea-shift), (void *)word);
    if ( errno )
    {
      errno = 0;
      qptrace(PTRACE_POKEDATA, process_handle, (void *)(size_t)(ea-shift), (void *)word);
    }
    if ( errno )
    {
      ok = 0;
      break;
    }
    ptr  += nbytes;
    ea   += nbytes;
    size -= nbytes;
  }

  if ( suspend )
    resume_all_threads();

  return ok;
}

//--------------------------------------------------------------------------
ssize_t idaapi linux_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring * /*errbuf*/)
{
  return _write_memory(-1, ea, buffer, size, true);
}

//--------------------------------------------------------------------------
ssize_t idaapi linux_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring * /*errbuf*/)
{
  return _read_memory(-1, ea, buffer, size, true);
}

//--------------------------------------------------------------------------
void linux_debmod_t::add_dll(ea_t base, asize_t size, const char *modname, const char *soname)
{
  debdeb("%a: new dll %s (soname=%s)\n", base, modname, soname);
  debug_event_t ev;
  modinfo_t &mi_ll = ev.set_modinfo(LIB_LOADED);
  ev.pid     = process_handle;
  ev.tid     = process_handle;
  ev.ea      = base;
  ev.handled = true;
  mi_ll.name = modname;
  mi_ll.base = base;
  mi_ll.size = size;
  mi_ll.rebase_to = BADADDR;
  if ( is_dll && input_file_path == modname )
    mi_ll.rebase_to = base;
  enqueue_event(ev, IN_FRONT);

  image_info_t ii(base, ev.modinfo().size, modname, soname);
  dlls.insert(make_pair(ii.base, ii));
  dlls_to_import.insert(ii.base);
}

#define LOOK_FOR_DEBUG_FILE_DEBUG_FLAG IDA_DEBUG_DEBUGGER
#include "../../plugins/dwarf/look_for_debug_file.cpp"

//--------------------------------------------------------------------------
void linux_debmod_t::_import_symbols_from_file(name_info_t *out, image_info_t &ii)
{
  struct dll_symbol_importer_t : public symbol_visitor_t
  {
    linux_debmod_t *ld;
    image_info_t &ii;
    name_info_t *out;
    dll_symbol_importer_t(linux_debmod_t *_ld, name_info_t *_out, image_info_t &_ii)
      : symbol_visitor_t(VISIT_SYMBOLS|VISIT_BUILDID|VISIT_DBGLINK),
      ld(_ld),
      ii(_ii),
      out(_out)
    {}
    virtual int visit_symbol(ea_t ea, const char *name) override
    {
      ea += ii.base;
      out->addrs.push_back(ea);
      out->names.push_back(qstrdup(name));
      ii.names[ea] = name;
      // every 10000th name send a message to ida - we are alive!
      if ( (out->addrs.size() % 10000) == 0 )
        ld->dmsg("");
      return 0;
    }
    virtual int visit_buildid(const char *buildid) override
    {
      ii.buildid = buildid;
      ld->debdeb("Build ID '%s' of '%s'\n", buildid, ii.fname.c_str());
      return 0;
    }
    virtual int visit_debuglink(const char *debuglink, uint32 crc) override
    {
      ii.debuglink = debuglink;
      ii.dl_crc = crc;
      ld->debdeb("debuglink '%s' of '%s'\n", debuglink, ii.fname.c_str());
      return 0;
    }
  };
  if ( ii.base == BADADDR )
  {
    debdeb("Can't import symbols from %s: no imagebase\n", ii.fname.c_str());
    return;
  }
  dll_symbol_importer_t dsi(this, out, ii);
  load_elf_symbols(ii.fname.c_str(), dsi);
}

//-------------------------------------------------------------------------
void linux_debmod_t::_import_dll(image_info_t &ii)
{
  bool is_libpthread = stristr(ii.soname.c_str(), "libpthread") != nullptr;
  // keep nptl names in a separate list to be able to resolve them any time
  name_info_t *storage = is_libpthread ? &nptl_names : &pending_names;
  if ( is_libpthread )
    nptl_base = ii.base;

  _import_symbols_from_file(storage, ii);
  // Try to locate file with the separate debug info.
  // FIXME: should we check that libpthread lacks symbols for libthread_db?
  // Library.so usually contains debuglink which points to itself,
  // so we need to avoid to load library.so another time.
  const char *elf_dbgdir = get_elf_debug_file_directory();
#ifdef TESTABLE_BUILD
  if ( per_pid_elf_dbgdir_resolver != nullptr )
  {
    const char *supp = per_pid_elf_dbgdir_resolver(pid);
    if ( supp != nullptr )
      elf_dbgdir = supp;
  }
#endif
  debug_info_file_visitor_t dif(
          elf_dbgdir,
          /*from envvar=*/ true,
          ii.fname.c_str(),
          ii.debuglink.c_str(),
          ii.dl_crc,
          ii.buildid.c_str());
  if ( dif.accept() != 0 && ii.fname != dif.fullpath )
  {
    debdeb("load separate debug info '%s'\n", dif.fullpath);
    image_info_t ii_deb(ii.base, 0, dif.fullpath, "");
    _import_symbols_from_file(storage, ii_deb);
  }

  if ( is_libpthread )
  {
    pending_names.addrs.insert(pending_names.addrs.end(), nptl_names.addrs.begin(), nptl_names.addrs.end());
    pending_names.names.insert(pending_names.names.end(), nptl_names.names.begin(), nptl_names.names.end());
    for ( int i=0; i < nptl_names.names.size(); i++ )
      nptl_names.names[i] = qstrdup(nptl_names.names[i]);
  }
}

//--------------------------------------------------------------------------
// enumerate names from the specified shared object and save the results
// we'll need to send it to IDA later
// if libname == nullptr, enum all modules
void linux_debmod_t::enum_names(const char *libname)
{
  if ( dlls_to_import.empty() )
    return;

  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    images_t::iterator q = dlls.find(*p);
    if ( q != dlls.end() )
    {
      image_info_t &ii = q->second;
      if ( libname != nullptr && ii.soname != libname )
      {
        ++p;
        continue;
      }
      _import_dll(ii);
    }
    p = dlls_to_import.erase(p);
  }
}

//--------------------------------------------------------------------------
ea_t linux_debmod_t::find_pending_name(const char *name)
{
  if ( name == nullptr )
    return BADADDR;
  // enumerate pending names in reverse order. we need this to find the latest
  // resolved address for a name (on android, pthread_..() functions exist twice)
  for ( int i=pending_names.addrs.size()-1; i >= 0; --i )
    if ( streq(pending_names.names[i], name) )
      return pending_names.addrs[i];
  for ( int i=0; i < nptl_names.addrs.size(); ++i )
    if ( streq(nptl_names.names[i], name) )
      return nptl_names.addrs[i];
  return BADADDR;
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_stopped_at_debug_event(import_infos_t *, bool dlls_added, thread_name_vec_t *thr_names)
{
  if ( dlls_added )
  {
    // we will take advantage of this event to import information
    // about the exported functions from the loaded dlls
    enum_names();

    name_info_t &ni = *get_debug_names();
    ni = pending_names; // NB: ownership of name pointers is transferred
    pending_names.clear();
  }
  if ( thr_names != nullptr )
    update_thread_names(thr_names);
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup(void)
{
  // if the process is still running, kill it, otherwise it runs uncontrolled
  // normally the process is dead at this time but may survive if we arrive
  // here after an interr.
  if ( process_handle != INVALID_HANDLE_VALUE )
    dbg_exit_process(nullptr);
  process_handle = INVALID_HANDLE_VALUE;
  thread_handle  = INVALID_HANDLE_VALUE;
  threads_collected = false;
  is_dll = false;
  requested_to_suspend = false;
  in_event = false;

  threads.clear();
  dlls.clear();
  dlls_to_import.clear();
  events.clear();
  if ( mapfp != nullptr )
  {
    qfclose(mapfp);
    mapfp = nullptr;
  }

  complained_shlib_bpt = false;
  bpts.clear();

  tdb_delete();
  erase_internal_bp(birth_bpt);
  erase_internal_bp(death_bpt);
  erase_internal_bp(shlib_bpt);
  npending_signals = 0;
  interp.clear();
  exe_path.qclear();
  exited = false;

  for ( int i=0; i < nptl_names.names.size(); i++ )
    qfree(nptl_names.names[i]);
  nptl_names.clear();

  inherited::cleanup();
}

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERFACE FUNCTIONS
//
//--------------------------------------------------------------------------
inline const char *skipword(const char *ptr)
{
  while ( !qisspace(*ptr) && *ptr != '\0' )
    ptr++;
  return ptr;
}

//--------------------------------------------------------------------------
// find a first mapping of shared lib in the memory information array
static const memory_info_t *find_first_mapping(const meminfo_vec_t &miv, const char *name)
{
  for ( int i=0; i < miv.size(); i++ )
    if ( miv[i].name == name )
      return &miv[i];
  return nullptr;
}

//--------------------------------------------------------------------------
static memory_info_t *find_first_mapping(meminfo_vec_t &miv, const char *name)    //lint !e1764 could be reference to const
{
  return CONST_CAST(memory_info_t *)(find_first_mapping(CONST_CAST(const meminfo_vec_t &)(miv), name));
}

//--------------------------------------------------------------------------
bool linux_debmod_t::add_shlib_bpt(const meminfo_vec_t &miv, bool attaching)
{
  if ( shlib_bpt.bpt_addr != 0 )
    return true;

  qstring interp_soname;
  if ( interp.empty() )
  {
    // find out the loader name
    struct interp_finder_t : public symbol_visitor_t
    {
      qstring interp;
      interp_finder_t(void) : symbol_visitor_t(VISIT_INTERP) {}
      virtual int visit_symbol(ea_t, const char *) override { return 0; } // unused
      virtual int visit_interp(const char *name) override
      {
        interp = name;
        return 2;
      }
    };
    interp_finder_t itf;
    const char *exename = exe_path.c_str();
    int code = load_elf_symbols(exename, itf);
    if ( code == 0 )
    { // no interpreter
      if ( !complained_shlib_bpt )
      {
        complained_shlib_bpt = true;
        dwarning("AUTOHIDE DATABASE\n%s:\n"
                 "Could not find the elf interpreter name,\n"
                 "shared object events will not be reported", exename);
      }
      return false;
    }
    if ( code != 2 )
    {
      dwarning("%s: could not read symbols on remote computer", exename);
      return false;
    }
    char path[QMAXPATH];
    qmake_full_path(path, sizeof(path), itf.interp.c_str());
    interp_soname.swap(itf.interp);
    interp = path;
  }
  else
  {
    interp_soname = qbasename(interp.c_str());
  }

  // check if it is present in the memory map (normally it is)
  debdeb("INTERP: %s, SONAME: %s\n", interp.c_str(), interp_soname.c_str());
  const memory_info_t *mi = find_first_mapping(miv, interp.c_str());
  if ( mi == nullptr )
  {
    dwarning("%s: could not find in process memory", interp.c_str());
    return false;
  }

  asize_t size = calc_module_size(miv, mi);
  add_dll(mi->start_ea, size, interp.c_str(), interp_soname.c_str());

  // set bpt at r_brk
  enum_names(interp_soname.c_str()); // update the name list
  const char *bpt_name = "_r_debug";
  ea_t ea = find_pending_name(bpt_name);
  if ( ea != BADADDR )
  {
    struct r_debug rd;
    if ( _read_memory(-1, ea, &rd, sizeof(rd), false) == sizeof(rd) )
    {
      if ( rd.r_brk != 0 )
      {
        if ( !add_internal_bp(shlib_bpt, rd.r_brk) )
        {
          ea_t ea1 = rd.r_brk;
          debdeb("%a: could not set shlib bpt\n", ea1);
        }
      }
    }
  }
  if ( shlib_bpt.bpt_addr == 0 )
  {
    static const char *const shlib_bpt_names[] =
    {
      "r_debug_state",
      "_r_debug_state",
      "_dl_debug_state",
      "rtld_db_dlactivity",
      "_rtld_debug_state",
      nullptr
    };

    for ( int i=0; i < qnumber(shlib_bpt_names); i++ )
    {
      bpt_name = shlib_bpt_names[i];
      ea = find_pending_name(bpt_name);
      if ( ea != BADADDR && ea != 0 )
      {
        if ( add_internal_bp(shlib_bpt, ea) )
          break;
        debdeb("%a: could not set shlib bpt (name=%s)\n", ea, bpt_name);
      }
    }
    if ( shlib_bpt.bpt_addr == 0 )
    {
#if defined(__ANDROID__) && defined(__X86__)
      // Last attempt for old Android,
      // the modern Android doesn't need the special handling
      return add_android_shlib_bpt(miv, attaching);
#else
      qnotused(attaching);
      return false;
#endif
    }
  }
  debdeb("%a: added shlib bpt (%s)\n", shlib_bpt.bpt_addr, bpt_name);
  return true;
}

//--------------------------------------------------------------------------
thread_info_t &linux_debmod_t::add_thread(int tid)
{
  std::pair<threads_t::iterator, bool> ret =
    threads.insert(std::make_pair(tid, thread_info_t(tid)));
  thread_info_t &ti = ret.first->second;
  get_thread_name(&ti.name, tid);
  return ti;
}

//--------------------------------------------------------------------------
void linux_debmod_t::del_thread(int tid)
{
  threads_t::iterator p = threads.find(tid);
  QASSERT(30064, p != threads.end());
  if ( p->second.got_pending_status )
    npending_signals--;
  threads.erase(p);

  if ( deleted_threads.size() >= 10 )
    deleted_threads.erase(deleted_threads.begin());

  deleted_threads.push_back(tid);
}

//--------------------------------------------------------------------------
bool linux_debmod_t::handle_process_start(pid_t _pid, attach_mode_t attaching)
{
  pid = _pid;
  deleted_threads.clear();
  process_handle = pid;
  threads_collected = false;
  add_thread(pid);
  int status;
  int options = 0;
  if ( attaching == AMT_ATTACH_BROKEN )
    options = WNOHANG;
  qwait(&status, pid, options); // (should succeed) consume SIGSTOP
  debdeb("process pid/tid: %d\n", pid);
  may_run = false;

  char fname[QMAXPATH];
  debug_event_t ev;
  modinfo_t &mi_ps = ev.set_modinfo(PROCESS_STARTED);
  ev.pid     = pid;
  ev.tid     = pid;
  ev.ea      = get_ip(pid);
  ev.handled = true;
  get_exec_fname(pid, fname, sizeof(fname));
  mi_ps.name = fname;
  mi_ps.base = BADADDR;
  mi_ps.size = 0;
  mi_ps.rebase_to = BADADDR;

  qsnprintf(fname, sizeof(fname), "/proc/%u/maps", pid);
  mapfp = fopenRT(fname);
  if ( mapfp == nullptr )
  {
    dmsg("%s: %s\n", fname, winerr(errno));
    return false;               // if fails, the process did not start
  }

  exe_path = mi_ps.name.c_str();
  if ( !is_dll )
    input_file_path = exe_path;

  // find the executable base
  meminfo_vec_t miv;
  // init debapp_attrs.addrsize: 32bit application by default
  // get_memory_info() may correct it if meets a 64-bit address
  set_addr_size(4);
  if ( get_memory_info(miv, false) <= 0 )
    INTERR(30065);

  init_dynamic_regs();

  const memory_info_t *mi = find_first_mapping(miv, mi_ps.name.c_str());
  if ( mi != nullptr )
  {
    mi_ps.base = mi->start_ea;
    mi_ps.size = calc_module_size(miv, mi);
    if ( !is_dll ) // exe files: rebase idb to the loaded address
      mi_ps.rebase_to = mi->start_ea;
  }
  else
  {
    if ( !is_dll )
      dmsg("%s: nowhere in the process memory?!\n", mi_ps.name.c_str());
  }

  if ( !add_shlib_bpt(miv, attaching) )
    dmsg("Could not set the shlib bpt, shared object events will not be handled\n");

  enqueue_event(ev, IN_BACK);
  if ( attaching != AMT_NO_ATTACH )
  {
    modinfo_t &mi_pa = ev.set_modinfo(PROCESS_ATTACHED);
    enqueue_event(ev, IN_BACK);
    if ( !qgetenv("IDA_SKIP_SYMS", nullptr) )
    {
      // collect exported names from the main module
      qstring soname;
      get_soname(mi_pa.name.c_str(), &soname);
      image_info_t ii(mi_pa.base, mi_pa.size, mi_pa.name.c_str(), soname);
      _import_dll(ii);
    }
  }

  return true;
}

//--------------------------------------------------------------------------
static void idaapi kill_all_processes(void)
{
  struct ida_local process_killer_t : public debmod_visitor_t
  {
    virtual int visit(debmod_t *debmod) override
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      if ( ld->process_handle != INVALID_HANDLE_VALUE )
        qkill(ld->process_handle, SIGKILL);
      return 0;
    }
  };
  process_killer_t pk;
  for_all_debuggers(pk);
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        launch_env_t *envs,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring *errbuf)
{
  void *child_pid;
  drc_t drc = maclnx_launch_process(this, path, args, envs, startdir, flags,
                                    input_path, input_file_crc32, &child_pid,
                                    errbuf);

  if ( drc > 0
    && child_pid != nullptr
    && !handle_process_start(size_t(child_pid), AMT_NO_ATTACH) )
  {
    dbg_exit_process(nullptr);
    drc = DRC_NETERR;
  }

  return drc;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
drc_t idaapi linux_debmod_t::dbg_attach_process(pid_t _pid, int /*event_id*/, int flags, qstring * /*errbuf*/)
{
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;
  if ( qptrace(PTRACE_ATTACH, _pid, nullptr, nullptr) == 0
    && handle_process_start(_pid, AMT_ATTACH_NORMAL) )
  {
    gen_library_events(_pid); // detect all loaded libraries
    return DRC_OK;
  }
  qptrace(PTRACE_DETACH, _pid, nullptr, nullptr);
  return DRC_FAILED;
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup_signals(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    // cannot leave pending sigstop, try to recieve and handle it
    if ( p->second.waiting_sigstop )
    {
      thread_info_t &ti = p->second;
      ldeb("cleanup_signals:\n");
      log(ti.tid, "must be STOPPED\n");
      QASSERT(30181, ti.state == STOPPED);
      qptrace(PTRACE_CONT, ti.tid, 0, 0);
      int status;
      int tid = check_for_signal(&status, ti.tid, -1);
      if ( tid != ti.tid )
        msg("%d: failed to clean up pending SIGSTOP\n", tid);
    }
  }
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup_breakpoints(void)
{
  erase_internal_bp(birth_bpt);
  erase_internal_bp(death_bpt);
  erase_internal_bp(shlib_bpt);
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_detach_process(void)
{
  // restore only internal breakpoints and signals
  cleanup_breakpoints();
  cleanup_signals();

  bool had_pid = false;
  bool ok = true;
  log(-1, "detach all threads.\n");
  for ( threads_t::iterator p=threads.begin(); ok && p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.tid == process_handle )
      had_pid = true;

    ok = qptrace(PTRACE_DETACH, ti.tid, nullptr, nullptr) == 0;
    log(-1, "detach tid %d: ok=%d\n", ti.tid, ok);
  }

  if ( ok && !had_pid )
  {
    // if pid was not in the thread list, detach it separately
    ok = qptrace(PTRACE_DETACH, process_handle, nullptr, nullptr) == 0;
    log(-1, "detach pid %d: ok=%d\n", process_handle, ok);
  }
  if ( ok )
  {
    debug_event_t ev;
    ev.set_eid(PROCESS_DETACHED);
    ev.pid     = process_handle;
    ev.tid     = process_handle;
    ev.ea      = BADADDR;
    ev.handled = true;
    enqueue_event(ev, IN_BACK);
    in_event = false;
    exited = true;
    threads.clear();
    process_handle = INVALID_HANDLE_VALUE;
    threads_collected = false;
    return DRC_OK;
  }
  return DRC_FAILED;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi linux_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
drc_t idaapi linux_debmod_t::dbg_prepare_to_pause_process(qstring * /*errbuf*/)
{
  if ( events.empty() )
  {
    qkill(process_handle, SIGSTOP);
    thread_info_t &ti = threads.begin()->second;
    ti.waiting_sigstop = true;
  }
  may_run = false;
  requested_to_suspend = true;
  ldeb("requested_to_suspend := 1\n");

  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_exit_process(qstring * /*errbuf*/)
{
  ldeb("------- exit process\n");
  bool ok = true;
  // suspend all threads to avoid problems (for example, killing a
  // thread may resume another thread and it can throw an exception because
  // of that)
  suspend_all_threads();
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.state == STOPPED )
    {
      if ( qptrace(PTRACE_KILL, ti.tid, 0, (void*)SIGKILL) != 0 && errno != ESRCH )
      {
        dmsg("PTRACE_KILL %d: %s\n", ti.tid, strerror(errno));
        ok = false;
      }
    }
    else
    {
      if ( ti.tid != INVALID_HANDLE_VALUE && qkill(ti.tid, SIGKILL) != 0 && errno != ESRCH )
      {
        dmsg("SIGKILL %d: %s\n", ti.tid, strerror(errno));
        ok = false;
      }
    }
    if ( ok )
    {
      set_thread_state(ti, RUNNING);
      ti.suspend_count = 0;
    }
  }
  if ( ok )
  {
    process_handle = INVALID_HANDLE_VALUE;
    threads_collected = false;
  }
  may_run = true;
  exited = true;
  return ok ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
// Set hardware breakpoints for one thread
bool linux_debmod_t::set_hwbpts(HANDLE hThread) const
{
#ifdef __ARM__
  qnotused(hThread);
  return false;
#else
  bool ok = set_dr(hThread, 0, hwbpt_ea[0])
         && set_dr(hThread, 1, hwbpt_ea[1])
         && set_dr(hThread, 2, hwbpt_ea[2])
         && set_dr(hThread, 3, hwbpt_ea[3])
         && set_dr(hThread, 6, 0)
         && set_dr(hThread, 7, dr7);
  // msg("set_hwbpts: DR0=%a DR1=%a DR2=%a DR3=%a DR7=%a => %d\n",
  //       hwbpt_ea[0],
  //       hwbpt_ea[1],
  //       hwbpt_ea[2],
  //       hwbpt_ea[3],
  //       dr7,
  //       ok);
  return ok;
#endif
}

//--------------------------------------------------------------------------
bool linux_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( !set_hwbpts(p->second.tid) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::erase_internal_bp(internal_bpt &bp)
{
  bool ok = bp.bpt_addr == 0 || dbg_del_bpt(BPT_SOFT, bp.bpt_addr, bp.saved, bp.nsaved);
  bp.bpt_addr = 0;
  bp.nsaved = 0;
  return ok;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::add_internal_bp(internal_bpt &bp, ea_t addr)
{
  int len = -1;
  int nread = sizeof(bp.saved);
#ifdef __ARM__
  if ( (addr & 1) != 0 )
  {
    len = 2;
    addr--;
  }
  else
  {
    len = 4;
  }
  CASSERT(sizeof(bp.saved) >= 4);
  nread = len;
#endif
  if ( _read_memory(-1, addr, bp.saved, nread) == nread )
  {
    if ( dbg_add_bpt(nullptr, BPT_SOFT, addr, len) )
    {
      bp.bpt_addr = addr;
      bp.nsaved = nread;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed, -2-read failed
int idaapi linux_debmod_t::dbg_add_bpt(
        bytevec_t *orig_bytes,
        bpttype_t type,
        ea_t ea,
        int len)
{
#if defined(__ARM__) && defined(__X86__)
  bool is_thumb32_bpt = false;
  if ( len == (2 | USE_THUMB32_BPT) )
  {
    is_thumb32_bpt = true;
    len = 4;
  }
#endif
  ldeb("%a: add bpt (size=%d)\n", ea, len);
  if ( type == BPT_SOFT )
  {
    if ( orig_bytes != nullptr && read_bpt_orgbytes(orig_bytes, ea, len) < 0 )
      return -2;
    const uchar *bptcode = bpt_code.begin();
#ifdef __ARM__
# ifndef __X86__
    if ( len < 0 )
      len = bpt_code.size();
    bptcode = aarch64_bpt;
# else
    if ( len < 0 )
    { // unknown mode. we have to decide between thumb and arm bpts
      // ideally we would decode the instruction and try to determine its mode
      // unfortunately we do not have instruction decoder in arm server.
      // besides, it cannot really help.
      // just check for some known opcodes. this is bad but i do not know
      // how to do better.

      len = 4; // default to arm mode
      uchar opcodes[2];
      if ( dbg_read_memory(ea, opcodes, sizeof(opcodes), nullptr) == sizeof(opcodes) )
      {
        static const uchar ins1[] = { 0x70, 0x47 }; // BX      LR
        static const uchar ins3[] = { 0x00, 0xB5 }; // PUSH    {LR}
        static const uchar ins2[] = { 0x00, 0xBD }; // POP     {PC}
        static const uchar *const ins[] = { ins1, ins2, ins3 };
        for ( int i=0; i < qnumber(ins); i++ )
        {
          const uchar *p = ins[i];
          if ( opcodes[0] == p[0] && opcodes[1] == p[1] )
          {
            len = 2;
            break;
          }
        }
      }
    }
    if ( len == 2 )
      bptcode = thumb16_bpt;
    else if ( len == 4 && is_thumb32_bpt )
      bptcode = thumb32_bpt;
# endif
#else
    if ( len < 0 )
      len = bpt_code.size();
#endif
    QASSERT(30066, len > 0 && len <= bpt_code.size());
    debmod_bpt_t dbpt(ea, len);
    if ( dbg_read_memory(ea, dbpt.saved, len, nullptr)
      && dbg_write_memory(ea, bptcode, len, nullptr) == len )
    {
      bpts[ea] = dbpt;
      removed_bpts.erase(ea);
      return 1;
    }
  }

#ifndef __ARM__
  if ( add_hwbpt(type, ea, len) )
    return 1;
#endif

  return 0;
}

//--------------------------------------------------------------------------
#ifdef __ARM__
void linux_debmod_t::adjust_swbpt(ea_t *p_ea, int *p_len)
{
  inherited::adjust_swbpt(p_ea, p_len);
  // for thumb mode we have to decide between 16-bit and 32-bit bpt
  if ( *p_len == 2 )
  {
    uint16 opcode;
    if ( dbg_read_memory(*p_ea, &opcode, sizeof(opcode), nullptr) <= 0 )
      return;
    if ( is_32bit_thumb_insn(opcode) )
      *p_len |= USE_THUMB32_BPT; // ask for thumb32 bpt
  }
}
#endif

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
#if defined(__ARM__) && defined(__X86__)
  if ( len == (2 | USE_THUMB32_BPT) )
    len = 4;
#endif
  ldeb("%a: del bpt (size=%d) exited=%d\n", ea, len, exited);
  if ( orig_bytes != nullptr )
  {
    if ( dbg_write_memory(ea, orig_bytes, len, nullptr) == len )
    {
      removed_bpts.insert(ea);
      return true;
    }
  }

#ifdef __ARM__
  qnotused(type);
  return false;
#else
  return del_hwbpt(ea, type);
#endif
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_thread_get_sreg_base(ea_t *pea, thid_t tid, int sreg_value, qstring * /*errbuf*/)
{
#ifdef __ARM__
  qnotused(tid);
  qnotused(sreg_value);
  qnotused(pea);
  return DRC_FAILED;
#else
  *pea = 0; // all other selectors (cs, ds) usually have base of 0...
  // since we do not receive the segment register id we need to retrieve, we
  // rely on the register value, which is not great. for example,
  // on x64 fs==gs==0, and when IDA passes sreg_value==0, we return the
  // base of fs.
  if ( sreg_value != 0 )
  {
    // find out which selector we're asked to retrieve
    struct user_regs_struct regs;
    memset(&regs, -1, sizeof(regs));
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return DRC_FAILED;
    if ( sreg_value == regs.INTEL_SREG(fs) )
      return thread_get_fs_base(tid, fs_idx, pea) ? DRC_OK : DRC_FAILED;
    else if ( sreg_value == regs.INTEL_SREG(gs) )
      return thread_get_fs_base(tid, gs_idx, pea) ? DRC_OK : DRC_FAILED;
  }
  return DRC_OK;
#endif
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_thread_suspend(thid_t tid)
{
  thread_info_t *ti = get_thread(tid);
  if ( ti == nullptr )
    return DRC_FAILED;
  if ( !dbg_freeze_threads(tid, false) )
    return DRC_FAILED;
  ti->user_suspend++;
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_thread_continue(thid_t tid)
{
  thread_info_t *ti = get_thread(tid);
  if ( ti == nullptr )
    return DRC_FAILED;
  if ( ti->user_suspend > 0 )
  {
    if ( --ti->user_suspend > 0 )
      return DRC_OK;
  }
  return dbg_thaw_threads(tid, false) ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return DRC_FAILED; // not supported

  thread_info_t *t = get_thread(tid);
  if ( t == nullptr )
    return DRC_FAILED;
  t->single_step = true;
  return DRC_OK;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::emulate_retn(int tid)
{
#ifdef __ARM__
# ifndef __X86__
  struct user_regs_struct regs;
  if ( !qptrace_get_prstatus(&regs, tid) )
    return false;

  // emulate BX LR
  regs.pc = regs.regs[LRREG_IDX];    // PC <- LR

  return qptrace_set_regset(NT_PRSTATUS, tid, &regs, sizeof(regs));
# else
  struct user_regs_struct regs;
  qptrace(PTRACE_GETREGS, tid, 0, &regs);
  // emulate BX LR
  int tbit = regs.uregs[14] & 1;
  regs.PCREG = regs.uregs[14] & ~1;    // PC <- LR
  setflag(regs.uregs[16], 1<<5, tbit); // Set/clear T bit in PSR
  return qptrace(PTRACE_SETREGS, tid, 0, &regs) == 0;
# endif
#else
  struct user_regs_struct regs;
  qptrace(PTRACE_GETREGS, tid, 0, &regs);
  size_t sizeof_pcreg = get_addr_size();
  if ( _read_memory(tid, regs.SPREG, &regs.PCREG, sizeof_pcreg, false) != sizeof_pcreg )
  {
    log(-1, "%d: reading return address from %a failed\n", tid, ea_t(regs.SPREG));
    if ( tid == process_handle )
      return false;
    if ( _read_memory(process_handle, regs.SPREG, &regs.PCREG, sizeof_pcreg, false) != sizeof_pcreg )
    {
      log(-1, "%d: reading return address from %a failed (2)\n", process_handle, ea_t(regs.SPREG));
      return false;
    }
  }
  regs.SPREG += sizeof_pcreg;
  log(-1, "%d: retn to %a\n", tid, ea_t(regs.PCREG));
  return qptrace(PTRACE_SETREGS, tid, 0, &regs) == 0;
#endif
}

//--------------------------------------------------------------------------
#define qoffsetof2(s, f) (qoffsetof(regctx_t, s) + qoffsetof(decltype(regctx_t::s), f))
#define offset_size(s, f) qoffsetof2(s, f), sizeof(decltype(regctx_t::s)::f)

#ifdef __ARM__
# ifndef __X86__
//--------------------------------------------------------------------------
// AArch64
//--------------------------------------------------------------------------
struct regctx_t : public regctx_base_t
{
  struct user_regs_struct regs;
#ifdef __HAVE_ARM_NEON__
  // struct user_fpsimd_struct
  // {
  //   __uint128_t vregs[32];
  //   uint32_t fpsr;
  //   uint32_t fpcr;
  // };
  // typedef struct user_fpsimd_struct fpregset_t;
  // typedef fpregset_t elf_fpregset_t;
  elf_fpregset_t neon_regs;
#endif

  // clsmask helpers
  bool clsmask_regs = false;
#ifdef __HAVE_ARM_NEON__
  bool clsmask_neon = false;
#endif

  regctx_t(dynamic_register_set_t &_idaregs);
  bool init();
  bool load();
  bool store();
};

//--------------------------------------------------------------------------
regctx_t::regctx_t(dynamic_register_set_t &_idaregs)
  : regctx_base_t(_idaregs)
{
  memset(&regs, 0, sizeof(regs));
#ifdef __HAVE_ARM_NEON__
  memset(&neon_regs, 0, sizeof(neon_regs));
#endif

  idaregs.set_regclasses(arm_register_classes);
}

//--------------------------------------------------------------------------
bool regctx_t::init(void)
{
  if ( (clsmask & ARM_RC_ALL) == 0 )
    return false;
  // setup clsmask helpers
  clsmask_regs = (clsmask & ARM_RC_GENERAL) != 0;
#ifdef __HAVE_ARM_NEON__
  clsmask_neon = (clsmask & ARM_RC_NEON) != 0;
#endif
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::load(void)
{
  if ( !init() )
    return false;
  if ( clsmask_regs )
    if ( !qptrace_get_prstatus(&regs, tid) )
      return false;
#ifdef __HAVE_ARM_NEON__
  if ( clsmask_neon )
  {
    struct iovec iovec;
    iovec.iov_base = &neon_regs;
    iovec.iov_len = sizeof(neon_regs);
    if ( qptrace(PTRACE_GETREGSET, tid, (void *)NT_FPREGSET, &iovec) != 0 )
      return false;   // Unable to fetch FP/SIMD registers
  }
#endif
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::store(void)
{
  if ( clsmask_regs )
    if ( !qptrace_set_regset(NT_PRSTATUS, tid, &regs, sizeof(regs)) )
      return false;
#ifdef __HAVE_ARM_NEON__
  if ( clsmask_neon )
  {
    struct iovec iovec;
    iovec.iov_base = &neon_regs;
    iovec.iov_len = sizeof(neon_regs);
    if ( qptrace(PTRACE_SETREGSET, tid, (void *)NT_FPREGSET, &iovec) != 0 )
      return false; // Unable to store FP/SIMD registers
  }
#endif
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::init_reg_ctx(void)
{
  reg_ctx = new regctx_t(idaregs);

  // Populate register context
  reg_ctx->add_ival(arch_registers[R_R0], offset_size(regs, regs[0]));
  reg_ctx->add_ival(arch_registers[R_R1], offset_size(regs, regs[1]));
  reg_ctx->add_ival(arch_registers[R_R2], offset_size(regs, regs[2]));
  reg_ctx->add_ival(arch_registers[R_R3], offset_size(regs, regs[3]));
  reg_ctx->add_ival(arch_registers[R_R4], offset_size(regs, regs[4]));
  reg_ctx->add_ival(arch_registers[R_R5], offset_size(regs, regs[5]));
  reg_ctx->add_ival(arch_registers[R_R6], offset_size(regs, regs[6]));
  reg_ctx->add_ival(arch_registers[R_R7], offset_size(regs, regs[7]));
  reg_ctx->add_ival(arch_registers[R_R8], offset_size(regs, regs[8]));
  reg_ctx->add_ival(arch_registers[R_R9], offset_size(regs, regs[9]));
  reg_ctx->add_ival(arch_registers[R_R10], offset_size(regs, regs[10]));
  reg_ctx->add_ival(arch_registers[R_R11], offset_size(regs, regs[11]));
  reg_ctx->add_ival(arch_registers[R_R12], offset_size(regs, regs[12]));
  reg_ctx->add_ival(arch_registers[R_R13], offset_size(regs, regs[13]));
  reg_ctx->add_ival(arch_registers[R_R14], offset_size(regs, regs[14]));
  reg_ctx->add_ival(arch_registers[R_R15], offset_size(regs, regs[15]));
  reg_ctx->add_ival(arch_registers[R_R16], offset_size(regs, regs[16]));
  reg_ctx->add_ival(arch_registers[R_R17], offset_size(regs, regs[17]));
  reg_ctx->add_ival(arch_registers[R_R18], offset_size(regs, regs[18]));
  reg_ctx->add_ival(arch_registers[R_R19], offset_size(regs, regs[19]));
  reg_ctx->add_ival(arch_registers[R_R20], offset_size(regs, regs[20]));
  reg_ctx->add_ival(arch_registers[R_R21], offset_size(regs, regs[21]));
  reg_ctx->add_ival(arch_registers[R_R22], offset_size(regs, regs[22]));
  reg_ctx->add_ival(arch_registers[R_R23], offset_size(regs, regs[23]));
  reg_ctx->add_ival(arch_registers[R_R24], offset_size(regs, regs[24]));
  reg_ctx->add_ival(arch_registers[R_R25], offset_size(regs, regs[25]));
  reg_ctx->add_ival(arch_registers[R_R26], offset_size(regs, regs[26]));
  reg_ctx->add_ival(arch_registers[R_R27], offset_size(regs, regs[27]));
  reg_ctx->add_ival(arch_registers[R_R28], offset_size(regs, regs[28]));
  reg_ctx->add_ival(arch_registers[R_R29], offset_size(regs, regs[29]));
  lr_idx = reg_ctx->add_ival(arch_registers[R_LR], offset_size(regs, regs[30]));
  sp_idx = reg_ctx->add_ival(arch_registers[R_SP], offset_size(regs, sp));
  pc_idx = reg_ctx->add_ival(arch_registers[R_PC], offset_size(regs, pc));
  sr_idx = reg_ctx->add_ival(arch_registers[R_PSR], offset_size(regs, pstate)); // 32-bit
#ifdef __HAVE_ARM_NEON__
  size_t offset = qoffsetof2(neon_regs, vregs);
  for ( size_t i = R_V0; i <= R_V31; i++, offset += sizeof(__uint128_t) )
    reg_ctx->add_data(arch_registers[i], offset, sizeof(__uint128_t));
  reg_ctx->add_ival(arch_registers[R_FPSR], offset_size(neon_regs, fpsr));
  reg_ctx->add_ival(arch_registers[R_FPCR], offset_size(neon_regs, fpcr));
#endif
}

# else  // __ARM__ && __X86__

//--------------------------------------------------------------------------
// ARM (32-bit)
//--------------------------------------------------------------------------
struct regctx_t : public regctx_base_t
{
  struct user_regs_struct regs;
#ifdef __HAVE_ARM_VFP__
  struct user_vfp vfp_regs;
#endif

  // clsmask helpers
  bool clsmask_regs;
#ifdef __HAVE_ARM_VFP__
  bool clsmask_vfp;
#endif

  regctx_t(dynamic_register_set_t &_idaregs);
  virtual bool init() override;
  virtual bool load() override;
  virtual bool store() override;
};

//--------------------------------------------------------------------------
regctx_t::regctx_t(dynamic_register_set_t &_idaregs)
  : regctx_base_t(_idaregs)
{
  memset(&regs, 0, sizeof(regs));
#ifdef __HAVE_ARM_VFP__
  memset(&vfp_regs, 0, sizeof(vfp_regs));
#endif

  clsmask_regs = 0;
#ifdef __HAVE_ARM_VFP__
  clsmask_vfp = 0;
#endif

  idaregs.set_regclasses(arm_register_classes);
}

//--------------------------------------------------------------------------
bool regctx_t::init(void)
{
  if ( (clsmask & ARM_RC_ALL) == 0 )
    return false;
  // setup clsmask helpers
  clsmask_regs = (clsmask & ARM_RC_GENERAL) != 0;
#ifdef __HAVE_ARM_VFP__
  clsmask_vfp = (clsmask & ARM_RC_VFP) != 0;
#endif
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::load(void)
{
  if ( !init() )
    return false;
  if ( clsmask_regs )
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return false;
#ifdef __HAVE_ARM_VFP__
  if ( clsmask_vfp )
    if ( qptrace(PTRACE_GETVFPREGS, tid, 0, &vfp_regs) != 0 )
      return false;
#endif
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::store(void)
{
  if ( clsmask_regs )
    if ( qptrace(PTRACE_SETREGS, tid, 0, &regs) != 0 )
      return false;
#ifdef __HAVE_ARM_VFP__
  if ( clsmask_vfp )
    if ( qptrace(PTRACE_SETVFPREGS, tid, 0, &vfp_regs) != 0 )
      return false;
#endif
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::init_reg_ctx()
{
  reg_ctx = new regctx_t(idaregs);

  // Populate register context
  reg_ctx->add_ival(arch_registers[ARM_R32_R0], offset_size(regs, uregs[0]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R1], offset_size(regs, uregs[1]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R2], offset_size(regs, uregs[2]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R3], offset_size(regs, uregs[3]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R4], offset_size(regs, uregs[4]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R5], offset_size(regs, uregs[5]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R6], offset_size(regs, uregs[6]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R7], offset_size(regs, uregs[7]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R8], offset_size(regs, uregs[8]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R9], offset_size(regs, uregs[9]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R10], offset_size(regs, uregs[10]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R11], offset_size(regs, uregs[11]));
  reg_ctx->add_ival(arch_registers[ARM_R32_R12], offset_size(regs, uregs[12]));
  sp_idx = reg_ctx->add_ival(arch_registers[ARM_R32_SP], offset_size(regs, uregs[13]));
  lr_idx = reg_ctx->add_ival(arch_registers[ARM_R32_LR], offset_size(regs, uregs[14]));
  pc_idx = reg_ctx->add_ival(arch_registers[ARM_R32_PC], offset_size(regs, uregs[15]));
  sr_idx = reg_ctx->add_ival(arch_registers[ARM_R32_PSR], offset_size(regs, uregs[16]));

#ifdef __HAVE_ARM_VFP__
  size_t offset = qoffsetof2(vfp_regs, fpregs);
  for ( size_t i = ARM_R32_D0; i <= ARM_R32_D31; i++, offset += sizeof(int64) )
    reg_ctx->add_data(arch_registers[i], offset, sizeof(int64));
  reg_ctx->add_ival(arch_registers[ARM_R32_FPSCR], offset_size(vfp_regs, fpscr));
#endif
}

# endif
#else     // !__ARM__

//--------------------------------------------------------------------------
// X86/X64
//-------------------------------------------------------------------------

//--------------------------------------------------------------------------
//lint -esym(749,TAG_*) local enumeration constant '' not referenced
enum
{
  TAG_VALID = 0,
  TAG_ZERO = 1,
  TAG_SPECIAL = 2,
  TAG_EMPTY = 3,
};

//-------------------------------------------------------------------------
// Intel 64 and IA-32 Architectures Software Developer's Manual
// Volume 1: Basic Architecture
// 253665-070US May 2019

// 13.1 XSAVE-SUPPORTED FEATURES AND STATE-COMPONENT BITMAPS
// Bit 1 corresponds to the state component used for registers used by the
// streaming SIMD extensions (SSE state).
#define X86_XSTATE_SSE (1ULL << 1)
// Bit 2 corresponds to the state component used for the additional register
// state used by the Intel Advanced Vector Extensions (AVX state).
#define X86_XSTATE_AVX (1ULL << 2)

// 13.4 XSAVE AREA
// The legacy region of an XSAVE area comprises the 512 bytes starting at the
// area's base address. [...] The XSAVE feature set uses the legacy area for
// x87 state (state component 0) and SSE state (state component 1).
#define XSAVE_LEGACY_REGION_OFFSET 0
// The XSAVE header of an XSAVE area comprises the 64 bytes starting at
// offset 512 from the area's base address:
#define XSAVE_HEADER_OFFSET 512
// The extended region of an XSAVE area starts at an offset of 576 bytes from
// the area's base address.
#define XSAVE_EXTENDED_REGION_OFFSET 576

// 13.4.2 XSAVE Header
//  Bytes 7:0 of the XSAVE header is a state-component bitmap (see Section
//  13.1) called XSTATE_BV.
#define XSAVE_XSTATE_BV XSAVE_HEADER_OFFSET

// 13.5.2 SSE State
// Bytes 287:160 are used for the registers XMM0-XMM7.
// Bytes 415:288 are used for the registers XMM8-XMM15.
#define XSAVE_XMM_OFFSET_BASE (XSAVE_LEGACY_REGION_OFFSET + 160)

// 13.5.3 AVX State
// Bytes 127:0 of the AVX-state section are used for YMM0_H-YMM7_H.
// Bytes 255:128 are used for YMM8_H-YMM15_H.
#define XSAVE_YMMH_OFFSET_BASE XSAVE_EXTENDED_REGION_OFFSET

//--------------------------------------------------------------------------
struct regctx_t : public regctx_base_t
{
  struct user_regs_struct regs;
  struct user_fpregs_struct i387;
#ifdef __X86__
  struct user_fpxregs_struct x387;
#endif
  uint8_t xstate[X86_XSTATE_MAX_SIZE];
  struct iovec ymm_iov;

  // clsmask helpers
  bool clsmask_regs;
  bool clsmask_fpregs;
#ifdef __X86__
  bool clsmask_fpxregs;
#endif
  bool clsmask_ymm;

  regctx_t(dynamic_register_set_t &_idaregs);
  virtual bool init() override;
  virtual bool load() override;
  virtual bool store() override;
};

//--------------------------------------------------------------------------
regctx_t::regctx_t(dynamic_register_set_t &_idaregs)
  : regctx_base_t(_idaregs)
{
  memset(&regs, 0, sizeof(regs));
  memset(&i387, 0, sizeof(i387));
#ifdef __X86__
  memset(&x387, 0, sizeof(x387));
#endif
  memset(xstate, 0, sizeof(xstate));

  clsmask_regs = 0;
  clsmask_fpregs = 0;
#ifdef __X86__
  clsmask_fpxregs = 0;
#endif
  clsmask_ymm = 0;

  ymm_iov.iov_base = xstate;
  ymm_iov.iov_len = sizeof(xstate);

  idaregs.set_regclasses(x86_register_classes);
}

//--------------------------------------------------------------------------
bool regctx_t::init(void)
{
  if ( (clsmask & X86_RC_ALL) == 0 )
    return false;
  // setup clsmask helpers
  clsmask_regs = (clsmask & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0;
#ifdef __X86__
  // 32-bit version uses two different structures to return xmm & fpu
  clsmask_fpregs = (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0;
  clsmask_fpxregs = (clsmask & X86_RC_XMM) != 0;
#else
  // 64-bit version uses one struct to return xmm & fpu
  clsmask_fpregs = (clsmask & (X86_RC_FPU|X86_RC_MMX|X86_RC_XMM)) != 0;
#endif
  clsmask_ymm = (clsmask & X86_RC_YMM) != 0;
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::load(void)
{
  if ( !init() )
    return false;
  if ( clsmask_regs )
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return false;
  // Note: On linux kernels older than 4.8, the ptrace call to fetch
  //       registers from xstate did not sanitize the state before
  //       copying data to user-space. If only the YMM register class
  //       was requested (and not fp or fpx), this could lead to IDA
  //       having stale data on the lower half of the YMM registers.
  //       The ptrace calls to fetch fp or fpx registers do sanitize
  //       the state. This is the only reason we may also get the fp
  //       registers when the YMM register class is requested, but
  //       the fp and fpx registers were not requested. The order is
  //       important in this case (first fp or fpx, then xstate).
#ifdef __X86__
  bool xstate_sanitized = clsmask_fpregs || clsmask_fpxregs;
#else
  bool xstate_sanitized = clsmask_fpregs;
#endif
  if ( clsmask_fpregs || (clsmask_ymm && !xstate_sanitized) )
    if ( qptrace(PTRACE_GETFPREGS, tid, 0, &i387) != 0 )
      return false;
#ifdef __X86__
  if ( clsmask_fpxregs )
    if ( qptrace(PTRACE_GETFPXREGS, tid, 0, &x387) != 0 )
      return false;
#endif
  if ( clsmask_ymm )
    if ( !qptrace_get_regset(&ymm_iov, NT_X86_XSTATE, tid) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
bool regctx_t::store(void)
{
  if ( clsmask_regs )
    if ( qptrace(PTRACE_SETREGS, tid, 0, &regs) != 0 )
      return false;
  // The order of the following calls is VERY IMPORTANT so as
  // PTRACE_SETFPXREGS can spoil FPU registers.
  // The subsequent call to PTRACE_SETFPREGS will correct them.
  // Could it be better to get rid of PTRACE_SETFPREGS and use
  // PTRACE_SETFPXREGS for both FPU and XMM registers instead?
  if ( clsmask_ymm )
    if ( !qptrace_set_regset(NT_X86_XSTATE, tid, ymm_iov) )
      return false;
#ifdef __X86__
  if ( clsmask_fpxregs )
    if ( qptrace(PTRACE_SETFPXREGS, tid, 0, &x387) != 0 )
      return false;
#endif
  if ( clsmask_fpregs )
    if ( qptrace(PTRACE_SETFPREGS, tid, 0, &i387) != 0 )
      return false;
  return true;
}

//--------------------------------------------------------------------------
static void ftag_read(const regctx_t *ctx, regval_t *value, void * /*user_data*/)
{
  uint32_t ival = ctx->i387.TAGS_REG;
#ifndef __X86__
  // fix 'ftag':
  // ---
  // Byte 4 is used for an abridged version of the x87 FPU Tag
  // Word (FTW). The following items describe its usage:
  // - For each j, 0 <= j <= 7, FXSAVE saves a 0 into bit j of
  //   byte 4 if x87 FPU data register STj has a empty tag;
  //   otherwise, FXSAVE saves a 1 into bit j of byte 4.
  // (...)
  // ---
  // See also the opposite conversion when writing registers
  // (look for 'abridged'.)
  uint8_t abridged = ival;
  int top = (ctx->i387.swd >> 11) & 0x7;
  uint16_t ftag = 0;
  for ( int st_idx = 7; st_idx >= 0; --st_idx )
  {
    uint16_t tag = TAG_EMPTY;
    if ( (abridged & (1 << st_idx)) != 0 )
    {
      int actual_st = (st_idx + 8 - top) % 8;
      const uint8_t *p = ((const uint8_t *) ctx->i387.st_space) + actual_st * (sizeof(ctx->i387.st_space)/8); //-V706 Suspicious division
      bool integer = (p[7] & 0x80) != 0;
      uint32 exp = ((p[9] & 0x7f) << 8) | p[8];   //-V557 Array overrun is possible
      uint32 frac0 = ((p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);
      uint32 frac1 = (((p[7] & 0x7f) << 24) | (p[6] << 16) | (p[5] << 8) | p[4]);
      if ( exp == 0x7fff )
        tag = TAG_SPECIAL;
      else if ( exp == 0 )
        tag = (frac0 == 0 && frac1 == 0 && !integer) ? TAG_ZERO : TAG_SPECIAL;
      else
        tag = integer ? TAG_VALID : TAG_SPECIAL;
    }
    ftag |= tag << (2 * st_idx);
  }
  ival = ftag;
#endif
  value->ival = ival;
}

//--------------------------------------------------------------------------
static void ftag_write(regctx_t *ctx, const regval_t *value, void * /*user_data*/)
{
#ifndef __X86__
  // => abridged
  // See also the opposite conversion when reading registers
  // (look for 'abridged'.)
  //
  // NOTE: This assumes that i387.swd _IS UP-TO-DATE_.
  // If it has to be overwritten later in the same batch of
  // updates, its new value won't be used here.
  uint16_t expanded = value->ival;
  uint8_t tags = 0;
  int top = (ctx->i387.swd >> 11) & 0x7;
  for ( int st_idx = 7; st_idx >= 0; --st_idx )
    if ( ((expanded >> (2 * st_idx)) & 3) != TAG_EMPTY )
      tags |= uint8_t(1 << ((st_idx + 8 - top) % 8));
  ctx->i387.TAGS_REG = tags;
#else
  ctx->i387.TAGS_REG = value->ival;
#endif
}

//--------------------------------------------------------------------------
static void ymm_read(const regctx_t *ctx, regval_t *value, void *user_data)
{
  size_t ymm_reg_idx = size_t(user_data);
  const uint128 *ptrl = (uint128 *) &ctx->xstate[XSAVE_XMM_OFFSET_BASE];
  const uint128 *ptrh = (uint128 *) &ctx->xstate[XSAVE_YMMH_OFFSET_BASE];
  uint8_t ymm[32];
  *(uint128 *) &ymm[ 0] = ptrl[ymm_reg_idx];
  *(uint128 *) &ymm[16] = ptrh[ymm_reg_idx];
  value->set_bytes(ymm, sizeof(ymm));
}

//--------------------------------------------------------------------------
static void ymm_write(regctx_t *ctx, const regval_t *value, void *user_data)
{
  size_t ymm_reg_idx = size_t(user_data);
  const uint8_t *ymm = (const uint8_t *) value->get_data();
  uint128 *ptrl = (uint128 *) &ctx->xstate[XSAVE_XMM_OFFSET_BASE];
  uint128 *ptrh = (uint128 *) &ctx->xstate[XSAVE_YMMH_OFFSET_BASE];
  ptrl[ymm_reg_idx] = *(uint128 *) &ymm[ 0];
  ptrh[ymm_reg_idx] = *(uint128 *) &ymm[16];
  ctx->xstate[XSAVE_XSTATE_BV] |= X86_XSTATE_SSE | X86_XSTATE_AVX;
}

//--------------------------------------------------------------------------
void linux_debmod_t::init_reg_ctx()
{
  reg_ctx = new regctx_t(idaregs);

  // Populate register context
  // order of registers corresponds to register_x86_t / register_x86_x86_t
  size_t offset = 0;

  offset = qoffsetof2(i387, st_space);
  for ( size_t i = R_ST0; i <= R_ST7; i++, offset += sizeof(regctx_t::i387.st_space)/8 ) //-V706 Suspicious division
    reg_ctx->add_fval(arch_registers[i], offset, 10);
  reg_ctx->add_ival(arch_registers[R_CTRL], offset_size(i387, cwd));
  reg_ctx->add_ival(arch_registers[R_STAT], offset_size(i387, swd));
  reg_ctx->add_func(arch_registers[R_TAGS], ftag_read, ftag_write);

  cs_idx = reg_ctx->add_ival(arch_registers[R_CS], offset_size(regs, INTEL_SREG(cs)));
  ds_idx = reg_ctx->add_ival(arch_registers[R_DS], offset_size(regs, INTEL_SREG(ds)));
  es_idx = reg_ctx->add_ival(arch_registers[R_ES], offset_size(regs, INTEL_SREG(es)));
  fs_idx = reg_ctx->add_ival(arch_registers[R_FS], offset_size(regs, INTEL_SREG(fs)));
  gs_idx = reg_ctx->add_ival(arch_registers[R_GS], offset_size(regs, INTEL_SREG(gs)));
  ss_idx = reg_ctx->add_ival(arch_registers[R_SS], offset_size(regs, INTEL_SREG(ss)));

#ifdef __EA64__
  bool is_64 = is_64bit_app();
  if ( is_64 )
  {
    reg_ctx->add_ival(r_rax, offset_size(regs, INTEL_REG(ax)));
    reg_ctx->add_ival(r_rbx, offset_size(regs, INTEL_REG(bx)));
    reg_ctx->add_ival(r_rcx, offset_size(regs, INTEL_REG(cx)));
    reg_ctx->add_ival(r_rdx, offset_size(regs, INTEL_REG(dx)));
    reg_ctx->add_ival(r_rsi, offset_size(regs, INTEL_REG(si)));
    reg_ctx->add_ival(r_rdi, offset_size(regs, INTEL_REG(di)));
    reg_ctx->add_ival(r_rbp, offset_size(regs, INTEL_REG(bp)));
    sp_idx = reg_ctx->add_ival(r_rsp, offset_size(regs, INTEL_REG(sp)));
    pc_idx = reg_ctx->add_ival(r_rip, offset_size(regs, INTEL_REG(ip)));
    reg_ctx->add_ival(r_r8, offset_size(regs, r8));
    reg_ctx->add_ival(r_r9, offset_size(regs, r9));
    reg_ctx->add_ival(r_r10, offset_size(regs, r10));
    reg_ctx->add_ival(r_r11, offset_size(regs, r11));
    reg_ctx->add_ival(r_r12, offset_size(regs, r12));
    reg_ctx->add_ival(r_r13, offset_size(regs, r13));
    reg_ctx->add_ival(r_r14, offset_size(regs, r14));
    reg_ctx->add_ival(r_r15, offset_size(regs, r15));
  }
  else
#endif
  {
    reg_ctx->add_ival(r_eax, offset_size(regs, INTEL_REG(ax)));
    reg_ctx->add_ival(r_ebx, offset_size(regs, INTEL_REG(bx)));
    reg_ctx->add_ival(r_ecx, offset_size(regs, INTEL_REG(cx)));
    reg_ctx->add_ival(r_edx, offset_size(regs, INTEL_REG(dx)));
    reg_ctx->add_ival(r_esi, offset_size(regs, INTEL_REG(si)));
    reg_ctx->add_ival(r_edi, offset_size(regs, INTEL_REG(di)));
    reg_ctx->add_ival(r_ebp, offset_size(regs, INTEL_REG(bp)));
    sp_idx = reg_ctx->add_ival(r_esp, offset_size(regs, INTEL_REG(sp)));
    pc_idx = reg_ctx->add_ival(r_eip, offset_size(regs, INTEL_REG(ip)));
  }
  sr_idx = reg_ctx->add_ival(arch_registers[R_EFLAGS], offset_size(regs, eflags));

  offset = qoffsetof2(XMM_STRUCT, xmm_space);
  for ( size_t i = R_XMM0; i <= R_LAST_XMM; i++, offset += 16 )
  {
#ifdef __EA64__
    if ( !is_64 && i >= R_XMM8 )
      break;
#endif
    reg_ctx->add_data(arch_registers[i], offset, 16);
  }
  reg_ctx->add_ival(arch_registers[R_MXCSR], offset_size(XMM_STRUCT, mxcsr));

  offset = qoffsetof2(i387, st_space);
  for ( size_t i = R_MMX0; i <= R_MMX7; i++, offset += sizeof(regctx_t::i387.st_space)/8 ) //-V706 Suspicious division
    reg_ctx->add_data(arch_registers[i], offset, 8);

  for ( size_t i = R_YMM0; i <= R_LAST_YMM; i++ )
  {
#ifdef __EA64__
    if ( !is_64 && i >= R_YMM8 )
      break;
#endif
    reg_ctx->add_func(arch_registers[i], ymm_read, ymm_write, (void *) (i - R_YMM0));
  }
}
#endif // !__ARM__

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_read_registers(
        thid_t tid,
        int clsmask,
        regval_t *values,
        qstring * /*errbuf*/)
{
  if ( values == nullptr )
    return DRC_FAILED;

  reg_ctx->setup(tid, clsmask);
  if ( !reg_ctx->load() )
    return DRC_FAILED;

  reg_ctx->read_all(values);
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_write_register(
        thid_t tid,
        int reg_idx,
        const regval_t *value,
        qstring * /*errbuf*/)
{
  if ( value == nullptr )
    return DRC_FAILED;

  reg_ctx->setup(tid);
  reg_ctx->setup_reg(reg_idx);
  if ( !reg_ctx->load() )
    return DRC_FAILED;

  if ( reg_idx == pc_idx )
    ldeb("NEW EIP: %08" FMT_64 "X\n", value->ival);

  if ( !reg_ctx->patch(reg_idx, value) )
    return DRC_FAILED;

  if ( !reg_ctx->store() )
    return DRC_FAILED;

  return DRC_OK;
}

//--------------------------------------------------------------------------
bool idaapi linux_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values)
{
  if ( values == nullptr )
    return false;

  reg_ctx->setup(tid);
  for ( size_t i = 0; i < count; i++ )
    reg_ctx->setup_reg(start + i);
  if ( !reg_ctx->load() )
    return false;

  for ( size_t i = 0; i < count; i++, values++ )
    if ( !reg_ctx->patch(start + i, values) )
      return false;

  if ( !reg_ctx->store() )
    return false;

  return true;
}

//--------------------------------------------------------------------------
// find DT_SONAME of a elf image directly from the memory
bool linux_debmod_t::get_soname(const char *fname, qstring *soname) const
{
  struct dll_soname_finder_t : public symbol_visitor_t
  {
    qstring *soname;
    dll_soname_finder_t(qstring *res) : symbol_visitor_t(VISIT_DYNINFO), soname(res) {}
    virtual int visit_dyninfo(uint64 tag, const char *name, uint64 /*value*/) override
    {
      if ( tag == DT_SONAME )
      {
        *soname = name;
        return 1;
      }
      return 0;
    }
  };

  dll_soname_finder_t dsf(soname);
  return load_elf_symbols(fname, dsf) == 1;
}

//--------------------------------------------------------------------------
asize_t linux_debmod_t::calc_module_size(const meminfo_vec_t &miv, const memory_info_t *mi) const
{
  QASSERT(30067, miv.begin() <= mi && mi < miv.end());
  ea_t start = mi->start_ea;
  ea_t end   = mi->end_ea;
  if ( end == 0 )
    return 0; // unknown size
  const qstring &name = mi->name;
  while ( ++mi != miv.end() )
  {
    if ( name != mi->name )
      break;
    end = mi->end_ea;
  }
  QASSERT(30068, end > start);
  return end - start;
}

//--------------------------------------------------------------------------
// may add/del threads!
void linux_debmod_t::handle_dll_movements(const meminfo_vec_t &_miv)
{
  ldeb("handle_dll_movements\n");

  // first, merge memory ranges by module
  meminfo_vec_t miv;
  for ( size_t i = 0, n = _miv.size(); i < n; ++i )
  {
    const memory_info_t &src = _miv[i];

    // See if we already registered a module with that name.
    memory_info_t *target = find_first_mapping(miv, src.name.c_str());
    if ( target != nullptr )
    {
      // Found one. Let's make sure it contains our addresses.
      target->extend(src.start_ea);
      target->extend(src.end_ea);
    }
    else
    {
      miv.push_back(src);
    }
  }

  // unload missing dlls
  images_t::iterator p;
  for ( p=dlls.begin(); p != dlls.end(); )
  {
    image_info_t &ii = p->second;
    const char *fname = ii.fname.c_str();
    if ( find_first_mapping(miv, fname) == nullptr )
    {
      if ( !del_pending_event(LIB_LOADED, fname) )
      {
        debug_event_t ev;
        ev.set_info(LIB_UNLOADED) = fname;
        ev.pid     = process_handle;
        ev.tid     = process_handle;
        ev.ea      = BADADDR;
        ev.handled = true;
        enqueue_event(ev, IN_FRONT);
      }
      p = dlls.erase(p);
    }
    else
    {
      ++p;
    }
  }

  // load new dlls
  int n = miv.size();
  for ( int i=0; i < n; i++ )
  {
    // ignore unnamed dlls
    if ( miv[i].name.empty() )
      continue;

    // ignore the input file
    if ( !is_dll && miv[i].name == input_file_path )
      continue;

    // ignore if dll already exists
    ea_t base = miv[i].start_ea;
    p = dlls.find(base);
    if ( p != dlls.end() )
      continue;

    // ignore memory chunks which do not correspond to an ELF header
    char magic[4];
    if ( _read_memory(-1, base, magic, 4, false) != 4 )
      continue;

    if ( memcmp(magic, "\x7F\x45\x4C\x46", 4) != 0 )
      continue;

    qstring soname;
    const char *modname = miv[i].name.c_str();
    get_soname(modname, &soname);
    asize_t size = calc_module_size(miv, &miv[i]);
    add_dll(base, size, modname, soname.c_str());
  }
  activate_multithreading();
}

//--------------------------------------------------------------------------
// this function has a side effect: it sets debapp_attrs.addrsize to 8
// if founds a 64-bit address in the mapfile
bool linux_debmod_t::read_mapping(mapfp_entry_t *me)
{
  qstring line;
  if ( qgetline(&line, mapfp) <= 0 )
    return false;

  me->ea1 = BADADDR;
  me->bitness = 0;
  int len = 0;
  me->perm[7] = '\0';
  me->device[7] = '\0';
  CASSERT(sizeof(me->perm) == 8);
  CASSERT(sizeof(me->device) == 8);
  int code = qsscanf(line.begin(), "%a-%a %7s %a %7s %" FMT_64 "x%n",
                     &me->ea1, &me->ea2, me->perm,
                     &me->offset, me->device, &me->inode, &len);
  if ( code == 6 )
  {
    me->bitness = 1;
    size_t pos = line.find('-');
    if ( pos != qstring::npos && pos > 8 )
    {
      me->bitness = 2;
      set_addr_size(8);
    }
    char *ptr = line.begin() + len;
    ptr = skip_spaces(ptr);
    // remove trailing spaces and eventual (deleted) suffix
    static const char delsuff[] = " (deleted)";
    const int suflen = sizeof(delsuff) - 1;
    char *end = tail(ptr);
    while ( end > ptr && qisspace(end[-1]) )
      *--end = '\0';
    if ( end-ptr > suflen && strncmp(end-suflen, delsuff, suflen) == 0 )
      end[-suflen] = '\0';
    me->fname = ptr;
  }
  return me->ea1 != BADADDR;
}

//--------------------------------------------------------------------------
drc_t linux_debmod_t::get_memory_info(meminfo_vec_t &miv, bool suspend)
{
  ldeb("get_memory_info(suspend=%d)\n", suspend);
  if ( exited || mapfp == nullptr )
    return DRC_NOPROC;
  if ( suspend )
    suspend_all_threads();

  rewind(mapfp);
  mapfp_entry_t me;
  qstrvec_t possible_interp;
  int bitness = 1;
  while ( read_mapping(&me) )
  {
    // skip empty ranges
    if ( me.empty() )
      continue;

    if ( interp.empty() && !me.fname.empty() && !possible_interp.has(me.fname) )
    {
      // check for [.../]ld-XXX.so"
      size_t pos = me.fname.find("ld-");
      if ( pos != qstring::npos && (pos == 0 || me.fname[pos-1] == '/') )
        possible_interp.push_back(me.fname);
    }

    // for some reason linux lists some ranges twice
    // ignore them
    int i;
    for ( i=0; i < miv.size(); i++ )
      if ( miv[i].start_ea == me.ea1 )
        break;
    if ( i != miv.size() )
      continue;

    memory_info_t &mi = miv.push_back();
    mi.start_ea = me.ea1;
    mi.end_ea   = me.ea2;
    mi.name.swap(me.fname);
#ifdef __ANDROID__
    // android reports simple library names without path. try to find it.
    make_android_abspath(&mi.name);
#endif
    mi.bitness = me.bitness;
    //msg("%s: %a..%a. Bitness: %d\n", mi.name.c_str(), mi.start_ea, mi.end_ea, mi.bitness);

    if ( bitness < mi.bitness )
      bitness = mi.bitness;

    if ( strchr(me.perm, 'r') != nullptr )
      mi.perm |= SEGPERM_READ;
    if ( strchr(me.perm, 'w') != nullptr )
      mi.perm |= SEGPERM_WRITE;
    if ( strchr(me.perm, 'x') != nullptr )
      mi.perm |= SEGPERM_EXEC;
  }

  if ( !possible_interp.empty() )
  {
    bool ok = false;

    for ( size_t i = 0; i < possible_interp.size(); ++i )
    {
      interp = possible_interp[i];
      debdeb("trying potential interpreter %s\n", interp.c_str());
      if ( add_shlib_bpt(miv, true) )
      {
        ok = true;
        dmsg("Found a valid interpeter in %s, will report shared library events!\n", interp.c_str());
        handle_dll_movements(miv);
      }
    }

    if ( !ok )
      interp.qclear();
  }

  // During the parsing of each memory segment we had just guessed the bitness.
  // So fix now bitness of all memory segments
  for ( int i = 0; i < miv.size(); i++ )
    miv[i].bitness = bitness;

  if ( suspend )
    resume_all_threads();
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_get_memory_info(meminfo_vec_t &ranges, qstring * /*errbuf*/)
{
  drc_t drc = get_memory_info(ranges, false);
  if ( drc == DRC_OK )
  {
    if ( same_as_oldmemcfg(ranges) )
      drc = DRC_NOCHG;
    else
      save_oldmemcfg(ranges);
  }
  return drc;
}

#ifdef HAVE_UPDATE_CALL_STACK
// define for libunwind include: remote is for unwinding another process
#define UNW_REMOTE_ONLY
#include <libunwind-ptrace.h>

// Prototypes of functions we use from libunwind.so.8:
typedef int unw_init_remote_t(unw_cursor_t *, unw_addr_space_t, void *);
typedef int unw_step_t(unw_cursor_t *);
typedef int unw_get_reg_t(unw_cursor_t *, int, unw_word_t *);
typedef unw_addr_space_t unw_create_addr_space_t(unw_accessors_t *, int);
typedef void unw_destroy_addr_space_t(unw_addr_space_t as);

// Prototypes of functions we use from libunwind-ptrace.so.0:
typedef void *_UPT_create_t(thid_t);
typedef void *_UPT_destroy_t(void *);

//-------------------------------------------------------------------------
//-V:libunwind_access_t:730 not all members of a class are initialized inside the constructor
struct libunwind_access_t
{
  void *libx86_64; // lib unwind ptr
  void *libptrace; // liwbunwind-ptrace ptr
  void *context;

// Pointers to imported functions libunwind-x86_64.so
  unw_init_remote_t *p_unw_init_remote;
  unw_step_t *p_unw_step;
  unw_get_reg_t *p_unw_get_reg;
  unw_create_addr_space_t *p_unw_create_addr_space;
  unw_destroy_addr_space_t *p_unw_destroy_addr_space;
// Pointers to imported functions:
  _UPT_create_t *p_ptrace_create;
  _UPT_destroy_t *p_ptrace_destroy;
  unw_accessors_t *p_ptrace_accessor;
// address space for libunwind
  //lint -e1401 member 'as' not initialized by constructor
  unw_addr_space_t as;

  struct symbol_resolve_info_t
  {
    const char *name;
    void **ptr;
  };

  symbol_resolve_info_t unwsyms[5] =
  {
    { "_Ux86_64_init_remote",        (void**)&p_unw_init_remote        },
    { "_Ux86_64_step",               (void**)&p_unw_step               },
    { "_Ux86_64_get_reg",            (void**)&p_unw_get_reg            },
    { "_Ux86_64_create_addr_space",  (void**)&p_unw_create_addr_space  },
    { "_Ux86_64_destroy_addr_space", (void**)&p_unw_destroy_addr_space }
  };

  symbol_resolve_info_t ptracesyms[3] =
  {
    { "_UPT_create",                 (void**)&p_ptrace_create          },
    { "_UPT_destroy",                (void**)&p_ptrace_destroy         },
    { "_UPT_accessors",              (void**)&p_ptrace_accessor        }
  };

  enum load_libunwind_status_t
  {
    UNW_LOADED      = 1,  // libunwind is loaded and address space created
    UNW_UKNOWN      = 0,  // libuniwnd is not yet initiliazes
    UNW_NOT_ALLOWED = -1, // libunwind is not allowed by env variable
  };

  load_libunwind_status_t unw_status;

  libunwind_access_t() : libx86_64(nullptr),
                         libptrace(nullptr),
                         context(nullptr),
                         p_unw_init_remote(nullptr),
                         p_unw_step(nullptr),
                         p_unw_get_reg(nullptr),
                         p_unw_create_addr_space(nullptr),
                         p_unw_destroy_addr_space(nullptr),
                         p_ptrace_create(nullptr),
                         p_ptrace_destroy(nullptr),
                         p_ptrace_accessor(nullptr),
                         unw_status(UNW_UKNOWN) {}

  ~libunwind_access_t();
  bool load_library_pair(qstring *out, const libunwind_pair_name_t &pair, const char *path);
  void init(qstring *out, const char *path, thid_t tid);
  bool load_lib_so(
        void** lib,
        const symbol_resolve_info_t symbol_table[],
        int sym_table_length,
        const char *libname) const;
  void close_lib(
        void** lib,
        const symbol_resolve_info_t symbol_table[],
        int sym_table_length) const;
};

static libunwind_access_t *p_libaccess = nullptr;

//-------------------------------------------------------------------------
//lint -esym(1540,libunwind_access_t::*) not deallocated nor zeroed by destructor
libunwind_access_t::~libunwind_access_t()
{
  if ( unw_status == UNW_LOADED )
  {
    if ( context != nullptr )
      p_ptrace_destroy(context);
    p_unw_destroy_addr_space(as);
    close_lib(&libptrace, ptracesyms, qnumber(ptracesyms));
    close_lib(&libx86_64, unwsyms, qnumber(unwsyms));
  }
  unw_status = UNW_UKNOWN;
}

//-------------------------------------------------------------------------
static void append_load_failure(qstring *out, const qstring &path)
{
  out->append("libunwind: failed to load ");
  out->append(path);
  out->append(".\n");
}

//-------------------------------------------------------------------------
bool libunwind_access_t::load_library_pair(qstring *out, const libunwind_pair_name_t &pair, const char *path)
{
  qstring buf;
  bool isabspath = qisabspath(path);
  char dirname[QMAXPATH];
  if ( isabspath && qdirname(dirname, sizeof(dirname), path) )
  {
    buf = dirname;
    buf.append("/");
  }
  buf.append(pair.libx86_64_name);
  if ( !load_lib_so(&libx86_64, unwsyms, qnumber(unwsyms), buf.c_str()) )
  {
    append_load_failure(out, buf);
    return false;
  }
  buf.clear();
  if ( isabspath )
  {
    buf = dirname;
    buf.append("/");
  }
  buf.append(pair.libptrace_name);
  if ( !load_lib_so(&libptrace, ptracesyms, qnumber(ptracesyms), buf.c_str()) )
  {
    append_load_failure(out, buf);
    close_lib(&libx86_64, unwsyms, qnumber(unwsyms));
    return false;
  }
  if ( dlinfo(libx86_64, RTLD_DI_ORIGIN, dirname) == 0 )
  {
    out->append("libunwind: sucessfully loaded ");
    out->append(dirname);
    out->append("/");
    out->append(pair.libx86_64_name);
    out->append(" and ");
    out->append(dirname);
    out->append("/");
    out->append(pair.libptrace_name);
    out->append(".");
  }
  return true;
}

//-------------------------------------------------------------------------
void libunwind_access_t::init(qstring *out, const char *path, thid_t tid)
{
  out->clear();
  if ( unw_status != UNW_UKNOWN )
    return;
  if ( path[0] == '\0' )
  {
    out->append("libunwind: no valid path provided.");
    unw_status = UNW_NOT_ALLOWED;
    return;
  }

  for ( int i = 0; i < qnumber(libunwind_pair_name); i++ )
  {
    if ( streq(libunwind_pair_name[i].libx86_64_name, qbasename(path)) )
    {
      if ( !load_library_pair(out, libunwind_pair_name[i], path) )
      {
        unw_status = UNW_NOT_ALLOWED;
        return;
      }
      break;
    }
  }
  as = p_unw_create_addr_space(p_ptrace_accessor, 0);
  context = p_ptrace_create(tid);
  unw_status = UNW_LOADED;
}

//-------------------------------------------------------------------------
void libunwind_access_t::close_lib(
        void** lib,
        const symbol_resolve_info_t symbol_table[],
        int sym_table_length) const
{
  for ( int i=0; i < sym_table_length; i++ )
    *symbol_table[i].ptr = nullptr;
  if ( *lib != nullptr )
    dlclose(*lib);
  *lib = nullptr;
}

//-------------------------------------------------------------------------
bool libunwind_access_t::load_lib_so(
        void** lib,
        const symbol_resolve_info_t symbol_table[],
        int sym_table_length,
        const char *libname) const
{
  if ( *lib == nullptr )
  {
    *lib = dlopen(libname, RTLD_NOW|RTLD_GLOBAL);
    if ( *lib == nullptr )
    {
      ldeb("dlopen(%s) failed: %s\n", libname, dlerror());
      return false;
    }
    for ( int i=0; i < sym_table_length; i++ )
    {
      *symbol_table[i].ptr = dlsym(*lib, symbol_table[i].name); //-V595 The 'symbol_table[i].ptr' pointer was utilized before it was verified against nullptr
      if ( symbol_table[i].ptr == nullptr )
      {
        ldeb("dlsym(%s.%s) failed: %s\n", libname, symbol_table[i].name, dlerror());
        close_lib(lib, symbol_table, sym_table_length);
        *lib = nullptr;
        return false;
      }
    }
  }
  return true;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_update_call_stack(thid_t tid, call_stack_t * trace)
{
  // it is possible to analyse 32 bits binaries with debugger 64 bits. We cannot
  // use libunwind for this case as we only use the 64 bits version of libunwind.
  if ( !is_64bit_app() )
    return DRC_FAILED;
  if ( libunwind_path.empty() )
    return DRC_FAILED;
  if ( p_libaccess == nullptr )
    p_libaccess = new libunwind_access_t;
  qstring out;
  if ( p_libaccess->unw_status == libunwind_access_t::UNW_UKNOWN )
    p_libaccess->init(&out, libunwind_path.c_str(), tid);
  dmsg("%s\n", out.c_str());
  if ( p_libaccess->unw_status == libunwind_access_t::UNW_NOT_ALLOWED )
  {
    delete p_libaccess;
    p_libaccess = nullptr;
    return DRC_FAILED;
  }

  unw_cursor_t cursor;
  if ( p_libaccess->p_unw_init_remote(&cursor, p_libaccess->as, p_libaccess->context) != 0 )
  {
    dmsg("libunwind: failed to initialize remote context\n");
    delete p_libaccess;
    p_libaccess = nullptr;
    return DRC_FAILED;
  }

  do
  {
    unw_word_t rip;
    if ( p_libaccess->p_unw_get_reg(&cursor, UNW_REG_IP, &rip) )
    {
      dmsg("libunwind: failed to retrieve stack trace\n");
      delete p_libaccess;
      p_libaccess = nullptr;
      return DRC_FAILED;
    }
    call_stack_info_t si;
    si.callea = rip;
    // TODO : determine how to have frame pointer.
    si.fp = BADADDR;
    si.funcea = BADADDR;
    trace->push_back(si);
  }
  while ( p_libaccess->p_unw_step(&cursor) > 0 );
  return DRC_OK;
}
#endif // HAVE_UPDATE_CALL_STACK

//--------------------------------------------------------------------------
linux_debmod_t::~linux_debmod_t()
{
  mapfp = nullptr;
  ta = nullptr;
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
drc_t idaapi linux_debmod_t::dbg_init(uint32_t *flags2, qstring * /*errbuf*/)
{
  dbg_term(); // initialize various variables
  if ( flags2 != nullptr )
    *flags2 = DBG_HAS_GET_PROCESSES | DBG_HAS_DETACH_PROCESS;
  return DRC_OK;
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_term(void)
{
#ifdef HAVE_UPDATE_CALL_STACK
  if ( p_libaccess != nullptr )
    delete p_libaccess;
  p_libaccess = nullptr;
#endif
  cleanup();
  cleanup_hwbpts();
}

//--------------------------------------------------------------------------
//lint -save -esym(818,pea) could be pointer to const
bool idaapi linux_debmod_t::thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea) const
{
#if !defined(__ARM__) && !defined(__X86__)

  /* The following definitions come from prctl.h, but may be absent
     for certain configurations.  */
  #ifndef ARCH_GET_FS
  #define ARCH_SET_GS 0x1001
  #define ARCH_SET_FS 0x1002
  #define ARCH_GET_FS 0x1003
  #define ARCH_GET_GS 0x1004
  #endif

  if ( reg_idx == fs_idx )
  {
    if ( qptrace(PTRACE_ARCH_PRCTL, tid, pea, (void *) ARCH_GET_FS) == 0 )
      return true;
  }
  else if ( reg_idx == gs_idx )
  {
    if ( qptrace(PTRACE_ARCH_PRCTL, tid, pea, (void *) ARCH_GET_GS) == 0 )
      return true;
  }
  else if ( reg_idx == cs_idx
         || reg_idx == ds_idx
         || reg_idx == es_idx
         || reg_idx == ss_idx )
  {
    *pea = 0;
    return true;
  }
  return false;
#else
  qnotused(tid);
  qnotused(reg_idx);
  qnotused(pea);
  return false;
#endif
} //lint -restore

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::handle_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void ** /*poutbuf*/,
        ssize_t * /*poutsize*/)
{
#ifdef HAVE_UPDATE_CALL_STACK
  if ( fn == LINUX_IOCTL_LIBUNWIND_PATH )
  {
    memory_deserializer_t mmdsr(buf, size);
    char *path = mmdsr.unpack_ds();
    libunwind_path.clear();
    libunwind_path.append(path);
    return 1;
  }
#else
  qnotused(fn);
  qnotused(buf);
  qnotused(size);
#endif // HAVE_UPDATE_CALL_STACK
  return 0;
}

//--------------------------------------------------------------------------
// recovering from a broken session consists in the following steps:
//
//  1 - Cleanup dlls previously recorded.
//  2 - Do like if we were attaching (calling handle_process_start(attaching=>AMT_ATTACH_BROKEN))
//  3 - Generate library events.
//  4 - Restore RIP/EIP if we stopped in a breakpoint.
//
bool idaapi linux_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(_pid);
  bool ret = in_event = false;

  // cleanup previously recorded information
  dlls.clear();

  // restore broken breakpoints and continue like a normal attach
  if ( restore_broken_breakpoints() && handle_process_start(_pid, AMT_ATTACH_BROKEN) )
  {
    // generate all library events
    gen_library_events(_pid);

    // fix instruction pointer in case we're at a breakpoint
    if ( !fix_instruction_pointer() )
      dmsg("Debugger failed to correctly restore the instruction pointer after recovering from a broken connection.\n");

    // and finally pause the process
    ret = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
// if the process was stopped at a breakpoint and then the connections goes
// down, when re-attaching the process we may be at EIP+1 (Intel procs) so
// we need to change EIP to EIP-1
bool linux_debmod_t::fix_instruction_pointer(void) const
{
  bool ret = true;
#if !defined(__ARM__)
  if ( last_event.eid() == BREAKPOINT )
  {
    ret = false;
    struct user_regs_struct regs;
    if ( qptrace(PTRACE_GETREGS, last_event.tid, 0, &regs) == 0 )
    {
      if ( last_event.ea == regs.PCREG-1 )
        regs.PCREG--;

      ret = qptrace(PTRACE_SETREGS, last_event.tid, 0, &regs) == 0;
    }
  }
#endif
  return ret;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
  qatexit(kill_all_processes);
  linux_debmod_t::reuse_broken_connections = true;
  return true;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  del_qatexit(kill_all_processes);
  term_multithreading();
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session(void *params)
{
#ifdef TESTABLE_BUILD
  // new_client_handler(), and thus create_debug_session() is called from
  // the main thread, so we don't risk a race for setting up the resolver.
  if ( per_pid_elf_dbgdir_resolver == nullptr )
    per_pid_elf_dbgdir_resolver = (per_pid_elf_dbgdir_resolver_t *) params; //lint !e611 cast between pointer to function type '' and pointer to object type 'void *'
#else
  qnotused(params);
#endif
  return new linux_debmod_t();
}
