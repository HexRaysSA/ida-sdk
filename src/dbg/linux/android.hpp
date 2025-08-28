/*

        Android specific definitions

*/

#ifndef __ANDROID_HPP
#define __ANDROID_HPP

// Android NDK lacks link.h, so we have to use our own definitions

#include <android/api-level.h>
#include "dbg_rpc_handler.h"

struct link_map
{
  uintptr_t l_addr;
  char * l_name;
  uintptr_t l_ld;
  struct link_map * l_next;
  struct link_map * l_prev;
};

struct r_debug
{
  int32_t r_version;
  struct link_map * r_map;
  int32_t r_brk;
  // Values for r_state
  enum
  {
    RT_CONSISTENT,
    RT_ADD,
    RT_DELETE
  };
  int32_t r_state;
  uintptr_t r_ldbase;
};

// pread64 is missing
#define pread64 pread

// thread_db.h lacks many definitions as well:

#define TD_MIN_EVENT_NUM 0
#define TD_MAX_EVENT_NUM 16
#define td_eventismember(set, n) (((set)->events & (1 << (n))) != 0)
typedef int td_thr_type_e;
extern "C"
{
  inline td_err_e td_init(void) { return TD_OK; }
  inline td_err_e td_thr_set_event(const td_thrhandle_t *, td_thr_events_t *) { return TD_OK; }
  inline td_err_e td_thr_setsigpending(const td_thrhandle_t *, unsigned char, const sigset_t *) { return TD_OK; }
}

// Other missing definitions:
typedef int32 __ptrace_request;

#define user_regs pt_regs

#endif // define __ANDROID_HPP
