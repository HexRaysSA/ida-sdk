
#include <pro.h>
#include "linux_debmod.h"
//--------------------------------------------------------------------------
pid_t linux_debmod_t::check_for_signal(int *status, int _pid, int timeout_ms) const
{
  // SIGCONT ending a group-stop is reported as WIFCONTINUED. it is not a
  // ptrace stop (the thread keeps running), so consume and skip it.
  // requesting it keeps such statuses from piling up in the child waiter.
  pid_t pid;
  do
    pid = qwait_timed(status, _pid, __WALL | WCONTINUED, timeout_ms);
  while ( pid > 0 && WIFCONTINUED(*status) );
  return pid;
}
