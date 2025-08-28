
#include <pro.h>
#include "linux_debmod.h"
//--------------------------------------------------------------------------
pid_t linux_debmod_t::check_for_signal(int *status, int _pid, int timeout_ms) const
{
  return qwait_timed(status, _pid, __WALL | WCONTINUED, timeout_ms);
}
