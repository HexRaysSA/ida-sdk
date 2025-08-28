#ifndef __LINUXBASE_HPP__
#define __LINUXBASE_HPP__

#include "debmod.h"

// Base class for linux modules

#ifdef __ARM__
#  define BASE_DEBUGGER_MODULE arm_debmod_t
#  include "arm_debmod.h"
#  define BPT_CODE_SIZE ARM_BPT_SIZE
#else
#  define BASE_DEBUGGER_MODULE pc_debmod_t
#  include "pc_debmod.h"
#  define BPT_CODE_SIZE X86_BPT_SIZE
#endif

class linuxbase_debmod_t: public BASE_DEBUGGER_MODULE
{
  typedef BASE_DEBUGGER_MODULE inherited;
protected:
  // return number of processes, -1 - not implemented
  virtual int idaapi get_process_list(procvec_t *proclist, qstring *errbuf) override;
  // return the file name assciated with pid
  virtual bool idaapi get_exec_fname(int pid, char *buf, size_t bufsize) newapi;
  // get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
  virtual int idaapi get_process_bitness(int pid) newapi;
};

#endif
