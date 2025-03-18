#ifndef __DEB_PC__
#define __DEB_PC__

#include <ua.hpp>
#include <range.hpp>
#include <idd.hpp>

#define MEMORY_PAGE_SIZE 0x1000
#define X86_BPT_CODE         { 0xCC }
#define MAX_BPT 4               // maximal number of hardware breakpoints
#define X86_BPT_SIZE 1         // size of 0xCC instruction
#define EFLAGS_TRAP_FLAG 0x00000100

//--------------------------------------------------------------------------
inline int check_x86_hwbpt(bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_RDWR         // type is good?
    && type != BPT_WRITE
    && type != BPT_EXEC )
  {
    return BPT_BAD_TYPE;
  }

  if ( len != 1                 // is length good?
    && (type == BPT_EXEC        // instruction hardware breakpoint only accepts the len of one byte
     || (len != 2 && len != 4
#ifndef __X86__
      && len != 8
#endif
     )) )
  {
    return BPT_BAD_LEN;
  }

  if ( (ea & (len-1)) != 0 )    // is alignment good?
    return BPT_BAD_ALIGN;

  return BPT_OK;
}

//--------------------------------------------------------------------------
inline int is_x86_valid_bpt(const debugger_t &_debugger, bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_SOFT )
  {
    if ( (_debugger.flags & DBG_FLAG_ANYSIZE_HWBPT) == 0 )
      return check_x86_hwbpt(type, ea, len);

    if ( type == 0 )
      return BPT_BAD_TYPE;
  }
  return BPT_OK;
}


#endif
