//
//
//      This file contains win32 specific implementations of win32_debugger_module class
//      IDA-side functionality only (for local debugger)
//
//

#include <pro.h>
#include "win32_debmod.h"

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::handle_ioctl(int /*fn*/, const void * /*buf*/, size_t /*size*/, void ** /*poutbuf*/, ssize_t * /*poutsize*/)
{
  return 0;
}
