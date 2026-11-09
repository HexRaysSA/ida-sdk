
Custom DLLs for emulated MS Windows environment
-----------------------------------------------

This directory contains files that demonstrate how to build a custom DLL
for the PE loader of the Bochs debugger.

compile.bat shows how to build a custom DLL with the MS compiler/linker.
The general rule is not to link with runtime libraries, but linking with
import libraries is ok.

"bxtest.c" demonstrates how to call functions in bochsys.dll.
"bochsys.h" has the list of functions that can be called from custom DLLs.
"bochsys.lib" is the corresponding import library

Custom DLLs must be mentioned in plugins\bochs\startup.idc.
For that please add a line like this:

/// load bxtest.dll

This will cause the DLL to be present in the memory space of the debugged process.
For the custom DLL to be useful, its exported functions should be connected
to API function names. For example, the following line redirects MessageBoxA
to bxtest.MyMessageBox:

/// func=MessageBoxA entry=bxtest.MyMessageBox

The exact format of the startup.idc file is explained in its header.

On the other hand, it is also possible to write a custom DLL that replaces system
DLLs like kernel32.dll or user32.dll.


The "load" command has an additional parameter "R0UserEntry=MyR0Entry" used as:
///load bxtest.dll R0UserEntry=MyR0Entry

Which means that bxtest.dll should be loaded into the process memory and
that this DLL has an exported entry that should be called by bochsys from ring0.
Such a facility is ideal if you're looking to replace or enhance bochsys's kernel.

To test how MessageBoxA is redirected to MyMessageBox, please follow these
steps:

        - compile and link bxtest.dll with compile.bat
          (we provide ready-to-use bxtest.dll for your convenience, so you
           skip this step)

        - add two lines mentioned above to startup.idc and api_user32.idc respectively

        - load test.pe into IDA and select Bochs debugger

        - run it and single step into the MessageBoxA function

With any questions, please contact us at support@hex-rays.com


Bochs plugin debugger extensions
-----------------------------------

Bochs extensions allow for accessing extended debugger functionality.

To get and use the extensions, query the currently loaded debugger using
get_debmod_extensions(). Usually it returns a pointer to a structure with
pointers to functions. Please follow this example:

#include "bochsext.h"

void idaapi run(int)
{
  if ( dbg == NULL )
  {
    msg("dbg == NULL\n");
    return;
  }
  const bochsext_t *ext = (const bochsext_t *)dbg->get_debmod_extensions();
  if ( ext == NULL )
  {
    msg("no debugger extensions!\n");
    return;
  }

  // dump 10 bytes from physical memory at 0x0
  qstring out;
  if ( !ext->send_command("xp /10mb 0x0\r\n", &out) )
  {
    msg("failed to send command!\n");
    return;
  }
  msg("->result=%s\n", out.c_str());
}
