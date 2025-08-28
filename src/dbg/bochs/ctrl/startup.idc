// This file contains bochs startup and exit procedures bochs_startup() and bochs_exit()
// The former is called when the process starts
// The latter is called when the process is about to exit
// Both functions cause IDA debugger to suspend if they return a non zero value

// This section declares which DLLs will be available:
// * Use the "stub" to mark a dll for stubbing

// * Use the "load" to mark a dll to be loaded as is
// The "load" keyword has an additional attributes called "R0UserEntry"
// This attribute is used to designate an exported function that will be called from ring0
// Such a mechanism is useful to extend bochsys kernel or even replace it after it is loaded
// One simple application is to modify the IDT and add R3 callable interrupts into your kernel

// Only lines containing three forward slashes ("/") are processed:

/// stub ntdll.dll
/// stub kernel32.dll
/// stub user32.dll
/// stub shell32.dll
/// stub shlwapi.dll
/// stub urlmon.dll
/// stub advapi32.dll
/// stub mswsock.dll
/// stub wininet.dll
/// stub msvcrt.dll
/// stub gdi32.dll
/// stub ole32.dll
/// stub wsock32.dll
/// stub ws2_32.dll

// Define our own environment variables.
// (add triple slashes to enable)
// env path=c:\games\bin;d:\bin\asdf\
// env userprofile=c:\games\

// Define your dependency mappings
// (add triple slashes to enable the following lines)
// map /home/guest/sys_dlls/user32.dll=d:\winnt\system32\user32.dll
// map /home/guest/sys_dlls/shell32.dll=d:\winnt\system32\shell32.dll
// map /home/guest/sys_dlls/kernel32.dll=d:\winnt\system32\kernel32.dll
// map /home/guest/sys_dlls/shlwapi.dll=d:\winnt\system32\shlwapi.dll
// map /home/guest/sys_dlls/urlmon.dll=d:\winnt\system32\urlmon.dll
// map /home/guest/sys_dlls/mswsock.dll=d:\winnt\system32\mswsock.dll
// map /home/guest/sys_dlls/wininet.dll=d:\winnt\system32\wininet.dll
// map /home/guest/sys_dlls/msvcrt.dll=d:\winnt\system32\msvcrt.dll
// map /home/guest/sys_dlls/gdi32.dll=d:\winnt\system32\gdi32.dll
// map /home/guest/sys_dlls/ntdll.dll=d:\winnt\system32\ntdll.dll
// map /home/guest/sys_dlls/advapi32.dll=d:\winnt\system32\advapi32.dll

// Define additional DLL path
// (add triple slashes to enable the following lines)
// path /home/guest/sys_dlls/=c:\winnt\system32\

// Bochs debugger plugin also allows you to specify the DLL path through the environment variable IDABXPATHMAP
// (It is possible to specify more than one key/value pair by separating them with a semi-colon)
// For example:
//    $ export IDABXPATHMAP="/home/guest/sys_dlls/=c:/winnt/system32/;/home/user2/other_dlls/=c:/program files/common files/3rd party/"
// Similarly, one can specify the environment variables through the environment variable IDABXENVMAP
// (it is possible to specify more than one key/value pair by separating them with a "++")
// For example:
//    $ export IDABXENVMAP="TMP=c:/Users/Guest/Temp++SystemDrive=C:++windir=c:/windows/"
//
// Please note that the forward slashes "/" in the value part of the key/value pair will always be replaced with a backslash

//
// The following are oneshot options. Once set they cannot be unset.
// To define them simply preceed the option name with triple slashes.
// - nosearchpath: Disables SearchPath() use for finding DLLs (this option is applicable on MS Windows only).
//                 By turning this option, Bochs plugin will try to load DLLs from the current directory.
//                 It useful for loading certain (old or new) versions of system DLLs instead of the ones currently installed
//                 on the system.
// - noactivationcontext: Disables the use of "Activation Context" (this option is applicable on MS Windows only).
//

//
// For loading drivers, you may uncomment the following stub definition(s):
//
// stub ntoskrnl.exe

// For example: to load a dll as is: load mydll.dll
// For example: to load a dll as is and specify a user R0 entry: load mydll.dll R0UserEntry=MyExportedFunc

#include <idc.idc>

//--------------------------------------------------------------------------
// IDC scripts that will be available during the debugging session

// MS Windows related functions
// ------------------------------
// BochsVirtXXXX functions allocate/free virtual memory in the emulated session.
// The "size" parameter is always rounded to a page.
//

//
// Allocate virtual memory
// This function emulates the VirtualAlloc function from MS Windows
//      addr - the preferred address for the allocation. Zero means no preference
//      size - size of the block to allocate
//      writable - should be allocated memory be wrtiable?
//                 Currently only read/write page protections are supported
// Returns: the address of the allocated block or zero
//
// long BochsVirtAlloc(long addr, long size, bool writable);
//

//
// Change protection of memory page
// This function emulates the VirtualProtect function from MS Windows
//      addr - the desired address to change protection.
//      size - size of the block
//      attr - the new page attribute:
//                 0 = Read only
//                 1 = Read/Write
// Returns: the old protection value or -1 on failure
//
// long BochsVirtProtect(long addr, long size, long attr);
//


//
// Free virtual memory
// This function emulates the VirtualFree function from MS Windows
//      addr - the address of previously allocated memory block
//      size - the size of the block. If zero, then the entire block at addr
//             will be freed.
// Returns: success
//
// bool BochsVirtFree(long addr, long size);
//

//
// Returns the base address of a given module name
//      module_name - The name of the module.
//                    The name can be full path or filename with extension, or simply filename without extension
// Returns: zero if it fails
//
// long BochsGetModuleHandle(string module_name);
//

//
// Returns a procedure's address
// This function calls the internal GetProcAddress to resolve function addresses.
//      hmod      - the module handle
//      procname  - name of the procedure inside the module
// Returns: the zero if procedure not found, otherwise the address
//
// long BochsGetProcAddress(long hmod, string procname);
//

//
// Returns the module name given its base address
//      module_handle: the base address of a given module
// Returns: empty string if module was not found
//
// string BochsGetModuleFileName(long module_handle)
//

//
// Returns the command line value passed to the application
//
// string BochsGetCommandLine()
//

//
// Set last error code
// This function emulates the SetLastError function from MS Windows.
// It writes the specified code to TIB.
//      error_code - new error code to set
// Returns: success
//
// success BochsWin32SetLastError(long error_num);
//

//
// Other functions:
// -------------------
//

//
// Sends arbitrary commands to the internal debugger of BOCHS. The output is returned as a string.
// This is useful for example to send some commands to BOCHS that are not exposed via the GUI of IDA.
//      command: the command you want to send
// Returns: output string or empty string if it failed
//
// string send_dbg_command(string command)
//

//
// Retrieves the parameter value passed to an IDC script that is implementing a given API.
// This same function can be implemented with this expression: #define BX_GETPARAM(n) get_wide_dword(esp+4*(n+1))
//      arg_num: the argument number (starting by one)
// Returns: the value or zero in case it fails
//
// string BochsGetParam(long arg_num)
//

//
// Calls a function inside Bochs
// This function can call functions inside Bochs. Very useful if you want to call
// functions in the user's code. The arguments are pushed from right to left.
//      func_ptr - The address of the function to be called
//      argN - a set of dwords that contain the arguments.
//             Arguments can be numbers or pointers
// Returns: success
//
// long BochsCall(long func_ptr, arg1, arg2, ...);
//


//
// These functions will return the total physical memory amount and the remaining free
// memory in bytes.
// Returns: memory size in bytes
//
// long BochsGetFreeMem()
// long BochsGetMaxMem()
//

// ----------------------------------------------------------------------------
static BochsPatchDbgDword(ea, dv)
{
  auto i;
  for (i=0;i<4;i++)
  {
    patch_dbg_byte(ea, dv & 0xFF);
    ea = ea + 1;
    dv = dv >> 8;
  }
}

// ----------------------------------------------------------------------------
// Utility function that can be used as a conditional breakpoint condition
// in order to skip to the next instruction w/o suspending IDA
static bochs_skipnext()
{
  Eip = next_head(eip, BADADDR);
  return 0;
}

// ----------------------------------------------------------------------------
// Utility function that can be used as a conditional breakpoint condition
// in order to execute the contents of the comments at the bp location
static bochs_execidc_comments()
{
  exec_idc(Comment(eip));
  return 0;
}

// ----------------------------------------------------------------------------
// Utility function used to dump registers. The output can be used as a comment
// with the bochs_execidc_comments() bp condition
static bochs_dump_registers()
{
  msg("eax=0x%x;ebx=0x%x;ecx=0x%x;edx=0x%x;esi=0x%x;edi=0x%x;ebp=0x%x;", eax, ebx, ecx, edx, esi, edi, ebp);
}

// ----------------------------------------------------------------------------
static bochs_startup()
{
  msg("Bochs debugger has been initialized.\n");
  return 0;
}

// ----------------------------------------------------------------------------
static bochs_exit()
{
  msg("Bochs debugger has been terminated.\n");
  return 0;
}

