#include "bochsys.h"
#include <windows.h>

//--------------------------------------------------------------------------
// dummy entry point so that linker does not use entrypoints from CRT
DWORD WINAPI Entry(DWORD a, DWORD b, DWORD c)
{
  return 0;
}

//--------------------------------------------------------------------------
// This function will be called by bochsys.dll from R0 before switching to R3
// This is even called before TLS callbacks
void WINAPI MyR0Entry(VOID)
{
  __asm
  {
    nop
    mov dx, 0378h
    in eax, dx
    nop
    nop
  }
}

//--------------------------------------------------------------------------
DWORD MyHandler(
  PEXCEPTION_RECORD rec,
  struct _EXCEPTION_REGISTRATION_RECORD *reg,
  PCONTEXT ctx,
  struct _EXCEPTION_REGISTRATION_RECORD **reg2)
{
  ctx->Eip += 2;
  return ExceptionContinueExecution;
}

//--------------------------------------------------------------------------
void BuggyFunction()
{
  BxInstallSEH(MyHandler);
  __asm
  {
    xor eax, eax
    mov eax, [eax]
  }
  BxUninstallSEH();
}


//--------------------------------------------------------------------------
// In this function, BxXXXXXX functions are used from the bochsys library
int __stdcall MyMessageBox(
  HWND hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT uType)
{
  char *p;
  int i;

  // Allocate memory
  p = BxVirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_READWRITE);

  // Fill the memory
  for (i=1;i<=0x1000;i++)
    *p++ = i & 0xFF;

  // Resolve an entry and call it
  (VOID (__stdcall *)(int, int)) BxGetProcAddress(BxLoadLibraryA("kernel32.dll"), "Beep")(5, 1);

  // Call a function that might cause an exception
  BuggyFunction();

  return 0;
}

//--------------------------------------------------------------------------
// In this function we import from user32 and kernel32
// (because VirtualAlloc->BxVirtualAlloc and MessageBoxA->bxtest.MyMessageBox are redirected and implemented)
int __stdcall MyRoutine(
  HWND hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT uType)
{
  VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
  MessageBoxA(0, "hey", "info", MB_OK);
  return 0;
}
