
#pragma once

#include <pro.h>
#include <idd.hpp>

//-------------------------------------------------------------------------
// NOTE: keep in sync with x86_register_classes
enum register_class_x86_t
{
  X86_RC_GENERAL          = 0x01, // General registers
  X86_RC_SEGMENTS         = 0x02, // Segment registers
  X86_RC_FPU              = 0x04, // FPU registers
  X86_RC_MMX              = 0x08, // MMX registers
  X86_RC_XMM              = 0x10, // XMM registers
  X86_RC_YMM              = 0x20, // YMM registers
  X86_RC_ALL = X86_RC_GENERAL
             | X86_RC_SEGMENTS
             | X86_RC_FPU
             | X86_RC_MMX
             | X86_RC_XMM
             | X86_RC_YMM
};

#ifdef __EA64__
//-------------------------------------------------------------------------
// NOTE: keep in sync with x86_x86_registers
// this register set is used when ida64 runs 32bit binaries
enum register_x86_x86_t
{
  // FPU registers
  R86_ST0,
  R86_ST1,
  R86_ST2,
  R86_ST3,
  R86_ST4,
  R86_ST5,
  R86_ST6,
  R86_ST7,
  R86_CTRL,
  R86_STAT,
  R86_TAGS,
  // Segment registers
  R86_CS,
  R86_DS,
  R86_ES,
  R86_FS,
  R86_GS,
  R86_SS,
  // General registers
  R86_EAX,
  R86_EBX,
  R86_ECX,
  R86_EDX,
  R86_ESI,
  R86_EDI,
  R86_EBP,
  R86_ESP,
  R86_EIP,
  R86_EFLAGS,
  // XMM registers
  R86_XMM0,
  R86_XMM1,
  R86_XMM2,
  R86_XMM3,
  R86_XMM4,
  R86_XMM5,
  R86_XMM6,
  R86_XMM7,
  R86_LAST_XMM = R86_XMM7,
  R86_MXCSR,
  // MMX registers
  R86_MMX0,
  R86_MMX1,
  R86_MMX2,
  R86_MMX3,
  R86_MMX4,
  R86_MMX5,
  R86_MMX6,
  R86_MMX7,
  // YMM registers
  R86_YMM0,
  R86_YMM1,
  R86_YMM2,
  R86_YMM3,
  R86_YMM4,
  R86_YMM5,
  R86_YMM6,
  R86_YMM7,
  R86_LAST_YMM = R86_YMM7,
};
#endif

//-------------------------------------------------------------------------
// NOTE: keep in sync with x86_registers
// this register set is used if binary bitness is the same as IDA bitness
// (i.e. ida with 32bit binary or ida64 with 64bit binary)
enum register_x86_t
{
  // FPU registers
  R_ST0,
  R_ST1,
  R_ST2,
  R_ST3,
  R_ST4,
  R_ST5,
  R_ST6,
  R_ST7,
  R_CTRL,
  R_STAT,
  R_TAGS,
  // Segment registers
  R_CS,
  R_DS,
  R_ES,
  R_FS,
  R_GS,
  R_SS,
  // General registers
  R_EAX,
  R_EBX,
  R_ECX,
  R_EDX,
  R_ESI,
  R_EDI,
  R_EBP,
  R_ESP,
  R_EIP,
#ifdef __EA64__
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
#endif
  R_EFLAGS,
  // XMM registers
  R_XMM0,
  R_XMM1,
  R_XMM2,
  R_XMM3,
  R_XMM4,
  R_XMM5,
  R_XMM6,
  R_XMM7,
#ifndef __EA64__
  R_LAST_XMM = R_XMM7,
#else
  R_XMM8,
  R_XMM9,
  R_XMM10,
  R_XMM11,
  R_XMM12,
  R_XMM13,
  R_XMM14,
  R_XMM15,
  R_LAST_XMM = R_XMM15,
#endif
  R_MXCSR,
  // MMX registers
  R_MMX0,
  R_MMX1,
  R_MMX2,
  R_MMX3,
  R_MMX4,
  R_MMX5,
  R_MMX6,
  R_MMX7,
  // YMM registers
  R_YMM0,
  R_YMM1,
  R_YMM2,
  R_YMM3,
  R_YMM4,
  R_YMM5,
  R_YMM6,
  R_YMM7,
#ifndef __EA64__
  R_LAST_YMM = R_YMM7,
#else
  R_YMM8,
  R_YMM9,
  R_YMM10,
  R_YMM11,
  R_YMM12,
  R_YMM13,
  R_YMM14,
  R_YMM15,
  R_LAST_YMM = R_YMM15,
#endif
};

// Number of registers in x86 and x64
#define X86_X64_NREGS 76
#define X86_X86_NREGS 52

#ifdef __EA64__
  #define X86_NREGS X86_X64_NREGS
#else
  #define X86_NREGS X86_X86_NREGS
#endif

//-------------------------------------------------------------------------
inline int x86reg_to_idx(register_x86_t r, bool is64bit)
{
#ifdef __EA64__
  if ( !is64bit )
  {
    if ( r <= R_R15 )
    {
      QASSERT(2769, r <= R_EIP);
      return r;
    }
    if ( r == R_EFLAGS )
      return R86_EFLAGS;
    if ( r <= R_LAST_XMM )
    {
      QASSERT(2770, r <= R_XMM7);
      return R86_XMM0 + (r-R_XMM0);
    }
    if ( r == R_MXCSR )
      return R86_MXCSR;
    if ( r <= R_MMX7 )
      return R86_MMX0 + (r-R_MMX0);
    QASSERT(2771, r <= R_YMM7);
    return R86_YMM0 + (r-R_YMM0);
  }
#else // not __EA64__
  QASSERT(2772, !is64bit);
#endif
  return r;
}

//-------------------------------------------------------------------------
inline register_x86_t idx_to_x86reg(int idx, bool is64bit)
{
#ifdef __EA64__
  if ( !is64bit )
  {
    if ( idx <= R86_EIP )
      return register_x86_t(idx);
    if ( idx == R86_EFLAGS )
      return R_EFLAGS;
    if ( idx <= R86_LAST_XMM )
      return register_x86_t(R_XMM0 + (idx-R86_XMM0));
    if ( idx == R86_MXCSR )
      return R_MXCSR;
    if ( idx <= R86_MMX7 )
      return register_x86_t(R_MMX0 + (idx-R86_MMX0));
    QASSERT(2773, idx <= R86_LAST_YMM);
    return register_x86_t(R_YMM0 + (idx-R86_YMM0));
  }
#else // not __EA64__
  QASSERT(2774, !is64bit);
#endif
  return register_x86_t(idx);
}

//-------------------------------------------------------------------------
// General registers
#ifdef __EA64__
extern register_info_t r_rax;
extern register_info_t r_rbx;
extern register_info_t r_rcx;
extern register_info_t r_rdx;
extern register_info_t r_rsi;
extern register_info_t r_rdi;
extern register_info_t r_rbp;
extern register_info_t r_rsp;
extern register_info_t r_rip;
extern register_info_t r_r8;
extern register_info_t r_r9;
extern register_info_t r_r10;
extern register_info_t r_r11;
extern register_info_t r_r12;
extern register_info_t r_r13;
extern register_info_t r_r14;
extern register_info_t r_r15;
#endif
extern register_info_t r_eax;
extern register_info_t r_ebx;
extern register_info_t r_ecx;
extern register_info_t r_edx;
extern register_info_t r_esi;
extern register_info_t r_edi;
extern register_info_t r_ebp;
extern register_info_t r_esp;
extern register_info_t r_eip;

//-------------------------------------------------------------------------
extern const char *x86_register_classes[];
extern register_info_t x86_registers[X86_NREGS];
extern register_info_t x86_x86_registers[X86_X86_NREGS];

//-------------------------------------------------------------------------
int x86_get_regidx(int *clsmask, const char *regname, bool is64);
int x86_get_regclass(int idx, bool is64);
