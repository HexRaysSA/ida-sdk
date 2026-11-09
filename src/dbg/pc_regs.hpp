
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

// Number of registers in x86 and x64
#define X86_X64_NREGS 76
#define X86_X86_NREGS 52

#ifdef __EA64__
  #define X86_NREGS X86_X64_NREGS
#else
  #define X86_NREGS X86_X86_NREGS
#endif

//-------------------------------------------------------------------------
// General registers
#ifdef __EA64__
extern register_info_t pc_ri_rax;
extern register_info_t pc_ri_rbx;
extern register_info_t pc_ri_rcx;
extern register_info_t pc_ri_rdx;
extern register_info_t pc_ri_rsi;
extern register_info_t pc_ri_rdi;
extern register_info_t pc_ri_rbp;
extern register_info_t pc_ri_rsp;
extern register_info_t pc_ri_rip;
extern register_info_t pc_ri_r8;
extern register_info_t pc_ri_r9;
extern register_info_t pc_ri_r10;
extern register_info_t pc_ri_r11;
extern register_info_t pc_ri_r12;
extern register_info_t pc_ri_r13;
extern register_info_t pc_ri_r14;
extern register_info_t pc_ri_r15;
#endif
extern register_info_t pc_ri_eax;
extern register_info_t pc_ri_ebx;
extern register_info_t pc_ri_ecx;
extern register_info_t pc_ri_edx;
extern register_info_t pc_ri_esi;
extern register_info_t pc_ri_edi;
extern register_info_t pc_ri_ebp;
extern register_info_t pc_ri_esp;
extern register_info_t pc_ri_eip;

extern register_info_t pc_ri_efl;

// FPU registers X86_RC_FPU
extern register_info_t pc_ri_st[];
extern register_info_t pc_ri_ctrl;
extern register_info_t pc_ri_stat;
extern register_info_t pc_ri_tags;

// Segment registers X86_RC_SEGMENTS
extern register_info_t pc_ri_cs;
extern register_info_t pc_ri_ds;
extern register_info_t pc_ri_es;
extern register_info_t pc_ri_fs;
extern register_info_t pc_ri_gs;
extern register_info_t pc_ri_ss;

// XMM registers X86_RC_XMM
extern register_info_t pc_ri_xmm[];
extern register_info_t pc_ri_mxcsr;

// MMX registers X86_RC_MMX
extern register_info_t pc_ri_mm[];

// YMM registers X86_RC_YMM
extern register_info_t pc_ri_ymm[];

//-------------------------------------------------------------------------
extern const char *x86_register_classes[];
extern register_info_t x86_registers[X86_NREGS];
extern register_info_t x86_x86_registers[X86_X86_NREGS];
