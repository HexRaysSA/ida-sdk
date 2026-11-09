
#pragma once

#include <pro.h>
#include <idd.hpp>

//-------------------------------------------------------------------------
#if defined(__LINUX__) && defined(__ARM__)
#  ifdef __EA64__
#    define __HAVE_ARM_NEON__
#  else
#    define __HAVE_ARM_VFP__
#  endif
#endif

//-------------------------------------------------------------------------
#if defined(__MAC__) && defined(__ARM__)
#  define __HAVE_ARM_NEON__
#endif

//-------------------------------------------------------------------------
// NOTE: keep in sync with arm_register_classes
enum register_class_arm_t
{
  ARM_RC_GENERAL          = 0x01, // General registers
  ARM_RC_VFP              = 0x02, // VFP registers
  ARM_RC_NEON             = 0x04, // NEON registers
  ARM_RC_ALL = ARM_RC_GENERAL
#ifdef __HAVE_ARM_VFP__
             | ARM_RC_VFP
#endif
#ifdef __HAVE_ARM_NEON__
             | ARM_RC_NEON
#endif
};

//-------------------------------------------------------------------------
// ARM32 General registers ARM_RC_GENERAL
extern register_info_t ri_arm32_r[];
extern size_t          ri_arm32_r_count;
extern register_info_t ri_arm32_sp;
extern register_info_t ri_arm32_lr;
extern register_info_t ri_arm32_pc;
extern register_info_t ri_arm32_psr;
// ARM32 VFP registers ARM_RC_VFP
extern register_info_t ri_arm32_d[];
extern size_t          ri_arm32_d_count;
extern register_info_t ri_arm32_fpscr;
#ifdef __EA64__
// ARM64 registers
extern register_info_t ri_arm64_x[];
extern size_t          ri_arm64_x_count;
extern register_info_t ri_arm64_lr;
extern register_info_t ri_arm64_sp;
extern register_info_t ri_arm64_pc;
extern register_info_t ri_arm64_psr;
extern register_info_t ri_arm64_v[];
extern size_t          ri_arm64_v_count;
extern register_info_t ri_arm64_fpsr;
extern register_info_t ri_arm64_fpcr;
#endif

//-------------------------------------------------------------------------
// Number of registers in arm and aarch64
#define ARM64_NREGS 68
#define ARM32_NREGS 50

#ifdef __EA64__
  #define ARM_NREGS ARM64_NREGS
#else
  #define ARM_NREGS ARM32_NREGS
#endif

//-------------------------------------------------------------------------
extern const char *arm_register_classes[];
extern register_info_t arm_registers[ARM_NREGS];
extern register_info_t arm32_registers[ARM32_NREGS];
