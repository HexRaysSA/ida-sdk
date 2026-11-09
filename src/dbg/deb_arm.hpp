#ifndef __DEB_ARM__
#define __DEB_ARM__

#include <ua.hpp>
#include <idd.hpp>

#define MEMORY_PAGE_SIZE 0x1000
#define ARM_BPT_CODE     { 0xF0, 0x01, 0xF0, 0xE7 }     // und #10
#define AARCH64_BPT_CODE { 0x00, 0x00, 0x20, 0xD4 }     // brk #0

#define ARM_BPT_SIZE 4         // size of BPT instruction

#define ARM_T 20                // number of virtual T segment register in IDA
                                // it controls thumb/arm mode.

#define ARM_MAX_HWBPTS 16
#define ARM_MAX_WATCHPOINTS 16

int is_arm_valid_bpt(bpttype_t type, ea_t ea, int len);

#endif

