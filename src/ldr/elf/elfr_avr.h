#ifndef __ELFR_AVR_H__
#define __ELFR_AVR_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

enum elf_RTYPE_avr
{
  R_AVR_NONE            =  0,
  R_AVR_32              =  1,
  R_AVR_7_PCREL         =  2,
  R_AVR_13_PCREL        =  3,
  R_AVR_16              =  4,
  R_AVR_16PM            =  5,
  R_AVR_LO8_LDI         =  6,
  R_AVR_HI8_LDI         =  7,
  R_AVR_HH8_LDI         =  8,
  R_AVR_LO8_LDI_NEG     =  9,
  R_AVR_HI8_LDI_NEG     = 10,
  R_AVR_HH8_LDI_NEG     = 11,
  R_AVR_LO8_LDI_PM      = 12,
  R_AVR_HI8_LDI_PM      = 13,
  R_AVR_HH8_LDI_PM      = 14,
  R_AVR_LO8_LDI_PM_NEG  = 15,
  R_AVR_HI8_LDI_PM_NEG  = 16,
  R_AVR_HH8_LDI_PM_NEG  = 17,
  R_AVR_CALL            = 18,
  // *nix obj's specific
  R_AVR_LDI             = 19,
  R_AVR_6               = 20,
  R_AVR_6_ADIW          = 21,
  R_AVR_MS8_LDI         = 22,
  R_AVR_MS8_LDI_NEG     = 23,
  R_AVR_LO8_LDI_GS      = 24,
  R_AVR_HI8_LDI_GS      = 25,
  R_AVR_8               = 26,
  R_AVR_8_LO8           = 27,
  R_AVR_8_HI8           = 28,
  R_AVR_8_HLO8          = 29,
  R_AVR_DIFF8           = 30,
  R_AVR_DIFF16          = 31,
  R_AVR_DIFF32          = 32,
  R_AVR_LDS_STS_16      = 33,
  R_AVR_PORT6           = 34,
  R_AVR_PORT5           = 35,
  R_AVR_32_PCREL        = 36,
};

// Flags:
// If bit #7 is set, it is assumed that the elf file uses local symbols
// as reference for the relocations so that linker relaxation is possible.
#define EF_AVR_LINKRELAX_PREPARED 0x80

// Processor specific flags for the ELF header e_flags field.
#define EF_AVR_MACH 0x7F
#define E_AVR_MACH_AVR1    1
#define E_AVR_MACH_AVR2    2
#define E_AVR_MACH_AVR25  25
#define E_AVR_MACH_AVR3    3
#define E_AVR_MACH_AVR31  31
#define E_AVR_MACH_AVR35  35
#define E_AVR_MACH_AVR4    4
#define E_AVR_MACH_AVR5    5
#define E_AVR_MACH_AVR51  51
#define E_AVR_MACH_AVR6    6
#define E_AVR_MACH_TINY   100
#define E_AVR_MACH_XMEGA1 101
#define E_AVR_MACH_XMEGA2 102
#define E_AVR_MACH_XMEGA3 103
#define E_AVR_MACH_XMEGA4 104
#define E_AVR_MACH_XMEGA5 105
#define E_AVR_MACH_XMEGA6 106
#define E_AVR_MACH_XMEGA7 107

// netnode flag's and constant
#define AVR_INFO_NODENAME   "$ atmel"
#define ELF_AVR_TAG         'f'
#define ELF_AVR_LDI_NEG     1
#define ELF_AVR_RAM_OFF     2
#define ELF_AVR_EEP_OFF     3
#define ELF_AVR_ABS_OFF     4
#define ELF_AVR_RAMBASE     0x800000
#define ELF_AVR_EEPROMBASE  0x810000
#define ELF_AVR_ABSBASE     0x1000000

#endif
