
#include "arm_regs.hpp"

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_class_arm_t
const char *arm_register_classes[] =
{
  "General registers",
  "VFP registers",
  "NEON registers",
  nullptr
};

#ifndef __EA64__
//-------------------------------------------------------------------------
static const char *const psr[] =
{
  "MODE",       // 0
  "MODE",       // 1
  "MODE",       // 2
  "MODE",       // 3
  "MODE",       // 4
  "T",          // 5
  "F",          // 6
  "I",          // 7
  "A",          // 8
  "E",          // 9
  "IT",         // 10
  "IT",         // 11
  "IT",         // 12
  "IT",         // 13
  "IT",         // 14
  "IT",         // 15
  "GE",         // 16
  "GE",         // 17
  "GE",         // 18
  "GE",         // 19
  nullptr,         // 20
  nullptr,         // 21
  nullptr,         // 22
  nullptr,         // 23
  "J",          // 24
  "IT2",        // 25 additional bits of IT
  "IT2",        // 26 additional bits of IT
  "Q",          // 27
  "V",          // 28
  "C",          // 29
  "Z",          // 30
  "N",          // 31
};
#else
//-------------------------------------------------------------------------
static const char *const psr[] =
{
  "M",          // 0 AArch32 mode that an exception was taken from
  "M",          // 1
  "M",          // 2
  "M",          // 3
  "M",          // 4 Execution state that the exception was taken from
  "T",          // 5 T32 Instruction set state bit
  "F",          // 6 FIQ mask bit
  "I",          // 7 IRQ mask bit
  "A",          // 8 Asynchronous data abort mask bit
  "E",          // 9 Endianness Execution State bit
  "IT",         // 10 If-Then
  "IT",         // 11
  "IT",         // 12
  "IT",         // 13
  "IT",         // 14
  "IT",         // 15
  "GE",         // 16 Greater than or Equal flags
  "GE",         // 17
  "GE",         // 18
  "GE",         // 19
  "IL",         // 20 Illegal Execution State bit
  nullptr,         // 21
  nullptr,         // 22
  nullptr,         // 23
  nullptr,         // 24
  "IT2",        // 25 If-Then
  "IT2",        // 26
  "Q",          // 27 Cumulative saturation bit
  "V",          // 28 oVerflow condition flag
  "C",          // 29 Carry condition flag
  "Z",          // 30 Zero condition flag
  "N",          // 31 Negative condition flag
};

//-------------------------------------------------------------------------
static const char *const neon_formats[] =
{
  "NEON_16_bytes",
  "NEON_8_words",
  "NEON_4_dwords",
  "NEON_2_qwords",
  "NEON_4_floats",
  "NEON_2_doubles",
};
#endif

//-------------------------------------------------------------------------
static const char *const vfp_format[] =
{
  "VFP_1_double",
};

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_arm_t
// this register set is used if binary bitness is the same as IDA bitness
// (i.e. ida with 32bit binary or ida64 with 64bit binary)
register_info_t arm_registers[] =
{
#ifndef __EA64__
  // General registers
  { "R0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R12",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "LR",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword,  psr,          0xF800007F },
  // VFP registers
  { "D0",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D1",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D2",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D3",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D4",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D5",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D6",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D7",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D8",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D9",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D10",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D11",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D12",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D13",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D14",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D15",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D16",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D17",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D18",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D19",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D20",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D21",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D22",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D23",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D24",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D25",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D26",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D27",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D28",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D29",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D30",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D31",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "FPSCR", 0,                            ARM_RC_VFP,      dt_dword,  nullptr,      0 },
#else
  // General registers
  { "X0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X12",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X13",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X14",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X15",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X16",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X17",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X18",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X19",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X20",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X21",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X22",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X23",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X24",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X25",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X26",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X27",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X28",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X29",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "X30",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_qword,  nullptr,      0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword,  psr,          0xF8000000 },
  { "V0",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V1",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V2",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V3",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V4",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V5",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V6",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V7",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V8",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V9",    REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V10",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V11",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V12",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V13",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V14",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V15",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V16",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V17",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V18",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V19",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V20",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V21",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V22",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V23",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V24",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V25",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V26",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V27",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V28",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V29",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V30",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "V31",   REGISTER_CUSTFMT,             ARM_RC_NEON,     dt_byte16, neon_formats, 0 },
  { "FPSR",  0,                            ARM_RC_NEON,     dt_dword,  nullptr,      0 },
  { "FPCR",  0,                            ARM_RC_NEON,     dt_dword,  nullptr,      0 },
#endif
};
CASSERT(qnumber(arm_registers) == ARM_NREGS);

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_arm32_t
// this register set is used when ida64 runs 32bit binaries
register_info_t arm32_registers[] =
{
  // General registers
  { "R0",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R1",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R2",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R3",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R4",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R5",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R6",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R7",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R8",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R9",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R10",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R11",   REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "R12",   REGISTER_ADDRESS|REGISTER_FP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "SP",    REGISTER_ADDRESS|REGISTER_SP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "LR",    REGISTER_ADDRESS,             ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "PC",    REGISTER_ADDRESS|REGISTER_IP, ARM_RC_GENERAL,  dt_dword,  nullptr,      0 },
  { "PSR",   0,                            ARM_RC_GENERAL,  dt_dword,  psr,          0xF800007F },
  // VFP registers
  { "D0",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D1",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D2",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D3",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D4",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D5",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D6",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D7",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D8",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D9",    REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D10",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D11",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D12",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D13",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D14",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D15",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D16",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D17",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D18",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D19",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D20",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D21",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D22",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D23",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D24",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D25",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D26",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D27",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D28",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D29",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D30",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "D31",   REGISTER_CUSTFMT,             ARM_RC_VFP,      dt_qword,  vfp_format,   0 },
  { "FPSCR", 0,                            ARM_RC_VFP,      dt_dword,  nullptr,      0 },
};
CASSERT(qnumber(arm32_registers) == ARM32_NREGS);

//-------------------------------------------------------------------------
static const register_info_t *armregs_by_bitness(size_t *count, bool is64)
{
  const register_info_t *regs = arm_registers;
  *count = qnumber(arm_registers);
#ifdef __EA64__
  if ( !is64 )
  {
    regs = arm32_registers;
    *count = qnumber(arm32_registers);
  }
#else
  qnotused(is64);
#endif
  return regs;
}

//-------------------------------------------------------------------------
int arm_get_regidx(int *clsmask, const char *regname, bool is64)
{
  size_t count;
  const register_info_t *regs = armregs_by_bitness(&count, is64);
  for ( size_t i = 0; i < count; i++ )
  {
    if ( strieq(regname, regs[i].name) )
    {
      if ( clsmask != nullptr )
        *clsmask = regs[i].register_class;
      return i;
    }
  }
  return -1;
}

//-------------------------------------------------------------------------
int arm_get_regclass(int idx, bool is64)
{
  size_t count;
  const register_info_t *regs = armregs_by_bitness(&count, is64);
  if ( idx >= 0 && idx < count )
    return regs[idx].register_class;
  return 0;
}
