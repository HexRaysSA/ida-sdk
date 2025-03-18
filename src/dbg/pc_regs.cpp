
#include "pc_regs.hpp"

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_class_x86_t
const char *x86_register_classes[] =
{
  "General registers",
  "Segment registers",
  "FPU registers",
  "MMX registers",
  "XMM registers",
  "YMM registers",
  nullptr
};

//-------------------------------------------------------------------------
static const char *const eflags[] =
{
  "CF",         //  0
  nullptr,         //  1
  "PF",         //  2
  nullptr,         //  3
  "AF",         //  4
  nullptr,         //  5
  "ZF",         //  6
  "SF",         //  7
  "TF",         //  8
  "IF",         //  9
  "DF",         // 10
  "OF",         // 11
  "IOPL",       // 12
  "IOPL",       // 13
  "NT",         // 14
  nullptr,         // 15
  "RF",         // 16
  "VM",         // 17
  "AC",         // 18
  "VIF",        // 19
  "VIP",        // 20
  "ID",         // 21
  nullptr,         // 22
  nullptr,         // 23
  nullptr,         // 24
  nullptr,         // 25
  nullptr,         // 26
  nullptr,         // 27
  nullptr,         // 28
  nullptr,         // 29
  nullptr,         // 30
  nullptr          // 31
};

//-------------------------------------------------------------------------
static const char *const ctrlflags[] =
{
  "CTRL.IM",
  "CTRL.DM",
  "CTRL.ZM",
  "CTRL.OM",
  "CTRL.UM",
  "CTRL.PM",
  nullptr,
  nullptr,
  "CTRL.PC",
  "CTRL.PC",
  "CTRL.RC",
  "CTRL.RC",
  "CTRL.X",
  nullptr,
  nullptr,
  nullptr
};

//-------------------------------------------------------------------------
static const char *const statflags[] =
{
  "STAT.IE",
  "STAT.DE",
  "STAT.ZE",
  "STAT.OE",
  "STAT.UE",
  "STAT.PE",
  "STAT.SF",
  "STAT.ES",
  "STAT.C0",
  "STAT.C1",
  "STAT.C2",
  "STAT.TOP",
  "STAT.TOP",
  "STAT.TOP",
  "STAT.C3",
  "STAT.B"
};

//-------------------------------------------------------------------------
static const char *const tagsflags[] =
{
  "TAG0",
  "TAG0",
  "TAG1",
  "TAG1",
  "TAG2",
  "TAG2",
  "TAG3",
  "TAG3",
  "TAG4",
  "TAG4",
  "TAG5",
  "TAG5",
  "TAG6",
  "TAG6",
  "TAG7",
  "TAG7"
};

//-------------------------------------------------------------------------
static const char *const xmm_format[] =
{
  "XMM_4_floats",
};

//-------------------------------------------------------------------------
static const char *const ymm_format[] =
{
  "YMM_8_floats",
};

//-------------------------------------------------------------------------
static const char *const mmx_format[] =
{
  "MMX_8_bytes",
};

//-------------------------------------------------------------------------
static const char *const mxcsr_bits[] =
{
  "IE",         //  0 Invalid Operation Flag
  "DE",         //  1 Denormal Flag
  "ZE",         //  2 Divide-by-Zero Flag
  "OE",         //  3 Overflow Flag
  "UE",         //  4 Underflow Flag
  "PE",         //  5 Precision Flag
  "DAZ",        //  6 Denormals Are Zeros*
  "IM",         //  7 Invalid Operation Mask
  "DM",         //  8 Denormal Operation Mask
  "ZM",         //  9 Divide-by-Zero Mask
  "OM",         // 10 Overflow Mask
  "UM",         // 11 Underflow Mask
  "PM",         // 12 Precision Mask
  "RC",         // 13 Rounding Control
  "RC",         // 14 Rounding Control
  "FZ",         // 15 Flush to Zero
  nullptr,         // 16
  nullptr,         // 17
  nullptr,         // 18
  nullptr,         // 19
  nullptr,         // 20
  nullptr,         // 21
  nullptr,         // 22
  nullptr,         // 23
  nullptr,         // 24
  nullptr,         // 25
  nullptr,         // 26
  nullptr,         // 27
  nullptr,         // 28
  nullptr,         // 29
  nullptr,         // 30
  nullptr          // 31
};

//-------------------------------------------------------------------------
// General registers X86_RC_GENERAL
#ifdef __EA64__
register_info_t pc_ri_rax = { "RAX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rbx = { "RBX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rcx = { "RCX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rdx = { "RDX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rsi = { "RSI", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rdi = { "RDI", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rbp = { "RBP", REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rsp = { "RSP", REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_rip = { "RIP", REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r8  = { "R8",  REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r9  = { "R9",  REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r10 = { "R10", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r11 = { "R11", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r12 = { "R12", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r13 = { "R13", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r14 = { "R14", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
register_info_t pc_ri_r15 = { "R15", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_qword, nullptr, 0 };
#endif
register_info_t pc_ri_eax = { "EAX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_ebx = { "EBX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_ecx = { "ECX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_edx = { "EDX", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_esi = { "ESI", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_edi = { "EDI", REGISTER_ADDRESS,             X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_ebp = { "EBP", REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_esp = { "ESP", REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL, dt_dword, nullptr, 0 };
register_info_t pc_ri_eip = { "EIP", REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL, dt_dword, nullptr, 0 };

register_info_t pc_ri_efl = { "EFL", 0, X86_RC_GENERAL, dt_dword, eflags, 0x00000FD5 }; // OF|DF|IF|TF|SF|ZF|AF|PF|CF

// FPU registers X86_RC_FPU
register_info_t pc_ri_st[] =
{
  { "ST0", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST1", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST2", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST3", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST4", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST5", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST6", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
  { "ST7", 0, X86_RC_FPU, dt_tbyte, nullptr, 0 },
};
register_info_t pc_ri_ctrl = { "CTRL", 0, X86_RC_FPU, dt_word, ctrlflags, 0x1F3F };
register_info_t pc_ri_stat = { "STAT", 0, X86_RC_FPU, dt_word, statflags, 0xFFFF };
register_info_t pc_ri_tags = { "TAGS", 0, X86_RC_FPU, dt_word, tagsflags, 0xFFFF };

// Segment registers X86_RC_SEGMENTS
register_info_t pc_ri_cs = { "CS", REGISTER_CS|REGISTER_NOLF, X86_RC_SEGMENTS, dt_word, nullptr, 0 };
register_info_t pc_ri_ds = { "DS", REGISTER_NOLF,             X86_RC_SEGMENTS, dt_word, nullptr, 0 };
register_info_t pc_ri_es = { "ES", 0,                         X86_RC_SEGMENTS, dt_word, nullptr, 0 };
register_info_t pc_ri_fs = { "FS", REGISTER_NOLF,             X86_RC_SEGMENTS, dt_word, nullptr, 0 };
register_info_t pc_ri_gs = { "GS", REGISTER_NOLF,             X86_RC_SEGMENTS, dt_word, nullptr, 0 };
register_info_t pc_ri_ss = { "SS", REGISTER_SS,               X86_RC_SEGMENTS, dt_word, nullptr, 0 };

// XMM registers X86_RC_XMM
register_info_t pc_ri_xmm[] =
{
  { "XMM0",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM1",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM2",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM3",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM4",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM5",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM6",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM7",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM8",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM9",  REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM10", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM11", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM12", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM13", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM14", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
  { "XMM15", REGISTER_CUSTFMT, X86_RC_XMM, dt_byte16, xmm_format, 0 },
};
register_info_t pc_ri_mxcsr = { "MXCSR", 0, X86_RC_XMM, dt_dword, mxcsr_bits, 0xFFFF };

// MMX registers X86_RC_MMX
register_info_t pc_ri_mm[] =
{
  { "MM0", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM1", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM2", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM3", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM4", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM5", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM6", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
  { "MM7", REGISTER_CUSTFMT, X86_RC_MMX, dt_qword, mmx_format, 0 },
};

// YMM registers X86_RC_YMM
register_info_t pc_ri_ymm[] =
{
  { "YMM0",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM1",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM2",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM3",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM4",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM5",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM6",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM7",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM8",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM9",  REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM10", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM11", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM12", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM13", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM14", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
  { "YMM15", REGISTER_CUSTFMT, X86_RC_YMM, dt_byte32, ymm_format, 0 },
};

//============================================================
// OBSOLETE
//============================================================
//-------------------------------------------------------------------------
// NOTE: keep in sync with register_x86_t
// this register set is used if binary bitness is the same as IDA bitness
// (i.e. ida with 32bit binary or ida64 with 64bit binary)
register_info_t x86_registers[] =
{
  // FPU registers
  { "ST0",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST1",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST2",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST3",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST4",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST5",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST6",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST7",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "CTRL",   0,                            X86_RC_FPU,      dt_word,   ctrlflags,  0x1F3F },
  { "STAT",   0,                            X86_RC_FPU,      dt_word,   statflags,  0xFFFF },
  { "TAGS",   0,                            X86_RC_FPU,      dt_word,   tagsflags,  0xFFFF },

  // Segment registers
  { "CS",     REGISTER_CS|REGISTER_NOLF,    X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "DS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "ES",     0,                            X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "FS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "GS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "SS",     REGISTER_SS,                  X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  // General registers
#ifdef __EA64__
  pc_ri_rax,
  pc_ri_rbx,
  pc_ri_rcx,
  pc_ri_rdx,
  pc_ri_rsi,
  pc_ri_rdi,
  pc_ri_rbp,
  pc_ri_rsp,
  pc_ri_rip,
  pc_ri_r8,
  pc_ri_r9,
  pc_ri_r10,
  pc_ri_r11,
  pc_ri_r12,
  pc_ri_r13,
  pc_ri_r14,
  pc_ri_r15,
#else
  pc_ri_eax,
  pc_ri_ebx,
  pc_ri_ecx,
  pc_ri_edx,
  pc_ri_esi,
  pc_ri_edi,
  pc_ri_ebp,
  pc_ri_esp,
  pc_ri_eip,
#endif
  { "EFL",    0,                            X86_RC_GENERAL,  dt_dword,  eflags,     0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
  // XMM registers
  { "XMM0",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM1",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM2",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM3",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM4",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM5",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM6",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM7",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
#ifdef __EA64__
  { "XMM8",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM9",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM10",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM11",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM12",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM13",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM14",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM15",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
#endif
  { "MXCSR",  0,                            X86_RC_XMM,      dt_dword,  mxcsr_bits, 0xFFFF },
  // MMX registers
  { "MM0",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM1",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM2",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM3",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM4",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM5",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM6",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM7",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  // YMM registers
  { "YMM0",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM1",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM2",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM3",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM4",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM5",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM6",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM7",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
#ifdef __EA64__
  { "YMM8",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM9",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM10",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM11",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM12",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM13",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM14",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM15",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
#endif
};
CASSERT(qnumber(x86_registers) == X86_NREGS);

#ifdef __EA64__
//-------------------------------------------------------------------------
// NOTE: keep in sync with register_x86_x86_t
// this register set is used when ida64 runs 32bit binaries
register_info_t x86_x86_registers[] =
{
  // FPU registers
  { "ST0",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST1",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST2",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST3",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST4",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST5",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST6",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "ST7",    0,                            X86_RC_FPU,      dt_tbyte,  nullptr,    0 },
  { "CTRL",   0,                            X86_RC_FPU,      dt_word,   ctrlflags,  0x1F3F },
  { "STAT",   0,                            X86_RC_FPU,      dt_word,   statflags,  0xFFFF },
  { "TAGS",   0,                            X86_RC_FPU,      dt_word,   tagsflags,  0xFFFF },
  // Segment registers
  { "CS",     REGISTER_CS|REGISTER_NOLF,    X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "DS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "ES",     0,                            X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "FS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "GS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  { "SS",     REGISTER_SS,                  X86_RC_SEGMENTS, dt_word,   nullptr,    0 },
  // General registers
  pc_ri_eax,
  pc_ri_ebx,
  pc_ri_ecx,
  pc_ri_edx,
  pc_ri_esi,
  pc_ri_edi,
  pc_ri_ebp,
  pc_ri_esp,
  pc_ri_eip,
  { "EFL",    0,                            X86_RC_GENERAL,  dt_dword,  eflags,     0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
  // XMM registers
  { "XMM0",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM1",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM2",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM3",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM4",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM5",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM6",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM7",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "MXCSR",  0,                            X86_RC_XMM,      dt_dword,  mxcsr_bits, 0xFFFF },
  // MMX registers
  { "MM0",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM1",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM2",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM3",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM4",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM5",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM6",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM7",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  // YMM registers
  { "YMM0",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM1",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM2",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM3",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM4",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM5",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM6",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM7",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
};
CASSERT(qnumber(x86_x86_registers) == X86_X86_NREGS);
#endif
