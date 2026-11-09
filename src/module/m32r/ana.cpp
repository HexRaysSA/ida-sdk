
#include "m32r.hpp"

struct opcode
{
  int instruction;        // instruction name

// flags for opcode_flags
#define OC_1        0x00000001    // first 4 bits, 0xF000
#define OC_2        0x00000002    // second 4 bits, 0x0F00
#define OC_3        0x00000004    // third 4 bits, 0x00F0
#define OC_4        0x00000008    // last 4 bits, 0x000F

  int opcode_flags;        // flags to situate the operation code (example OC_1|OC_3 : first and third operands)
  int opcode_value;        // value for the operation code

// flags for op[1-3].flags

// operand type
#define OP_REG      0x00000001    // operand is register
#define OP_IMM      0x00000002    // operand is immediate
#define OP_ADDR     0x00000004    // operand is immediate

// operand size
#define OP_S4       0x00000010    // operand is 4 bits long
#define OP_S8       0x00000020    // operand is 8 bits long
#define OP_S16      0x00000040    // operand is 16 bits long
#define OP_S24      0x00000080    // operand is 24 bits long

// operand offset
#define OP_O4       0x00000100     // operand is located at offset 4
#define OP_O8       0x00000200     // operand is located at offset 8
#define OP_O12      0x00000400     // operand is located at offset 12
#define OP_O16      0x00000800     // operand is located at offset 16

// operand phrase type (optional for non-phrase op)
#define OP_PHRASE1  0x00001000    // @R
#define OP_PHRASE2  0x00002000    // @R+
#define OP_PHRASE4  0x00008000    // @+R
#define OP_PHRASE5  0x00010000    // @-R

// displacement argument
#define OP_DISPL_A    0x00004000    // reg in @(imm, reg)
#define OP_DISPL_B    0x00100000    // imm in @(imm, reg)

  int op1_flags;        // first operand flags, if exists
  int op2_flags;        // second operand flags, if exists
  int op3_flags;        // third operand flags, if exists

#define op1     op1_flags
#define op2     op2_flags
#define op3     op3_flags
};

static const opcode opcodes[] =
{
  { m32r_add,       OC_1|OC_3,            0x000A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_add3,      OC_1|OC_3,            0x008A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_addi,      OC_1,                 0x0004,        OP_REG|OP_S4|OP_O4,     OP_IMM|OP_S8|OP_O8,       0                               },
  { m32r_addv,      OC_1|OC_3,            0x0008,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_addv3,     OC_1|OC_3,            0x0088,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_addx,      OC_1|OC_3,            0x0009,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_and,       OC_1|OC_3,            0x000C,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_and3,      OC_1|OC_3,            0x008C,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_bc,        OC_1|OC_2,            0x007C,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32r_bc,        OC_1|OC_2,            0x00FC,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32r_beq,       OC_1|OC_3,            0x00B0,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_ADDR|OP_S16|OP_O16           },
  { m32r_beqz,      OC_1|OC_2|OC_3,       0x0B08,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bgez,      OC_1|OC_2|OC_3,       0x0B0B,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bgtz,      OC_1|OC_2|OC_3,       0x0B0D,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bl,        OC_1|OC_2,            0x007E,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32r_bl,        OC_1|OC_2,            0x00FE,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32r_blez,      OC_1|OC_2|OC_3,       0x0B0C,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bltz,      OC_1|OC_2|OC_3,       0x0B0A,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bnc,       OC_1|OC_2,            0x007D,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32r_bnc,       OC_1|OC_2,            0x00FD,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32r_bne,       OC_1|OC_3,            0x00B1,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_ADDR|OP_S16|OP_O16           },
  { m32r_bnez,      OC_1|OC_2|OC_3,       0x0B09,        OP_REG|OP_S4|OP_O12,    OP_ADDR|OP_S16|OP_O16,    0                               },
  { m32r_bra,       OC_1|OC_2,            0x007F,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32r_bra,       OC_1|OC_2,            0x00FF,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32r_cmp,       OC_1|OC_3,            0x0004,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_cmpi,      OC_1|OC_2|OC_3,       0x0804,        OP_REG|OP_S4|OP_O12,    OP_IMM|OP_S16|OP_O16,     0                               },
  { m32r_cmpu,      OC_1|OC_3,            0x0005,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_cmpui,     OC_1|OC_2|OC_3,       0x0805,        OP_REG|OP_S4|OP_O12,    OP_IMM|OP_S16|OP_O16,     0                               },
  { m32r_div,       OC_1|OC_3,            0x0090,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_divu,      OC_1|OC_3,            0x0091,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_jl,        OC_1|OC_2|OC_3,       0x01EC,        OP_REG|OP_S4|OP_O12,    0,                        0                               },
  { m32r_jmp,       OC_1|OC_2|OC_3,       0x01FC,        OP_REG|OP_S4|OP_O12,    0,                        0                               },
  { m32r_ld,        OC_1|OC_3,            0x002C,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_ld,        OC_1|OC_3,            0x002E,        OP_REG|OP_S4|OP_O4,     OP_PHRASE2|OP_S4|OP_O12,  0                               },
  { m32r_ld,        OC_1|OC_3,            0x00AC,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_ld24,      OC_1,                 0x000E,        OP_REG|OP_S4|OP_O4,     OP_IMM|OP_S24|OP_O8,      0                               },
  { m32r_ldb,       OC_1|OC_3,            0x0028,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_ldb,       OC_1|OC_3,            0x00A8,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_ldh,       OC_1|OC_3,            0x002A,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_ldh,       OC_1|OC_3,            0x00AA,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_ldi,       OC_1,                 0x0006,        OP_REG|OP_S4|OP_O4,     OP_IMM|OP_S8|OP_O8,       0                               },
  { m32r_ldi,       OC_1|OC_3|OC_4,       0x09F0,        OP_REG|OP_S4|OP_O4,     OP_IMM|OP_S16|OP_O16,     0                               },
  { m32r_ldub,      OC_1|OC_3,            0x0029,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_ldub,      OC_1|OC_3,            0x00A9,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_lduh,      OC_1|OC_3,            0x002B,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_lduh,      OC_1|OC_3,            0x00AB,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_lock,      OC_1|OC_3,            0x002D,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_machi,     OC_1|OC_3,            0x0034,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_maclo,     OC_1|OC_3,            0x0035,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_macwhi,    OC_1|OC_3,            0x0036,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_macwlo,    OC_1|OC_3,            0x0037,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mul,       OC_1|OC_3,            0x0016,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mulhi,     OC_1|OC_3,            0x0030,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mullo,     OC_1|OC_3,            0x0031,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mulwhi,    OC_1|OC_3,            0x0032,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mulwlo,    OC_1|OC_3,            0x0033,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mv,        OC_1|OC_3,            0x0018,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mvfachi,   OC_1|OC_3|OC_4,       0x05F0,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32r_mvfaclo,   OC_1|OC_3|OC_4,       0x05F1,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32r_mvfacmi,   OC_1|OC_3|OC_4,       0x05F2,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32r_mvfc,      OC_1|OC_3,            0x0019,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_mvtachi,   OC_1|OC_3|OC_4,       0x0570,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32r_mvtaclo,   OC_1|OC_3|OC_4,       0x0571,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32r_mvtc,      OC_1|OC_3,            0x001A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_neg,       OC_1|OC_3,            0x0003,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_nop,       OC_1|OC_2|OC_3|OC_4,  0x7000,        0,                      0,                        0                               },
  { m32r_not,       OC_1|OC_3,            0x000B,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_or,        OC_1|OC_3,            0x000E,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_or3,       OC_1|OC_3,            0x008E,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_rac,       OC_1|OC_2|OC_3|OC_4,  0x5090,        0,                      0,                        0                               },
  { m32r_rach,      OC_1|OC_2|OC_3|OC_4,  0x5080,        0,                      0,                        0                               },
  { m32r_rem,       OC_1|OC_3,            0x0092,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_remu,      OC_1|OC_3,            0x0093,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_rte,       OC_1|OC_2|OC_3|OC_4,  0x10D6,        0,                      0,                        0                               },
  { m32r_seth,      OC_1|OC_3|OC_4,       0x0DC0,        OP_REG|OP_S4|OP_O4,     OP_IMM|OP_S16|OP_O16,     0                               },
  { m32r_sll,       OC_1|OC_3,            0x0014,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_sll3,      OC_1|OC_3,            0x009C,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_sra,       OC_1|OC_3,            0x0012,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_sra3,      OC_1|OC_3,            0x009A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
#if 0
  { m32r_srai,    OC_1|OC_3,            0x0051    },    // Shirt right arithmetic immediate
  { m32r_slli,    OC_1|OC_3,            0x0082    },    // Shift left logical immediate
  { m32r_srli,    OC_1|OC_3,            0x0050    },    // Shift right logical immediate
#endif
  { m32r_srl,       OC_1|OC_3,            0x0010,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_srl3,      OC_1|OC_3,            0x0098,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },
  { m32r_st,        OC_1|OC_3,            0x0024,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_st,        OC_1|OC_3,            0x0026,        OP_REG|OP_S4|OP_O4,     OP_PHRASE4|OP_S4|OP_O12,  0                               },
  { m32r_st,        OC_1|OC_3,            0x0027,        OP_REG|OP_S4|OP_O4,     OP_PHRASE5|OP_S4|OP_O12,  0                               },
  { m32r_st,        OC_1|OC_3,            0x00A4,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_stb,       OC_1|OC_3,            0x0020,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_stb,       OC_1|OC_3,            0x00A0,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_sth,       OC_1|OC_3,            0x0022,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_sth,       OC_1|OC_3,            0x0023,        OP_REG|OP_S4|OP_O4,     OP_PHRASE2|OP_S4|OP_O12,  0                               }, // guessed, see mail from David.Ward@ecutek.com
  { m32r_sth,       OC_1|OC_3,            0x00A2,        OP_REG|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_sub,       OC_1|OC_3,            0x0002,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_subv,      OC_1|OC_3,            0x0000,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_subx,      OC_1|OC_3,            0x0001,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_trap,      OC_1|OC_2|OC_3,       0x010F,        OP_IMM|OP_S4|OP_O12,    0,                        0                               },
  { m32r_unlock,    OC_1|OC_3,            0x0025,        OP_REG|OP_S4|OP_O4,     OP_PHRASE1|OP_S4|OP_O12,  0                               },
  { m32r_xor,       OC_1|OC_3,            0x000D,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32r_xor3,      OC_1|OC_3,            0x008D,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      OP_IMM|OP_S16|OP_O16            },

  { m32r_setpsw,    OC_1|OC_2,            0x0071,        OP_IMM|OP_S8|OP_O8,     0,                        0                               },
  { m32r_clrpsw,    OC_1|OC_2,            0x0072,        OP_IMM|OP_S8|OP_O8,     0,                        0                               },
  { m32r_bset,      OC_1|OC_3,            0x00A6,        OP_IMM|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_bclr,      OC_1|OC_3,            0x00A7,        OP_IMM|OP_S4|OP_O4,     OP_DISPL_A|OP_S4|OP_O12,  OP_DISPL_B|OP_S16|OP_O16        },
  { m32r_btst,      OC_1|OC_3,            0x000F,        OP_IMM|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
};

// M32RX additional opcodes :
static const opcode ext_opcodes[] =
{
  { m32rx_bcl,      OC_1|OC_2,            0x0078,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32rx_bcl,      OC_1|OC_2,            0x00F8,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32rx_bncl,     OC_1|OC_2,            0x0079,        OP_ADDR|OP_S8|OP_O8,    0,                        0                               },
  { m32rx_bncl,     OC_1|OC_2,            0x00F9,        OP_ADDR|OP_S24|OP_O8,   0,                        0                               },
  { m32rx_cmpeq,    OC_1|OC_3,            0x0006,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_cmpz,     OC_1|OC_2|OC_3,       0x0007,        OP_REG|OP_S4|OP_O12,    0,                        0                               },
  { m32rx_mulwu1,   OC_1|OC_3,            0x005A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_macwu1,   OC_1|OC_3,            0x005B,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_maclh1,   OC_1|OC_3,            0x005C,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_msblo,    OC_1|OC_3,            0x005D,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_sadd,     OC_1|OC_2|OC_3|OC_4,  0x50E4,        0,                      0,                        0                               },
  { m32rx_sat,      OC_1|OC_3,            0x0086,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
#if 0
  { m32rx_divh,      OC_1|OC_3,            0x0090,        OP_REG|OP_S4|OP_O4,       OP_REG|OP_S4|OP_O12,      0                                 },
#endif
  { m32rx_mulhi,    OC_1|OC_3,            0x0038,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_mullo,    OC_1|OC_3,            0x0039,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_machi,    OC_1|OC_3,            0x003C,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_maclo,    OC_1|OC_3,            0x003D,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_mvfachi,  OC_1|OC_3|OC_4,       0x05F4,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32rx_mvfaclo,  OC_1|OC_3|OC_4,       0x05F5,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32rx_mvfacmi,  OC_1|OC_3|OC_4,       0x05F6,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32rx_mvtachi,  OC_1|OC_3|OC_4,       0x0574,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32rx_mvtaclo,  OC_1|OC_3|OC_4,       0x0575,        OP_REG|OP_S4|OP_O4,     0,                        0                               },
  { m32rx_sc,       OC_1|OC_2|OC_3|OC_4,  0x7401,        0,                      0,                        0                               },
  { m32rx_snc,      OC_1|OC_2|OC_3|OC_4,  0x7501,        0,                      0,                        0                               },
  { m32rx_jc,       OC_1|OC_2|OC_3,       0x01CC,        OP_REG|OP_S4|OP_O12,    0,                        0                               },
  { m32rx_jnc,      OC_1|OC_2|OC_3,       0x01DC,        OP_REG|OP_S4|OP_O12,    0,                        0                               },
  { m32rx_mulwhi,   OC_1|OC_3,            0x003A,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_mulwlo,   OC_1|OC_3,            0x003B,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_macwhi,   OC_1|OC_3,            0x003E,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_macwlo,   OC_1|OC_3,            0x003F,        OP_REG|OP_S4|OP_O4,     OP_REG|OP_S4|OP_O12,      0                               },
  { m32rx_pcmpbz,   OC_1|OC_2|OC_3,       0x0037,        OP_REG|OP_S4|OP_O12,    0,                        0                               }
};

//----------------------------------------------------------------------------
// get size of this operand (in bits)
static int get_size(int op)
{
  if ( op & OP_S4 )
    return 4;
  if ( op & OP_S8 )
    return 8;
  if ( op & OP_S16 )
    return 16;
  if ( op & OP_S24 )
    return 24;

  return 0;
}

//----------------------------------------------------------------------------
// get size of this instruction (in bits)
static int get_insn_size(const opcode *oc)
{
  int s = 0;

  if ( oc->opcode_flags & OC_1 )
    s += 4;
  if ( oc->opcode_flags & OC_2 )
    s += 4;
  if ( oc->opcode_flags & OC_3 )
    s += 4;
  if ( oc->opcode_flags & OC_4 )
    s += 4;

  if ( oc->op1 != 0 )
    s += get_size(oc->op1);
  if ( oc->op2 != 0 )
    s += get_size(oc->op2);
  if ( oc->op3 != 0 )
    s += get_size(oc->op3);

  return s;
}

//----------------------------------------------------------------------------
// get value of target operand in target operation code
static int get_offset(int word, int word2, int size, int op)
{
  if ( op & OP_O4 )
  {
    switch ( size )
    {
      case 4:     return (word & 0x0F00) >> 8;
      default:    INTERR(10195);
    }
  }
  if ( op & OP_O8 )
  {
    switch ( size )
    {
      case 4:     return (word & 0x00F0) >> 4;
      case 8:     return word & 0x00FF;
      case 24:    return ((word & 0x00FF) << 16) + (word2 & 0xFFFF);
      default:    INTERR(10196);
    }
  }
  if ( op & OP_O12 )
  {
    switch ( size )
    {
      case 4:     return word & 0x000F;
      default:    INTERR(10197);
    }
  }
  if ( op & OP_O16 )
  {
    switch ( size )
    {
      case 16:    return word2 & 0xFFFF;
      default:    INTERR(10198);
    }
  }

  INTERR(10199);
}

//----------------------------------------------------------------------------
// return the corresponding dt_xxx element for a specified size (in bits)
static inline uchar bits2dt(int size)
{
  switch ( size )
  {
    case 4:  return dt_byte;
    case 8:  return dt_byte;
    case 16: return dt_word;
    case 24: return dt_dword;
  }

  INTERR(10200);
}

//----------------------------------------------------------------------------
// swap 2 opcodes (o1 <=> o2)
static inline void swap_op(op_t &o1, op_t &o2)
{
  op_t tmp = o1;
  o1 = o2;
  o2 = tmp;
}

//----------------------------------------------------------------------------
// convert a general-purpose register to a control register
static uint16 r2cr(int reg)
{
  switch ( reg )
  {
    case rR0: return rCR0;
    case rR1: return rCR1;
    case rR2: return rCR2;
    case rR3: return rCR3;
    case rR6: return rCR6;
    case rR7: return rCR7;
  }
  return ushort(-1);
}

//----------------------------------------------------------------------------
// initialize a register operand
inline void set_reg(op_t &op, uint16 reg)
{
  op.type = o_reg;
  op.reg = reg;
  // all m32r registers are 32 bits long
  op.dtype = dt_word;
}

#define sign_extend(x) ( ( ( signed ) ( (x) << 8 ) ) >> 8 )

//----------------------------------------------------------------------------
// fill a target insn-operand structure with fresh data
static void set_arg(const insn_t &insn, int word, int word2, op_t &op, int oc)
{
  int size = get_size(oc);
  int val = get_offset(word, word2, size, oc);

  if ( oc & OP_REG )
  {
    set_reg(op, (uint16)val);
  }
  else if ( oc & OP_IMM )
  {
    op.type = o_imm;
    switch ( size )
    {
      case 4:
      case 8:
        op.value = (signed char) val;
        break;
      case 16:
        op.value = (signed short) val;
        break;
      case 24:
        op.value = val & 0x00ffffff;
        break;
      default:
        INTERR(10201);
    }
    op.dtype = bits2dt(size);
  }
  else if ( oc & OP_ADDR )
  {
    op.type = o_near;
    switch ( size )
    {
      case 8:
        op.addr = (signed char) val;
        break;
      case 16:
        op.addr = (signed short) val;
        break;
      case 24:
        op.addr = sign_extend(val);
        break;
      default:
        INTERR(10202);
    }
    op.addr <<= 2;
    op.addr += insn.ip & 0xfffffffc;
    op.dtype = dt_code;
  }
  else if ( oc & OP_PHRASE1 )       // @R
  {
    op.type = o_phrase;
    op.specflag1 = fRI;
    op.reg = uint16(val);
  }
  else if ( oc & OP_PHRASE2 )       // @R+
  {
    op.type = o_phrase;
    op.specflag1 = fRIBA;
    op.reg = uint16(val);
  }
  else if ( oc & OP_DISPL_A )       // reg in @(imm, reg )
  {
    op.type = o_displ;
    op.reg = uint16(val);
  }
  else if ( oc & OP_DISPL_B )       // imm in @(imm, reg )
  {
    op.type = o_displ;
    op.addr = (signed short) val;
  }
  else if ( oc & OP_PHRASE4 )       // @+R
  {
    op.type = o_phrase;
    op.specflag1 = fRIAA;
    op.reg = uint16(val);
  }
  else if ( oc & OP_PHRASE5 )       // @-R
  {
    op.type = o_phrase;
    op.specflag1 = fRIAS;
    op.reg = uint16(val);
  }
  else
  {
    INTERR(10203);
  }
}

//----------------------------------------------------------------------------
static int get_code(const opcode *op, int word)
{
  int code = 0;

  if ( op->opcode_flags & OC_1 )
    code = (code << 4) + ((word & 0xF000) >> 12);
  if ( op->opcode_flags & OC_2 )
    code = (code << 4) + ((word & 0x0F00) >> 8);
  if ( op->opcode_flags & OC_3 )
    code = (code << 4) + ((word & 0x00F0) >> 4);
  if ( op->opcode_flags & OC_4 )
    code = (code << 4) + ((word & 0x000F) >> 0);
  return code;
}

//----------------------------------------------------------------------------
// from the first picked word, scan the opcode table and return the corresponding entry (if exists)
const opcode *m32r_t::get_opcode(int word) const
{
  for ( int i = 0; i < qnumber(opcodes); i++ )
    if ( opcodes[i].opcode_value == get_code(&opcodes[i], word) )
      return &opcodes[i];

  if ( ptype == prc_m32rx )
  {
    for ( int i = 0; i < qnumber(ext_opcodes); i++ )
    {
      if ( ext_opcodes[i].opcode_value == get_code(&ext_opcodes[i], word) )
        return &ext_opcodes[i];
    }
  }
  return nullptr;
}

//----------------------------------------------------------------------------
// analyze a special instruction
bool m32r_t::ana_special(insn_t &insn, int word, int *s) const
{
  bool special = false;

  // srli, srai, and slli are 3 special instructions, with this kind of opcode format :
  // 0101 dest 000 imm5 (SRLI)
  // 0101 dest 001 imm5 (SRAI)
  // 0101 dest 010 imm5 (SLLI)
  if ( ((word & 0xF000) >> 12) == 5 )
  {
    int imm5 = word & 0x1F;
    uint16 reg = (word & 0x0F00) >> 8;
    switch ( (word & /*0x0070*/ 0x00F0) >> 5 )
    {
      case 0:
        special = true;
        insn.itype = m32r_srli;
        break;
      case 1:
        special = true;
        insn.itype = m32r_srai;
        break;
      case 2:
        special = true;
        insn.itype = m32r_slli;
        break;
    }
    if ( special )
    {
      insn.Op1.type = o_reg;
      insn.Op1.reg = reg;
      insn.Op2.type = o_imm;
      insn.Op2.value = imm5;
      *s = 16;
      return true;
    }
  }

  // detect m32rx rac/rach instructions
  if ( ptype == prc_m32rx )
  {
    int v = (word & 0x00F0) >> 4;
    uint16 itype = (v == 9 ? m32rx_rac : v == 8 ? m32rx_rach : -1);

    if ( itype == uint16(-1) )
      return false;

    switch ( word & 0xFF0F )
    {
      // rac[h] a1
      case 0x5400:
        set_reg(insn.Op1, rA1);
        special = true;
        break;

      // rac[h] a0, a1
      case 0x5004:
        set_reg(insn.Op1, rA0);
        set_reg(insn.Op2, rA1);
        special = true;
        break;

      // rac[h] a1, a1
      case 0x5404:
        set_reg(insn.Op1, rA1);
        set_reg(insn.Op2, rA1);
        special = true;
        break;

      // rac[h] a0, a1, #2
      case 0x5005:
        set_reg(insn.Op1, rA0);
        set_reg(insn.Op2, rA1);
        insn.Op3.type = o_imm;
        insn.Op3.value = 2;
        insn.Op3.dtype = dt_byte;
        special = true;
        break;

      // rac[h] a1, a0, #2
      case 0x5401:
        set_reg(insn.Op1, rA1);
        set_reg(insn.Op2, rA0);
        insn.Op3.type = o_imm;
        insn.Op3.value = 2;
        insn.Op3.dtype = dt_byte;
        special = true;
        break;
    }

    if ( special )
    {
      insn.itype = itype;
      return true;
    }
  }

  return false;
}

//----------------------------------------------------------------------------
int m32r_t::parse_fp_insn(insn_t &insn, int word)
{
  static const ushort fp_itypes[] =
  {
    m32r_fadd, m32r_fmul, m32r_fdiv, m32r_fmadd,  // 0
    m32r_itof, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 1
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 2
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 3
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_fsub, m32r_null, m32r_null, m32r_fmsub,  // 4
    m32r_utof, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 5
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 6
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 7
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 8
    m32r_ftoi, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // 9
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // A
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // B
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_fcmp, m32r_null, m32r_null, m32r_null,   // C
    m32r_ftos, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_fcmpe,m32r_null, m32r_null, m32r_null,   // D
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // E
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,   // F
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
    m32r_null, m32r_null, m32r_null, m32r_null,
  };
  int word2 = insn.get_next_word();
  int idx = (word2 & 0x00F0) | (word2 >> 12);
  if ( idx >= qnumber(fp_itypes) )    //-V547 always false
    return 0;
  insn.itype = fp_itypes[idx];
  if ( insn.itype == m32r_null )
    return 0;
  set_reg(insn.Op1, (word2 >> 8) & 0xF);
  set_reg(insn.Op2, (word  >> 8) & 0xF);
  int f = insn.get_canon_feature(ph);
  if ( (f & CF_USE3) == 0 )
  {
    if ( (word & 0xF) != 0 )
      return 0;
  }
  else
  {
    set_reg(insn.Op3, word & 0xF);
  }
  return insn.size;
}

//----------------------------------------------------------------------------
// decode an instruction
int m32r_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

//#define CHECK_OPCODES
#ifdef CHECK_OPCODES
  for ( int i=0; i < qnumber(opcodes); i++ )
  {
    int s = get_insn_size(&opcodes[i]);
    if ( s != 16 && s != 32 )
      error("wrong opcode template %d", i);
  }
#endif

  int word, word2 = 0, s = 0;

  word = insn.get_next_word();

  // if the MSB if 1 and the current address NOT divisible by 4, then remove the MSB
  if ( ((word & 0x8000) >> 15) == 1 )
  {
    if ( insn.ea % 4 != 0 )
    {
      word &= 0x7FFF;
    }
  }

  if ( (word & 0xF0F0) == 0xD000 )
    return parse_fp_insn(insn, word);

  bool special = ana_special(insn, word, &s);

  if ( !special )
  {
    // retrieve the corresponding opcode struct entry
    const opcode *oc = get_opcode(word);
    if ( oc == nullptr )
      return 0;

    // fill the insn name
    insn.itype = (uint16)oc->instruction;

    // compute the size of our operation code
    s = get_insn_size(oc);

    // size must be either 16 or 32 bits long
    if ( s != 16 && s != 32 )
      INTERR(10204);

    // 32 bits ? we need to pick an another word
    if ( s == 32 )
      word2 = insn.get_next_word();

    // those '16-bit' instructions are always followed by an another word
    // (which is specified in the array).
    // this code will check if the next word has the right value, according
    // to the current instruction.

    struct doubleword_insn_t
    {
      uint16 insn;
      uint16 word;
    };
    static const doubleword_insn_t sinsn[] =
    {
      { m32r_div,   0x0000 },
      { m32r_divu,  0x0000 },
      { m32r_rem,   0x0000 },
      { m32r_remu,  0x0000 },
      { m32rx_sat,  0x0000 },
      { m32rx_satb, 0x0300 },
      { m32rx_sath, 0x0200 },
      { m32rx_divh, 0x0010 },
    };

    if ( s == 16 )
    {
      for ( int i = 0; i < qnumber(sinsn); i++ )
      {
        if ( sinsn[i].insn != insn.itype )
          continue;

        word2 = get_word(insn.ea + 2);
        if ( word2 != sinsn[i].word )
        {
          // second chance for div
          if ( insn.itype == m32r_div )
          {
            insn.itype = m32rx_divh;
            continue;
          }

          // second chance for sat
          if ( insn.itype == m32rx_sat )
          {
            insn.itype = m32rx_satb;
            continue;
          }

          // second chance for satb
          if ( insn.itype == m32rx_satb )
          {
            insn.itype = m32rx_sath;
            continue;
          }
          return 0;
        }
        word2 = insn.get_next_word();
        s += 16;
        break;
      }
    }

    // fill the appropriate operands of the insn structure
    if ( oc->op1 != 0 )
      set_arg(insn, word, word2, insn.Op1, oc->op1);
    if ( oc->op2 != 0 )
      set_arg(insn, word, word2, insn.Op2, oc->op2);
    if ( oc->op3 != 0 )
    {
      // @(imm, reg) : fill the second operand
      if ( oc->op3 & OP_DISPL_B )
        set_arg(insn, word, word2, insn.Op2, oc->op3);
      else
        set_arg(insn, word, word2, insn.Op3, oc->op3);
    }

    // Additionnal code
    switch ( oc->instruction )
    {
      // instructions mvfc - mvtc uses control registers
      case m32r_mvtc:
        swap_op(insn.Op1, insn.Op2);
        // no break
      case m32r_mvfc:
        insn.Op2.reg = r2cr(insn.Op2.reg);
        if ( insn.Op2.reg == ushort(-1) )
          return 0;
        break;

      // some of the m32rx instructions uses accumulator registers
      case m32rx_mulhi:
      case m32rx_mullo:
      case m32rx_machi:
      case m32rx_maclo:
      case m32rx_mvfachi:
      case m32rx_mvfaclo:
      case m32rx_mvfacmi:
      case m32rx_mvtachi:
      case m32rx_mvtaclo:
      case m32rx_mulwhi:
      case m32rx_mulwlo:
      case m32rx_macwhi:
      case m32rx_macwlo:
        insn.Op3.type = o_reg;
        insn.Op3.reg = rA1;        // this is the default
        insn.Op3.dtype = dt_dword;
        break;

      // synthetic instructions
      case m32r_bc:
      case m32r_bl:
      case m32r_bnc:
      case m32r_bra:
      case m32r_ldi:
        insn.segpref |= (s == 16 ? SYNTHETIC_SHORT : SYNTHETIC_LONG);
        break;

      case m32r_st:
        if ( insn.Op2.specflag1 == fRIAS && insn.Op2.reg == rSP )
        {
          insn.itype = (use_synthetic_insn() ? m32r_push : m32r_st);
          insn.Op2.type = (use_synthetic_insn() ? o_void : o_phrase);
        }
        break;
      case m32r_ld:
        if ( insn.Op2.specflag1 == fRIBA && insn.Op2.reg == rSP )
        {
          insn.itype = (use_synthetic_insn() ? m32r_pop : m32r_ld);
          insn.Op2.type = (use_synthetic_insn() ? o_void : o_phrase);
        }
        break;
    }
  }

  // detect parallel NOP / DSP instructions
  if ( s == 16 && (insn.ea % 4) == 0 )
  {
    int b = get_word(insn.ea + insn.size);

    if ( ((b & 0x8FFF) >> 15) == 1 )
    {
      // next opcode is NOP
      if ( b == 0xF000 )
      {
        insn.size += 2;
        insn.segpref |= NEXT_INSN_PARALLEL_NOP;
      }
      // this opcode is NOP, the next should be a DSP insn
      else if ( word == 0x7000 )
      {
        // recall the analyzer (and therefore erase the current NOP)
        ana(&insn);
        // flag the DSP instruction
        insn.segpref |= NEXT_INSN_PARALLEL_DSP;
      }
      else
      {
        insn_t insn2;
        decode_insn(&insn2, insn.ea + insn.size);
        if ( insn2.size == 2 )
          insn.segpref |= NEXT_INSN_PARALLEL_OTHER;
      }
    }
  }
  return insn.size;
}
