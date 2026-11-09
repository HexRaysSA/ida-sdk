
#include "fr.hpp"

// distinct sizes :
//lint -esym(749, S_11) not referenced
enum
{
  S_0,
  S_4,        // 4 bits
  S_5,        // 5 bits
  S_8,        // 8 bits
  S_11,       // 11 bits
  S_12,       // 12 bits
  S_16        // 16 bits
};

// bits numbers for sizes :
const int bits[] =
{
  0,
  4,
  5,
  8,
  11,
  12,
  16
};

// masks for sizes :
const int masks[] =
{
  0x0000,
  0x000F,
  0x001F,
  0x00FF,
  0x07FF,
  0x0FFF,
  0xFFFF
};

const char dtypes[] =
{
  0,
  dt_byte,
  dt_byte,
  dt_byte,
  dt_word,
  dt_word,
  dt_word
};

// distinct operands :
enum
{
  O_null,         // null opcode
  O_gr,           // general register                         Ri
  O_gri,          // general register indirect                @Ri
  O_grip,         // general register indirect post-increment @Ri+
  O_r13_gr_i,     // indirect r13 + general register          @(R13, Ri)
  O_r14_imm8_i,   // indirect r14 + 8 bits immediate value    @(R14, imm)
  O_r15_imm4_i,   // indirect r15 + 4 bits immediate value    @(R15, imm)
  O_r15ip,        // indirect r15 post-increment              @R15+
  O_r15im,        // indirect r15 pre-decrement               @-R15
  O_r13,          // register r13                             R13
  O_r13ip,        // indirect r13 post-increment              @R13+
  O_dr,           // dedicated register                       Rs
  O_ps,           // program status register (PS)             PS
  O_imm,          // immediate value                          #i
  O_diri,         // indirect direct value                    @i
  O_rel,          // relative value                           label5
  O_reglist       // register list                            (R0, R1, R2, ...)
};

static int invert_word(int word)
{
  int new_word = 0;

  new_word |= (word & 0x000F) >> 0;
  new_word <<= 4;
  new_word |= (word & 0x00F0) >> 4;
  new_word <<= 4;
  new_word |= (word & 0x0F00) >> 8;
  new_word <<= 4;
  new_word |= (word & 0xF000) >> 12;

  return new_word;
}

// structure of an opcode :
struct opcode_t
{
  int itype;
  int opcode;
  int opcode_size;

  int op1;
  int op1_size;
  int op2;
  int op2_size;

#define I_SWAPOPS          0x00000100      // swap operands
#define I_DSHOT            0x00000200      // delay shot
#define I_ADDR_R           OP_ADDR_R
#define I_ADDR_W           OP_ADDR_W
#define I_IMM_2            0x00001000      // imm = imm * 2
#define I_IMM_4            0x00002000      // imm = imm * 4
  int flags;

  inline bool swap_ops(void) const { return (flags & I_SWAPOPS) != 0; }
  inline bool delay_shot(void) const { return (flags & I_DSHOT) != 0; }
  inline bool implied(void) const { return op1 == O_null && op2 == O_null; }

  int size(void) const
  {
    int n = bits[opcode_size];
    if ( op1 != O_null )
      n += bits[op1_size];
    if ( op2 != O_null )
      n += bits[op2_size];
    return n;
  }

  static void check(void);
  static const struct opcode_t *find(insn_t &insn, int *_data);
};

// FR opcodes :
static const struct opcode_t opcodes[] =
{
  { fr_add,       0xA6,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_add,       0xA4,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_add2,      0xA5,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_addc,      0xA7,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_addn,      0xA2,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_addn,      0xA0,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_addn2,     0xA1,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_sub,       0xAC,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_subc,      0xAD,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_subn,      0xAE,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_cmp,       0xAA,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_cmp,       0xA8,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_cmp2,      0xA9,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_and,       0x82,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_and,       0x84,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_andh,      0x85,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_andb,      0x86,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_or,        0x92,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_or,        0x94,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_orh,       0x95,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_orb,       0x96,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_eor,       0x9A,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_eor,       0x9C,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_eorh,      0x9D,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_eorb,      0x9E,       S_8,    O_gr,           S_4,    O_gri,      S_4,        0         },
  { fr_bandl,     0x80,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_bandh,     0x81,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_borl,      0x90,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_borh,      0x91,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_beorl,     0x98,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_beorh,     0x99,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_btstl,     0x88,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_btsth,     0x89,       S_8,    O_imm,          S_4,    O_gri,      S_4,        0         },
  { fr_mul,       0xAF,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_mulu,      0xAB,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_mulh,      0xBF,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_muluh,     0xBB,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_div0s,     0x974,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_div0u,     0x975,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_div1,      0x976,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_div2,      0x977,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_div3,      0x9F60,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_div4s,     0x9F70,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_lsl,       0xB6,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_lsl,       0xB4,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_lsl2,      0xB5,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_lsr,       0xB2,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_lsr,       0xB0,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_lsr2,      0xB1,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_asr,       0xBA,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_asr,       0xB8,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  { fr_asr2,      0xB9,       S_8,    O_imm,          S_4,    O_gr,       S_4,        0         },
  // fr_ldi_32 not here (considered as special)
  // fr_ldi_20 not here (considered as special)
  { fr_ldi_8,     0x0C,       S_4,    O_imm,          S_8,    O_gr,       S_4,        0         },
  { fr_ld,        0x04,       S_8,    O_gri,          S_4,    O_gr,       S_4,        0         },
  { fr_ld,        0x00,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        0         },
  { fr_ld,        0x02,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        I_IMM_4   },
  { fr_ld,        0x03,       S_8,    O_r15_imm4_i,   S_4,    O_gr,       S_4,        I_IMM_4   },
  { fr_ld,        0x70,       S_12,   O_r15ip,        S_0,    O_gr,       S_4,        0         },
  { fr_ld,        0x78,       S_12,   O_r15ip,        S_0,    O_dr,       S_4,        0         },
  { fr_ld,        0x790,      S_16,   O_r15ip,        S_0,    O_ps,       S_0,        0         },
  { fr_lduh,      0x05,       S_8,    O_gri,          S_4,    O_gr,       S_4,        0         },
  { fr_lduh,      0x01,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        0         },
  { fr_lduh,      0x04,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        I_IMM_2   },
  { fr_ldub,      0x06,       S_8,    O_gri,          S_4,    O_gr,       S_4,        0         },
  { fr_ldub,      0x02,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        0         },
  { fr_ldub,      0x06,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        0         },
  { fr_st,        0x14,       S_8,    O_gri,          S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_st,        0x10,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_st,        0x03,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        I_SWAPOPS|I_IMM_4 },
  { fr_st,        0x13,       S_8,    O_r15_imm4_i,   S_4,    O_gr,       S_4,        I_SWAPOPS|I_IMM_4 },
  { fr_st,        0x170,      S_12,   O_gr,           S_4,    O_r15im,    S_0,        0         },
  { fr_st,        0x178,      S_12,   O_dr,           S_4,    O_r15im,    S_0,        0         },
  { fr_st,        0x1790,     S_16,   O_ps,           S_0,    O_r15im,    S_0,        0         },
  { fr_sth,       0x15,       S_8,    O_gri,          S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_sth,       0x11,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_sth,       0x05,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        I_SWAPOPS|I_IMM_2 },
  { fr_stb,       0x16,       S_8,    O_gri,          S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_stb,       0x12,       S_8,    O_r13_gr_i,     S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_stb,       0x07,       S_4,    O_r14_imm8_i,   S_8,    O_gr,       S_4,        I_SWAPOPS },
  { fr_mov,       0x8B,       S_8,    O_gr,           S_4,    O_gr,       S_4,        0         },
  { fr_mov,       0xB7,       S_8,    O_dr,           S_4,    O_gr,       S_4,        0         },
  { fr_mov,       0x171,      S_12,   O_ps,           S_0,    O_gr,       S_4,        0         },
  { fr_mov,       0xB3,       S_8,    O_dr,           S_4,    O_gr,       S_4,        I_SWAPOPS },
  { fr_mov,       0x71,       S_12,   O_gr,           S_4,    O_ps,       S_0,        0         },
  { fr_jmp,       0x970,      S_12,   O_gri,          S_4,    O_null,     0,          0         },
  { fr_call,      0x971,      S_12,   O_gri,          S_4,    O_null,     0,          0         },
  { fr_ret,       0x9720,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_int,       0x1F,       S_8,    O_imm,          S_8,    O_null,     0,          0         },
  { fr_inte,      0x9F30,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_reti,      0x9730,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_bra,       0xE0,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bno,       0xE1,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_beq,       0xE2,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bne,       0xE3,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bc,        0xE4,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bnc,       0xE5,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bn,        0xE6,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bp,        0xE7,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bv,        0xE8,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bnv,       0xE9,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_blt,       0xEA,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bge,       0xEB,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_ble,       0xEC,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bgt,       0xED,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bls,       0xEE,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_bhi,       0xEF,       S_8,    O_rel,          S_8,    O_null,     0,          0         },
  { fr_jmp,       0x9F0,      S_12,   O_gri,          S_4,    O_null,     0,          I_DSHOT   },
  { fr_call,      0x9F1,      S_12,   O_gri,          S_4,    O_null,     0,          I_DSHOT   },
  { fr_ret,       0x9F20,     S_16,   O_null,         0,      O_null,     0,          I_DSHOT   },
  { fr_bra,       0xF0,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bno,       0xF1,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_beq,       0xF2,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bne,       0xF3,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bc,        0xF4,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bnc,       0xF5,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bn,        0xF6,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bp,        0xF7,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bv,        0xF8,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bnv,       0xF9,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_blt,       0xFA,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bge,       0xFB,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_ble,       0xFC,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bgt,       0xFD,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bls,       0xFE,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_bhi,       0xFF,       S_8,    O_rel,          S_8,    O_null,     0,          I_DSHOT   },
  { fr_dmov,      0x08,       S_8,    O_diri,         S_8,    O_r13,      S_0,        I_ADDR_R  },
  { fr_dmov,      0x18,       S_8,    O_r13,          S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmov,      0x0C,       S_8,    O_diri,         S_8,    O_r13ip,    S_0,        I_ADDR_R  },
  { fr_dmov,      0x1C,       S_8,    O_r13ip,        S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmov,      0x0B,       S_8,    O_diri,         S_8,    O_r15im,    S_0,        I_ADDR_R  },
  { fr_dmov,      0x1B,       S_8,    O_r15ip,        S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmovh,     0x09,       S_8,    O_diri,         S_8,    O_r13,      S_0,        I_ADDR_R  },
  { fr_dmovh,     0x19,       S_8,    O_r13,          S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmovh,     0x0D,       S_8,    O_diri,         S_8,    O_r13ip,    S_0,        I_ADDR_R  },
  { fr_dmovh,     0x1D,       S_8,    O_r13ip,        S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmovb,     0x0A,       S_8,    O_diri,         S_8,    O_r13,      S_0,        I_ADDR_R  },
  { fr_dmovb,     0x1A,       S_8,    O_r13,          S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_dmovb,     0x0E,       S_8,    O_diri,         S_8,    O_r13ip,    S_0,        I_ADDR_R  },
  { fr_dmovb,     0x1E,       S_8,    O_r13ip,        S_0,    O_diri,     S_8,        I_ADDR_W  },
  { fr_ldres,     0xBC,       S_8,    O_imm,          S_4,    O_grip,     S_4,        I_SWAPOPS },
  { fr_stres,     0xBD,       S_8,    O_imm,          S_4,    O_grip,     S_4,        0         },
  // fr_copop not here (considered as special)
  // fr_copld not here (considered as special)
  // fr_copst not here (considered as special)
  // fr_copsv not here (considered as special)
  { fr_nop,       0x9FA0,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_andccr,    0x83,       S_8,    O_imm,          S_8,    O_null,     0,          0         },
  { fr_orccr,     0x93,       S_8,    O_imm,          S_8,    O_null,     0,          0         },
  { fr_stilm,     0x87,       S_8,    O_imm,          S_8,    O_null,     0,          0         },
  { fr_addsp,     0xA3,       S_8,    O_imm,          S_8,    O_null,     0,          0         },
  { fr_extsb,     0x978,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_extub,     0x979,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_extsh,     0x97A,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_extuh,     0x97B,      S_12,   O_gr,           S_4,    O_null,     0,          0         },
  { fr_ldm0,      0x8C,       S_8,    O_reglist,      S_8,    O_null,     0,          0         },
  { fr_ldm1,      0x8D,       S_8,    O_reglist,      S_8,    O_null,     0,          0         },
  { fr_stm0,      0x8E,       S_8,    O_reglist,      S_8,    O_null,     0,          0         },
  { fr_stm1,      0x8F,       S_8,    O_reglist,      S_8,    O_null,     0,          0         },
  { fr_enter,     0x0F,       S_8,    O_imm,          S_8,    O_null,     0,          I_IMM_4   },
  { fr_leave,     0x9F90,     S_16,   O_null,         0,      O_null,     0,          0         },
  { fr_xchb,      0x8A,       S_8,    O_gri,          S_4,    O_gr,       S_4,        0         }
};

void opcode_t::check(void)
{
  for ( int i = 0; i < qnumber(opcodes); i++ )
  {
    int n = opcodes[i].size();
//  if ( n != 16 && n != 32 )
//      msg("instruction n%d (%d) : size %d\n", i, opcodes[i].insn, n);
    QASSERT(10001, n == 16 || n == 32);
  }
}

const struct opcode_t * opcode_t::find(insn_t &insn, int *_data)
{
  QASSERT(10002, _data != nullptr);

  int data = (*_data << 8) | get_byte(insn.ip + insn.size);
  for ( int i = 0; i < qnumber(opcodes); i++ )
  {
    int mask;
    int shift;
    switch ( opcodes[i].opcode_size )
    {
      case S_4:  mask = 0xF000; shift = 12; break;
      case S_5:  mask = 0xF100; shift = 11; break;
      case S_8:  mask = 0xFF00; shift = 8;  break;
      case S_12: mask = 0xFFF0; shift = 4;  break;
      case S_16: mask = 0xFFFF; shift = 0;  break;
      default:   INTERR(10012);
    }
    if ( ((data & mask) >> shift) != opcodes[i].opcode )
      continue;

    insn.size++;
    *_data = invert_word(data);
    return &opcodes[i];
  }
  return nullptr;
}

// get general register.
static int get_gr(const int num)
{
  QASSERT(10003, num >= 0 && num <= 15);
  return num;
}

// get coprocessor register.
static int get_cr(const int num)
{
  QASSERT(10004, num >= 0 && num <= 15);
  return num + 16;
}

// get dedicated register.
static int get_dr(int num)
{
  static const int drs[] =
  {
    rTBR,
    rRP,
    rSSP,
    rUSP,
    rMDH,
    rMDL,
    rReserved6,
    rReserved7,
    rReserved8,
    rReserved9,
    rReserved10,
    rReserved11,
    rReserved12,
    rReserved13,
    rReserved14,
    rReserved15
  };
  QASSERT(10005, num >= 0 && num <= 15);
  return drs[num];
}

// fill an operand as a register.
static void set_reg(op_t &op, int reg, char d_typ)
{
  op.type = o_reg;
  op.reg = (uint16)reg;
  op.dtype = d_typ;
}

// fill an operand as an immediate value.
static void set_imm(op_t &op, int imm, char d_typ)
{
  op.type = o_imm;
  switch ( d_typ )
  {
    case dt_byte:  op.value = (char) imm; break;
    case dt_word:  op.value = (short) imm; break;
    case dt_dword: op.value = imm; break;
    default:       INTERR(10013);
  }
  op.dtype = d_typ;
}

// fill an operand as a phrase.
static void set_phrase(op_t &op, int type, int val, char d_typ)
{
  switch ( type )
  {
    case fIGR:       // indirect general register
    case fIGRP:      // indirect general register with post-increment
    case fIGRM:      // indirect general register with pre-decrement
    case fR13RI:     // indirect displacement between R13 and a general register
      op.reg = (uint16)val;
      break;

    case fIRA:       // indirect relative address
      op.addr = val;
      break;

    default:
      INTERR(10014);
  }
  op.type = o_phrase;
  op.specflag2 = (char)type;
  op.dtype = d_typ;
}

// fill an operand as a relative address.
static void set_rel(const insn_t &insn, op_t &op, int addr, char d_typ)
{
  op.type = o_near;
  int raddr;
  switch ( d_typ ) /* ugly but functional */
  {
    case dt_byte:
      raddr = ((signed char) addr);
      break;

    case dt_word:
      raddr = ((signed short) addr);
      break;

    default:
      INTERR(10015);
  }
  op.addr = insn.ip + 2 + (raddr * 2);    //-V614 uninitialized variable 'raddr'
#if defined(__DEBUG__)
  msg("0x%a = 0x%a + 2 + ((signed) 0x%X) * 2)\n", op.addr, insn.ip, addr);
#endif /* __DEBUG__ */
  op.dtype = dt_code;
}

// fill an operand as a reglist
static void set_reglist(op_t &op, int list)
{
  op.type = o_reglist;
  op.value = list;
  op.dtype = dt_byte;  // list is coded in a byte
}

static void set_displ(op_t &op, int reg, int imm, int flag, int local_flag)
{
  op.type = o_displ;
  if ( reg != -1 )
    op.reg = (uint16)get_gr(reg);
  if ( imm != -1 )
  {
    int mul = 1;
    if ( local_flag & I_IMM_2 )
      mul = 2;
    if ( local_flag & I_IMM_4 )
      mul = 4;
    op.value = ((unsigned) imm) * mul;
  }
  op.dtype = dt_byte;
  op.specflag1 |= flag;
}

// swap 2 opcodes (o1 <=> o2).
static void swap_ops(op_t &o1, op_t &o2)
{
  QASSERT(10006, o1.type != o_void && o2.type != o_void);
  op_t tmp = o1;
  o1 = o2;
  o2 = tmp;
}

static void adjust_data(int size, int *data)
{
  QASSERT(10007, data != nullptr);
  int new_data = *data >> bits[size];
  *data = new_data;
}

/*
static void prepare_data(int size, int *data) {
    QASSERT(10008, data != nullptr);
    int new_data = 0;
    switch ( size ) {
        case S_0:
        case S_4:
            new_data = *data;
            break;

        case S_5:
        case S_8:
            new_data |= (*data & 0x00F0) >> 4;
            new_data |= (*data & 0x000F) << 4;
            break;

        case S_11:
        case S_12:
            new_data |= (*data & 0x0F00) >> 8;
            new_data |= (*data & 0x00F0) >> 0;
            new_data |= (*data & 0x000F) << 8;
            break;

        case S_16:
            new_data |= (*data & 0xF000) >> 12;
            new_data |= (*data & 0x0F00) >> 4;
            new_data |= (*data & 0x00F0) << 4;
            new_data |= (*data & 0x000F) << 12;
            break;
    }
    *data = new_data;
}*/

#define SWAP_IF_BYTE(data)          \
    do                              \
    {                               \
      if ( operand_size == S_8 )    \
      {                             \
        int h = (data & 0x0F) << 4; \
        int l = (data & 0xF0) >> 4; \
        data = h | l;               \
      }                             \
    }                               \
    while ( 0 )

//
// defines some shortcuts.
//

#define __set_gr(op, reg)               set_reg(op, reg, dt_byte)
#define set_gr(op, reg)                 __set_gr(op, get_gr(reg))
#define __set_dr(op, reg)               set_reg(op, reg, dt_word)
#define set_dr(op, reg)                 __set_dr(op, get_dr(reg))
#define __set_cr(op, reg)               set_reg(op, reg, dt_word)
#define set_cr(op, reg)                 __set_cr(op, get_cr(reg))

#define set_gri(insn, op, reg)          set_phrase(op, fIGR, get_gr(reg), dt_byte)
#define set_grip(insn, op, reg)         set_phrase(op, fIGRP, get_gr(reg), dt_byte)
#define set_grim(insn, op, reg)         set_phrase(op, fIGRM, get_gr(reg), dt_byte)
#define set_diri(insn, op, addr)        set_phrase(op, fIRA, addr, dt_word)
#define set_r13_gr_i(insn, op, reg)     set_phrase(op, fR13RI, get_gr(reg), dt_byte)
#define fill_op1(insn, data, opc)       fill_op(insn, data, insn.Op1, opc->op1, opc->op1_size, opc->flags)
#define fill_op2(insn, data, opc)       fill_op(insn, data, insn.Op2, opc->op2, opc->op2_size, opc->flags)
//#define set_displ_gr(op, gr, f1)        set_displ(op, gr, -1, f1, 0)
#define set_displ_imm(op, imm, f1, f2)  set_displ(op, -1, imm, f1, f2)

static void fill_op(const insn_t &insn, int data, op_t &op, int operand, int operand_size, int flags)
{
  data &= masks[operand_size];
  //prepare_data(operand_size, &data);
  switch ( operand )
  {
    case O_gr:           // general register                         Ri
      QASSERT(10009, operand_size == S_4);
      set_gr(op, data);
      break;

    case O_gri:          // general register indirect                @Ri
      QASSERT(10010, operand_size == S_4);
      set_gri(insn, op, data);
      break;

    case O_grip:          // general register indirect                @Ri
      QASSERT(10011, operand_size == S_4);
      set_grip(insn, op, data);
      break;

    case O_r13_gr_i:     // indirect r13 + general register          @(R13, Ri)
      set_r13_gr_i(insn, op, data);
      break;

    case O_r14_imm8_i:   // indirect r14 + 8 bits immediate value    @(R14, imm)
      SWAP_IF_BYTE(data);
      set_displ_imm(op, data, OP_DISPL_IMM_R14, flags);
      break;

    case O_r15_imm4_i:   // indirect r15 + 4 bits immediate value    @(R15, imm)
      SWAP_IF_BYTE(data);
      set_displ_imm(op, data, OP_DISPL_IMM_R15, flags);
      break;

    case O_r15ip:        // indirect r15 post-increment              @R15+
      set_grip(insn, op, rR15);
      break;

    case O_r15im:        // indirect r15 pre-decrement               @-R15
      set_grim(insn, op, rR15);
      break;

    case O_r13:          // register r13                             R13
      __set_gr(op, rR13);
      break;

    case O_r13ip:        // indirect r13 post-increment              @R13+
      set_grip(insn, op, rR13);
      break;

    case O_dr:           // dedicated register                       Rs
      set_dr(op, data);
      break;

    case O_ps:           // program status register (PS)             PS
      __set_dr(op, rPS);
      break;

    case O_imm:          // immediate value                          #i
      SWAP_IF_BYTE(data);
      if ( insn.itype == fr_enter )
        data *= 4;
      if ( insn.itype == fr_addsp )
        data = ((signed) data) * 4;
      set_imm(op, data, dtypes[operand_size]);
      break;

    case O_diri:         // indirect direct value                    @i
      SWAP_IF_BYTE(data);
      if ( insn.itype == fr_dmov )
        data *= 4;
      if ( insn.itype == fr_dmovh )
        data *= 2;
      set_diri(insn, op, data);
      op.specflag1 |= flags;
      break;

    case O_rel:          // relative value                           label5
      SWAP_IF_BYTE(data);
      set_rel(insn, op, data, dtypes[operand_size]);
      break;

    case O_reglist:      // register list                            (R0, R1, R2, ...)
      SWAP_IF_BYTE(data);
      set_reglist(op, data);
      break;

    case O_null:         // null opcode
      INTERR(10016);
  }
}

// analyze a "common" instruction (those which are listed in the opcodes[] array).
static bool ana_common(insn_t &insn, int data)
{
  const struct opcode_t *op = opcode_t::find(insn, &data);
  if ( op == nullptr )
    return false;

  // fill instruction type
  insn.itype = (uint16)op->itype;

  // if instruction is implied, our job is finished!
  if ( op->implied() )
    goto ana_finished;

  adjust_data(op->opcode_size, &data);

  // fill operand 1
  if ( op->op1 != O_null )
  {
    fill_op1(insn, data, op);
    adjust_data(op->op1_size, &data);
  }

  // fill operand 2
  if ( op->op2 != O_null )
  {
    fill_op2(insn, data, op);
    adjust_data(op->op2_size, &data);
  }

  // swap opcodes if needed
  if ( op->swap_ops() )
    swap_ops(insn.Op1, insn.Op2);

ana_finished:
  insn.auxpref = 0;

  // is insn delay shot ?
  if ( op->delay_shot() )
    insn.auxpref |= INSN_DELAY_SHOT;

  return true;
}

// analyze a "special" instruction (those which are NOT listed in the opcodes[] array).
static bool ana_special(insn_t &insn, int data)
{
  // detect ldi:20 instructions
  if ( data == 0x9B )
  {
    insn.itype = fr_ldi_20;
    data = (data << 8) | insn.get_next_byte();
    set_gr(insn.Op2, data & 0x000F);
    set_imm(insn.Op1, insn.get_next_word() | ((data & 0x00F0) << 12), dt_dword);
    return true;
  }

  data = (data << 8) | get_byte(insn.ea + insn.size);

  // detect ldi:32 instructions
  if ( (data & 0xFFF0) == 0x9F80 )
  {
    insn.size++;
    insn.itype = fr_ldi_32;
    set_gr(insn.Op2, data & 0x000F);
    set_imm(insn.Op1, insn.get_next_dword(), dt_dword);
    return true;
  }

  // detect call [rel] instructions
  int tmp = (data & 0xF800) >> 11;
  if ( tmp == 0x1A || tmp == 0x1B )
  {
    insn.itype = fr_call;
    insn.size++;
    // extend sign
    if ( data & 0x400 )
      data |= ~0x07FF;
    else
      data &= 0x07FF;
    set_rel(insn, insn.Op1, data, dt_word);
    if ( tmp == 0x1B )
      insn.auxpref |= INSN_DELAY_SHOT;
    return true;
  }

  // detect copop/copld/copst/copsv instructions
  if ( ((data & 0xFF00) >> 8) == 0x9F )
  {
    int word = get_word(insn.ea + insn.size + 1);
    insn.itype = fr_null;
    switch ( (data & 0x00F0) >> 4 )
    {
      // copop
      case 0xC:
        insn.itype = fr_copop;
        set_cr(insn.Op3, (word & 0x00F0) >> 4);
        set_cr(insn.Op4, word & 0x000F);
        break;

      // copld
      case 0xD:
        insn.itype = fr_copld;
        set_gr(insn.Op3, (word & 0x00F0) >> 4);
        set_cr(insn.Op4, word & 0x000F);
        break;

      // copst
      case 0xE:
        insn.itype = fr_copst;
        set_cr(insn.Op3, (word & 0x00F0) >> 4);
        set_gr(insn.Op4, word & 0x000F);
        break;

      // copsv
      case 0xF:
        insn.itype = fr_copsv;
        set_cr(insn.Op3, (word & 0x00F0) >> 4);
        set_gr(insn.Op4, word & 0x000F);
        break;
    }
    if ( insn.itype != fr_null )
    {
      set_imm(insn.Op1, data & 0x000F, dt_byte);
      set_imm(insn.Op2, (word & 0xFF00) >> 8, dt_byte);
      insn.size += 3;
      return true;
    }
  }

  return false;
}

// analyze an instruction.
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

#if defined(__DEBUG__)
  opcode_t::check();
#endif /* __DEBUG__ */

  int byte = insn.get_next_byte();

  bool ok = ana_special(insn, byte);
  if ( !ok )
    ok = ana_common(insn, byte);

  return ok ? insn.size : 0;
}
