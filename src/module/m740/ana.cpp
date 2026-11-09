
#include "m740.hpp"

// 740 addressing modes :
enum m740_addr_mode_t ENUM_SIZE(uint8)
{
  A_IMM,            // immediate
  A_ACC,            // accumulator
  A_ZP,             // zero page
  A_ZPX,            // zero page X
  A_ZPY,            // zero page Y
  A_ABS,            // absolute
  A_ABSX,           // absolute X
  A_ABSY,           // absolute Y
  A_IMPL,           // implied
  A_REL,            // relative
  A_INDX,           // indirect X
  A_INDY,           // indirect Y
  A_INDABS,         // indirect absolute
  A_ZPIND,          // zero page indirect
  A_SP,             // special page
  A_ZPB,            // zero page bit
  A_ACCB,           // accumulator bit
  A_ACCBREL,        // accumulator bit relative
  A_ZPBREL          // zero page bit relative
};

//lint -e{958} padding needed
struct opcode
{
  uint16 insn;                  // instruction ID
  uchar code;                   // operation code, one byte
  m740_addr_mode_t addr;        // addressing mode
};

// 740 operation codes :
static const struct opcode opcodes[] =
{
  { m740_adc,        0x69,        A_IMM           },
  { m740_adc,        0x65,        A_ZP            },
  { m740_adc,        0x75,        A_ZPX           },
  { m740_adc,        0x6D,        A_ABS           },
  { m740_adc,        0x7D,        A_ABSX          },
  { m740_adc,        0x79,        A_ABSY          },
  { m740_adc,        0x61,        A_INDX          },
  { m740_adc,        0x71,        A_INDY          },
  { m740_and,        0x29,        A_IMM           },
  { m740_and,        0x25,        A_ZP            },
  { m740_and,        0x35,        A_ZPX           },
  { m740_and,        0x2D,        A_ABS           },
  { m740_and,        0x3D,        A_ABSX          },
  { m740_and,        0x39,        A_ABSY          },
  { m740_and,        0x21,        A_INDX          },
  { m740_and,        0x31,        A_INDY          },
  { m740_asl,        0x0A,        A_ACC           },
  { m740_asl,        0x06,        A_ZP            },
  { m740_asl,        0x16,        A_ZPX           },
  { m740_asl,        0x0E,        A_ABS           },
  { m740_asl,        0x1E,        A_ABSX          },
  { m740_bcc,        0x90,        A_REL           },
  { m740_bcs,        0xB0,        A_REL           },
  { m740_beq,        0xF0,        A_REL           },
  { m740_bit,        0x24,        A_ZP            },
  { m740_bit,        0x2C,        A_ABS           },
  { m740_bmi,        0x30,        A_REL           },
  { m740_bne,        0xD0,        A_REL           },
  { m740_bpl,        0x10,        A_REL           },
  { m740_bra,        0x80,        A_REL           },
  { m740_brk,        0x00,        A_IMPL          },
  { m740_bvc,        0x50,        A_REL           },
  { m740_bvs,        0x70,        A_REL           },
  { m740_clc,        0x18,        A_IMPL          },
  { m740_cld,        0xD8,        A_IMPL          },
  { m740_cli,        0x58,        A_IMPL          },
  { m740_clt,        0x12,        A_IMPL          },
  { m740_clv,        0xB8,        A_IMPL          },
  { m740_cmp,        0xC9,        A_IMM           },
  { m740_cmp,        0xC5,        A_ZP            },
  { m740_cmp,        0xD5,        A_ZPX           },
  { m740_cmp,        0xCD,        A_ABS           },
  { m740_cmp,        0xDD,        A_ABSX          },
  { m740_cmp,        0xD9,        A_ABSY          },
  { m740_cmp,        0xC1,        A_INDX          },
  { m740_cmp,        0xD1,        A_INDY          },
  { m740_com,        0x44,        A_ZP            },
  { m740_cpx,        0xE0,        A_IMM           },
  { m740_cpx,        0xE4,        A_ZP            },
  { m740_cpx,        0xEC,        A_ABS           },
  { m740_cpy,        0xC0,        A_IMM           },
  { m740_cpy,        0xC4,        A_ZP            },
  { m740_cpy,        0xCC,        A_ABS           },
  { m740_dec,        0x1A,        A_ACC           },
  { m740_dec,        0xC6,        A_ZP            },
  { m740_dec,        0xD6,        A_ZPX           },
  { m740_dec,        0xCE,        A_ABS           },
  { m740_dec,        0xDE,        A_ABSX          },
  { m740_dex,        0xCA,        A_IMPL          },
  { m740_dey,        0x88,        A_IMPL          },
  { m740_div,        0xE2,        A_ZPX           },
  { m740_eor,        0x49,        A_IMM           },
  { m740_eor,        0x45,        A_ZP            },
  { m740_eor,        0x55,        A_ZPX           },
  { m740_eor,        0x4D,        A_ABS           },
  { m740_eor,        0x5D,        A_ABSX          },
  { m740_eor,        0x59,        A_ABSY          },
  { m740_eor,        0x41,        A_INDX          },
  { m740_eor,        0x51,        A_INDY          },
  { m740_inc,        0x3A,        A_ACC           },
  { m740_inc,        0xE6,        A_ZP            },
  { m740_inc,        0xF6,        A_ZPX           },
  { m740_inc,        0xEE,        A_ABS           },
  { m740_inc,        0xFE,        A_ABSX          },
  { m740_inx,        0xE8,        A_IMPL          },
  { m740_iny,        0xC8,        A_IMPL          },
  { m740_jmp,        0x4C,        A_ABS           },
  { m740_jmp,        0x6C,        A_INDABS        },
  { m740_jmp,        0xB2,        A_ZPIND         },
  { m740_jsr,        0x20,        A_ABS           },
  { m740_jsr,        0x22,        A_SP            },
  { m740_jsr,        0x02,        A_ZPIND         },
  { m740_lda,        0xA9,        A_IMM           },
  { m740_lda,        0xA5,        A_ZP            },
  { m740_lda,        0xB5,        A_ZPX           },
  { m740_lda,        0xAD,        A_ABS           },
  { m740_lda,        0xBD,        A_ABSX          },
  { m740_lda,        0xB9,        A_ABSY          },
  { m740_lda,        0xA1,        A_INDX          },
  { m740_lda,        0xB1,        A_INDY          },
  { m740_ldm,        0x3C,        A_ZP            },
  { m740_ldx,        0xA2,        A_IMM           },
  { m740_ldx,        0xA6,        A_ZP            },
  { m740_ldx,        0xB6,        A_ZPY           },
  { m740_ldx,        0xAE,        A_ABS           },
  { m740_ldx,        0xBE,        A_ABSY          },
  { m740_ldy,        0xA0,        A_IMM           },
  { m740_ldy,        0xA4,        A_ZP            },
  { m740_ldy,        0xB4,        A_ZPX           },
  { m740_ldy,        0xAC,        A_ABS           },
  { m740_ldy,        0xBC,        A_ABSX          },
  { m740_lsr,        0x4A,        A_ACC           },
  { m740_lsr,        0x46,        A_ZP            },
  { m740_lsr,        0x56,        A_ZPX           },
  { m740_lsr,        0x4E,        A_ABS           },
  { m740_lsr,        0x5E,        A_ABSX          },
  { m740_mul,        0x62,        A_ZPX           },
  { m740_nop,        0xEA,        A_IMPL          },
  { m740_ora,        0x09,        A_IMM           },
  { m740_ora,        0x05,        A_ZP            },
  { m740_ora,        0x15,        A_ZPX           },
  { m740_ora,        0x0D,        A_ABS           },
  { m740_ora,        0x1D,        A_ABSX          },
  { m740_ora,        0x19,        A_ABSY          },
  { m740_ora,        0x01,        A_INDX          },
  { m740_ora,        0x11,        A_INDY          },
  { m740_pha,        0x48,        A_IMPL          },
  { m740_php,        0x08,        A_IMPL          },
  { m740_pla,        0x68,        A_IMPL          },
  { m740_plp,        0x28,        A_IMPL          },
  { m740_rol,        0x2A,        A_ACC           },
  { m740_rol,        0x26,        A_ZP            },
  { m740_rol,        0x36,        A_ZPX           },
  { m740_rol,        0x2E,        A_ABS           },
  { m740_rol,        0x3E,        A_ABSX          },
  { m740_ror,        0x6A,        A_ACC           },
  { m740_ror,        0x66,        A_ZP            },
  { m740_ror,        0x76,        A_ZPX           },
  { m740_ror,        0x6E,        A_ABS           },
  { m740_ror,        0x7E,        A_ABSX          },
  { m740_rrf,        0x82,        A_ZP            },
  { m740_rti,        0x40,        A_IMPL          },
  { m740_rts,        0x60,        A_IMPL          },
  { m740_sbc,        0xE9,        A_IMM           },
  { m740_sbc,        0xE5,        A_ZP            },
  { m740_sbc,        0xF5,        A_ZPX           },
  { m740_sbc,        0xED,        A_ABS           },
  { m740_sbc,        0xFD,        A_ABSX          },
  { m740_sbc,        0xF9,        A_ABSY          },
  { m740_sbc,        0xE1,        A_INDX          },
  { m740_sbc,        0xF1,        A_INDY          },
  { m740_sec,        0x38,        A_IMPL          },
  { m740_sed,        0xF8,        A_IMPL          },
  { m740_sei,        0x78,        A_IMPL          },
  { m740_set,        0x32,        A_IMPL          },
  { m740_sta,        0x85,        A_ZP            },
  { m740_sta,        0x95,        A_ZPX           },
  { m740_sta,        0x8D,        A_ABS           },
  { m740_sta,        0x9D,        A_ABSX          },
  { m740_sta,        0x99,        A_ABSY          },
  { m740_sta,        0x81,        A_INDX          },
  { m740_sta,        0x91,        A_INDY          },
  { m740_stp,        0x42,        A_IMPL          },
  { m740_stx,        0x86,        A_ZP            },
  { m740_stx,        0x96,        A_ZPY           },
  { m740_stx,        0x8E,        A_ABS           },
  { m740_sty,        0x84,        A_ZP            },
  { m740_sty,        0x94,        A_ZPX           },
  { m740_sty,        0x8C,        A_ABS           },
  { m740_tax,        0xAA,        A_IMPL          },
  { m740_tay,        0xA8,        A_IMPL          },
  { m740_tst,        0x64,        A_ZP            },
  { m740_tsx,        0xBA,        A_IMPL          },
  { m740_txa,        0x8A,        A_IMPL          },
  { m740_txs,        0x9A,        A_IMPL          },
  { m740_tya,        0x98,        A_IMPL          },
  { m740_wit,        0xC2,        A_IMPL          }
};

struct opcode_flag
{
  uint16 insn;
  uchar  flags;
#define MEM_R    OP_ADDR_R    // read access
#define MEM_W    OP_ADDR_W    // write access
};

static const struct opcode_flag opcodes_flags[] =
{
  { m740_adc,     MEM_R    },
  { m740_and,     MEM_R    },
  { m740_asl,     MEM_W    },
  { m740_bbc,     MEM_R    },
  { m740_bbs,     MEM_R    },
  { m740_bit,     MEM_R    },
  { m740_clb,     MEM_W    },
  { m740_cmp,     MEM_R    },
  { m740_com,     MEM_W    },
  { m740_cpx,     MEM_R    },
  { m740_cpy,     MEM_R    },
  { m740_dec,     MEM_W    },
  { m740_eor,     MEM_R    },
  { m740_inc,     MEM_W    },
  { m740_jmp,     MEM_R    },
  { m740_jsr,     MEM_R    },
  { m740_lda,     MEM_R    },
  { m740_ldm,     MEM_W    },
  { m740_ldx,     MEM_R    },
  { m740_ldy,     MEM_R    },
  { m740_lsr,     MEM_W    },
  { m740_ora,     MEM_R    },
  { m740_rol,     MEM_W    },
  { m740_ror,     MEM_W    },
  { m740_sbc,     MEM_R    },
  { m740_seb,     MEM_W    },
  { m740_sta,     MEM_W    },
  { m740_stx,     MEM_W    },
  { m740_sty,     MEM_W    },
  { m740_tst,     MEM_R    },
  { m740_rrf,     MEM_W    }
};

// fill operand as a register
inline static void set_op_reg(op_t &op, uint16 reg)
{
  op.type = o_reg;
  op.reg = reg;
  op.dtype = dt_word; // XXX not sure
}

// a shortcut to make our live easier
#define set_op_acc(x)    set_op_reg(x, rA)

// fill operand as a code address
inline static void set_op_addr(op_t &op, ea_t addr)
{
  op.type = o_near;
  op.addr = addr;
  op.dtype = dt_code;
}

// fill operand as a displacement between a memory address and a register contents
inline static void set_op_displ(insn_t &insn, int addr, uint16 reg, char d_typ = dt_byte)
{
  insn.Op1.type = o_displ;
  insn.Op1.addr = addr;
  insn.Op1.reg = reg;
  insn.Op1.dtype = d_typ;
}

// fill operand as a data address
inline static void set_op_mem(op_t &op, int addr, const uchar flags = 0, char d_typ = dt_byte)
{
  op.type = o_mem;
  op.addr = addr;
  op.dtype = d_typ;
  op.specflag1 = flags;
}

// fill operand as an immediate value
inline static void set_op_imm(op_t &op, int imm)
{
  op.type = o_imm;
  op.value = imm;
  op.dtype = dt_byte;
}

// fill the insn structure according to the addressing mode of the
// current analyzed instruction
static void fill_insn(insn_t &insn, m740_addr_mode_t addr, const uchar flags = 0)
{
  switch ( addr )
  {
    case A_IMM:            // immediate
      set_op_imm(insn.Op1, insn.get_next_byte());
      break;

    case A_ACC:            // accumulator
      set_op_acc(insn.Op1);
      break;

    case A_ZP:            // zero page
      if ( insn.itype == m740_ldm )  // special case
      {
        set_op_imm(insn.Op1, insn.get_next_byte());
        set_op_mem(insn.Op2, insn.get_next_byte(), flags);
      }
      else
      {
        set_op_mem(insn.Op1, insn.get_next_byte(), flags);
      }
      break;

    case A_ZPX:            // zero page X
      set_op_displ(insn, insn.get_next_byte(), rX);
      insn.auxpref |= INSN_DISPL_ZPX;
      break;

    case A_ZPY:            // zero page Y
      set_op_displ(insn, insn.get_next_byte(), rY);
      insn.auxpref |= INSN_DISPL_ZPY;
      break;

    case A_ABS:            // absolute
      if ( insn.itype == m740_jmp || insn.itype == m740_jsr )
        set_op_addr(insn.Op1, insn.get_next_word());
      else
        set_op_mem(insn.Op1, insn.get_next_word(), flags);
      break;

    case A_ABSX:        // absolute X
      set_op_displ(insn, insn.get_next_word(), rX);
      insn.auxpref |= INSN_DISPL_ABSX;
      break;

    case A_ABSY:        // absolute Y
      set_op_displ(insn, insn.get_next_word(), rY);
      insn.auxpref |= INSN_DISPL_ABSY;
      break;

    case A_IMPL:        // implied
      // nothing to do..
      break;

    case A_REL:            // relative
      set_op_addr(insn.Op1, (signed char) insn.get_next_byte() + insn.ea + 2);
      break;

    case A_INDX:        // indirect X
      set_op_displ(insn, insn.get_next_byte(), rX, dt_word);
      insn.auxpref |= INSN_DISPL_INDX;
      break;

    case A_INDY:        // indirect Y
      set_op_displ(insn, insn.get_next_byte(), rY, dt_word);
      insn.auxpref |= INSN_DISPL_INDY;
      break;

    case A_INDABS:        // indirect absolute
      set_op_mem(insn.Op1, insn.get_next_word(), flags, dt_word);
      insn.Op1.specflag1 |= OP_ADDR_IND;
      break;

    case A_ZPIND:        // zero page indirect
      set_op_mem(insn.Op1, insn.get_next_byte(), 0, dt_word);
      insn.Op1.specflag1 |= OP_ADDR_IND;
      break;

    case A_SP:            // special page
      set_op_addr(insn.Op1, insn.get_next_byte() | 0xFF00);
      insn.Op1.specflag1 |= OP_ADDR_SP;
      break;

    case A_ZPB:            // zero page bit
      set_op_mem(insn.Op2, insn.get_next_byte(), flags, dt_word);
      break;

    case A_ACCB:        // accumulator bit
      set_op_acc(insn.Op2);
      break;

    case A_ACCBREL:        // accumulator bit relative
      set_op_acc(insn.Op2);
      set_op_addr(insn.Op3, (signed char) insn.get_next_byte() + insn.ea + 2);
      break;

    case A_ZPBREL:        // zero page bit relative
      set_op_mem(insn.Op2, insn.get_next_byte(), flags);
      set_op_addr(insn.Op3, (signed char) insn.get_next_byte() + insn.ea + 3);
      break;

    default:
      INTERR(10025);
  }
}

// try to find an opcode in our table from the fetched byte
static const struct opcode *get_opcode(int byte)
{
  for ( int i = 0; i < qnumber(opcodes); i++ )
  {
    if ( opcodes[i].code != byte )
      continue;
    return &opcodes[i];
  }
  return nullptr;
}

static uchar get_opcode_flags(const uint16 insn)
{
  for ( int i = 0; i < qnumber(opcodes_flags); i++ )
  {
    if ( opcodes_flags[i].insn != insn )
      continue;
    return opcodes_flags[i].flags;
  }
  return 0;
}

// detect special instructions, whose we can't detect using the table and the
// get_opcode() routine
static bool ana_special(insn_t &insn, int byte)
{
  bool special = false;

  //lint -e{958} padding needed
  struct spec_info_t
  {
    uint16 insn;                  // instruction ID
    uchar  val;                   // (20i + val)
    m740_addr_mode_t addr;        // which addressing mode ?
  };
  static const spec_info_t specials[] =
  {
    { m740_bbc, 0x13,    A_ACCBREL },
    { m740_bbc, 0x17,    A_ZPBREL  },
    { m740_bbs, 0x03,    A_ACCBREL },
    { m740_bbs, 0x07,    A_ZPBREL  },
    { m740_clb, 0x1B,    A_ACCB    },
    { m740_clb, 0x1F,    A_ZPB     },
    { m740_seb, 0x0B,    A_ACCB    },
    { m740_seb, 0x0F,    A_ZPB     }
  };

  for ( int i = 0; i < qnumber(specials); i++ )
  {
    int t = (uchar) byte - specials[i].val;
    if ( (t % 0x20) != 0 )
      continue;

    insn.itype = specials[i].insn;

    set_op_imm(insn.Op1, t / 0x20);
    insn.Op1.specflag1 |= OP_IMM_BIT;
    fill_insn(insn, specials[i].addr, get_opcode_flags(specials[i].insn));
    special = true;
    break;
  }

  return special;
}

// analyze an instruction
int idaapi ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  bool special;
  int byte;

  byte = insn.get_next_byte();
  special = ana_special(insn, byte);

  if ( !special )
  {
    const struct opcode *op = get_opcode(byte);
    if ( op == nullptr )        // unmatched insn
      return 0;

    insn.itype = op->insn;
    fill_insn(insn, op->addr, get_opcode_flags(op->insn));
  }

  return insn.size;
}
