/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

struct sparse_tabent_t
{
  ushort code;
  ushort itype;
  char opnum;
};

//--------------------------------------------------------------------------
inline void opimm(op_t &x, uval_t value, char dtype)
{
  x.type = o_imm;
  x.dtype = dtype;
  x.value = value;
}

//--------------------------------------------------------------------------
inline void opreg(op_t &x, int reg)
{
  x.type = o_reg;
  x.dtype = dt_dword;
  x.reg = (uchar)reg;
}

//--------------------------------------------------------------------------
inline void opmem(op_t &x, uval_t addr, char dtype)
{
  x.type  = o_mem;
  x.dtype = dtype;
  x.addr  = addr;
}

//--------------------------------------------------------------------------
inline void opdsp(op_t &x, int base, int idx, int scale, uval_t disp, char dtype)
{
  x.type  = o_displ;
  x.dtype = dtype;
  x.addr  = disp;
  x.reg   = (uint16)base;
  x.index = (uchar)idx;
  x.scale = (uchar)scale;
}

//--------------------------------------------------------------------------
inline void opphr(op_t &x, int base, int idx, int scale, char dtype)
{
  x.type  = o_phrase;
  x.dtype = dtype;
  x.reg   = (uint16)base;
  x.index = (uchar)idx;
  x.scale = (uchar)scale;
}

//--------------------------------------------------------------------------
inline void i960_t::opnear(op_t &x, uval_t addr) const
{
  x.type = o_near;
  x.dtype = dt_code;
  x.addr = trunc_uval(addr);
}

//--------------------------------------------------------------------------
bool i960_t::ctrl(insn_t &insn, uint32 code)
{
  static const ushort itypes[] =
  {
    I960_null,          /* 0x00 */
    I960_null,          /* 0x01 */
    I960_null,          /* 0x02 */
    I960_null,          /* 0x03 */
    I960_null,          /* 0x04 */
    I960_null,          /* 0x05 */
    I960_null,          /* 0x06 */
    I960_null,          /* 0x07 */
    I960_b,             /* 0x08 */
    I960_call,          /* 0x09 */
    I960_ret,           /* 0x0a */
    I960_bal,           /* 0x0b */
    I960_null,          /* 0x0c */
    I960_null,          /* 0x0d */
    I960_null,          /* 0x0e */
    I960_null,          /* 0x0f */
    I960_bno,           /* 0x10 */
    I960_bg,            /* 0x11 */
    I960_be,            /* 0x12 */
    I960_bge,           /* 0x13 */
    I960_bl,            /* 0x14 */
    I960_bne,           /* 0x15 */
    I960_ble,           /* 0x16 */
    I960_bo,            /* 0x17 */
    I960_faultno,       /* 0x18 */
    I960_faultg,        /* 0x19 */
    I960_faulte,        /* 0x1a */
    I960_faultge,       /* 0x1b */
    I960_faultl,        /* 0x1c */
    I960_faultne,       /* 0x1d */
    I960_faultle,       /* 0x1e */
    I960_faulto,        /* 0x1f */
  };
  int opcode = code >> 24;
  if ( opcode >= qnumber(itypes) )
    return false;
  if ( is_strict() && (code & 1) != 0 )
    return false;
  insn.itype = itypes[opcode];
  if ( opcode >= 0x10 )         // .t or .f are allowed
  {
    insn.auxpref |= (code & 2) ? aux_f : aux_t;
  }
  // has operand?
  if ( Instructions[insn.itype].feature & CF_USE1 )
  {
    sval_t disp = code & 0xFFFFFC;
    if ( disp & 0x800000 )
      disp |= ~uval_t(0xFFFFFF); // sign extend
    opnear(insn.Op1, insn.ip+disp);
  }
  return true;
}

//--------------------------------------------------------------------------
bool i960_t::cobr(insn_t &insn, uint32 code) const
{
  static const ushort itypes[] =
  {
    I960_testno,        /* 0x20 */
    I960_testg,         /* 0x21 */
    I960_teste,         /* 0x22 */
    I960_testge,        /* 0x23 */
    I960_testl,         /* 0x24 */
    I960_testne,        /* 0x25 */
    I960_testle,        /* 0x26 */
    I960_testo,         /* 0x27 */
    I960_null,          /* 0x28 */
    I960_null,          /* 0x29 */
    I960_null,          /* 0x2a */
    I960_null,          /* 0x2b */
    I960_null,          /* 0x2c */
    I960_null,          /* 0x2d */
    I960_null,          /* 0x2e */
    I960_null,          /* 0x2f */
    I960_bbc,           /* 0x30 */
    I960_cmpobg,        /* 0x31 */
    I960_cmpobe,        /* 0x32 */
    I960_cmpobge,       /* 0x33 */
    I960_cmpobl,        /* 0x34 */
    I960_cmpobne,       /* 0x35 */
    I960_cmpoble,       /* 0x36 */
    I960_bbs,           /* 0x37 */
    I960_cmpibno,       /* 0x38 */
    I960_cmpibg,        /* 0x39 */
    I960_cmpibe,        /* 0x3a */
    I960_cmpibge,       /* 0x3b */
    I960_cmpibl,        /* 0x3c */
    I960_cmpibne,       /* 0x3d */
    I960_cmpible,       /* 0x3e */
    I960_cmpibo,        /* 0x3f */
  };
  uint32 opcode = (code >> 24) - 0x20;
  if ( opcode >= qnumber(itypes) )
    return false;
  insn.itype = itypes[opcode];
  insn.auxpref |= (code & 2) ? aux_f : aux_t;

  int src1 = (code >> 19) & 0x1F;
  int src2 = (code >> 14) & 0x1F;

  // operand 1
  if ( code & 0x2000 ) // M1
  {
    opimm(insn.Op1, src1, dt_byte);
    if ( opcode < 8 )
      return false;  // test instructions can't have imm
  }
  else
  {
    opreg(insn.Op1, src1);
  }

  if ( Instructions[insn.itype].feature & (CF_USE2|CF_CHG2) )
  {
    // instruction has at least 3 operands
    if ( code & 1 )
      src2 += SF0; // S2
    opreg(insn.Op2, src2);
    sval_t disp = code & 0x1FFC;
    if ( disp & 0x1000 )
      disp |= ~uval_t(0x1FFF); // sign extend
    opnear(insn.Op3, insn.ip+disp);
  }
  return true;
}

//--------------------------------------------------------------------------
bool i960_t::opmemory(insn_t &insn, op_t &x, uint32 code, char dtype)
{
  int reg2 = (code >> 14) & 0x1F;
  int mode = (code >> 10) & 0xF;
  if ( mode & 4 )                     /* MEMB FORMAT */
  {
    unsigned scale = (code >> 7) & 0x07;
    if ( (scale > 4) )
      return false;
    bool badscale = ((code >> 5) & 0x03) != 0;
    static const int scale_tab[] = { 1, 2, 4, 8, 16 };
    scale = scale_tab[scale];

    int reg3 = code & 0x1F;
    uval_t disp;
    switch ( mode )
    {
      case 4:                                   /* (reg) */
        opphr(x, reg2, -1, 1, dtype);
        break;
      case 5:                                   /* displ+8(ip) */
        x.offb = (uchar)insn.size;
        disp = insn.get_next_dword();
        opdsp(x, IP, -1, 1, disp, dtype);
//        opmem(x, insn.ip+8+disp, dtype);
//        insn.auxpref |= aux_ip;
        break;
      case 7:                                   /* (reg)[index*scale] */
        if ( is_strict() && badscale )
          return false;
        opphr(x, reg2, reg3, scale, dtype);
        break;
      case 12:                                  /* displacement */
        x.offb = (uchar)insn.size;
        disp = insn.get_next_dword();
        opmem(x, disp, dtype);
        break;
      case 13:                                  /* displ(reg) */
        x.offb = (uchar)insn.size;
        disp = insn.get_next_dword();
        opdsp(x, reg2, -1, 1, disp, dtype);
        break;
      case 14:                                  /* displ[index*scale] */
        if ( is_strict() && badscale )
          return false;
        x.offb = (uchar)insn.size;
        disp = insn.get_next_dword();
        opdsp(x, -1, reg3, scale, disp, dtype);
        break;
      case 15:                                  /* displ(reg)[index*scale] */
        if ( is_strict() && badscale )
          return false;
        x.offb = (uchar)insn.size;
        disp = insn.get_next_dword();
        opdsp(x, reg2, reg3, scale, disp, dtype);
        break;
      default:
        return false;
    }
  }
  else                                /* MEMA FORMAT */
  {
    int offset = code & 0xFFF;
    if ( mode & 8 )
      opdsp(x, reg2, -1, 1, offset, dtype);
    else
      opmem(x, offset, dtype);
  }
  if ( x.type == o_mem && dtype == dt_code )
  {
    x.type = o_near;
    x.addr = trunc_uval(x.addr);
  }
  return true;
}

//--------------------------------------------------------------------------
bool i960_t::mem(insn_t &insn, uint32 code)
{
  static const tabent_t itypes[] =
  {
    { /* 0x80 */ I960_ldob,   2, dt_byte   },
    { /* 0x81 */ I960_null,   0, 0         },
    { /* 0x82 */ I960_stob,  -2, dt_byte   },
    { /* 0x83 */ I960_null,   0, 0         },
    { /* 0x84 */ I960_bx,     1, dt_code   },
    { /* 0x85 */ I960_balx,   2, dt_code   },
    { /* 0x86 */ I960_callx,  1, dt_code   },
    { /* 0x87 */ I960_null,   0, 0         },
    { /* 0x88 */ I960_ldos,   2, dt_word   },
    { /* 0x89 */ I960_null,   0, 0         },
    { /* 0x8a */ I960_stos,  -2, dt_word   },
    { /* 0x8b */ I960_null,   0, 0         },
    { /* 0x8c */ I960_lda,    2, dt_byte   },
    { /* 0x8d */ I960_null,   0, 0         },
    { /* 0x8e */ I960_null,   0, 0         },
    { /* 0x8f */ I960_null,   0, 0         },
    { /* 0x90 */ I960_ld,     2, dt_dword  },
    { /* 0x91 */ I960_null,   0, 0         },
    { /* 0x92 */ I960_st,    -2, dt_dword  },
    { /* 0x93 */ I960_null,   0, 0         },
    { /* 0x94 */ I960_null,   0, 0         },
    { /* 0x95 */ I960_null,   0, 0         },
    { /* 0x96 */ I960_null,   0, 0         },
    { /* 0x97 */ I960_null,   0, 0         },
    { /* 0x98 */ I960_ldl,    2, dt_qword  },
    { /* 0x99 */ I960_null,   0, 0         },
    { /* 0x9a */ I960_stl,   -2, dt_qword  },
    { /* 0x9b */ I960_null,   0, 0         },
    { /* 0x9c */ I960_null,   0, 0         },
    { /* 0x9d */ I960_null,   0, 0         },
    { /* 0x9e */ I960_null,   0, 0         },
    { /* 0x9f */ I960_null,   0, 0         },
    { /* 0xa0 */ I960_ldt,    2, dt_fword  },
    { /* 0xa1 */ I960_null,   0, 0         },
    { /* 0xa2 */ I960_stt,   -2, dt_fword  },
    { /* 0xa3 */ I960_null,   0, 0         },
    { /* 0xa4 */ I960_null,   0, 0         },
    { /* 0xa5 */ I960_null,   0, 0         },
    { /* 0xa6 */ I960_null,   0, 0         },
    { /* 0xa7 */ I960_null,   0, 0         },
    { /* 0xa8 */ I960_null,   0, 0         },
    { /* 0xa9 */ I960_null,   0, 0         },
    { /* 0xaa */ I960_null,   0, 0         },
    { /* 0xab */ I960_null,   0, 0         },
    { /* 0xac */ I960_dcinva, 1, dt_byte   },
    { /* 0xad */ I960_null,   0, 0         },
    { /* 0xae */ I960_null,   0, 0         },
    { /* 0xaf */ I960_null,   0, 0         },
    { /* 0xb0 */ I960_ldq,    2, dt_byte16 },
    { /* 0xb1 */ I960_null,   0, 0         },
    { /* 0xb2 */ I960_stq,   -2, dt_byte16 },
    { /* 0xb3 */ I960_null,   0, 0         },
    { /* 0xb4 */ I960_null,   0, 0         },
    { /* 0xb5 */ I960_null,   0, 0         },
    { /* 0xb6 */ I960_null,   0, 0         },
    { /* 0xb7 */ I960_null,   0, 0         },
    { /* 0xb8 */ I960_null,   0, 0         },
    { /* 0xb9 */ I960_null,   0, 0         },
    { /* 0xba */ I960_null,   0, 0         },
    { /* 0xbb */ I960_null,   0, 0         },
    { /* 0xbc */ I960_null,   0, 0         },
    { /* 0xbd */ I960_null,   0, 0         },
    { /* 0xbe */ I960_null,   0, 0         },
    { /* 0xbf */ I960_null,   0, 0         },
    { /* 0xc0 */ I960_ldib,   2, dt_byte   },
    { /* 0xc1 */ I960_null,   0, 0         },
    { /* 0xc2 */ I960_stib,  -2, dt_byte   },
    { /* 0xc3 */ I960_null,   0, 0         },
    { /* 0xc4 */ I960_null,   0, 0         },
    { /* 0xc5 */ I960_null,   0, 0         },
    { /* 0xc6 */ I960_null,   0, 0         },
    { /* 0xc7 */ I960_null,   0, 0         },
    { /* 0xc8 */ I960_ldis,   2, dt_word   },
    { /* 0xc9 */ I960_null,   0, 0         },
    { /* 0xca */ I960_stis,  -2, dt_word   },
  };

  uint32 opcode = (code >> 24) - 0x80;
  if ( opcode >= qnumber(itypes) )
    return false;
  insn.itype = itypes[opcode].itype;

  int reg1 = (code >> 19) & 0x1F;
  switch ( itypes[opcode].opnum )
  {
    case -2: /* STORE INSTRUCTION */
      opreg(insn.Op1, reg1);
      if ( !opmemory(insn, insn.Op2, code, itypes[opcode].dtype) )
        return false;
      break;

    case 2: /* LOAD INSTRUCTION */
      opreg(insn.Op2, reg1);
      // no break

    case 1: /* BX/CALLX INSTRUCTION */
      if ( !opmemory(insn, insn.Op1, code, itypes[opcode].dtype) )
        return false;
      break;
  }
  if ( insn.itype == I960_lda && insn.Op1.type == o_mem )
    opimm(insn.Op1, insn.Op1.addr, dt_dword);
  return true;
}

//--------------------------------------------------------------------------
static void regop(op_t &x, bool mode, bool spec, int reg, bool fp)
{
  if ( fp )                     /* FLOATING POINT INSTRUCTION */
  {
    if ( mode )                 /* FP operand */
    {
      switch ( reg )
      {
        case 0:
          opreg(x, FP0);
          break;
        case 1:
          opreg(x, FP1);
          break;
        case 2:
          opreg(x, FP2);
          break;
        case 3:
          opreg(x, FP3);
          break;
/*        case 16: "0f0.0"
          break;
        case 22: "0f1.0"
          break;
        default: "?"
          break;*/
      }
    }
    else
    {                           /* Non-FP register */
      opreg(x, reg);
    }
  }
  else
  {                             /* NOT FLOATING POINT */
    if ( mode )                 /* Literal */
    {
      opimm(x, reg, dt_dword);
    }
    else
    {                           /* Register */
      if ( spec )
        reg += SF0;
      opreg(x, reg);
    }
  }
}

//--------------------------------------------------------------------------
// Register Instruction Destination Operand
static void dstop(op_t &x, bool mode, int reg, bool fp)
{
  // 'dst' operand can't be a literal. On non-FP instructions,  register
  // mode is assumed and "m3" acts as if were "s3";  on FP-instructions,
  // sf registers are not allowed so m3 acts normally.
  if ( fp )
    regop(x, mode, false, reg, fp);
  else
    regop(x, false, mode, reg, fp);
}

//--------------------------------------------------------------------------
bool i960_t::reg(insn_t &insn, uint32 code)
{
  static const sparse_tabent_t reg_init[] =
  {
    { 0x580,      I960_notbit,        3 },
    { 0x581,      I960_and,           3 },
    { 0x582,      I960_andnot,        3 },
    { 0x583,      I960_setbit,        3 },
    { 0x584,      I960_notand,        3 },
    { 0x586,      I960_xor,           3 },
    { 0x587,      I960_or,            3 },
    { 0x588,      I960_nor,           3 },
    { 0x589,      I960_xnor,          3 },
    { 0x58a,      I960_not,          -2 },
    { 0x58b,      I960_ornot,         3 },
    { 0x58c,      I960_clrbit,        3 },
    { 0x58d,      I960_notor,         3 },
    { 0x58e,      I960_nand,          3 },
    { 0x58f,      I960_alterbit,      3 },
    { 0x590,      I960_addo,          3 },
    { 0x591,      I960_addi,          3 },
    { 0x592,      I960_subo,          3 },
    { 0x593,      I960_subi,          3 },
    { 0x594,      I960_cmpob,         2 },
    { 0x595,      I960_cmpib,         2 },
    { 0x596,      I960_cmpos,         2 },
    { 0x597,      I960_cmpis,         2 },
    { 0x598,      I960_shro,          3 },
    { 0x59a,      I960_shrdi,         3 },
    { 0x59b,      I960_shri,          3 },
    { 0x59c,      I960_shlo,          3 },
    { 0x59d,      I960_rotate,        3 },
    { 0x59e,      I960_shli,          3 },
    { 0x5a0,      I960_cmpo,          2 },
    { 0x5a1,      I960_cmpi,          2 },
    { 0x5a2,      I960_concmpo,       2 },
    { 0x5a3,      I960_concmpi,       2 },
    { 0x5a4,      I960_cmpinco,       3 },
    { 0x5a5,      I960_cmpinci,       3 },
    { 0x5a6,      I960_cmpdeco,       3 },
    { 0x5a7,      I960_cmpdeci,       3 },
    { 0x5ac,      I960_scanbyte,      2 },
    { 0x5ad,      I960_bswap,        -2 },
    { 0x5ae,      I960_chkbit,        2 },
    { 0x5b0,      I960_addc,          3 },
    { 0x5b2,      I960_subc,          3 },
    { 0x5b4,      I960_intdis,        0 },
    { 0x5b5,      I960_inten,         0 },
    { 0x5cc,      I960_mov,          -2 },
    { 0x5d8,      I960_eshro,         3 },
    { 0x5dc,      I960_movl,         -2 },
    { 0x5ec,      I960_movt,         -2 },
    { 0x5fc,      I960_movq,         -2 },
    { 0x600,      I960_synmov,        2 },
    { 0x601,      I960_synmovl,       2 },
    { 0x602,      I960_synmovq,       2 },
    { 0x603,      I960_cmpstr,        3 },
    { 0x604,      I960_movqstr,       3 },
    { 0x605,      I960_movstr,        3 },
    { 0x610,      I960_atmod,         3 },
    { 0x612,      I960_atadd,         3 },
    { 0x613,      I960_inspacc,      -2 },
    { 0x614,      I960_ldphy,        -2 },
    { 0x615,      I960_synld,        -2 },
    { 0x617,      I960_fill,          3 },
    { 0x630,      I960_sdma,          3 },
    { 0x631,      I960_udma,          0 },
    { 0x640,      I960_spanbit,      -2 },
    { 0x641,      I960_scanbit,      -2 },
    { 0x642,      I960_daddc,         3 },
    { 0x643,      I960_dsubc,         3 },
    { 0x644,      I960_dmovt,        -2 },
    { 0x645,      I960_modac,         3 },
    { 0x646,      I960_condrec,      -2 },
    { 0x650,      I960_modify,        3 },
    { 0x651,      I960_extract,       3 },
    { 0x654,      I960_modtc,         3 },
    { 0x655,      I960_modpc,         3 },
    { 0x656,      I960_receive,      -2 },
    { 0x658,      I960_intctl,       -2 },
    { 0x659,      I960_sysctl,        3 },
    { 0x65b,      I960_icctl,         3 },
    { 0x65c,      I960_dcctl,         3 },
    { 0x65d,      I960_halt,          1 },
    { 0x660,      I960_calls,         1 },
    { 0x662,      I960_send,          3 },
    { 0x663,      I960_sendserv,      1 },
    { 0x664,      I960_resumprcs,     1 },
    { 0x665,      I960_schedprcs,     1 },
    { 0x666,      I960_saveprcs,      0 },
    { 0x668,      I960_condwait,      1 },
    { 0x669,      I960_wait,          1 },
    { 0x66a,      I960_signal,        1 },
    { 0x66b,      I960_mark,          0 },
    { 0x66c,      I960_fmark,         0 },
    { 0x66d,      I960_flushreg,      0 },
    { 0x66f,      I960_syncf,         0 },
    { 0x670,      I960_emul,          3 },
    { 0x671,      I960_ediv,          3 },
    { 0x673,      I960_ldtime,       -1 },
    { 0x674,      I960_fcvtir,       -2 },
    { 0x675,      I960_fcvtilr,      -2 },
    { 0x676,      I960_fscalerl,      3 },
    { 0x677,      I960_fscaler,       3 },
    { 0x680,      I960_fatanr,        3 },
    { 0x681,      I960_flogepr,       3 },
    { 0x682,      I960_flogr,         3 },
    { 0x683,      I960_fremr,         3 },
    { 0x684,      I960_fcmpor,        2 },
    { 0x685,      I960_fcmpr,         2 },
    { 0x688,      I960_fsqrtr,       -2 },
    { 0x689,      I960_fexpr,        -2 },
    { 0x68a,      I960_flogbnr,      -2 },
    { 0x68b,      I960_froundr,      -2 },
    { 0x68c,      I960_fsinr,        -2 },
    { 0x68d,      I960_fcosr,        -2 },
    { 0x68e,      I960_ftanr,        -2 },
    { 0x68f,      I960_fclassr,       1 },
    { 0x690,      I960_fatanrl,       3 },
    { 0x691,      I960_flogeprl,      3 },
    { 0x692,      I960_flogrl,        3 },
    { 0x693,      I960_fremrl,        3 },
    { 0x694,      I960_fcmporl,       2 },
    { 0x695,      I960_fcmprl,        2 },
    { 0x698,      I960_fsqrtrl,      -2 },
    { 0x699,      I960_fexprl,       -2 },
    { 0x69a,      I960_flogbnrl,     -2 },
    { 0x69b,      I960_froundrl,     -2 },
    { 0x69c,      I960_fsinrl,       -2 },
    { 0x69d,      I960_fcosrl,       -2 },
    { 0x69e,      I960_ftanrl,       -2 },
    { 0x69f,      I960_fclassrl,      1 },
    { 0x6c0,      I960_fcvtri,       -2 },
    { 0x6c1,      I960_fcvtril,      -2 },
    { 0x6c2,      I960_fcvtzri,      -2 },
    { 0x6c3,      I960_fcvtzril,     -2 },
    { 0x6c9,      I960_fmovr,        -2 },
    { 0x6d9,      I960_fmovrl,       -2 },
    { 0x6e1,      I960_fmovre,       -2 },
    { 0x6e2,      I960_fcpysre,       3 },
    { 0x6e3,      I960_fcpyrsre,      3 },
    { 0x701,      I960_mulo,          3 },
    { 0x708,      I960_remo,          3 },
    { 0x70b,      I960_divo,          3 },
    { 0x741,      I960_muli,          3 },
    { 0x748,      I960_remi,          3 },
    { 0x749,      I960_modi,          3 },
    { 0x74b,      I960_divi,          3 },
    { 0x780,      I960_addono,        3 },
    { 0x781,      I960_addino,        3 },
    { 0x782,      I960_subono,        3 },
    { 0x783,      I960_subino,        3 },
    { 0x784,      I960_selno,         3 },
    { 0x78b,      I960_fdivr,         3 },
    { 0x78c,      I960_fmulr,         3 },
    { 0x78d,      I960_fsubr,         3 },
    { 0x78f,      I960_faddr,         3 },
    { 0x790,      I960_addog,         3 },
    { 0x791,      I960_addig,         3 },
    { 0x792,      I960_subog,         3 },
    { 0x793,      I960_subig,         3 },
    { 0x794,      I960_selg,          3 },
    { 0x79b,      I960_fdivrl,        3 },
    { 0x79c,      I960_fmulrl,        3 },
    { 0x79d,      I960_fsubrl,        3 },
    { 0x79f,      I960_faddrl,        3 },
    { 0x7a0,      I960_addoe,         3 },
    { 0x7a1,      I960_addie,         3 },
    { 0x7a2,      I960_suboe,         3 },
    { 0x7a3,      I960_subie,         3 },
    { 0x7a4,      I960_sele,          3 },
    { 0x7b0,      I960_addoge,        3 },
    { 0x7b1,      I960_addige,        3 },
    { 0x7b2,      I960_suboge,        3 },
    { 0x7b3,      I960_subige,        3 },
    { 0x7b4,      I960_selge,         3 },
    { 0x7c0,      I960_addol,         3 },
    { 0x7c1,      I960_addil,         3 },
    { 0x7c2,      I960_subol,         3 },
    { 0x7c3,      I960_subil,         3 },
    { 0x7c4,      I960_sell,          3 },
    { 0x7d0,      I960_addone,        3 },
    { 0x7d1,      I960_addine,        3 },
    { 0x7d2,      I960_subone,        3 },
    { 0x7d3,      I960_subine,        3 },
    { 0x7d4,      I960_selne,         3 },
    { 0x7e0,      I960_addole,        3 },
    { 0x7e1,      I960_addile,        3 },
    { 0x7e2,      I960_subole,        3 },
    { 0x7e3,      I960_subile,        3 },
    { 0x7e4,      I960_selle,         3 },
    { 0x7f0,      I960_addoo,         3 },
    { 0x7f1,      I960_addio,         3 },
    { 0x7f2,      I960_suboo,         3 },
    { 0x7f3,      I960_subio,         3 },
    { 0x7f4,      I960_selo,          3 },
  };
  if ( reg_tab == nullptr )
  {
    reg_tab = reg_tab_buf;
    for ( int i = 0; i < qnumber(reg_init); i++ )
    {
      int j = reg_init[i].code - REG_MIN;
      QASSERT(10086, j >= 0 && j < qnumber(reg_tab_buf));
      reg_tab[j].itype = reg_init[i].itype;
      reg_tab[j].opnum = reg_init[i].opnum;
    }
  }

  int opcode = ((code >> 20) & 0xff0) | ((code >> 7) & 0xf);
  if ( opcode < REG_MIN || opcode > REG_MAX )
    return false;

  int i = opcode - REG_MIN;
  insn.itype = reg_tab[i].itype;
  bool fp = insn.itype >= I960_fp_first && insn.itype <= I960_fp_last;

  bool s1   = ((code >> 5)  & 1) != 0;
  bool s2   = ((code >> 6)  & 1) != 0;
  bool m1   = ((code >> 11) & 1) != 0;
  bool m2   = ((code >> 12) & 1) != 0;
  bool m3   = ((code >> 13) & 1) != 0;
  int src  =  code        & 0x1f;
  int src2 = (code >> 14) & 0x1f;
  int dst  = (code >> 19) & 0x1f;

  switch ( reg_tab[i].opnum )
  {
    case 1:
      regop(insn.Op1, m1, s1, src, fp);
      break;
    case -1:
      dstop(insn.Op1, m3, dst, fp);
      break;
    case 2:
      regop(insn.Op1, m1, s1, src, fp);
      regop(insn.Op2, m2, s2, src2, fp);
      break;
    case -2:
      regop(insn.Op1, m1, s1, src, fp);
      dstop(insn.Op2, m3, dst, fp);
      break;
    case 3:
      regop(insn.Op1, m1, s1, src, fp);
      regop(insn.Op2, m2, s2, src2, fp);
      dstop(insn.Op3, m3, dst, fp);
      break;
  }
  return true;
}

//--------------------------------------------------------------------------
int i960_t::i960_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  if ( insn.ip & 3 )
    return 0;   // alignment error
  uint32 code = insn.get_next_dword();
  switch ( code >> 28 )
  {
    case 0x0:
    case 0x1:
      if ( !ctrl(insn, code) )
        return 0;
      break;
    case 0x2:
    case 0x3:
      if ( !cobr(insn, code) )
        return 0;
      break;
    case 0x5:
    case 0x6:
    case 0x7:
      if ( !reg(insn, code) )
        return 0;
      break;
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
    case 0xC:
      if ( !mem(insn, code) )
        return 0;
      break;
    default:
      return 0;
  }
  return insn.itype == I960_null ? 0 : insn.size;
}

