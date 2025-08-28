/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

 // SWAP4 is not disassembled!

#include "tms6.hpp"

//lint -estring(958,member) padding is required
//lint -e754 local struct member is not referenced

//--------------------------------------------------------------------------
struct tmsinsn_t
{
  uint16 itype;
  uchar src1;
  uchar src2;
  uchar dst;
  bool flip_src1_src2;
};

// operand types
enum op_types_t
{
t_none,
t_sint,
t_xsint,
t_uint,
t_xuint,
t_slong,
t_xslong,
t_ulong,
t_xulong,
t_scst5,
t_ucst5,
t_slsb16,
t_xslsb16,
t_ulsb16,
t_xulsb16,
t_smsb16,
t_xsmsb16,
t_umsb16,
t_xumsb16,
t_irp,
t_cregr,
t_cregw,
t_ucst1,
t_dp,
t_xdp,
t_sp,
t_xsp,
t_ucst15,
t_scst7,
t_ucst3,
t_b14,
t_dint,
t_i2,
t_xi2,
t_i4,
t_xi4,
t_s2,
t_xs2,
t_u2,
t_xu2,
t_s4,
t_xs4,
t_u4,
t_xu4,
t_scst10,
t_scst12,
t_scst21,
t_a3,          // a3 or b3
t_bv2,         // 2 bits
t_bv4,         // 4 bits
t_ds2,
t_sllong,
t_ullong,
t_dws4,
t_dwu4,
t_xdwop1,
t_xdwop2,
t_dwop1,
t_dwdst,
t_qwop2,
t_qwdst,
t_xop,
t_dst,
t_xdwop,
t_op1,
t_xop2,
t_qwop1,
t_op2,
t_xop1,

// Some instructions dont have the second unit on the first operand
t_op1_nx
};

//--------------------------------------------------------------------------
static void swap_op1_and_op2(insn_t &insn)
{
  if ( (insn.cflags & aux_pseudo) == 0 )
  {
    op_t tmp = insn.Op1;
    insn.Op1 = insn.Op2;
    insn.Op2 = tmp;
    insn.Op1.n = 0;
    insn.Op2.n = 1;
  }
}

//--------------------------------------------------------------------------
static void swap_op2_and_op3(insn_t &insn)
{
  if ( (insn.cflags & aux_pseudo) == 0 )
  {
    op_t tmp = insn.Op3;
    insn.Op3 = insn.Op2;
    insn.Op2 = tmp;
    insn.Op2.n = 1;
    insn.Op3.n = 2;
  }
}

//--------------------------------------------------------------------------
inline int op_spmask(const insn_t &insn, op_t &x, uint32 code)
{
  x.type  = o_spmask;
  x.dtype = dt_dword;
  x.reg   = (code >> 18) & 0xFF;
  return insn.size;
}

//--------------------------------------------------------------------------
inline void op_reg(op_t &x, int reg)
{
  x.type  = o_reg;
  x.dtype = dt_dword;
  x.reg   = reg;
}

//--------------------------------------------------------------------------
inline void op_ucst15(op_t &x, uint32 code)
{
  x.type  = o_imm;
  x.dtype = dt_dword;
  x.value = (code >> 8) & 0x7FFF;
}

//--------------------------------------------------------------------------
inline bool second_unit(const insn_t &insn)
{
  return insn.funit == FU_L2
      || insn.funit == FU_S2
      || insn.funit == FU_M2
      || insn.funit == FU_D2;
}

//--------------------------------------------------------------------------
inline void op_reg(
        op_t &x,
        const insn_t &insn,
        int reg,
        bool cross_path = false)
{
  x.type  = o_reg;
  x.dtype = dt_dword;
  x.reg   = reg;
  if ( second_unit(insn) != cross_path )
    x.reg += rB0;
}

//--------------------------------------------------------------------------
static uchar make_reg(const insn_t &insn, int32 v, bool isother)
{
  if ( second_unit(insn) == isother )
    return uchar(v);
  else
    return uchar((v) + rB0);
}

//--------------------------------------------------------------------------
inline void op_imm(op_t &x, uval_t val)
{
  x.type  = o_imm;
  x.dtype = dt_dword;
  x.value = val;
}

//--------------------------------------------------------------------------
inline void get_unit(insn_t &insn, ushort code, funit_t base_unit)
{
  uint8 s = code & 1;
  insn.funit = base_unit + s;
}

//--------------------------------------------------------------------------
inline sval_t cst3_to_scst5(uint16 cst3, bool sn)
{
  int scst5 = sn ? cst3 - 8 : cst3;
  if ( scst5 == 0 )
    scst5 = 8;
  return scst5;
}

//--------------------------------------------------------------------------
inline uval_t cst3_to_ucst5(uint16 cst3)
{
  uval_t scst5 = cst3 == 0 ? 16
            : cst3 == 7 ? 8
            : cst3;
  return scst5;
}

//--------------------------------------------------------------------------
// bcb __ea64__ fails with backend error if this function is declared inline
void tms6_t::op_near(
        const insn_t &insn,
        op_t &x,
        uint32 code,
        int shift,
        uval_t mask) const
{
  x.type = o_near;
  x.dtype = dt_code;
  sval_t cst = (code >> shift) & mask;
  int signbit = (mask + 1) >> 1;
  if ( cst & signbit )
    cst |= ~mask;     // extend sign

  // for BNOP the shift amount changes when its in a compact fetch packet
  if ( insn.itype == TMS6_bnop
    && get_fph(nullptr, get_fph_pos(insn.ea)) )
  {
    cst <<= 1;
  }
  else
  {
    cst <<= 2;
  }

  x.addr = trunc_ea((insn.ip & ~0x1F) + cst);
}

//--------------------------------------------------------------------------
struct tms_reginfo_t
{
  int mask;
  int idx;
  int reg;
};

static const tms_reginfo_t ctrls[] =
{
  { 0x21F, 0x00, rAMR    }, // Addressing mode register
  { 0x21F, 0x01, rCSR    }, // Control status register
//  { 0x21F, 0x02, rIFR    }, // Interrupt flag register
  { 0x21F, 0x02, rISR    }, // Interrupt set register
  { 0x21F, 0x03, rICR    }, // Interrupt clear register
  { 0x21F, 0x04, rIER    }, // Interrupt enable register
  { 0x21F, 0x05, rISTP   }, // Interrupt service table pointer register
  { 0x21F, 0x06, rIRP    }, // Interrupt return pointer register
  { 0x21F, 0x07, rNRP    }, // Nonmaskable interrupt or exception return pointer
  { 0x3FF, 0x0A, rTSCL   }, // Time-stamp counter (low 32 bits) register
  { 0x3FF, 0x0B, rTSCH   }, // Time-stamp counter (high 32 bits) register
  { 0x3FF, 0x0D, rILC    }, // Inner loop count register
  { 0x3FF, 0x0E, rRILC   }, // Reload inner loop count register
  { 0x3FF, 0x0F, rREP    }, // Restricted entry point address register
  { 0x3FF, 0x10, rPCE1   }, // Program counter, E1 phase
  { 0x3FF, 0x11, rDNUM   }, // DSP core number register
  { 0x3FF, 0x12, rFADCR  }, // Floating-point adder configuration register
  { 0x3FF, 0x13, rFAUCR  }, // Floating-point auxiliary configuration register
  { 0x3FF, 0x14, rFMCR   }, // Floating-point multiplier configuration register
  { 0x3FF, 0x15, rSSR    }, // Saturation status register
  { 0x3FF, 0x16, rGPLYA  }, // GMPY A-side polynomial register
  { 0x3FF, 0x17, rGPLYB  }, // GMPY B-side polynomial register
  { 0x3FF, 0x18, rGFPGFR }, // Galois field multiply control register
  { 0x3FF, 0x1A, rTSR    }, // Task state register
  { 0x3FF, 0x1B, rITSR   }, // Interrupt task state register
  { 0x3FF, 0x1C, rNTSR   }, // NMI/Exception task state register
  { 0x3FF, 0x1D, rECR    }, // Exception clear register
//  { 0x3FF, 0x1D, rEFR    }, // Exception flag register
  { 0x3FF, 0x1F, rIERR   }, // Internal exception report register
};

//--------------------------------------------------------------------------
static int find_crreg(int idx)
{
  for ( int i=0; i < qnumber(ctrls); i++ )
    if ( ctrls[i].idx == (idx & ctrls[i].mask) )
      return ctrls[i].reg;
  return -1;
}

//--------------------------------------------------------------------------
static const uint8 cond_map[] =
{
  0xC, 0xD, 0x2, 0x3
};

//--------------------------------------------------------------------------
int tms6_t::make_op(
        const insn_t &insn,
        op_t &x,
        uint32 code,
        uchar optype,
        int32 v,
        bool isother) const
{
  switch ( optype )
  {
    case t_none:
      break;
    case t_s2:
    case t_u2:
    case t_i2:
    case t_i4:
    case t_s4:
    case t_u4:
    case t_ds2:
    case t_sint:
    case t_uint:
    case t_bv2:
    case t_bv4:
    case t_xop1:
      isother = false;
      [[fallthrough]];
    case t_xs2:
    case t_xu2:
    case t_xi2:
    case t_xi4:
    case t_xu4:
    case t_xs4:
    case t_xsint:
    case t_xuint:
    case t_xop:
    case t_op2:
      x.type = o_reg;
      x.dtype = dt_dword;
      x.reg = make_reg(insn, v, isother);
      break;
    case t_slsb16:
    case t_ulsb16:
    case t_smsb16:
    case t_umsb16:
      isother = false;
      [[fallthrough]];
    case t_xslsb16:
    case t_xulsb16:
    case t_xsmsb16:
    case t_xumsb16:
      x.type = o_reg;
      x.dtype = dt_word;
      x.reg = make_reg(insn, v, isother);
      break;
    case t_dint:
    case t_slong:
    case t_ulong:
    case t_sllong:
    case t_ullong:
    case t_dws4:
    case t_dwu4:
    case t_dwdst:
    case t_dwop1:
      isother = false;
      [[fallthrough]];
    case t_xslong:
    case t_xulong:
    case t_xdwop2:
    case t_xdwop1:
    case t_xdwop:
      x.type = o_regpair;
      x.quad_regpair = false;
      x.dtype = dt_qword;
      x.reg = make_reg(insn, v, isother);
      break;
    case t_sp:
    case t_dst:
    case t_op1_nx:
      isother = false;
      [[fallthrough]];
    case t_xsp:
    case t_op1:
    case t_xop2:
      x.type = o_reg;
      x.dtype = dt_float;
      x.reg = make_reg(insn, v, isother);
      break;
    case t_dp:
      isother = false;
      [[fallthrough]];
    case t_xdp:
      x.type = o_regpair;
      x.quad_regpair = false;
      x.dtype = dt_double;
      x.reg = make_reg(insn, v & ~1, isother);
      break;
    case t_ucst1:
      op_imm(x, v & 1);
      break;
    case t_scst5:
      if ( v & 0x10 )
        v |= ~0x1F;              // extend sign
      [[fallthrough]];
    case t_ucst5:
      op_imm(x, v);
      break;
    case t_ucst15:
      op_imm(x, (code >> 8) & 0x7FFF);
      break;
    case t_ucst3:
      op_imm(x, (code >> 13) & 7);
      break;
    case t_scst7:
      op_near(insn, x, code, 16, 0x7F);
      break;
    case t_scst10:
      op_near(insn, x, code, 13, 0x3FF);
      break;
    case t_scst12:
      op_near(insn, x, code, 16, 0xFFF);
      break;
    case t_scst21:
      op_near(insn, x, code, 7, 0x1FFFFF);
      break;
    case t_irp:
      x.type = o_reg;
      x.dtype = dt_word;
      if ( v == 6 )
        x.reg = rIRP;
      else if ( v == 7 )
        x.reg = rNRP;
      else
        return 0;
      break;
    case t_cregr: // read control reg
      {
        int idx = (code >> 18) & 0x1F;
        int reg = find_crreg(idx);
        if ( reg == -1 )
          return 0;
        if ( reg == rISR )
          reg = rIFR;
        if ( reg == rECR )
          reg = rEFR;
        op_reg(x, reg);
      }
      break;
    case t_cregw:
      {
        int idx = (code >> 23) & 0x1F;
        int reg = find_crreg(idx);
        if ( reg == -1 )
          return 0;
        op_reg(x, reg);
      }
      break;
    case t_b14:
      op_reg(x, rB14 + ((code >> 7) & 1));
      break;
    case t_a3:
      op_reg(x, make_reg(insn, rA3, isother));
      break;
    case t_qwop2:
    case t_qwdst:
      isother = false;
      [[fallthrough]];
    case t_qwop1:
      x.type = o_regpair;
      x.quad_regpair = true;
      x.dtype = dt_byte16;
      x.reg = make_reg(insn, v, isother);
      break;
    default:
      INTERR(257);
  }
  return true;
}

//--------------------------------------------------------------------------
void tms6_t::make_pseudo(insn_t &insn) const
{
  switch ( insn.itype )
  {
    case TMS6_add:
    case TMS6_or:
      if ( insn.Op1.type == o_imm && insn.Op1.value == 0 )
      {
        insn.itype = TMS6_mv;
SHIFT_OPS:
        insn.Op1 = insn.Op2;
        insn.Op2 = insn.Op3;
        insn.Op1.n = 0;
        insn.Op2.n = 1;
        insn.Op3.type = o_void;
        insn.cflags |= aux_pseudo;
      }
      break;
    case TMS6_sub:
      if ( insn.Op1.type == o_imm
        && insn.Op1.value == 0
        && insn.funit != FU_D1
        && insn.funit != FU_D2 )
      {
        insn.itype = TMS6_neg;
        goto SHIFT_OPS;
      }
      if ( insn.Op1.type == o_reg
        && insn.Op2.type == o_reg
        && insn.Op3.type == o_reg
        && insn.Op1.reg  == insn.Op2.reg )
      {
        insn.itype = TMS6_zero;
        insn.Op1.reg = insn.Op3.reg;
        insn.Op2.type = o_void;
        insn.Op3.type = o_void;
        insn.cflags |= aux_pseudo;
      }
      break;
    case TMS6_xor:
      if ( insn.Op1.type == o_imm && insn.Op1.value == uval_t(-1) )
      {
        insn.itype = TMS6_not;
        goto SHIFT_OPS;
      }
      break;
    case TMS6_packlh2:
      if ( insn.Op1.type == o_reg
        && insn.Op2.type == o_reg
        && insn.Op1.reg  == insn.Op2.reg )
      {
        insn.itype = TMS6_swap2;
        swap_op2_and_op3(insn);
        insn.Op3.type = o_void;
        insn.cflags |= aux_pseudo;
      }
      break;
  }
}

//--------------------------------------------------------------------------
int tms6_t::table_insns(
        insn_t &insn,
        uint32 code,
        const tmsinsn_t *tinsn,
        bool isother) const
{
// +------------------------------------------...
// |31    29|28|27    23|22   18|17        13|...
// |  creg  |z |  dst   |  src2 |  src1/cst  |...
// +------------------------------------------...

  if ( tinsn->itype == TMS6_null )
    return 0;
  insn.itype = tinsn->itype;
  if ( isother )
    insn.cflags |= aux_xp;  // xpath is used

  op_t *xptr = &insn.Op1;
  if ( !make_op(insn, *xptr, code, tinsn->src1, (code >> (tinsn->flip_src1_src2 ? 18 : 13)) & 0x1F, isother) )
    return 0;
  if ( xptr->type != o_void )
    xptr++;
  if ( !make_op(insn, *xptr, code, tinsn->src2, (code >> (tinsn->flip_src1_src2 ? 13 : 18)) & 0x1F, isother) )
    return 0;
  if ( xptr->type != o_void )
    xptr++;
  if ( !make_op(insn, *xptr, code, tinsn->dst, (code >> 23) & 0x1F, isother) )
    return 0;

  make_pseudo(insn);
  return insn.size;
}

//==========================================================================
// Classic opcodes map (32 bits)
//==========================================================================

//--------------------------------------------------------------------------
//      L UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t lops[128] =
{                                                                // bits 11..5
  { TMS6_pack2,   t_i2,          t_xi2,          t_i2            }, // 000 0000
  { TMS6_dptrunc, t_none,        t_dp,           t_sint          }, // 000 0001
  { TMS6_add,     t_scst5,       t_xsint,        t_sint          }, // 000 0010
  { TMS6_add,     t_sint,        t_xsint,        t_sint          }, // 000 0011
  { TMS6_sub2,    t_i2,          t_xi2,          t_i2            }, // 000 0100
  { TMS6_add2,    t_i2,          t_xi2,          t_i2            }, // 000 0101
  { TMS6_sub,     t_scst5,       t_xsint,        t_sint          }, // 000 0110
  { TMS6_sub,     t_sint,        t_xsint,        t_sint          }, // 000 0111
  { TMS6_dpint,   t_none,        t_dp,           t_sint          }, // 000 1000
  { TMS6_dpsp,    t_none,        t_dp,           t_sp            }, // 000 1001
  { TMS6_spint,   t_none,        t_sp,           t_sint          }, // 000 1010
  { TMS6_sptrunc, t_none,        t_xsp,          t_sint          }, // 000 1011
  { TMS6_null,    t_none,        t_none,         t_none          }, // 000 1100
  { TMS6_null,    t_none,        t_none,         t_none          }, // 000 1101
  { TMS6_ssub,    t_scst5,       t_xsint,        t_sint          }, // 000 1110
  { TMS6_ssub,    t_sint,        t_xsint,        t_sint          }, // 000 1111
  { TMS6_addsp,   t_sp,          t_xsp,          t_sp            }, // 001 0000
  { TMS6_subsp,   t_sp,          t_xsp,          t_sp            }, // 001 0001
  { TMS6_sadd,    t_scst5,       t_xsint,        t_sint          }, // 001 0010
  { TMS6_sadd,    t_sint,        t_xsint,        t_sint          }, // 001 0011
  { TMS6_null,    t_none,        t_none,         t_none          }, // 001 0100
  { TMS6_subsp,   t_xsp,         t_sp,           t_sp            }, // 001 0101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 001 0110
  { TMS6_sub,     t_xsint,       t_sint,         t_sint          }, // 001 0111
  { TMS6_adddp,   t_dp,          t_xdp,          t_dp            }, // 001 1000
  { TMS6_subdp,   t_dp,          t_xdp,          t_dp            }, // 001 1001
  { TMS6_null,    t_none,        t_xsint,        t_sint          }, // 001 1010 * why parse args?
  { TMS6_packlh2, t_i2,          t_xi2,          t_i2            }, // 001 1011 *
  { TMS6_packhl2, t_i2,          t_xi2,          t_i2            }, // 001 1100
  { TMS6_subdp,   t_xdp,         t_dp,           t_dp            }, // 001 1101
  { TMS6_packh2,  t_i2,          t_xi2,          t_i2            }, // 001 1110
  { TMS6_ssub,    t_xsint,       t_sint,         t_sint          }, // 001 1111
  { TMS6_add,     t_scst5,       t_slong,        t_slong         }, // 010 0000
  { TMS6_add,     t_xsint,       t_slong,        t_slong         }, // 010 0001
  { TMS6_dadd,    t_scst5,       t_xdwop2,       t_dwdst         }, // 010 0010
  { TMS6_add,     t_sint,        t_xsint,        t_slong         }, // 010 0011
  { TMS6_sub,     t_scst5,       t_slong,        t_slong         }, // 010 0100
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 0101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 0110
  { TMS6_sub,     t_sint,        t_xsint,        t_slong         }, // 010 0111
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 1000
  { TMS6_addu,    t_xuint,       t_ulong,        t_ulong         }, // 010 1001
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 1010
  { TMS6_addu,    t_uint,        t_xuint,        t_ulong         }, // 010 1011
  { TMS6_ssub,    t_scst5,       t_slong,        t_slong         }, // 010 1100
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 1101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 010 1110
  { TMS6_subu,    t_uint,        t_xuint,        t_ulong         }, // 010 1111
  { TMS6_sadd,    t_scst5,       t_slong,        t_slong         }, // 011 0000
  { TMS6_sadd,    t_xsint,       t_slong,        t_slong         }, // 011 0001
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 0010
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 0011
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 0100
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 0101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 0110
  { TMS6_sub,     t_xsint,       t_sint,         t_slong         }, // 011 0111
  { TMS6_abs,     t_none,        t_slong,        t_slong         }, // 011 1000
  { TMS6_intdp,   t_none,        t_xsint,        t_dp            }, // 011 1001
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 1010
  { TMS6_intdpu,  t_none,        t_xuint,        t_dp            }, // 011 1011
  { TMS6_faddsp,  t_op1_nx,      t_xop2,         t_dst           }, // 011 1100
  { TMS6_fsubsp,  t_op1_nx,      t_xop2,         t_dst           }, // 011 1101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 011 1110
  { TMS6_subu,    t_xuint,       t_uint,         t_ulong         }, // 011 1111
  { TMS6_sat,     t_none,        t_slong,        t_sint          }, // 100 0000
  { TMS6_min2,    t_s2,          t_xs2,          t_s2            }, // 100 0001
  { TMS6_max2,    t_s2,          t_xs2,          t_s2            }, // 100 0010
  { TMS6_maxu4,   t_u4,          t_xu4,          t_u4            }, // 100 0011
  { TMS6_cmpgt,   t_scst5,       t_slong,        t_uint          }, // 100 0100
  { TMS6_cmpgt,   t_xsint,       t_slong,        t_uint          }, // 100 0101
  { TMS6_cmpgt,   t_scst5,       t_xsint,        t_uint          }, // 100 0110
  { TMS6_cmpgt,   t_sint,        t_xsint,        t_uint          }, // 100 0111
  { TMS6_minu4,   t_u4,          t_xu4,          t_u4            }, // 100 1000
  { TMS6_intspu,  t_none,        t_xuint,        t_sp            }, // 100 1010
  { TMS6_intsp,   t_none,        t_xsint,        t_sp            }, // 100 1010
  { TMS6_subc,    t_uint,        t_xuint,        t_uint          }, // 100 1011
  // 1: on the C62x and C67x, op1 is ucst4 (the TI docs are misleading); on the
  //    C64x/C64x+ and C66x, op1 is ucst5; since the MSB should always be clear
  //    on the former we can treat it as a 5-bit field
  { TMS6_cmpgtu,  t_ucst5,       t_ulong,        t_uint          }, // 100 1100 // see [1]
  { TMS6_cmpgtu,  t_xuint,       t_ulong,        t_uint          }, // 100 1101
  { TMS6_cmpgtu,  t_ucst5,       t_xuint,        t_uint          }, // 100 1110 // see [1]
  { TMS6_cmpgtu,  t_uint,        t_xuint,        t_uint          }, // 100 1111
  { TMS6_cmpeq,   t_scst5,       t_slong,        t_uint          }, // 101 0000
  { TMS6_cmpeq,   t_xsint,       t_slong,        t_uint          }, // 101 0001
  { TMS6_cmpeq,   t_scst5,       t_xsint,        t_uint          }, // 101 0010
  { TMS6_cmpeq,   t_sint,        t_xsint,        t_uint          }, // 101 0011
  { TMS6_cmplt,   t_scst5,       t_slong,        t_uint          }, // 101 0100
  { TMS6_cmplt,   t_xsint,       t_slong,        t_uint          }, // 101 0101
  { TMS6_cmplt,   t_scst5,       t_xsint,        t_uint          }, // 101 0110
  { TMS6_cmplt,   t_sint,        t_xsint,        t_uint          }, // 101 0111
  { TMS6_fadddp,  t_dwop1,       t_xdwop2,       t_dwdst         }, // 101 1000
  { TMS6_fsubdp,  t_dwop1,       t_xdwop2,       t_dwdst         }, // 101 1001
  { TMS6_subabs4, t_u4,          t_xu4,          t_u4            }, // 101 1010
  { TMS6_null,    t_none,        t_none,         t_none          }, // 101 1011
  { TMS6_cmpltu,  t_ucst5,       t_ulong,        t_uint          }, // 101 1100 // see [1]
  { TMS6_cmpltu,  t_xuint,       t_ulong,        t_uint          }, // 101 1101
  { TMS6_cmpltu,  t_ucst5,       t_xuint,        t_uint          }, // 101 1110 // see [1]
  { TMS6_cmpltu,  t_uint,        t_xuint,        t_uint          }, // 101 1111
  { TMS6_norm,    t_none,        t_slong,        t_uint          }, // 110 0000
  { TMS6_shlmb,   t_u4,          t_xu4,          t_u4            }, // 110 0001
  { TMS6_shrmb,   t_u4,          t_xu4,          t_u4            }, // 110 0010
  { TMS6_norm,    t_none,        t_xsint,        t_uint          }, // 110 0011
  { TMS6_ssub2,   t_s2,          t_xs2,          t_s2            }, // 110 0100
  { TMS6_add4,    t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_sub4,    t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_null,    t_none,        t_none,         t_none          }, // 110 0111
  { TMS6_packl4,  t_i4,          t_xi4,          t_i4            }, // 110 1000
  { TMS6_packh4,  t_i4,          t_xi4,          t_i4            }, // 110 1001
  // op1 is actually scst5, but because only the LSB is meaningful, we decode
  // it as ucst1 so that the result would be correct for the assembler
  { TMS6_lmbd,   t_ucst1,       t_xuint,        t_uint          }, // 110 1010
  { TMS6_lmbd,   t_uint,        t_xuint,        t_uint          }, // 110 1011
  { TMS6_dmv,    t_op1_nx,      t_xop2,         t_dwdst         }, // 110 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 1101
  { TMS6_xor,    t_scst5,       t_xuint,        t_uint          }, // 110 1110
  { TMS6_xor,    t_uint,        t_xuint,        t_uint          }, // 110 1111
  { TMS6_addsp,  t_sp,          t_xsp,          t_sp            }, // 111 0000
  { TMS6_subsp,  t_sp,          t_xsp,          t_sp            }, // 111 0001
  { TMS6_adddp,  t_dp,          t_xdp,          t_dp            }, // 111 0010
  { TMS6_subdp,  t_dp,          t_xdp,          t_dp            }, // 111 0011
  { TMS6_faddsp, t_op1_nx,      t_xop2,         t_dst           }, // 111 0100
  { TMS6_subsp,  t_xsp,         t_sp,           t_sp            }, // 111 0101
  { TMS6_fsubsp, t_op1_nx,      t_xop2,         t_dst           }, // 111 0110
  { TMS6_subdp,  t_xdp,         t_dp,           t_dp            }, // 111 0111
  { TMS6_land,   t_op1_nx,      t_xop2,         t_dst           }, // 111 1000
  { TMS6_landn,  t_op1_nx,      t_xop2,         t_dst           }, // 111 1001
  { TMS6_and,    t_scst5,       t_xuint,        t_uint          }, // 111 1010
  { TMS6_and,    t_uint,        t_xuint,        t_uint          }, // 111 1011
  { TMS6_andn,   t_uint,        t_xuint,        t_uint          }, // 111 1100
  { TMS6_lor,    t_op1,         t_xop2,         t_dst           }, // 111 1101
  { TMS6_or,     t_scst5,       t_xuint,        t_uint          }, // 111 1110
  { TMS6_or,     t_uint,        t_xuint,        t_uint          }, // 111 1111
};

static const tmsinsn_t esc1A[32] =
{
  { TMS6_abs,      t_none,        t_xsint,        t_sint          }, // 0 0000
  { TMS6_swap4,    t_none,        t_xu4,          t_u4            }, // 0 0001
  { TMS6_unpklu4,  t_none,        t_xsint,        t_sint          }, // 0 0010
  { TMS6_unpkhu4,  t_none,        t_xsint,        t_sint          }, // 0 0011
  { TMS6_abs2,     t_none,        t_xs2,          t_s2            }, // 0 0100
  { TMS6_mvk,      t_none,        t_scst5,        t_sint          }, // 0 0101
  { TMS6_unpkhu2,  t_none,        t_xop,          t_dwdst         }, // 0 0110
  { TMS6_unpkh2,   t_none,        t_xop,          t_dwdst         }, // 0 0111
  { TMS6_unpkbu4,  t_none,        t_xop,          t_dwdst         }, // 0 1000
  { TMS6_crot90,   t_none,        t_xop,          t_dst           }, // 0 1001
  { TMS6_crot270,  t_none,        t_xop,          t_dst           }, // 0 1010
  { TMS6_null,     t_none,        t_none,         t_none          }, // 0 1011
  { TMS6_null,     t_none,        t_none,         t_none          }, // 0 1100
  { TMS6_null,     t_none,        t_none,         t_none          }, // 0 1101
  { TMS6_null,     t_none,        t_none,         t_none          }, // 0 1110
  { TMS6_null,     t_none,        t_none,         t_none          }, // 0 1111
  { TMS6_dspinth,  t_none,        t_xdwop,        t_dst           }, // 1 0000
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 0001
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 0010
  { TMS6_dinthspu, t_none,        t_xop,          t_dwdst         }, // 1 0011
  { TMS6_dspint,   t_none,        t_xdwop,        t_dwdst         }, // 1 0100
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 0101
  { TMS6_dintspu,  t_none,        t_xdwop2,       t_dwdst         }, // 1 0110
  //               ^manual is wrong its t_xdwop2, not x_op
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 0111
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1000
  { TMS6_dcrot270, t_none,        t_xdwop,        t_dwdst         }, // 1 1001
  { TMS6_dcrot90,  t_none,        t_xdwop,        t_dwdst         }, // 1 1010
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1011
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1100
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1101
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1110
  { TMS6_null,     t_none,        t_none,         t_none          }, // 1 1111
};

int tms6_t::l_ops(insn_t &insn, uint32 code) const
{
// +--------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|1|0|s|p|
// +--------------------------------------------------------------+
  int opcode = (code >> 5) & 0x7F;
  if ( opcode == 2 && (code & BIT17) != 0 )
  {
    // SUB (.unit) src1, scst5, dst is encoded as ADD (.unit) -scst5, src2, dst
    // where the src1 register is now scst5 and scst5 is now -scst5
    static const tmsinsn_t t_sub = { TMS6_sub, t_scst5, t_sint, t_sint };
    int res = table_insns(insn, code, &t_sub, (code & BIT12) != 0);
    if ( res != 0 )
    {
      insn.Op1.value = ~insn.Op1.value + 1;
      swap_op1_and_op2(insn);
      return res;
    }
  }

  const tmsinsn_t *table = lops;
  switch ( opcode )
  {
    case 0x1A:
      opcode = (code >> 13) & 0x1F;
      table = esc1A;
      break;
    case 0x70: // addsp
    case 0x71: // subsp
    case 0x72: // adddp
    case 0x73: // subdp
    case 0x74: // faddsp
    case 0x76: // fsubsp
      insn.funit += 2; // move from L to S unit
      break;
  }
  return table_insns(insn, code, table + opcode, (code & BIT12) != 0);
}

//--------------------------------------------------------------------------
//      M UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t mops[32] =
{                                                              // bits 11..7
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0000
  { TMS6_mpyh,    t_smsb16,     t_xsmsb16,      t_sint          }, // 0 0001
  { TMS6_smpyh,   t_smsb16,     t_xsmsb16,      t_sint          }, // 0 0010
  { TMS6_mpyhsu,  t_smsb16,     t_xumsb16,      t_sint          }, // 0 0011
  { TMS6_mpyi,    t_sint,       t_xsint,        t_sint          }, // 0 0100
  { TMS6_mpyhus,  t_umsb16,     t_xsmsb16,      t_sint          }, // 0 0101
  { TMS6_mpyi,    t_scst5,      t_xsint,        t_sint          }, // 0 0110
  { TMS6_mpyhu,   t_umsb16,     t_xumsb16,      t_uint          }, // 0 0111
  { TMS6_mpyid,   t_sint,       t_xsint,        t_dint          }, // 0 1000
  { TMS6_mpyhl,   t_smsb16,     t_xslsb16,      t_sint          }, // 0 1001
  { TMS6_smpyhl,  t_smsb16,     t_xslsb16,      t_sint          }, // 0 1010
  { TMS6_mpyhslu, t_smsb16,     t_xulsb16,      t_sint          }, // 0 1011
  { TMS6_mpyid,   t_scst5,      t_xsint,        t_dint          }, // 0 1100
  { TMS6_mpyhuls, t_umsb16,     t_xslsb16,      t_sint          }, // 0 1101
  { TMS6_mpydp,   t_dp,         t_dp,           t_dp            }, // 0 1110
  { TMS6_mpyhlu,  t_umsb16,     t_xulsb16,      t_uint          }, // 0 1111
  { TMS6_mpy32,   t_sint,       t_xsint,        t_sint          }, // 1 0000
  { TMS6_mpylh,   t_slsb16,     t_xsmsb16,      t_sint          }, // 1 0001
  { TMS6_smpylh,  t_slsb16,     t_xsmsb16,      t_sint          }, // 1 0010
  { TMS6_mpylshu, t_slsb16,     t_xumsb16,      t_sint          }, // 1 0011
  { TMS6_mpy32,   t_sint,       t_xsint,        t_dint          }, // 1 0100
  { TMS6_mpyluhs, t_ulsb16,     t_xsmsb16,      t_sint          }, // 1 0101
  { TMS6_mpy32su, t_sint,       t_xuint,        t_dint          }, // 1 0000
  { TMS6_mpylhu,  t_ulsb16,     t_xumsb16,      t_uint          }, // 1 0111
  { TMS6_mpy,     t_scst5,      t_xslsb16,      t_sint          }, // 1 1000
  { TMS6_mpy,     t_slsb16,     t_xslsb16,      t_sint          }, // 1 1001
  { TMS6_smpy,    t_slsb16,     t_xslsb16,      t_sint          }, // 1 1010
  { TMS6_mpysu,   t_slsb16,     t_xulsb16,      t_sint          }, // 1 1011
  { TMS6_mpysp,   t_sp,         t_xsp,          t_sp            }, // 1 1100
  { TMS6_mpyus,   t_ulsb16,     t_xslsb16,      t_sint          }, // 1 1101
  { TMS6_mpysu,   t_scst5,      t_xulsb16,      t_sint          }, // 1 1110
  { TMS6_mpyu,    t_ulsb16,     t_xulsb16,      t_uint          }, // 1 1111
};

int tms6_t::m_ops(insn_t &insn, uint32 code) const
{
// +------------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |0|0|0|0|0|s|p|
// +------------------------------------------------------------------+

  return table_insns(insn, code, mops + ((code >> 7) & 0x1F), (code & BIT12) != 0);
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t dops[] =
{                                                               // bits 12..7
  { TMS6_add,   t_sint,         t_sint,         t_sint          }, // 01 0000
  { TMS6_sub,   t_sint,         t_sint,         t_sint          }, // 01 0001
  { TMS6_add,   t_ucst5,        t_sint,         t_sint          }, // 01 0010
  { TMS6_sub,   t_ucst5,        t_sint,         t_sint          }, // 01 0011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 0111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 01 1111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 0111
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1000
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1001
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1010
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1011
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1100
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 10 1111
  { TMS6_addab, t_sint,         t_sint,         t_sint          }, // 11 0000
  { TMS6_subab, t_sint,         t_sint,         t_sint          }, // 11 0001
  { TMS6_addab, t_ucst5,        t_sint,         t_sint          }, // 11 0010
  { TMS6_subab, t_ucst5,        t_sint,         t_sint          }, // 11 0011
  { TMS6_addah, t_sint,         t_sint,         t_sint          }, // 11 0100
  { TMS6_subah, t_sint,         t_sint,         t_sint          }, // 11 0101
  { TMS6_addah, t_ucst5,        t_sint,         t_sint          }, // 11 0110
  { TMS6_subah, t_ucst5,        t_sint,         t_sint          }, // 11 0111
  { TMS6_addaw, t_sint,         t_sint,         t_sint          }, // 11 1000
  { TMS6_subaw, t_sint,         t_sint,         t_sint          }, // 11 1001
  { TMS6_addaw, t_ucst5,        t_sint,         t_sint          }, // 11 1010
  { TMS6_subaw, t_ucst5,        t_sint,         t_sint          }, // 11 1011
  { TMS6_addad, t_sint,         t_sint,         t_sint          }, // 11 1100
  { TMS6_addad, t_ucst5,        t_sint,         t_sint          }, // 11 1101
  { TMS6_null,  t_none,         t_none,         t_none          }, // 11 1110
  { TMS6_null,  t_none,         t_none,         t_none          }, // 11 1111
};

int tms6_t::d_ops(insn_t &insn, uint32 code) const
{
// +--------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |  op  |1|0|0|0|0|s|p|
// +--------------------------------------------------------------+

  int opcode = (code >> 7) & 0x3F;
  int res = 0;
  if ( opcode == 0 )
  {
    static const tmsinsn_t mvk = { TMS6_mvk, t_scst5, t_none, t_sint };
    res = table_insns(insn, code, &mvk, 0);
  }
  else if ( opcode >= 0x10 )
  {
    res = table_insns(insn, code, dops + (opcode - 0x10), 0);
    if ( res != 0 )
      swap_op1_and_op2(insn);
  }
  return res;
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS WITH CROSSPATH
//--------------------------------------------------------------------------
static const tmsinsn_t dxops[32] =
{                                                               // bits 11..7
  { TMS6_mpy2,    t_s2,         t_xs2,          t_ullong        }, // 0 0000
  { TMS6_dotpsu4, t_s4,         t_xu4,          t_uint          }, // 0 0001
  { TMS6_mpyu4,   t_u4,         t_xu4,          t_dwu4          }, // 0 0010
  { TMS6_dotpu4,  t_s4,         t_xu4,          t_uint          }, // 0 0011
  { TMS6_mpyu2,   t_op1_nx,     t_xop2,         t_dwdst         }, // 0 0100
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0101
  { TMS6_dotp2,   t_s2,         t_xs2,          t_sint          }, // 0 0110
  { TMS6_mpylir,  t_sint,       t_xsint,        t_sint          }, // 0 0111
  { TMS6_mpyhir,  t_sint,       t_xsint,        t_sint          }, // 0 1000
  { TMS6_avgu4,   t_u4,         t_xu4,          t_u4            }, // 0 1001
  { TMS6_mpyhi,   t_sint,       t_xsint,        t_sllong        }, // 0 1010
  // TI docs say mpyspdp operands are "sp, xsp, sp", but the TI assembler wants
  // regpairs for operands 2 and 3, so the docs must be wrong
  { TMS6_mpyspdp, t_sp,         t_xdp,          t_dp            }, // 0 1011
  { TMS6_mpy32u,  t_uint,       t_xuint,        t_dint          }, // 0 1100
  { TMS6_sshvr,   t_sint,       t_xsint,        t_sint          }, // 0 1101
  { TMS6_sshvl,   t_sint,       t_xsint,        t_sint          }, // 0 1110
  { TMS6_rotl,    t_ucst5,      t_xuint,        t_uint          }, // 0 1111
  { TMS6_andn,    t_uint,       t_xuint,        t_uint          }, // 1 0000
  { TMS6_or,      t_uint,       t_xuint,        t_uint          }, // 1 0001
  { TMS6_add2,    t_i2,         t_xi2,          t_i2            }, // 1 0010
  { TMS6_and,     t_uint,       t_xuint,        t_uint          }, // 1 0011
  { TMS6_null,    t_none,       t_none,         t_none          }, // 1 0100
  { TMS6_add,     t_sint,       t_xsint,        t_sint          }, // 1 0101
  { TMS6_sub,     t_sint,       t_xsint,        t_sint          }, // 1 0110
  { TMS6_xor,     t_uint,       t_xuint,        t_uint          }, // 1 0111
  { TMS6_sadd2,   t_s2,         t_xs2,          t_s2            }, // 1 1000
  { TMS6_spack2,  t_sint,       t_xsint,        t_s2            }, // 1 1001
  { TMS6_spacku4, t_s2,         t_xs2,          t_u4            }, // 1 1010
  { TMS6_andn,    t_uint,       t_xuint,        t_uint          }, // 1 1011
  { TMS6_shru2,   t_uint,       t_xu2,          t_u2            }, // 1 1011
  { TMS6_shrmb,   t_u4,         t_xu4,          t_u4            }, // 1 1101
  { TMS6_min2,    t_s2,         t_xs2,          t_s2            }, // 1 1110
  { TMS6_fsubdp,  t_dwop1,      t_xdwop2,       t_dwdst         }, // 1 1111
};

int tms6_t::handle_dx(insn_t &insn, const tmsinsn_t *table, uint32 code) const
{
  int opcode = (code >> 7) & 0x1F;
  if ( opcode < 0x10 )
    insn.funit -= 2; // D -> M
  else if ( opcode >= 0x18 )
    insn.funit -= 4; // D -> S

  if ( opcode == 1 )
  {
    uint8 opfield = (code >> 13) & 0x1F;
    const tmsinsn_t *t_insn = nullptr;
    switch ( opfield )
    {
      case 0x10:
        {
          static const tmsinsn_t t_dxpnd4 =
          { TMS6_dxpnd4, t_none, t_xop, t_dwdst };
          //       ^ op1, xop2 are the same thing
          t_insn = &t_dxpnd4;
          break;
        }
      case 0x11:
        {
          static const tmsinsn_t t_dxpnd2 =
          { TMS6_dxpnd2, t_none, t_xop, t_dwdst };
          //       ^ op1, xop2 are the same thing
          t_insn = &t_dxpnd2;
          break;
        }
      default:
        break;
    }

    if ( t_insn != nullptr )
      return table_insns(insn, code, t_insn, (code & BIT12) != 0);
  }

  int size = table_insns(insn, code, table + opcode, (code & BIT12) != 0);
  if ( size > 0 )
  {
    switch ( insn.itype )
    {
      case TMS6_rotl:
      case TMS6_sshvl:
      case TMS6_sshvr:
      case TMS6_shru2:
        swap_op1_and_op2(insn);
        break;
    }
  }
  return size;
}

int tms6_t::dx_ops(insn_t &insn, uint32 code) const
{
// +-----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |  op  |0|1|1|0|0|s|p|
// +-----------------------------------------------------------------+

  return handle_dx(insn, dxops, code);
}

//--------------------------------------------------------------------------
//      D UNIT OPERATIONS WITH CONSTANT CROSSPATH
//--------------------------------------------------------------------------
#define BITGRP uint16(-1)

static const tmsinsn_t dxcops[32] =
{                                                                // bits 11..7
  { TMS6_smpy2,     t_s2,        t_xs2,          t_ullong        }, // 0 0000
  { BITGRP,         t_none,      t_xu4,          t_u4            }, // 0 0001
  { TMS6_mpysu4,    t_s4,        t_xu4,          t_dws4          }, // 0 0010
  { TMS6_dotpnrsu2, t_s2,        t_xu2,          t_sint          }, // 0 0011
  { TMS6_dotpn2,    t_s2,        t_xs2,          t_sint          }, // 0 0100
  { TMS6_dotp2,     t_s2,        t_xs2,          t_sllong        }, // 0 0101
  { TMS6_dotprsu2,  t_s2,        t_xu2,          t_sint          }, // 0 0110
  { TMS6_fmpydp,    t_dwop1,     t_xdwop1,       t_dwdst         }, // 0 0111
  { TMS6_gmpy4,     t_u4,        t_xu4,          t_u4,           }, // 0 1000
  { TMS6_avg2,      t_s2,        t_xs2,          t_s2            }, // 0 1001
  { TMS6_mpyli,     t_sint,      t_xsint,        t_sllong        }, // 0 1010
  // TI docs say mpysp2dp operands are "sp, xsp, sp", but the TI assembler
  // wants a regpair for operand 3, so the docs must be wrong
  { TMS6_mpysp2dp,  t_sp,        t_xsp,          t_dp            }, // 0 1011
  { TMS6_mpy32us,   t_uint,      t_xsint,        t_dint          }, // 0 1100
  { TMS6_null,      t_none,      t_none,         t_none          }, // 0 1101
  { TMS6_rotl,      t_uint,      t_xuint,        t_uint          }, // 0 1110
  { TMS6_null,      t_none,      t_none,         t_none          }, // 0 1111
  { TMS6_null,      t_none,      t_none,         t_none          }, // 1 0000
  { TMS6_or,        t_scst5,     t_xuint,        t_uint          }, // 1 0001
  { TMS6_sub2,      t_i2,        t_xi2,          t_i2            }, // 1 0010
  { TMS6_and,       t_scst5,     t_xuint,        t_uint          }, // 1 0011
  { TMS6_null,      t_none,      t_none,         t_none          }, // 1 0100
  { TMS6_add,       t_scst5,     t_xsint,        t_sint          }, // 1 0101
  { TMS6_null,      t_none,      t_none,         t_none          }, // 1 0110
  { TMS6_xor,       t_scst5,     t_xuint,        t_uint          }, // 1 0111
  { TMS6_saddus2,   t_u2,        t_xs2,          t_u2            }, // 1 1000
  { TMS6_saddu4,    t_u4,        t_xu4,          t_u4            }, // 1 1001
  { TMS6_sub,       t_sint,      t_xsint,        t_sint          }, // 1 1010
  { TMS6_shr2,      t_uint,      t_xs2,          t_s2            }, // 1 1011
  { TMS6_shlmb,     t_u4,        t_xu4,          t_u4            }, // 1 1100
  { TMS6_dmv,       t_sint,      t_xsint,        t_dint          }, // 1 1101
  { TMS6_max2,      t_s2,        t_xs2,          t_s2            }, // 1 1110
  { TMS6_pack2,     t_i2,        t_xi2,          t_i2            }, // 1 1111
};

static const uint16 bititypes[32] =
{
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_null,  TMS6_null,  TMS6_null,  TMS6_null,
  TMS6_xpnd4, TMS6_xpnd2, TMS6_mvd,   TMS6_null,
  TMS6_shfl,  TMS6_deal,  TMS6_bitc4, TMS6_bitr,
};

int tms6_t::dxc_ops(insn_t &insn, uint32 code) const
{
// +-----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11   7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |  op  |1|1|1|0|0|s|p|
// +-----------------------------------------------------------------+

  int size = handle_dx(insn, dxcops, code);
  if ( size > 0 )
  {
    switch ( insn.itype )
    {
      case BITGRP:
        insn.itype = bititypes[(code >>13) & 0x1F];
        if ( insn.itype == TMS6_null )
          return 0;
        break;
      case TMS6_shr2:
        swap_op1_and_op2(insn);
        break;
    }
  }
  return size;
}

//--------------------------------------------------------------------------
//      LOAD/STORE WITH 15-BIT OFFSET (ON D2 UNIT)
//--------------------------------------------------------------------------
struct tms_ldinfo_t
{
  uchar itype;
  uchar dtype;
  uchar shift;
};

static const tms_ldinfo_t ldinfo[] =
{
  { TMS6_ldhu,  dt_word,  1 },  // 0000
  { TMS6_ldbu,  dt_byte,  0 },  // 0001
  { TMS6_ldb,   dt_byte,  0 },  // 0010
  { TMS6_stb,   dt_byte,  0 },  // 0011
  { TMS6_ldh,   dt_word,  1 },  // 0100
  { TMS6_sth,   dt_word,  1 },  // 0101
  { TMS6_ldw,   dt_dword, 2 },  // 0110
  { TMS6_stw,   dt_dword, 2 },  // 0111
  { TMS6_null,  0,        0 },  // 1000
  { TMS6_null,  0,        0 },  // 1001
  { TMS6_ldndw, dt_qword, 3 },  // 1010
  { TMS6_ldnw,  dt_dword, 2 },  // 1011
  { TMS6_stdw,  dt_qword, 3 },  // 1100
  { TMS6_stnw,  dt_dword, 2 },  // 1101
  { TMS6_lddw,  dt_qword, 3 },  // 1110
  { TMS6_stndw, dt_qword, 3 },  // 1111
};

int tms6_t::ld_common(insn_t &insn, uint32 code, bool use_bit8) const
{
  int idx = (code >> 4) & 7;
  if ( use_bit8 )
    idx |= (code & BIT8) >> 5;
  const tms_ldinfo_t *ld = &ldinfo[idx];
  insn.itype = ld->itype;
  if ( insn.itype == TMS6_null )
    return -1;
  insn.Op2.type  = o_reg;
  insn.Op2.dtype = dt_dword;
  insn.Op2.reg   = (code >> 23) & 0x1F;
  if ( code & BIT1 )
    insn.Op2.reg += rB0;
  insn.Op1.dtype = ld->dtype;
  if ( ld->shift == 3 )
  {
    insn.Op2.reg &= ~1;
    insn.Op2.type = o_regpair;
    insn.Op2.quad_regpair = false;
    if ( (code & BIT23) == 0
      && (insn.itype == TMS6_ldndw || insn.itype == TMS6_stndw) )
    {
      return 0; // no scaling
    }
  }
  return ld->shift;
}

static bool is_store_insn(ushort itype)
{
  switch ( itype )
  {
    case TMS6_stb:
    case TMS6_sth:
    case TMS6_stw:
    case TMS6_stdw:
    case TMS6_stnw:
    case TMS6_stndw:
      return true;
    default:
      return false;
  }
}

int tms6_t::ld15(insn_t &insn, uint32 code) const
{
  int shift = ld_common(insn, code, false);
  if ( shift == -1 )
    return 0;
  insn.Op1.type = o_displ;
  insn.Op1.mode = 5;             // *+R[cst]
  insn.Op1.reg  = code & BIT7 ? rB15 : rB14;
  insn.Op1.addr = ((code >> 8) & 0x7FFF) << shift;
  insn.Op1.scale = shift;
  bool is_store = is_store_insn(insn.itype);
  if ( is_store )
    swap_op1_and_op2(insn);
  return insn.size;
}

//--------------------------------------------------------------------------
//      LOAD/STORE BASER+OFFSETR/CONST (ON D UNITS)
//--------------------------------------------------------------------------
int tms6_t::ldbase(insn_t &insn, uint32 code) const
{
// +------------------------------------------------------------------------+
// |31    29|28|27   23|22     18|17           13|12   9|8|7|6     4|3|2|1|0|
// |  creg  |z |  dst  |  baseR  | offsetR/ucst5 | mode |r|y| ld/st |0|1|s|p|
// +------------------------------------------------------------------------+

  int shift = ld_common(insn, code, true);
  if ( shift == -1 )
    return 0;
  insn.Op1.mode = (code >> 9) & 0xF;
  bool is_store = is_store_insn(insn.itype);
  switch ( insn.Op1.mode )
  {
    case 0x02:  // 0010
    case 0x03:  // 0011
    case 0x06:  // 0110
    case 0x07:  // 0111
      return 0;
    case 0x00:  // 0000 *-R[cst]
    case 0x01:  // 0001 *+R[cst]
    case 0x08:  // 1000 *--R[cst]
    case 0x09:  // 1001 *++R[cst]
    case 0x0A:  // 1010 *R--[cst]
    case 0x0B:  // 1011 *R++[cst]
      insn.Op1.type = o_displ;
      insn.Op1.addr = ((code >> 13) & 0x1F) << shift;
      insn.Op1.scale = shift;
      break;
    case 0x04:  // 0100 *-Rb[Ro]
    case 0x05:  // 0101 *+Rb[Ro]
    case 0x0C:  // 1100 *--Rb[Ro]
    case 0x0D:  // 1101 *++Rb[Ro]
    case 0x0E:  // 1110 *Rb--[Ro]
    case 0x0F:  // 1111 *Rb++[Ro]
      insn.Op1.type   = o_phrase;
      insn.Op1.secreg = make_reg(insn, (code >> 13) & 0x1F, 0);
      break;
  }
  insn.Op1.reg = make_reg(insn, (code >> 18) & 0x1F, 0);
  if ( is_store )
    swap_op1_and_op2(insn);
  return insn.size;
}

//--------------------------------------------------------------------------
//      S UNIT OPERATIONS
//--------------------------------------------------------------------------
static const tmsinsn_t sops[64] =
{                                                                // bits 11..6
  { TMS6_bdec,    t_scst10,      t_none,         t_uint          }, // 00 0000
  { TMS6_add2,    t_i2,          t_xi2,          t_i2            }, // 00 0001
  { TMS6_spdp,    t_none,        t_xsp,          t_dp            }, // 00 0010
  { TMS6_b,       t_none,        t_irp,          t_none          }, // 00 0011
  { TMS6_bnop,    t_none,        t_scst12,       t_ucst3         }, // 00 0100
  { TMS6_addkpc,  t_scst7,       t_ucst3,        t_uint          }, // 00 0101
  { TMS6_add,     t_scst5,       t_xsint,        t_sint          }, // 00 0110
  { TMS6_add,     t_sint,        t_xsint,        t_sint          }, // 00 0111
  { TMS6_packhl2, t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_packh2,  t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_xor,     t_scst5,       t_xuint,        t_uint          }, // 00 1010
  { TMS6_xor,     t_uint,        t_xuint,        t_uint          }, // 00 1011
  { TMS6_fadddp,  t_dwop1,       t_xdwop2,       t_dwdst         }, // 00 1100
  { TMS6_b,       t_none,        t_xuint,        t_none          }, // 00 1101
  { TMS6_mvc,     t_none,        t_xuint,        t_cregw         }, // 00 1110
  { TMS6_mvc,     t_none,        t_cregr,        t_uint          }, // 00 1111
  { TMS6_packlh2, t_i2,          t_xi2,          t_i2            }, // 01 0000
  { TMS6_sub2,    t_sint,        t_xsint,        t_sint          }, // 01 0001
  { TMS6_shl,     t_ucst5,       t_xsint,        t_slong         }, // 01 0010
  { TMS6_shl,     t_uint,        t_xsint,        t_slong         }, // 01 0011
  { TMS6_cmpgt2,  t_s2,          t_xs2,          t_bv2           }, // 01 0100
  { TMS6_cmpgtu4, t_u4,          t_xu4,          t_bv4           }, // 01 0101
  { TMS6_sub,     t_scst5,       t_xsint,        t_sint          }, // 01 0110
  { TMS6_sub,     t_sint,        t_xsint,        t_sint          }, // 01 0111
  { TMS6_shr2,    t_ucst5,       t_xs2,          t_s2            }, // 01 1000
  { TMS6_shru2,   t_ucst5,       t_xu2,          t_u2            }, // 01 1001
  { TMS6_or,      t_scst5,       t_xuint,        t_uint          }, // 01 1010
  { TMS6_or,      t_uint,        t_xuint,        t_uint          }, // 01 1011
  { TMS6_cmpeq4,  t_s4,          t_xs4,          t_bv4           }, // 01 1100
  { TMS6_cmpeq2,  t_s2,          t_xs2,          t_bv2           }, // 01 1101
  { TMS6_and,     t_scst5,       t_xuint,        t_uint          }, // 01 1110
  { TMS6_and,     t_uint,        t_xuint,        t_uint          }, // 01 1111
  { TMS6_sadd,    t_sint,        t_xsint,        t_sint          }, // 10 0000
  { TMS6_dadd,    t_scst5,       t_xdwop2,       t_dwdst         }, // 10 0001
  { TMS6_sshl,    t_ucst5,       t_xsint,        t_sint          }, // 10 0010
  { TMS6_sshl,    t_uint,        t_xsint,        t_sint          }, // 10 0011
  { TMS6_shru,    t_ucst5,       t_ulong,        t_ulong         }, // 10 0100
  { TMS6_shru,    t_uint,        t_ulong,        t_ulong         }, // 10 0101
  { TMS6_shru,    t_ucst5,       t_xuint,        t_uint          }, // 10 0110
  { TMS6_shru,    t_uint,        t_xuint,        t_uint          }, // 10 0111
  { TMS6_cmpeqdp, t_dp,          t_xdp,          t_sint          }, // 10 1000
  { TMS6_cmpgtdp, t_dp,          t_xdp,          t_sint          }, // 10 1001
  { TMS6_cmpltdp, t_dp,          t_xdp,          t_sint          }, // 10 1010
  { TMS6_extu,    t_uint,        t_xuint,        t_uint          }, // 10 1011
  { TMS6_absdp,   t_dp,          t_none,         t_dp            }, // 10 1100
  { TMS6_rcpdp,   t_dp,          t_none,         t_dp            }, // 10 1101
  { TMS6_rsqrdp,  t_dp,          t_none,         t_dp            }, // 10 1110
  { TMS6_ext,     t_uint,        t_xsint,        t_sint          }, // 10 1111
  { TMS6_shl,     t_ucst5,       t_slong,        t_slong         }, // 11 0000
  { TMS6_shl,     t_uint,        t_slong,        t_slong         }, // 11 0001
  { TMS6_shl,     t_ucst5,       t_xsint,        t_sint          }, // 11 0010
  { TMS6_shl,     t_uint,        t_xsint,        t_sint          }, // 11 0011
  { TMS6_shr,     t_ucst5,       t_slong,        t_slong         }, // 11 0100
  { TMS6_shr,     t_uint,        t_slong,        t_slong         }, // 11 0101
  { TMS6_shr,     t_ucst5,       t_xsint,        t_sint          }, // 11 0110
  { TMS6_shr,     t_uint,        t_xsint,        t_sint          }, // 11 0111
  { TMS6_cmpeqsp, t_sp,          t_xsp,          t_sint          }, // 11 1000
  { TMS6_cmpgtsp, t_sp,          t_xsp,          t_sint          }, // 11 1001
  { TMS6_cmpltsp, t_sp,          t_xsp,          t_sint          }, // 11 1010
  { TMS6_set,     t_uint,        t_xuint,        t_uint          }, // 11 1011
  { TMS6_abssp,   t_none,        t_xsp,          t_sp            }, // 11 1100
  { TMS6_rcpsp,   t_none,        t_xsp,          t_sp            }, // 11 1101
  { TMS6_rsqrsp,  t_none,        t_xsp,          t_sp            }, // 11 1110
  { TMS6_clr,     t_uint,        t_xuint,        t_uint          }, // 11 1111
};

int tms6_t::s_ops(insn_t &insn, uint32 code) const
{
// +----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|0|0|0|s|p|
// +----------------------------------------------------------------+

  // Special case for DINTHSP.S, DINTHSPU.S, ...
  int other_opcode = (code >> 13) & 0x1F;
  if ( other_opcode > 3 && ((code & 0xFFC) == 0xF20) )
  {
    const tmsinsn_t *t_insn = nullptr;
    switch ( other_opcode )
    {
      case 0x6:
        {
          static const tmsinsn_t t_unpkhu2 =
          { TMS6_unpkhu2, t_none, t_xop, t_dwdst };
          t_insn = &t_unpkhu2;
          break;
        }
      case 0x7:
        {
          static const tmsinsn_t t_unpkh2 =
          { TMS6_unpkh2, t_none, t_xop, t_dwdst };
          t_insn = &t_unpkh2;
          break;
        }
      case 0x8:
        {
          static const tmsinsn_t t_unpkbu4 =
          { TMS6_unpkbu4, t_none, t_xop, t_dwdst };
          t_insn = &t_unpkbu4;
          break;
        }
      case 0x10:
        {
          static const tmsinsn_t t_dspinth =
          { TMS6_dspinth, t_none, t_xdwop, t_dst };
          t_insn = &t_dspinth;
          break;
        }
      case 0x11:
        {
          static const tmsinsn_t t_dintspu =
          { TMS6_dintspu, t_none, t_xdwop2, t_dwdst };
          // ^manual is wrong its t_xdwop2, not x_op
          t_insn = &t_dintspu;
          break;
        }
      case 0x13:
        {
          static const tmsinsn_t t_dinthspu =
          { TMS6_dinthspu, t_none, t_xop, t_dwdst };
          t_insn = &t_dinthspu;
          break;
        }
      case 0x14:
        {
          static const tmsinsn_t t_dspint =
          { TMS6_dspint, t_none, t_xdwop, t_dwdst };
          t_insn = &t_dspint;
          break;
        }
      default:
        break;
    }

    if ( t_insn == nullptr )
      return 0;
    return table_insns(insn, code, t_insn, (code & BIT12) != 0);
  }

  int opcode = (code >> 6) & 0x3F;
  if ( table_insns(insn, code, sops + opcode, (code & BIT12) != 0) )
  {
    switch ( insn.itype )
    {
      case TMS6_mvc:
        insn.cflags &= ~aux_xp;            // XPATH should not be displayed
                                          // (assembler does not like it)
        if ( insn.funit != FU_S2 )
          return 0;
        break;
      case TMS6_b:
        if ( insn.funit != FU_S2 )
          return 0;
        if ( opcode != 3 )        // b irp
        {
          switch ( (code >> 23) & 0x1F )
          {
            case 0:  // b
              break;
            case 1:  // bnop
              insn.itype = TMS6_bnop;
              make_op(insn, insn.Op2, code, t_ucst3, (code >> 13) & 0x1F, false);
              break;
            default:
              return 0;
          }
        }
        break;
      case TMS6_bdec:
        insn.cflags &= ~aux_xp;            // XPATH should not be displayed
        if ( (code & BIT12) == 0 )
          insn.itype = TMS6_bpos;
        break;
      case TMS6_extu:
      case TMS6_ext:
      case TMS6_set:
      case TMS6_clr:
        insn.cflags &= ~aux_xp;            // XPATH should not be displayed
                                          // (assembler does not like it)
        [[fallthrough]];
      case TMS6_shl:
      case TMS6_sshl:
      case TMS6_shr:
      case TMS6_shru:
      case TMS6_shr2:
      case TMS6_shru2:
        swap_op1_and_op2(insn);
        break;
      case TMS6_addkpc:
        swap_op2_and_op3(insn);
        break;
    }
    return insn.size;
  }

  return 0;
}

//--------------------------------------------------------------------------
//      ADDK ON S UNITS
//--------------------------------------------------------------------------
int tms6_t::addk(insn_t &insn, uint32 code) const
{
// +-----------------------------------------------------+
// |31    29|28|27    23|22               7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |        cst       |1|0|1|0|0|s|p|
// +-----------------------------------------------------+

  insn.itype     = TMS6_addk;
  insn.Op1.type  = o_imm;
  insn.Op1.dtype = dt_word;
  insn.Op1.value = short(code >> 7);
  insn.Op2.type  = o_reg;
  insn.Op2.dtype = dt_dword;
  insn.Op2.reg   = make_reg(insn, (code >> 23) & 0x1F, 0);
  return insn.size;
}

//--------------------------------------------------------------------------
//      FIELD OPERATIONS (IMMEDIATE FORMS) ON S UNITS
//--------------------------------------------------------------------------
int tms6_t::field_ops(insn_t &insn, uint32 code) const
{
// +---------------------------------------------------------------+
// |31    29|28|27    23|22   18|17    13|12     8|7  6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  csta  |  cstb  | op |0|0|1|0|s|p|
// +---------------------------------------------------------------+
  static const uint16 itypes[] =
  {
    TMS6_extu,  // 00
    TMS6_ext,   // 01
    TMS6_set,   // 10
    TMS6_clr,   // 11
  };
  insn.itype = itypes[(code >> 6) & 3];
  insn.Op1.type  = o_imm;
  insn.Op1.value = (code >> 13) & 0x1F;
  insn.Op2.type  = o_imm;
  insn.Op2.value = (code >> 8) & 0x1F;
  insn.Op3.type  = o_reg;
  insn.Op3.reg   = make_reg(insn, (code >> 23) & 0x1F, 0);
  insn.Op1.src2  = make_reg(insn, (code >> 18) & 0x1F, 0);
  insn.cflags   |= aux_src2;
  return insn.size;
}

//--------------------------------------------------------------------------
//      MVK AND MVKH ON S UNITS
//--------------------------------------------------------------------------
int tms6_t::mvk(insn_t &insn, uint32 code) const
{
// +-----------------------------------------------------+
// |31    29|28|27    23|22               7|6|5|4|3|2|1|0|
// |  creg  |z |  dst   |        cst       |x|1|0|1|0|s|p|
// +-----------------------------------------------------+

  insn.itype     = code & BIT6 ? TMS6_mvkh : TMS6_mvk;
  insn.Op1.type  = o_imm;
  insn.Op1.dtype = dt_dword;
  insn.Op1.value = int16(code >> 7);
  if ( insn.itype == TMS6_mvkh )
    // we cannot use <<= 16 because bcb6 generates wrong code for __EA64__
    insn.Op1.value = uint32(insn.Op1.value << 16);
  insn.Op2.type  = o_reg;
  insn.Op2.dtype = dt_word;
  insn.Op2.reg   = make_reg(insn, (code >> 23) & 0x1F, 0);
  return insn.size;
}

//--------------------------------------------------------------------------
//      BCOND DISP ON S UNITS
//--------------------------------------------------------------------------
int tms6_t::bcond(insn_t &insn, uint32 code) const
{
// +--------------------------------------------+
// |31    29|28|27               7|6|5|4|3|2|1|0|
// |  creg  |z |        cst       |0|0|1|0|0|s|p|
// +--------------------------------------------+

  insn.itype = TMS6_b;
  op_near(insn, insn.Op1, code, 7, 0x1FFFFF);
  return insn.size;
}

//--------------------------------------------------------------------------
//      INSTRUCTIONS THAT CANNOT BE PREDICATED
//--------------------------------------------------------------------------
struct tmsinsn_indexed_t
{
  tmsinsn_t header;

  uint32 index;
  uint32 mask;
  funit_t unit;

  bool xbit_at_12;

  tmsinsn_indexed_t(tmsinsn_t _header, uint32 _index,
    uint32 _mask, funit_t _unit,
    bool flip_src1_src2 = false, bool xbit_at_12 = false) :
    header(std::move(_header)), index(_index), mask(_mask), unit(_unit), xbit_at_12(xbit_at_12)
  {
    header.flip_src1_src2 = flip_src1_src2;
  }
};

static const tmsinsn_indexed_t nopreds[] =
{                                                                // bits 11..2
  { { TMS6_callp,      t_scst21,    t_a3,           t_none   },  0x004,     0x01F,      FU_S1,   false, false },
  { { TMS6_addab,      t_b14,       t_ucst15,       t_uint   },  0x00F,     0x01F,      FU_D1,   false, false },
  { { TMS6_addad,      t_b14,       t_ucst15,       t_uint   },  0x010,     0x01F,      FU_D1,   false, false },
  { { TMS6_addah,      t_b14,       t_ucst15,       t_uint   },  0x017,     0x01F,      FU_D1,   false, false },
  { { TMS6_addaw,      t_b14,       t_ucst15,       t_uint   },  0x01F,     0x01F,      FU_D1,   false, false },
  { { TMS6_addsub,     t_sint,      t_xsint,        t_dint   },  0x066,     0x3FF,      FU_L1,   false, false },
  { { TMS6_saddsub,    t_sint,      t_xsint,        t_dint   },  0x076,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dpack2,     t_sint,      t_xsint,        t_dint   },  0x1A6,     0x3FF,      FU_L1,   false, false },
  { { TMS6_shfl3,      t_sint,      t_xsint,        t_dint   },  0x1B6,     0x3FF,      FU_L1,   false, false },
  { { TMS6_addsub2,    t_sint,      t_xsint,        t_dint   },  0x06E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_saddsub2,   t_sint,      t_xsint,        t_dint   },  0x07E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dpackx2,    t_sint,      t_xsint,        t_dint   },  0x19E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_cmpy,       t_s2,        t_xs2,          t_dint   },  0x0AC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_cmpyr,      t_s2,        t_xs2,          t_s2     },  0x0BC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_cmpyr1,     t_s2,        t_xs2,          t_s2     },  0x0CC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_mpy2ir,     t_sint,      t_xsint,        t_dint   },  0x0FC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_ddotpl2r,   t_dint,      t_xs2,          t_s2     },  0x14C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_ddotph2r,   t_dint,      t_xs2,          t_s2     },  0x15C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_ddotpl2,    t_dint,      t_xs2,          t_dint   },  0x16C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_ddotph2,    t_dint,      t_xs2,          t_dint   },  0x17C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_ddotp4,     t_ds2,       t_xs2,          t_dint   },  0x18C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_smpy32,     t_sint,      t_xsint,        t_sint   },  0x19C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_xormpy,     t_uint,      t_xuint,        t_uint   },  0x1BC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_gmpy,       t_uint,      t_xuint,        t_uint   },  0x1FC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_rpack2,     t_sint,      t_xsint,        t_s2     },  0x3BC,     0x3FF,      FU_S1,   false, false },
  { { TMS6_swe,        t_none,      t_none,         t_none   },  0x0000000, 0x3FFFFFF,  FU_NONE, false, false },
  { { TMS6_dint,       t_none,      t_none,         t_none   },  0x0001000, 0x3FFFFFF,  FU_NONE, false, false },
  { { TMS6_swenr,      t_none,      t_none,         t_none   },  0x0000800, 0x3FFFFFF,  FU_NONE, false, false },
  { { TMS6_rint,       t_none,      t_none,         t_none   },  0x0001800, 0x3FFFFFF,  FU_NONE, false, false },
  { { TMS6_cmatmpy,    t_xdwop1,    t_qwop2,        t_qwdst  },  0x080,     0x3FF,      FU_M1,   true,  false },
  { { TMS6_ccmatmpyr1, t_xdwop1,    t_qwop2,        t_dwdst  },  0x0E0,     0x3FF,      FU_M1,   true,  false },
  { { TMS6_ccmpy32r1,  t_dwop1,     t_xdwop2,       t_dwdst  },  0x09C,     0x1FF,      FU_M1,   false, false },
  { { TMS6_ccmatmpy,   t_xdwop1,    t_qwop2,        t_qwdst  },  0x0A0,     0x3FF,      FU_M1,   true,  false },
  { { TMS6_cmatmpyr1,  t_xdwop1,    t_qwop2,        t_dwdst  },  0x0C0,     0x3FF,      FU_M1,   true,  false },
  { { TMS6_cmpysp,     t_dwop1,     t_xdwop2,       t_qwdst  },  0x3C0,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dadd,       t_dwop1,     t_xdwop2,       t_dwdst  },  0x078,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dadd,       t_dwop1,     t_xdwop2,       t_dwdst  },  0x01E,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dadd2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x018,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dadd2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x02E,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_daddsp,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x1E6,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_daddsp,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x2C8,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dapys2,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x1C6,     0x3FF,      FU_L1,   false, false },
  { { TMS6_davg2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x13C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_davgnr2,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x11C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_davgnru4,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x10C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_davgu4,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x12C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dccmpy,     t_dwop1,     t_xdwop2,       t_qwdst  },  0x060,     0x3FF,      FU_M1,   false, false },
  //                                                ^manual is wrong, its qwdst, not dwdst
  //                                                 also the bit 4..5 are wrong
  { { TMS6_dccmpyr1,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x0EC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dcmpeq2,    t_dwop1,     t_xdwop2,       t_dst    },  0x1D8,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dcmpeq4,    t_dwop1,     t_xdwop2,       t_dst    },  0x1C8,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dcmpgt2,    t_dwop1,     t_xdwop2,       t_dst    },  0x148,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dcmpgtu4,   t_dwop1,     t_xdwop2,       t_dst    },  0x158,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dcmpy,      t_dwop1,     t_xdwop2,       t_qwdst  },  0x040,     0x3FF,      FU_M1,   false, false },
  //                                                ^manual is wrong, its qwdst, not dwdst
  //                                                 also the bit 4..5 are wrong
  { { TMS6_dcmpyr1,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x0DC,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmax2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x216,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dmaxu4,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x21E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dmin2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x20E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dminu4,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x246,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dmpy2,      t_dwop1,     t_xdwop2,       t_qwdst  },  0x00C,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmpysp,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x380,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmpysu4,    t_dwop1,     t_xdwop2,       t_qwdst  },  0x300,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmpyu2,     t_dwop1,     t_xdwop2,       t_qwdst  },  0x020,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmpyu4,     t_dwop1,     t_xdwop2,       t_qwdst  },  0x04c,     0x3FF,      FU_M1,   false, false },
  { { TMS6_dmvd,       t_op1_nx,    t_xop2,         t_dwdst  },  0x33c,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dmvd,       t_op1_nx,    t_xop2,         t_dwdst  },  0x366,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpackh2,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x0F6,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpackh2,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x098,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dpackh4,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x34E,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpackhl2,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x088,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dpackhl2,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x0E6,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpackl2,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x006,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpackl2,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x3FC,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dpackl4,    t_dwop1,     t_xdwop2,       t_dwdst  },  0x346,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dpacklh2,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x0DE,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dpacklh2,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x108,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dsadd,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x208,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dsadd,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x09E,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dsadd2,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x30C,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dsadd2,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x0A6,     0x3FF,      FU_L1,   false, true  },

  { { TMS6_dshl,       t_xdwop1,    t_op1_nx,       t_dwdst  },  0x338,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshl,       t_xdwop1,    t_ucst5,        t_dwdst  },  0x328,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dshl2,      t_xdwop1,    t_op1_nx,       t_dwdst  },  0x128,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshl2,      t_xdwop1,    t_ucst5,        t_dwdst  },  0x068,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dshr,       t_xdwop1,    t_op1_nx,       t_dwdst  },  0x378,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshr,       t_xdwop1,    t_ucst5,        t_dwdst  },  0x368,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dshr2,      t_xdwop1,    t_op1_nx,       t_dwdst  },  0x37C,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshr2,      t_xdwop1,    t_ucst5,        t_dwdst  },  0x188,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dshru,      t_xdwop1,    t_op1_nx,       t_dwdst  },  0x278,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshru,      t_xdwop1,    t_ucst5,        t_dwdst  },  0x268,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dshru2,     t_xdwop1,    t_op1_nx,       t_dwdst  },  0x38C,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_dshru2,     t_xdwop1,    t_ucst5,        t_dwdst  },  0x198,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dsmpy2,     t_dwop1,     t_xdwop2,       t_qwdst  },  0x01C,     0x3FF,      FU_M1,   false, false },

  { { TMS6_dspacku4,   t_dwop1,     t_xdwop2,       t_dwdst  },  0x34C,     0x3FF,      FU_S1,   true, true   },

  { { TMS6_dssub,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x33E,     0x3FF,      FU_L1,   false, false },
  { { TMS6_dssub2,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x326,     0x3FF,      FU_L1,   false, false },

  { { TMS6_dsub,       t_dwop1,     t_xdwop2,       t_dwdst  },  0x178,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dsub,       t_dwop1,     t_xdwop2,       t_dwdst  },  0x03E,     0x3FF,      FU_L1,   false, true  },

  { { TMS6_dsub2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x118,     0x3FF,      FU_S1,   false, true  },
  { { TMS6_dsub2,      t_dwop1,     t_xdwop2,       t_dwdst  },  0x026,     0x3FF,      FU_L1,   false, true  },

  { { TMS6_dsubsp,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x1EE,     0x3FF,      FU_L1,   false, true  },
  { { TMS6_dsubsp,     t_dwop1,     t_xdwop2,       t_dwdst  },  0x2D8,     0x3FF,      FU_S1,   false, true  },

  { { TMS6_mfence,     t_none,      t_none,         t_none   },  0x000,     0x3FF,      FU_NONE, false, false },

  { { TMS6_qmpy32,     t_qwop1,     t_qwop2,        t_qwdst  },  0x200,     0x3FF,      FU_M1,   false, false },
  { { TMS6_qmpysp,     t_qwop1,     t_qwop2,        t_qwdst  },  0x3a0,     0x3FF,      FU_M1,   false, false },
  { { TMS6_qsmpy32r1,  t_qwop1,     t_qwop2,        t_qwdst  },  0x1AC,     0x3FF,      FU_M1,   false, false },

  { { TMS6_shl2,       t_xop,      t_op1_nx,        t_dst    },  0x138,     0x3FF,      FU_S1,   true, true   },
  { { TMS6_shl2,       t_xop,      t_ucst5,         t_dst    },  0x038,     0x3FF,      FU_S1,   true, true   },
};

int tms6_t::nopred(insn_t &insn, uint32 code) const
{
  int idx = (code >> 2) & 0x3FFFFFF;
  const tmsinsn_indexed_t *p = nopreds;
  for ( int i=0; i < qnumber(nopreds); i++, p++ )
  {
    if ( p->index == (idx & p->mask) )
    {
      insn.funit = p->unit + ((code & BIT1) >> 1);
      bool other = false;
      if ( p->header.itype != TMS6_callp )
      {
        if ( p->unit == FU_M1 || p->unit == FU_L1 || p->xbit_at_12 )
          other = (code & BIT12) != 0;
        else
          other = (code & BIT1) != 0;
      }

      int size = table_insns(insn, code, (tmsinsn_t *)p, other);

      // ADDAW doesn't have a x-path bit, so we need to manually check for it
      if ( insn.itype == TMS6_addaw && !second_unit(insn) )
        insn.cflags |= aux_xp;
      else if ( p->header.src1 == t_b14 )
        insn.cflags &= ~aux_xp;

      return size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
int tms6_t::ana_classic(insn_t *_insn) const
{
  insn_t &insn = *_insn;
  if ( insn.ip & 3 )
    return 0;           // alignment error

  uint32 code = insn.get_next_dword();

  if ( code & BIT0 )
    insn.cflags |= aux_para;     // parallel execution with the next insn

  insn.cond = code >> 28;
  switch ( insn.cond )
  {
    case 0x0: // 0000 unconditional
    case 0x2: // 0010 B0
    case 0x3: // 0011 !B0
    case 0x4: // 0100 B1
    case 0x5: // 0101 !B1
    case 0x6: // 0110 B2
    case 0x7: // 0111 !B2
    case 0x8: // 1000 A1
    case 0x9: // 1001 !A1
    case 0xA: // 1010 A2
    case 0xB: // 1011 !A2
    case 0xC: // 1100 A0
    case 0xD: // 1101 !A0
      break;
    case 0xE: // 1110 reserved
    case 0xF: // 1111 reserved
      return 0;
    case 0x1: // 0001 no predicate
      insn.cond = 0;
      return nopred(insn, code);
  }

  switch ( (code >> 2) & 0x1F )
  {
//
//      Operations on L units
//
    case 0x06: // 00110
    case 0x0E: // 01110
    case 0x16: // 10110
    case 0x1E: // 11110
      insn.funit = code & BIT1 ? FU_L2 : FU_L1;
      return l_ops(insn, code);
//
//      Operations on M units
//
    case 0x00: // 00000
      if ( (code & 0x3FFFC) == 0x1E000 )
      {
        insn.itype = TMS6_idle;
        return insn.size;
      }
      if ( (code & 0x21FFE) == 0 )
      {
        insn.Op1.type  = o_imm;
        insn.Op1.dtype = dt_dword;
        insn.Op1.value = ((code >> 13) & 0xF) + 1;
        if ( insn.Op1.value > 9 )
          return 0;
        if ( insn.Op1.value == 1 )
          insn.Op1.clr_shown();
        insn.itype = TMS6_nop;
        return insn.size;
      }
      if ( (code & 0x0C03FFFC) == 0x32000 )
      {
        insn.itype = TMS6_spmaskr;
        return op_spmask(insn, insn.Op1, code);
      }
      if ( (code & 0x0C03FFFC) == 0x30000 )
      {
        insn.itype = TMS6_spmask;
        return op_spmask(insn, insn.Op1, code);
      }
      if ( (code & 0x371FFC) == 0x030000 )
      {
        static const uint16 itypes[] =
        {
          TMS6_null,   TMS6_null,    TMS6_spkernel,  TMS6_spkernelr,
          TMS6_sploop, TMS6_sploopd, TMS6_null,      TMS6_sploopw,
        };
        int idx = (code >> 13) & 7;
        insn.itype = itypes[idx];
        switch ( idx )
        {
          default:
            return 0;
          case 2:               // spkernel
            insn.Op1.type  = o_stgcyc;
            insn.Op1.dtype = dt_dword;
            insn.Op1.value = ((code >> 22) & 0x3F);
            break;
          case 3:               // spkernelr
            break;
          case 4:               // sploop
          case 5:               // sploopd
          case 7:               // sploopw
            insn.Op1.type  = o_imm;
            insn.Op1.dtype = dt_dword;
            insn.Op1.value = ((code >> 23) & 0x1F) + 1;
            break;

        }
        return insn.size;
      }
      insn.funit = code & BIT1 ? FU_M2 : FU_M1;
      return m_ops(insn, code);
//
//      Operations on D units
//
    case 0x10: // 10000
      insn.funit = code & BIT1 ? FU_D2 : FU_D1;
      return d_ops(insn, code);
//
//      Operations on D units (with cross path)
//
    case 0x0C: // 01100
      insn.funit = code & BIT1 ? FU_D2 : FU_D1;
      return dx_ops(insn, code);
//
//      Operations on D units (cross path used with a constant)
//
    case 0x1C: // 11100
      insn.funit = code & BIT1 ? FU_D2 : FU_D1;
      return dxc_ops(insn, code);
//
//      Load/store with 15-bit offset (on D2 unit)
//
    case 0x03: // 00011
    case 0x07: // 00111
    case 0x0B: // 01011
    case 0x0F: // 01111
    case 0x13: // 10011
    case 0x17: // 10111
    case 0x1B: // 11011
    case 0x1F: // 11111
      insn.funit = FU_D2;
      return ld15(insn, code);
//
//      Load/store baseR+offsetR/const (on D units)
//
    case 0x01: // 00001
    case 0x05: // 00101
    case 0x09: // 01001
    case 0x0D: // 01101
    case 0x11: // 10001
    case 0x15: // 10101
    case 0x19: // 11001
    case 0x1D: // 11101
      insn.funit = code & BIT7 ? FU_D2 : FU_D1;
      return ldbase(insn, code);
//
//      Operations on S units
//
    case 0x08: // 01000
    case 0x18: // 11000
      insn.funit = code & BIT1 ? FU_S2 : FU_S1;
      return s_ops(insn, code);
//
//      ADDK on S units
//
    case 0x14: // 10100
      insn.funit = code & BIT1 ? FU_S2 : FU_S1;
      return addk(insn, code);
//
//      Field operations (immediate forms) on S units
//
    case 0x02: // 00010
    case 0x12: // 10010
      insn.funit = code & BIT1 ? FU_S2 : FU_S1;
      return field_ops(insn, code);
//
//      MVK and MVKH on S units
//
    case 0x0A: // 01010
    case 0x1A: // 11010
      insn.funit = code & BIT1 ? FU_S2 : FU_S1;
      return mvk(insn, code);
//
//      Bcond disp on S units
//
    case 0x04: // 00100
      insn.funit = code & BIT1 ? FU_S2 : FU_S1;
      return bcond(insn, code);
  }
  return 0;
}
//lint -e754
//==========================================================================
//==========================================================================
// Compact opcodes map (16 bits)
//==========================================================================
//==========================================================================

//--------------------------------------------------------------------------
// D Unit

// Doff4 / Dind / Dinc / Ddec (and their DW variant) Instruction Format
struct cmpct_tmsinsn_ldst_t
{
  uchar itype;
  uchar dtype_reg;
  uchar dtype_ptr;
  uchar shift;
  uchar index;
  uchar mask;
};

static const struct cmpct_tmsinsn_ldst_t cmpct_ldst_ops[] =
{                                                 //  DSZ   sz ld/st na
  { TMS6_stw,   dt_dword, dt_dword, 2, 0x00, 0x26 }, // 0 x x   0   0   *
  { TMS6_ldw,   dt_dword, dt_dword, 2, 0x02, 0x26 }, // 0 x x   0   1   *
  { TMS6_stb,   dt_dword, dt_byte,  0, 0x04, 0x3e }, // 0 0 0   1   0   *
  { TMS6_ldbu,  dt_dword, dt_byte,  0, 0x06, 0x3e }, // 0 0 0   1   1   *
  { TMS6_stb,   dt_dword, dt_byte,  0, 0x0c, 0x3e }, // 0 0 1   1   0   *
  { TMS6_ldb,   dt_dword, dt_byte,  0, 0x0e, 0x3e }, // 0 0 1   1   1   *
  { TMS6_sth,   dt_dword, dt_word,  1, 0x14, 0x3e }, // 0 1 0   1   0   *
  { TMS6_ldhu,  dt_dword, dt_word,  1, 0x16, 0x3e }, // 0 1 0   1   1   *
  { TMS6_sth,   dt_dword, dt_word,  1, 0x1c, 0x3e }, // 0 1 1   1   0   *
  { TMS6_ldh,   dt_dword, dt_word,  1, 0x1e, 0x3e }, // 0 1 1   1   1   *
  { TMS6_stw,   dt_dword, dt_dword, 2, 0x24, 0x3e }, // 1 0 0   1   0   *
  { TMS6_ldw,   dt_dword, dt_dword, 2, 0x26, 0x3e }, // 1 0 0   1   1   *
  { TMS6_stb,   dt_dword, dt_byte,  0, 0x2c, 0x3e }, // 1 0 1   1   0   *
  { TMS6_ldb,   dt_dword, dt_byte,  0, 0x2e, 0x3e }, // 1 0 1   1   1   *
  { TMS6_stnw,  dt_dword, dt_dword, 2, 0x34, 0x3e }, // 1 1 0   1   0   *
  { TMS6_ldnw,  dt_dword, dt_dword, 2, 0x36, 0x3e }, // 1 1 0   1   1   *
  { TMS6_sth,   dt_dword, dt_word,  1, 0x3c, 0x3e }, // 1 1 1   1   0   *
  { TMS6_ldh,   dt_dword, dt_word,  1, 0x3e, 0x3e }, // 1 1 1   1   1   *
  { TMS6_stdw,  dt_qword, dt_qword, 3, 0x20, 0x27 }, // 1 x x   0   0   0
  { TMS6_lddw,  dt_qword, dt_qword, 3, 0x22, 0x27 }, // 1 x x   0   1   0
  { TMS6_stndw, dt_qword, dt_qword, 1, 0x21, 0x27 }, // 1 x x   0   0   1
  { TMS6_ldndw, dt_qword, dt_qword, 1, 0x23, 0x27 }  // 1 x x   0   1   1
};

static void cmpct_Doff4_Dind_Dinc_Ddec(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  // Doff4    +-----------------------------------------------+
  // 0x0004   |15    13|12|11|10| 9| 8  7| 6     4| 3| 2| 1| 0|
  // 0x0406   |ucst 2-0| t|uc| 0|sz| ptr | src/dst|ld| 1| 0| s|
  //          +------------st3---------------------/st--------+

  // Doff4DW  +-----------------------------------------------+
  // 0x0004   |15    13|12|11|10| 9| 8  7| 6  5| 4| 3| 2| 1| 0|
  // 0x0406   |ucst 2-0| t|uc| 0|sz| ptr | src |na|ld| 1| 0| s|
  //          +------------st3-------------/dst----/st--------+

  // Dind     +-----------------------------------------------+
  // 0x0404   |15    13|12|11|10| 9| 8  7| 6     4| 3| 2| 1| 0|
  // 0x0c06   |  src1  | t| 0| 1|sz| ptr | src/dst|ld| 1| 0| s|
  //          +------------------------------------/st--------+

  // DindDW   +-----------------------------------------------+
  // 0x0404   |15    13|12|11|10| 9| 8  7| 6  5| 4| 3| 2| 1| 0|
  // 0x0c06   |  src1  | t| 0| 1|sz| ptr | src |na|ld| 1| 0| s|
  //          +----------------------------/dst----/st--------+

  // Dinc     +-----------------------------------------------+
  // 0x0c04   |15|14|13|12|11|10| 9| 8  7| 6     4| 3| 2| 1| 0|
  // 0xcc06   | 0| 0|uc| t| 1| 1|sz| ptr | src/dst|ld| 1| 0| s|
  //          +------st0---------------------------/st--------+

  // DincDW   +-----------------------------------------------+
  // 0x0c04   |15|14|13|12|11|10| 9| 8  7| 6  5| 4| 3| 2| 1| 0|
  // 0xcc06   | 0| 0|uc| t| 1| 1|sz| ptr | src |na|ld| 1| 0| s|
  //          +------st0-------------------/dst----/st--------+

  // Ddec     +-----------------------------------------------+
  // 0x4c04   |15|14|13|12|11|10| 9| 8  7| 6     4| 3| 2| 1| 0|
  // 0xcc06   | 0| 1|uc| t| 1| 1|sz| ptr | src/dst|ld| 1| 0| s|
  //          +------st0---------------------------/st--------+

  // DdecDW   +-----------------------------------------------+
  // 0x4c04   |15|14|13|12|11|10| 9| 8  7| 6  5| 4| 3| 2| 1| 0|
  // 0xcc06   | 0| 1|uc| t| 1| 1|sz| ptr | src |na|ld| 1| 0| s|
  //          +------st0-------------------/dst----/st--------+

  op_t *reg, *ptr;
  int i;
  uchar shift = 0;

  // functional unit (based on register file for ptr)
  insn.funit = (code & BIT0) ? FU_D2 : FU_D1;

  // operand selection
  if ( code & BIT3 )
  { // Load
    ptr = &insn.Op1;
    reg = &insn.Op2;
  }
  else
  { // Store
    reg = &insn.Op1;
    ptr = &insn.Op2;
  }

  // sub operation search
  uchar mw = \
    (((fph >> 16) & 7) << 3)   // DSZ
    | (((code >> 9) & 1) << 2) // sz
    | (((code >> 3) & 1) << 1) // ld/st
    | (((code >> 4) & 1) << 0);  // na

  for ( i=0; i < qnumber(cmpct_ldst_ops); i++ )
  {
    const struct cmpct_tmsinsn_ldst_t *op_desc = &cmpct_ldst_ops[i];

    if ( (mw & op_desc->mask) == op_desc->index )
    {
      insn.itype = op_desc->itype;
      ptr->dtype = op_desc->dtype_ptr;
      reg->dtype = op_desc->dtype_reg;
      shift = op_desc->shift;
      break;
    }
  }

  // src/dst register
  if ( ptr->dtype == dt_qword )
  {
    reg->type = o_regpair;
    insn.Op2.quad_regpair = false;
    reg->reg = (code >> 4) & 6;
  }
  else
  {
    reg->type = o_reg;
    reg->reg = (code >> 4) & 7;
  }

  if ( (code & BIT12) != 0 )
    reg->reg += rB0;

  // pointer
  ptr->reg = ((code >> 7) & 3) + rA4;
  if ( (code & BIT0) != 0 )
    ptr->reg += rB0;

  if ( !(code & BIT10) )
  {
    // Doff4 & Doff4DW
    ptr->type = o_displ;
    ptr->mode = 1;
    ptr->addr = (((code >> 11) & 1) << 3) | ((code >> 13) & 7);
  }
  else if ( !(code & BIT11) )
  {
    // Dind & DindDW
    ptr->type = o_phrase;
    ptr->mode = 1;
    ptr->secreg = (code >> 13) & 7;
    if ( (code & BIT0) != 0 )
      ptr->secreg += rB0;

    ptr->addr = 0;
  }
  else if ( !(code & BIT14) )
  {
    // Dinc & DincDW
    ptr->type = o_displ;
    ptr->mode = 11; // *R++[cst]
    ptr->addr = (code & BIT13) ? 2 : 1;
  }
  else
  {
    // Ddec & DdecDW
    ptr->type = o_displ;
    ptr->mode = 8; // *--R[cst]
    ptr->addr = (code & BIT13) ? 2 : 1;
  }

  ptr->scale = shift;
  ptr->addr <<= shift;
}


// Dpp Instruction Format (0x0077 / 0x087f)
static void cmpct_Dpp(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10        7| 6| 5| 4| 3| 2| 1| 0|
  // |dw|ld|uc| t| 0| src/dst   | 1| 1| 1| 0| 1| 1| 1|
  // +--/st-st0-----------4--------------------------+
  // 1. ptr = B15
  // 2. ucst2 = ucst0 + 1
  // 3. src / dst is from A0 - A15, B0 - B15
  // 4. RS header bit is ignored
  op_t *reg, *ptr;

  // functional unit
  insn.funit = FU_D2;

  bool dw = (code & BIT15) != 0;
  int srcdst = (code >> 7) & 0x1F;
  int ucst = ((code >> 13) & 1) + 1;

  // operand selection + itype
  if ( code & BIT14 )
  { // Load
    ptr = &insn.Op1;
    reg = &insn.Op2;
    insn.itype = dw ? TMS6_lddw : TMS6_ldw;
  }
  else
  { // Store
    reg = &insn.Op1;
    ptr = &insn.Op2;
    insn.itype = dw ? TMS6_stdw : TMS6_stw;
  }

  // src/dst register
  reg->type = dw ? o_regpair : o_reg;
  if ( reg->type == o_regpair )
    insn.Op2.quad_regpair = false;

  reg->dtype = dt_dword;
  reg->reg = srcdst;
  if ( (code & BIT12) != 0 )
    reg->reg += rB0;

  // pointer
  ptr->type = o_displ;
  ptr->dtype = dt_dword;
  ptr->mode = ((code & BIT14) != 0) ? 0x09 : 0x0A;
  ptr->reg = rB15;
  ptr->addr = ucst << (dw ? 3 : 2);
}

// Dstk Instruction Format (0x8c04 / 0x8c06)
static void cmpct_Dstk(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15|14 13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // | 1|ucst | t| 1| 1|ucst 4-2| src/dst|ld| 1| 0| s|
  // +------10----------------------------/st--------+

  op_t *reg, *ptr;

  // functional unit
  insn.funit = FU_D2;

  // operand selection + itype
  if ( code & BIT3 )
  { // Load
    ptr = &insn.Op1;
    reg = &insn.Op2;
    insn.itype = TMS6_ldw;
  }
  else
  { // Store
    reg = &insn.Op1;
    ptr = &insn.Op2;
    insn.itype = TMS6_stw;
  }

  // src/dst register
  reg->type = o_reg;
  reg->dtype = dt_dword;
  reg->reg  = (code >>4) & 7;
  reg->reg += (code & BIT0) ? rA4 : rB4;

  // pointer
  ptr->type = o_displ;
  ptr->dtype = dt_dword;
  ptr->mode = 0;
  ptr->reg  = rB15;
  ptr->addr = (((code >> 7) & 7) << 2) | ((code >> 13) & 3);
  ptr->addr <<= 2;
}

// Dx2op Instruction Format (0x0036 / 0x04fe)
static void cmpct_Dx2op(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // | src/dst| x|op| 0|   src2 | 0| 1| 1| 0| 1| 1| s|
  // +-----------------------------------------------+
  insn.itype = (code & BIT11) ? TMS6_sub : TMS6_add;
  get_unit(insn, code, FU_D1);

  uint16 src_dst = make_reg(insn, (code >> 13) & 7, false);
  op_reg(insn.Op1, src_dst);
  op_reg(insn.Op2, insn, (code >> 7) & 7, (code & BIT12) != 0);
  op_reg(insn.Op3, src_dst);
}

// Dx5 Instruction Format (0x0436 / 0x047e)
static void cmpct_Dx5(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |ucst 2-0|ucst | 1|   dst  | 0| 1| 1| 0| 1| 1| s|
  // +------------43---------------------------------+
  get_unit(insn, code, FU_D1);
  insn.itype = TMS6_addaw;

  op_reg(insn.Op1, rB15);
  op_imm(insn.Op2, ((code >> 11) & 1) | ((code >> 13) & 7));
  op_reg(insn.Op3, make_reg(insn, ((code >> 7) & 7), false));

  // The Dx5 version always uses rB15,
  // if the other side uses the a-side, it crosses paths
  if ( insn.funit == FU_D1 )
    insn.cflags |= aux_xp;
}

// Dx5p Instruction Format (0x0c77 / 0x1c7f)
static void cmpct_Dx5p(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

   // +-----------------------------------------------+
   // |15    13|12|11|10| 9  8| 7| 6| 5| 4| 3| 2| 1| 0|
   // |ucst 2-0| 0| 1| 1|ucst |op| 1| 1| 1| 0| 1| 1| 1|
   // +---------------------43------------------------+
  insn.funit = FU_D2;
  insn.itype = (code & BIT7) ? TMS6_subaw : TMS6_addaw;

  op_reg(insn.Op1, rB15);
  op_imm(insn.Op2, ((code >> 8) & 3) << 3 | ((code >> 13) & 7));
  op_reg(insn.Op3, rB15);
}

// Dx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 1| 0| 1| 1| s|
// +-----------------------------------------------+

//--------------------------------------------------------------------------
// L Unit

//--------------------------------------------------------------------------
// L3 Instruction Format (0x0000 / 0x040e)
static void cmpct_L3(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  src1  | x|op| 0|  src2  |   dst  | 0| 0| 0| s|
  // +-----------------------------------------------+

  static const uint16 map[] =
  {
    TMS6_add, TMS6_sadd, TMS6_sub, TMS6_ssub
  };

  uint8 op = ((uint8)(fph >> 14) & 1) | ((uint8)(code >> 11) & 1) << 1;
  if ( op < qnumber(map) )
  {
    insn.itype = map[op];
    get_unit(insn, code, FU_L1);

    uint16 s1 = ((code >> 13) & 7);
    uint16 s2 = ((code >> 7) & 7);
    uint16 dst = ((code >> 4) & 7);
    bool cross_path = (code & BIT12) != 0;
    op_reg(insn.Op1, insn, s1);
    op_reg(insn.Op2, insn, s2, cross_path);
    op_reg(insn.Op3, insn, dst);
  }
}

// L3i Instruction Format (0x0400 / 0x040e)
static void cmpct_L3i(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  cst3  | x|sn| 1|  src2  |   dst  | 0| 0| 0| s|
  // +-----------------------------------------------+

  insn.itype = TMS6_add;
  get_unit(insn, code, FU_L1);

  uint16 val = (code >> 13) & 7;
  op_imm(insn.Op1, cst3_to_scst5(val, (code & BIT11) != 0));

  uint16 s2 = ((code >> 7) & 7);
  uint16 dst = ((code >> 4) & 7);
  bool cross_path = (code & BIT12) != 0;
  op_reg(insn.Op2, insn, s2, cross_path);
  op_reg(insn.Op3, insn, dst);
}

// Ltbd Instruction Format (0x0008 / 0x040e)
static void cmpct_Ltbd(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |  |  |  | x|  | 0|  src2  |  |  |  | 1| 0| 0| s|
  // +-----------------------------------------------+

}

// L2c Instruction Format (0x0408 / 0x040e)
static void cmpct_L2c(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |  src1  | x|op| 1|  src2  |op 10|ds| 1| 0| 0| s|
  // +-------------2--------------------t------------+
  static const uint16 map[] =
  {
    TMS6_and, TMS6_or, TMS6_xor, TMS6_cmpeq,
    TMS6_cmplt, TMS6_cmpgt, TMS6_cmpltu, TMS6_cmpgtu
  };

  uint8 op = ((uint8)(code >> 5) & 3) | ((uint8)(code >> 11) & 1) << 2;
  if ( op < qnumber(map) )
  {
    insn.itype = map[op];
    get_unit(insn, code, FU_L1);

    uint16 s1 = ((code >> 13) & 7);
    uint16 s2 = ((code >> 7) & 7);
    uint16 dst = ((code >> 4) & 1);
    bool cross_path = (code & BIT12) != 0;
    op_reg(insn.Op1, insn, s1);
    op_reg(insn.Op2, insn, s2, cross_path);
    op_reg(insn.Op3, insn, dst);
  }
}

// Lx5 Instruction Format (0x426 / 0x47e)
static void cmpct_Lx5(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |scst 2-0|scst | 1|   dst  | 0| 1| 0| 0| 1| 1| s|
  // +------------43---------------------------------+
  insn.itype = TMS6_mvk;
  get_unit(insn, code, FU_L1);

  op_imm(insn.Op1, ((code >> 11) & 3) << 3 | ((code >> 13) & 7));
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, false));
}

// Lx3c Instruction Format (0x26 / 0x147e)
static void cmpct_Lx3c(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |  ucst3 | 0|ds| 0|  src2  | 0| 1| 0| 0| 1| 1| s|
  // +-------------t---------------------------------+
  insn.itype = TMS6_cmpeq;
  get_unit(insn, code, FU_L1);

  op_imm(insn.Op1, (code >> 13) & 7);
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, false));
  op_reg(insn.Op3, make_reg(insn, (code >> 11) & 1, false));
}

// Lx1c Instruction Format (0x1026 / 0x1466)
static void cmpct_Lx1c(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15 14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |  op |uc| 1|ds| 0|  src2  | 0| 1| 0| 0| 1| 1| s|
  // +------st1----t---------------------------------+
  get_unit(insn, code, FU_L1);

  static const uint16 map[] = { TMS6_cmplt, TMS6_cmpgt, TMS6_cmpltu, TMS6_cmpgtu };
  insn.itype = map[(code >> 14) & 3];

  op_imm(insn.Op1, (code >> 13) & 1);
  op_reg(insn.Op2, insn, (code >> 7) & 7);
  op_reg(insn.Op3, insn, (code >> 11) & 1);
}

// Lx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 0| 0| 1| 1| s|
// +-----------------------------------------------+

//--------------------------------------------------------------------------
// M Unit

// M3 Instruction Format (0x1e / 0x1e)
static void cmpct_M3(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);

  // +-----------------------------------------------+
  // |15    13|12|11 10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |  src1  | x| dst |  src2  |  op | 1| 1| 1| 1| s|
  // +-----------------------------------------------+
  get_unit(insn, code, FU_M1);

  // SAT + OP
  uint8 op = ((uint8)(fph >> 14) & 1) << 2 | ((uint8)(code >> 5) & 3);
  static const uint16 map[] =
  {
    TMS6_mpy, TMS6_mpyh, TMS6_mpylh, TMS6_mpyhl,
    TMS6_smpy, TMS6_smpyh, TMS6_smpylh, TMS6_smpyhl
  };

  if ( op < qnumber(map) )
  {
    insn.itype = map[op];

    bool cross_path = (code & BIT12) != 0;

    uint16 s1 = (code >> 13) & 7;
    uint16 s2 = (code >> 7) & 7;
    uint16 dst = ((code >> 10) & 3) * 2;
    if ( (fph & BIT19) != 0 )
    {
      s1 += rA16;
      s2 += rA16;
      dst += rA16;
    }

    op_reg(insn.Op1, make_reg(insn, s1, false));
    op_reg(insn.Op2, insn, s2, cross_path);
    op_reg(insn.Op3, make_reg(insn, dst, false));
  }
}

//--------------------------------------------------------------------------
// S Unit

// Sbs7 (0xa / 0x3e), Sbs7c (0x2a / 0x2e)
// Sbu8 (0xc00a / 0xc03e), Sbu8c (0xc02a / 0xc02e)
// Instruction Formats
static void cmpct_Sbs7_c_sbu8_c(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // Sbs7 Instruction Format
  // +-----------------------------------------------+
  // |15    13|12                 6| 5| 4| 3| 2| 1| 0|
  // |   N3   |        scst7       | 0| 0| 1| 0| 1| s|
  // +-----------------------------------------------+
  // N3 = 0,1,2,3,4 or 5

  // Sbs7c Instruction Format
  // +-----------------------------------------------+
  // |15    13|12                 6| 5| 4| 3| 2| 1| 0|
  // |   N3   |        scst7       | 1| z| 1| 0| 1| s|
  // +-----------------------------------------------+
  // N3 = 0,1,2,3,4 or 5

  // Sbu8 Instruction Format
  // +-----------------------------------------------+
  // |15|14|13                    6| 5| 4| 3| 2| 1| 0|
  // | 1| 1|        ucst8          | 0| 0| 1| 0| 1| s|
  // +-----------------------------------------------+

  // Sbu8c Instruction Format
  // +-----------------------------------------------+
  // |15|14|13                    6| 5| 4| 3| 2| 1| 0|
  // | 1| 1|        ucst8          | 1| z| 1| 0| 1| s|
  // +-----------------------------------------------+

  get_unit(insn, code, FU_S1);
  insn.itype = TMS6_bnop;

  bool bit5_set = (code & BIT5) != 0; // /c variant

  uval_t imm = 0;
  int16 offset = 0;
  if ( (code & 0xC000) == 0xC000 ) // Sbu8/c
  {
    imm = 5;
    if ( bit5_set )
      offset = (code >> 5) & 0x1FE;
    else
      offset = (2 * (code >> 6)) & 0x1FE;
  }
  else // Sbs7/c
  {
    imm = code >> 13;
    if ( bit5_set )
      offset = (code >> 5) & 0xFE;
    else
      offset = 2 * ((code >> 6) & 0x7F);
  }

  insn.Op1.dtype = dt_code;
  insn.Op1.type = o_near;
  insn.Op1.addr = (insn.ip & ~0x1F) + offset;
  op_imm(insn.Op2, imm);

  if ( (code & BIT5) == 0 )
    return;

  // BR + s + z
  uint32 cnd = (((fph >> 15) & 1) << 2 | (code & 1u) << 1 | ((code >> 4) & 1)) - 4;
  if ( cnd < qnumber(cond_map) )
    insn.cond = cond_map[cnd];
}

// Scs10 Instruction Format (0x1a / 0x3e)
//lint -e{818, 1762} member function parameter 'proc' ... could be pointer to const
static void cmpct_Scs10(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(fph);

  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
  // |            scst10           | 0| 1| 1| 0| 1| s|
  // +-----------------------------------------------+
  insn.itype = TMS6_callp;

  get_unit(insn, code, FU_S1);
  proc->op_near(insn, insn.Op1, code, 6, 0x3FF);
  op_reg(insn.Op2, make_reg(insn, rA3, false));
}

// S3 (0xa / 0x40e), S3i (0x40a / 0x40e) Instruction Formats
static void cmpct_S3_S3i(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);

  // S3 Instruction Format
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  src1  | x|op| 0|  src2  |   dst  | 1| 0| 1| s|
  // +-----------------------------------------------+

  // S3i Instruction Format
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  cst3  | x|op| 1|  src2  |   dst  | 1| 0| 1| s|
  // +-----------------------------------------------+

  uint16 src1_cst3 = (code >> 13) & 7;

  // SAT + op
  bool is_S3i = (code & BIT10) != 0;
  uint8 op = (uint8)(((fph >> 14) & 1) << 1 | ((code >> 11) & 1));
  switch ( op )
  {
    case 0:
      insn.itype = is_S3i ? TMS6_shl : TMS6_add;
      break;
    case 1:
      insn.itype = is_S3i ? TMS6_shr : TMS6_sub;
      break;
    case 2:
      insn.itype = TMS6_sadd;
      break;
    case 3:
      insn.itype = TMS6_sub;
      break;
    default:
      INTERR(10495);
  }

  get_unit(insn, code, FU_S1);

  op_t &src2_op = is_S3i ? insn.Op1 : insn.Op2;
  op_reg(src2_op, make_reg(insn, (code >> 7) & 7, (code & BIT12) != 0));

  if ( is_S3i )
    op_imm(insn.Op2, cst3_to_ucst5(src1_cst3));
  else
    op_reg(insn.Op1, make_reg(insn, src1_cst3, false));

  op_reg(insn.Op3, make_reg(insn, (code >> 4) & 7, false));
}

// Smvk8 Instruction Format (0x12 / 0x1e)
static void cmpct_Smvk8(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12 11|10| 9    7| 6  5| 4| 3| 2| 1| 0|
  // |ucst 2-0|ucst |uc|   dst  |ucst | 1| 0| 0| 1| s|
  // +------------43-st7------------65---------------+

  get_unit(insn, code, FU_S1);

  insn.itype = TMS6_mvk;

  op_imm(insn.Op1, ((code >> 10) & 1) << 7 | ((code >> 5) & 3) << 5 | ((code >> 11) & 3) << 3 | (code >> 13) & 7);
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, false));
}

// Ssh5 (0x402 / 0x41e), S2sh (0x462 / 0x47e) Instruction Formats
static void cmpct_Ssh5_S2sh(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);

  // Ssh5 Instruction Format
  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |ucst 2-0|ucst | 1|src2/dst|  op | 0| 0| 0| 1| s|
  // +------------43---------------------------------+

  // S2sh Instruction Format
  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |  src1  |  op | 1|src2/dst| 1| 1| 0| 0| 0| 1| s|
  // +-----------------------------------------------+

  get_unit(insn, code, FU_S1);

  bool sat = (fph & BIT14) != 0;
  bool is_S2sh = (code & 0x60) == 0x60;

  uint8 op = (code >> (is_S2sh ? 11 : 5)) & 3;
  switch ( op )
  {
    case 0:
      insn.itype = TMS6_shl;
      break;
    case 1:
      insn.itype = TMS6_shr;
      break;
    case 2:
      insn.itype = (!is_S2sh && sat) ? TMS6_sshl : TMS6_shru;
      break;
    case 3:
      {
        if ( is_S2sh )
          insn.itype = TMS6_sshl;
        break;
      }
  }

  uint16 src2_dst = make_reg(insn, (code >> 7) & 7, false);
  op_reg(insn.Op1, src2_dst);
  op_reg(insn.Op3, src2_dst);

  if ( is_S2sh )
    op_reg(insn.Op2, make_reg(insn, (code >> 13) & 7, false));
  else
    op_imm(insn.Op2, ((code >> 11) & 3) << 3 | (code >> 13) & 7);
}

// Sc5 (0x2 / 41e), S2ext (0x62 / 4de) Instruction Formats
static void cmpct_Sc5_S2ext(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // Sc5 Instruction Format
  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |ucst 2-0|ucst | 0|src2/dst|  op | 0| 0| 0| 1| s|
  // +------------43---------------------------------+

  // S2ext Instruction Format
  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |   dst  |  op | 0|   src2 | 1| 1| 0| 0| 0| 1| s|
  // +-----------------------------------------------+

  get_unit(insn, code, FU_S1);

  bool is_S2ext = (code & 0x60) == 0x60;
  uint8 op = (code >> (is_S2ext ? 11 : 5)) & 3;

  uint16 src2_dst = make_reg(insn, (code >> 7) & 7, false);
  uint16 dst = make_reg(insn, (code >> 13) & 7, false);

  uint8 ucst5_val = 0;
  if ( is_S2ext )
  {
    insn.itype = ((code & BIT12) != 0) ? TMS6_extu : TMS6_ext;
    ucst5_val = ((code & BIT11) != 0) ? 24 : 16;

    op_reg(insn.Op3, dst);
    op_imm(insn.Op2, ucst5_val);
  }
  else
  {
    static const uint16 Scs5_table[] = { TMS6_extu, TMS6_set, TMS6_clr };

    insn.itype = Scs5_table[op];
    ucst5_val = ((code >> 11) & 3) << 3 | (code >> 13) & 7;

    bool is_extu = insn.itype == TMS6_extu;
    op_imm(insn.Op2, is_extu ? 31 : ucst5_val);
    op_reg(insn.Op3, is_extu ? (uint16)(((code & BIT0) != 0) ? rB0 : rA0) : src2_dst);
  }

  op_imm(insn.Op1, ucst5_val);
  insn.Op1.src2 = src2_dst;

  insn.cflags |= aux_src2;
}

// Sx2op Instruction Format (0x2e / 0x47e)
static void cmpct_Sx2op(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |src1/dst| x|op| 0|   src2 | 0| 1| 0| 1| 1| 1| s|
  // +-----------------------------------------------+

  get_unit(insn, code, FU_S1);

  insn.itype = ((code & BIT11) != 0) ? TMS6_sub : TMS6_add;

  uint16 src1_dst = make_reg(insn, (code >> 13) & 7, false);
  op_reg(insn.Op1, src1_dst);
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, (code & BIT12) != 0));
  op_reg(insn.Op3, src1_dst);
}

// Sx5 Instruction Format (0x42e / 0x47e)
static void cmpct_Sx5(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |ucst 2-0|ucst | 1|src2/dst| 0| 1| 0| 1| 1| 1| s|
  // +------------43---------------------------------+

  get_unit(insn, code, FU_S1);

  insn.itype = TMS6_addk;

  op_imm(insn.Op1, ((code >> 11) & 3) << 3 | (code >> 13) & 7);
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, false));
}

// Sx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 0| 1| 1| 1| s|
// +-----------------------------------------------+

// Sx1b Instruction Format (0x6e / 0x187e)
static void cmpct_Sx1b(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10        7| 6| 5| 4| 3| 2| 1| 0|
  // |   N3   | 0| 0|    src2   | 1| 1| 0| 1| 1| 1| s|
  // +-----------------------------------------------+

  get_unit(insn, code, FU_S1);

  insn.itype = TMS6_bnop;

  op_reg(insn.Op1, make_reg(insn, (code >> 7) & 0xF, false));
  op_imm(insn.Op2, (code >> 13) & 7);
}

//--------------------------------------------------------------------------
// .D .L or .S Unit

//--------------------------------------------------------------------------
bool get_lsd_unit(insn_t &insn, uint16 code)
{
  static const funit_t unit_map[] =
  {
    FU_L1, FU_S1, FU_D1
  };
  uint8 unit_idx = (code >> 3) & 3;

  // Fixes collision with the M3 format (unit can't be 1|1)
  if ( unit_idx >= qnumber(unit_map) )
    return false;

  get_unit(insn, code, unit_map[unit_idx]);
  return true;
}

// LSDmvto (0x66 / 0x06), LSDmvfr (0x66 / 0x46) Instruction Formats
static void cmpct_LSDmvto_LSDmvfr(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // LSDmvto Instruction Forma
  // +-----------------------------------------------+
  // |15    13|12|11 10| 9     7| 6| 5| 4  3| 2| 1| 0|
  // |   dst  | x|srcms|   src2 | 0| 0| unit| 1| 1| s|
  // +-----------------------------------------------+

  // LSDmvfr Instruction Format
  // +-----------------------------------------------+
  // |15    13|12|11 10| 9     7| 6| 5| 4  3| 2| 1| 0|
  // |   dst  | x|dstms|   src2 | 1| 0| unit| 1| 1| s|
  // +-----------------------------------------------+

  // Fixes collision with the M3 format (unit can't be 1|1)
  if ( !get_lsd_unit(insn, code) )
    return;

  insn.itype = TMS6_mv;

  bool is_LSDmvto = (code & BIT6) == 0;
  uint16 ms = ((code & 0xC00) >> 7);

  uint16 src = (code >> 7) & 7;
  uint16 dst = (code >> 13) & 7;
  if ( is_LSDmvto )
    src |= ms;
  else
    dst |= ms;

  op_reg(insn.Op1, make_reg(insn, src, (code & BIT12) != 0));
  op_reg(insn.Op2, make_reg(insn, dst, false));
}

// LSDx1c Instruction Format (0x866 / 0x1c66)
static void cmpct_LSDx1c(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15 14|13|12|11|10| 9     7| 6| 5| 4  3| 2| 1| 0|
  // |  cc |uc| 0| 1| 0|   dst  | 1| 1| unit| 1| 1| s|
  // +------st---------------------------------------+

  if ( !get_lsd_unit(insn, code) )
    return;

  insn.itype = TMS6_mvk;

  uint8 cc = (code >> 14) & 3;
  insn.cond = cond_map[cc];

  op_imm(insn.Op1, (code & BIT13) != 0);
  op_reg(insn.Op2, make_reg(insn, (code >> 7) & 7, false));
}

// LSDx1 Instruction Format (0x1866 / 0x1c66)
static void cmpct_LSDx1(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);

  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6| 5| 4  3| 2| 1| 0|
  // |   op   | 1| 1| 0| src/dst| 1| 1| unit| 1| 1| s|
  // +-----------------------------------------------+

  if ( !get_lsd_unit(insn, code) )
    return;

  uint8 src_dst = make_reg(insn, (code >> 7) & 7, false);
  uint8 unit = (code >> 3) & 3;

  uint8 op = (code >> 13) & 7;
  switch ( op )
  {
    case 0:
    case 1:
      insn.itype = TMS6_mvk;
      op_imm(insn.Op1, op);
      op_reg(insn.Op2, src_dst);
      break;
    case 2:
      {
        // Lx1/Sx1
        if ( unit <= 1 )
        {
          insn.itype = TMS6_neg;
          op_reg(insn.Op1, src_dst);
          op_reg(insn.Op2, src_dst);
        }
        break;
      }
    case 3:
      insn.itype = TMS6_sub;
      op_reg(insn.Op1, src_dst);
      op_imm(insn.Op2, 1);
      op_reg(insn.Op3, src_dst);
      break;
    case 5:
      insn.itype = TMS6_add;
      op_reg(insn.Op1, src_dst);
      op_imm(insn.Op2, 1);
      op_reg(insn.Op3, src_dst);
      break;
    case 6:
      insn.itype = TMS6_mvc;
      op_reg(insn.Op1, src_dst);
      op_reg(insn.Op2, rILC);
      break;
    case 7:
      insn.itype = TMS6_xor;
      op_reg(insn.Op1, src_dst);
      op_imm(insn.Op2, 1);
      op_reg(insn.Op3, src_dst);
      break;
    default:
      break;
  }
}

//--------------------------------------------------------------------------
// No Unit

// Uspl Instruction Format (0x0c66 / 0xbc7e)
static void cmpct_Uspl(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // | 0|ii| 0| 0| 1| 1|  ii2-0 | 1| 1| 0| 0| 1| 1|op|
  // +----3------------------------------------------+

  insn.itype = (code & BIT0) ? TMS6_sploopd : TMS6_sploop;

  insn.Op1.type = o_imm;
  insn.Op1.dtype = dt_dword;
  insn.Op1.value = 1 + (((code >> 7) & 7) | ((code >> (14-3)) & 8));
}

// Uspldr Instruction Format (0x8c66 / 0xbc7e)
static void cmpct_Uspldr(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // | 1|ii| 0| 0| 1| 1|  ii2-0 | 1| 1| 0| 0| 1| 1|op|
  // +----3------------------------------------------+

  insn.itype = TMS6_sploopd;

  insn.Op1.type = o_imm;
  insn.Op1.dtype = dt_dword;
  insn.Op1.value = 1 + (((code >> 7) & 7) | ((code >> (14-3)) & 8));

  insn.cond = (code & BIT0) ? 0x2 : 0xC; // [B0] : [A0]
}

// Uspk Instruction Format (0x1c66 / 0x3c7e)
static void cmpct_Uspk(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15 14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |ii4-3| 0| 1| 1| 1| ii 2-0 | 1| 1| 0| 0| 1| 1|ii5
  // +stg----------------stg-----------------------stg

 insn.itype = TMS6_spkernel;

 insn.Op1.type = o_stgcyc;
 insn.Op1.dtype = dt_dword;
 insn.Op1.value = ((code >> 7) & 7)
                  | ((code >> (14-3)) & 0x18)
                  | ((code << 5) & 0x20);
}

// Uspm Instruction Format (0x2c66 / 0x2c7e)
static void cmpct_Uspm(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
  // |D2|D1| 1| ?| 1| 1|S2|S1|L2| 1| 1| 0| 0| 1| 1|L1|
  // +-----------------------------------------------+

  insn.itype = (code & BIT12) ? TMS6_spmaskr : TMS6_spmask;

  insn.Op1.type = o_imm;
  insn.Op1.dtype = dt_dword;
  insn.Op1.value = (code & 1)                 // L1
                  | ((code >> (7-1)) & 0xe)   // S2-S1-L2
                  | ((code >> (14-4)) & 0x30);// D2-D1
}

// Unop Instruction Format (0x0c6e / 0x1fff)
static void cmpct_Unop(tms6_t *proc, insn_t &insn, uint32 fph, ushort code)
{
  qnotused(proc);
  qnotused(fph);
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
  // |   N3   | 0| 1| 1| 0| 0| 0| 1| 1| 0| 1| 1| 1| 0|
  // +-----------------------------------------------+

  insn.itype = TMS6_nop;

  insn.Op1.type = o_imm;
  insn.Op1.dtype = dt_dword;
  insn.Op1.value = ((code >> 13) & 0xF) + 1;
  if ( insn.Op1.value == 1 )
    insn.Op1.clr_shown();
}

//--------------------------------------------------------------------------
struct cmpct_tmsinsn_t
{
  ushort code_val;
  ushort code_mask;
  uchar exp_val;
  uchar exp_mask;
  void (*handler)(tms6_t *proc, insn_t &insn, uint32 fph, ushort code);
  uint32 xpath_bit; // there can't be a xpath at bit0
};

static const struct cmpct_tmsinsn_t cmpct_tmsinsn[] =
{
  { 0x8c04, 0x8c06, 0x00, 0x00, cmpct_Dstk, 0 },
  { 0x0077, 0x087f, 0x00, 0x00, cmpct_Dpp, 0 },
  { 0x0004, 0x0006, 0x00, 0x00, cmpct_Doff4_Dind_Dinc_Ddec, 0 },

  // LSDmvto
  { 0x0006, 0x0066, 0x00, 0x00, cmpct_LSDmvto_LSDmvfr, BIT12 },

  // LSDmvfr
  { 0x0046, 0x0066, 0x00, 0x00, cmpct_LSDmvto_LSDmvfr, BIT12 },

  { 0x0000, 0x040e, 0x00, 0x00, cmpct_L3, BIT12 },
  { 0x0400, 0x040e, 0x00, 0x00, cmpct_L3i, BIT12 },
  { 0x0008, 0x040e, 0x00, 0x00, cmpct_Ltbd, BIT12 },
  { 0x0408, 0x040e, 0x00, 0x00, cmpct_L2c, BIT12 },
  { 0x0426, 0x047e, 0x00, 0x00, cmpct_Lx5, 0 },
  { 0x1026, 0x147e, 0x00, 0x00, cmpct_Lx1c, 0 },
  { 0x0026, 0x147e, 0x00, 0x00, cmpct_Lx3c, 0 },

  { 0x0c6e, 0x1fff, 0x00, 0x00, cmpct_Unop, 0 },
  { 0x8c66, 0xbc7e, 0x00, 0x00, cmpct_Uspldr, 0 },
  { 0x0c66, 0xbc7e, 0x00, 0x00, cmpct_Uspl, 0 },
  { 0x1c66, 0x3c7e, 0x00, 0x00, cmpct_Uspk, 0 },
  { 0x2c66, 0x2c7e, 0x00, 0x00, cmpct_Uspm, 0 },

  { 0x001a, 0x003e, 0x02, 0x02, cmpct_Scs10, 0 }, // BR = 1

  // Sbs7
  { 0x000a, 0x003e, 0x02, 0x03, cmpct_Sbs7_c_sbu8_c, 0 }, // SAT = 0, BR = 1

  // Sbs7c
  { 0x002a, 0x002e, 0x02, 0x03, cmpct_Sbs7_c_sbu8_c, 0 }, // SAT = 0, BR = 1

  // Sbu8
  { 0xc00a, 0xc03e, 0x02, 0x03, cmpct_Sbs7_c_sbu8_c, 0 }, // SAT = 0, BR = 1

  // Sbu8c
  { 0xc02a, 0xc02e, 0x02, 0x03, cmpct_Sbs7_c_sbu8_c, 0 }, // SAT = 0, BR = 1

  // S3
  { 0x000a, 0x040e, 0x00, 0x02, cmpct_S3_S3i, BIT12 }, // BR = 0

  // S3i
  { 0x040a, 0x040e, 0x00, 0x02, cmpct_S3_S3i, BIT12 }, // BR = 0

  { 0x0402, 0x041e, 0x00, 0x00, cmpct_Ssh5_S2sh, 0 }, // SAT = 0/1

  { 0x0002, 0x041e, 0x00, 0x00, cmpct_Sc5_S2ext, 0 },

  { 0x0012, 0x001e, 0x00, 0x00, cmpct_Smvk8, 0 },

  { 0x042e, 0x047e, 0x00, 0x00, cmpct_Sx5, 0 },

  { 0x002e, 0x047e, 0x00, 0x00, cmpct_Sx2op, BIT12 },

  { 0x006e, 0x187e, 0x00, 0x00, cmpct_Sx1b, 0 },

  { 0x0436, 0x047e, 0x00, 0x00, cmpct_Dx5, 0 },
  { 0x0c77, 0x1c7f, 0x00, 0x00, cmpct_Dx5p, 0 },
  { 0x0036, 0x04fe, 0x00, 0x00, cmpct_Dx2op, BIT12 },

  { 0x001e, 0x001e, 0x00, 0x00, cmpct_M3, BIT12 },

  { 0x866, 0x1c66, 0x00, 0x00, cmpct_LSDx1c, 0 },
  { 0x1866, 0x1c66, 0x00, 0x00, cmpct_LSDx1, 0 }
};

//lint -e{818, 1762} parameter could be pointer to const, member function could be made const
int tms6_t::ana_compact(insn_t *_insn, uint32 fph)
{
  int i;

  insn_t &insn = *_insn;
  if ( insn.ip & 1 )
    return 0;           // alignment error

  int n = get_word_pos(insn.ea, true);
  ushort code = get_word(insn.ea);
  insn.size = 2;

  if ( fph & (1 << n) ) // check the p-bits field
    insn.cflags |= aux_para; // parallel execution with the next insn

  insn.itype = TMS6_null;

  for ( i=0; i < qnumber(cmpct_tmsinsn); i++ )
  {
    const struct cmpct_tmsinsn_t *cinsn = &cmpct_tmsinsn[i];
    uchar exp = (fph >> 14) & 0x7f;
    if ( ((code & cinsn->code_mask) == cinsn->code_val)
      && ((exp & cinsn->exp_mask) == cinsn->exp_val) )
    {
      cinsn->handler(this, insn, fph, code);
      if ( insn.itype != TMS6_null )
      {
        if ( cinsn->xpath_bit != 0 && (code & cinsn->xpath_bit) != 0 )
          insn.cflags |= aux_xp;

        break;
      }
    }
  }

  return insn.itype == TMS6_null ? 0 : insn.size;
}

//==========================================================================
// Main analysis entry point
//==========================================================================

int tms6_t::ana(insn_t *_insn)
{
  uint32 fph = 0;
  int rv = 0;

  insn_t &insn = *_insn;

  // Get (potential) header (last dword of a 8 dword fetch packet)

  // Are we in a "Header based fetch packet"? (see SPRU732J Section 3.9)
  if ( get_fph(&fph, get_fph_pos(insn.ea)) )
  {
    int n = get_word_pos(insn.ea, false);

    // Is it the header word itself?
    if ( n == 7 )
    {
      // Nothing to output, generated by the compiler directly
      insn.size = 4;
      insn.itype = TMS6_fphead;
      insn.auxpref = fph;
      rv = insn.size;
    }
    // Is it a compact instruction?
    else if ( fph_is_compact_insn(fph, n) ) // check the layout field
    {
      rv = ana_compact(&insn, fph);
    }
    else
    {
      // Classic 32-bit instruction
      rv = ana_classic(&insn);
    }
  }
  else
  {
    // Standard C6000 Fetch Packet => Always long instructions
    rv = ana_classic(&insn);
  }

  return rv;
}

//lint -e754
