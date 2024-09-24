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
};

// operand types
#define t_none           0
#define t_sint           1
#define t_xsint          2
#define t_uint           3
#define t_xuint          4
#define t_slong          5
#define t_xslong         6
#define t_ulong          7
#define t_xulong         8
#define t_scst5          9
#define t_ucst5         10
#define t_slsb16        11
#define t_xslsb16       12
#define t_ulsb16        13
#define t_xulsb16       14
#define t_smsb16        15
#define t_xsmsb16       16
#define t_umsb16        17
#define t_xumsb16       18
#define t_irp           19
#define t_cregr         20
#define t_cregw         21
#define t_ucst1         22
#define t_dp            23
#define t_xdp           24
#define t_sp            25
#define t_xsp           26
#define t_ucst15        27
#define t_scst7         28
#define t_ucst3         29
#define t_b14           30
#define t_dint          31
#define t_i2            32
#define t_xi2           33
#define t_i4            34
#define t_xi4           35
#define t_s2            36
#define t_xs2           37
#define t_u2            38
#define t_xu2           39
#define t_s4            40
#define t_xs4           41
#define t_u4            42
#define t_xu4           43
#define t_scst10        44
#define t_scst12        45
#define t_scst21        46
#define t_a3            47      // a3 or b3
#define t_bv2           48      // 2 bits
#define t_bv4           49      // 4 bits
#define t_ds2           50
#define t_sllong        51
#define t_ullong        52
#define t_dws4          53
#define t_dwu4          54

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
  cst <<= 2;
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

static int find_crreg(int idx)
{
  for ( int i=0; i < qnumber(ctrls); i++ )
    if ( ctrls[i].idx == (idx & ctrls[i].mask) )
      return ctrls[i].reg;
  return -1;
}

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
      isother = false;
      // no break
    case t_xs2:
    case t_xu2:
    case t_xi2:
    case t_xi4:
    case t_xu4:
    case t_xs4:
    case t_xsint:
    case t_xuint:
      x.type  = o_reg;
      x.dtype = dt_dword;
      x.reg   = make_reg(insn, v, isother);
      break;
    case t_slsb16:
    case t_ulsb16:
    case t_smsb16:
    case t_umsb16:
      isother = false;
      // no break
    case t_xslsb16:
    case t_xulsb16:
    case t_xsmsb16:
    case t_xumsb16:
      x.type  = o_reg;
      x.dtype = dt_word;
      x.reg   = make_reg(insn, v, isother);
      break;
    case t_dint:
    case t_slong:
    case t_ulong:
    case t_sllong:
    case t_ullong:
    case t_dws4:
    case t_dwu4:
      isother = false;
      // no break
    case t_xslong:
    case t_xulong:
      x.type  = o_regpair;
      x.dtype = dt_qword;
      x.reg   = make_reg(insn, v, isother);
      break;
    case t_sp:
      isother = false;
      // no break
    case t_xsp:
      x.type  = o_reg;
      x.dtype = dt_float;
      x.reg   = make_reg(insn, v, isother);
      break;
    case t_dp:
      isother = false;
      // no break
    case t_xdp:
      x.type  = o_regpair;
      x.dtype = dt_double;
      x.reg   = make_reg(insn, v & ~1, isother);
      break;
    case t_ucst1:
      op_imm(x, v & 1);
      break;
    case t_scst5:
      if ( v & 0x10 )
        v |= ~0x1F;              // extend sign
      /* fall thru */
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
  if ( !make_op(insn, *xptr, code, tinsn->src1, (code >> 13) & 0x1F, isother) )
    return 0;
  if ( xptr->type != o_void )
    xptr++;
  if ( !make_op(insn, *xptr, code, tinsn->src2, (code >> 18) & 0x1F, isother) )
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
  { TMS6_pack2,  t_i2,          t_xi2,          t_i2            }, // 000 0000
  { TMS6_dptrunc,t_none,        t_dp,           t_sint          }, // 000 0001
  { TMS6_add,    t_scst5,       t_xsint,        t_sint          }, // 000 0010
  { TMS6_add,    t_sint,        t_xsint,        t_sint          }, // 000 0011
  { TMS6_sub2,   t_i2,          t_xi2,          t_i2            }, // 000 0100
  { TMS6_add2,   t_i2,          t_xi2,          t_i2            }, // 000 0101
  { TMS6_sub,    t_scst5,       t_xsint,        t_sint          }, // 000 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_sint          }, // 000 0111
  { TMS6_dpint,  t_none,        t_dp,           t_sint          }, // 000 1000
  { TMS6_dpsp,   t_none,        t_dp,           t_sp            }, // 000 1001
  { TMS6_spint,  t_none,        t_sp,           t_sint          }, // 000 1010
  { TMS6_sptrunc,t_none,        t_xsp,          t_sint          }, // 000 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 000 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 000 1101
  { TMS6_ssub,   t_scst5,       t_xsint,        t_sint          }, // 000 1110
  { TMS6_ssub,   t_sint,        t_xsint,        t_sint          }, // 000 1111
  { TMS6_addsp,  t_sp,          t_xsp,          t_sp            }, // 001 0000
  { TMS6_subsp,  t_sp,          t_xsp,          t_sp            }, // 001 0001
  { TMS6_sadd,   t_scst5,       t_xsint,        t_sint          }, // 001 0010
  { TMS6_sadd,   t_sint,        t_xsint,        t_sint          }, // 001 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 001 0100
  { TMS6_subsp,  t_xsp,         t_sp,           t_sp            }, // 001 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 001 0110
  { TMS6_sub,    t_xsint,       t_sint,         t_sint          }, // 001 0111
  { TMS6_adddp,  t_dp,          t_xdp,          t_dp            }, // 001 1000
  { TMS6_subdp,  t_dp,          t_xdp,          t_dp            }, // 001 1001
  { TMS6_null,   t_none,        t_xsint,        t_sint          }, // 001 1010 * why parse args?
  { TMS6_packlh2,t_i2,          t_xi2,          t_i2            }, // 001 1011 *
  { TMS6_packhl2,t_i2,          t_xi2,          t_i2            }, // 001 1100
  { TMS6_subdp,  t_xdp,         t_dp,           t_dp            }, // 001 1101
  { TMS6_packh2, t_i2,          t_xi2,          t_i2            }, // 001 1110
  { TMS6_ssub,   t_xsint,       t_sint,         t_sint          }, // 001 1111
  { TMS6_add,    t_scst5,       t_slong,        t_slong         }, // 010 0000
  { TMS6_add,    t_xsint,       t_slong,        t_slong         }, // 010 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0010
  { TMS6_add,    t_sint,        t_xsint,        t_slong         }, // 010 0011
  { TMS6_sub,    t_scst5,       t_slong,        t_slong         }, // 010 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_slong         }, // 010 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1000
  { TMS6_addu,   t_xuint,       t_ulong,        t_ulong         }, // 010 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1010
  { TMS6_addu,   t_uint,        t_xuint,        t_ulong         }, // 010 1011
  { TMS6_ssub,   t_scst5,       t_slong,        t_slong         }, // 010 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 010 1110
  { TMS6_subu,   t_uint,        t_xuint,        t_ulong         }, // 010 1111
  { TMS6_sadd,   t_scst5,       t_slong,        t_slong         }, // 011 0000
  { TMS6_sadd,   t_xsint,       t_slong,        t_slong         }, // 011 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 0110
  { TMS6_sub,    t_xsint,       t_sint,         t_slong         }, // 011 0111
  { TMS6_abs,    t_none,        t_slong,        t_slong         }, // 011 1000
  { TMS6_intdp,  t_none,        t_xsint,        t_dp            }, // 011 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1010
  { TMS6_intdpu, t_none,        t_xuint,        t_dp            }, // 011 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 011 1110
  { TMS6_subu,   t_xuint,       t_uint,         t_ulong         }, // 011 1111
  { TMS6_sat,    t_none,        t_slong,        t_sint          }, // 100 0000
  { TMS6_min2,   t_s2,          t_xs2,          t_s2            }, // 100 0001
  { TMS6_max2,   t_s2,          t_xs2,          t_s2            }, // 100 0010
  { TMS6_maxu4,  t_u4,          t_xu4,          t_u4            }, // 100 0011
  { TMS6_cmpgt,  t_scst5,       t_slong,        t_uint          }, // 100 0100
  { TMS6_cmpgt,  t_xsint,       t_slong,        t_uint          }, // 100 0101
  { TMS6_cmpgt,  t_scst5,       t_xsint,        t_uint          }, // 100 0110
  { TMS6_cmpgt,  t_sint,        t_xsint,        t_uint          }, // 100 0111
  { TMS6_minu4,  t_u4,          t_xu4,          t_u4            }, // 100 1000
  { TMS6_intspu, t_none,        t_xuint,        t_sp            }, // 100 1010
  { TMS6_intsp,  t_none,        t_xsint,        t_sp            }, // 100 1010
  { TMS6_subc,   t_uint,        t_xuint,        t_uint          }, // 100 1011
  // 1: on the C62x and C67x, op1 is ucst4 (the TI docs are misleading); on the
  //    C64x/C64x+ and C66x, op1 is ucst5; since the MSB should always be clear
  //    on the former we can treat it as a 5-bit field
  { TMS6_cmpgtu, t_ucst5,       t_ulong,        t_uint          }, // 100 1100 // see [1]
  { TMS6_cmpgtu, t_xuint,       t_ulong,        t_uint          }, // 100 1101
  { TMS6_cmpgtu, t_ucst5,       t_xuint,        t_uint          }, // 100 1110 // see [1]
  { TMS6_cmpgtu, t_uint,        t_xuint,        t_uint          }, // 100 1111
  { TMS6_cmpeq,  t_scst5,       t_slong,        t_uint          }, // 101 0000
  { TMS6_cmpeq,  t_xsint,       t_slong,        t_uint          }, // 101 0001
  { TMS6_cmpeq,  t_scst5,       t_xsint,        t_uint          }, // 101 0010
  { TMS6_cmpeq,  t_sint,        t_xsint,        t_uint          }, // 101 0011
  { TMS6_cmplt,  t_scst5,       t_slong,        t_uint          }, // 101 0100
  { TMS6_cmplt,  t_xsint,       t_slong,        t_uint          }, // 101 0101
  { TMS6_cmplt,  t_scst5,       t_xsint,        t_uint          }, // 101 0110
  { TMS6_cmplt,  t_sint,        t_xsint,        t_uint          }, // 101 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1001
  { TMS6_subabs4,t_u4,          t_xu4,          t_u4            }, // 101 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 101 1011
  { TMS6_cmpltu, t_ucst5,       t_ulong,        t_uint          }, // 101 1100 // see [1]
  { TMS6_cmpltu, t_xuint,       t_ulong,        t_uint          }, // 101 1101
  { TMS6_cmpltu, t_ucst5,       t_xuint,        t_uint          }, // 101 1110 // see [1]
  { TMS6_cmpltu, t_uint,        t_xuint,        t_uint          }, // 101 1111
  { TMS6_norm,   t_none,        t_slong,        t_uint          }, // 110 0000
  { TMS6_shlmb,  t_u4,          t_xu4,          t_u4            }, // 110 0001
  { TMS6_shrmb,  t_u4,          t_xu4,          t_u4            }, // 110 0010
  { TMS6_norm,   t_none,        t_xsint,        t_uint          }, // 110 0011
  { TMS6_ssub2,  t_s2,          t_xs2,          t_s2            }, // 110 0100
  { TMS6_add4,   t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_sub4,   t_i4,          t_xi4,          t_i4            }, // 110 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 0111
  { TMS6_packl4, t_i4,          t_xi4,          t_i4            }, // 110 1000
  { TMS6_packh4, t_i4,          t_xi4,          t_i4            }, // 110 1001
  // op1 is actually scst5, but because only the LSB is meaningful, we decode
  // it as ucst1 so that the result would be correct for the assembler
  { TMS6_lmbd,   t_ucst1,       t_xuint,        t_uint          }, // 110 1010
  { TMS6_lmbd,   t_uint,        t_xuint,        t_uint          }, // 110 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 110 1101
  { TMS6_xor,    t_scst5,       t_xuint,        t_uint          }, // 110 1110
  { TMS6_xor,    t_uint,        t_xuint,        t_uint          }, // 110 1111
  { TMS6_addsp,  t_sp,          t_xsp,          t_sp            }, // 111 0000
  { TMS6_subsp,  t_sp,          t_xsp,          t_sp            }, // 111 0001
  { TMS6_adddp,  t_dp,          t_xdp,          t_dp            }, // 111 0010
  { TMS6_subdp,  t_dp,          t_xdp,          t_dp            }, // 111 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 0100
  { TMS6_subsp,  t_xsp,         t_sp,           t_sp            }, // 111 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 0110
  { TMS6_subdp,  t_xdp,         t_dp,           t_dp            }, // 111 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1001
  { TMS6_and,    t_scst5,       t_xuint,        t_uint          }, // 111 1010
  { TMS6_and,    t_uint,        t_xuint,        t_uint          }, // 111 1011
  { TMS6_andn,   t_uint,        t_xuint,        t_uint          }, // 111 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 111 1101
  { TMS6_or,     t_scst5,       t_xuint,        t_uint          }, // 111 1110
  { TMS6_or,     t_uint,        t_xuint,        t_uint          }, // 111 1111
};

static const tmsinsn_t esc1A[32] =
{
  { TMS6_abs,    t_none,        t_xsint,        t_sint          }, // 0 0000
  { TMS6_swap4,  t_none,        t_xu4,          t_u4            }, // 0 0001
  { TMS6_unpklu4,t_none,        t_xsint,        t_sint          }, // 0 0010
  { TMS6_unpkhu4,t_none,        t_xsint,        t_sint          }, // 0 0011
  { TMS6_abs2,   t_none,        t_xs2,          t_s2            }, // 0 0100
  { TMS6_mvk,    t_none,        t_scst5,        t_sint          }, // 0 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 0110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 0 1111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 0111
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1001
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1010
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1100
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1101
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1110
  { TMS6_null,   t_none,        t_none,         t_none          }, // 1 1111
};

int tms6_t::l_ops(insn_t &insn, uint32 code) const
{
// +--------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|1|0|s|p|
// +--------------------------------------------------------------+

  int opcode = (code >> 5) & 0x7F;
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
  { TMS6_null,    t_none,       t_none,         t_none          }, // 0 0100
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
  { TMS6_null,    t_none,       t_none,         t_none          }, // 1 1111
};

int tms6_t::handle_dx(insn_t &insn, const tmsinsn_t *table, uint32 code) const
{
  int opcode = (code >> 7) & 0x1F;
  if ( opcode < 0x10 )
    insn.funit -= 2; // D -> M
  else if ( opcode >= 0x18 )
    insn.funit -= 4; // D -> S
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
{                                                              // bits 11..7
  { TMS6_smpy2,    t_s2,        t_xs2,          t_ullong        }, // 0 0000
  { BITGRP,        t_none,      t_xu4,          t_u4            }, // 0 0001
  { TMS6_mpysu4,   t_s4,        t_xu4,          t_dws4          }, // 0 0010
  { TMS6_dotpnrsu2,t_s2,        t_xu2,          t_sint          }, // 0 0011
  { TMS6_dotpn2,   t_s2,        t_xs2,          t_sint          }, // 0 0100
  { TMS6_dotp2,    t_s2,        t_xs2,          t_sllong        }, // 0 0101
  { TMS6_dotprsu2, t_s2,        t_xu2,          t_sint          }, // 0 0110
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 0111
  { TMS6_gmpy4,    t_u4,        t_xu4,          t_u4,           }, // 0 1000
  { TMS6_avg2,     t_s2,        t_xs2,          t_s2            }, // 0 1001
  { TMS6_mpyli,    t_sint,      t_xsint,        t_sllong        }, // 0 1010
  // TI docs say mpysp2dp operands are "sp, xsp, sp", but the TI assembler
  // wants a regpair for operand 3, so the docs must be wrong
  { TMS6_mpysp2dp, t_sp,        t_xsp,          t_dp            }, // 0 1011
  { TMS6_mpy32us,  t_uint,      t_xsint,        t_dint          }, // 0 1100
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 1101
  { TMS6_rotl,     t_uint,      t_xuint,        t_uint          }, // 0 1110
  { TMS6_null,     t_none,      t_none,         t_none          }, // 0 1111
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0000
  { TMS6_or,       t_scst5,     t_xuint,        t_uint          }, // 1 0001
  { TMS6_sub2,     t_i2,        t_xi2,          t_i2            }, // 1 0010
  { TMS6_and,      t_scst5,     t_xuint,        t_uint          }, // 1 0011
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0100
  { TMS6_add,      t_scst5,     t_xsint,        t_sint          }, // 1 0101
  { TMS6_null,     t_none,      t_none,         t_none          }, // 1 0110
  { TMS6_xor,      t_scst5,     t_xuint,        t_uint          }, // 1 0111
  { TMS6_saddus2,  t_u2,        t_xs2,          t_u2            }, // 1 1000
  { TMS6_saddu4,   t_u4,        t_xu4,          t_u4            }, // 1 1001
  { TMS6_sub,      t_sint,      t_xsint,        t_sint          }, // 1 1010
  { TMS6_shr2,     t_uint,      t_xs2,          t_s2            }, // 1 1011
  { TMS6_shlmb,    t_u4,        t_xu4,          t_u4            }, // 1 1100
  { TMS6_dmv,      t_sint,      t_xsint,        t_dint          }, // 1 1101
  { TMS6_max2,     t_s2,        t_xs2,          t_s2            }, // 1 1110
  { TMS6_pack2,    t_i2,        t_xi2,          t_i2            }, // 1 1111
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
    if ( (code & BIT23) == 0 )
      if ( insn.itype == TMS6_ldndw || insn.itype == TMS6_stndw )
        return 1; // no scaling
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
  insn.Op1.addr = (code >> 8) & 0x7FFF;
  bool is_store = is_store_insn(insn.itype);
  if ( is_off(get_flags(insn.ea), is_store) )
    insn.Op1.addr <<= shift;
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
      insn.Op1.addr = (code >> 13) & 0x1F;
      if ( is_off(get_flags(insn.ea), is_store) )
        insn.Op1.addr <<= shift;
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
{                                                               // bits 11..6
  { TMS6_bdec,   t_scst10,      t_none,         t_uint          }, // 00 0000
  { TMS6_add2,   t_i2,          t_xi2,          t_i2            }, // 00 0001
  { TMS6_spdp,   t_none,        t_xsp,          t_dp            }, // 00 0010
  { TMS6_b,      t_none,        t_irp,          t_none          }, // 00 0011
  { TMS6_bnop,   t_none,        t_scst12,       t_ucst3         }, // 00 0100
  { TMS6_addkpc, t_scst7,       t_ucst3,        t_uint          }, // 00 0101
  { TMS6_add,    t_scst5,       t_xsint,        t_sint          }, // 00 0110
  { TMS6_add,    t_sint,        t_xsint,        t_sint          }, // 00 0111
  { TMS6_packhl2,t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_packh2, t_i2,          t_xi2,          t_i2            }, // 00 1000
  { TMS6_xor,    t_scst5,       t_xuint,        t_uint          }, // 00 1010
  { TMS6_xor,    t_uint,        t_xuint,        t_uint          }, // 00 1011
  { TMS6_null,   t_none,        t_none,         t_none          }, // 00 1100
  { TMS6_b,      t_none,        t_xuint,        t_none          }, // 00 1101
  { TMS6_mvc,    t_none,        t_xuint,        t_cregw         }, // 00 1110
  { TMS6_mvc,    t_none,        t_cregr,        t_uint          }, // 00 1111
  { TMS6_packlh2,t_i2,          t_xi2,          t_i2            }, // 01 0000
  { TMS6_sub2,   t_sint,        t_xsint,        t_sint          }, // 01 0001
  { TMS6_shl,    t_ucst5,       t_xsint,        t_slong         }, // 01 0010
  { TMS6_shl,    t_uint,        t_xsint,        t_slong         }, // 01 0011
  { TMS6_cmpgt2, t_s2,          t_xs2,          t_bv2           }, // 01 0100
  { TMS6_cmpgtu4,t_u4,          t_xu4,          t_bv4           }, // 01 0101
  { TMS6_sub,    t_scst5,       t_xsint,        t_sint          }, // 01 0110
  { TMS6_sub,    t_sint,        t_xsint,        t_sint          }, // 01 0111
  { TMS6_shr2,   t_ucst5,       t_xs2,          t_s2            }, // 01 1000
  { TMS6_shru2,  t_ucst5,       t_xu2,          t_u2            }, // 01 1001
  { TMS6_or,     t_scst5,       t_xuint,        t_uint          }, // 01 1010
  { TMS6_or,     t_uint,        t_xuint,        t_uint          }, // 01 1011
  { TMS6_cmpeq4, t_s4,          t_xs4,          t_bv4           }, // 01 1100
  { TMS6_cmpeq2, t_s2,          t_xs2,          t_bv2           }, // 01 1101
  { TMS6_and,    t_scst5,       t_xuint,        t_uint          }, // 01 1110
  { TMS6_and,    t_uint,        t_xuint,        t_uint          }, // 01 1111
  { TMS6_sadd,   t_sint,        t_xsint,        t_sint          }, // 10 0000
  { TMS6_null,   t_none,        t_none,         t_none          }, // 10 0001
  { TMS6_sshl,   t_ucst5,       t_xsint,        t_sint          }, // 10 0010
  { TMS6_sshl,   t_uint,        t_xsint,        t_sint          }, // 10 0011
  { TMS6_shru,   t_ucst5,       t_ulong,        t_ulong         }, // 10 0100
  { TMS6_shru,   t_uint,        t_ulong,        t_ulong         }, // 10 0101
  { TMS6_shru,   t_ucst5,       t_xuint,        t_uint          }, // 10 0110
  { TMS6_shru,   t_uint,        t_xuint,        t_uint          }, // 10 0111
  { TMS6_cmpeqdp,t_dp,          t_xdp,          t_sint          }, // 10 1000
  { TMS6_cmpgtdp,t_dp,          t_xdp,          t_sint          }, // 10 1001
  { TMS6_cmpltdp,t_dp,          t_xdp,          t_sint          }, // 10 1010
  { TMS6_extu,   t_uint,        t_xuint,        t_uint          }, // 10 1011
  { TMS6_absdp,  t_dp,          t_none,         t_dp            }, // 10 1100
  { TMS6_rcpdp,  t_dp,          t_none,         t_dp            }, // 10 1101
  { TMS6_rsqrdp, t_dp,          t_none,         t_dp            }, // 10 1110
  { TMS6_ext,    t_uint,        t_xsint,        t_sint          }, // 10 1111
  { TMS6_shl,    t_ucst5,       t_slong,        t_slong         }, // 11 0000
  { TMS6_shl,    t_uint,        t_slong,        t_slong         }, // 11 0001
  { TMS6_shl,    t_ucst5,       t_xsint,        t_sint          }, // 11 0010
  { TMS6_shl,    t_uint,        t_xsint,        t_sint          }, // 11 0011
  { TMS6_shr,    t_ucst5,       t_slong,        t_slong         }, // 11 0100
  { TMS6_shr,    t_uint,        t_slong,        t_slong         }, // 11 0101
  { TMS6_shr,    t_ucst5,       t_xsint,        t_sint          }, // 11 0110
  { TMS6_shr,    t_uint,        t_xsint,        t_sint          }, // 11 0111
  { TMS6_cmpeqsp,t_sp,          t_xsp,          t_sint          }, // 11 1000
  { TMS6_cmpgtsp,t_sp,          t_xsp,          t_sint          }, // 11 1001
  { TMS6_cmpltsp,t_sp,          t_xsp,          t_sint          }, // 11 1010
  { TMS6_set,    t_uint,        t_xuint,        t_uint          }, // 11 1011
  { TMS6_abssp,  t_none,        t_xsp,          t_sp            }, // 11 1100
  { TMS6_rcpsp,  t_none,        t_xsp,          t_sp            }, // 11 1101
  { TMS6_rsqrsp, t_none,        t_xsp,          t_sp            }, // 11 1110
  { TMS6_clr,    t_uint,        t_xuint,        t_uint          }, // 11 1111
};

int tms6_t::s_ops(insn_t &insn, uint32 code) const
{
// +----------------------------------------------------------------+
// |31    29|28|27    23|22   18|17        13|12|11    6|5|4|3|2|1|0|
// |  creg  |z |  dst   |  src2 |  src1/cst  |x |   op  |1|0|0|0|s|p|
// +----------------------------------------------------------------+

  int opcode = (code >> 6) & 0x3F;
  if ( !table_insns(insn, code, sops + opcode, (code & BIT12) != 0) )
    return 0;
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
      /* fall thru */
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
  uint16 itype;
  uchar src1;
  uchar src2;
  uchar dst;
  uint32 index;
  uint32 mask;
  funit_t unit;
};
static const tmsinsn_indexed_t nopreds[] =
{                                                  // bits 11..2
  { TMS6_callp,    t_scst21,    t_a3,           t_none,  0x004, 0x01F, FU_S1 },
  { TMS6_addab,    t_b14,       t_ucst15,       t_uint,  0x00F, 0x01F, FU_D1 },
  { TMS6_addad,    t_b14,       t_ucst15,       t_uint,  0x010, 0x01F, FU_D1 },
  { TMS6_addah,    t_b14,       t_ucst15,       t_uint,  0x017, 0x01F, FU_D1 },
  { TMS6_addaw,    t_b14,       t_ucst15,       t_uint,  0x01F, 0x01F, FU_D1 },
  { TMS6_addsub,   t_sint,      t_xsint,        t_dint,  0x066, 0x3FF, FU_L1 },
  { TMS6_saddsub,  t_sint,      t_xsint,        t_dint,  0x076, 0x3FF, FU_L1 },
  { TMS6_dpack2,   t_sint,      t_xsint,        t_dint,  0x1A6, 0x3FF, FU_L1 },
  { TMS6_shfl3,    t_sint,      t_xsint,        t_dint,  0x1B6, 0x3FF, FU_L1 },
  { TMS6_addsub2,  t_sint,      t_xsint,        t_dint,  0x06E, 0x3FF, FU_L1 },
  { TMS6_saddsub2, t_sint,      t_xsint,        t_dint,  0x07E, 0x3FF, FU_L1 },
  { TMS6_dpackx2,  t_sint,      t_xsint,        t_dint,  0x19E, 0x3FF, FU_L1 },
  { TMS6_cmpy,     t_s2,        t_xs2,          t_dint,  0x0AC, 0x3FF, FU_M1 },
  { TMS6_cmpyr,    t_s2,        t_xs2,          t_s2,    0x0BC, 0x3FF, FU_M1 },
  { TMS6_cmpyr1,   t_s2,        t_xs2,          t_s2,    0x0CC, 0x3FF, FU_M1 },
  { TMS6_mpy2ir,   t_sint,      t_xsint,        t_dint,  0x0FC, 0x3FF, FU_M1 },
  { TMS6_ddotpl2r, t_dint,      t_xs2,          t_s2,    0x14C, 0x3FF, FU_M1 },
  { TMS6_ddotph2r, t_dint,      t_xs2,          t_s2,    0x15C, 0x3FF, FU_M1 },
  { TMS6_ddotpl2,  t_dint,      t_xs2,          t_dint,  0x16C, 0x3FF, FU_M1 },
  { TMS6_ddotph2,  t_dint,      t_xs2,          t_dint,  0x17C, 0x3FF, FU_M1 },
  { TMS6_ddotp4,   t_ds2,       t_xs2,          t_dint,  0x18C, 0x3FF, FU_M1 },
  { TMS6_smpy32,   t_sint,      t_xsint,        t_sint,  0x19C, 0x3FF, FU_M1 },
  { TMS6_xormpy,   t_uint,      t_xuint,        t_uint,  0x1BC, 0x3FF, FU_M1 },
  { TMS6_gmpy,     t_uint,      t_xuint,        t_uint,  0x1FC, 0x3FF, FU_M1 },
  { TMS6_rpack2,   t_sint,      t_xsint,        t_s2,    0x3BC, 0x3FF, FU_S1 },
  { TMS6_swe,      t_none,      t_none,         t_none,  0x0000000, 0x3FFFFFF, FU_NONE },
  { TMS6_dint,     t_none,      t_none,         t_none,  0x0001000, 0x3FFFFFF, FU_NONE },
  { TMS6_swenr,    t_none,      t_none,         t_none,  0x0000800, 0x3FFFFFF, FU_NONE },
  { TMS6_rint,     t_none,      t_none,         t_none,  0x0001800, 0x3FFFFFF, FU_NONE },
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
      bool other = (code & BIT1) != 0;
      if ( p->unit == FU_M1 || p->unit == FU_L1 )
        other = (code & BIT12) != 0;
      int size = table_insns(insn, code, (tmsinsn_t *)p, other);
      if ( p->src1 == t_b14 )
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

static void cmpct_Doff4_Dind_Dinc_Ddec(insn_t &insn, uint32 fph, ushort code)
{
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
    reg->reg = (code >> 4) & 6;
  }
  else
  {
    reg->type = o_reg;
    reg->reg = (code >> 4) & 7;
  }
  reg->reg += (code & BIT12) ? rA16 : rB16;

  // pointer
  ptr->reg = (code >> 7) & 3;
  ptr->reg += (code & BIT0) ? rA4 : rB4;

  if ( !(code & BIT10) )
  {
    // Doff4 & Doff4DW
    ptr->type = o_displ;
    ptr->mode = 0;
    ptr->addr = (((code >> 11) & 1) << 3) | ((code >> 13) & 7);
  }
  else if ( !(code & BIT11) )
  {
    // Dind & DindDW
    ptr->type = o_phrase;
    ptr->mode = 0;
    ptr->secreg = (code >> 13) & 7;
    ptr->secreg += (code & BIT0) ? rA16 : rB16;
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

  ptr->addr <<= shift;
}


// Dpp Instruction Format (0x0877 / 0x087f)
static void cmpct_Dpp(insn_t &insn, uint32 fph, ushort code)
{
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
  // int ucst = ((code >> 13) & 1) + 1;

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
  reg->type = o_reg;
  reg->dtype = dt_dword;
  reg->reg = srcdst;
  reg->reg += (code & BIT12) ? rA4 : rB4;

  // pointer
  ptr->type = o_displ;
  ptr->dtype = dt_dword;
  ptr->mode = 0;
  ptr->reg = rB15;
  ptr->addr = (((code >> 7) & 7) << 2) | ((code >> 13) & 3);
  ptr->addr <<= 2;

}

// Dstk Instruction Format (0x8c04 / 0x8c06)
static void cmpct_Dstk(insn_t &insn, uint32 fph, ushort code)
{
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

// Dx2op Instruction Format
inline void cmpct_Dx2op(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(fph);
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // | src/dst| x|op| 0|   src2 | 0| 1| 1| 0| 1| 1| s|
  // +-----------------------------------------------+

  insn.itype = (code & BIT11) ? TMS6_sub : TMS6_add;

  insn.Op1.type = o_reg;
  insn.Op1.dtype = dt_dword;
  insn.Op1.reg = 0;

  insn.Op2.type = o_reg;
  insn.Op2.dtype = dt_dword;

  insn.Op3 = insn.Op1;

}

// Dx5 Instruction Format
// +-----------------------------------------------+
// |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |ucst 2-0|ucst | 1|   dst  | 0| 1| 1| 0| 1| 1| s|
// +------------43---------------------------------+

// Dx5p Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9  8| 7| 6| 5| 4| 3| 2| 1| 0|
// |ucst 2-0| 0| 1| 1|ucst |op| 1| 1| 1| 0| 1| 1| 1|
// +---------------------43------------------------+

// Dx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 1| 0| 1| 1| s|
// +-----------------------------------------------+

// Dpp Instruction Format
// +-----------------------------------------------+
// |15|14|13|12|11|10        7| 6| 5| 4| 3| 2| 1| 0|
// |dw|ld|uc| t| 0|  src/dst  | 1| 1| 1| 0| 1| 1| 1|
// +--/st-st0--------------------------------------+

//--------------------------------------------------------------------------
// L Unit

// L3 Instruction Format (0x0000 / 0x040e)
static void cmpct_L3(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  src1  | x|op| 0|  src2  |   dst  | 0| 0| 0| s|
  // +-----------------------------------------------+

}

// L3i Instruction Format (0x0400 / 0x040e)
static void cmpct_L3i(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6     4| 3| 2| 1| 0|
  // |  cst3  | x|sn| 1|  src2  |   dst  | 0| 0| 0| s|
  // +-----------------------------------------------+

}

// Ltbd Instruction Format (0x0008 / 0x040e)
static void cmpct_Ltbd(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15|14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
  // |  |  |  | x|  | 0|  src2  |  |  |  | 1| 0| 0| s|
  // +-----------------------------------------------+

}

// L2c Instruction Format (0x0408 / 0x040e)
static void cmpct_L2c(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15    13|12|11|10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |  src1  | x|op| 1|  src2  |op 10|ds| 1| 0| 0| s|
  // +-------------2--------------------t------------+

}

// Lx5 Instruction Format
// +-----------------------------------------------+
// |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |scst 2-0|scst | 1|   dst  | 0| 1| 0| 0| 1| 1| s|
// +------------43---------------------------------+

// Lx3c Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |  ucst3 | 0|ds| 0|  src2  | 0| 1| 0| 0| 1| 1| s|
// +-------------t---------------------------------+

// Lx1c Instruction Format
// +-----------------------------------------------+
// |15 14|13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |  op |uc| 1|ds| 0|  src2  | 0| 1| 0| 0| 1| 1| s|
// +------st1----t---------------------------------+

// Lx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 0| 0| 1| 1| s|
// +-----------------------------------------------+

//--------------------------------------------------------------------------
// M Unit

// M3 Instruction Format
inline void cmpct_M3(insn_t &insn, uint32 fph, ushort code)
{
  qnotused(insn);
  qnotused(fph);
  qnotused(code);
  // +-----------------------------------------------+
  // |15    13|12|11 10| 9     7| 6  5| 4| 3| 2| 1| 0|
  // |  src1  | x| dst |  src2  |  op | 1| 1| 1| 1| s|
  // +-----------------------------------------------+

}

//--------------------------------------------------------------------------
// S Unit

// Sbs7 Instruction Format
// +-----------------------------------------------+
// |15    13|12                 6| 5| 4| 3| 2| 1| 0|
// |   N3   |        scst7       | 0| 0| 1| 0| 1| s|
// +-----------------------------------------------+
// N3 = 0,1,2,3,4 or 5

// Sbu8 Instruction Format
// +-----------------------------------------------+
// |15|14|13                    6| 5| 4| 3| 2| 1| 0|
// | 1| 1|        ucst8          | 0| 0| 1| 0| 1| s|
// +-----------------------------------------------+

// Scs10 Instruction Format
// +-----------------------------------------------+
// |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
// |            scst10           | 0| 1| 1| 0| 1| s|
// +-----------------------------------------------+

// Sbs7c Instruction Format
// +-----------------------------------------------+
// |15    13|12                 6| 5| 4| 3| 2| 1| 0|
// |   N3   |        scst7       | 1| z| 1| 0| 1| s|
// +-----------------------------------------------+
// N3 = 0,1,2,3,4 or 5

// Sbu8c Instruction Format
// +-----------------------------------------------+
// |15|14|13                    6| 5| 4| 3| 2| 1| 0|
// | 1| 1|        ucst8          | 1| z| 1| 0| 1| s|
// +-----------------------------------------------+

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

// Smvk8 Instruction Format
// +-----------------------------------------------+
// |15    13|12 11|10| 9     7| 6  5| 4| 3| 2| 1| 0|
// |ucst 2-0|ucst |uc|   dst  |ucst | 1| 0| 0| 1| s|
// +------------43-st7------------65---------------+

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

// Sx2op Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |src1/dst| x|op| 0|   src2 | 0| 1| 0| 1| 1| 1| s|
// +-----------------------------------------------+

// Sx5 Instruction Format
// +-----------------------------------------------+
// |15    13|12 11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |ucst 2-0|ucst | 1|src2/dst| 0| 1| 0| 1| 1| 1| s|
// +------------43---------------------------------+

// Sx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4| 3| 2| 1| 0|
// |   op   | 1| 1| 0|src2/dst| 1| 1| 0| 1| 1| 1| s|
// +-----------------------------------------------+

// Sx1b Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10        7| 6| 5| 4| 3| 2| 1| 0|
// |   N3   | 0| 0|    src2   | 1| 1| 0| 1| 1| 1| s|
// +-----------------------------------------------+


//--------------------------------------------------------------------------
// .D .L or .S Unit


// LSDmvto Instruction Format
// +-----------------------------------------------+
// |15    13|12|11 10| 9     7| 6| 5| 4  3| 2| 1| 0|
// |   dst  | x|srcms|   src2 | 0| 0| unit| 1| 1| s|
// +-----------------------------------------------+


// LSDmvfr Instruction Format
// +-----------------------------------------------+
// |15    13|12|11 10| 9     7| 6| 5| 4  3| 2| 1| 0|
// |   dst  | x|dstms|   src2 | 1| 0| unit| 1| 1| s|
// +-----------------------------------------------+


// LSDx1c Instruction Format
// +-----------------------------------------------+
// |15 14|13|12|11|10| 9     7| 6| 5| 4  3| 2| 1| 0|
// |  cc |uc| 0| 1| 0|   dst  | 1| 1| unit| 1| 1| s|
// +------st---------------------------------------+


// LSDx1 Instruction Format
// +-----------------------------------------------+
// |15    13|12|11|10| 9     7| 6| 5| 4  3| 2| 1| 0|
// |   op   | 1| 1| 0| src/dst| 1| 1| unit| 1| 1| s|
// +-----------------------------------------------+

//--------------------------------------------------------------------------
// No Unit

// Uspl Instruction Format (0x0c66 / 0xbc7e)
static void cmpct_Uspl(insn_t &insn, uint32 fph, ushort code)
{
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
static void cmpct_Uspldr(insn_t &insn, uint32 fph, ushort code)
{
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
static void cmpct_Uspk(insn_t &insn, uint32 fph, ushort code)
{
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
static void cmpct_Uspm(insn_t &insn, uint32 fph, ushort code)
{
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
static void cmpct_Unop(insn_t &insn, uint32 fph, ushort code)
{
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
  void (*handler)(insn_t &insn, uint32 fph, ushort code);
};

static const struct cmpct_tmsinsn_t cmpct_tmsinsn[] =
{
  { 0x0077, 0x087f, 0x00, 0x00, cmpct_Dstk },
  { 0x8c04, 0x8c06, 0x00, 0x00, cmpct_Dpp },
  { 0x0004, 0x0006, 0x00, 0x00, cmpct_Doff4_Dind_Dinc_Ddec },

  { 0x0000, 0x040e, 0x00, 0x00, cmpct_L3 },
  { 0x0400, 0x040e, 0x00, 0x00, cmpct_L3i },
  { 0x0008, 0x040e, 0x00, 0x00, cmpct_Ltbd },
  { 0x0408, 0x040e, 0x00, 0x00, cmpct_L2c },

  { 0x0c6e, 0x1fff, 0x00, 0x00, cmpct_Unop },
  { 0x8c66, 0xbc7e, 0x00, 0x00, cmpct_Uspldr },
  { 0x0c66, 0xbc7e, 0x00, 0x00, cmpct_Uspl },
  { 0x1c66, 0x3c7e, 0x00, 0x00, cmpct_Uspk },
  { 0x2c66, 0x2c7e, 0x00, 0x00, cmpct_Uspm },
};


int tms6_t::ana_compact(insn_t *_insn, uint32 fph) const
{
  int i;

  insn_t &insn = *_insn;
  if ( insn.ip & 1 )
    return 0;           // alignment error

  int n = (insn.ea & 31) >> 1;
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
      cinsn->handler(insn, fph, code);
      msg("%d: %08a\n", i, insn.ea);  // FIXME
      break;
    }
  }

  return insn.itype == TMS6_null ? 0 : insn.size;
}

//==========================================================================
// Main analysis entry point
//==========================================================================

int tms6_t::ana(insn_t *_insn)
{
  uint32 fph;
  int rv = 0;

  insn_t &insn = *_insn;

  // Get (potential) header (last dword of a 8 dword fetch packet)
  fph = get_dword((insn.ea & ~31) + 28);

  // Are we in a "Header based fetch packet"? (see SPRU732J Section 3.9)
  if ( (fph & 0xf0000000) == 0xe0000000 )
  {
    int n = (insn.ea & 31) >> 2;

    // Is it the header word itself?
    if ( n == 7 )
    {
      // Nothing to output, generated by the compiler directly
      insn.size = 4;
      insn.itype = TMS6_null;
      rv = insn.size;
    }
    // Is it a compact instruction?
    else if ( fph & (1 << (21 + n)) ) // check the layout field
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
