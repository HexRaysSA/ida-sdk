/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "hppa.hpp"

//--------------------------------------------------------------------------
static void simplify(insn_t &insn, uint32 code)
{
  switch ( insn.itype )
  {
    // B,L,n target, %r0                =>      B,n    target
    // B,L,n target, %r2                =>      CALL,n target
    case HPPA_b:
      {
        int sub = (code>>13) & 7;
        if ( sub == 1 || sub == 4 )
          break;  // ,gate or ,push
        switch ( insn.Op2.reg )
        {
          case R0:
            insn.Op2.type = o_void;
            break;
          case R2:
            insn.itype = HPPA_call;
            insn.Op2.type = o_void;
            break;
        }
      }
      break;

     // BVE,L,n (b), %r2                =>      CALL,n (b)
     // BVE,n   (%r2)                   =>      RET,n
    case HPPA_bve:
      if ( code & BIT31 )
        break;        // ,push or ,pop
      if ( insn.Op2.type == o_reg )
      {
        insn.itype = HPPA_call;
        insn.Op1.type = o_void;
        break;
      }
      if ( insn.Op1.phrase == R2 )
      {
        insn.itype = HPPA_ret;
        insn.Op1.type = o_void;
      }
      break;

    // DEPD,Z,cond r,63-sa,64-sa,t      =>      SHLD,cond r,sa,t
    // DEPW,Z,cond r,31-sa,32-sa,t      =>      SHLW,cond r,sa,t
    case HPPA_depd:
    case HPPA_depw:
      if ( code & BIT21 )
        break;        // no Z flag
      if ( insn.Op2.type == o_imm
        && insn.Op3.type == o_imm
        && (insn.Op2.value+1) == insn.Op3.value )
      {
        insn.itype    += (HPPA_shld-HPPA_depd);
        insn.Op2.value = (insn.itype == HPPA_shld ? 63 : 31) - insn.Op2.value;
        insn.Op3       = insn.Op4;
        insn.Op4.type  = o_void;
      }
      break;

    // DEPWI,Z,cond -1,31,x,t      =>      LDI,cond (1<<x)-1,t
    case HPPA_depwi:
      if ( code & BIT21 )
        break;        // no Z flag
      if ( insn.Op2.type == o_imm && insn.Op2.value == 31
        && insn.Op3.type == o_imm && insn.Op3.value <= 16 )
      {
        insn.itype     = HPPA_ldi;
        insn.Op1.value = (uval_t(1) << insn.Op3.value) - 1;
        insn.Op2       = insn.Op4;
        insn.Op3.type  = o_void;
        insn.Op4.type  = o_void;
      }
      break;
    // EXTRD,S,cond r,63-sa,64-sa,t     =>      SHRD,S,cond r,sa,t
    // EXTRD,U,cond r,63-sa,64-sa,t     =>      SHRD,U,cond r,sa,t
    // EXTRW,S,cond r,31-sa,32-sa,t     =>      SHRW,S,cond r,sa,t
    // EXTRW,U,cond r,31-sa,32-sa,t     =>      SHRW,U,cond r,sa,t
    case HPPA_extrd:
    case HPPA_extrw:
      if ( insn.Op2.type == o_imm
        && insn.Op3.type == o_imm
        && (insn.Op2.value+1) == insn.Op3.value )
      {
        insn.itype    += HPPA_shrd - HPPA_extrd;
        insn.Op2.value = (insn.itype == HPPA_shrd ? 63 : 31) - insn.Op2.value;
        insn.Op3       = insn.Op4;
        insn.Op4.type  = o_void;
      }
      break;

    // LDO i(%r0), t                    =>      LDI i, t
    // LDO 0(r), t                      =>      COPY r, t
    case HPPA_ldo:
      if ( insn.Op1.reg == R0 )
      {
        insn.itype = HPPA_ldi;
        insn.Op1.type = o_imm;
        insn.Op1.value = insn.Op1.addr;
        break;
      }
      if ( insn.Op1.addr == 0 )
      {
        insn.itype = HPPA_copy;
        insn.Op1.type = o_reg;
      }
      break;

    // MTCTL r, %sar                    =>      MTSAR r
    case HPPA_mtctl:
      if ( insn.Op2.reg == CR11 )
      {
        insn.itype = HPPA_mtsar;
        insn.Op2.type = o_void;
      }
      break;

    // OR %r0, %r0, %r0                 =>      NOP
    // OR %r, %r0, %t                   =>      COPY r, t
    // OR %r0, %r, %t                   =>      COPY r, t
    case HPPA_or:
      if ( ((code>>13) & 7) )
        break;    // condition codes not zero
      if ( insn.Op1.reg == R0 )
      {
        if ( insn.Op2.reg == R0 && insn.Op3.reg == R0 )
        {
          insn.itype = HPPA_nop;
          insn.Op1.type = o_void;
          insn.Op2.type = o_void;
          insn.Op3.type = o_void;
          break;
        }
        insn.itype = HPPA_copy;
        insn.Op1 = insn.Op2;
        insn.Op2 = insn.Op3;
        insn.Op3.type = o_void;
        break;
      }
      if ( insn.Op2.reg == R0 )
      {
        insn.itype = HPPA_copy;
        insn.Op2 = insn.Op3;
        insn.Op3.type = o_void;
      }
      break;
  }
}

//--------------------------------------------------------------------------
struct table1_t
{
  ushort itype;
  char dtype;
};

static const table1_t C1[] =
{
  { 0,               dt_qword }, // 00
  { 0,               dt_qword }, // 01
  { 0,               dt_qword }, // 02
  { 0,               dt_qword }, // 03
  { 0,               dt_qword }, // 04
  { HPPA_diag,       dt_qword }, // 05
  { HPPA_fmpyadd,    dt_qword }, // 06
  { HPPA_null,       dt_qword }, // 07
  { HPPA_ldil,       dt_qword }, // 08
  { 0,               dt_qword }, // 09
  { HPPA_addil,      dt_qword }, // 0A
  { 0,               dt_qword }, // 0B
  { HPPA_copr,       dt_qword }, // 0C
  { HPPA_ldo,        dt_dword }, // 0D
  { 0,               dt_qword }, // 0E
  { HPPA_null,       dt_qword }, // 0F
  { HPPA_ldb,        dt_byte  }, // 10
  { HPPA_ldh,        dt_word  }, // 11
  { HPPA_ldw,        dt_dword }, // 12
  { HPPA_ldw,        dt_dword }, // 13
  { 0,               dt_qword }, // 14
  { HPPA_null,       dt_dword }, // 15
  { HPPA_fldw,       dt_dword }, // 16
  { 0,               dt_dword }, // 17
  { HPPA_stb,        dt_byte  }, // 18
  { HPPA_sth,        dt_word  }, // 19
  { HPPA_stw,        dt_dword }, // 1A
  { HPPA_stw,        dt_dword }, // 1B
  { 0,               dt_qword }, // 1C
  { HPPA_null,       dt_dword }, // 1D
  { HPPA_fstw,       dt_dword }, // 1E
  { 0,               dt_dword }, // 1F
  { HPPA_cmpb,       dt_byte  }, // 20
  { HPPA_cmpib,      dt_byte  }, // 21
  { HPPA_cmpb,       dt_byte  }, // 22
  { HPPA_cmpib,      dt_dword }, // 23
  { HPPA_cmpiclr,    dt_qword }, // 24
  { HPPA_subi,       dt_dword }, // 25
  { HPPA_fmpysub,    dt_dword }, // 26
  { HPPA_cmpb,       dt_byte  }, // 27
  { HPPA_addb,       dt_byte  }, // 28
  { HPPA_addib,      dt_byte  }, // 29
  { HPPA_addb,       dt_byte  }, // 2A
  { HPPA_addib,      dt_byte  }, // 2B
  { HPPA_addi,       dt_dword }, // 2C
  { HPPA_addi,       dt_dword }, // 2D
  { 0,               dt_dword }, // 2E
  { HPPA_cmpb,       dt_byte  }, // 2F
  { HPPA_bb,         dt_dword }, // 30
  { HPPA_bb,         dt_dword }, // 31
  { HPPA_movb,       dt_byte  }, // 32
  { HPPA_movib,      dt_byte  }, // 33
  { 0,               dt_dword }, // 34
  { 0,               dt_dword }, // 35
  { HPPA_extrd,      dt_qword }, // 36
  { HPPA_null,       dt_dword }, // 37
  { HPPA_be,         dt_dword }, // 38
  { HPPA_be,         dt_dword }, // 39
  { 0,               dt_dword }, // 3A
  { HPPA_cmpib,      dt_byte  }, // 3B
  { 0,               dt_dword }, // 3C
  { 0,               dt_dword }, // 3D
  { 0,               dt_dword }, // 3E
  { HPPA_null,       dt_dword }, // 3F
};

struct ldst_t
{
  ushort itype;
  char dtype;
};

static const ldst_t C6[] =
{
  { HPPA_ldb,   dt_byte  }, // 0
  { HPPA_ldh,   dt_word  }, // 1
  { HPPA_ldw,   dt_dword }, // 2
  { HPPA_ldd,   dt_qword }, // 3
  { HPPA_ldda,  dt_qword }, // 4
  { HPPA_ldcd,  dt_qword }, // 5
  { HPPA_ldwa,  dt_dword }, // 6
  { HPPA_ldcw,  dt_dword }, // 7
  { HPPA_stb,   dt_byte  }, // 8
  { HPPA_sth,   dt_word  }, // 9
  { HPPA_stw,   dt_dword }, // A
  { HPPA_std,   dt_qword }, // B
  { HPPA_stby,  dt_byte  }, // C
  { HPPA_stdby, dt_qword }, // D
  { HPPA_stwa,  dt_dword }, // E
  { HPPA_stda,  dt_qword }, // F
};

//--------------------------------------------------------------------------
static void opr(op_t &x, uint32 rgnum)
{
  x.reg = (uint16)rgnum;
/*  if ( rgnum == 0 )
  {
    x.type = o_imm;
    x.value = 0;
    x.dtype = dt_dword;
  }
  else*/
  {
    x.type = o_reg;
    x.dtype = dt_qword;
  }
}

//--------------------------------------------------------------------------
inline void opi(op_t &x, uval_t v)
{
  x.type = o_imm;
  x.value = v;
  x.dtype = dt_dword;
}

//--------------------------------------------------------------------------
inline void opb(op_t &x, int r)
{
  x.type   = o_based;
  x.phrase = (uint16)r;
  x.dtype  = dt_dword;
}

//--------------------------------------------------------------------------
inline void opbs(insn_t &insn, op_t &x, int sr, int r)
{
  opb(x, r);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    insn.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
inline void opx(op_t &x, int b, int xx, char dtype)
{
  x.type   = o_phrase;
  x.phrase = uint16(b);
  x.secreg = uchar(xx);
  x.dtype  = dtype;
}

//--------------------------------------------------------------------------
inline void opxs(insn_t &insn, op_t &x, int sr, int b, int xx, char dtype)
{
  opx(x, b, xx, dtype);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    insn.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
inline void opd(op_t &x, int b, uval_t value, char dtype)
{
  x.type   = o_displ;
  x.phrase = uint16(b);
  x.addr   = value;
  x.dtype  = dtype;
}

//--------------------------------------------------------------------------
inline void opds(insn_t &insn, op_t &x, int sr, int b, uval_t value, char dtype)
{
  opd(x, b, value, dtype);
  x.sid = uchar(SR0+sr);
  if ( sr != 0 )
    insn.auxpref |= aux_space;
}

//--------------------------------------------------------------------------
struct table_t
{
  char code;
  ushort itype; //lint !e958 padding is required to align members
};

static const table_t C5[] =
{
  { 0x18,  HPPA_add      },
  { 0x28,  HPPA_add      },
  { 0x38,  HPPA_add      },
  { 0x1C,  HPPA_add      },
  { 0x3C,  HPPA_add      },
  { 0x19,  HPPA_shladd   },
  { 0x29,  HPPA_shladd   },
  { 0x39,  HPPA_shladd   },
  { 0x1A,  HPPA_shladd   },
  { 0x2A,  HPPA_shladd   },
  { 0x3A,  HPPA_shladd   },
  { 0x1B,  HPPA_shladd   },
  { 0x2B,  HPPA_shladd   },
  { 0x3B,  HPPA_shladd   },
  { 0x10,  HPPA_sub      },
  { 0x30,  HPPA_sub      },
  { 0x13,  HPPA_sub      },
  { 0x33,  HPPA_sub      },
  { 0x14,  HPPA_sub      },
  { 0x34,  HPPA_sub      },
  { 0x11,  HPPA_ds       },
  { 0x00,  HPPA_andcm    },
  { 0x08,  HPPA_and      },
  { 0x09,  HPPA_or       },
  { 0x0A,  HPPA_xor      },
  { 0x0E,  HPPA_uxor     },
  { 0x22,  HPPA_cmpclr   },
  { 0x26,  HPPA_uaddcm   },
  { 0x27,  HPPA_uaddcm   },
  { 0x2E,  HPPA_dcor     },
  { 0x2F,  HPPA_dcor     },
  { 0x0F,  HPPA_hadd     },
  { 0x0D,  HPPA_hadd     },
  { 0x0C,  HPPA_hadd     },
  { 0x07,  HPPA_hsub     },
  { 0x05,  HPPA_hsub     },
  { 0x04,  HPPA_hsub     },
  { 0x0B,  HPPA_havg     },
  { 0x1D,  HPPA_hshladd  },
  { 0x1E,  HPPA_hshladd  },
  { 0x1F,  HPPA_hshladd  },
  { 0x15,  HPPA_hshladd  },
  { 0x16,  HPPA_hshladd  },
  { 0x17,  HPPA_hshladd  },
  { 0,     HPPA_null     },
};

static ushort find_itype(const table_t *table, int code)
{
  while ( table->itype )
  {
    if ( table->code == code )
      return table->itype;
    table++;
  }
  return HPPA_null;
}

//--------------------------------------------------------------------------
inline sval_t ls5(int i5)     { return (( i5>>1)&15)    | (( i5 & 1) ?    ~sval_t(15) : 0);  }
inline sval_t ls11(int i11)   { return ((i11>>1)&0x3FF) | ((i11 & 1) ? ~sval_t(0x1FF) : 0);  }
inline sval_t s12(int imm12)  { return (imm12 & 0x0800) ? (imm12 | ~sval_t(0x0FFF)) : imm12; }
inline sval_t s16(int imm16)  { return (imm16 & 0x8000) ? (imm16 | ~sval_t(0xFFFF)) : imm16; }
inline sval_t s17(uint32 i17) { return (i17  & 0x10000) ? (i17  | ~sval_t(0x1FFFF)) : i17;   }
inline sval_t s22(uint32 i22) { return (i22 & 0x200000) ? (i22 | ~sval_t(0x3FFFFF)) : i22;   }
inline int mfr(int r, bool d) { return (d ? F0 : F16L) + r; }
inline int as3(int s)
{
  return ((s>>1) & 3) | ((s&1) << 2);
}
inline int fr(int r, int y)
{
  return F0 + r + ((y&1)<<5);
}

//--------------------------------------------------------------------------
static void handle_float_0C(insn_t &insn, uint32 code)
{
  int uid = (code>> 6) & 7;
  if ( uid == 2 )               // performance coprocessor
  {
    int sub = (code>>9) & 0x1F;
    switch ( sub )
    {
      case 1:
        insn.itype = HPPA_pmdis;
        break;
      case 3:
        insn.itype = (code & BIT26) ? HPPA_null : HPPA_pmenb;
        break;
      default:
        insn.itype = HPPA_null;
        break;
    }
    return;
  }
  if ( uid != 0 )
    return;            // other coprocessors

  // floating-point coprocessor
  int cls = (code>>9) & 3;
  switch ( cls )
  {
    case 0:
      {
        static const ushort itypes[] =
        {
          HPPA_fid,   HPPA_null, HPPA_fcpy, HPPA_fabs,
          HPPA_fsqrt, HPPA_frnd, HPPA_fneg, HPPA_fnegabs
        };
        insn.itype = itypes[(code>>13)&7];
        if ( insn.itype != HPPA_fid )
        {
          opr(insn.Op1, F0 + r06(code));
          opr(insn.Op2, F0 + r27(code));
        }
      }
      break;
    case 1:
      insn.itype = HPPA_fcnv;
      opr(insn.Op1, F0 + r06(code));
      opr(insn.Op2, F0 + r27(code));
      break;
    case 2:
      if ( code & BIT26 )
      {
        insn.itype = HPPA_ftest;
        int y = (code>>13) & 7;
        if ( y != 1 )
          opr(insn.Op1, CA0+(y^1)-1);
      }
      else
      {
        insn.itype = HPPA_fcmp;
        opr(insn.Op1, F0 + r06(code));
        opr(insn.Op2, F0 + r11(code));
        int y = (code>>13) & 7;
        if ( y )
          opr(insn.Op3, CA0+y-1);
      }
      break;
    case 3:
      {
        static const nameNum itypes[] =
        {
          HPPA_fadd, HPPA_fsub, HPPA_fmpy, HPPA_fdiv,
          HPPA_frem, HPPA_null, HPPA_null, HPPA_null
        };
        int sub = (code>>13) & 7;
        insn.itype = (code & BIT26) ? HPPA_null : itypes[sub];
        opr(insn.Op1, F0 + r06(code));
        opr(insn.Op2, F0 + r11(code));
        opr(insn.Op3, F0 + r27(code));
      }
      break;
  }
}

//--------------------------------------------------------------------------
static void handle_float_0E(insn_t &insn, uint32 code)
{
  int cls = (code>>9) & 3;
  switch ( cls )
  {
    case 0:
      {
        static const ushort itypes[] =
        {
          HPPA_null,  HPPA_null, HPPA_fcpy, HPPA_fabs,
          HPPA_fsqrt, HPPA_frnd, HPPA_fneg, HPPA_fnegabs
        };
        insn.itype = itypes[(code>>13)&7];
        opr(insn.Op1, fr(r06(code), (code>>7)&1));
        opr(insn.Op2, fr(r27(code), (code>>6)&1));
      }
      break;
    case 1:
      insn.itype = HPPA_fcnv;
      opr(insn.Op1, fr(r06(code), (code>>7)&1));
      opr(insn.Op2, fr(r27(code), (code>>6)&1));
      break;
    case 2:
      {
        insn.itype = HPPA_fcmp;
        opr(insn.Op1, fr(r06(code), (code>>7)&1));
        opr(insn.Op2, fr(r11(code), (code>>12)&1));
        int y = (code>>13) & 7;
        if ( y )
          opr(insn.Op3, CA0+y-1);
      }
      break;
    case 3:
      {
        static const ushort itypes[] =
        {
          HPPA_fadd, HPPA_fsub, HPPA_fmpy, HPPA_fdiv,
          HPPA_null, HPPA_null, HPPA_null, HPPA_null
        };
        int sub = (code>>13) & 7;
        insn.itype = itypes[sub];
        if ( code & BIT23 )
        {
          insn.itype = (sub == 2) ? HPPA_xmpyu : HPPA_null;
        }
        opr(insn.Op1, fr(r06(code), (code>>7)&1));
        opr(insn.Op2, fr(r11(code), (code>>12)&1));
        opr(insn.Op3, fr(r27(code), (code>>6)&1));
      }
      break;
  }
}

//--------------------------------------------------------------------------
inline void opn(op_t &x, sval_t disp, ea_t ip)
{
  disp <<= 2;
  x.type = o_near;
  x.addr = ip + 8 + disp;
}

//--------------------------------------------------------------------------
int hppa_t::ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;
  if ( insn.ip & 3 )
    return 0;           // alignment error

  uint32 code = insn.get_next_dword();

  int op = opcode(code);
  insn.itype = C1[op].itype;
  char dtype = C1[op].dtype;
  switch ( op )
  {
    case 0x00:
      switch ( (code>>5) & 0xFF )
      {
        case 0x00:
          insn.itype = HPPA_break;
          opi(insn.Op1, r27(code));
          opi(insn.Op2, (code>>13) & 0x1FFF);
          break;
        case 0x20:
          insn.itype = (code & BIT11) ? HPPA_syncdma : HPPA_sync;
          break;
        case 0x60:
        case 0x65:
          insn.itype = HPPA_rfi;
          break;
        case 0x6B:
          insn.itype = HPPA_ssm;
RSM_SSM:
          opi(insn.Op1, (code>>16)&0x3FF);
          opr(insn.Op2, r27(code));
          break;
        case 0x73:
          insn.itype = HPPA_rsm;
          goto RSM_SSM;
        case 0xC3:
          insn.itype = HPPA_mtsm;
          opr(insn.Op1, r11(code));
          break;
        case 0x85:
          insn.itype = HPPA_ldsid;
          opbs(insn, insn.Op1, (code>>14)&3, r06(code));
          opr(insn.Op2, r27(code));
          break;
        case 0xC1:
          insn.itype = HPPA_mtsp;
          opr(insn.Op1, r11(code));
          opr(insn.Op2, SR0+((code>>13)&7));
          break;
        case 0x25:
          insn.itype = HPPA_mfsp;
          opr(insn.Op1, SR0+((code>>13)&7));
          opr(insn.Op2, r27(code));
          break;
        case 0xA5:
          insn.itype = HPPA_mfia;
          opr(insn.Op1, r27(code));
          break;
        case 0xC2:
          insn.itype = HPPA_mtctl;
          opr(insn.Op1, r11(code));
          opr(insn.Op2, CR0+r06(code));
          break;
        case 0xC6:
          if ( r06(code) != 0xB )
            return 0;
          insn.itype = HPPA_mtsarcm;
          opr(insn.Op1, r11(code));
          break;
        case 0x45:
          insn.itype = HPPA_mfctl;
          opr(insn.Op1, CR0+r06(code));
          opr(insn.Op2, r27(code));
          break;
        default:
          return 0;
      }
      break;

    case 0x01:
      if ( code & BIT19 )
      {
        switch ( (code>>6) & 0xFF )
        {
          case 0x60:
            insn.itype = HPPA_idtlbt;
            opr(insn.Op1, CR0+r06(code));
            opr(insn.Op2, r27(code));
            break;
          case 0x48:
          case 0x58:
            insn.itype = HPPA_pdtlb;
            goto PDT;
          case 0x49:
            insn.itype = HPPA_pdtlbe;
PDT:
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4A:
            insn.itype = HPPA_fdc;
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0xCA:
            insn.itype = HPPA_fdc;
            opds(insn, insn.Op1, (code>>14)&3, r06(code), ls5(r11(code)), dt_dword);
            if ( code & BIT26 )
              return 0;
            break;
          case 0x4B:
            insn.itype = HPPA_fdce;
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4E:
            insn.itype = HPPA_pdc;
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x4F:
            insn.itype = HPPA_fic;
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            break;
          case 0x46:
          case 0x47:
            insn.itype = HPPA_probe;
            opbs(insn, insn.Op1, (code>>14)&3, r06(code));
            opr(insn.Op2, r11(code));
            opr(insn.Op3, r27(code));
            break;
          case 0xC6:
          case 0xC7:
            insn.itype = HPPA_probei;
            opbs(insn, insn.Op1, (code>>14)&3, r06(code));
            opi(insn.Op2, r11(code));
            opr(insn.Op3, r27(code));
            break;
          case 0x4D:
            insn.itype = HPPA_lpa;
MAKE_LPA:
            opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dt_dword);
            opr(insn.Op2, r27(code));
            break;
          case 0x4C:
            insn.itype = HPPA_lci;
            if ( code & BIT26 )
              return 0;
            goto MAKE_LPA;
          default:
            return 0;
        }
      }
      else
      {
        switch ( (code>>6) & 0x7F )
        {
          case 0x20:
            insn.itype = HPPA_iitlbt;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            break;
          case 0x18:
          case 0x08:
            insn.itype = HPPA_pitlb;
PIT:
            opxs(insn, insn.Op1, as3((code>>13)&7), r06(code), r11(code), dt_dword);
            insn.auxpref |= aux_space;
            break;
          case 0x09:
            insn.itype = HPPA_pitlbe;
            goto PIT;
          case 0x0A:
            insn.itype = HPPA_fic;
            goto PIT;
          case 0x0B:
            insn.itype = HPPA_fice;
            goto PIT;
          default:
            return 0;
        }
      }
      break;

    case 0x02:
      insn.auxpref = (code>>13) & aux_cndc; // condition
      insn.itype = find_itype(C5, (code>>6)&0x3F);
      switch ( insn.itype )
      {
        default:
        // case HPPA_add:
        // case HPPA_sub:
        // case HPPA_ds:
        // case HPPA_and:
        // case HPPA_andcm:
        // case HPPA_or:
        // case HPPA_xor:
        // case HPPA_uxor:
        // case HPPA_cmpclr:
        // case HPPA_uaddcm:
        // case HPPA_hadd:
        // case HPPA_hsub:
        // case HPPA_havg:
          opr(insn.Op1, r11(code));
          opr(insn.Op2, r06(code));
          opr(insn.Op3, r27(code));
          break;
        case HPPA_dcor:
          opr(insn.Op1, r06(code));
          opr(insn.Op2, r27(code));
          break;
        case HPPA_shladd:
          opr(insn.Op1, r11(code));
          opi(insn.Op2, (code>>6)&3);
          if ( ((code>>6) & 3) == 0 )
            return 0;
          opr(insn.Op3, r06(code));
          opr(insn.Op4, r27(code));
          break;
        case HPPA_hshladd:
          opr(insn.Op1, r11(code));
          opr(insn.Op2, r06(code));
          if ( ((code>>6) & 3) == 0 )
            return 0;
          if ( insn.auxpref )
            return 0;  // condition should be never
          opi(insn.Op3, (code>>6)&3);
          opr(insn.Op4, r27(code));
          break;
      }
      break;

    case 0x03:
      {
        int idx = (code>>6) & 0xF;
        if ( (code & BIT19) == 0 && idx > 7 )
          return 0;
        insn.itype = C6[idx].itype;
        dtype = C6[idx].dtype;
        if ( code & BIT19 )             // short
        {
          if ( idx > 7 )        // store
          {
            opr(insn.Op1, r11(code));
            opds(insn, insn.Op2, (code>>14)&3, r06(code), ls5(r27(code)), dtype);
          }
          else                  // load
          {
            opds(insn, insn.Op1, (code>>14)&3, r06(code), ls5(r11(code)), dtype);
            opr(insn.Op2, r27(code));
          }
        }
        else                            // index
        {
          opxs(insn, insn.Op1, (code>>14)&3, r06(code), r11(code), dtype);
          opr(insn.Op2, r27(code));
        }
        if ( (idx & 7) == 6 )
          insn.auxpref &= ~aux_space; // ldwa, stwa
      }
      break;

    case 0x04:
      switch ( (code>>9) & 3 )
      {
        case 0:
          insn.itype = HPPA_spop0;
          break;
        case 1:
          insn.itype = HPPA_spop1;
          opr(insn.Op1, r27(code));
          break;
        case 2:
          insn.itype = HPPA_spop2;
          opr(insn.Op1, r06(code));
          break;
        case 3:
          insn.itype = HPPA_spop3;
          opr(insn.Op1, r11(code));
          opr(insn.Op2, r06(code));
          break;
      }
      break;

    case 0x05:  // diag
      opi(insn.Op1, code & 0x3FFFFFF);
      break;

    case 0x06:  // fmpyadd
    case 0x26:  // fmpysub
      {
        bool d = !((code>>5) & 1);
        opr(insn.Op1, mfr(r06(code),d));
        opr(insn.Op2, mfr(r11(code),d));
        opr(insn.Op3, mfr(r27(code),d));
        opr(insn.Op4, mfr((code>>6)&0x1F,d));
        opr(insn.Op5, mfr((code>>11)&0x1F,d));
      }
      break;

    case 0x07:
      return 0;

    case 0x08:  // ldil
      opi(insn.Op1, as21(code & 0x1FFFFF));
      opr(insn.Op2, r06(code));
      break;

    case 0x09: // cldw, cstw, fstd, fstw
    case 0x0B: // cldd, cstd, fldd, fldw
      {
        op_t *x;
        int uid = (code>> 6) & 7;
        if ( code & BIT22 )
        {
          insn.itype = HPPA_cstd;
          opr(insn.Op1, r27(code));
          x = &insn.Op2;
          if ( uid < 2 )
          {
            insn.itype = HPPA_fstd;
            insn.Op1.reg += F0 + ((code>>1)&0x20);
          }
        }
        else
        {
          insn.itype = HPPA_cldd;
          opr(insn.Op2, r27(code));
          x = &insn.Op1;
          if ( uid < 2 )
          {
            insn.itype = HPPA_fldd;
            insn.Op2.reg += F0 + ((code>>1)&0x20);
          }
        }
        dtype = dt_qword;
        if ( op == 0x09 )
        {
          insn.itype++; // cldw, cstw
          dtype = dt_dword;
        }
        if ( code & BIT19 )
          opds(insn, *x, (code>>14)&3, r06(code), ls5(r11(code)), dtype);
        else
          opxs(insn, *x, (code>>14)&3, r06(code), r11(code), dtype);
      }
      break;

    case 0x0A:  // addil
      opi(insn.Op1, as21(code & 0x1FFFFF));
      opr(insn.Op2, r06(code));
      opr(insn.Op3, R1);
      break;

    case 0x0C:  // copr
      handle_float_0C(insn, code);
      break;

    case 0x0D:  // ldo
      if ( getseg(insn.ea)->is_64bit() )
        dtype = dt_qword;
      opd(insn.Op1, r06(code), s16(get_ldo(code)), dtype);
      opr(insn.Op2, r11(code));
      break;

    case 0x0E:
      handle_float_0E(insn, code);
      break;

    case 0x0F:
      return 0;

    case 0x10:  // ldb
    case 0x11:  // ldh
    case 0x12:  // ldw
    case 0x13:  // ldw (mod)
      {
        int s = (code>>14) & 3;
        opds(insn, insn.Op1, s, r06(code), s16(assemble_16(s,code & 0x3FFF)), dtype);
        opr(insn.Op2, r11(code));
      }
      break;

    case 0x14:
      {
        int s = (code>>14) & 3;
        insn.itype = (code & BIT30) ? HPPA_fldd : HPPA_ldd;
        int im10a = ((code>>3) & 0x7FE) | (code & 1);
        opds(insn, insn.Op1, s, r06(code), s16(assemble_16(s,im10a)), dtype);
        opr(insn.Op2, r11(code));
        if ( code & BIT30 )
          insn.Op2.reg += F0;
      }
      break;

    case 0x1C:
      {
        int s = (code>>14) & 3;
        insn.itype = (code & BIT30) ? HPPA_fstd : HPPA_std;
        int im10a = ((code>>3) & 0x7FE) | (code & 1);
        opr(insn.Op1, r11(code));
        if ( code & BIT30 )
          insn.Op1.reg += F0;
        opds(insn, insn.Op2, s, r06(code), s16(assemble_16(s,im10a)), dtype);
      }
      break;

    case 0x16:
    case 0x17:
      {
        int s = (code>>14) & 3;
        insn.itype = op & 1 && (code & BIT29) ? HPPA_ldw : HPPA_fldw;
        int im11a = ((code>>3) & 0xFFE) | (code & 1);
        opds(insn, insn.Op1, s, r06(code), s16(assemble_16(s,im11a)), dtype);
        opr(insn.Op2, r11(code));
        if ( code & BIT29 )
          insn.Op2.reg += F0 + ((code<<4) & 0x20);
      }
      break;

    case 0x1E:
    case 0x1F:
      {
        int s = (code>>14) & 3;
        insn.itype = op & 1 && (code & BIT29) ? HPPA_stw : HPPA_fstw;
        int im11a = ((code>>3) & 0xFFE) | (code & 1);
        opr(insn.Op1, r11(code));
        if ( code & BIT29 )
          insn.Op1.reg += F0 + ((code<<4) & 0x20);
        opds(insn, insn.Op2, s, r06(code), s16(assemble_16(s,im11a)), dtype);
      }
      break;

    case 0x18:  // stb
    case 0x19:  // sth
    case 0x1A:  // stw
    case 0x1B:  // stw (mod)
      {
        int s = (code>>14) & 3;
        opr(insn.Op1, r11(code));
        opds(insn, insn.Op2, s, r06(code), s16(assemble_16(s,code & 0x3FFF)), dtype);
      }
      break;

    case 0x15:
    case 0x1D:
      return 0;

    case 0x20:  // cmpb
    case 0x22:  // cmpb
    case 0x27:  // cmpb
    case 0x2F:  // cmpb
    case 0x28:  // addb
    case 0x2A:  // addb
    case 0x32:  // movb
      insn.auxpref = (code>>13) & aux_cndc; // condition
      opr(insn.Op1, r11(code));
      opr(insn.Op2, r06(code));
      opn(insn.Op3, s12(get11(code)|((code&1)<<11)), insn.ip);
      break;

    case 0x21:  // cmpib
    case 0x23:  // cmpib
    case 0x3B:  // cmpib
    case 0x29:  // addib
    case 0x2B:  // addib
    case 0x33:  // movib
      insn.auxpref = (code>>13) & aux_cndc; // condition
      opi(insn.Op1, ls5(r11(code)));
      opr(insn.Op2, r06(code));
      opn(insn.Op3, s12(get11(code)|((code&1)<<11)), insn.ip);
      break;

    case 0x24:  // cmpiclr
    case 0x25:  // subi
    case 0x2C:  // addi
    case 0x2D:  // addi
      insn.auxpref = (code>>13) & aux_cndc; // condition
      opi(insn.Op1, ls11(code & 0x7FF));
      opr(insn.Op2, r06(code));
      opr(insn.Op3, r11(code));
      break;

    case 0x2E:
      {
        insn.itype = (code & BIT26) ? HPPA_fmpynfadd : HPPA_fmpyfadd;
        bool d = (code>>11) & 1;
        opr(insn.Op1, mfr(r06(code),d));
        opr(insn.Op2, mfr(r11(code),d));
        int ra = ((code>>10) & 0x38) | ((code>>8) & 0x7);
        opr(insn.Op3, F0+ra);
        opr(insn.Op4, mfr(r27(code),d));
      }
      break;

    case 0x30:  // bb
    case 0x31:
      opr(insn.Op1, r11(code));
      if ( op & 1 )
      {
        int pos = r06(code) | ((code>>8) & 0x20);
        opi(insn.Op2, pos);
      }
      else
      {
        opr(insn.Op2, CR11);
      }
      opn(insn.Op3, s12(get11(code)|((code&1)<<11)), insn.ip);
      break;

    case 0x34:
      insn.auxpref = (code>>13) & aux_cndc; // condition
      switch ( (code>>11) & 3 )     // bits 19, 20
      {
        case 0:
          if ( (code & BIT21) == 0 )            // format 11
          {
            insn.itype = (code & BIT22) ? HPPA_shrpd : HPPA_shrpw;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            opr(insn.Op3, CR11);
            opr(insn.Op4, r27(code));
            break;
          }
          // no break
        case 1:                                 // format 14
          {
            insn.itype = (code & BIT21) ? HPPA_shrpd : HPPA_shrpw;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            int sa = (insn.itype == HPPA_shrpd ? 63 : 31) - (r22(code)|((code>>10)&1));
            opi(insn.Op3, sa);
            opr(insn.Op4, r27(code));
          }
          break;
        case 2:                                 // format 12
          {
            insn.itype = (code & BIT22) ? HPPA_extrd : HPPA_extrw;
            opr(insn.Op1, r06(code));
            opr(insn.Op2, CR11);
            int cl = (code>>3) & 0x20;
            if ( (code & BIT22) == 0 && cl )
              return 0;
            opi(insn.Op3, (32-r27(code))|cl);
            opr(insn.Op4, r11(code));
          }
          break;
        case 3:                                 // format 15
          insn.itype = HPPA_extrw;
          opr(insn.Op1, r06(code));
          opi(insn.Op2, r22(code));
          opi(insn.Op3, 32-r27(code));
          opr(insn.Op4, r11(code));
          break;
      }
      break;

    case 0x35:
      insn.auxpref = (code>>13) & aux_cndc; // condition
      if ( code & BIT20 )                       // format 16
      {
        if ( code & BIT19 )
        {
          insn.itype = HPPA_depwi;
          opi(insn.Op1, ls5(r11(code)));
        }
        else
        {
          insn.itype = HPPA_depw;
          opr(insn.Op1, r11(code));
        }
        opi(insn.Op2, 31-r22(code));
        opi(insn.Op3, 32-r27(code));
        opr(insn.Op4, r06(code));
      }
      else                                      // format 13
      {
        if ( code & BIT19 )
        {
          insn.itype = (code & BIT22) ? HPPA_depdi : HPPA_depwi;
          opi(insn.Op1, ls5(r11(code)));
          opr(insn.Op2, CR11);
        }
        else
        {
          insn.itype = (code & BIT22) ? HPPA_depd : HPPA_depw;
          opr(insn.Op1, r11(code));
          opr(insn.Op2, CR11);
        }
        int cl = (code>>3) & 0x20;
        if ( (code & BIT22) == 0 && cl )
          return 0;
        opi(insn.Op3, (32-r27(code))|cl);
        opr(insn.Op4, r06(code));
      }
      break;

    case 0x36:  // extrd
      {
        insn.auxpref = (code>>13) & aux_cndc; // condition
        opr(insn.Op1, r06(code));
        opi(insn.Op2, ((code>>6)&0x20)|r22(code));
        int cl = (code>>7) & 0x20;
        opi(insn.Op3, (32-r27(code))|cl);
        opr(insn.Op4, r11(code));
      }
      break;

    case 0x37:
      return 0;

    case 0x38:  // be
    case 0x39:  // be
      {
        int32 w = get17(code);
        opds(insn, insn.Op1, as3((code>>13)&7), r06(code), s17(w)<<2, dt_code);
        insn.auxpref |= aux_space;
        if ( op & 1 )
        {
          opr(insn.Op2, SR0);
          opr(insn.Op3, R31);
        }
      }
      break;

    case 0x3A:
      {
        int sub = (code>>13) & 7;
        switch ( sub )
        {
          case 0x2:
            if ( code & BIT19 )
              return 0;
            insn.itype = HPPA_blr;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            break;
          case 0x6:
            insn.itype = (code & BIT19) ? HPPA_bve : HPPA_bv;
            if ( insn.itype == HPPA_bv )
              opx(insn.Op1, r06(code), r11(code), dt_code);
            else
              opb(insn.Op1, r06(code));
            break;
          case 0x7:
            if ( !(code & BIT19) )
              return 0;
            insn.itype = HPPA_bve;
            opb(insn.Op1, r06(code));
            opr(insn.Op1, R2);
            break;
          case 0x0:
          case 0x1:
            {
              insn.itype = HPPA_b;
              int32 w = get17(code);
              opn(insn.Op1, s17(w), insn.ip);
              opr(insn.Op2, r06(code));
            }
            break;
          case 0x4:
          case 0x5:
            {
              insn.itype = HPPA_b;
              int32 w = ((code&1) << 21)
                     | (r06(code) << 16)
                     | (r11(code) << 11)
                     | get11(code);
              opn(insn.Op1, s22(w), insn.ip);
              opr(insn.Op2, R2);
            }
            break;
        }
      }
      break;

    case 0x3C:
      insn.itype = HPPA_depd;
      opr(insn.Op1, r11(code));
DEPD:
      opi(insn.Op2, (32-r22(code))|((code>>7)&0x20));
      opi(insn.Op3, r27(code));
      opr(insn.Op4, r06(code));
      insn.auxpref = (code>>13) & aux_cndc; // condition
      break;

    case 0x3D:
      insn.itype = HPPA_depdi;
      opi(insn.Op1, ls5(r11(code)));
      goto DEPD;

    case 0x3E:
      if ( code & BIT16 )
      {
        switch ( (code>>10) & 3 )
        {
          case 0:
            insn.itype = HPPA_mixw;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            opr(insn.Op3, r27(code));
            break;
          case 1:
            insn.itype = HPPA_mixh;
            opr(insn.Op1, r11(code));
            opr(insn.Op2, r06(code));
            opr(insn.Op3, r27(code));
            break;
          case 2:
            if ( ((code>>13)&3) == 0 )
            {
              insn.itype = HPPA_hshl;
              opr(insn.Op1, r11(code));
              opi(insn.Op2, (code>>6) & 0xF);
              opr(insn.Op3, r27(code));
              break;
            }
            // no break;
          case 3:
            insn.itype = HPPA_hshr;
            opr(insn.Op1, r06(code));
            opi(insn.Op2, (code>>6) & 0xF);
            opr(insn.Op3, r27(code));
            break;
          default:
            return 0;
        }
      }
      else
      {
        insn.itype = HPPA_permh;
        if ( r06(code) != r11(code) )
          return 0;
        opr(insn.Op1, r06(code));
        opr(insn.Op2, r27(code));
      }
      break;

    case 0x3F:
      return 0;

    default:
      interr(insn, "ana");
  }
  if ( insn.itype == 0 )
    return 0;

  if ( dosimple() )
    simplify(insn, code);

  char buf[80];
  if ( !build_insn_completer(insn, code, buf, sizeof(buf)) )
    return 0;

  return insn.size;
}

//--------------------------------------------------------------------------
void interr(const insn_t &insn, const char *module)
{
  const char *name = nullptr;
  if ( insn.itype < HPPA_last )
    name = Instructions[insn.itype].name;
  warning("%a(%s): internal error in %s", insn.ea, name, module);
}

