/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//----------------------------------------------------------------------
void i860_t::op_s1ni(op_t &x)
{
  x.reg = op_s1();
  x.type = o_reg;
}

//----------------------------------------------------------------------
void i860_t::op_s2(op_t &x)
{
  x.reg = op_s2();
  x.type = o_reg;
}

//----------------------------------------------------------------------
void i860_t::op_fs1(op_t &x)
{
  x.reg = op_s1() + R_f0;
  x.type = o_reg;
}

//----------------------------------------------------------------------
void i860_t::op_fs2(op_t &x)
{
  x.reg = op_s2() + R_f0;
  x.type = o_reg;
}

//----------------------------------------------------------------------
void i860_t::op_s1s(op_t &x)
{
  if ( code & bit26 )           // immediate src1
  {
    x.type  = o_imm;
    x.value = short(code);
  }
  else
  {
    op_s1ni(x);
  }
}

//----------------------------------------------------------------------
void i860_t::op_s1u(op_t &x)
{
  if ( code & bit26 )           // immediate src1
  {
    x.type  = o_imm;
    x.value = ushort(code);
  }
  else
  {
    op_s1ni(x);
  }
}

//----------------------------------------------------------------------
void i860_t::op_s1s2(op_t &x)
{
  x.reg = op_s2();
  if ( code & bit26 )           // immediate src1
  {
    x.type = o_displ;
    x.addr = trunc_uval(short(code));
    if ( code & bit28 )
      x.addr &= ~1;
    if ( x.reg == 0 )
      x.type = o_mem;
  }
  else
  {
    x.type = o_phrase;
    x.addr = op_s1();
  }
}

//----------------------------------------------------------------------
void i860_t::op_dest(op_t &x)
{
  x.reg = op_ds();
  x.type  = o_reg;
}

//----------------------------------------------------------------------
void i860_t::op_fdest(op_t &x)
{
  x.reg = op_ds() + R_f0;
  x.type  = o_reg;
}

//----------------------------------------------------------------------
char i860_t::dsize_28_0(void) const
{
  if ( code & bit28 )
    return (code & bit0) ? dt_dword : dt_word;
  return dt_byte;
}

//----------------------------------------------------------------------
char i860_t::dsize_1_2(void) const
{
  if ( code & bit1 )
    return dt_dword;
  return (code & bit2) ? dt_byte16 : dt_qword;
}

//----------------------------------------------------------------------
char i860_t::dsize_10_9(void) const
{
  if ( code & bit10 )
    return (code & bit9) ? dt_dword : dt_dword;
  return (code & bit9) ? dt_word : dt_byte;
}

//----------------------------------------------------------------------
void i860_t::op_stoff(op_t &x)
{
  x.type = o_displ;
  x.reg  = op_s2();
  x.addr = short((code & 0x7FF) + (op_ds() << 11));    // extend sign
}

//----------------------------------------------------------------------
//lint -e{1764} Reference parameter '' could be declared const ref
void i860_t::op_bteoff(insn_t &insn, op_t &x)
{
  x.type = o_near;
  x.addr = insn.ea + insn.size
         + (sval_t((code & 0x7FF)+(op_ds()<<11)) << 2); // extend sign
  x.dtype = dt_code;
}

//----------------------------------------------------------------------
//lint -e{1764} Reference parameter '' could be declared const ref
void i860_t::op_lbroff(insn_t &insn, op_t &x) const
{
  x.type = o_near;
  sval_t lbr = code & 0x3FFFFFF;
  if ( code & bit25 )
    lbr |= ~uval_t(0x3FFFFFF);  // extend sign
  x.addr = insn.ea + insn.size + (lbr << 2);
  x.dtype = dt_code;
}

//----------------------------------------------------------------------
void i860_t::op_ainc(op_t &x)
{
  op_s1s2(x);
  if ( code & bit0 )
    x.reg = - x.reg;    //lint !e2501 negation of value of unsigned type
  if ( x.type == o_displ || x.type == o_mem )
  {
    x.addr &= ~3;
    if ( (code & bit1) == 0 )
      x.addr &= ~7;
  }
  x.dtype = dsize_1_2();
}

//----------------------------------------------------------------------
int i860_t::op_ctl(op_t &x)
{
  op_s2(x);
  if ( x.reg > (is860XP() ? 11 : 5) )
    return 0;
  x.reg += R_fir;
  return 1;
}

//----------------------------------------------------------------------
int i860_t::i860_ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;

  if ( (insn.ea & 3) != 0 )
    return 0;            // only four byte boundaries
  code = insn.get_next_dword();

  insn.Op1.dtype = dt_dword;
  insn.Op2.dtype = dt_dword;
  insn.Op3.dtype = dt_dword;
  insn.itype = I860_null;

  switch ( code>>26 )
  {
    case 0x00:
    case 0x01:
    case 0x04:
    case 0x05:
      insn.itype = I860_ld;
      op_s1s2(insn.Op1);
      op_dest(insn.Op2);
      insn.Op1.dtype = dsize_28_0();
      insn.Op2.dtype = insn.Op1.dtype;
      break;
    case 0x03:
    case 0x07:
      insn.itype = I860_st;
      op_s1ni(insn.Op2);
      op_stoff(insn.Op1);
      insn.Op1.dtype = dsize_28_0();
      insn.Op2.dtype = insn.Op1.dtype;
      break;
    case 0x02:
      insn.itype = I860_ixfr;
      op_s1ni(insn.Op1);
      op_fdest(insn.Op2);
      break;
    case 0x08:
    case 0x09:
      insn.itype = I860_fld;
      op_ainc(insn.Op1);
      op_fdest(insn.Op2);
      insn.Op2.dtype = insn.Op1.dtype;
      break;
    case 0x0A:
    case 0x0B:
      insn.itype = I860_fst;
      op_fdest(insn.Op1);
      op_ainc(insn.Op2);
      insn.Op1.dtype = insn.Op2.dtype;
      break;
    case 0x0D:
      insn.itype = I860_flush;
      op_ainc(insn.Op1);
      break;
    case 0x0F:
      insn.itype = I860_pst_d;
      op_fdest(insn.Op1);
      op_ainc(insn.Op2);
      insn.Op1.dtype = insn.Op2.dtype;
      break;
    case 0x0C:
      if ( !op_ctl(insn.Op1) )
        break;
      op_dest(insn.Op2);
      insn.itype = I860_ld_c;
      break;
    case 0x0E:
      op_s1ni(insn.Op1);
      if ( !op_ctl(insn.Op2) )
        break;
      insn.itype = I860_st_c;
      break;
    case 0x10:
      insn.itype = I860_bri;
      op_s1ni(insn.Op1);
      break;
    case 0x11:
      insn.itype = I860_trap;
      op_s1ni(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
    case 0x12:
      FPunit(insn);
      break;
    case 0x13:
      COREunit(insn);
      break;
    case 0x14:
    case 0x16:
    case 0x15:
    case 0x17:
      insn.itype = (code & bit27) ? I860_bte : I860_btne;
      if ( code & bit26 ) // small immediate
      {
        insn.Op1.type = o_imm;
        insn.Op1.value = op_s1();
      }
      else
      {
        op_s1ni(insn.Op1);
      }
      op_s2(insn.Op2);
      op_bteoff(insn, insn.Op3);
      break;
    case 0x18:
    case 0x19:
      op_ainc(insn.Op1);
      op_fdest(insn.Op2);
      insn.Op2.dtype = insn.Op1.dtype;
      if ( !is860XP() && insn.Op2.dtype == dt_byte16 )
        break;
      insn.itype = I860_pfld;
      break;
    case 0x1A:
      insn.itype = I860_br;
      op_lbroff(insn, insn.Op1);
      break;
    case 0x1B:
      insn.itype = I860_call;
      op_lbroff(insn, insn.Op1);
      break;
    case 0x1C:
    case 0x1D:
      insn.itype = (code & bit26) ? I860_bc_t : I860_bc;
      op_lbroff(insn, insn.Op1);
      break;
    case 0x1E:
    case 0x1F:
      insn.itype = (code & bit26) ? I860_bnc_t : I860_bnc;
      op_lbroff(insn, insn.Op1);
      break;
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x24: case 0x25: case 0x26: case 0x27:
      insn.itype = (code & bit27)
                        ? (code & bit28) ? I860_subs : I860_subu
                        : (code & bit28) ? I860_adds : I860_addu;
      op_s1s(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B:
      insn.itype = (code & bit27) ? I860_shr : I860_shl;
      op_s1u(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
    case 0x2C:
      insn.itype = I860_shrd;
      op_s1ni(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
    case 0x2D:
      insn.itype = I860_bla;
      op_s1ni(insn.Op1);
      op_s2(insn.Op2);
      op_bteoff(insn, insn.Op3);
      break;
    case 0x2E:
    case 0x2F:
      insn.itype = I860_shra;
      op_s1u(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
    case 0x30: case 0x31: case 0x33:
      insn.itype = (code & bit27) ? I860_andh : I860_and;
      goto common;
    case 0x34: case 0x35: case 0x37:
      insn.itype = (code & bit27) ? I860_andnoth : I860_andnot;
      goto common;
    case 0x38: case 0x39: case 0x3B:
      insn.itype = (code & bit27) ? I860_orh : I860_or;
      goto common;
    case 0x3C: case 0x3D: case 0x3F:
      insn.itype = (code & bit27) ? I860_xorh : I860_xor;
common:
      op_s1u(insn.Op1);
      op_s2(insn.Op2);
      op_dest(insn.Op3);
      break;
  }
  if ( insn.itype == I860_null )
    return 0;
  return 4;
}

//----------------------------------------------------------------------
void i860_t::COREunit(insn_t &insn)
{
  if ( (code & 0x1E0) != 0 )
    return;
  switch ( code & 0x1F )
  {
    case 1:
      insn.itype = I860_lock;
      break;
    case 2:
      insn.itype = I860_calli;
      op_s1ni(insn.Op1);
      insn.Op1.dtype = dt_code;
      break;
    case 4:
      insn.itype = I860_introvr;
      break;
    case 7:
      insn.itype = I860_unlock;
      break;
    case 8:
      if ( !is860XP() )
        break;
      insn.itype = I860_ldio;
common:
      op_s2(insn.Op1);
      op_dest(insn.Op2);
      insn.Op1.dtype = dsize_10_9();
      insn.Op2.dtype = insn.Op1.dtype;
      break;
    case 9:
      if ( !is860XP() )
        break;
      insn.itype = I860_stio;
      op_s1ni(insn.Op1);
      op_s2(insn.Op2);
      insn.Op1.dtype = dsize_10_9();
      insn.Op2.dtype = insn.Op1.dtype;
      break;
    case 0x0A:
      if ( !is860XP() )
        break;
      insn.itype = I860_ldint;
      goto common;
    case 0x0B:
      if ( !is860XP() )
        break;
      insn.itype = I860_scyc;
      op_s2(insn.Op1);
      break;
  }
}

//----------------------------------------------------------------------
void i860_t::FPunit(insn_t &insn)
{
  switch ( code & 0x7F )
  {
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x04: case 0x05: case 0x06: case 0x07:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x0C: case 0x0D: case 0x0E: case 0x0F:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x14: case 0x15: case 0x16: case 0x17:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x1C: case 0x1D: case 0x1E:
      {
        static const int Pintrs[] =
        {
          I860_r2p1,   I860_r2pt,   I860_r2ap1, I860_r2apt,
          I860_i2p1,   I860_i2pt,   I860_i2ap1, I860_i2apt,
          I860_rat1p2, I860_m12apm, I860_ra1p2, I860_m12ttpa,
          I860_iat1p2, I860_m12tpm, I860_ia1p2, I860_m12tpa,
          I860_r2s1,   I860_r2st,   I860_r2as1, I860_r2ast,
          I860_i2s1,   I860_i2st,   I860_i2as1, I860_i2ast,
          I860_rat1s2, I860_m12asm, I860_ra1s2, I860_m12ttsa,
          I860_iat1s2, I860_m12tsm, I860_ia1s2, I860_m12tsa
        };
        static const int Mintrs[] =
        {
          I860_mr2p1,  I860_mr2pt,  I860_mr2mp1,I860_mr2mpt,
          I860_mi2p1,  I860_mi2pt,  I860_mi2mp1,I860_mi2mpt,
          I860_mrmt1p2,I860_mm12mpm,I860_mrm1p2,I860_mm12ttpm,
          I860_mimt1p2,I860_mm12tpm,I860_mim1p2,I860_null,
          I860_mr2s1,  I860_mr2st,  I860_mr2ms1,I860_mr2mst,
          I860_mi2s1,  I860_mi2st,  I860_mi2ms1,I860_mi2mst,
          I860_mrmt1s2,I860_mm12msm,I860_mrm1s2,I860_mm12ttsm,
          I860_mimt1s2,I860_mm12tsm,I860_mim1s2,I860_null
        };
        if ( isDS() )
          break;
        insn.itype = uint16(((code & Pbit) ? Pintrs : Mintrs)[ int(code) & 0xF ]);
      }
common3:
      op_fs1(insn.Op1);
      op_fs2(insn.Op2);
      op_dest(insn.Op3);
common:
      if ( code & Dbit )
        insn.auxpref |= aux_dual;
      if ( code & Sbit )
        insn.auxpref |= aux_sdbl;
      if ( code & Rbit )
        insn.auxpref |= aux_rdbl;
      break;
    case 0x20:
      if ( isDS() )
        break;
      insn.itype = (code & Pbit) ? I860_pfmul : I860_fmul;
      goto common3;
    case 0x21:
      insn.itype = I860_fmlow_dd;
      goto common3;
    case 0x22:
      if ( isDS() )
        break;
      insn.itype = I860_frcp;
common22:
      op_fs2(insn.Op1);
      op_dest(insn.Op2);
      goto common;
    case 0x23:
      if ( isDS() )
        break;
      insn.itype = I860_frsqr;
      goto common22;
    case 0x24:
      if ( (code & (Rbit|Sbit)) != (Rbit|Sbit) )
        break;
      insn.itype = I860_pfmul3_dd;
      goto common3;
    case 0x30:
      if ( isDS() )
        break;
      insn.itype = (code & Pbit) ? I860_pfadd : I860_fadd;
      goto common3;
    case 0x31:
      if ( isDS() )
        break;
      insn.itype = (code & Pbit) ? I860_pfsub : I860_fsub;
      goto common3;
    case 0x32:
      if ( !isSDDD() )
        break;
      insn.itype = (code & Pbit) ? I860_pfix : I860_fix;
      goto common21;
    case 0x33:
      insn.itype = (code & Pbit) ? I860_pfamov : I860_famov;
      goto common21;
    case 0x34:
      if ( isDS() )
        break;
      insn.itype = (code & Rbit) ? I860_pfle : I860_pfgt;
      goto common3;
    case 0x35:
      if ( isDS() )
        break;
      insn.itype = I860_pfeq;
      goto common3;
    case 0x3A:
      if ( !isSDDD() )
        break;
      insn.itype = (code & Pbit) ? I860_pftrunc : I860_ftrunc;
      goto common21;
    case 0x40:
      insn.itype = I860_fxfr;
common21:
      op_fs1(insn.Op1);
      op_dest(insn.Op2);
      goto common;
    case 0x49:
      if ( !isSSDD() )
        break;
      insn.itype = (code & Pbit) ? I860_pfiadd : I860_fiadd;
      goto common3;
    case 0x4D:
      if ( !isSSDD() )
        break;
      insn.itype = (code & Pbit) ? I860_pfisub : I860_fisub;
      goto common3;
    case 0x57: insn.itype = (code & Pbit) ? I860_pfzchkl: I860_fzchkl;goto common3;
    case 0x5F: insn.itype = (code & Pbit) ? I860_pfzchks: I860_fzchks;goto common3;
    case 0x50: insn.itype = (code & Pbit) ? I860_pfaddp : I860_faddp;    goto common3;
    case 0x51: insn.itype = (code & Pbit) ? I860_pfaddz : I860_faddz;    goto common3;
    case 0x5A:
      insn.itype = (code & Pbit) ? I860_pform : I860_form;
      goto common21;
  }
}
