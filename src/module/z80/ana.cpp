/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-96 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i5.hpp"

//----------------------------------------------------------------------
inline void GetImm(insn_t &insn, op_t &x)
{
  x.type = o_imm;
  x.value = insn.get_next_byte();
}

//------------------------------------------------------------------------
inline void op_c(op_t &x)
{
  x.type = o_phrase;
  x.phrase = R_c;
}

//------------------------------------------------------------------------
static void op_ad(insn_t &insn, op_t &x)
{
  x.type = o_near;
  x.addr = insn.get_next_word();
}

static void op_a(op_t &x);
static void op_e(insn_t &insn, op_t &x);
static void op_nn(insn_t &insn, op_t &x);
static void op_ad(insn_t &insn, op_t &x);
static void op_n(insn_t &insn, op_t &x);
static void op_mm(insn_t &insn, op_t &x);

static const uint16 W    [] = { I5_add,I5_adc,I5_sub,I5_sbb,I5_ana,I5_xra,I5_ora,I5_cmp };
static const uint16 Wi   [] = { I5_adi,I5_aci,I5_sui,I5_sbi,I5_ani,I5_xri,I5_ori,I5_cpi };
static const uint16 calls[] = { I5_cnz,I5_cz, I5_cnc,I5_cc, I5_cpo,I5_cpe,I5_cp, I5_cm  };
static const uint16 jumps[] = { I5_jnz,I5_jz, I5_jnc,I5_jc, I5_jpo,I5_jpe,I5_jp, I5_jm  };
static const uint16 rets [] = { I5_rnz,I5_rz, I5_rnc,I5_rc, I5_rpo,I5_rpe,I5_rp, I5_rm  };
static const uint16 rols [] = { I5_rlc,I5_rrc,I5_ral,I5_rar,I5_daa,I5_cma,I5_stc,I5_cmc };
static const uint16 CBrols[]= { Z80_rlc,Z80_rrc,Z80_rl,Z80_rr,Z80_sla,Z80_sra,Z80_srr,Z80_srl };
static const uint16 Zrols[] = { Z80_rlca,Z80_rrca,Z80_rla,Z80_rra,I5_daa,Z80_cpl,Z80_scf,Z80_ccf };

//----------------------------------------------------------------------
static void ConvertToFunny(insn_t &insn)
{
  switch ( insn.itype )
  {
    case I5_mov:
      insn.Op1.set_shown();
      insn.Op2.set_shown();
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_mem )
      {
        switch ( insn.Op1.reg )
        {
          case R_bc:
            insn.itype = A80_lbcd;
            insn.Op1.clr_shown();
            break;
          case R_de:
            insn.itype = A80_lded;
            insn.Op1.clr_shown();
            break;
          case R_sp:
            insn.itype = A80_lspd;
            insn.Op1.clr_shown();
            break;
          case R_ix:
            insn.itype = A80_lixd;
            insn.Op1.clr_shown();
            break;
          case R_iy:
            insn.itype = A80_liyd;
            insn.Op1.clr_shown();
            break;
        }
      }
      if ( insn.Op1.type == o_mem && insn.Op2.type == o_reg )
      {
        switch ( insn.Op2.reg )
        {
          case R_bc:
            insn.itype = A80_sbcd;
            insn.Op2.clr_shown();
            break;
          case R_de:
            insn.itype = A80_sded;
            insn.Op2.clr_shown();
            break;
          case R_sp:
            insn.itype = A80_sspd;
            insn.Op2.clr_shown();
            break;
          case R_ix:
            insn.itype = A80_sixd;
            insn.Op2.clr_shown();
            break;
          case R_iy:
            insn.itype = A80_siyd;
            insn.Op2.clr_shown();
            break;
        }
      }
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_reg )
      {
        switch ( insn.Op1.reg )
        {
          case R_sp:
            if ( insn.Op2.reg == R_ix )
            {
              insn.Op1.clr_shown();
              insn.Op2.clr_shown();
              insn.itype = A80_spix;
            }
            if ( insn.Op2.reg == R_iy )
            {
              insn.Op1.clr_shown();
              insn.Op2.clr_shown();
              insn.itype = A80_spiy;
            }
            break;
          case R_r:
            insn.itype = A80_mvra;
            insn.Op1.clr_shown();
            insn.Op2.clr_shown();
            break;
          case R_i:
            insn.itype = A80_mvia;
            insn.Op1.clr_shown();
            insn.Op2.clr_shown();
            break;
          case R_a:
            if ( insn.Op2.reg == R_r )
            {
              insn.itype = A80_mvar;
              insn.Op1.clr_shown();
              insn.Op2.clr_shown();
            }
            if ( insn.Op2.reg == R_i )
            {
              insn.itype = A80_mvai;
              insn.Op1.clr_shown();
              insn.Op2.clr_shown();
            }
            break;
        }
      }
      break;    /* mov */
    case Z80_jp:
      if ( insn.Op2.type == o_phrase && insn.Op2.phrase == R_ix )
      {
        insn.itype = A80_pcix;
        insn.Op2.clr_shown();
        break;
      }
      if ( insn.Op2.type == o_phrase && insn.Op2.phrase == R_iy )
      {
        insn.itype = A80_pciy;
        insn.Op2.clr_shown();
        break;
      }
      break;    /* jp */
    case Z80_ex:
      insn.Op1.clr_shown();
      insn.Op2.clr_shown();
      if ( insn.Op2.reg == R_ix )
        insn.itype = A80_xtix;
      if ( insn.Op2.reg == R_iy )
        insn.itype = A80_xtiy;
      break;    /* ex */
    case I5_in:
      if ( insn.Op2.type == o_phrase && insn.Op2.reg == R_c )
      {
        insn.itype = Z80_inp;
        insn.Op2.clr_shown();
      }
      break;
    case I5_out:
      if ( insn.Op1.type == o_phrase && insn.Op1.reg == R_c )
      {
        insn.itype = Z80_outp;
        insn.Op1.clr_shown();
      }
      break;
    case Z80_cpl:
      insn.itype = I5_cma;
      break;
    case Z80_scf:
      insn.itype = I5_stc;
      break;
    case Z80_ccf:
      insn.itype = I5_cmc;
      break;
    case I5_add:
      if ( insn.Op1.type == o_reg && insn.Op1.reg == R_ix )
      {
        insn.itype = A80_addix;
        insn.Op1.clr_shown();
        if ( insn.Op2.type == o_reg && insn.Op2.reg == R_ix )
          insn.Op2.reg = R_hl;
        break;
      }
      if ( insn.Op1.type == o_reg && insn.Op1.reg == R_iy )
      {
        insn.itype = A80_addiy;
        insn.Op1.clr_shown();
        if ( insn.Op2.type == o_reg && insn.Op2.reg == R_iy )
          insn.Op2.reg = R_hl;
        break;
      }
      break;
    case I5_adc:
      if ( insn.Op1.dtype == dt_word && insn.Op1.type == o_reg )
      {
        insn.itype = A80_addc;
        insn.Op1.clr_shown();
        if ( insn.Op1.reg == R_ix )
          insn.itype = A80_addcix;
        if ( insn.Op1.reg == R_iy )
          insn.itype = A80_addciy;
        if ( insn.Op2.type == o_reg && insn.Op1.reg == insn.Op2.reg )
          insn.Op2.reg = R_hl;
      }
      break;
    case Z80_sbc:
      if ( insn.Op1.dtype == dt_word && insn.Op1.type == o_reg )
      {
        insn.itype = A80_subc;
        insn.Op1.clr_shown();
        if ( insn.Op1.reg == R_ix )
          insn.itype = A80_subcix;
        if ( insn.Op1.reg == R_iy )
          insn.itype = A80_subciy;
        if ( insn.Op2.type == o_reg && insn.Op1.reg == insn.Op2.reg )
          insn.Op2.reg = R_hl;
      }
      break;
    case Z80_jr:
      insn.Op1.clr_shown();
      switch ( insn.Op1.Cond )
      {
        case oc_c:      insn.itype = A80_jrc;    break;
        case oc_nc:     insn.itype = A80_jrnc;   break;
        case oc_z:      insn.itype = A80_jrz;    break;
        case oc_nz:     insn.itype = A80_jrnz;   break;
      }
      break;
    case Z80_rrca:      insn.itype = I5_rrc;     break;
    case Z80_rlca:      insn.itype = I5_rlc;     break;
    case Z80_rla:       insn.itype = I5_ral;     break;
    case Z80_rl:        insn.itype = I5_ral;     break;
    case Z80_rra:       insn.itype = I5_rar;     break;
    case Z80_rr:        insn.itype = I5_rar;     break;
    case Z80_cpi:       insn.itype = A80_cmpi;   break;
    case Z80_cpd:       insn.itype = A80_cmpd;   break;
    case Z80_outi:      insn.itype = A80_oti;    break;
    case Z80_outd:      insn.itype = A80_otd;    break;
    case Z80_inc:       insn.itype = I5_inr;     break;
    case Z80_dec:       insn.itype = I5_dcr;     break;
    case Z80_im:
      if ( insn.Op1.value == 0 )
        insn.itype = A80_im0;
      else if ( insn.Op1.value == 1 )
        insn.itype = A80_im1;
      else
        insn.itype = A80_im2;
      insn.Op1.clr_shown();
      break;
  }
}

//----------------------------------------------------------------------
void z80_t::ConvertToZ80(insn_t &insn)
{
  uint16 cc;
  if ( insn.itype < Z80_and )
  {
    insn.Op1.set_shown();
    insn.Op2.set_shown();
  }
  switch ( insn.itype )
  {
    case I5_aci:
      insn.itype = I5_adc;
      break;
    case I5_adi:
    case I5_dad:
      insn.itype = I5_add;
      break;
    case I5_cmp:
    case I5_cpi:
      insn.itype = Z80_cp;
      if ( !isZ380() )
        insn.Op1.clr_shown();
      break;
    case I5_ana:
    case I5_ani:
      insn.itype = Z80_and;
      if ( !isZ380() )
        insn.Op1.clr_shown();
      break;
    case I5_ora:
    case I5_ori:
      insn.itype = Z80_or;
      if ( !isZ380() )
        insn.Op1.clr_shown();
      break;
    case I5_xra:
    case I5_xri:
      insn.itype = Z80_xor;
      if ( !isZ380() )
        insn.Op1.clr_shown();
      break;
    case I5_sbi:
    case I5_sbb:
      insn.itype = Z80_sbc;
      break;
    case I5_sui:
    case I5_sub:
      insn.itype = I5_sub;
      if ( !isZ380() )
        insn.Op1.clr_shown();
      break;
    case I5_dcr:
    case I5_dcx:
      insn.itype = Z80_dec;
      break;
    case I5_inr:
    case I5_inx:
      insn.itype = Z80_inc;
      break;
    case I5_halt:
      insn.itype = Z80_halt;
      break;
    case I5_sphl:
    case I5_mov:
    case I5_mvi:
    case I5_ldax:
    case I5_lxi:
    case I5_lhld:
    case I5_shld:
    case I5_sta:
    case I5_stax:
    case I5_lda:
      insn.itype = Z80_ld;
      break;
    case I5_xchg:
    case I5_xthl:
      insn.itype = Z80_ex;
      break;
    case I5_pchl:
      insn.Op1.type = o_phrase;
      insn.Op1.reg = R_hl;
      cc = oc_not;
      goto zjump;

    case I5_call:       cc = oc_not;goto zcall;
    case I5_cnz:        cc = oc_nz; goto zcall;
    case I5_cz:         cc = oc_z;  goto zcall;
    case I5_cnc:        cc = oc_nc; goto zcall;
    case I5_cc:         cc = oc_c;  goto zcall;
    case I5_cpo:        cc = oc_po; goto zcall;
    case I5_cpe:        cc = oc_pe; goto zcall;
    case I5_cp:         cc = oc_p;  goto zcall;
    case I5_cm:         cc = oc_m;  goto zcall;
    case I5_jmp:        cc = oc_not;goto zjump;
    case I5_jnz:        cc = oc_nz; goto zjump;
    case I5_jz:         cc = oc_z;  goto zjump;
    case I5_jnc:        cc = oc_nc; goto zjump;
    case I5_jc:         cc = oc_c;  goto zjump;
    case I5_jpo:        cc = oc_po; goto zjump;
    case I5_jpe:        cc = oc_pe; goto zjump;
    case I5_jp:         cc = oc_p;  goto zjump;
    case I5_jm:         cc = oc_m;  goto zjump;
    case I5_ret:        cc = oc_not;goto zret;
    case I5_rnz:        cc = oc_nz; goto zret;
    case I5_rz:         cc = oc_z;  goto zret;
    case I5_rnc:        cc = oc_nc; goto zret;
    case I5_rc:         cc = oc_c;  goto zret;
    case I5_rpo:        cc = oc_po; goto zret;
    case I5_rpe:        cc = oc_pe; goto zret;
    case I5_rp:         cc = oc_p;  goto zret;
    case I5_rm:         cc = oc_m;  goto zret;

zret:
      insn.itype = Z80_ret;
      goto zcc;
zjump:
      insn.itype = Z80_jp;
      goto zcc;
zcall:
      insn.itype = Z80_call;
      goto zcc;
zcc:
      insn.Op2 = insn.Op1;
      insn.Op2.n = 1;
      insn.Op1.type = o_cond;
      insn.Op1.Cond = cc;
      break;

  }
}

//----------------------------------------------------------------------
static bool is_gameboy_insn(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case Z80_adc:
    case Z80_add:
    case Z80_and:
    case Z80_bit:
    case Z80_call:
    case Z80_ccf:
    case Z80_cp:
    case Z80_cpl:
    case I5_daa:
    case Z80_dec:
    case Z80_di:
    case Z80_ei:
    case Z80_halt:
    case Z80_inc:
    case Z80_jp:
    case Z80_jr:
    case Z80_ld:
    case Z80_ldd:
    case GB_ldh:
    case Z80_ldi:
    case I5_nop:
    case Z80_or:
    case Z80_pop:
    case Z80_push:
    case Z80_res:
    case Z80_ret:
    case Z80_reti:
    case Z80_rl:
    case Z80_rla:
    case Z80_rlc:
    case Z80_rlca:
    case Z80_rr:
    case Z80_rra:
    case Z80_rrc:
    case Z80_rrca:
    case I5_rst:
    case Z80_sbc:
    case Z80_scf:
    case Z80_set:
    case Z80_sla:
    case Z80_sra:
    case Z80_srl:
    case GB_stop:
    case Z80_sub:
    case Z80_swap:
    case Z80_xor:
      break;
    default:
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
static void swap_operands(insn_t &insn)
{
  op_t op = insn.Op1;
  insn.Op1 = insn.Op2;
  insn.Op2 = op;
}

//----------------------------------------------------------------------
int z80_t::i5_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  insn.Op1.dtype = dt_byte;
  insn.Op2.dtype = dt_byte;
  insn.itype = I5_null;

  code = insn.get_next_byte();

  switch ( code & 0xC0 )
  {
    case 0x00:
      switch ( code & 0xF )
      {
        case 0:
        case 8:
          {
            int sub = ( code >> 3 ) & 7;
            switch ( sub )
            {
              case 0:
                insn.itype = I5_nop;
                break;
              case 1:                   // 08
                if ( isGB() )           // 08 bb aa LD ($aabb),SP
                {
                  insn.itype = Z80_ld;
                  op_mm(insn, insn.Op1);
                  insn.Op1.dtype = dt_word;
                  insn.Op2.type = o_reg;
                  insn.Op2.reg = R_sp;
                }
                else if ( isZ80() )
                {
                  insn.itype = Z80_ex;
                  insn.Op1.type = o_reg;
                  insn.Op1.reg  = R_af;
                  insn.Op2.type = o_reg;
                  insn.Op2.reg  = R_af2;
                }
                else
                {
                  insn.itype = I5_dsub;  // undoc
                }
                break;
              case 2:                   // 10
                if ( isGB() )           // 10 00 STOP
                {
                  if ( insn.get_next_byte() )
                    return 0;
                  insn.itype = GB_stop;
                }
                else if ( isZ80() )
                {
                  insn.itype = Z80_djnz;
                  op_e(insn, insn.Op1);
                }
                else
                {
                  insn.itype = I5_arhl;  // undoc
                }
                break;
              case 3:                   // 18
                if ( isZ80() )
                {
Z80_COMMON:
                  static const uint16 conds[] = { 0,1,2,oc_not,oc_nz,oc_z,oc_nc,oc_c };
                  insn.Op1.Cond = conds[sub];
                  insn.itype = Z80_jr;
                  insn.Op1.type = o_cond;
                  op_e(insn, insn.Op2);
                  break;
                }
                insn.itype = I5_rdel;  // undoc
                break;
              case 4:                   // 20
                if ( isZ80() )
                  goto Z80_COMMON;
                insn.itype = I5_rim;
                break;
              case 5:                   // 28
                if ( isZ80() )
                  goto Z80_COMMON;
                insn.itype = I5_ldhi;  // undoc
                GetImm(insn, insn.Op1);
                break;
              case 6:                   // 30
                if ( isZ80() )
                  goto Z80_COMMON;
                insn.itype = I5_sim;
                break;
              case 7:                   // 38
                if ( isZ80() )
                  goto Z80_COMMON;
                insn.itype = I5_ldsi;
                GetImm(insn, insn.Op1);
                break;
            }
          }
          break;
        case 1:
          insn.itype = I5_lxi;
          op_ss(insn.Op1);
          op_nn(insn, insn.Op2);
          break;

        case 9:
          insn.itype = I5_dad;
          insn.Op1.reg = R_hl;
          insn.Op1.dtype = dt_word;
          insn.Op1.type = o_reg;
          insn.Op1.clr_shown();
          op_ss(insn.Op2);
          break;
        case 0xA:
          if ( (code & 0x20) == 0 )
          {
            insn.itype = I5_ldax;
            insn.Op2.type = o_phrase;
            insn.Op2.phrase = R_bc + ((code >> 4) & 1);
            op_a(insn.Op1);
          }
          else
          {
            if ( isGB() )
            {
              insn.itype = (code & 0x10) ? Z80_ldd : Z80_ldi;
              insn.Op1.type = o_reg;
              insn.Op1.reg = R_a;
              insn.Op2.type = o_phrase;
              insn.Op2.phrase = R_hl;
              break;
            }
            insn.Op1.type = o_reg;
            if ( (code & 0x10) == 0 )
            {
              insn.itype = I5_lhld;
              insn.Op1.dtype = dt_word;
              insn.Op2.dtype = dt_word;
              insn.Op1.reg = R_hl;
            }
            else
            {
              insn.itype = I5_lda;
              insn.Op1.reg = R_a;
            }
            op_mm(insn, insn.Op2);
          }
          insn.Op1.clr_shown();
          break;
        case 2:
          if ( (code & 0x20) == 0 )
          {
            insn.itype = I5_stax;
            insn.Op1.type = o_phrase;
            insn.Op1.phrase = R_bc + ((code >> 4) & 1);
            op_a(insn.Op2);
          }
          else
          {
            if ( isGB() )
            {
              insn.itype = (code & 0x10) ? Z80_ldd : Z80_ldi;
              insn.Op1.type = o_phrase;
              insn.Op1.phrase = R_hl;
              insn.Op2.type = o_reg;
              insn.Op2.reg = R_a;
              break;
            }
            insn.Op2.type = o_reg;
            if ( (code & 0x10) == 0 )
            {
              insn.itype = I5_shld;
              insn.Op1.dtype = dt_word;
              insn.Op2.dtype = dt_word;
              insn.Op2.reg = R_hl;
            }
            else
            {
              insn.itype = I5_sta;
              insn.Op2.reg = R_a;
            }
            op_mm(insn, insn.Op1);
          }
          insn.Op2.clr_shown();
          break;
        case 3:
          insn.itype = I5_inx;
          op_ss(insn.Op1);
          break;
        case 0xB:
          insn.itype = I5_dcx;
          op_ss(insn.Op1);
          break;
        case 4:
        case 0xC:
          insn.itype = I5_inr;
          op_r1(insn.Op1);
          break;
        case 5:
        case 0xD:
          insn.itype = I5_dcr;
          op_r1(insn.Op1);
          break;
        case 6:
        case 0xE:
          insn.itype = I5_mvi;
          op_r1(insn.Op1);
          op_n (insn, insn.Op2);
          break;
        case 7:
        case 0xF:
          insn.itype = (isZ80() ? Zrols : rols)[ (code >> 3) & 7 ];
          break;
      }
      break;
    case 0x40:
      insn.itype = I5_halt;
      if ( code != 0x76 )
      {
        insn.itype = I5_mov;
        op_r1(insn.Op1);
        op_r2(insn.Op2);
      }
      break;
    case 0x80:
      op_r2(insn.Op2);
common:
      insn.Op1.type = o_reg;
      insn.Op1.reg = R_a;
      insn.itype = (insn.Op2.type == o_imm ? Wi : W)[ (code >> 3) & 7 ];
      insn.Op1.clr_shown();
      break;
    case 0xC0:                          /* 11?????? */
      switch ( code & 0xF )
      {
        case 0x0:
        case 0x8:                     /* 11???000 */
          if ( isGB() )
          {
            switch ( code )
            {
              case 0xE0:
              case 0xF0:
                insn.itype = Z80_ld;
                insn.Op1.type = o_mem;
                insn.Op1.addr = 0xFF00 + insn.get_next_byte();
                insn.Op2.type = o_reg;
                insn.Op2.reg = R_a;
                if ( code & 0x10 )
                  swap_operands(insn);
                break;
              case 0xE8:
                insn.itype = Z80_add;
                insn.Op1.type = o_reg;
                insn.Op1.reg  = R_sp;
                GetImm(insn, insn.Op2);
                break;
              case 0xF8:  // docs say this is "ld hl, sp"
                          // Daniel Filner <danf@codefrog.cx> says
                          // this is "ld hl, sp+immbyte"
                insn.itype = Z80_ld;
                insn.Op1.type = o_reg;
                insn.Op1.reg  = R_hl;
                insn.Op2.type = o_displ;
                insn.Op2.phrase = R_sp;
                insn.Op2.addr = insn.get_next_byte();
                break;
              default:
                goto RETS;
            }
            break;
          }
RETS:
          insn.itype = rets[ (code >> 3) & 7 ];
          break;
        case 0x2:
        case 0xA:                     /* 11???010 */
          if ( isGB() )
          {
            switch ( code )
            {
              case 0xE2:
              case 0xF2:
                insn.itype = Z80_ld;
                insn.auxpref |= aux_off16;
                op_c(insn.Op1);
                insn.Op2.type = o_reg;
                insn.Op2.reg = R_a;
                if ( code & 0x10 )
                  swap_operands(insn);
                break;
              case 0xEA:
              case 0xFA:
                insn.itype = Z80_ld;
                op_mm(insn, insn.Op1);
                insn.Op2.type = o_reg;
                insn.Op2.reg = R_a;
                if ( code & 0x10 )
                  swap_operands(insn);
                break;
              default:
                goto JUMPS;
            }
            break;
          }
JUMPS:
          insn.itype = jumps[ (code >> 3) & 7 ];
          op_ad(insn, insn.Op1);
          break;
        case 0x3:
        case 0xB:                     /* 11???011 */
          switch ( ( code >> 3 ) & 7 )
          {
            case 0:                   /* 11000011=C3 */
              insn.itype = I5_jmp;
              op_ad(insn, insn.Op1);
              break;
            case 1:                   // 11001011=CB - Z80 extensions
              if ( isZ80() )
              {
                code = insn.get_next_byte();
                int fn = (code>>6);
                if ( fn == 0 )
                {
                  op_r2(insn.Op1);
                  insn.itype = CBrols[ (code>>3) & 7 ];
                  if ( insn.itype == Z80_srr )
                  {
                    if ( isZ380() )
                    {
                      insn.itype = Z80_ex;
                      op_r2(insn.Op2);
                      insn.Op2.reg += R_b2;
                    }
                    else if ( isGB() )
                    {
                      insn.itype = Z80_swap;
                    }
                  }
                }
                else
                {
                  static const uint16 brs[] = { 0, Z80_bit,Z80_res,Z80_set };
                  insn.itype = brs[fn];
                  insn.Op1.type = o_imm;
                  insn.Op1.value = (code>>3) & 7;
                  op_r2(insn.Op2);
                }
              }
              else
              {
                insn.itype = I5_rstv;  // undoc
              }
              break;
            case 2:                   /* 11010011=D3 */
              insn.itype = I5_out;
              op_a(insn.Op2);
              op_n(insn, insn.Op1);
              break;
            case 3:                   // DB
              insn.itype = I5_in;
              op_a(insn.Op1);
              op_n(insn, insn.Op2);
              break;
            case 4:                   // E3
              insn.itype = I5_xthl;
              insn.Op1.type = o_phrase;
              insn.Op1.reg = R_sp;
              insn.Op1.clr_shown();
              insn.Op2.type = o_reg;
              insn.Op2.reg = R_hl;
              insn.Op2.clr_shown();
              break;
            case 5:                   // EB
              insn.itype = I5_xchg;
              insn.Op1.type = o_reg;
              insn.Op1.reg = R_de;
              insn.Op1.clr_shown();
              insn.Op2.type = o_reg;
              insn.Op2.reg = R_hl;
              insn.Op2.clr_shown();
              break;
            case 6:                   // F3
              insn.itype = I5_di;
              break;
            case 7:                   // FB
              insn.itype = I5_ei;
              break;
          }
          break;
        case 0x4:
        case 0xC:                     /* 11???100 */
          insn.itype = calls[ (code >> 3) & 7 ];
          op_ad(insn, insn.Op1);
          break;
        case 0x1:
        case 0x5:                     // 11????01
          insn.itype = (code & 4) ? I5_push : I5_pop;
          op_dd(insn.Op1);
          break;
        case 0x6:
        case 0xE:                     // 11???110
          op_n(insn, insn.Op2);
          goto common;
        case 0x7:
        case 0xF:                     // 11???111
          insn.itype = I5_rst;
          insn.Op1.type = o_imm;
          insn.Op1.value = (code >> 3) & 7;
          if ( isZ80() )
          { // workaround for bcb6 bug:
            uval_t x = insn.Op1.value;
            x <<= 3;
            insn.Op1.value = x;
          }
          break;
        case 0x9:
          switch ( (code >> 4) & 3 )
          {
            case 0:
              insn.itype = I5_ret;     // 11001001 = C9
              break;
            case 1:                   // 11011001 = D9
              if ( isGB() )
                insn.itype = Z80_reti;
              else if ( isZ80() )
                insn.itype = Z80_exx;
              else
                insn.itype = I5_shlx;  // undoc
              break;
            case 2:
              insn.itype = I5_pchl;
              break;
            case 3:
              insn.itype = I5_sphl;
              insn.Op1.type = o_reg;
              insn.Op1.reg = R_sp;
              insn.Op1.clr_shown();
              insn.Op2.type = o_reg;
              insn.Op2.reg = R_hl;
              insn.Op2.clr_shown();
              break;
          }
          break;
        case 0xD:                     /* 11??1101 */
          switch ( (code >> 4) & 3 )
          {
            case 0:
              insn.itype = I5_call;
              op_ad(insn, insn.Op1);
              break;
            case 1:           // 11011101 = DD - Z80 extensions
              if ( is8085() )
              {
                insn.itype = I5_jnx5;   // undoc
                op_ad(insn, insn.Op1);
              }
              else
              {
                z80_ixcommands(insn, true);
              }
              break;
            case 2:           // 11101101 = ED - Z80 extensions
              if ( isGB() )
                return 0;
              else if ( isZ380() )
                z380_ED(insn);
              else if ( is8085() )
                insn.itype = I5_lhlx;  // undoc
              else
                z80_misc(insn);
              break;
            case 3:           // 11111101 = FD - Z80 extensions
              if ( is8085() )
              {
                insn.itype = I5_jx5;   // undoc
                op_ad(insn, insn.Op1);
              }
              else
              {
                z80_ixcommands(insn, false);
              }
              break;
          }
          break;
      }
      break;
  }

  if ( insn.itype == I5_null )
    return 0;

  if ( isZ80() )
  {
    if ( ash.uflag & UAS_FUNNY )
      ConvertToFunny(insn);
    else
      ConvertToZ80(insn);
    if ( isGB() && !is_gameboy_insn(insn) )
      return 0;
  }

  return insn.size;

}

//------------------------------------------------------------------------
void z80_t::op_r1(op_t &x) const
{
  uint16 mode = (code >> 3) & 7;
  if ( mode == 6 )
  {
    x.type = o_phrase;
    x.phrase = R_hl;
  }
  else
  {
    x.type = o_reg;
    x.reg = mode;
  }
}

//------------------------------------------------------------------------
void z80_t::op_r2(op_t &x) const
{
  uint16 mode = code & 7;
  if ( mode == 6 )
  {
    x.type = o_phrase;
    x.phrase = R_hl;
  }
  else
  {
    x.type = o_reg;
    x.reg = mode;
  }
}

//------------------------------------------------------------------------
void z80_t::op_ss(op_t &x) const
{
  uint16 ss = (code >> 4) & 3;
  x.type = o_reg;
  x.dtype = dt_word;
  x.reg = ss + R_bc;
  if ( ss == 3 )
    x.reg = R_sp;
}

//------------------------------------------------------------------------
void z80_t::op_dd(op_t &x) const
{
  uint16 ss = (code >> 4) & 3;
  x.type = o_reg;
  x.dtype = dt_word;
  x.reg = ss + R_bc;
}

//------------------------------------------------------------------------
static void op_nn(insn_t &insn, op_t &x)
{
  x.type = o_imm;
  x.dtype = dt_word;
  x.value = insn.get_next_word();
}

//------------------------------------------------------------------------
static void op_n(insn_t &insn, op_t &x)
{
  x.type = o_imm;
  x.value = insn.get_next_byte();
}

//------------------------------------------------------------------------
static void op_e(insn_t &insn, op_t &x)
{
  x.type = o_near;
  sval_t rel = char(insn.get_next_byte());
  x.addr = ushort(insn.ip + insn.size + rel);
}

//------------------------------------------------------------------------
static void op_a(op_t &x)
{
  x.type = o_reg;
  x.reg = R_a;
  x.clr_shown();
}

//------------------------------------------------------------------------
static void op_mm(insn_t &insn, op_t &x)
{
  x.type = o_mem;
  x.addr = insn.get_next_word();
}

//------------------------------------------------------------------------
static void op_f(op_t &x)
{
  x.type  = o_reg;
  x.dtype = dt_byte;
  x.reg   = R_f;
}

//------------------------------------------------------------------------
void z80_t::op_xdispl(insn_t &insn, op_t &x) const
{
  x.type = o_displ;
  x.phrase = isx ? R_ix : R_iy;
  x.addr = insn.get_next_byte();
}

//------------------------------------------------------------------------
void z80_t::op_ix(op_t &x) const
{
  x.type = o_reg;
  x.reg = isx ? R_ix : R_iy;
  x.dtype = dt_word;
}

//------------------------------------------------------------------------
void z80_t::op_ibyte(op_t &x, int low) const
{
  x.type = o_reg;
  x.reg = isx
        ? (low ? R_xl : R_xh)
        : (low ? R_yl : R_yh);
}

//------------------------------------------------------------------------
int z80_t::op_xbytereg(op_t &x, uint16 mode) const
{
  if ( mode == 6 )
  {
    x.type = o_phrase;
    x.phrase = R_hl;
    return 1;
  }
  else
  {
    if ( mode == R_h )
    {
      op_ibyte(x,0);
    }
    else if ( mode == R_l )
    {
      op_ibyte(x,1);
    }
    else
    {
      x.type = o_reg;
      x.reg = mode;
    }
    return 0;
  }
}

//------------------------------------------------------------------------
int z80_t::op_xr1(op_t &x) const
{
  return op_xbytereg(x,(code >> 3) & 7);
}

//------------------------------------------------------------------------
int z80_t::op_xr2(op_t &x) const
{
  return op_xbytereg(x,code & 7);
}

//------------------------------------------------------------------------
struct insndesc_t
{
  uchar code;
  ushort itype; //lint !e958 padding is required to align members
  uchar op1;
  uchar op2;
};

#define rA      (R_a+1)
#define rB      (R_b+1)
#define rC      (R_c+1)
#define rD      (R_d+1)
#define rE      (R_e+1)
#define rH      (R_h+1)
#define rL      (R_l+1)
#define rI      (R_i+1)
#define rW      (R_w+1)
#define rR      (R_r+1)
#define rBC     (R_bc+1)
#define rDE     (R_de+1)
#define rHL     (R_hl+1)
#define rIX     (R_ix+1)
#define rIY     (R_iy+1)
#define rSP     (R_sp+1)
#define rLW     (R_lw+1)
#define rIXL    (R_ixl+1)
#define rIXU    (R_ixu+1)
#define rDSR    (R_dsr+1)
#define rXSR    (R_xsr+1)
#define rIYL    (R_iyl+1)
#define rIYU    (R_iyu+1)
#define rYSR    (R_ysr+1)
#define rSR     (R_sr+1)
#define rIB     (R_ib+1)
#define rIW     (R_iw+1)
#define rXM     (R_xm+1)
#define rLCK    (R_lck+1)
#define rBC2    (R_bc2+1)
#define rDE2    (R_de2+1)
#define rHL2    (R_hl2+1)
#define rIX2    (R_ix2+1)
#define rIY2    (R_iy2+1)

#define atBC    0x30
#define atDE    0x31
#define atHL    0x32
#define atSP    0x33
#define atIX    0x34
#define atIY    0x35
#define atC     0x36
#define rip8    0x37    // ip relative displ 8bits
#define rip16   0x38    // ip relative displ 16bits
#define rip24   0x39    // ip relative displ 24bits
#define imm8    0x3A    // 8bit immval
#define imm16   0x3B    // 16bit immval
#define mem16   0x3C    // (1234h)

#define ix8     0x40    // (IX+12)
#define iy8     0x41    // (IY+12)
#define ixs     0x42    // (IX+saved_value)
#define iys     0x43    // (IY+saved_value)
#define sps     0x44    // (SP+saved_value)

// condition codes
#define ccNZ    0x50
#define ccZ     0x51
#define ccNC    0x52
#define ccC     0x53
#define ccPO    0x54
#define ccPE    0x55
#define ccP     0x56
#define ccM     0x57

#define c0      0x60
#define c1      0x61
#define c2      0x62
#define c3      0x63
#define c4      0x64
#define c5      0x65
#define c6      0x66
#define c7      0x67

static const insndesc_t cmdsDD[] =
{
  { 0x01, Z80_ld,     atBC,       rIX         },
  { 0x02, Z80_ld,     rBC,        rDE         },
  { 0x03, Z80_ld,     rIX,        atBC        },
  { 0x07, Z80_ld,     rIX,        rBC         },
  { 0x09, Z80_add,    rIX,        rBC         },
  { 0x0B, Z80_ld,     rBC,        rIX         },
  { 0x0C, Z80_ld,     rBC,        atBC        },
  { 0x0D, Z80_ld,     rBC,        atDE        },
  { 0x0F, Z80_ld,     rBC,        atHL        },
  { 0x10, Z80_djnz,   rip16                   },
  { 0x11, Z80_ld,     atDE,       rIX         },
  { 0x12, Z80_ld,     rDE,        rDE         },
  { 0x13, Z80_ld,     rIX,        atDE        },
  { 0x17, Z80_ld,     rIX,        rDE         },
  { 0x18, Z80_jr,     rip16                   },
  { 0x19, Z80_add,    rIX,        rDE         },
  { 0x1B, Z80_ld,     rDE,        rIX         },
  { 0x1C, Z80_ld,     rDE,        atBC        },
  { 0x1D, Z80_ld,     rDE,        atDE        },
  { 0x1F, Z80_ld,     rDE,        atHL        },
  { 0x20, Z80_jr,     ccNZ,       rip16       },
  { 0x21, Z80_ld,     rIX,        imm16       },
  { 0x22, Z80_ld,     mem16,      rIX         },
  { 0x23, Z80_inc,    rIX                     },
  { 0x24, Z80_inc,    rIXU                    },
  { 0x25, Z80_dec,    rIXU                    },
  { 0x26, Z80_ld,     rIXU,       imm8        },
  { 0x27, Z80_ld,     rIX,        rIY         },
  { 0x28, Z80_jr,     ccZ,        rip16       },
  { 0x29, Z80_add,    rIX,        rIX         },
  { 0x2A, Z80_ld,     rIX,        mem16       },
  { 0x2B, Z80_dec,    rIX                     },
  { 0x2C, Z80_inc,    rIXL                    },
  { 0x2D, Z80_dec,    rIXL                    },
  { 0x2E, Z80_ld,     rIXL,       imm8        },
  { 0x2F, Z80_cplw,   rHL                     },
  { 0x30, Z80_jr,     ccNC,       rip16       },
  { 0x31, Z80_ld,     atHL,       rIX         },
  { 0x32, Z80_ld,     rHL,        rDE         },
  { 0x33, Z80_ld,     rIX,        atHL        },
  { 0x34, Z80_inc,    ix8                     },
  { 0x35, Z80_dec,    ix8                     },
  { 0x36, Z80_ld,     ix8,        imm8        },
  { 0x37, Z80_ld,     rIX,        rHL         },
  { 0x38, Z80_jr,     ccC,        rip16       },
  { 0x39, Z80_add,    rIX,        rSP         },
  { 0x3B, Z80_ld,     rHL,        rIX         },
  { 0x3C, Z80_ld,     rHL,        atBC        },
  { 0x3D, Z80_ld,     rHL,        atDE        },
  { 0x3E, Z80_swap,   rIX                     },
  { 0x3F, Z80_ld,     rHL,        atHL        },
  { 0x40, Z80_inw,    rBC,        atC         },
  { 0x41, Z80_outw,   atC,        rBC         },
  { 0x44, Z80_ld,     rB,         rIXU        },
  { 0x45, Z80_ld,     rB,         rIXL        },
  { 0x46, Z80_ld,     rB,         ix8         },
  { 0x47, Z80_ldw,    rI,         rHL         },
  { 0x4C, Z80_ld,     rC,         rIXU        },
  { 0x4D, Z80_ld,     rC,         rIXL        },
  { 0x4E, Z80_ld,     rC,         ix8         },
  { 0x50, Z80_inw,    rDE,        atC         },
  { 0x51, Z80_outw,   atC,        rDE         },
  { 0x54, Z80_ld,     rD,         rIXU        },
  { 0x55, Z80_ld,     rD,         rIXL        },
  { 0x56, Z80_ld,     rD,         ix8         },
  { 0x57, Z80_ldw,    rHL,        rI          },
  { 0x5D, Z80_ld,     rE,         rIXL        },
  { 0x5E, Z80_ld,     rE,         ix8         },
  { 0x60, Z80_ld,     rIXU,       rB          },
  { 0x61, Z80_ld,     rIXU,       rC          },
  { 0x62, Z80_ld,     rIXU,       rD          },
  { 0x63, Z80_ld,     rIXU,       rE          },
  { 0x64, Z80_ld,     rIXU,       rIXU        },
  { 0x65, Z80_ld,     rIXU,       rIXL        },
  { 0x66, Z80_ld,     rH,         ix8         },
  { 0x67, Z80_ld,     rIXU,       rA          },
  { 0x68, Z80_ld,     rIXL,       rB          },
  { 0x69, Z80_ld,     rIXL,       rC          },
  { 0x6A, Z80_ld,     rIXL,       rD          },
  { 0x6B, Z80_ld,     rIXL,       rE          },
  { 0x6C, Z80_ld,     rIXL,       rIXU        },
  { 0x6D, Z80_ld,     rIXL,       rIXL        },
  { 0x6E, Z80_ld,     rL,         ix8         },
  { 0x6F, Z80_ld,     rIXL,       rA          },
  { 0x70, Z80_ld,     ix8,        rB          },
  { 0x71, Z80_ld,     ix8,        rC          },
  { 0x72, Z80_ld,     ix8,        rD          },
  { 0x73, Z80_ld,     ix8,        rE          },
  { 0x74, Z80_ld,     ix8,        rH          },
  { 0x75, Z80_ld,     ix8,        rL          },
  { 0x77, Z80_ld,     ix8,        rA          },
  { 0x78, Z80_inw,    rHL,        atC         },
  { 0x79, Z80_outw,   atC,        rHL         },
  { 0x7C, Z80_ld,     rA,         rIXU        },
  { 0x7D, Z80_ld,     rA,         rIXL        },
  { 0x7E, Z80_ld,     rA,         ix8         },
  { 0x84, Z80_add,    rA,         rIXU        },
  { 0x85, Z80_add,    rA,         rIXL        },
  { 0x86, Z80_add,    rA,         ix8         },
  { 0x87, Z80_addw,   rHL,        rIX         },
  { 0x8C, Z80_adc,    rA,         rIXU        },
  { 0x8D, Z80_adc,    rA,         rIXL        },
  { 0x8E, Z80_adc,    rA,         ix8         },
  { 0x8F, Z80_adcw,   rHL,        rIX         },
  { 0x94, Z80_sub,    rA,         rIXU        },
  { 0x95, Z80_sub,    rA,         rIXL        },
  { 0x96, Z80_sub,    rA,         ix8         },
  { 0x97, Z80_subw,   rHL,        rIX         },
  { 0x9C, Z80_sbc,    rA,         rIXU        },
  { 0x9D, Z80_sbc,    rA,         rIXL        },
  { 0x9E, Z80_sbc,    rA,         ix8         },
  { 0x9F, Z80_sbcw,   rHL,        rIX         },
  { 0xA4, Z80_and,    rA,         rIXU        },
  { 0xA5, Z80_and,    rA,         rIXL        },
  { 0xA6, Z80_and,    rA,         ix8         },
  { 0xA7, Z80_andw,   rHL,        rIX         },
  { 0xAC, Z80_xor,    rA,         rIXU        },
  { 0xAD, Z80_xor,    rA,         rIXL        },
  { 0xAE, Z80_xor,    rA,         ix8         },
  { 0xAF, Z80_xorw,   rHL,        rIX         },
  { 0xB4, Z80_or,     rA,         rIXU        },
  { 0xB5, Z80_or,     rA,         rIXL        },
  { 0xB6, Z80_or,     rA,         ix8         },
  { 0xB7, Z80_orw,    rHL,        rIX         },
  { 0xBC, Z80_cp,     rA,         rIXU        },
  { 0xBD, Z80_cp,     rA,         rIXL        },
  { 0xBE, Z80_cp,     rA,         ix8         },
  { 0xBF, Z80_cpw,    rHL,        rIX         },
  { 0xC0, Z80_ddir,   rW                      },
  { 0xC1, Z80_ddir,   rIB,        rW          },
  { 0xC2, Z80_ddir,   rIW,        rW          },
  { 0xC3, Z80_ddir,   rIB                     },
  { 0xC4, Z80_calr,   ccNZ,       rip16       },
  { 0xC6, Z80_addw,   rHL,        ix8         },
  { 0xC8, Z80_ldctl,  rSR,        rA          },
  { 0xCA, Z80_ldctl,  rSR,        imm8        },
  { 0xCC, Z80_calr,   ccZ,        rip16       },
  { 0xCD, Z80_calr,   rip16                   },
  { 0xCE, Z80_adcw,   rHL,        ix8         },
  { 0xCF, Z80_mtest,                          },
  { 0xD0, Z80_ldctl,  rA,         rXSR        },
  { 0xD4, Z80_calr,   ccNC,       rip16       },
  { 0xD6, Z80_subw,   rHL,        ix8         },
  { 0xD8, Z80_ldctl,  rXSR,       rA          },
  { 0xD9, Z80_exxx,                           },
  { 0xDA, Z80_ldctl,  rXSR,       imm8        },
  { 0xDC, Z80_calr,   ccC,        rip16       },
  { 0xDE, Z80_sbcw,   rHL,        ix8         },
  { 0xE1, Z80_pop,    rIX                     },
  { 0xE3, Z80_ex,     atSP,       rIX         },
  { 0xE4, Z80_calr,   ccPO,       rip16       },
  { 0xE5, Z80_push,   rIX                     },
  { 0xE6, Z80_andw,   rHL,        ix8         },
  { 0xE9, Z80_jp,     atIX                    },
  { 0xEC, Z80_calr,   ccPE,       rip16       },
  { 0xEE, Z80_xorw,   rHL,        ix8         },
  { 0xF3, Z80_di,     imm8                    },
  { 0xF4, Z80_calr,   ccP,        rip16       },
  { 0xF6, Z80_orw,    rHL,        ix8         },
  { 0xF7, Z80_setc,   rLW                     },
  { 0xF9, Z80_ld,     rSP,        rIX         },
  { 0xFB, Z80_ei,     imm8                    },
  { 0xFC, Z80_calr,   ccM,        rip16       },
  { 0xFE, Z80_cpw,    rHL,        ix8         },
  { 0xFF, Z80_resc,   rLW                     },
  { 0x00, 0 },
};

// the next byte after DDBC is in saved_value
static const insndesc_t cmdsDDCB[] =
{
  { 0x01, Z80_ld,     rBC,        sps         },
  { 0x02, Z80_rlcw,   ixs                     },
  { 0x03, Z80_ld,     rBC,        ixs         },
  { 0x06, Z80_rlc,    ixs                     },
  { 0x09, Z80_ld,     sps,        rBC         },
  { 0x0A, Z80_rrcw,   ixs                     },
  { 0x0B, Z80_ld,     ixs,        rBC         },
  { 0x0E, Z80_rrc,    ixs                     },
  { 0x11, Z80_ld,     rDE,        sps         },
  { 0x12, Z80_rlw,    ixs                     },
  { 0x13, Z80_ld,     rDE,        ixs         },
  { 0x16, Z80_rl,     ixs                     },
  { 0x19, Z80_ld,     sps,        rDE         },
  { 0x1A, Z80_rrw,    ixs                     },
  { 0x1B, Z80_ld,     ixs,        rDE         },
  { 0x1E, Z80_rr,     ixs                     },
  { 0x21, Z80_ld,     rIX,        sps         },
  { 0x22, Z80_slaw,   ixs                     },
  { 0x23, Z80_ld,     rIY,        ixs         },
  { 0x26, Z80_sla,    ixs                     },
  { 0x29, Z80_ld,     sps,        rIX         },
  { 0x2A, Z80_sraw,   ixs                     },
  { 0x2B, Z80_ld,     ixs,        rIY         },
  { 0x2E, Z80_sra,    ixs                     },
  { 0x31, Z80_ld,     rHL,        sps         },
  { 0x33, Z80_ld,     rHL,        ixs         },
  { 0x39, Z80_ld,     sps,        rHL         },
  { 0x3A, Z80_srlw,   ixs                     },
  { 0x3B, Z80_ld,     ixs,        rHL         },
  { 0x3E, Z80_srl,    ixs                     },
  { 0x46, Z80_bit,    c0,         ixs         },
  { 0x4E, Z80_bit,    c1,         ixs         },
  { 0x56, Z80_bit,    c2,         ixs         },
  { 0x5E, Z80_bit,    c3,         ixs         },
  { 0x66, Z80_bit,    c4,         ixs         },
  { 0x6E, Z80_bit,    c5,         ixs         },
  { 0x76, Z80_bit,    c6,         ixs         },
  { 0x7E, Z80_bit,    c7,         ixs         },
  { 0x86, Z80_res,    c0,         ixs         },
  { 0x8E, Z80_res,    c1,         ixs         },
  { 0x92, Z80_multw,  ixs                     },
  { 0x92, Z80_multw,  rHL,        ixs         },
  { 0x96, Z80_res,    c2,         ixs         },
  { 0x9A, Z80_multuw, ixs                     },
  { 0x9A, Z80_multuw, rHL,        ixs         },
  { 0x9E, Z80_res,    c3,         ixs         },
  { 0xA6, Z80_res,    c4,         ixs         },
  { 0xAE, Z80_res,    c5,         ixs         },
  { 0xB6, Z80_res,    c6,         ixs         },
  { 0xBA, Z80_divuw,  ixs                     },
  { 0xBA, Z80_divuw,  rHL,        ixs         },
  { 0xBE, Z80_res,    c7,         ixs         },
  { 0xC6, Z80_set,    c0,         ixs         },
  { 0xCE, Z80_set,    c1,         ixs         },
  { 0xD6, Z80_set,    c2,         ixs         },
  { 0xDE, Z80_set,    c3,         ixs         },
  { 0xE6, Z80_set,    c4,         ixs         },
  { 0xEE, Z80_set,    c5,         ixs         },
  { 0xF6, Z80_set,    c6,         ixs         },
  { 0xFE, Z80_set,    c7,         ixs         },
  { 0x00, 0 },
};


static const insndesc_t cmdsFD[] =
{
  { 0x01, Z80_ld,     atBC,       rIY         },
  { 0x02, Z80_ld,     rBC,        rHL         },
  { 0x03, Z80_ld,     rIY,        atBC        },
  { 0x07, Z80_ld,     rIY,        rBC         },
  { 0x09, Z80_add,    rIY,        rBC         },
  { 0x0B, Z80_ld,     rBC,        rIY         },
  { 0x0C, Z80_ld,     atBC,       rBC         },
  { 0x0D, Z80_ld,     atDE,       rBC         },
  { 0x0F, Z80_ld,     atHL,       rBC         },
  { 0x10, Z80_djnz,   rip24                   },
  { 0x11, Z80_ld,     atDE,       rIY         },
  { 0x12, Z80_ld,     rDE,        rHL         },
  { 0x13, Z80_ld,     rIY,        atDE        },
  { 0x17, Z80_ld,     rIY,        rDE         },
  { 0x18, Z80_jr,     rip24                   },
  { 0x19, Z80_add,    rIY,        rDE         },
  { 0x1B, Z80_ld,     rDE,        rIY         },
  { 0x1C, Z80_ld,     atBC,       rDE         },
  { 0x1D, Z80_ld,     atDE,       rDE         },
  { 0x1F, Z80_ld,     atHL,       rDE         },
  { 0x20, Z80_jr,     ccNZ,       rip24       },
  { 0x21, Z80_ld,     rIY,        imm16       },
  { 0x22, Z80_ld,     mem16,      rIY         },
  { 0x23, Z80_inc,    rIY                     },
  { 0x24, Z80_inc,    rIYU                    },
  { 0x25, Z80_dec,    rIYU                    },
  { 0x26, Z80_ld,     rIYU,       imm8        },
  { 0x27, Z80_ld,     rIY,        rIX         },
  { 0x28, Z80_jr,     ccZ,        rip24       },
  { 0x29, Z80_add,    rIY,        rIY         },
  { 0x2A, Z80_ld,     rIY,        mem16       },
  { 0x2B, Z80_dec,    rIY                     },
  { 0x2C, Z80_inc,    rIYL                    },
  { 0x2D, Z80_dec,    rIYL                    },
  { 0x2E, Z80_ld,     rIYL,       imm8        },
  { 0x30, Z80_jr,     ccNC,       rip24       },
  { 0x31, Z80_ld,     atHL,       rIY         },
  { 0x32, Z80_ld,     rHL,        rHL         },
  { 0x33, Z80_ld,     rIY,        atHL        },
  { 0x34, Z80_inc,    iy8                     },
  { 0x35, Z80_dec,    iy8                     },
  { 0x36, Z80_ld,     iy8,        imm8        },
  { 0x26, Z80_ld,     rIYU,       imm8        },
  { 0x37, Z80_ld,     rIY,        rHL         },
  { 0x38, Z80_jr,     ccC,        rip24       },
  { 0x39, Z80_add,    rIY,        rSP         },
  { 0x3B, Z80_ld,     rHL,        rIY         },
  { 0x3C, Z80_ld,     atBC,       rHL         },
  { 0x3D, Z80_ld,     atDE,       rHL         },
  { 0x3E, Z80_swap,   rIY                     },
  { 0x3F, Z80_ld,     atHL,       rHL         },
  { 0x44, Z80_ld,     rB,         rIYU        },
  { 0x45, Z80_ld,     rB,         rIYL        },
  { 0x46, Z80_ld,     rB,         iy8         },
  { 0x4C, Z80_ld,     rC,         rIYU        },
  { 0x4D, Z80_ld,     rC,         rIYL        },
  { 0x4E, Z80_ld,     rC,         iy8         },
  { 0x54, Z80_ld,     rD,         rIYU        },
  { 0x55, Z80_ld,     rD,         rIYL        },
  { 0x56, Z80_ld,     rD,         iy8         },
  { 0x5C, Z80_ld,     rE,         rIYU        },
  { 0x5D, Z80_ld,     rE,         rIYL        },
  { 0x5E, Z80_ld,     rE,         iy8         },
  { 0x60, Z80_ld,     rIYU,       rB          },
  { 0x61, Z80_ld,     rIYU,       rC          },
  { 0x62, Z80_ld,     rIYU,       rD          },
  { 0x63, Z80_ld,     rIYU,       rE          },
  { 0x64, Z80_ld,     rIYU,       rIYU        },
  { 0x65, Z80_ld,     rIYU,       rIYL        },
  { 0x66, Z80_ld,     rH,         iy8         },
  { 0x67, Z80_ld,     rIYU,       rA          },
  { 0x68, Z80_ld,     rIYL,       rB          },
  { 0x69, Z80_ld,     rIYL,       rC          },
  { 0x6A, Z80_ld,     rIYL,       rD          },
  { 0x6B, Z80_ld,     rIYL,       rE          },
  { 0x6C, Z80_ld,     rIYL,       rIYU        },
  { 0x6D, Z80_ld,     rIYL,       rIYL        },
  { 0x6E, Z80_ld,     rL,         iy8         },
  { 0x6F, Z80_ld,     rIYL,       rA          },
  { 0x70, Z80_ld,     iy8,        rB          },
  { 0x71, Z80_ld,     iy8,        rC          },
  { 0x72, Z80_ld,     iy8,        rD          },
  { 0x73, Z80_ld,     iy8,        rE          },
  { 0x74, Z80_ld,     iy8,        rH          },
  { 0x75, Z80_ld,     iy8,        rL          },
  { 0x77, Z80_ld,     iy8,        rA          },
  { 0x79, Z80_outw,   atC,        imm16       },
  { 0x7C, Z80_ld,     rA,         rIYU        },
  { 0x7D, Z80_ld,     rA,         rIYL        },
  { 0x7E, Z80_ld,     rA,         iy8         },
  { 0x84, Z80_add,    rA,         rIYU        },
  { 0x85, Z80_add,    rA,         rIYL        },
  { 0x86, Z80_add,    rA,         iy8         },
  { 0x87, Z80_addw,   rHL,        rIY         },
  { 0x8C, Z80_adc,    rA,         rIYU        },
  { 0x8D, Z80_adc,    rA,         rIYL        },
  { 0x8E, Z80_adc,    rA,         iy8         },
  { 0x8F, Z80_adcw,   rHL,        rIY         },
  { 0x8F, Z80_adcw,   rIY                     },
  { 0x94, Z80_sub,    rA,         rIYU        },
  { 0x95, Z80_sub,    rA,         rIYL        },
  { 0x96, Z80_sub,    rA,         iy8         },
  { 0x97, Z80_subw,   rHL,        rIY         },
  { 0x9C, Z80_sbc,    rA,         rIYU        },
  { 0x9D, Z80_sbc,    rA,         rIYL        },
  { 0x9E, Z80_sbc,    rA,         iy8         },
  { 0x9F, Z80_sbcw,   rHL,        rIY         },
  { 0xA4, Z80_and,    rA,         rIYU        },
  { 0xA5, Z80_and,    rA,         rIYL        },
  { 0xA6, Z80_and,    rA,         iy8         },
  { 0xA7, Z80_andw,   rHL,        rIY         },
  { 0xAC, Z80_xor,    rA,         rIYU        },
  { 0xAD, Z80_xor,    rA,         rIYL        },
  { 0xAE, Z80_xor,    rA,         iy8         },
  { 0xAF, Z80_xorw,   rHL,        rIY         },
  { 0xB4, Z80_or,     rA,         rIYU        },
  { 0xB5, Z80_or,     rA,         rIYL        },
  { 0xB6, Z80_or,     rA,         iy8         },
  { 0xB7, Z80_orw,    rHL,        rIY         },
  { 0xBC, Z80_cp,     rA,         rIYU        },
  { 0xBD, Z80_cp,     rA,         rIYL        },
  { 0xBE, Z80_cp,     rA,         iy8         },
  { 0xBF, Z80_cpw,    rHL,        rIY         },
  { 0xC0, Z80_ddir,   rLW                     },
  { 0xC1, Z80_ddir,   rIB,        rLW         },
  { 0xC2, Z80_ddir,   rIW,        rLW         },
  { 0xC3, Z80_ddir,   rIW                     },
  { 0xC4, Z80_calr,   ccNZ,       rip24       },
  { 0xC6, Z80_addw,   iy8                     },
  { 0xC6, Z80_addw,   rHL,        iy8         },
  { 0xCC, Z80_calr,   ccZ,        rip24       },
  { 0xCD, Z80_calr,   rip24                   },
  { 0xCE, Z80_adcw,   rHL,        iy8         },
  { 0xD0, Z80_ldctl,  rA,         rYSR        },
  { 0xD3, Z80_outaw,  imm16,      rHL         },
  { 0xD4, Z80_calr,   ccNC,       rip24       },
  { 0xD6, Z80_subw,   rHL,        iy8         },
  { 0xD8, Z80_ldctl,  rYSR,       rA          },
  { 0xD9, Z80_exxy,                           },
  { 0xDA, Z80_ldctl,  rYSR,       imm8        },
  { 0xDB, Z80_inaw,   rHL,        imm16       },
  { 0xDC, Z80_calr,   ccC,        rip24       },
  { 0xDE, Z80_sbcw,   rHL,        iy8         },
  { 0xE1, Z80_pop,    rIY                     },
  { 0xE3, Z80_ex,     atSP,       rIY         },
  { 0xE4, Z80_calr,   ccPO,       rip24       },
  { 0xE5, Z80_push,   rIY                     },
  { 0xE6, Z80_andw,   rHL,        iy8         },
  { 0xE9, Z80_jp,     atIY                    },
  { 0xEC, Z80_calr,   ccPE,       rip24       },
  { 0xEE, Z80_xorw,   rHL,        iy8         },
  { 0xF4, Z80_calr,   ccP,        rip24       },
  { 0xF5, Z80_push,   imm16                   },
  { 0xF6, Z80_orw,    rHL,        iy8         },
  { 0xF7, Z80_setc,   rXM                     },
  { 0xF9, Z80_ld,     rSP,        rIY         },
  { 0xFC, Z80_calr,   ccM,        rip24       },
  { 0xFE, Z80_cpw,    rHL,        iy8         },
  { 0x00, 0 },
};

// the next byte after FDBC is in saved_value
static const insndesc_t cmdsFDCB[] =
{
  { 0x02, Z80_rlcw,   iys                     },
  { 0x03, Z80_ld,     rBC,        iys         },
  { 0x06, Z80_rlc,    iys                     },
  { 0x0A, Z80_rrcw,   iys                     },
  { 0x0B, Z80_ld,     iys,        rBC         },
  { 0x0E, Z80_rrc,    iys                     },
  { 0x12, Z80_rlw,    iys                     },
  { 0x13, Z80_ld,     rDE,        iys         },
  { 0x16, Z80_rl,     iys                     },
  { 0x1A, Z80_rrw,    iys                     },
  { 0x1B, Z80_ld,     iys,        rDE         },
  { 0x1E, Z80_rr,     iys                     },
  { 0x21, Z80_ld,     rIY,        sps         },
  { 0x22, Z80_slaw,   iys                     },
  { 0x23, Z80_ld,     rIX,        iys         },
  { 0x26, Z80_sla,    iys                     },
  { 0x29, Z80_ld,     sps,        rIY         },
  { 0x2A, Z80_sraw,   iys                     },
  { 0x2B, Z80_ld,     iys,        rIX         },
  { 0x2E, Z80_sra,    iys                     },
  { 0x33, Z80_ld,     rHL,        iys         },
  { 0x3A, Z80_srlw,   iys                     },
  { 0x3B, Z80_ld,     iys,        rHL         },
  { 0x3E, Z80_srl,    iys                     },
  { 0x46, Z80_bit,    c0,         iys         },
  { 0x4E, Z80_bit,    c1,         iys         },
  { 0x56, Z80_bit,    c2,         iys         },
  { 0x5E, Z80_bit,    c3,         iys         },
  { 0x66, Z80_bit,    c4,         iys         },
  { 0x6E, Z80_bit,    c5,         iys         },
  { 0x76, Z80_bit,    c6,         iys         },
  { 0x7E, Z80_bit,    c7,         iys         },
  { 0x86, Z80_res,    c0,         iys         },
  { 0x8E, Z80_res,    c1,         iys         },
  { 0x92, Z80_multw,  iys                     },
  { 0x92, Z80_multw,  rHL,        iys         },
  { 0x96, Z80_res,    c2,         iys         },
  { 0x9A, Z80_multuw, iys                     },
  { 0x9A, Z80_multuw, rHL,        iys         },
  { 0x9E, Z80_res,    c3,         iys         },
  { 0xA6, Z80_res,    c4,         iys         },
  { 0xAE, Z80_res,    c5,         iys         },
  { 0xB6, Z80_res,    c6,         iys         },
  { 0xBA, Z80_divuw,  iys                     },
  { 0xBA, Z80_divuw,  rHL,        iys         },
  { 0xBE, Z80_res,    c7,         iys         },
  { 0xC6, Z80_set,    c0,         iys         },
  { 0xCE, Z80_set,    c1,         iys         },
  { 0xD6, Z80_set,    c2,         iys         },
  { 0xDE, Z80_set,    c3,         iys         },
  { 0xE6, Z80_set,    c4,         iys         },
  { 0xEE, Z80_set,    c5,         iys         },
  { 0xF6, Z80_set,    c6,         iys         },
  { 0xFE, Z80_set,    c7,         iys         },
  { 0x00, 0 },
};

static const insndesc_t cmdsED[] =
{
  { 0x00, Z80_in0,    rB,         imm8        },
  { 0x01, Z80_out0,   imm8,       rB          },
  { 0x02, Z80_ld,     rBC,        rBC         },
  { 0x03, Z80_ex,     rBC,        rIX         },
  { 0x04, Z80_tst,    rB                      },
  { 0x05, Z80_ex,     rBC,        rDE         },
  { 0x06, Z80_ldw,    atBC,       imm16       },
  { 0x07, Z80_ex,     rA,         rB          },
  { 0x08, Z80_in0,    rC,         imm8        },
  { 0x09, Z80_out0,   imm8,       rC          },
  { 0x0B, Z80_ex,     rBC,        rIY         },
  { 0x0C, Z80_tst,    rC                      },
  { 0x0D, Z80_ex,     rBC,        rHL         },
  { 0x0E, Z80_swap,   rBC                     },
  { 0x0F, Z80_ex,     rA,         rC          },
  { 0x10, Z80_in0,    rD,         imm8        },
  { 0x11, Z80_out0,   imm8,       rD          },
  { 0x12, Z80_ld,     rDE,        rBC         },
  { 0x13, Z80_ex,     rDE,        rIX         },
  { 0x14, Z80_tst,    rD                      },
  { 0x16, Z80_ldw,    atDE,       imm16       },
  { 0x17, Z80_ex,     rA,         rD          },
  { 0x18, Z80_in0,    rE,         imm8        },
  { 0x19, Z80_out0,   imm8,       rE          },
  { 0x1B, Z80_ex,     rDE,        rIY         },
  { 0x1C, Z80_tst,    rE                      },
  { 0x1E, Z80_swap,   rDE                     },
  { 0x1F, Z80_ex,     rA,         rE          },
  { 0x20, Z80_in0,    rH,         imm8        },
  { 0x21, Z80_out0,   imm8,       rH          },
  { 0x24, Z80_tst,    rH                      },
  { 0x27, Z80_ex,     rA,         rH          },
  { 0x28, Z80_in0,    rL,         imm8        },
  { 0x29, Z80_out0,   imm8,       rL          },
  { 0x2B, Z80_ex,     rIX,        rIY         },
  { 0x2C, Z80_tst,    rL                      },
  { 0x2F, Z80_ex,     rA,         rL          },
  { 0x30, Z80_in0,    imm8                    },
  { 0x32, Z80_ld,     rHL,        rBC         },
  { 0x33, Z80_ex,     rHL,        rIX         },
  { 0x34, Z80_tst,    atHL                    },
  { 0x36, Z80_ldw,    atHL,       imm16       },
  { 0x37, Z80_ex,     rA,         atHL        },
  { 0x38, Z80_in0,    rA,         imm8        },
  { 0x39, Z80_out0,   imm8,       rA          },
  { 0x3B, Z80_ex,     rHL,        rIY         },
  { 0x3C, Z80_tst,    rA                      },
  { 0x3E, Z80_swap,   rHL                     },
  { 0x3F, Z80_ex,     rA,         rA          },
  { 0x40, Z80_in,     rB,         atC         },
  { 0x41, Z80_out,    atC,        rB          },
  { 0x42, Z80_sbc,    rHL,        rBC         },
  { 0x43, Z80_ld,     mem16,      rBC         },
  { 0x44, Z80_neg,    rA                      },
  { 0x45, Z80_retn,                           },
  { 0x46, Z80_im,     c0                      },
  { 0x47, Z80_ld,     rI,         rA          },
  { 0x48, Z80_in,     rC,         atC         },
  { 0x49, Z80_out,    atC,        rC          },
  { 0x4A, Z80_adc,    rHL,        rBC         },
  { 0x4B, Z80_ld,     rBC,        mem16       },
  { 0x4C, Z80_mlt,    rBC                     },
  { 0x4D, Z80_reti,                           },
  { 0x4E, Z80_im,     c3                      },
  { 0x4F, Z80_ld,     rR,         rA          },
  { 0x50, Z80_in,     rD,         atC         },
  { 0x51, Z80_out,    atC,        rD          },
  { 0x52, Z80_sbc,    rHL,        rDE         },
  { 0x53, Z80_ld,     mem16,      rDE         },
  { 0x54, Z80_negw,   rHL                     },
  { 0x56, Z80_im,     c1                      },
  { 0x57, Z80_ld,     rA,         rI          },
  { 0x58, Z80_in,     rE,         atC         },
  { 0x59, Z80_out,    atC,        rE          },
  { 0x5A, Z80_adc,    rHL,        rDE         },
  { 0x5B, Z80_ld,     rDE,        mem16       },
  { 0x5C, Z80_mlt,    rDE                     },
  { 0x5E, Z80_im,     c2                      },
  { 0x5F, Z80_ld,     rA,         rR          },
  { 0x60, Z80_in,     rH,         atC         },
  { 0x61, Z80_out,    atC,        rH          },
  { 0x62, Z80_sbc,    rHL,        rHL         },
  { 0x64, Z80_tst,    imm8                    },
  { 0x65, Z80_exts,   rA                      },
  { 0x67, Z80_rrd,                            },
  { 0x68, Z80_in,     rL,         atC         },
  { 0x69, Z80_out,    atC,        rL          },
  { 0x6A, Z80_adc,    rHL,        rHL         },
  { 0x6C, Z80_mlt,    rHL                     },
  { 0x6F, Z80_rld,                            },
  { 0x71, Z80_out,    atC,        imm8        },
  { 0x72, Z80_sbc,    rHL,        rSP         },
  { 0x73, Z80_ld,     mem16,      rSP         },
  { 0x74, Z80_tstio,  imm8                    },
  { 0x75, Z80_extsw,  rHL                     },
  { 0x76, Z80_slp,                            },
  { 0x78, Z80_in,     rA,         atC         },
  { 0x79, Z80_out,    atC,        rA          },
  { 0x7A, Z80_adc,    rHL,        rSP         },
  { 0x7B, Z80_ld,     rSP,        mem16       },
  { 0x7C, Z80_mlt,    rSP                     },
  { 0x82, Z80_add,    rSP,        imm16       },
  { 0x83, Z80_otim,                           },
  { 0x84, Z80_addw,   rHL,        rBC         },
  { 0x85, Z80_addw,   rHL,        rDE         },
  { 0x86, Z80_addw,   rHL,        imm16       },
  { 0x87, Z80_addw,   rHL,        rHL         },
  { 0x8B, Z80_otdm,                           },
  { 0x8C, Z80_adcw,   rHL,        rBC         },
  { 0x8D, Z80_adcw,   rHL,        rDE         },
  { 0x8E, Z80_adcw,   rHL,        imm16       },
  { 0x8F, Z80_adcw,   rHL,        rHL         },
  { 0x92, Z80_sub,    rSP,        imm16       },
  { 0x93, Z80_otimr,                          },
  { 0x94, Z80_subw,   rHL,        rBC         },
  { 0x95, Z80_subw,   rHL,        rDE         },
  { 0x96, Z80_subw,   rHL,        imm16       },
  { 0x97, Z80_subw,   rHL,        rHL         },
  { 0x9B, Z80_otdmr,                          },
  { 0x9C, Z80_sbcw,   rHL,        rBC         },
  { 0x9D, Z80_sbcw,   rHL,        rDE         },
  { 0x9E, Z80_sbcw,   rHL,        imm16       },
  { 0x9F, Z80_sbcw,   rHL,        rHL         },
  { 0xA0, Z80_ldi,                            },
  { 0xA1, Z80_cpi,                            },
  { 0xA2, Z80_ini,                            },
  { 0xA3, Z80_outi,                           },
  { 0xA4, Z80_andw,   rHL,        rBC         },
  { 0xA5, Z80_andw,   rHL,        rDE         },
  { 0xA6, Z80_andw,   rHL,        imm16       },
  { 0xA7, Z80_andw,   rHL,        rHL         },
  { 0xA8, Z80_ldd,                            },
  { 0xA9, Z80_cpd,                            },
  { 0xAA, Z80_ind,                            },
  { 0xAB, Z80_outd,                           },
  { 0xAC, Z80_xorw,   rHL,        rBC         },
  { 0xAD, Z80_xorw,   rHL,        rDE         },
  { 0xAE, Z80_xorw,   rHL,        imm16       },
  { 0xAF, Z80_xorw,   rHL,        rHL         },
  { 0xB0, Z80_ldir,                           },
  { 0xB1, Z80_cpir,                           },
  { 0xB2, Z80_inir,                           },
  { 0xB3, Z80_otir,                           },
  { 0xB4, Z80_orw,    rHL,        rBC         },
  { 0xB5, Z80_orw,    rHL,        rDE         },
  { 0xB6, Z80_orw,    rHL,        imm16       },
  { 0xB7, Z80_orw,    rHL,        rHL         },
  { 0xB8, Z80_lddr,                           },
  { 0xB9, Z80_cpdr,                           },
  { 0xBA, Z80_indr,                           },
  { 0xBB, Z80_otdr,                           },
  { 0xBC, Z80_cpw,    rHL,        rBC         },
  { 0xBD, Z80_cpw,    rHL,        rDE         },
  { 0xBE, Z80_cpw,    rHL,        imm16       },
  { 0xBF, Z80_cpw,    rHL,        rHL         },
  { 0xC0, Z80_ldctl,  rHL,        rSR         },
  { 0xC1, Z80_pop,    rSR                     },
  { 0xC4, Z80_calr,   ccNZ,       rip8        },
  { 0xC5, Z80_push,   rSR                     },
  { 0xC6, Z80_add,    rHL,        mem16       },
  { 0xC8, Z80_ldctl,  rSR,        rHL         },
  { 0xCC, Z80_calr,   ccZ,        rip8        },
  { 0xCD, Z80_calr,   rip8                    },
  { 0xCF, Z80_btest,                          },
  { 0xD0, Z80_ldctl,  rA,         rDSR        },
  { 0xD3, Z80_outa,   mem16,      rA          },
  { 0xD4, Z80_calr,   ccNC,       rip8        },
  { 0xD6, Z80_sub,    rHL,        mem16       },
  { 0xD8, Z80_ldctl,  rDSR,       rA          },
  { 0xD9, Z80_exall,                          },
  { 0xDA, Z80_ldctl,  rDSR,       imm8        },
  { 0xDB, Z80_ina,    rA,         mem16       },
  { 0xDC, Z80_calr,   ccC,        rip8        },
  { 0xE0, Z80_ldiw,                           },
  { 0xE2, Z80_iniw,                           },
  { 0xE3, Z80_outiw,                          },
  { 0xE4, Z80_calr,   ccPO,       rip8        },
  { 0xE8, Z80_lddw,                           },
  { 0xEA, Z80_indw,                           },
  { 0xEB, Z80_outdw,                          },
  { 0xEC, Z80_calr,   ccPE,       rip8        },
  { 0xF0, Z80_ldirw,                          },
  { 0xF2, Z80_inirw,                          },
  { 0xF3, Z80_otirw,                          },
  { 0xF4, Z80_calr,   ccP,        rip8        },
  { 0xF7, Z80_setc,   rLCK                    },
  { 0xF8, Z80_lddrw,                          },
  { 0xFA, Z80_indrw,                          },
  { 0xFB, Z80_otdrw,                          },
  { 0xFC, Z80_calr,   ccM,        rip8        },
  { 0xFF, Z80_resc,   rLCK                    },
};

static const insndesc_t cmdsEDCB[] =
{
  { 0x00, Z80_rlcw,   rBC                     },
  { 0x01, Z80_rlcw,   rDE                     },
  { 0x02, Z80_rlcw,   atHL                    },
  { 0x03, Z80_rlcw,   rHL                     },
  { 0x04, Z80_rlcw,   rIX                     },
  { 0x05, Z80_rlcw,   rIY                     },
  { 0x08, Z80_rrcw,   rBC                     },
  { 0x09, Z80_rrcw,   rDE                     },
  { 0x0A, Z80_rrcw,   atHL                    },
  { 0x0B, Z80_rrcw,   rHL                     },
  { 0x0C, Z80_rrcw,   rIX                     },
  { 0x0D, Z80_rrcw,   rIY                     },
  { 0x10, Z80_rlw,    rBC                     },
  { 0x11, Z80_rlw,    rDE                     },
  { 0x12, Z80_rlw,    atHL                    },
  { 0x13, Z80_rlw,    rHL                     },
  { 0x14, Z80_rlw,    rIX                     },
  { 0x15, Z80_rlw,    rIY                     },
  { 0x18, Z80_rrw,    rBC                     },
  { 0x19, Z80_rrw,    rDE                     },
  { 0x1A, Z80_rrw,    atHL                    },
  { 0x1B, Z80_rrw,    rHL                     },
  { 0x1C, Z80_rrw,    rIX                     },
  { 0x1D, Z80_rrw,    rIY                     },
  { 0x20, Z80_slaw,   rBC                     },
  { 0x21, Z80_slaw,   rDE                     },
  { 0x22, Z80_slaw,   atHL                    },
  { 0x23, Z80_slaw,   rHL                     },
  { 0x24, Z80_slaw,   rIX                     },
  { 0x25, Z80_slaw,   rIY                     },
  { 0x28, Z80_sraw,   rBC                     },
  { 0x29, Z80_sraw,   rDE                     },
  { 0x2A, Z80_sraw,   atHL                    },
  { 0x2B, Z80_sraw,   rHL                     },
  { 0x2C, Z80_sraw,   rIX                     },
  { 0x2D, Z80_sraw,   rIY                     },
  { 0x30, Z80_ex,     rBC,        rBC2        },
  { 0x31, Z80_ex,     rDE,        rDE2        },
  { 0x33, Z80_ex,     rHL,        rHL2        },
  { 0x34, Z80_ex,     rIX,        rIX2        },
  { 0x35, Z80_ex,     rIY,        rIY2        },
  { 0x38, Z80_srlw,   rBC                     },
  { 0x39, Z80_srlw,   rDE                     },
  { 0x3A, Z80_srlw,   atHL                    },
  { 0x3B, Z80_srlw,   rHL                     },
  { 0x3C, Z80_srlw,   rIX                     },
  { 0x3D, Z80_srlw,   rIY                     },
  { 0x90, Z80_multw,  rHL,        rBC         },
  { 0x91, Z80_multw,  rHL,        rDE         },
  { 0x93, Z80_multw,  rHL,        rHL         },
  { 0x94, Z80_multw,  rHL,        rIX         },
  { 0x95, Z80_multw,  rHL,        rIY         },
  { 0x97, Z80_multw,  rHL,        imm16       },
  { 0x98, Z80_multuw, rHL,        rBC         },
  { 0x99, Z80_multuw, rHL,        rDE         },
  { 0x9B, Z80_multuw, rHL,        rHL         },
  { 0x9C, Z80_multuw, rHL,        rIX         },
  { 0x9D, Z80_multuw, rHL,        rIY         },
  { 0x9F, Z80_multuw, rHL,        imm16       },
  { 0xB8, Z80_divuw,  rHL,        rBC         },
  { 0xB9, Z80_divuw,  rHL,        rDE         },
  { 0xBB, Z80_divuw,  rHL,        rHL         },
  { 0xBC, Z80_divuw,  rHL,        rIX         },
  { 0xBD, Z80_divuw,  rHL,        rIY         },
  { 0xBF, Z80_divuw,  rHL,        imm16       },
};

//------------------------------------------------------------------------
void z80_t::load_z80_operand(insn_t &insn, op_t &x, uchar op)
{
  if ( op == 0 )
    return;
  switch ( op )
  {
    case rBC:
    case rDE:
    case rHL:
    case rIX:
    case rIY:
    case rBC2:
    case rDE2:
    case rHL2:
    case rIX2:
    case rIY2:
    case rSP:
    case rLW:
    case rIXL:
    case rIXU:
    case rDSR:
    case rXSR:
    case rIYL:
    case rIYU:
    case rYSR:
    case rSR:
    case rIB:
    case rIW:
    case rXM:
    case rLCK:
      x.dtype = dt_word;
      // fallthrough
    case rA:
    case rB:
    case rC:
    case rD:
    case rE:
    case rH:
    case rL:
    case rI:
    case rW:
    case rR:
      x.type = o_reg;
      x.reg = op - 1;
      break;

    case atBC:
      x.type = o_phrase;
      x.phrase = R_bc;
      break;
    case atDE:
      x.type = o_phrase;
      x.phrase = R_de;
      break;
    case atHL:
      x.type = o_phrase;
      x.phrase = R_hl;
      break;
    case atSP:
      x.type = o_phrase;
      x.phrase = R_sp;
      break;
    case atIX:
      x.type = o_phrase;
      x.phrase = R_ix;
      break;
    case atIY:
      x.type = o_phrase;
      x.phrase = R_iy;
      break;
    case atC:
      x.type = o_phrase;
      x.phrase = R_c;
      break;

    case rip8:
      {
        sval_t disp = char(insn.get_next_byte());
        x.type = o_near;
        x.addr = insn.ip + insn.size + disp;
      }
      break;
    case rip16:
      {
        sval_t disp = short(insn.get_next_word());
        x.type = o_near;
        x.addr = insn.ip + insn.size + disp;
      }
      break;
    case rip24:
      {
        sval_t disp = insn.get_next_word();
        disp |= (sval_t((char)(insn.get_next_byte())) << 16);
        x.type = o_near;
        x.addr = insn.ip + insn.size + disp;
      }
      break;

    case imm8:
      x.type = o_imm;
      x.value = insn.get_next_byte();
      break;

    case imm16:
      x.type = o_imm;
      x.dtype = dt_word;
      x.value = insn.get_next_word();
      break;

    case mem16:
      x.type = o_mem;
      x.addr = insn.get_next_word();
      break;

    case ix8:
      x.type = o_displ;
      x.phrase = R_ix;
      x.addr = insn.get_next_byte();
      break;
    case iy8:
      x.type = o_displ;
      x.phrase = R_iy;
      x.addr = insn.get_next_byte();
      break;
    case ixs:
      x.type = o_displ;
      x.phrase = R_ix;
      x.addr = saved_value;
      break;
    case iys:
      x.type = o_displ;
      x.phrase = R_iy;
      x.addr = saved_value;
      break;
    case sps:
      x.type = o_displ;
      x.phrase = R_sp;
      x.addr = saved_value;
      break;

    case ccNZ:
    case ccZ:
    case ccNC:
    case ccC:
    case ccPO:
    case ccPE:
    case ccP:
    case ccM:
      x.type = o_cond;
      x.Cond = op - ccNZ;
      break;

    case c0:
    case c1:
    case c2:
    case c3:
    case c4:
    case c5:
    case c6:
    case c7:
      x.type = o_imm;
      x.value = op - c0;
      break;

    default:
      warning("%a: interr in z380, code=%x", insn.ea, code);
  }
}

//------------------------------------------------------------------------
bool z80_t::search_map(insn_t &insn, const insndesc_t *map, uchar _code)
{
  for ( int i=0; map[i].itype; i++ )
  {
    if ( map[i].code > _code )
      break;
    if ( map[i].code == _code )
    {
      insn.itype = map[i].itype;
      load_z80_operand(insn, insn.Op1, map[i].op1);
      load_z80_operand(insn, insn.Op2, map[i].op2);
      return true;
    }
  }
  return false;
}

//------------------------------------------------------------------------
bool z80_t::z380_insns(insn_t &insn, const insndesc_t *map, const insndesc_t *cb)
{
  code = insn.get_next_byte();
  if ( code == 0xCB )
  {
    map = cb;
    saved_value = insn.get_next_byte();
    code = insn.get_next_byte();
  }
  return search_map(insn, map, (uchar)code);
}

//------------------------------------------------------------------------
bool z80_t::z380_ED(insn_t &insn)
{
  const insndesc_t *map = cmdsED;
  code = insn.get_next_byte();
  if ( code == 0xCB )
  {
    map = cmdsEDCB;
    code = insn.get_next_byte();
  }
  return search_map(insn, map, (uchar)code);
}

//------------------------------------------------------------------------
void z80_t::z80_ixcommands(insn_t &insn, bool _isx)
{
  if ( isGB() )
    return;
  if ( isZ380() )
  {
    if ( _isx )
      z380_insns(insn, cmdsDD, cmdsDDCB);
    else
      z380_insns(insn, cmdsFD, cmdsFDCB);
    return;
  }

  isx = _isx;
  code = insn.get_next_byte();
  switch ( (code>>4) & 0xF )
  {
    case 0:                             /* 0000???? */
    case 1:                             /* 0001???? */
      if ( (code & 0xF) == 9 )
      {
        insn.itype = I5_add;
        op_ix(insn.Op1);
        op_ss(insn.Op2);
        insn.Op1.dtype = dt_word;
        insn.Op2.dtype = dt_word;
      }
      break;
    case 2:                             /* 0010???? */
      insn.Op1.dtype = dt_word;
      insn.Op2.dtype = dt_word;
      (code & 4) ? op_ibyte(insn.Op1,code & 8) : op_ix(insn.Op1);
      switch ( code & 0xF )
      {
        case 1:
          insn.itype = I5_lxi;
          op_nn(insn, insn.Op2);
          break;
        case 2:
          insn.itype = I5_mov;
          op_mm(insn, insn.Op1);
          op_ix(insn.Op2);
          break;
        case 3:
          insn.itype = I5_inx;
          break;
        case 4:
        case 0xC:
          insn.itype = I5_inr;
          break;
        case 5:
        case 0xD:
          insn.itype = I5_dcr;
          break;
        case 6:
        case 0xE:
          insn.itype = I5_mvi;
          op_n(insn, insn.Op2);
          break;
        case 9:
          insn.itype = I5_add;
          op_ix(insn.Op2);
          break;
        case 0xA:
          insn.itype = I5_mov;
          op_mm(insn, insn.Op2);
          break;
        case 0xB:
          insn.itype = I5_dcx;
          break;
      }
      break;
    case 3:
      switch ( code & 0xF )
      {
        case 4:
          insn.itype = I5_inr;
          op_xdispl(insn, insn.Op1);
          break;
        case 5:
          insn.itype = I5_dcr;
          op_xdispl(insn, insn.Op1);
          break;
        case 6:
          insn.itype = I5_mvi;
          op_xdispl(insn, insn.Op1);
          op_n(insn, insn.Op2);
          break;
        case 9:
          insn.itype = I5_add;
          op_ix(insn.Op1);
          op_ss(insn.Op2);
          insn.Op1.dtype = dt_word;
          insn.Op2.dtype = dt_word;
          break;
      }
      break;
    case 4:
    case 5:
      if ( (code & 6) == 4 )
      {
        insn.itype = I5_mov;
        op_xr1(insn.Op1);
        op_ibyte(insn.Op2,code & 1);
        break;
      }
      /* no break */
    case 6:
      if ( (code & 6) == 4 )
        break;
      if ( (code & 7) == 6 )
      {
        if ( op_xr1(insn.Op1) )
          break;   // mem,mem not allowed
        if ( code == 0x66 )
          insn.Op1.reg = R_h;
        if ( code == 0x6E )
          insn.Op1.reg = R_l;
        op_xdispl(insn, insn.Op2);
        insn.itype = I5_mov;
        break;
      }
      if ( (code & 0xF0) == 0x60 )
      {
        op_ibyte(insn.Op1,code & 8);
        op_xr2(insn.Op2);
        insn.itype = I5_mov;
      }
      break;
    case 7:
      switch ( code & 0xF )
      {
        case 0: case 1: case 2: case 3: case 4: case 5: case 7:
          op_xdispl(insn, insn.Op1);
          if ( !op_xr2(insn.Op2) )
            insn.itype = I5_mov;
          if ( code == 0x74 )
            insn.Op2.reg = R_h;
          if ( code == 0x75 )
            insn.Op2.reg = R_l;
          break;
        case 0xE:
          op_xdispl(insn, insn.Op2);
          op_a(insn.Op1);
          insn.itype = I5_mov;           // to show all regs
          break;
        case 0xC:
        case 0xD:
          op_ibyte(insn.Op2,code & 1);
          op_a(insn.Op1);
          insn.itype = I5_mov;           // to show all regs
          break;
      }
      break;
    case 8:
    case 9:
    case 0xA:
    case 0xB:
      if ( (code & 4) == 4 && (code & 7) != 7 )
      {
        int type = (code >> 3) & 7;
        insn.itype = W[type];
        op_a(insn.Op1);
        ((code & 7) == 6) ? op_xdispl(insn, insn.Op2)
                          : op_ibyte(insn.Op2,code & 1);
//      if ( type == 0 || type == 1 || type == 3 ) insn.Op1.clr_show();
      }
      break;
    case 0xC:
      if ( code == 0xCB )
      {
        op_xdispl(insn, insn.Op2);
        code = insn.get_next_byte();
        if ( (code & 7) == 6 )
        {
          int type = (code>>6) & 3;
          if ( type == 0 )
          {
            insn.itype = CBrols[ (code >> 3) & 7 ];
            op_a(insn.Op1);
          }
          else
          {
            static const uint16 brs[] = { I5_null, Z80_bit, Z80_res, Z80_set };
            insn.itype = brs[type];
            insn.Op1.type = o_imm;
            insn.Op1.value = (code >> 3) & 7;
          }
        }
      }
      break;
    case 0xE:
      switch ( code & 0xF )
      {
        case 1:
          insn.itype = I5_pop;
          op_ix(insn.Op1);
          break;
        case 3:
          insn.itype = Z80_ex;
          insn.Op1.type   = o_phrase;
          insn.Op1.phrase = R_sp;
          insn.Op1.dtype  = dt_word;
          op_ix(insn.Op2);
          break;
        case 5:
          insn.itype = I5_push;
          op_ix(insn.Op1);
          break;
        case 9:
          insn.itype = Z80_jp;
          insn.Op1.type = o_cond;
          insn.Op1.Cond = oc_not;
          insn.Op2.type   = o_phrase;
          insn.Op2.phrase = isx ? R_ix : R_iy;
          insn.Op2.dtype  = dt_code;
          break;
        case 0xD:
          code = insn.get_next_byte();
          switch ( code )
          {
            case 0x42:
            case 0x4A:
            case 0x52:
            case 0x5A:
            case 0x62:
            case 0x6A:
            case 0x72:
            case 0x7A:
              insn.itype = (code & 8) ? I5_adc : Z80_sbc;
              op_ix(insn.Op1);
              op_ss(insn.Op2);
              if ( insn.Op2.reg == R_hl )
                op_ix(insn.Op2);
              break;
            case 0x60:
            case 0x68:
              insn.itype = I5_in;
              op_ibyte(insn.Op1,code & 8);
              op_c(insn.Op2);
              break;
            case 0x61:
            case 0x69:
              insn.itype = I5_out;
              op_c(insn.Op1);
              op_ibyte(insn.Op2,code & 8);
              break;
          }
          break;
      }
      // fallthrough
    case 0xF:
      if ( code == 0xF9 )
      {
        insn.itype = I5_mov;
        insn.Op1.type   = o_reg;
        insn.Op1.phrase = R_sp;
        insn.Op1.dtype  = dt_word;
        op_ix(insn.Op2);
      }
      break;
  }
}


//------------------------------------------------------------------------
void z80_t::z80_misc(insn_t &insn)
{
  code = insn.get_next_byte();
  switch ( code )
  {
    case 0x40:
    case 0x48:
    case 0x50:
    case 0x58:
    case 0x60:
    case 0x68:
    case 0x78:
      insn.itype = I5_in;
      op_r1(insn.Op1);
      op_c(insn.Op2);
      break;
    case 0x41:
    case 0x49:
    case 0x51:
    case 0x59:
    case 0x61:
    case 0x69:
    case 0x79:
      insn.itype = I5_out;
      op_c(insn.Op1);
      op_r1(insn.Op2);
      break;
    case 0x42:
    case 0x4A:
    case 0x52:
    case 0x5A:
    case 0x62:
    case 0x6A:
    case 0x72:
    case 0x7A:
      insn.itype = (code & 8) ? I5_adc : Z80_sbc;
      insn.Op1.type  = o_reg;
      insn.Op1.reg   = R_hl;
      insn.Op1.dtype = dt_word;
      op_ss(insn.Op2);
      break;
    case 0x43:
    case 0x53:
    case 0x73:
      insn.itype = I5_mov;
      op_mm(insn, insn.Op1);
      op_ss(insn.Op2);
      insn.Op1.dtype  = dt_word;
      insn.Op2.dtype  = dt_word;
      break;
    case 0x44:  insn.itype = Z80_neg;    break;
    case 0x45:  insn.itype = Z80_retn;   break;
    case 0x46:
      insn.itype = Z80_im;
      insn.Op1.type = o_imm;
      insn.Op1.value = 0;
      break;
    case 0x47:
      insn.itype = I5_mov;               // to show all regs
      insn.Op1.type = o_reg;
      insn.Op1.reg = R_i;
      op_a(insn.Op2);
      break;
    case 0x4B:
    case 0x5B:
    case 0x7B:
      insn.itype = I5_mov;
      op_ss(insn.Op1);
      op_mm(insn, insn.Op2);
      insn.Op1.dtype  = dt_word;
      insn.Op2.dtype  = dt_word;
      break;
    case 0x4D:
      insn.itype = Z80_reti;
      break;
    case 0x4F:
      insn.itype = I5_mov;               // to show all regs
      insn.Op1.type = o_reg;
      insn.Op1.reg = R_r;
      op_a(insn.Op2);
      break;
    case 0x56:
      insn.itype = Z80_im;
      insn.Op1.type = o_imm;
      insn.Op1.value = 1;
      break;
    case 0x5E:
      insn.itype = Z80_im;
      insn.Op1.type = o_imm;
      insn.Op1.value = 2;
      break;
    case 0x57:
      insn.itype = I5_mov;               // to show all regs
      op_a(insn.Op1);
      insn.Op2.type = o_reg;
      insn.Op2.reg = R_i;
      break;
    case 0x5F:
      insn.itype = I5_mov;               // to show all regs
      op_a(insn.Op1);
      insn.Op2.type = o_reg;
      insn.Op2.reg = R_r;
      break;
    case 0x67:  insn.itype = Z80_rrd;    break;
    case 0x6F:  insn.itype = Z80_rld;    break;

    case 0xA0:  insn.itype = Z80_ldi;    break;
    case 0xA1:  insn.itype = Z80_cpi;    break;
    case 0xA2:  insn.itype = Z80_ini;    break;
    case 0xA3:  insn.itype = Z80_outi;   break;
    case 0xA8:  insn.itype = Z80_ldd;    break;
    case 0xA9:  insn.itype = Z80_cpd;    break;
    case 0xAA:  insn.itype = Z80_ind;    break;
    case 0xAB:  insn.itype = Z80_outd;   break;
    case 0xB0:  insn.itype = Z80_ldir;   break;
    case 0xB1:  insn.itype = Z80_cpir;   break;
    case 0xB2:  insn.itype = Z80_inir;   break;
    case 0xB3:  insn.itype = Z80_otir;   break;
    case 0xB8:  insn.itype = Z80_lddr;   break;
    case 0xB9:  insn.itype = Z80_cpdr;   break;
    case 0xBA:  insn.itype = Z80_indr;   break;
    case 0xBB:  insn.itype = Z80_otdr;   break;
//
//      HD64180 extensions
//
    case 0x76:  if ( is64180() ) insn.itype = HD_slp;    break;
    case 0x83:  if ( is64180() ) insn.itype = HD_otim;   break;
    case 0x93:  if ( is64180() ) insn.itype = HD_otimr;  break;
    case 0x8B:  if ( is64180() ) insn.itype = HD_otdm;   break;
    case 0x9B:  if ( is64180() ) insn.itype = HD_otdmr;  break;
    case 0x64:
      if ( is64180() )
      {
        insn.itype = HD_tst;
        op_n(insn, insn.Op1);
      }
      break;
    case 0x74:
      if ( is64180() )
      {
        insn.itype = HD_tstio;
        op_n(insn, insn.Op1);
      }
      break;
    default:
// I did not find an assembler that understands this...
//      if ( (code & 0xC0) == 0x40 && (code & 6) == 0 )        // undocumented
//      {
//        insn.itype = (code & 1) ? I5_out : I5_in;
//        op_r1(insn.Op1);
//        break;
//      }
//--------
      if ( is64180() )
      {
        switch ( code & 0xC0 )
        {
          case 0:
            switch ( code & 7 )
            {
              case 0:
                insn.itype = HD_in0;
                op_r1(insn.Op1);
                op_n(insn, insn.Op2);
                if ( insn.Op1.type == o_phrase )
                  op_f(insn.Op1);
                break;
              case 1:
                insn.itype = HD_out0;
                op_n(insn, insn.Op1);
                op_r1(insn.Op2);
                break;
              case 4:
                insn.itype = HD_tst;
                op_r1(insn.Op1);
                break;
            }
            break;
          case 0x40:
            if ( code == 0x70 )
            {
              insn.itype = I5_in;
              op_f(insn.Op1);
              op_c(insn.Op2);
              break;
            }
            if ( (code & 0xF) == 0xC )
            {
              insn.itype = HD_mlt;
              op_ss(insn.Op1);
            }
            break;
        }
      }
      break;
  }
}
