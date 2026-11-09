/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"

//----------------------------------------------------------------------
static void loadoper(insn_t &insn, op_t *Op, uint16 nibble)
{
  ushort base;
  switch ( nibble )
  {
    case 027:
      {
        flags64_t F1 = get_flags(insn.ea);
        flags64_t F2 = get_flags(insn.ea+insn.size);
        Op->type = o_imm;
        Op->ill_imm = is_head(F1) ? !is_tail(F2) : is_head(F2);
        Op->offb = (uchar)insn.size;
        Op->value = insn.get_next_word();
      }
      break;
    case 037:
    case 077:
    case 067:
      Op->type = o_mem;
      Op->offb = (uchar)insn.size;
      base = insn.get_next_word();
      if ( (Op->phrase = nibble) != 037 )
        base += (short)(insn.ip + insn.size);
      Op->addr16 = base;
      break;
    default:
      if ( (nibble & 070) == 0 )
      {
        Op->type = o_reg;
        Op->reg = nibble;
      }
      else
      {
        Op->phrase = nibble;
        if ( nibble < 060 )
        {
          Op->type = o_phrase;
        }
        else
        {
          Op->type = o_displ;
          Op->offb = (uchar)insn.size;
          Op->addr16 = insn.get_next_word();
        }
      }
      break;
  }
}

//----------------------------------------------------------------------
void pdp11_t::jmpoper(insn_t &insn, op_t *Op, uint16 nibble)
{
  loadoper(insn, Op, nibble);
  if ( Op->type == o_mem && Op->phrase != 077 )
    Op->type = o_near;
  if ( Op->type == o_near
    && Op->addr16 >= ml.ovrcallbeg
    && Op->addr16 <= ml.ovrcallend )
  {
    uint32 trans = (uint32)ovrtrans.altval(Op->addr16);
// msg("addr=%o, trans=%lo\n", Op->addr16, trans);
    if ( trans != 0 )
    {
      segment_t *S = getseg(trans);
      if ( S != nullptr )
      {
        Op->type = o_far;
        Op->segval = (uint16)S->sel;
        Op->addr16 = (ushort)(trans - to_ea(Op->segval,0));
      }
    }
  }
}

//----------------------------------------------------------------------
int pdp11_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  static const char twoop[5] = { pdp_mov, pdp_cmp, pdp_bit, pdp_bic, pdp_bis };
  static const char onecmd[12] =
  {
    pdp_clr, pdp_com, pdp_inc, pdp_dec,
    pdp_neg, pdp_adc, pdp_sbc, pdp_tst, pdp_ror, pdp_rol,
    pdp_asr, pdp_asl
  };
  static const char cc2com[8] =
  {
    pdp_bpl, pdp_bmi, pdp_bhi, pdp_blos,
    pdp_bvc, pdp_bvs, pdp_bcc, pdp_bcs
  };

  if ( insn.ip & 1 )
    return 0;

  insn.Op1.dtype = insn.Op2.dtype = dt_word;
//  insn.bytecmd = 0;

  uint code = insn.get_next_word();

  uchar nibble0 = (code & 077);
  uchar nibble1 = (code >> 6 ) & 077;
  uchar nibble2 = (code >> 12) & 017;
  uchar nib1swt = nibble1 >> 3;

  switch ( nibble2 )
  {
    case 017:
      if ( nibble1 == 0 )
      {
        switch ( nibble0 )
        {
          case   0: insn.itype = pdp_cfcc; break;
          case   1: insn.itype = pdp_setf; break;
          case   2: insn.itype = pdp_seti; break;
          case 011: insn.itype = pdp_setd; break;
          case 012: insn.itype = pdp_setl; break;
          default:  return 0;
        }
        break;
      }
      loadoper(insn, &insn.Op1, nibble0);
      if ( nib1swt != 0 )
      {
        static const char fpcom2[14] =
        {
          pdp_muld, pdp_modd, pdp_addd,
          pdp_ldd, pdp_subd, pdp_cmpd, pdp_std, pdp_divd, pdp_stexp,
          pdp_stcdi, pdp_stcdf, pdp_ldexp, pdp_ldcif, pdp_ldcfd
        };
        insn.Op2.type = o_fpreg;
        insn.Op2.reg = (nibble1 & 3);
        insn.Op2.dtype = dt_double;
        int idx = (nibble1 >> 2) - 2;
        QASSERT(10084, idx >= 0 && idx < qnumber(fpcom2));
        insn.itype = fpcom2[idx];
        if ( insn.itype != pdp_ldexp && insn.itype != pdp_stexp )
        {
          if ( insn.Op1.type == o_reg )
            insn.Op1.type = o_fpreg;
          if ( insn.itype != pdp_stcdi && insn.itype != pdp_ldcif )
            insn.Op1.dtype = dt_double;
        }
        if ( insn.itype == pdp_std
          || insn.itype == pdp_stexp
          || insn.itype == pdp_stcdi
          || insn.itype == pdp_stcdf )
        {
          op_t temp;
          temp = insn.Op2;
          insn.Op2 = insn.Op1;
          insn.Op1 = temp;
          insn.Op1.n = 0;
          insn.Op2.n = 1;
        }
      }
      else
      {
        static const char fpcom1[7] =
        {
          pdp_ldfps, pdp_stfps, pdp_stst, pdp_clrd,
          pdp_tstd, pdp_absd, pdp_negd
        };
        if ( nibble1 >= 4 )
        {
          insn.Op1.dtype = insn.Op2.dtype = dt_double;
          if ( insn.Op1.type == o_reg )
            insn.Op1.type = o_fpreg;
        }
        QASSERT(10085, (nibble1-1) >= 0 && nibble1-1 < qnumber(fpcom1));
        insn.itype = fpcom1[nibble1 - 1];   //lint !e676 possibly indexing before the beginning of an allocation
      }
      break;

    case 7:
      switch ( nib1swt )
      {
        case 6:           // CIS
          return 0;
        case 5:          // FIS
          {
            static const char ficom[4] = { pdp_fadd, pdp_fsub, pdp_fmul, pdp_fdiv };
            if ( nibble1 != 050 || nibble0 >= 040 )
              return 0;
            insn.Op1.type = o_reg;
            insn.Op1.reg = nibble0 & 7;
            insn.itype = ficom[nibble0 >> 3];
            break;
          }
        case 7:         // SOB
          insn.itype = pdp_sob;
          insn.Op1.type = o_reg;
          insn.Op1.reg = nibble1 & 7;
          insn.Op2.type = o_near;
          insn.Op2.phrase = 0;
          insn.Op2.addr16 = (ushort)(insn.ip + 2 - (2*nibble0));
          break;
        default:
          {
            static const char eiscom[5] = { pdp_mul, pdp_div, pdp_ash, pdp_ashc, pdp_xor };
            insn.Op2.type = o_reg;
            insn.Op2.reg = nibble1 & 7;
            loadoper(insn, &insn.Op1, nibble0);
            insn.itype = eiscom[nib1swt];
            break;
          }
      }
      break;

    case 016:
      insn.itype = pdp_sub;
      goto twoopcmd;
    case   6:
      insn.itype = pdp_add;
      goto twoopcmd;
    default:                      // Normal 2 op
      insn.itype = twoop[(nibble2 & 7) - 1];
      insn.bytecmd = ((nibble2 & 010) != 0);
twoopcmd:
      loadoper(insn, &insn.Op1, nibble1);
      loadoper(insn, &insn.Op2, nibble0);
      break;

    case 010:
      if ( nibble1 >= 070 )
        return 0;
      if ( nibble1 >= 064 )
      {
        static const char mt1cmd[4] = { pdp_mtps, pdp_mfpd, pdp_mtpd, pdp_mfps };
        insn.itype = mt1cmd[nibble1 - 064];
        loadoper(insn, &insn.Op1, nibble0);
        break;
      }
      if ( nibble1 >= 050 )
      {
        insn.bytecmd = 1;
oneoper:
        loadoper(insn, &insn.Op1, nibble0);
        insn.itype = onecmd[nibble1 - 050];
        break;
      }
      if ( nibble1 >= 040 )
      {
        insn.Op1.type = o_number;             // EMT/TRAP
        insn.Op1.value = code & 0377;
        insn.itype = (nibble1 >= 044) ? pdp_trap : pdp_emt;
        break;
      }
      insn.itype = cc2com[nibble1 >> 2];
condoper:
      insn.Op1.type = o_near;
      insn.Op1.phrase = 0;
      insn.Op1.addr16 = (ushort)(insn.ip + insn.size + (2*(short)((char)code)));
      break;

    case 0:
      if ( nibble1 >= 070 )
        return 0;
      if ( nibble1 > 064 )
      {
        static const char mt2cmd[3] = { pdp_mfpi, pdp_mtpi, pdp_sxt };
        insn.itype = mt2cmd[nibble1 - 065];
        loadoper(insn, &insn.Op1, nibble0);
        break;
      }
      if ( nibble1 == 064 )
      {
        insn.itype = pdp_mark;
        insn.Op1.type = o_number;
        insn.Op1.value = nibble0;
        break;
      }
      if ( nibble1 >= 050 )
        goto oneoper;
      if ( nibble1 >= 040 )
      {
        if ( (nibble1 & 7) == 7 )
        {
          insn.itype = pdp_call;
          jmpoper(insn, &insn.Op1, nibble0);
        }
        else
        {
          insn.itype = pdp_jsr;
          insn.Op1.type = o_reg;
          insn.Op1.reg = nibble1 & 7;
          jmpoper(insn, &insn.Op2, nibble0);
        }
        break;
      }
      switch ( nibble1 )
      {
        case 3:
          insn.itype = pdp_swab;
          loadoper(insn, &insn.Op1, nibble0);
          break;
        case 1:
          insn.itype = pdp_jmp;
          jmpoper(insn, &insn.Op1, nibble0);
          break;
        case 2:
          if ( nibble0 == 7 )
          {
            insn.itype = pdp_return;
            break;
          }
          if ( nibble0 < 7 )
          {
            insn.itype = pdp_rts;
            insn.Op1.type = o_reg;
            insn.Op1.reg = nibble0;
            break;
          }
          if ( nibble0 < 030 )
            return 0;
          if ( nibble0 < 040 )
          {
            insn.itype = pdp_spl;
            insn.Op1.value = nibble0 & 7;
            insn.Op1.type = o_number;
            break;
          }
          switch ( nibble0 & 037 )
          {
            case 000: insn.itype = pdp_nop; break;
            case 001: insn.itype = pdp_clc; break;
            case 002: insn.itype = pdp_clv; break;
            case 004: insn.itype = pdp_clz; break;
            case 010: insn.itype = pdp_cln; break;
            case 017: insn.itype = pdp_ccc; break;
            case 021: insn.itype = pdp_sec; break;
            case 022: insn.itype = pdp_sev; break;
            case 024: insn.itype = pdp_sez; break;
            case 030: insn.itype = pdp_sen; break;
            case 037: insn.itype = pdp_scc; break;
            default:
              insn.itype = pdp_compcc;
              insn.Op1.phrase = nibble0 & 037;
              break;
          }
          break;
        case 0:
          {
            static const char misc0[16] =
            {
              pdp_halt, pdp_wait, pdp_rti, pdp_bpt,
              pdp_iot, pdp_reset, pdp_rtt, pdp_mfpt
            };
            if ( nibble0 > 7 )
              return 0;
            insn.itype = misc0[nibble0];
            break;
          }
        default:          // >=4
          {
            static const char lcc2com[7] =
            {
              pdp_br, pdp_bne, pdp_beq, pdp_bge,
              pdp_blt, pdp_bgt, pdp_ble
            };
            insn.itype = lcc2com[(nibble1 >> 2) - 1];
            goto condoper;
          }
      }
      break;
  }

  if ( insn.bytecmd )
  {
    if ( insn.Op1.type == o_mem && insn.Op1.phrase != 077
      || insn.Op1.type == o_displ && (insn.Op1.phrase & 070) == 060 )
    {
      insn.Op1.dtype = dt_byte;
    }
    if ( insn.Op2.type == o_mem && insn.Op2.phrase != 077
      || insn.Op2.type == o_displ && (insn.Op2.phrase & 070) == 060 )
    {
      insn.Op2.dtype = dt_byte;
    }
  }

  if ( insn.Op1.type == o_imm && insn.Op1.ill_imm )
    insn.size -= 2;
  if ( insn.Op2.type == o_imm && insn.Op2.ill_imm )
    insn.size -= 2;

  return int(insn.size);
}
