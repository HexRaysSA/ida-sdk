/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"
#include "ins.hpp"

//----------------------------------------------------------------------
struct wsr_mapping_t
{
  ushort base;
  uchar wsr;
  uchar wsrbase;
  uchar wsr1base;
};

static const wsr_mapping_t mappings[] =
{
  { 0x0000, 0x10, 0x80, 0xFF },        // 0080-00FF
  { 0x0080, 0x11, 0x80, 0xFF },
  { 0x0100, 0x12, 0x80, 0xFF },
  { 0x0180, 0x13, 0x80, 0xFF },
  { 0x0200, 0x14, 0x80, 0xFF },
  { 0x0280, 0x15, 0x80, 0xFF },
  { 0x0300, 0x16, 0x80, 0xFF },
  { 0x0380, 0x17, 0x80, 0xFF },
  { 0x1F00, 0x1E, 0x80, 0xFF },
  { 0x1F80, 0x1F, 0x80, 0xFF },
  { 0x0000, 0x20, 0xC0, 0x40 },        // 00C0-00FF or 0040-007F
  { 0x0040, 0x21, 0xC0, 0x40 },
  { 0x0080, 0x22, 0xC0, 0x40 },
  { 0x00C0, 0x23, 0xC0, 0x40 },
  { 0x0100, 0x24, 0xC0, 0x40 },
  { 0x0140, 0x25, 0xC0, 0x40 },
  { 0x0180, 0x26, 0xC0, 0x40 },
  { 0x01C0, 0x27, 0xC0, 0x40 },
  { 0x0200, 0x28, 0xC0, 0x40 },
  { 0x0240, 0x29, 0xC0, 0x40 },
  { 0x0280, 0x2A, 0xC0, 0x40 },
  { 0x02C0, 0x2B, 0xC0, 0x40 },
  { 0x0300, 0x2C, 0xC0, 0x40 },
  { 0x0340, 0x2D, 0xC0, 0x40 },
  { 0x0380, 0x2E, 0xC0, 0x40 },
  { 0x03C0, 0x2F, 0xC0, 0x40 },
  { 0x1F00, 0x3C, 0xC0, 0x40 },
  { 0x1F40, 0x3D, 0xC0, 0x40 },
  { 0x1F80, 0x3E, 0xC0, 0x40 },
  { 0x1FC0, 0x3F, 0xC0, 0x40 },
  { 0x0000, 0x40, 0xE0, 0x60 },        // 00E0-00FF or 0060-007F
  { 0x0020, 0x41, 0xE0, 0x60 },
  { 0x0040, 0x42, 0xE0, 0x60 },
  { 0x0060, 0x43, 0xE0, 0x60 },
  { 0x0080, 0x44, 0xE0, 0x60 },
  { 0x00A0, 0x45, 0xE0, 0x60 },
  { 0x00C0, 0x46, 0xE0, 0x60 },
  { 0x00E0, 0x47, 0xE0, 0x60 },
  { 0x0100, 0x48, 0xE0, 0x60 },
  { 0x0120, 0x49, 0xE0, 0x60 },
  { 0x0140, 0x4A, 0xE0, 0x60 },
  { 0x0160, 0x4B, 0xE0, 0x60 },
  { 0x0180, 0x4C, 0xE0, 0x60 },
  { 0x01A0, 0x4D, 0xE0, 0x60 },
  { 0x01C0, 0x4E, 0xE0, 0x60 },
  { 0x01E0, 0x4F, 0xE0, 0x60 },
  { 0x0200, 0x50, 0xE0, 0x60 },
  { 0x0220, 0x51, 0xE0, 0x60 },
  { 0x0240, 0x52, 0xE0, 0x60 },
  { 0x0260, 0x53, 0xE0, 0x60 },
  { 0x0280, 0x54, 0xE0, 0x60 },
  { 0x02A0, 0x55, 0xE0, 0x60 },
  { 0x02C0, 0x56, 0xE0, 0x60 },
  { 0x02E0, 0x57, 0xE0, 0x60 },
  { 0x0300, 0x58, 0xE0, 0x60 },
  { 0x0320, 0x59, 0xE0, 0x60 },
  { 0x0340, 0x5A, 0xE0, 0x60 },
  { 0x0360, 0x5B, 0xE0, 0x60 },
  { 0x0380, 0x5C, 0xE0, 0x60 },
  { 0x03A0, 0x5D, 0xE0, 0x60 },
  { 0x03C0, 0x5E, 0xE0, 0x60 },
  { 0x03E0, 0x5F, 0xE0, 0x60 },
  { 0x1F00, 0x78, 0xE0, 0x60 },
  { 0x1F20, 0x79, 0xE0, 0x60 },
  { 0x1F40, 0x7A, 0xE0, 0x60 },
  { 0x1F60, 0x7B, 0xE0, 0x60 },
  { 0x1F80, 0x7C, 0xE0, 0x60 },
  { 0x1FA0, 0x7D, 0xE0, 0x60 },
  { 0x1FC0, 0x7E, 0xE0, 0x60 },
  { 0x1FE0, 0x7F, 0xE0, 0x60 },
};

static int NT_CDECL cmp(const void *x, const void *y)
{
  const wsr_mapping_t *a = (const wsr_mapping_t *)x;
  const wsr_mapping_t *b = (const wsr_mapping_t *)y;
  return a->wsr - b->wsr;
}

//----------------------------------------------------------------------
// perform WSR/WSR1 mapping
ea_t i196_t::map(ea_t iea, ea_t v) const
{
  if ( !extended )
    return v;
  if ( v < 0x40 )
    return v;
  sel_t wsr = get_sreg(iea, v < 0x80 ? WSR1 : WSR) & 0x7F;
  if ( wsr < 0x10 )
    return v;

  wsr_mapping_t key;
  key.wsr = (char)wsr;
  wsr_mapping_t *p = (wsr_mapping_t *)
                bsearch(&key, mappings, qnumber(mappings), sizeof(key), cmp);
  if ( p == nullptr )
    return v;

  int delta = v < 0x80 ? p->wsr1base : p->wsrbase;
  if ( v < delta )
    return v;
  return v - delta + p->base;
}

//----------------------------------------------------------------------
void i196_t::aop(insn_t &insn, uint code, op_t &op)
{
  switch ( code & 3 )
  {
    case 0:   // direct
      op.type = o_mem;
      op.addr = map(insn.ea, insn.get_next_byte());
      break;

    case 1:   // immediate
      op.type = o_imm;
      if ( (code & 0x10) == 0 && (code & 0xFC) != 0xAC ) // ldbze always baop
      {
        op.dtype = dt_word;
        op.value = insn.get_next_word();
      }
      else
      {
        op.value = insn.get_next_byte();
      }
      break;

    case 2:   // indirect
      op.dtype = dt_word;
      op.addr = insn.get_next_byte();
      op.type = (op.addr & 1) ? o_indirect_inc : o_indirect;
      op.addr = map(insn.ea, op.addr & ~1);
      break;

    case 3:   // indexed
      op.dtype = dt_word;
      op.type  = o_indexed;
      op.value = insn.get_next_byte();   // short (reg file)
      op.addr  = (op.value & 1) ? insn.get_next_word() : insn.get_next_byte();
      op.value = map(insn.ea, op.value & ~1);
  }
}

//----------------------------------------------------------------------
int i196_t::ld_st(insn_t &insn, ushort itype, char dtype, bool indirect, op_t &reg, op_t &mem)
{
  if ( !extended )
    return 0;
  insn.itype = itype;
  reg.dtype  = dtype;
  mem.dtype  = dtype;
  mem.addr   = insn.get_next_byte();
  if ( indirect ) // indirect
  {
    mem.type = (mem.addr & 1) ? o_indirect_inc : o_indirect;
    mem.addr = map(insn.ea, mem.addr & ~1);
  }
  else
  {
    mem.type  = o_indexed;
    mem.value = map(insn.ea, mem.addr);
    mem.addr  = insn.get_next_word();
    mem.addr |= insn.get_next_byte() << 16;
  }
  reg.type = o_mem;
  reg.addr = map(insn.ea, insn.get_next_byte());
  return insn.size;
}

//----------------------------------------------------------------------
int i196_t::ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;

  insn.Op1.dtype = dt_byte;
  insn.Op2.dtype = dt_byte;
  insn.Op3.dtype = dt_byte;

  uint code = insn.get_next_byte();

  uint nibble0 = (code & 0xF);
  uint nibble1 = (code >> 4);

  char offc;
  int32 off;
  uint tmp;

  if ( nibble1 < 2 )   // 0,1
  {
    static const char cmd01[] =
    {
      I196_skip, I196_clr,  I196_not,   I196_neg,
      I196_xch,  I196_dec,  I196_ext,   I196_inc,
      I196_shr,  I196_shl,  I196_shra,  I196_xch,
      I196_shrl, I196_shll, I196_shral, I196_norml,
      I196_null, I196_clrb, I196_notb,  I196_negb,
      I196_xchb, I196_decb, I196_extb,  I196_incb,
      I196_shrb, I196_shlb, I196_shrab, I196_xchb,
      I196_est,  I196_est,  I196_estb,  I196_estb
    };

    insn.itype = cmd01[code & 0x1F];

    if ( insn.itype == I196_null )
      return 0;   // unknown instruction

    switch ( code )
    {
      case 0x4: case 0x14:  // xch reg,aop        direct
      case 0xB: case 0x1B:  // xch reg,aop        indexed
        if ( (code & 0x10) == 0 )
          insn.Op2.dtype = dt_word;
        aop(insn, code, insn.Op2);
        insn.Op1.addr = map(insn.ea, insn.get_next_byte());
        insn.Op1.type = o_mem;
        break;

      case 0xF:             // norml lreg,breg
        insn.Op2.addr = map(insn.ea, insn.get_next_byte());
        insn.Op2.type = o_mem;
        insn.Op1.addr = map(insn.ea, insn.get_next_byte());
        insn.Op1.type = o_mem;
        break;

      case 0x1C:                 // est.indirect
      case 0x1D:                 // est.indexed
        return ld_st(insn, I196_est, dt_word, code == 0x1C, insn.Op1, insn.Op2);

      case 0x1E:                 // estb.indirect
      case 0x1F:                 // estb.indexed
        return ld_st(insn, I196_estb, dt_byte, code == 0x1E, insn.Op1, insn.Op2);

      default:              // shifts
        tmp = insn.get_next_byte();
        if ( tmp < 16 )
        {
          insn.Op2.value = tmp;
          insn.Op2.type  = o_imm;
        }
        else
        {
          insn.Op2.addr = map(insn.ea, tmp);
          insn.Op2.type = o_mem;
        }
        // fallthrough

      case 0x0:  case 0x1:  case 0x2:  case 0x3:
      case 0x5:  case 0x6:  case 0x7:  case 0x11:
      case 0x12: case 0x13: case 0x15: case 0x16: case 0x17:
        insn.Op1.addr = map(insn.ea, insn.get_next_byte());
        insn.Op1.type = o_mem;
    }

    switch ( code )
    {
      case 0x1: case 0x2: case 0x3: case 0x4: case 0x5:
      case 0x7: case 0x8: case 0x9: case 0xA: case 0xB: case 0x16:
        insn.Op1.dtype = dt_word;
        break;

      case 0x6: case 0xC: case 0xD: case 0xE: case 0xF:
        insn.Op1.dtype = dt_dword;
        break;
    }
  }
  else if ( nibble1 < 4 )    // 2,3
  {
    static const char cmd23[] = { I196_sjmp, I196_scall, I196_jbc, I196_jbs };

    insn.itype = cmd23[ ((code - 0x20) >> 3) & 3 ];

    if ( nibble1 == 2 )      // sjmp/scall
    {
      insn.Op1.type = o_near;
      off = insn.get_next_byte() + ((code & 7) << 8);
      if ( off & 0x400 )
        off |= ~0x7FF;
      else
        off &= 0x7FF;  // make signed
      insn.Op1.addr = truncate(insn.ip + insn.size + off);     // signed addition
//      insn.Op1.dtype = dt_word;
    }
    else                    // jbc/jbs
    {
      insn.Op2.type = o_bit;
      insn.Op2.reg  = code & 7;
      insn.Op1.addr = map(insn.ea, insn.get_next_byte());
      insn.Op1.type = o_mem;
      insn.Op3.type = o_near;
      offc = insn.get_next_byte();
      insn.Op3.addr = truncate(insn.ip + insn.size + offc);      // signed addition
//      insn.Op3.dtype = dt_word;
    }
  }
  else if ( nibble1 < 6 )    // 4,5
  {
    static const char cmd45[] =
    {
      I196_and3,  I196_add3,  I196_sub3,  I196_mulu3,
      I196_andb3, I196_addb3, I196_subb3, I196_mulub3
    };

    insn.itype = cmd45[ ((code - 0x40) >> 2) & 7 ];

    if ( (code & 0x10) == 0 )
      insn.Op1.dtype = insn.Op2.dtype = insn.Op3.dtype = dt_word;

    if ( (code & 0xc) == 0xc )   // mulu/mulub
      insn.Op1.dtype++;           // word->dword/byte->word

    aop(insn, code, insn.Op3);
    insn.Op2.addr  = map(insn.ea, insn.get_next_byte());
    insn.Op2.type  = o_mem;
    insn.Op1.addr  = map(insn.ea, insn.get_next_byte());
    insn.Op1.type  = o_mem;
  }
  else if ( nibble1 < 0xD )    // 6,7,8,9,A,B,C
  {
    static const char cmd6c[] =
    {
      I196_and2,  I196_add2,   I196_sub2,   I196_mulu2,
      I196_andb2, I196_addb2,  I196_subb2,  I196_mulub2,
      I196_or,    I196_xor,    I196_cmp,    I196_divu,
      I196_orb,   I196_xorb,   I196_cmpb,   I196_divub,
      I196_ld,    I196_addc,   I196_subc,   I196_ldbze,
      I196_ldb,   I196_addcb,  I196_subcb,  I196_ldbse,
      I196_st,    I196_stb,    I196_push,   I196_pop,
      I196_null,  I196_null,   I196_null,   I196_null,
    };

    insn.itype = cmd6c[ ((code - 0x60) >> 2) & 31 ];

    switch ( nibble1 )
    {
      case 6:     // and/add/sub/mulu
      case 8:     // or/xor/cmp/duvu
        insn.Op1.dtype = insn.Op2.dtype = dt_word;
        if ( (nibble0 & 0xC) == 0xC )
          insn.Op1.dtype++;   // mulu/divu
        break;

      case 0xA:   // ld/addc/subc/ldbze
        insn.Op1.dtype = insn.Op2.dtype = dt_word;
        if ( (nibble0 & 0xC) == 0xC )
          insn.Op2.dtype = dt_byte;   // ldbze
        break;
    }

    switch ( code & 0xFC )
    {
      case 0xC0:    // st
        insn.Op2.dtype = dt_word;

      case 0x7C: case 0x9C: case 0xBC: case 0xC8: case 0xCC:
        insn.Op1.dtype = dt_word;
    }

    switch ( code )
    {
      case 0xC1:
        insn.itype = I196_bmov;
        goto cont1;

      case 0xC5:
        insn.itype     = I196_cmpl;
        insn.Op2.dtype = dt_dword;
        goto cont2;

      case 0xCD:
        insn.itype = I196_bmovi;
cont1:
        insn.Op2.dtype = dt_word;
cont2:
        insn.Op2.addr = map(insn.ea, insn.get_next_byte());
        insn.Op2.type = o_mem;
        insn.Op1.dtype = dt_dword;
//        insn.Op1.addr = insn.get_next_byte();
//        insn.Op1.type = o_mem;
        goto cont3;

      default:
        if ( code > 0xC7 )
        {
          aop(insn, code, insn.Op1);
        }
        else
        {
          aop(insn, code, insn.Op2);
cont3:
          insn.Op1.addr  = map(insn.ea, insn.get_next_byte());
          insn.Op1.type  = o_mem;
        }
    }
  }
  else if ( nibble1 == 0xD )     // jcc
  {
    static const char cmdd[] =
    {
      I196_jnst, I196_jnh, I196_jgt, I196_jnc,
      I196_jnvt, I196_jnv, I196_jge, I196_jne,
      I196_jst,  I196_jh,  I196_jle, I196_jc,
      I196_jvt,  I196_jv,  I196_jlt, I196_je
    };

    insn.itype = cmdd[nibble0];

    insn.Op1.type = o_near;
    offc = insn.get_next_byte();
    insn.Op1.addr = truncate(insn.ip + insn.size + offc);      // signed addition
//    insn.Op1.dtype = dt_word;
  }
  else if ( nibble1 == 0xE )     // Ex
  {
    switch ( nibble0 )
    {
      case 0x0: case 0x1:       // djnz, djnzw
        if ( nibble0 & 1 )
        {
          insn.itype = I196_djnzw;
          insn.Op1.dtype = dt_word;
        }
        else
        {
          insn.itype = I196_djnz;
        }
        insn.Op1.type = o_mem;
        insn.Op1.addr = map(insn.ea, insn.get_next_byte());
        offc = insn.get_next_byte();
        insn.Op2.type = o_near;
        insn.Op2.addr = truncate(insn.ip + insn.size + offc);  // signed addition
        break;

      case 0x2:                 // tijmp
        insn.itype     = I196_tijmp;
        insn.Op1.dtype = insn.Op2.dtype = dt_word;
        insn.Op2.type  = o_indirect;
        insn.Op2.addr  = map(insn.ea, insn.get_next_byte());
        insn.Op3.type  = o_imm;
        insn.Op3.value = insn.get_next_byte();
        insn.Op1.type  = o_mem;
        insn.Op1.addr  = map(insn.ea, insn.get_next_byte());
        break;

      case 0x3:                 // br
        insn.itype = extended ? I196_ebr : I196_br;
        aop(insn, 2, insn.Op1);
        break;

      case 0x4:                 // ebmovi
        if ( !extended )
          return 0;
        insn.itype = I196_ebmovi;
        insn.Op1.type = o_mem;
        insn.Op1.addr = map(insn.ea, insn.get_next_byte());
        insn.Op2.type = o_mem;
        insn.Op2.addr = map(insn.ea, insn.get_next_byte());
        break;

      case 0x6:                 // ejmp
        if ( !extended )
          return 0;
        insn.itype    = I196_ejmp;
        insn.Op1.type = o_near;
        off = insn.get_next_word();
        off |= int32(insn.get_next_byte()) << 16;
        insn.Op1.addr = truncate(insn.ip + insn.size + off);   // signed addition
        break;

      case 0x8:                 // eld.indirect
      case 0x9:                 // eld.indexed
        return ld_st(insn, I196_eld, dt_word, nibble0 == 0x8, insn.Op1, insn.Op2);

      case 0xA:                 // eldb.indirect
      case 0xB:                 // eldb.indexed
        return ld_st(insn, I196_eldb, dt_byte, nibble0 == 0xA, insn.Op1, insn.Op2);

      case 0xC:                 // dpts
        insn.itype = I196_dpts;
        break;

      case 0xD:                 // epts
        insn.itype = I196_epts;
        break;

      case 0x7: case 0xF:       // ljmp, lcall
        insn.itype    = (nibble0 & 8) ? I196_lcall : I196_ljmp;
        insn.Op1.type = o_near;
        off = short(insn.get_next_word());
        insn.Op1.addr = truncate(insn.ip + insn.size + off);   // signed addition
        insn.Op1.dtype = dt_word;
        break;

      default:
        return 0;
    }
  }
  else
  {
    static const char cmdf[] =
    {
      I196_ret,   I196_ecall,I196_pushf, I196_popf,
      I196_pusha, I196_popa, I196_idlpd, I196_trap,
      I196_clrc,  I196_setc, I196_di,    I196_ei,
      I196_clrvt, I196_nop,  I196_null,  I196_rst
    };

    insn.itype = cmdf[nibble0];
    if ( nibble0 == 1 ) // ecall
    {
      if ( !extended )
        return 0;
      off = insn.get_next_word();
      off |= int32(insn.get_next_byte()) << 16;
      insn.Op1.type = o_near;
      insn.Op1.addr = truncate(insn.ip + insn.size + off);
    }
    else if ( nibble0 == 6 )        // idlpd
    {
      insn.Op1.type  = o_imm;
      insn.Op1.value = insn.get_next_byte();
    }
    else if ( nibble0 == 0xE ) // prefix
    {
      code = insn.get_next_byte();

      switch ( code & 0xFC )
      {
        case 0x4C: case 0x5C:
          if ( code & 0x10 )
          {
            insn.itype = I196_mulb3;
            insn.Op1.dtype = dt_word;
          }
          else
          {
            insn.itype = I196_mul3;
            insn.Op3.dtype = insn.Op2.dtype = dt_word;
            insn.Op1.dtype = dt_dword;
          }

          aop(insn, code, insn.Op3);
          insn.Op2.addr = map(insn.ea, insn.get_next_byte());
          insn.Op2.type = o_mem;
          insn.Op1.addr = map(insn.ea, insn.get_next_byte());
          insn.Op1.type = o_mem;
          break;

        case 0x6C: case 0x7C: case 0x8C: case 0x9C:
          insn.itype = (code & 0x80)
                    ? (code & 0x10) ? I196_divb  : I196_div
                    : (code & 0x10) ? I196_mulb2 : I196_mul2;

          if ( code & 0x10 )
          {
            insn.Op1.dtype = dt_word;
          }
          else
          {
            insn.Op1.dtype = dt_dword;
            insn.Op2.dtype = dt_word;
          }

          aop(insn, code, insn.Op2);
          insn.Op1.addr = map(insn.ea, insn.get_next_byte());
          insn.Op1.type = o_mem;
          break;

        default:
          return 0;
      }
    }
  }

  return insn.size;
}
