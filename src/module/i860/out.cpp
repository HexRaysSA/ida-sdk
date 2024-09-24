/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//----------------------------------------------------------------------
class out_i860_t : public outctx_t
{
  out_i860_t(void) = delete; // not used
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_i860_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_i860_t)

//----------------------------------------------------------------------
bool out_i860_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;
    case o_displ:
      out_value(x, OOF_ADDR|OOFW_32);
      goto common;
    case o_phrase:
      OutReg(int(x.addr));
common:
      {
        int s2 = char(x.reg);
        if ( s2 != 0 )
        {
          out_symbol('(');
          OutReg(s2 < 0 ? -s2 : s2);
          out_symbol(')');
          if ( char(x.reg) < 0 )
          {
            out_symbol('+');
            out_symbol('+');
          }
        }
      }
      break;
    case o_imm:
      out_value(x, OOF_SIGNED|OOFW_32);
      break;
    case o_mem:
    case o_near:
      if ( !out_name_expr(x, x.addr, x.addr) )
      {
        out_value(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
      }
      break;
    case o_void:
      return 0;
    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_i860_t::out_insn(void)
{
  {
    out_tagon(COLOR_INSN);
    const char *cname = insn.get_canon_mnem(ph);
    int i = 16 - (inf_get_indent() & 7);
    if ( insn.auxpref & Dbit )
    {
      out_char('d');
      out_char('.');
      i -= 2;
    }
    while ( *cname != 0 )
    {
      out_char(*cname++);
      i--;
    }
    switch ( insn.itype )
    {
      case I860_fadd:
      case I860_pfadd:
      case I860_famov:
      case I860_pfamov:
      case I860_fiadd:
      case I860_pfiadd:
      case I860_fisub:
      case I860_pfisub:
      case I860_fix:
      case I860_pfix:
      case I860_fmul:
      case I860_pfmul:
      case I860_frcp:
      case I860_frsqr:
      case I860_fsub:
      case I860_pfsub:
      case I860_ftrunc:
      case I860_pftrunc:
      case I860_pfeq:
      case I860_pfgt:
      case I860_pfle:
      case I860_r2p1:
      case I860_r2pt:
      case I860_r2ap1:
      case I860_r2apt:
      case I860_i2p1:
      case I860_i2pt:
      case I860_i2ap1:
      case I860_i2apt:
      case I860_rat1p2:
      case I860_m12apm:
      case I860_ra1p2:
      case I860_m12ttpa:
      case I860_iat1p2:
      case I860_m12tpm:
      case I860_ia1p2:
      case I860_m12tpa:
      case I860_r2s1:
      case I860_r2st:
      case I860_r2as1:
      case I860_r2ast:
      case I860_i2s1:
      case I860_i2st:
      case I860_i2as1:
      case I860_i2ast:
      case I860_rat1s2:
      case I860_m12asm:
      case I860_ra1s2:
      case I860_m12ttsa:
      case I860_iat1s2:
      case I860_m12tsm:
      case I860_ia1s2:
      case I860_m12tsa:
      case I860_mr2p1:
      case I860_mr2pt:
      case I860_mr2mp1:
      case I860_mr2mpt:
      case I860_mi2p1:
      case I860_mi2pt:
      case I860_mi2mp1:
      case I860_mi2mpt:
      case I860_mrmt1p2:
      case I860_mm12mpm:
      case I860_mrm1p2:
      case I860_mm12ttpm:
      case I860_mimt1p2:
      case I860_mm12tpm:
      case I860_mim1p2:
      case I860_mr2s1:
      case I860_mr2st:
      case I860_mr2ms1:
      case I860_mr2mst:
      case I860_mi2s1:
      case I860_mi2st:
      case I860_mi2ms1:
      case I860_mi2mst:
      case I860_mrmt1s2:
      case I860_mm12msm:
      case I860_mrm1s2:
      case I860_mm12ttsm:
      case I860_mimt1s2:
      case I860_mm12tsm:
      case I860_mim1s2:
        out_char('.');
        out_char( (insn.auxpref & Sbit) ? 'd' : 's');
        out_char( (insn.auxpref & Rbit) ? 'd' : 's');
        i -= 3;
        break;
      case I860_fld:
      case I860_fst:
      case I860_ld:
      case I860_ldint:
      case I860_ldio:
      case I860_pfld:
      case I860_scyc:
      case I860_st:
      case I860_stio:
        out_char('.');
        switch ( insn.Op1.dtype )
        {
          case dt_byte:         out_char('b');   break;
          case dt_word:         out_char('s');   break;
          case dt_dword:        out_char('l');   break;
          case dt_qword:        out_char('d');   break;
          case dt_byte16:       out_char('q');   break;
        }
        i -= 2;
        break;
    }
    out_tagoff(COLOR_INSN);
    do
    {
      out_char(' ');
      i--;
    } while ( i > 0 );
  }

  bool comma = out_one_operand(0);

  if ( comma && insn.Op2.shown() && insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
  }

  out_one_operand(1);

  if ( comma && insn.Op3.shown() && insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
  }

  out_one_operand(2);

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void idaapi i860_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC);
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void i860_t::i860_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring sname;
  get_segm_name(&sname, Sarea);
  ctx.gen_printf(DEFAULT_INDENT, COLSTR(".text %s %s",SCOLOR_ASMDIR), ash.cmnt, sname.c_str());

  const char *p = ".byte";
  switch ( Sarea->align )
  {
    case saRelByte:   p = ".byte";    break;
    case saRelWord:   p = ".word";    break;
    case saRelPara:   p = ".float";   break;
  }
  ctx.gen_printf(DEFAULT_INDENT, COLSTR(".align %s", SCOLOR_ASMDIR), p);

  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT,
                     COLSTR("%s%s %s",SCOLOR_AUTOCMT),
                     ash.cmnt, ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void i860_t::i860_footer(outctx_t &ctx) const
{
  char buf[MAXSTR];
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    char *ptr = buf;
    char *end = buf + sizeof(buf);
    APPEND(ptr, end, ash.end);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, name.begin());
    }
    ctx.flush_buf(buf, DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}
