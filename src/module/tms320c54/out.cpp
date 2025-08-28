/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c54_t : public outctx_t
{
  out_tms320c54_t(void) = delete; // not used

  tms320c54_t &pm() { return *static_cast<tms320c54_t *>(procmod); }
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_address(ea_t ea, const op_t &x, bool mapping, bool at);
  void out_cond8(char value);
};
CASSERT(sizeof(out_tms320c54_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_tms320c54_t)

//----------------------------------------------------------------------
void out_tms320c54_t::out_address(ea_t ea, const op_t &x, bool mapping, bool at)
{
  regnum_t reg = pm().get_mapped_register(ea);
  if ( mapping && reg != rnone )
  {
    out_register(ph.reg_names[reg]);
  }
  else
  {
#ifndef TMS320C54_NO_NAME_NO_REF
    qstring qbuf;
    // since tms320c54 uses memory mapping, we turn off verification
    // of name expression values (4th arg of get_name_expr is BADADDR)
    if ( get_name_expr(&qbuf, insn.ea+x.offb, x.n, ea, BADADDR) > 0 )
    {
      if ( at )
        out_symbol('@');
      out_line(qbuf.begin());
    }
    else
#endif
    {
      out_tagon(COLOR_ERROR);
      out_value(x, OOF_ADDR|OOFW_32);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
  }
}

//----------------------------------------------------------------------
const char *get_cond8(char value)
{
  switch ( value )
  {
    case COND8_UNC:  return "unc";
    case COND8_NBIO: return "nbio";
    case COND8_BIO:  return "bio";
    case COND8_NC:   return "nc";
    case COND8_C:    return "c";
    case COND8_NTC:  return "ntc";
    case COND8_TC:   return "tc";
    case COND8_AGEQ: return "ageq";
    case COND8_ALT:  return "alt";
    case COND8_ANEQ: return "aneq";
    case COND8_AEQ:  return "aeq";
    case COND8_AGT:  return "agt";
    case COND8_ALEQ: return "aleq";
    case COND8_ANOV: return "anov";
    case COND8_AOV:  return "aov";
    case COND8_BGEQ: return "bgeq";
    case COND8_BLT:  return "blt";
    case COND8_BNEQ: return "bneq";
    case COND8_BEQ:  return "beq";
    case COND8_BGT:  return "bgt";
    case COND8_BLEQ: return "bleq";
    case COND8_BNOV: return "bnov";
    case COND8_BOV:  return "bov";
    default: return nullptr;
  }
}

//----------------------------------------------------------------------
void out_tms320c54_t::out_cond8(char value)
{
  const char *cond = get_cond8(value);
  QASSERT(256, cond != nullptr);
  out_line(cond, COLOR_REG);
}

//----------------------------------------------------------------------
bool out_tms320c54_t::out_operand(const op_t &x)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;

    case o_near:
    case o_far:
      ea = calc_code_mem(insn, x.addr, x.type == o_near);
      out_address(ea, x, false, false);
      break;

    case o_imm:
      {
        const char *name = nullptr;
        if ( pm().idpflags & TMS320C54_IO && x.IOimm )
          name = pm().find_sym(x.value);
        if ( !x.NoCardinal )
          out_symbol('#');
        if ( name != nullptr && name[0] != '\0' )
        {
          out_line(name, COLOR_IMPNAME);
        }
        else
        {
          if ( !x.Signed )
            out_value(x, OOFW_IMM);
          else
            out_value(x, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
        }
        break;
      }

    case o_local:
      out_value(x, OOF_ADDR|OOFW_32);
      break;

    case o_mmr:
    case o_mem:
    case o_farmem:
      if ( x.IndirectAddressingMOD == ABSOLUTE_INDIRECT_ADRESSING )
      {
        out_symbol('*');
        out_symbol('(');
      }
      ea = pm().calc_data_mem(insn, x.addr, x.type == o_mem);
      if ( ea != BADADDR )
      {
        // no '@' if absolute "indirect" adressing
        bool at = x.IndirectAddressingMOD != ABSOLUTE_INDIRECT_ADRESSING;
        out_address(ea, x, true, at);
      }
      else
      {
        out_value(x, OOF_ADDR|OOFW_32);
      }
      if ( x.IndirectAddressingMOD == ABSOLUTE_INDIRECT_ADRESSING )
        out_symbol(')');
      break;

    case o_displ: // Indirect addressing mode
      {
        char buf[8];
        const char *reg = ph.reg_names[x.reg];
        switch ( x.IndirectAddressingMOD )
        {
          case 0:
            qsnprintf(buf, sizeof(buf), "*%s",reg);
            out_register(buf);
            break;
          case 1:
            qsnprintf(buf, sizeof(buf), "*%s-",reg);
            out_register(buf);
            break;
          case 2:
            qsnprintf(buf, sizeof(buf), "*%s+",reg);
            out_register(buf);
            break;
          case 3:
            qsnprintf(buf, sizeof(buf), "*+%s",reg);
            out_register(buf);
            break;
          case 4:
            qsnprintf(buf, sizeof(buf), "*%s-0B",reg);
            out_register(buf);
            break;
          case 5:
            qsnprintf(buf, sizeof(buf), "*%s-0",reg);
            out_register(buf);
            break;
          case 6:
            qsnprintf(buf, sizeof(buf), "*%s+0",reg);
            out_register(buf);
            break;
          case 7:
            qsnprintf(buf, sizeof(buf), "*%s+0B",reg);
            out_register(buf);
            break;
          case 8:
            qsnprintf(buf, sizeof(buf), "*%s-%%",reg);
            out_register(buf);
            break;
          case 9:
            qsnprintf(buf, sizeof(buf), "*%s-0%%",reg);
            out_register(buf);
            break;
          case 0xA:
            qsnprintf(buf, sizeof(buf), "*%s+%%",reg);
            out_register(buf);
            break;
          case 0xB:
            qsnprintf(buf, sizeof(buf), "*%s+0%%",reg);
            out_register(buf);
            break;
          case 0xC:
            qsnprintf(buf, sizeof(buf), "*%s(",reg);
            out_register(buf);
            out_value(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            break;
          case 0xD:
            qsnprintf(buf, sizeof(buf), "*+%s(",reg);
            out_register(buf);
            out_value(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            break;
          case 0xE:
            qsnprintf(buf, sizeof(buf), "*+%s(",reg);
            out_register(buf);
            out_value(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
            out_symbol(')');
            out_symbol('%');
            break;
          // this special adressing mode is now defined as o_farmem !
          // case ABSOLUTE_INDIRECT_ADRESSING:
          //   out_symbol('*');
          //   out_symbol('(');
          //   out_value(x, OOF_ADDR|OOF_SIGNED|OOFW_16);
          //   out_symbol(')');
          //   break;
          default:
            error("interr: out: o_displ");
        }
        break;
      }

    case o_bit:
      {
        if ( !x.NoCardinal )
          out_symbol('#');
        char buf[20];
        qsnprintf(buf, sizeof(buf), "%d", int(x.value));
        out_line(buf, COLOR_REG);
        break;
      }

    case o_cond8:
      out_cond8((uchar)x.value);
      break;

    case o_cond2:
      {
        const char *cond = "";
        switch ( x.value )
        {
          case 0: cond = "eq";  break;
          case 1: cond = "lt";  break;
          case 2: cond = "gt";  break;
          case 3: cond = "neq"; break;
          default: warning("interr: out 2-bit condition");
        }
        out_line(cond, COLOR_REG);
        break;
      }

    default:
      error("interr: out");
  }
  return 1;
}

//----------------------------------------------------------------------
void out_tms320c54_t::out_insn(void)
{
  out_mnemonic();
  out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
    if ( insn.IsParallel )
    { // new line for Parallel instructions
      flush_outbuf();
      out_line("|| ", COLOR_INSN);
      const char *insn2 = nullptr;
      switch ( insn.itype )
      {
        case TMS320C54_ld_mac:  insn2 = "mac  "; break;
        case TMS320C54_ld_macr: insn2 = "macr "; break;
        case TMS320C54_ld_mas:  insn2 = "mas  "; break;
        case TMS320C54_ld_masr: insn2 = "masr "; break;
        case TMS320C54_st_add:  insn2 = "add  "; break;
        case TMS320C54_st_sub:  insn2 = "sub  "; break;
        case TMS320C54_st_ld:   insn2 = "ld   "; break;
        case TMS320C54_st_mpy:  insn2 = "mpy  "; break;
        case TMS320C54_st_mac:  insn2 = "mac  "; break;
        case TMS320C54_st_macr: insn2 = "macr "; break;
        case TMS320C54_st_mas:  insn2 = "mas  "; break;
        case TMS320C54_st_masr: insn2 = "masr "; break;
        default: warning("interr: out parallel instruction");
      }
      out_line(insn2, COLOR_INSN);
    }
    if ( insn.Op3.type != o_void )
    {
      if ( !insn.IsParallel )
      {
        out_symbol(',');
        out_char(' ');
      }
      out_one_operand(2);
      if ( insn.Op4_type != 0 )
      {
        out_symbol(',');
        out_char(' ');
        switch ( insn.Op4_type )
        {
          case o_reg:
            out_register(ph.reg_names[insn.Op4_value]);
            break;
          case o_cond8:
            out_cond8(insn.Op4_value);
            break;
          default:
            break;
        }
      }
    }
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void tms320c54_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    ctx.gen_cmt_line("assume %s = %s", ph.reg_names[reg], buf);
  }
  else
  {
    ctx.gen_cmt_line("drop %s", ph.reg_names[reg]);
  }
}

//--------------------------------------------------------------------------
// function to produce assume directives
//lint -e{1764} ctx could be const
void tms320c54_t::assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || seg == nullptr )
    return;
  bool seg_started = (ea == seg->start_ea);

  for ( int i = ph.reg_first_sreg; i <= ph.reg_last_sreg; ++i )
  {
    if ( i == ph.reg_code_sreg )
      continue;
    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) )
      continue;
    if ( seg_started || sra.start_ea == ea )
    {
      sel_t now = get_sreg(ea, i);
      sreg_range_t prev;
      bool prev_exists = ea > 0 && get_sreg_range(&prev, ea-1, i);
      if ( seg_started || (prev_exists && get_sreg(prev.start_ea, i) != now) )
        print_segment_register(ctx, i, now);
    }
  }
}

//--------------------------------------------------------------------------
//lint -e{818} seg could be const
void tms320c54_t::segstart(outctx_t &ctx, segment_t *seg) const
{
  if ( is_spec_segm(seg->type) )
    return;

  qstring sclas;
  get_segm_class(&sclas, seg);

  if ( sclas == "CODE" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( sclas == "DATA" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".data", SCOLOR_ASMDIR));

  if ( seg->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), seg->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL | GH_BYTESEX_HAS_HIGHBYTE);
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void tms320c54_t::footer(outctx_t &ctx) const
{
  ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s",SCOLOR_ASMDIR), ash.end);
}

//--------------------------------------------------------------------------
void tms320c54_t::gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  ctx.out_printf(COLSTR("%s",SCOLOR_KEYWORD) " "
                 COLSTR("%c%s",SCOLOR_DNUM)
                 COLSTR(",",SCOLOR_SYMBOL) " "
                 COLSTR("%s",SCOLOR_LOCNAME),
                 ash.a_equ,
                 sign,
                 vstr,
                 stkvar->name.c_str());
}

