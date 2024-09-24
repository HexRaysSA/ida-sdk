/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st7.hpp"

//----------------------------------------------------------------------
class out_st7_t : public outctx_t
{
  out_st7_t(void) = delete; // not used
public:
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void outmem(const op_t &x, ea_t ea);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_st7_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_st7_t)

//----------------------------------------------------------------------
void out_st7_t::outmem(const op_t &x, ea_t ea)
{
  qstring qbuf;
  if ( get_name_expr(&qbuf, insn.ea+x.offb, x.n, ea, BADADDR) <= 0 )
  {
    st7_t &pm = *static_cast<st7_t *>(procmod);
    const ioport_t *p = pm.find_sym(x.addr);
    if ( p == nullptr )
    {
      out_tagon(COLOR_ERROR);
      out_btoa(x.addr, 16);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
    else
    {
      out_line(p->name.c_str(), COLOR_IMPNAME);
    }
  }
  else
  {
    bool complex = strchr(qbuf.begin(), '+') || strchr(qbuf.begin(), '-');
    if ( complex )
      out_symbol(ash.lbrace);
    out_line(qbuf.begin());
    if ( complex )
      out_symbol(ash.rbrace);
  }
}

//----------------------------------------------------------------------
bool out_st7_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_displ:
// o_displ Short     Direct   Indexed  ld A,($10,X)             00..1FE                + 1
// o_displ Long      Direct   Indexed  ld A,($1000,X)           0000..FFFF             + 2
      out_symbol('(');
      out_value(x, OOFS_IFSIGN
                       |OOF_ADDR
                       |((insn.auxpref & aux_16) ? OOFW_16 : OOFW_8));
      out_symbol(',');
      outreg(x.reg);
      out_symbol(')');
      break;

    case o_phrase:
      out_symbol('(');
      outreg(x.reg);
      out_symbol(')');
      break;

    case o_mem:
// o_mem   Short     Direct            ld A,$10                 00..FF                 + 1
// o_mem   Long      Direct            ld A,$1000               0000..FFFF             + 2
// o_mem   Short     Indirect          ld A,[$10]               00..FF     00..FF byte + 2
// o_mem   Long      Indirect          ld A,[$10.w]             0000..FFFF 00..FF word + 2
// o_mem   Short     Indirect Indexed  ld A,([$10],X)           00..1FE    00..FF byte + 2
// o_mem   Long      Indirect Indexed  ld A,([$10.w],X)         0000..FFFF 00..FF word + 2
// o_mem   Relative  Indirect          jrne [$10]               PC+/-127   00..FF byte + 2
// o_mem   Bit       Direct            bset $10,#7              00..FF                 + 1
// o_mem   Bit       Indirect          bset [$10],#7            00..FF     00..FF byte + 2
// o_mem   Bit       Direct   Relative btjt $10,#7,skip         00..FF                 + 2
// o_mem   Bit       Indirect Relative btjt [$10],#7,skip       00..FF     00..FF byte + 3
      if ( insn.auxpref & aux_index )
        out_symbol('(');
      if ( insn.auxpref & aux_indir )
        out_symbol('[');
      outmem(x, calc_mem(insn, x.addr));
      if ( insn.auxpref & aux_long )
      {
        out_symbol('.');
        out_symbol('w');
      }
      if ( insn.auxpref & aux_indir )
        out_symbol(']');
      if ( insn.auxpref & aux_index )
      {
        out_symbol(',');
        outreg(x.reg);
        out_symbol(')');
      }
      break;

    case o_near:
      outmem(x, calc_mem(insn, x.addr));
      break;

    default:
      INTERR(10379);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_st7_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }
  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, seg) could be made const
void idaapi st7_segstart(outctx_t &ctx, segment_t *seg)
{
  if ( is_spec_segm(seg->type) )
    return;

  const char *align;
  switch ( seg->align )
  {
    case saAbs:        align = "at: ";  break;
    case saRelByte:    align = "byte";  break;
    case saRelWord:    align = "word";  break;
    case saRelPara:    align = "para";  break;
    case saRelPage:    align = "page";  break;
    case saRel4K:      align = "4k";    break;
    case saRel64Bytes: align = "64";    break;
    default:           align = nullptr; break;
  }
  if ( align == nullptr )
  {
    ctx.gen_cmt_line("Segment alignment '%s' cannot be represented in assembly",
                     get_segment_alignment(seg->align));
    align = "";
  }

  qstring sname;
  qstring sclas;
  get_visible_segm_name(&sname, seg);
  get_segm_class(&sclas, seg);

  ctx.out_printf(SCOLOR_ON SCOLOR_ASMDIR "%-*s segment %s ",
                 inf_get_indent()-1,
                 sname.c_str(),
                 align);
  if ( seg->align == saAbs )
  {
    ea_t absbase = get_segm_base(seg);
    ctx.out_btoa(absbase);
    ctx.out_char(' ');
  }
  const char *comb;
  switch ( seg->comb )
  {
    case scPub:
    case scPub2:
    case scPub3:    comb = "";        break;
    case scCommon:  comb = "common";  break;
    default:        comb = nullptr;   break;
  }
  if ( comb == nullptr )
  {
    ctx.gen_cmt_line("Segment combination '%s' cannot be represented in assembly",
                     get_segment_combination(seg->comb));
    comb = "";
  }
  ctx.out_printf("%s '%s'", comb, sclas.c_str());
  ctx.out_tagoff(COLOR_ASMDIR);
  ctx.flush_outbuf(0);
}

//--------------------------------------------------------------------------
void idaapi st7_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi st7_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC | GH_PRINT_HEADER);
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void st7_t::st7_footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                   ash.end, ash.cmnt, name);
}

