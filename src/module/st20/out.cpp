/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"

//----------------------------------------------------------------------
class out_st20_t : public outctx_t
{
  out_st20_t(void) = delete; // not used
public:
  void outmem(const op_t &x, ea_t ea);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_st20_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_st20_t)

//----------------------------------------------------------------------
void out_st20_t::outmem(const op_t &x, ea_t ea)
{
  if ( !out_name_expr(x, ea, BADADDR) )
  {
    out_tagon(COLOR_ERROR);
    out_btoa(x.addr, 16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME,insn.ea);
  }
}

//----------------------------------------------------------------------
bool out_st20_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_imm:
      out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_near:
      outmem(x, calc_mem(insn, x.addr));
      break;

    default:
      INTERR(10377);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_st20_t::out_insn(void)
{
  out_mnemonic();
  out_one_operand(0);
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi st20_segstart(outctx_t &ctx, segment_t *Sarea)
{
  if ( is_spec_segm(Sarea->type) )
    return;

  qstring sname;
  get_visible_segm_name(&sname, Sarea);

  ctx.gen_cmt_line("section %s", sname.c_str());
}

//--------------------------------------------------------------------------
void idaapi st20_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi st20_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC);
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void st20_t::st20_footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT,COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                   ash.end, ash.cmnt, name);
}

