/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"

//----------------------------------------------------------------------
class out_C39_t : public outctx_t
{
  out_C39_t(void) = delete; // not used
public:
  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_C39_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_C39_t)

//----------------------------------------------------------------------
void out_C39_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
bool out_C39_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;

    case o_imm:
      out_symbol('#');
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(&ri, insn.ea, x.n) )
      {
        if ( ri.flags == REF_OFF16 )
        {
          set_refinfo(insn.ea, x.n,
                      REF_OFF32, ri.target, ri.base, ri.tdelta);
//          msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//                insn.ea,
//                ri.flags,ri.target,ri.base,ri.tdelta);
        }
      }
      out_value(x, /*OOFS_NOSIGN | */ OOF_SIGNED | OOFW_IMM);
      break;

    case o_near:
      OutVarName(x);
      break;

    case o_mem:
      if ( x.specflag1&URR_IND )
        out_symbol('(');
      out_value(x, OOFS_NOSIGN | OOFW_IMM);
      if ( x.specflag1&URR_IND )
        out_symbol(')');
      break;

    case o_void:
      return 0;

    default:
      INTERR(10133);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_C39_t::out_insn(void)
{
  out_mnemonic();

  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
    if ( insn.Op3.type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(2);
    }
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void c39_t::C39_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void c39_t::C39_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // RSEG <NAME>
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1,"%s %s ",SegType, sn.c_str());
  // if non-zero offset (ORG XXXX)
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      ctx.gen_printf(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
void c39_t::C39_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      size_t i = strlen(ash.end);
      do
        ctx.out_char(' ');
      while ( ++i < 8 );
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi C39_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // micro bug-fix
  refinfo_t ri;
  if ( get_refinfo(&ri, ea, 0) && ri.flags == REF_OFF16 )
    set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);

  ctx.out_data(analyze_only);
}
