/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "pan.hpp"

//----------------------------------------------------------------------
class out_mn102_t : public outctx_t
{
  out_mn102_t(void) = delete; // not used
public:
  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_mn102_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_mn102_t)

//----------------------------------------------------------------------
void out_mn102_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
// print one operand
bool out_mn102_t::out_operand(const op_t & x)
{
  switch ( x.type )
  {
    // memory reference with a regsiter
    // (disp,Ri)
    case o_displ:
      out_symbol('(');
      out_value(x);
      out_symbol(',');
      out_register(ph.reg_names[x.reg]);
      out_symbol(')');
      break;

    // register
    case o_reg:
      if ( x.reg&0x80 )
        out_symbol('(');
      if ( x.reg&0x10 )
      {
        out_register(ph.reg_names[((x.reg>>5)&3)+rD0]);
        out_symbol(',');
      }
      out_register(ph.reg_names[x.reg&0x0F]);
      if ( x.reg&0x80 )
        out_symbol(')');
      break;

    // immediate operand
    case o_imm:
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(&ri, insn.ea, x.n) )
      {
        if ( ri.flags == REF_OFF16 )
          set_refinfo(insn.ea, x.n, REF_OFF32, ri.target, ri.base, ri.tdelta);
      }
      out_value(x, /*OOFS_NOSIGN | */ OOF_SIGNED | OOFW_IMM);
      break;

    // code reference
    case o_near:
      OutVarName(x);
      break;

    // direct memory reference
    case o_mem:
      out_symbol('(');
      OutVarName(x);
      out_symbol(')');
      break;

    // nothing for void
    case o_void:
      return 0;

    // unknown operand
    default:
      warning("out: %a: bad optype %d",insn.ea,x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
// main instruction printer
void out_mn102_t::out_insn(void)
{
  // print mnemonic
  out_mnemonic();

  // print first operands
  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  // second operand
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
    // third operand
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
// listing header
void mn102_t::mn102_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
// segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void mn102_t::mn102_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  ea_t ea = ctx.insn_ea;
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // print RSEG <NAME>
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1, "%s %s ", SegType, sn.c_str());
  // if org is not zero, print it
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      ctx.gen_printf(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
// end of listing
void mn102_t::mn102_footer(outctx_t &ctx) const
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
void idaapi mn102_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // micro bug-fix
  refinfo_t ri;
  if ( get_refinfo(&ri, ea, 0) && ri.flags == REF_OFF16 )
    set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);

  ctx.out_data(analyze_only);
}
