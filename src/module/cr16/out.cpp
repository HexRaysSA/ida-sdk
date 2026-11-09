
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

//----------------------------------------------------------------------
class out_CR16_t : public outctx_t
{
  out_CR16_t(void) = delete; // not used
public:
  void OutVarName(const op_t &x);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_CR16_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_CR16_t)

//----------------------------------------------------------------------
void out_CR16_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);

  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
// output one operand
bool out_CR16_t::out_operand(const op_t &x)
{
  int flags;
  switch ( x.type )
  {
    case o_displ:
      flags = OOF_ADDR | OOF_SIGNED | (x.dtype == dt_word ? OOFW_16 : OOFW_8);
      out_value(x, flags);
      out_symbol('(');
      if ( x.specflag1 & URR_PAIR )
      {
        out_register(ph.reg_names[x.reg + 1]);
        out_symbol(',');
        out_register(ph.reg_names[x.reg]);
      }
      else
      {
        out_register(ph.reg_names[x.reg]);
      }
      out_symbol(')');
      break;

    case o_reg:
      if ( x.specflag1 & URR_PAIR )
      {
        out_symbol('(');
        out_register(ph.reg_names[x.reg + 1]);
        out_symbol(',');
        out_register(ph.reg_names[x.reg]);
        out_symbol(')');
      }
      else
      {
        out_register(ph.reg_names[x.reg]);
      }
      break;

    case o_imm:
      out_symbol('$');
      flags = /*OOFS_NOSIGN |  OOF_SIGNED  | */OOFW_IMM;
      switch ( insn.itype )
      {
        case CR16_addb:
        case CR16_addw:
        case CR16_addub:
        case CR16_adduw:
        case CR16_addcb:
        case CR16_addcw:
        case CR16_ashub:
        case CR16_ashuw:
        case CR16_lshb:
        case CR16_lshw:
          flags |= OOF_SIGNED;
          break;
      }
      out_value(x, flags);
      break;

    case o_near:
      OutVarName(x);
      break;

    case o_mem:
      OutVarName(x);
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
// main output function
void out_CR16_t::out_insn(void)
{
  // print mnemonic
  out_mnemonic();

  // print first operand
  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  // print second operand
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// header of the listing
void cr16_t::CR16_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
// segment start
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void cr16_t::CR16_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // print RSEG <NAME>
  qstring sn;

  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1, "%s %s ", SegType, sn.c_str());
  // if offset not zero, print it (ORG XXXX)
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
// end of listing
void cr16_t::CR16_footer(outctx_t &ctx) const
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
