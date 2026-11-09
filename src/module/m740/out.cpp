
#include "m740.hpp"

//----------------------------------------------------------------------
class out_m740_t : public outctx_t
{
  out_m740_t(void) = delete; // not used
public:
  void outreg(const int n) { out_register(ph.reg_names[n]); }
  void outaddr(const op_t &op, bool replace_with_label = true);
  void outdispl(void);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_m740_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_m740_t)

//--------------------------------------------------------------------------
// output an address
void out_m740_t::outaddr(const op_t &op, bool replace_with_label)
{
  bool ind = is_addr_ind(op);      // is operand indirect ?
  bool sp = is_addr_sp(op);        // is operand special page ?

  int size = 16;  // operand is 16 bits long

  if ( ind )
    out_symbol('(');
  if ( sp )
  {
    out_symbol('\\');
    size = 8; /* just display the first 8 bits */
  }

  if ( !replace_with_label
    || !out_name_expr(op, to_ea(insn.cs, op.addr), op.addr) )
  {
    if ( replace_with_label )
      out_tagon(COLOR_ERROR);
    out_value(op, OOF_ADDR | OOFS_NOSIGN | (size < 16 ? OOFW_8 : OOFW_16));
    if ( replace_with_label )
      out_tagoff(COLOR_ERROR);
  }

  if ( ind )
    out_symbol(')');
}

//--------------------------------------------------------------------------
// output a displacement
void out_m740_t::outdispl(void)
{
  if ( is_displ_indx(insn) )
  {
    out_symbol('(');
    outaddr(insn.Op1, false);
    out_symbol(',');
    if ( !(ash.uflag & UAS_INDX_NOSPACE) )
      out_char(' ');
    outreg(insn.Op1.reg);
    out_symbol(')');
    return;
  }
  if ( is_displ_indy(insn) )
  {
    out_symbol('(');
    outaddr(insn.Op1, false);
    out_symbol(')');
    out_symbol(',');
    out_char(' ');
    outreg(insn.Op1.reg);
    return;
  }
  if ( is_displ_zpx(insn) || is_displ_zpy(insn) || is_displ_absx(insn) || is_displ_absy(insn) )
  {
    outaddr(insn.Op1, false);
    out_symbol(',');
    out_char(' ');
    outreg(insn.Op1.reg);
    return;
  }
  INTERR(10023);
}

//--------------------------------------------------------------------------
// generate header
void m740_t::m740_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, nullptr, ioh.device.c_str());
}

//--------------------------------------------------------------------------
// generate footer
void m740_t::m740_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      ctx.out_char(' ');
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
// output an operand
bool out_m740_t::out_operand(const op_t &op)
{
  switch ( op.type )
  {
    // register
    case o_reg:
      outreg(op.reg);
      break;

    // immediate
    case o_imm:
      if ( (op.specflag1 & OP_IMM_BIT) == 0 )
        out_symbol('#');
      out_value(op, OOFW_IMM);
      break;

    // data / code memory address
    case o_near:
    case o_mem:
      outaddr(op);
      break;

    // displ
    case o_displ:
      outdispl();
      break;

    // ignore void operands
    case o_void:
      break;

    default:
      INTERR(10024);
  }
  return 1;
}

//--------------------------------------------------------------------------
// outputs an instruction
void out_m740_t::out_insn(void)
{
  out_mnemonic();
  out_one_operand(0);        // output the first operand

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

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void m740_t::m740_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring sname;
  get_visible_segm_name(&sname, Sarea);

  if ( ash.uflag & UAS_SEGM )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), sname.c_str());
  else if ( ash.uflag & UAS_RSEG )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("RSEG %s", SCOLOR_ASMDIR), sname.c_str());

  ea_t orgbase = ctx.insn_ea - get_segm_para(Sarea);
  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}
