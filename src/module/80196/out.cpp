/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//----------------------------------------------------------------------
class out_i196_t : public outctx_t
{
  out_i196_t(void) = delete; // not used
public:

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_i196_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_i196_t)

//--------------------------------------------------------------------------
void idaapi i196_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
}

//--------------------------------------------------------------------------
void idaapi i196_footer(outctx_t &ctx)
{
  ctx.gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void i196_t::i196_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring name;
  get_visible_segm_name(&name, Sarea);
  ctx.gen_cmt_line(COLSTR("segment %s", SCOLOR_AUTOCMT), name.c_str());

  ea_t org = ctx.insn_ea - get_segm_base(Sarea);
  if ( org != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), org);
    ctx.gen_cmt_line("%s %s", ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
//lint -esym(818, seg) could be made const
void idaapi i196_segend(outctx_t &ctx, segment_t *seg)
{
  qstring name;
  get_visible_segm_name(&name, seg);
  ctx.gen_cmt_line("end of '%s'", name.c_str());
}

//----------------------------------------------------------------------
void out_i196_t::out_insn(void)
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

//----------------------------------------------------------------------
static bool is_ext_insn(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case I196_ebmovi:      // Extended interruptable block move
    case I196_ebr:         // Extended branch indirect
    case I196_ecall:       // Extended call
    case I196_ejmp:        // Extended jump
    case I196_eld:         // Extended load word
    case I196_eldb:        // Extended load byte
    case I196_est:         // Extended store word
    case I196_estb:        // Extended store byte
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool out_i196_t::out_operand(const op_t &x)
{
  uval_t v, v1;
//  const char *ptr;

  switch ( x.type )
  {
    case o_imm:
      out_symbol('#');
      out_value(x, OOF_SIGNED | OOFW_IMM);
      break;

    case o_indexed:
      out_value(x, OOF_ADDR|OOF_SIGNED|(is_ext_insn(insn) ? OOFW_32 : OOFW_16)); //.addr
      v = x.value;
      out_symbol('[');
      if ( v != 0 )
        goto OUTPHRASE;
      out_symbol(']');
      break;

    case o_indirect:
    case o_indirect_inc:
      out_symbol('[');
      // fallthrough

    case o_mem:
    case o_near:
      v = x.addr;
OUTPHRASE:
      v1 = to_ea(get_sreg(insn.ea, (x.type == o_near) ? rVcs : rVds), v);
      if ( !out_name_expr(x, v1, v ) )
      {
        out_value(x, (x.type == o_indexed ? 0 : OOF_ADDR)
                   | OOF_NUMBER|OOFS_NOSIGN
                   | (x.type == o_near
                    ? (is_ext_insn(insn) ? OOFW_32 : OOFW_16)
                    : OOFW_8));
        remember_problem(PR_NONAME, insn.ea);
      }

      if ( x.type == o_indirect
        || x.type == o_indirect_inc
        || x.type == o_indexed )
      {
        out_symbol(']');
        if ( x.type == o_indirect_inc )
          out_symbol('+');
      }
      break;

    case o_void:
      return 0;

    case o_bit:
      out_symbol(char('0' + x.reg));
      break;

    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
  }

  return 1;
}
