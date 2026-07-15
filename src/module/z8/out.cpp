/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"

static const char *const phrases[] =
{
  "F", "LT", "LE", "ULE", "OV",  "MI", "Z",  "C",
  "T", "GE", "GT", "UGT", "NOV", "PL", "NZ", "NC"
};

//----------------------------------------------------------------------
inline void z8_t::out_reg(outctx_t &ctx, int rgnum)
{
  ctx.out_register(ph.reg_names[rgnum]);
}

//--------------------------------------------------------------------------
void z8_t::z8_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_ASM_AND_BYTESEX);
}

//--------------------------------------------------------------------------
void z8_t::z8_footer(outctx_t &ctx)
{
  ctx.gen_empty_line();

  ctx.out_line(ash.end, COLOR_ASMDIR);
  ctx.flush_outbuf(DEFAULT_INDENT);

  ctx.gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void z8_t::z8_segstart(outctx_t &ctx, ea_t seg_ea)
{
  segment_info_t si;
  if ( !get_segment_info(&si, seg_ea, GSI_NAME) )
    return;

  qstring sname;
  si.visible_name(&sname);

  ctx.gen_cmt_line(COLSTR("segment %s", SCOLOR_AUTOCMT), sname.c_str());

  ea_t org = ctx.insn_ea - si.base();
  if ( org != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), org);
    ctx.gen_cmt_line("%s %s", ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void z8_t::z8_segend(outctx_t &ctx, ea_t seg_ea)
{
  segment_info_t si;
  if ( !get_segment_info(&si, seg_ea, GSI_NAME) )
    return;

  qstring sname;
  si.visible_name(&sname);
  ctx.gen_cmt_line("end of '%s'", sname.c_str());
}

//----------------------------------------------------------------------
void idaapi out_insn(outctx_t &ctx)
{
  ctx.out_mnemonic();

  ctx.out_one_operand(0);

  if ( ctx.insn.Op2.type != o_void )
  {
    ctx.out_symbol(',');
    ctx.out_char(' ');
    ctx.out_one_operand(1);
  }

  ctx.out_immchar_cmts();
  ctx.flush_outbuf();
}

//----------------------------------------------------------------------
bool z8_t::out_opnd(outctx_t &ctx, const op_t &x)
{
  uval_t v;

  z8_t &pm = *static_cast<z8_t *>(ctx.procmod);
  switch ( x.type )
  {
    case o_imm:
      ctx.out_symbol('#');
      ctx.out_value(x, OOFW_IMM);
      break;

    case o_ind_reg:
      ctx.out_symbol('@');
      [[fallthrough]];

    case o_reg:
      out_reg(ctx, x.reg);
      break;

    case o_phrase:
      ctx.out_keyword(phrases[x.phrase]);
      break;

    case o_displ:
      ctx.out_value(x, OOF_ADDR | OOFW_16);
      ctx.out_symbol('(');
      out_reg(ctx, x.reg);
      ctx.out_symbol(')');
      break;

    case o_ind_mem:
      ctx.out_symbol('@');
      [[fallthrough]];

    case o_mem:
    case o_near:
      v = pm.map_addr(ctx.insn, x.addr, x.n, x.type != o_near);
      if ( !ctx.out_name_expr(x, v, x.addr) )
      {
        const char *name = pm.find_ioport(v);
        if ( name != nullptr )
        {
          ctx.out_line(name, COLOR_IMPNAME);
        }
        else
        {
          ctx.out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
          remember_problem(PR_NONAME, ctx.insn.ea);
        }
      }
      break;

    case o_void:
      return 0;

    default:
      warning("out: %a: bad optype %d", ctx.insn.ea, x.type);
  }

  return 1;
}

//--------------------------------------------------------------------------
static void out_equ(outctx_t &ctx, const char *name, const char *equ, uchar off)
{
  ctx.out_line(name, COLOR_DNAME);
  ctx.out_char(' ');
  ctx.out_line(equ, COLOR_KEYWORD);
  ctx.out_char(' ');
  ctx.out_tagon(COLOR_NUMBER);
  ctx.out_btoa(off);
  ctx.out_tagoff(COLOR_NUMBER);
  ctx.ctxflags |= CTXF_LABEL_OK;
  ctx.flush_outbuf(0x80000000);
}

//--------------------------------------------------------------------------
void z8_t::z8_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  segment_info_t si;
  if ( get_segment_info(&si, ea) && si.get_type() == SEG_IMEM )
  {
    qstring name;
    if ( get_visible_name(&name, ea) > 0 )
      out_equ(ctx, name.begin(), ash.a_equ, uint16(ea - si.base()));
  }
  else
  {
    ctx.out_data(analyze_only);
  }
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void z8_t::z8_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_info_t si;
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || !get_segment_info(&si, ea) )
    return;
  // always show at the start of code segments
  bool seg_started = (ea == si.start_ea) && (si.get_type() == SEG_CODE);

  sreg_range_t sra;
  if ( !get_sreg_range(&sra, ea, rRp) )
    return;
  bool show = sra.start_ea == ea;
  if ( show )
  {
    sreg_range_t prev_sra;
    if ( get_prev_sreg_range(&prev_sra, ea, rRp) )
      show = sra.val != prev_sra.val;
  }
  if ( seg_started || show )
  {
    sel_t rp = sra.val;
    if ( rp == BADSEL )
      rp = 0;
    char num[MAX_NUMBUF];
    btoa(num, sizeof(num), rp);
    char nbuf[MAXSTR];
    qsnprintf(nbuf, sizeof(nbuf), COLSTR(".rp %s", SCOLOR_ASMDIR), num);
    ctx.flush_buf(nbuf, DEFAULT_INDENT);
  }
}
