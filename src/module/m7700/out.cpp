
#include "m7700.hpp"

//----------------------------------------------------------------------
class out_m7700_t : public outctx_t
{
  out_m7700_t(void) = delete; // not used
  m7700_t &pm() { return *static_cast<m7700_t *>(procmod); }
public:
  void outreg(const int n) { out_register(ph.reg_names[n]); }
  void outaddr(const op_t &op, const bool replace_with_label = true);
  void outdispl(const op_t &op);
  bool bitmask2list(const op_t &op);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_m7700_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_m7700_t)

//--------------------------------------------------------------------------
void out_m7700_t::outaddr(const op_t &op, const bool replace_with_label)
{
  bool ind = is_addr_ind(op);      // is operand indirect ?

  if ( ind )
    out_symbol('(');

  // if addressing mode is direct and the value of DR is unknown,
  // we have to print DR:x (where x is the "indexed" value)
  if ( is_addr_dr_rel(op) && get_sreg(insn.ea, rDR) == BADSEL )
  {
    outreg(rDR);
    out_symbol(':');
    out_value(op, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
  }
  // otherwise ...
  else if ( !replace_with_label
         || !out_name_expr(op, to_ea(insn.cs, op.addr), op.addr) )
  {
    if ( replace_with_label )
      out_tagon(COLOR_ERROR);
    out_value(op, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
    if ( replace_with_label )
      out_tagoff(COLOR_ERROR);
  }

  if ( ind )
    out_symbol(')');
}

//--------------------------------------------------------------------------
void out_m7700_t::outdispl(const op_t &op)
{
  if ( is_displ_ind(op) )
  {
    out_symbol('(');
    outaddr(op, false);
    out_symbol(',');
    if ( !(ash.uflag & UAS_INDX_NOSPACE) )
      out_char(' ');
    outreg(op.reg);
    out_symbol(')');
  }
  else if ( is_displ_ind_p1(op) )
  {
    out_symbol('(');
    outaddr(op, false);
    out_symbol(')');
    out_symbol(',');
    out_char(' ');
    outreg(op.reg);
  }
  else
  {
    outaddr(op, false);
    out_symbol(',');
    out_char(' ');
    outreg(op.reg);
  }
}

//--------------------------------------------------------------------------
void m7700_t::m7700_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, nullptr, ioh.device.c_str());
  if ( ash.uflag & UAS_DEVICE_DIR )
  {
    switch ( ptype )
    {
      case prc_m7700:
        ctx.gen_printf(DEFAULT_INDENT, ".MCU M37700");
        break;
      case prc_m7750:
        ctx.gen_printf(DEFAULT_INDENT, ".MCU M37750");
        break;
      default:
        INTERR(10029);
    }
  }
}

//--------------------------------------------------------------------------
void m7700_t::m7700_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      ctx.out_char(' ');
      if ( ash.uflag & UAS_END_WITHOUT_LABEL )
        ctx.out_line("; ");
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
bool out_m7700_t::bitmask2list(const op_t &op)
{
  static const char *const flags[] =
  {
    "N", "V", "m", "x", "D", "I", "Z", "C"
  };
  static const int regs[] =
  {
    rPS, rPG, rDT, rDR, rY, rX, rB, rA
  };

  enum { bitFLAGS, bitREGS } t;
  switch ( insn.itype )
  {
    case m7700_psh:
    case m7700_pul:
      t = bitREGS;
      break;

    case m7700_sep:
    case m7700_clp:
      t = bitFLAGS;
      break;

    default:
      return false;
  }

  if ( op.value == 0 )
    return false;

  bool ok = false;
  for ( int tmp = (int)op.value, i = 1, j = 0; j < 8; i *= 2, j++ )
  {
    if ( ((tmp & i) >> j) != 1 )
      continue;

    if ( ok )
    {
      out_symbol(',');
      out_char(' ');
    }

    switch ( t )
    {
      case bitFLAGS:
        out_register(flags[7 - j]);
        break;
      case bitREGS:
        outreg(regs[7 - j]);
        break;
    }
    ok = true;
  }
  return true;
}

//--------------------------------------------------------------------------
bool out_m7700_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    // register
    case o_reg:
      outreg(x.reg);
      break;

    // immediate
    case o_imm:
      {
        bool list_ok = false;

        if ( ash.uflag & UAS_BITMASK_LIST )
          list_ok = bitmask2list(x);

        if ( !list_ok )
        {
          if ( !(is_imm_without_sharp(x)) )
            out_symbol('#');
          out_value(x, OOFW_IMM);
        }
      }
      break;

    // bit
    case o_bit:
      {
        const ioport_bit_t * port = nullptr;

        if ( x.n == 0 && (insn.Op2.type == o_near || insn.Op2.type == o_mem) )
          port = pm().find_bit(insn.Op2.addr, (size_t)x.value);

        // this immediate is represented in the .cfg file
        if ( port != nullptr && !port->name.empty() )
        {
          // output the port name instead of the numeric value
          out_line(port->name.c_str(), COLOR_IMPNAME);
        }
        // otherwise, simply print the value
        else
        {
          out_symbol('#');
          out_value(x, OOFW_IMM);
        }
      }
      break;

    // data / code memory address
    case o_near:
    case o_mem:
      outaddr(x);
      break;

    // displ
    case o_displ:
      outdispl(x);
      break;

    // ignore void operands
    case o_void:
      break;

    default:
      INTERR(10030);
  }
  return 1;
}

//--------------------------------------------------------------------------
void out_m7700_t::out_proc_mnem(void)
{
  const char *pfx = is_insn_long_format(insn) ? "l" : nullptr;
  out_mnem(8, pfx);
}

//--------------------------------------------------------------------------
void out_m7700_t::out_insn(void)
{
  out_mnemonic();

  //
  // print insn operands
  //

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
//lint -esym(818, Srange) could be made const
void m7700_t::m7700_segstart(outctx_t &ctx, segment_t *Srange) const
{
  qstring sname;
  get_visible_segm_name(&sname, Srange);

  if ( ash.uflag & UAS_SEGM )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), sname.c_str());
  else
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".SECTION %s", SCOLOR_ASMDIR), sname.c_str());

  ea_t orgbase = ctx.insn_ea - get_segm_para(Srange);
  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
inline bool show_assume_line(const sreg_range_t *sra, ea_t ea, int segreg)
{
  bool show = false;
  if ( sra->start_ea == ea )
  {
    sreg_range_t prev_sra;
    if ( get_prev_sreg_range(&prev_sra, ea, segreg) )
      show = sra->val != prev_sra.val;
  }
  return show;
}

//--------------------------------------------------------------------------
void m7700_t::m7700_assumes(outctx_t &ctx) const
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || seg == nullptr )
    return;
  bool seg_started = (ea == seg->start_ea);

  sreg_range_t sra;
  if ( get_sreg_range(&sra, ea, rDR) )
  {
    if ( (seg_started && sra.val != BADSEL) || show_assume_line(&sra, ea, rDR) )
      ctx.gen_printf(-1, COLSTR("%s DPR = %a", SCOLOR_REGCMT), ash.cmnt, sra.val);
  }

  if ( get_sreg_range(&sra, ea, rfM) )
  {
    if ( seg_started || show_assume_line(&sra, ea, rfM) )
      ctx.gen_printf(-1, COLSTR("%s m = %a", SCOLOR_REGCMT), ash.cmnt, eah().trunc_uval(sra.val));
  }

  if ( get_sreg_range(&sra, ea, rfX) )
  {
    if ( seg_started || show_assume_line(&sra, ea, rfX) )
      ctx.gen_printf(-1, COLSTR("%s x = %a", SCOLOR_REGCMT), ash.cmnt, eah().trunc_uval(sra.val));
  }
}
