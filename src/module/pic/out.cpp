/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "pic.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>

//----------------------------------------------------------------------
class out_pic_t : public outctx_t
{
  out_pic_t(void) = delete; // not used
  pic_t &pm() { return *static_cast<pic_t *>(procmod); }
public:
  void outreg(int r) { out_register(pm().ph.reg_names[r]); }
  void out_bad_address(ea_t addr);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_pic_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_pic_t)

//----------------------------------------------------------------------
void out_pic_t::out_bad_address(ea_t addr)
{
  out_tagon(COLOR_ERROR);
  out_btoa(addr, 16);
  out_tagoff(COLOR_ERROR);
  remember_problem(PR_NONAME, insn.ea);
}

//----------------------------------------------------------------------
ea_t calc_code_mem(const insn_t &insn, ea_t ea)
{
  return to_ea(insn.cs, ea);
}

//----------------------------------------------------------------------
ea_t pic_t::calc_data_mem(ea_t ea)
{
  return dataseg + map_port(ea);
}

//----------------------------------------------------------------------
int calc_outf(const op_t &x)
{
  switch ( x.dtype )
  {
    default:
      INTERR(249);
    case dt_byte: return OOFS_IFSIGN|OOFW_8;
    case dt_word: return OOFS_IFSIGN|OOFW_16;
  }
}

//----------------------------------------------------------------------
bool out_pic_t::out_operand(const op_t &x)
{
  ea_t ea;
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      switch ( x.specflag1 )
      {

        case 0:
          outreg(x.reg);
          break;

        case 1:
          out_line("++", COLOR_SYMBOL);
          outreg(x.reg);
          break;

        case 2:
          out_line("--", COLOR_SYMBOL);
          outreg(x.reg);
          break;

        case 3:
          outreg(x.reg);
          out_line("++", COLOR_SYMBOL);
          break;

        case 4:
          outreg(x.reg);
          out_line("--", COLOR_SYMBOL);
          break;

        default:
          INTERR(10313);
      }
      break;

    case o_imm:
      if ( is_bit_insn(insn) )
      {
        const char *name = pm().find_bit(insn.Op1.addr, (int)x.value);
        if ( name != nullptr && name[0] != '\0' )
        {
          out_line(name, COLOR_IMPNAME);
          break;
        }
      }
      out_value(x, calc_outf(x));
      break;

    case o_mem:
      {
        ea = pm().calc_data_mem(x.addr);
        const char *name = pm().find_sym(x.addr);
        if ( name == nullptr || name[0] == '\0' )
          goto OUTNAME;
        out_addr_tag(ea);
        out_line(name, COLOR_IMPNAME);
      }
      break;

    case o_near:
      {
        ea = calc_code_mem(insn, x.addr);
OUTNAME:
        if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_displ:
      out_value(x, OOF_ADDR | OOFW_8);
      out_symbol('[');
      outreg(x.phrase);
      out_symbol(']');
      break;
    default:
      INTERR(10314);
  }
  return 1;
}

//----------------------------------------------------------------------
bool pic_t::conditional_insn(const insn_t &insn, flags64_t flags) const
{
  if ( is_flow(flags) )
  {
    int code;
    switch ( ptype )
    {
      case PIC12:
        if ( insn.ea == 0 )
          break;
        code = get_wide_byte(insn.ea-1);
        if ( (code & 0xFC0) == 0x2C0 )
          return true;  // 0010 11df ffff DECFSZ  f, d           Decrement f, Skip if 0
        else if ( (code & 0xFC0) == 0x3C0 )
          return true;  // 0011 11df ffff INCFSZ  f, d           Increment f, Skip if 0
        else if ( (code & 0xF00) == 0x600 )
          return true;  // 0110 bbbf ffff BTFSC   f, b           Bit Test f, Skip if Clear
        else if ( (code & 0xF00) == 0x700 )
          return true;  // 0111 bbbf ffff BTFSS   f, b           Bit Test f, Skip if Set
        break;
      case PIC14:
        if ( insn.ea == 0 )
          break;
        code = get_wide_byte(insn.ea-1);
        if ( (code & 0x3F00) == 0x0B00 )
          return true;  // 00 1011 dfff ffff DECFSZ  f, d        Decrement f, Skip if 0
        else if ( (code & 0x3F00) == 0x0F00 )
          return true;  // 00 1111 dfff ffff INCFSZ  f, d        Increment f, Skip if 0
        else if ( (code & 0x3C00) == 0x1800 )
          return true;  // 01 10bb bfff ffff BTFSC   f, b        Bit Test f, Skip if Clear
        else if ( (code & 0x3C00) == 0x1C00 )
          return true;  // 01 11bb bfff ffff BTFSS   f, b        Bit Test f, Skip if Set
        break;
      case PIC16:
        if ( insn.ea < 2 )
          break;
        code = get_word(insn.ea-2);
        code >>= 10;
        // 1010 bbba ffff ffff BTFSS  f, b, a    Bit Test f, Skip if Set
        // 1011 bbba ffff ffff BTFSC  f, b, a    Bit Test f, Skip if Clear
        if ( (code & 0x38) == 0x28 )
          return true;
        switch ( code )
        {
          case 0x0B: // 0010 11da ffff ffff DECFSZ f, d, a    Decrement f, Skip if 0
          case 0x0F: // 0011 11da ffff ffff INCFSZ f, d, a    Increment f, Skip if 0
          case 0x12: // 0100 10da ffff ffff INFSNZ f, d, a    Increment f, Skip if not 0
          case 0x13: // 0100 11da ffff ffff DCFSNZ f, d, a    Decrement f, Skip if not 0
          case 0x18: // 0110 000a ffff ffff CPFSLT f, a       Compare f with W, Skip if <
                     // 0110 001a ffff ffff CPFSEQ f, a       Compare f with W, Skip if ==
          case 0x19: // 0110 010a ffff ffff CPFSGT f, a       Compare f with W, Skip if >
                     // 0110 011a ffff ffff TSTFSZ f, a       Test f, Skip if 0
            return true;
        }
        break;
    }
  }
  return false;
}

//----------------------------------------------------------------------
void out_pic_t::out_insn(void)
{
  if ( pm().conditional_insn(insn, F) )
    out_char(' ');
  out_mnemonic();

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

  if ( ( insn.Op1.type == o_mem && insn.Op1.addr == PIC16_INDF2 )
    || ( insn.Op2.type == o_mem && insn.Op2.addr == PIC16_INDF2 ) )
  {
    func_t *pfn = get_func(insn.ea);
    tinfo_t frame;
    frame.get_func_frame(pfn);
    if ( pfn != nullptr && !frame.empty() )
    {
      udm_t stkvar;
      stkvar.offset = (pfn->frregs + pfn->frsize)*8LL;
      ssize_t stkvar_idx = frame.find_udm(&stkvar, STRMEM_OFFSET);
      if ( stkvar_idx != -1 )
      {
        out_char(' ');
        out_line(ash.cmnt, COLOR_AUTOCMT);
        out_char(' ');
        out_line(stkvar.name.c_str(), COLOR_LOCNAME);
      }
    }
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void pic_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  if ( value != BADSEL )
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
//lint -esym(1764, ctx) could be made const
void pic_t::pic_assumes(outctx_t &ctx)         // function to produce assume directives
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
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void pic_t::pic_segstart(outctx_t &ctx, segment_t *Srange) const
{
  if ( is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_visible_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s (%s)", SCOLOR_AUTOCMT),
                 ash.cmnt,
                 sclas == "CODE" ? ".text" :
                 sclas == "BSS" ? ".bss" :
                 ".data",
                 sname.c_str());
  if ( Srange->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Srange->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi pic_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void pic_t::pic_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
  ctx.gen_printf(0, COLSTR("include \"P%s.INC\"", SCOLOR_ASMDIR), ioh.device.c_str());
  ctx.gen_header_extra();
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void pic_t::pic_footer(outctx_t &ctx) const
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

//--------------------------------------------------------------------------
void pic_t::out_equ(outctx_t &ctx, bool indent, const char *name, uval_t off)
{
  if ( name != nullptr && name[0] != '\0' )
  {
    if ( indent )
      ctx.out_char(' ');
    ctx.out_line(name);
    ctx.out_spaces(inf_get_indent()-1);
    ctx.out_char(' ');
    ctx.out_line(ash.a_equ, COLOR_KEYWORD);
    ctx.out_char(' ');
    ctx.out_tagon(COLOR_NUMBER);
    ctx.out_btoa(off);
    ctx.out_tagoff(COLOR_NUMBER);
    ctx.set_gen_label();
    ctx.flush_outbuf(0x80000000);
  }
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary
int pic_t::out_equ(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *s = getseg(ea);
  if ( s != nullptr && s->type == SEG_IMEM && ash.a_equ != nullptr )
  {
    qstring name;
    if ( get_visible_name(&name, ea) > 0 )
    {
      ctx.ctxflags |= CTXF_LABEL_OK;
      uval_t off = ea - get_segm_base(s);
      out_equ(ctx, false, name.begin(), off);
      const ioport_bits_t *_bits = find_bits(off);
      if ( _bits != nullptr )
      {
        const ioport_bits_t &bits = *_bits;
        for ( int i=0; i < bits.size(); i++ )
          out_equ(ctx, true, bits[i].name.c_str(), i);
        if ( !bits.empty() )
          ctx.gen_empty_line();
      }
    }
    else
    {
      ctx.flush_buf("");
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void pic_t::pic_data(outctx_t &ctx, bool analyze_only)
{
  // the kernel's standard routine which outputs the data knows nothing
  // about "equ" directives. So we do the following:
  //    - try to output an "equ" directive
  //    - if we succeed, then ok
  //    - otherwise let the standard data output routine, out_data()
  //        do all the job

  if ( !out_equ(ctx) )
    ctx.out_data(analyze_only);
}
