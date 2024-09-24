/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <segregs.hpp>

//----------------------------------------------------------------------
class out_h8500_t : public outctx_t
{
  out_h8500_t(void) = delete; // not used
public:
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void out_bad_address(ea_t addr);
  void out_sizer(const op_t &x);
  void out_reglist(int reg, int cnt);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_h8500_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_h8500_t)

//----------------------------------------------------------------------
void out_h8500_t::out_bad_address(ea_t addr)
{
  h8500_t &pm = *static_cast<h8500_t *>(procmod);
  const char *name = pm.find_sym((int)addr);
  if ( name != nullptr && name[0] != '\0' )
  {
    out_line(name, COLOR_IMPNAME);
  }
  else
  {
    out_tagon(COLOR_ERROR);
    out_btoa(addr, 16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}
//----------------------------------------------------------------------
static int calc_sizer(const insn_t &insn, const op_t &x)
{
  if ( insn.itype == H8500_mov_g && x.type == o_imm )
    return insn.auxpref & aux_mov16 ? 16 : 8;
  // special case: cmp:g.b #x:8, @(d:16,r)
  // special case: cmp:g.w #x:16, @(d:8,r)
  else if ( insn.itype == H8500_cmp_g && x.type == o_imm )
    return insn.auxpref & aux_word ? 16 : 8;
  else
    return (insn.auxpref & aux_disp24) ? 24 : (insn.auxpref & aux_disp16) ? 16 : 8;
}

//----------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, const op_t &x)
{
  if ( x.type == o_near )
    return to_ea(insn.cs, x.addr);

// Before this was simply to_ea, now we do it like this:
// (if someone complains, both methods should be retained)
  ea_t ea = x.addr;
  switch ( calc_sizer(insn, x) )
  {
    case 8:
      if ( insn.auxpref & aux_page )
      {
        ea &= 0xFF;
        sel_t br = get_sreg(insn.ea, BR);
        if ( br != BADSEL )
          ea |= br << 8;
        else
          ea = BADADDR;
      }
      break;
    case 16:
      ea &= 0xFFFF;
      if ( x.type == o_mem )
      {
        sel_t dp = get_sreg(insn.ea, DP);
        if ( dp != BADSEL )
          ea |= dp << 16;
        else
          ea = BADADDR;
      }
      else
      {
        ea |= insn.ea & ~0xFFFF;
      }
      break;
  }
  return ea;
}

//----------------------------------------------------------------------
void out_h8500_t::out_sizer(const op_t &x)
{
  h8500_t &pm = *static_cast<h8500_t *>(procmod);
  if ( pm.show_sizer == -1 )
    pm.show_sizer = !qgetenv("H8_NOSIZER");
  if ( !pm.show_sizer )
    return;
  if ( (insn.auxpref & (aux_disp8|aux_disp16|aux_disp24)) == 0 )
    return;
  out_symbol(':');
  // 1D 00 11 07 00 01                 mov:g.w #1:16, @0x11:16
  // 1D 00 11 06 01                    mov:g.w #1:16, @0x11:16
  // 0D 11 07 00 01                    mov:g.w #1:8, @0x11:8
  // 0D 11 06 01                       mov:g.w #1:8, @0x11:8
  // 0D 11 07 00 01                    mov:g.w #1:8, @0x11:8
  // 1D 00 11 07 00 01                 mov:g.w #1:16, @0x11:16
  // 15 00 11 06 01                    mov:g.b #1:16, @0x11:16
  // 05 11 06 01                       mov:g.b #1:8, @0x11:8
  int s = calc_sizer(insn, x);
  out_long(s, 10);
}

//----------------------------------------------------------------------
void out_h8500_t::out_reglist(int reg, int cnt)
{
  int bit = 1;
  int delayed = -1;
  int first = 1;
  for ( int i=0; i <= cnt; i++,bit<<=1 )
  {
    if ( (reg & bit) == 0 )
    {
      if ( delayed >= 0 )
      {
        if ( !first )
          out_symbol(',');
        if ( delayed == (i-1) )
        {
          outreg(delayed);
        }
        else if ( delayed == (i-2) )
        {
          outreg(delayed);
          out_symbol(',');
          outreg(delayed+1);
        }
        else
        {
          outreg(delayed);
          out_symbol('-');
          outreg(i-1);
        }
        delayed = -1;
        first = 0;
      }
    }
    else
    {
      if ( delayed < 0 )
        delayed = i;
    }
  }
}

//----------------------------------------------------------------------
int calc_opimm_flags(const insn_t &insn)
{
  bool sign = insn.itype == H8500_add_q
           || insn.itype == H8500_adds
           || insn.itype == H8500_subs;
  return OOFS_IFSIGN|OOFW_IMM|(sign ? OOF_SIGNED : 0);
}

//----------------------------------------------------------------------
int calc_opdispl_flags(const insn_t &insn)
{
  bool sign = (insn.auxpref & aux_disp8) != 0;
  return OOF_ADDR | OOFS_IFSIGN | (sign ? OOF_SIGNED : 0)
       | (insn.auxpref & aux_disp24 ? OOFW_32
        : insn.auxpref & aux_disp16 ? OOFW_16
        :                             OOFW_8);
}

//----------------------------------------------------------------------
bool out_h8500_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_reglist:
      out_symbol('(');
      out_reglist(x.reg, 8);
      out_symbol(')');
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, calc_opimm_flags(insn));
      out_sizer(x);
      break;

    case o_mem:
      out_symbol('@');
      // fallthrough
    case o_near:
    case o_far:
      {
        ea_t ea = calc_mem(insn, x);
        if ( !out_name_expr(x, ea, BADADDR) )
          out_bad_address(x.addr);
        out_sizer(x);
      }
      break;

    case o_phrase:
      if ( x.phtype == ph_normal )
      {
        bool outdisp = is_off(F, x.n)
                    || is_stkvar(F, x.n)
                    || is_enum(F, x.n)
                    || is_stroff(F, x.n);
        if ( outdisp )
          goto OUTDISP;
      }
      out_symbol('@');
      if ( x.phtype == ph_pre )
        out_symbol('-');
      outreg(x.phrase);
      if ( x.phtype == ph_post )
        out_symbol('+');
      break;

    case o_displ:
OUTDISP:
      out_symbol('@');
      out_symbol('(');
      out_value(x, calc_opdispl_flags(insn));
      out_sizer(x);
      out_symbol(',');
      outreg(x.reg);
      out_symbol(')');
      break;

    default:
      INTERR(10099);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_h8500_t::out_proc_mnem(void)
{
  const char *postfix = nullptr;
  if ( insn.auxpref & aux_byte )
    postfix = ".b";
  else if ( insn.auxpref & aux_word )
    postfix = ".w";
  else if ( insn.auxpref & aux_f )
    postfix = "/f";
  else if ( insn.auxpref & aux_ne )
    postfix = "/ne";
  else if ( insn.auxpref & aux_eq )
    postfix = "/eq";
  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
void out_h8500_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);
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
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void h8500_t::h8500_segstart(outctx_t &ctx, segment_t *Srange) const
{
  const char *predefined[] =
  {
    ".text",    // Text section
    ".rdata",   // Read-only data section
    ".data",    // Data sections
    ".lit8",    // Data sections
    ".lit4",    // Data sections
    ".sdata",   // Small data section, addressed through register $gp
    ".sbss",    // Small bss section, addressed through register $gp
    ".bss",     // bss (block started by storage) section, which loads zero-initialized data
  };

  if ( is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  if ( !print_predefined_segname(ctx, &sname, predefined, qnumber(predefined)) )
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                   sclas == "CODE" ? ".text" :
                   sclas == "BSS" ? ".bss" :
                   ".data",
                   ash.cmnt,
                   sname.c_str());
  if ( Srange->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Srange->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi h8500_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void h8500_t::h8500_assume(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);

  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || seg == nullptr )
    return;
  bool seg_started = (ea == seg->start_ea);

  for ( int i=ph.reg_first_sreg; i <= ph.reg_last_sreg; i++ )
  {
    if ( i == ph.reg_code_sreg )
      continue;
    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) )
      continue;
    bool show = sra.start_ea == ea;
    if ( show )
    {
      sreg_range_t prev_sra;
      if ( get_prev_sreg_range(&prev_sra, ea, i) )
        show = sra.val != prev_sra.val;
    }
    if ( seg_started || show )
    {
      if ( ctx.outbuf.empty() )
      {
        ctx.out_tagon(COLOR_AUTOCMT);
        ctx.out_line(ash.cmnt);
        ctx.out_line(" assume ");
      }
      else
      {
        ctx.out_line(", ");
      }
      ctx.out_line(ph.reg_names[i]);
      ctx.out_char(':');
      if ( sra.val == BADSEL )
        ctx.out_line("nothing");
      else
        ctx.out_btoa(sra.val, 16);
    }
  }
  if ( !ctx.outbuf.empty() )
  {
    ctx.out_tagoff(COLOR_AUTOCMT);
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
}

//--------------------------------------------------------------------------
void idaapi h8500_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL);
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void h8500_t::h8500_footer(outctx_t &ctx) const
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
