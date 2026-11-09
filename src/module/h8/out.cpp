/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"
#include <segregs.hpp>
#include <typeinf.hpp>

//----------------------------------------------------------------------
class out_h8_t : public outctx_t
{
  out_h8_t(void) = delete; // not used
public:
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void out_bad_address(ea_t addr);
  void out_sizer(char szfl);

  void attach_name_comment(const op_t &x, ea_t v) const; // modifies idb!

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_h8_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_h8_t)

//----------------------------------------------------------------------
int h8_t::get_displ_outf(const op_t &x, flags64_t F)
{
  return OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED
       | ((is_stkvar(F, x.n) || (x.szfl & disp_32) || advanced()) ? OOFW_32 : OOFW_16);
}

//----------------------------------------------------------------------
void out_h8_t::out_bad_address(ea_t addr)
{
  h8_t &pm = *static_cast<h8_t *>(procmod);
  const char *name = pm.find_sym(addr);
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
ea_t h8_t::trim_ea_branch(ea_t ea) const
{
  switch ( ptype & MODE_MASK )
  {
    case MODE_MID:
    case MODE_ADV:
      return ea & 0x00FFFFFF;
    case MODE_MAX:
      return ea;
  }
  return ea & 0x0000FFFF;
}

//----------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea)
{
  return to_ea(insn.cs, ea);
}

//----------------------------------------------------------------------
ea_t calc_mem_sbr_based(const insn_t &insn, ea_t ea)
{
  sel_t base = get_sreg(insn.ea, SBR);
  return (base & 0xFFFFFF00) | (ea & 0x000000FF);
}

//----------------------------------------------------------------------
void out_h8_t::out_sizer(char szfl)
{
  h8_t &pm = *static_cast<h8_t *>(procmod);
  if ( pm.show_sizer == -1 )
    pm.show_sizer = !qgetenv("H8_NOSIZER");
  if ( !pm.show_sizer )
    return;

  if ( szfl & disp_2 )
    return;
  int size = (szfl & disp_32) ? 32 :
             (szfl & disp_24) ? 24 :
             (szfl & disp_16) ? 16 : 8;
  out_symbol(':');
  out_long(size, 10);
}

//----------------------------------------------------------------------
void out_h8_t::attach_name_comment(const op_t &x, ea_t v) const
{
  if ( !has_cmt(F) )
  {
    qstring qbuf;
    if ( get_name_expr(&qbuf, insn.ea, x.n, v, BADADDR) > 0 )
      set_cmt(insn.ea, qbuf.begin(), false);
  }
}

//----------------------------------------------------------------------
static ea_t get_data_ref(ea_t ea)
{
  ea_t to = BADADDR;
  xrefblk_t xb;
  for ( bool ok=xb.first_from(ea, XREF_DATA); ok; ok=xb.next_from() )
  {
    if ( xb.type == dr_O )
      return xb.to;
  }
  return to;
}

//----------------------------------------------------------------------
bool out_h8_t::out_operand(const op_t &x)
{
  h8_t &pm = *static_cast<h8_t *>(procmod);
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_reglist:
      if ( pm.is_hew_asm() )
        out_symbol('(');
      outreg(x.reg);
      out_symbol('-');
      outreg(x.reg+x.nregs-1);
      if ( pm.is_hew_asm() )
        out_symbol(')');
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_mem:
      out_symbol('@');
      if ( x.memtype == mem_vec7 || x.memtype == mem_ind )
        out_symbol('@');
      // no break
    case o_near:
      {
        ea_t ea = x.memtype == mem_sbr
                ? calc_mem_sbr_based(insn, x.addr)
                : calc_mem(insn, x.addr);
        if ( pm.is_hew_asm() && (x.szfl & disp_24) )
          out_symbol('@');
        out_addr_tag(ea);
        if ( x.memtype == mem_sbr
          || !out_name_expr(x, ea, x.addr) )
        {
          out_bad_address(x.addr);
          if ( x.memtype == mem_sbr )
            attach_name_comment(x, ea);
        }
        if ( x.memtype != mem_vec7 )
          out_sizer(x.szfl);
      }
      break;

    case o_phrase:
      out_symbol('@');

      if ( x.phtype == ph_pre_dec )
        out_symbol('-');
      else if ( x.phtype == ph_pre_inc )
        out_symbol('+');

      outreg(x.phrase);

      if ( x.phtype == ph_post_inc )
        out_symbol('+');
      else if ( x.phtype == ph_post_dec )
        out_symbol('-');

      {
        ea_t ea = get_data_ref(insn.ea);
        if ( ea != BADADDR )
          attach_name_comment(x, ea);
      }
      break;

    case o_displ:
      out_symbol('@');
      out_symbol('(');
      {
        int outf = pm.get_displ_outf(x, F);
        out_value(x, outf);
        out_sizer(x.szfl);
      }
      out_symbol(',');
      if ( x.displtype == dt_movaop1 )
      {
        op_t ea;
        memset(&ea, 0, sizeof(ea));
        ea.offb   = insn.Op1.offo;
        ea.type   = insn.Op1.idxt;
        ea.phrase = insn.Op1.phrase;
        ea.phtype = insn.Op1.idxdt;
        ea.addr   = insn.Op1.value;
        ea.szfl   = insn.Op1.idxsz;
        out_operand(ea);
        out_symbol('.');
        out_symbol(x.szfl & idx_byte ? 'b' :
                   x.szfl & idx_word ? 'w' : 'l');
      }
      else if ( x.displtype == dt_regidx )
      {
        outreg(x.reg);
        out_symbol('.');
        out_symbol(x.szfl & idx_byte ? 'b' :
                   x.szfl & idx_word ? 'w' : 'l');
      }
      else
      {
        outreg(x.reg);
      }
      out_symbol(')');
      break;

    case o_pcidx:
      outreg(x.reg);
      break;

    default:
      INTERR(10096);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_h8_t::out_proc_mnem(void)
{
  static const char *const postfixes[] = { nullptr, ".b", ".w", ".l" };
  const char *postfix = postfixes[insn.auxpref];
  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
void out_h8_t::out_insn(void)
{
  out_mnemonic();

  bool showOp1 = insn.Op1.shown();
  if ( showOp1 )
    out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    if ( showOp1 )
    {
      out_symbol(',');
      out_char(' ');
    }
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

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void h8_t::h8_segstart(outctx_t &ctx, segment_t *Srange) const
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
  };

  if ( Srange == nullptr || is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  if ( !print_predefined_segname(ctx, &sname, predefined, qnumber(predefined)) )
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                   sclas == "CODE" ? ".text" : ".data",
                   ash.cmnt,
                   sname.c_str());
}

//--------------------------------------------------------------------------
void idaapi h8_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void h8_t::h8_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || seg == nullptr )
    return;
  bool seg_started = (ea == seg->start_ea);

  for ( int i = ph.reg_first_sreg; i <= ph.reg_last_sreg; i++ )
  {
    if ( i == ph.reg_code_sreg || i == ph.reg_data_sreg )
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
      ctx.gen_cmt_line("%-*s assume %s: %a", int(inf_get_indent()-strlen(ash.cmnt)-2), "", ph.reg_names[i], trunc_uval(sra.val));
  }
}

//--------------------------------------------------------------------------
//  Generate stack variable definition line
//  If this function is nullptr, then the kernel will create the line itself.
void h8_t::h8_gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const
{
  char sign = ' ';
  if ( v < 0 )
  {
    v = -v;
    sign = '-';
  }

  char num[MAX_NUMBUF];
  btoa(num, sizeof(num), v);

  if ( is_hew_asm() )
  {
    ctx.out_printf(COLSTR("%s", SCOLOR_LOCNAME)
                   COLSTR(": ", SCOLOR_SYMBOL)
                   COLSTR(".assign", SCOLOR_ASMDIR)
                   COLSTR(" %c", SCOLOR_SYMBOL)
                   COLSTR("%s", SCOLOR_DNUM),
                   stkvar->name.c_str(), sign, num);
  }
  else
  {
    ctx.out_printf(COLSTR("%-*s", SCOLOR_LOCNAME)
                   COLSTR("= %c", SCOLOR_SYMBOL)
                   COLSTR("%s", SCOLOR_DNUM),
                   inf_get_indent(), stkvar->name.c_str(), sign, num);
  }
}

//--------------------------------------------------------------------------
void h8_t::h8_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL);

  if ( ptype == P300 )
    return;
  char procdir[MAXSTR];
  qsnprintf(procdir, sizeof(procdir), ".h8300%s%s",
            is_h8sx() ? "sx" : is_h8s() ? "s" : "h",
            advanced() ? "" : "n");
  ctx.gen_empty_line();
  ctx.gen_printf(DEFAULT_INDENT, "%s", procdir);
}

//--------------------------------------------------------------------------
void h8_t::h8_footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                   ash.end,
                   ash.cmnt,
                   name);
}
