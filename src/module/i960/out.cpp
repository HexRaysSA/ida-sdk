/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

//----------------------------------------------------------------------
class out_i960_t : public outctx_t
{
  out_i960_t(void) = delete; // not used
  i960_t &pm() { return *static_cast<i960_t *>(procmod); }
public:
  void outreg(int r);
  bool outmem(const op_t &x, ea_t ea, bool printerr = true);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_i960_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_i960_t)

//----------------------------------------------------------------------
void out_i960_t::outreg(int r)
{
  if ( r > MAXREG )
    warning("%a: outreg: illegal reg %d", insn.ea, r);
  else
    out_register(ph.reg_names[r]);
}

//----------------------------------------------------------------------
bool out_i960_t::outmem(const op_t &x, ea_t ea, bool printerr)
{
  if ( out_name_expr(x, ea, BADADDR) )
    return true;
  const char *p = pm().find_sym(x.addr);
  if ( p == nullptr || p[0] == '\0' )
  {
    if ( printerr )
    {
      out_tagon(COLOR_ERROR);
      out_btoa(x.addr, 16);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME,insn.ea);
    }
  }
  else
  {
    out_line(p, COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool out_i960_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {

    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_imm:
      {
        if ( insn.itype == I960_lda && (is_off(F, x.n) || !is_defarg(F, x.n)) )
        {
          op_t y = x;
          y.addr = x.value;
          if ( outmem(y, calc_mem(insn, y.addr), false) )
            break;
        }
        out_value(x, OOFS_IFSIGN|OOFW_IMM);
      }
      break;

    case o_displ:
      {
        if ( x.addr != 0
          || is_off(F, x.n)
          || is_stkvar(F, x.n)
          || is_enum(F, x.n)
          || is_stroff(F, x.n) )
        {
          out_value(x, OOFS_IFSIGN|OOF_SIGNED|OOF_ADDR|OOFW_32);
        }
      }
      // no break
    case o_phrase:
      if ( uchar(x.reg) != uchar(-1) )
      {
        out_symbol('(');
        outreg(x.reg);
        out_symbol(')');
      }
      if ( uchar(x.index) != uchar(-1) )
      {
        out_symbol('[');
        outreg(x.index);
        if ( x.scale != 1 )
        {
          out_tagon(COLOR_SYMBOL);
          out_char('*');
          out_btoa(x.scale, 10);
          out_tagoff(COLOR_SYMBOL);
        }
        out_symbol(']');
      }
      break;

    case o_mem:
    case o_near:
      outmem(x, calc_mem(insn, x.addr));
      break;

    default:
      INTERR(10365);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_i960_t::out_proc_mnem(void)
{
  const char *postfix = nullptr;
//  if ( insn.auxpref & aux_t ) postfix = ".t";
  if ( insn.auxpref & aux_f )
    postfix = ".f";
  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
void out_i960_t::out_insn(void)
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

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void i960_t::i960_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  const char *const predefined[] =
  {
    ".text",    // Text section
//    ".rdata",   // Read-only data section
    ".data",    // Data sections
//    ".lit8",    // Data sections
//    ".lit4",    // Data sections
//    ".sdata",   // Small data section, addressed through register $gp
//    ".sbss",    // Small bss section, addressed through register $gp
//    ".bss",     // bss (block started by storage) section, which loads zero-initialized data
  };

  if ( is_spec_segm(Sarea->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, Sarea);
  get_segm_class(&sclas, Sarea);

  if ( sname == ".bss" )
  {
    int align = 0;
    switch ( Sarea->align )
    {
      case saAbs:        align = 0;  break;
      case saRelByte:    align = 0;  break;
      case saRelWord:    align = 1;  break;
      case saRelPara:    align = 4;  break;
      case saRelPage:    align = 8;  break;
      case saRelDble:    align = 2;  break;
      case saRel4K:      align = 12; break;
      case saGroup:      align = 0;  break;
      case saRel32Bytes: align = 5;  break;
      case saRel64Bytes: align = 6;  break;
      case saRelQword:   align = 3;  break;
    };
    asize_t size = Sarea->type == SEG_NULL ? 0 : Sarea->size();
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), size);
    validate_name(&sname, VNT_IDENT);
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s %s, %d", SCOLOR_ASMDIR),
                   sname.c_str(), buf, align);
  }
  else
  {
    if ( !print_predefined_segname(ctx, &sname, predefined, qnumber(predefined)) )
      ctx.gen_printf(DEFAULT_INDENT,
                     COLSTR("%s", SCOLOR_ASMDIR) "" COLSTR("%s %s", SCOLOR_AUTOCMT),
                     sclas == "CODE" ? ".text" : ".data",
                     ash.cmnt,
                     sname.c_str());
  }
}

//--------------------------------------------------------------------------
void idaapi i960_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi i960_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void i960_t::i960_footer(outctx_t &ctx) const
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

