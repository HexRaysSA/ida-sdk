/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "f2mc.hpp"
#include <frame.hpp>
#include <segregs.hpp>

//----------------------------------------------------------------------
class out_f2mc_t : public outctx_t
{
  out_f2mc_t(void) = delete; // not used
public:
  void out_address(ea_t ea, const op_t &x);
  void out_reglist(ushort reglist);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_f2mc_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_f2mc_t)

//----------------------------------------------------------------------
void out_f2mc_t::out_address(ea_t ea, const op_t &x)
{
  if ( !out_name_expr(x, ea, x.addr & 0xffff) )
  {
    out_tagon(COLOR_ERROR);
    out_btoa(x.addr, 16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_f2mc_t::out_reglist(ushort reglist)
{
  out_symbol('(');
  bool first = true;
  int i = 0;
  while ( i < 8 )
  {
    int size = 1;
    if ( (reglist>>i) & 1 )
    {
      while ( (i + size < 8) && ((reglist>>(i+size)) & 1 ) )
        size++;
      if ( first )
        first = false;
      else
        out_symbol(',');
      out_register(ph.reg_names[RW0+i]);
      if ( size > 1 )
      {
        out_symbol('-');
        out_register(ph.reg_names[RW0+i+size-1]);
      }
    }
    i+=size;
  }
  out_symbol(')');
}

//----------------------------------------------------------------------
bool f2mc_t::exist_bits(ea_t ea, int bitl, int bith)
{
  for ( int i = bitl; i <= bith; i++ )
  {
    const char *name = find_bit(ea, i);
    if ( name != nullptr && name[0] != '\0' )
      return true;
  }
  return false;
}

// adjust to respect 16 bits an 32 bits definitions
void f2mc_t::adjust_ea_bit(ea_t &ea, int &bit)
{
  const char *name = find_sym(ea);
  if ( name != nullptr && name[0] != '\0' )
    return;
  name = find_sym(ea-1);
  if ( name != nullptr && name[0] != '\0' && exist_bits(ea-1, 8, 15) )
  {
    ea--;
    bit+=8;
    return;
  }
  name = find_sym(ea-2);
  if ( name != nullptr && name[0] != '\0' && exist_bits(ea-2, 16, 31) )
  {
    ea-=2;
    bit+=16;
    return;
  }
  name = find_sym(ea-3);
  if ( name != nullptr && name[0] != '\0' && exist_bits(ea-3, 16, 31) )
  {
    ea-=3;
    bit+=24;
    return;
  }
}

//----------------------------------------------------------------------
int calc_outf(const op_t &x)
{
  if ( x.type == o_imm )
    return OOFS_IFSIGN|OOFW_IMM;

  QASSERT(10103, x.type == o_displ);
  if ( x.addr_dtyp == dt_byte )
    return OOF_ADDR|OOFS_NEEDSIGN|OOF_SIGNED|OOFW_8;
  if ( x.addr_dtyp == dt_word )
    return OOF_ADDR|OOFS_NEEDSIGN|OOF_SIGNED|OOFW_16;
  INTERR(10104);
}

//----------------------------------------------------------------------
bool out_f2mc_t::out_operand(const op_t &x)
{
  f2mc_t &pm = *static_cast<f2mc_t *>(procmod);
  ea_t ea;

  if ( insn.prefix_bank && (insn.op_bank == x.n)
    && (insn.prefix_bank != insn.default_bank) )
  {
    out_register(ph.reg_names[insn.prefix_bank]);
    out_symbol(':');
  }

  for ( int i = 0; i < x.at_qty; i++ )
    out_symbol('@');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;

    case o_near:
    case o_far:
      {
        ea_t addr = x.addr;
        if ( x.type == o_near )
          addr = calc_code_mem(insn, addr);
        out_address(addr, x);
      }
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, calc_outf(x));
      break;

    case o_mem:
      {
        ea = calc_data_mem(x.addr);
        if ( x.addr_dtyp != 'i' ) // data address
        {
          if ( x.addr_dtyp )
          {
            out_symbol(x.addr_dtyp);
            out_symbol(':');
          }
          out_address(ea, x);
          if ( x.special_mode == MODE_BIT )
          {
            out_symbol(':');
            out_symbol('0' + x.byte_bit);
          }
        }
        else // IO address
        {
          int bit = x.byte_bit;
          out_symbol('i'); out_symbol(':');
          if ( x.special_mode == MODE_BIT )
            pm.adjust_ea_bit(ea, bit);
          const char *name = pm.find_sym(ea);
          if ( name != nullptr && name[0] != '\0' )
          {
            out_addr_tag(ea);
            out_line(name, COLOR_IMPNAME);
          }
          else
          {
            out_address(ea, x);
          }
          if ( x.special_mode == MODE_BIT )
          {
            name = pm.find_bit(ea,bit);
            if ( name != nullptr && name[0] != '\0' )
            {
              out_symbol('_');
              out_line(name, COLOR_IMPNAME);
            }
            else
            {
              out_symbol(':');
              out_tagon(COLOR_SYMBOL);
              out_btoa(bit, 10);
              out_tagoff(COLOR_SYMBOL);
            }
          }
        }
      }
      break;

    case o_phrase:
      out_register(ph.reg_names[x.reg]);
      switch ( x.special_mode )
      {
        case MODE_INC:
          out_symbol('+');
          break;
        case MODE_INDEX:
          out_symbol('+');
          out_register(ph.reg_names[x.f2mc_index]);
          break;
      }
      break;

    case o_displ:
      out_register(ph.reg_names[x.reg]);
      out_value(x, calc_outf(x));
      break;

    case o_reglist:
      out_reglist(x.reg);
      break;

    default:
      error("interr: out");
  }
  return 1;
}

//----------------------------------------------------------------------
void out_f2mc_t::out_insn(void)
{
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

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void f2mc_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  char buf[MAX_NUMBUF];
  btoa(buf, sizeof(buf), value);
  ctx.gen_cmt_line("assume %s = %s", ph.reg_names[reg], buf);
}

//--------------------------------------------------------------------------
// function to produce assume directives
//lint -esym(1764, ctx) could be made const
void f2mc_t::f2mc_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( seg == nullptr || (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 )
    return;

  for ( int i = ph.reg_first_sreg; i <= ph.reg_last_sreg; ++i )
  {
    if ( i == ph.reg_code_sreg )
      continue;
    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) )
      continue;
    sel_t now = get_sreg(ea, i);
    bool seg_started = (ea == seg->start_ea);
    if ( seg_started || sra.start_ea == ea )
    {
      sreg_range_t prev_sra;
      bool prev_exists = ea > 0 && get_sreg_range(&prev_sra, ea - 1, i);
      if ( seg_started || (prev_exists && get_sreg(prev_sra.start_ea, i) != now) )
        print_segment_register(ctx, i, now);
    }
  }
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void f2mc_t::f2mc_segstart(outctx_t &ctx, segment_t *Srange) const
{
  if ( is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_visible_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  ctx.gen_printf(DEFAULT_INDENT,
                 COLSTR(".section %s, %s", SCOLOR_ASMDIR),
                 sname.c_str(),
                 sclas == "CODE" ? "code"
                 : sclas == "BSS" ? "data"
                 : "const");
  if ( Srange->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Srange->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi f2mc_segend(outctx_t &, segment_t *) {}

//--------------------------------------------------------------------------
void f2mc_t::f2mc_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM, ioh.device.c_str(), ioh.deviceparams.c_str());
  ctx.gen_printf(0, "");
  ctx.gen_printf(0, COLSTR("#include <_ffmc16_a.asm>", SCOLOR_ASMDIR));
  ctx.gen_header_extra();
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void f2mc_t::f2mc_footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  ctx.gen_printf(DEFAULT_INDENT,
                 COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                 ash.end,
                 ash.cmnt,
                 name);
}
