
#include <ctype.h>
#include "kr1878.hpp"
#include <segregs.hpp>


//----------------------------------------------------------------------
class out_kr1878_t : public outctx_t
{
  out_kr1878_t(void) = delete; // not used
  kr1878_t &pm() { return *static_cast<kr1878_t *>(procmod); }
public:
  void outreg(int r) { out_register(ph.reg_names[r]); }
  bool out_port_address(ea_t addr);
  void out_bad_address(ea_t addr);
  void out_address(ea_t ea, const op_t &x);
  void out_ip_rel(int displ);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_kr1878_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_kr1878_t)

//----------------------------------------------------------------------
bool out_kr1878_t::out_port_address(ea_t addr)
{
  const ioport_t *port = pm().find_port(addr);
  if ( port != nullptr && !port->name.empty() )
  {
    out_line(port->name.c_str(), COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
void out_kr1878_t::out_bad_address(ea_t addr)
{
  if ( !out_port_address(addr) )
  {
    out_tagon(COLOR_ERROR);
    out_btoa(addr, 16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_kr1878_t::out_address(ea_t ea, const op_t &x)
{
  segment_t *s = getseg(ea);
  ea_t value = s != nullptr ? ea - get_segm_base(s) : ea;
  if ( !out_name_expr(x, ea, value) )
  {
    out_tagon(COLOR_ERROR);
    out_printf("%a", ea);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_kr1878_t::out_ip_rel(int displ)
{
  out_printf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
               ash.a_curip, displ);
}

//----------------------------------------------------------------------
bool out_kr1878_t::out_operand(const op_t & x)
{
  ea_t ea;
  if ( x.type == o_imm )
    out_symbol('#');
  char buf[MAXSTR];

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);

      break;

    case o_mem:
      // no break;
    case o_near:
      {
        ea = calc_mem(insn, x);
        if ( ea == insn.ea+insn.size )
          out_ip_rel(insn.size);
        else if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      qsnprintf(buf, sizeof(buf), "%%%c%" FMT_EA "x", 'a' + x.reg, x.value);

      ea = pm().calc_data_mem(insn, x, as + x.reg);
      if ( ea != BADADDR && (x.reg != SR3 || x.value < 6) )
      {
        out_line(buf, COLOR_AUTOCMT);
        out_symbol(' ');
        out_address(ea, x);
      }
      else
      {
        out_line(buf, COLOR_REG);
      }
      break;

    default:
      interr(insn, "out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_kr1878_t::out_insn(void)
{
  out_mnemonic();

  bool comma = out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    if ( comma )
      out_symbol(',');
    out_one_operand(1);
  }
  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_one_operand(2);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void kr1878_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  if ( value != BADADDR )
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
// function to produce assume directives
void kr1878_t::kr1878_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( seg == nullptr || (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 )
    return;
  bool seg_started = (ea == seg->start_ea);

  for ( int i = ph.reg_first_sreg; i <= ph.reg_last_sreg; ++i )
  {
    if ( i == ph.reg_code_sreg )
      continue;
    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) )
      continue;
    sel_t now = get_sreg(ea, i);
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
void kr1878_t::kr1878_segstart(outctx_t &ctx, segment_t *Srange) const
{
  if ( is_spec_segm(Srange->type) )
    return;

  qstring sclas;
  get_segm_class(&sclas, Srange);

  if ( sclas == "CODE" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( sclas == "DATA" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".data", SCOLOR_ASMDIR));

  if ( Srange->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Srange->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi kr1878_segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi kr1878_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL);
}

//--------------------------------------------------------------------------
void kr1878_t::kr1878_footer(outctx_t &ctx) const
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

