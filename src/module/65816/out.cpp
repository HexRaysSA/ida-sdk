/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65816.hpp"
#include "bt.hpp"

//----------------------------------------------------------------------
class out_m65816_t : public outctx_t
{
  out_m65816_t(void) = delete; // not used
  m65816_t &pm() { return *static_cast<m65816_t *>(procmod); }
public:
  void out_dp(const op_t &x);
  void out_addr_near_b(const op_t &x);
  void out_addr_near(const op_t &x);
  void out_addr_far(const op_t &x);
  void print_orig_ea(const op_t &x);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_m65816_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_m65816_t)

//----------------------------------------------------------------------
void out_m65816_t::out_dp(const op_t &x)
{
  sel_t dp = get_sreg(insn.ea, rD);
  if ( dp != BADSEL )
  {
    ea_t orig_ea = dp + x.addr;
    ea_t ea = pm().xlat(orig_ea);

    if ( !out_name_expr(x, ea, BADADDR) )
    {
      out_tagon(COLOR_ERROR);
      out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_8);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
  }
  else
  {
    out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_8);
  }
}

//----------------------------------------------------------------------
void out_m65816_t::out_addr_near_b(const op_t &x)
{
  sel_t db = get_sreg(insn.ea, rB);
  if ( db != BADSEL )
  {
    ea_t orig_ea = (db << 16) + x.addr;
    ea_t ea = pm().xlat(orig_ea);

    if ( !out_name_expr(x, ea, BADADDR) )
    {
      out_tagon(COLOR_ERROR);
      out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
  }
  else
  {
    out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
  }
}

//-------------------------------------------------------------------------
void out_m65816_t::out_addr_near(const op_t &x)
{
  ea_t orig_ea = map_code_ea(insn, x);
  ea_t ea = pm().xlat(orig_ea);
  if ( !out_name_expr(x, ea, BADADDR) )
  {
    out_tagon(COLOR_ERROR);
    out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_m65816_t::out_addr_far(const op_t &x)
{
  ea_t orig_ea = x.addr;
  ea_t ea = pm().xlat(orig_ea);

  if ( !out_name_expr(x, ea, BADADDR) )
  {
    out_tagon(COLOR_ERROR);
    out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_24);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_m65816_t::print_orig_ea(const op_t &x)
{
  if ( !has_cmt(F) )
  {
    char buf[64];
    qsnprintf(buf, sizeof(buf),
              COLSTR(" %s orig=0x%0*a", SCOLOR_AUTOCMT),
              ash.cmnt,
              (x.type == o_far || x.type == o_mem_far) ? 6 : 4,
              x.addr);
    out_line(buf);
  }
}

//----------------------------------------------------------------------
ea_t m65816_t::calc_addr(const op_t &x, ea_t *orig_ea, const insn_t &insn)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_near:
      ea = map_code_ea(insn, x);
      goto XLAT_ADDR;
    case o_far:
    case o_mem_far:
      ea = x.addr;
      goto XLAT_ADDR;
    case o_mem:
      ea = map_data_ea(insn, x);
XLAT_ADDR:
      if ( orig_ea != nullptr )
        *orig_ea = ea;
      return xlat(ea);
    default:
      INTERR(559);
  }
}

//----------------------------------------------------------------------
bool out_m65816_t::out_operand(const op_t &x)
{
  ea_t ea, orig_ea;
  switch ( x.type )
  {
    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;
    case o_imm:
      out_symbol('#');
      out_value(x, 0);
      break;
    case o_near:
    case o_far:
      if ( insn.indirect )
        out_symbol('(');
      ea = pm().calc_addr(x, &orig_ea, insn);
      if ( !out_name_expr(x, ea, BADADDR) )
      {
        uint32 v = x.addr;
        if ( x.type == o_far )
          v &= 0xFFFFFF;
        else
          v &= 0xFFFF;
        out_tagon(COLOR_ERROR);
        out_btoa(v, 16);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
      }
      if ( insn.indirect )
        out_symbol(')');
      if ( orig_ea != ea )
        print_orig_ea(x);
      break;
    case o_mem:
    case o_mem_far:
      {
        if ( insn.indirect )
          out_symbol('(');

        if ( x.type == o_mem_far )
        {
          ea = pm().calc_addr(x, &orig_ea, insn);
          out_addr_far(x);
        }
        else
        {
          sel_t db = get_sreg(insn.ea, rB);
          if ( db == BADSEL )
            ea = orig_ea = x.addr;
          else
            ea = pm().calc_addr(x, &orig_ea, insn);
          out_addr_near_b(x);
        }

        if ( insn.indirect )
          out_symbol(')');

        if ( orig_ea != ea )
          print_orig_ea(x);
      }
      break;
    case o_displ:
      switch ( x.phrase )
      {
        case rS:
          out_register(ph.reg_names[x.phrase]);
          out_symbol(',');
          out_char(' ');
          out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_8);
          break;
        case rD:
          out_register(ph.reg_names[x.phrase]);
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          break;
        case rSiY:
          out_symbol('(');
          out_register("S");
          out_symbol(',');
          out_char(' ');
          out_value(x, OOF_ADDR|OOFS_NOSIGN|OOFW_8);
          out_symbol(',');
          out_char(' ');
          out_register("Y");
          out_symbol(')');
          break;
        case rDi:
        case rSDi:
          out_symbol('(');
          out_register("D");
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          out_symbol(')');
          break;
        case rDiL:
          out_symbol('[');
          out_register("D");
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          out_symbol(']');
          break;
        case rDX:
        case rDY:
          out_register("D");
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          out_symbol(',');
          out_char(' ');
          out_register((x.phrase == rDX) ? "X" : "Y");
          break;
        case riDX:
          out_symbol('(');
          out_register("D");
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          out_symbol(',');
          out_char(' ');
          out_register("X");
          out_symbol(')');
          break;
        case rDiY:
        case rDiLY:
          out_symbol(x.phrase == rDiLY ? '[' : '(');
          out_register("D");
          out_symbol(',');
          out_char(' ');
          out_dp(x);
          out_symbol(x.phrase == rDiLY ? ']' : ')');
          out_symbol(',');
          out_char(' ');
          out_register("Y");
          break;
        case rAbsi:
          out_symbol('(');
          out_addr_near_b(x);
          out_symbol(')');
          break;
        case rAbsiL:
          out_symbol('[');
          out_addr_near_b(x);
          out_symbol(']');
          break;
        case rAbsX:
        case rAbsY:
          out_addr_near_b(x);
          out_symbol(',');
          out_char(' ');
          out_register(x.phrase == rAbsY ? "Y" : "X");
          break;
        case rAbsLX:
          {
            ea_t lorig_ea = x.addr;
            ea_t lea = pm().xlat(lorig_ea);

            out_addr_far(x);
            out_symbol(',');
            out_char(' ');
            out_register("X");

            if ( lorig_ea != lea )
              print_orig_ea(x);
          }
          break;
        case rAbsXi:
          out_symbol('(');
          out_addr_near(x); // jmp, jsr
          out_symbol(',');
          out_char(' ');
          out_register("X");
          out_symbol(')');
          break;
        default:
          goto err;
      }
      break;
    case o_void:
      return 0;
    default:
    err:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}


//----------------------------------------------------------------------
static bool forced_print(flags64_t F, int reg)
{
  return (reg == rFm || reg == rFx) && is_func(F);
}

//----------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
void m65816_t::m65816_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  char buf[MAXSTR];
  char *ptr = buf;
  char *end = buf + sizeof(buf);
  segment_t *seg = getseg(ea);
  bool seg_started = (ea == seg->start_ea);
  for ( int reg=ph.reg_first_sreg; reg <= ph.reg_last_sreg; reg++ )
  {
    if ( reg == rCs )
      continue;
    sreg_range_t srrange;
    if ( !get_sreg_range(&srrange, ea, reg) )
      continue;
    sel_t curval = srrange.val;
    if ( seg_started || srrange.start_ea == ea )
    {
      sreg_range_t prev;
      bool prev_exists = ea > 0 && get_sreg_range(&prev, ea - 1, reg);
      if ( seg_started
        || (prev_exists && prev.val != curval)
        || forced_print(ctx.F, reg) )
      {
        if ( reg == rFm || reg == rFx )
        {
          ctx.gen_printf(0, ".%c%d", reg == rFm ? 'A' : 'I', curval > 0 ? 8 : 16);
        }
        else
        {
          if ( ptr != buf )
            APPCHAR(ptr, end, ' ');
          ptr += qsnprintf(ptr, end-ptr, "%s=%a", ph.reg_names[reg], curval);
        }
      }
    }
  }
  if ( ptr != buf )
    ctx.gen_cmt_line("%s", buf);
}

//----------------------------------------------------------------------
void out_m65816_t::out_insn(void)
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
void m65816_t::m65816_header(outctx_t &ctx) const
{
  ctx.gen_cmt_line("%s Processor:        %s", ash.cmnt, inf_get_procname().c_str());
  ctx.gen_cmt_line("%s Target assembler: %s", ash.cmnt, ash.name);
  if ( ash.header != nullptr )
    for ( const char *const *ptr=ash.header; *ptr != nullptr; ptr++ )
      ctx.flush_buf(*ptr,0);
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void m65816_t::m65816_segstart(outctx_t &ctx, segment_t *Srange) const
{
  qstring name;
  get_visible_segm_name(&name, Srange);
  if ( ash.uflag & UAS_SECT )
  {
    ctx.gen_printf(0, COLSTR("%s: .section",SCOLOR_ASMDIR), name.c_str());
  }
  else
  {
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s.segment %s",SCOLOR_ASMDIR),
                   (ash.uflag & UAS_NOSEG) ? ash.cmnt : "",
                   name.c_str());
    if ( ash.uflag & UAS_SELSG )
      ctx.flush_buf(name.c_str(), DEFAULT_INDENT);
    if ( ash.uflag & UAS_CDSEG )
      ctx.flush_buf(COLSTR("CSEG",SCOLOR_ASMDIR), DEFAULT_INDENT);  // XSEG - eXternal memory
  }
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(Srange);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s",SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void m65816_t::m65816_footer(outctx_t &ctx) const
{
  char buf[MAXSTR];
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    char *ptr = buf;
    char *end = buf + sizeof(buf);
    APPEND(ptr, end, ash.end);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      if ( ash.uflag & UAS_NOENS )
        APPEND(ptr, end, ash.cmnt);
      APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, name.begin());
    }
    ctx.flush_buf(buf, DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}
