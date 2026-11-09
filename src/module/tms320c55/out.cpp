/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c55.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>

//? problem with stack variables:
// SP+offsets point to a word, but stack variables works at the byte level
// => variables offsets aren't just

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c55_t : public outctx_t
{
  out_tms320c55_t(void) = delete; // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
  void out_address(const op_t &op);
  void out_shift(uval_t value);
  void out_symbol_shift(const op_t &op, bool is_out = false);
  void out_operators_begin(const op_t &op);
  void out_operators_end(const op_t &op);
  void out_reg(const op_t &op);
  void out_cond(const op_t &x);
  void out_relop(const op_t &op);
};
CASSERT(sizeof(out_tms320c55_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_tms320c55_t)

//----------------------------------------------------------------------
void out_tms320c55_t::out_address(const op_t &op)
{
  tms320c55_t &pm = *static_cast<tms320c55_t *>(procmod);
  ea_t ea = BADADDR;
  if ( op.type == o_near )
    ea = calc_code_mem(insn, op.addr);
  else if ( op.type == o_mem )
    ea = calc_data_mem(insn, op);
  else if ( op.type == o_io )
    ea = calc_io_mem(insn, op);

  int reg = -1;
  if ( op.type == o_mem )
    reg = pm.get_mapped_register(ea);

  // print begin of the modifier
  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
      break;
    case TMS_MODIFIER_DMA:
      if ( (int)reg == -1 )
        out_symbol('@');
      break;
    case TMS_MODIFIER_ABS16:
    case TMS_MODIFIER_PTR:
      out_symbol('*');
      if ( op.tms_modifier == TMS_MODIFIER_ABS16 )
        out_line("abs16", COLOR_SYMBOL);
      out_line("(#", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_MMAP:
      out_line("mmap(@", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_PORT:
      out_line("port(#", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_PORT_AT:
      out_line("port(@", COLOR_SYMBOL);
      break;
    default:
      error("interr: out: o_address: modifier_begin");
  }

  if ( op.type != o_io )
  {
    if ( int(reg) != -1 ) // memory mapped register
    {
      out_register(ph.reg_names[reg]);
    }
    else
    {
#ifndef TMS320C55_NO_NAME_NO_REF
      if ( !out_name_expr(op, ea, ea) )
#endif
      {
        out_tagon(COLOR_ERROR);
        out_btoa(op.addr, 16);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
      }
    }
  }
  else // IO address
  {
    if ( ea != BADADDR )
    {
      const char *name = nullptr;
      if ( pm.idpflags & TMS320C55_IO )
        name = pm.find_sym(ea);
      if ( name != nullptr && name[0] != '\0' )
        out_line(name, COLOR_IMPNAME);
      else
        out_btoa(ea, 16);
    }
    else
    {
      out_tagon(COLOR_ERROR);
      out_btoa(op.addr, 16);
      out_tagoff(COLOR_ERROR);
    }
  }

  // print end of the modifier
  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
    case TMS_MODIFIER_DMA:
      break;
    case TMS_MODIFIER_ABS16:
    case TMS_MODIFIER_PTR:
    case TMS_MODIFIER_MMAP:
    case TMS_MODIFIER_PORT:
    case TMS_MODIFIER_PORT_AT:
      out_symbol(')'); break;
    default:
      error("interr: out: o_address: modifier_begin");
  }
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_shift(uval_t value)
{
  out_symbol('#');
  char buf[8];
  qsnprintf(buf, sizeof(buf), "%d", (int)value);
  out_line(buf, COLOR_DNUM);
}

//--------------------------------------------------------------------------
// output shift symbol (if out = true, output outside of brackets)
void out_tms320c55_t::out_symbol_shift(const op_t &op, bool is_out)
{
  if ( op.tms_shift != TMS_OP_SHIFT_NULL )
  {
    if ( ((op.tms_shift & TMS_OP_SHIFT_OUT) != 0) == is_out ) // check if the shift must be print inside or outside the brackets
    {
      switch ( op.tms_shift & TMS_OP_SHIFT_TYPE )
      {
        case TMS_OP_SHIFTL_IMM:
          out_line(" << ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_SHIFTL_REG:
          out_line(" << ",COLOR_SYMBOL);
          out_register(ph.reg_names[op.tms_shift_value]);
          break;
        case TMS_OP_SHIFTR_IMM:
          out_line(" >> ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_EQ:
          out_line(" == ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        case TMS_OP_NEQ:
          out_line(" != ",COLOR_SYMBOL);
          out_shift(op.tms_shift_value);
          break;
        default:
          error("interr: out: out_symbol_shift");
      }
    }
  }
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_operators_begin(const op_t &op)
{
  static const char *const strings[TMS_OPERATORS_SIZE] =
  {
    "T3=",       "!",          "uns(",      "dbl(",
    "rnd(",      "pair(",      "lo(",       "hi(",
    "low_byte(", "high_byte(", "saturate(", "dual(",
    "port("
  };
  short operators = (op.tms_operator2 << 8) | (op.tms_operator1 &0xFF);
  for ( int i = 0; i < TMS_OPERATORS_SIZE; i++ )
    if ( operators & (1<<i) )
      out_line(strings[i], COLOR_SYMBOL);
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_operators_end(const op_t &op)
{
  short operators = (op.tms_operator2 << 8) | (op.tms_operator1 &0xFF);
  int brackets = 0;
  for ( int i = 0; i < TMS_OPERATORS_SIZE; i++ )
    if ( operators & (1<<i) )
      brackets++;
  if ( operators & TMS_OPERATOR_T3 )
    brackets--;
  if ( operators & TMS_OPERATOR_NOT )
    brackets--;
  for ( int i = 0; i < brackets; i++ )
    out_line(")", COLOR_SYMBOL);
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_reg(const op_t &op)
{
  const char *reg = ph.reg_names[op.reg];

  switch ( op.tms_modifier )
  {
    case TMS_MODIFIER_NULL:
      out_register(reg);
      break;
    case TMS_MODIFIER_REG:
      out_symbol('*');
      out_register(reg);
      break;
    case TMS_MODIFIER_REG_P:
      out_symbol('*');
      out_register(reg);
      out_symbol('+');
      break;
    case TMS_MODIFIER_REG_M:
      out_symbol('*');
      out_register(reg);
      out_symbol('-');
      break;
    case TMS_MODIFIER_REG_P_T0:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register(ph.reg_names[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_P_T1:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register(ph.reg_names[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T0:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register(ph.reg_names[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T1:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register(ph.reg_names[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_T0:
      out_symbol('*');
      out_register(reg);
      out_symbol('(');
      out_register(ph.reg_names[T0]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_OFFSET:
    case TMS_MODIFIER_P_REG_OFFSET:
      out_symbol('*');
      if ( op.tms_modifier == TMS_MODIFIER_P_REG_OFFSET )
        out_symbol('+');
      out_register(reg);
      out_line("(#", COLOR_SYMBOL);
      out_value(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_SHORT_OFFSET:
      out_symbol('*');
      out_register(reg);
      out_line("(short(#", COLOR_SYMBOL);
      out_value(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      out_line("))", COLOR_SYMBOL);
      break;
    case TMS_MODIFIER_REG_T1:
      out_symbol('*');
      out_register(reg);
      out_symbol('(');
      out_register(ph.reg_names[T1]);
      out_symbol(')');
      break;
    case TMS_MODIFIER_P_REG:
      out_symbol('+');
      out_register(reg);
      break;
    case TMS_MODIFIER_M_REG:
      out_symbol('-');
      out_register(reg);
      break;
    case TMS_MODIFIER_REG_P_T0B:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('+');
      out_register("T0B");
      out_symbol(')');
      break;
    case TMS_MODIFIER_REG_M_T0B:
      out_line("*(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol('-');
      out_register("T0B");
      out_symbol(')');
      break;
    default:
      error("interr: out: o_reg: modifier");
  }
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_cond(const op_t &x)
{
  const char *reg = ph.reg_names[x.reg];
  switch ( x.value )
  {
    case 0x00:
      out_register(reg);
      out_line(" == #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x10:
      out_register(reg);
      out_line(" != #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x20:
      out_register(reg);
      out_line(" < #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x30:
      out_register(reg);
      out_line(" <= #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x40:
      out_register(reg);
      out_line(" > #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x50:
      out_register(reg);
      out_line(" >= #", COLOR_SYMBOL);
      out_long(0, 10);
      break;
    case 0x60:
      out_line("overflow(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol(')');
      break;
    case 0x64:
      out_register(ph.reg_names[TC1]);
      break;
    case 0x65:
      out_register(ph.reg_names[TC2]);
      break;
    case 0x66:
      out_register(ph.reg_names[CARRY]);
      break;
    case 0x68:
      out_register(ph.reg_names[TC1]);
      out_line(" & ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x69:
      out_register(ph.reg_names[TC1]);
      out_line(" & !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x6A:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" & ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x6B:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" & !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x70:
      out_line("!overflow(", COLOR_SYMBOL);
      out_register(reg);
      out_symbol(')');
      break;
    case 0x74:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      break;
    case 0x75:
      out_symbol('!');
      out_register(ph.reg_names[TC2]);
      break;
    case 0x76:
      out_symbol('!');
      out_register(ph.reg_names[CARRY]);
      break;
    case 0x78:
      out_register(ph.reg_names[TC1]);
      out_line(" | ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x79:
      out_register(ph.reg_names[TC1]);
      out_line(" | !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7A:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" | ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7B:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" | !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7C:
      out_register(ph.reg_names[TC1]);
      out_line(" ^ ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7D:
      out_register(ph.reg_names[TC1]);
      out_line(" ^ !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7E:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" ^ ", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    case 0x7F:
      out_symbol('!');
      out_register(ph.reg_names[TC1]);
      out_line(" ^ !", COLOR_SYMBOL);
      out_register(ph.reg_names[TC2]);
      break;
    default:
      error("interr: out: o_cond");
  }
}

//--------------------------------------------------------------------------
void out_tms320c55_t::out_relop(const op_t &op)
{
  out_register(ph.reg_names[op.reg]);

  const char *relop = nullptr;
  switch ( op.tms_relop )
  {
    case 0:
      relop = " == ";
      break;
    case 1:
      relop = " < ";
      break;
    case 2:
      relop = " >= ";
      break;
    case 3:
      relop = " != ";
      break;
    default:
      error("interr: out: o_relop");
  }
  out_line(relop, COLOR_SYMBOL);

  switch ( op.tms_relop_type )
  {
    case TMS_RELOP_REG:
      out_register(ph.reg_names[int(op.value)]);
      break;
    case TMS_RELOP_IMM:
      out_symbol('#');
      out_value(op, OOFS_IFSIGN|OOF_SIGNED|OOF_NUMBER|OOFW_IMM);
      break;
  }
}

//----------------------------------------------------------------------
bool out_tms320c55_t::out_operand(const op_t &op)
{
  switch ( op.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_operators_begin(op);
      out_reg(op);
      out_symbol_shift(op, false);
      out_operators_end(op);
      out_symbol_shift(op, true);
      break;

    case o_relop:
      out_relop(op);
      break;

    case o_shift:
      out_shift(op.value);
      break;

    case o_imm:
      if ( op.tms_prefix == 0 )
        out_symbol('#');
      else
        out_symbol(op.tms_prefix);
      if ( op.tms_signed )
        out_value(op, OOFS_IFSIGN|OOF_SIGNED|OOFW_IMM);
      else
        out_value(op, OOFW_IMM);
      out_symbol_shift(op);
      break;

    case o_near:
      out_address(op);
      break;

    case o_mem:
    case o_io:
      out_operators_begin(op);
      out_address(op);
      out_symbol_shift(op, false);
      out_operators_end(op);
      out_symbol_shift(op, true);
      break;

    case o_cond:
      out_cond(op);
      break;

    default:
      error("interr: out");
  }
  return 1;
}

//----------------------------------------------------------------------
void out_tms320c55_t::out_proc_mnem(void)
{
  if ( (insn.SpecialModes & TMS_MODE_USER_PARALLEL) == 0 )
  {
    if ( (insn.SpecialModes & (TMS_MODE_LR|TMS_MODE_CR)) != 0 )
    {
      out_line(insn.get_canon_mnem(ph), COLOR_INSN);
      out_line((insn.SpecialModes & TMS_MODE_LR) ? ".lr ":".cr ", COLOR_INSN);
    }
    else
    {
      out_mnem();
    }
  }
  else
  { // user-defined parallelism
    out_line("|| ", COLOR_INSN);
    out_line(insn.get_canon_mnem(ph), COLOR_INSN);
    out_line(" ", COLOR_INSN);
  }
}

//----------------------------------------------------------------------
void out_tms320c55_t::out_insn(void)
{
  out_mnemonic();
  for ( int op = 0; op < UA_MAXOP; op++ )
  {
    if ( insn.ops[op].type == o_void )
      break;
    if ( op != 0 ) // not the first operand
    {
      if ( insn.Parallel != TMS_PARALLEL_BIT && op == insn.Parallel ) // multi-line instruction
      {
        flush_outbuf();
        // print the second instruction line
        if ( insn.SpecialModes & TMS_MODE_SIMULATE_USER_PARALLEL )
          out_line("|| ", COLOR_INSN);
        else
          out_line(":: ", COLOR_INSN);
        const char *insn2 = insn.get_canon_mnem(ph);
        if ( insn2 == nullptr )
          insn2 = "?";
        insn2 += strlen(insn2);
        insn2++;
        out_line(insn2, COLOR_INSN);
      }
      else
        out_symbol(',');
      out_char(' ');
    }
    // print the operand
    out_one_operand(op);
  }

  // print immediate values
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void tms320c55_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  char buf[MAX_NUMBUF];
  btoa(buf, sizeof(buf), value);
  switch ( reg )
  {
    case ARMS:
      if ( value == BADSEL )
        break;
      ctx.gen_printf(DEFAULT_INDENT,COLSTR(".arms_%s",SCOLOR_ASMDIR), value ? "on":"off");
      return;
    case CPL:
      if ( value == BADSEL )
        break;
      ctx.gen_printf(DEFAULT_INDENT,COLSTR(".cpl_%s",SCOLOR_ASMDIR), value ? "on":"off");
      return;
    case DP:
      if ( value == BADSEL )
        break;
      ctx.gen_printf(DEFAULT_INDENT,COLSTR(".dp %s",SCOLOR_ASMDIR), buf);
      return;
  }
  ctx.gen_cmt_line("assume %s = %s", ph.reg_names[reg], buf);
}

//--------------------------------------------------------------------------
// function to produce assume directives
//lint -e{1764} ctx could be const
void tms320c55_t::assumes(outctx_t &ctx)
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
//lint -e{818} seg could be const
void tms320c55_t::segstart(outctx_t &ctx, segment_t *seg) const
{
  ea_t ea = seg->start_ea;
  segment_t *Srange = getseg(ea);
  if ( is_spec_segm(Srange->type) )
    return;

  qstring sclas;
  get_segm_class(&sclas, Srange);

  if ( sclas == "CODE" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( sclas == "DATA" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".data", SCOLOR_ASMDIR));
//    gen_printf(DEFAULT_INDENT, COLSTR(".sect %s", SCOLOR_ASMDIR), sname);

  if ( Srange->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), Srange->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL | GH_BYTESEX_HAS_HIGHBYTE);
  ctx.gen_empty_line();
  ctx.gen_printf(0,COLSTR("MY_BYTE .macro BYTE",SCOLOR_ASMDIR));
  ctx.gen_printf(0,COLSTR("        .emsg \"ERROR - Impossible to generate 8bit bytes on this processor. Please convert them to 16bit words.\"",SCOLOR_ASMDIR));
  ctx.gen_printf(0,COLSTR("        .endm",SCOLOR_ASMDIR));
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void tms320c55_t::footer(outctx_t &ctx) const
{
  ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s",SCOLOR_ASMDIR), ash.end);
}

//--------------------------------------------------------------------------
void tms320c55_t::gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  ctx.out_printf(COLSTR("  %s ",SCOLOR_KEYWORD)
                 COLSTR("%c%s",SCOLOR_DNUM)
                 COLSTR(",",SCOLOR_SYMBOL) " "
                 COLSTR("%s",SCOLOR_LOCNAME),
                 ash.a_equ,
                 sign,
                 vstr,
                 stkvar->name.c_str());
}
