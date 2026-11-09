/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#include "tms6.hpp"

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c6_t : public outctx_t
{
  out_tms320c6_t(void) = delete; // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void out_pre_mode(int mode);
  void out_post_mode(int mode);
  void print_stg_cyc(ea_t ea, int stgcyc);
  bool tms6_out_name_expr(const op_t &x, uval_t opval);
};
CASSERT(sizeof(out_tms320c6_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_tms320c6_t)

//----------------------------------------------------------------------
static bool is_first_insn_in_exec_packet(ea_t ea)
{
//  if ( (ea & 0x1F) == 0 )
//    return 1;
  ea = prev_not_tail(ea);
  return ea == BADADDR
      || !is_code(get_flags(ea))
      || (get_dword(ea) & BIT0) == 0;
}

//----------------------------------------------------------------------
static bool prev_complex(const insn_t &insn)
{
  ea_t ea = prev_not_tail(insn.ea);
  if ( ea == BADADDR || !is_code(get_flags(ea)) )
    return 0;
  return !is_first_insn_in_exec_packet(ea);
}

//----------------------------------------------------------------------
void out_tms320c6_t::out_pre_mode(int mode)
{
  out_symbol('*');
  switch ( mode )
  {
    case 0x08:  // 1000 *--R[cst]
    case 0x0C:  // 1100 *--Rb[Ro]
      out_symbol('-');
      // fallthrough
    case 0x00:  // 0000 *-R[cst]
    case 0x04:  // 0100 *-Rb[Ro]
      out_symbol('-');
      break;
    case 0x09:  // 1001 *++R[cst]
    case 0x0D:  // 1101 *++Rb[Ro]
      out_symbol('+');
      out_symbol('+');
      break;
    case 0x01:  // 0001 *+R[cst]
    case 0x05:  // 0101 *+Rb[Ro]
//      out_symbol('+');
      break;
    case 0x0A:  // 1010 *R--[cst]
    case 0x0B:  // 1011 *R++[cst]
    case 0x0E:  // 1110 *Rb--[Ro]
    case 0x0F:  // 1111 *Rb++[Ro]
      break;
  }
}

//----------------------------------------------------------------------
void out_tms320c6_t::out_post_mode(int mode)
{
  switch ( mode )
  {
    case 0x08:  // 1000 *--R[cst]
    case 0x0C:  // 1100 *--Rb[Ro]
    case 0x00:  // 0000 *-R[cst]
    case 0x04:  // 0100 *-Rb[Ro]
    case 0x09:  // 1001 *++R[cst]
    case 0x0D:  // 1101 *++Rb[Ro]
    case 0x01:  // 0001 *+R[cst]
    case 0x05:  // 0101 *+Rb[Ro]
      break;
    case 0x0A:  // 1010 *R--[cst]
    case 0x0E:  // 1110 *Rb--[Ro]
      out_symbol('-');
      out_symbol('-');
      break;
    case 0x0B:  // 1011 *R++[cst]
    case 0x0F:  // 1111 *Rb++[Ro]
      out_symbol('+');
      out_symbol('+');
      break;
  }
}

//----------------------------------------------------------------------
struct ii_info_t
{
  char ii;
  char cyc;
};

static const ii_info_t ii_info[] =
{
  { 1,  0 },
  { 2,  1 },
  { 4,  2 },
  { 8,  3 },
  { 14, 4 },
};

void out_tms320c6_t::print_stg_cyc(ea_t ea, int stgcyc)
{
  int ii = 1;
  insn_t prev;
  for ( int i=0; i < 14 && decode_prev_insn(&prev, ea) != BADADDR; i++ )
  {
    if ( prev.itype == TMS6_sploop
      || prev.itype == TMS6_sploopd
      || prev.itype == TMS6_sploopw )
    {
      ii = prev.Op1.value;
      break;
    }
    ea = prev.ea;
  }
  for ( int i=0; i < qnumber(ii_info); i++ )
  {
    if ( ii_info[i].ii >= ii )
    {
      int cyc = ii_info[i].cyc;
      int stg = 0;
      int stgbits = 6 - cyc;
      int bit = 1 << cyc;
      for ( int j=0; j < stgbits; j++, bit<<=1 )
      {
        stg <<= 1;
        if ( stgcyc & bit )
          stg |= 1;
      }
      cyc = stgcyc & ((1<<cyc)-1);
      out_long(stg, 10);
      out_symbol(',');
      out_long(cyc, 10);
      break;
    }
  }
}

//----------------------------------------------------------------------
bool out_tms320c6_t::tms6_out_name_expr(const op_t &x, uval_t opval)
{
  ea_t ea = to_ea(insn.cs, opval);
  ea_t safe = find_first_insn_in_packet(ea);
  adiff_t delta = ea - safe;
  if ( !out_name_expr(x, safe, opval - delta) )
    return false;
  if ( delta > 0 )
  {
    out_symbol('+');
    out_long(delta, 16);
  }
  return true;
}

//----------------------------------------------------------------------
bool out_tms320c6_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      outreg(x.reg);
      break;

    case o_regpair:
      outreg(x.reg + 1);
      out_symbol(':');
      outreg(x.reg);
      break;

    case o_imm:
      {
        uchar sign = insn.itype == TMS6_mvkh
                  || insn.itype == TMS6_mvklh
                  || (insn.itype == TMS6_mvk && is_mvk_scst16_form(insn.ea))
                   ? 0
                   : OOF_SIGNED;
        out_value(x, OOFS_IFSIGN|OOFW_IMM|sign);
        break;
      }

    case o_stgcyc:
      print_stg_cyc(insn.ea, x.value);
      break;

    case o_near:
      if ( !tms6_out_name_expr(x, x.addr) )
      {
        out_tagon(COLOR_ERROR);
        out_btoa(x.addr, 16);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
      }
      break;

    case o_phrase:
      out_pre_mode(x.mode);
      outreg(x.reg);
      out_post_mode(x.mode);
      out_symbol('[');
      outreg(x.secreg);
      out_symbol(']');
      break;

    case o_displ:
      out_pre_mode(x.mode);
      outreg(x.reg);
      out_post_mode(x.mode);
      {
        if ( x.addr != 0 || is_off(F, x.n) )
        {
          if ( is_off(F, x.n) )
          {
            out_symbol('(');
            out_value(x, OOF_ADDR|OOFS_IFSIGN|OOFW_IMM|OOF_SIGNED|OOFW_32);
            out_symbol(')');
          }
          else
          {
            out_symbol('[');
            out_value(x, OOF_ADDR|OOFS_IFSIGN|OOFW_IMM|OOF_SIGNED|OOFW_32);
            out_symbol(']');
          }
        }
      }
      break;

    case o_spmask:
      {
        static const char units[] = "LLSSDDMM";
        uchar mask = x.reg;
        bool need_comma = false;
        for ( int i=0; i < 8; i++, mask>>=1 )
        {
          if ( mask & 1 )
          {
            if ( need_comma )
              out_symbol(',');
            out_tagon(COLOR_KEYWORD);
            out_char(units[i]);
            out_char('1'+(i&1));
            out_tagoff(COLOR_KEYWORD);
            need_comma = true;
          }
        }
      }
      break;

    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_tms320c6_t::out_insn(void)
{
//
//      Parallel instructions
//
  ea_t ea = insn.ea;
  if ( !is_first_insn_in_exec_packet(ea) )
  {
    out_symbol('|');
    out_symbol('|');
  }
  else
  {
    if ( !has_any_name(F)
      && (prev_complex(insn) || insn.cflags & aux_para) )
    {
      gen_empty_line();
    }
    out_char(' ');
    out_char(' ');
  }

//
//      Condition code
//
  static const char *const conds[] =
  {
    "     ", "     ", "[B0] ", "[!B0]",
    "[B1] ", "[!B1]", "[B2] ", "[!B2]",
    "[A1] ", "[!A1]", "[A2] ", "[!A2]",
    "[A0] ", "[!A0]", "     ", "     "
  };
  out_keyword(conds[insn.cond]);
  out_char(' ');

//
//      Instruction name
//
  out_mnemonic();
//
//      Functional unit
//
  static const char *const units[] =
  {
    nullptr,
    ".L1", ".L2",
    ".S1", ".S2",
    ".M1", ".M2",
    ".D1", ".D2",
  };
  if ( insn.funit != FU_NONE )
    out_keyword(units[uchar(insn.funit)]);
  else
    out_line("   ");
  if ( insn.cflags & aux_xp )
    out_keyword("X");
  else
    out_char(' ');
  out_line("   ");

//
//      Operands
//
  if ( (insn.cflags & aux_src2) != 0 )
  {
    outreg(insn.Op1.src2);
    out_symbol(',');
    out_char(' ');
  }

  if ( insn.Op1.shown() )
    out_one_operand(0);

  if ( insn.Op2.type != o_void && insn.Op2.shown() )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }


  if ( insn.Op3.type != o_void && insn.Op3.shown() )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }

  out_immchar_cmts();

  int indent = inf_get_indent() - 8;  // reserve space for conditions
  if ( indent <= 1 )            // too little space?
    indent = 2;                 // pass -2, which means one space
                                // (-1 would mean 'use DEFAULT_INDENT')
  flush_outbuf(-indent);        // negative value means 'print opcodes here'

  if ( (insn.cflags & aux_para) == 0 )
  {
    tms6_t &pm = *static_cast<tms6_t *>(procmod);
    tgtinfo_t tgt;
    if ( tgt.restore_from_idb(pm, ea) )
    {
      qstring buf = tgt.get_type_name();
      if ( tgt.has_target() )
      {
        qstring name = get_colored_name(tgt.target);
        buf.append(" ");
        buf.append(name);
      }
      gen_printf(DEFAULT_INDENT,
                 COLSTR("; %s OCCURS", SCOLOR_AUTOCMT),
                 buf.c_str());
    }
  }
}

//--------------------------------------------------------------------------
//lint -e{818} seg could be const
void idaapi segstart(outctx_t &ctx, segment_t *seg)
{
  if ( is_spec_segm(seg->type) )
    return;

  qstring sname;
  get_segm_name(&sname, seg);

  if ( sname == ".bss" )
    return;
  if ( sname == ".text" || sname == ".data" )
  {
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s", SCOLOR_ASMDIR), sname.c_str());
  }
  else
  {
    validate_name(&sname, VNT_IDENT);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".sect \"%s\"", SCOLOR_ASMDIR), sname.c_str());
  }
}

//--------------------------------------------------------------------------
void idaapi segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void idaapi header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL);
}

//--------------------------------------------------------------------------
void tms6_t::footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s end %s", SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s", SCOLOR_ASMDIR)
                   " "
                   COLSTR("%s %s", SCOLOR_AUTOCMT), ash.end, ash.cmnt, name);
}

//--------------------------------------------------------------------------
void idaapi data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  segment_t *s = getseg(ea);
  if ( s != nullptr )
  {
    qstring sname;
    if ( get_segm_name(&sname, s) > 0 && sname == ".bss" )
    {
      qstring name;
      if ( get_colored_name(&name, ea) <= 0 )
        name.sprnt(COLSTR("bss_dummy_name_%a", SCOLOR_UNKNAME), ea);
      char num[MAX_NUMBUF];
      btoa(num, sizeof(num), get_item_size(ea), get_radix(ctx.F, 0));
      ctx.ctxflags |= CTXF_LABEL_OK;
      ctx.gen_printf(-1,
                     COLSTR(".bss", SCOLOR_KEYWORD)
                     " %s, "
                     COLSTR("%s", SCOLOR_DNUM),
                     name.begin(),
                     num);
      return;
    }
  }
  ctx.out_data(analyze_only);
}

//--------------------------------------------------------------------------
//lint -e{1764} ctx could be const
bool tms6_t::outspec(outctx_t &ctx, uchar stype) const
{
  ea_t ea = ctx.insn_ea;
  qstring nbuf;
  if ( get_colored_name(&nbuf, ea) <= 0 )
    return false;
  const char *name = nbuf.begin();
  char buf[MAX_NUMBUF];
  switch ( stype )
  {
    case SEG_XTRN:
      return ctx.gen_printf(-1, COLSTR("%s %s", SCOLOR_ASMDIR), ash.a_extrn,name);
    case SEG_ABSSYM:
      // i don't know how to declare absolute symbols.
      // perhaps, like this?
      btoa(buf, sizeof(buf), get_dword(ea));
      return ctx.gen_printf(-1, COLSTR("%s = %s", SCOLOR_ASMDIR), name, buf);
    case SEG_COMM:
      btoa(buf, sizeof(buf), get_dword(ea));
      ctx.gen_printf(-1,
                     COLSTR("%s \"%s\", %s", SCOLOR_ASMDIR),
                     ash.a_comdef, name, buf);
  }
  return false;
}
