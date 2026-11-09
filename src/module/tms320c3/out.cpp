/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c3x.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c3_t : public outctx_t
{
  out_tms320c3_t(void) = delete; // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
  void out_address(ea_t ea, const op_t &x, bool at);
};
CASSERT(sizeof(out_tms320c3_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_tms320c3_t)

//----------------------------------------------------------------------
#define SYM(x) COLSTR(x, SCOLOR_SYMBOL)
#define REG(x) COLSTR(x, SCOLOR_REG)
#define REGP(x) SYM("(") REG(x) SYM(")")

// o_phrase output format strings, indexed by phtype
static const char *const formats[0x1a] =
{
  SYM("*+")  REG("%s"),                                     // 0     "*+arn(NN)"
  SYM("*-")  REG("%s"),                                     // 1     "*-arn(NN)"
  SYM("*++") REG("%s"),                                     // 2     "*++arn(NN)"
  SYM("*--") REG("%s"),                                     // 3     "*--arn(NN)"
  SYM("*")   REG("%s") SYM("++"),                           // 4     "*arn++(NN)"
  SYM("*")   REG("%s") SYM("--"),                           // 5     "*arn--(NN)"
  SYM("*")   REG("%s") SYM("++"),                           // 6     "*arn++(NN)%"
  SYM("*")   REG("%s") SYM("--"),                           // 7     "*arn--(NN)%"
  SYM("*+")  REG("%s") REGP("ir0"),                         // 8     "*+arn(ir0)"
  SYM("*-")  REG("%s") REGP("ir0"),                         // 9     "*-arn(ir0)"
  SYM("*++") REG("%s") REGP("ir0"),                         // a     "*++arn(ir0)"
  SYM("*--") REG("%s") REGP("ir0"),                         // b     "*--arn(ir0)"
  SYM("*")   REG("%s") SYM("++") REGP("ir0"),               // c     "*arn++(ir0)"
  SYM("*")   REG("%s") SYM("--") REGP("ir0"),               // d     "*arn--(ir0)"
  SYM("*")   REG("%s") SYM("++") REGP("ir0") SYM("%%"),     // e     "*arn++(ir0)%"
  SYM("*")   REG("%s") SYM("--") REGP("ir0") SYM("%%"),     // f     "*arn--(ir0)%"
  SYM("*+")  REG("%s") REGP("ir1"),                         // 10    "*+arn(ir1)"
  SYM("*-")  REG("%s") REGP("ir1"),                         // 11    "*-arn(ir1)"
  SYM("*++") REG("%s") REGP("ir1"),                         // 12    "*++arn(ir1)"
  SYM("*--") REG("%s") REGP("ir1"),                         // 13    "*--arn(ir1)"
  SYM("*")   REG("%s") SYM("++") REGP("ir1"),               // 14    "*arn++(ir1)"
  SYM("*")   REG("%s") SYM("--") REGP("ir1"),               // 15    "*arn--(ir1)"
  SYM("*")   REG("%s") SYM("++") REGP("ir1") SYM("%%"),     // 16    "*arn++(ir1)%"
  SYM("*")   REG("%s") SYM("--") REGP("ir1") SYM("%%"),     // 17    "*arn--(ir1)%"
  SYM("*")   REG("%s"),                                     // 18    "*arn"
  SYM("*")   REG("%s") SYM("++") REGP("ir0") SYM("B"),      // 19    "*arn++(ir0)B"
};

//--------------------------------------------------------------------------
static const char *const cc_text[] =
{
  // Unconditional compares
  "u",    // Unconditional

  // Unsigned compares
  "lo",   // Lower than
  "ls",   // Lower than or same as
  "hi",   // Higher than
  "hs",   // Higher than or same as
  "e",    // Equal to
  "ne",   // Not equal to

  // Signed compares
  "lt",   // Less than
  "le",   // Less than or equal to
  "gt",   // Greater than
  "ge",   // Greater than or equal to

  // Unknown
  "?",    // Unknown

  // Compare to condition flags
  "nv",   // No overflow
  "v",    // Overflow
  "nuf",  // No underflow
  "uf",   // Underflow
  "nlv",  // No latched overflow
  "lv",   // Latched overflow
  "nluf", // No latched floating-point underflow
  "luf",  // Latched floating-point underflow
  "zuf"   // Zero or floating-point underflow
};

//----------------------------------------------------------------------
void out_tms320c3_t::out_address(ea_t ea, const op_t &x, bool at)
{
  qstring qbuf;
  if ( get_name_expr(&qbuf, insn.ea+x.offb, x.n, ea, ea) > 0 )
  {
    if ( at )
      out_symbol('@');
    out_line(qbuf.begin());
  }
  else
  {
    if ( at )
      out_symbol('@');
    out_tagon(COLOR_ERROR);
    out_value(x, OOFW_IMM|OOF_ADDR|OOFW_16);
    out_printf(" (ea = %a)", ea);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }

}

//----------------------------------------------------------------------
bool out_tms320c3_t::out_operand(const op_t &x)
{
  ea_t ea;
  char buf[MAXSTR];

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      out_register(ph.reg_names[x.reg]);
      break;

    case o_near:
      out_address(calc_code_mem(insn, x), x, false);
      break;

    case o_imm:
      if ( insn.itype != TMS320C3X_TRAPcond )
        out_symbol('#');

      if ( insn.auxpref & ImmFltFlag )
      {
        int16 v = int16(x.value);
        print_fpval(buf, sizeof(buf), &v, 2);
        out_line(buf[0] == ' ' ? &buf[1] : buf, COLOR_NUMBER);
      }
      else
      {
        out_value(x, OOFW_IMM);
      }
      break;

    case o_mem:
      ea = calc_data_mem(insn, x);
      if ( ea != BADADDR )
      {
        out_address(ea, x, true);
      }
      else
      {
        out_tagon(COLOR_ERROR);
        out_value(x, OOFW_IMM|OOF_ADDR|OOFW_16);
        out_tagoff(COLOR_ERROR);
      }
      break;

    case o_phrase: // Indirect addressing mode
      {
        if ( x.phrase < qnumber(formats) )
        {
          op_t y = x;
          bool outdisp = x.phrase < 8;
          bool printmod = x.phrase >= 6;
          if ( x.phrase == 0x18 )
          {
            // this is *arn phrase
            // check if we need to print the displacement
            int n = x.n;
            if ( is_off(F, n) || is_stkvar(F, n) || is_enum(F, n) || is_stroff(F, n) )
            {
              outdisp = true;
              y.addr = 0;
              printmod = false;
              y.phrase = 0; // use '*+arn(NN)' syntax
            }
          }

          // print the base part
          const char *reg = ph.reg_names[uchar(y.phtype)];
          nowarn_qsnprintf(buf, sizeof(buf), formats[uchar(y.phrase)], reg);
          out_colored_register_line(buf);

          // print the displacement
          if ( outdisp )
          {
            out_symbol('(');
            out_value(y, OOFS_IFSIGN|OOF_ADDR|OOFW_32);
            out_symbol(')');
            if ( printmod )
              out_symbol('%'); // %: circular modify
          }
        }
        else
        {
          out_line("<bad indirect>", COLOR_ERROR);
        }
        break;
      }

    default:
      INTERR(10261);
  }
  return 1;
}

//----------------------------------------------------------------------
void out_tms320c3_t::out_proc_mnem(void)
{
  char postfix[8];
  postfix[0] = '\0';
  switch ( insn.itype )
  {
    case TMS320C3X_LDFcond:
    case TMS320C3X_LDIcond:
    case TMS320C3X_Bcond:
    case TMS320C3X_DBcond:
    case TMS320C3X_CALLcond:
    case TMS320C3X_TRAPcond:
    case TMS320C3X_RETIcond:
    case TMS320C3X_RETScond:
      qstrncpy(postfix, cc_text[insn.auxpref & 0x1f ], sizeof(postfix));
      if ( insn.auxpref & DBrFlag ) // delayed branch?
        qstrncat(postfix, "d", sizeof(postfix));
      break;
  }

  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
void out_tms320c3_t::out_insn(void)
{
  out_mnemonic();

  // following operand combinations exist:
  // 0, 1, 2, 3 for non-parallel
  // 2+2, 3+2, 3+3 for parallel

  out_one_operand(0);   // two operands can be printed always
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_one_operand(1);
  }
  if ( insn.itype2 )             // Parallel
  {
    if ( insn.i2op > 2 ) // 3rd operand is for first instruction half
    {
      out_symbol(',');
      out_one_operand(2);
    }
    flush_outbuf();

    char insn2[MAXSTR];
    qsnprintf(insn2, sizeof(insn2), "||%s", ph.instruc[uchar(insn.itype2)].name);
    ::add_spaces(insn2, sizeof(insn2), 8);
    out_line(insn2, COLOR_INSN);

    if ( insn.i2op == 2 ) // 3rd operand is for second instruction half
    {
      out_one_operand(2);
      out_symbol(',');
    }

    if ( insn.Op4.type != o_void )
      out_one_operand(3);

    if ( insn.Op5.type != o_void )
    {
      out_symbol(',');
      out_one_operand(4);
    }

    if ( insn.Op6.type != o_void )
    {
      out_symbol(',');
      out_one_operand(5);
    }
  }
  else if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_one_operand(2);
  }

  out_immchar_cmts();

  flush_outbuf();
}

//--------------------------------------------------------------------------
void tms320c3x_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
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
//lint -e{1764} ctx could be const
void tms320c3x_t::assumes(outctx_t &ctx)
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
void tms320c3x_t::segstart(outctx_t &ctx, segment_t *seg) const
{
  if ( is_spec_segm(seg->type) )
    return;

  qstring sclas;
  get_segm_class(&sclas, seg);

  if ( sclas == "CODE" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".text", SCOLOR_ASMDIR));
  else if ( sclas == "DATA" )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".data", SCOLOR_ASMDIR));

  if ( seg->orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), seg->orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void idaapi segend(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void tms320c3x_t::header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL | GH_BYTESEX_HAS_HIGHBYTE, nullptr, ioh.device.c_str());
  ctx.gen_empty_line();
}

//--------------------------------------------------------------------------
void tms320c3x_t::footer(outctx_t &ctx) const
{
  ctx.gen_printf(DEFAULT_INDENT,COLSTR("%s",SCOLOR_ASMDIR),ash.end);
}

//--------------------------------------------------------------------------
void tms320c3x_t::gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  ctx.out_printf(COLSTR("%s",SCOLOR_KEYWORD)
                 COLSTR("%c%s",SCOLOR_DNUM)
                 COLSTR(",",SCOLOR_SYMBOL) " "
                 COLSTR("%s",SCOLOR_LOCNAME),
                 ash.a_equ,
                 sign,
                 vstr,
                 stkvar->name.c_str());
}
