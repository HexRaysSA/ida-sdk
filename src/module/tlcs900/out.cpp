/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

// phrase
static const char *const phrases[] =
{
  // empty
  "",
  // conditions
  "F", "LT", "LE", "ULE", "PE", "MI", "Z", "C",
  "(T)", "GE", "GT", "UGT", "PO", "PL", "NZ", "NC",
  // special register
  "F", "F'",
  // misc
  "SR", "PC"
};


// register's name
static const uchar reg_byte[8] =
{
  rW, rA, rB, rC, rD, rE, rH, rL
};
static const uchar reg_word[8] =
{
  rWA, rBC, rDE, rHL, rIX, rIY, rIZ, rSP
};
static const uchar reg_long[8] =
{
  rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP
};
static const uchar reg_ib[8] =
{
  rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH
};

//----------------------------------------------------------------------
class out_T900_t : public outctx_t
{
  out_T900_t(void) = delete; // not used
public:
  void OutReg(size_t rgnum, uchar size);
  void OutVarName(const op_t &x);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_T900_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_T900_t)

//----------------------------------------------------------------------
void out_T900_t::OutReg(size_t rgnum, uchar size)
{
  ushort reg_name=0;      // main phrase
  if ( size != dt_dword )
  {
    // if 32 - w/o prefixes
    if ( rgnum&2 ) // prefix Q
      out_symbol('Q');
    else if ( rgnum < 0xD0 ) // need R ?
      out_symbol('R');
  }
  // register name
  switch ( size )
  {
    case dt_byte:
      if ( (rgnum&0xF0) != 0xF0 )
        // general register
        reg_name=reg_byte[((1-rgnum)&1)|((rgnum>>1)&6)];
      else
        // byte I*- regs
        reg_name=reg_ib[(rgnum&1)|((rgnum>>1)&6)];
      break;
    case dt_word:
      if ( (rgnum&0xF0) != 0xF0 )
        // general word regs
        reg_name=reg_word[(rgnum>>2)&3];
      else
        // high regs
        reg_name=reg_word[((rgnum>>2)&3)+4];
      break;
    case dt_dword:
      if ( (rgnum&0xF0) != 0xF0 )
        // general double word regs
        reg_name=reg_long[(rgnum>>2)&3];
      else
        // high regs
        reg_name=reg_long[((rgnum>>2)&3)+4];
      break;

    case 255: // special
      reg_name=ushort(rgnum);
      break;
  }
  if ( reg_name >= ph.regs_num )
  {
    out_symbol('?');
    msg("Bad Register Ref=%x, size=%x\n", (int)reg_name, (int)size);
  }
  else
  {
    out_register(ph.reg_names[reg_name]);
  }
  // postfix
  if ( (rgnum&0xF0) == 0xD0 )
    out_symbol('\'');
  else if ( rgnum < 0xD0 ) // or banki name
    out_symbol('0'+((rgnum>>4)&0xF));
}

//----------------------------------------------------------------------
// label name
void out_T900_t::OutVarName(const op_t &x)
{
  ea_t toea = map_code_ea(insn, x);
  if ( !out_name_expr(x, toea, x.addr) )
  {
    out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
bool out_T900_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      OutReg((size_t)x.value, x.dtype);
      break;

    case o_phrase:
      out_line(phrases[x.phrase]);
      break;

    case o_imm:
ImmOut:
      refinfo_t ri;
      // micro bug-fix
      if ( get_refinfo(&ri, insn.ea, x.n) )
      {
        if ( ri.flags == REF_OFF16 )
          set_refinfo(insn.ea, x.n, REF_OFF32, ri.target, ri.base, ri.tdelta);
//        msg("Exec OFF16_Op Fix AT:%a Flags=%x, Target=%a, Base=%a, Delta=%a\n",
//            insn.ea, ri.flags, ri.target, ri.base, uval_t(ri.tdelta));
      }
      out_value(x, OOFS_NOSIGN | OOFW_IMM);
      break;

    case o_mem:
    case o_near:
      if ( x.specflag1&URB_LDA2 && is_defarg1(F) )
        goto ImmOut;
      if ( !(x.specflag1&URB_LDA) )
        out_symbol('(');
      OutVarName(x);
      if ( !(x.specflag1&URB_LDA) )
        out_symbol(')');
      break;

    case o_displ: // open paren
      if ( !(x.specflag1&URB_LDA) )
        out_symbol('(');
      // with reg?
      if ( x.reg != rNULLReg )
      {
        // dec?
        if ( x.specflag2 & URB_DECR )
          out_symbol('-');
        // base eg
        OutReg(x.reg, 2);        // 32 bit always
        // dec
        if ( x.specflag2 & URB_DCMASK )
        {
          if ( (x.specflag2&URB_DECR) == 0 )
            out_symbol('+');
          out_symbol(':');
          out_symbol('0'+(x.specflag2&7));
        }
        // singleton dec
        if ( x.specflag2 & URB_UDEC )
          out_symbol('-');
        if ( x.specflag2 & URB_UINC )
          out_symbol('+');
        // offset?
        if ( x.offb != 0 )
        {
          out_symbol('+');
          if ( is_off(F, x.n) )
            OutVarName(x);
          else
            out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        }
        // additional reg?
        if ( x.specval_shorts.low != rNULLReg )
        {
          out_symbol('+');
          OutReg(x.specval_shorts.low, x.specflag1&URB_WORD ? dt_word : dt_byte);
        }
      }
      // closed paren
      if ( !(x.specflag1&URB_LDA) )
        out_symbol(')');
      break;

    case o_void:
      return 0;

    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_T900_t::out_insn(void)
{
  out_mnemonic();

  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  // imm data if any
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void tlcs900_t::T900_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void tlcs900_t::T900_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  const char *SegType = Sarea->type == SEG_CODE ? "CSEG"
                      : Sarea->type == SEG_DATA ? "DSEG"
                      :                           "RSEG";
  // "RSEG <NAME>"
  qstring sn;
  get_visible_segm_name(&sn, Sarea);
  ctx.gen_printf(-1, "%s %s ", SegType, sn.c_str());
  // non-zero offset - "ORG XXXX"
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      char bufn[MAX_NUMBUF];
      btoa(bufn, sizeof(bufn), org);
      ctx.gen_printf(-1, "%s %s", ash.origin, bufn);
    }
  }
}

//--------------------------------------------------------------------------
void tlcs900_t::T900_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      size_t i = strlen(ash.end);
      do
        ctx.out_char(' ');
      while ( ++i < 8 );
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}

//--------------------------------------------------------------------------
void idaapi T900_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // micro bug-fix
  refinfo_t ri;
  if ( get_refinfo(&ri, ea, 0) && ri.flags == REF_OFF16 )
    set_refinfo(ea, 0, REF_OFF32, ri.target, ri.base, ri.tdelta);

  ctx.out_data(analyze_only);
}
