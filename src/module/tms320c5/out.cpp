/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "tms.hpp"

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_tms320c5_t : public outctx_t
{
  out_tms320c5_t(void) = delete; // not used
  void set_has_phrase(void) { user_data = (void*)1; }
  bool has_phrase() const { return user_data != nullptr; }
  const tms320c5_t &pm() const { return *static_cast<tms320c5_t *>(procmod); }

public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void outreg(int r) { out_register(ph.reg_names[r]); }
  void OutDecimal(uval_t x);
  int  outnextar(const op_t &o, bool comma);
  bool shouldIndent(void) const;
  void outphraseAr(void);
  void OutImmVoid(const op_t &x);
};
CASSERT(sizeof(out_tms320c5_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_tms320c5_t)

//----------------------------------------------------------------------
static const char *const phrases[] =
{
  "*",     "*-",  "*+",  "?",
  "*br0-", "*0-", "*0+", "*br0+"
};

//----------------------------------------------------------------------
void out_tms320c5_t::OutDecimal(uval_t x)
{
  char buf[40];
  qsnprintf(buf, sizeof(buf), "%" FMT_EA "u", x);
  out_line(buf, COLOR_NUMBER);
}

//----------------------------------------------------------------------
bool is_mpy(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case TMS_mpy:       // Multiply
    case TMS_mpya:      // Multiply and Accumulate Previous Product
    case TMS_mpys:      // Multiply and Subtract Previous Product
    case TMS2_mpy:      // Multiply (with T register, store product in P register)
    case TMS2_mpya:     // Multiply and accumulate previous product
    case TMS2_mpyk:     // Multiply immediate
    case TMS2_mpys:     // Multiply and subtract previous product
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool out_tms320c5_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      outreg(x.reg);
      break;
    case o_phrase:
      QASSERT(10087, (x.phrase>>4) < qnumber(phrases));
      out_line(phrases[x.phrase>>4], COLOR_SYMBOL);
      set_has_phrase();
      break;
    case o_imm:
      switch ( x.sib )
      {
        default:
          {
            if ( !pm().isC2() )
              out_symbol('#');
            flags64_t saved = F;
            if ( !is_defarg(F, x.n)
              && (is_mpy(insn) || is_invsign(insn.ea, F, x.n)) )
            {
              F |= dec_flag();
            }
            int outflags = OOFW_16|(is_mpy(insn) ? OOF_SIGNED : 0);
            out_value(x, outflags);
            F = saved;
          }
          break;
        case 1:
          out_value(x, OOF_NUMBER|OOFS_NOSIGN);
          break;
        case 2:
        case 3:
          OutDecimal(x.value);
          break;
      }
      break;
    case o_near:
      if ( insn.itype == TMS_blpd )
        out_symbol('#');
      // fallthrough
    case o_mem:
      {
        if ( insn.itype == TMS_bldd && x.sib )
          out_symbol('#');
        ea_t v = map_ea(insn, x, x.type == o_near);
        bool rptb_tail = false;
        uval_t addr = x.addr;
        if ( insn.itype == TMS_rptb && is_tail(get_flags(v)) )
        {
          // small hack to display end_loop-1 instead of before_end_loop+1
          v++;
          addr++;
          rptb_tail = true;
        }
        bool ok = out_name_expr(x, v, addr);
        if ( !ok )
        {
          out_value(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_16);
          remember_problem(PR_NONAME, insn.ea);
        }
        else
        {
          if ( rptb_tail )
          {
            out_symbol('-');
            out_line("1", COLOR_NUMBER);
          }
        }
      }
      break;
    case o_void:
      return 0;
    case o_bit:
      {
        static const char *const bitnames[] =
        {
          "intm", "ovm", "cnf", "sxm",
          "hm", "tc", "xf", "c"
        };
        out_keyword(bitnames[uchar(x.value)]);
      }
      break;
    case o_cond:
      {
        int mask = int(x.value>>0) & 0xF;
        int cond = int(x.value>>4) & 0xF;
        int comma = 1;
        out_tagon(COLOR_KEYWORD);
        switch ( (mask>>2) & 3 )      // Z L
        {
          case 0:
            comma = 0;
            break;
          case 1:
            out_line((cond>>2)&1 ? "lt" : "gt");
            break;
          case 2:
            out_line((cond>>2)&2 ? "eq" : "neq");
            break;
          case 3:
            switch ( (cond>>2)&3 )
            {
              case 2: out_line("geq"); break;
              case 3: out_line("leq"); break;
            }
            break;
        }
        if ( mask & 1 )               // C
        {
          if ( comma )
            out_char(',');
          if ( (cond & 1) == 0 )
            out_char('n');
          out_char('c');
          comma = 1;
        }
        if ( mask & 2 )               // V
        {
          if ( comma )
            out_char(',');
          if ( (cond & 2) == 0 )
            out_char('n');
          out_char('o');
          out_char('v');
          comma = 1;
        }
        static const char *const TP[] = { "bio", "tc", "ntc", nullptr };
        const char *ptr = TP[int(x.value>>8) & 3];
        if ( ptr != nullptr )
        {
          if ( comma )
            out_char(',');
          out_line(ptr);
        }
        out_tagoff(COLOR_KEYWORD);
      }
      break;
    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
int out_tms320c5_t::outnextar(const op_t &o, bool comma)
{
  if ( o.type == o_phrase && (o.phrase & 8) != 0 )
  {
    if ( comma )
    {
      out_symbol(',');
      out_char(' ');
    }
    outreg(rAr0+(o.phrase&7));
    return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
static int isDelayed(ushort code)
{
// 7D?? BD    0111 1101 1AAA AAAA + 1  Branch unconditional with AR update delayed
// 7E?? CALLD 0111 1110 1AAA AAAA + 1  Call unconditional with AR update delayed
// 7F?? BANZD 0111 1111 1AAA AAAA + 1  Branch AR=0 with AR update delayed
// BE3D CALAD 1011 1110 0011 1101      Call subroutine addressed by ACC delayed
// BE21 BACCD 1011 1110 0010 0001      Branch addressed by ACC delayed
// FF00 RETD  1111 1111 0000 0000      Return, delayed
// F??? CCD   1111 10TP ZLVC ZLVC + 1  Call conditional delayed
// F??? RETCD 1111 11TP ZLVC ZLVC      Return conditional delayed
// F??? BCNDD 1111 00TP ZLVC ZLVC + 1  Branch conditional delayed
  ushort subcode;
  switch ( code>>12 )
  {
    case 7:
      subcode = (code >> 7);
      return subcode == 0xFB || subcode == 0xFD || subcode == 0xFF;
    case 0xB:
      return code == 0xBE21u || code == 0xBE3Du;
    case 0xF:
      if ( code == 0xFF00 )
        return 1;
      subcode = (code & 0x0C00);
      return subcode != 0x400;
  }
  return 0;
}

//----------------------------------------------------------------------
bool out_tms320c5_t::shouldIndent(void) const
{
  if ( pm().isC2() )
    return false;                               // TMS320C2 - no indention
  if ( !is_flow(F) )
    return false;                               // no previous instructions
  ea_t ea = prev_not_tail(insn.ea);
  if ( ea == BADADDR )
    return false;
  flags64_t flags = get_flags(ea);
  if ( !is_code(flags) )
    return false;
  if ( isDelayed((ushort)get_wide_byte(ea)) )
    return true;
  if ( insn.size == 2 )                         // our instruction is long
  {
    ; // nothing to do
  }
  else
  {                                             // our instruction short
    if ( (insn.ea-ea) == 2 )                    // prev instruction long
      return false;                             // can't be executed in delayed manner
    if ( !is_flow(flags) )
      return false;                             // no prev instr...
    ea = prev_not_tail(ea);
    if ( ea == BADADDR )
      return false;
    flags = get_flags(ea);
  }
  return is_code(flags) && isDelayed((ushort)get_wide_byte(ea));
}


//----------------------------------------------------------------------
void out_tms320c5_t::outphraseAr(void)
{
  ea_t ar;
  if ( pm().find_ar(insn, &ar) )
  {
    char buf[MAXSTR];
    ea2str(buf, sizeof(buf), ar);
    out_printf(COLSTR(" %s(%s)", SCOLOR_AUTOCMT), ash.cmnt, buf);
  }
}

//----------------------------------------------------------------------
void out_tms320c5_t::OutImmVoid(const op_t &x)
{
  if ( !pm().tmsfunny )
    return;
  if ( x.type == o_imm )
  {
    if ( x.value != 0 )
    {
      int v = int(short(x.value) * 10000 / 0x7FFF);
      out_char(' ');
      out_tagon(COLOR_AUTOCMT);
      out_line(ash.cmnt);
      out_char(' ');
      if ( v < 0 )
      {
        out_char('-');
        v = -v;
      }
      char buf[10];
      if ( v == 10000 )
        qstrncpy(buf, "1.0000", sizeof(buf));
      else
        qsnprintf(buf, sizeof(buf), "0.%04d", v);
      out_line(buf);
      out_tagoff(COLOR_AUTOCMT);
    }
  }
}

//----------------------------------------------------------------------
void out_tms320c5_t::out_insn(void)
{
  if ( shouldIndent() )
    out_char(' ');
  out_mnemonic();

  bool comma = insn.Op1.shown() && out_one_operand(0);

  if ( insn.Op2.shown() && insn.Op2.type != o_void )
  {
    if ( comma )
    {
      out_tagon(COLOR_SYMBOL);
      out_char(',');
      out_tagoff(COLOR_SYMBOL);
      out_char(' ');
    }
    out_one_operand(1);
  }

  if ( insn.Op1.type == o_phrase )
    if ( outnextar(insn.Op1, comma) )
      comma = true;
  if ( insn.Op2.type == o_phrase )
    outnextar(insn.Op2, comma);

  out_immchar_cmts();

  if ( has_phrase() )
    outphraseAr();

  flush_outbuf();
}

//--------------------------------------------------------------------------
void idaapi header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
//lint -e{818} seg could be const
void tms320c5_t::segstart(outctx_t &ctx, segment_t *seg) const
{
  qstring sname;
  get_visible_segm_name(&sname, seg);

  ctx.gen_printf(DEFAULT_INDENT, COLSTR(".sect \"%s\"", SCOLOR_ASMDIR), sname.c_str());
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = seg->start_ea - get_segm_base(seg);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s .org %s", SCOLOR_AUTOCMT),
                     ash.cmnt, buf);
    }
  }
}

//--------------------------------------------------------------------------
void tms320c5_t::footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      ctx.out_char(' ');
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
//lint -e{1764} ctx could be const
void tms320c5_t::tms_assumes(outctx_t &ctx) const
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || seg == nullptr )
    return;
  bool seg_started = (ea == seg->start_ea);

  if ( seg->type == SEG_XTRN
    || seg->type == SEG_DATA
    || (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 )
  {
    return;
  }

  sreg_range_t sra;
  if ( !get_sreg_range(&sra, ea, rDP) )
    return;
  bool show = sra.start_ea == ea;
  if ( show )
  {
    sreg_range_t prev_sra;
    if ( get_prev_sreg_range(&prev_sra, ea, rDP) )
      show = sra.val != prev_sra.val;
  }
  if ( seg_started || show )
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s --- assume DP %04X", SCOLOR_AUTOCMT),
                   ash.cmnt, uint(sra.val));
}
