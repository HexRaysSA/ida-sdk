/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"

//----------------------------------------------------------------------
class out_pdp_t : public outctx_t
{
  out_pdp_t(void) = delete; // not used
  pdp11_t &pm() { return *static_cast<pdp11_t *>(procmod); }
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_pdp_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_pdp_t)

//----------------------------------------------------------------------
bool out_pdp_t::out_operand(const op_t &x)
{
  ea_t segadr;
  switch ( x.type )
  {
    case o_void:
      return 0;
    case o_reg:
      OutReg(x.reg);
      break;
    case o_fpreg:
      OutReg(x.reg + 8);
      break;
    case o_imm:            // 27
      if ( x.ill_imm )
      {
        out_symbol('(');
        OutReg(rPC);
        out_symbol(')');
        out_symbol('+');
      }
      else
      {
        out_symbol('#');
        if ( x.dtype == dt_float || x.dtype == dt_double )
        {
          char str[MAXSTR];
          if ( print_fpval(str, sizeof(str), &x.value, 2) )
          {
            char *p = str;
            while ( *p == ' ' )
              p++;
            out_symbol('^');
            out_symbol('F');
            out_line(p, COLOR_NUMBER);
          }
          else
          {
            out_long(x.value, 8);
          }
        }
        else
        {
          out_value(x, OOF_SIGNED | OOFW_IMM);
        }
      }
      break;
    case o_mem:            // 37/67/77
    case o_near:      // jcc/ [jmp/call 37/67]
    case o_far:
      if ( x.phrase != 0 )
      {
        if ( x.phrase == 077 || x.phrase == 037 )
          out_symbol('@');
        if ( x.phrase == 037 )
          out_symbol('#');
        if ( x.addr16 < pm().ml.asect_top && !is_off(F, x.n) )
        {
          out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
          break;
        }
      }
      segadr = x.type == o_far
             ? to_ea(x.segval, x.addr16)
             : map_code_ea(insn, x.addr16, x.n);
      if ( !out_name_expr(x, segadr, x.addr16) )
      {
        if ( x.type == o_far || x.addr16 < 0160000 )
          remember_problem(PR_NONAME, insn.ea);
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_16);
      }
      break;
    case o_number:      // EMT/TRAP/MARK/SPL
      out_value(x, OOF_NUMBER | OOFS_NOSIGN | OOFW_8);
      break;
    case o_displ:           // 6x/7x (!67/!77)
      if ( x.phrase >= 070 )
        out_symbol('@');
      out_value(x, OOF_ADDR | OOF_SIGNED | OOFW_16);
      out_symbol('(');
      goto endregout;
    case o_phrase:         // 1x/2x/3x/4x/5x (!27/!37)
      switch ( x.phrase >> 3 )
      {
        case 1:
          out_symbol('@');
          OutReg(x.phrase & 7);
          break;
        case 3:
          out_symbol('@');
          // fallthrough
        case 2:
          out_symbol('(');
          OutReg(x.phrase & 7);
          out_symbol(')');
          out_symbol('+');
          break;
        case 5:
          out_symbol('@');
          // fallthrough
        case 4:
          out_symbol('-');
          out_symbol('(');
endregout:
          OutReg(x.phrase & 7);
          out_symbol(')');
          break;
      }
      break;
    default:
      warning("out: %" FMT_EA "o: bad optype %d", insn.ip, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_pdp_t::out_proc_mnem(void)
{
  static const char *const postfix[] = { "", "b" };
  out_mnem(8, postfix[insn.bytecmd]);
}

//----------------------------------------------------------------------
void out_pdp_t::out_insn(void)
{
  out_mnemonic();
  if ( insn.itype == pdp_compcc )
  {
    uint i = 0, code, first = 0;
    static const uint tabcc[8] =
    {
      pdp_clc, pdp_clv, pdp_clz, pdp_cln,
      pdp_sec, pdp_sev, pdp_sez, pdp_sen
    };
    code = insn.Op1.phrase;
    out_symbol('<');
    if ( code >= 020 )
    {
      if ( (code ^= 020) == 0 )
        out_line(COLSTR("nop!^O20", SCOLOR_INSN));
      i = 4;
    }
    for ( ; code; i++, code >>= 1 )
    {
      if ( code & 1 )
      {
        if ( first++ )
          out_symbol('!');
        out_line(ph.instruc[tabcc[i]].name, COLOR_INSN);
      }
    }
    out_symbol('>');
  }

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
void idaapi pdp_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, seg) could be made const
void pdp11_t::pdp_segstart(outctx_t &ctx, segment_t *seg)
{
  if ( seg->type == SEG_IMEM )
  {
    ctx.flush_buf(COLSTR(".ASECT", SCOLOR_ASMDIR), DEFAULT_INDENT);
  }
  else
  {
    qstring sname;
    get_visible_segm_name(&sname, seg);
    ctx.out_printf(COLSTR(".PSECT %s", SCOLOR_ASMDIR), sname.c_str());
    if ( seg->ovrname != 0 )
    {
      char bseg[MAX_NUMBUF];
      char breg[MAX_NUMBUF];
      btoa(bseg, sizeof(bseg), seg->ovrname & 0xFFFF, 10);
      btoa(breg, sizeof(breg), seg->ovrname >> 16, 10);
      ctx.out_printf(
                COLSTR(" %s Overlay Segment %s, Region %s", SCOLOR_AUTOCMT),
                ash.cmnt, bseg, breg);
    }
    ctx.flush_outbuf(0);
  }

  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    size_t org = size_t(ctx.insn_ea-get_segm_base(seg));
    if ( org != 0 && org != ml.asect_top && seg->comorg() )
    {
      ctx.out_tagon(COLOR_ASMDIR);
      ctx.out_line(ash.origin);
      ctx.out_line(ash.a_equ);
      if ( seg->type != SEG_IMEM )
      {
        ctx.out_line(ash.origin);
        ctx.out_char('+');
      }
      ctx.out_btoa(org);
      ctx.out_tagoff(COLOR_ASMDIR);
      ctx.flush_outbuf(DEFAULT_INDENT);
    }
  }
}

//--------------------------------------------------------------------------
void pdp11_t::pdp_footer(outctx_t &ctx) const
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
bool pdp11_t::out_equ(outctx_t &ctx, ea_t ea) const
{
  segment_t *s = getseg(ea);
  char buf[MAXSTR];
  if ( s != nullptr )
  {
    if ( s->type != SEG_IMEM && !is_loaded(ea) )
    {
      char num[MAX_NUMBUF];
      btoa(num, sizeof(num), get_item_size(ea));
      nowarn_qsnprintf(buf, sizeof(buf), ash.a_bss, num);
      ctx.flush_buf(buf);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
void pdp11_t::pdp_data(outctx_t &ctx, bool analyze_only) const
{
  char buf[MAXSTR];
  ushort v[5];
  ea_t endea;
  ushort i, j;

  ea_t ea = ctx.insn_ea;
  if ( out_equ(ctx, ea) )
    return;

  i = 0;
  flags64_t F = ctx.F;
  if ( !is_unknown(F) )
  {
    if ( is_word(F) && get_radix(F,0) == 16 )
      i = 2;
    else if ( is_dword(F) )
      i = 4;
    else if ( is_qword(F) )
      i = 8;
    else if ( is_tbyte(F) )
      i = 10;
    if ( i == 0 )
    {
      ctx.out_data(analyze_only);
      return;
    }

    int radix = get_radix(F, 0);
    endea = get_item_end(ea);
    for ( ; ea < endea; ea += i )
    {
      memset(v, 0, sizeof(v));
      if ( get_bytes(v, i, ea) != i || r50_to_asc(buf, v, i/2) != 0 )
      {
        ctx.out_keyword(".word   ");
        for ( j = 0; j < i/2; j++ )
        {
          if ( j )
            ctx.out_symbol(',');
          btoa(buf, sizeof(buf), v[j], radix);
          ctx.out_line(buf, COLOR_NUMBER);
        }
      }
      else
      {
        ctx.out_keyword(".rad50  ");
        ctx.out_tagon(COLOR_CHAR);
        ctx.out_char('/');
        ctx.out_line(buf);
        ctx.out_char('/');
        ctx.out_tagoff(COLOR_CHAR);
      }
      if ( ctx.flush_outbuf() )
        return;   // too many lines
    }
    return;
  }
// unknown
  if ( !is_loaded(ea) )
  {
    ctx.flush_buf(COLSTR(".blkb", SCOLOR_KEYWORD));
  }
  else
  {
    uchar c = get_byte(ea);

    char cbuf[MAX_NUMBUF];
    btoa(cbuf, sizeof(cbuf), c);
    ctx.out_printf(COLSTR(".byte ", SCOLOR_KEYWORD)
                   COLSTR("%4s ", SCOLOR_DNUM)
                   COLSTR("%s %c", SCOLOR_AUTOCMT),
                   cbuf,
                   ash.cmnt,
                   c >= ' ' ? c : ' ');
    if ( !(ea & 1) && (i = get_word(ea)) != 0 )
    {
      ctx.out_tagon(COLOR_AUTOCMT);
      ctx.out_char(' ');
      b2a32(buf, sizeof(buf), i, 2, 0);
      ctx.out_line(buf);
      ctx.out_char(' ');
      ushort w = i;
      r50_to_asc(buf, &w, 1);
      ctx.out_line(buf);
      ctx.out_tagoff(COLOR_AUTOCMT);
    }
    ctx.flush_outbuf();
  } // undefined
}
