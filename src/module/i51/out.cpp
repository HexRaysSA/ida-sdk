/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"
#include <fpro.h>
#include <diskio.hpp>

//----------------------------------------------------------------------
AS_PRINTF(1, 0) static void vlog(const char *format, va_list va)
{
  static FILE *fp = nullptr;
  if ( fp == nullptr )
    fp = fopenWT("debug_log");
  qvfprintf(fp, format, va);
  qflush(fp);
}
//----------------------------------------------------------------------
AS_PRINTF(1, 2) inline void log(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vlog(format, va);
  va_end(va);
}

#define AT   COLSTR("@", SCOLOR_SYMBOL)
#define PLUS COLSTR("+", SCOLOR_SYMBOL)

static const char *const phrases[] =
{
  AT COLSTR("R0", SCOLOR_REG),
  AT COLSTR("R1", SCOLOR_REG),
  AT COLSTR("DPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("DPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("PC", SCOLOR_REG),
  AT COLSTR("WR", SCOLOR_REG),
  AT COLSTR("EPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("EPTR", SCOLOR_REG),
  AT COLSTR("PR0", SCOLOR_REG),
  AT COLSTR("PR1", SCOLOR_REG),
};

//----------------------------------------------------------------------
class out_i51_t : public outctx_t
{
  out_i51_t(void) = delete; // not used
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_i51_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_i51_t)

//----------------------------------------------------------------------
// generate the text representation of an operand
bool out_i51_t::out_operand(const op_t &x)
{
  i51_t &pm = *static_cast<i51_t *>(procmod);
  uval_t v;
  int dir, bit;
  qstring qbuf;
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      if ( x.reg == fRi )
      {
        out_symbol('@');
        OutReg(x.indreg);
      }
      else
      {
        out_colored_register_line(phrases[x.phrase]);
      }
      if ( x.imm_disp )
      {
        out_symbol('+');
        out_symbol('#');
        out_value(x, OOFS_IFSIGN | OOFW_IMM);
      }
      break;

    case o_displ:
      out_symbol('@');
      OutReg(x.reg);
      out_symbol('+');
      out_value(x, OOF_ADDR | OOFS_IFSIGN | OOFW_16);
      break;

    case o_imm:
      out_symbol('#');
      if ( insn.auxpref & aux_0ext )
        out_symbol('0');
      if ( insn.auxpref & aux_1ext )
        out_symbol('1');
      out_value(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_mem:
    case o_near:
      v = x.type == o_near
        ? map_code_ea(insn, x)
        : pm.i51_map_data_ea(insn, x.addr, x.n);
      if ( get_name_expr(&qbuf, insn.ea+x.offb, x.n, v, x.addr) <= 0 )
      {
/*        int nbit;
        if ( insn.itype == I51_ecall || insn.itype == I51_ejmp )
          nbit = OOFW_32;
        else
          nbit = OOFW_16;*/
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
        break;
      }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:

      if ( x.type == o_mem && x.addr >= 0x80 )
      {
        tag_remove(&qbuf);
        out_register(qbuf.begin());
        break;
      }
      out_line(qbuf.begin());
      break;

    case o_void:
      return false;

    case o_bit251:
      if ( x.b251_bitneg )
        out_symbol('/');
      dir = (int)x.addr;
      bit = x.b251_bit;
      goto OUTBIT;

    case o_bitnot:
      out_symbol('/');
      // fallthrough
    case o_bit:
      dir = (x.reg & 0xF8);
      bit = x.reg & 7;
      if ( (dir & 0x80) == 0 )
        dir = dir/8 + 0x20;
OUTBIT:
      v = pm.i51_map_data_ea(insn, dir, x.n);
      out_addr_tag(v);
      if ( ash.uflag & UAS_PBIT )
      {
        const ioport_bit_t *predef = pm.find_bit(dir, bit);
        if ( predef != nullptr )
        {
          out_line(predef->name.c_str(), COLOR_REG);
          break;
        }
      }
      {
        ssize_t len = get_name_expr(&qbuf, insn.ea+x.offb, x.n, v, dir);
        if ( len > 0 && strchr(qbuf.begin(), '+') == nullptr )
        {

      // we want to output the bit names always in COLOR_REG,
      // so remove the color tags and output it manually:

          if ( dir < 0x80 )
          {
            out_line(qbuf.begin());
          }
          else
          {
            tag_remove(&qbuf);
            out_register(qbuf.begin());
          }
        }
        else
        {
          out_long(dir, 16);
        }
        out_symbol(ash.uflag & UAS_NOBIT ? '_' : '.');
        out_symbol(char('0'+bit));
      }
      break;

     default:
       warning("out: %a: bad optype %d",insn.ea,x.type);
       break;
  }
  return true;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the 'cmd' structure
void out_i51_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);                   // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);                 // output the second operand
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);                 // output the third operand
  }


  // output a character representation of the immediate values
  // embedded in the instruction as comments

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void i51_t::i51_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
// generate start of a segment
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void i51_t::i51_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  char buf[MAXSTR];

  qstring name;
  get_visible_segm_name(&name, Sarea);

  if ( ash.uflag & UAS_SECT )
  {
    if ( Sarea->type == SEG_IMEM )
      ctx.flush_buf(".RSECT", DEFAULT_INDENT);
    else
      ctx.gen_printf(0, COLSTR("%s: .section", SCOLOR_ASMDIR), name.c_str());
  }
  else
  {
    if ( ash.uflag & UAS_NOSEG )
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s.segment %s", SCOLOR_AUTOCMT), ash.cmnt, name.c_str());
    else
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("segment %s",SCOLOR_ASMDIR), name.c_str());
    if ( ash.uflag & UAS_SELSG )
      ctx.flush_buf(name.c_str(), DEFAULT_INDENT);
    if ( ash.uflag & UAS_CDSEG )
      ctx.flush_buf(Sarea->type == SEG_IMEM
                  ? COLSTR("DSEG", SCOLOR_ASMDIR)
                  : COLSTR("CSEG", SCOLOR_ASMDIR),
                    DEFAULT_INDENT);
    // XSEG - eXternal memory
  }
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    adiff_t org = ctx.insn_ea - get_segm_base(Sarea);
    if ( org != 0 )
    {
      btoa(buf, sizeof(buf), org);
      ctx.gen_cmt_line("%s %s", ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly
void i51_t::i51_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      ctx.out_char(' ');
      if ( ash.uflag & UAS_NOENS )
        ctx.out_line(ash.cmnt);
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
// output one "equ" directive
void i51_t::do_out_equ(outctx_t &ctx, const char *name, const char *equ, uchar off) const
{
  if ( ash.uflag & UAS_PSAM )
  {
    ctx.out_line(equ, COLOR_KEYWORD);
    ctx.out_char(' ');
    ctx.out_line(name);
    ctx.out_symbol(',');
  }
  else
  {
    ctx.out_line(name);
    if ( ash.uflag & UAS_EQCLN )
      ctx.out_symbol(':');
    ctx.out_char(' ');
    ctx.out_line(equ, COLOR_KEYWORD);
    ctx.out_char(' ');
  }
  ctx.out_long(off, 16);
  ctx.clr_gen_label();
  ctx.flush_outbuf(0x80000000);
}

//--------------------------------------------------------------------------
int i51_t::out_equ(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *s = getseg(ea);
  if ( s != nullptr && s->type == SEG_IMEM && ash.a_equ != nullptr )
  {
    qstring name = get_visible_name(ea);
    if ( !name.empty()
      && ((ash.uflag & UAS_PBYTNODEF) == 0 || !IsPredefined(name.begin())) )
    {
      get_colored_name(&name, ea);
      uchar off = uchar(ea - get_segm_base(s));
      do_out_equ(ctx, name.begin(), ash.a_equ, off);
      if ( (ash.uflag & UAS_AUBIT) == 0 && (off & 0xF8) == off )
      {
        ctx.out_tagon(COLOR_SYMBOL);
        ctx.out_char(ash.uflag & UAS_NOBIT ? '_' : '.');
        qstring pfx = ctx.outbuf;
        for ( int i=0; i < 8; i++ )
        {
          ctx.outbuf = pfx;
          const ioport_bit_t *b = find_bit(off, i);
          if ( b == nullptr || b->name.empty() )
            ctx.out_char('0' + i);
          else
            ctx.out_line(b->name.c_str(), COLOR_HIDNAME);
          ctx.out_tagoff(COLOR_SYMBOL);
          qstring full = name + ctx.outbuf;
          ctx.outbuf.qclear();
          do_out_equ(ctx, full.begin(), ash.a_equ, uchar(off+i));
        }
        ctx.gen_empty_line();
      }
    }
    else
    {
      ctx.clr_gen_label();
      ctx.flush_buf("");
    }
    return 1;
  }
  if ( (ash.uflag & UAS_NODS) != 0 )
  {
    if ( s != nullptr && !is_loaded(ea) && s->type == SEG_CODE )
    {
      char buf[MAX_NUMBUF];
      adiff_t org = ea - get_segm_base(s) + get_item_size(ea);
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
      return 1;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
// generate a data representation
// usually all the job is handled by the kernel's standard procedure,
// out_data()
// But 8051 has its own quirks (namely, "equ" directives) and out_data()
// can't handle them. So we output "equ" ourselves and pass everything
// else to out_data()
// Again, let's repeat: usually the data items are output by the kernel
// function out_data(). You have to override it only if the processor
// has special features and the data items should be displayed in a
// special way.

void i51_t::i51_data(outctx_t &ctx, bool analyze_only)
{
  // the kernel's standard routine which outputs the data knows nothing
  // about "equ" directives. So we do the following:
  //    - try to output an "equ" directive
  //    - if we succeed, then ok
  //    - otherwise let the standard data output routine, out_data()
  //        do all the job

  if ( !out_equ(ctx) )
    ctx.out_data(analyze_only);
}
