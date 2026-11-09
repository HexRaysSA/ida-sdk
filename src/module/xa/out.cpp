/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"
#include <fpro.h>
#include <diskio.hpp>

//----------------------------------------------------------------------
class out_xa_t : public outctx_t
{
  out_xa_t(void) = delete; // not used
public:
  void OutReg(int rgnum)
  {
    out_register(ph.reg_names[rgnum]);
  }
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);

  void do_out_equ(const char *name, uchar off);
  int out_equ(void);
};
CASSERT(sizeof(out_xa_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_xa_t)

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
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("DPTR", SCOLOR_REG),
  AT COLSTR("A", SCOLOR_REG) PLUS COLSTR("PC", SCOLOR_REG)
};

//----------------------------------------------------------------------
// generate the text representation of an operand

bool out_xa_t::out_operand(const op_t &x)
{
  uval_t v = 0;
  int dir, bit;
  qstring qbuf;
  switch ( x.type )
  {
    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      switch ( x.phrase )
      {
        case fAdptr:
        case fApc:
          out_colored_register_line(phrases[x.phrase]);
          break;
        case fRi:
          out_symbol('[');
          OutReg(x.indreg);
          out_symbol(']');
          break;
        case fRip:
          out_symbol('[');
          OutReg(x.indreg);
          out_symbol('+');
          out_symbol(']');
          break;
        case fRii:
          out_symbol('[');
          out_symbol('[');
          OutReg(x.indreg);
          out_symbol(']');
          out_symbol(']');
          break;
        case fRipi:
          out_symbol('[');
          out_symbol('[');
          OutReg(x.indreg);
          out_symbol('+');
          out_symbol(']');
          out_symbol(']');
          break;
        case fRlistL:
        case fRlistH:
          v = x.indreg;
          dir = (x.dtype == dt_byte) ? rR0L : rR0;
          if ( x.phrase == fRlistH )
            dir += 8;
          for ( bit = 0; bit < 8; bit++,dir++,v >>= 1 )
          {
            if ( v&1 )
            {
              OutReg(dir);
              if ( v & 0xfe )
                out_symbol(',');
            }
          }
          break;
      }
      break;

    case o_displ:
      if ( insn.itype != XA_lea )
        out_symbol('[');
      OutReg(x.indreg);
      if ( x.indreg == rR7 || x.phrase != fRi )
        out_value(x, OOF_ADDR | OOFS_NEEDSIGN | OOF_SIGNED | OOFW_16);
      if ( insn.itype != XA_lea )
        out_symbol(']');
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, OOFS_IFSIGN | /* OOF_SIGNED | */ OOFW_IMM);
      break;

    case o_mem:
    case o_near:
    case o_far:
      switch ( x.type )
      {
        case o_mem:
          v = map_addr(x.addr);
          break;
        case o_near:
          v = to_ea(insn.cs, x.addr);
          break;
        case o_far:
          v = x.addr + (x.specval<<16);
          break;
      }
      if ( get_name_expr(&qbuf, insn.ea+x.offb, x.n, v, x.addr & 0xFFFF) <= 0 )
      {
        if ( x.type == o_far )
        {
          // print the segment part
          out_long(x.specval, 16);
          out_symbol(':');
        }
        // now print the offset
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
        break;
      }

      // we want to output SFR register names always in COLOR_REG,
      // so remove the color tags and output it manually:

      if ( x.type == o_mem && x.addr >= 0x400 )
      {
        tag_remove(&qbuf);
        out_register(qbuf.begin());
        break;
      }
      out_line(qbuf.begin());
      break;

    case o_void:
      return 0;

    case o_bitnot:
      out_symbol('/');
      // fallthrough
    case o_bit:
      dir = int(x.addr >> 3);
      bit = x.addr & 7;
      if ( dir & 0x40 ) // SFR
      {
        dir += 0x3c0;
      }
      else if ( (dir & 0x20) == 0 ) // Register file
      {
        dir = int(x.addr >> 4);
        bit = x.addr & 15;
        OutReg(rR0+dir);
        out_symbol(ash.uflag & UAS_NOBIT ? '_' : '.');
        if ( bit > 9 )
        {
          out_symbol('1');
          bit -= 10;
        }
        out_symbol(char('0'+bit));
        break;
      }
      if ( ash.uflag & UAS_PBIT )
      {
        xa_t &pm = *static_cast<xa_t *>(procmod);
        const predefined_t *predef = pm.GetPredefinedBits(dir, bit);
        if ( predef != nullptr )
        {
          out_line(predef->name, COLOR_REG);
          break;
        }
      }
      {
        v = map_addr(dir);
        bool ok = get_name_expr(&qbuf, insn.ea+x.offb, x.n, v, dir) > 0;
        if ( ok && strchr(qbuf.begin(), '+') == nullptr )
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
       warning("out: %a: bad optype %d", insn.ea, x.type);
       break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_xa_t::out_proc_mnem(void)
{
  if ( insn.Op1.type != o_void )
  {
    switch ( insn.Op1.dtype )
    {
      case dt_byte:
        out_mnem(8,".b");
        break;
      case dt_word:
        out_mnem(8,".w");
        break;
      case dt_dword:
        out_mnem(8,".d");
        break;
      default:
        out_mnem();
    }
  }
  else
  {
    out_mnem();                      // output instruction mnemonics
  }
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
// the information about the instruction is in the insn structure

void out_xa_t::out_insn(void)
{
  out_mnemonic();
  out_one_operand(0);             // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);           // output the second operand
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);           // output the third operand
  }


  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void xa_t::xa_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// generate start of a segment

//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void xa_t::xa_segstart(outctx_t &ctx, segment_t *Sarea)
{
  qstring sname;
  get_visible_segm_name(&sname, Sarea);

  if ( ash.uflag & UAS_SECT )
  {
    if ( Sarea->type == SEG_IMEM )
      ctx.flush_buf(".RSECT", DEFAULT_INDENT);
    else
      ctx.gen_printf(0, COLSTR("%s: .section", SCOLOR_ASMDIR), sname.c_str());
  }
  else
  {
    if ( ash.uflag & UAS_NOSEG )
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s.segment %s", SCOLOR_AUTOCMT),
                 ash.cmnt, sname.c_str());
    else
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("segment %s",SCOLOR_ASMDIR), sname.c_str());
    if ( ash.uflag & UAS_SELSG )
      ctx.flush_buf(sname.c_str(), DEFAULT_INDENT);
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
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_cmt_line("%s %s", ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly

void xa_t::xa_footer(outctx_t &ctx)
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

void out_xa_t::do_out_equ(const char *name, uchar off)
{
  if ( (ash.uflag & UAS_PSAM) != 0 )
  {
    out_line(ash.a_equ, COLOR_KEYWORD);
    out_char(' ');
    out_line(name);
    out_symbol(',');
  }
  else
  {
    out_line(name);
    if ( ash.uflag & UAS_EQCLN )
      out_symbol(':');
    out_char(' ');
    out_line(ash.a_equ, COLOR_KEYWORD);
    out_char(' ');
  }
  out_long(off, 16);
  clr_gen_label();
  out_tagoff(COLOR_SYMBOL);
  flush_outbuf(0);
}

//--------------------------------------------------------------------------
// output "equ" directive(s) if necessary
int out_xa_t::out_equ(void)
{
  ea_t ea = insn.ea;
  segment_t *s = getseg(ea);
  if ( s != nullptr && s->type == SEG_IMEM && ash.a_equ != nullptr )
  {
    qstring name;
    if ( get_visible_name(&name, ea) > 0
      && ((ash.uflag & UAS_PBYTNODEF) == 0 || !xa_t::IsPredefined(name.begin())) )
    {
      get_colored_name(&name, ea);
      uchar off = uchar(ea - get_segm_base(s));
      do_out_equ(name.begin(), off);
      if ( (ash.uflag & UAS_AUBIT) == 0 && (off & 0xF8) == off )
      {
        qstring tmp;
        out_tagon(COLOR_SYMBOL);
        out_char(ash.uflag & UAS_NOBIT ? '_' : '.');
        tmp.swap(outbuf);
        for ( int i=0; i < 8; i++,off++ )
        {
          qstring full = tmp;
          full.append('0' + i);
          do_out_equ(full.begin(), off);
        }
        gen_empty_line();
      }
    }
    else
    {
      clr_gen_label();
      flush_buf("");
    }
    return 1;
  }
  if ( (ash.uflag & UAS_NODS) != 0 )
  {
    if ( !is_loaded(ea) && s->type == SEG_CODE )
    {
      adiff_t org = ea - get_segm_base(s) + get_item_size(ea);
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
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
// has special features and the data itesm should be displayed in a
// special way.

void xa_t::xa_data(outctx_t &ctx, bool analyze_only)
{
  // the kernel's standard routine which outputs the data knows nothing
  // about "equ" directives. So we do the following:
  //    - try to output an "equ" directive
  //    - if we succeed, then ok
  //    - otherwise let the standard data output routine, out_data()
  //        do all the job

  out_xa_t *p = (out_xa_t *)&ctx;
  if ( !p->out_equ() )
    ctx.out_data(analyze_only);
}
