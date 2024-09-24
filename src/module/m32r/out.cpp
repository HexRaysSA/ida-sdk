
#include "m32r.hpp"
#include <diskio.hpp>

//----------------------------------------------------------------------
class out_m32r_t : public outctx_t
{
  out_m32r_t(void) = delete; // not used
  m32r_t &pm() { return *static_cast<m32r_t *>(procmod); }
public:
  void outreg(int n) { out_register(ph.reg_names[n]); }

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_m32r_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_m32r_t)

//----------------------------------------------------------------------------
inline const char *m32r_t::ptype_str(void) const
{
  switch ( ptype )
  {
    case prc_m32r:  return "m32r";
    case prc_m32rx: return "m32rx";
  }
  return nullptr;    //lint !e527 statement is unreachable
}

//----------------------------------------------------------------------------
// generate header
void m32r_t::m32r_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, nullptr, ioh.device.c_str());

  char buf[MAXSTR];
  const char *n = ptype_str();

  // print the processor directive .m32r, or .m32rx
  if ( n != nullptr )
  {
    qsnprintf(buf, sizeof(buf), COLSTR(".%s", SCOLOR_ASMDIR), n);
    ctx.flush_buf(buf,0);
  }
}

//----------------------------------------------------------------------------
// generate footer
void idaapi m32r_footer(outctx_t &ctx)
{
  ctx.gen_cmt_line("end of file");
}

//----------------------------------------------------------------------------
// output an operand
bool out_m32r_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    // register
    case o_reg:
      outreg(x.reg);
      break;

    // immediate
    case o_imm:
      {
        const ioport_t *port = pm().find_sym(x.value);

        // this immediate is represented in the .cfg file
        if ( port != nullptr )
        {
          // output the port name instead of the numeric value
          out_line(port->name.c_str(), COLOR_IMPNAME);
        }
        // otherwise, simply print the value
        else
        {
          out_symbol('#');
          out_value(x, OOFW_IMM|OOF_SIGNED);
        }
      }
      break;

    // displ @(imm, reg)
    case o_displ:
      out_symbol('@');
      out_symbol('(');
      out_value(x, OOF_SIGNED | OOF_ADDR | OOFW_32);
      out_symbol(',');
      out_char(' ');
      outreg(x.reg);
      out_symbol(')');
      break;

    // address
    case o_near:
      if ( !out_name_expr(x, to_ea(insn.cs, x.addr), x.addr) )
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32);
      break;

    // phrase
    case o_phrase:
      switch ( x.specflag1 )
      {
        // @R
        case fRI:
          out_symbol('@');
          if ( is_defarg(F, x.n) )
          {
            out_symbol('(');
            out_value(x, 0);   // will print 0
            out_symbol(',');
            out_char(' ');
            outreg(x.reg);
            out_symbol(')');
          }
          else
          {
            outreg(x.reg);
          }
          break;

        // @R+
        case fRIBA:
          out_symbol('@');
          outreg(x.reg);
          out_symbol('+');
          break;

        // @+R
        case fRIAA:
          out_symbol('@');
          out_symbol('+');
          outreg(x.reg);
          break;

        // @-R
        case fRIAS:
          out_symbol('@');
          out_symbol('-');
          outreg(x.reg);
          break;
      }
      break;
  }
  return 1;
}

//----------------------------------------------------------------------------
void out_m32r_t::out_proc_mnem(void)
{
  char postfix[3];                        // postfix to eventually insert after the insn name
  postfix[0] = '\0';                      // postfix is null by default

  // use synthetic option is selected
  if ( pm().use_synthetic_insn() )
  {
    if ( insn.segpref & SYNTHETIC_SHORT )
      qstrncpy(postfix, (insn.itype == m32r_ldi ? "8" : ".s"), sizeof(postfix));
    if ( insn.segpref & SYNTHETIC_LONG )
      qstrncpy(postfix, (insn.itype == m32r_ldi ? "16" : ".l"), sizeof(postfix));
  }

  out_mnem(8, postfix);
}

//----------------------------------------------------------------------------
// output an instruction and its operands
void out_m32r_t::out_insn(void)
{
  // if this DSP instruction in executed in parallel with a NOP instruction
  // (example: nop || machi r1, r2), first print the NOP.
  if ( insn.segpref & NEXT_INSN_PARALLEL_DSP )
  {
    out_line("nop", COLOR_INSN);
    out_char(' ');
    out_symbol('|');
    out_symbol('|');
    out_char(' ');
  }

  out_mnemonic();

  out_one_operand(0);                   // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);               // output the second operand
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);               // output the third operand
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();

  // print a parallel NOP instruction unless the current instruction
  // is either push or pop (in this special case, nop cannot be executed in //)
  if ( (insn.itype != m32r_push && insn.itype != m32r_pop)
    && insn.segpref & NEXT_INSN_PARALLEL_NOP )
  {
    // don't print NOP if the instruction was ld/st reg, fp, and has been converted to ld/st reg, @(arg, fp)
    // (in other words, in the second operand is a stack variable).
    // because the o_displ form of ld/st insn is 32 bits, and cannot handle a parallel nop.
    if ( (insn.itype != m32r_ld && insn.itype != m32r_st) || !is_stkvar1(F) )
    {
      if ( insn.Op1.type != o_void )
        out_char(' ');
      out_symbol('|');
      out_symbol('|');
      out_char(' ');
      out_line("nop", COLOR_INSN);
    }
  }

  if ( insn.segpref & NEXT_INSN_PARALLEL_OTHER )
  {
    if ( insn.Op1.type != o_void )
      out_char(' ');
    out_symbol('|');
    out_symbol('|');
    out_symbol('\\');
  }
  flush_outbuf();
}

//----------------------------------------------------------------------------
// generate segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void idaapi m32r_segstart(outctx_t &ctx, segment_t *Sarea)
{
  qstring sname;
  get_visible_segm_name(&sname, Sarea);
  char *segname = sname.begin();

  if ( !sname.empty() && *segname == '_' )
    *segname = '.';

  ctx.gen_printf(0, COLSTR(".section %s", SCOLOR_ASMDIR), sname.c_str());
}
