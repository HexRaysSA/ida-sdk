/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"

//----------------------------------------------------------------------
class out_nec78k0s_t : public outctx_t
{
  out_nec78k0s_t(void) = delete; // not used
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }
  int OutVarName(const op_t &x, bool iscode);

  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_nec78k0s_t) == sizeof(outctx_t));

//----------------------------------------------------------------------
void idaapi out_insn(outctx_t &ctx)
{
  out_nec78k0s_t *p = (out_nec78k0s_t *)&ctx;
  p->out_insn();
}

bool idaapi out_opnd(outctx_t &ctx, const op_t &x)
{
  out_nec78k0s_t *p = (out_nec78k0s_t *)&ctx;
  return p->out_operand(x);
}

//----------------------------------------------------------------------
int out_nec78k0s_t::OutVarName(const op_t &x, bool iscode)
{
  ushort addr = ushort(x.addr);
  // get linear address
  ea_t toea = map_ea(insn, addr, x.n, iscode);
  // get its string representation
  return out_name_expr(x, toea, x.addr);
}

//----------------------------------------------------------------------
bool out_nec78k0s_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      if ( x.prepost )
        out_symbol('[');
      OutReg(x.reg);
      if ( x.xmode )
      {
        out_symbol('+');
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_8);
      }
      if ( x.prepost )
        out_symbol(']');
      break;

    case o_phrase:
      out_line(ph.reg_names[x.reg]);
      break;

    case o_bit:
      switch ( x.reg )
      {
        case rPSW:
          out_line("PSW.");
          switch ( x.value )
          {
            case 0:
              out_line("CY");
              break;
            case 4:
              out_line("AC");
              break;
            case 6:
              out_line("Z");
              break;
            case 7:
              out_line("IE");
              break;
            default:
              out_value(x, OOFW_IMM);
              break;
          }
          break;

        case rA:
          out_line("A.");
          out_char(char('0'+x.value));
          break;

        default:
          if ( !OutVarName(x, true) )
            out_value(x, OOF_ADDR | OOFW_16);
          out_symbol('.');
          // Look for a bit using its address
          nec78k0s_t &pm = *static_cast<nec78k0s_t *>(procmod);
          if ( !pm.nec_find_ioport_bit(*this, (int)x.addr, (int)x.value) )
            out_char(char('0'+x.value)); // output data as immediate
          break;
      }
      break;

    case o_imm:
      if ( !x.regmode )
      {
        out_symbol('#');
        out_value(x, OOFW_IMM);
      }
      else
      {
        out_symbol('1');
      }
      break;

    case o_mem:
      // output a memory address (e.g. byte_98)
      if ( x.addr16 )
        out_symbol('!');
      // output a name
      if ( !OutVarName(x, false) )
        out_value(x, OOF_ADDR | OOFW_16); // output just an address
      break;

    case o_near:
      {
        if ( x.addr16 )
          out_symbol('!');
        if ( x.form )
          out_symbol('[');
        // get linear address
        ea_t v = to_ea(insn.cs,x.addr);
        if ( !out_name_expr(x, v, x.addr) )
        {
          // print its value
          out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_16);
          remember_problem(PR_NONAME, insn.ea);
        }
        if ( x.form )
          out_symbol(']');
      }
      break;

    default:
      warning("out: %a: bad optype %d", insn.ip, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_nec78k0s_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);

  // more operands?
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');// print delimiter
    // unless UAS_NOSPA is set, add a space
    if ( !(ash.uflag & UAS_NOSPA) )
      out_char(' ');
    out_one_operand(1);
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    if ( !(ash.uflag & UAS_NOSPA) )
      out_char(' ');
    out_one_operand(2);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void nec78k0s_t::nec78k0s_header(outctx_t &ctx)
{
  ctx.gen_cmt_line("Processor:       %s [%s]",
                   !ioh.device.empty()
                 ? ioh.device.c_str()
                 : inf_get_procname().c_str(),
                   ioh.deviceparams.c_str());
  ctx.gen_cmt_line("Target assebler: %s", ash.name);
  if ( ash.header != nullptr )
    for ( const char *const *ptr=ash.header; *ptr != nullptr; ptr++ )
      ctx.flush_buf(*ptr, 0);
}

//--------------------------------------------------------------------------
void idaapi nec78k0s_segstart(outctx_t &, segment_t *)
{
}

//--------------------------------------------------------------------------
void nec78k0s_t::nec78k0s_footer(outctx_t &ctx) const
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
