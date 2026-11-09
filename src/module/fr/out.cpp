
#include "fr.hpp"

//----------------------------------------------------------------------
class out_fr_t : public outctx_t
{
  out_fr_t(void) = delete; // not used
public:
  void out_reg(ushort reg) { out_register(ph.reg_names[reg]); }
  void out_reg(const op_t &op) { out_reg(op.reg); }
  void out_imm(const op_t &op, bool no_sharp = false);
  void out_addr(const op_t &op);
  void out_reglist(const op_t &op);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
private:
  void out_reg_if_bit(ushort reg, uval_t value, int bit);
};
CASSERT(sizeof(out_fr_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_fr_t)

//----------------------------------------------------------------------
// Output an operand as an immediate value
void out_fr_t::out_imm(const op_t &op, bool no_sharp)
{
  if ( !no_sharp )
    out_symbol('#');
  out_value(op, OOFW_IMM);
}

//----------------------------------------------------------------------
// Output an operand as an address
void out_fr_t::out_addr(const op_t &op)
{
  if ( !out_name_expr(op, to_ea(insn.cs, op.addr), op.addr) )
    out_value(op, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
}

//----------------------------------------------------------------------
void out_fr_t::out_reg_if_bit(ushort reg, uval_t value, int bit)
{
  fr_t &pm = *static_cast<fr_t *>(procmod);
  if ( (value & bit) == bit )
  {
    if ( pm.print_comma )
    {
      out_symbol(',');
      out_char(' ');
    }
    out_reg(reg);
    pm.print_comma = true;
  }
}

void out_fr_t::out_reglist(const op_t &op)
{
  static const uint16 regs_ldm0[] = { rR7,  rR6,  rR5,  rR4,  rR3,  rR2,  rR1,  rR0  };
  static const uint16 regs_stm0[] = { rR0,  rR1,  rR2,  rR3,  rR4,  rR5,  rR6,  rR7  };
  static const uint16 regs_ldm1[] = { rR15, rR14, rR13, rR12, rR11, rR10, rR9,  rR8  };
  static const uint16 regs_stm1[] = { rR8,  rR9,  rR10, rR11, rR12, rR13, rR14, rR15 };
  fr_t &pm = *static_cast<fr_t *>(procmod);
  const uint16 *regs;
  bool left;

  switch ( insn.itype )
  {
    case fr_ldm0:   regs = regs_ldm0; left = false; break;
    case fr_stm0:   regs = regs_stm0; left = true;  break;
    case fr_ldm1:   regs = regs_ldm1; left = false; break;
    case fr_stm1:   regs = regs_stm1; left = true;  break;
    default:
      INTERR(10018);
  }

  pm.print_comma = false;

  out_symbol('(');
  if ( left )   //-V614 uninitialized variable 'left'
  {
    for ( int i = 0, bit = 128; bit != 0; bit >>= 1, i++ )
      out_reg_if_bit(regs[i], op.value, bit);
  }
  else
  {
    for ( int i = 7, bit = 1; bit <= 128; bit <<= 1, i-- )
      out_reg_if_bit(regs[i], op.value, bit);
  }
  out_symbol(')');
}

//----------------------------------------------------------------------
// Generate disassembly header
void fr_t::fr_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, nullptr, ioh.device.c_str());
}

//----------------------------------------------------------------------
// Generate disassembly footer
void fr_t::fr_footer(outctx_t &ctx) const
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

//----------------------------------------------------------------------
// Generate a segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void fr_t::fr_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring sname;
  if ( get_visible_segm_name(&sname, Sarea) <= 0 )
    return;

  const char *segname = sname.c_str();
  if ( *segname == '_' )
    segname++;

  ctx.gen_printf(DEFAULT_INDENT, COLSTR(".section .%s", SCOLOR_ASMDIR), segname);

  ea_t orgbase = ctx.insn_ea - get_segm_para(Sarea);

  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//----------------------------------------------------------------------
// Output an operand.
bool out_fr_t::out_operand(const op_t & op)
{
  fr_t &pm = *static_cast<fr_t *>(procmod);
  switch ( op.type )
  {
    case o_near:
    case o_mem:
      out_addr(op);
      break;

    // immediate value
    case o_imm:
      {
        const ioport_t *port = pm.find_sym(op.value);

        // this immediate is represented in the .cfg file
        // output the port name instead of the numeric value
        if ( port != nullptr )
          out_line(port->name.c_str(), COLOR_IMPNAME);
        else // otherwise, simply print the value
          out_imm(op);
      }
      break;

    // register
    case o_reg:
      out_reg(op);
      break;

    // phrase
    case o_phrase:
      out_symbol('@');
      switch ( op.specflag2 )
      {
        case fIGR:       // indirect general register
          out_reg(op);
          break;

        case fIRA:       // indirect relative address
          out_value(op, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
          break;

        case fIGRP:      // indirect general register with post-increment
          out_reg(op);
          out_symbol('+');
          break;

        case fIGRM:      // indirect general register with pre-decrement
          out_symbol('-');
          out_reg(op);
          break;

        case fR13RI:     // indirect displacement between R13 and a general register
          out_symbol('(');
          out_reg(rR13);
          out_symbol(',');
          out_char(' ');
          out_reg(op);
          out_symbol(')');
          break;

        default:
          INTERR(10019);
      }
      break;

    // displacement
    case o_displ:
      out_symbol('@');
      out_symbol('(');

      // @(R14, #i)
      if ( op_displ_imm_r14(op) )
      {
        out_reg(rR14);
        out_symbol(',');
        out_char(' ');
        out_imm(op, true);
      }
      // @(R15, #i)
      else if ( op_displ_imm_r15(op) )
      {
        out_reg(rR15);
        out_symbol(',');
        out_char(' ');
        out_imm(op, true);
      }
      else
        INTERR(10020);

      out_symbol(')');
      break;

    // reglist
    case o_reglist:
      out_reglist(op);
      break;

    // void operand
    case o_void:
      break;

    default:
      INTERR(10021);
  }
  return 1;
}


//----------------------------------------------------------------------
void out_fr_t::out_proc_mnem(void)
{
  char postfix[5];
  postfix[0] = '\0';

  if ( insn.auxpref & INSN_DELAY_SHOT )
    qstrncpy(postfix, ":D", sizeof(postfix));
  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
// Output an instruction
void out_fr_t::out_insn(void)
{

  //
  // print insn mnemonic
  //
  out_mnemonic();

  for ( int i=0; i < 4; i++ )
  {
    if ( insn.ops[i].type != o_void )
    {
      if ( i != 0 )
      {
        out_symbol(',');
        out_char(' ');
      }
      out_one_operand(i);
    }
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();
  flush_outbuf();
}
