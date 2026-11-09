
#include "sam8.hpp"

//----------------------------------------------------------------------
class out_sam8_t : public outctx_t
{
  out_sam8_t(void) = delete; // not used
public:
  void OutRegString(bool isWorkingReg, bool isPair, int regNum, int regBit = -1);
  void OutAddr(const op_t &x, ea_t ea, ea_t off, bool isSigned = false);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_sam8_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_sam8_t)

//----------------------------------------------------------------------
void out_sam8_t::OutRegString(bool isWorkingReg, bool isPair, int regNum, int regBit)
{
  char buf[256];

  // if it is a working register, output it with an R in front
  if ( isWorkingReg )
  {
    if ( !isPair )
      qsnprintf(buf, sizeof(buf), "R%u", (unsigned int) regNum);
    else
      qsnprintf(buf, sizeof(buf), "RR%u", (unsigned int) regNum);
  }
  else
  {
    // output either working or non-working reg
    if ( !isPair )
    {
      // N.B. working registers start at 0xC0
      if ( regNum >= 0xC0 )
        qsnprintf(buf, sizeof(buf), "R%u", (unsigned int) (regNum - 0xC0));
      else
        qsnprintf(buf, sizeof(buf), "0%XH", regNum);
    }
    else
    {
      // N.B. working registers start at 0xC0
      if ( regNum >= 0xC0 )
        qsnprintf(buf, sizeof(buf), "RR%u", (unsigned int) regNum - 0xC0);
      else
        qsnprintf(buf, sizeof(buf), "0%XH", regNum);
    }
  }
  out_register(buf);

  // output regBit if requested
  if ( regBit != -1 )
  {
    qsnprintf(buf, sizeof(buf), ".%i", regBit);
    out_line(buf, COLOR_DEFAULT);
  }
}

//----------------------------------------------------------------------
void out_sam8_t::OutAddr(const op_t &x, ea_t ea, ea_t off, bool isSigned)
{
  // try and find the real name expression
  if ( !out_name_expr(x, ea, off) )
  {
    // work out flags correctly
    uint32 flags = OOF_ADDR | OOFW_16;
    if ( isSigned )
      flags |= OOF_SIGNED;
    else
      flags |= OOFS_NOSIGN;

    // if name wasn't found, just output the value & add to noname queue
    out_value(x, flags);
    remember_problem(PR_NONAME, insn.ea);
  }
}


//----------------------------------------------------------------------
// generate the text representation of an operand

bool out_sam8_t::out_operand(const op_t &x)
{
  // output operands
  switch ( x.type )
  {
    case o_reg:
      OutRegString(x.fl_workingReg != 0, x.fl_regPair != 0, x.reg);
      break;

    case o_reg_bit:
      OutRegString(x.fl_workingReg != 0, x.fl_regPair != 0, x.reg, (int)x.v_bit);
      break;

    case o_imm:
      out_symbol('#');
      out_value(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_cmem_ind:
      // this needs special treatment... has to have a # in front of it
      out_symbol('#');
      OutAddr(x, x.addr, x.addr);
      break;

    case o_near:
    case o_cmem:
      OutAddr(x, x.addr, x.addr);
      break;

    case o_emem:
      OutAddr(x, SAM8_EDATASEG_START + x.addr, x.addr);
      break;

    case o_phrase:
      switch ( x.phrase )
      {
        case fIndReg:
          out_symbol('@');
          OutRegString(x.fl_workingReg != 0, x.fl_regPair != 0, x.v_phrase_reg);
          break;

        case fIdxReg:
          out_symbol('#');
          OutRegString(false, false, x.v_phrase_reg);
          out_symbol('[');
          OutRegString(true, false, x.v_phrase_idxreg);
          out_symbol(']');
          break;
      }
      break;

    case o_displ:
      switch ( x.phrase )
      {
        case fIdxCAddr:
          out_symbol('#');
          OutAddr(x, x.addr, x.addr, (x.addr > 0xffff));
          out_symbol('[');
          OutRegString(true, true, x.v_phrase_idxreg);
          out_symbol(']');
          break;

        case fIdxEAddr:
          out_symbol('#');
          OutAddr(x, SAM8_EDATASEG_START + x.addr, x.addr, (x.addr > 0xffff));
          out_symbol('[');
          OutRegString(true, true, x.v_phrase_idxreg);
          out_symbol(']');
          break;
      }
      break;
  }

  // OK
  return 1;
}

//----------------------------------------------------------------------
// generate a text representation of an instruction
void out_sam8_t::out_insn(void)
{
  // output instruction mnemonics
  out_mnemonic();

  // check for JP/JR instruction with condition code
  // add the condition on as a pseudo operand if present
  if ( insn.itype == SAM8_JR
    || insn.itype == SAM8_JP && insn.c_condition != ccNone )
  {
    // sanity check
    if ( insn.c_condition >= cc_last )
    {
      warning("%a (%s): Internal error: bad condition code %i",
              insn.ea, insn.get_canon_mnem(ph), insn.c_condition);
      return;
    }

    // output the condition code normally
    out_keyword(ccNames[insn.c_condition]);
    out_symbol(',');
    out_char(' ');
  }

  // output the first operand
  if ( insn.Op1.type != o_void )
    out_one_operand(0);

  // output the second operand
  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  // output the third operand
  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }
  flush_outbuf();
}


//--------------------------------------------------------------------------
// generate start of the disassembly
void idaapi sam8_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}


// --------------------------------------------------------------------------
// generate start of segment
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void sam8_t::sam8_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  // generate ORG directive if necessary
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    // get segment data
    size_t org = size_t(ctx.insn_ea - get_segm_base(Sarea));

    // generate line
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}


// --------------------------------------------------------------------------
// generate end of the disassembly
void sam8_t::sam8_footer(outctx_t &ctx) const
{
  // if assembler supplies end statement, output it
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
}


// --------------------------------------------------------------------------
// customised address output
void idaapi sam8_out_data(outctx_t &ctx, bool analyze_only)
{
  ea_t ea = ctx.insn_ea;
  // if addres is valid, use normal output function
  if ( is_loaded(ea) )
    ctx.out_data(analyze_only);
  else
    ctx.flush_buf(COLSTR("; db ?", SCOLOR_SYMBOL));
}
