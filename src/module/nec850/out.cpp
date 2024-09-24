/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Output
 *
 */
#include "necv850.hpp"

//--------------------------------------------------------------------------
// LIST12 table mapping to corresponding registers
static const int list12_table[] =
{
  rR31, // 0
  rR29, // 1
  rR28, // 2
  rR23, // 3
  rR22, // 4
  rR21, // 5
  rR20, // 6
  rR27, // 7
  rR26, // 8
  rR25, // 9
  rR24, // 10
  rEP   // 11
};

// Using the indexes in this table as indexes in list12_table[]
// we can test for bits in List12 in order
static const int list12order_table[] =
{
  6,    // 0  r20
  5,    // 1  r21
  4,    // 2  r22
  3,    // 3  r23
  10,   // 4  r24
  9,    // 5  r25
  8,    // 6  r26
  7,    // 7  r27
  2,    // 8  r28
  1,    // 9  r29
  11,   // 10 r30
  0,    // 11 r31
};

//----------------------------------------------------------------------
int get_displ_outf(const insn_t &insn, const op_t &x, flags64_t F)
{
  qnotused(insn);
  qnotused(F);

  int outf = OOF_ADDR;
  outf |= ( x.specflag1 & N850F_VAL32 ) ? OOFW_32 : OOFW_16;
  if ( ( x.specflag1 & N850F_OUTSIGNED ) != 0 )
    outf |= OOFS_IFSIGN | OOF_SIGNED;

  return outf;
}

//----------------------------------------------------------------------
class out_nec850_t : public outctx_t
{
  out_nec850_t(void) = delete; // not used
  nec850_t &pm() { return *static_cast<nec850_t *>(procmod); }

  void get_reg_name(char *output_name, size_t output_size, uint16 reg) const;
public:
  void OutReg(const op_t &r);
  void out_reg_list(uint32 L);
  void out_reg_range(const op_t &op);
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_cond(const op_t &r);
  void out_fcond(const op_t &r);
};
CASSERT(sizeof(out_nec850_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_nec850_t)

//--------------------------------------------------------------------------
bool reg_in_list12(uint16 reg, uint32 L)
{
  if ( rR20 <= reg && reg <= rR31 )
  {
    uint32 idx = list12order_table[reg - rR20];   //lint !e676 possibly indexing before the beginning of an allocation
    return (L & (1 << idx)) != 0;
  }
  return false;
}

//--------------------------------------------------------------------------
void out_nec850_t::out_reg_list(uint32 L)
{
  int last = qnumber(list12_table);
  int in_order = 0, c = 0;
  const char *last_rn = nullptr;

  out_symbol('{');
  for ( int i=0; i < qnumber(list12order_table); i++ )
  {
    uint32 idx = list12order_table[i];
    if ( (L & (1 << idx)) == 0 )
      continue;
    c++;
    const char *rn = RegNames[list12_table[idx]];
    if ( last + 1 == i )
      in_order++;
    else
    {
      if ( in_order > 1 )
      {
        out_symbol('-');
        out_register(last_rn);
        out_line(", ", COLOR_SYMBOL);
      }
      else if ( c > 1 )
      {
        out_line(", ", COLOR_SYMBOL);
      }
      out_register(rn);
      in_order = 1;
    }
    last_rn = rn;
    last    = i;
  }
  if ( in_order > 1 )
  {
    out_symbol('-');
    out_register(last_rn);
  }
  out_symbol('}');
}

void out_nec850_t::get_reg_name(char *output_name, size_t output_size, uint16 reg) const
{
  if ( insn.itype == NEC850_LDM_MP || insn.itype == NEC850_STM_MP )
  {
    qsnprintf(output_name, output_size, "e%u", reg);
    return;
  }

  qstrncpy(output_name, RegNames[reg], output_size);
}

//--------------------------------------------------------------------------
void out_nec850_t::out_reg_range(const op_t &op)
{
  char regname_high[8];
  char regname_low[8];

  get_reg_name(regname_high, sizeof(regname_high), op.regrange_high);
  get_reg_name(regname_low, sizeof(regname_low), op.regrange_low);

  out_register(regname_high);
  out_symbol('-');
  out_register(regname_low);
}
//--------------------------------------------------------------------------
void idaapi nec850_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
}

//--------------------------------------------------------------------------
void nec850_t::nec850_footer(outctx_t &ctx) const
{
  ctx.gen_empty_line();
  ctx.out_line(ash.end, COLOR_ASMDIR);
  ctx.flush_outbuf(DEFAULT_INDENT);
  ctx.gen_cmt_line("-------------- end of module --------------");
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, s) could be made const
void idaapi nec850_segstart(outctx_t &ctx, segment_t *s)
{
  qstring sname;
  qstring sclass;

  get_visible_segm_name(&sname, s);
  get_segm_class(&sclass, s);

  const char *p_class;
  if ( (s->perm == (SEGPERM_READ|SEGPERM_WRITE)) && s->type == SEG_BSS )
    p_class = "bss";
  else if ( s->perm == SEGPERM_READ )
    p_class = "const";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_WRITE) )
    p_class = "data";
  else if ( s->perm == (SEGPERM_READ|SEGPERM_EXEC) )
    p_class = "text";
  else if ( s->type == SEG_XTRN )
    p_class = "symtab";
  else
    p_class = sclass.c_str();

  ctx.gen_printf(0, COLSTR(".section \"%s\", %s", SCOLOR_ASMDIR), sname.c_str(), p_class);
}

//--------------------------------------------------------------------------
void idaapi nec850_segend(outctx_t &, segment_t *)
{
}

//----------------------------------------------------------------------
void out_nec850_t::OutReg(const op_t &r)
{
  // LDSR reg2, regID, selID
  // STSR regID, reg2, selID
  // don't use symbolic name for regID if selID is not 0
  // TODO: add per-processsor regID, selID -> name mappings
  if ( (insn.itype == NEC850_LDSR && r.n == 1
     || insn.itype == NEC850_STSR && r.n == 0)
    && insn.Op3.value != 0 )
  {
    char regname[8];
    qsnprintf(regname, sizeof(regname), "sr%d", r.reg-rSR0);
    out_register(regname);
    return;
  }
  bool brackets = r.specflag1 & N850F_USEBRACKETS;
  if ( brackets )
    out_symbol('[');
  out_register(ph.reg_names[r.reg]);
  if ( brackets )
    out_symbol(']');

  if ( r.specflag1 & N850F_POST_INCREMENT )
    out_symbol('+');

  if ( r.specflag1 & N850F_POST_DECREMENT )
    out_symbol('-');

  if ( r.specflag1 & N850F_MODULO_ADRESSING )
    out_symbol('%');

  if ( r.specflag1 & N850F_BIT_REV_ADRESSING )
    out_symbol('!');
}

static const char *cond_tbl[16] =
{
  "v",    // 0000: Overflow (OV=1)
  "c/l",  // 0001: Carry (CY=1)
  "z",    // 0010: Zero (Z=1)
  "nh",   // 0011: Not higher (Less than or equal) ((CY or Z) = 1)
  "s/n",  // 0100: Negative) S=1
  "t",    // 0101: Always (true)
  "lt",   // 0110: Less than signed (S xor OV) = 1
  "le",   // 0111: Less than or equal signed (((S xor OV) or Z) = 1)
  "nv",   // 1000: no overflow (OV=0)
  "nc/nl",// 1001: no carry (CY=0)
  "nz",   // 1010: not zero (Z=0)
  "h",    // 0011: Higher (Greater than) ((CY or Z) = 0)
  "ns/p", // 0100: Positive (S=0)
  "sat",  // 1101: Saturated (SAT=1)
  "ge",   // 1110: Greater than or equal signed (S xor OV) = 0
  "gt",   // 1111: Greater than signed (((S xor OV) or Z) = 0)
};

static const char *fcond_tbl[16] =
{
  "f/t",
  "un/or",
  "eq/neq",
  "ueq/ogl",
  "olt/uge",
  "ult/oge",
  "ole/ugt",
  "ule/ogt",
  "sf/st",
  "ngle/gle",
  "seq/sne",
  "ngl/gl",
  "lt/nlt",
  "nge/ge",
  "le/nle",
  "ngt/gt"
};

//----------------------------------------------------------------------
void out_nec850_t::out_cond(const op_t &r)
{
  int cc = r.value;
  QASSERT(10327, r.type == o_cond && cc < qnumber(cond_tbl));
  out_keyword(cond_tbl[cc]);
}

//----------------------------------------------------------------------
void out_nec850_t::out_fcond(const op_t &r)
{
  int cc = r.value;
  QASSERT(10323, r.type == o_cond && cc < qnumber(fcond_tbl));
  out_keyword(fcond_tbl[cc]);
}

//----------------------------------------------------------------------
void out_nec850_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);

  for ( int i=1; i < UA_MAXOP; i++ )
  {
    if ( insn.ops[i].type == o_void )
      break;
    out_symbol(',');
    out_char(' ');
    out_one_operand(i);
  }

  // add the comment for indirect jumps
  if ( is_call_or_jump(insn.itype)
    && (insn.Op1.type == o_reg || insn.Op1.type == o_displ) )
  {
    out_fcref_names();
  }
  flush_outbuf();
}

//----------------------------------------------------------------------
// Generate text representation of an instructon operand.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
// The output text is placed in the output buffer initialized with init_output_buffer()
// This function uses out_...() functions from ua.hpp to generate the operand text
// Returns: 1-ok, 0-operand is hidden.
bool out_nec850_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return false;
    case o_reglist:
      out_reg_list(x.value);
      break;
    case o_regrange:
      out_reg_range(x);
      break;
    case o_reg:
      OutReg(x);
      break;
    case o_imm:
      out_value(x, OOFW_IMM | ((x.specflag1 & N850F_OUTSIGNED) ? OOF_SIGNED : 0));
      break;
    case o_near:
    case o_mem:
      if ( !out_name_expr(x, pm().trunc_uval(x.addr), BADADDR) )
      {
        out_tagon(COLOR_ERROR);
        out_value(x, OOF_ADDR | OOFW_IMM | OOFW_32);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
      }
      break;
    case o_displ:
      if ( x.addr != 0 || x.reg == rSP || is_defarg(getF(), x.n) )
        out_value(x, get_displ_outf(insn, x, F));
      OutReg(x);
      break;
    case o_cond:
      if ( insn.auxpref & N850F_FP )
        out_fcond(x);
      else
        out_cond(x);
      break;
    default:
      return false;
  }
  return true;
}
