/*
 *                      Interactive disassembler (IDA).
 *                      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                      ALL RIGHTS RESERVED.
 *                                                                                                                      E-mail: ig@estar.msk.su, ig@datarescue.com
 *                                                                                                                      FIDO:    2:5020/209
 *
 */

#include "arc.hpp"

// generic condition codes
static const char *const ccode[] =
{
  "",    ".z",  ".nz", ".p",
  ".n",  ".c",  ".nc", ".v",
  ".nv", ".gt", ".ge", ".lt",
  ".le", ".hi", ".ls", ".pnz",
  ".ss", ".sc", ".c0x12", ".c0x13",
  ".c0x14", ".c0x15", ".c0x16", ".c0x17",
  ".c0x18", ".c0x19", ".c0x1A", ".c0x1B",
  ".c0x1C", ".c0x1D", ".c0x1E", ".c0x1F",
};

// generic condition codes for ARCv2
static const char *const ccode_v2[] =
{
  "",    ".eq", ".ne", ".p",
  ".n",  ".c",  ".nc", ".v",
  ".nv", ".gt", ".ge", ".lt",
  ".le", ".hi", ".ls", ".pnz",
  ".c0x10", ".c0x11", ".c0x12", ".c0x13",
  ".c0x14", ".c0x15", ".c0x16", ".c0x17",
  ".c0x18", ".c0x19", ".c0x1A", ".c0x1B",
  ".c0x1C", ".c0x1D", ".c0x1E", ".c0x1F",
};


// condition codes for branches
static const char *const ccode_b[] =
{
  "",   "eq", "ne", "pl",
  "mi", "lo", "hs", "vs",
  "vc", "gt", "ge", "lt",
  "le", "hi", "ls", "pnz",
  "ss", "sc", "c0x12", "c0x13",
  "c0x14", "c0x15", "c0x16", "c0x17",
  "c0x18", "c0x19", "c0x1A", "c0x1B",
  "c0x1C", "c0x1D", "c0x1E", "c0x1F",
};

// condition codes for ARCv2 branches
static const char *const ccode_b_v2[] =
{
  "",   "eq", "ne", "p",
  "n",  "lo", "hs", "v",
  "nv", "gt", "ge", "lt",
  "le", "hi", "ls", "pnz",
  "c0x10", "c0x11", "c0x12", "c0x13",
  "c0x14", "c0x15", "c0x16", "c0x17",
  "c0x18", "c0x19", "c0x1A", "c0x1B",
  "c0x1C", "c0x1D", "c0x1E", "c0x1F",
};


/* jump delay slot codes */
static const char ncode[][4] = { "", ".d", ".jd", ".d?" };

//----------------------------------------------------------------------
class out_arc_t : public outctx_t
{
  out_arc_t(void) = delete; // not used
  void set_gr_cmt(const char *cmt) { user_data = (void *)cmt; }
  const char *get_gr_cmt(void) const { return (const char *)user_data; }
public:
  void outreg(int rn);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
  void out_specreg(const ioports_t &table, const op_t &x);
  void out_aux(const op_t &x)
  {
    arc_t &pm = *static_cast<arc_t *>(procmod);
    out_specreg(pm.auxregs, x);
  }
};
CASSERT(sizeof(out_arc_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_arc_t)

//----------------------------------------------------------------------
void out_arc_t::outreg(int rn)
{
  const char *regname = (rn < ph.regs_num) ? ph.reg_names[rn] : "<bad register>";
  out_register(regname);
}

//----------------------------------------------------------------------
void out_arc_t::out_specreg(const ioports_t &table, const op_t &x)
{
  const ioport_t *reg = find_ioport(table, x.value);
  if ( reg == nullptr )
  {
    out_symbol('[');
    out_value(x, OOFS_IFSIGN | OOFW_32);
    out_symbol(']');
  }
  else
  {
    out_register(reg->name.c_str());
    if ( !reg->cmt.empty() && !has_cmt(F) )
      set_gr_cmt(reg->cmt.c_str());
  }
}

//----------------------------------------------------------------------
/* outputs an operand 'x' */
bool out_arc_t::out_operand(const op_t & x)
{
  arc_t &pm = *static_cast<arc_t *>(procmod);
  ea_t v;
  switch ( x.type )
  {
    case o_reg:
      outreg(x.reg);
      break;

    case o_phrase:
      {
        int hidden_base = is_hidden_base_reg(x.reg);
        if ( hidden_base != -1 )
          out_symbol('[');
        if ( hidden_base == 0 )
        {
          outreg(x.reg);
          out_symbol(',');
        }
        outreg(x.secreg);
        if ( hidden_base != -1 )
          out_symbol(']');
      }
      break;

    case o_imm:
      // check for: LR <dest>, [aux]
      //            SR <src>, [aux]
      if ( x.n == 1
        && !is_defarg(F, x.n)      // don't use aux register if op type is set
        && (insn.itype == ARC_lr || insn.itype == ARC_sr) )
        out_aux(x);
      else
        out_value(x, OOFS_IFSIGN | OOFW_IMM);
      break;

    case o_mem:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        if ( (insn.auxpref & aux_pcload) != 0 )
        {
          // A little hack to make the output
          // more readable...
          op_t y;
          if ( pm.copy_insn_optype(insn, x, ea, &y.value) )
          {
            y.dtype = x.dtype;
            y.flags = OF_SHOW;
            out_symbol('=');
            set_dlbind_opnd();
            ea_t insn_ea_sav = insn_ea;
            flags64_t savedF = F;
            insn_ea = ea;    // change context
            F = get_flags(ea);
            out_value(y, OOFS_IFSIGN|OOFW_IMM);
            insn_ea = insn_ea_sav;    // restore context
            F = savedF;
            break;
          }
        }
        out_symbol('[');
        if ( insn.itype != ARC_lr && insn.itype != ARC_sr )
        {
          if ( !out_name_expr(x, ea, x.addr) )
          {
            out_tagon(COLOR_ERROR);
            out_btoa(uint32(x.addr), 16);
            out_tagoff(COLOR_ERROR);
            remember_problem(PR_NONAME, insn.ea);
          }
        }
        else
        {
          out_btoa(uint32(x.addr), 16);
        }
        if ( x.immdisp != 0 )
        {
          out_symbol('-');
          out_btoa(uint32(x.immdisp * get_scale_factor(insn)), 16);
          out_symbol(',');
          out_btoa(uint32(x.immdisp), 16);
        }
        out_symbol(']');
      }
      break;

    case o_near:
      v = to_ea(insn.cs, x.addr);
      if ( !out_name_expr(x, v, x.addr) )
      {
        out_value(x, OOF_ADDR|OOF_NUMBER|OOFS_NOSIGN|OOFW_32);
        remember_problem(PR_NONAME, insn.ea);
        break;
      }
      break;

    case o_displ:
      {
        // membase=0: [reg, #addr]
        // membase=1: [#addr, reg]
        int hidden_base = is_hidden_base_reg(x.reg);
        if ( hidden_base != -1 )
          out_symbol('[');
        if ( x.membase == 0 && hidden_base == 0 )
          outreg(x.reg);
        if ( x.addr != 0
          || hidden_base != 0
          || is_off(F, x.n)
          || is_stkvar(F, x.n)
          || is_enum(F, x.n)
          || is_stroff(F, x.n) )
        {
          if ( x.membase == 0 && hidden_base == 0 )
            out_symbol(',');
          out_value(x, OOF_ADDR|OOFS_IFSIGN|OOF_SIGNED|OOFW_32);
          if ( x.membase != 0 )
            out_symbol(',');
        }
        if ( x.membase != 0 )
          outreg(x.reg);
        if ( hidden_base != -1 )
          out_symbol(']');
      }
      break;

    case o_reglist:
      {
        out_symbol('{');
        bool need_comma = false;
        int regs = x.reglist & REGLIST_REGS;
        if ( regs > REGLISTR_MAX )
        {
          out_tagon(COLOR_ERROR);
          out_btoa(regs, 16);
          out_tagoff(COLOR_ERROR);
          need_comma = true;
        }
        else if ( regs > 0 )
        {
          outreg(R13);
          if ( regs > 1 )
          {
            out_symbol('-');
            outreg(R13 + regs - 1);
          }
          need_comma = true;
        }
        if ( (x.reglist & REGLIST_FP) != 0 )
        {
          if ( need_comma )
            out_symbol(',');
          outreg(FP);
          need_comma = true;
        }
        if ( (x.reglist & REGLIST_BLINK) != 0 )
        {
          if ( need_comma )
            out_symbol(',');
          outreg(BLINK);
          need_comma = true;
        }
        if ( (x.reglist & REGLIST_PCL) != 0 )
        {
          if ( need_comma )
            out_symbol(',');
          outreg(PCL);
          need_comma = true;
        }
        out_symbol('}');
      }
      break;

    default:
      out_symbol('?');
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
inline bool is_branch(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case ARC_b:
    case ARC_lp:
    case ARC_bl:
    case ARC_j:
    case ARC_jl:
    case ARC_br:
    case ARC_bbit0:
    case ARC_bbit1:
      return true;
  }
#ifndef NDEBUG
  // delay slot bits must be only set for branches
  QASSERT(10184, !has_dslot(insn));
#endif
  return false;
}

//----------------------------------------------------------------------
void out_arc_t::out_proc_mnem(void)
{
  arc_t &pm = *static_cast<arc_t *>(procmod);
  char postfix[MAXSTR];
  postfix[0] = '\0';
  if ( insn.itype == ARC_null )
  {
    uint32 code = get_dword(insn.ea);

    int i = (code>>27)&31;
    if ( i == 3 )
    {
      int c = (code>>9)&63;
      qsnprintf(postfix, sizeof(postfix), "ext%02X_%02X", i, c);
    }
    else
    {
      qsnprintf(postfix, sizeof(postfix), "ext%02X", i);
    }
  }

  /* if we have a load or store instruction, flags are used a bit different */
  if ( insn.itype <= ARC_store_instructions )
  {
    switch ( insn.auxpref & aux_zmask )
    {
      case 0:
        break;
      case aux_b:
        qstrncat(postfix, "b", sizeof(postfix));
        break;
      case aux_w:
        qstrncat(postfix, pm.is_arcv2() ? "h" : "w", sizeof(postfix));
        break;
      default:
        qstrncat(postfix, "?", sizeof(postfix));
        break;
    }
    if ( (insn.auxpref & aux_s) != 0 )
      qstrncat(postfix, "_s", sizeof(postfix));
    if ( insn.auxpref & aux_x )
      qstrncat(postfix, ".x", sizeof(postfix));
    switch ( insn.auxpref & aux_amask )
    {
      case 0:
        break;
      case aux_a:
        qstrncat(postfix, ".a", sizeof(postfix));
        break;
      case aux_as:
        qstrncat(postfix, ".as", sizeof(postfix));
        break;
      case aux_ab:
        qstrncat(postfix, ".ab", sizeof(postfix));
        break;
      default:
        qstrncat(postfix, "?", sizeof(postfix));
        break;
    }
    if ( insn.auxpref & aux_di )
      qstrncat(postfix, ".di", sizeof(postfix));
  }
  else
  {
    uint8 cond = insn.auxpref & aux_cmask;
    if ( cond != cAL && is_branch(insn) )
    {
      if ( pm.is_arcv2() )
        qstrncat(postfix, ccode_b_v2[cond], sizeof(postfix));
      else
        qstrncat(postfix, ccode_b[cond], sizeof(postfix));
    }

    if ( (insn.auxpref & aux_s) != 0 )
      qstrncat(postfix, "_s", sizeof(postfix));

    if ( cond != cAL && !is_branch(insn) )
    {
      if ( pm.is_arcv2() )
        qstrncat(postfix, ccode_v2[cond], sizeof(postfix));
      else
        qstrncat(postfix, ccode[cond], sizeof(postfix));
    }
  }
  if ( is_branch(insn) )  // delay slot code
  {
    qstrncat(postfix, ncode[(insn.auxpref >> 5) & 3], sizeof(postfix));
  }
  else if ( (insn.auxpref & aux_f) != 0 )
  {
    // for these load/store like instructions, the f bit is used for the .di
    if ( insn.itype == ARC_ex
      || insn.itype == ARC_llock
      || insn.itype == ARC_scond )
    {
      qstrncat(postfix, ".di", sizeof(postfix));
    }
    else if ( insn.itype != ARC_flag     // flag implicitly sets this bit
           && insn.itype != ARC_rcmp )   // rcmp implicitly sets this bit
    {
      qstrncat(postfix, ".f", sizeof(postfix));
    }
  }

  if ( pm.is_arcv2() && ( insn.auxpref & aux_bhint ) != 0 )
  {
    // print static prediction hint
    /*
      from "Assembler Syntax for Static Branch Predictions"
      The default static prediction, in the absence of any <.T> syntax, is always BTFN (Backwards Taken, Forwards Not Taken).
      Therefore, a BRcc instruction always has the Y bit set to 0 by default, whereas a BBITn instruction always has the Y bit set to 1
      by default.
    */
    bool backwards = insn.Op3.addr <= insn.ea;
    const char *suf = nullptr;
    if ( insn.itype == ARC_br )
      suf = backwards ? ".t" : ".nt";
    else
      suf = backwards ? ".nt" : ".t";
    qstrncat(postfix, suf, sizeof(postfix));
  }

  out_mnem(8, postfix);    // output instruction mnemonics
}

//----------------------------------------------------------------------
void out_arc_t::out_insn(void)
{
  arc_t &pm = *static_cast<arc_t *>(procmod);
  out_mnemonic();
  if ( insn.Op1.type != o_void )
    out_one_operand(0);   // output the first operand

  for ( int i = 1; i < PROC_MAXOP; ++i )
  {
    if ( insn.ops[i].type != o_void )
    {
      if ( !(insn.ops[i].type == o_reg && insn.ops[i].regpair) )
      {
        out_symbol(',');
        out_char(' ');
      }
      out_one_operand(i);   // output the current operand
    }
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();

  // add comments for indirect calls or calculated data xrefs
  nodeidx_t callee = pm.get_callee(insn.ea);
  if ( callee == BADADDR )
    callee = pm.get_dxref(insn.ea);
  if ( callee != BADADDR )
    set_comment_addr(callee & ~1);
  const char *gr_cmt = get_gr_cmt();
  if ( gr_cmt != nullptr )
  {
    out_char(' ');
    out_line(ash.cmnt, COLOR_AUTOCMT);
    out_char(' ');

    out_line(gr_cmt, COLOR_AUTOCMT);
    if ( ash.cmnt2 != nullptr )
    {
      out_char(' ');
      out_line(ash.cmnt2, COLOR_AUTOCMT);
    }
  }
  flush_outbuf();
}

//--------------------------------------------------------------------------
// generate start of the disassembly

void idaapi arc_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// generate start of a segment
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void arc_t::arc_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring name;
  get_visible_segm_name(&name, Sarea);
  ctx.gen_printf(0, COLSTR(".section %s", SCOLOR_ASMDIR), name.c_str());
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    adiff_t org = ctx.insn_ea - get_segm_base(Sarea);

    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];

      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(0, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
// generate end of the disassembly
void idaapi arc_footer(outctx_t &ctx)
{
  ctx.gen_empty_line();

  ctx.out_line(".end", COLOR_ASMDIR);

  qstring name;
  if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
  {
    ctx.out_line(" #");
    ctx.out_line(name.begin());
  }
  ctx.flush_outbuf(DEFAULT_INDENT);
}
