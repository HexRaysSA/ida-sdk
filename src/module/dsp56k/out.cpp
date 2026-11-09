
#include "dsp56k.hpp"

// simple wrapper class for syntactic sugar of member functions
// this class may have only simple member functions.
// virtual functions and data fields are forbidden, otherwise the class
// layout may change
class out_dsp56k_t : public outctx_t
{
  out_dsp56k_t(void) = delete; // not used
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
  void outreg(int r) { out_register(ph.reg_names[r]); }
  bool out_port_address(ea_t addr);
  void out_bad_address(ea_t addr);
  void out_ip_rel(int displ);
  void out_operand_group(int idx, const op_t *x);
};
CASSERT(sizeof(out_dsp56k_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_dsp56k_t)

//--------------------------------------------------------------------------
static const char *const cc_text[] =
{
  "cc", // carry clear (higher or same) C=0
  "ge", // greater than or equal N & V=0
  "ne", // not equal Z=0
  "pl", // plus N=0
  "nn", // not normalized Z+(U.E)=0
  "ec", // extension clear E=0
  "lc", // limit clear L=0
  "gt", // greater than Z+(N & V)=0
  "cs", // carry set (lower) C=1
  "lt", // less than N & V=1
  "eq", // equal Z=1
  "mi", // minus N=1
  "nr", // normalized Z+(U.E)=1
  "es", // extension set E=1
  "ls", // limit set L=1
  "le", // less than or equal Z+(N & V)=1
};

//--------------------------------------------------------------------------
static const char *const su_text[] =
{
  "ss", // signed * signed
  "su", // signed * unsigned
  "uu", // unsigned * unsigned
};

static const char *const formats[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("+", SCOLOR_SYMBOL) COLSTR("n%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  "internal error with o_phrase",
  COLSTR("-(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("$+", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("a1", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("b1", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
};
// 0 (Rn)-Nn
// 1 (Rn)+Nn
// 2 (Rn)-
// 3 (Rn)+
// 4 (Rn)
// 5 (Rn+Nn)
// 7 -(Rn)
// 8 $+Rn
// 9 (a1)
// 10 (b1)


static const char *const formats2[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("+", SCOLOR_SYMBOL) COLSTR("$%X", SCOLOR_NUMBER) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR("-", SCOLOR_SYMBOL) COLSTR("$%X", SCOLOR_NUMBER) COLSTR(")", SCOLOR_SYMBOL),
};


//----------------------------------------------------------------------
bool out_dsp56k_t::out_port_address(ea_t addr)
{
  dsp56k_t &pm = *static_cast<dsp56k_t *>(procmod);
  const ioport_t *port = pm.find_port(addr);
  if ( port != nullptr && !port->name.empty() )
  {
    out_line(port->name.c_str(), COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
void out_dsp56k_t::out_bad_address(ea_t addr)
{
  if ( !out_port_address(addr) )
  {
    out_tagon(COLOR_ERROR);
    out_btoa(addr, 16);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }
}

//----------------------------------------------------------------------
void out_dsp56k_t::out_ip_rel(int displ)
{
  out_printf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
               ash.a_curip, displ);
}

//----------------------------------------------------------------------
bool out_dsp56k_t::out_operand(const op_t &x)
{
  dsp56k_t &pm = *static_cast<dsp56k_t *>(procmod);
  if ( x.type == o_imm )
  {
    out_symbol('#');
  }
  else
  {
    if ( x.amode & amode_x )
    {
      out_register("x");
      out_symbol(':');
    }
    if ( x.amode & amode_y )
    {
      out_register("y");
      out_symbol(':');
    }
    if ( x.amode & amode_p )
    {
      out_register("p");
      out_symbol(':');
    }
    if ( x.amode & amode_l )
    {
      out_register("l");
      out_symbol(':');
    }
  }
  if ( x.amode & amode_ioshort )
  {
    out_symbol('<');
    out_symbol('<');
  }
  if ( x.amode & amode_short )
    out_symbol('<');
  if ( x.amode & amode_long )
    out_symbol('>');
  if ( x.amode & amode_neg )
    out_symbol('-');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);
      break;

    case o_mem:
      // no break;
    case o_near:
      {
        ea_t ea = pm.calc_mem(insn, x);
        // xmem ioports
        if ( x.amode & (amode_x|amode_l) && out_port_address(x.addr) )
        {
          const ioport_t *port = pm.find_port(x.addr);
          if ( port != nullptr && !has_user_name(get_flags(ea)) )
            set_name(ea, port->name.c_str(), SN_NODUMMY);
          break;
        }
        if ( ea == insn.ea+insn.size )
          out_ip_rel(insn.size);
        else if ( !out_name_expr(x, ea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      {
        char buf[MAXSTR];
        nowarn_qsnprintf(buf, sizeof(buf), formats[uchar(x.phtype)], x.phrase, x.phrase);
        out_colored_register_line(buf);
      }
      break;

    case o_displ:
      {
        char buf[MAXSTR];
        nowarn_qsnprintf(buf, sizeof(buf), formats2[uchar(x.phtype)], x.phrase, x.addr);
        out_colored_register_line(buf);
      }
      break;

    case o_iftype:
      {
        char postfix[4];
        qstrncpy(postfix, cc_text[insn.auxpref & aux_cc], sizeof(postfix));
        if ( x.imode == imode_if )
          out_printf(COLSTR("IF%s", SCOLOR_SYMBOL), postfix);
        else
          out_printf(COLSTR("IF%s.U", SCOLOR_SYMBOL), postfix);
      }
      break;

    case o_vsltype:
      out_symbol((insn.auxpref & 1) + '0');
      break;

    default:
      interr(&insn, "out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_dsp56k_t::out_operand_group(int idx, const op_t *x)
{
  for ( int i=0; i < 2; i++,x++ )
  {
    if ( x->type == o_void )
      break;
    if ( i != 0 )
    {
      out_symbol(',');
    }
    else if ( insn.itype != DSP56_move || idx != 0 )
    {
      size_t n = 16;
      if ( idx == (insn.itype == DSP56_move) )
        n = tag_strlen(outbuf.c_str());
      do
        out_char(' ');
      while ( ++n < 20 );
    }
    out_operand(*x);
  }
}

//----------------------------------------------------------------------
void out_dsp56k_t::out_proc_mnem(void)
{
  // output instruction mnemonics
  char postfix[4];
  postfix[0] = '\0';
  switch ( insn.itype )
  {
    case DSP56_tcc:
    case DSP56_debugcc:
    case DSP56_jcc:
    case DSP56_jscc:
    case DSP56_bcc:
    case DSP56_bscc:
    case DSP56_trapcc:
      qstrncpy(postfix, cc_text[insn.auxpref & aux_cc], sizeof(postfix));
      break;

    case DSP56_dmac:
    case DSP56_mac_s_u:
    case DSP56_mpy_s_u:
      qstrncpy(postfix, su_text[insn.auxpref & aux_su], sizeof(postfix));
      break;
  }

  out_mnem(8, postfix);
}

//----------------------------------------------------------------------
void out_dsp56k_t::out_insn(void)
{
  dsp56k_t &pm = *static_cast<dsp56k_t *>(procmod);
  out_mnemonic();
  bool comma = out_one_operand(0);
  if ( insn.Op2.type != o_void )
  {
    if ( comma )
      out_symbol(',');
    out_one_operand(1);
  }
  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_one_operand(2);
  }

  pm.fill_additional_args(insn);
  for ( int i=0; i < pm.aa.nargs; i++ )
    out_operand_group(i, pm.aa.args[i]);

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
//lint -e{818} seg could be made const
void dsp56k_t::segstart(outctx_t &ctx, segment_t *seg) const
{
  if ( is_spec_segm(seg->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, seg);
  get_segm_class(&sclas, seg);

  if ( ash.uflag & UAS_GNU )
  {
    const char *predefined[] =
    {
      ".text",    // Text section
      ".data",    // Data sections
      ".rdata",
      ".comm",
    };
    if ( !print_predefined_segname(ctx, &sname, predefined, qnumber(predefined)) )
      ctx.gen_printf(DEFAULT_INDENT,
                     COLSTR(".section %s", SCOLOR_ASMDIR) " " COLSTR("%s %s", SCOLOR_AUTOCMT),
                     sname.c_str(),
                     ash.cmnt,
                     sclas.c_str());
  }
  else
  {
    validate_name(&sname, VNT_IDENT);
    if ( sname == "XMEM" || sname == "YMEM" )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), seg->start_ea-get_segm_base(seg));
      ctx.gen_printf(DEFAULT_INDENT,
                     COLSTR("%s %c:%s", SCOLOR_ASMDIR),
                     ash.origin,
                     qtolower(sname[0]),
                     buf);
    }
    else
    {
      ctx.gen_printf(DEFAULT_INDENT,
                     COLSTR("section %s", SCOLOR_ASMDIR) " " COLSTR("%s %s", SCOLOR_AUTOCMT),
                     sname.c_str(),
                     ash.cmnt,
                     sclas.c_str());
    }
  }
}

//--------------------------------------------------------------------------
//lint -e{818} seg could be made const
void dsp56k_t::segend(outctx_t &ctx, segment_t *seg) const
{
  if ( is_spec_segm(seg->type) )
    return;

  if ( (ash.uflag & UAS_GNU) == 0 )
  {
    qstring sname;
    get_segm_name(&sname, seg);
    if ( sname != "XMEM" && sname != "YMEM" )
      ctx.gen_printf(DEFAULT_INDENT, "endsec");
  }
}

//--------------------------------------------------------------------------
void dsp56k_t::header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL, nullptr, ioh.device.c_str());
}

//--------------------------------------------------------------------------
void dsp56k_t::footer(outctx_t &ctx) const
{
  qstring nbuf = get_colored_name(inf_get_start_ea());
  const char *name = nbuf.c_str();
  const char *end = ash.end;
  if ( end == nullptr )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name);
  else
    ctx.gen_printf(DEFAULT_INDENT,
                   COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
                   ash.end, ash.cmnt, name);
}
