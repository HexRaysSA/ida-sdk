
#include "oakdsp.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>

//--------------------------------------------------------------------------
static const char *const cc_text[] =
{
  "",          // Always
  "eq",        // Equal to zero Z = 1
  "neq",       // Not equal to zero Z = 0
  "gt",        // Greater than zero M = 0 and Z = 0
  "ge",        // Greater than or equal to zero M = 0
  "lt",        // Less than zero M =1
  "le",        // Less than or equal to zero M = 1 or Z = 1
  "nn",        // Normalized flag is cleared N = 0
  "v",         // Overflow flag is set V = 1
  "c",         // Carry flag is set C = 1
  "e",         // Extension flag is set E = 1
  "l",         // Limit flag is set L = 1
  "nr",        // flag is cleared R = 0
  "niu0",      // Input user pin 0 is cleared
  "iu0",       // Input user pin 0 is set
  "iu1",       // Input user pin 1 is set

};


static const char *const formats[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+1", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")-1", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("r%d", SCOLOR_REG) COLSTR(")+s", SCOLOR_SYMBOL),
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("reg", SCOLOR_REG) COLSTR(")", SCOLOR_SYMBOL),
};

// 0 (Rn)
// 1 (Rn)+1
// 2 (Rn)-1
// 3 (Rn)+s
// 4 (any_reg)

static const char *const formats2[] =
{
  COLSTR("(", SCOLOR_SYMBOL) COLSTR("rb+#", SCOLOR_REG),
  COLSTR("#", SCOLOR_REG),
};
// 0 (rb + #)
// 1 #

static const char *const swap_formats[] =
{
  COLSTR("(a0, b0)", SCOLOR_REG),
  COLSTR("(a0, b1)", SCOLOR_REG),
  COLSTR("(a1, b0)", SCOLOR_REG),
  COLSTR("(a1, b1)", SCOLOR_REG),
  COLSTR("(a0, b0), (a1, b1)", SCOLOR_REG),
  COLSTR("(a0, b1), (a1, b0)", SCOLOR_REG),
  COLSTR("(a0, b0, a1)", SCOLOR_REG),
  COLSTR("(a0, b1, a1)", SCOLOR_REG),
  COLSTR("(a1, b0, a0)", SCOLOR_REG),
  COLSTR("(a1, b1, a0)", SCOLOR_REG),
  COLSTR("(b0, a0, b1)", SCOLOR_REG),
  COLSTR("(b0, a1, b1)", SCOLOR_REG),
  COLSTR("(b1, a0, b0)", SCOLOR_REG),
  COLSTR("(b1, a1, b0)", SCOLOR_REG),
};

// (a0, b0)
// (a0, b1)
// (a1, b0)
// (a1, b1)
// (a0, b0), (a1, b1)
// (a0, b1), (a1, b0)
// (a0, b0, a1)
// (a0, b1, a1)
// (a1, b0, a0)
// (a1, b1, a0)
// (b0, a0, b1)
// (b0, a1, b1)
// (b1, a0, b0)
// (b1, a1, b0)

//----------------------------------------------------------------------
class out_oakdsp_t : public outctx_t
{
  out_oakdsp_t(void) = delete; // not used
  oakdsp_t &pm() { return *static_cast<oakdsp_t *>(procmod); }
public:
  void outreg(int r) { out_register(ph.reg_names[r]); }
  bool out_port_address(ea_t addr);
  void out_bad_address(ea_t addr);
  void out_address(ea_t ea, const op_t &x);
  void out_ip_rel(int displ)
  {
    out_printf(COLSTR("%s+", SCOLOR_SYMBOL) COLSTR("%d", SCOLOR_NUMBER),
               ash.a_curip, displ);
  }
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_oakdsp_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_oakdsp_t)

//----------------------------------------------------------------------
bool out_oakdsp_t::out_port_address(ea_t addr)
{
  const ioport_t *port = pm().find_port(addr);
  if ( port != nullptr && !port->name.empty() )
  {
    out_line(port->name.c_str(), COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
void out_oakdsp_t::out_bad_address(ea_t addr)
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
void out_oakdsp_t::out_address(ea_t ea, const op_t &x)
{
  if ( !out_name_expr(x, ea,/* ea */ BADADDR) )
  {
    out_tagon(COLOR_ERROR);
    out_value(x, OOF_ADDR|OOFW_16);
    out_printf(" (ea = %a)", ea);
    out_tagoff(COLOR_ERROR);
    remember_problem(PR_NONAME, insn.ea);
  }

}

//----------------------------------------------------------------------
bool out_oakdsp_t::out_operand(const op_t & x)
{
  ea_t ea;
  char buf[MAXSTR];

  if ( x.type == o_imm )
    out_symbol('#');

  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_imm:
      if ( x.amode & amode_signed )
        out_value(x, OOF_SIGNED|OOFW_IMM);
      else
        out_value(x, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_reg:
      outreg(x.reg);
      break;

    case o_mem:
      // no break;
      ea = pm().calc_mem(insn, x);
      if ( ea != BADADDR )
        out_address(ea, x);
      else
      {
        out_tagon(COLOR_ERROR);
        out_value(x, OOF_ADDR|OOFW_16);
        out_tagoff(COLOR_ERROR);
      }
      break;

    case o_near:
      {
        ea_t lea = pm().calc_mem(insn, x);
        // xmem ioports
        if ( x.amode & (amode_x) && out_port_address(x.addr) )
        {
          const ioport_t *port = pm().find_port(x.addr);
          if ( port != nullptr && !has_user_name(get_flags(lea)) )
            set_name(lea, port->name.c_str(), SN_NODUMMY);
          break;
        }
        if ( lea == insn.ea+insn.size )
          out_ip_rel(insn.size);
        else if ( !out_name_expr(x, lea, x.addr) )
          out_bad_address(x.addr);
      }
      break;

    case o_phrase:
      {
        if ( x.phtype < 4 )
        {
          nowarn_qsnprintf(buf, sizeof(buf), formats[uchar(x.phtype)], x.phrase);
          out_colored_register_line(buf);
        }
        if ( x.phtype == 4 )
        {
          out_symbol('(');
          outreg(x.reg);
          out_symbol(')');
        }
      }
      break;

    case o_local:
      {
        out_colored_register_line(formats2[uchar(x.phtype)]);
        out_value(x, OOF_SIGNED|OOF_ADDR|OOFW_16);
        if ( x.phtype == 0 )
          out_symbol(')');
        break;
      }

    case o_textphrase:
      {
        switch ( x.textphtype )
        {
          case text_swap:
            out_line(swap_formats[x.phrase], COLOR_REG);
            break;

          case text_banke:

            int comma;
            char r0[10], r1[10], r4[10], cfgi[10];
            comma = 0;


            r0[0]=r1[0]=r4[0]=cfgi[0]='\0';

            if ( x.phrase & 0x01 ) // cfgi
            {
              qsnprintf(cfgi, sizeof(cfgi), "cfgi");
              comma = 1;
            }

            if ( x.phrase & 0x02 ) // r4
            {
              qsnprintf(r4, sizeof(r4), "r4%s", (comma?", ":""));
              comma = 1;
            }

            if ( x.phrase & 0x04 ) // r1
            {
              qsnprintf(r1, sizeof(r1), "r1%s", (comma?", ":""));
              comma = 1;
            }

            if ( x.phrase & 0x08 ) // r0
              qsnprintf(r0, sizeof(r0), "r0%s", (comma?", ":""));

            qsnprintf(buf, sizeof(buf), "%s%s%s%s", r0, r1, r4, cfgi);
            out_line(buf, COLOR_REG);

            break;
          case text_cntx:
            out_symbol(x.phrase ? 'r': 's');
            break;
          case text_dmod:
            if ( x.phrase )
              qsnprintf(buf, sizeof(buf), " no modulo");
            else
              qsnprintf(buf, sizeof(buf), " modulo");

            out_line(buf, COLOR_REG);

            break;
          case text_eu:
            qsnprintf(buf, sizeof(buf), " eu");
            out_line(buf, COLOR_REG);
            break;
        }

      }
      break;


    default:
      interr(insn, "out");
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
void out_oakdsp_t::out_insn(void)
{
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
  out_immchar_cmts();

  switch ( insn.itype )
  {
    case OAK_Dsp_callr:
    case OAK_Dsp_ret:
    case OAK_Dsp_br:
    case OAK_Dsp_call:
    case OAK_Dsp_reti:
    case OAK_Dsp_brr:
    case OAK_Dsp_shfc:
    case OAK_Dsp_shr:
    case OAK_Dsp_shr4:
    case OAK_Dsp_shl:
    case OAK_Dsp_shl4:
    case OAK_Dsp_ror:
    case OAK_Dsp_rol:
    case OAK_Dsp_clr:
    case OAK_Dsp_not:
    case OAK_Dsp_neg:
    case OAK_Dsp_rnd:
    case OAK_Dsp_pacr:
    case OAK_Dsp_clrr:
    case OAK_Dsp_inc:
    case OAK_Dsp_dec:
    case OAK_Dsp_copy:
    case OAK_Dsp_maxd:
    case OAK_Dsp_max:
    case OAK_Dsp_min:
      char buf[MAXSTR];
      qsnprintf(buf,
                sizeof(buf),
                "%s%s%s",
                (insn.auxpref & aux_comma_cc) ? ", ": "",
                cc_text[insn.auxpref & aux_cc],
                (insn.auxpref & aux_iret_context) ? ", context": "");
      out_line(buf, COLOR_REG);
      break;
  }
  flush_outbuf();
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void oakdsp_t::oakdsp_segstart(outctx_t &ctx, segment_t *Srange) const
{
  ea_t ea = ctx.insn_ea;
  if ( is_spec_segm(Srange->type) )
    return;

  qstring sname;
  qstring sclas;
  get_segm_name(&sname, Srange);
  get_segm_class(&sclas, Srange);

  if ( ash.uflag & UAS_GNU )
  {
    const char *const predefined[] =
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
    if ( sname == "XMEM" )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), ea-get_segm_base(Srange));
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
void oakdsp_t::print_segment_register(outctx_t &ctx, int reg, sel_t value)
{
  if ( reg == ph.reg_data_sreg )
    return;
  if ( value != BADADDR )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), value);
    ctx.gen_cmt_line("assume %s = %s", ph.reg_names[reg], buf);
  }
  else
  {
    ctx.gen_cmt_line("drop %s", ph.reg_names[reg]);
  }
}

//--------------------------------------------------------------------------
// function to produce assume directives
void oakdsp_t::oakdsp_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *seg = getseg(ea);
  if ( seg == nullptr || (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 )
    return;
  bool seg_started = (ea == seg->start_ea);

  for ( int i = ph.reg_first_sreg; i <= ph.reg_last_sreg; ++i )
  {
    if ( i == ph.reg_code_sreg )
      continue;
    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) )
      continue;
    sel_t now = get_sreg(ea, i);
    if ( seg_started || sra.start_ea == ea )
    {
      sreg_range_t prev_sra;
      bool prev_exists = ea > 0 && get_sreg_range(&prev_sra, ea - 1, i);
      if ( seg_started || (prev_exists && get_sreg(prev_sra.start_ea, i) != now) )
        print_segment_register(ctx, i, now);
    }
  }
}

//--------------------------------------------------------------------------
void oakdsp_t::oakdsp_segend(outctx_t &ctx, segment_t *Srange) const
{
  if ( !is_spec_segm(Srange->type) && (ash.uflag & UAS_GNU) == 0 )
  {
    qstring sname;
    get_segm_name(&sname, Srange);
    if ( sname != "XMEM" )
      ctx.gen_printf(DEFAULT_INDENT, "endsec");
  }
}

//--------------------------------------------------------------------------
void oakdsp_t::oakdsp_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL, nullptr, ioh.device.c_str());
}

//--------------------------------------------------------------------------
void oakdsp_t::oakdsp_footer(outctx_t &ctx) const
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

//--------------------------------------------------------------------------
void oakdsp_t::gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const
{
  char sign = ' ';
  if ( v < 0 )
  {
    sign = '-';
    v = -v;
  }

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  ctx.out_printf(COLSTR("%s",SCOLOR_KEYWORD) " "
                 COLSTR("%c%s",SCOLOR_DNUM)
                 COLSTR(",",SCOLOR_SYMBOL) " "
                 COLSTR("%s",SCOLOR_LOCNAME),
                 ash.a_equ,
                 sign,
                 vstr,
                 stkvar->name.c_str());
}
