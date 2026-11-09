/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#include "i5.hpp"

//----------------------------------------------------------------------
class out_z80_t : public outctx_t
{
  out_z80_t(void) = delete; // not used
  z80_t &pm() { return *static_cast<z80_t *>(procmod); }

public:
  void OutReg(int rgnum);
  bool out_operand(const op_t &x);
  void out_insn(void);
};
CASSERT(sizeof(out_z80_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_z80_t)

//----------------------------------------------------------------------
static const char *const condNames[] =
{
  "nz",
  "z",
  "nc",
  "c",
  "po",
  "pe",
  "p",
  "m"
};

//----------------------------------------------------------------------
void out_z80_t::OutReg(int rgnum)
{
  if ( (ash.uflag & UAS_NPAIR) != 0 )
  {
    switch ( rgnum )
    {
      case R_bc: out_register(ph.reg_names[R_b]); return;
      case R_de: out_register(ph.reg_names[R_d]); return;
      case R_hl: out_register(ph.reg_names[R_h]); return;
    }
  }
  if ( rgnum == R_af && pm().isZ80() && !pm().isFunny() )
    out_register("af");
  else
    out_register(ph.reg_names[rgnum]);
}

//----------------------------------------------------------------------
bool out_z80_t::out_operand(const op_t &x)
{
  if ( !x.shown() )
    return false;
  switch ( x.type )
  {
    case o_cond:
      if ( x.Cond == oc_not )
        return false;
      {
        char buf[3];
        qstrncpy(buf, condNames[ x.Cond ], sizeof(buf));
        if ( ash.uflag & UAS_CNDUP )
          qstrupr(buf);
        out_keyword(buf);
      }
      break;

    case o_reg:
      OutReg(x.reg);
      break;

    case o_displ:         // Z80 only!!! + GB, one instruction
      if ( ash.uflag & UAS_MKOFF )
        out_value(x, OOF_ADDR|OOFW_16);
      if ( !pm().isGB() )
        out_symbol('(');
      OutReg(x.phrase);
      if ( !(ash.uflag & UAS_MKOFF) )
      {
        qstring buf;
        if ( is_off(F, x.n)
          && get_offset_expression(&buf, insn.ea,x.n,insn.ea+x.offb,x.addr) )
        {
          out_symbol('+');
          out_line(buf.c_str());
        }
        else
        {
          int offbit = (insn.auxpref & aux_off16) ? OOFW_16 : OOFW_8;
          int outf = OOF_ADDR|offbit|OOFS_NEEDSIGN;
          if ( ash.uflag & UAS_TOFF )
            outf |= OOF_SIGNED;
          out_value(x, outf);
        }
      }
      if ( !pm().isGB() )
        out_symbol(')');
      break;

    case o_phrase:
      if ( pm().isZ80() && !pm().isFunny() )
      {
        out_symbol((ash.uflag & UAS_GBASM) ? '[' : '(');
        OutReg(x.phrase);
        out_symbol((ash.uflag & UAS_GBASM) ? ']' : ')');
      }
      else
      {
        if ( x.phrase == R_hl )
          out_register("m");
        else
          OutReg(x.phrase);
      }
      break;

    case o_void:
      return 0;

    case o_imm:
      {
        const char *name = nullptr;
        bool needbrace = false;
        if ( pm().isZ80() )
        {
          switch ( insn.itype )
          {
            case I5_rst:
              if ( pm().isFunny() )
              {
                int radix = get_radix(F, x.n);
                out_long(x.value/8, radix);
                return 1;
              }
            case Z80_im:
            case Z80_bit:
            case Z80_res:
            case Z80_set:
//              name = pm().find_ioport_bit(x.value);
              break;
            case HD_in0:
            case HD_out0:
              name = pm().find_ioport(x.value);
              // fallthrough
            case I5_in:
            case I5_out:
            case Z80_outaw:
            case Z80_inaw:
              if ( !pm().isFunny() )
              {
                out_symbol('(');
                needbrace = true;
              }
              break;
            default:
              if ( ash.uflag & UAS_MKIMM )
                out_symbol('#');
              break;
          }
        }
        if ( name != nullptr )
          out_line(name, COLOR_IMPNAME);
        else
          out_value(x, 0);
        if ( needbrace )
          out_symbol(')');
      }
      break;

    case o_mem:
      if ( pm().isZ80() && !pm().isFunny() )
        out_symbol((ash.uflag & UAS_GBASM) ? '[' : '(');
      // no break
    case o_near:
      {
        ea_t v = map_ea(insn, x, x.type == o_near);
        if ( v == insn.ea && ash.a_curip != nullptr )
        {
          out_line(ash.a_curip);
        }
        else if ( !out_name_expr(x, v, x.addr) )
        {
          out_tagon(COLOR_ERROR);
          out_btoa(x.addr,16);
          out_tagoff(COLOR_ERROR);
          remember_problem(PR_NONAME,insn.ea);
        }
        if ( x.type == o_mem && pm().isZ80() && !pm().isFunny() )
          out_symbol((ash.uflag & UAS_GBASM) ? ']' : ')');
      }
      break;

    default:
      warning("bad optype %x", x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
static bool isIxyByte(const op_t &x)
{
  return x.type == o_reg
      && (x.reg == R_xl
       || x.reg == R_xh
       || x.reg == R_yl
       || x.reg == R_yh);
}

//----------------------------------------------------------------------
inline bool isIxyOperand(const op_t &x)
{
  return isIxyByte(x) || x.type == o_displ;
}

//----------------------------------------------------------------------
void out_z80_t::out_insn(void)
{
  out_mnemonic();

  bool comma = out_one_operand(0);

  if ( comma && insn.Op2.shown() && insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_symbol(' ');
  }

  out_one_operand(1);

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void z80_t::i5_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, ioh.device.c_str(), ioh.deviceparams.c_str());
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, segm) could be made const
void z80_t::i5_segstart(outctx_t &ctx, segment_t *segm)
{
  qstring sname;
  get_segm_name(&sname, segm);

  if ( ash.uflag & UAS_GBASM )
  {
    validate_name(&sname, VNT_IDENT);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("SECTION \"%s\", %s",SCOLOR_ASMDIR),
                   sname.c_str(),
                   segtype(ctx.insn_ea) == SEG_CODE ? "CODE" : "DATA");
  }
  else if ( ash.uflag & UAS_ZMASM )
  {
    const char *dir = "segment";
    if ( sname == ".text"
      || sname == ".data"
      || sname == ".bss" )
    {
      sname.clear();
      dir = sname.c_str();
    }
    else
    {
      validate_name(&sname, VNT_IDENT);
    }
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s",SCOLOR_ASMDIR), dir, sname.c_str());
  }
  else if ( ash.uflag & UAS_CSEGS )
  {
    validate_name(&sname, VNT_IDENT);
    ctx.gen_cmt_line("segment '%s'", sname.c_str());
    ctx.gen_printf(DEFAULT_INDENT,COLSTR("%cseg",SCOLOR_ASMDIR),segm->align == saAbs ? 'a' : 'c');
  }
  if ( (inf_get_outflags() & OFLG_GEN_ORG) != 0 )
  {
    ea_t org = ctx.insn_ea - get_segm_base(segm);
    if ( org != 0 )
    {
      char buf[MAX_NUMBUF];
      btoa(buf, sizeof(buf), org);
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
    }
  }
}

//--------------------------------------------------------------------------
void z80_t::i5_footer(outctx_t & ctx)
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      if ( ash.uflag & UAS_NOENS )
      {
        ctx.out_char(' ');
        ctx.out_line(ash.cmnt);
      }
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
