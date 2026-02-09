/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

//----------------------------------------------------------------------

// Mnemonics translations for 8x6x processtor types
static const std::unordered_map<uint16, const char *const> mnemonics_8x6x =
{
  { I196_skip,  "skp"  },
  { I196_clr,   "clrw" },
  { I196_not,   "cplw" },
  { I196_neg,   "negw" },
  { I196_dec,   "decw" },
  { I196_ext,   "sexw" },
  { I196_inc,   "incw" },
  { I196_shr,   "shrw" },
  { I196_shl,   "shlw" },
  { I196_shra,  "asrw" },
  { I196_shrl,  "shrdw" },
  { I196_shll,  "shldw" },
  { I196_shral, "asrdw" },
  { I196_norml, "norm" },
  { I196_notb,  "cplb" },
  { I196_extb,  "sexb" },
  { I196_shrab, "asrb" },
  { I196_jbc,   "jnb"  },
  { I196_jbs,   "jb"   },
  { I196_and3,   "an3w" },
  { I196_add3,   "ad3w" },
  { I196_sub3,   "sb3w" },
  { I196_mul3,  "sml3w" },
  { I196_mulu3,  "ml3w" },
  { I196_andb3,  "an3b" },
  { I196_addb3,  "ad3b" },
  { I196_subb3,  "sb3b" },
  { I196_mulb3, "sml3b" },
  { I196_mulub3, "ml3b" },
  { I196_and2,  "an2w" },
  { I196_add2,  "ad2w" },
  { I196_sub2,  "sb2w" },
  { I196_mul2, "sml2w" },
  { I196_mulu2, "ml2w" },
  { I196_andb2, "an2b" },
  { I196_addb2, "ad2b" },
  { I196_subb2, "sb2b" },
  { I196_mulb2, "sml2b" },
  { I196_mulub2, "ml2b" },
  { I196_or,    "orrw" },
  { I196_xor,   "xrw"  },
  { I196_cmp,   "cmpw" },
  { I196_divu,  "divw" },
  { I196_div,  "sdivw" },
  { I196_orb,   "orrb" },
  { I196_xorb,  "xrb"  },
  { I196_divub, "divb" },
  { I196_divb, "sdivb" },
  { I196_ld,    "ldw" },
  { I196_addc,   "adcw"  },
  { I196_subc,   "sbbw" },
  { I196_ldbze,  "ldzbw" },
  { I196_addcb,    "adcb" },
  { I196_subcb,   "sbbb"  },
  { I196_ldbse,   "ldsbw" },
  { I196_st,  "stw" },
  { I196_push,   "pushw" },
  { I196_pop,  "popw" },
  { I196_jnh,   "jleu" },
  { I196_jh,  "jgtu" },
  { I196_ljmp,  "jump" },
  { I196_lcall,  "call" },
  { I196_pushf,   "pushp" },
  { I196_popf,  "popp" },
  { I196_setc,  "stc" }
};


//----------------------------------------------------------------------
class out_i196_t : public outctx_t
{
  out_i196_t(void) = delete; // not used
public:

  bool out_operand(const op_t &x);
  void out_insn(bool use_alternative_mnem);

private:
  void out_mnem_alternative(uint16 inst, bool use_alternative_mnem);
};
CASSERT(sizeof(out_i196_t) == sizeof(outctx_t));

//--------------------------------------------------------------------------
void idaapi out_insn(outctx_t &ctx, bool use_alternative_mnem)
{
  out_i196_t *p = (out_i196_t *)&ctx;
  p->out_insn(use_alternative_mnem);
}

//--------------------------------------------------------------------------
bool idaapi out_opnd(outctx_t &ctx, const op_t &x)
{
  out_i196_t *p = (out_i196_t *)&ctx;
  return p->out_operand(x);
}

//--------------------------------------------------------------------------
void idaapi i196_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_PROC_AND_ASM);
}

//--------------------------------------------------------------------------
void idaapi i196_footer(outctx_t &ctx)
{
  ctx.gen_cmt_line("end of file");
}

//--------------------------------------------------------------------------
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void i196_t::i196_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring name;
  get_visible_segm_name(&name, Sarea);
  ctx.gen_cmt_line(COLSTR("segment %s", SCOLOR_AUTOCMT), name.c_str());

  ea_t org = ctx.insn_ea - get_segm_base(Sarea);
  if ( org != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), org);
    ctx.gen_cmt_line("%s %s", ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
//lint -esym(818, seg) could be made const
void idaapi i196_segend(outctx_t &ctx, segment_t *seg)
{
  qstring name;
  get_visible_segm_name(&name, seg);
  ctx.gen_cmt_line("end of '%s'", name.c_str());
}

//----------------------------------------------------------------------
void out_i196_t::out_mnem_alternative(uint16 inst, bool use_alternative_mnem)
{
  if ( use_alternative_mnem )
  {
    // 8x6x processors use different mnemonics for some instructions
    auto it = mnemonics_8x6x.find(inst);
    if ( it != mnemonics_8x6x.end() )
    {
      out_custom_mnem(it->second);
      return;
    }
  }

  out_mnemonic();
}

//----------------------------------------------------------------------
void out_i196_t::out_insn(bool use_alternative_mnem)
{
  out_mnem_alternative(insn.itype, use_alternative_mnem);

  out_one_operand(0);

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//----------------------------------------------------------------------
static bool is_ext_insn(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case I196_ebmovi:      // Extended interruptable block move
    case I196_ebr:         // Extended branch indirect
    case I196_ecall:       // Extended call
    case I196_ejmp:        // Extended jump
    case I196_eld:         // Extended load word
    case I196_eldb:        // Extended load byte
    case I196_est:         // Extended store word
    case I196_estb:        // Extended store byte
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool out_i196_t::out_operand(const op_t &x)
{
  uval_t v, v1;
//  const char *ptr;

  switch ( x.type )
  {
    case o_imm:
      out_symbol('#');
      out_value(x, OOF_SIGNED | OOFW_IMM);
      break;

    case o_indexed:
      out_value(x, OOF_ADDR|OOF_SIGNED|(is_ext_insn(insn) ? OOFW_32 : OOFW_16)); //.addr
      v = x.value;
      out_symbol('[');
      if ( v != 0 )
        goto OUTPHRASE;
      out_symbol(']');
      break;

    case o_indirect:
    case o_indirect_inc:
      out_symbol('[');
      [[fallthrough]];

    case o_mem:
    case o_near:
      v = x.addr;
OUTPHRASE:
      v1 = to_ea(get_sreg(insn.ea, (x.type == o_near) ? rVcs : rVds), v);
      if ( !out_name_expr(x, v1, v ) )
      {
        out_value(x, (x.type == o_indexed ? 0 : OOF_ADDR)
                   | OOF_NUMBER|OOFS_NOSIGN
                   | (x.type == o_near
                    ? (is_ext_insn(insn) ? OOFW_32 : OOFW_16)
                    : OOFW_8));
        remember_problem(PR_NONAME, insn.ea);
      }

      if ( x.type == o_indirect
        || x.type == o_indirect_inc
        || x.type == o_indexed )
      {
        out_symbol(']');
        if ( x.type == o_indirect_inc )
          out_symbol('+');
      }
      break;

    case o_void:
      return 0;

    case o_bit:
      out_symbol(char('0' + x.reg));
      break;

    default:
      warning("out: %a: bad optype %d", insn.ea, x.type);
  }

  return 1;
}
