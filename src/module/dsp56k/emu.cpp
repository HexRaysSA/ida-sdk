
#include "dsp56k.hpp"
#include <frame.hpp>

//----------------------------------------------------------------------
ea_t dsp56k_t::calc_mem(const insn_t &insn, const op_t &x) const
{
  if ( x.amode & (amode_x|amode_l) )
    return xmem == BADADDR ? BADADDR : xmem+x.addr;
  if ( x.amode & amode_y )
    return ymem == BADADDR ? BADADDR : ymem+x.addr;
  return to_ea(insn.cs, x.addr);
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == SP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &x)
{
  return OP_SP_ADD | (x.phrase == SP ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, n) )
    return;
  switch ( insn.itype )
  {
//      case DSP56_asl:
//      case DSP56_asr:
    case DSP56_bchg:
    case DSP56_bclr:
    case DSP56_brclr:
    case DSP56_brset:
    case DSP56_bsclr:
    case DSP56_bset:
    case DSP56_bsset:
    case DSP56_btst:
    case DSP56_jclr:
    case DSP56_jset:
    case DSP56_jsclr:
    case DSP56_jsset:
//      case DSP56_lsl:
//      case DSP56_lsr:

      op_dec(insn.ea, n);
      break;


    case DSP56_add:
    case DSP56_and:
    case DSP56_andi:
    case DSP56_cmp:
    case DSP56_eor:
    case DSP56_extract:
    case DSP56_extractu:
    case DSP56_insert:
    case DSP56_mac:
    case DSP56_maci:
    case DSP56_macr:
    case DSP56_macri:
    case DSP56_mpy:
    case DSP56_mpyi:
    case DSP56_mpyr:
    case DSP56_mpyri:
    case DSP56_or:
    case DSP56_ori:
    case DSP56_sub:
    case DSP56_do:
    case DSP56_dor:
    case DSP56_rep:

      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
void dsp56k_t::add_near_ref(const insn_t &insn, const op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( has_insn_feature(insn.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  insn.add_cref(ea, x.offb, ftype);
}

//----------------------------------------------------------------------
void dsp56k_t::handle_operand(
        const insn_t &insn,
        const op_t &x,
        flags64_t F,
        bool is_forced,
        bool isload)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    default:
      break;
    case o_imm:
      process_immediate_number(insn, x.n, F);
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, OOFS_IFSIGN);
      break;
    case o_phrase:
      if ( !is_forced && op_adds_xrefs(F, x.n) )
      {
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, OOF_ADDR);
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(insn, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
        if ( x.amode & amode_l )
        {
          ea = ymem + x.addr;
          insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
          insn.create_op_data(ea, x);
        }
      }
      break;
    case o_near:
      add_near_ref(insn, x, calc_mem(insn, x));
      break;
  }
}

//----------------------------------------------------------------------
int dsp56k_t::emu(const insn_t &insn)
{
  if ( segtype(insn.ea) == SEG_XTRN )
    return 1;

  uint32 Feature = insn.get_canon_feature(ph);
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  flags64_t F = get_flags(insn.ea);
  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, F, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, F, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, F, flag3, true);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, F, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, F, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, F, flag3, false);

  insn_t copy = insn;
  fill_additional_args(copy);
  for ( int i=0; i < aa.nargs; i++ )
  {
    op_t *x = aa.args[i];
    for ( int j=0; j < 2; j++,x++ )
    {
      if ( x->type == o_void )
        break;
      handle_operand(insn, *x, F, 0, j == 0);
    }
  }

//
//      Determine if the next instruction should be executed
//
  if ( Feature & CF_STOP )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int dsp56k_t::is_sane_insn(const insn_t &insn, int /*nocrefs*/) const
{
  // disallow jumps to nowhere
  if ( insn.Op1.type == o_near && !is_mapped(calc_mem(insn, insn.Op1)) )
    return 0;

  // disallow many nops in a now
  int i = 0;
  for ( ea_t ea=insn.ea; i < 32; i++,ea++ )
    if ( get_byte(ea) != 0 )
      break;
  if ( i == 32 )
    return 0;

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case DSP56_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

