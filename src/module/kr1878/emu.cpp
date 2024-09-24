
#include "kr1878.hpp"
#include <frame.hpp>
#include <segregs.hpp>

//----------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, const op_t &x)
{
  return to_ea(insn.cs, x.addr);
}

//------------------------------------------------------------------------
ea_t kr1878_t::calc_data_mem(const insn_t &insn, const op_t &x, ushort segreg) const
{
  sel_t dpage = get_sreg(insn.ea, segreg);
  if ( dpage == BADSEL )
    return BADSEL;
  return xmem + (((dpage & 0xFF) << 3) | (x.value));
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == DSP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &x)
{
  return OP_SP_ADD | (x.phrase == DSP ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea),n) )
    return;
  switch ( insn.itype )
  {

    case KR1878_movl:
    case KR1878_cmpl:     // Compare
    case KR1878_addl:     // Addition
    case KR1878_subl:     // Subtract
    case KR1878_bic:
    case KR1878_bis:
    case KR1878_btg:
    case KR1878_btt:
    case KR1878_ldr:
    case KR1878_sst:
    case KR1878_cst:

      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
void kr1878_t::add_near_ref(const insn_t &insn, const op_t &x, ea_t ea)
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
void kr1878_t::handle_operand(const insn_t &insn, const op_t &x, bool isAlt, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    default:
//      interr("emu");
      break;
    case o_imm:
      if ( !isload )
        interr(insn, "emu2");
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, OOFS_IFSIGN);
      break;
    case o_mem:
      if ( !isAlt )
      {
        ea_t ea = calc_mem(insn, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
      }
      break;
    case o_phrase:
      if ( !isAlt )
      {
        if ( x.reg != SR3 || x.value < 6 )
        {
          ea_t ea = calc_data_mem(insn, x, as + x.reg);
          insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
          insn.create_op_data(ea, x);
        }
      }
      break;
    case o_near:
      if ( !isAlt )
        add_near_ref(insn, x, calc_mem(insn, x));
      break;
  }
}

//----------------------------------------------------------------------
int kr1878_t::emu(const insn_t &insn)
{
  if ( segtype(insn.ea) == SEG_XTRN )
    return 1;

  uint32 Feature = insn.get_canon_feature(ph);
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, flag3, true);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, flag3, false);

// check for Segment changes
  if ( insn.itype == KR1878_ldr
    && insn.Op1.type == o_reg
    && insn.Op1.reg < SR4 )
  {
    split_sreg_range(get_item_end(insn.ea), as + insn.Op1.reg, insn.Op2.value & 0xFF, SR_auto);
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
int may_be_func(const insn_t &)           // can a function start here?
{
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(const insn_t &insn, int /*nocrefs*/)
{
  // disallow jumps to nowhere
  if ( insn.Op1.type == o_near && !is_mapped(calc_mem(insn, insn.Op1)) )
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
    case KR1878_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

