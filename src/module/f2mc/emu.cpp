/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "f2mc.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//------------------------------------------------------------------------
static int get_reglist_size(ushort reglist)
{
  int size = 0;
  for ( int i = 0; i < 8; i++ )
    if ( (reglist >> i) & 1 )
      size++;
  return size;
}

//------------------------------------------------------------------------
static bool is_bank(const op_t &op)
{
  if ( op.type != o_reg )
    return false;

  return op.reg == DTB
      || op.reg == ADB
      || op.reg == SSB
      || op.reg == USB
      || op.reg == DPR
      || op.reg == PCB;
}

//----------------------------------------------------------------------
static void process_imm(const insn_t &insn, const op_t &x)
{
  set_immd(insn.ea);

  if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
    insn.add_off_drefs(x, dr_O, calc_outf(x));

  if ( is_defarg(get_flags(insn.ea), x.n) )
    return; // if already defined by user

  switch ( insn.itype )
  {
    case F2MC_add:
    case F2MC_addl:
    case F2MC_addsp:
    case F2MC_addw2:
    case F2MC_and:
    case F2MC_andw2:
    case F2MC_callv:
    case F2MC_cbne:
    case F2MC_cmp2:
    case F2MC_cmpl:
    case F2MC_cmpw2:
    case F2MC_cwbne:
    case F2MC_int:
    case F2MC_link:
    case F2MC_mov:
    case F2MC_movl:
    case F2MC_movn:
    case F2MC_movw:
    case F2MC_movx:
    case F2MC_or:
    case F2MC_orw2:
    case F2MC_sub:
    case F2MC_subl:
    case F2MC_subw2:
    case F2MC_xor:
    case F2MC_xorw2:
      op_num(insn.ea, x.n);
  }
}

//----------------------------------------------------------------------
void f2mc_t::handle_operand(const insn_t &insn, const op_t &x, bool use)
{
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
    case o_reglist:
      return;

    case o_near:
    case o_far:
      {
        cref_t ftype = fl_JN;
        ea_t ea = x.addr;
        // 24-bit (far) operands store the full address.
        // so this calculation is needed only for near jumps/calls
        if ( x.type == o_near )
          ea = calc_code_mem(insn, x.addr);

        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      break;

    case o_imm:
      QASSERT(10102, use);
      process_imm(insn, x);
      break;

    case o_mem:
      {
        ea_t ea = calc_data_mem(x.addr);
        insn.add_dref(ea, x.offb, use ? dr_R : dr_W);
        insn.create_op_data(ea, x);
      }
      break;
    case o_displ:
      process_imm(insn, x);
      if ( may_create_stkvars() && x.reg == RW3 )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr
          && (pfn->flags & FUNC_FRAME) != 0
          && insn.create_stkvar(x, x.addr, STKVAR_VALID_SIZE) )
        {
          op_stkvar(insn.ea, x.n);
        }
      }
      break;

    default:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
  }
}

//----------------------------------------------------------------------
inline bool add_stkpnt(func_t *pfn, sval_t delta, const insn_t &insn)
{
  return add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(const insn_t &insn)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return;

  switch ( insn.itype )
  {
    case F2MC_int:
    case F2MC_intp:
    case F2MC_int9:
      add_stkpnt(pfn, -6*2, insn);
      break;
    case F2MC_reti:
      add_stkpnt(pfn, 6*2, insn);
      break;
    case F2MC_link:
      add_stkpnt(pfn, -2-insn.Op1.value, insn);
      break;
    case F2MC_unlink:
      add_stkpnt(pfn, -get_spd(pfn, insn.ea), insn);
      break;
    case F2MC_ret:
      add_stkpnt(pfn, 2, insn);
      break;
    case F2MC_retp:
      add_stkpnt(pfn, 2*2, insn);
      break;
    case F2MC_pushw:
      if ( insn.Op1.type == o_reglist )
        add_stkpnt(pfn, -get_reglist_size(insn.Op1.reg)*2, insn);
      else
        add_stkpnt(pfn, -2, insn);
      break;
    case F2MC_popw:
      if ( insn.Op1.type == o_reglist )
        add_stkpnt(pfn, get_reglist_size(insn.Op1.reg)*2, insn);
      else
        add_stkpnt(pfn, 2, insn);
      break;
    case F2MC_addsp:
      add_stkpnt(pfn, insn.Op1.value, insn);
      break;
  }
}

//----------------------------------------------------------------------

int f2mc_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = (feature & CF_STOP) == 0;

  if ( feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( feature & CF_USE2 ) handle_operand(insn, insn.Op2, true);
  if ( feature & CF_USE3 ) handle_operand(insn, insn.Op3, true);

  if ( feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);
  if ( feature & CF_CHG2 ) handle_operand(insn, insn.Op2, false);
  if ( feature & CF_CHG3 ) handle_operand(insn, insn.Op3, false);

  // check for CCR changes
  if ( insn.Op1.type == o_reg && insn.Op1.reg == CCR )
  {
    op_bin(insn.ea, 1);

    sel_t ccr = get_sreg(insn.ea, CCR);
    if ( ccr == BADSEL )
      ccr = 0;

    if ( insn.itype == F2MC_and )
      ccr &= insn.Op2.value;     // and ccr,imm8
    else if ( insn.itype == F2MC_or )
      ccr |= insn.Op2.value; // or  ccr,imm8
    split_sreg_range(get_item_end(insn.ea), CCR, ccr, SR_auto);
  }


  // check for DTB,ADB,SSB,USB,DPR changes
  if ( insn.itype == F2MC_mov && is_bank(insn.Op1)
    && insn.Op2.type == o_reg && insn.Op2.reg == A ) // mov dtb|adb|ssb|usb|dpr,a
  {
    sel_t bank = BADSEL;
    insn_t l;
    if ( decode_prev_insn(&l, insn.ea) != BADADDR && l.itype == F2MC_mov
      && l.Op1.type == o_reg && l.Op1.reg == A )
    {
      if ( l.Op2.type == o_imm ) // mov a,imm8
        bank = l.Op2.value;
      else if ( is_bank(l.Op2) ) // mov a,dtb|adb|ssb|usb|dpr|pcb
      {
        bank = get_sreg(l.ea, l.Op2.reg);
        if ( bank == BADSEL )
          bank = 0;
      }
    }
    if ( bank != BADSEL )
      split_sreg_range(get_item_end(insn.ea), insn.Op1.reg, bank, SR_auto);
  }


  // determine if the next instruction should be executed
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(insn.ea);     // recalculate SP register for the next insn
    else
      trace_sp(insn);
  }

  return 1;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->start_ea;
      if ( ea + 4 < pfn->end_ea ) // minimum 2+1+1 bytes needed
      {
        insn_t insn;
        decode_insn(&insn, ea);
        if ( insn.itype == F2MC_link )
        {
          size_t localsize = (size_t)insn.Op1.value;
          ushort regsize   = 2;
          decode_insn(&insn, ea + 2);
          pfn->flags |= FUNC_FRAME;
          return add_frame(pfn, localsize, regsize, 0);
        }
      }
    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &)
{
  return OP_SP_ADD | OP_FP_BASED;
}
