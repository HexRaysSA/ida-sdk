/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <frame.hpp>

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), n) )
    return;
  switch ( insn.itype )
  {
    case H8500_add_q:
    case H8500_bclr:
    case H8500_bnot:
    case H8500_bset:
    case H8500_btst:
      op_dec(insn.ea, n);
      break;
    case H8500_and:
    case H8500_or:
    case H8500_xor:
    case H8500_andc:
    case H8500_orc:
    case H8500_xorc:
      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
inline bool issp(int x)
{
  return x == SP;
}

inline bool isbp(int x)
{
  return x == FP;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &x)
{
  return OP_SP_ADD
       | ((x.type == o_displ || x.type == o_phrase) && issp(x.phrase)
        ? OP_SP_BASED
        : OP_FP_BASED);
}

//----------------------------------------------------------------------
static void add_stkpnt(const insn_t &insn, sval_t value)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return;

  if ( value & 1 )
    value++;

  add_auto_stkpnt(pfn, insn.ea+insn.size, value);
}

//----------------------------------------------------------------------
inline bool is_mov(int itype)
{
  return itype >= H8500_mov_g && itype <= H8500_mov_s;
}

//----------------------------------------------------------------------
static bool get_op_value(const insn_t &insn, const op_t &x, int *value)
{
  if ( x.type == o_imm )
  {
    *value = (int)x.value;
    return true;
  }
  bool ok = false;
  if ( x.type == o_reg )
  {
    int reg = x.reg;
    insn_t movi;
    if ( decode_prev_insn(&movi, insn.ea) != BADADDR
      && is_mov(movi.itype)
      && movi.Op1.type == o_imm
      && movi.Op2.type == o_reg
      && movi.Op2.reg  == reg )
    {
      *value = (int)movi.Op1.value;
      ok = true;
    }
  }
  return ok;
}

//----------------------------------------------------------------------
static int calc_reglist_count(int regs)
{
  int count = 0;
  for ( int i=0; i < 8; i++,regs>>=1 )
    if ( regs & 1 )
      count++;
  return count;
}

//----------------------------------------------------------------------
// @--sp
inline bool is_sp_dec(const op_t &x)
{
  return x.type == o_phrase
      && issp(x.reg)
      && x.phtype == ph_pre;
}

//----------------------------------------------------------------------
// @sp++
inline bool is_sp_inc(const op_t &x)
{
  return x.type == o_phrase
      && issp(x.reg)
      && x.phtype == ph_post;
}

//----------------------------------------------------------------------
static void trace_sp(const insn_t &insn)
{
  // @sp++
  if ( is_sp_inc(insn.Op1) )
  {
    int size = 2;
    if ( insn.Op2.type == o_reglist )
      size *= calc_reglist_count(insn.Op2.reg);
    add_stkpnt(insn, size);
    return;
  }

  // @--sp
  if ( is_sp_dec(insn.Op2) )
  {
    int size = 2;
    if ( insn.Op1.type == o_reglist )
      size *= calc_reglist_count(insn.Op1.reg);
    add_stkpnt(insn, -size);
    return;
  }
  // xxx @--sp
  if ( is_sp_dec(insn.Op1) )
  {
    add_stkpnt(insn, -2);
    return;
  }

  int v;
  switch ( insn.itype )
  {
    case H8500_add_g:
    case H8500_add_q:
    case H8500_adds:
      if ( issp(insn.Op2.reg) && get_op_value(insn, insn.Op1, &v) )
        add_stkpnt(insn, v);
      break;
    case H8500_sub:
    case H8500_subs:
      if ( issp(insn.Op2.reg) && get_op_value(insn, insn.Op1, &v) )
        add_stkpnt(insn, -v);
      break;
  }
}

//----------------------------------------------------------------------
static sval_t calc_func_call_delta(const insn_t &insn, ea_t callee)
{
  sval_t delta;
  func_t *pfn = get_func(callee);
  if ( pfn != nullptr )
  {
    delta = pfn->argsize;
    if ( (pfn->flags & FUNC_FAR) != 0 && insn.Op1.type == o_near )
      delta += 2; // function will pop the code segment
  }
  else
  {
    delta = get_ind_purged(callee);
    if ( delta == -1 )
      delta = 0;
  }
  return delta;
}

//----------------------------------------------------------------------
// trace a function call.
// adjuct the stack, determine the execution flow
// returns:
//      true  - the called function returns to the caller
//      false - the called function doesn't return to the caller
static bool handle_function_call(const insn_t &insn, ea_t callee)
{
  bool funcflow = true;
  if ( !func_does_return(callee) )
    funcflow = false;
  if ( inf_should_trace_sp() )
  {
    func_t *caller = get_func(insn.ea);
    if ( func_contains(caller, insn.ea+insn.size) )
    {
      sval_t delta = calc_func_call_delta(insn, callee);
      if ( delta != 0 )
        add_stkpnt(insn, delta);
    }
  }
  return funcflow;
}

//----------------------------------------------------------------------
inline ea_t find_callee(const insn_t &insn)
{
  return get_first_fcref_from(insn.ea);
}

//----------------------------------------------------------------------
void h8500_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
    case o_reglist:
      return;
    case o_imm:
      QASSERT(10090, isload);
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, calc_opimm_flags(insn));
      break;
    case o_phrase:
    case o_displ:
      {
        process_immediate_number(insn, x.n);
        if ( is_forced )
          break;
        flags64_t F = get_flags(insn.ea);
        if ( op_adds_xrefs(F, x.n) )
        {
          ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, calc_opdispl_flags(insn));
          if ( ea != BADADDR )
            insn.create_op_data(ea, x);
        }
        // create stack variables if required
        if ( x.type == o_displ
          && may_create_stkvars()
          && !is_defarg(F, x.n) )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != nullptr
            && (issp(x.phrase)
             || isbp(x.phrase) && (pfn->flags & FUNC_FRAME) != 0) )
          {
            if ( insn.create_stkvar(x, x.addr, STKVAR_VALID_SIZE) )
              op_stkvar(insn.ea, x.n);
          }
        }
      }
      break;
    case o_near:
    case o_far:
      {
        cref_t ftype = x.type == o_near ? fl_JN : fl_JF;
        ea_t ea = calc_mem(insn, x);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = x.type == o_near ? fl_CN : fl_CF;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(insn, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
      }
      break;
    default:
      INTERR(10091);
  }
}

//----------------------------------------------------------------------
inline bool is_far_ending(const insn_t &insn)
{
  return insn.itype == H8500_prts
      || insn.itype == H8500_prtd;
}

//----------------------------------------------------------------------
int h8500_t::h8500_emu(const insn_t &insn)
{
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

//
//      Determine if the next instruction should be executed
//
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;

//
// Handle loads to segment registers
//
  sel_t v = BADSEL;
  switch ( insn.itype )
  {
    case H8500_andc:
      if ( insn.Op1.value == 0 )
        v = 0;
      goto SPLIT;
    case H8500_orc:
      if ( insn.Op1.value == 0xFF )
        v = 0xFF;
      goto SPLIT;
    case H8500_ldc:
      if ( insn.Op1.type == o_imm )
        v = insn.Op1.value;
      // fallthrough
    case H8500_xorc:
SPLIT:
      if ( insn.Op2.reg >= BR && insn.Op2.reg <= TP )
        split_sreg_range(insn.ea+insn.size, insn.Op2.reg, v, SR_auto);
      break;
  }

  if ( (Feature & CF_CALL) != 0 )
  {
    ea_t callee = find_callee(insn);
    if ( !handle_function_call(insn, callee) )
      flow = false;
  }

//
//      Handle SP modifications
//
  if ( may_trace_sp() )
  {
    func_t *pfn = get_func(insn.ea);
    if ( pfn != nullptr )
    {
      if ( (pfn->flags & FUNC_USERFAR) == 0
        && (pfn->flags & FUNC_FAR) == 0
        && is_far_ending(insn) )
      {
        pfn->flags |= FUNC_FAR;
        update_func(pfn);
        reanalyze_callers(pfn->start_ea, 0);
      }
      if ( !flow )
        recalc_spd(insn.ea);     // recalculate SP register for the next insn
      else
        trace_sp(insn);
    }
  }

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int is_jump_func(const func_t * /*pfn*/, ea_t *jump_target)
{
  *jump_target = BADADDR;
  return 0; // means "don't know"
}

//----------------------------------------------------------------------
int may_be_func(const insn_t &)
{
//  if ( insn.itype == H8_push && isbp(insn.Op1.reg) ) return 100;  // push.l er6
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(const insn_t &insn, int /*nocrefs*/)
{
  if ( insn.itype == H8500_nop )
  {
    for ( int i=0; i < 8; i++ )
      if ( get_word(insn.ea-i*2) != 0 )
        return 1;
    return 0; // too many nops in a row
  }
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
    case H8500_nop:
      break;
    case H8500_mov_g:         // B/W Move data
    case H8500_mov_e:         // B   Move data
    case H8500_mov_i:         // W   Move data
    case H8500_mov_f:         // B/W Move data
    case H8500_mov_l:         // B/W Move data
    case H8500_mov_s:         // B/W Move data
    case H8500_or:
    case H8500_and:
      if ( insn.Op1.type == insn.Op2.type && insn.Op1.reg == insn.Op2.reg )
        break;
    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
int idaapi h8500_get_frame_retsize(const func_t *pfn)
{
  return pfn == nullptr ?        0
       : pfn->flags & FUNC_FAR ? 4
       :                         2;
}

//----------------------------------------------------------------------
static uval_t find_ret_purged(const func_t *pfn)
{
  uval_t argsize = 0;
  ea_t ea = pfn->start_ea;
  insn_t insn;
  while ( ea < pfn->end_ea )
  {
    decode_insn(&insn, ea);
    if ( insn.itype == H8500_rtd || insn.itype == H8500_prtd )
    {
      argsize = insn.Op1.value;
      break;
    }
    ea = next_that(ea, pfn->end_ea, f_is_code);
  }

  // could not find any ret instructions
  // but the function ends with a jump
  if ( ea >= pfn->end_ea
    && (insn.itype == H8500_jmp || insn.itype == H8500_pjmp) )
  {
    ea_t target = calc_mem(insn, insn.Op1);
    pfn = get_func(target);
    if ( pfn != nullptr )
      argsize = pfn->argsize;
  }

  return argsize;
}

//----------------------------------------------------------------------
static void setup_far_func(func_t *pfn)
{
  if ( (pfn->flags & FUNC_FAR) == 0 )
  {
    ea_t ea1 = pfn->start_ea;
    ea_t ea2 = pfn->end_ea;
    while ( ea1 < ea2 )
    {
      if ( is_code(get_flags(ea1)) )
      {
        insn_t insn;
        decode_insn(&insn, ea1);
        if ( is_far_ending(insn) )
        {
          pfn->flags |= FUNC_FAR;
          update_func(pfn);
          break;
        }
      }
      ea1 = next_head(ea1, ea2);
    }
  }
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn != nullptr )
  {
    setup_far_func(pfn);
    uval_t argsize = find_ret_purged(pfn);
    add_frame(pfn, 0, 0, argsize);
  }
  return true;
}
