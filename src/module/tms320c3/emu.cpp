/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c3x.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//----------------------------------------------------------------------
ea_t calc_code_mem(const insn_t &insn, const op_t &x)
{
  return to_ea(insn.cs, x.addr);
}

//------------------------------------------------------------------------
ea_t calc_data_mem(const insn_t &insn, const op_t &x)
{
  sel_t dpage = get_sreg(insn.ea, dp);
  if ( dpage == BADSEL )
    return BADSEL;
  return ((dpage & 0xFF) << 16) | (x.addr);
}

//----------------------------------------------------------------------
static void process_imm(const insn_t &insn, const op_t &x, flags64_t F)
{
  set_immd(insn.ea);
  if ( !is_defarg(F, x.n) )
    op_num(insn.ea, x.n);
}

//----------------------------------------------------------------------
void tms320c3x_t::handle_operand(const insn_t &insn, const op_t &x, flags64_t F, bool use)
{
  switch ( x.type )
  {
    case o_reg:
      return;

    case o_near:
      if ( insn.itype != TMS320C3X_RPTB )
      {
        cref_t ftype = fl_JN;
        ea_t ea = calc_code_mem(insn, x);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      else // evaluate RPTB loops as dref
      {
        insn.add_dref(calc_code_mem(insn, x), x.offb, dr_I);
      }
      break;

    case o_imm:
      QASSERT(10112, use);
      process_imm(insn, x, F);
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, 0);
      break;

    case o_mem:
      {
        ea_t ea = calc_data_mem(insn, x);
        if ( ea != BADADDR )
        {
          insn.add_dref(ea, x.offb, use ? dr_R : dr_W);
          insn.create_op_data(ea, x);
        }
      }
      break;

    case o_phrase:
      break;

    case o_displ:
      set_immd(insn.ea);
      break;

    default:
      if ( x.type == o_void )
      {
        if ( insn.itype == TMS320C3X_ABSF )
          break;
        if ( insn.itype == TMS320C3X_ABSI )
          break;
      }
      warning("interr: emu2 address:%a operand:%d type:%d", insn.ea, x.n, x.type);
  }
}

//----------------------------------------------------------------------
// is the previous instruction unconditional delayed jump ?
//
// The following array shows all delayed instructions (xxx[D])
// who are required to always stop.
//
// BRANCH INSTRUCTIONS

// TMS320C3X_BRD,               // Branch unconditionally (delayed)     0110 0001 xxxx xxxx xxxx xxxx xxxx xxxx
// TMS320C3X_Bcond,             // Branch conditionally                 0110 10x0 001x xxxx xxxx xxxx xxxx xxxx
// TMS320C3X_DBcond,            // Decrement and branch conditionally   0110 11xx xx1x xxxx xxxx xxxx xxxx xxxx


static bool delayed_stop(const insn_t &insn, flags64_t F)
{
  if ( !is_flow(F) )
    return false;  // Does the previous instruction exist and pass execution flow to the current byte?

  if ( insn.size == 0 )
    return false;

  int sub = 3; // backward offset to skip 3 previous 1-word instruction
  if ( insn.ea < sub )
    return false;

  ea_t ea = insn.ea - sub;

  if ( is_code(get_flags(ea)) )          // Does flag denote start of an instruction?
  {
    int code = get_wide_byte(ea); // get the instruction word

    if ( (code & 0xff000000) == 0x61000000 )
      return true;    // Branch unconditionally delayed                               0110 0001 xxxx xxxx xxxx xxxx xxxx xxxx
    if ( (code & 0xfdff0000) == 0x68200000 )
      return true;    // Branch conditionally delayed (with U cond )                  0110 10x0 001x xxxx xxxx xxxx xxxx xxxx
    //if ( (code & 0xfc3f0000) == 0x6c200000)       return true;    // Decrement and branch conditionally (with U cond )    0110 11xx xx1x xxxx xxxx xxxx xxxx xxxx
    // removed  since it's only use for loop
    // and loops don't leave functions
  }


  return false;
}

//----------------------------------------------------------------------
// if previous instruction is delayed jump return jump adr, else -1
static ea_t GetDelayedBranchAdr(const insn_t &insn, flags64_t F)
{
  int16 disp;

  if ( !is_flow(F) )
    return BADADDR; // Does the previous instruction exist and pass execution flow to the current byte?

  if ( insn.size == 0 )
    return BADADDR;

  int sub = 3; // backward offset to skip 3 previous 1-word instruction
  if ( insn.ea < sub )
    return BADADDR;

  ea_t ea = insn.ea - sub;

  if ( is_code(get_flags(ea)) )    // Does flag denote start of an instruction?
  {
    int code = get_wide_byte(ea); // get the instruction word

    if ( (code & 0xff000000) == 0x61000000 ) // Branch unconditionally (delayed )
      return code & 0xffffff;

    if ( (code & 0xffe00000) == 0x6a200000 ) // BranchD conditionally
    {
      disp = code & 0xffff;
      return insn.ea + disp;
    }

    if ( (code & 0xfe200000) == 0x6e200000 ) // DecrementD and branch conditionally
    {
      disp = code & 0xffff;
      return insn.ea + disp;
    }
  }
  return BADADDR;
}

//----------------------------------------------------------------------
bool is_basic_block_end(const insn_t &insn)
{
  flags64_t F = get_flags(insn.ea);
  if ( delayed_stop(insn, F) )
    return true;
  return !is_flow(get_flags(insn.ea+insn.size));
}

//----------------------------------------------------------------------
static bool add_stkpnt(const insn_t &insn, sval_t delta)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  return add_auto_stkpnt(pfn, insn.ea+insn.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case TMS320C3X_RETIcond:
      add_stkpnt(insn, -2);
      break;
    case TMS320C3X_RETScond:
      add_stkpnt(insn, -1);
      break;
    case TMS320C3X_POP:
    case TMS320C3X_POPF:
      add_stkpnt(insn, -1);
      break;
    case TMS320C3X_PUSH:
    case TMS320C3X_PUSHF:
      add_stkpnt(insn, 1);
      break;
    case TMS320C3X_SUBI:
      if ( insn.Op2.is_reg(sp) && insn.Op1.type == o_imm )
        add_stkpnt(insn, 0-insn.Op1.value);
      break;
    case TMS320C3X_ADDI:
      if ( insn.Op2.is_reg(sp) && insn.Op1.type == o_imm )
        add_stkpnt(insn, insn.Op1.value);
      break;
  }
}

//----------------------------------------------------------------------
int tms320c3x_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = (feature & CF_STOP) == 0;

  flags64_t F = get_flags(insn.ea);
  if ( (insn.auxpref & DBrFlag) == 0 ) // no need to process operands of delayed branches
                                      // branch address will be processed 3 instructions later
  {
    if ( feature & CF_USE1 ) handle_operand(insn, insn.Op1, F, true);
    if ( feature & CF_USE2 ) handle_operand(insn, insn.Op2, F, true);
    if ( feature & CF_USE3 ) handle_operand(insn, insn.Op3, F, true);

    if ( feature & CF_CHG1 ) handle_operand(insn, insn.Op1, F, false);
    if ( feature & CF_CHG2 ) handle_operand(insn, insn.Op2, F, false);
    if ( feature & CF_CHG3 ) handle_operand(insn, insn.Op3, F, false);
  }


  ea_t dbaddr = GetDelayedBranchAdr(insn, F);
  if ( dbaddr != BADADDR )  // add xref to the delayed target
    add_cref(insn.ea, to_ea(insn.cs, dbaddr), fl_JN);

  if ( insn.itype == TMS320C3X_RETScond )  // add xref to conditional exit
    add_cref(insn.ea, insn.ea, fl_JN);

  // check for DP changes
  if ( (insn.itype == TMS320C3X_LDIcond || insn.itype == TMS320C3X_LDI)
    && insn.Op1.type == o_imm
    && insn.Op2.type == o_reg
    && insn.Op2.reg == dp )
  {
    split_sreg_range(get_item_end(insn.ea), dp, insn.Op1.value & 0xFF, SR_auto);
  }

  // determine if the next instruction should be executed
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow && delayed_stop(insn, F) )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

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
bool idaapi create_func_frame(func_t *pfn)     // create frame of newly created function
{
  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      insn_t insn;
      ea_t ea = pfn->start_ea;
      ushort regsize = 0;
      while ( ea < pfn->end_ea ) // check for register pushs
      {
        decode_insn(&insn, ea);
        ea += insn.size;         // count pushes
        if ( (insn.itype == TMS320C3X_PUSH || insn.itype == TMS320C3X_PUSHF)
          && insn.Op1.type == o_reg )
        {
          regsize++;
        }
        else if ( insn.Op1.type == o_reg && insn.Op1.reg == sp
               || insn.Op2.type == o_reg && insn.Op2.reg == sp )
        { // ignore manipulations of this kind:
          //   LDI     SP,AR3  ADDI    #0001,SP
          continue;
        }
        else
        {
          break;
        }
      }

      ea = pfn->start_ea;
      int localsize = 0;
      while ( ea < pfn->end_ea ) // check for frame creation
      {
        decode_insn(&insn, ea);
        ea += insn.size; // try to find ADDI    #0001,SP
        if ( insn.itype == TMS320C3X_ADDI
          && insn.Op1.type == o_imm
          && insn.Op2.type == o_reg
          && insn.Op2.reg == sp )
        {
          localsize = (int)insn.Op1.value;
          break;
        }
      }
      add_frame(pfn, localsize, regsize, 0);
    }
  }
  return 0;
}

//----------------------------------------------------------------------
//      Is the instruction created only for alignment purposes?
//      returns: number of bytes in the instruction
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;

  switch ( insn.itype )
  {
    case TMS320C3X_NOP:
      break;
    default:
      return 0;
  }

  return insn.size;
}

//#processor_t.can_have_type
//----------------------------------------------------------------------
bool idaapi can_have_type(const op_t &op)
{
  switch ( op.type )
  {
    case o_imm:
    case o_displ:
    case o_mem:
      return 1;

    case o_phrase:
      if ( op.phrase < 8 || op.phrase == 0x18 ) // uses address field, or *arN
        return 1;
  }
  return 0;
}

