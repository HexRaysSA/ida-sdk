/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea),n) )
    return;
  switch ( insn.itype )
  {
    case ST20_ajw:
      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea)
{
  return to_ea(insn.cs, ea);
}

//----------------------------------------------------------------------
void st20_t::handle_operand(const insn_t &insn, const op_t &x, bool isload)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_imm:
      QASSERT(10110, isload);
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, 0);
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea = calc_mem(insn, x.addr);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      break;
    default:
      INTERR(10376);
  }
}


//----------------------------------------------------------------------
int st20_t::st20_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea,insn.ea+insn.size,fl_F);

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
  if ( insn.itype == ST20_nop )
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
    case ST20_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

