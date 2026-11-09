/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#include "i51.hpp"
#include <frame.hpp>

//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static flags64_t set_immd_bit(const insn_t &insn, flags64_t F)
{
  if ( !has_immd(F) )
  {
    set_immd(insn.ea);
    F = get_flags(insn.ea);
  }
  switch ( insn.itype )
  {
    case I51_anl:
    case I51_orl:
    case I51_xrl:
      if ( !is_defarg1(F) )
      {
        op_num(insn.ea, 1);
        F = get_flags(insn.ea);
      }
      break;
  }
  return F;
}

//----------------------------------------------------------------------
void i51_t::attach_bit_comment(const insn_t &insn, ea_t addr, int bit)
{
  const ioport_bit_t *predef = find_bit(addr, bit);
  if ( predef != nullptr && get_cmt(nullptr, insn.ea, false) <= 0 )
    set_cmt(insn.ea, predef->cmt.c_str(), false);
}

//----------------------------------------------------------------------
// Calculate the target data address
ea_t i51_t::i51_map_data_ea(const insn_t &insn, ea_t addr, int opnum) const
{
  if ( is_off(get_flags(insn.ea), opnum) )
    return get_offbase(insn.ea, opnum) >> 4;
  return ((addr >= 0x80 && addr < 0x100) ? sfrmem : intmem) + addr;
}

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace

void i51_t::handle_operand(const insn_t &insn, const op_t &x, bool loading)
{
  ea_t addr = x.addr;
  flags64_t F = get_flags(insn.ea);
  switch ( x.type )
  {
    case o_phrase:              // no special hanlding for these types
    case o_reg:
      break;

    case o_imm:                         // an immediate number as an operand
      if ( !loading )
        goto BAD_LOGIC;                 // this can't happen!
      F = set_immd_bit(insn, F);        // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, OOFS_IFSIGN);

      break;

    case o_displ:
      F = set_immd_bit(insn, F);        // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, loading?dr_R:dr_W, OOFS_IFSIGN|OOF_ADDR);
      break;

    case o_bit:                         // 8051 specific operand types - bits
    case o_bitnot:
      addr = (x.reg & 0xF8);
      if ( (addr & 0x80) == 0 )
        addr = addr/8 + 0x20;
      attach_bit_comment(insn, addr, x.reg & 7);  // attach a comment if necessary
      goto MEM_XREF;

    case o_bit251:
      attach_bit_comment(insn, addr, x.b251_bit);
      /* no break */

    case o_mem:                         // an ordinary memory data reference
MEM_XREF:
      {
        ea_t dea = i51_map_data_ea(insn, addr, x.n);
        insn.create_op_data(dea, x);
        insn.add_dref(dea, x.offb, loading ? dr_R : dr_W);
      }
      break;

    case o_near:                        // a code reference
      {
        ea_t ea = map_code_ea(insn, x);
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
          flow = func_does_return(ea);
      }
      break;

    default:
BAD_LOGIC:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static void add_stkpnt(const insn_t &insn, sval_t v)
{
  if ( !may_trace_sp() )
    return;

  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return;

  add_auto_stkpnt(pfn, insn.ea+insn.size, v);
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyze the delayed branches and similar constructs
// The kernel calls ana() before calling emu(), so you may be sure that
// the 'cmd' structure contains a valid and up-to-date information.
// You are not allowed to modify the 'cmd' structure.
// Upon entering this function, the 'uFlag' variable contains the flags of
// insn.ea. If you change the characteristics of the current instruction, you
// are required to refresh 'uFlag'.
// Usually the kernel calls emu() with consecutive addresses in insn.ea but
// you can't rely on this - for example, if the user asks to analyze an
// instruction at arbirary address, his request will be handled immediately,
// thus breaking the normal sequence of emulation.
// If you need to analyze the surroundings of the current instruction, you
// are allowed to save the contents of the 'cmd' structure and call ana().
// For example, this is a very common pattern:
//  {
//    insn_t saved = cmd;
//    if ( decode_prev_insn(&cmd, insn.ea) != BADADDR )
//    {
//      ....
//    }
//    cmd = saved;
//  }
//
// This sample emu() function is a very simple emulation engine.

int i51_t::emu(const insn_t &insn)
{
  flags64_t F = get_flags(insn.ea);
  uint32 Feature = insn.get_canon_feature(ph);
  flow = ((Feature & CF_STOP) == 0);

  // you may emulate selected instructions with a greater care:
  switch ( insn.itype )
  {
    case I51_mov:
      if ( insn.Op1.type == o_mem && insn.Op1.addr == 0x81 )  // mov SP, #num
      {
        if ( insn.Op2.type == o_imm && !is_defarg(F,1) )
        {
          ea_t base = intmem;
          if ( base == BADADDR )
            base = calc_offset_base(insn.ea, 1);
          if ( base != BADADDR )
            op_plain_offset(insn.ea, 1, base);    // convert it to an offset
        }
      }
      break;
    case I51_trap:
      add_cref(insn.ea, 0x7B, fl_CN);
      break;
    case I51_pop:
      add_stkpnt(insn, 1);
      break;
    case I51_push:
      add_stkpnt(insn, -1);
      break;
  }

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, false);

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;    // actually the return value is unimportant, but let's it be so
}

//-------------------------------------------------------------------------
// reason meaning:
// 1: the instruction has no code refs to it.
//    ida just tries to convert unexplored bytes
//    to an instruction (but there is no other
//    reason to convert them into an instruction)
// 0: the instruction is created because
//    of some coderef, user request or another
//    weighty reason.
bool is_sane_insn(const insn_t &insn, int reason)
{
  if ( reason != 0 )
  {
    switch ( insn.itype )
    {
      case I51_mov:
        if ( get_byte(insn.ea) == 0xFF )
          return false;
        break;
    }
  }
  return true;
}
