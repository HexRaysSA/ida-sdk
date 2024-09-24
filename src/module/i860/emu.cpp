/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), 1) )
    return;
  switch ( insn.itype )
  {
    case I860_and:
    case I860_andh:
    case I860_andnot:
    case I860_andnoth:
    case I860_xor:
    case I860_xorh:
      op_num(insn.ea, 1);
      break;
  }
}

//----------------------------------------------------------------------
bool i860_t::handle_operand(const insn_t &insn, const op_t &x, bool isload) const
{
  dref_t xreftype;
  uchar outf;
  switch ( x.type )
  {
    case o_phrase:                // 2 registers
    case o_reg:
      break;
    case o_imm:
      if ( !isload )
        goto badTouch;
      xreftype = dr_O;
      outf = OOF_SIGNED;
      goto makeImm;
    case o_displ:
      xreftype = isload ? dr_R : dr_W;
      outf = OOF_SIGNED|OOF_ADDR;
makeImm:
      set_immd_bit(insn);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, xreftype, outf);
      break;
    case o_mem:
      insn.create_op_data(x.addr, x);
      insn.add_dref(x.addr, x.offb, isload ? dr_R : dr_W);
      break;
    case o_near:
      {
        int iscall = has_insn_feature(insn.itype,CF_CALL);
        insn.add_cref(x.addr, x.offb, iscall ? fl_CN : fl_JN);
        if ( iscall && !func_does_return(x.addr) )
          return false;
      }
      break;
    default:
badTouch:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
  return true;
}

//----------------------------------------------------------------------
static bool isDual(uint32 code)
{
  return int(code>>26) == 0x12 && (code & Dbit) != 0;
}

//----------------------------------------------------------------------
static int isDelayedStop(uint32 code)
{
                        // br bri
  int opcode = int(code >> 26);
  switch ( opcode )
  {
    case 0x10:          // bri
    case 0x1A:          // br
      return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
static bool canFlow(const insn_t &insn)
{
  if ( !is_flow(get_flags(insn.ea)) || insn.ea < 4 )
    return 1;             // no previous instructions
  ea_t ea = insn.ea - 4;
  flags64_t F = get_flags(ea);
  if ( is_flow(F) && is_code(F) )
  {
    if ( isDelayedStop(get_dword(ea)) )         // now or later
    {
      ea -= 4;
      if ( !is_code(get_flags(ea)) || !isDual(get_dword(ea)) )
        return 0;
      return 1;
    }
    if ( is_flow(F) )
    {
      ea -= 4;
      return !is_code(get_flags(ea)) || !isDelayedStop(get_dword(ea));
    }
  }
  return 1;
}

//----------------------------------------------------------------------
int i860_t::i860_emu(const insn_t &insn) const
{
  bool flow = true;

  uint32 Feature = insn.get_canon_feature(ph);

  if ( Feature & CF_USE1 && !handle_operand(insn, insn.Op1, true) )
    flow = false;
  if ( Feature & CF_USE2 && !handle_operand(insn, insn.Op2, true) )
    flow = false;
  if ( Feature & CF_USE3 && !handle_operand(insn, insn.Op3, true) )
    flow = false;
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 && !handle_operand(insn, insn.Op1, false) )
    flow = false;
  if ( Feature & CF_CHG2 && !handle_operand(insn, insn.Op2, false) )
    flow = false;
  if ( Feature & CF_CHG3 && !handle_operand(insn, insn.Op3, false) )
    flow = false;

  if ( flow && canFlow(insn) )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);
  return 1;
}
