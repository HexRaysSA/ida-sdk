/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"

//------------------------------------------------------------------------
void DataSet(const insn_t &insn, const op_t &x, ea_t EA, int isload)
{
  insn.create_op_data(EA, x);
  insn.add_dref(EA, x.offb, isload ? dr_R : dr_W);
}

//----------------------------------------------------------------------
void nec78k0s_t::handle_operand(const op_t &x, bool forced_op, bool isload, const insn_t &insn)
{
  switch ( x.type )
  {
    case o_phrase:
    case o_void:
    case o_reg:
      break;

    case o_imm:
    case o_displ:
      set_immd(insn.ea);
      if ( !forced_op )
      {
        ushort addr = ushort(x.addr);
        if ( x.type == o_displ )
        {
          addr += (ushort)insn.ip;
          addr += insn.size;
          uint32 offb = map_code_ea(insn, addr, x.n);
          DataSet(insn, x, offb, isload);
        }
        else if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        {
          insn.add_off_drefs(x, dr_O, 0);
        }
      }
      break;

    case o_bit:
    case o_mem:
      DataSet(insn, x, map_code_ea(insn, x), isload);
      break;

    case o_near:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);
        if ( iscall )
          flow = func_does_return(ea);
      }
      break;

    default:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}
//----------------------------------------------------------------------
int nec78k0s_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  flow = (Feature & CF_STOP) == 0;

  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  if ( Feature & CF_USE1 )
    handle_operand(insn.Op1, flag1, 1, insn);
  if ( Feature & CF_USE2 )
    handle_operand(insn.Op2, flag2, 1, insn);
  if ( Feature & CF_USE3 )
    handle_operand(insn.Op3, flag3, 1, insn);
  if ( Feature & CF_CHG1 )
    handle_operand(insn.Op1, flag1, 0, insn);
  if ( Feature & CF_CHG2 )
    handle_operand(insn.Op2, flag2, 0, insn);
  if ( Feature & CF_CHG3 )
    handle_operand(insn.Op3, flag3, 0, insn);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}
