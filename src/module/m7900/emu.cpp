/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "7900.hpp"

//------------------------------------------------------------------------
// convert to data and add cross-ref
static void DataSet(const insn_t &insn, const op_t &x, ea_t EA, int isload)
{
  insn.create_op_data(EA, x);
  insn.add_dref(EA, x.offb, isload ? dr_R : dr_W);
}

//----------------------------------------------------------------------
void m7900_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  flags64_t F = get_flags(insn.ea);
  switch ( x.type )
  {
    case o_phrase:
      //remember_problem(PR_JUMP, insn.ea);
    case o_void:
    case o_reg:
      break;

    case o_sr:
    case o_displ:
      set_immd(insn.ea);
      if ( !is_forced )
      {
        ushort addr = ushort(x.addr);
        if ( x.type == o_displ )
        {
          addr += (ushort)insn.ip;
          addr += insn.size;
          uint32 offb = map_code_ea(insn, addr, x.n);
          DataSet(insn, x, offb, isload);
        }
        else if ( op_adds_xrefs(F, x.n) )
        {
          insn.add_off_drefs(x, dr_O, 0);
        }
      }
      break;

    case o_stk:
    case o_imm:
      set_immd(insn.ea);
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, 0);
      break;

    case o_ab:
      if ( x.TypeOper == TAB_INDIRECTED_ABS_X )
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        insn.create_op_data(ea, x.offb, dt_word);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);

        // get data
        uint32 Addr;
        Addr = get_word(ea);
        Addr = uint32(Addr | (getPG<<16));
        insn.add_cref(Addr, 2, fl_JF);
      }
      else
      {
        DataSet(insn, x, map_code_ea(insn, x), isload);
      }
      break;

    case o_mem:
      // convert to data, add cross ref
      switch ( x.TypeOper )
      {
        case TDIR_DIR_Y:
        case TDIR_DIR_X:
        case TDIR_DIR:
        case TDIR_INDIRECT_DIR:
        case TDIR_INDIRECT_DIR_X:
        case TDIR_INDIRECT_DIR_Y:
        case TDIR_L_INDIRECT_DIR:
        case TDIR_L_INDIRECT_DIR_Y:
          if ( getDPReg == 1 )
          {
            insn_t tmp = insn;
            op_t &tmpx = tmp.ops[x.n];
            tmpx.addr &= 0xFF3F;
            DataSet(tmp, tmpx, map_code_ea(tmp, tmpx), isload);
          }
          else
          {
            DataSet(insn, x, map_code_ea(insn, x), isload);
          }
          break;
        default:
          DataSet(insn, x, map_code_ea(insn, x), isload);
          break;
      }
      break;

    case o_near:
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        switch ( insn.itype )
        {
          case m7900_jsr:
            insn.add_cref(ea, x.offb, fl_CN);
            if ( !func_does_return(ea) )
              flow = false;
            break;

          case m7900_jsrl:
            insn.add_cref(ea, x.offb, fl_CF);
            if ( !func_does_return(ea) )
              flow = false;
            break;

          case m7900_jmpl:
            insn.add_cref(ea, x.offb, fl_JF);
            break;

          default:
            insn.add_cref(ea, x.offb, fl_JN);
            break;
        }
      }
      break;

    default:
      //      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static void LDD(const insn_t &ins)
{
  static const int DPR[] = { rDPR0, rDPR1, rDPR2, rDPR3 };

  for ( int i=0; i < 4; i++ )
    if ( GETBIT(ins.Op1.value, i) == 1 )
      split_sreg_range(ins.ea+ins.size, DPR[i], ins.ops[1+i].value, SR_auto);
}

//----------------------------------------------------------------------
int m7900_t::emu(const insn_t &insn)
{
  // Set PG
  split_sreg_range(insn.ea, rPG, ( insn.ea & 0xFF0000 ) >> 16, SR_auto);

  uint32 Feature = insn.get_canon_feature(ph);
  flow = (Feature & CF_STOP) == 0;

  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);
  bool flag4 = is_forced_operand(insn.ea, 3);
  bool flag5 = is_forced_operand(insn.ea, 4);


  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, flag3, true);
  if ( Feature & CF_USE4 ) handle_operand(insn, insn.Op4, flag4, true);
  if ( Feature & CF_USE5 ) handle_operand(insn, insn.Op5, flag5, true);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, flag3, false);
  if ( Feature & CF_CHG4 ) handle_operand(insn, insn.Op4, flag4, false);
  if ( Feature & CF_CHG5 ) handle_operand(insn, insn.Op5, flag5, false);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  switch ( insn.itype )
  {
    case m7900_lddn:
      //split_sreg_range(insn.ea + insn.size, GetDPR(), insn.Op1.value, SR_auto);
      LDD(insn);
      break;

    case m7900_ldt:
      split_sreg_range(insn.ea + insn.size, rDT, insn.Op1.value, SR_auto);
      break;

    // clear m flag
    case m7900_clm:
      split_sreg_range(insn.ea + insn.size, rfM, 0, SR_auto);
      break;
    // set m flag
    case m7900_sem:
      split_sreg_range(insn.ea + insn.size, rfM, 1, SR_auto);
      break;

    // clear processor status
    case m7900_clp:
      // clear m flag
      if ( ((insn.Op1.value & 0x20) >> 5) == 1 )
        split_sreg_range(insn.ea + insn.size, rfM, 0, SR_auto);
      // clear x flag
      if ( ((insn.Op1.value & 0x10) >> 4) == 1 )
        split_sreg_range(insn.ea + insn.size, rfX, 0, SR_auto);
      break;

    // set processor status
    case m7900_sep:
      // set m flag
      if ( ((insn.Op1.value & 0x20) >> 5) == 1 )
        split_sreg_range(insn.ea + insn.size, rfM, 1, SR_auto);
      // set x flag
      if ( ((insn.Op1.value & 0x10) >> 4) == 1 )
        split_sreg_range(insn.ea + insn.size, rfX, 1, SR_auto);
      break;

    // pull processor status from stack
    case m7900_plp:
      split_sreg_range(insn.ea + insn.size, rfM, BADSEL, SR_auto);
      split_sreg_range(insn.ea + insn.size, rfX, BADSEL, SR_auto);
      break;

  }
  return 1;
}
