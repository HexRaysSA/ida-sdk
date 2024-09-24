/*
 * Disassembler for Samsung SAM87 processors
 */

#include "sam8.hpp"

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace
void sam8_t::handle_operand(const insn_t &insn, const op_t &x, bool loading)
{
  switch ( x.type )
  {
    case o_phrase:              // no special handling for these types
    case o_reg:
    case o_reg_bit:
      break;

    case o_imm:
      // this can't happen!
      if ( !loading )
        goto BAD_LOGIC;

      // set immediate flag
      set_immd(insn.ea);

      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, 0);
      break;

    case o_displ:
      if ( x.phrase == fIdxCAddr )
      {
        insn.create_op_data(x.addr, x);
        insn.add_dref(x.addr, x.offb, loading ? dr_R : dr_W);
      }
      else
      {
        // create name
        char buf[256];
        qsnprintf(buf, sizeof(buf), "emem_%a", x.addr);
        set_name(SAM8_EDATASEG_START + x.addr, buf, SN_NOCHECK|SN_AUTO);

        // setup data xrefs etc
        insn.create_op_data(SAM8_EDATASEG_START + x.addr, x);
        insn.add_dref(SAM8_EDATASEG_START + x.addr, x.offb, loading ? dr_R : dr_W);
      }
      break;

    case o_emem:
      {
        // create variable name
        char buf[256];
        qsnprintf(buf, sizeof(buf), "emem_%a", x.addr);
        set_name(SAM8_EDATASEG_START + x.addr, buf, SN_NOCHECK|SN_AUTO);

        // setup data xrefs etc
        insn.create_op_data(SAM8_EDATASEG_START + x.addr, x);
        insn.add_dref(SAM8_EDATASEG_START + x.addr, x.offb, loading ? dr_R : dr_W);
        break;
      }

    case o_cmem:
      insn.create_op_data(x.addr, x);
      insn.add_dref(x.addr, x.offb, loading ? dr_R : dr_W);
      break;

    case o_near:
      {
        // work out if it is a CALL, and add in a code xref
        bool iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(x.addr, x.offb, iscall ? fl_CN : fl_JN);

        // if dest is a non-returning function, don't flow onto next op
        if ( flow && iscall )
        {
          if ( !func_does_return(x.addr) )
            flow = false;
        }
        break;
      }

    case o_cmem_ind:
      // setup code xref/variable
      insn.create_op_data(x.addr, x.offb, dt_word);
      insn.add_dref(x.addr, x.offb, loading ? dr_R : dr_W);

      // Now, since we KNOW this is an indirect code jump, turn
      // the word at the x.addr into an offset into a subroutine
      if ( is_mapped(x.addr) )
      {
        // get value stored in that address
        ushort destAddr = get_word(x.addr);

        // add in cref & turn into offset
        add_cref(x.addr, destAddr, fl_JN);
        op_plain_offset(x.addr, 0, 0);
      }
      break;

    default:
BAD_LOGIC:
      warning("%a (%s): bad optype", insn.ea, insn.get_canon_mnem(ph));
      break;
  }
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyze the delayed branches and similar constructs

int sam8_t::emu(const insn_t &insn)
{
  // setup
  uint32 Feature = insn.get_canon_feature(ph);
  flow = true;

  // disable flow if CF_STOP set
  if ( Feature & CF_STOP )
    flow = false;

  // you may emulate selected instructions with a greater care:
  switch ( insn.itype )
  {
    case SAM8_JR: case SAM8_JP:
      // Do extended condition code checking on these instructions
      if ( insn.c_condition == ccNone || insn.c_condition == ccT )
        flow = false;
      break;
  }

  // deal with operands
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
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  // OK (actual code unimportant)
  return 1;
}
