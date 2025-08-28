
#include "m740.hpp"

static void handle_imm(const insn_t &insn, const op_t &op, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, op.n) )
    return;
  bool in_hex = false;
  switch ( insn.itype )
  {
    case m740_and:
    case m740_ora:
      in_hex = true;
      break;
  }
  if ( in_hex )
    op_hex(insn.ea, op.n);
}

void m740_t::handle_operand(const insn_t &insn, const op_t &op)
{
  flags64_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    // code address
    case o_near:
      {
        ea_t ea = to_ea(insn.cs, op.addr);
        cref_t mode = fl_JN;
        if ( insn.itype == m740_jsr )
        {
          if ( !func_does_return(ea) )
            flow = false;
          mode = fl_CN;
        }
        insn.add_cref(ea, op.offb, mode);
      }
      break;

    // data address
    case o_mem:
      {
        enum dref_t mode = dr_U;

        if ( is_addr_ind(op) )
          mode = dr_R;    /* NOT dr_O */
        else if ( is_addr_read(op) )
          mode = dr_R;
        else if ( is_addr_write(op) )
          mode = dr_W;

        insn.add_dref(to_ea(insn.cs, op.addr), op.offb, mode);
        insn.create_op_data(op.addr, op);
      }
      break;

    // immediate
    case o_imm:
      handle_imm(insn, op, F);
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, 0);
      break;

    // displ
    case o_displ:
      if ( op_adds_xrefs(F, op.n) )
      {
        ea_t ea = insn.add_off_drefs(op, dr_O, OOF_ADDR);
        insn.create_op_data(ea, op);
      }
      break;

    // reg - do nothing
    case o_reg:
    case o_void:
      break;

    default:
      INTERR(10022);
  }
}

// emulate an instruction
int m740_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = ((feature & CF_STOP) == 0);

  if ( insn.Op1.type != o_void ) handle_operand(insn, insn.Op1);
  if ( insn.Op2.type != o_void ) handle_operand(insn, insn.Op2);
  if ( insn.Op3.type != o_void ) handle_operand(insn, insn.Op3);

/*
   we can't use this code

  if ( feature & CF_USE1)    handle_operand(insn, insn.Op1, 1 );
  if ( feature & CF_USE2)    handle_operand(insn, insn.Op2, 1 );
  if ( feature & CF_USE3)    handle_operand(insn, insn.Op3, 1 );
*/

  // we don't use CF_JUMP
  // if ( feature & CF_JUMP )
  switch ( insn.itype )
  {
    case m740_jmp:
    case m740_jsr:
      if ( insn.Op1.type != o_void && is_addr_ind(insn.Op1) )
        remember_problem(PR_JUMP, insn.ea);
      break;
  }

/*
  if ( feature & CF_CHG1)    handle_operand(insn, insn.Op1, 0 );
  if ( feature & CF_CHG2)    handle_operand(insn, insn.Op2, 0 );
  if ( feature & CF_CHG3)    handle_operand(insn, insn.Op3, 0 );
*/

  if ( flow )
  {
    // skip the next byte if the current insn is brk
    if ( insn.itype == m740_brk )
    {
      add_cref(insn.ea, insn.ea + insn.size + 1, fl_JN);
      create_byte(insn.ea + insn.size, 1);
    }
    else
    {
      add_cref(insn.ea, insn.ea + insn.size, fl_F);
    }
  }

  return 1;
}
