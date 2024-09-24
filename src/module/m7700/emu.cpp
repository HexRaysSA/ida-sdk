
#include "m7700.hpp"

//----------------------------------------------------------------------
static void handle_imm(const insn_t &insn, const op_t &op, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, op.n) )
    return;
  bool in_hex = false;
  switch ( insn.itype )
  {
    case m7700_and:
    case m7700_ora:
      in_hex = true;
      break;
  }
  if ( in_hex )
    op_hex(insn.ea, op.n);
}

//----------------------------------------------------------------------
// propagate m and x to the jump target
static void propagate_bits_to(const insn_t &insn, ea_t ea)
{
  if ( !is_loaded(ea) )
    return;
  split_sreg_range(ea, rfM, get_sreg(insn.ea, rfM), SR_auto);
  split_sreg_range(ea, rfX, get_sreg(insn.ea, rfX), SR_auto);
}

//----------------------------------------------------------------------
void m7700_t::handle_operand(const insn_t &insn, const op_t &op)
{
  flags64_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    // code address
    case o_near:
      {
        ea_t ea = to_ea(insn.cs, op.addr);
        cref_t mode;
        if ( insn.itype == m7700_jsr )
        {
          mode = is_insn_long_format(insn) ? fl_CF : fl_CN;
          if ( !func_does_return(ea) )
            flow = false;
        }
        else
        {
          mode = is_insn_long_format(insn) ? fl_JF : fl_JN;
        }
        insn.add_cref(ea, op.offb, mode);
        propagate_bits_to(insn, ea);
      }
      break;

    // data address
    case o_mem:
      // create xref for instructions with :
      //      - direct addressing mode if the value of DR is known
      //        (and therefore, computed by the analyzer)
      //      - other addressing modes
      if ( !is_addr_dr_rel(op) || get_sreg(insn.ea, rDR) != BADSEL )
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

    // bit
    case o_bit:
      handle_imm(insn, op, F);
      // create a comment if this immediate is represented in the .cfg file
      if ( op.n == 0 && (insn.Op2.type == o_near || insn.Op2.type == o_mem) )
      {
        const ioport_bit_t * port = find_bit(insn.Op2.addr, (size_t)op.value);

        if ( port != nullptr && !port->name.empty() && !has_cmt(F) )
          set_cmt(insn.ea, port->cmt.c_str(), false);
      }
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, 0);
      break;

    // displ
    case o_displ:
      if ( op_adds_xrefs(F, op.n) )
      {
        ea_t ea = insn.add_off_drefs(op, dr_O, OOF_ADDR | OOFW_32);
        insn.create_op_data(ea, op);
      }
      break;

    // reg - do nothing
    case o_reg:
    case o_void:
      break;

    default:
      INTERR(10028);
  }
}

//-------------------------------------------------------------------------
// emulate an instruction
int m7700_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = ((feature & CF_STOP) == 0);

  if ( insn.Op1.type != o_void ) handle_operand(insn, insn.Op1);
  if ( insn.Op2.type != o_void ) handle_operand(insn, insn.Op2);
  if ( insn.Op3.type != o_void ) handle_operand(insn, insn.Op3);

  switch ( insn.itype )
  {
    case m7700_jmp:
    case m7700_jsr:
      if ( insn.Op1.type != o_void && is_addr_ind(insn.Op1) )
        remember_problem(PR_JUMP, insn.ea);
      break;
  }

  if ( flow )
  {
    // skip the next byte if the current insn is brk
    if ( insn.itype == m7700_brk )
    {
      add_cref(insn.ea, insn.ea + insn.size + 1, fl_JN);
      create_byte(insn.ea + insn.size, 1);
    }
    else
    {
      add_cref(insn.ea, insn.ea + insn.size, fl_F);
    }
  }

  switch ( insn.itype )
  {
    // clear m flag
    case m7700_clm:
      split_sreg_range(insn.ea + insn.size, rfM, 0, SR_auto);
      break;
    // set m flag
    case m7700_sem:
      split_sreg_range(insn.ea + insn.size, rfM, 1, SR_auto);
      break;

    // clear processor status
    case m7700_clp:
      // clear m flag
      if ( ((insn.Op1.value & 0x20) >> 5) == 1 )
        split_sreg_range(insn.ea + insn.size, rfM, 0, SR_auto);
      // clear x flag
      if ( ((insn.Op1.value & 0x10) >> 4) == 1 )
        split_sreg_range(insn.ea + insn.size, rfX, 0, SR_auto);
      break;

    // set processor status
    case m7700_sep:
      // set m flag
      if ( ((insn.Op1.value & 0x20) >> 5) == 1 )
        split_sreg_range(insn.ea + insn.size, rfM, 1, SR_auto);
      // set x flag
      if ( ((insn.Op1.value & 0x10) >> 4) == 1 )
        split_sreg_range(insn.ea + insn.size, rfX, 1, SR_auto);
      break;

    // pull processor status from stack
    case m7700_plp:
      split_sreg_range(insn.ea + insn.size, rfM, BADSEL, SR_auto);
      split_sreg_range(insn.ea + insn.size, rfX, BADSEL, SR_auto);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
static bool is_func_far(ea_t ea)
{
  bool func_far = false;
  insn_t insn;
  while ( true )
  {
    if ( decode_insn(&insn, ea) == 0 )
      break;
    ea += insn.size;

    // rts = jsr
    if ( insn.itype == m7700_rts )
      break;

    // rtl = jsrl
    if ( insn.itype == m7700_rtl )
    {
      func_far = true;
      break;
    }
  }
  return func_far;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  // PC (2 bytes long) is always pushed
  int context_size = 2;

  // detect phd
  ea_t ea = pfn->start_ea;

  // if far, 1 byte more on the stack (PG register)
  if ( is_func_far(ea) )
  {
    pfn->flags |= FUNC_FAR;
    context_size++;
  }

  insn_t insn;
  decode_insn(&insn, ea);
  ea += insn.size;
  if ( insn.itype != m7700_phd )
    return 0;

  // DR (2 bytes long) is pushed
  context_size += 2;

  int auto_size = 0;

  while ( true )
  {
    decode_insn(&insn, ea);
    ea += insn.size;

    // A (2 bytes long) is pushed
    if ( insn.itype != m7700_pha )
      break;

    auto_size += 2;
  }

  // gen comment
  char b[MAXSTR];
  qsnprintf(b, sizeof b, "Auto Size (%d) - Context Size (%d)", auto_size, context_size);
  set_func_cmt(pfn, b, false);

  return add_frame(pfn, auto_size, 0, 0);
}

//----------------------------------------------------------------------
int idaapi idp_get_frame_retsize(const func_t *pfn)
{
  return pfn == nullptr ?             0
       : is_func_far(pfn->start_ea) ? 2
       :                              3;
}
