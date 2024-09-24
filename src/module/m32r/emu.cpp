
#include "m32r.hpp"

// handle immediate values
static void handle_imm(const insn_t &insn)
{
  set_immd(insn.ea);
}

//----------------------------------------------------------------------
// handle the custom switch format
//     ....
//     bl.s next || nop  <- insn_ea
//  next:
//     add  lr, R0
//     jmp  lr
// si.jumps:
//     bra.s case0 || nop
//     bra.l case1
//     ...
int m32r_create_switch_xrefs(ea_t insn_ea, const switch_info_t &si)
{
  if ( (si.flags & SWI_CUSTOM) != 0 )
  {
    insn_t insn;
    decode_insn(&insn, insn_ea);
    ea_t ea = si.jumps;
    for ( int i = 0; i < si.ncases; i++, ea += insn.size )
    {
      add_cref(insn_ea, ea, fl_JN);
      decode_insn(&insn, ea);
      if ( insn.Op1.type == o_near )
      {
        ea_t target = to_ea(insn.cs, insn.Op1.addr);
        // xrefs are from "bl" -> branch target.
        add_cref(insn_ea, target, fl_JN);
      }
    }
  }
  return 1; // ok
}

//----------------------------------------------------------------------
int m32r_calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si)
{
  if ( (si.flags & SWI_CUSTOM) == 0 )
    return 0;

  insn_t insn;
  decode_insn(&insn, insn_ea);

  ea_t ea = si.jumps;
  svalvec_t vals;
  vals.push_back(0); // add one item
  for ( int i=0; i < si.ncases; i++, ea += insn.size )
  {
    decode_insn(&insn, ea);
    if ( targets != nullptr )
    {
      if ( insn.itype == m32r_bra && insn.Op1.type == o_near )
        targets->push_back(insn.Op1.addr);
      else
        targets->push_back(insn.ea);
    }
    if ( casevec != nullptr )
    {
      vals[0] = i;
      casevec->push_back(vals);
    }
  }
  return 1; // ok
}

//----------------------------------------------------------------------
static bool handle_switch(const insn_t &insn)
{
  switch_info_t si;
  bool was_switch = (get_flags(insn.ea) & FF_JUMP) != 0
                 && get_switch_info(&si, insn.ea) > 0;
  // do not overwrite the existing switch
  // FIXME: reanalyze non user defined switches
  if ( was_switch )
    return true;

  // ask plugins about a possible switch
  switch ( processor_t::is_switch(&si, insn) )
  {
    case 1:
      set_switch_info(insn.ea, si);
      create_switch_table(insn.ea, si);
      return true;
    case -1:
      return false;
    default:
      // this processor module does not handle ev_is_switch
      break;
  }

  //  ldi8    R1, #0x21 ; '!'
  //  cmpu    R1, R0
  //  bc.l    loc_67F8C
  //  slli    R0, #2
  //  addi    R0, #4
  //  bl.s    next || nop
  // next:
  //  add     lr, R0
  //  jmp     lr
  //  bra.s   loc_67CDC || nop
  //  bra.s   loc_67D34 || nop
  //  bra.l   loc_67F8C
  //  ...
  if ( insn.itype != m32r_bl )
    return false;

  // bl should be to next address
  ea_t tgt = to_ea(insn.cs, insn.Op1.addr);
  if ( tgt != insn.ea + insn.size )
    return false;

  insn_t insn2;
  // check for add lr, R0; jmp lr
  if ( decode_insn(&insn2, tgt) == 0
    || insn2.itype != m32r_add
    || !insn2.Op1.is_reg(rLR)
    || insn2.Op2.type != o_reg )
  {
BAD_MATCH:
    return false;
  }

  int switch_reg = insn2.Op2.reg;

  // jmp lr
  if ( decode_insn(&insn2, insn2.ea + insn2.size) == 0
    || insn2.itype != m32r_jmp
    || !insn2.Op1.is_reg(rLR) )
  {
    goto BAD_MATCH;
  }

  // addi    R0, #4
  if ( decode_prev_insn(&insn2, insn.ea) == BADADDR
    || insn2.itype != m32r_addi
    || !insn2.Op1.is_reg(switch_reg)
    || insn2.Op2.type != o_imm )
  {
    goto BAD_MATCH;
  }

  ea_t jumps = insn.ea + insn.size + insn2.Op2.value;

  // slli    R0, #2
  if ( decode_prev_insn(&insn2, insn2.ea) == BADADDR
    || insn2.itype != m32r_slli
    || !insn2.Op1.is_reg(switch_reg)
    || !insn2.Op2.is_imm(2) )
  {
    goto BAD_MATCH;
  }

  // bc.l    default
  if ( decode_prev_insn(&insn2, insn2.ea) == BADADDR
    || insn2.itype != m32r_bc )
  {
    goto BAD_MATCH;
  }

  ea_t defea = to_ea(insn2.cs, insn2.Op1.addr);

  // cmpu    R1, R0
  if ( decode_prev_insn(&insn2, insn2.ea) == BADADDR
    || insn2.itype != m32r_cmpu
    || !insn2.Op2.is_reg(switch_reg)
    || insn2.Op1.type != o_reg )
  {
    goto BAD_MATCH;
  }

  int cmpreg = insn2.Op1.reg;

  // ldi8    R1, #max
  if ( decode_prev_insn(&insn2, insn2.ea) == BADADDR
    || insn2.itype != m32r_ldi
    || !insn2.Op1.is_reg(cmpreg)
    || insn2.Op2.type != o_imm )
  {
    goto BAD_MATCH;
  }

  // looks good

  si.flags  |= SWI_CUSTOM | SWI_J32;
  si.ncases  = insn2.Op2.value + 1;
  si.jumps   = jumps;
  si.lowcase = 0;
  si.startea = insn2.ea;
  si.set_expr(switch_reg, dt_dword);
  si.defjump = defea;
  set_switch_info(insn.ea, si);
  create_switch_table(insn.ea, si);
  return true;
}

//----------------------------------------------------------------------
// emulate operand
void m32r_t::handle_operand(const insn_t &insn, const op_t &op, bool loading)
{
  flags64_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    // Address
    case o_near:
      // branch label - create code reference (call or jump
      // according to the instruction)
      {
        ea_t ea = to_ea(insn.cs, op.addr);
        cref_t ftype = fl_JN;
        if ( insn.itype == m32r_bl && !handle_switch(insn) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, op.offb, ftype);
      }
      break;

    // Immediate
    case o_imm:
      QASSERT(10135, loading);
      handle_imm(insn);
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, OOFW_IMM|OOF_SIGNED);

      // create a comment if this immediate is represented in the .cfg file
      {
        const ioport_t *port = find_sym(op.value);
        if ( port != nullptr && !has_cmt(F) )
          set_cmt(insn.ea, port->cmt.c_str(), false);
      }
      break;

    // Displ
    case o_displ:
      handle_imm(insn);
      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, loading ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR|OOFW_32);

      // create stack variables if required
      if ( may_create_stkvars() && !is_defarg(F, op.n) )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr && (op.reg == rFP || op.reg == rSP) && pfn->flags & FUNC_FRAME )
        {
          if ( insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, op.n);
        }
      }
      break;

    case o_phrase:
      /* create stack variables if required */
      if ( op.specflag1 == fRI && may_create_stkvars() && !is_defarg(F, op.n) )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr
          && (op.reg == rFP || op.reg == rSP)
          && (pfn->flags & FUNC_FRAME) != 0 )
        {
          if ( insn.create_stkvar(op, 0, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, op.n);
        }
      }
      break;

    // Phrase - register - void : do nothing
    case o_reg:
    case o_void:
      break;

    // Others types should never be called
    default:
      INTERR(10136);
  }
}

//----------------------------------------------------------------------------
// emulate an instruction
int m32r_t::emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = ((feature & CF_STOP) == 0);

  if ( feature & CF_USE1 )    handle_operand(insn, insn.Op1, true);
  if ( feature & CF_USE2 )    handle_operand(insn, insn.Op2, true);
  if ( feature & CF_USE3 )    handle_operand(insn, insn.Op3, true);

  if ( feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( feature & CF_CHG1 )    handle_operand(insn, insn.Op1, false);
  if ( feature & CF_CHG2 )    handle_operand(insn, insn.Op2, false);
  if ( feature & CF_CHG3 )    handle_operand(insn, insn.Op3, false);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn == nullptr )
    return 0;

  ea_t ea = pfn->start_ea;
  insn_t insn[4];
  int i;

  for ( i = 0; i < 4; i++ )
  {
    decode_insn(&insn[i], ea);
    ea += insn[i].size;
  }

  i = 0;
  ushort regsize = 0;            // number of saved registers

  // first insn is not either push fp OR st fp, @-sp
  if ( (insn[i].itype != m32r_push
     || insn[i].Op1.reg != rFP)
    && (insn[i].itype != m32r_st
     || insn[i].Op1.reg != rFP
     || insn[i].Op2.reg != rSP
     || insn[i].Op2.specflag1 != fRIAS) )
  {
    return 0;
  }

  regsize += 4;
  i++;

  // next insn is push lr OR st lr, @-sp
  if ( (insn[i].itype == m32r_push
     && insn[i].Op1.reg == rLR)
    || (insn[i].itype == m32r_st
     && insn[i].Op1.reg == rFP
     && insn[i].Op2.reg == rLR
     && insn[i].Op2.specflag1 != fRIAS) )
  {
    regsize += 4;
    i++;
  }

  // next insn is not addi sp, #imm
  if ( insn[i].itype != m32r_addi || insn[i].Op1.reg != rSP )
    return 0;

  sval_t offset = - (sval_t) insn[i].Op2.value;

  // toggle to the negative sign of the immediate operand of the addi insn
  if ( !is_invsign(insn[i].ea, get_flags(insn[i].ea), 2) )
    toggle_sign(insn[i].ea, 2);

  i++;

  // next insn is not mv fp, sp
  if ( insn[i].itype != m32r_mv || insn[i].Op1.reg != rFP || insn[i].Op2.reg != rSP )
    return 0;

  pfn->flags |= (FUNC_FRAME | FUNC_BOTTOMBP);
  return add_frame(pfn, offset, regsize, 0);
}

//----------------------------------------------------------------------------
// should always returns 0
int idaapi m32r_get_frame_retsize(const func_t *)
{
  return 0;
}

//----------------------------------------------------------------------------
// check is the specified operand is relative to the SP register
int idaapi is_sp_based(const insn_t &/*insn*/, const op_t &op)
{
  return OP_SP_ADD | (op.reg == rSP ? OP_SP_BASED : OP_FP_BASED);
}

//----------------------------------------------------------------------------
bool idaapi can_have_type(const op_t &x)
{
  switch ( x.type )
  {
    case o_imm:
    case o_displ:
      return 1;

    case o_phrase:
      if ( x.specflag1 == fRI )
        return 1;
      break;
  }
  return 0;
}
