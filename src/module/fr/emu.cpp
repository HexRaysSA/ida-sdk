
#include "fr.hpp"

// Analyze an instruction
static ea_t next_insn(insn_t *insn, ea_t ea)
{
  if ( decode_insn(insn, ea) == 0 )
    return 0;
  ea += insn->size;
  return ea;
}

// Emulate an operand.
static void handle_operand(const insn_t &insn, const op_t &op)
{
  bool offset = false;
  switch ( op.type )
  {
    case o_near:
      insn.add_cref(to_ea(insn.cs, op.addr), op.offb, (insn.itype == fr_call) ? fl_CN : fl_JN);
      break;

    case o_mem:
      {
        enum dref_t mode = dr_U;

        if ( op.specflag1 & OP_ADDR_R )
          mode = dr_R;
        else if ( op.specflag1 & OP_ADDR_W )
          mode = dr_W;

        ea_t ea = to_ea(insn.cs, op.addr);
        insn.add_dref(ea, op.offb, mode);
        insn.create_op_data(ea, op);
      }
      break;

    case o_imm:
      // if current insn is ldi:32 #imm, r1
      // and next insn is call @r1,
      // replace the immediate value with an offset.
      if ( insn.itype == fr_ldi_32
        && insn.Op1.type == o_imm
        && insn.Op2.type == o_reg )
      {
        const int callreg = insn.Op2.reg;
        insn_t nexti;
        if ( next_insn(&nexti, insn.ea + insn.size ) > 0
          && nexti.itype == fr_call
          && nexti.Op1.type == o_phrase
          && nexti.Op1.specflag2 == fIGR
          && nexti.Op1.reg == callreg )
        {
          offset = true;
        }
        if ( !is_defarg(get_flags(insn.ea), 0) && offset )
          op_plain_offset(insn.ea, 0, 0);
      }
      set_immd(insn.ea);
      // if the value was converted to an offset, then create a data xref:
      if ( !offset && op_adds_xrefs(get_flags(insn.ea), op.n) )
        insn.add_off_drefs(op, dr_O, 0);

      // create stack variables if necessary
      {
        bool ok = false;
        // ldi8 #our_value, R1
        // extsb R1
        // addn R14, R1
        if ( insn.itype == fr_ldi_8
          && insn.Op2.type == o_reg
          && insn.Op2.reg == rR1 )
        {
          insn_t nexti;
          next_insn(&nexti, insn.ea + insn.size);
          if ( nexti.itype == fr_extsb
            && nexti.Op1.type == o_reg
            && nexti.Op1.reg == rR1 )
          {
            ok = true;
          }
          if ( ok )
          {
            ok = false;
            next_insn(&nexti, nexti.ea + insn.size);
            if ( nexti.itype == fr_addn
              && nexti.Op1.type == o_reg
              && nexti.Op1.reg == rR14
              && nexti.Op2.type == o_reg
              && nexti.Op2.reg == rR1 )
            {
              ok = true;
            }
          }
        }
        // ldi32 #our_value, Ri
        // addn R14, Ri
        //
        // (where Ri is either R1 or R2)
        else if ( insn.itype == fr_ldi_32
               && insn.Op2.type == o_reg
               && (insn.Op2.reg == rR1 || insn.Op2.reg == rR2) )
        {
          ushort the_reg = insn.Op2.reg;
          insn_t nexti;
          next_insn(&nexti, insn.ea + insn.size);
          if ( nexti.itype == fr_addn
            && nexti.Op1.type == o_reg
            && nexti.Op1.reg == rR14
            && nexti.Op2.type == o_reg
            && nexti.Op2.reg == the_reg )
          {
            ok = true;
          }
        }

        if ( ok && may_create_stkvars()
          && !is_defarg(get_flags(insn.ea), op.n) )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != nullptr && pfn->flags & FUNC_FRAME )
          {
            if ( insn.create_stkvar(op, op.value, 0) )
              op_stkvar(insn.ea, op.n);
          }
        }
      }
      break;

    case o_displ:
    case o_phrase:  // XXX
    case o_reglist:
    case o_void:
    case o_reg:
      break;

    default:
      INTERR(10017);
  }
}

inline bool fr_t::is_stop(const insn_t &insn) const
{
  uint32 feature = insn.get_canon_feature(ph);
  return (feature & CF_STOP) != 0;
}

// Emulate an instruction.
int fr_t::emu(const insn_t &insn) const
{
  bool flow = !is_stop(insn) || (insn.auxpref & INSN_DELAY_SHOT);
  if ( flow )
  {
    insn_t previ;
    if ( decode_prev_insn(&previ, insn.ea) != BADADDR )
      flow = !(is_stop(previ) && (previ.auxpref & INSN_DELAY_SHOT));
  }

  if ( insn.Op1.type != o_void ) handle_operand(insn, insn.Op1);
  if ( insn.Op2.type != o_void ) handle_operand(insn, insn.Op2);
  if ( insn.Op3.type != o_void ) handle_operand(insn, insn.Op3);
  if ( insn.Op4.type != o_void ) handle_operand(insn, insn.Op4);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}

// Create a function frame
bool idaapi create_func_frame(func_t *pfn)
{
  ushort savedreg_size = 0;
  uint32 args_size = 0;
  uint32 localvar_size;

  ea_t ea = pfn->start_ea;

  // detect multiple ``st Ri, @-R15'' instructions.
  insn_t insn;
  while ( (ea=next_insn(&insn, ea)) != 0
       && insn.itype == fr_st
       && insn.Op1.type == o_reg
       && insn.Op2.type == o_phrase
       && insn.Op2.reg == rR15
       && insn.Op2.specflag2 == fIGRM )
  {
    savedreg_size += 4;
#if defined(__DEBUG__)
    msg("0x%a: detected st Rx, @-R15\n", ea);
#endif /* __DEBUG__ */
  }

  // detect enter #nn
  if ( insn.itype == fr_enter )
  {
    // R14 is automatically pushed by fr_enter
    savedreg_size += 4;
    localvar_size = uint32(insn.Op1.value - 4);
#if defined(__DEBUG__)
    msg("0x%a: detected enter #0x%a\n", ea, insn.Op1.value);
#endif /* __DEBUG__ */
  }
  // detect mov R15, R14 + ldi #imm, R0 instructions
  else
  {
    if ( insn.itype != fr_mov
      || insn.Op1.type != o_reg
      || insn.Op1.reg != rR15
      || insn.Op2.type != o_reg
      || insn.Op2.reg != rR14 )
    {
      goto BAD_FUNC;
    }
    /*ea = */next_insn(&insn, ea);
    if ( (insn.itype == fr_ldi_20 || insn.itype == fr_ldi_32)
      && insn.Op1.type == o_imm
      && insn.Op2.type == o_reg
      && insn.Op2.reg == rR0 )
    {
      localvar_size = uint32(insn.Op1.value);
    }
    else
    {
      goto BAD_FUNC;
    }
#if defined(__DEBUG__)
    msg("0x%a: detected ldi #0x%a, R0\n", ea, insn.Op1.value);
#endif /* __DEBUG__ */
  }

  // XXX we don't care about near/far functions, because currently
  // we don't know how to detect them ;-)

  pfn->flags |= FUNC_FRAME;
  return add_frame(pfn, localvar_size, savedreg_size, args_size);

BAD_FUNC:
  return 0;
}

int idaapi is_sp_based(const insn_t &, const op_t &)
{
  return OP_SP_ADD | OP_FP_BASED;
}

int idaapi is_align_insn(ea_t ea)
{
  return get_byte(ea) == 0;
}
