/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor emulator
 *
 */
#include <ida.hpp>
#include <auto.hpp>
#include <frame.hpp>
//#include <jumptable.hpp>
#include <segregs.hpp>
#include "necv850.hpp"

//----------------------------------------------------------------------
//#notify.is_sane_insn
// is the instruction sane for the current file type?
// arg:  int no_crefs
// 1: the instruction has no code refs to it.
//    ida just tries to convert unexplored bytes
//    to an instruction (but there is no other
//    reason to convert them into an instruction)
// 0: the instruction is created because
//    of some coderef, user request or another
//    weighty reason.
// returns: false if the instruction isn't likely to appear in the program
bool nec850_t::is_sane_insn(const insn_t &insn, int /*no_crefs*/) const
{
  int Feature = insn.get_canon_feature(ph);
  for ( int i = 0; i < 2; ++i )
    if ( has_cf_chg(Feature, i) && insn.ops[i].is_reg(rZERO) )
      return false;
  if ( insn.itype == NEC850_JARL
    && insn.Op1.type == o_near
    && insn.Op1.addr == insn.ea )
  {
    return false; // endless loop should not use JARL
  }
  return true;
}

//----------------------------------------------------------------------
size_t v850_is_align_insn(ea_t ea)
{
  if ( get_word(ea) == 0 )
    return 2;
  return 0;
}

//----------------------------------------------------------------------
// movea #imm, sp, reg
inline bool is_stkvar_sp_offset(const insn_t &insn)
{
  // assert: insn.Op2.type == o_reg
  return (insn.itype == NEC850_ADDI || insn.itype == NEC850_MOVEA)
      && insn.Op2.reg == rSP
      && insn.Op3.type == o_reg
      && insn.Op3.reg != rSP;
}

//----------------------------------------------------------------------
int nec850_is_sp_based(const insn_t &insn, const op_t &x)
{
  int res = OP_SP_ADD;
  // we assume that ep-based stackvars are created when EP==SP
  if ( x.type == o_displ && (x.reg == rSP || x.reg == rEP) )
    return res | OP_SP_BASED;

  // check for movea   8, sp, r28
  if ( x.n == 0
    && x.type == o_imm
    && insn.Op2.type == o_reg
    && is_stkvar_sp_offset(insn) )
  {
    return res | OP_SP_BASED;
  }

  return res | OP_FP_BASED;
}

//----------------------------------------------------------------------
ea_t nec850_t::get_fixed_sreg(ea_t ea, int reg) const
{
  // if REG refers to a known fixed register (e.g. GP ot TP),
  // return its value.
  int sreg;
  ea_t g_ea;
  switch ( reg )
  {
    case rGP: sreg = srGP; g_ea = g_gp_ea; break;
    case rTP: sreg = srTP; g_ea = g_tp_ea; break;
    case rEP: sreg = srEP; g_ea = g_ep_ea; break;
    default: return BADADDR;
  }
  // first try local segreg value, then global setting
  ea_t base = get_sreg(ea, sreg);
  return base != BADADDR ? base : g_ea;
}

//----------------------------------------------------------------------
ea_t nec850_t::get_base(ea_t ea, int reg, reg_value_info_t *rvi) const
{
  atype_t auto_state = get_auto_state();
  if ( auto_state == AU_NONE
    || auto_state == AU_WEAK
    || auto_state == AU_CODE )
  {
    return get_fixed_sreg(ea, reg);
  }
  // we can safely use the regtracker
  reg_value_info_t buf;
  if ( rvi == nullptr )
    rvi = &buf;
  ea_t base;
  if ( find_rvi(rvi, ea, reg) && rvi->get_num(&base) )
    return base;
  return BADADDR;
};

//-------------------------------------------------------------------------
bool is_branch_insn(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NEC850_JR:
    case NEC850_JMP:
    case NEC850_CALLT:
    case NEC850_SWITCH:
    case NEC850_LOOP:
    case NEC850_RETI:
    case NEC850_CTRET:
    case NEC850_EIRET:
    case NEC850_FERET:
    case NEC850_DBRET:
    case NEC850_DISPOSE_r:
      return true;

    case NEC850_BV:
    case NEC850_BL:
    case NEC850_BZ:
    case NEC850_BNH:
    case NEC850_BN:
    case NEC850_BR:
    case NEC850_BLT:
    case NEC850_BLE:
    case NEC850_BNV:
    case NEC850_BNC:
    case NEC850_BNZ:
    case NEC850_BH:
    case NEC850_BP:
    case NEC850_BSA:
    case NEC850_BGE:
    case NEC850_BGT:
      return true;

    case NEC850_DBHVTRAP:
    case NEC850_DBTRAP:
    case NEC850_FETRAP:
    case NEC850_HALT:
    case NEC850_HVCALL:
    case NEC850_HVTRAP:
    case NEC850_RIE:
    case NEC850_RMTRAP:
    case NEC850_SYSCALL:
    case NEC850_TRAP:
      return true;

    case NEC850_JARL:
      if ( insn.Op1.type == o_reg )
        return true;
      // assert: insn.Op1.type == o_near
      return to_ea(insn.cs, insn.Op1.addr) != insn.ea + insn.size;
  }
  return false;
}

//-------------------------------------------------------------------------
bool nec850_t::is_call_insn(const insn_t &insn) const
{
  ea_t nextaddr = insn.ea + insn.size;
  switch ( insn.itype )
  {
    case NEC850_JARL:
      // jarl nextaddr, r2 == jump
      if ( to_ea(insn.cs, insn.Op1.addr) != nextaddr )
        return true;
      break;
    case NEC850_CALLT:
      return true;
    case NEC850_JMP:
      if ( insn.Op1.type == o_reg && insn.Op1.reg != rLP )
      {
        // jmp + lp points to nextaddr == call
        // use ONLY_LINEAR because this function can be called from
        // find_rvi()
        ea_t lp_val;
        if ( find_reg_definition(&lp_val, insn.ea, rLP,
                                 nullptr, /*only_linear*/true)
          && lp_val == nextaddr )
        {
          return true;
        }
      }
      break;
  }
  return false;
}

//--------------------------------------------------------------------------
reglist_t nec850_t::callee_saved_regs() const
{
  // Callee-Save registers:
  // These general-purpose registers must be saved and restored by the
  // called function. It is thus guaranteed to the caller that the register
  // contents will be the same before and after the function call.
  // r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30(*), r31(**)
  // General-purpose registers other than the Callee-Save registers above
  // could be overwritten by the called function.
  // r3 is a stack pointer.
  // It is possible to specify usage of r4, r5, and r30(*) using options:
  // - r4 is the global pointer,
  // - r5 is the text pointer,
  // - r30 (*) is the element pointer (we have no binaries with fixed EP),
  // (**) I doubt that LP is a callee-saved register.
  reglist_t regs;
  regs.add_range(rR20, 10);
  regs.add(rSP);
  if ( is_gp_callee_saved() )
    regs.add(rGP);
  if ( is_tp_callee_saved() )
    regs.add(rTP);
  if ( is_ep_callee_saved() )
    regs.add(rEP);
  if ( is_r2_callee_saved() )
    regs.add(rR2);
  return regs;
}

//-------------------------------------------------------------------------
void nec850_t::spoils(reglist_t *regs, const insn_t &insn) const
{
  // we don't create yet another insn code for Format XI insns (with 3
  // registers), so we should check them explicitly.
  // for these insns the correct descripion for Format XI should be:
  // { "shr",    CF_USE1|CF_USE2|CF_CHG3|CF_SHFT }, // Shift Logical Right (Format XI)
  // { "shl",    CF_USE1|CF_USE2|CF_CHG3|CF_SHFT }, // Shift Logical Left (Format XI)
  // { "satsub", CF_USE1|CF_USE2|CF_CHG3         }, // Saturated Subtract (Format XI)
  // { "satadd", CF_USE1|CF_USE2|CF_CHG3         }, // Saturated Add (Format XI)
  // { "sar",    CF_USE1|CF_USE2|CF_CHG3|CF_SHFT }, // Shift Arithmetic Right (Format XI)
  // i.e. CF_CHG2 is replaced with CF_CHG3
  switch ( insn.itype )
  {
    case NEC850_SHR:
    case NEC850_SHL:
    case NEC850_SATSUB:
    case NEC850_SATADD:
    case NEC850_SAR:
      if ( insn.Op3.type == o_reg )
      {
        regs->add(insn.Op3.reg);
        return;
      }
      break;
    case NEC850_JARL:
    case NEC850_JR:
    case NEC850_CALLT:
      {
        reglist_t func_regs;
        if ( special_func_spoils(&func_regs, insn) )
        {
          regs->add(func_regs);
          return;
        }
        break;
      }
    default:
      break;
  }

  uint32 feature = insn.get_canon_feature(ph);
  for ( size_t i = 0; i < PROC_MAXOP; ++i )
  {
    if ( !has_cf_chg(feature, i) )
      continue;
    const op_t &x = insn.ops[i];
    if ( x.type == o_reg )
    {
      regs->add(x.reg);
    }
    else if ( x.type == o_reglist )
    {
      regs->add_reglist(x);
    }
    else if ( x.type == o_regrange )
    {
      int count = x.regrange_high - x.regrange_low + 1;
      if ( count > 0 )
        regs->add_range(x.regrange_low, count);
    }
  }

  // the addressing modes that change the base register: [reg]+ or [reg]-
  // find the memory operand
  for ( size_t i = 0; i < PROC_MAXOP; ++i )
  {
    const op_t &x = insn.ops[i];
    if ( (x.type == o_displ
       || x.type == o_phrase
       || x.type == o_reg && (x.specflag1 & N850F_USEBRACKETS) != 0)
      && (x.specflag1 & (N850F_POST_INCREMENT|N850F_POST_DECREMENT)) != 0 )
    {
      regs->add(x.phrase);
      break;
    }
  }

  if ( is_call_insn(insn) )
  {
    reglist_t saved = callee_saved_regs();
    saved.invert_gprs();
    regs->add(saved);
  }

  switch ( insn.itype )
  {
    // the insns with 64-bit result
    case NEC850_MAC:
    case NEC850_MACU:
      regs->add(insn.Op4.reg + 1);
      break;
    case NEC850_STTC_VR:
    case NEC850_LD_DW:
      regs->add(insn.Op2.reg + 1);
      break;
    case NEC850_MOV_DW:
      if ( insn.Op2.type == o_reg && is_gpr(insn.Op2.reg) )
        regs->add(insn.Op2.reg + 1);
      break;

    // the insns that implicitly change SP
    case NEC850_PREPARE_sp:
      regs->add(rEP);
      [[fallthrough]];
    case NEC850_DISPOSE_r0:
    case NEC850_DISPOSE_r:
    case NEC850_PREPARE_i:
    case NEC850_PUSHSP:
    case NEC850_POPSP:
      regs->add(rSP);
      break;

    case NEC850_RESBANK:
      // this insn may restore R1-R31
      regs->add_range(rR1, 31);
      break;

    default:
      break;
  }
}

//-------------------------------------------------------------------------
void nec850_t::uses(reglist_t *regs, const insn_t &insn) const
{
  uint32 feature = insn.get_canon_feature(ph);
  for ( size_t i = 0; i < PROC_MAXOP; ++i )
  {
    if ( !has_cf_use(feature, i) )
      continue;
    const op_t &x = insn.ops[i];
    if ( x.type == o_reg )
    {
      regs->add(x.reg);
    }
    else if ( x.type == o_reglist )
    {
      regs->add_reglist(x);
    }
    else if ( x.type == o_regrange )
    {
      int count = x.regrange_high - x.regrange_low + 1;
      if ( count > 0 )
        regs->add_range(x.regrange_low, count);
    }
  }

  // for each the indirect memory operand
  for ( size_t i = 0; i < PROC_MAXOP; ++i )
  {
    const op_t &x = insn.ops[i];
    if ( x.type == o_displ || x.type == o_phrase )
    {
      regs->add(x.phrase);
      // this addressing mode ([reg]%) uses the next register after the
      // index one
      if ( (x.specflag1 & N850F_MODULO_ADRESSING) != 0
        && i + 1 < PROC_MAXOP
        && insn.ops[i + 1].type == o_reg ) // the index register
      {
        regs->add(insn.ops[i + 1].reg + 1);
      }
    }
  }

  // respect ABI
  if ( is_call_insn(insn) )
    regs->add_range(rR6, 4); // input registers
  if ( insn.itype == NEC850_DISPOSE_r && insn.Op3.is_reg(rLP)
    || insn.itype == NEC850_JMP && insn.Op1.is_reg(rLP) )
  {
    regs->add_range(rR10, 2); // return registers
  }


  switch ( insn.itype )
  {
    // the insns that use 64-bit registers
    case NEC850_MAC:
    case NEC850_MACU:
      regs->add(insn.Op3.reg + 1);
      break;
    case NEC850_LDTC_VR:
    case NEC850_MODADD:
    case NEC850_ST_DW:
      regs->add(insn.Op1.reg + 1);
      break;
    case NEC850_MOV_DW:
      if ( insn.Op1.type == o_reg && is_gpr(insn.Op1.reg) )
        regs->add(insn.Op1.reg + 1);
      break;

    // the insns that implicitly use SP
    case NEC850_PREPARE_sp:
    case NEC850_DISPOSE_r0:
    case NEC850_DISPOSE_r:
    case NEC850_PREPARE_i:
    case NEC850_PUSHSP:
    case NEC850_POPSP:
      regs->add(rSP);
      break;

    default:
      break;
  }
}

//----------------------------------------------------------------------
// does EP == SP?
inline bool is_ep_equal_to_sp(ea_t ea)
{
  sval_t sp_value, ep_value;
  return find_sp_value(&sp_value, ea, rSP)
      && find_sp_value(&ep_value, ea, rEP)
      && sp_value == ep_value;
}

//----------------------------------------------------------------------
// movea #imm, ep, reg (reg != ep && ep == sp)
inline bool is_stkvar_ep_offset(const insn_t &insn)
{
  // assert: insn.Op2.type == o_reg
  return insn.itype == NEC850_MOVEA
      && insn.Op2.reg == rEP
      && insn.Op3.type == o_reg
      && insn.Op3.reg != rEP
      && is_ep_equal_to_sp(insn.ea);
}

//----------------------------------------------------------------------
ea_t nec850_t::get_callt_ea(const insn_t &insn) const
{
  if ( insn.itype != NEC850_CALLT || insn.Op1.type != o_near )
    return BADADDR;
  return insn.Op1.addr;
}

//-------------------------------------------------------------------------
// we have a possible reference from FROM to TARGET
// check if we should make it an offset
// like arm_t::good_target()
static bool is_good_target(ea_t target, bool allow_low_addrs = false)
{
  if ( target == BADADDR )
    return false;
  segment_t *seg = getseg(target);
  if ( seg == nullptr )
    return false;
  if ( !is_mapped(target) )
    return false;
  if ( !allow_low_addrs && target < 0x10000 )
    return false;

  flags64_t F32 = get_flags32(target);
  // check if it points to code
  if ( is_code(F32) )
  {
    if ( !is_head(F32) ) // middle of instruction?
      return false;
    // references to the dead code are accepted
    if ( !is_flow(F32) )
      return true;
    // references to the function start are accepted
    func_t *pfn = get_func(target);
    return pfn != nullptr && target == pfn->start_ea;
  }
  // check if it points into a DATA segment
  qstring segname;
  get_segm_name(&segname, seg);
  if ( is_data(F32)
    || seg->type == SEG_DATA
    || seg->type == SEG_BSS
    || segname == "ROM" // e.g. a firmware image
    || seg->start_ea == target )
  {
    // skip pointers to the loader header
    if ( segname == "HEADER" || segname == "LOAD" )
      return false;
    // like kdata_t::good_offset_value()
    if ( !is_tail(F32) )
      return true;
    // references to the beginning of a structure field are accepted
    ea_t head = get_item_head(target);
    if ( is_struct(get_flags32(head)) )
    {
      tinfo_t tif;
      tif.get_type_by_tid(get_strid(head));
      if ( tif.is_udt() )
      {
        uint64 offset = (target - head) * 8LL;
        if ( !tif.get_innermost_member_type(offset, &offset).empty()
          && offset == 0 )
        {
          return true;
        }
      }
    }
  }
  return false;
}

//----------------------------------------------------------------------
inline bool is_auto_refinfo(const refinfo_t &ri)
{
  return ri.target == BADADDR
      && ri.base == 0
      && !ri.no_base_xref() // the correct offset has REFINFO_NOBASE
      && ri.tdelta == 0
      && ri.type() == REF_OFF32;
}

//----------------------------------------------------------------------
inline bool can_set_offset(ea_t ea, flags64_t F, int n)
{
  if ( !is_defarg(F, n) )
    return true;
  if ( !is_off(F, n) )
    return false;
  // allow to set over a possible incorrect zero-based offset
  refinfo_t ri;
  return get_refinfo(&ri, ea, n) && is_auto_refinfo(ri);
}

//----------------------------------------------------------------------
static bool fix_localpic_label(
        uint32 *flags,
        const reg_value_info_t &rvi)
{
  ea_t localpic;
  if ( !rvi.get_num(&localpic) || !rvi.is_all_vals_pc_based() )
    return false;
  *flags &= ~REFINFO_NOBASE; // show the base as a label
  if ( !has_name(get_flags32(localpic)) )
    force_name(localpic, "localpic", SN_NOWARN|SN_LOCAL);
  return true;
}

//----------------------------------------------------------------------
static bool create_offset_for_add(
        const nec850_t &pm,
        ea_t ea,
        int n,
        sval_t value,
        int reg,
        bool strict = false)
{
  reg_value_info_t rvi;
  ea_t base = pm.get_base(ea, reg, &rvi);

  if ( strict )
  {
    // the zero base for such insns is suspicious too
    if ( base == BADADDR || base == 0 )
      return false;
    if ( !is_good_target(pm.trunc_uval(base + value), true) )
      return false;
  }

  bool has_movhi = false;
  insn_t movhi;
  if ( !rvi.empty() )
  {
    const reg_value_def_t &val = *rvi.vals_begin();
    has_movhi = int(value) >= SHRT_MIN
             && int(value) <= SHRT_MAX
             && val.def_itype == NEC850_MOVHI
             && decode_insn(&movhi, val.def_ea) > 0;
  }
  uint32 flags = REFINFO_PASTEND | REFINFO_SIGNEDOP | REFINFO_NOBASE;
  if ( !has_movhi )
  {
    if ( base == BADADDR )
      return false;
    fix_localpic_label(&flags, rvi);
    return op_offset(ea, n, flags | REF_OFF32, BADADDR, base);
  }
  // assert: movhi.Op1.type == o_imm
  ea_t target;
  if ( base != BADADDR )
  {
    target = pm.trunc_uval(base + int16(value));
    // try to detect PIC patterns
    if ( rvi.is_num() )
    {
      if ( !pm.find_rvi(&rvi, movhi.ea, movhi.Op2.reg) )
        INTERR(0);
      fix_localpic_label(&flags, rvi);
    }
    base = pm.trunc_uval(base - (movhi.Op1.value << 16));
  }
  else
  {
    // assume a zero-based index in movhi.Op2.reg
    target = pm.trunc_uval((movhi.Op1.value << 16) + int16(value));
    if ( !is_good_target(target) )
      return false;
    base = 0;
  }
  if ( !op_offset(ea, n, flags | REF_LOW16, target, base) )
    return false;
  if ( !is_defarg0(get_flags32(movhi.ea)) )
    op_offset(movhi.ea, 0, flags | pm.ref_ha16_id, target, base);
  return true;
}

//----------------------------------------------------------------------
bool nec850_t::handle_immop_for_addi(
        const insn_t &insn,
        const op_t &op) const
{
  // assert: op.n == 0
  // ignore small changes
  if ( op.value == 0 || op.value == 1 || sval_t(op.value) == -1 )
    return false;

  int dstreg = insn.Op3.type == o_reg ? insn.Op3.reg : insn.Op2.reg;
  // ignore pseudo-compare insns
  if ( dstreg == rZERO )
    return false;
  // ignore the fixed regs setup
  if ( get_fixed_sreg(insn.ea, dstreg) != BADADDR )
    return false;

  return create_offset_for_add(*this, insn.ea, 0,
                               op.value, insn.Op2.reg, true);
}

//----------------------------------------------------------------------
bool nec850_t::handle_displ(const insn_t &insn, const op_t &op) const
{
  return create_offset_for_add(*this, insn.ea, op.n, op.addr, op.phrase);
}

//----------------------------------------------------------------------
void nec850_t::handle_operand(
        const insn_t &insn,
        const op_t &op,
        bool isRead) const
{
  flags64_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    case o_imm:
      set_immd(insn.ea);
      if ( op.n == 0 && insn.Op2.type == o_reg )
      {
        if ( (is_stkvar_sp_offset(insn) || is_stkvar_ep_offset(insn)) )
        {
          // addi imm, sp, reg
          // 0 in create_stkvar() means that we don't know the stkvar size
          if ( may_create_stkvars()
            && !is_defarg0(F)
            && insn.create_stkvar(op, op.value, 0) )
          {
            op_stkvar(insn.ea, 0);
          }
        }
        else if ( can_set_offset(insn.ea, F, 0) )
        {
          bool is_like_addi = (insn.itype == NEC850_MOVEA
                            || insn.itype == NEC850_ADDI
                            || insn.itype == NEC850_ADD)
                           && insn.Op2.reg != rSP;
          bool ok = is_like_addi && handle_immop_for_addi(insn, op);
          // AF_IMMOFF is off for our processor
          // so we do the same thing only for some insn types
          if ( !ok
            && !inf_op_offset()
            && !is_off0(F)
            && (insn.itype == NEC850_MOV
             || insn.itype == NEC850_CMP
             || is_like_addi)
            && is_good_target(op.value) )
          {
            op_plain_offset(insn.ea, op.n, 0);
          }
        }
      }
      F = get_flags(insn.ea);
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, 0);
      break;

    case o_displ:
      set_immd(insn.ea);
      if ( is_call_or_jump(insn.itype) )
        break; // already handled in handle_call_or_jump()
      if ( (op.reg == rSP
         || (op.reg == rEP && is_ep_equal_to_sp(insn.ea))) )
      {
        if ( may_create_stkvars()
          && !is_defarg(F, op.n)
          && insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE) )
        {
          op_stkvar(insn.ea, op.n);
        }
      }
      else if ( can_set_offset(insn.ea, F, op.n) )
      {
        bool ok = handle_displ(insn, op);
        // AF_IMMOFF is off for our processor
        // so we do the same thing manually
        if ( !ok
          && !inf_op_offset()
          && !is_off(F, op.n)
          && is_good_target(op.addr) )
        {
          // assume a zero based index
          op_plain_offset(insn.ea, op.n, 0);
        }
      }
      F = get_flags(insn.ea);
      if ( op_adds_xrefs(F, op.n) )
      { // create data xrefs
        int outf = get_displ_outf(insn, op, F);
        ea_t ea = insn.add_off_drefs(op, isRead ? dr_R : dr_W, outf);
        if ( ea != BADADDR )
          insn.create_op_data(ea, op);
      }
      break;

    case o_near:
      if ( is_call_or_jump(insn.itype) )
        break; // already handled in handle_call_or_jump()
      insn.add_cref(to_ea(insn.cs, op.addr), op.offb, fl_JN);
      break;

    case o_mem:
      if ( uval2ea(op.addr) != BADADDR )
      {
        ea_t ea = to_ea(insn.cs, op.addr);
        insn.create_op_data(ea, op);
        insn.add_dref(op.addr, op.offb, isRead ? dr_R : dr_W);
      }
      break;
  }
}

//-------------------------------------------------------------------------
// for PREPARE/DISPOSE
int nec850_t::calc_stack_delta(const insn_t &insn) const
{
  reglist_t regs;
  uval_t locals = 0;
  bool sub;
  switch ( insn.itype )
  {
    case NEC850_PREPARE_i:
    case NEC850_PREPARE_sp:
      regs.add_reglist(insn.Op1);
      locals = insn.Op2.value * 4;
      sub = true;
      break;
    case NEC850_DISPOSE_r:
    case NEC850_DISPOSE_r0:
      regs.add_reglist(insn.Op2);
      locals = insn.Op1.value * 4;
      sub = false;
      break;
    case NEC850_JARL:
    case NEC850_JR:
    case NEC850_CALLT:
      switch ( is_special_func_call(&regs, &locals, insn) )
      {
        case SPF_SAVE:
          sub = true;
          break;
        case SPF_RETURN:
          sub = false;
          break;
        default:
          return 0;
      }
      break;
    default:
      return 0;
  }
  int res = regs.count() * 4 + locals;
  return sub ? -res : res;
}

//----------------------------------------------------------------------
void nec850_t::trace_sp(func_t *pfn, const insn_t &insn) const
{
  sval_t delta;
  switch ( insn.itype )
  {
    case NEC850_PREPARE_i:
    case NEC850_PREPARE_sp:
    case NEC850_DISPOSE_r:
    case NEC850_DISPOSE_r0:
    case NEC850_JARL:
    case NEC850_JR:
    case NEC850_CALLT:
      delta = calc_stack_delta(insn);
      break;
    case NEC850_ADD:
    case NEC850_ADDI:
    case NEC850_MOVEA:
      if ( insn.Op1.type == o_imm
        && insn.Op2.is_reg(rSP)
        && (insn.Op3.type == o_void || insn.Op3.is_reg(rSP)) )
      {
        delta = insn.Op1.value;
        break;
      }
      return;
    case NEC850_PUSHSP:
    case NEC850_POPSP:
      // assert: insn.Op1.type == o_regrange
      delta = 4 * (insn.Op1.regrange_high - insn.Op1.regrange_low + 1);
      if ( insn.itype == NEC850_PUSHSP )
        delta = -delta;
      break;
    default:
      return;
  }
  add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

//-------------------------------------------------------------------------
bool nec850_t::find_reg_definition(
        ea_t *_val,
        ea_t ea,
        int reg,
        def_insn_t *def_insn,
        bool only_linear) const
{
  // look for the defining insn
  reg_value_info_t rvi;
  if ( !find_rvi(&rvi, ea, reg, 0, only_linear ? 20 : 0) )
    return false;
  if ( !rvi.is_num() || !rvi.is_value_unique() )
    return false;
  const reg_value_def_t &val = *rvi.vals_begin();
  switch ( val.def_itype )
  {
    case NEC850_MOV:
    case NEC850_MOVEA:
    case NEC850_ADD:
      // mov loc, lp
      // movea (loc - 0xXXXX), r29, lp
      // add loc - PC, lp
      if ( def_insn != nullptr )
        *def_insn = def_insn_t(val);
      break;
    case NEC850_JARL:
    case NEC850_LD_W:
    case NEC850_SLD_W:
      if ( def_insn != nullptr )
        *def_insn = def_insn_t();
      break;
    default:
      return false;
  }
  *_val = val.val;
  return true;
}

//-------------------------------------------------------------------------
bool nec850_t::def_insn_t::apply_offset(
        const nec850_t &pm,
        ea_t target) const
{
  if ( ea == BADADDR )
    return false;
  if ( is_defarg0(get_flags32(ea)) )
    return false;
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 || insn.Op1.type != o_imm )
    return false;
  switch ( insn.itype )
  {
    case NEC850_MOV:
      return op_offset(ea, 0, REF_OFF32); // a simple zero-base offset
    case NEC850_ADD:
      {
        ea_t base = pm.trunc_uval(target - insn.Op1.value);
        // so there is no need to check the high/low parts for 'add',
        // because it is used only in the following pattern:
        //   1000   jarl loc_1000F6, lp
        //   1004 loc_1000F6:
        //   1004   add  4, lp  -- LP points to 0x1008
        //   1006   jmp  [r20]
        return op_offset(ea, 0, REF_OFF32|REFINFO_SIGNEDOP, BADADDR, base);
      }
    case NEC850_MOVEA:
      return create_offset_for_add(pm, ea, 0, insn.Op1.value, insn.Op2.reg);
  }
  return false;
}

//-------------------------------------------------------------------------
// this function analyzes code references from INSN
// it sets far code refs and return 'true' if there is a control flow to the
// next insn. also it sets offsets
bool nec850_t::handle_call_or_jump(const insn_t &insn) const
{
  // assert: is_call_or_jump(insn.itype)
  // jmp   [r1]     (o_reg)   jump
  // jmp   disp[r1] (o_displ) jump
  // jarl  addr, r2 (o_near)  call
  // jarl  [r1], r2 (o_reg)   call
  // callt imm      (o_imm)   call
  // callt addr     (o_near)  call
  // jarl  nextaddr, r2 == jump (w/o flow)
  // jmp + lp points to nextaddr == call + flow
  // jmp + lp points somewhere   == call + jump
  // jalr  _return_r31        jump
  // we ignore [r0] targets

  ea_t nextaddr = insn.ea + insn.size;
  int reg = -1;
  bool is_call = true;
  switch ( insn.itype )
  {
    case NEC850_JMP:
      is_call = false;
      if ( insn.Op1.type == o_reg )
      {
        reg = insn.Op1.reg;
        if ( reg != rLP )
        {
          ea_t lp_val;
          def_insn_t def_insn;
          if ( find_reg_definition(&lp_val, insn.ea, rLP, &def_insn) )
          {
            def_insn.apply_offset(*this, lp_val);
            is_call = true; // 'jmp' is very similar to call
            nextaddr = lp_val;
          }
        }
      }
      else if ( insn.Op1.type == o_displ )
      {
        reg = insn.Op1.phrase;
      }
      else
      {
        INTERR(10461);
      }
      break;
    case NEC850_JARL:
      if ( insn.Op1.type == o_reg )
        reg = insn.Op1.reg;
      else if ( insn.Op1.type != o_near )
        INTERR(10462);
      else if ( to_ea(insn.cs, insn.Op1.addr) == nextaddr )
        is_call = false;
      break;
    case NEC850_CALLT:
      if ( insn.Op1.type == o_imm )
        return true; // assume this is a simple call
      else if ( insn.Op1.type != o_near )
        INTERR(10463);
      break;
  }

  bool flow = is_call;
  if ( flow && nextaddr != insn.ea + insn.size )
  {
    // add xref to return address
    // v850e1_fpufw.bin C755C
    add_cref(insn.ea, nextaddr, fl_JN);
    flow = false;
  }

  ea_t target;
  def_insn_t def_insn;
  if ( reg == -1 || reg == rZERO && insn.Op1.type == o_displ )
  {
    // assert: insn.Op1.type == o_near
    target = to_ea(insn.cs, insn.Op1.addr);
  }
  else if ( reg != rZERO
         && get_auto_state() == AU_USED
         && find_reg_definition(&target, insn.ea, reg, &def_insn) )
  {
    if ( insn.Op1.type == o_displ )
      target = trunc_uval(target + insn.Op1.addr);
    else
      def_insn.apply_offset(*this, target);
  }
  else
  {
    return flow;
  }

  insn.add_cref(target, insn.Op1.offb, is_call ? fl_CN : fl_JN);

  if ( is_call && !func_does_return(target) )
    flow = false;
  if ( is_call && is_special_return_func(insn) )
    flow = false;
  if ( is_call )
    auto_apply_type(insn.ea, target);
  return flow;
}

//-------------------------------------------------------------------------
int nec850_t::nec850_emu(const insn_t &insn) const
{
  int Feature = insn.get_canon_feature(ph);

  // detect the flow to the next insn
  bool flow = (Feature & CF_STOP) == 0;
  if ( nec850_is_switch(insn) )
    flow = false;
  else if ( is_call_or_jump(insn.itype) )
    flow = handle_call_or_jump(insn);
  // restore flow as soon as possible
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_USE3 )
    handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_CHG3 )
    handle_operand(insn, insn.Op3, false);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( may_trace_sp() )
  {
    func_t *pfn = get_func(insn.ea);
    if ( pfn != nullptr )
      if ( !recalc_spd_for_basic_block(pfn, insn.ea) )
        trace_sp(pfn, insn);
  }

  // add dref to callt table entry address
  if ( insn.itype == NEC850_CALLT )
  {
    ea_t ctbp_ea = get_sreg(insn.ea, srCTBP);
    if ( is_mapped(ctbp_ea) )
    {
      ea_t ea = trunc_uval(ctbp_ea + (insn.Op1.value << 1));
      insn.create_op_data(ea, insn.Op1.offb, dt_word);
      insn.add_dref(ea, insn.Op1.offb, dr_R);
    }
  }

  // ldsr reg2, ctbp
  if ( insn.itype == NEC850_LDSR
    && insn.Op2.is_reg(rCTBP)
    && insn.Op3.type == o_void )
  {
    uval_t ctbp_val;
    if ( find_regval(&ctbp_val, insn.ea, insn.Op1.reg) )
      split_sreg_range(insn.ea + insn.size, srCTBP, ctbp_val, SR_auto);
  }

  return 1;
}

//----------------------------------------------------------------------
int nec850_t::may_be_func(const insn_t &start_insn) const
{
  switch ( start_insn.itype )
  {
    case NEC850_PREPARE_i:
    case NEC850_PREPARE_sp:
      return 100;
    case NEC850_JARL:
    case NEC850_JR:
    case NEC850_CALLT:
      if ( is_special_save_func(start_insn) )
        return 100;
      break;
    case NEC850_ADD:
    case NEC850_ADDI:
      // add -0x18, sp
      if ( start_insn.Op1.type == o_imm
        && start_insn.Op2.is_reg(rSP)
        && (start_insn.Op3.type == o_void || start_insn.Op3.is_reg(rSP))
        && sval_t(start_insn.Op1.value) < 0 )
      {
        sval_t spd = start_insn.Op1.value;
        ea_t ea = start_insn.ea + start_insn.size;
        insn_t insn;
        // st.w lp, var_s14[sp]
        if ( decode_insn(&insn, ea) > 0
          && insn.itype == NEC850_ST_W
          && insn.Op1.is_reg(rLP)
          && insn.Op2.type == o_displ
          && insn.Op2.phrase == rSP
          && spd + insn.Op2.addr == -4 )
        {
          return 100;
        }
      }
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
bool nec850_t::is_return_insn(const insn_t &insn, bool strict) const
{
  if ( is_ret_itype(insn) )
    return true;
  if ( !strict && insn.itype == NEC850_DISPOSE_r0 )
    return true;
  if ( is_special_return_func(insn) )
    return true;
  return false;
}

//-------------------------------------------------------------------------
sval_t nec850_t::regval(
        const op_t &op,
        getreg_t *getreg,
        const regval_t *rv) const
{
  if ( op.reg > rWR31 )
  {
    warning("Bad register number passed to nec850.get_register_value: %d", op.reg);
    return 0;
  }
  return sval_t(getreg(ph.reg_names[op.reg], rv).ival);
}

//-------------------------------------------------------------------------
static bool is_bcond(int itype)
{
  return itype == NEC850_BV
      || itype == NEC850_BL
      || itype == NEC850_BZ
      || itype == NEC850_BNH
      || itype == NEC850_BN
      || itype == NEC850_BR
      || itype == NEC850_BLT
      || itype == NEC850_BLE
      || itype == NEC850_BNV
      || itype == NEC850_BNC
      || itype == NEC850_BNZ
      || itype == NEC850_BH
      || itype == NEC850_BP
      || itype == NEC850_BSA
      || itype == NEC850_BGE
      || itype == NEC850_BGT;
}

//-------------------------------------------------------------------------
ea_t nec850_t::nec850_next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues) const
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return BADADDR;

  // First check for Bcond.
  if ( is_bcond(insn.itype) )
  {
    uint32_t PSW = getreg("PSW", regvalues).ival;
    bool Z   = (PSW & (1 << 0)) != 0;
    bool S   = (PSW & (1 << 1)) != 0;
    bool OV  = (PSW & (1 << 2)) != 0;
    bool CY  = (PSW & (1 << 3)) != 0;
    bool SAT = (PSW & (1 << 4)) != 0;
    bool condition = false;
    switch ( insn.itype )
    {
      case NEC850_BV:  condition = OV;                break;
      case NEC850_BL:  condition = CY;                break;
      case NEC850_BZ:  condition = Z;                 break;
      case NEC850_BNH: condition = (CY || Z);         break;
      case NEC850_BN:  condition = S;                 break;
      case NEC850_BR:  condition = true;              break;
      case NEC850_BLT: condition = (S != OV);         break;
      case NEC850_BLE: condition = ((S != OV) || Z);  break;
      case NEC850_BNV: condition = !OV;               break;
      case NEC850_BNC: condition = !CY;               break;
      case NEC850_BNZ: condition = !Z;                break;
      case NEC850_BH:  condition = !(CY || Z);        break;
      case NEC850_BP:  condition = !S;                break;
      case NEC850_BSA: condition = SAT;               break;
      case NEC850_BGE: condition = !(S != OV);        break;
      case NEC850_BGT: condition = !((S != OV) || Z); break;
    }
    ea_t target = condition ? insn.Op1.addr : BADADDR;
    return target;
  }

  // Then check for other instructions.
  ea_t target = BADADDR;
  switch ( insn.itype )
  {
    case NEC850_RETI:
      {
        uint32_t PSW = getreg("PSW", regvalues).ival;
        if ( (PSW & (1 << 6)) != 0 ) // PSW.EP
        {
          target = getreg("EIPC", regvalues).ival;
        }
        else
        {
          if ( (PSW & (1 << 7)) != 0 ) // PSW.NP
            target = getreg("FEPC", regvalues).ival;
          else
            target = getreg("EIPC", regvalues).ival;
        }
      }
      break;

    case NEC850_JR:
      target = insn.Op1.addr;
      break;

    case NEC850_JMP:
      target = regval(insn.Op1, getreg, regvalues) + insn.Op1.addr;
      break;

    case NEC850_JARL:
      if ( insn.Op1.type == o_reg )
        target = regval(insn.Op1, getreg, regvalues);
      else
        target = insn.Op1.addr;
      break;

    case NEC850_SWITCH:
      // TODO
      break;

    case NEC850_DISPOSE_r:
      target = regval(insn.Op3, getreg, regvalues);
      break;

    case NEC850_CALLT:
      target = get_callt_ea(insn);
      break;

    case NEC850_CTRET:
      target = getreg("CTPC", regvalues).ival;
      break;

    case NEC850_EIRET:
      target = getreg("EIPC", regvalues).ival;
      break;

    case NEC850_FERET:
      target = getreg("FEPC", regvalues).ival;
      break;

    case NEC850_LOOP:
      if ( regval(insn.Op1, getreg, regvalues) - 1 != 0 )
        target = insn.Op2.addr;
      break;

    case NEC850_DBHVTRAP:
    case NEC850_DBRET:
    case NEC850_DBTRAP:
    case NEC850_FETRAP:
    case NEC850_HALT:
    case NEC850_HVCALL:
    case NEC850_HVTRAP:
    case NEC850_RIE:
    case NEC850_RMTRAP:
    case NEC850_SYSCALL:
    case NEC850_TRAP:
      // TODO
      break;
  }

  return target;
}

//-------------------------------------------------------------------------
ea_t nec850_t::nec850_calc_step_over(ea_t ip) const
{
  insn_t insn;
  if ( ip == BADADDR || decode_insn(&insn, ip) <= 0 )
    return BADADDR;
  ea_t nextaddr = insn.ea + insn.size;
  switch ( insn.itype )
  {
    default:
      return BADADDR;
    case NEC850_LOOP:
      break;
    case NEC850_JARL:
      // jarl nextaddr, r2 == jump (w/o flow)
      if ( to_ea(insn.cs, insn.Op1.addr) == nextaddr )
        return BADADDR; // the step over is equal to step into
      break;
    case NEC850_CALLT:
      if ( !is_mapped(get_callt_ea(insn)) )
        break; // step over the call
      return BADADDR;
    case NEC850_JMP:
      if ( insn.Op1.type == o_reg && insn.Op1.reg != rLP )
      {
        // jmp + lp points to nextaddr == call
        ea_t lp_val;
        if ( find_reg_definition(&lp_val, insn.ea, rLP)
          && lp_val == nextaddr )
        {
          break; // step over the call
        }
      }
      return BADADDR;
  }
  return nextaddr;
}

//-------------------------------------------------------------------------
bool nec850_t::nec850_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues)
{
  if ( n < 0 || n > 4 ) // check the operand number
    return false;
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return false;

  // TODO check for op.type == o_cond?
  opinf->modified = has_cf_chg(insn.get_canon_feature(ph), n);

  uint64 v = 0;
  const op_t &op = insn.ops[n];
  switch ( op.type )
  {
    case o_imm:
      v = op.value;
      break;


    case o_near:
      if ( insn.itype == NEC850_CALLT )
      {
        opinf->ea = get_callt_ea(insn);
        break;
      }
    case o_mem:
      opinf->ea = op.addr;
      break;

    case o_reg:
      v = regval(op, getreg, regvalues);
      break;

    case o_displ:
      // TODO
      break;

    case o_reglist:
    case o_regrange:
      // TODO how to represent multiple registers?
      break;

    default:
      return false;
  }
  opinf->value._set_int(v);
  opinf->value_size = get_dtype_size(op.dtype);
  return true;
}

//--------------------------------------------------------------------------
int nec850_t::nec850_get_reg_index(const char *name) const
{
  if ( name == nullptr || name[0] == '\0' )
    return -1;
  for ( size_t i = 0; i < ph.regs_num; i++ )
    if ( stricmp(ph.reg_names[i], name) == 0 )
      return i;
  return -1;
}

//--------------------------------------------------------------------------
bool nec850_t::nec850_get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname)
{
  int regnum = nec850_get_reg_index(regname);
  if ( regnum == -1 )
    return false;

  if ( bitrange != nullptr )
    *bitrange = bitrange_t(0, 32);

  if ( main_regname != nullptr )
    *main_regname = ph.reg_names[regnum];

  return true;
}
