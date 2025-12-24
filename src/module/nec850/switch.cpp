#include "necv850.hpp"
#include <jumptable.hpp>

//----------------------------------------------------------------------
// does the instruction spoil the flags?
static bool spoils_flags(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NEC850_ADD:
    case NEC850_ADDI:
    case NEC850_ADF:
    case NEC850_AND:
    case NEC850_ANDI:
    case NEC850_BSH:
    case NEC850_BSW:
    case NEC850_CAXI:
    case NEC850_CLR1:
    case NEC850_CMP:
    case NEC850_CTRET:
    case NEC850_DIV:
    case NEC850_DIVH:
    case NEC850_DIVHU:
    case NEC850_DIVH_r3:
    case NEC850_DIVQ:
    case NEC850_DIVQU:
    case NEC850_DIVU:
    case NEC850_EIRET:
    case NEC850_FERET:
    case NEC850_HSH:
    case NEC850_HSW:
    case NEC850_NOT:
    case NEC850_NOT1:
    case NEC850_OR:
    case NEC850_ORI:
    case NEC850_RETI:
    case NEC850_SAR:
    case NEC850_SATADD:
    case NEC850_SATSUB:
    case NEC850_SATSUBI:
    case NEC850_SATSUBR:
    case NEC850_SBF:
    case NEC850_SCH0L:
    case NEC850_SCH0R:
    case NEC850_SCH1L:
    case NEC850_SCH1R:
    case NEC850_SET1:
    case NEC850_SHL:
    case NEC850_SHR:
    case NEC850_SUB:
    case NEC850_SUBR:
    case NEC850_TST:
    case NEC850_TST1:
    case NEC850_XOR:
    case NEC850_XORI:

    case NEC850_BINS:
    case NEC850_ROTL:
    case NEC850_CLIP_B:
    case NEC850_CLIP_BU:
    case NEC850_CLIP_H:
    case NEC850_CLIP_HU:
    case NEC850_VABS_H:
    case NEC850_VABS_W:
    case NEC850_VNEG_H:
    case NEC850_VNEG_W:
    case NEC850_VMADSAT_H:
    case NEC850_VMADSAT_W:
    case NEC850_VMADRN_H:
    case NEC850_VMADRN_W:
    case NEC850_VMSUMAD_H:
    case NEC850_VMSUMAD_W:
    case NEC850_VMSUMADRE_H:
    case NEC850_VMSUMADRE_W:
    case NEC850_VMSUMADIM_H:
    case NEC850_VMSUMADIM_W:
    case NEC850_VMSUMADRN_H:
    case NEC850_VBIQ_H:
    case NEC850_PKI32I16:
    case NEC850_PKQ31Q15:
    case NEC850_PKQ30Q31:
    case NEC850_PKI64I32:
    case NEC850_CNVQ30Q15:
    case NEC850_CNVQ62Q31:
    case NEC850_VCALCH:
    case NEC850_VCALCW:
    case NEC850_TRFSRV_W4:
      return true;

    default:
      // other insns don't spoil fixed point flags
      return false;
  }
}

//-------------------------------------------------------------------------
struct nec850_jump_pattern_t : public jump_pattern_t
{
protected:
  enum { rA, rC };

  nec850_t &pm;

  nec850_jump_pattern_t(
        procmod_t *_pm,
        switch_info_t *_si, const char (*_depends)[4])
    : jump_pattern_t(_si, _depends, rC),
      pm(*(nec850_t *)_pm)
  {
    si->flags |= SWI_HXNOLOWCASE;
    modifying_r32_spoils_r64 = false;
    non_spoiled_reg = rA;
  }

public:
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  virtual void check_spoiled(tracked_regs_t *_regs) const override;

protected:
  // movea  -minv, rA', rA  | add -minv, rA
  bool jpi_sub_lowcase();
  // cmp followed by the conditional jump
  // it calls jpi_condjump() and jpi_cmp_ncases() that can be redefined in
  // the derived class.
  bool jpi_cmp_ncases_condjump();
  // switch rA
  bool jpi_jump();

  // bh default
  virtual bool jpi_condjump() newapi;
  // cmp ncases, rA
  virtual bool jpi_cmp_ncases() newapi;
};

//-------------------------------------------------------------------------
bool nec850_jump_pattern_t::handle_mov(tracked_regs_t &_regs)
{
  if ( insn.itype != NEC850_MOV
    && insn.Op1.type != o_reg
    && insn.Op2.type != o_reg )
  {
    return false;
  }
  return set_moved(insn.Op2, insn.Op1, _regs);
}

//-------------------------------------------------------------------------
#define PROC_MAXCHGOP 3
void nec850_jump_pattern_t::check_spoiled(tracked_regs_t *__regs) const
{
  tracked_regs_t &_regs = *__regs;
  for ( uint i = 0; i < _regs.size(); ++i )
  {
    const op_t &x = _regs[i];
    if ( x.type == o_reg && pm.spoils(insn, x.reg)
      || x.type == o_condjump && ::spoils_flags(insn) )
    {
      set_spoiled(&_regs, x);
    }
  }
  check_spoiled_not_reg(&_regs, PROC_MAXCHGOP);
}

//----------------------------------------------------------------------
// movea  -minv, rA', rA  | add -minv, rA
bool nec850_jump_pattern_t::jpi_sub_lowcase()
{
  if ( insn.itype == NEC850_MOVEA )
  {
    if ( insn.Op1.type != o_imm
      || insn.Op2.type != o_reg
      || !is_equal(insn.Op3, rA) )
    {
      return false;
    }
    trackop(insn.Op2, rA);
  }
  else if ( insn.itype == NEC850_ADD )
  {
    if ( insn.Op1.type != o_imm || !is_equal(insn.Op2, rA) )
      return false;
  }
  else
  {
    return false;
  }
  si->lowcase = uval_t(0-uint32(insn.Op1.value));
  return true;
}

//-------------------------------------------------------------------------
// cmp followed by the conditional jump
bool nec850_jump_pattern_t::jpi_cmp_ncases_condjump(void)
{
  // var should not be spoiled
  QASSERT(10317, !is_spoiled(rA));

  if ( jpi_condjump() // continue matching if found
    || is_spoiled(rC)
    || !jpi_cmp_ncases() )
  {
    return false;
  }

  op_t &op = regs[rC];
  // assert: op.type == o_condjump
  if ( (op.specflag1 & cc_inc_ncases) != 0 )
    ++si->ncases;
  si->defjump = op.specval;
  si->set_expr(insn.Op2.reg, insn.Op2.dtype);
  return true;
}

//----------------------------------------------------------------------
// switch rA
bool nec850_jump_pattern_t::jpi_jump()
{
  if ( insn.itype != NEC850_SWITCH
    || insn.Op1.type != o_reg
    || insn.Op1.reg == rZERO )
  {
    return false;
  }

  si->jumps = insn.ea + insn.size;
  si->set_elbase(si->jumps);
  si->flags |= SWI_SIGNED;
  si->set_jtable_element_size(2);
  si->set_shift(1);
  si->set_expr(insn.Op1.reg, dt_dword);
  trackop(insn.Op1, rA);
  return true;
}

//----------------------------------------------------------------------
// bh default
bool nec850_jump_pattern_t::jpi_condjump()
{
  op_t op;
  op.type = o_condjump;
  op.specflag1 = 0;
  switch ( insn.itype )
  {
    case NEC850_BH:   // higher
    case NEC850_BNH:  // not higher
      op.specflag1 |= cc_inc_ncases;
      break;
    case NEC850_BL:   // lower
    case NEC850_BNC:  // no carry (not lower)
      break;
    default:
      return false;
  }
  ea_t jump = to_ea(insn.cs, insn.Op1.addr);
  switch ( insn.itype )
  {
    case NEC850_BH:
    case NEC850_BNC:
      op.specval = jump;
      break;
    case NEC850_BL:
    case NEC850_BNH:
      // we have conditional jump to the switch body
      // assert: eas[0] != BADADDR
      if ( jump > eas[0] )
        return false;
      op.specval = insn.ea + insn.size;

      // possibly followed by 'jr default'
      {
        insn_t deflt;
        if ( decode_insn(&deflt, op.specval) > 0
          && deflt.itype == NEC850_JR
          && deflt.Op1.type == o_near )
        {
          op.specval = deflt.Op1.addr;
        }
      }
      break;
    default:
      return false;
  }
  op.addr = insn.ea;
  trackop(op, rC);
  return true;
}

//----------------------------------------------------------------------
// cmp ncases, rA
bool nec850_jump_pattern_t::jpi_cmp_ncases()
{
  if ( insn.itype != NEC850_CMP
    || insn.Op1.type != o_imm && insn.Op1.type != o_reg
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }

  const op_t &x = insn.Op1;
  uval_t val;
  if ( x.type == o_imm )
    val = x.value;
  else if ( !pm.find_regval(&val, insn.ea, x.reg) ) // x.type == o_reg
    return false;
  si->ncases = ushort(val);
  return true;
}

//----------------------------------------------------------------------
// jump pattern #1
// 2 movea  -minv, rA', rA  | add -minv, rA (optional)
// 1 cmp    ncases, rA      | cmp rNcases, rA
//   bh     default           (nearest to "cmp")
// 0 switch  rA
// 0 -> 1 -> 2

static const char nec850_depends1[][4] =
{
  { 1 },                      // 0
  { 2 | JPT_OPT | JPT_NEAR }, // 1
  { 0 },                      // 2 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern1_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern1_t(procmod_t *_pm, switch_info_t *_si)
    : nec850_jump_pattern_t(_pm, _si, nec850_depends1) {}

  virtual bool jpi2(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi1(void) override { return jpi_cmp_ncases_condjump(); }
  virtual bool jpi0(void) override { return jpi_jump(); }
};

//----------------------------------------------------------------------
static int is_jump_pattern1(
        switch_info_t *si,
        const insn_t &insn,
        procmod_t *pm)
{
  nec850_jump_pattern1_t jp(pm, si);
  if ( !jp.match(insn) )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
// jump pattern #2 (addi instead of cmp)
// 2 movea  -minv, rA', rA  | add -minv, rA (optional)
// 1 addi   -ncases, rA, r0
//   bl     default           (nearest to "cmp")
// 0 switch  rA
// 0 -> 1 -> 2

static const char nec850_depends2[][4] =
{
  { 1 },                      // 0
  { 2 | JPT_OPT | JPT_NEAR }, // 1
  { 0 },                      // 2 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern2_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern2_t(procmod_t *_pm, switch_info_t *_si)
    : nec850_jump_pattern_t(_pm, _si, nec850_depends2) {}

  bool jpi2(void) override { return jpi_sub_lowcase(); }
  bool jpi1(void) override { return jpi_cmp_ncases_condjump(); }
  bool jpi0(void) override { return jpi_jump(); }

protected:
  // bl default
  bool jpi_condjump() override;
  // addi -ncases, rA, r0
  bool jpi_cmp_ncases() override;
};

//----------------------------------------------------------------------
// bl default
bool nec850_jump_pattern2_t::jpi_condjump()
{
  op_t op;
  op.type = o_condjump;
  op.specflag1 = 0;
  switch ( insn.itype )
  {
    case NEC850_BH:   // higher
    case NEC850_BNH:  // not higher
      op.specflag1 |= cc_inc_ncases;
      break;
    case NEC850_BL:   // lower
    case NEC850_BNC:  // no carry (not lower)
      break;
    default:
      return false;
  }
  ea_t jump = to_ea(insn.cs, insn.Op1.addr);
  switch ( insn.itype )
  {
    case NEC850_BL:
    case NEC850_BNH:
      op.specval = jump;
      break;
    case NEC850_BH:
    case NEC850_BNC:
      // we have conditional jump to the switch body
      // assert: eas[0] != BADADDR
      if ( jump > eas[0] )
        return false;
      op.specval = insn.ea + insn.size;

      // possibly followed by 'jr default'
      {
        insn_t deflt;
        if ( decode_insn(&deflt, op.specval) > 0
          && deflt.itype == NEC850_JR
          && deflt.Op1.type == o_near )
        {
          op.specval = deflt.Op1.addr;
        }
      }
      break;
    default:
      return false;
  }
  op.addr = insn.ea;
  trackop(op, rC);
  return true;
}

//----------------------------------------------------------------------
// addi -ncases, rA, r0
bool nec850_jump_pattern2_t::jpi_cmp_ncases()
{
  if ( insn.itype != NEC850_ADDI
    || insn.Op1.type != o_imm
    || !insn.Op3.is_reg(rZERO)
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }

  si->ncases = ushort(0-uint32(insn.Op1.value));
  return true;
}

//----------------------------------------------------------------------
static int is_jump_pattern2(
        switch_info_t *si,
        const insn_t &insn,
        procmod_t *pm)
{
  nec850_jump_pattern2_t jp(pm, si);
  if ( !jp.match(insn) )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
// jump pattern #3 (without 'switch' insn)
// 3 movea -minv, rA', rA     | add -minv, rA (optional)
// 2 cmp   ncases, rA         | cmp rNcases, rA
//   bh    default              (nearest to "cmp")
// 1 shl   2, rA              | shl 1, rA
// 0 jmp   jumps[rA]
//
// jumps:  jr case0 (4 bytes) | (2 bytes)
//         jr case1
//         ...
//
// 0 -> 1 -> 2 -> 3

static const char nec850_depends3[][4] =
{
  { 1 },                      // 0
  { 2 },                      // 1
  { 3 | JPT_OPT | JPT_NEAR }, // 2
  { 0 },                      // 3 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern3_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern3_t(procmod_t *_pm, switch_info_t *_si)
    : nec850_jump_pattern_t(_pm, _si, nec850_depends3)
  {
    si->flags |= SWI_JMPINSN;
  }

  virtual bool jpi3(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi2(void) override { return jpi_cmp_ncases_condjump(); }
  virtual bool jpi1(void) override; // shl shift, rA
  virtual bool jpi0(void) override; // jmp jumps[rA]
};

//----------------------------------------------------------------------
// shl shift, rA
bool nec850_jump_pattern3_t::jpi1()
{
  if ( insn.itype != NEC850_SHL
    || insn.Op1.type != o_imm
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }
  int elsize;
  if ( insn.Op1.value == 1 )
    elsize = 2;
  else if ( insn.Op1.value == 2 )
    elsize = 4;
  else
    return false;
  si->set_jtable_element_size(elsize);
  return true;
}

//----------------------------------------------------------------------
// jmp jumps[rA]
bool nec850_jump_pattern3_t::jpi0()
{
  if ( insn.itype != NEC850_JMP || insn.Op1.type != o_displ )
    return false;
  si->jumps = insn.Op1.addr;
  track(insn.Op1.phrase, rA, dt_dword);
  return true;
}

//----------------------------------------------------------------------
static int is_jump_pattern3(
        switch_info_t *si,
        const insn_t &insn,
        procmod_t *pm)
{
  nec850_jump_pattern3_t jp(pm, si);
  if ( !jp.match(insn) )
    return JT_NONE;
  op_offset(jp.eas[0], 0, REFINFO_NOBASE | REF_OFF32);
  // rollback data created in handle_operand()
  del_items(si->jumps, DELIT_SIMPLE);
  return JT_SWITCH;
}

//----------------------------------------------------------------------
bool nec850_is_switch(const insn_t &insn)
{
  if ( !inf_create_jump_tables() )
    return false;
  if ( insn.itype != NEC850_SWITCH && insn.itype != NEC850_JMP )
    return false;
  switch_info_t si;
  bool was_switch = (get_flags32(insn.ea) & FF_JUMP) != 0
                 && get_switch_info(&si, insn.ea) > 0;
  if ( was_switch && si.is_user_defined() )
    return true;
  if ( was_switch && get_auto_state() != AU_USED )
    return true; // do not reanalyze existing switches on the early phases

  if ( was_switch )
    delete_switch_table(insn.ea, si);

  // ask plugins about a possible switch
  bool ok;
  switch ( processor_t::is_switch(&si, insn) )
  {
    case 1:
      ok = true;
      break;
    case -1:
      ok = false;
      break;
    default:
      // no one could process this instruction
      {
        static is_pattern_t *const patterns[] =
        {
          is_jump_pattern1,
          is_jump_pattern2,
          is_jump_pattern3,
        };
        ok = check_for_table_jump(&si, insn, patterns, qnumber(patterns));
      }
      break;
  }
  if ( ok )
  {
    set_switch_info(insn.ea, si);
    create_switch_table(insn.ea, si);
    return true;
  }
  if ( was_switch )
    del_switch_info(insn.ea);
  return false;
}

