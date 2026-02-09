/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      V850/RH850 module
 *
 */

#include "necv850.hpp"
#include <frame.hpp>
#include <cvt64.hpp>

//---------------------------------------------------------------------
void pushinfo_t::serialize(bytevec_t *_packed, ea_t entry_ea) const
{
  bytevec_t &packed = *_packed;
  packed.pack_db(PUSHINFO_VERSION);
  packed.pack_dd(flags);

  packed.pack_dw(uint16(size()));
  for ( const auto &pr : *this )
  {
    packed.pack_ea(pr.ea - entry_ea);
    packed.pack_ea(-pr.off);
    packed.pack_ea(pr.width);
    packed.pack_dw(pr.reg);
  }
}

//---------------------------------------------------------------------
bool pushinfo_t::deserialize(
        memory_deserializer_t *_mmdsr,
        ea_t entry_ea)
{
  memory_deserializer_t &mmdsr = *_mmdsr;
  /*int version = */mmdsr.unpack_db();
  flags = mmdsr.unpack_dd();

  resize(mmdsr.unpack_dw());
  for ( auto &pr : *this )
  {
    pr.ea = mmdsr_unpack_ea(mmdsr, entry_ea);
    pr.off = -mmdsr_unpack_sval(mmdsr);
    pr.width = mmdsr_unpack_ea(mmdsr);
    pr.reg = NEC850_regnum_t(mmdsr.unpack_dw());
  }
  return true;
}

//---------------------------------------------------------------------
void pushinfo_t::save_to_idb(nec850_t &pm, ea_t ea) const
{
  bytevec_t packed;
  serialize(&packed, ea);
  pm.helper.setblob_ea(&packed[0], packed.size(),
                       ea, nec850_t::PUSHINFO_TAG);
}

//---------------------------------------------------------------------
bool pushinfo_t::restore_from_idb(nec850_t &pm, ea_t ea)
{
  bytevec_t packed;
  if ( pm.helper.getblob_ea(&packed, ea, nec850_t::PUSHINFO_TAG) <= 0 )
    return false;
  memory_deserializer_t mmdsr(packed);
  return deserialize(&mmdsr, ea);
}

//-------------------------------------------------------------------------
// tracked registers (including SPD for SP-based ones)
struct tracked_reg_t
{
  int reg;
  int srcreg; // -1 means that REG is spoiled
  sval_t spd; // only if is_sp_based()
  tracked_reg_t(int _reg, int _srcreg, sval_t _spd = SVAL_MIN)
    : reg(_reg), srcreg(_srcreg), spd(_spd) {}

  bool is_spoiled()  const { return srcreg == -1; }
  bool is_sp_based() const { return srcreg == rSP; }
};
struct reg_vals_t
{
protected:
  qvector<tracked_reg_t> store;
  reglist_t spoiled;
  mutable tracked_reg_t spoiled_tr; // to return from find()

public:
  reg_vals_t() : store(), spoiled(), spoiled_tr(-1, -1)
  {
    // SP is the first register
    store.emplace_back(rSP, rSP, 0);
  }
  const tracked_reg_t *find(int reg) const
  {
    if ( spoiled.has(reg) )
    {
      spoiled_tr.reg = reg;
      return &spoiled_tr;
    }
    for ( const tracked_reg_t &x : store )
      if ( x.reg == reg )
        return &x;
    return nullptr; // REG is the initial register
  }
  bool find_sp_based(sval_t *spd, int reg) const
  {
    const tracked_reg_t *spdp = find(reg);
    if ( spdp == nullptr || !spdp->is_sp_based() )
      return false;
    *spd = spdp->spd;
    return true;
  }
  sval_t get_spd() const
  {
    QASSERT(10521, !store.empty()
            && store[0].reg == rSP
            && store[0].srcreg == rSP);
    return store[0].spd;
  }
  void set(
        int dstreg,
        const tracked_reg_t *src_trp,
        int srcreg = -1,
        sval_t spd = SVAL_MIN)
  {
    if ( src_trp != nullptr )
    {
      srcreg = src_trp->srcreg;
      spd = src_trp->spd;
    }
    if ( srcreg == -1 )
    {
      spoiled.add(dstreg);
      return;
    }
    spoiled.del(dstreg);
    for ( tracked_reg_t &x : store )
    {
      if ( x.reg == dstreg )
      {
        x.srcreg = srcreg;
        x.spd = spd;
        return;
      }
    }
    store.emplace_back(dstreg, srcreg, spd);
  }
  void spoils(const reglist_t &regs) { spoiled.add(regs); }
  void spoils(int reg) { spoiled.add(reg); }
};

//-------------------------------------------------------------------------
struct rh850_frame_t
{
  nec850_t &pm;
  func_t *pfn;
  pushinfo_t psi;             // info about pushed/stored registers
  eavec_t prolog_insns;       // additional prolog instructions

  reg_vals_t tracked_regs;

  // candidates for saving (callee-saved registers + SP, LP)
  /*const*/ reglist_t preserving_regs;

  rh850_frame_t(nec850_t &_pm, func_t *pfn_) : pm(_pm), pfn(pfn_)
  {
    preserving_regs.add_range(rR20, 10);
    preserving_regs.add(rSP);
    preserving_regs.add(rLP);
    // R2, GP, TP, EP can be preserved too
    preserving_regs.add(rR2);
    preserving_regs.add(rGP);
    preserving_regs.add(rTP);
    preserving_regs.add(rEP);
  }
  bool can_be_saved(int reg) const
  {
    return preserving_regs.has(reg)
        || reg == rCTPC
        || reg == rCTPSW;
  }

  bool analyze_frame(bool reanalyze);

  enum track_res_t { PROLOG, STOP, UNKNOWN };
  track_res_t track_stack(const insn_t &insn);
  reglist_t spoils(const insn_t &insn) const
  {
    reglist_t spoiled;
    pm.spoils(&spoiled, insn);
    return spoiled;
  }
  bool prepare_frame(bool reanalyze);

  bool update_spbased_reg(int reg, sval_t spd, ea_t sp_change_ea);
  void save_reg(
        int reg,
        sval_t spd,
        uval_t width,
        const insn_t &insn);

  // compare pushed register by offset from the top frame
  static bool comp_pushreg_by_off(const pushreg_t &l, const pushreg_t &r)
  {
    // remember that SPDs are negative
    // we prefer earlier instructions
    return l.off > r.off || l.off == r.off && l.ea < r.ea;
  }
  // compare pushregs by instruction address
  static bool comp_pushreg_by_ea(const pushreg_t &l, const pushreg_t &r)
  {
    return l.ea < r.ea || l.ea == r.ea && l.off > r.off;
  }
};

//-------------------------------------------------------------------------
// track stack changes,
// collect push info,
// create frame,
// mark prolog instructions
// it returns the success flag
bool rh850_frame_t::analyze_frame(bool reanalyze)
{
  // scan starting instructions
  insn_t insn;
  for ( ea_t ea = pfn->start_ea;
        ea < pfn->end_ea && decode_insn(&insn, ea) > 0;
        ea += insn.size )
  {
    // keep track of the stack modifications
    track_res_t res = track_stack(insn);
    if ( res == PROLOG )
      continue;
    if ( res == STOP )
      break;

    // check spoilage
    reglist_t spoiled = spoils(insn);
    if ( spoiled.has(rSP) )
      break; // unknown stack modification stops the analysis
    // check spoilage of the tracked registers
    tracked_regs.spoils(spoiled);
  }

  // update frame info
  if ( !prepare_frame(reanalyze) )
    return false;

  // sort by EA
  std::sort(psi.begin(), psi.end(), comp_pushreg_by_ea);
  std::sort(prolog_insns.begin(), prolog_insns.end());

  // save pushinfo in the database for future analysis
  if ( pfn->size() != 1 ) // hack from arm_pushinfo_t::analyze_frame
    psi.save_to_idb(pm, pfn->start_ea);

  // mark prolog instructions
  for ( const auto &pr : psi )
    pm.mark_prolog_insn(pr.ea);
  for ( ea_t ea : prolog_insns )
    pm.mark_prolog_insn(ea);
  return true;
}

//-------------------------------------------------------------------------
// track changes of SP and registers derived from it
// track saves to stack area (pushes)
rh850_frame_t::track_res_t rh850_frame_t::track_stack(const insn_t &insn)
{
  if ( is_branch_insn(insn) )
  {
    reglist_t regs;
    uval_t locals;
    special_func_t spf = pm.is_special_func_call(&regs, &locals, insn);
    if ( spf == SPF_SAVE )
    {
      // the register order is opposite to DISPOSE
      uval_t delta = regs.count() * 4;
      // allocate the frame
      sval_t addr = tracked_regs.get_spd() - delta;
      if ( !update_spbased_reg(rSP, addr - locals, insn.ea) )
        return STOP;
      regs.for_each(
        [this, &addr, &insn](int reg)
        {
          save_reg(reg, addr, 4, insn);
          addr += 4;
          return 0;
        } );
      return PROLOG;
    }
    return STOP; // a branch/call stops the prolog analysis
  }

  switch ( insn.itype )
  {
    // the frame setup
    case NEC850_PREPARE_i:
    case NEC850_PREPARE_sp:
      {
        // assert: insn.Op1.type == o_reglist
        reglist_t regs(insn.Op1);
        // assert: insn.Op2.type == o_imm
        uval_t delta = (regs.count() + insn.Op2.value) * 4;
        // allocate the frame
        sval_t addr = tracked_regs.get_spd(); // the initial SPD
        if ( !update_spbased_reg(rSP, addr - delta, insn.ea) )
          return STOP;
        regs.for_each(
          [this, &addr, &insn](int reg)
          {
            addr -= 4;
            save_reg(reg, addr, 4, insn);
            return 0;
          } );
        break;
      }

    case NEC850_ADD:
    case NEC850_ADDI:
    case NEC850_MOVEA:
      {
        if ( insn.Op1.type != o_imm )
          return UNKNOWN;
        // assert: insn.Op2.type == o_reg
        //      && (insn.Op3.type == o_reg || insn.Op3.type == o_void)
        // should know the source register
        sval_t new_spd;
        if ( !tracked_regs.find_sp_based(&new_spd, insn.Op2.reg) )
          return UNKNOWN;
        new_spd += sval_t(insn.Op1.value);
        const op_t &dst = insn.Op3.type == o_void ? insn.Op2 : insn.Op3;
        if ( !update_spbased_reg(dst.reg, new_spd, insn.ea) )
          return STOP; // shrinking the stack area means the end of prolog
      }
      break;

    case NEC850_MOV:
    case NEC850_STSR:
      {
        if ( insn.Op1.type != o_reg )
          return UNKNOWN;
        int srcreg = insn.Op1.reg;
        // assert: insn.Op2.type == o_reg
        int dstreg = insn.Op2.reg;
        // should know the source register
        if ( dstreg == srcreg )
          return PROLOG; // no operation
        const tracked_reg_t *trp = tracked_regs.find(srcreg);
        if ( trp == nullptr || !trp->is_sp_based() )
        {
          if ( dstreg == rSP )
            return STOP; // unknown stack modification stops the analysis
          // remember the register alias (it will be used in save_reg())
          // assert: srcreg != SP because SP is always tracked
          tracked_regs.set(dstreg, trp, srcreg);
          return PROLOG;
        }
        if ( !update_spbased_reg(dstreg, trp->spd, insn.ea) )
          return STOP;
      }
      break;

    // saves (pushes)
    case NEC850_ST_W:   // st.w  lp, 0x44+var_4[sp]
    case NEC850_ST_DW:  // st.dw r18, 0x44+var_8[sp]
    case NEC850_SST_W:  // sst.w lp, 0x18+var_14[ep]
      {
        // assert: insn.Op2.type == o_displ || insn.Op2.type == o_phrase
        sval_t addr; // the initial SPD
        if ( !tracked_regs.find_sp_based(&addr, insn.Op2.phrase) )
          return UNKNOWN;
        if ( insn.Op2.type == o_displ )
          addr += insn.Op2.addr;
        // assert: insn.Op1.type == o_reg
        save_reg(insn.Op1.reg, addr, 4, insn);
        if ( insn.itype == NEC850_ST_DW )
          save_reg(insn.Op1.reg + 1, addr + 4, 4, insn);
        return PROLOG;
      }
      break;

    default:
      return UNKNOWN;
  }
  return PROLOG;
}

//-------------------------------------------------------------------------
/* The typical prolog:
  +-----------------------+  <-- SP on entry
  |GPR vararg save area   |  (optional)
  +-----------------------+
  |LP'                    |  (optional)
  +-----------------------+
  |callee-saved registers |  (optional)
  +-----------------------+
  |local variables        |  (optional)
  +-----------------------+  <-- SP while running
*/
bool rh850_frame_t::prepare_frame(bool reanalyze)
{
  sval_t sp_spd = tracked_regs.get_spd();
  if ( sp_spd >= 0 )
    return true; // no frame

  // verify callee-saved registers
  // registers should be pushed together at the top
  std::sort(psi.begin(), psi.end(), comp_pushreg_by_off);
  sval_t curoff = 0;
  pushreg_t *p = psi.begin();
  // skip possible vararg area
  int arg = rR9;
  while ( arg >= rR6
       && p != psi.end()
       && p->reg == arg
       && p->off + p->width == curoff )
  {
    curoff -= p->width;
    ++p;
    --arg;
  }
  // registers should be pushed together at the top
  while ( p != psi.end()
       && can_be_saved(p->reg)
       && p->off + p->width == curoff )
  {
    curoff -= p->width;
    ++p;
  }
  // erase other registers
  psi.erase(p, psi.end());

  // save frame info
  asize_t frregs = -curoff;
  asize_t frsize = -sp_spd - frregs;
  asize_t frsize_old = pfn->frsize;
  // trying to speed up the analysis:
  // Changing anything among FRSIZE, FRREGS, ARGSIZE results in a full
  // renanalysis of the function, which may take some time.
  // But reducing the frame size alone does not require such reanalysis.
  // If the frame size is larger than required, it will only result in free
  // space in the stack frame.
  if ( reanalyze && frregs == pfn->frregs )
    if ( frsize < frsize_old )
      frsize = frsize_old;
  if ( !set_frame_size(pfn, frsize, frregs, 0) )
    return false;
  return true;
}

//-------------------------------------------------------------------------
bool rh850_frame_t::update_spbased_reg(
        int reg,
        sval_t spd,
        ea_t sp_change_ea)
{
  if ( reg == rSP )
  {
    // shrinking the stack area means the end of prolog
    // (remember that SPDs are negative)
    if ( spd > tracked_regs.get_spd() )
      return false;
    // mark as prolog instruction (stack allocation)
    if ( sp_change_ea != BADADDR )
      prolog_insns.add_unique(sp_change_ea);
  }

  // store the new spd
  tracked_regs.set(reg, nullptr, rSP, spd);
  return true;
}

//-------------------------------------------------------------------------
void rh850_frame_t::save_reg(
        int reg,
        sval_t spd,
        uval_t width,
        const insn_t &insn)
{
  const tracked_reg_t *trp = tracked_regs.find(reg);
  if ( trp != nullptr )
  {
    if ( trp->is_spoiled() )
      return; // do not save spoiled registers
    if ( trp->is_sp_based() && trp->spd != 0 )
      return; // do not save not initial SP
    reg = trp->srcreg; // obtain the initial register
  }

  // the bottom of the stack area
  sval_t sp_spd = tracked_regs.get_spd();
  // SPD should be in the stack area (remember that SPDs are negative)
  if ( spd >= 0 || spd < sp_spd )
    return;

  // stop tracking pushes of the saved register but not SP
  if ( reg != rSP )
    tracked_regs.spoils(reg);

  // save register
  pushreg_t &pr = psi.push_back();
  pr.ea = insn.ea;
  pr.off = spd;
  pr.width = width;
  pr.reg = NEC850_regnum_t(reg);
}

//----------------------------------------------------------------------
// Create a function frame
bool nec850_t::create_func_frame(func_t *pfn, bool reanalyze)
{
  rh850_frame_t frame(*this, pfn);
  return frame.analyze_frame(reanalyze);
}
