/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#include <pro.h>
#include <regfinder.hpp>
#include <frame.hpp> // calc_frame_offset
#include "necv850.hpp"
#include "ins.hpp"
//lint -esym{1746,flow} non-reference parameter could be reference to const

//-------------------------------------------------------------------------
struct nec850_reg_finder_t : public reg_finder_t
{
  nec850_reg_finder_t(const procmod_t &_pm) : reg_finder_t(_pm) {}

protected:
  virtual rvi_t handle_well_known_regs(
        flow_t flow,
        rfop_t op,
        bool is_func_start) const override;
  virtual bool is_move_insn(
        move_desc_t *move_desc,
        const rfop_t &op,
        const insn_t &insn) override;
  virtual bool emulate_insn(
        rvi_t *value,
        const rfop_t &op,
        const insn_t &insn,
        flow_t flow) override;
  //virtual bool is_mem_readonly(ea_t ea) const override;
  virtual int get_sp_reg(ea_t) const override { return rSP; }
  virtual bool is_funcwide_reg(ea_t, int reg) const override
  {
    return reg == rSP || reg == rGP;
  }
  virtual bool can_track_op(
        op_t *op,
        const insn_t &insn,
        func_t *pfn) const override;
};

//-------------------------------------------------------------------------
// processor specific methods
//-------------------------------------------------------------------------
reg_value_info_t nec850_reg_finder_t::handle_well_known_regs(
        flow_t flow,
        rfop_t op,
        bool /*is_func_start*/) const
{
  ea_t ea = flow.actual_ea();
  if ( op.is_reg(rZERO) )
    return rvi_t::make_num(0, ea);
  auto &_pm = (const nec850_t &)pm;
  if ( op.is_reg(rGP) && _pm.g_gp_ea != BADADDR )
    return rvi_t::make_num(_pm.g_gp_ea, ea, reg_value_def_t::LIKE_GOT);
  return rvi_t();
}

//-------------------------------------------------------------------------
static bool get_load_insn_signness(uint16 itype)
{
  switch ( itype )
  {
    case NEC850_LD_B:
    case NEC850_LD_H:
    case NEC850_LD_W:
    case NEC850_SLD_B:
    case NEC850_SLD_H:
    case NEC850_SLD_W:  return true;
    case NEC850_LD_BU:
    case NEC850_LD_HU:
    case NEC850_SLD_BU:
    case NEC850_SLD_HU: return false;
    default: INTERR(10464);
  }
}

//-------------------------------------------------------------------------
bool nec850_reg_finder_t::is_move_insn(
        move_desc_t *move,
        const rfop_t &,
        const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NEC850_MOV:
      if ( insn.Op1.type != o_reg )
        break;
      move->dst_op = &insn.Op2;
      move->src_op = &insn.Op1;
      return true;
    case NEC850_LD_B:
    case NEC850_LD_BU:
    case NEC850_LD_H:
    case NEC850_LD_HU:
    case NEC850_LD_W:
    case NEC850_SLD_B:
    case NEC850_SLD_BU:
    case NEC850_SLD_H:
    case NEC850_SLD_HU:
    case NEC850_SLD_W:
      move->dst_op = &insn.Op2;
      move->src_op = &insn.Op1;
      move->is_signed = get_load_insn_signness(insn.itype);
      return true;
    case NEC850_ST_B:
    case NEC850_ST_H:
    case NEC850_ST_W:
    case NEC850_SST_B:
    case NEC850_SST_H:
    case NEC850_SST_W:
      move->dst_op = &insn.Op2;
      move->src_op = &insn.Op1;
      return true;
  }
  return false;
}

//-------------------------------------------------------------------------
bool nec850_reg_finder_t::emulate_insn(
        rvi_t *value,
        const rfop_t &op,
        const insn_t &insn,
        flow_t flow)
{
  if ( op.is_stkvar() )
  {
    // there are no memory modification insns in RISC processors
    // so we just check if the INSN spoils the operand or not
    if ( may_modify_stkvar(op, insn) )
    {
      value->set_unkinsn(insn);
      return true;
    }
    return false; // continue tracking
  }

  // assert: op.is_reg()
  int reg = op.get_reg();
  auto &_pm = (const nec850_t &)pm;
  // Note! there may be a recursive call of find()
  // spoils() calls is_call_insn()
  // it may call find_lp_definition()
  // it calls find_rvi()
  if ( !_pm.spoils(insn, reg) )
    return false;

  // assert: op->get_width() <= pm.eah().ea_size
  switch ( insn.itype )
  {
    case NEC850_MOV:
      if ( insn.Op1.type != o_imm )
        break;
      value->set_num(insn.Op1.value, insn);
      return true;
    case NEC850_MOVEA:
    case NEC850_ADDI:
    case NEC850_ADD:
    case NEC850_SUB:
    case NEC850_SHL:
      {
        rvi_t::arith_op_t aop = rvi_t::ADD;
        if ( insn.itype == NEC850_SUB )
          aop = rvi_t::SUB;
        else if ( insn.itype == NEC850_SHL )
          aop = rvi_t::SLL;
        emulate_binary_op(value, aop, insn.Op2, insn.Op1, insn, flow);
        return true;
      }
    case NEC850_MOVHI:
      {
        rvi_t::arith_op_t aop = rvi_t::ADD;
        op_t imm;
        pm.make_op_imm(&imm, (int32)(insn.Op1.value << 16));
        emulate_binary_op(value, aop, insn.Op2, imm, insn, flow);
        return true;
      }
    case NEC850_LD_B:
    case NEC850_LD_BU:
    case NEC850_LD_H:
    case NEC850_LD_HU:
    case NEC850_LD_W:
    case NEC850_SLD_B:
    case NEC850_SLD_BU:
    case NEC850_SLD_H:
    case NEC850_SLD_HU:
    case NEC850_SLD_W:
      {
        calc_op_addr(value, insn.Op1, insn, flow);
        bool is_signed = get_load_insn_signness(insn.itype);
        int width = get_dtype_size(insn.Op1.dtype);
        emulate_mem_read(value, *value, width, is_signed, insn);
        return true;
      }
    case NEC850_JARL:
      if ( insn.Op1.type == o_near && insn.Op2.is_reg(reg) )
      {
        // jarl nextaddr, r2 == jump (w/o flow)
        ea_t nextaddr = insn.ea + insn.size;
        if ( to_ea(insn.cs, insn.Op1.addr) == nextaddr )
        {
          value->set_num(nextaddr, insn, reg_value_def_t::PC_BASED);
          return true;
        }
      }
      break;
  }

  // found an unsupported change of REG
  value->set_unkinsn(insn);
  return true;
}

#if 0
//-------------------------------------------------------------------------
bool nec850_reg_finder_t::is_mem_readonly(ea_t ea) const
{
  if ( inf_get_filetype() != f_ELF )
    return false;
  segment_t *seg = getseg(ea);
  if ( seg == nullptr )
    return false;
  // check by names
  qstring segname;
  if ( get_segm_name(&segname, seg) <= 0 )
    return false;
  // we assume that the following segments are readonly
  return  segname == ".got"
       || segname == ".text"
       || segname == ".rodata"
       || segname == ".got.plt"
       || segname == ".plt"
       || segname == ".init"
       || segname == ".fini"
       || segname == ".preinit_array"
       || segname == ".init_array"
       || segname == ".fini_array";
}
#endif

//-------------------------------------------------------------------------
bool nec850_reg_finder_t::can_track_op(
        op_t *op,
        const insn_t &,
        func_t *) const
{
  switch ( op->type )
  {
    case o_reg:
      return op->reg <= rR31;
    case o_displ:
      return op->phrase == rSP;
    default:
      return false;
  }
}

//-------------------------------------------------------------------------
// functions that use nec850_reg_finder_t
//-------------------------------------------------------------------------
nec850_reg_finder_t *alloc_reg_finder(const nec850_t &pm)
{
  return new nec850_reg_finder_t(pm);
}

//-------------------------------------------------------------------------
void free_reg_finder(nec850_reg_finder_t *rf)
{
  delete rf;
}

//-------------------------------------------------------------------------
void nec850_t::invalidate_reg_cache(ea_t to, ea_t from) const
{
  if ( reg_finder != nullptr )
    reg_finder->invalidate_cache(to, from);
}

//-------------------------------------------------------------------------
void nec850_t::invalidate_reg_cache() const
{
  if ( reg_finder != nullptr )
    reg_finder->invalidate_cache();
}

//-------------------------------------------------------------------------
bool nec850_t::find_regval(uval_t *value, ea_t ea, int reg) const
{
  if ( reg == rSP || reg_finder == nullptr )
    return false;
  auto rfop = reg_finder_op_t::make_reg(*this, reg);
  return reg_finder->find_const(value, ea, rfop);
}

//-------------------------------------------------------------------------
bool nec850_t::find_rvi(
        reg_value_info_t *rvi,
        ea_t ea,
        int reg,
        int max_depth) const
{
  if ( reg == rSP || reg_finder == nullptr )
    return false;
  auto rfop = reg_finder_op_t::make_reg(*this, reg);
  *rvi = reg_finder->find(ea, rfop, max_depth);
  return true;
}

//-------------------------------------------------------------------------
bool nec850_t::find_sp_value(sval_t *spval, ea_t ea, int reg) const
{
  if ( reg_finder == nullptr )
    return false;
  return reg_finder->find_spd(spval, ea, reg);
}
