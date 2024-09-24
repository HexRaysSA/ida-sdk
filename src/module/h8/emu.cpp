/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8.hpp"
#include <frame.hpp>
#include <segregs.hpp>
#include <jumptable.hpp>

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n, flags64_t F)
{
  set_immd(insn.ea);
  if ( is_defarg(F, n) )
    return;
  switch ( insn.itype )
  {
    case H8_shal:
    case H8_shar:
    case H8_shll:
    case H8_shlr:
    case H8_rotl:
    case H8_rotr:
    case H8_rotxl:
    case H8_rotxr:
      if ( n == 0 )
        op_dec(insn.ea, n);
      break;
    case H8_and:
    case H8_or:
    case H8_xor:
      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
inline bool issp(int x)
{
  return x == R7 || x == ER7;
}

inline bool isbp(int x)
{
  return x == R6 || x == ER6;
}

//----------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &x)
{
  return OP_SP_ADD
       | ((x.type == o_displ || x.type == o_phrase) && issp(x.phrase)
        ? OP_SP_BASED
        : OP_FP_BASED);
}

//----------------------------------------------------------------------
static void add_stkpnt(const insn_t &insn, ssize_t value)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return;

  if ( value & 1 )
    value++;

  add_auto_stkpnt(pfn, insn.ea+insn.size, value);
}

//----------------------------------------------------------------------
static const int RegBySize[8][3] =
{
  { R0L, R0, ER0 },
  { R1L, R1, ER1 },
  { R2L, R2, ER2 },
  { R3L, R3, ER3 },
  { R4L, R4, ER4 },
  { R5L, R5, ER5 },
  { R6L, R6, ER6 },
  { R7L, R7, ER7 },
};

inline op_dtype_t get_regsize(int reg)
{
  switch ( reg / 8 )
  {
    case 0:   // Rn
    case 1:   // En
      return dt_word;
    case 2:   // RnH
    case 3:   // RnL
      return dt_byte;
    case 4:   // ERn
      return dt_dword;
    default:  // not general registers
      return dt_void;
  }
}

inline int cvt_to_wholereg(int reg, op_dtype_t dtype = dt_word)
{
  if ( dtype > dt_dword )
    return -1;
  return RegBySize[reg & 7][size_t(dtype)]; //lint !e571 Suspicious cast
}

inline bool is_high_bits_reg(int reg)
{
  switch ( reg / 8 )
  {
    case 1:   // En
    case 2:   // RnH
      return true;
    default:
      return false;
  }
}

//------------------------------------------------------------------------
// a) is_same_reg(R0, R0L) -> true
// b) is_same_reg(R0, R0H) -> false
inline bool is_same_reg(int r1, int r2)
{
  op_dtype_t dt1 = get_regsize(r1);
  op_dtype_t dt2 = get_regsize(r2);
  // assert: dt1 != dt_void && dt2 != o_void
  if ( dt1 < dt2 )
    r2 = cvt_to_wholereg(r2, dt1);
  else if ( dt1 > dt2 )
    r1 = cvt_to_wholereg(r1, dt2);
  // a) R0L == R0L; b) R0L != R0H
  return r1 == r2;
}

//-------------------------------------------------------------------------
// a) regs_have_common_bits(R0, R0L) -> true
// b) regs_have_common_bits(R0, R0H) -> true
// b) regs_have_common_bits(E0, R0H) -> false
inline bool regs_have_common_bits(
        int r1,
        int r2,
        op_dtype_t dt1,
        op_dtype_t dt2)
{
  // assert: dt1 != dt_void && dt2 != o_void
  if ( dt1 < dt2 )
    r1 = cvt_to_wholereg(r1, dt2);
  else if ( dt1 > dt2 )
    r2 = cvt_to_wholereg(r2, dt1);
  // a) R0 == R0; b) R0 == R0; c) E0 != R0
  return r1 == r2;
}
inline bool regs_have_common_bits(int r1, int r2)
{
  return regs_have_common_bits(r1, r2, get_regsize(r1), get_regsize(r2));
}
inline bool regs_have_common_bits(int r1, int r2, op_dtype_t dt1)
{
  return regs_have_common_bits(r1, r2, dt1, get_regsize(r2));
}

//-------------------------------------------------------------------------
// does the instruction spoil the register?
#define PROC_MAXCHGOP 3
bool h8_t::spoils(const insn_t &insn, int reg) const
{
  op_dtype_t dtype = get_regsize(reg);
  switch ( insn.itype )
  {
    case H8_bsr:
    case H8_bsrbc:
    case H8_bsrbs:
    case H8_jsr:
    case H8_trapa:
      return true;  // TODO take in account ABI
    case H8_eepmov:
    case H8_movmd:
    case H8_movsd:
      return true;  // TODO check R4/L, ER5, ER6
    case H8_push:
    case H8_pop:
    case H8_rts:
    case H8_rte:
    case H8_rtsl:
    case H8_rtel:
      if ( regs_have_common_bits(reg, SP, dtype, dt_word) )
        return true;
      break;
  }
  uint32 feature = insn.get_canon_feature(ph);
  if ( feature == 0 )
    return false;
  for ( int i = 0; i < PROC_MAXCHGOP; ++i )
  {
    if ( !has_cf_use(feature, i) )
      continue;
    const op_t &x = insn.ops[i];
    if ( x.type == o_phrase
      && x.phtype != ph_normal
      && regs_have_common_bits(reg, x.phrase, dtype) )
    {
      return true;
    }
  }
  for ( int i = 0; i < PROC_MAXCHGOP; ++i )
  {
    if ( !has_cf_chg(feature, i) )
      continue;
    const op_t &x = insn.ops[i];
    if ( x.type == o_reg && regs_have_common_bits(reg, x.reg, dtype)
      || x.type == o_reglist )  // TODO check reg in list
    {
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// does the instruction spoil the flags?
static bool spoils_flags(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case H8_ldm:
    case H8_stm:
    case H8_movab:
    case H8_movaw:
    case H8_eepmov:
    case H8_movmd:
    case H8_movsd:
      return false;

    case H8_adds:
    case H8_subs:
    case H8_mulxu:
    case H8_mulu:
    case H8_muluu:
    case H8_mac:
    case H8_clrmac:
    case H8_ldmac:
      return false;

    case H8_bset:
    case H8_bclr:
    case H8_bnot:
    case H8_bsetne:
    case H8_bseteq:
    case H8_bclrne:
    case H8_bclreq:
    case H8_bst:
    case H8_bist:
    case H8_bstz:
    case H8_bistz:
    case H8_bfld:
    case H8_bfst:
      return false;

    case H8_brabs:
    case H8_brabc:
    case H8_bra:
    case H8_brn:
    case H8_bhi:
    case H8_bls:
    case H8_bcc:
    case H8_bcs:
    case H8_bne:
    case H8_beq:
    case H8_bvc:
    case H8_bvs:
    case H8_bpl:
    case H8_bmi:
    case H8_bge:
    case H8_blt:
    case H8_bgt:
    case H8_ble:
    case H8_bras:
    case H8_jmp:
    case H8_rts:
    case H8_rtsl:
      return false;

    case H8_ldc:
    case H8_andc:
    case H8_orc:
    case H8_xorc:
      return insn.Op2.is_reg(CCR);
    case H8_stc:
    case H8_sleep:
    case H8_nop:
      return false;

    default:
      return true;
  }
}

//----------------------------------------------------------------------
bool h8_t::get_op_value(uval_t *value, const insn_t &_insn, const op_t &x) const
{
  if ( x.type == o_imm )
  {
    *value = x.value;
    return true;
  }

  if ( x.type != o_reg
    && (x.type != o_displ
     || x.displtype != dt_normal && x.displtype != dt_regidx)
    && x.type != o_phrase
    && x.type != o_pcidx )
  {
    return false;
  }
  uint16 reg = x.reg;

  bool ok = false;
  insn_t insn;
  ea_t next_ea = _insn.ea;
  while ( (!has_xref(get_flags(next_ea)) || get_first_cref_to(next_ea) == BADADDR)
       && decode_prev_insn(&insn, next_ea) != BADADDR )
  {
    if ( insn.itype == H8_mov
      && insn.Op1.type == o_imm
      && insn.Op2.type == o_reg
      && insn.Op2.reg  == reg )
    {
      *value = insn.Op1.value;
      ok = true;
      break;
    }

    if ( spoils(insn, reg) )
      break;

    next_ea = insn.ea;
  }

  if ( ok )
  {
    if ( x.type == o_phrase )
    {
      if ( x.phtype == ph_pre_inc )
        *value += 1;
      else if ( x.phtype == ph_pre_dec )
        *value -= 1;
    }
    else if ( x.type == o_displ )
    {
      if ( x.displtype == dt_regidx )
      {
        if ( (_insn.auxpref == aux_long) != 0 )
          *value <<= 2;
        else if ( (_insn.auxpref == aux_word) != 0 )
          *value <<= 1;
      }
      *value += x.addr;
    }
  }
  return ok;
}

//----------------------------------------------------------------------
void h8_t::trace_sp(const insn_t &insn) const
{
  // @sp++
  if ( insn.Op1.type == o_phrase
    && issp(insn.Op1.reg)
    && insn.Op1.phtype == ph_post_inc )
  {
    ssize_t size = get_dtype_size(insn.Op2.dtype);
    if ( insn.Op2.type == o_reglist )
      size *= insn.Op2.nregs;
    add_stkpnt(insn, size);
    return;
  }

  // @--sp
  if ( insn.Op2.type == o_phrase
    && issp(insn.Op2.reg)
    && insn.Op2.phtype == ph_pre_dec )
  {
    ssize_t size = get_dtype_size(insn.Op1.dtype);
    if ( insn.Op1.type == o_reglist )
      size *= insn.Op1.nregs;
    add_stkpnt(insn, -size);
    return;
  }

  uval_t v;
  switch ( insn.itype )
  {
    case H8_add:
    case H8_adds:
      if ( !issp(insn.Op2.reg) )
        break;
      if ( get_op_value(&v, insn, insn.Op1) )
        add_stkpnt(insn, v);
      break;
    case H8_sub:
    case H8_subs:
      if ( !issp(insn.Op2.reg) )
        break;
      if ( get_op_value(&v, insn, insn.Op1) )
        add_stkpnt(insn, 0-v);
      break;
    case H8_push:
      add_stkpnt(insn, 0-get_dtype_size(insn.Op1.dtype));
      break;
    case H8_pop:
      add_stkpnt(insn, get_dtype_size(insn.Op1.dtype));
      break;
  }
}

//----------------------------------------------------------------------
void h8_t::add_code_xref(const insn_t &insn, const op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( has_insn_feature(insn.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  insn.add_cref(ea, x.offb, ftype);
}

//----------------------------------------------------------------------
void h8_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  uval_t op_value;
  flags64_t F = get_flags(insn.ea);
  switch ( x.type )
  {
    case o_reg:
    case o_reglist:
      return;

    case o_imm:
      QASSERT(10094, isload);
      process_immediate_number(insn, x.n, F);
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, OOFS_IFSIGN|OOFW_IMM);
      break;

    case o_phrase:
      if ( is_forced )
        break;
      if ( !is_defarg(F, x.n) && get_op_value(&op_value, insn, x) )
      {
        op_offset(insn.ea, x.n, REF_OFF32 | REFINFO_NOBASE, BADADDR, op_value);
      }
      if ( op_adds_xrefs(F, x.n) )
      {
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, get_displ_outf(x, F));
        if ( ea != BADADDR )
        {
          insn.create_op_data(ea, x);
        }
      }
      break;

    case o_displ:
      if ( is_forced )
        break;
      if ( op_adds_xrefs(F, x.n) )
      {
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, get_displ_outf(x, F));
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
        if ( (x.flags & OF_OUTER_DISP) != 0 )
        {
          ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, OOF_OUTER | OOF_SIGNED | OOFW_32);
          if ( ea != BADADDR )
            insn.create_op_data(ea, x.offo, x.szfl & idx_byte ? dt_byte : dt_word);
        }
      }
      // create stack variables if required
      if ( may_create_stkvars() && !is_defarg(F, x.n) )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr
          && (issp(x.phrase)
           || isbp(x.phrase) && (pfn->flags & FUNC_FRAME) != 0) )
        {
          if ( insn.create_stkvar(x, x.addr, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, x.n);
        }
      }
      break;
    case o_near:
      add_code_xref(insn, x, calc_mem(insn, x.addr));
      break;
    case o_mem:
      {
        ea_t ea = x.memtype == mem_sbr
                ? calc_mem_sbr_based(insn, x.addr)
                : calc_mem(insn, x.addr);
        if ( !is_mapped(ea) )
        {
          const char *name = find_sym(ea);
          if ( name != nullptr && name[0] != '\0' )
            break;      // address not here
        }
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
        if ( x.memtype == mem_ind || x.memtype == mem_vec7 )
        {
          ssize_t size = get_dtype_size(x.dtype);
          flags64_t eaF = get_flags(ea);
          if ( (is_word(eaF) || is_dword(eaF))
            && (!is_defarg0(eaF) || is_off0(eaF)) )
          {
            ea_t target = calc_mem(
                    insn,
                    size == 2 ? get_word(ea) : trim_ea_branch(get_dword(ea)));
            if ( is_mapped(target) )
              add_code_xref(insn, x, target);
            if ( !is_off0(eaF) )
              op_plain_offset(ea, 0, calc_mem(insn, 0));
          }
          break;
        }
      }
      break;
    case o_pcidx:
      {
        uval_t value;
        bool ok = get_op_value(&value, insn, x);
        if ( ok )
        {
          ea_t ea = insn.ea + insn.size + (value << 1);
          add_code_xref(insn, x, ea);
        }
      }
      break;
    default:
      INTERR(10095);
  }
}


//----------------------------------------------------------------------
void h8_t::check_base_reg_change_value(const insn_t &insn) const
{
  if ( insn.itype == H8_ldc
    && insn.Op2.type == o_reg
    && (insn.Op2.reg == SBR || insn.Op2.reg == VBR) )
  {
    sel_t value = BADSEL;
    bool ok = get_op_value(&value, insn, insn.Op1);
    split_sreg_range(insn.ea + insn.size, insn.Op2.reg, value, ok ? SR_autostart : SR_user);
  }
}

//----------------------------------------------------------------------
int h8_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, flag3, true);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, flag3, false);

//
//      Check for SBR, VBR change value
//
  if ( is_h8sx() )
    check_base_reg_change_value(insn);

//
//      Determine if the next instruction should be executed
//
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);


//
//      Handle SP modifications
//
  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(insn.ea);     // recalculate SP register for the next insn
    else
      trace_sp(insn);
  }

  return 1;
}

//----------------------------------------------------------------------
int is_jump_func(const func_t * /*pfn*/, ea_t *jump_target)
{
  *jump_target = BADADDR;
  return 0; // means "don't know"
}

//----------------------------------------------------------------------
int may_be_func(const insn_t &insn) // can a function start here?
                                    // returns: probability 0..100
                                    // 'insn' structure is filled upon the entrace
                                    // the idp module is allowed to modify 'insn'
{
  if ( insn.itype == H8_push && isbp(insn.Op1.reg) )
    return 100;  // push.l er6
  if ( insn.itype == H8_push && insn.Op1.reg == ER3 )
    return 100;  // push.l er3
  if ( insn.itype == H8_push && insn.Op1.reg == R3 )
    return 100;  // push.w r3
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(const insn_t &insn, int /*nocrefs*/)
{
  if ( insn.itype == H8_nop )
  {
    for ( int i=0; i < 8; i++ )
      if ( get_word(insn.ea-i*2) != 0 )
        return 1;
    return 0; // too many nops in a row
  }
  return 1;
}

//----------------------------------------------------------------------
int idaapi h8_is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case H8_nop:
      break;
    case H8_mov:
    case H8_or:
      if ( insn.Op1.type == insn.Op2.type && insn.Op1.reg == insn.Op2.reg )
        break;
    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
bool idaapi is_return_insn(const insn_t &insn)
{
  return insn.itype == H8_rte
      || insn.itype == H8_rts
      || insn.itype == H8_rtel
      || insn.itype == H8_rtsl;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)
{
  if ( pfn->frame == BADNODE )
  {
    size_t regs = 0;
    ea_t ea = pfn->start_ea;
    bool bpused = false;
    insn_t insn;
    while ( ea < pfn->end_ea )                 // skip all pushregs
    {                                         // (must test that ea is lower
                                              // than pfn->end_ea)
      decode_insn(&insn, ea);
      ea += insn.size;
      switch ( insn.itype )
      {
        case H8_nop:
          continue;
        case H8_push:
          regs += get_dtype_size(insn.Op1.dtype);
          continue;
        case H8_stm:
          if ( !issp(insn.Op2.reg) )
            break;
          regs += insn.Op1.nregs * get_dtype_size(insn.Op1.dtype);
          continue;
        case H8_mov:  // mov.l er6, sp
          if ( insn.Op1.type == o_reg && issp(insn.Op1.reg)
            && insn.Op2.type == o_reg && isbp(insn.Op2.reg) )
          {
            bpused = true;
          }
          break;
        default:
          break;
      }
      break;
    }
    if ( regs != 0 || bpused )
    {
      setflag((uint32 &)pfn->flags, FUNC_FRAME, bpused);
      return add_frame(pfn, 0, (ushort)regs, 0);
    }
  }
  return false;
}

//----------------------------------------------------------------------
int h8_t::h8_get_frame_retsize(const func_t *)
{
  return advanced() ? 4 : 2;
}

//-------------------------------------------------------------------------
inline bool is_clear_reg_insn(const insn_t &insn)
{
  return (insn.itype == H8_sub || insn.itype == H8_xor)
      && insn.Op2.type == o_reg
      && insn.Op1.is_reg(insn.Op2.reg)
      || insn.itype == H8_mov
      && insn.Op2.type == o_reg
      && insn.Op1.is_imm(0);
}

//-------------------------------------------------------------------------
struct h8_jump_pattern_t : public jump_pattern_t
{
protected:
  enum { rA, rC };

  h8_t &pm;
  op_dtype_t jump_displ_size;
  int shift; //lint !e958 padding is required
  int sub_lowcase2_njpi;        // njpi of tied 'sub.b #low minv, rA'
  op_dtype_t sub_lowcase_size;  // too pass to jpi_sub_lowcase_tied()

  h8_jump_pattern_t(
          procmod_t *_pm,
          switch_info_t *_si,
          const char (*_depends)[4],
          int sub_lowcase2_njpi_)
    : jump_pattern_t(_si, _depends, rC),
      pm(*(h8_t*)_pm),
      jump_displ_size(dt_void),
      shift(-1),
      sub_lowcase2_njpi(sub_lowcase2_njpi_),
      sub_lowcase_size(dt_void)
  {
    modifying_r32_spoils_r64 = false;
    non_spoiled_reg = rA;
  }

public:
  virtual bool equal_ops(const op_t &x, const op_t &y) const override;
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  virtual void check_spoiled(tracked_regs_t *_regs) const override;
  virtual op_dtype_t extend_dtype(const op_t &op) const override;

  bool finish(int ld_njpi);

protected:
  static inline bool optype_supported(const op_t &x);
  void h8_track(int reg, int r_i) { track(reg, r_i, get_regsize(reg)); }

  bool jpi_ld(int shl_njpi);
  bool jpi_shl();
  bool jpi_cmp_ncases_condjump(int body_njpi);
  bool jpi_sub_lowcase();
  bool jpi_sub_lowcase_tied() const;

  // helpers
  bool jpi_add_sub(
        uval_t *value,
        op_dtype_t *add_size,
        int tied_jpi);
  bool jpi_add_sub_tied(uval_t *value, op_dtype_t add_size) const;
  bool jpi_cmp_ncases();
  bool jpi_condjump(int body_njpi);

  static inline reftype_t get_off_reftype(op_dtype_t dtype);
  static inline reftype_t get_lo_reftype(op_dtype_t dtype);
  static inline reftype_t get_hi_reftype(op_dtype_t dtype);
};

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::equal_ops(const op_t &x, const op_t &y) const
{
  if ( x.type != y.type )
    return false;
  // ignore difference in the data size of registers
  switch ( x.type )
  {
    case o_void:
      // consider spoiled values as not equal
      return false;
    case o_reg:
      // the data size of registers will be taken into account as the
      // operand size
      return is_same_reg(x.reg, y.reg);
    case o_displ:
      return x.phrase == y.phrase
          && x.addr == y.addr
          && x.displtype == y.displtype;
    case o_phrase:
      return x.phrase == y.phrase && x.phtype == y.phtype;
    case o_mem:
      return x.addr == y.addr && x.memtype == y.memtype;
    case o_condjump:
      // we do not track the condition flags
      return true;
  }
  return false;
}

//-------------------------------------------------------------------------
inline bool h8_jump_pattern_t::optype_supported(const op_t &x)
{
  // we can work with the following types only
  return x.type == o_reg && x.reg < MACL
      || x.type == o_displ
      && (x.displtype == dt_normal || x.displtype == dt_regidx)
      || x.type == o_phrase && x.phtype == ph_normal
      || x.type == o_mem
      && (x.memtype == mem_sbr || x.memtype == mem_direct);
}

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::handle_mov(tracked_regs_t &_regs)
{
  // some binaries use 'sub.b r0h, r0h' instead of 'extu.w r0'
  if ( is_clear_reg_insn(insn) && is_high_bits_reg(insn.Op2.reg) )
  {
    const op_t &x = insn.Op2;
    op_t src;
    src.type  = o_reg;
    src.dtype = x.dtype;
    src.reg   = cvt_to_wholereg(x.reg, src.dtype);
    // assert: src.reg != x.reg because !is_high_bits_reg(src.reg)
    op_t dst;
    dst.type  = o_reg;
    dst.dtype = op_dtype_t(x.dtype + 1);
    dst.reg   = cvt_to_wholereg(x.reg, dst.dtype);
    return set_moved(dst, src, _regs);
  }

  op_dtype_t dst_dtype = dt_void;
  op_dtype_t src_dtype = dt_void;
  switch ( insn.itype )
  {
    case H8_mov:
      // some binaries use the following pattern
      //    sub.b   r0h, r0h
      //    mov.b   @(jpt_XXX:16,r0), r0l
      // instead of
      //    mov.b   @(jpt_XXX:16,r0), r0l
      //    sub.b   r0h, r0h
      // or
      //    mov.b   @(jpt_XXX:16,r0), r0l
      //    extu.w  r0
      dst_dtype = extend_dtype(insn.Op2);
      break;
    case H8_extu:
      // assert: insn.Op1.type == o_imm
      if ( insn.Op2.dtype == dt_word )
        src_dtype = dt_byte;  // extu.w r0
      else if ( insn.Op1.value == 1 )
        src_dtype = dt_word;  // extu.l er0
      else if ( insn.Op1.value == 2 )
        src_dtype = dt_byte;  // extu.l #2, er0
      else
        return false;
      break;
    default:
      return false;
  }
  bool is_mov_insn = src_dtype == dt_void;
  if ( !optype_supported(insn.Op2)
    || is_mov_insn && !optype_supported(insn.Op1) )
  {
    return false;
  }
  return set_moved(insn.Op2,
                   is_mov_insn ? insn.Op1 : insn.Op2,
                   _regs,
                   dst_dtype,
                   src_dtype);
}

//-------------------------------------------------------------------------
void h8_jump_pattern_t::check_spoiled(tracked_regs_t *__regs) const
{
  tracked_regs_t &_regs = *__regs;
  for ( uint i = 0; i < _regs.size(); ++i )
  {
    const op_t &x = _regs[i];
    if ( x.type == o_reg && pm.spoils(insn, x.reg)
      || x.type == o_condjump && spoils_flags(insn) )
    {
      set_spoiled(&_regs, x);
    }
  }
  check_spoiled_not_reg(&_regs, PROC_MAXCHGOP);
}

//-------------------------------------------------------------------------
op_dtype_t h8_jump_pattern_t::extend_dtype(const op_t &op) const
{
  if ( op.type == o_reg && (op.dtype == dt_byte || op.dtype == dt_word) )
  {
    insn_t prev;
    if ( decode_prev_insn(&prev, insn.ea) != BADADDR
      && is_clear_reg_insn(prev) )
    {
      // sub.w r0, r0 | mov.b ..., r0l
      if ( prev.Op2.dtype > op.dtype
        && cvt_to_wholereg(prev.Op2.reg, op.dtype) == op.reg )
      {
        return prev.Op1.dtype;
      }
      // sub.b r0h, r0h | mov.b ..., r0l
      if ( prev.Op2.dtype == op.dtype
        && is_high_bits_reg(prev.Op2.reg)
        && cvt_to_wholereg(prev.Op2.reg) == cvt_to_wholereg(op.reg) )
      {
        return op_dtype_t(prev.Op1.dtype + 1);
      }
    }
  }
  return op.dtype;
}

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::finish(int ld_njpi)
{
  if ( eas[ld_njpi] != BADADDR && jump_displ_size != dt_void )
  {
    reftype_t rtype = get_off_reftype(jump_displ_size);
    op_offset(eas[ld_njpi], 0, rtype);
  }
  if ( eas[sub_lowcase2_njpi - 1] != BADADDR )
    si->lowcase = 0-si->lowcase;
  return true;
}

//-------------------------------------------------------------------------
// mov.X @(jumps:size,rA'), rA
bool h8_jump_pattern_t::jpi_ld(int shl_njpi)
{
  if ( insn.itype != H8_mov
    || insn.Op1.type != o_displ
    || insn.Op1.displtype != dt_normal && insn.Op1.displtype != dt_regidx
    || !is_equal(insn.Op2, rA) )
  {
    return false;
  }
  shift = insn.Op2.dtype; // shift == log2size(insn.Op2)
  si->set_jtable_element_size(1 << shift);
  if ( insn.Op1.displtype == dt_regidx )
    shift = 0;  // register is shifted by the address mode
  if ( shift == 0 )
    skip[shl_njpi] = true; // no need for an additional shift
  h8_track(insn.Op1.phrase, rA);
  si->jumps = insn.Op1.addr;
  if ( (insn.Op1.szfl & disp_16) != 0 )
    jump_displ_size = dt_word;
  else if ( (insn.Op1.szfl & disp_32) != 0 )
    jump_displ_size = dt_dword;
  return true;
}

//-------------------------------------------------------------------------
// add.X rA, rA | shll.X #shift, rA
bool h8_jump_pattern_t::jpi_shl()
{
  if ( shift <= 0 || !is_equal(insn.Op2, rA) )
    return false;
  if ( insn.itype == H8_shll )
  {
    if ( !insn.Op1.is_imm(shift) )
      return false;
    // continue to track rA
  }
  else if ( insn.itype == H8_add )
  {
    if ( shift != 1
      || insn.Op1.type != o_reg
      || !insn.Op2.is_reg(insn.Op1.reg) )
    {
      return false;
    }
    // continue to track rA
  }
  else
  {
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::jpi_cmp_ncases_condjump(int body_njpi)
{
  // assert: !is_spoiled(rA) because rA is non spoiled register

  // look for the conditional jump
  if ( jpi_condjump(body_njpi) )
    return false;

  // the condition between 'cmp' and the conditional jump should not be
  // spoiled
  if ( is_spoiled(rC) )
    return false;

  // look for the 'cmp' insn
  if ( jpi_cmp_ncases() )
  {
    op_t &op = regs[rC];
    // assert: op.type == o_condjump
    if ( (op.value & cc_inc_ncases) != 0 )
      ++si->ncases;
    si->defjump = op.specval;
    si->set_expr(insn.Op2.reg, insn.Op2.dtype);
    return true;
  }
  return false;
}

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::jpi_sub_lowcase()
{
  // continue to track rA
  return jpi_add_sub(&si->lowcase, &sub_lowcase_size, sub_lowcase2_njpi);
}

//-------------------------------------------------------------------------
bool h8_jump_pattern_t::jpi_sub_lowcase_tied() const
{
  // continue to track rA
  return jpi_add_sub_tied(&si->lowcase, sub_lowcase_size);
}

//-------------------------------------------------------------------------
// add.b  #value, rAl/h | sub.b  #value, rAl/h
// add.w  #value, rA/eA | sub.w  #value, rA/eA
// add.l  #value, erA   | sub.l  #value, erA
// inc.b  rAl/h         | dec.b  rAl/h
// inc.w  #value, rA/eA | dec.w  #value, rA/eA
// inc.l  #value, erA   | dec.l  #value, erA
// addx.b #high value, rAh
// addx.w #hword value, eA
bool h8_jump_pattern_t::jpi_add_sub(
        uval_t *value,
        op_dtype_t *add_size,
        int tied_jpi)
{
  if ( insn.itype != H8_add
    && insn.itype != H8_addx
    && insn.itype != H8_sub
    && insn.itype != H8_inc
    && insn.itype != H8_dec
    || insn.Op1.type != o_imm )
  {
    return false;
  }
  const op_t &op = insn.Op2;
  if ( insn.itype != H8_addx )
  {
    if ( !is_equal(op, rA) )
      return false;
  }
  else
  {
    const op_t &dst = regs[rA];
    // assert: !is_spoiled(rA) because rA is non spoiled register
    // example:
    //    addx #high value, r0h <-- op
    //    jmp  @r0              <-- dst
    if ( op.dtype + 1 != dst.dtype
      || op.type != o_reg
      || dst.type != o_reg
      || !is_high_bits_reg(op.reg)
      || cvt_to_wholereg(op.reg, dst.dtype) != dst.reg )
    {
      return false;
    }
  }
  *value = insn.Op1.value;
  *add_size = op.dtype;
  if ( insn.itype == H8_addx )
  {
    *value <<= (8 * get_dtype_size(op.dtype));
    skip[tied_jpi] = false;
  }
  else if ( insn.itype == H8_sub || insn.itype == H8_dec )
  {
    *value = 0-*value;
  }
  return true;
}

//-------------------------------------------------------------------------
// add.b #low value, rAl
// add.w #lword value, rA
bool h8_jump_pattern_t::jpi_add_sub_tied(
        uval_t *value,
        op_dtype_t add_size) const
{
  if ( insn.itype != H8_add || insn.Op1.type != o_imm )
    return false;
  // assert: !is_spoiled(rA) because rA is non spoiled register
  const op_t &op = insn.Op2;
  const op_t &reg = regs[rA];
  if ( op.dtype != add_size
    || op.dtype + 1 != reg.dtype
    || op.type != o_reg
    || reg.type != o_reg
    || is_high_bits_reg(op.reg)
    || cvt_to_wholereg(op.reg, reg.dtype) != reg.reg )
  {
    return false;
  }
  *value += insn.Op1.value;
  return true;
}

//-------------------------------------------------------------------------
// cmp.X rSize, rA
// cmp.X #size, rA
bool h8_jump_pattern_t::jpi_cmp_ncases()
{
  // assert: !is_spoiled(rA) because rA is non spoiled register
  if ( insn.itype != H8_cmp
    || insn.Op1.type != o_imm && insn.Op1.type != o_reg
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }

  uval_t value;
  if ( insn.Op1.type == o_imm )
    value = insn.Op1.value;
  // assert: insn.Op1.type == o_reg
  else if ( !pm.get_op_value(&value, insn, insn.Op1) )
    return false;
  si->ncases = ushort(value);
  return true;
}

//-------------------------------------------------------------------------
// bhi   default
// bls   switch_body
bool h8_jump_pattern_t::jpi_condjump(int body_njpi)
{
  op_t op;
  op.type = o_condjump;
  op.value = 0;
  switch ( insn.itype )
  {
    case H8_bhi:  // higher
    case H8_bls:  // lower or same
      op.value |= cc_inc_ncases;
      break;
    case H8_bcs:  // lower
    case H8_bcc:  // higher or same
      break;
    default:
      return false;
  }
  if ( insn.Op1.type != o_near )
    return false;
  ea_t jump = to_ea(insn.cs, insn.Op1.addr);
  switch ( insn.itype )
  {
    case H8_bhi:  // higher
    case H8_bcc:  // higher or same
      op.specval = jump;
      break;
    case H8_bcs:  // lower
    case H8_bls:  // lower or same
      // we have conditional jump to the switch body
      {
        int njpi;
        for ( njpi = body_njpi; njpi > 0 && eas[njpi] == BADADDR; --njpi )
          ;
        // assert: eas[njpi] != BADADDR because eas[0] != BADADDR
        if ( jump > eas[njpi] )
          return false;
        op.specval = insn.ea + insn.size;

        // possibly followed by 'B default'
        insn_t dflt;
        if ( decode_insn(&dflt, op.specval) > 0
          && (dflt.itype == H8_bra || dflt.itype == H8_jmp)
          && dflt.Op1.type == o_near )
        {
          op.specval = to_ea(dflt.cs, dflt.Op1.addr);
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
static const reftype_t off_reftype[3] = { REF_OFF8, REF_OFF16, REF_OFF32 };
static const reftype_t lo_reftype[2] = { REF_LOW8,  REF_LOW16 };
static const reftype_t hi_reftype[2] = { REF_HIGH8, REF_HIGH16 };
inline reftype_t h8_jump_pattern_t::get_off_reftype(op_dtype_t dtype)
{
  // assert: dtype <= op_dword
  return off_reftype[size_t(dtype)]; //lint !e571 Suspicious cast
}
inline reftype_t h8_jump_pattern_t::get_lo_reftype(op_dtype_t dtype)
{
  // assert: dtype <= op_word
  return lo_reftype[size_t(dtype)]; //lint !e571 Suspicious cast
}
inline reftype_t h8_jump_pattern_t::get_hi_reftype(op_dtype_t dtype)
{
  // assert: dtype <= op_word
  return hi_reftype[size_t(dtype)]; //lint !e571 Suspicious cast
}

//----------------------------------------------------------------------
// jump pattern #1
// 7 add.b #low minv, rAl   | add.X/sub.X #minv, rA (.X: .b/.w/.l)
// 6 addx  #high minv, rAh
// 5 cmp.w rSize, rA        | cmp.X #size, rA
//   bhi   default          | bls   switch_body     (nearest to "cmp")
// 4 add.X rA, rA                                   (if 3 is .w)
// 3 mov.b/w @(jumps,rA'), rA
// 2 add.b #low elbase, rAl | add.X #elbase, rA
// 1 addx  #high elbase, rAh
// 0 jmp   @rA

static const char depends1[][4] =
{
  { 1 | JPT_OPT  }, // 0
  { 2 },            // 1 optional
  { 3 },            // 2 tied to 1
  { 4 },            // 3
  { 5 },            // 4 tied to 3
  { 6 | JPT_OPT },  // 5
  { 7 },            // 6 optional
  { 0 },            // 7 tied to 6
};

//-------------------------------------------------------------------------
class h8_jump_pattern1_t : public h8_jump_pattern_t
{
protected:
  enum
  {
    JPI_SUB_LOWCASE2 = 7,
    JPI_SHIFT        = 4,
    JPI_LD           = 3,
    JPI_ADD_ELBASE2  = 2,
    JPI_ADD_ELBASE   = 1,
  };
  op_dtype_t add_elbase_size;

public:
  h8_jump_pattern1_t(procmod_t *_pm, switch_info_t *_si)
    : h8_jump_pattern_t(_pm, _si, depends1, JPI_SUB_LOWCASE2),
      add_elbase_size(dt_void) {}

  virtual bool jpi7(void) override { return jpi_sub_lowcase_tied(); }
  virtual bool jpi6(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi5(void) override { return jpi_cmp_ncases_condjump(JPI_SHIFT); }
  virtual bool jpi4(void) override { return jpi_shl(); }
  virtual bool jpi3(void) override { return jpi_ld(JPI_SHIFT); }
  virtual bool jpi2(void) override;  // (tied to 1)
  virtual bool jpi1(void) override;  // add #elbase, rA
  virtual bool jpi0(void) override;  // jmp @rA

  bool finish(); //lint !e1511 Member hides non-virtual member
};

//----------------------------------------------------------------------
// jmp @rA
bool h8_jump_pattern1_t::jpi0()
{
  if ( insn.itype != H8_jmp
    || insn.Op1.type != o_phrase
    || insn.Op1.phtype != ph_normal )
  {
    return false;
  }
  h8_track(insn.Op1.phrase, rA);
  skip[JPI_SUB_LOWCASE2] = true;
  skip[JPI_ADD_ELBASE2] = true;
  return true;
}

//----------------------------------------------------------------------
// add.X  #elbase, rA
// addx.b #high elbase, rAh
// addx.w #hword elbase, rA
bool h8_jump_pattern1_t::jpi1()
{
  // continue to track rA
  return jpi_add_sub(&si->elbase, &add_elbase_size, JPI_ADD_ELBASE2);
}

//----------------------------------------------------------------------
// add.b #low elbase, rAh
// add.w #lword elbase, rA
bool h8_jump_pattern1_t::jpi2()
{
  // continue to track rA
  return jpi_add_sub_tied(&si->elbase, add_elbase_size);
}

//----------------------------------------------------------------------
bool h8_jump_pattern1_t::finish()
{
  if ( eas[JPI_ADD_ELBASE] != BADADDR )
  {
    reftype_t rtype = get_off_reftype(add_elbase_size);
    if ( eas[JPI_ADD_ELBASE2] == BADADDR )
    {
      op_offset(eas[JPI_ADD_ELBASE], 0, rtype);
    }
    else
    {
      // low part
      rtype = get_lo_reftype(add_elbase_size);
      op_offset(eas[JPI_ADD_ELBASE2], 0, rtype, si->elbase);
      // high part
      rtype = get_hi_reftype(add_elbase_size);
      op_offset(eas[JPI_ADD_ELBASE], 0, rtype, si->elbase);
    }
    si->flags |= SWI_ELBASE;
  }
  return h8_jump_pattern_t::finish(JPI_LD);
}

//----------------------------------------------------------------------
static int is_jump_pattern1(switch_info_t *si, const insn_t &insn, procmod_t *pm)
{
  h8_jump_pattern1_t jp(pm, si);
  if ( !jp.match(insn) || !jp.finish() )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
// jump pattern #2
// 6 add.b #low minv, rAl
// 5 addx  #high minv, rAh
// 4 cmp.X #size, rA
//   bhi   default          (nearest to "cmp")
// 3 add.X rA, rA           (if needed)
// 2 mov.b/w @(jumps,rA'), rA
// 1 shlr.X rA              (optional)
// 0 bra    rA

static const char depends2[][4] =
{
  { 1 | JPT_OPT  }, // 0
  { 2 },            // 1 optional
  { 3 },            // 2
  { 4 },            // 3 tied to 2
  { 5 | JPT_OPT },  // 4
  { 6 },            // 5 optional
  { 0 },            // 6 tied to 5
};

//-------------------------------------------------------------------------
class h8_jump_pattern2_t : public h8_jump_pattern_t
{
protected:
  enum
  {
    JPI_SUB_LOWCASE2 = 6,
    JPI_SHIFT        = 3,
    JPI_LD           = 2,
    JPI_EL_SHIFT     = 1,
  };

public:
  h8_jump_pattern2_t(procmod_t *_pm, switch_info_t *_si)
    : h8_jump_pattern_t(_pm, _si, depends2, JPI_SUB_LOWCASE2) {}

  virtual bool jpi6(void) override { return jpi_sub_lowcase_tied(); }
  virtual bool jpi5(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi4(void) override { return jpi_cmp_ncases_condjump(JPI_SHIFT); }
  virtual bool jpi3(void) override { return jpi_shl(); }
  virtual bool jpi2(void) override { return jpi_ld(JPI_SHIFT); }
  virtual bool jpi1(void) override;  // shlr.X rA
  virtual bool jpi0(void) override;  // bra rA

  bool finish(); //lint !e1511 Member hides non-virtual member
};

//----------------------------------------------------------------------
// bra rA
bool h8_jump_pattern2_t::jpi0()
{
  if ( insn.itype != H8_bra || insn.Op1.type != o_pcidx )
    return false;

  h8_track(insn.Op1.reg, rA);
  skip[JPI_SUB_LOWCASE2] = true;
  si->set_elbase(insn.ea + insn.size);
  return true;
}

//----------------------------------------------------------------------
// shlr.X rA
bool h8_jump_pattern2_t::jpi1()
{
  if ( insn.itype != H8_shlr
    || !insn.Op1.is_imm(1)
    || !is_equal(insn.Op2, rA) )
  {
    return false;
  }
  // continue to track rA
  return true;
}

//----------------------------------------------------------------------
bool h8_jump_pattern2_t::finish()
{
  if ( eas[JPI_EL_SHIFT] == BADADDR )
    si->set_shift(1); // register is shifted left by the 'bra' insn
  return h8_jump_pattern_t::finish(JPI_LD);
}

//----------------------------------------------------------------------
static int is_jump_pattern2(switch_info_t *si, const insn_t &insn, procmod_t *pm)
{
  h8_jump_pattern2_t jp(pm, si);
  if ( !jp.match(insn) || !jp.finish() )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
bool idaapi h8_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype != H8_jmp && insn.itype != H8_bra )
    return false;

  static is_pattern_t *const patterns[] =
  {
    is_jump_pattern1,
    is_jump_pattern2,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns));
}

