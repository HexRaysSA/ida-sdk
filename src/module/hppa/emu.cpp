/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"
#include <frame.hpp>
#include <typeinf.hpp>

//----------------------------------------------------------------------
// map virtual to physical ea
ea_t calc_mem(ea_t ea)
{
  return ea;
}

//------------------------------------------------------------------------
ea_t hppa_t::get_dp(const insn_t &insn) const
{
  if ( got == BADADDR )
    return BADADDR;
  sel_t delta = get_sreg(insn.ea, DPSEG);
  if ( delta == BADSEL )
    return BADADDR;
  // calculate the return value
  // if we don't do it in a separate statement, bcb6 generates
  // wrong code with __EA64__
  ea_t dp = trunc_ea(got + delta);
  return dp;
}

//-------------------------------------------------------------------------
// returns:
//      -1: doesn't spoil anything
//      -2: spoils everything
//     >=0: the number of the register which is spoiled
static int spoils(const insn_t &insn, const uint32 *regs, int n)
{
  switch ( insn.itype )
  {
    case HPPA_call:
    case HPPA_blr:
      for ( int i=0; i < n; i++ )
        if ( regs[i] >= 23 && regs[i] != DP ) // assume the first 8 registers are not spoiled
          return i;                           // dp is never spoiled
  }
  return get_spoiled_reg(insn, regs, n);
}

//----------------------------------------------------------------------
static bool find_addil_or_ldil(ea_t ea, uint32 r, ea_t dp, uval_t *pv)
{
  uval_t v;
  insn_t insn;
  func_item_iterator_t fii(get_func(ea), ea);
  while ( fii.decode_prev_insn(&insn) )
  {
    switch ( insn.itype )
    {
      case HPPA_addil:
        if ( insn.Op3.reg == r )
        {
          if ( insn.Op2.reg == R0 )
          {
            v = insn.Op1.value;
RETTRUE:
            *pv = v;
            return true;
          }
          if ( insn.Op2.reg == DP )
          {
            v = dp + insn.Op1.value;
            goto RETTRUE;
          }
        }
        continue;
      case HPPA_ldil:
        if ( insn.Op2.reg == r )
        {
          v = insn.Op1.value;
          goto RETTRUE;
        }
      case HPPA_copy:
        if ( insn.Op2.reg == r )
        {
          r = insn.Op1.reg;
          if ( r == R0 )
          {
            v = 0;
            goto RETTRUE;
          }
        }
        continue;
    }
    if ( spoils(insn, &r, 1) != -1 )
      break;
  }
  return false;
}

//----------------------------------------------------------------------
//      addil           -0x2800, %dp, %r1
//      stw             %r5, 0x764(%sr0,%r1)
ea_t hppa_t::calc_possible_memref(const insn_t &insn, const op_t &x)
{
  ea_t dp = get_dp(insn);
  if ( dp != BADADDR )
  {
    if ( x.phrase == DP )
    {
      dp = trunc_uval(dp + x.addr);
    }
    else
    {
      int r = x.phrase;
      uval_t v = x.addr;
      uval_t v2 = 0;
      if ( find_addil_or_ldil(insn.ea, r, dp, &v2) )
      {
        dp = trunc_uval(v + v2);
      }
      else
        dp = BADADDR;
    }
  }
  return dp;
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == SP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &/*insn*/, const op_t &x)
{
  return OP_SP_ADD | (is_stkreg(x.phrase) ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
// is the register the frame pointer?
bool hppa_t::is_frreg(const insn_t &insn, int reg)
{
  if ( reg != 0 )
  {
    func_t *pfn = get_func(insn.ea);
    if ( pfn != nullptr )
    {
      ea_t ea = pfn->start_ea;
      if ( ea != oldea )
      {
        oldea = ea;
        oldreg = helper.altval_ea(oldea);
      }
      return reg == oldreg;
    }
  }
  return false;
}

//------------------------------------------------------------------------
inline bool stldwm(const insn_t &insn)
{
  return insn.itype == HPPA_ldo && insn.Op2.reg == SP     // ldo .., %sp
      || (opcode(get_dword(insn.ea)) & 0x13) == 0x13;     // st/ldw,m
}

//------------------------------------------------------------------------
inline void remove_unwanted_typeinfo(const insn_t &insn, int n)
{
  if ( is_defarg(get_flags(insn.ea), n) )
    clr_op_type(insn.ea, n);
}

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), n) )
    return;
  switch ( insn.itype )
  {
    case HPPA_depd:
    case HPPA_depw:
    case HPPA_extrd:
    case HPPA_extrw:
    case HPPA_hshl:
    case HPPA_hshladd:
    case HPPA_hshr:
    case HPPA_hshradd:
    case HPPA_shladd:
    case HPPA_shrpd:
    case HPPA_shrpw:
    case HPPA_shrd:
    case HPPA_shrw:
    case HPPA_shld:
    case HPPA_shlw:
      op_dec(insn.ea, n);
      break;
    case HPPA_depdi:
    case HPPA_depwi:
      if ( n == 0 )
        op_num(insn.ea, n);
      else
        op_dec(insn.ea, n);
      break;
    case HPPA_popbts:
    case HPPA_rsm:
    case HPPA_ssm:
      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
enum nullicode_t { NEVER, SKIP, NULLIFY };
static nullicode_t may_skip_next_insn(ea_t ea)
{
  nullicode_t may = NEVER;
  insn_t insn;
  if ( decode_insn(&insn, ea) > 0 )
  {
    switch ( insn.itype )
    {
      case HPPA_pmdis:    // format 55
      case HPPA_spop0:    // format 34
      case HPPA_spop1:    // format 35
      case HPPA_spop2:    // format 36
      case HPPA_spop3:    // format 37
      case HPPA_copr:     // format 38
        may = (get_dword(ea) & BIT26) != 0 ? SKIP : NEVER;
        break;
      case HPPA_addb:     // format 17
      case HPPA_addib:
      case HPPA_cmpb:
      case HPPA_cmpib:
      case HPPA_movb:
      case HPPA_movib:
      case HPPA_bb:       // format 18
      case HPPA_be:       // format 19
      case HPPA_b:        // format 20
      case HPPA_blr:      // format 21
      case HPPA_bv:
      case HPPA_call:     // pseudo-op
      case HPPA_bve:      // format 22
      case HPPA_ret:      // pseudo-op
        may = ((get_dword(ea) & BIT30) != 0) ? NULLIFY : NEVER;
        break;
      default:
        may = (insn.auxpref & aux_cndc) != 0 ? SKIP : NEVER;
        break;
    }
  }
  return may;
}

//----------------------------------------------------------------------
static bool is_cond_branch(uint32 code)
{
  switch ( opcode(code) )
  {
    case 0x20:  // cmpb
    case 0x22:  // cmpb
    case 0x27:  // cmpb
    case 0x2F:  // cmpb
    case 0x28:  // addb
    case 0x2A:  // addb
    case 0x32:  // movb
    case 0x21:  // cmpib
    case 0x23:  // cmpib
    case 0x3B:  // cmpib
    case 0x29:  // addib
    case 0x2B:  // addib
    case 0x33:  // movib
    case 0x30:  // bb
    case 0x31:  // bb
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_uncond_branch(uint32 code)
{
  int sub;
  switch ( opcode(code) )
  {
    case 0x38:          // be
      return true;
    case 0x3A:
      sub = (code>>13) & 7;
      switch ( sub )
      {
        case 0:     // b,l
        case 1:     // b,gate
        case 2:     // blr
          return r06(code) == R0;
        case 6:     // bv/bve
          return true;
      }
      break;
    case 0x22:            // cmpb
    case 0x23:            // cmpib
    case 0x2F:            // cmpb
    case 0x2A:            // addb
    case 0x2B:            // addib
      return ((code>>13) & 7) == 0;
    case 0x32:            // movb
    case 0x33:            // movib
      return ((code>>13) & 7) == 4;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_call_branch(uint32 code)
{
  int sub;
  switch ( opcode(code) )
  {
    case 0x39:          // be,l
      return true;
    case 0x3A:
      sub = (code>>13) & 7;
      switch ( sub )
      {
        case 0:     // b,l
        case 1:     // b,gate
        case 2:     // blr
          return r06(code) != R0;
        case 4:     // b,l,push
        case 5:     // b,l
        case 7:     // bve,l
          return true;
      }
      break;
  }
  return false;
}

//----------------------------------------------------------------------
static nullicode_t may_be_skipped(ea_t ea)
{
  if ( !is_flow(get_flags(ea)) )
    return NEVER;
  if ( ea < 4 )
    return NEVER;
  return may_skip_next_insn(ea-4);
}

//----------------------------------------------------------------------
static ea_t calc_branch_target(ea_t ea)
{
  ea_t res = BADADDR;
  insn_t insn;
  if ( decode_insn(&insn, ea) > 0 )
  {
    for ( int i=0; i < UA_MAXOP; i++ )
    {
      if ( insn.ops[i].type == o_near )
      {
        res = insn.ops[i].addr;
        break;
      }
    }
  }
  return res;
}

//----------------------------------------------------------------------
inline bool is_stop(uint32 code, bool include_calls_and_conds)
{
  return is_uncond_branch(code)
      || include_calls_and_conds
      && (is_cond_branch(code) || is_call_branch(code));
}

//----------------------------------------------------------------------
// does the specified address have a delay slot?
static bool has_delay_slot(ea_t ea, bool include_calls_and_conds)
{
  if ( (include_calls_and_conds || may_be_skipped(ea) != SKIP)
    && calc_branch_target(ea) != ea+4 )
  {
    uint32 code = get_dword(ea);
    return is_stop(code, include_calls_and_conds) && (code & BIT30) == 0;
  }
  return false;
}

//----------------------------------------------------------------------
// is the current insruction in a delay slot?
static bool is_delayed_stop(const insn_t &insn, bool include_calls_and_conds)
{
  uint32 code = get_dword(insn.ea);
  if ( (code & BIT30) != 0              // ,n
    && is_stop(code, include_calls_and_conds)
    && (include_calls_and_conds || may_be_skipped(insn.ea) != SKIP) )
  {
    // seems to be a branch which nullifies the next instruction
    return true;
  }

  if ( !is_flow(get_flags(insn.ea)) )
    return false;

  return insn.ea >= 4 && has_delay_slot(insn.ea-4, include_calls_and_conds);
}

//----------------------------------------------------------------------
void hppa_t::add_near_ref(const insn_t &insn, const op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( is_call_branch(get_dword(insn.ea)) )
    ftype = fl_CN;
  if ( has_insn_feature(insn.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  insn.add_cref(ea, x.offb, ftype);
  if ( ftype == fl_CN )
    auto_apply_type(insn.ea, ea);
}

//----------------------------------------------------------------------
inline dref_t calc_dref_type(const insn_t &insn, bool isload)
{
  if ( insn.itype == HPPA_ldo )
    return dr_O;
  return isload ? dr_R : dr_W;
}

//----------------------------------------------------------------------
static bool create_lvar(const insn_t &insn, const op_t &x, uval_t v)
{
  struct lvar_info_t
  {
    int delta;
    const char *name; //lint !e958 padding is required to align members
  };
  static const lvar_info_t linfo[] =
  {
    { -4,   "prev_sp"     },
    { -8,   "rs_rp"       },    // RP'' (relocation stub RP)
    { -12,  "cleanup"     },
    { -16,  "static_link" },
    { -20,  "cur_rp"      },
    { -24,  "es_rp"       },    // RP' (external/stub RP)
    { -28,  "LPT_"        },    // (external SR4/LT pointer)
    { -32,  "LPT"         },    // (external Data/LT pointer)
  };

  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  sval_t delta;
  tinfo_t frame;
  ssize_t stkvar_idx = frame.get_stkvar(&delta, insn, &x, v);
  if ( stkvar_idx == -1 )
  {
    if ( !insn.create_stkvar(x, v, STKVAR_VALID_SIZE) )
      return false;
    stkvar_idx = frame.get_stkvar(&delta, insn, &x, v);
    if ( stkvar_idx == -1 )
      return false;   // should not happen but better check
    delta -= pfn->argsize;
    // delta contains real offset from SP
    for ( size_t i=0; i < qnumber(linfo); i++ )
    {
      if ( delta == linfo[i].delta )
      {
        stkvar_idx = frame.find_udm((delta+pfn->argsize)*8LL);
        if ( stkvar_idx != -1 )
          frame.rename_udm(stkvar_idx, linfo[i].name);
        break;
      }
    }
    if ( delta <= -0x34 )       // seems to be an argument in the stack
    {                           // this means that the current function
                                // has at least 4 register arguments
      pfn = get_func(insn.ea);
      while ( pfn->regargqty < 4 )
        add_regarg(pfn, R26-pfn->regargqty, tinfo_t(BT_INT), nullptr);
    }
  }

  return op_stkvar(insn.ea, x.n);
}

//----------------------------------------------------------------------
// recognize the following code:
// 20 20 08 01                 ldil            -0x40000000, %r1
// E4 20 E0 08                 be,l            4(%sr7,%r1), %sr0, %r31 # C0000004
// followed by:
//                             ldi             NNN, %r22
// as a system call number NNN.
// return -1 if not found
static int get_syscall_number(ea_t ea)
{
  int syscall = -1;
  if ( get_dword(ea) == 0x20200801
    && get_dword(ea+4) == 0xE420E008 )
  {
    insn_t l;
    decode_insn(&l, ea+8);
    if ( l.itype == HPPA_ldi && l.Op2.reg == R22 )
      syscall = (int)l.Op1.value;
  }
  return syscall;
}

//----------------------------------------------------------------------
void hppa_t::process_operand(const insn_t &insn, const op_t &x, bool isAlt, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
/*      if ( x.reg == GP
        && insn.itype != ALPHA_lda
        && insn.itype != ALPHA_ldah
        && insn.itype != ALPHA_br
        && !isload ) split_srarea(insn.ea+insn.size, GPSEG, BADSEL, SR_auto);*/
      break;
    default:
      if ( insn.itype == HPPA_fcmp
        || insn.itype == HPPA_b
        || insn.itype == HPPA_ftest )
      {
        return;
      }
      interr(insn, "emu");
      break;
    case o_based:     // (%r5)
      break;
    case o_imm:
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, OOF_SIGNED);
      break;
    case o_displ:
      process_immediate_number(insn, x.n);
      if ( is_stkreg(x.reg) || is_frreg(insn, x.reg) )
      {
        if ( may_create_stkvars() && !is_defarg(get_flags(insn.ea), x.n) )
        {
          if ( stldwm(insn) )
            op_num(insn.ea, -1);
          else
            create_lvar(insn, x, x.addr);
        }
      }
      else
      {
        ea_t ea = calc_possible_memref(insn, x);
        if ( ea != BADADDR )
        {
          if ( insn.itype == HPPA_be )
            add_near_ref(insn, x, ea);
          else
            insn.add_dref(ea, x.offb, calc_dref_type(insn, isload));
          insn.create_op_data(ea, x);
          if ( isload )
          {
            ea_t ea2 = get_dword(ea);
            if ( is_mapped(ea2) )
              insn.add_dref(ea2, x.offb, dr_O);
          }
        }
      }
      // no break
    case o_phrase:
      if ( isAlt )
        break;
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
      {
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, OOF_SIGNED|OOF_ADDR);
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
      }
      break;
    case o_near:
      add_near_ref(insn, x, calc_mem(x.addr));
      break;
  }
}

//----------------------------------------------------------------------
static bool add_stkpnt(const insn_t &insn, sval_t delta)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  return add_auto_stkpnt(pfn, insn.ea+insn.size, delta);
}

//----------------------------------------------------------------------
void hppa_t::trace_sp(const insn_t &insn)
{
  switch ( insn.itype )
  {
    // stw,m           %r3, 0x80(%sr0,%sp)
    case HPPA_stw:
      if ( opcode(get_dword(insn.ea)) == 0x1B     // stw,m
        && is_stkreg(insn.Op2.reg) )
      {
        add_stkpnt(insn, insn.Op2.addr);
      }
      break;
    // ldw,m           -0x80(%sr0,%sp), %r3
    case HPPA_ldw:
      if ( opcode(get_dword(insn.ea)) == 0x13     // ldw,m
        && is_stkreg(insn.Op1.reg) )
      {
        add_stkpnt(insn, insn.Op1.addr);
      }
      break;
    case HPPA_ldo:
      if ( is_stkreg(insn.Op2.reg) )
      {
        // ldo -0x80(%sp), %sp
        if ( is_stkreg(insn.Op1.reg) )
        {
          add_stkpnt(insn, insn.Op1.addr);
        }
        else if ( is_frreg(insn, insn.Op1.reg) )
        {
          // analog of the 'leave' instruction
          // (restores the original value of sp + optional delta
          // using the frame pointer register)
          // ldo 4(%r4), %sp
          func_t *pfn = get_func(insn.ea);
          if ( pfn != nullptr )
          {
            sval_t delta = insn.Op1.addr + pfn->frregs - get_spd(pfn,insn.ea);
            add_stkpnt(insn, -delta);
          }
        }
      }
      break;
  }
}

//----------------------------------------------------------------------

int hppa_t::emu(const insn_t &insn)
{

  if ( segtype(insn.ea) == SEG_XTRN )
    return 1;

  uint32 Feature = insn.get_canon_feature(ph);
  flow = ((Feature & CF_STOP) == 0);

  int i;
  for ( i=0; i < PROC_MAXOP; i++ )
    if ( has_cf_use(Feature, i) )
      process_operand(insn, insn.ops[i], is_forced_operand(insn.ea, i), true);

  for ( i=0; i < PROC_MAXOP; i++ )
    if ( has_cf_chg(Feature, i) )
      process_operand(insn, insn.ops[i], is_forced_operand(insn.ea, i), false);

//
//      Determine if the next instruction should be executed
//
  if ( Feature & CF_STOP )
    flow = false;
  if ( is_delayed_stop(insn, false) )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size,fl_F);

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

// Handle system calls
  if ( insn.itype == HPPA_ldi && insn.ea >= 8 && !has_cmt(get_flags(insn.ea)) )
  {
    int syscall = get_syscall_number(insn.ea-8);
    if ( syscall >= 0 )
    {
      const char *syscall_name = get_syscall_name(syscall);
      if ( syscall_name != nullptr )
      {
        append_cmt(insn.ea, syscall_name, false);
        flags64_t F = get_flags(insn.ea-8);
        if ( has_xref(F) && !has_user_name(F) )
          set_name(insn.ea-8, syscall_name, SN_NOCHECK|SN_NOWARN|SN_NODUMMY);
      }
    }
  }
  return 1;
}

//----------------------------------------------------------------------
int may_be_func(const insn_t &/*insn*/) // can a function start here?
                                    // returns: probability 0..100
{
//      ldah    $gp, 0x2000($27)
//  if ( insn.itype == ALPHA_ldah && insn.Op1.reg == GP )
//    return 100;
  return 0;
}

//----------------------------------------------------------------------
int is_sane_insn(const insn_t &insn, int /*nocrefs*/)
{
  // disallow jumps to nowhere
  if ( insn.Op1.type == o_near && !is_mapped(calc_mem(insn.Op1.addr)) )
    return 0;
  // don't disassemble 0 as break 0,0 automatically
  if ( insn.itype == HPPA_break && get_dword(insn.ea) == 0 )
    return 0;
  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case HPPA_break:
      if ( get_dword(insn.ea) )
        return 0;
      break;
    case HPPA_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
int idaapi hppa_get_frame_retsize(const func_t *)
{
  return 0;     // ALPHA doesn't use stack for function return addresses
}

//----------------------------------------------------------------------
//lint -e{818} could be declared as pointing to const
bool hppa_t::create_func_frame(func_t *pfn)
{
  ea_t ea = pfn->start_ea;
  int frame_reg = 0;
  for ( int i=0; i < 16; i++ )
  {
    insn_t insn;
    decode_insn(&insn, ea);
    if ( insn.itype == HPPA_copy && is_stkreg(insn.Op1.reg) )
      frame_reg = insn.Op2.reg;
    if ( opcode(get_dword(ea)) == 0x1B )    // stw,m
    {
      if ( frame_reg != 0 )
        helper.altset_ea(pfn->start_ea, frame_reg);
//      return true;//add_frame(pfn, 0, 0, 0);
      return add_frame(pfn, insn.Op2.addr, 0, 0);
    }
    ea += 4;
  }
  return 0;
}

//----------------------------------------------------------------------
bool is_basic_block_end(const insn_t &insn)
{
  if ( is_delayed_stop(insn, true) )
    return true;
  return !is_flow(get_flags(insn.ea+insn.size));
}

//-------------------------------------------------------------------------
bool calc_hppa_arglocs(func_type_data_t *fti)
{
  int r = 0;
  int n = fti->size();
  for ( int i=0; i < n; i++ )
  {
    funcarg_t &fa = fti->at(i);
    size_t a = fa.type.get_size();
    if ( a == BADSIZE )
      return false;
    a = align_up(a, inf_get_cc_size_i());
    if ( r < 4 )        // first 4 arguments are in %r26, 25, 24, 23
      fa.argloc.set_reg1(26 - r);
    else
      fa.argloc.set_stkoff(0x24 + r * 4);
    r += int(a / 4);
  }
  fti->stkargs = r < 4 ? 0 : 0x24 + r * 4;
  return true;
}

//-------------------------------------------------------------------------
static bool hppa_set_op_type(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name,
        eavec_t &visited)
{
  tinfo_t type = tif;
  switch ( x.type )
  {
    case o_imm:
      if ( type.is_ptr()
        && x.value != 0
        && !is_defarg(get_flags(insn.ea), x.n) )
      {
        return op_plain_offset(insn.ea, x.n, 0);
      }
      break;
    case o_mem:
      {
        ea_t dea = calc_mem(x.addr);
        return apply_once_tinfo_and_name(dea, type, name);
      }
    case o_displ:
      return apply_tinfo_to_stkarg(insn, x, x.addr, type, name);
    case o_reg:
      {
        uint32 r = x.reg;
        func_t *pfn = get_func(insn.ea);
        if ( pfn == nullptr )
          return false;
        bool ok;
        bool farref;
        func_item_iterator_t fii;
        insn_t l;
        for ( ok=fii.set(pfn, insn.ea);
              ok && (ok=fii.decode_preceding_insn(&visited, &farref, &l)) != 0;
              )
        {
          if ( visited.size() > 4096 )
            break; // decoded enough of it, abandon
          if ( farref )
            continue;
          switch ( l.itype )
          {
            case HPPA_ldo:
              if ( l.Op2.reg != r )
                continue;
              remove_tinfo_pointer(&type, &name);
              // no break
            case HPPA_copy:
            case HPPA_ldw:
            case HPPA_ldi:
            case HPPA_ldil:
              if ( l.Op2.reg != r )
                continue;
              return hppa_set_op_type(l, l.Op1, type, name, visited);
            default:
              {
                int code = spoils(insn, &r, 1);
                if ( code == -1 )
                  continue;
              }
              break;
          }
          break;
        }
        if ( !ok && l.ea == pfn->start_ea )
        { // reached the function start, this looks like a register argument
          add_regarg(pfn, r, type, name);
          break;
        }
      }
      break;
  }
  return false;
}

//-------------------------------------------------------------------------
inline bool set_op_type(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &type,
        const char *name)
{
  eavec_t visited;
  return hppa_set_op_type(insn, x, type, name, visited);
}

//-------------------------------------------------------------------------
int use_hppa_regarg_type(ea_t ea, const funcargvec_t &rargs)
{
  insn_t insn;
  int idx = -1;
  if ( decode_insn(&insn, ea) > 0 )
  {
    qvector<uint32> regs;
    int n = rargs.size();
    regs.resize(n);
    for ( int i=0; i < n; i++ )
      regs[i] = rargs[i].argloc.reg1();

    idx = spoils(insn, regs.begin(), n);
    if ( idx >= 0 )
    {
      tinfo_t type = rargs[idx].type;
      const char *name = rargs[idx].name.begin();
      switch ( insn.itype )
      {
        case HPPA_ldo:
          remove_tinfo_pointer(&type, &name);
          // no break
        case HPPA_copy:
        case HPPA_ldw:
        case HPPA_ldi:
        case HPPA_ldil:
          set_op_type(insn, insn.Op1, type, name);
        case HPPA_depw:
        case HPPA_depwi:
        case HPPA_depd:
        case HPPA_depdi:
        case HPPA_extrw:
        case HPPA_extrd:
          break;
        default: // unknown instruction changed the register, stop tracing it
          idx |= REG_SPOIL;
          break;
      }
    }
  }
  return idx;
}

//-------------------------------------------------------------------------
struct hppa_argtinfo_helper_t : public argtinfo_helper_t
{
  bool idaapi set_op_tinfo(
        const insn_t &_insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name) override
  {
    return set_op_type(_insn, x, tif, name);
  }

  // does the current instruction prepare a stack argument?
  bool idaapi is_stkarg_load(const insn_t &insn, int *src, int *dst) override
  {
    if ( insn.itype == HPPA_stw )
    {
      *src = 0;
      *dst = 1;
      return true;
    }
    return false;
  }

  bool idaapi has_delay_slot(ea_t caller) override
  {
    return ::has_delay_slot(caller, true);
  }
};

//-------------------------------------------------------------------------
void hppa_t::use_hppa_arg_types(ea_t ea, func_type_data_t *fti, funcargvec_t *rargs)
{
  hppa_argtinfo_helper_t argtypes_helper;
  argtypes_helper.use_arg_tinfos(ea, fti, rargs);
}
