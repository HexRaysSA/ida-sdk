/*
 *      Decompiler project
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Verify microcode consistency
 *
 */

#include "allmicro.h"

// PC-lint errs on union members:
//lint -esym(413,nnn) Likely use of null
//lint -esym(413,d)
//lint -esym(413,f)
//lint -esym(413,a)
//lint -esym(413,c)
//lint -esym(413,fpc)
//lint -esym(413,pair)
//lint -esym(413,op_parent_info_t::curins)

//-------------------------------------------------------------------------
bool hexrays_vars_t::should_verify()
{
#ifndef NDEBUG
  return true;
#else
  return under_debugger || (vdrun_flags & VDRUN_TEST) != 0;
#endif
}

//-------------------------------------------------------------------------
void mcallinfo_t::verify(const micro_verifier_t &mv, int size) const
{
  if ( get_cc(cc) == CM_CC_INVALID )
    INTERR(50733); // invalid calling convention is used
  // check args
  for ( int i=0; i < args.size(); i++ )
  {
    const mcallarg_t &a = args[i];
    if ( !a.type.is_correct() )
      INTERR(50734); // incorrect argument type
    if ( a.type.get_size() != a.size )
      INTERR(50735); // argument size and its type size mismatch
    if ( a.size == 0 )
      INTERR(50736); // zero sized argument
    if ( a.ea != BADADDR && !is_mapped(mv.mba->map_fict_ea(a.ea)) )
      INTERR(51066); // argument defined at non-existent address
    if ( verify_argloc(a.argloc, a.size, nullptr) != 0 )
      INTERR(50732); // wrong argument location
    // we already checked that the operand size is equal to type size
    a.verify(mv, VMOP_ANYSIZE);
    if ( a.empty() )
      INTERR(50737); // argument of mop_z type
    if ( !is_acceptable_argtype(i, args[i].type) )
      INTERR(52016); // impossible argument type
  }
  if ( solid_args > args.size() )
    INTERR(50738); // too short argument list
  if ( !return_type.is_correct() )
    INTERR(50739); // incorrect return type
  if ( !pass_regs.empty() )
  {
    if ( !mv.mba->has_passregs() )
      INTERR(51087); // passthrough registers exist but HAS_PASSREGS is not set
    if ( !pass_regs.is_subset_of(spoiled) )
      INTERR(50991); // passthrough registers must be part of SPOILED
  }
  if ( (flags & FCI_NOSPL) == 0 && !return_regs.is_subset_of(spoiled) )
    INTERR(50740); // return registers must be part of SPOILED
  if ( !dead_regs.is_subset_of(return_regs) )
    INTERR(50741); // DEAD_REGS must be part of return registers

  if ( size == NOSIZE )
    INTERR(50742); // call retval size is NOSIZE?!
  if ( (flags & FCI_PROP) == 0 )
  {
    mlist_t tmp = used_retvals();
    if ( tmp.reg.count() != size )
      INTERR(50743); // size of registers returned from a call mismatches the retval size
    int s2 = 0;
    int vmop = 0;
    // special handling for long double (10 bytes)
    if ( retregs.size() == 1 && return_type.get_size() == retregs[0].size )
      vmop = VMOP_ANYSIZE;
    for ( int i=0; i < retregs.size(); i++ )
    {
      const mop_t &m = retregs[i];
      m.verify(mv, vmop);
      s2 += m.size;
    }
    if ( flags & FCI_DEAD )  // some return registers are dead
    {
      if ( s2 < size )
        INTERR(50744); // size of return registers mismatches the retval size
    }
    else
    {
      if ( s2 != size )
        INTERR(50745); // size of return registers mismatches the retval size
    }
  }
}

//-------------------------------------------------------------------------
void mcases_t::verify(const micro_verifier_t &mv) const
{
  int n = targets.size();
  if ( n != values.size() )
    INTERR(50746); // switch: sizes of values and targets mismatch
  if ( n == 0 )
    INTERR(50747); // switch: no targets?!
  if ( n == 1 )
  {
    int nvals = values[0].size();
    if ( nvals == 0 )
      INTERR(50748); // switch: only single 'default' case?!
  }
  bool seen_default = false;
  std::set<uint64> seen;
  easet_t targset;
  for ( int i=0; i < n; i++ )
  {
    const svalvec_t &v = values[i];
    if ( v.empty() )
    {
      if ( seen_default )
        INTERR(50750); // switch: duplicate 'default' cases?!
      seen_default = true;
    }
    for ( int j=0; j < v.size(); j++ )
      if ( !seen.insert(v[j]).second )
        INTERR(50751); // switch: duplicate case value
    int b = targets[i];
    if ( b <= 0 || b >= mv.mba->qty )
      INTERR(50752); // switch: wrong case target
    if ( !targset.insert(b).second )
      INTERR(50753); // switch: duplicate target
  }

}

//-------------------------------------------------------------------------
inline bool valid_pair_part(mopt_t t)
{
  switch ( t )
  {
    case mop_r:
    case mop_n:
    case mop_d:
    case mop_S:
    case mop_v:
    case mop_l:
    case mop_a:
    case mop_fn:
    case mop_p:
    case mop_sc:
      return true;
  }
  return false;
}

//-------------------------------------------------------------------------
// A special case: alignment of va_list on  platforms with addrsize < slotsize.
// In pseudocode it is represented as (va+7) & 0xFFFFFFF8
// in microcode: and &va@7, #0xFFFFFFF8 (see va_visitor_t in calls.cpp)
static bool is_va_list_align(const mvm_t &mvm, const lvar_t &v, int flags)
{
  if ( (flags & VMOP_ADRUSED) == 0 )
    return false;                 // not access by address
  if ( addrsize(mvm) >= slotsize(mvm) )
    return false;                 // inappropriate platform
  hexrays_vars_t &hv = mvm.hv;    // used by T_VA_LIST
  if ( v.type() != T_VA_LIST )
    return false;   // not va_list
  return true;
}

//-------------------------------------------------------------------------
void mop_t::verify(const micro_verifier_t &mv, int flags) const
{
  const mvm_t &mvm = mv.mba->mvm;
  // check the operand size
  switch ( t )
  {
    case mop_z:
      // propagated insn destination must have a valid size
      if ( (flags & VMOP_PROPDST) != 0 )
        break;
       // no break
    case mop_b:           // basic blocks have no size
    case mop_c:           // cases have no size
      if ( size != NOSIZE )
        INTERR(50754); // meaningless 'size' value
    case mop_h:           // helper functions have no size
      break;
    case mop_str:
      if ( size != addrsize(mvm) )
        INTERR(50755); // constant strings must be ADDRSIZE
      // fallthrough
    case mop_n:
      if ( size <= 0 || size > 8 )
        INTERR(51586); // bad constant size
      if ( (flags & VMOP_ANYSIZE) == 0 && !is_pow2(size) )
        INTERR(51587); // bad constant size
      break;
    case mop_r:
    default:
      // mop_a operand size is unknown
      if ( (flags & VMOP_ADRUSED) != 0 )
      {
        // &reg must be used with the size info.
        if ( t != mop_r && t != mop_l && size != NOSIZE )
          INTERR(50756); // unknown operand size is forbidden
      }
      else if ( (flags & VMOP_ANYSIZE) == 0 && !is_udt() )
      {
        // function calls might end up having zero size if the returned
        // result is not used or the function does not return anything
        if ( !is_valid_size(size)
          && (!is_arglist() || size != 0 && size != double_opsize(mvm)) // calls may be void or xmm
          && (size != double_opsize(mvm) || !accepts_double_size_ops(mvm, mv.curins->opcode)) )
        {
          // allow any size for external instruction addresses
          if ( mv.mba == nullptr || !mv.mba->is_extins_ea(mv.curins->ea) )
          {
            processor_t &ph = PH;
            if ( size != ph.sizeof_ldbl() && size != ph.tbyte_size )
              INTERR(50757); // bad operand size
          }
        }
        if ( !is_valid_fp_size(size) )
        {
          if ( (flags & VMOP_FPVAL) != 0 )
            INTERR(51275); // bad floating operand size
          if ( probably_floating() )
            INTERR(52064); // bad possibly floating operand size
        }
      }
      break;
  }

  switch ( t )
  {
    case mop_z: // none
      break;
    case mop_v: // global variable
      // check that the address fits 32bit if ida64 is running 32bit binary
      // assert: mvm.addrsize <= sizeof(ea_t)
      if ( g != BADADDR && !mv.fits_ea_space(g) )
        INTERR(52673); // address does not fit the address space
      break;
    case mop_n: // immediate
      if ( nnn == nullptr )
        INTERR(50758); // missing constant info
      if ( nnn->ea != BADADDR && !is_mapped(mv.mba->map_fict_ea(nnn->ea)) )
        INTERR(50759); // bad definition address of a constant
      if ( nnn->opnum > UA_MAXOP )
        INTERR(50760); // bad operand number of a constant
      if ( size < sizeof(uint64) && (nnn->value & ~(left_shift(uint64(1), size*8)-1)) != 0 )
        INTERR(50761); // illegal bits in constant value
      break;
    case mop_S: // local stack variable                     LOW
      if ( mv.mba != nullptr && s->mba != mv.mba )
        INTERR(50762); // foreign stack variable (from another mba)
      if ( s->off < 0 )
        INTERR(50763); // stack variables must have a positive offset
      if ( s->off != mv.ea2sval(s->off) )
        INTERR(52679);     // overflow
      break;
    case mop_r: // register                                 LOW
      if ( r < 0 )
        INTERR(50764); // negative microregister number is wrong
      if ( is_bit_reg(mvm) && size != 1 && mv.curins->opcode != m_ext )
        INTERR(50765); // bit registers must have size=1
      if ( size <= 0 )
        INTERR(50766); // bad register size
      break;
    case mop_d: // result of another instruction
      {
        if ( d == nullptr )
          INTERR(50767); // missing sub-instruction
        if ( size != d->d.size )
          INTERR(50768); // sub-instruction size mismatch
        micro_verifier_t mv2 = mv;
        mv2.curins = d;
        d->verify(mv2, false);
      }
      break;
    case mop_b: // micro basic block (mblock_t)
      if ( !mv.mba->is_pattern() && (b < 0 || b >= mv.mba->qty) )
        INTERR(50770); // bad block number
      if ( (flags & VMOP_MOPB) == 0 )
        INTERR(51650); // block number is forbidden for the operand
      break;
    case mop_f: // list of arguments
      if ( f == nullptr )
        INTERR(50771); // missing list of arguments
      f->verify(mv, size);
      if ( &mv.curins->d != this )
        INTERR(50772); // argument list is valid only as the 'd' operand
      if ( !is_mcode_call(mv.curins->opcode) )
        INTERR(50773); // argument list can be used only in a 'call' instruction
      break;
    case mop_l: // local variable
      if ( l->mba == nullptr )
        INTERR(50774); // lvar operand: missing reference to the microcode object
      if ( mv.mba != nullptr )
      {
        if ( l->mba != mv.mba )
          INTERR(50775); // lvar operand: reference to foreign microcode object
        const lvars_t &lvs = mv.mba->vars;
        if ( l->idx >= lvs.size() )
          INTERR(50776); // lvar operand: wrong variable index
        if ( !mv.mba->lvar_alloc_failed() )
        {
          const lvar_t &v = lvs[l->idx];
          if ( !mv.mba->is_pattern()
            && !mv.mba->is_stkarg(v)
            && !v.has_user_type()
            && !v.is_mapdst_var() ) // relax the check for mapdsts because map destination may eventually shrink
          {
            if ( size == NOSIZE )
            { // allow address references past end of item: &buf[sizeof(buf)]
              if ( v.width < l->off && !is_va_list_align(mvm, v, flags) )
                INTERR(50777); // lvar operand: reference past end of variable
            }
            else
            { // allow references only in the middle of the item
              if ( v.width <= l->off )
                INTERR(50778); // lvar operand: reference past end of variable
            }
          }
          if ( l->off < 0 )
            INTERR(50779); // lvar operand: reference before start of variable
        }
      }
      break;
    case mop_a: // address of variable (mop_l, mop_v, mop_S, mop_r)
      if ( a == nullptr )
        INTERR(51067); // missing operand in mop_a
      if ( a->t != mop_l && a->t != mop_v && a->t != mop_S )
      {
        if ( a->t != mop_r || mv.curins->l.t != mop_h && !a->is_kreg(mvm) )
          INTERR(50780); // addresses of registers are allowed only in helper functions
      }
      if ( size > addrsize(mvm) )
        INTERR(50781); // wrong size of an operand address
      a->verify(mv, VMOP_ADRUSED);
      break;
    case mop_h: // helper function
      if ( helper == nullptr || helper[0] == 0 )
        INTERR(50782); // wrong helper name
      if ( mv.curins->opcode != m_call )
        INTERR(50784); // helper can be used only in a 'call' instruction
      break;
    case mop_str:
      if ( cstr == nullptr )
        INTERR(50785); // missing string constant
      break;
    case mop_c: // cases
      if ( (flags & VMOP_MOPC) == 0 )
        INTERR(51651); // unexpected list of cases
      if ( c == nullptr )
        INTERR(50786); // missing list of cases
      c->verify(mv);
      break;
    case mop_fn:
      if ( fpc == nullptr )
        INTERR(50787); // missing floating point constant
      if ( uint(fpc->nbytes) > 16 )
        INTERR(50788); // size of a floating point constant is too big
      break;
    case mop_p:
      if ( pair == nullptr )
        INTERR(50789); // missing info about a mop_p operand
      if ( pair->lop.size != pair->hop.size )
        INTERR(50790); // low and high operand pairs must be of the same size
      if ( size != pair->lop.size+pair->hop.size )
        INTERR(50791); // inconsistent size of a pair operand
      if ( !valid_pair_part(pair->lop.t) )
        INTERR(50792); // invalid low pair part
      if ( !valid_pair_part(pair->hop.t) )
        INTERR(50793); // invalid high pair part
      pair->lop.verify(mv, 0);
      pair->hop.verify(mv, 0);
      // both parts of the pair can be calculated in any order
      if ( mv.blk != nullptr )
      {
        // we cannot call can_make_pair() if lvars was allocated
        // because in this case append_use_list() includes in the list the
        // whole var not its part and it can intersect with the other part
        // of this var. see interr_52045_6.idb
        if ( !mv.mba->lvars_allocated()
          && !mv.blk->can_make_pair(pair->lop, pair->hop) )
        {
          INTERR(52045); // calculation order of pair parts may change the result
                         // in other words, pair parts may depend on each other,
                         // this is wrong
        }
      }
      break;
    case mop_sc:
      {
        // only scattered vdlocs are allowed, other vdlocs must be
        // represented by other operand types
        if ( !scif->is_scattered() )
          INTERR(51135); // a scattered operand must have a scattered location
        ushort last = 0;
        const scattered_aloc_t &scvl = scif->scattered();
        scattered_aloc_t::const_iterator p = scvl.begin();
        scattered_aloc_t::const_iterator pend = scvl.end();
        while ( p != pend )
        {
          if ( p->off < last )
            INTERR(51136); // scattered: wrong part offset
          if ( ushort(p->off+p->size) < p->off )
            INTERR(51137); // scattered: wrong part offset
          last = p->off + p->size;
          if ( !p->is_stkoff() && !p->is_reg1() )
            INTERR(51138); // scattered: only simple reg/stack locations are permitted
          ++p;
        }
      }
      break;
    default:
      INTERR(50794); // wrong operand type
  }
}

//-------------------------------------------------------------------------
bool mop_t::is_valid_m_ext_op(const mvm_t &mvm, ea_t ea) const
{
  switch ( t )
  {
    case mop_b:
    case mop_f:
      return false;
    case mop_d:
      return !d->has_side_effects(mvm) && d->all_subinsns_are_at(ea);
  }
  return true;
}

//-------------------------------------------------------------------------
static void verify_segoff(
        const mba_t *mba,
        const mop_t &seg,
        const mop_t &off,
        int opsize)
{
  const mvm_t &mvm = mba->mvm;
  if ( off.size != addrsize(mvm) )
    if ( ((mvm.flags & MVM_OFF16_OK) == 0 || off.size != 2) )
      INTERR(50826); // wrong offset size
  if ( seg.size != 2 )
    INTERR(50827);   // wrong segment size
  if ( opsize <= 0 )
    INTERR(52816);   // wrong operand size

  // complain about resolvable [seg,off] pairs because they may cause
  // problems at the ctree generation time.
  if ( mba->maturity >= MMAT_GLBOPT3
    && off.is_glbaddr()
    && seg.t == mop_r
    && (seg.r == mvm.mr_ds || seg.r == mvm.mr_cs || seg.r == mvm.mr_ss)
    && mba->is_memref_resolvable(off, opsize) )
  {
    INTERR(52503); // memory reference must have been resolved
  }
}

//-------------------------------------------------------------------------
void minsn_t::verify(micro_verifier_t &mv, bool with_target) const
{
  const mvm_t &mvm = mv.mba->mvm;
  if ( !mv.mba->is_pattern() )
  {
    if ( ea == BADADDR )
      INTERR(50795); // unknown instruction address
    ea_t org_ea = mv.mba->map_fict_ea(ea);
    if ( !mv.mba->range_contains(org_ea) )
      INTERR(50863); // wrong instruction address
  }
  // check insn list
  if ( next != nullptr && next->prev != this )
    INTERR(50797); // inconsistent instruction list pointers
  if ( prev != nullptr && prev->next != this )
    INTERR(50798); // inconsistent instruction list pointers
  if ( !with_target && (prev != nullptr || next != nullptr) )
    INTERR(50799); // a subinstruction may not be part of an instruction list

  bool hasd = !d.empty();
  int lf = 0;
  int rf = 0;
  int df = with_target ? 0 : VMOP_PROPDST;

  // propagated instructions == subinstructions
  if ( !with_target && !is_mcode_propagatable(opcode) )
    INTERR(50800); // this opcode cannot be used in a subinstruction

  // check fpinsn flag
  switch ( opcode )
  {
    case m_ext:
    case m_ldx:
    case m_stx:
    case m_mov:
    case m_setnz:
    case m_setz:
    case m_setae:
    case m_setb:
    case m_seta:
    case m_setbe:
    case m_setp:
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jbe:
    case m_jb:
    case m_ja:          // may or may not be fpinsn
      break;
    default:
      if ( is_mcode_fpu(opcode) != is_fpinsn() )
        INTERR(50801); // wrong FPINSN mark
      break;
  }

  // check other IPROP_... bits
  if ( is_extstx() && opcode != m_ext )
    INTERR(52723); // IPROP_EXTSTX may be set only for m_ext

  switch ( opcode )
  {
    // these insn cannot be propagated
    case m_goto:
    case m_nop:
    case m_ext:
    case m_push:
    case m_ijmp:
    case m_stx:
    case m_und:
    case m_pop:
    case m_jcnd:
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jb:
    case m_ja:
    case m_jbe:
    case m_jg:
    case m_jge:
    case m_jl:
    case m_jle:
    case m_jtbl:
    case m_ret:
      if ( !with_target )
        INTERR(50802); // cannot be a subinstruction
      break;
    // these insns may be propagated
    case m_add:
    case m_sub:
    case m_mul:
    case m_or:
    case m_and:
    case m_xor:
    case m_shl:
    case m_shr:
    case m_sar:
    case m_cfadd:
    case m_ofadd:
    case m_cfshl:
    case m_cfshr:
    case m_ldc:
    case m_neg:
    case m_xds:
    case m_xdu:
    case m_low:
    case m_high:
    case m_setz:
    case m_setp:
    case m_setnz:
    case m_sets:
    case m_lnot:
    case m_bnot:
    case m_setae:
    case m_setb:
    case m_seta:
    case m_setbe:
    case m_setg:
    case m_setge:
    case m_setl:
    case m_setle:
    case m_seto:
    case m_f2i:
    case m_f2u:
    case m_i2f:
    case m_u2f:
    case m_f2f:
    case m_fneg:
    case m_fadd:
    case m_fsub:
    case m_fmul:
    case m_fdiv:
      if ( hasd != with_target )
        INTERR(50803); // subinstructions must lack the 'd' operand
                       // top level instructions must have the 'd' operand
      break;
      // ldx/mov/div/mod instructions without the target are allowed even at the top level
      // such mov instructions are deleted by eliminate_dead_regs()
      // ldx instructions may survided up to m2c and generate useless memory
      // reads, div/mod can generate division by zero
      // well, they are useful because they show that there was a memory access
      // division by zero in the input binary code.
    case m_ldx:
    case m_mov:
    case m_udiv:
    case m_sdiv:
    case m_umod:
    case m_smod:
      // even if the target register is not present, the size must be present
      if ( d.empty() )
        df |= VMOP_PROPDST;
      break;
    case m_call:
    case m_icall:
      break;
    default:
      INTERR(50804); // wrong instruction opcode
  }

  if ( !with_target && (next != nullptr || prev != nullptr) )
    INTERR(50805); // subinstructions must not have prev or next fields

  // check operand presence
  switch ( opcode )
  {
    case m_nop:
    case m_ret:
      if ( !l.empty()
        || !r.empty()
        || !d.empty() )
      {
        INTERR(50806); // operand(s) are forbidden
      }
      break;
    case m_ext:
      lf |= VMOP_ANYSIZE;
      rf |= VMOP_ANYSIZE;
      df |= VMOP_ANYSIZE;
      if ( !l.is_valid_m_ext_op(mvm, ea) )
        INTERR(50807); // wrong operand of m_ext
      if ( !r.is_valid_m_ext_op(mvm, ea) )
        INTERR(50808); // wrong operand of m_ext
      if ( !d.is_valid_m_ext_op(mvm, ea) )
        INTERR(50809); // wrong operand of m_ext
      break;
    case m_push:
      if ( l.empty()
        || !r.empty()
        || !d.empty() )
      {
        INTERR(50811); // wrong operands
      }
      break;
    case m_goto:
      if ( l.t != mop_b && l.t != mop_v
        || !r.empty()
        || !d.empty() )
      {
        INTERR(50812); // wrong operands
      }
      lf = VMOP_ADRUSED | VMOP_MOPB;
      break;
    case m_ijmp:
      if ( !l.empty()
        || r.empty()
        || d.empty() )
      {
        INTERR(50813); // wrong operands
      }
      break;
    case m_stx:
    case m_ldx:
    case m_add:
    case m_sub:
    case m_mul:
    case m_udiv:
    case m_sdiv:
    case m_umod:
    case m_smod:
    case m_or:
    case m_and:
    case m_xor:
    case m_shl:
    case m_shr:
    case m_sar:
    case m_cfadd:
    case m_ofadd:
    case m_cfshl:
    case m_cfshr:
    case m_setp:
    case m_setz:
    case m_setnz:
    case m_setae:
    case m_setb:
    case m_seta:
    case m_setbe:
    case m_setg:
    case m_setge:
    case m_setl:
    case m_setle:
    case m_seto:
    case m_fadd:
    case m_fsub:
    case m_fmul:
    case m_fdiv:
      if ( l.empty() || r.empty() )
        INTERR(50815); // wrong operands
      break;
    case m_low:
    case m_high:
    case m_ldc:
    case m_mov:
    case m_neg:
    case m_xds:
    case m_xdu:
    case m_sets:
    case m_lnot:
    case m_bnot:
    case m_f2i:
    case m_f2u:
    case m_i2f:
    case m_u2f:
    case m_f2f:
    case m_fneg:
      if ( l.empty() || !r.empty() )
        INTERR(50817); // wrong operands
      break;
    case m_und:
    case m_pop:
      if ( !l.empty()
        || !r.empty()
        || d.empty() )
      {
        INTERR(50818); // wrong operands
      }
      break;
    case m_jcnd:
      if ( l.empty()
        || !r.empty()
        || d.t != mop_v && d.t != mop_b )
      {
        INTERR(50819); // wrong operands
      }
      df = VMOP_ADRUSED | VMOP_MOPB;
      break;
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jb:
    case m_ja:
    case m_jbe:
    case m_jg:
    case m_jge:
    case m_jl:
    case m_jle:
      if ( l.empty()
        || r.empty()
        || d.t != mop_v && d.t != mop_b )
      {
        INTERR(50820); // wrong operands
      }
      df = VMOP_ADRUSED | VMOP_MOPB;
      break;
    case m_jtbl:
      if ( l.empty()
        || r.t != mop_c
        || !d.empty() )
      {
        INTERR(50821); // wrong operands
      }
      rf |= VMOP_MOPC;
      break;
    case m_call:
      if ( !r.empty() )
        INTERR(50822); // wrong operands
      lf = VMOP_ADRUSED;
      // no break
    case m_icall:
      switch ( l.t )
      {
        case mop_z:
        case mop_b:
        case mop_f:
        case mop_a:
          INTERR(50823); // wrong operands
      }
      if ( mv.blk != nullptr && (mv.blk->flags & MBL_CALL) != 0 && !d.is_arglist() )
        INTERR(50824); // call without an argument list?!
      // each call must have a unique address. we need this to avoid confusion
      // and interrs during type derivation. however, we enforce this rule only
      // if MBA2_NO_DUP_CALLS is set because users may install third party
      // plugins that make copies of calls.
      if ( (mv.mba->flags2 & MBA2_NO_DUP_CALLS) != 0
        && mv.seen_calls != nullptr
        && l.t != mop_h // ignore helpers
        && !mv.mba->is_pattern() )
      {
        if ( !mv.seen_calls->add_unique(ea) )
          INTERR(51264); // indistinguishable call instructions
      }
      break;
  }

  // ok, now check the operand sizes
  switch ( opcode )
  {
    case m_ijmp:
      verify_segoff(mv.mba, r, d, addrsize(mvm));
      break;
    case m_stx:
      verify_segoff(mv.mba, r, d, l.size);
      break;
    case m_ldx:
      verify_segoff(mv.mba, l, r, d.size);
      break;
    case m_add:
    case m_sub:
    case m_mul:
    case m_udiv:
    case m_sdiv:
    case m_umod:
    case m_smod:
    case m_or:
    case m_and:
    case m_xor:
    case m_fadd:
    case m_fsub:
    case m_fmul:
    case m_fdiv:
      if ( r.size != d.size )
        INTERR(50830); // wrong operand sizes
      // no break
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jb:
    case m_ja:
    case m_jbe:
    case m_jg:
    case m_jge:
    case m_jl:
    case m_jle:
      if ( l.size != r.size )
        INTERR(50831); // wrong operand sizes
      break;
    case m_cfadd:
    case m_ofadd:
    case m_setp:
    case m_setz:
    case m_setnz:
    case m_setae:
    case m_setb:
    case m_seta:
    case m_setbe:
    case m_setg:
    case m_setge:
    case m_setl:
    case m_setle:
    case m_seto:
      if ( l.size != r.size )
        INTERR(50832); // wrong operand sizes
      // no break
    case m_sets:
      if ( d.size != 1 )
        INTERR(50833); // wrong operand size
      break;
    case m_cfshl:
    case m_cfshr:
      if ( r.size != 1 || d.size != 1 )
        INTERR(50834); // wrong operand sizes
      break;
    case m_shl:
    case m_shr:
    case m_sar:
      if ( r.size != 1 )
        INTERR(50835); // wrong operand size
      if ( r.t == mop_n )
      {
        int shm = mvm.get_shift_mask(l.size);
        if ( shm != 0 && uint8(r.nnn->value) > shm )
          INTERR(52118); // wrong shift value
      }
      // no break
    case m_ldc:
    case m_mov:
    case m_neg:
    case m_bnot:
    case m_fneg:
      if ( l.size != d.size )
        INTERR(50836); // wrong operand sizes
      break;
    case m_lnot:
      if ( l.size != 1 || d.size != 1 )
        INTERR(52338); // wrong operand size for lnot
      break;
    case m_xds:
    case m_xdu:
      if ( l.size >= d.size )
        INTERR(50837); // wrong operand sizes
      break;
    case m_low:
    case m_high:
      if ( l.size <= d.size )
        INTERR(50838); // wrong operand sizes
      if ( l.is_insn() )
      {
        const minsn_t *ld = l.d;
        if ( (ld->opcode == m_low || ld->opcode == m_high) && ld->l.is_udt() )
        {
          // low(high(udt)), high(low(udt)): accept any size of the inner insn
          // (they are handled in a special way in m2c)
          lf = VMOP_ANYSIZE;
        }
      }
      break;
  }

  if ( opcode != m_ijmp && opcode != m_stx && opcode != m_ext )
  {
    switch ( d.t )
    {
      case mop_d:
        if ( opcode == m_und && d.d->opcode == m_ldx )
          break;  // und ss:(sp+#N) is allowed
        INTERR(50839); // the destination cannot be another insn
      case mop_a:
      case mop_n:
      case mop_fn:
      case mop_str:
      case mop_h:
        INTERR(51652); // wrong instruction destination
    }
  }

  // check fpinsn operand sizes
  if ( is_fpinsn() )
  {
    if ( is_l_fpval() )
      lf |= VMOP_FPVAL;
    if ( is_r_fpval() )
      rf |= VMOP_FPVAL;
    if ( is_d_fpval() )
      df |= VMOP_FPVAL;
  }

  if ( is_assert() && !is_mov() )
    INTERR(52123); // only mov/f2f instructions may be assertions

  // check each operand
  mv.curins = CONST_CAST(minsn_t*)(this);
  l.verify(mv, lf);
  r.verify(mv, rf);
  d.verify(mv, df);
}

//-------------------------------------------------------------------------
void mblock_t::verify(eavec_t *seen_calls) const
{
  if ( (mba->get_mba_flags2() & MBA2_DONT_VERIFY) != 0 )
    return;
  if ( nextb != nullptr && nextb->prevb != this )
    INTERR(50840); // corrupted block list
  if ( prevb != nullptr && prevb->nextb != this )
    INTERR(50841); // corrupted block list

  if ( (nextb == nullptr) != (mba->qty-1 == serial) )
    INTERR(50842); // wrong end of the block list
  if ( (prevb == nullptr) != (serial == 0) )
    INTERR(50843); // wrong beginning of the block list

  int all = MBL_PRIV|MBL_FAKE|MBL_GOTO|MBL_TCAL|MBL_PUSH|MBL_DMT64|MBL_COMB
          | MBL_PROP|MBL_DEAD|MBL_LIST|MBL_INCONST|MBL_CALL|MBL_BACKPROP
          | MBL_NORET|MBL_DSLOT|MBL_VALRANGES|MBL_KEEP|MBL_INLINED|MBL_EXTFRAME;
  if ( flags & ~all )
    INTERR(50844); // unknown bits in the block flags
  if ( !needs_propagation() && lists_dirty() && (flags & MBL_INCONST) == 0 )
    INTERR(50845); // use-def lists must be ready if propagation is not requested

  if ( !mustbuse.is_subset_of(maybuse) )
    INTERR(50846); // must-use locations must be subset of may-use locations
  if ( !mustbdef.is_subset_of(maybdef) )
    INTERR(50847); // must-def locations must be subset of may-def locations

  if ( serial == 0 || type == BLT_STOP || type == BLT_XTRN )
  {
    if ( head != nullptr && !mba->is_pattern() )
      INTERR(51814); // entry/exit/extern blocks must be empty
    if ( !mustbuse.empty() || !mustbdef.empty() )
      INTERR(50848); // entry/exit/extern blocks: cannot define/use anything
    if ( serial == 0 )
    {
      if ( !maybuse.empty() )
        INTERR(50849); // entry block: may not use anything
    }
    else
    {
      if ( !maybdef.empty() )
        INTERR(50850); // exit/extern blocks: may not define anything
    }
  }

  if ( serial >= mba->qty )
    INTERR(50851); // wrong block serial number
  if ( mba->natural[serial] != this )
    INTERR(50852); // corrupted 'natural' block array

  if ( minbstkref != 0 && mba->minstkref > minbstkref )
    INTERR(50853); // wrong minbstkref

  if ( (flags & MBL_EXTFRAME) != 0 )
  {
    if ( subframe_idx == mba_t::MAIN_SUBFRAME_IDX )
      INTERR(52729); // the main chunk cannot have a subframe
    if ( subframe_idx >= mba->subframes.size() )
      INTERR(52730); // wrong subframe index
    if ( local_minstkref != 0 )
    {
      const subframe_t &sf = mba->subframes[subframe_idx];
      if ( local_minstkref != sf.top() && !sf.contains(local_minstkref) )
        INTERR(52731); // wrong local minstkef of a subframe
      if ( local_minstkref < sf.minstkref )
        INTERR(52732); // too low subframe minstkref
    }
  }

  if ( type != BLT_NONE )
  {
    int ns;
    switch ( type )
    {
      // case BLT_NONE: // unknown block type
      //  break;
      case BLT_STOP: // stops execution
        ns = 0;
        // stop block may not have dirty lists after building calls
        // its use-list is calculated by refine_return_type and must not
        // be destroyed
        if ( lists_dirty() && mba->callinfo_built() )
          INTERR(51328); // exit block with dirty use-def lists?!
        break;
      case BLT_XTRN: // external block
      case BLT_0WAY: // does not have successors
        ns = 0;
        break;
      case BLT_1WAY: // passes execution to one block
        ns = 1;
        // passes execution to another function?
        if ( is_call_block() )
        {
          if ( tail->is_noret_call(hv.mvm, NORET_FORBID_ANALYSIS) ) // -V595 tail is used before verifying against nullptr
            INTERR(51774);    // should be BLT_0WAY
          if ( nsucc() == 0 || succ(0) != serial+1 )
            INTERR(50854); // 1-way call block must pass execution to the next block
        }
        break;
      case BLT_2WAY: // passes execution to two blocks
        ns = 2;
        break;
      case BLT_NWAY: // passes execution to many blocks
        ns = nsucc();
        break;
      default:
        INTERR(51815); // wrong block type
    }
    // jtbl instructions always imply BLT_NWAY
    if ( (type == BLT_NWAY) != (tail != nullptr && tail->opcode == m_jtbl) )
      INTERR(50855); // n-way blocks can be used only with jtbl instructions

    if ( nsucc() != ns )
      INTERR(50856); // wrong size of a block successor set
    for ( int i=0; i < ns; i++ )
    {
      int n = succ(i);
      if ( n < 0 || n >= mba->qty )
        INTERR(50857); // wrong block number is the successor set
      if ( !mba->natural[n]->predset.has(serial) )
        INTERR(50858); // inconsistent predecessor set
    }

    // check that the successor list is correct
    intvec_t outs;
    switch ( tail == nullptr ? m_nop : tail->opcode )
    {
      case m_jtbl:
        if ( tail->r.t != mop_c )
          INTERR(50859); // jtbl without the case list?!
        outs = tail->r.c->targets;
        break;
      case m_goto:
        if ( tail->l.t == mop_b )
          outs.add(tail->l.b);
        break;
      case m_jcnd:
      case m_jnz:
      case m_jz:
      case m_jae:
      case m_jb:
      case m_ja:
      case m_jbe:
      case m_jg:
      case m_jge:
      case m_jl:
      case m_jle:
        // conditional jumps must pass control to the next block
        // if the condition is not satisfied
        outs.add(serial+1);
        outs.add_unique(tail->d.b); // if true, control is passed to the jump target
        break;
      default:
        if ( ns != 0 )
          outs.add(serial+1);
        break;
      case m_ijmp:
      case m_ret:
        break;
      case m_ext:
        // we cannot verify m_ext insns because of ignored insns
        outs = succset;
        break;
    }
    if ( outs != succset )
      INTERR(50860); // wrong successor set
  }

  // check that predecessors have us in their succset's
  for ( int i=0; i < npred(); i++ )
  {
    int p = pred(i);
    if ( !mba->natural[p]->succset.has(serial) )
      INTERR(50861); // inconsistent successor set
  }

  // check that predecessors are unique
  {
    intset_t pr;
    for ( int i=0; i < npred(); i++ )
    {
      int p = pred(i);
      if ( !pr.insert(p).second )
        INTERR(50862); // duplicate predecessors
    }
  }

  bool found_tail = false;
  micro_verifier_t mv;
  mv.mba = mba;
  mv.blk = CONST_CAST(mblock_t *)(this);
  mv.seen_calls = seen_calls;
  for ( minsn_t *i=head; i != nullptr; i=i->next )
  {
    mv.topins = i;
    mv.curins = i;
    i->verify(mv, true);
    if ( i == tail )
      found_tail = true;
    else if ( must_mcode_close_block(i->opcode, i->d.empty()) )
      INTERR(50864); // opcode must be the last instruction in a block
    if ( (flags & MBL_PUSH) == 0 // converted push/pop to mov instructions?
      && (i->opcode == m_push || i->opcode == m_pop) )
    {
      INTERR(50865); // push/pop may be present only before converting them
    }
  }

  if ( !empty() )
  {
    if ( !found_tail )
      INTERR(50866); // non-empty block without the tail instruction?!
    if ( head->prev != nullptr )
      INTERR(50867); // head must be the first instruction
    if ( tail->next != nullptr )
      INTERR(50868); // tail must be the last instruction
    if ( (mba->get_mba_flags() & MBA_NOFUNC) == 0 )
    {
      if ( start >= end && (flags & MBL_FAKE) == 0 )
        INTERR(50869); // wrong block boundaries
      if ( end != BADADDR
        && getf_reginsn(head) != nullptr
        && (mba->get_mba_flags() & MBA_CMBBLK) != 0
        && !test_bit(mba->occurred_warns, WARN_FIXED_INSN) )
      {
        // since we subtract one, we cannot use mba_t::range_contains directly
        ea_t real_end = mba->map_fict_ea(end);
        if ( !mba->mbr.range_contains(real_end-1) )
          INTERR(50870); // block outside of function boundaries
      }
    }
  }
  else
  {
    if ( head != nullptr )
      INTERR(50871); // empty block: head instruction must not exist
    if ( tail != nullptr )
      INTERR(50872); // empty block: tail instruction must not exist
  }

  if ( lists_ready()
    && !mba->lvars_allocated()
    && !mba->deleted_pairs()     // delete_dest_pairs() may introduce kernel regs that are not taken into account in use/def lists
    && serial != 0
    && type != BLT_STOP
    && type != BLT_XTRN )
  {
    mlist_t test_maybuse;
    mlist_t test_maybdef;
    mlist_t test_mustbuse;
    mlist_t test_mustbdef;
    mlist_t test_dnu;
    for ( minsn_t *m=head; m != nullptr; m=m->next )
    {
      if ( !m->is_assert() )
      {
        mlist_t ui1 = build_use_list(*m, MAY_ACCESS);
        if ( !ui1.empty() )
        {
          test_dnu.sub(ui1);
          ui1.sub(extract_restricted_list(mba, test_maybdef));
          test_maybuse.add(ui1);
          mlist_t ui2 = build_use_list(*m, MUST_ACCESS);
          ui2.sub(test_maybdef);
          test_mustbuse.add(ui2);
        }
        mlist_t di1 = build_def_list(*m, MAY_ACCESS);
        if ( !di1.empty() )
        {
          // fixme: spoiled registers are not really defined by the block
          //        introduce 'spoiled' list
          test_maybdef.add(di1);
          mlist_t di2 = build_def_list(*m, MUST_ACCESS);
          test_mustbdef.add(di2);
          test_dnu.add(extract_restricted_list(mba, di2));
        }
      }
    }
    const mlist_t &temp = get_temp_regs(mba->mvm);
    test_mustbdef.sub(temp);
    test_maybdef.sub(temp);
    test_dnu.sub(extract_restricted_list(mba, temp));
    if ( test_maybuse != maybuse )
      INTERR(50873); // wrong maybuse
    if ( test_maybdef != maybdef )
      INTERR(50874); // wrong maybdef
    if ( test_mustbuse != mustbuse )
      INTERR(50875); // wrong mustbuse
    if ( test_mustbdef != mustbdef )
      INTERR(50876); // wrong mustbdef
    if ( test_dnu != dnu )
      INTERR(50877); // wrong dnu

    // block should access only main frame or its local frame
    ea_t sp = mba->spbase;
    ivlset_t invisible_mem(ivl_t(sp, mba->main_subframe().bottom));
    if ( (flags & MBL_EXTFRAME) != 0 )
    {
      const subframe_t &sf = mba->subframes[subframe_idx];
      invisible_mem.sub(sp+sf.bottom, sf.size);
    }
    if ( invisible_mem.has_common(mustbdef.mem) )
      INTERR(52733); // block writes to a wrong stack location
    if ( invisible_mem.has_common(mustbuse.mem) )
    {
      // block can use memory above subframe if a function call has too many stkargs
      if ( !mba->subframe_overflow() )
        INTERR(52724); // block reads from a wrong stack location
    }
  }

  const mlist_t &tmp = get_temp_regs(mba->mvm);
  if ( maybuse.has_common(tmp) )
    INTERR(50920); // temporary registers cannot cross block boundaries
}

//-------------------------------------------------------------------------
// verify input arguments
void mba_t::verify_args() const
{
  // do not check first stkoff if MBA2_ARGIDX_OK is not yet set
  // (necessary dummy arguments can be added by tune_cc())
  sval_t base_stkoff = argidx_ok() ? inargoff : -1;
  if ( final_type && is_user_cc(cc) && !idb_type.empty() )
  {
    // disable check of stack offsets in case of specified by user function
    // with explicit stack locations
    func_type_data_t fti;
    if ( idb_type.get_func_details(&fti) && (fti.flags & FTI_EXPLOCS) != 0 )
      base_stkoff = -1;
  }
  usercc_argloc_verifier_t argloc_verifier(hv, base_stkoff);
  mlist_t used;
  for ( int i=0; i < argidx.size(); i++ )
  {
    const lvar_t &v = vars[argidx[i]];
    if ( !v.is_arg_var() )
      INTERR(50906); // non-argvar in the argument list

    if ( lvar_alloc_failed() )
      continue;

    mlist_t vlst;
    v.append_list(this, &vlst);
    if ( vlst.has_common(used) )
      INTERR(50904); // overlapping arguments
    used.add(vlst);

    if ( is_user_cc(cc) && nargs() < hv.hrcfg.max_func_args )
    {
      if ( !argloc_verifier.validate_next_vdloc(v.location, v.type(), v.width) )
        INTERR(51053); // incorrect argument locations for usercall
    }
  }
  if ( is_cdtr() )
  { // the first argument must be 'this'
    if ( nargs() == 0 )
      INTERR(51871); // constructor without arguments (no 'this'?!)
    const lvar_t &thisarg = arg(0);
    if ( !thisarg.has_user_name() && thisarg.name != "this" )
      INTERR(51872); // first argument of a constructor must be named 'this'
    if ( !thisarg.has_user_type() && !thisarg.type().is_ptr() )
      INTERR(51873); // first argument of a constructor must be a pointer
    if ( !thisarg.is_thisarg() )
      INTERR(51887); // first argument of a constructor must be marked as 'this'
  }
}

//-------------------------------------------------------------------------
static void verify_lvar_names(const strings_t &s1, const strings_t &s2)
{
//  for ( auto &p : s1 )
//    msg("s1 %s\n", p.c_str());
//  for ( auto &p : s2 )
//    msg("s2 %s\n", p.c_str());

  strings_t::iterator p = s1.begin();
  strings_t::iterator q = s2.begin();
  while ( true )
  {
    if ( p == s1.end() )
    {
      if ( q != s2.end() )
        INTERR(51502); // inconsistent lvar name cache
      break;
    }
    if ( q == s2.end() )
      INTERR(51503); // inconsistent lvar name cache
    if ( *p != *q )
      INTERR(51504); // inconsistent lvar name cache
    ++p;
    ++q;
  }
}

//-------------------------------------------------------------------------
void mba_t::verify_lvars(bool check_args) const
{
  strings_t names;
  std::set<lvar_locator_t> seen;
  for ( int i=0; i < vars.size(); i++ )
  {
    const lvar_t &v = vars[i];
    if ( v.name.empty() )
      QASSERT(50891, lvars_renamed()); // empty variable names are permitted only at the final stage
    else
      names.insert(v.name);
    if ( v.type().empty() )
      INTERR(50892); // lvar without a type
    if ( !v.type().is_correct() )
      INTERR(50893); // incorrect lvar type
    // the public version won't check this for now.
    // however, we will enforce this requirement in the future
#ifdef TESTABLE_BUILD
    if ( v.defea == BADADDR && precise_defeas() )
      INTERR(50894); // wrong lvar definition address
#endif
    if ( v.defblk < 0 || v.defblk >= qty && qty > 0 )
      INTERR(50895); // wrong lvar definition block number
    if ( argidx_ok() )
    {
      if ( v.is_arg_var() )
      {
        if ( v.defblk != 0 )
          INTERR(50896); // arguments must be defined in block #0
        if ( lvars_allocated() )
        { // check argidx only when lvars are allocated
          if ( !argidx.has(i) )
            INTERR(50897); // an argument variable is not in the argument list
        }
      }
      else
      {
        if ( v.is_thisarg() )
          INTERR(51888); // 'this' variable is not marked as argument
      }
      if ( check_args && v.is_arg_var() == v.is_notarg() )
        INTERR(52036); // lvar is marked as argument and non-argument
    }
    if ( v.width <= 0 )
      INTERR(51297); // wrong variable size
    if ( v.type().get_size() != v.width )
    {
      if ( !v.is_unpadded() )
        INTERR(50898); // variable type and size mistmatch
      if ( v.width != v.type().get_unpadded_size() )
        INTERR(51926); // variable type and size mismatch even when taking into account the padding
    }
    if ( v.location.is_badloc() )
      INTERR(51219); // wrong variable location
    if ( retvaridx == i )
    {
      if ( v.location.has_stkoff() && !has_stack_retval() )
        INTERR(50899); // return value cannot have any stack part
      if ( !v.is_result_var() )
        INTERR(50900); // return variable is not marked as such
    }
    else
    {
      if ( v.is_result_var() )
        INTERR(50901); // a variable is marked as retval but is not returned
    }
    if ( (flags2 & MBA2_NO_DUP_LVARS) != 0
      && precise_defeas()
      && !lvar_alloc_failed()
      && !seen.insert(v).second )
    {
      INTERR(50902); // two indistinguishable variables (the same location and defea)
    }
  }
  if ( lvar_names_ok() )
    verify_lvar_names(lvar_names, names);
}

//-------------------------------------------------------------------------
void mba_t::verify(bool always) const
{
  if ( !always && !hv.should_verify() )
    return;
  if ( (get_mba_flags2() & MBA2_DONT_VERIFY) != 0 )
    return;
  DECLARE_HIT_COUNTER("verify");

  bool real_code = !is_pattern() && (flags & MBA_LOADED) == 0;
  int cnt = 0;
  ivlset_t fbody;
  eavec_t seen_calls;
  for ( mblock_t *b=blocks; b != nullptr; b=b->nextb )
  {
    b->verify(&seen_calls);
    if ( natural[cnt] != b )
      INTERR(50878); // inconsistent basic block numbering
//msg("%d: %a..%a\n", cnt, b->start, b->end);
    if ( real_code && (b->flags & MBL_FAKE) == 0 && (flags & MBA_PREOPT) == 0 )
    {
      ivl_t bbody(b->start, b->end-b->start);
      if ( fbody.has_common(bbody) )
        INTERR(50879); // overlapping basic blocks
      fbody.add(bbody);
    }
    cnt++;
  }
  if ( cnt != qty )
    INTERR(50880); // inconsistent list of basic blocks

  if ( flags & 0x80000000 )
    INTERR(51685); // reserved mba_t::flags bit is set
  if ( flags2 & ~MBA2_ALL_FLAGS )
    INTERR(50881); // reserved mba_t::flags2 bit is set

  //mbl_graph_t *bg;              // graph of basic blocks
  //prolog_info_t *pi;            // prolog information

  if ( fullsize < 0 || stacksize < 0 || minstkref < 0 )
    INTERR(50882); // negative function frame sizes

  if ( !is_pattern() && subframes.empty() )
    INTERR(52701); // at least one subframe should exist
  if ( !subframes.empty() )
  {
    const subframe_t &mf = main_subframe();
    if ( mf.top() != stacksize )
      INTERR(52702); // the main frame always ends with 'stacksize'
    if ( mf.minstkref != minstkref )
      INTERR(52703); // mba_t::minstkref is just a copy of main frame minstkref
    if ( subframes.back().bottom != 0 )
      INTERR(52704); // the last subframe must be based at zero
    for ( size_t i = 0; i < subframes.size(); ++i )
    {
      const auto &sf = subframes[i];
      if ( i != 0 && sf.top() != subframes[i-1].bottom )
        INTERR(52705); // should follow each other in descending order with no gaps
      if ( i != MAIN_SUBFRAME_IDX )
      {
        if ( !sf.contains(sf.minstkref) && sf.minstkref != sf.top() )
          INTERR(52706); // subframe minstkref, if undefined, must point to the top
      }
    }
  }
  if ( fullsize < minargref )
    INTERR(50883); // wrong minargref
  if ( real_code )
  {
    if ( fullsize < stacksize )
      INTERR(50884); // full stack size is less than lvar area size?!
    if ( minstkref > stacksize )
      INTERR(50885); // minstkref is higher than lvar area size?!
    if ( frsize+frregs > stacksize )
      INTERR(50886); // wrong lvar area size
    func_t *pfn = get_curfunc();
    if ( pfn != nullptr )
    {
      if ( pfn->frsize != frsize )
        INTERR(50887); // wrong frame frsize
      if ( pfn->frregs != frregs )
        INTERR(50888); // wrong frame frregs
      if ( pfn->fpd != fpd )
        INTERR(51704); // wrong frame fpd
      if ( get_frame_retsize(pfn) != retsize )
        INTERR(50889); // wrong frame retsize
    }

    if ( is_snippet() )
    {
      if ( mbr.ranges.empty() )
        INTERR(52620); // empty snippet range
    }
    else
    {
      if ( has_outlines() )
      { // microcode is marked as having outlined code
        if ( mbr.ranges.empty() )
          INTERR(52666); // missing inlined ranges
      }
      else
      { // microcode is not marked as having outlined code
        if ( !mbr.ranges.empty() )
          INTERR(52667); // unexpected inlined ranges
      }
    }

    // verify standard intervals
    ea_t off = spbase;
    if ( get_std_region(MMIDX_GLBLOW).end() != off )
      INTERR(52098); // wrong start of the standard region GLBLOW
    if ( get_std_region(MMIDX_LVARS).off != off )
      INTERR(52099); // wrong start of the standard region LVARS
    if ( get_std_region(MMIDX_LVARS).size != stacksize )
      INTERR(52100); // wrong size of the standard region LVARS
    off += stacksize;
    if ( get_std_region(MMIDX_RETADDR).off != off )
      INTERR(52101); // wrong start of the standard region RETADDR
    if ( get_std_region(MMIDX_RETADDR).size != retsize )
      INTERR(52102); // wrong size of the standard region RETADDR
    off += retsize;
    if ( get_std_region(MMIDX_SHADOW).off != off )
      INTERR(52103); // wrong start of the standard region SHADOW
    if ( get_std_region(MMIDX_SHADOW).size != shadow_args )
      INTERR(52104); // wrong size of the standard region SHADOW
    off += shadow_args;
    if ( !common_stkvars_stkargs() || consumed_argregs.empty() )
    {
      if ( spbase + inargoff != off )
        INTERR(52108); // inconsistent offset of the argument area
    }
    else
    {
      // after fix_scattered_movs() INARGOFF may be less than STACKSIZE
      if ( spbase + inargoff > off )
        INTERR(52109); // inconsistent offset of the argument area
    }
    if ( get_std_region(MMIDX_ARGS).off != off )
      INTERR(52105); // wrong start of the standard region ARGS
    uval_t max_argsize = hv.hrcfg.max_func_args * slotsize();
    if ( get_std_region(MMIDX_ARGS).size != max_argsize - shadow_args )
      INTERR(52106); // wrong size of the standard region ARGS
    off += max_argsize - shadow_args;
    if ( spbase + fullsize != off )
      INTERR(52112); // wrong full stack size
    if ( get_std_region(MMIDX_GLBHIGH).off != off )
      INTERR(52107); // wrong start of the standard region GLBHIGH
  }

  if ( !is_pattern() )
    verify_lvars(true);

  verify_args();

  if ( retvaridx != -1 && (retvaridx < 0 || retvaridx >= vars.size()) )
    INTERR(50911); // wrong index of the return variable

  // int npurged;         // -1 - unknown
  if ( cc == 0 )
    INTERR(50912); // wrong calling convention

  if ( final_type )
  {
    if ( !idb_type.is_correct() )
      INTERR(50913); // incorrect function type retrieved from the idb
  }

  if ( real_code && use_frame() )
  {
    flags64_t f = get_flags(entry_ea);
    if ( !is_func(f) )
      INTERR(50914); // function entry is not marked as a function
  }
}

//-------------------------------------------------------------------------
void pattern_t::verify(bool always) const
{
  mba_t::verify(always);

  for ( labels_t::const_iterator p=labels.begin(); p != labels.end(); ++p )
  {
    const insref_t &ir = p->second;
    if ( ir.nblk < 0 || ir.nblk >= qty )
      INTERR(50958); // wrong block reference in a pattern
    const mblock_t *b = get_mblock(ir.nblk);
    const minsn_t *m = b->get_insn(ir.nins);
    if ( m == nullptr )
      INTERR(50959); // wrong instruction reference in a pattern
  }

  micro_verifier_t mv;
  mv.mba = CONST_CAST(pattern_t*)(this);
  mv.blk = nullptr;
  for ( int i=0; i < postactions.size(); i++ )
  {
    mv.topins = mv.curins = CONST_CAST(minsn_t*)(&postactions[i].insn);
    mv.topins->verify(mv, true);
  }

  mv.topins = mv.curins = nullptr;
  for ( int i=0; i < conditions.size(); i++ )
    conditions[i].verify(mv, 0);

  for ( int i=0; i < typereqs.size(); i++ )
    typereqs[i].mop.verify(mv, 0);
}

//-------------------------------------------------------------------------
// in order to lvar allocation to create distinguishable lvars,
// all instruction destinations must be different for any given ea.
// unfortunately this requirement is too strong for the moment.
// there are some instructions (adc, for example), that
// update their destinations multiple times. we will have to
// this this in the future. meanwhile, this check is commented out.
void mba_t::verify_dest_eas() const
{
/*
  struct ida_local dest_ea_verifier_t : public minsn_visitor_t
  {
    const mlist_t &tempregs;
    std::set<lvar_locator_t> seen;
    int idaapi visit_minsn()
    {
      if ( curins->modifies_d() )
      {
        lvar_locator_t ll;
        if ( curins->d.is_reg() )
        {
          ll.location = ARGLOC_REG | curins->d.r;
          if ( tempregs.has(curins->d.r) )
            return 0;
        }
        else if ( curins->d.t == mop_S )
        {
          ll.location = curins->d.s->off;
        }
        else
        {
          return 0;
        }
        ll.defea = curins->ea;
        if ( !seen.insert(ll).second )
        {
          interr_ea = ll.defea;
          INTERR(50919); // only one microinsn at an address may modify a destination location
        }
      }
      return 0;
    }
    dest_ea_verifier_t() : tempregs(get_temp_regs()) {}
  };
  dest_ea_verifier_t dv;
  CONST_CAST(mba_t*)(this)->for_all_topinsns(dv);
*/
}

//-------------------------------------------------------------------------
void mba_t::verify_stkpnts(bool cumulative_spds, bool good_stacksize) const
{
  size_t n = stkpnts.size();
  for ( size_t i=0; i < n; i++ )
  {
    const stkpnt_t &sp = stkpnts[i];
    if ( cumulative_spds && good_stacksize && sp.spd + stacksize < 0 )
      INTERR(51712); // wrong calculated sp value
    if ( i > 0 && sp.ea <= stkpnts[i-1].ea )
      INTERR(51713); // wrong calculated sp value
  }
  if ( good_stacksize )
  {
    sval_t sp_entry = getspd(entry_ea);
    if ( is_snippet() ? sp_entry > stacksize : sp_entry != stacksize )
      INTERR(51714); // wrong calculated sp value at the function entry point
  }
}

/*
Some common interrs that occur in other parts of the decompiler:

50409 a 'nop' instruction is still present in the microcode at the ctree
      generation time. this error is usually caused by modifying the microcode
      without informing the decompiler, i.e. erroneously returning 0
      from a callback.

50340 local variable allocation failed to reach the fixed point.
      this error is usually due to a flaw in the variable allocation logic.
      if possible, please send us the idb file so we can fix the bug.

*/
