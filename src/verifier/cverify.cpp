/*
 *      Decompiler project
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 *
 *      Verify ctree consistency
 *
 */

#include "allmicro.h"

#define CFAIL_QASSERT(code, e) do { if ( under_debugger ) { body.dump_graph(e, "failure"); BPT; } INTERR(code); } while(0)

//-------------------------------------------------------------------------
void cnumber_t::verify() const
{
  if ( nf.opnum > UA_MAXOP )
    INTERR(50670); // cnumber: wrong operand number
  if ( is_off(nf.flags, nf.opnum)
    || is_seg(nf.flags, nf.opnum)
    || is_manual(nf.flags, nf.opnum)
    || is_stkvar(nf.flags, nf.opnum)
    || is_fltnum(nf.flags, nf.opnum) )
  {
    INTERR(50671); // cnumber: unexpected operand representation
  }
  if ( (nf.is_enum() || nf.is_stroff())
    && !get_named_type(nullptr, nf.type_name.c_str(), NTF_TYPE) )
  {
    INTERR(50672); // cnumber: invalid enumeration or structure type
  }
}

//-------------------------------------------------------------------------
inline void cfunc_t::verify_item(const citem_t *item) const
{
  if ( item->op < cot_empty || item->op >= cit_end )    //lint !e685 relational operator '<' always evaluates to 'false'
    CFAIL_QASSERT(50673, item); // ctree: wrong item type
  if ( item->label_num < -1 )
    CFAIL_QASSERT(50674, item); // ctree: wrong item label
  size_t qty = mba->qty; // avoid integer overflow
  if ( item->label_num >= 0 && item->label_num > qty*qty )
    CFAIL_QASSERT(52519, item); // ctree: wrong item label
}

//-------------------------------------------------------------------------
void cfunc_t::verify_switch(const cswitch_t &sw) const
{
  if ( sw.cases.empty() )
    INTERR(50676); // ctree: wrong number of switch cases
  sw.mvnf.verify();
  bool seen_default = false;
  std::set<uint64> seen_values;
  for ( ccases_t::const_iterator p=sw.cases.begin(); p != sw.cases.end(); ++p )
  {
    const ccase_t &cc = *p;
    verify_insn(&cc);
    if ( cc.values.empty() )
    {
      if ( seen_default )
        INTERR(50677); // ctree: duplicate default switch case
      seen_default = true;
      continue;
    }
    qvector<uint64>::const_iterator q;
    for ( q=cc.values.begin(); q != cc.values.end(); ++q )
    {
      if ( !seen_values.insert(*q).second )
        INTERR(50678); // ctree: duplicate switch case value
    }
  }
}

//-------------------------------------------------------------------------
struct cinsn_verifier_t : public ctree_parentee_t
{
  const cfunc_t &func;
  cinsn_verifier_t(const cfunc_t &f) : func(f) {}
  int idaapi visit_insn(cinsn_t *i) override { func.verify_insn(i); return 0; }
  int idaapi visit_expr(cexpr_t *e) override { func.verify_expr(parent_expr(), e); return 0; }
};

//-------------------------------------------------------------------------
void cfunc_t::verify_insn(const cinsn_t *i) const
{
  verify_item(i);
  switch ( i->op )
  {
    case cit_switch:
      verify_switch(*i->cswitch);
      break;
    case cit_goto:
      if ( i->cgoto->label_num < 0 )
        CFAIL_QASSERT(50679, i); // ctree: goto without a label
      break;
    case cit_asm:
      if ( i->casm->empty() )
        CFAIL_QASSERT(50680, i); // ctree: empty assembler instruction list
      break;
    case cit_try:
      if ( i->ctry->is_wind )
      {
        if ( i->ctry->catchs.size() != 1 )
          CFAIL_QASSERT(52707, i); // ctree: __wind must have exactly one __unwind
        const ccatch_t &cc = i->ctry->catchs.front();
        if ( !cc.is_catch_all() )
          CFAIL_QASSERT(52708, i); // ctree: __unwind must have "catch all"
      }
      else
      {
        if ( i->ctry->catchs.empty() )
          CFAIL_QASSERT(52738, i); // ctree: 'try' without any 'catch' clauses?!
      }
      for ( const ccatch_t &cc : i->ctry->catchs )
        for ( const catchexpr_t &ce : cc.exprs )
          verify_expr(i, &ce.obj);
      break;
  }
  // check instruction address
  switch ( i->op )
  {
    case cit_block:
      if ( i->ea == BADADDR )   // addressless block
      {                         // block statements must have addresses
        cblock_t *b = i->cblock;
        for ( cblock_t::const_iterator p=b->begin(); p != b->end(); ++p )
        {
          ctype_t op = p->op;
          if ( op != cit_empty  // except some statements
            && op != cit_break
            && op != cit_continue
            && op != cit_return
            && op != cit_goto )
          {
            CFAIL_QASSERT(50681, i); // ctree: missing statement address
          }
        }
      }
      break;
    case cit_expr:
      if ( i->ea == BADADDR && !i->cexpr->is_helper_call() && i->cexpr->op != cot_empty )
        CFAIL_QASSERT(50682, i); // ctree: missing expression address
      break;
    case cit_if:
      if ( maturity < CMAT_TRANS1 || maturity >= CMAT_CASTED )
      {
        ea_t jea = i->cif->expr.calc_jmp_cnd_ea();
        if ( jea != BADADDR && i->ea != jea )
          CFAIL_QASSERT(50683, i); // ctree: mismatch in if-statement and its expression addresses
      }
      // no break
    case cit_for:
    case cit_while:
    case cit_do:
    case cit_switch:
    case cit_asm:
      if ( i->ea == BADADDR )
        CFAIL_QASSERT(50684, i); // ctree: missing statement address
      break;
//    case cit_empty:
//    case cit_break:
//    case cit_continue:
//    case cit_return:
//    case cit_goto:
//    case cit_throw:
//    case cit_try:
  }
}

//-------------------------------------------------------------------------
bool is_acceptable_lvalue(const citem_t *parent, const cexpr_t *e, ctree_maturity_t maturity)
{
  ctype_t op = e->op;
  if ( (!is_lvalue(op) || parent->op != cot_ref && e->type.is_array() && maturity >= CMAT_CPA)
    && !e->is_odd_lvalue()
    && op != cot_helper
    && (op != cot_call || !e->type.is_small_udt()) ) // for small udts, allow cast
  {
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
static bool is_value_used(const cfunc_t *func, const cexpr_t *e)
{
  const citem_t *p = func->body.find_parent_of(e);
  return e->is_value_used(p);
}

//-------------------------------------------------------------------------
// this is ok: array VS ptr
static bool is_array_castable_to_pointer(const tinfo_t &array, const tinfo_t &ptr)
{
  tinfo_t ptrobj = ptr.get_pointed_object();
  tinfo_t eltype = array.get_array_element();
  return eltype.is_castable_to(ptrobj);
}

//-------------------------------------------------------------------------
bool is_acceptable_array_op(
        const citem_t *parent,
        const cexpr_t *e,
        const tinfo_t &array_type)
{
  switch ( parent->op )
  {
    case cot_idx:
      return true;
    case cot_add:
    case cot_sub:
      return true;
    case cot_ptr:
      return true;
    case cot_cast:
      return true;
    case cot_call:
      {
        cexpr_t *pe = (cexpr_t *)parent;
        if ( e == pe->x )
          return false;
        carg_t *ca = get_call_arg(pe, e, nullptr);
        return is_array_castable_to_pointer(array_type, ca->formal_type);
      }
    default:
      if ( is_relational(parent->op) )
      {
        cexpr_t *other = ((cexpr_t *)parent)->theother(e);
        return is_array_castable_to_pointer(array_type, other->type);
      }
      return false;
  }
}

//-------------------------------------------------------------------------
bool cfunc_t::is_acceptable_udt(
        const citem_t *parent,
        const cexpr_t *e,
        const tinfo_t *etype) const
{
  if ( parent->op != cot_cast
    && parent->op != cot_ref
    && parent->op != cot_memref
    && parent->op != cot_sizeof
    && parent->op != cit_try )
  {
    const tinfo_t &type = etype != nullptr ? *etype : e->type;
    if ( !type.is_scalar()
      && (!type.is_array() || !is_acceptable_array_op(parent, e, type)) )
    {
      // accept structure assignments
      if ( !accepts_udts(parent->op) || !type.is_udt() )
      {
        // if ternary type is void, accept any type for y and z, it won't
        // be used anyway
        if ( parent->op != cot_tern
          || ((cexpr_t *)parent)->x == e
          || is_value_used(this, (cexpr_t *)parent) )
        {
          // udts can be returned or assigned
          if ( !is_acceptable_small_udt(parent, e, &type) )
            return false;
        }
      }
    }
  }
  return true;
}

//-------------------------------------------------------------------------
// a ternary operator should not not have y and z of incompatible types
// but we accept some relaxations
static bool verify_tern_yz(const cexpr_t *y, const cexpr_t *z)
{
  const tinfo_t &yt = y->type;
  const tinfo_t &zt = z->type;
  if ( yt.is_paf() == zt.is_paf() )
    return true;  // check only pointers against non-pointers
  if ( yt.is_void() || zt.is_void() )
    return true;  // one of parts is void => ok
  if ( y->is_zero_const() || z->is_zero_const() )
    return true;  // assume zero const is castable to any type
  if ( yt.is_partial() && !zt.is_enum() )
    return true;  // non-enum and partial are compatible, see cexpr_t::cast()
  if ( yt.compare_with(zt, TCMP_IGNMODS|TCMP_DELPTR) )
    return true;  // keep compatibility with calc_type()
  return false;
}

//-------------------------------------------------------------------------
void cfunc_t::verify_expr(const citem_t *parent, const cexpr_t *e) const
{
  hv.verifying++;
  if ( (e->exflags & ~EXFL_ALL) != 0 )
    CFAIL_QASSERT(50685, e); // ctree: illegal property bits
  if ( !e->is_child_of(parent) )
    CFAIL_QASSERT(50686, e); // ctree: broken tree structure

  verify_item(e);

  // only some instructions permit empty expressions
  ctype_t op = e->op;
  if ( op == cot_empty )
  {
    switch ( parent->op )
    {
      default:
        CFAIL_QASSERT(50687, e); // ctree: bad parent of an empty expression
      case cit_expr:
      case cot_sizeof:
      case cit_return:
      case cit_for:
      case cit_try:
      case cit_throw:
        break;
    }
  }

  const tinfo_t &type = e->type;
  if ( type.empty() )
  {
    switch ( op )
    {
      case cot_empty:
      case cot_insn:
      case cot_helper:
        break;
      default:
        if ( !e->contains_insn() && !e->contains_operator(cot_helper) )
          CFAIL_QASSERT(50688, e); // ctree: missing expression type
    }
  }
  else
  {
    // we can take addresses of incomplete types
    if ( parent->op != cot_ref && !type.is_correct() )
      CFAIL_QASSERT(50689, e); // ctree: incorrect expression type
    // empty expressions are enabled only in for statement and sizeof
    if ( op == cot_empty && parent->op != cit_for && parent->op != cot_sizeof )
      CFAIL_QASSERT(51084, e); // ctree: illegal empty expression
    // instruction cannot have type
    if ( op == cot_insn )
      CFAIL_QASSERT(50690, e); // ctree: type of a transient statement-expression is meaningless
    if ( !type.print(nullptr) )
      CFAIL_QASSERT(50691, e); // ctree: unprintable expression type

    if ( parent->is_expr() )
    {
      cexpr_t *pe = (cexpr_t *)parent;
      if ( pe->requires_int_operands() && type.is_floating() )
        CFAIL_QASSERT(50692, e); // ctree: integer operator may not have floating arguments
      if ( requires_fp_operands(pe->op) && !pe->is_fpop() )
        CFAIL_QASSERT(50693, e); // ctree: floating operator is not marked as such
      if ( (pe->is_fpop() || requires_fp_operands(pe->op)) && !type.is_floating() )
        CFAIL_QASSERT(50694, e); // ctree: floating operator must yield a floating type
    }

    if ( maturity < CMAT_TRANS2 )
    {
      tinfo_t copy = calculate_type(hv, e, e->x->type, e->y->type, e->z->type);
      if ( type != copy )
        CFAIL_QASSERT(50695, e); // ctree: wrong expression type. maybe recalc_parent_types() would help?
    }
  }

  const cexpr_t *x = e->x;
  const cexpr_t *y = e->y;
  if ( maturity >= CMAT_CASTED )
  {
    // labels in expressions must be gone at this stage
    if ( e->label_num != -1 )
      CFAIL_QASSERT(50696, e); // ctree: labels are not permitted in expressions

    bool px = op_uses_x(op) && x->type.is_paf();
    bool py = op_uses_y(op) && y->type.is_paf();
    if ( op == cot_tern )
    {
      if ( !verify_tern_yz(y, e->z) )
        CFAIL_QASSERT(52561, e); // ctree: incompatible types of y and z
    }
    else if ( px || py )
    {
      switch ( op )
      {
        case cot_cast:     // (type)x
        case cot_comma:    // x, y
        case cot_tern:     // x ? y : z
        case cot_lor:      // x || y
        case cot_land:     // x && y
        case cot_lnot:     // !x
        case cot_ptr:      // *x
        case cot_ref:      // &x
        case cot_postinc:  // x++
        case cot_postdec:  // x--
        case cot_preinc:   // ++x
        case cot_predec:   // --x
        case cot_call:     // x(...)
        case cot_obj:      // obj_ea
        case cot_var:      // v
        case cot_sizeof:   // sizeof(x)
          break;
        case cot_asg:      // x = y
          if ( !py && !y->is_zero_const() && !y->type.is_func() )
            CFAIL_QASSERT(50698, e); // ctree: non-pointer is assigned to a pointer type
          break;
        case cot_asgadd:   // x += y
        case cot_add:      // x + y
        case cot_asgsub:   // x -= y
          if ( px && py )
            CFAIL_QASSERT(50699, e); // ctree: two pointers cannot added to each other
          break;
        case cot_eq:       // x == y
        case cot_ne:       // x != y
        case cot_uge:      // x >= y unsigned
        case cot_ule:      // x <= y unsigned
        case cot_ugt:      // x >  y unsigned
        case cot_ult:      // x <  y unsigned
CHECK_EQUAL:
          if ( !can_compare(hv, x, y, op) )
            CFAIL_QASSERT(50700, e); // ctree: incompatible pointer types
          break;
        case cot_sub:      // x - y
          if ( !px )
            CFAIL_QASSERT(50701, e); // ctree: a pointer cannot be a subtrahend
          if ( py )
            goto CHECK_EQUAL;
          break;
        case cot_memptr:   // x->m
        case cot_idx:      // x[y]
          break; // see checks below
        default:
          CFAIL_QASSERT(50704, e); // ctree: wrong expression code
      }
    }
  }

  if ( e->cpadone() )
  {
    if ( parent->op == cot_call )
    {
      if ( e->is_call_object_of(parent) )
      {
        tinfo_t tmp = remove_pointer(type);
        if ( !tmp.is_func() )
          CFAIL_QASSERT(50705, e); // ctree: call of a non-function
      }
      else if ( maturity >= CMAT_CASTED )
      {
        // FIXME: uncomment this. currently this doesn't work because
        // my_is_castable returns false for DWORD->int
/*
        carg_t *a = get_call_arg((cexpr_t*)parent, this, nullptr);
        if ( !is_type_castable_to(type, a->formal_type) )
          CFAIL_QASSERT(50706, e); // ctree: incompatible call argument type
*/
      }
    }
    else if ( !is_acceptable_udt(parent, e) )
    {
      CFAIL_QASSERT(50707, e); // ctree: bad use of a struct/union type
    }
  }

  if ( ((cexpr_t *)parent)->requires_lvalue(e) )
    if ( !is_acceptable_lvalue(parent, e, maturity) )
      CFAIL_QASSERT(50708, e); // ctree: unacceptable lvalue

  // sign sensitive operations must have their operands with the correct signs
  // i.e. for an unsigned operation, the common type must be unsigned
  if ( maturity >= CMAT_CASTED && is_sign_sensitive(op) && !e->is_fpop() )
  {
    type_sign_t ts1 = e->calc_op_signness(hv);
    type_sign_t ts2 = get_op_signness(op);
    if ( ts1 != ts2 && e->x->type.is_well_defined() && e->y->type.is_well_defined() )
    {
      bool ok = false;
      // this is ok: x <u sN where sN is a positive signed constant
      //             sizeof(sN) < inf.cc.size_i
      if ( ts2 == type_unsigned && !is_shiftop(op) )
      {
        const cexpr_t *sN = e->find_num_op();
        if ( sN != nullptr
          && sN->type.get_size() < hv.app_cc.size_i
          && int64(sN->numval()) >= 0 )
        {
          ok = true;
        }
      }
      if ( !ok )
        CFAIL_QASSERT(50709, e); // ctree: wrong operation sign
    }
  }

  type_t bt;
  switch ( op )
  {
    case cot_cast:
      // cannot cast to arrays or functions. casting to array in golang is ok
      if ( type.is_array()
        && !hv.is_golang
        && (parent->op != cot_call
         || !is_golang_cc(((cexpr_t *)parent)->a->functype.get_cc())) )
      {
        CFAIL_QASSERT(50710, e); // ctree: casting to array is forbidden
      }
      if ( type.is_func() )
        CFAIL_QASSERT(50711, e); // ctree: casting to function is forbidden
      if ( maturity >= CMAT_CASTED && type.is_floating() && x->type.is_paf() )
        CFAIL_QASSERT(50697, e); // a pointer cannot be cast into a floating value
      break;
      // no break
    case cot_type:
      if ( type.empty() )
        CFAIL_QASSERT(50712, e); // ctree: missing cast type
      break;
    case cot_add:
      if ( parent->op == cot_ptr
        && !x->type.is_ptr_or_array()
        && !y->type.is_ptr_or_array() )
      {
        CFAIL_QASSERT(51602, e); // ctree: unexpected pointer result of an addition
      }
      break;
    case cot_ptr:
      if ( maturity >= CMAT_CASTED )
      {
        if ( x->op == cot_ref && !x->x->type.is_array() && type != x->x->type )
          CFAIL_QASSERT(50713, e); // ctree: unexpected type of *& operators
      }
      if ( e->ptrsize <= 0 )
        CFAIL_QASSERT(50714, e); // ctree: wrong dereference size
      bt = x->type.get_realtype();
      if ( !is_type_ptr_or_array(bt) )
        CFAIL_QASSERT(50717, e); // ctree: only pointers and arrays can be dereferenced
      if ( is_type_ptr(bt) )
      {
        if ( e->ptrsize != type.get_size() && !type.is_array() )
          CFAIL_QASSERT(50715, e); // ctree: unexpected dereference size
      }
      else
      { // array
        tinfo_t el = x->type.get_array_element();
        if ( e->ptrsize != el.get_size() && !el.is_array() )
          CFAIL_QASSERT(50716, e); // ctree: unexpected size of dereferencing an array
      }
      break;
    case cot_call: // x(...)
      if ( !e->a->functype.is_func() )
        CFAIL_QASSERT(52818, e);
      bt = x->type.get_realtype();
      if ( is_type_ptr(bt) )
        bt = x->type.get_pointed_object().get_realtype();
      if ( !is_type_func(bt) )
        CFAIL_QASSERT(50718, e); // ctree: call of a non-function
                                 // fixme: remove 50705, it is a dup
      break;
    case cot_memref: // x.m
      bt = x->type.get_realtype();
MEM:
      if ( !is_type_struni(bt) )
        CFAIL_QASSERT(50719, e); // ctree: member dereference of non struct/union
      {
        udm_t udm;
        int sflags = (e->is_vftable() ? STRMEM_VFTABLE : 0) | STRMEM_AUTO;
        if ( find_udm(&udm, remove_pointer(x->type), e->m, sflags) == -1 )
          CFAIL_QASSERT(50922, e); // ctree: dereferencing of unexisting struct/union member

#if defined(TESTABLE_BUILD)
        if ( !e->type.equals_to(udm.type)
          && !e->type.get_ptrarr_object().equals_to(udm.type.get_array_element()) )
        {
          tinfo_t tmp = remove_pointer(e->type);
          if ( !tmp.is_func() )
            CFAIL_QASSERT(50720, e); // ctree: the expression type must be equal to the member type
        }
#endif
      }
      break;
    case cot_memptr: // x->m
      bt = x->type.get_pointed_object().get_realtype();
      goto MEM;
    case cot_idx:
      // x[y] normally appears after cpa and immediately has good type.
      // in other words it always must use a pointer. otherwise we risk
      // getting interr 50397 when calculating types.
      if ( !x->type.is_ptr_or_array() || y->type.is_paf() )
        CFAIL_QASSERT(50703, e); // ctree: index operator can be applied only to pointers and arrays
      break;
    case cot_num: // n
      e->n->verify();
      if ( (e->n->nf.props & NF_VALID) != 0 ) // is enum/stroff reference ok?
      {
        // some enum references may be incorrect in the sense
        // that they do not resolve into any symbolic constant.
        // however, it is a temporary situation because we may replace the
        // number during decompilation and this may make the enum
        // reference correct.
        if ( e->n->nf.is_enum() )
        {
          qstring name;
          if ( !e->type.get_type_name(&name) || name != e->n->nf.type_name )
            INTERR(52378); // cnumber: enum type name mismatch
        }
        /* fixme: ensure the following condition in all cases
        else if ( e->n->nf.is_stroff() )
        {
          if ( !e->type.compare_with(T_UADDRSIZE) )
            INTERR(52380); // cnumber: wrong stroff expression type
        }
        */
      }
      else if ( maturity == CMAT_FINAL )
      {
        // at the very end of decompilation all enum/stroff references must be good.
        if ( e->n->nf.is_enum() || e->n->nf.is_stroff() )
          INTERR(52381); // cnumber: wrong enum/stroff reference
      }
      break;
    case cot_var: // l
      if ( e->v.idx >= mba->vars.size() )
        CFAIL_QASSERT(50722, e); // ctree: bad reference to a local variable
      break;
    case cot_helper: // arbitrary name
      if ( (e->exflags & EXFL_ALONE) == 0 )
      {
        if ( !e->is_call_object_of(parent) )
          CFAIL_QASSERT(50723, e); // ctree: regular helpers can only be called
      }
      break;
    case cot_str: // string constant
      if ( e->string == nullptr )
        CFAIL_QASSERT(50724, e); // ctree: missing string constant
      break;
    case cot_insn:
      if ( maturity >= CMAT_TRANS1 )
        CFAIL_QASSERT(50725, e); // ctree: transient instruction-expressions are illegal after CMAT_TRANS1
      break;
  }
  hv.verifying--;
}

//-------------------------------------------------------------------------
void cfunc_t::verify(allow_unused_labels_t _aul, bool always) const
{
  if ( !always && !hv.should_verify() )
    return;
  if ( (mba->get_mba_flags2() & MBA2_DONT_VERIFY) != 0 )
    return;

  if ( mba->use_frame() && mba->entry_ea != BADADDR )
  {
    flags64_t f = get_flags(mba->entry_ea);
    if ( !is_func(f) )
      INTERR(50726); // ctree: the function entry is not marked as 'is_func'
  }

  cinsn_verifier_t cv(*this);
  cv.apply_to(CONST_CAST(cinsn_t *)(&body), nullptr);

  // check that all goto labels exist
  //lint -e{958} padding needed
  struct ida_local label_info_collector_t : public ctree_visitor_t
  {
    hexrays_vars_t &hv;
    bitset_t labels;
    bitset_t gotos;
    label_info_collector_t(hexrays_vars_t &_hv) : ctree_visitor_t(CV_FAST), hv(_hv) {}
    bool add_label(citem_t *i)
    {
      if ( i->label_num != -1 )
      {
        if ( !labels.add(i->label_num) )
          INTERR(50727); // ctree: duplicate label
      }
      return true;
    }
    int idaapi visit_insn(cinsn_t *i) override
    {
      add_label(i);
      if ( i->op == cit_goto )
        gotos.add(i->cgoto->label_num);
      return 0;
    }
    int idaapi visit_expr(cexpr_t *e) override
    {
      add_label(e);
      return 0;
    }
    bool verify(allow_unused_labels_t aul) const
    {
      // for each goto there is a label
      for ( bitset_t::iterator p=gotos.begin(); p != gotos.end(); gotos.inc(p) )
      {
        int label = *p;
        if ( !labels.has(label) )
          INTERR(50728); // ctree: goto to unexisting label
      }
      if ( aul == FORBID_UNUSED_LABELS )
      {
        // for each label there is a goto
        for ( bitset_t::iterator p=labels.begin(); p != labels.end(); labels.inc(p) )
        {
          int label = *p;
          if ( !gotos.has(label) )
          {
            dump_ctree(hv, &hv.gfunc->body, "UNUSED LABEL %d", label);
            INTERR(50729); // ctree: unused label
          }
        }
      }
      return true;
    }
  };
  label_info_collector_t lic(hv);
  lic.apply_to((citem_t *)&body, nullptr);
  lic.verify(_aul);

#if 0
  // check that all items are distinct
  struct ida_local item_address_collector_t : public ctree_visitor_t
  {
    std::set<citem_t *> items;
    item_address_collector_t() : ctree_visitor_t(CV_FAST) {}
    int add_item(citem_t *i)
    {
      if ( !items.insert(i).second )
        INTERR(50730); // ctree: broken tree structure
      return 0;
    }
    int idaapi visit_insn(cinsn_t *i) override { return add_item(i); }
    int idaapi visit_expr(cexpr_t *e) override { return add_item(e); }
  };
  item_address_collector_t adc;
  adc.apply_to((citem_t *)&body, nullptr);
#endif

#ifdef TESTABLE_BUILD
  if ( hv.num_cfuncs == 1 )
  {
    // verify citem_t leaks
    struct ida_local leak_verifier_t : public ctree_visitor_t
    {
      ptrset_t leaks;
      int remove_leak(citem_t *i)
      {
        ptrset_t::iterator p = leaks.find(i);
        if ( p != leaks.end() )
        {
//          msg("  ver %p: %s\n", i, i->dstr());
          leaks.erase(p);
        }
        return 0;
      }
      int idaapi visit_insn(cinsn_t *i) override
      {
        return remove_leak(i);
      }
      int idaapi visit_expr(cexpr_t *e) override
      {
        return remove_leak(e);
      }
      leak_verifier_t(const ptrset_t &_items)
        : ctree_visitor_t(CV_FAST), leaks(_items) {}
    };
    leak_verifier_t lv(hv.cverify_items);
    lv.apply_to((citem_t *)&body, nullptr);
    if ( !lv.leaks.empty() )
    {
      msg("%" FMT_Z " leaked items:\n", lv.leaks.size());
      for ( ptrset_t::iterator p=lv.leaks.begin(); p != lv.leaks.end(); ++p )
      {
        citem_t *i = (citem_t *)*p;
        msg("  %p: %s\n", i, i->dstr());
      }
      hv.clear_leak_info();
      INTERR(50731); // ctree: detected memory leak of citem_t objects
    }
  }
#endif
  hv.verifying = 0;
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
void *citem_t::operator new(size_t /*size*/, void *ptr)
{
  citem_t *c = (citem_t *)ptr;
  c->op = cot_empty;
  c->label_num = -1;
  return ptr;
}

//-------------------------------------------------------------------------
void *citem_t::operator new(size_t size)
{
  void *ret = hexrays_alloc(size);
  new (ret) citem_t;
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  bool ok = hv.cverify_items.insert(ret).second;
  QASSERT(50915, ok); // ctree: citem_t allocator returned the same address twice
  return ret;
}

//-------------------------------------------------------------------------
void remitem(const citem_t *e)
{
  hexrays_vars_t &hv = *GET_MODULE_DATA(hexrays_vars_t);
  void *p = (void *)e;
  hv.cverify_items.erase(p);
}
#else
void remitem(const citem_t *) {}
#endif

//-------------------------------------------------------------------------
void hexrays_vars_t::clear_leak_info()
{
  cverify_items.clear();
}

