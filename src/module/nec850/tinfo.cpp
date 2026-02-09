#include "necv850.hpp"
#include "../tinfocmn.cpp"

//-------------------------------------------------------------------------
struct nec850_argtinfo_helper_t : public argtinfo_helper_t
{
  nec850_t &pm;
  nec850_argtinfo_helper_t(nec850_t &_pm) : pm(_pm) {}
  bool idaapi set_op_tinfo(
        const insn_t &_insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name) override
  {
    insn_t insn = _insn;
    eavec_t visited;
    return pm.set_op_type(&insn, &visited, x, tif, name);
  }

  bool idaapi is_stkarg_load(const insn_t &insn, int *src, int *dst) override
  {
    if ( (insn.itype == NEC850_ST_W || insn.itype == NEC850_ST_DW)
      && insn.Op2.type == o_displ
      && insn.Op2.phrase == rSP )
    {
      *src = 0;
      *dst = 1;
      return true;
    }
    if ( insn.itype == NEC850_PUSHSP )
    {
      *src = 0;
      *dst = -1;
      return true;
    }
    return false;
  }
};

//-------------------------------------------------------------------------
void nec850_t::use_nec850_arg_types(ea_t ea, func_type_data_t *fti, funcargvec_t *rargs)
{
  nec850_argtinfo_helper_t argtinfo_helper(*this);
  argtinfo_helper.use_arg_tinfos(ea, fti, rargs);
}

//-------------------------------------------------------------------------
inline bool is_auto_refinfo(ea_t ea, int opno)
{
  refinfo_t ri;
  return get_refinfo(&ri, ea, opno)
      && ri.target == BADADDR
      && ri.base == 0
      && !ri.no_base_xref() // a correct offset has REFINFO_NOBASE
      && ri.tdelta == 0
      && ri.type() == get_default_reftype(ea);
}

//-------------------------------------------------------------------------
bool nec850_t::set_op_type(
        insn_t *insn,
        eavec_t *visited, // for recursive calls
        const op_t &x,
        const tinfo_t &type,
        const char *name)
{
  switch ( x.type )
  {
    case o_imm:
      if ( type.is_ptr() && x.value != 0 )
      {
        if ( !is_defarg(get_flags(insn->ea), x.n) )
          op_plain_offset(insn->ea, x.n, 0);
        tinfo_t deref_type = type;
        if ( !remove_tinfo_pointer(&deref_type, &name) )
          break;
        return apply_once_tinfo_and_name(trunc_uval(x.value), deref_type, name);
      }
      if ( type.is_scalar()
        && insn->itype == NEC850_MOV
        && x.n == 0
        && type.get_size() == get_dtype_size(x.dtype) )
      {
        flags64_t F = get_flags32(insn->ea);
        // also replace incorrect zero-based offsets
        if ( !is_defarg0(F)
          || is_off0(F) && is_auto_refinfo(insn->ea, 0) )
        {
          if ( type.is_floating() )
            op_flt(insn->ea, 0);
          else
            op_num(insn->ea, 0);
          return true;
        }
      }
      break;
    case o_mem:
      return apply_once_tinfo_and_name(x.addr, type, name);
    case o_displ:
      if ( x.phrase == rSP )
      {
        return apply_tinfo_to_stkarg(*insn, x, x.addr, type, name);
      }
      else if ( is_off(get_flags(insn->ea), x.n) )
      {
        refinfo_t ri;
        ea_t target;
        if ( get_refinfo(&ri, insn->ea, x.n)
          && calc_reference_data(&target, nullptr,
                                 insn->ea + x.offb, ri, x.addr) )
        {
          return apply_once_tinfo_and_name(target, type, name);
        }
      }
      break;
    case o_reg:
      {
        uint32 r = x.reg;
        func_t *pfn = get_func(insn->ea);
        if ( pfn == nullptr )
          break;
        bool ok;
        bool farref;
        func_item_iterator_t fii;
        for ( ok=fii.set(pfn, insn->ea);
              ok && (ok=fii.decode_preceding_insn(visited, &farref, insn)) != 0;
              )
        {
          if ( visited->size() > 4096 )
            break; // decoded enough of it, abandon
          if ( farref )
            continue;
          switch ( insn->itype )
          {
            case NEC850_MOV:
            case NEC850_LD_DW:
            case NEC850_LD_W:
            case NEC850_LD_H:
            case NEC850_LD_HU:
            case NEC850_LD_B:
            case NEC850_LD_BU:
              if ( insn->Op2.reg != r )
                continue;
              return set_op_type(insn, visited, insn->Op1, type, name);
            case NEC850_MOVEA:
              if ( insn->Op3.reg != r )
                continue;
              if ( !insn->Op2.is_reg(rSP) || insn->Op1.type != o_imm )
                break;
              {
                tinfo_t deref_type = type;
                if ( !remove_tinfo_pointer(&deref_type, &name) )
                  break;
                return apply_tinfo_to_stkarg(*insn, insn->Op1, insn->Op1.value, deref_type, name);
              }
            default:
              if ( !spoils(*insn, r) )
                continue;
              break;

          }
          break;
        }
        if ( !ok && fii.current() == pfn->start_ea )
        {
          // reached the function start, this looks like a register argument
          add_regarg(pfn, r, type, name);
          break;
        }
      }
      break;
  }
  return false;
}

//-------------------------------------------------------------------------
int nec850_t::use_nec850_regarg_type(ea_t ea, const funcargvec_t &rargs)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return -1;
  int idx = -1;
  for ( int i = 0; i < rargs.size(); i++ )
  {
    if ( spoils(insn, rargs[i].argloc.reg1()) )
    {
      idx = i;
      break;
    }
  }
  if ( idx == -1 )
    return -1;
  tinfo_t type = rargs[idx].type;
  const char *name = rargs[idx].name.c_str();
  switch ( insn.itype )
  {
    case NEC850_MOV:
      {
        eavec_t visited;
        set_op_type(&insn, &visited, insn.Op1, type, name);
        break;
      }
    case NEC850_MOVEA:
      if ( insn.Op2.is_reg(rSP) && insn.Op1.type == o_imm )
        if ( remove_tinfo_pointer(&type, &name) )
          apply_tinfo_to_stkarg(insn, insn.Op1, insn.Op1.value, type, name);
      break;
    default:
      // unknown instruction changed the register, stop tracing it
      idx |= REG_SPOIL;
      break;
  }
  return idx;
}

//-------------------------------------------------------------------------
// how to pass an argloc or return a retloc
//lint -esym(749,how_to_pass_t::BY_REF) local enumeration constant not referenced
enum how_to_pass_t
{
  BAD,                  // cannot calculate argloc
  IN_GPR,               // pass an argument in GPR
  ON_STACK,             // on the stack
  SCATTERED,            // pass in GPR(s) and maybe on the stack
  BY_REF,               // should lower the type
};
//-------------------------------------------------------------------------
//lint -e{958} padding needed to align member
struct arg_allocator_t
{
  static constexpr size_t max_regs = 4;

  size_t num_gprs = 0;    // the number of registers used so far
  sval_t stkoff   = 0;    // the stack offset (divisible by the slot size)
  const nec850_t &pm;     // ABI bits

  arg_allocator_t(const nec850_t &_pm) : pm(_pm) {}

  bool has_free_gprs(size_t req_nregs = 1) const
  {
    return num_gprs + req_nregs <= max_regs;
  }

  bool calc_argloc(
        argloc_t *arg_loc,
        const tinfo_t &arg_type,
        bool is_vararg = false);
  bool lower_rettype(const tinfo_t &rettype) const;

  how_to_pass_t find_how_to_pass_arg(
        const tinfo_t &arg_type,
        int size) const;

  void alloc_slot(argloc_t *aloc)
  {
    int regno = get_regno(1);
    if ( aloc != nullptr )
      aloc->_set_reg1(regno);
  }

  void alloc_double_slot(argloc_t *aloc)
  {
    int regno = get_regno(2);
    if ( aloc != nullptr )
      aloc->_set_reg2(regno, regno + 1);
  }

  void alloc_stk(argloc_t *aloc, int size)
  {
    if ( aloc != nullptr )
      aloc->set_stkoff(stkoff);
    stkoff = align_up(stkoff + size, 4);
    // assert: stkoff % 4 == 0
  }

  void alloc_scattered(argloc_t *aloc, size_t size);

protected:
  int get_regno(size_t req_nregs)
  {
    QASSERT(10518, num_gprs + req_nregs <= max_regs);
    int regno = rR6 + num_gprs;
    num_gprs += req_nregs;
    return regno;
  }
};

//-------------------------------------------------------------------------
void arg_allocator_t::alloc_scattered(argloc_t *aloc, size_t size)
{
  QASSERT(10519, has_free_gprs());

  std::unique_ptr<scattered_aloc_t> scloc(new scattered_aloc_t);
  size_t chunk_off = 0;

  // registers
  while ( has_free_gprs() && size > 0 )
  {
    argpart_t &ap = scloc->push_back();
    ap.off = chunk_off;
    ap.size = std::min(size, size_t(4));
    alloc_slot(&ap);
    size -= ap.size;
    chunk_off += ap.size;
  }

  // remaining
  if ( size > 0 )
  {
    argpart_t &ap = scloc->push_back();
    ap.off = chunk_off;
    ap.size = size;
    alloc_stk(&ap, size);
  }

  if ( aloc != nullptr )
    aloc->consume_scattered(scloc.release());
}

//------------------------------------------------------------------------
bool arg_allocator_t::calc_argloc(
        argloc_t *argloc,
        const tinfo_t &type,
        bool is_vararg)
{
  // Old GCC
  // https://www.filibeto.org/unix/tru64/lib/ossc/doc/cygnus_doc-99r1/html/6_embed/embV850.html#Args_passing

  // RH850
  // CC-RH Compiler User's Manual
  // <4> If the function prototype is unknown, then each scalar-type argument is stored as follows.
  //     ...
  //     - 4-byte scalar floating-point number ->Promoted to 8-byte floating-point number, then stored
  uint32 align;
  size_t size = type.get_size(&align);
  if ( size == BADSIZE )
    return false;
  if ( is_vararg && size == 4 && type.is_floating() )
  {
    size = 8;
    align = 8;
  }
  if ( align > 4 && has_free_gprs() )
  {
    // only scalar values are aligned (not in the doc)
    if ( pm.abi == ABI_OLDGCC || pm.abi_align8 && type.is_scalar() )
      num_gprs = align_up(num_gprs, 2);
  }
  switch ( find_how_to_pass_arg(type, size) )
  {
    case IN_GPR:
      if ( size <= 4 )
        alloc_slot(argloc);
      else // size <= 8
        alloc_double_slot(argloc);
      break;
    case ON_STACK:
      if ( align > 4 )
      {
        // RH850 only scalar values are aligned (not in the doc)
        if ( pm.abi_align8 && type.is_scalar() )
          stkoff = align_up(stkoff, align);
      }
      alloc_stk(argloc, size);
      break;
    case SCATTERED:
      alloc_scattered(argloc, size);
      break;
    case BAD:
      return false;
    default:
      INTERR(10520);
  }
  return true;
}

//-------------------------------------------------------------------------
how_to_pass_t arg_allocator_t::find_how_to_pass_arg(
        const tinfo_t &type,
        int size) const
{
  if ( type.is_scalar() )
  {
    if ( size <= 4 )
      return has_free_gprs() ? IN_GPR : ON_STACK;
    if ( size <= 8 )
    {
      return has_free_gprs(2) ? IN_GPR
           : has_free_gprs()  ? SCATTERED
           :                    ON_STACK;
    }
    return BAD;
  }
  if ( type.is_udt() )
  {
    // Old GCC: "Structures greater than 8 bytes in length, passed by value,
    // are automatically converted into pass-by-invisible-reference
    // structures"
    if ( pm.abi == ABI_OLDGCC && size > 8 )
      return BAD;
    return has_free_gprs() ? SCATTERED : ON_STACK;
  }
  return BAD; // cannot handle arrays and funcs
}

//------------------------------------------------------------------------
bool nec850_t::calc_nec850_arglocs(func_type_data_t *fti, int nfixed)
{
  if ( !calc_nec850_retloc(&fti->retloc, fti->rettype, fti->get_cc()) )
    return false;

  arg_allocator_t aa(*this);
  for ( size_t i = 0; i < fti->size(); ++i )
  {
    funcarg_t &fa = fti->at(i);
    const bool is_vararg = nfixed > 0 && i >= nfixed;
    // in case of calc_varglocs() leave fixed args arglocs unchanged
    argloc_t *argloc = nfixed == 0 || is_vararg ? &fa.argloc : nullptr;
    if ( !aa.calc_argloc(argloc, fa.type, is_vararg) )
      return false;
  }
  fti->stkargs = aa.stkoff;

#ifdef TESTABLE_BUILD
  if ( (debug & IDA_DEBUG_IDP) != 0 )
  {
    qstring fti_dump;
    fti->dump(&fti_dump);
    deb(IDA_DEBUG_IDP,
        "calc_nec850_arglocs:\n%s%s\n",
        fti_dump.c_str(),
        fti->is_vararg_cc() ? "  ...\n" : "");
  }
#endif
  return true;
}

//-------------------------------------------------------------------------
// Not all structures are passed by reference!
// GCC option description: "Integer sized structures and unions are
// returned in register r10."
// how the compiler works:
// +--------------+--------------+------------------+
// | the field #1 | the field #2 | the single field |
// +--------+-----+--------+-----+--------+---------+
// | char   |0[r6]| char   |1[r6]| char   | r10     |
// | short  |0[r6]| char   |2[r6]| short  | r10     |
// | int    |  r10| char   |  r11| int    | r10     |
// | int    |  r10| short  |  r11| float  | r10     |
// | float  |  r10| int    |  r11| double | r11:r10 |
// +--------+-----+--------+-----+--------+---------+
// Arrays and nested stuctures are flattened.
// Unions (of size 8 bytes or smaller) are returned in registers.
static bool should_pass_struct_by_value(const tinfo_t &type)
{
  // assert: type.is_udt() && type.get_size() <= 8
  if ( type.is_union() )
    return true;
  qvector<flat_member_t> parts;
  if ( !flatten_struct(&parts, 2, type) || parts.empty() )
    return false;
  // assert: parts[0].off == 0
  if ( parts.size() == 1 )
    return true; // the struct with the single field
  // assert: parts.size() == 2
  return parts[1].off == 4;
}

//-------------------------------------------------------------------------
bool nec850_t::calc_nec850_retloc(
        argloc_t *retloc,
        const tinfo_t &rettype,
        cm_t)
{
  if ( rettype.is_void() )
    return true;

  // old GCC
  // https://www.filibeto.org/unix/tru64/lib/ossc/doc/cygnus_doc-99r1/html/6_embed/embV850.html#Func_return_value
  // Scalar or pointer return values are returned in r10 and sign-extended
  // or zero-extended to 32 bits for types smaller than 32 bits.
  // 32-bit floating point values are returned in r10.
  // 64-bit floating point values are returned in the register pair, r10 and
  // r11.
  // To call a function which returns a structure or union in C and C++, the
  // address of a temporary of the return type is passed by the caller in
  // r6. The function returns the structure value by copying the return
  // value to the address pointed to by r6, and copies r6 into r10 before
  // returning to the caller.
  // see also the comment before should_pass_struct_by_value() above

  // RH850
  // CC-RH Compiler User's Manual
  // (a) If value is scalar type 4 bytes or smaller
  //     The return value is returned to the caller via r10.
  //     If the value is a scalar type less than 4 bytes in size, data promoted to 4 bytes is set in r10.
  //     Zero promotion is performed on unsigned return values, and signed promotion on signed return values.
  // (b) If value is scalar type 8 bytes
  //     The return value is returned to the caller via r10 and r11.
  //     The lower 32 bits are set in r10, and the upper 32 bits in r11.
  // (c) If the value is a structure or union
  // If the return value is a structure or union, then when the caller calls the function, it sets the address
  // to which to write the return value in the argument register r6. The caller sets the return value in the
  // address location indicated by parameter register r6, and returns to the calling function.
  // Upon return, r6 and r10 are undefined (same as Caller-Save registers) to the calling function.
  // All structures and unions are turned by the same method, regardless of size. The actual data of the
  // structure or union is not returned in the register.
  size_t size = rettype.get_size();
  if ( size == BADSIZE )
    return false;
  if ( rettype.is_scalar() )
  {
    if ( size > 8 )
      return false;
    if ( retloc != nullptr )
    {
      if ( size <= 4 )
        retloc->_set_reg1(rR10);
      else
        retloc->_set_reg2(rR10, rR11);
    }
    return true;
  }
  if ( rettype.is_udt() )
  {
    if ( retloc != nullptr )
    {
      if ( abi == ABI_RH850 )
      {
        retloc->set_badloc(); // return void
      }
      else
      {
        if ( size > 8 || !should_pass_struct_by_value(rettype) )
          retloc->_set_reg1(rR10); // return the pointer to the structure
        else if ( size <= 4 )
          retloc->_set_reg1(rR10);
        else
          retloc->_set_reg2(rR10, rR11);
      }
    }
    return true;
  }
  return false;
}

//-------------------------------------------------------------------------
void nec850_t::nec850_lower_func_arg_types(
        intvec_t *argnums,
        const func_type_data_t &fti)
{
  if ( abi == ABI_OLDGCC )
  {
    // Old GCC
    // https://www.filibeto.org/unix/tru64/lib/ossc/doc/cygnus_doc-99r1/html/6_embed/embV850.html#Func_return_value
    // see the comment in calc_nec850_retloc() above
    if ( fti.rettype.is_udt()
      && (fti.rettype.get_size() > 8
       || !should_pass_struct_by_value(fti.rettype)) )
    {
      argnums->push_back(-1); // convert to pointer and return it
    }
    // Structures greater than 8 bytes in length, passed by value, are
    // automatically converted into pass-by-invisible-reference structures
    // (i.e., the compiler arranges to pass a pointer instead of the entire
    // structure).
    for ( size_t i = 0; i < fti.size(); ++i )
    {
      const funcarg_t &fa = fti[i];
      if ( fa.type.is_udt() && fa.type.get_size() > 8 )
      {
        // convert an argument to a pointer to the real argument
        argnums->push_back(i);
      }
    }
  }
  else
  {
    // RH850
    // CC-RH Compiler User's Manual
    // The first 4 words (16 bytes) of the created memory image are passed via registers r6 to r9, and the portion
    // that does not fit is passed on the stack.
    // ...
    // (c) If the value is a structure or union
    // If the return value is a structure or union, then when the caller calls the function, it sets the address
    // to which to write the return value in the argument register r6. The caller sets the return value in the
    // address location indicated by parameter register r6, and returns to the calling function.
    // Upon return, r6 and r10 are undefined (same as Caller-Save registers) to the calling function.
    // All structures and unions are turned by the same method, regardless of size. The actual data of the
    // structure or union is not returned in the register.
    if ( fti.rettype.is_udt() )
      argnums->push_back(-3); // convert to pointer and return 'void'
  }
}

//-------------------------------------------------------------------------
bool nec850_t::get_nec850_cc_regs(callregs_t *callregs, callcnv_t cc)
{
  if ( cc != CM_CC_FASTCALL && cc != CM_CC_ELLIPSIS )
    return false;
  callregs->set_registers(callregs_t::GPREGS, rR6, rR9);
  callregs->policy = ARGREGS_GP_ONLY;
  callregs->nregs = 4;
  return true;
}

