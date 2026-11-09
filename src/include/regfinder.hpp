/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#pragma once

#include <pro.h>
#include <idp.hpp>
#include <ua.hpp>
#include <map>
#include <memory>     // std::unique_ptr
#include <algorithm>  // std::sort

//-------------------------------------------------------------------------
/* A chain is a set of addresses where a register has the same value.
 * Inside basic blocks, we collect these addresses by going backward until
 * the register changes or may change its value. The instruction that
 * changes the register value is not included in the chain.
 * These addresses are stored in REG_USES and the value in CHAINS.
 * If the result of an instruction that changes a value we are looking for
 * depends on another value, we start a new chain.
 * Example:
 * a:=1
 *   |
 *   *<----\
 *   |     |
 *   |   a:=a+1
 *   |     |
 *   +=====/
 *   |
 *  a?
 *
 * Chains are constructed in the depth-first way.
 * This is the listing for the above example:
 * 00       li    $v0, 1        # a:=1
 * 04 loc_4:                    # (*)
 * 04       sw    $v0, 0($a0)   # <body>
 * 08       sltiu $v1, $v0, 0xA
 * 0C       bnezl $v1, loc_4    # (+)
 * 10       addiu $v0, 1        # a:=a+1 (the delay slot of a likely branch)
 * 14       sw    $a0, 0($v0)   # a?
 *
 * after calling find_const($v0, 0x14) we get the following chains:
 *   0=>free
 *   1=>1@0(li) (no addresses)
 *   2=><UNK> (04, 08, 0C, 10, 14)
 */

//-------------------------------------------------------------------------
struct reg_value_def_t;
#define DECLARE_REG_VALUE_DEF_HELPERS(decl)\
decl void ida_export reg_value_def_dstr(const reg_value_def_t *_this, qstring *vout, int how, const procmod_t *pm);

DECLARE_REG_VALUE_DEF_HELPERS(idaman)

//-------------------------------------------------------------------------
/// the register value and its defining instruction
/// \note A simple add/sub instruction (like PUSH for SP) is not considered
/// as the defining instruction.
struct reg_value_def_t
{
  uval_t val = BADADDR;     ///< the value
  ea_t   def_ea = BADADDR;  ///< the instruction address
  uint16 def_itype = 0;     ///< the instruction code (processor specific)
  uint16 flags = 0;         ///< additional info about the value

#define DEF_BIT static constexpr uint16
  DEF_BIT SHORT_INSN = 0x0001;  ///< like 'addi reg, imm'
  DEF_BIT PC_BASED   = 0x0010;  ///< the value depends on DEF_EA
                                ///< only for numbers \sa is_num()
  DEF_BIT LIKE_GOT   = 0x0020;  ///< the value is like GOT
                                ///< only for numbers \sa is_num()
#undef DEF_BIT
  static bool is_short_insn(const insn_t &insn)
  {
    return insn.Op2.type == o_imm && insn.Op3.type == o_void;
  }

  reg_value_def_t() {}
  reg_value_def_t(uval_t _val, ea_t ea, uint16 _flags = 0)
    : val(_val), def_ea(ea), flags(_flags) {}
  reg_value_def_t(uval_t _val, const insn_t &insn, uint16 _flags = 0)
    : val(_val),
      def_ea(insn.ea),
      def_itype(insn.itype),
      flags(_flags | (is_short_insn(insn) ? SHORT_INSN : 0)) {}

  bool is_short_insn() const { return (flags & SHORT_INSN) != 0; }
  bool is_pc_based()   const { return (flags & PC_BASED)   != 0; }
  bool is_like_got()   const { return (flags & LIKE_GOT)   != 0; }

  bool operator==(const reg_value_def_t &r) const
  {
    return def_ea == r.def_ea && val == r.val;
  }
  bool operator<(const reg_value_def_t &r) const
  {
    if ( def_ea < r.def_ea )
      return true;
    if ( def_ea > r.def_ea )
      return false;
    return val < r.val;
  }

  /// How to print reg_value_def_t?
  enum dstr_val_t
  {
    NOVAL,  ///< without a value
    UVAL,   ///< as a number
    SPVAL,  ///< as a SP delta
  };
  /// Return the string representation.
  qstring dstr(dstr_val_t how, const procmod_t *pm = nullptr) const
  {
    qstring out;
    reg_value_def_dstr(this, &out, how, pm);
    return out;
  }

protected:
  DECLARE_REG_VALUE_DEF_HELPERS(friend)

  qstring dstr_impl(dstr_val_t how, const procmod_t *pm) const;
};
DECLARE_TYPE_AS_MOVABLE(reg_value_def_t);

//-------------------------------------------------------------------------
struct reg_value_info_t;
#define DECLARE_REG_VALUE_INFO_HELPERS(decl)\
decl int ida_export reg_value_info_vals_union(reg_value_info_t *_this, const reg_value_info_t *r);\
decl void ida_export reg_value_info_dstr(const reg_value_info_t *_this, qstring *vout, const procmod_t *pm);

DECLARE_REG_VALUE_INFO_HELPERS(idaman)

//-------------------------------------------------------------------------
/// the value in a register after emulating instructions
struct reg_value_info_t
{
protected:
  using val_def_t = reg_value_def_t;
  friend struct reg_finder_block_t; // for join_values()

  enum state_t : uint8
  {
    UNDEF,    // we know nothing about a value
    DEADEND,  // no execution flow to the insn
    ABORTED,  // the tracking process was aborted because the maximal
              // tracking depth is not enough to find a value
    BADINSN,  // the insn cannot be decoded
    UNKINSN,  // the result of the insn execution is unknown
    UNKFUNC,  // the register comes from the function start
    UNKLOOP,  // the register is changed in a loop
    UNKMULT,  // the register has incompatible values
              // (a number and SP delta)
    NUMINSN,  // the value is a number after executing a insn
    NUMADDR,  // the value is a number before an address
    SPDINSN,  // the value is a SP delta after executing a insn
    SPDADDR,  // the value is a SP delta before an address
  };
  // the SP delta is the value of SP minus the initial value of SP at the
  // function start.
  // each value (except UNDEF) may be set either before or after executing
  // an insn at vals[i].def_ea. in the table below, these options are
  // labeled B and A, respectively. The table shows what address is in
  // vals[i].def_ea.
  // the states below allow a single value
  // DEADEND  B  the address of the dead end
  // ABORTED  B  the address where it was aborted
  // BADINSN  A  the insn address (ITYPE is not set)
  // UNKINSN  A  the insn address
  // UNKFUNC  B  the function start address
  // UNKLOOP  B  the address of the changing insn
  // UNKMULT  B  the address of the joint point
  // the states below allow multiple values
  // NUMINSN  A  the address of the defining insn
  // NUMADDR  B  the address after which the value became known
  // SPDINSN  A  the address of the defining insn
  // SPDADDR  B  the address after which the value became known

  qvector<val_def_t> vals;  // sorted
  state_t state = UNDEF;

  explicit reg_value_info_t(
        state_t _state,
        ea_t def_ea,
        uval_t _val = BADADDR,
        uint16 val_flags = 0)
    : state(_state)
  {
    vals.push_back(val_def_t(_val, def_ea, val_flags));
  }
  explicit reg_value_info_t(
        state_t _state,
        const insn_t &insn,
        uval_t _val = BADADDR,
        uint16 val_flags = 0)
    : state(_state)
  {
    vals.push_back(val_def_t(_val, insn, val_flags));
  }

public:
  reg_value_info_t() {}
  /// Undefine the value.
  void clear()
  {
    state = UNDEF;
    vals.qclear();
  }
  /// Return 'true' if we know nothing about a value.
  bool empty() const { return state == UNDEF; }

  /// Return the undefined value because of a dead end.
  /// \sa is_dead_end()
  static reg_value_info_t make_dead_end(ea_t dead_end_ea)
  {
    return reg_value_info_t(DEADEND, dead_end_ea);
  }

  /// Return the value after aborting.
  /// \sa aborted()
  static reg_value_info_t make_aborted(ea_t bblk_ea)
  {
    return reg_value_info_t(ABORTED, bblk_ea);
  }

  /// Return the unknown value after a bad insn.
  /// \sa is_badinsn()
  static reg_value_info_t make_badinsn(ea_t insn_ea)
  {
    return reg_value_info_t(BADINSN, insn_ea);
  }

  /// Return the unknown value after executing the insn.
  /// \sa is_unkinsn()
  static reg_value_info_t make_unkinsn(const insn_t &insn)
  {
    return reg_value_info_t(UNKINSN, insn);
  }

  /// Return the unknown value from the function start.
  /// \sa is_unkfunc()
  static reg_value_info_t make_unkfunc(ea_t func_ea)
  {
    return reg_value_info_t(UNKFUNC, func_ea);
  }

  /// Return the unknown value if it changes in a loop.
  /// \sa is_unkloop()
  static reg_value_info_t make_unkloop(ea_t bblk_ea)
  {
    return reg_value_info_t(UNKLOOP, bblk_ea);
  }

  /// Return the unknown value if the register has incompatible values.
  /// \sa is_unkmult()
  static reg_value_info_t make_unkmult(ea_t bblk_ea)
  {
    return reg_value_info_t(UNKMULT, bblk_ea);
  }

  /// Return the value that is the RVAL number.
  /// \sa is_num()
  static reg_value_info_t make_num(
        uval_t rval,
        const insn_t &insn,
        uint16 val_flags = 0)
  {
    return reg_value_info_t(NUMINSN, insn, rval, val_flags);
  }
  /// Return the value that is the RVAL number.
  /// \sa is_num()
  static reg_value_info_t make_num(
        uval_t rval,
        ea_t val_ea,
        uint16 val_flags = 0)
  {
    return reg_value_info_t(NUMADDR, val_ea, rval, val_flags);
  }

  /// Return the value that is the initial stack pointer.
  /// \sa is_spd()
  static reg_value_info_t make_initial_sp(ea_t func_ea)
  {
    return reg_value_info_t(SPDADDR, func_ea, 0);
  }

  //-----------------------------------------------------------------------
  // access methods

  /// Return 'true' if the value is undefined because of a dead end.
  bool is_dead_end() const { return state == DEADEND; }
  /// Return 'true' if the tracking process was aborted.
  bool aborted() const { return state == ABORTED; }
  /// Return 'true' if the value requires special handling.
  bool is_special() const { return is_dead_end() || aborted(); }

  /// Return 'true' if the value is unknown because of a bad insn.
  bool is_badinsn() const { return state == BADINSN; }
  /// Return 'true' if the value is unknown after executing the insn.
  bool is_unkinsn() const { return state == UNKINSN; }
  /// Return 'true' if the value is unknown from the function start.
  bool is_unkfunc() const { return state == UNKFUNC; }
  /// Return 'true' if the value is unknown because it changes in a loop.
  bool is_unkloop() const { return state == UNKLOOP; }
  /// Return 'true' if the value is unknown because the register has
  /// incompatible values (a number and SP delta).
  bool is_unkmult() const { return state == UNKMULT; }
  /// Return 'true' if the value is unknown.
  bool is_unknown() const
  {
    return state == BADINSN
        || state == UNKINSN
        || state == UNKFUNC
        || state == UNKLOOP
        || state == UNKMULT;
  }

  /// Return 'true' if the value is a constant.
  bool is_num() const { return state == NUMINSN || state == NUMADDR; }
  /// Return 'true' if the value depends on the stack pointer.
  bool is_spd() const { return state == SPDINSN || state == SPDADDR; }
  /// Return 'true' if the value is known (i.e. it is a number or SP delta).
  bool is_known() const { return is_num() || is_spd(); }

  /// Return the number if the value is a constant.
  /// \sa is_num()
  bool get_num(uval_t *uval) const
  {
    if ( !is_num() || !is_value_unique() )
      return false;
    *uval = vals.begin()->val;
    return true;
  }
  /// Return the SP delta if the value depends on the stack pointer.
  /// \sa is_spd()
  /// \param [out] sval  the value of SP minus the initial value of SP at
  ///                    the function start.
  bool get_spd(sval_t *sval) const
  {
    if ( !is_spd() || !is_value_unique() )
      return false;
    *sval = vals.begin()->val;
    return true;
  }
  /// Return the defining address.
  ea_t get_def_ea() const
  {
    return !is_value_unique() ? BADADDR : vals.begin()->def_ea;
  }
  /// Return the defining instruction code (processor specific).
  uint16 get_def_itype() const
  {
    return !is_value_unique() ? 0 : vals.begin()->def_itype;
  }

  /// Return a const iterator to the first value.
  const reg_value_def_t *vals_begin() const { return vals.begin(); }
  /// Return a const iterator right after the last value.
  const reg_value_def_t *vals_end() const { return vals.end(); }
  /// Return the number of values.
  size_t vals_size() const { return vals.size(); }

  /// Check that the value is unique.
  bool is_value_unique() const
  {
    if ( empty() )
      return false;
    if ( vals.size() == 1 )
      return true;
    auto p = vals.begin();
    uval_t v = p->val;
    for ( ++p; p != vals.end(); ++p )
      if ( p->val != v )
        return false;
    return true;
  }

  /// Check the given flag for each value.
  bool have_all_vals_flag(uint16 val_flags) const
  {
    for ( auto p : vals )
      if ( (p.flags & val_flags) == 0 )
        return false;
    return true;
  }
  bool is_all_vals_pc_based() const
  {
    return have_all_vals_flag(val_def_t::PC_BASED);
  }
  bool is_all_vals_like_got() const
  {
    return have_all_vals_flag(val_def_t::LIKE_GOT);
  }

  //-----------------------------------------------------------------------
  // modification methods

  /// Set the value to be undefined because of a dead end.
  /// \sa is_dead_end()
  void set_dead_end(ea_t dead_end_ea)
  {
    state = DEADEND;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, dead_end_ea));
  }

  /// Set the value to be unknown after a bad insn.
  /// \sa is_badinsn()
  void set_badinsn(ea_t insn_ea)
  {
    state = BADINSN;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, insn_ea));
  }

  /// Set the value to be unknown after executing the insn.
  /// \sa is_unkinsn()
  void set_unkinsn(const insn_t &insn)
  {
    state = UNKINSN;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, insn));
  }

  /// Set the value to be unknown from the function start.
  /// \sa is_unkfunc()
  void set_unkfunc(ea_t func_ea)
  {
    state = UNKFUNC;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, func_ea));
  }

  /// Set the value to be unknown because it changes in a loop.
  /// \sa is_unkloop()
  void set_unkloop(ea_t bblk_ea)
  {
    state = UNKLOOP;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, bblk_ea));
  }

  /// Set the value to be unknown because the register has incompatible values.
  /// \sa is_unkmult()
  void set_unkmult(ea_t bblk_ea)
  {
    state = UNKMULT;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, bblk_ea));
  }

  /// Set the value after aborting.
  /// \sa aborted()
  void set_aborted(ea_t bblk_ea)
  {
    state = ABORTED;
    vals.qclear();
    vals.push_back(val_def_t(BADADDR, bblk_ea));
  }

  /// Set the value to be a number after executing an insn.
  /// \sa is_num()
  void set_num(uval_t rval, const insn_t &insn, uint16 val_flags = 0)
  {
    state = NUMINSN;
    vals.qclear();
    vals.push_back(val_def_t(rval, insn, val_flags));
  }
  /// Set the value to be numbers after executing an insn.
  /// \note This method spoils RVALS.
  /// \sa is_num()
  void set_num(uvalvec_t *rvals, const insn_t &insn)
  {
    state = NUMINSN;
    set_multivals(rvals, insn);
  }
  /// Set the value to be a number before an address.
  /// \sa is_num()
  void set_num(uval_t rval, ea_t val_ea, uint16 val_flags = 0)
  {
    state = NUMADDR;
    vals.qclear();
    vals.push_back(val_def_t(rval, val_ea, val_flags));
  }

  /// The result of comparison of 2 value sets.
  enum set_compare_res_t
  {
    EQUAL,          ///< L==R
    CONTAINS,       ///< L contains R (i.e. R\L is empty)
    CONTAINED,      ///< L is contained in R (i.e. L\R is empty)
    NOT_COMPARABLE, ///< L\R is not empty and R\L is not empty
  };
  /// Add values from R into THIS ignoring duplicates.
  /// \note This method is the only way to get multiple values.
  /// \retval EQUAL           THIS is not changed
  /// \retval CONTAINS        THIS is not changed
  /// \retval CONTAINED       THIS is a copy of R
  /// \retval NOT_COMPARABLE  values from R are added to THIS
  set_compare_res_t vals_union(const reg_value_info_t &r)
  {
    return set_compare_res_t(reg_value_info_vals_union(this, &r));
  }

  /// Sign-, or zero-extend the number or SP delta value to full size.
  /// The initial value is considered to be of size WIDTH.
  /// \note This method do nothing for unknown values.
  inline void extend(const procmod_t &pm, int width, bool is_signed);

  /// Truncate the number to the application bitness.
  /// \note This method do nothing for non-number values.
  inline void trunc_uval(const procmod_t &pm);

  // arithmetic operations
  enum arith_op_t
  {
    ADD, SUB,
    OR, AND, XOR, AND_NOT,
    SLL, SLR, MOVT,
    NEG, NOT,
  };

  /// Add R to the value, save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void add(const reg_value_info_t &r, const insn_t &insn);
  /// Subtract R from the value, save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void sub(const reg_value_info_t &r, const insn_t &insn);
  /// Make bitwise OR of R to the value,
  /// save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void bor(const reg_value_info_t &r, const insn_t &insn);
  /// Make bitwise AND of R to the value,
  /// save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void band(const reg_value_info_t &r, const insn_t &insn);
  /// Make bitwise eXclusive OR of R to the value,
  /// save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void bxor(const reg_value_info_t &r, const insn_t &insn);
  /// Make bitwise AND of the inverse of R to the value,
  /// save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void bandnot(const reg_value_info_t &r, const insn_t &insn);
  /// Shift the value left by R, save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void sll(const reg_value_info_t &r, const insn_t &insn);
  /// Shift the value right by R, save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void slr(const reg_value_info_t &r, const insn_t &insn);
  /// Replace the top 16 bits with bottom 16 bits of R, leaving the bottom
  /// 16 bits untouched, save INSN as a defining instruction.
  /// \note Either THIS or R must have a single value.
  inline void movt(const reg_value_info_t &r, const insn_t &insn);
  /// Negate the value, save INSN as a defining instruction.
  inline void neg(const insn_t &insn);
  /// Make bitwise inverse of the value,
  /// save INSN as a defining instruction.
  inline void bnot(const insn_t &insn);
  /// Add R to the value, save INSN as a defining instruction.
  /// \note This method do nothing for unknown values.
  inline void add_num(uval_t r, const insn_t &insn);

  /// Add R to the value, do not change the defining instructions.
  /// \note This method do nothing for unknown values.
  inline void add_num(uval_t r);
  /// Shift the value left by R, do not change the defining instructions.
  /// \note This method do nothing for unknown values.
  inline void shift_left(uval_t r);
  /// Shift the value right by R, do not change the defining instructions.
  /// \note This method do nothing for unknown values.
  inline void shift_right(uval_t r);

  /// Return the string representation.
  qstring dstr(const procmod_t *pm = nullptr) const
  {
    qstring out;
    reg_value_info_dstr(this, &out, pm);
    return out;
  }

protected:
  DECLARE_REG_VALUE_INFO_HELPERS(friend)

  // helper implementation
  set_compare_res_t vals_union_impl(const reg_value_info_t &r);
  qstring dstr_impl(const procmod_t *pm) const;

  // perform a binary operation
  // \note Either THIS or R must have a single value.
  inline bool perform_binary_op(
        const reg_value_info_t &r,
        arith_op_t aop,
        const insn_t &insn);
  // fix the sorting order and set VALS
  inline void set_multivals(uvalvec_t *rvals, const insn_t &insn);
  // fix the sorting order
  inline void sort_multivals();
};

//-------------------------------------------------------------------------
// what operand are we going to track?
struct reg_finder_op_t
{
private:
  static constexpr uint32 REG         = 0;
  static constexpr uint32 STKVAR      = 1 << 31;
  static constexpr int    WIDTH_SHIFT = 29;
  static constexpr uint32 WIDTH_MASK  = 0x3 << WIDTH_SHIFT;
  static constexpr uint32 SIGNED      = 1 << 28;
  static constexpr int    STKOFF_SIGNBIT = 1 << 27;
  static constexpr uint32 STKOFF_MASK = STKOFF_SIGNBIT - 1;
  // the impossible combination of bits
  static constexpr uint32 BADREG = 0x10000;

  uint32 packed = BADREG;

  explicit reg_finder_op_t(uint32 _packed) : packed(_packed) {}

public:
  using rfop_t = reg_finder_op_t;
  reg_finder_op_t() {}
  reg_finder_op_t(const rfop_t &r) = default;
  rfop_t &operator=(const rfop_t &r) = default;

  // if after constructors empty() returns 'true'
  // that means that arguments are bad
  bool empty() const { return packed == BADREG; }
  void clear() { packed = BADREG; }

  static bool is_valid_reg(int reg)
  {
    return reg >= 0 && reg < BADREG;
  }
  inline static reg_finder_op_t make_reg(int reg, int width);
  static reg_finder_op_t make_reg(const procmod_t &pm, int reg)
  {
    return make_reg(reg, pm.eah().ea_size); // 4 or 8
  }

  static bool is_valid_stkoff(sval_t stkoff)
  {
    return stkoff >= -sval_t(STKOFF_MASK) && stkoff <= sval_t(STKOFF_MASK);
  }
  inline static reg_finder_op_t make_stkoff(sval_t stkoff, int width);
  inline static int get_op_width(const op_t &op);

  inline void set_width(int width);
  inline void set_signness(bool is_signed);
  inline void set_width_signness(int width, bool is_signed);

  bool is_reg()    const { return (packed & STKVAR) == 0; }
  bool is_stkvar() const { return (packed & STKVAR) != 0; }
  bool is_signed() const { return (packed & SIGNED) != 0; }
  int get_width() const
  {
    return 1 << ((packed & WIDTH_MASK) >> WIDTH_SHIFT);
  }

  uint16 get_reg() const { return uint16(packed); }
  sval_t get_stkoff() const
  {
    sval_t stkoff = packed & STKOFF_MASK;
    return (packed & STKOFF_SIGNBIT) == 0 ? stkoff : -stkoff;
  }

  bool is_reg(int reg) const { return is_reg() && get_reg() == reg; }

  DECLARE_COMPARISONS(reg_finder_op_t)
  {
    // the empty object is less than any other object
    if ( empty() )
      return r.empty() ? 0 : -1;
    if ( r.empty() )
      return 1;
    return ::compare(packed, r.packed);
  }


protected:
  inline static uint32 pack_width(int width);
};

//-------------------------------------------------------------------------
struct reg_finder_t;
struct reg_value_ud_chain_t;
typedef void (*reg_finder_binary_ops_adjust_fun)(
        reg_value_info_t *v1,
        reg_value_info_t *v2,
        const insn_t &insn,
        void *ud);

#define DECLARE_REG_FINDER_HELPERS(decl)\
decl void ida_export reg_finder_invalidate_cache(reg_finder_t *_this, ea_t to, ea_t from);\
decl void ida_export reg_finder_find(reg_finder_t *_this, reg_value_info_t *out, ea_t ea, ea_t ds, reg_finder_op_t op, int max_depth);\
decl void ida_export reg_finder_make_rfop(reg_finder_t *_this, reg_finder_op_t *rfop, const op_t *op, const insn_t *insn, func_t *pfn);\
decl bool ida_export reg_finder_calc_op_addr(reg_finder_t *_this, reg_value_info_t *addr, const op_t *memop, const insn_t *insn, ea_t ea, ea_t ds, int max_depth);\
decl bool ida_export reg_finder_emulate_mem_read(reg_finder_t *_this, reg_value_info_t *value, const reg_value_info_t *addr, int width, bool is_signed, const insn_t *insn);\
decl void ida_export reg_finder_emulate_binary_op(reg_finder_t *_this, reg_value_info_t *value, int aop, const op_t *op1, const op_t *op2, const insn_t *insn, ea_t ea, ea_t ds, reg_finder_binary_ops_adjust_fun adjust, void *ud);\
decl void ida_export reg_finder_emulate_unary_op(reg_finder_t *_this, reg_value_info_t *value, int aop, int reg, const insn_t *insn, ea_t ea, ea_t ds);\
decl bool ida_export reg_finder_may_modify_stkvar(reg_finder_t *_this, reg_finder_op_t op, const insn_t *insn);\
decl void ida_export reg_finder_ctr(reg_finder_t *_this);\
decl void ida_export reg_finder_dtr(reg_finder_t *_this);

DECLARE_REG_FINDER_HELPERS(idaman)

//-------------------------------------------------------------------------
//lint -e{958} padding needed
struct reg_finder_block_t;
struct reg_finder_pred_t;
struct reg_finder_t
{
  const procmod_t &pm;
  const int proc_maxop; // max number of operands in insns
  // a call insn may modify stkvars (via aliased stkvars passed as args).
  // this member indicates how to answer this question.
  bool does_call_spoil_stkvars;
  // we can track stkvars even without a function (basing on the SP value).
  // but this can take a lot of time.
  bool allow_stkvar_without_func;

protected:
  using rvi_t = reg_value_info_t;
  using rfop_t = reg_finder_op_t;
  using block_t = reg_finder_block_t;
  using pred_t = reg_finder_pred_t;
  friend struct reg_finder_block_t;
  friend struct reg_finder_pred_t;

  // the data members below are set by the each call of find()
  func_t *cur_func = nullptr;   // function to search in
  size_t initial_block_idx = 0;
  int cur_max_depth = 0;        // maximum search depth
  bool auto_max_depth = true;   // is the initial CUR_MAX_DEPTH taken
                                // from ida.cfg?
  ea_t aborting_ea = BADADDR;   // to make tracking aborting easier
  bool tracking_aborted() const { return aborting_ea != BADADDR; }
  void abort_tracking(ea_t ea) { aborting_ea = ea; }
  rvi_t standalone_value;       // to return a value for the initial block
                                // without addresses

  static constexpr size_t NO_CHAIN = size_t(-1);

  // a temporary storage to return from is_move_insn()
  op_t fake_op1;
  op_t fake_op2;

  // the condition under which the instruction is executed,
  // and some additional instruction features
  struct cond_t
  {
  private:
    uint32 packed;
    static constexpr uint32 COND_MASK   = 0x0F;
    static constexpr int    KIND_SHIFT  = 4;
    static constexpr uint32 KIND_MASK   = 0xF;

  public:
    // got from arm.hpp
    enum : uchar
    {
      EQ, // 0000 Z                        Equal
      NE, // 0001 !Z                       Not equal
      CS, // 0010 C                        Unsigned higher or same
      CC, // 0011 !C                       Unsigned lower
      MI, // 0100 N                        Negative
      PL, // 0101 !N                       Positive or Zero
      VS, // 0110 V                        Overflow
      VC, // 0111 !V                       No overflow
      HI, // 1000 C & !Z                   Unsigned higher
      LS, // 1001 !C | Z                   Unsigned lower or same
      GE, // 1010 (N & V) | (!N & !V)      Greater or equal
      LT, // 1011 (N & !V) | (!N & V)      Less than
      GT, // 1100 !Z & ((N & V)|(!N & !V)) Greater than
      LE, // 1101 Z | (N & !V) | (!N & V)  Less than or equal
      AL, // 1110 Always
      NV, // 1111 Never
    };

    enum : uchar
    {
      NONE,
      MODIFIES_CC,
      JUMPS,
    };

    cond_t(uchar cond = AL, uchar kind = NONE)
      : packed((cond & COND_MASK) | ((kind & KIND_MASK) << KIND_SHIFT)) {}

    uchar get_cond() const { return uchar(packed & COND_MASK); }
    // e.g. GE includes GE, GT, EQ
    //   MOVGE ...  this insn is executed if the branch is taken
    //   BGT   away
    bool is_included_in(cond_t r) const
    {
      // TODO implement non-trivial cases
      uchar cnd = get_cond();
      uchar rcnd = r.get_cond();
      // AL includes all other conditions
      return cnd == rcnd || rcnd == AL;
    }

    uchar get_kind() const
    {
      return uchar((packed >> KIND_SHIFT) & KIND_MASK);
    }
    bool modifies_cond_codes() const { return get_kind() == MODIFIES_CC; }
    bool jumps()               const { return get_kind() == JUMPS;       }
  };

private:
  using udc_t = reg_value_ud_chain_t;

  friend struct reg_finder_chainvec_t;
  struct reg_finder_chainvec_t *chains = nullptr; // the chain values
  size_t nfreechains = 0;

  struct addr_t
  {
    ea_t ea;
    rfop_t rfop;
    addr_t(ea_t _ea, rfop_t _rfop = rfop_t()) : ea(_ea), rfop(_rfop) {}
    DECLARE_COMPARISONS(addr_t)
    {
      int code = ::compare(ea, r.ea);
      if ( code == 0 )
        code = rfop.compare(r.rfop);
      return code;
    }
  };
  // where does the value come from?
  struct vref_t
  {
    size_t chain_num; // the chain number
    sval_t delta;     // the addend to the chain value
    explicit vref_t(
        size_t _chain_num = reg_finder_t::NO_CHAIN,
        sval_t _delta = 0)
     : chain_num(_chain_num), delta(_delta) {}
    bool empty() const { return chain_num == reg_finder_t::NO_CHAIN; }
    void clear() { chain_num = reg_finder_t::NO_CHAIN; delta = 0; }
    bool operator==(const vref_t &r)
    {
      return chain_num == r.chain_num && delta == r.delta;
    }
  };

  // key - an operand and an address,
  // value - the reference to the value of the register at this address
  //         (the chain value + DELTA)
  friend struct reg_finder_rfop_chains_t; // the opaque type
  struct reg_finder_rfop_chains_t *rfop_chains = nullptr;

  // the path of depth-first search
  qvector<vref_t> path;

  bool debug_on = true;

public:
  reg_finder_t(
        const procmod_t &_pm,
        int _proc_maxop = 3,
        bool _does_call_spoil_stkvars = true,
        bool _allow_stkvar_without_func = false)
    : pm(_pm),
      proc_maxop(_proc_maxop),
      does_call_spoil_stkvars(_does_call_spoil_stkvars),
      allow_stkvar_without_func(_allow_stkvar_without_func)
  {
    reg_finder_ctr(this);
  }
  virtual ~reg_finder_t() { reg_finder_dtr(this); }

  // the code xref from FROM to TO was added or deleted.
  // if we have TO address in the cache we should invalidate the value at
  // this address and the dependent values.
  void invalidate_cache(ea_t to, ea_t from)
  {
    reg_finder_invalidate_cache(this, to, from);
  }
  // clear the entire cache.
  void invalidate_cache()
  {
    reg_finder_invalidate_cache(this, BADADDR, BADADDR);
  }

  // find a value of OP before EA
  // \param max_depth  the maximum search depth.
  //                   0 means the value of REGTRACK_MAX_DEPTH or
  //                   REGTRACK_FUNC_MAX_DEPTH from ida.cfg depending on the
  //                   register,
  //                   -1 means always the value of REGTRACK_FUNC_MAX_DEPTH.
  rvi_t find(ea_t ea, rfop_t rfop, int max_depth = 0)
  {
    flow_t flow = process_delay_slot(pm.trunc_uval(ea), fl_U);
    return find(flow, rfop, max_depth);
  }

  // find the value of any of the two registers
  int find_nearest(
        reg_value_info_t *rvi,
        ea_t ea,
        const int reg[2])
  {
    if ( reg[0] == reg[1] )
      return -1;
    *rvi = find(ea, rfop_t::make_reg(pm, reg[0]), 1);
    if ( rvi->is_known() )
      return 0;
    *rvi = find(ea, rfop_t::make_reg(pm, reg[1]), 1);
    if ( rvi->is_known() )
      return 1;
    *rvi = find(ea, rfop_t::make_reg(pm, reg[0]), 0);
    if ( rvi->is_known() )
      return 0;
    *rvi = find(ea, rfop_t::make_reg(pm, reg[1]), 0);
    if ( rvi->is_known() )
      return 1;
    return -1;
  }

  // find a value of non-SP based register before EA
  bool find_const(uval_t *val, ea_t ea, rfop_t rfop, int max_depth = 0)
  {
    return find(ea, rfop, max_depth).get_num(val);
  }

  // find a value of SP based register before EA
  // by default it uses the SP register and REGTRACK_FUNC_MAX_DEPTH
  bool find_spd(sval_t *spval, ea_t ea, int reg = -1, int max_depth = -1)
  {
    if ( reg == -1 )
    {
      reg = get_sp_reg(ea);
      if ( reg == -1 )
        return false;
    }
    return find(ea, rfop_t::make_reg(pm, reg), max_depth).get_spd(spval);
  }

  // make the regfinder operand from the insn operand.
  // if OP is unsupported this function returns an empty operand.
  rfop_t make_rfop(const op_t &_op, const insn_t &insn, func_t *pfn)
  {
    op_t op = _op; // make a copy
    if ( !can_track_op(&op, insn, pfn) )
      return rfop_t();
    rfop_t res;
    reg_finder_make_rfop(this, &res, &op, &insn, pfn);
    return res;
  }

  // find the operand addresses (o_displ or o_phrase or o_mem)
  // \li in the case of 'o_displ', the address is formed by adding
  // memop.addr to the content of memop.phrase
  // \li in the case of 'o_phrase', the address is formed by adding
  // memop.addr to the sum of the content of memop.phrase and the content of
  // the second register (memop.value), \sa procmod_t::make_op_phrase()
  // \li in the case of 'o_mem', the address is just memop.addr
  // \param memop      the operand
  // \param insn       the emulated insn
  // \param max_depth  the maximum search depth.
  rvi_t find_op_addr(
        const op_t &memop,
        const insn_t &insn,
        int max_depth = 0)
  {
    rvi_t ret;
    flow_t flow = process_delay_slot(pm.trunc_uval(insn.ea), fl_U);
    reg_finder_calc_op_addr(this, &ret,
                            &memop,
                            &insn, flow.ea, flow.ds, max_depth);
    return ret;
  }

  // handle a memory read
  // \note this method checks that the address belongs to the readonly
  // segment, if not it calls is_mem_readonly() to make an additional
  // check.
  // \param addr         the address to read from.
  //                     this parameter may be the same as VALUE.
  // \param width        the data width. it must be 1/2/4/8.
  //                     \sa get_data_value()
  // \param is_signed    if 'true' the result should be sign-extended
  // \param insn         the emulated insn
  void emulate_mem_read(
        rvi_t *value,
        const rvi_t &addr,
        int width,
        bool is_signed,
        const insn_t &insn)
  {
    reg_finder_emulate_mem_read(this, value, &addr,
                                width, is_signed,
                                &insn);
  }


protected:
  // the address of the emulated instruction, taking into account a possible
  // delay slot
  struct flow_t
  {
    ea_t ea;
    ea_t ds; // to handle a delay slot
    bool has_delay_slot() const { return ds != BADADDR; }
    // pre-condidition: has_delay_slot()
    bool is_ea_handled() const { return ds > ea; }
    // pre-condidition: is_ea_handled()
    void handle_delay_slot() { qswap(ea, ds); }

    flow_t(ea_t _ea, ea_t _ds = BADADDR) : ea(_ea), ds(_ds) {}

    // the address of the actually emulated insn
    // when handling a delay slot we are actually emulating the main insn
    // 00 func:
    // 00     beq ..., @away # $t9 is not 00 because it is modified in the
    //                       # delay slot
    // 04     addui $t9, ... # $t9 is 00 before this insn
    ea_t actual_ea() const { return has_delay_slot() ? ds : ea; }
    operator ea_t() const { return actual_ea(); }

    bool operator<(const flow_t &r) const { return ea < r.ea; }

  };

  // processor specific methods

  // we reached EA using REF.
  // For processors with delay slots we can process another insn first.
  // 00 jal   main
  // 04 addiu $a1, $v0, 4 <-- EA but we should start with 00
  // \param ref how did we reach EA?
  //              - fl_F:         by the ordinary flow,
  //              - fl_JN, fl_JF: by the jump,
  //              - fl_U:         from the find() method.
  virtual flow_t process_delay_slot(ea_t ea, cref_t /*ref*/) const
  {
    return flow_t(ea); // no delay slots
  }

  // an instruction may be executed under a condition
  virtual cond_t get_cond(ea_t ea) const
  {
    qnotused(ea);
    return cond_t(); // no conditional instructions
  }

  // we may know the value of some registers
  // \retval empty()      we know nothing
  // \retval is_unkfunc() there may be any value (e.g. a func argument)
  // \retval is_known()   we found the value (e.g. the GOT register)
  virtual rvi_t handle_well_known_regs(
        flow_t flow,
        rfop_t rfop,
        bool is_func_start) const
  {
    qnotused(rfop);
    qnotused(flow);
    qnotused(is_func_start);
    return rvi_t(); // know nothing about registers
  }

  // is the content of memory at EA a constant?
  // \note this method is called from emulate_mem_read() if it cannot itself
  // determine that this memory is read-only.
  virtual bool is_mem_readonly(ea_t /*ea*/) const
  {
    return false;
  }

  // get the SP register
  virtual int get_sp_reg(ea_t ea) const
  {
    qnotused(ea);
    return -1;
  }

  // is REG used throughout the function?
  virtual bool is_funcwide_reg(ea_t ea, int reg) const
  {
    return reg == get_sp_reg(ea);
  }

  // we can track only registers and stkvars (including BP-based)
  virtual bool can_track_op(op_t *op, const insn_t &insn, func_t *pfn) const
  {
    qnotused(op);
    qnotused(insn);
    qnotused(pfn);
    return false;
  }

  // is INSN a 'move' instruction? (or a simple add/sub instruction)
  struct move_desc_t
  {
    // the first case (if !new_rfop.empty()):
    // is_move_insn() already knows the new tracked operand
    rfop_t new_rfop;

    // the second case (if new_rfop.empty()):
    // the operand types should be byte/word/dword/qword
    // both DST_OP and SRC_OP cannot be memory operands
    // the pointer to the source operand
    const op_t *dst_op = nullptr;
    // the pointer to the destination operand
    const op_t *src_op = nullptr;
    // if 'true' and DST_OP is wider than SRC_OP then the source operand
    // will be sign extended
    bool is_signed = false;

    // if non-zero then the instruction is a simple 'add/sub' insn with an
    // immediate value. the operands must have the same size.
    // \note this member is used by both cases.
    // DELTA is positive for the 'add' insn.
    sval_t delta = 0;
  };
  // \param [out] move_desc  the decription of the 'move' insn
  // \param [in] rfop        the operand to find a value of
  // \param insn             the emulating insn
  // \retval false  if INSN is not a 'move' insn
  // \retval true   INSN is a 'move' insn
  virtual bool is_move_insn(
        move_desc_t *move_desc,
        const rfop_t &rfop,
        const insn_t &insn)
  {
    qnotused(move_desc);
    qnotused(rfop);
    qnotused(insn);
    return false;
  }

  // emulate INSN and find the value of OP
  // to get values of the source registers this method may call find()
  // (this call will be recursive)
  // \param [out] value  only if the method returns 'true'
  //                     is_dead_end(): there is no flow to this insn
  //                     aborted():     the tracking process was aborted
  //                     is_unkinsn():  INSN spoils OP in an unknown way
  //                     is_known():    the found value
  // \param [in] rfop    the operand to find a value of
  // \param [in] insn    the instruction to emulate
  // \param [in] flow    the control flow to get a preceding insn.
  //                     It should be pass to find().
  // \retval true   the found value is in VALUE
  // \retval false  INSN does not modify OP
  virtual bool emulate_insn(
        rvi_t *value,
        const rfop_t &rfop,
        const insn_t &insn,
        flow_t flow)
  {
    qnotused(rfop);
    qnotused(flow);
    value->set_unkinsn(insn); // do not support any instruction
    return true;
  }

  // helper methods for emulate_insn()

  // get values of the operand from emulate_insn()
  // \param flow       the control flow to get a starting insn
  // \param rfop       the operand to find a value of
  // \param max_depth  the maximum search depth.
  //                   when find is called recursively, MAX_DEPTH is added
  //                   to the current search depth, but the new maximum
  //                   depth cannot exceed the maximum depth set on the
  //                   first call to find().
  rvi_t find(flow_t flow, rfop_t rfop, int max_depth = 0)
  {
    rvi_t ret;
    reg_finder_find(this, &ret, flow.ea, flow.ds, rfop, max_depth);
    return ret;
  }

  // get values of the register from emulate_insn()
  // \param flow       the control flow to get a starting insn
  // \param reg        the register to find a value of
  rvi_t find(flow_t flow, int reg)
  {
    rvi_t ret;
    rfop_t rfop = rfop_t::make_reg(pm, reg);
    reg_finder_find(this, &ret, flow.ea, flow.ds, rfop, 0);
    return ret;
  }

  // get operand addresses (o_displ or o_phrase or o_mem)
  // \sa find_op_addr()
  void calc_op_addr(
        rvi_t *addr,
        const op_t &memop,
        const insn_t &insn,
        flow_t flow)
  {
    reg_finder_calc_op_addr(this, addr,
                            &memop,
                            &insn, flow.ea, flow.ds, 0);
  }

  void emulate_binary_op(
        rvi_t *value,
        rvi_t::arith_op_t aop, // not NEG, NOT
        const op_t &op1,
        const op_t &op2,
        const insn_t &insn,
        flow_t flow,
        reg_finder_binary_ops_adjust_fun adjust = nullptr,
        void *ud = nullptr)
  {
    reg_finder_emulate_binary_op(this, value,
                                 aop, &op1, &op2,
                                 &insn, flow.ea, flow.ds,
                                 adjust, ud);
  }
  void emulate_unary_op(
        rvi_t *value,
        rvi_t::arith_op_t aop, // only NEG, NOT
        int reg,
        const insn_t &insn,
        flow_t flow)
  {
    reg_finder_emulate_unary_op(this, value,
                                 aop, reg,
                                 &insn, flow.ea, flow.ds);
  }

  // this method returns 'true' if there is the slightest possibility that
  // INSN changes OP (it is a stkvar).
  // in the current implementation we assume that any store instruction with
  // an unknown address or any call instruction may modify stkvars.
  bool may_modify_stkvar(rfop_t rfop, const insn_t &insn)
  {
    return reg_finder_may_modify_stkvar(this, rfop, &insn);
  }

private:
  // implementation methods
  rvi_t find_chain(flow_t flow, rfop_t rfop);
  void create_initial_block(flow_t flow, rfop_t rfop);
  bool create_new_block(vref_t *res_vref, const pred_t &pred);
  bool handle_block_pred(size_t chain_num, vref_t pred_vref);
  vref_t finalize_block();

  // for create_new_block()
  bool collect_predecessors(qvector<flow_t> *pred_addrs, flow_t flow) const;
  bool analyze_linear_flow(
        qvector<flow_t> *pred_addrs,
        eavec_t *to_eas,
        ea_t initial_ea) const;
  bool merge_loop_blocks(const block_t *loop_block, sval_t delta);
  bool decode_and_emulate_insn(
        rvi_t *value,
        rfop_t *rfop,
        sval_t *delta,
        flow_t flow);
  bool is_same_func(ea_t ea) const
  {
    return cur_func != nullptr
         ? func_contains(cur_func, ea)
         : get_fchunk(ea) == nullptr;
  }

  // what to do after move handling?
  enum handle_move_res_t
  {
    HANDLED,      // the move is handled, we get a new tracked operand or
                  // we are sure that it is not spoiled
    UNSUPPORTED,  // the move does not touch the tracked operand
    SPOILED,      // a partial modification of the tracked operand is
                  // detected
  };
  // handle a move to a tracked register
  // \note the operand types should be byte/word/dword/qword.
  // \param [inout] rfop  the tracked operand
  // \param move_desc     the decription of the 'move' insn
  //                      (move_desc_t::delta is not used in this function)
  // \param insn          the move instruction
  handle_move_res_t handle_move(
        rfop_t *rfop,
        const move_desc_t &move_desc,
        const insn_t &insn);

  // for SAME the operand widths may be different
  // if it failed to calculate the stkvar offset it returns OVERLAPS
  enum overlap_res_t { SAME, OVERLAPS, DIFFERENT };
  overlap_res_t does_rfop_overlap_with_op(
        rfop_t rfop,
        const op_t &op,
        const insn_t &insn);

  // it returns success
  bool calc_stkvar_off(
        sval_t *stkoff,
        const op_t &op,
        const insn_t &insn,
        func_t *pfn);

  // to work with chains
  reg_value_ud_chain_t &get_chain(size_t chain_num);
  const reg_value_ud_chain_t &get_chain(size_t chain_num) const;
  void erase_block(size_t chain_num);
  // move addresses to the block of TO_CHAIN_NUM adjusting deltas
  void move_addrs(
        size_t from_chain_num,
        size_t to_chain_num,
        sval_t delta);
  void adjust_deltas(const qvector<addr_t> &addrs, sval_t delta);
  void trim_cache(ea_t ea, int max_cache_size);

  DECLARE_REG_FINDER_HELPERS(friend)

  // helper implementation
  void invalidate_cache_impl(ea_t to, ea_t from);
  rvi_t find_impl(flow_t flow, rfop_t rfop, int max_depth);
  rvi_t find_impl(flow_t flow, const op_t &op);
  rvi_t find_impl(flow_t flow, int reg, int max_depth = 0)
  {
    return find_impl(flow, rfop_t::make_reg(pm, reg), max_depth);
  }
  rfop_t make_rfop_impl(const op_t &op, const insn_t &insn, func_t *pfn);
  bool calc_op_addr_impl(
        rvi_t *addr,
        const op_t &memop,
        const insn_t &insn,
        flow_t flow,
        int max_depth);
  bool emulate_mem_read_impl(
        rvi_t *value,
        const rvi_t &addr,
        int width,
        bool is_signed,
        const insn_t &insn);
  void emulate_binary_op_impl(
        rvi_t *value,
        rvi_t::arith_op_t aop, // not NEG, NOT
        const op_t &op1,
        const op_t &op2,
        const insn_t &insn,
        flow_t flow,
        reg_finder_binary_ops_adjust_fun adjust = nullptr,
        void *ud = nullptr);
  void emulate_unary_op_impl(
        rvi_t *value,
        rvi_t::arith_op_t aop, // only NEG, NOT
        int reg,
        const insn_t &insn,
        flow_t flow);
  bool may_modify_stkvar_impl(rfop_t rfop, const insn_t &insn);

};

//-------------------------------------------------------------------------
// convenience functions
//-------------------------------------------------------------------------
/// Find register value using the register tracker.
/// \note The returned value is valid *before* executing the instruction.
/// \param [out] uval the found value
/// \param ea         the address to find a value at
/// \param reg        the register to find
/// \retval 0         no value (the value is varying or the find depth is
///                   not enough to find a value)
/// \retval 1         the found value is in VAL
/// \retval -1        the processor module does not support a register
///                   tracker
inline int idaapi find_reg_value(uval_t *uval, ea_t ea, int reg)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return 0;
  ssize_t code = processor_t::find_reg_value(uval, insn, reg);
  if ( code != 0 )
    return code == 1 ? 1 : 0;
  // try regfinder
  reg_finder_t *rf = processor_t::get_regfinder();
  if ( rf == nullptr )
    return -1; // not implemented
  auto rfop = reg_finder_op_t::make_reg(rf->pm, reg);
  return rf->find_const(uval, ea, rfop) ? 1 : 0;
}

//-------------------------------------------------------------------------
/// Find a value of the SP based register using the register tracker.
/// \note The returned value is valid *before* executing the instruction.
/// \param [out] sval the found value
/// \param ea         the address to find a value at
/// \param reg        the register to find.
///                   by default the SP register is used.
/// \retval 0         no value (the value is varying or the find depth is
///                   not enough to find a value)
/// \retval 1         the found value is in VAL
/// \retval -1        the processor module does not support a register
///                   tracker
inline int idaapi find_sp_value(sval_t *sval, ea_t ea, int reg = -1)
{
  reg_finder_t *rf = processor_t::get_regfinder();
  if ( rf == nullptr )
    return -1; // not implemented
  return rf->find_spd(sval, ea, reg) ? 1 : 0;
}

//-------------------------------------------------------------------------
/// Find register value using the register tracker.
/// \note The returned value is valid *before* executing the instruction.
/// \note The _undefined_ value means that there is no execution flow to EA,
/// e.g.  we try to find a value after the call of NORET function.
/// \note The _unknown_ value means that the value is:
/// \li a result of unsupported instruction, e.g. the result of a call,
/// \li a function argument,
/// \li is varying, e.g. it is a loop counter.
/// \param [out] rvi  the found value with additional attributes
/// \param ea         the address to find a value at
/// \param reg        the register to find
/// \param max_depth  the number of basic blocks to look before aborting the
///                   search and returning the unknown value.
///                   0 means the value of REGTRACK_MAX_DEPTH from ida.cfg
///                   for ordinal registers or REGTRACK_FUNC_MAX_DEPTH
///                   for the function-wide registers,
///                   -1 means the value of REGTRACK_FUNC_MAX_DEPTH from
///                   ida.cfg.
/// \retval 'false'   the processor module does not support a register
///                   tracker
/// \retval 'true'    the found value is in RVI
inline bool idaapi find_reg_value_info(
        reg_value_info_t *rvi,
        ea_t ea,
        int reg,
        int max_depth = 0)
{
  reg_finder_t *rf = processor_t::get_regfinder();
  if ( rf == nullptr )
    return false; // not implemented
  auto rfop = reg_finder_op_t::make_reg(rf->pm, reg);
  *rvi = rf->find(ea, rfop, max_depth);
  return true;
}

//-------------------------------------------------------------------------
/// Find the value of any of the two registers using the register tracker.
/// First, this function tries to find the registers in the basic block of
/// EA, and if it could not do this, then it tries to find in the entire
/// function.
/// \param [out] rvi  the found value with additional attributes
/// \param ea         the address to find a value at
/// \param reg        the registers to find
/// \return           the index of the found register or -1
inline int idaapi find_nearest_rvi(
        reg_value_info_t *rvi,
        ea_t ea,
        const int reg[2])
{
  reg_finder_t *rf = processor_t::get_regfinder();
  if ( rf == nullptr )
    return -1; // not implemented
  return rf->find_nearest(rvi, ea, reg);
}

//-------------------------------------------------------------------------
/// The control flow from FROM to TO has changed.
/// Remove from the register tracker cache all values at TO and all
/// dependent values.
/// if TO == BADADDR then clear the entire cache.
inline void idaapi invalidate_regfinder_cache(
        ea_t to = BADADDR,
        ea_t from = BADADDR)
{
  reg_finder_t *rf = processor_t::get_regfinder();
  if ( rf == nullptr )
    return;
  if ( to == BADADDR )
    rf->invalidate_cache();
  else
    rf->invalidate_cache(to, from);
}

//-------------------------------------------------------------------------
// inline methods
//-------------------------------------------------------------------------
inline void reg_value_info_t::extend(
        const procmod_t &pm,
        int width,
        bool is_signed)
{
  if ( !is_known() )
    return;
  for ( auto &p : vals )
  {
    p.val = extend_sign(p.val, width, is_signed);
    if ( !is_spd() ) // SP delta is signed
      p.val = pm.trunc_uval(p.val);
    else
      p.val = pm.ea2sval(p.val);
  }
  sort_multivals();
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::trunc_uval(const procmod_t &pm)
{
  if ( !is_num() )
    return;
  for ( auto &p : vals )
    p.val = pm.trunc_uval(p.val);
  sort_multivals();
}

//-------------------------------------------------------------------------
inline bool reg_value_info_t::perform_binary_op(
        const reg_value_info_t &r,
        arith_op_t aop,
        const insn_t &insn)
{
  const reg_value_info_t *mv;
  uval_t sv;
  if ( r.is_value_unique() )
  {
    mv = this;
    sv = r.vals.begin()->val;
  }
  else if ( is_value_unique() )
  {
    mv = &r;
    sv = vals.begin()->val;
  }
  else
  {
    return false; // both THIS and R have multiple values
  }
  uvalvec_t rvals;
  rvals.reserve(mv->vals.size());
  for ( const auto &p : mv->vals )
  {
    uval_t res = BADADDR;
    switch ( aop )
    {
      case ADD:     res = p.val + sv;  break;
      case SUB:     res = p.val - sv;  break;
      case OR:      res = p.val | sv;  break;
      case AND:     res = p.val & sv;  break;
      case XOR:     res = p.val ^ sv;  break;
      case AND_NOT: res = p.val & ~sv; break;
      case SLL:     res = p.val << sv; break;
      case SLR:     res = p.val >> sv; break;
      case MOVT:    res = (p.val & 0xFFFF) | ((sv & 0xFFFF) << 16); break;
      default: return false;
    }
    rvals.push_back(res);
  }
  set_multivals(&rvals, insn);
  return true;
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::add(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_spd() && r.is_num()   // spd + num -> spd
    || is_num() && r.is_spd()   // num + spd -> spd
    || is_num() && r.is_num() ) // num + num -> num
  {
    if ( perform_binary_op(r, ADD, insn) )
    {
      if ( is_spd() || r.is_spd() )
        state = SPDINSN;
      return;
    }
  }
  // spd + spd or unknown or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::sub(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_spd() && r.is_num()   // spd - num -> spd
    || is_spd() && r.is_spd()   // spd - spd -> num
    || is_num() && r.is_num() ) // num - num -> num
  {
    if ( perform_binary_op(r, SUB, insn) )
    {
      if ( is_spd() )
        state = r.is_spd() ? NUMINSN : SPDINSN;
      return;
    }
  }
  // num - spd or unknown or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::bor(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_num() && r.is_num() )
    if ( perform_binary_op(r, OR, insn) )
      return;
  // not numbers or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::band(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  uval_t mask;
  if ( is_spd() && r.get_num(&mask) && is_pow2(mask + 1) && mask <= 31 )
  {
    if ( perform_binary_op(r, AND, insn) )
    {
      state = NUMINSN;
      return;
    }
  }
  if ( is_num() && r.is_num() )
  {
    if ( perform_binary_op(r, AND, insn) )
      return;
  }
  // not numbers or not mask of SPD or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::bxor(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_num() && r.is_num() )
    if ( perform_binary_op(r, XOR, insn) )
      return;
  // not numbers or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::bandnot(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  uval_t mask;
  if ( is_spd() && r.get_num(&mask) && is_pow2(mask + 1) && mask <= 31 )
    if ( perform_binary_op(r, AND_NOT, insn) )
      return;
  if ( is_num() && r.is_num() )
    if ( perform_binary_op(r, AND_NOT, insn) )
      return;
  // not numbers or not SPD aligning or both THIS and R have multiple values
  set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::sll(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_num() && r.is_num() && perform_binary_op(r, SLL, insn) )
    ;
  else // not numbers
    set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::slr(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_num() && r.is_num() && perform_binary_op(r, SLR, insn) )
    ;
  else // not numbers
    set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::movt(
        const reg_value_info_t &r,
        const insn_t &insn)
{
  if ( is_num() && r.is_num() && perform_binary_op(r, MOVT, insn) )
    ;
  else // not numbers
    set_unkinsn(insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::neg(const insn_t &insn)
{
  if ( is_num() )
  {
    uvalvec_t rvals;
    rvals.reserve(vals.size());
    for ( auto &p : vals )
      rvals.push_back(0-p.val);
    set_multivals(&rvals, insn);
  }
  else // not a number
  {
    set_unkinsn(insn);
  }
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::bnot(const insn_t &insn)
{
  if ( is_num() )
  {
    uvalvec_t rvals;
    rvals.reserve(vals.size());
    for ( auto &p : vals )
      rvals.push_back(~p.val);
    set_multivals(&rvals, insn);
  }
  else // not a number
  {
    set_unkinsn(insn);
  }
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::add_num(uval_t r, const insn_t &insn)
{
  if ( !is_known() || r == 0 )
    return;
  uvalvec_t rvals;
  rvals.reserve(vals.size());
  for ( auto &p : vals )
    rvals.push_back(p.val + r);
  set_multivals(&rvals, insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::add_num(uval_t r)
{
  if ( !is_known() || r == 0 )
    return;
  for ( auto &p : vals )
    p.val += r;
  sort_multivals();
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::shift_left(uval_t r)
{
  if ( !is_known() || r == 0 )
    return;
  for ( auto &p : vals )
    p.val <<= r;
  sort_multivals();
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::shift_right(uval_t r)
{
  if ( !is_known() || r == 0 )
    return;
  for ( auto &p : vals )
    p.val >>= r;
  sort_multivals();
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::set_multivals(
        uvalvec_t *rvals,
        const insn_t &insn)
{
  // DEF_EA will be the same so it is enough to sort only VAL
  std::sort(rvals->begin(), rvals->end());
  size_t newsz = std::unique(rvals->begin(), rvals->end()) - rvals->begin();
  vals.resize(newsz);
  for ( size_t i = 0; i < newsz; ++i )
    vals[i] = val_def_t(rvals->at(i), insn);
}

//-------------------------------------------------------------------------
inline void reg_value_info_t::sort_multivals()
{
  // at this point we use reg_value_def_t::operator<()
  std::sort(vals.begin(), vals.end());
  // at this point we use reg_value_def_t::operator==()
  size_t new_size = std::unique(vals.begin(), vals.end()) - vals.begin();
  vals.resize(new_size);
}

//-------------------------------------------------------------------------
inline reg_finder_op_t reg_finder_op_t::make_reg(int reg, int width)
{
  uint32 packed_width = pack_width(width);
  if ( packed_width == BADREG || !is_valid_reg(reg) )
    return rfop_t();
  return rfop_t(REG | packed_width | uint16(reg));
}

//-------------------------------------------------------------------------
inline reg_finder_op_t reg_finder_op_t::make_stkoff(
        sval_t stkoff,
        int width)
{
  uint32 packed_width = pack_width(width);
  if ( packed_width == BADREG || !is_valid_stkoff(stkoff) )
    return rfop_t();
  bool negative = stkoff < 0;
  return rfop_t(STKVAR
              | packed_width
              | (negative ? STKOFF_SIGNBIT : 0)
              | uint32(negative ? -stkoff : stkoff));
}

//-------------------------------------------------------------------------
inline void reg_finder_op_t::set_width(int width)
{
  uint32 packed_width = pack_width(width);
  if ( packed_width == BADREG )
  {
    clear();
    return;
  }
  packed &= ~WIDTH_MASK;
  packed |= packed_width;
}

//-------------------------------------------------------------------------
inline void reg_finder_op_t::set_signness(bool is_signed)
{
  packed &= ~SIGNED;
  if ( is_signed )
    packed |= SIGNED;
}

//-------------------------------------------------------------------------
inline void reg_finder_op_t::set_width_signness(int width, bool is_signed)
{
  uint32 packed_width = pack_width(width);
  if ( packed_width == BADREG )
  {
    clear();
    return;
  }
  packed &= ~WIDTH_MASK;
  packed |= packed_width;
  packed &= ~SIGNED;
  if ( is_signed )
    packed |= SIGNED;
}

//-------------------------------------------------------------------------
inline uint32 reg_finder_op_t::pack_width(int width)
{
  switch ( width )
  {
    case 1: return 0 << WIDTH_SHIFT; break;
    case 2: return 1 << WIDTH_SHIFT; break;
    case 4: return 2 << WIDTH_SHIFT; break;
    case 8: return 3 << WIDTH_SHIFT; break;
    default: return BADREG;
  }
}

//-------------------------------------------------------------------------
inline int reg_finder_op_t::get_op_width(const op_t &op)
{
  switch ( op.dtype )
  {
    case dt_byte:   return 1;
    case dt_word:   return 2;
    case dt_dword:
    case dt_float:  return 4;
    case dt_qword:
    case dt_double: return 8;
    case dt_byte16: return 16;
    default:        return 0;
  }
}
