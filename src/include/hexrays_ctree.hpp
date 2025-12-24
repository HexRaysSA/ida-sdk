#pragma once
#include <hexrays_defs.hpp>

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif
void hexapi remitem(const citem_t *e);
//-------------------------------------------------------------------------
/// Ctree item code. At the beginning of this list there are expression
/// codes (cot_...), followed by statement codes (cit_...).
enum ctype_t
{
  cot_empty    = 0,
  cot_comma    = 1,   ///< x, y
  cot_asg      = 2,   ///< x = y
  cot_asgbor   = 3,   ///< x |= y
  cot_asgxor   = 4,   ///< x ^= y
  cot_asgband  = 5,   ///< x &= y
  cot_asgadd   = 6,   ///< x += y
  cot_asgsub   = 7,   ///< x -= y
  cot_asgmul   = 8,   ///< x *= y
  cot_asgsshr  = 9,   ///< x >>= y signed
  cot_asgushr  = 10,  ///< x >>= y unsigned
  cot_asgshl   = 11,  ///< x <<= y
  cot_asgsdiv  = 12,  ///< x /= y signed
  cot_asgudiv  = 13,  ///< x /= y unsigned
  cot_asgsmod  = 14,  ///< x %= y signed
  cot_asgumod  = 15,  ///< x %= y unsigned
  cot_tern     = 16,  ///< x ? y : z
  cot_lor      = 17,  ///< x || y
  cot_land     = 18,  ///< x && y
  cot_bor      = 19,  ///< x | y
  cot_xor      = 20,  ///< x ^ y
  cot_band     = 21,  ///< x & y
  cot_eq       = 22,  ///< x == y int or fpu (see EXFL_FPOP)
  cot_ne       = 23,  ///< x != y int or fpu (see EXFL_FPOP)
  cot_sge      = 24,  ///< x >= y signed or fpu (see EXFL_FPOP)
  cot_uge      = 25,  ///< x >= y unsigned
  cot_sle      = 26,  ///< x <= y signed or fpu (see EXFL_FPOP)
  cot_ule      = 27,  ///< x <= y unsigned
  cot_sgt      = 28,  ///< x >  y signed or fpu (see EXFL_FPOP)
  cot_ugt      = 29,  ///< x >  y unsigned
  cot_slt      = 30,  ///< x <  y signed or fpu (see EXFL_FPOP)
  cot_ult      = 31,  ///< x <  y unsigned
  cot_sshr     = 32,  ///< x >> y signed
  cot_ushr     = 33,  ///< x >> y unsigned
  cot_shl      = 34,  ///< x << y
  cot_add      = 35,  ///< x + y
  cot_sub      = 36,  ///< x - y
  cot_mul      = 37,  ///< x * y
  cot_sdiv     = 38,  ///< x / y signed
  cot_udiv     = 39,  ///< x / y unsigned
  cot_smod     = 40,  ///< x % y signed
  cot_umod     = 41,  ///< x % y unsigned
  cot_fadd     = 42,  ///< x + y fp
  cot_fsub     = 43,  ///< x - y fp
  cot_fmul     = 44,  ///< x * y fp
  cot_fdiv     = 45,  ///< x / y fp
  cot_fneg     = 46,  ///< -x fp
  cot_neg      = 47,  ///< -x
  cot_cast     = 48,  ///< (type)x
  cot_lnot     = 49,  ///< !x
  cot_bnot     = 50,  ///< ~x
  cot_ptr      = 51,  ///< *x, access size in 'ptrsize'
  cot_ref      = 52,  ///< &x
  cot_postinc  = 53,  ///< x++
  cot_postdec  = 54,  ///< x--
  cot_preinc   = 55,  ///< ++x
  cot_predec   = 56,  ///< --x
  cot_call     = 57,  ///< x(...)
  cot_idx      = 58,  ///< x[y]
  cot_memref   = 59,  ///< x.m
  cot_memptr   = 60,  ///< x->m, access size in 'ptrsize'
  cot_num      = 61,  ///< n
  cot_fnum     = 62,  ///< fpc
  cot_str      = 63,  ///< string constant (user representation)
  cot_obj      = 64,  ///< obj_ea
  cot_var      = 65,  ///< v
  cot_insn     = 66,  ///< instruction in expression, internal representation only
  cot_sizeof   = 67,  ///< sizeof(x)
  cot_helper   = 68,  ///< arbitrary name
  cot_type     = 69,  ///< arbitrary type
  cot_last     = cot_type,
  cit_empty    = 70,  ///< instruction types start here
  cit_block    = 71,  ///< block-statement: { ... }
  cit_expr     = 72,  ///< expression-statement: expr;
  cit_if       = 73,  ///< if-statement
  cit_for      = 74,  ///< for-statement
  cit_while    = 75,  ///< while-statement
  cit_do       = 76,  ///< do-statement
  cit_switch   = 77,  ///< switch-statement
  cit_break    = 78,  ///< break-statement
  cit_continue = 79,  ///< continue-statement
  cit_return   = 80,  ///< return-statement
  cit_goto     = 81,  ///< goto-statement
  cit_asm      = 82,  ///< asm-statement
  cit_try      = 83,  ///< C++ try-statement
  cit_throw    = 84,  ///< C++ throw-statement
  cit_end
};

/// Negate a comparison operator. For example, \ref cot_sge becomes \ref cot_slt
ctype_t hexapi negated_relation(ctype_t op);
/// Swap a comparison operator. For example, \ref cot_sge becomes \ref cot_sle
ctype_t hexapi swapped_relation(ctype_t op);
/// Get operator sign. Meaningful for sign-dependent operators, like \ref cot_sdiv
type_sign_t hexapi get_op_signness(ctype_t op);
/// Convert plain operator into assignment operator. For example, \ref cot_add returns \ref cot_asgadd
ctype_t hexapi asgop(ctype_t cop);
/// Convert assignment operator into plain operator. For example, \ref cot_asgadd returns \ref cot_add
/// \return cot_empty is the input operator is not an assignment operator.
ctype_t hexapi asgop_revert(ctype_t cop);
/// Does operator use the 'x' field of cexpr_t?
inline bool op_uses_x(ctype_t op) { return (op >= cot_comma && op <= cot_memptr) || op == cot_sizeof; }
/// Does operator use the 'y' field of cexpr_t?
inline bool op_uses_y(ctype_t op) { return (op >= cot_comma && op <= cot_fdiv) || op == cot_idx; }
/// Does operator use the 'z' field of cexpr_t?
inline bool op_uses_z(ctype_t op) { return op == cot_tern; }
/// Is binary operator?
inline bool is_binary(ctype_t op) { return op_uses_y(op) && op != cot_tern; } // x,y
/// Is unary operator?
inline bool is_unary(ctype_t op) { return op >= cot_fneg && op <= cot_predec; }
/// Is comparison operator?
inline bool is_relational(ctype_t op) { return op >= cot_eq && op <= cot_ult; }
/// Is assignment operator?
inline bool is_assignment(ctype_t op) { return op >= cot_asg && op <= cot_asgumod; }
// Can operate on UDTs?
inline bool accepts_udts(ctype_t op) { return op == cot_asg || op == cot_comma || op > cot_last; }
/// Is pre/post increment/decrement operator?
inline bool is_prepost(ctype_t op)    { return op >= cot_postinc && op <= cot_predec; }
/// Is commutative operator?
inline bool is_commutative(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_add
      || op == cot_mul
      || op == cot_fadd
      || op == cot_fmul
      || op == cot_ne
      || op == cot_eq;
}
/// Is additive operator?
inline bool is_additive(ctype_t op)
{
  return op == cot_add
      || op == cot_sub
      || op == cot_fadd
      || op == cot_fsub;
}
/// Is multiplicative operator?
inline bool is_multiplicative(ctype_t op)
{
  return op == cot_mul
      || op == cot_sdiv
      || op == cot_udiv
      || op == cot_fmul
      || op == cot_fdiv;
}

/// Is bit related operator?
inline bool is_bitop(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_bnot;
}

/// Is logical operator?
inline bool is_logical(ctype_t op)
{
  return op == cot_lor
      || op == cot_land
      || op == cot_lnot;
}

/// Is loop statement code?
inline bool is_loop(ctype_t op)
{
  return op == cit_for
      || op == cit_while
      || op == cit_do;
}
/// Does a break statement influence the specified statement code?
inline bool is_break_consumer(ctype_t op)
{
  return is_loop(op) || op == cit_switch;
}

/// Is Lvalue operator?
inline bool is_lvalue(ctype_t op)
{
  return op == cot_ptr      // *x
      || op == cot_idx      // x[y]
      || op == cot_memref   // x.m
      || op == cot_memptr   // x->m
      || op == cot_obj      // v
      || op == cot_var;     // l
}

/// Is the operator allowed on small structure or union?
inline bool accepts_small_udts(ctype_t op)
{
  return op == cot_asg
      || op == cot_eq
      || op == cot_ne
      || op == cot_comma
      || op == cot_tern
      || (op > cot_last && op < cit_end); // any insn
}

/// An immediate number
struct cnumber_t
{
  uint64 _value = 0;            ///< its value
  number_format_t nf;           ///< how to represent it
  cnumber_t(int _opnum=0) : nf(_opnum) {}

  /// Get text representation
  /// \param vout output buffer
  /// \param type number type
  /// \param parent parent expression
  /// \param nice_stroff out: printed as stroff expression
  void hexapi print(
        qstring *vout,
        const tinfo_t &type,
        const citem_t *parent=nullptr,
        bool *nice_stroff=nullptr) const;

  /// Get value.
  /// This function will properly extend the number sign to 64bits
  /// depending on the type sign.
  uint64 hexapi value(const tinfo_t &type) const;

  /// Assign new value
  /// \param v new value
  /// \param nbytes size of the new value in bytes
  /// \param sign sign of the value
  void hexapi assign(uint64 v, int nbytes, type_sign_t sign);

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(cnumber_t);
};

/// Reference to a local variable
struct var_ref_t
{
  mba_t *mba;           ///< pointer to the underlying micro array
  int idx;              ///< index into lvars_t
  lvar_t &getv() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(var_ref_t);
};

/// Vector of parents
typedef qvector<citem_t *> citem_pointers_t;
typedef citem_pointers_t parents_t;

/// Ctree maturity level. The level will increase
/// as we switch from one phase of ctree generation to the next one
enum ctree_maturity_t
{
  CMAT_ZERO,            ///< does not exist
  CMAT_BUILT,           ///< just generated
  CMAT_TRANS1,          ///< applied first wave of transformations
  CMAT_NICE,            ///< nicefied expressions
  CMAT_TRANS2,          ///< applied second wave of transformations
  CMAT_CPA,             ///< corrected pointer arithmetic
  CMAT_TRANS3,          ///< applied third wave of transformations
  CMAT_CASTED,          ///< added necessary casts
  CMAT_FINAL,           ///< ready-to-use
};

//--------------------------------------------------------------------------
/// Comment item preciser.
/// Item preciser is used to assign comments to ctree items
/// A ctree item may have several comments attached to it. For example,
/// an if-statement may have the following comments: <pre>
///  if ( ... )    // cmt1
///  {             // cmt2
///  }             // cmt3
///  else          // cmt4
///  {                     -- usually the else block has a separate ea
///  } </pre>
/// The first 4 comments will have the same ea. In order to denote the exact
/// line for the comment, we store the item_preciser along with ea.
enum item_preciser_t
{
  // inner comments (comments within an expression)
  ITP_EMPTY,    ///< nothing
  ITP_ARG1,     ///< , (64 entries are reserved for 64 call arguments)
  ITP_ARG64 = ITP_ARG1+63, // ,
  ITP_BRACE1,   // (
  ITP_INNER_LAST = ITP_BRACE1,
  // outer comments
  ITP_ASM,      ///< __asm-line
  ITP_ELSE,     ///< else-line
  ITP_DO,       ///< do-line
  ITP_SEMI,     ///< semicolon
  ITP_CURLY1,   ///< {
  ITP_CURLY2,   ///< }
  ITP_BRACE2,   ///< )
  ITP_COLON,    ///< : (label)
  ITP_BLOCK1,   ///< opening block comment. this comment is printed before the item
                ///< (other comments are indented and printed after the item)
  ITP_BLOCK2,   ///< closing block comment.
  ITP_TRY,      ///< C++ try statement
  ITP_CASE = 0x40000000, ///< bit for switch cases
  ITP_SIGN = 0x20000000, ///< if this bit is set too, then we have a negative case value
                         // this is a hack, we better introduce special indexes for case values
                         // case value >= ITP_CASE will be processed incorrectly
};
/// Ctree location. Used to denote comment locations.
struct treeloc_t
{
  ea_t ea;
  item_preciser_t itp;
  bool operator < (const treeloc_t &r) const
  {
    return ea < r.ea
        || (ea == r.ea && itp < r.itp);
  }
  bool operator == (const treeloc_t &r) const
  {
    return ea == r.ea && itp == r.itp;
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Comment retrieval type.
/// Ctree remembers what comments have already been retrieved.
/// This is done because our mechanism of item_precisers is still
/// not perfect and in theory some listing lines cannot be told
/// apart. To avoid comment duplication, we remember if a comment
/// has already been used or not.
enum cmt_retrieval_type_t
{
  RETRIEVE_ONCE,        ///< Retrieve comment if it has not been used yet
  RETRIEVE_ALWAYS,      ///< Retrieve comment even if it has been used
};

/// Ctree item comment.
/// For each comment we remember its body and the fact of its retrieval
struct citem_cmt_t : public qstring
{
  mutable bool used = false; ///< the comment has been retrieved?
  citem_cmt_t() {}
  citem_cmt_t(const char *s) : qstring(s) {}
};

// Comments are attached to tree locations:
typedef qmap<treeloc_t, citem_cmt_t> user_cmts_t;

/// Generic ctree item locator. It can be used for instructions and some expression
/// types. However, we need more precise locators for other items (e.g. for numbers)
struct citem_locator_t
{
  ea_t ea;              ///< citem address
  ctype_t op;           ///< citem operation
  citem_locator_t() = delete;
public:
  citem_locator_t(ea_t _ea, ctype_t _op) : ea(_ea), op(_op) {}
  citem_locator_t(const citem_t *i);
  DECLARE_COMPARISONS(citem_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

// citem_t::iflags are attached to (ea,op) pairs
typedef qmap<citem_locator_t, int32> user_iflags_t;

// union field selections
// they are represented as a vector of integers. each integer represents the
// number of union field (0 means the first union field, etc)
// the size of this vector is equal to the number of nested unions in the selection.
typedef qmap<ea_t, intvec_t> user_unions_t;

//--------------------------------------------------------------------------
struct bit_bound_t
{
  int16 nbits; // total number of non-zero bits. we cannot guarantee that
               // they are zero. example: a random "int var" has nbits==32
  int16 sbits; // number of sign bits (they can be either 0 or 1, all of them)
               // if bits are known to be zeroes, they are not taken into account here
               // (in this case nbits should be reduced)
               // if bits are unknown and can be anything, they cannot be included
               // in sbits.
               // sbits==1 is a special case and should not be used
  bit_bound_t(int n=0, int s=0) : nbits(n), sbits(s) {}
};

//--------------------------------------------------------------------------
/// Basic ctree item. This is an abstract class (but we don't use virtual
/// functions in ctree, so the compiler will not disallow you to create citem_t
/// instances). However, items of pure citem_t type must never be created.
/// Two classes, cexpr_t and cinsn_t are derived from it.
struct citem_t
{
  ea_t ea = BADADDR;      ///< address that corresponds to the item. may be BADADDR
  ctype_t op;             ///< item type
  int label_num = -1;     ///< label number. -1 means no label. items of the expression
                          ///< types (cot_...) should not have labels at the final maturity
                          ///< level, but at the intermediate levels any ctree item
                          ///< may have a label. Labels must be unique. Usually
                          ///< they correspond to the basic block numbers.
  mutable int index = -1; ///< an index in cfunc_t::treeitems.
                          ///< meaningful only after print_func()
  citem_t(ctype_t o=cot_empty) : op(o) {}
  /// Swap two citem_t
  void swap(citem_t &r)
  {
    std::swap(ea, r.ea);
    std::swap(op, r.op);
    std::swap(label_num, r.label_num);
  }
  /// Is an expression?
  bool is_expr() const { return op <= cot_last; }
  /// Does the item contain an expression?
  bool hexapi contains_expr(const cexpr_t *e) const;
  /// Does the item contain a label?
  bool hexapi contains_label() const;
  /// Find parent of the specified item.
  /// \param item Item to find the parent of. The search will be performed
  ///            among the children of the item pointed by \c this.
  /// \return nullptr if not found
  const citem_t *hexapi find_parent_of(const citem_t *item) const;
  citem_t *find_parent_of(const citem_t *item)
  { return CONST_CAST(citem_t*)((CONST_CAST(const citem_t*)(this))->find_parent_of(item)); }
  citem_t *hexapi find_closest_addr(ea_t _ea);
  void print1(qstring *vout, const cfunc_t *func) const;
  ~citem_t()
  {
    remitem(this);
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(citem_t);

/// Ctree item: expression.
/// Depending on the exact expression item type, various fields of this structure are used.
struct cexpr_t : public citem_t
{
  union
  {
    cnumber_t *n;     ///< used for \ref cot_num
    fnumber_t *fpc;   ///< used for \ref cot_fnum
    struct
    {
      union
      {
        var_ref_t v;  ///< used for \ref cot_var
        ea_t obj_ea;  ///< used for \ref cot_obj
      };
      int refwidth;   ///< how many bytes are accessed? (-1: none)
    };
    struct
    {
      cexpr_t *x;     ///< the first operand of the expression
      union
      {
        cexpr_t *y;   ///< the second operand of the expression
        carglist_t *a;///< argument list (used for \ref cot_call)
        uint32 m;     ///< member offset (used for \ref cot_memptr, \ref cot_memref)
                      ///< for unions, the member number
      };
      union
      {
        cexpr_t *z;   ///< the third operand of the expression
        int ptrsize;  ///< memory access size (used for \ref cot_ptr, \ref cot_memptr)
      };
    };
    cinsn_t *insn;    ///< an embedded statement, they are prohibited
                      ///< at the final maturity stage (\ref CMAT_FINAL)
    char *helper;     ///< helper name (used for \ref cot_helper)
    char *string;     ///< utf8 string constant, user representation (used for \ref cot_str)
  };
  tinfo_t type;       ///< expression type. must be carefully maintained
  uint32 exflags = 0; ///< \ref EXFL_
/// \defgroup EXFL_ Expression attributes
/// Used in cexpr_t::exflags
///@{
#define EXFL_CPADONE 0x0001 ///< pointer arithmetic correction done
#define EXFL_LVALUE  0x0002 ///< expression is lvalue even if it doesn't look like it
#define EXFL_FPOP    0x0004 ///< floating point operation
#define EXFL_ALONE   0x0008 ///< standalone helper
#define EXFL_CSTR    0x0010 ///< string literal
#define EXFL_PARTIAL 0x0020 ///< type of the expression is considered partial
#define EXFL_UNDEF   0x0040 ///< expression uses undefined value
#define EXFL_JUMPOUT 0x0080 ///< jump out-of-function
#define EXFL_VFTABLE 0x0100 ///< is ptr to vftable (used for \ref cot_memptr, \ref cot_memref)
#define EXFL_ALL     0x01FF ///< all currently defined bits
///@}
  /// Pointer arithmetic correction done for this expression?
  bool cpadone() const         { return (exflags & EXFL_CPADONE) != 0; }
  bool is_odd_lvalue() const   { return (exflags & EXFL_LVALUE) != 0; }
  bool is_fpop() const         { return (exflags & EXFL_FPOP) != 0; }
  bool is_cstr() const         { return (exflags & EXFL_CSTR) != 0; }
  bool is_type_partial() const { return (exflags & EXFL_PARTIAL) != 0; }
  bool is_undef_val() const    { return (exflags & EXFL_UNDEF) != 0; }
  bool is_jumpout() const      { return (exflags & EXFL_JUMPOUT) != 0; }
  bool is_vftable() const      { return (exflags & EXFL_VFTABLE) != 0; }


  void set_cpadone()      { exflags |= EXFL_CPADONE; }
  void set_vftable()      { exflags |= EXFL_VFTABLE; }
  void set_type_partial(bool val = true)
  {
    if ( val )
      exflags |= EXFL_PARTIAL;
    else
      exflags &= ~EXFL_PARTIAL;
  }

  cexpr_t() : x(nullptr), y(nullptr), z(nullptr) {}
  cexpr_t(ctype_t cexpr_op, cexpr_t *_x, cexpr_t *_y=nullptr, cexpr_t *_z=nullptr)
    : citem_t(cexpr_op), x(_x), y(_y), z(_z) {}
  cexpr_t(mba_t *mba, const lvar_t &v);
  cexpr_t(const cexpr_t &r) : citem_t() { *this = r; }
  void swap(cexpr_t &r)
  {
    citem_t &ci = *this;
    ci.swap(r);
    std::swap(x, r.x);
    std::swap(y, r.y);
    std::swap(z, r.z);
    type.swap(r.type);
    std::swap(exflags, r.exflags);
  }
  cexpr_t &operator=(const cexpr_t &r) { return assign(r); }
  cexpr_t &hexapi assign(const cexpr_t &r);
  DECLARE_COMPARISONS(cexpr_t);
  ~cexpr_t() { cleanup(); }

  /// Replace the expression.
  /// The children of the expression are abandoned (not freed).
  /// The expression pointed by 'r' is moved to 'this' expression
  /// \param r the source expression. It is deleted after being copied
  void hexapi replace_by(cexpr_t *r);

  /// Cleanup the expression.
  /// This function properly deletes all children and sets the item type to cot_empty.
  void hexapi cleanup();

  /// Assign a number to the expression.
  /// \param func current function
  /// \param value number value
  /// \param nbytes size of the number in bytes
  /// \param sign number sign
  void hexapi put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign=no_sign);

  /// Print expression into one line.
  /// \param vout output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  void hexapi print1(qstring *vout, const cfunc_t *func) const;

  /// Calculate the type of the expression.
  /// Use this function to calculate the expression type when a new expression is built
  /// \param recursive if true, types of all children expression will be calculated
  ///                  before calculating our type
  void hexapi calc_type(bool recursive);

  /// Compare two expressions.
  /// This function tries to compare two expressions in an 'intelligent' manner.
  /// For example, it knows about commutitive operators and can ignore useless casts.
  /// \param r the expression to compare against the current expression
  /// \return true expressions can be considered equal
  bool hexapi equal_effect(const cexpr_t &r) const;

  /// Verify if the specified item is our parent.
  /// \param parent possible parent item
  /// \return true if the specified item is our parent
  bool hexapi is_child_of(const citem_t *parent) const;

  /// Check if the expression contains the specified operator.
  /// \param needed_op operator code to search for
  /// \param times how many times the operator code should be present
  /// \return true if the expression has at least TIMES children with NEEDED_OP
  bool hexapi contains_operator(ctype_t needed_op, int times=1) const;

  /// Does the expression contain a comma operator?
  bool contains_comma(int times=1) const { return contains_operator(cot_comma, times); }
  /// Does the expression contain an embedded statement operator?
  bool contains_insn(int times=1) const { return contains_operator(cot_insn, times); }
  /// Does the expression contain an embedded statement operator or a label?
  bool contains_insn_or_label() const { return contains_insn() || contains_label(); }
  /// Does the expression contain a comma operator or an embedded statement operator or a label?
  bool contains_comma_or_insn_or_label(int maxcommas=1) const { return contains_comma(maxcommas) || contains_insn_or_label(); }
  /// Is nice expression?
  /// Nice expressions do not contain comma operators, embedded statements, or labels.
  bool is_nice_expr() const { return !contains_comma_or_insn_or_label(); }
  /// Is nice condition?.
  /// Nice condition is a nice expression of the boolean type.
  bool is_nice_cond() const { return is_nice_expr() && type.is_bool(); }
  /// Is call object?
  /// \return true if our expression is the call object of the specified parent expression.
  bool is_call_object_of(const citem_t *parent) const { return parent != nullptr && parent->op == cot_call && ((cexpr_t*)parent)->x == this; }
  /// Is call argument?
  /// \return true if our expression is a call argument of the specified parent expression.
  bool is_call_arg_of(const citem_t *parent) const { return parent != nullptr && parent->op == cot_call && ((cexpr_t*)parent)->x != this; }
  /// Get expression sign
  type_sign_t get_type_sign() const { return type.get_sign(); }
  /// Is expression unsigned?
  bool is_type_unsigned() const { return type.is_unsigned(); }
  /// Is expression signed?
  bool is_type_signed() const { return type.is_signed(); }
  /// Get max number of bits that can really be used by the expression.
  /// For example, x % 16 can yield only 4 non-zero bits, higher bits are zero
  bit_bound_t hexapi get_high_nbit_bound() const;
  /// Get min number of bits that are certainly required to represent the expression.
  /// For example, constant 16 always uses 5 bits: 10000.
  int hexapi get_low_nbit_bound() const;
  /// Check if the expression requires an lvalue.
  /// \param child The function will check if this child of our expression must be an lvalue.
  /// \return true if child must be an lvalue.
  bool hexapi requires_lvalue(const cexpr_t *child) const;
  /// Check if the expression has side effects.
  /// Calls, pre/post inc/dec, and assignments have side effects.
  bool hexapi has_side_effects() const;
  /// Does the expression look like a boolean expression?
  /// In other words, its possible values are only 0 and 1.
  bool like_boolean() const;
  /// Check if the expression if aliasable.
  /// Simple registers and non-aliasble stack slots return false.
  bool is_aliasable() const;
  /// Get numeric value of the expression.
  /// This function can be called only on cot_num expressions!
  uint64 numval() const
  {
    QASSERT(50071, op == cot_num);
    return n->value(type);
  }
  /// Check if the expression is a number with the specified value.
  bool is_const_value(uint64 _v) const
  {
    return op == cot_num && numval() == _v;
  }
  /// Check if the expression is a negative number.
  bool is_negative_const() const
  {
    return op == cot_num && int64(numval()) < 0;
  }
  /// Check if the expression is a non-negative number.
  bool is_non_negative_const() const
  {
    return op == cot_num && int64(numval()) >= 0;
  }
  /// Check if the expression is a non-zero number.
  bool is_non_zero_const() const
  {
    return op == cot_num && numval() != 0;
  }
  /// Check if the expression is a zero.
  bool is_zero_const() const { return is_const_value(0); }
  /// Does the PARENT need the expression value
  bool is_value_used(const citem_t *parent) const;
  /// Get expression value.
  /// \param out Pointer to the variable where the expression value is returned.
  /// \return true if the expression is a number.
  bool get_const_value(uint64 *out) const
  {
    if ( op == cot_num )
    {
      if ( out != nullptr )
        *out = numval();
      return true;
    }
    return false;
  }
  /// May the expression be a pointer?
  bool hexapi maybe_ptr() const;

  /// Find pointer or array child.
  cexpr_t *get_ptr_or_array()
  {
    if ( x->type.is_ptr_or_array() )
      return x;
    if ( y->type.is_ptr_or_array() )
      return y;
    return nullptr;
  }
  /// Find the child with the specified operator.
  const cexpr_t *find_op(ctype_t _op) const
  {
    if ( x->op == _op )
      return x;
    if ( y->op == _op )
      return y;
    return nullptr;
  }
  cexpr_t *find_op(ctype_t _op)
  {
    return (cexpr_t *)((const cexpr_t *)this)->find_op(_op);
  }

  /// Find the operand with a numeric value
  const cexpr_t *find_num_op() const { return find_op(cot_num); }
        cexpr_t *find_num_op()       { return find_op(cot_num); }
  /// Find the pointer operand.
  /// This function returns the pointer operand for binary expressions.
  const cexpr_t *find_ptr_or_array(bool remove_eqsize_casts) const;
  /// Get the other operand.
  /// This function returns the other operand (not the specified one)
  /// for binary expressions.
  const cexpr_t *theother(const cexpr_t *what) const { return what == x ? y : x; }
        cexpr_t *theother(const cexpr_t *what)       { return what == x ? y : x; }

  // these are inline functions, see below
  bool get_1num_op(cexpr_t **o1, cexpr_t **o2);
  bool get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const;

  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(cexpr_t);

/// Statement with an expression.
/// This is a base class for various statements with expressions.
struct ceinsn_t
{
  cexpr_t expr;         ///< Expression of the statement
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(ceinsn_t);

/// Should curly braces be printed?
enum use_curly_t
{
  CALC_CURLY_BRACES,    ///< print curly braces if necessary
  NO_CURLY_BRACES,      ///< don't print curly braces
  USE_CURLY_BRACES,     ///< print curly braces without any checks
};

/// If statement
struct cif_t : public ceinsn_t
{
  cinsn_t *ithen = nullptr; ///< Then-branch of the if-statement
  cinsn_t *ielse = nullptr; ///< Else-branch of the if-statement. May be nullptr.
  cif_t() {}
  cif_t(const cif_t &r) : ceinsn_t(), ithen(nullptr), ielse(nullptr) { *this = r; }
  cif_t &operator=(const cif_t &r) { return assign(r); }
  cif_t &hexapi assign(const cif_t &r);
  DECLARE_COMPARISONS(cif_t);
  ~cif_t() { cleanup(); }
  void cleanup();
};

/// Base class for loop statements
struct cloop_t : public ceinsn_t
{
  cinsn_t *body = nullptr;
  cloop_t(cinsn_t *b=nullptr) : body(b) {}
  cloop_t(const cloop_t &r) : ceinsn_t() { *this = r; }
  cloop_t &operator=(const cloop_t &r) { return assign(r); }
  cloop_t &hexapi assign(const cloop_t &r);
  ~cloop_t() { cleanup(); }
  void cleanup();
};

/// For-loop
struct cfor_t : public cloop_t
{
  cexpr_t init;                 ///< Initialization expression
  cexpr_t step;                 ///< Step expression
  DECLARE_COMPARISONS(cfor_t);
};

/// While-loop
struct cwhile_t : public cloop_t
{
  DECLARE_COMPARISONS(cwhile_t);
};

/// Do-loop
struct cdo_t : public cloop_t
{
  DECLARE_COMPARISONS(cdo_t);
};

/// Return statement
struct creturn_t : public ceinsn_t
{
  DECLARE_COMPARISONS(creturn_t);
};

/// Goto statement
struct cgoto_t
{
  int label_num;        ///< Target label number
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
  DECLARE_COMPARISONS(cgoto_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// asm statement
struct casm_t : public eavec_t
{
  casm_t(ea_t ea) { push_back(ea); }
  casm_t(const casm_t &r) : eavec_t(eavec_t(r)) {}
  DECLARE_COMPARISONS(casm_t);
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
  bool one_insn() const { return size() == 1; }
  void genasm(qstring *buf, ea_t ea) const;
};

/// Vector of pointers to statements.
typedef qvector<cinsn_t *> cinsnptrvec_t;

/// Ctree item: statement.
/// Depending on the exact statement type, various fields of the union are used.
struct cinsn_t : public citem_t
{
  union
  {
    cblock_t *cblock;   ///< details of block-statement
    cexpr_t *cexpr;     ///< details of expression-statement
    cif_t *cif;         ///< details of if-statement
    cfor_t *cfor;       ///< details of for-statement
    cwhile_t *cwhile;   ///< details of while-statement
    cdo_t *cdo;         ///< details of do-statement
    cswitch_t *cswitch; ///< details of switch-statement
    creturn_t *creturn; ///< details of return-statement
    cgoto_t *cgoto;     ///< details of goto-statement
    casm_t *casm;       ///< details of asm-statement
    ctry_t *ctry;       ///< details of try-statement
    cthrow_t *cthrow;   ///< details of throw-statement
  };

  cinsn_t() { zero(); }
  cinsn_t(const cinsn_t &r) : citem_t(cit_empty) { *this = r; }
  void swap(cinsn_t &r) { citem_t::swap(r); std::swap(cblock, r.cblock); }
  cinsn_t &operator=(const cinsn_t &r) { return assign(r); }
  cinsn_t &hexapi assign(const cinsn_t &r);
  DECLARE_COMPARISONS(cinsn_t);
  ~cinsn_t() { cleanup(); }

  /// Replace the statement.
  /// The children of the statement are abandoned (not freed).
  /// The statement pointed by 'r' is moved to 'this' statement
  /// \param r the source statement. It is deleted after being copied
  void hexapi replace_by(cinsn_t *r);

  /// Cleanup the statement.
  /// This function properly deletes all children and sets the item type to cit_empty.
  void hexapi cleanup();

  /// Overwrite with zeroes without cleaning memory or deleting children
  void zero() { op = cit_empty; cblock = nullptr; }

  /// Create a new statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param insn_ea statement address
  cinsn_t &hexapi new_insn(ea_t insn_ea);

  /// Create a new if-statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param cnd if condition. It will be deleted after being copied.
  cif_t &hexapi create_if(cexpr_t *cnd);

  /// Print the statement into many lines.
  /// \param indent indention (number of spaces) for the statement
  /// \param vp printer helper class which will receive the generated text.
  /// \param use_curly if the statement is a block, how should curly braces be printed.
  void hexapi print(int indent, vc_printer_t &vp, use_curly_t use_curly=CALC_CURLY_BRACES) const;

  /// Print the statement into one line.
  /// Currently this function is not available.
  /// \param vout output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  void hexapi print1(qstring *vout, const cfunc_t *func) const;

  /// Check if the statement passes execution to the next statement.
  /// \return false if the statement breaks the control flow (like goto, return, etc)
  bool hexapi is_ordinary_flow() const;

  /// Check if the statement contains a statement of the specified type.
  /// \param type statement opcode to look for
  /// \param times how many times TYPE should be present
  /// \return true if the statement has at least TIMES children with opcode == TYPE
  bool hexapi contains_insn(ctype_t type, int times=1) const;

  /// Collect free \c break statements.
  /// This function finds all free \c break statements within the current statement.
  /// A \c break statement is free if it does not have a loop or switch parent that
  /// that is also within the current statement.
  /// \param breaks pointer to the variable where the vector of all found free
  ///               \c break statements is returned. This argument can be nullptr.
  /// \return true if some free \c break statements have been found
  bool hexapi collect_free_breaks(cinsnptrvec_t *breaks);

  /// Collect free \c continue statements.
  /// This function finds all free \c continue statements within the current statement.
  /// A \c continue statement is free if it does not have a loop parent that
  /// that is also within the current statement.
  /// \param continues pointer to the variable where the vector of all found free
  ///               \c continue statements is returned. This argument can be nullptr.
  /// \return true if some free \c continue statements have been found
  bool hexapi collect_free_continues(cinsnptrvec_t *continues);

  /// Check if the statement has free \c break statements.
  bool contains_free_break() const { return CONST_CAST(cinsn_t*)(this)->collect_free_breaks(nullptr); }
  /// Check if the statement has free \c continue statements.
  bool contains_free_continue() const { return CONST_CAST(cinsn_t*)(this)->collect_free_continues(nullptr); }

  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(cinsn_t);

typedef qlist<cinsn_t> cinsn_list_t;

/// Compound statement (curly braces)
struct cblock_t : public cinsn_list_t // we need list to be able to manipulate
{                                     // its elements freely
  DECLARE_COMPARISONS(cblock_t);
};

/// Function argument
struct carg_t : public cexpr_t
{
  bool is_vararg = false;     ///< is a vararg (matches ...)
  tinfo_t formal_type;        ///< formal parameter type (if known)
  void consume_cexpr(cexpr_t *e)
  {
    e->swap(*this);
    delete e;
  }
  DECLARE_COMPARISONS(carg_t)
  {
    return cexpr_t::compare(r);
  }
};
DECLARE_TYPE_AS_MOVABLE(carg_t);

/// Function argument list
struct carglist_t : public qvector<carg_t>
{
  tinfo_t functype;   ///< function object type
  int flags = 0;      ///< call flags
#define CFL_FINAL   0x0001  ///< call type is final, should not be changed
#define CFL_HELPER  0x0002  ///< created from a decompiler helper function
#define CFL_NORET   0x0004  ///< call does not return
  carglist_t() {}
  carglist_t(const tinfo_t &ftype, int fl = 0) : functype(ftype), flags(fl) {}
  DECLARE_COMPARISONS(carglist_t);
  void print(qstring *vout, const cfunc_t *func) const;
  int print(int curpos, vc_printer_t &vp) const;
};

/// Switch case. Usually cinsn_t is a block
struct ccase_t : public cinsn_t
{
  uint64vec_t values;        ///< List of case values.
                             ///< if empty, then 'default' case
  DECLARE_COMPARISONS(ccase_t);
  void set_insn(cinsn_t *i); // deletes 'i'
  size_t size() const { return values.size(); }
  const uint64 &value(int i) const { return values[i]; }
};
DECLARE_TYPE_AS_MOVABLE(ccase_t);

/// Vector of switch cases
struct ccases_t : public qvector<ccase_t>
{
  DECLARE_COMPARISONS(ccases_t);
  int find_value(uint64 v) const;
};

/// Switch statement
struct cswitch_t : public ceinsn_t
{
  cnumber_t mvnf;       ///< Maximal switch value and number format
  ccases_t cases;       ///< Switch cases: values and instructions
  DECLARE_COMPARISONS(cswitch_t);
};

/// Catch expression
struct catchexpr_t
{
  cexpr_t obj;  ///< the caught object. if obj.op==cot_empty, no object.
                ///< ideally, obj.op==cot_var
  qstring fake_type; ///< if not empty, type of the caught object.
                ///< ideally, obj.type should be enough. however, in some
                ///< cases the detailed type info is not available.
  DECLARE_COMPARISONS(catchexpr_t);
  void swap(catchexpr_t &r)
  {
    obj.swap(r.obj);
    fake_type.swap(r.fake_type);
  }
  bool is_catch_all() const { return obj.op == cot_empty && fake_type.empty(); }
};
DECLARE_TYPE_AS_MOVABLE(catchexpr_t);
typedef qvector<catchexpr_t> catchexprs_t;

/// Catch clause: "catch ( type obj )"
struct ccatch_t : public cblock_t
{
  catchexprs_t exprs;
  DECLARE_COMPARISONS(ccatch_t);
  bool is_catch_all() const { return exprs.empty(); }
  void swap(ccatch_t &r)
  {
    exprs.swap(r.exprs);
    cblock_t *cb = this;
    cb->swap(r);
  }
};
typedef qvector<ccatch_t> ccatchvec_t;

/// C++ Try statement.
/// This structure is also used to represent wind statements.
struct ctry_t : public cblock_t
{
  ccatchvec_t catchs;   ///< "catch all", if present, must be the last element.
                        ///< wind-statements must have "catch all" and nothing else.
  size_t old_state = 0; ///< old state number (internal, MSVC related)
  size_t new_state = 0; ///< new state number (internal, MSVC related)

  /// Is C++ wind statement? (not part of the C++ language)
  /// MSVC generates code like the following to keep track of constructed
  /// objects and destroy them upon an exception. Example:
  ///
  /// // an object is constructed at this point
  /// __wind
  /// {
  ///   // some other code that may throw an exception
  /// }
  /// __unwind
  /// {
  ///   // this code is executed only if there was an exception
  ///   // in the __wind block. normally here we destroy the object
  ///   // after that the exception is passed to the
  ///   // exception handler, regular control flow is interrupted here.
  /// }
  /// // regular logic continues here, if there were no exceptions
  /// // also the object's destructor is called
  bool is_wind = false; // if false, then try/catch

  DECLARE_COMPARISONS(ctry_t);
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
};

/// Throw statement
struct cthrow_t : public ceinsn_t
{
  DECLARE_COMPARISONS(cthrow_t);
};

//---------------------------------------------------------------------------
/// Additional position information for cblocks
struct cblock_pos_t
{
  cblock_t *blk;        // cinsn_t::cblock or cinsn_t::ctry or cinsn_t::ctry->catchs[x]
  cblock_t::iterator p; // iterator pointing to the current item
  bool is_first_insn() const { return p == blk->begin(); }
  cinsn_t *insn() const { return &*p; }
  cinsn_t *prev_insn() { --p; return insn(); }
};
DECLARE_TYPE_AS_MOVABLE(cblock_pos_t);
typedef qvector<cblock_pos_t> cblock_posvec_t;

/// A generic helper class that is used for ctree traversal.
/// When traversing the ctree, the currently visited ctree item and its children
/// can be freely modified without interrupting the traversal. However, if a
/// parent of the visited item is modified, the traversal must be immediately
/// stopped by returning a non-zero value.
struct ctree_visitor_t
{
  int cv_flags;           ///< \ref CV_
/// \defgroup CV_ Ctree visitor property bits
/// Used in ctree_visitor_t::cv_flags
///@{
#define CV_FAST    0x0000 ///< do not maintain parent information
#define CV_PRUNE   0x0001 ///< this bit is set by visit...() to prune the walk
#define CV_PARENTS 0x0002 ///< maintain parent information
#define CV_POST    0x0004 ///< call the leave...() functions
#define CV_RESTART 0x0008 ///< restart enumeration at the top expr (apply_to_exprs)
#define CV_INSNS   0x0010 ///< visit only statements, prune all expressions
                          ///< do not use before the final ctree maturity because
                          ///< expressions may contain statements at intermediate
                          ///< stages (see cot_insn). Otherwise you risk missing
                          ///< statements embedded into expressions.
///@}
  /// Should the parent information by maintained?
  bool maintain_parents() const { return (cv_flags & CV_PARENTS) != 0; }
  /// Should the traversal skip the children of the current item?
  bool must_prune()       const { return (cv_flags & CV_PRUNE) != 0; }
  /// Should the traversal restart?
  bool must_restart()     const { return (cv_flags & CV_RESTART) != 0; }
  /// Should the leave...() functions be called?
  bool is_postorder()     const { return (cv_flags & CV_POST) != 0; }
  /// Should all expressions be automatically pruned?
  bool only_insns()       const { return (cv_flags & CV_INSNS) != 0; }
  /// Prune children.
  /// This function may be called by a visitor() to skip all children of the current item.
  void prune_now() { cv_flags |= CV_PRUNE; }
  /// Do not prune children. This is an internal function, no need to call it.
  void clr_prune() { cv_flags &= ~CV_PRUNE; }
  /// Restart the travesal. Meaningful only in apply_to_exprs()
  void set_restart() { cv_flags |= CV_RESTART; }
  /// Do not restart. This is an internal function, no need to call it.
  void clr_restart() { cv_flags &= ~CV_RESTART; }

  parents_t parents;       ///< Vector of parents of the current item
  cblock_posvec_t bposvec; ///< Vector of block positions.
                           ///< Only cit_block and cit_try parents have
                           ///< the corresponding element in this vector.

  /// Constructor.
  /// This constructor can be used with CV_FAST, CV_PARENTS
  /// combined with CV_POST, CV_ONLYINS
  ctree_visitor_t(int _flags) : cv_flags(_flags) {}

  virtual ~ctree_visitor_t() {}
  /// Traverse ctree.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as nullptr.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to(citem_t *item, citem_t *parent);

  /// Traverse only expressions.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as nullptr.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to_exprs(citem_t *item, citem_t *parent);

  /// Get parent of the current item as an item (statement or expression)
  citem_t *parent_item()
  {
    return !parents.empty() ? parents.back() : nullptr;
  }

  /// Get parent of the current item as an expression
  cexpr_t *parent_expr()
  {
    citem_t *item = parent_item();
    return item != nullptr && item->is_expr() ? (cexpr_t *)item : nullptr;
  }

  /// Get parent of the current item as a statement
  cinsn_t *parent_insn()
  {
    citem_t *item = parent_item();
    return item != nullptr && !item->is_expr() ? (cinsn_t *)item : nullptr;
  }

  // the following functions are redefined by the derived class
  // in order to perform the desired actions during the traversal

  /// Visit a statement.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_insn(cinsn_t *) { return 0; }

  /// Visit an expression.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_expr(cexpr_t *) { return 0; }

  /// Visit a statement after having visited its children.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_insn(cinsn_t *) { return 0; }

  /// Visit an expression after having visited its children.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_expr(cexpr_t *) { return 0; }

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// A helper ctree traversal class that maintains parent information
struct ctree_parentee_t : public ctree_visitor_t
{
  ctree_parentee_t(bool post=false)
    : ctree_visitor_t((post ? CV_POST : 0)|CV_PARENTS) {}

  /// Recalculate type of parent nodes.
  /// If a node type has been changed, the visitor must recalculate
  /// all parent types, otherwise the ctree becomes inconsistent.
  /// If during this recalculation a parent node is added/deleted,
  /// this function returns true. In this case the traversal must be
  /// stopped because the information about parent nodes is stale.
  /// \return false-ok to continue the traversal, true-must stop.
  bool hexapi recalc_parent_types();
};

/// Class to traverse the whole function.
struct cfunc_parentee_t : public ctree_parentee_t
{
  cfunc_t *func;        ///< Pointer to current function
  cfunc_parentee_t(cfunc_t *f, bool post=false)
    : ctree_parentee_t(post), func(f) {}

  /// Calculate rvalue type.
  /// This function tries to determine the type of the specified item
  /// based on its context. For example, if the current expression is the
  /// right side of an assignment operator, the type
  /// of its left side will be returned. This function can be used to determine the 'best'
  /// type of the specified expression.
  /// \param[in] e expression to determine the desired type
  /// \param[out] target 'best' type of the expression will be returned here
  /// \return false if failed
  bool hexapi calc_rvalue_type(tinfo_t *target, const cexpr_t *e);
};

//---------------------------------------------------------------------------
/// Invisible COLOR_ADDR tags in the output text are used to refer to ctree items and variables
struct ctree_anchor_t
{
  uval_t value = BADADDR;
#define ANCHOR_INDEX  0x1FFFFFFF
#define ANCHOR_MASK   0xC0000000
#define   ANCHOR_CITEM 0x00000000 ///< c-tree item
#define   ANCHOR_LVAR  0x40000000 ///< declaration of local variable
#define   ANCHOR_ITP   0x80000000 ///< item type preciser
#define ANCHOR_BLKCMT 0x20000000  ///< block comment (for ctree items)
  int get_index() const { return value & ANCHOR_INDEX; }
  item_preciser_t get_itp() const { return item_preciser_t(value & ~ANCHOR_ITP); }
  bool is_valid_anchor() const { return value != BADADDR; }
  bool is_citem_anchor() const { return (value & ANCHOR_MASK) == ANCHOR_CITEM; }
  bool is_lvar_anchor() const { return (value & ANCHOR_MASK) == ANCHOR_LVAR; }
  bool is_itp_anchor() const { return (value & ANCHOR_ITP) != 0; }
  bool is_blkcmt_anchor() const { return (value & ANCHOR_BLKCMT) != 0; }
};

/// Type of the cursor item.
enum cursor_item_type_t
{
  VDI_NONE, ///< undefined
  VDI_EXPR, ///< c-tree item
  VDI_LVAR, ///< declaration of local variable
  VDI_FUNC, ///< the function itself (the very first line with the function prototype)
  VDI_TAIL, ///< cursor is at (beyond) the line end (commentable line)
};

/// Cursor item.
/// Information about the item under the cursor
struct ctree_item_t
{
  cursor_item_type_t citype = VDI_NONE; ///< Item type
  union
  {
    citem_t *it;
    cexpr_t *e;         ///< VDI_EXPR: Expression
    cinsn_t *i;         ///< VDI_EXPR: Statement
    lvar_t *l;          ///< VDI_LVAR: Local variable
    cfunc_t *f;         ///< VDI_FUNC: Function
    treeloc_t loc;      ///< VDI_TAIL: Line tail
  };

  void verify(const mba_t *mba) const;

  /// Get type of a structure field.
  /// If the current item is a structure/union field,
  /// this function will return information about it.
  /// \param[out] udm    pointer to buffer for the udt member info.
  /// \param[out] parent pointer to buffer for the struct/union type.
  /// \param[out] p_offset pointer to the offset in bits inside udt.
  /// \return member index or -1 if failed
  /// Both output parameters can be nullptr.

  int hexapi get_udm(
        udm_t *udm=nullptr,
        tinfo_t *parent=nullptr,
        uint64 *p_offset=nullptr) const;

  /// Get type of an enum member.
  /// If the current item is a symbolic constant,
  /// this function will return information about it.
  /// \param[out] parent pointer to buffer for the enum type.
  /// \return member index or -1 if failed

  int hexapi get_edm(tinfo_t *parent) const;

  /// Get pointer to local variable.
  /// If the current item is a local variable,
  /// this function will return pointer to its definition.
  /// \return nullptr if failed

  lvar_t *hexapi get_lvar() const;


  /// Get address of the current item.
  /// Each ctree item has an address.
  /// \return BADADDR if failed

  ea_t hexapi get_ea() const;


  /// Get label number of the current item.
  /// \param[in] gln_flags Combination of \ref GLN_ bits
  /// \return -1 if failed or no label

  int hexapi get_label_num(int gln_flags) const;
/// \defgroup GLN_ get_label_num control
///@{
#define GLN_CURRENT     0x01 ///< get label of the current item
#define GLN_GOTO_TARGET 0x02 ///< get goto target
#define GLN_ALL         0x03 ///< get both
///@}

  /// Is the current item is a ctree item?
  bool is_citem() const { return citype == VDI_EXPR; }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Unused label disposition.
enum allow_unused_labels_t
{
  FORBID_UNUSED_LABELS = 0,     ///< Unused labels cause interr
  ALLOW_UNUSED_LABELS = 1,      ///< Unused labels are permitted
};

typedef qmap<int, qstring> user_labels_t;

/// Logically negate the specified expression.
/// The specified expression will be logically negated.
/// For example, "x == y" is converted into "x != y" by this function.
/// \param e expression to negate. After the call, e must not be used anymore
///          because it can be changed by the function. The function return value
///          must be used to refer to the expression.
/// \return logically negated expression.

cexpr_t *hexapi lnot(cexpr_t *e);


/// Create a new block-statement.

cinsn_t *hexapi new_block();


/// Create a helper object.
/// This function creates a helper object.
/// The named function is not required to exist, the decompiler will only print
/// its name in the output. Helper functions are usually used to represent arbitrary
/// function or macro calls in the output.
/// \param standalone false:helper must be called; true:helper can be used in any expression
/// \param type type of the create function object
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va);

/// Create a helper object..
AS_PRINTF(3, 4) inline cexpr_t *create_helper(bool standalone, const tinfo_t &type, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcreate_helper(standalone, type, format, va);
  va_end(va);
  return e;
}


/// Create a helper call expression.
/// This function creates a new expression: a call of a helper function.
/// \param rettype type of the whole expression.
/// \param args helper arguments. this object will be consumed by the function.
///             if there are no args, this parameter may be specified as nullptr.
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va);

/// Create a helper call.
AS_PRINTF(3, 4) inline cexpr_t *call_helper(
        const tinfo_t &rettype,
        carglist_t *args,
        const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcall_helper(rettype, args, format, va);
  va_end(va);
  return e;
}


/// Create a number expression
/// \param n value
/// \param func current function
/// \param ea definition address of the number
/// \param opnum operand number of the number (in the disassembly listing)
/// \param sign number sign
/// \param size size of number in bytes
/// Please note that the type of the resulting expression can be anything because
/// it can be inherited from the disassembly listing or taken from the user
/// specified number representation in the pseudocode view.

cexpr_t *hexapi make_num(uint64 n, cfunc_t *func=nullptr, ea_t ea=BADADDR, int opnum=0, type_sign_t sign=no_sign, int size=0);


/// Create a reference.
/// This function performs the following conversion: "obj" => "&obj".
/// It can handle casts, annihilate "&*", and process other special cases.

cexpr_t *hexapi make_ref(cexpr_t *e);


/// Dereference a pointer.
/// This function dereferences a pointer expression.
/// It performs the following conversion: "ptr" => "*ptr"
/// It can handle discrepancies in the pointer type and the access size.
/// \param e expression to deference
/// \param ptrsize access size
/// \param is_flt dereferencing for floating point access?
/// \return dereferenced expression

cexpr_t *hexapi dereference(cexpr_t *e, int ptrsize, bool is_flt=false);


/// Save user defined labels into the database.
/// \param func_ea the entry address of the function,
///                ignored if FUNC != nullptr
/// \param user_labels collection of user defined labels
/// \param func pointer to current function,
///             if FUNC != nullptr, then save labels using a more stable
///             method that preserves them even when the decompiler
///             output drastically changes

void hexapi save_user_labels(ea_t func_ea, const user_labels_t *user_labels, const cfunc_t *func=nullptr);


/// Save user defined comments into the database.
/// \param func_ea the entry address of the function
/// \param user_cmts collection of user defined comments

void hexapi save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts);

/// Save user defined number formats into the database.
/// \param func_ea the entry address of the function
/// \param numforms collection of user defined comments

void hexapi save_user_numforms(ea_t func_ea, const user_numforms_t *numforms);


/// Save user defined citem iflags into the database.
/// \param func_ea the entry address of the function
/// \param iflags collection of user defined citem iflags

void hexapi save_user_iflags(ea_t func_ea, const user_iflags_t *iflags);


/// Save user defined union field selections into the database.
/// \param func_ea the entry address of the function
/// \param unions collection of union field selections

void hexapi save_user_unions(ea_t func_ea, const user_unions_t *unions);


/// Restore user defined labels from the database.
/// \param func_ea the entry address of the function,
///                ignored if FUNC != nullptr
/// \param func    pointer to current function
/// \return collection of user defined labels.
///         The returned object must be deleted by the caller using delete_user_labels()

user_labels_t *hexapi restore_user_labels(ea_t func_ea, const cfunc_t *func=nullptr);


/// Restore user defined comments from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined comments.
///         The returned object must be deleted by the caller using delete_user_cmts()

user_cmts_t *hexapi restore_user_cmts(ea_t func_ea);


/// Restore user defined number formats from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined number formats.
///         The returned object must be deleted by the caller using delete_user_numforms()

user_numforms_t *hexapi restore_user_numforms(ea_t func_ea);


/// Restore user defined citem iflags from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined iflags.
///         The returned object must be deleted by the caller using delete_user_iflags()

user_iflags_t *hexapi restore_user_iflags(ea_t func_ea);


/// Restore user defined union field selections from the database.
/// \param func_ea the entry address of the function
/// \return collection of union field selections
///         The returned object must be deleted by the caller using delete_user_unions()

user_unions_t *hexapi restore_user_unions(ea_t func_ea);


typedef qmap<ea_t, cinsnptrvec_t> eamap_t;
// map of instruction boundaries. may contain INS_EPILOG for the epilog instructions
typedef qmap<cinsn_t *, rangeset_t> boundaries_t;
#define INS_EPILOG ((cinsn_t *)1)

// Tags to find this location quickly: #cfunc_t #func_t
//-------------------------------------------------------------------------
/// Decompiled function. Decompilation result is kept here.
struct cfunc_t
{
  ea_t entry_ea;             ///< function entry address
  mba_t *mba;                ///< underlying microcode
  cinsn_t body;              ///< function body, must be a block
  intvec_t &argidx;          ///< list of arguments (indexes into vars)
  ctree_maturity_t maturity; ///< maturity level
  // The following maps must be accessed using helper functions.
  // Example: for user_labels_t, see functions starting with "user_labels_".
  user_labels_t *user_labels;///< user-defined labels.
  user_cmts_t *user_cmts;    ///< user-defined comments.
  user_numforms_t *numforms; ///< user-defined number formats.
  user_iflags_t *user_iflags;///< user-defined item flags \ref CIT_
  user_unions_t *user_unions;///< user-defined union field selections.
/// \defgroup CIT_ ctree item iflags bits
///@{
#define CIT_COLLAPSED 0x0001 ///< display ctree item in collapsed form
///@}
  int refcnt;                ///< reference count to this object. use cfuncptr_t
  int statebits;             ///< current cfunc_t state. see \ref CFS_
/// \defgroup CFS_ cfunc state bits
#define CFS_BOUNDS       0x0001 ///< 'eamap' and 'boundaries' are ready
#define CFS_TEXT         0x0002 ///< 'sv' is ready (and hdrlines)
#define CFS_LVARS_HIDDEN 0x0004 ///< local variable definitions are collapsed
#define CFS_LOCKED       0x0008 ///< cfunc is temporarily locked
  eamap_t *eamap;            ///< ea->insn map. use \ref get_eamap
  boundaries_t *boundaries;  ///< map of instruction boundaries. use \ref get_boundaries
  strvec_t sv;               ///< decompilation output: function text. use \ref get_pseudocode
  int hdrlines;              ///< number of lines in the declaration area
  mutable citem_pointers_t treeitems; ///< vector of pointers to citem_t objects (nodes constituting the ctree)

  // the exact size of this class is not documented, there may be more fields
  char reserved[];

public:
  cfunc_t(mba_t *mba);          // use create_cfunc()
  ~cfunc_t() { cleanup(); }
  void release() { delete this; }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()

  /// Generate the function body.
  /// This function (re)generates the function body from the underlying microcode.
  void hexapi build_c_tree();

  /// Verify the ctree.
  /// This function verifies the ctree. If the ctree is malformed, an internal error
  /// is generated. Use it to verify the ctree after your modifications.
  /// \param aul Are unused labels acceptable?
  /// \param even_without_debugger if false and there is no debugger, the verification will be skipped
  void hexapi verify(allow_unused_labels_t aul, bool even_without_debugger) const;

  /// Print function prototype.
  /// \param vout output buffer
  void hexapi print_dcl(qstring *vout) const;

  /// Print function text.
  /// \param vp printer helper class to receive the generated text.
  void hexapi print_func(vc_printer_t &vp) const;

  /// Get the function type.
  /// \param type variable where the function type is returned
  /// \return false if failure
  bool hexapi get_func_type(tinfo_t *type) const;

  /// Get vector of local variables.
  /// \return pointer to the vector of local variables. If you modify this vector,
  ///         the ctree must be regenerated in order to have correct cast operators.
  ///         Use build_c_tree() for that.
  ///         Removing lvars should be done carefully: all references in ctree
  ///         and microcode must be corrected after that.
  lvars_t *hexapi get_lvars();

  /// Get stack offset delta.
  /// The local variable stack offsets retrieved by v.location.stkoff()
  /// should be adjusted before being used as stack frame offsets in IDA.
  /// \return the delta to apply.
  ///         example: ida_stkoff = v.location.stkoff() - f->get_stkoff_delta()
  sval_t hexapi get_stkoff_delta();

  /// Find the label.
  /// \return pointer to the ctree item with the specified label number.
  citem_t *hexapi find_label(int label);

  /// Remove unused labels.
  /// This function checks what labels are really used by the function and
  /// removes the unused ones. You must call it after deleting a goto statement.
  void hexapi remove_unused_labels();

  /// Retrieve a user defined comment.
  /// \param loc ctree location
  /// \param rt should already retrieved comments retrieved again?
  /// \return pointer to the comment string or nullptr
  const char *hexapi get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const;

  /// Set a user defined comment.
  /// This function stores the specified comment in the cfunc_t structure.
  /// The save_user_cmts() function must be called after it.
  /// \param loc ctree location
  /// \param cmt new comment. if empty or nullptr, then an existing comment is deleted.
  void hexapi set_user_cmt(const treeloc_t &loc, const char *cmt);

  /// Retrieve citem iflags.
  /// \param loc citem locator
  /// \return \ref CIT_ or 0
  int32 hexapi get_user_iflags(const citem_locator_t &loc) const;

  /// Set citem iflags.
  /// \param loc citem locator
  /// \param iflags new iflags
  void hexapi set_user_iflags(const citem_locator_t &loc, int32 iflags);

  /// Check if there are orphan comments.
  bool hexapi has_orphan_cmts() const;

  /// Delete all orphan comments.
  /// The save_user_cmts() function must be called after this call.
  int hexapi del_orphan_cmts();

  /// Retrieve a user defined union field selection.
  /// \param ea address
  /// \param path out: path describing the union selection.
  /// \return pointer to the path or nullptr
  bool hexapi get_user_union_selection(ea_t ea, intvec_t *path);

  /// Set a union field selection.
  /// The save_user_unions() function must be called after calling this function.
  /// \param ea address
  /// \param path in: path describing the union selection.
  void hexapi set_user_union_selection(ea_t ea, const intvec_t &path);

  /// Save user-defined labels into the database
  void hexapi save_user_labels() const;
  /// Save user-defined comments into the database
  void hexapi save_user_cmts() const;
  /// Save user-defined number formats into the database
  void hexapi save_user_numforms() const;
  /// Save user-defined iflags into the database
  void hexapi save_user_iflags() const;
  /// Save user-defined union field selections into the database
  void hexapi save_user_unions() const;

  /// Get ctree item for the specified cursor position.
  /// \return false if failed to get the current item
  /// \param line line of decompilation text (element of \ref sv)
  /// \param x x cursor coordinate in the line
  /// \param is_ctree_line does the line belong to statement area? (if not, it is assumed to belong to the declaration area)
  /// \param phead ptr to the first item on the line (used to attach block comments). May be nullptr
  /// \param pitem ptr to the current item. May be nullptr
  /// \param ptail ptr to the last item on the line (used to attach indented comments). May be nullptr
  /// \sa vdui_t::get_current_item()
  bool hexapi get_line_item(
        const char *line,
        int x,
        bool is_ctree_line,
        ctree_item_t *phead,
        ctree_item_t *pitem,
        ctree_item_t *ptail);

  /// Get information about decompilation warnings.
  /// \return reference to the vector of warnings
  hexwarns_t &hexapi get_warnings();

  /// Get pointer to ea->insn map.
  /// This function initializes eamap if not done yet.
  eamap_t &hexapi get_eamap();

  /// Get pointer to map of instruction boundaries.
  /// This function initializes the boundary map if not done yet.
  boundaries_t &hexapi get_boundaries();

  /// Get pointer to decompilation output: the pseudocode.
  /// This function generates pseudocode if not done yet.
  const strvec_t &hexapi get_pseudocode();

  /// Refresh ctext after a ctree modification.
  /// This function informs the decompiler that ctree (\ref body) have been
  /// modified and ctext (\ref sv) does not correspond to it anymore.
  /// It also refreshes the pseudocode windows if there is any.
  void hexapi refresh_func_ctext();

  /// Recalculate item adresses.
  /// This function may be required after shuffling ctree items.
  /// For example, when adding or removing statements of a block,
  /// or changing 'if' statements.
  void hexapi recalc_item_addresses();

  bool hexapi gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm=nullptr) const;
  bool hexapi find_item_coords(const citem_t *item, int *px, int *py);
  bool locked() const { return (statebits & CFS_LOCKED) != 0; }
  /// Serialize cfunc into a sequence of bytes.
  bool hexapi serialize(bytevec_t *vout);

  /// Deserialize a byte sequence into cfunc_t
  /// \param mba the matching mba object
  /// \param bytes pointer to the beginning of the byte sequence.
  /// \param nbytes number of bytes in the byte sequence.
  /// \return new cfunc_t object
  WARN_UNUSED_RESULT static cfunc_t *hexapi deserialize(
        mba_t *mba,
        const uchar *bytes,
        size_t nbytes);

private:
  /// Cleanup.
  /// Properly delete all children and free memory.
  void hexapi cleanup();
  DECLARE_UNCOPYABLE(cfunc_t)
};
typedef qvector<cfuncptr_t> cfuncptrs_t;

/// Close the waitbox displayed by the decompiler.
/// Useful if DECOMP_NO_HIDE was used during decompilation.

void hexapi close_hexrays_waitbox();


/// Decompile a snippet or a function.
/// \param mbr          what to decompile
/// \param hf           extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

cfuncptr_t hexapi decompile(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0);


/// Decompile a function.
/// Multiple decompilations of the same function return the same object.
/// \param pfn pointer to function to decompile
/// \param hf  extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

inline cfuncptr_t decompile_func(
        func_t *pfn,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0)
{
  mba_ranges_t mbr(pfn);
  return decompile(mbr, hf, decomp_flags);
}


/// Decompile a snippet.
/// \param ranges       snippet ranges. ranges[0].start_ea is the entry point
/// \param hf           extended error information (if failed)
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.

inline cfuncptr_t decompile_snippet(
        const rangevec_t &ranges,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0)
{
  mba_ranges_t mbr(ranges);
  return decompile(mbr, hf, decomp_flags);
}


/// Create a new cfunc_t object.
/// \param mba microcode object.
/// After creating the cfunc object it takes the ownership of MBA.

cfuncptr_t hexapi create_cfunc(mba_t *mba);


/// Flush the cached decompilation results.
/// Erases a cache entry for the specified function.
/// \param ea function to erase from the cache
/// \param close_views close pseudocode windows that show the function
/// \return if a cache entry existed.

bool hexapi mark_cfunc_dirty(ea_t ea, bool close_views=false);


/// Flush all cached decompilation results.

void hexapi clear_cached_cfuncs();


/// Do we have a cached decompilation result for 'ea'?

bool hexapi has_cached_cfunc(ea_t ea);

//--------------------------------------------------------------------------
// Now cinsn_t class is defined, define the cleanup functions:
inline void cif_t::cleanup()     { delete ithen; delete ielse; }
inline void cloop_t::cleanup()   { delete body; }

/// Print item into one line.
/// \param vout output buffer
/// \param func parent function. This argument is used to find out the referenced variable names.
/// \return length of the generated text.

inline void citem_t::print1(qstring *vout, const cfunc_t *func) const
{
  if ( is_expr() )
    ((cexpr_t*)this)->print1(vout, func);
  else
    ((cinsn_t*)this)->print1(vout, func);
}

/// Get pointers to operands. at last one operand should be a number
/// o1 will be pointer to the number

inline bool cexpr_t::get_1num_op(cexpr_t **o1, cexpr_t **o2)
{
  if ( x->op == cot_num )
  {
    *o1 = x;
    *o2 = y;
  }
  else
  {
    if ( y->op != cot_num )
      return false;
    *o1 = y;
    *o2 = x;
  }
  return true;
}

inline bool cexpr_t::get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const
{
  return CONST_CAST(cexpr_t*)(this)->get_1num_op(
         CONST_CAST(cexpr_t**)(o1),
         CONST_CAST(cexpr_t**)(o2));
}

inline citem_locator_t::citem_locator_t(const citem_t *i)
  : ea(i != nullptr ? i->ea : BADADDR),
    op(i != nullptr ? i->op : cot_empty)
{
}

#ifdef __MICRO_HPP
inline lvar_t &var_ref_t::getv() const
{
  return mba->vars[idx];
}
#endif

const char *hexapi get_ctype_name(ctype_t op);
qstring hexapi create_field_name(const tinfo_t &type, uval_t offset=BADADDR);
typedef void *hexdsp_t(int code, ...);
const int64 HEXRAYS_API_MAGIC = 0x00DEC0DE00000004LL;

/// Decompiler events.
/// Use install_hexrays_callback() to install a handler for decompiler events.
/// When the possible return value is not specified, your callback
/// must return zero.
enum hexrays_event_t ENUM_SIZE(int)
{
  // When a function is decompiled, the following events occur:

  hxe_flowchart,        ///< Flowchart has been generated.
                        ///< \param fc (qflow_chart_t *)
                        ///< \param mba (mba_t *)
                        ///< \param reachable_blocks (bitset_t *)
                        ///< \param decomp_flags (int)
                        ///< \return \ref MERR_

  hxe_stkpnts,          ///< SP change points have been calculated.
                        ///< \param mba (mba_t *)
                        ///< \param stkpnts (stkpnts_t *)
                        ///< \return \ref MERR_
                        ///< This event is generated for each inlined range as well.

  hxe_prolog,           ///< Prolog analysis has been finished.
                        ///< \param mba (mba_t *)
                        ///< \param fc (qflow_chart_t *)
                        ///< \param reachable_blocks (const bitset_t *)
                        ///< \param decomp_flags (int)
                        ///< \return \ref MERR_
                        ///< This event is generated for each inlined range as well.

  hxe_microcode,        ///< Microcode has been generated.
                        ///< \param mba (mba_t *)
                        ///< \return \ref MERR_

  hxe_preoptimized,     ///< Microcode has been preoptimized.
                        ///< \param mba (mba_t *)
                        ///< \return \ref MERR_

  hxe_locopt,           ///< Basic block level optimization has been finished.
                        ///< \param mba (mba_t *)
                        ///< \return \ref MERR_

  hxe_prealloc,         ///< Local variables: preallocation step begins.
                        ///< \param mba (mba_t *)
                        ///< This event may occur several times.
                        ///< Should return: 1 if modified microcode
                        ///< Negative values are \ref MERR_

  hxe_glbopt,           ///< Global optimization has been finished.
                        ///< If microcode is modified, MERR_LOOP must be returned.
                        ///< It will cause a complete restart of the optimization.
                        ///< \param mba (mba_t *)
                        ///< \return \ref MERR_

  hxe_pre_structural,   ///< Structure analysis is starting.
                        ///< \param ct (control_graph_t *) in/out: control graph
                        ///< \param cfunc (cfunc_t *) in: the current function
                        ///< \param g (const simple_graph_t *) in: control flow graph
                        ///< \return \ref MERR_; MERR_BLOCK means that the analysis has been performed by a plugin

  hxe_structural,       ///< Structural analysis has been finished.
                        ///< \param ct (control_graph_t *)

  hxe_maturity,         ///< Ctree maturity level is being changed.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param new_maturity (ctree_maturity_t)

  hxe_interr,           ///< Internal error has occurred.
                        ///< \param errcode (int )

  hxe_combine,          ///< Trying to combine instructions of basic block.
                        ///< \param blk (mblock_t *)
                        ///< \param insn (minsn_t *)
                        ///< Should return: 1 if combined the current instruction with a preceding one
                        ///                 -1 if the instruction should not be combined
                        ///                 0 else

  hxe_print_func,       ///< Printing ctree and generating text.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param vp (vc_printer_t *)
                        ///< Returns: 1 if text has been generated by the plugin
                        ///< It is forbidden to modify ctree at this event.

  hxe_func_printed,     ///< Function text has been generated. Plugins may
                        ///< modify the text in \ref cfunc_t::sv. However,
                        ///< it is too late to modify the ctree or microcode.
                        ///< The text uses regular color codes (see lines.hpp)
                        ///< COLOR_ADDR is used to store pointers to ctree items.
                        ///< \param cfunc (cfunc_t *)

  hxe_resolve_stkaddrs, ///< The optimizer is about to resolve stack addresses.
                        ///< \param mba (mba_t *)

  hxe_build_callinfo,   ///< Analyzing a call instruction.
                        ///< \param blk (mblock_t *) blk->tail is the call.
                        ///< \param type (tinfo_t *) buffer for the output type.
                        ///< \param callinfo (mcallinfo_t **) prepared callinfo.
                        ///< The plugin should either specify the function type,
                        ///< either allocate and return a new mcallinfo_t object.

  hxe_callinfo_built,   ///< A call instruction has been anallyzed.
                        ///< \param blk (mblock_t *) blk->tail is the call.

  hxe_calls_done,       ///< All calls have been analyzed.
                        ///< \param mba (mba_t *)
                        ///< This event is generated immediately after analyzing
                        ///< all calls, before any optimizitions, call unmerging
                        ///< and block merging.

  hxe_begin_inlining,   ///< Starting to inline outlined functions.
                        ///< \param cdg (codegen_t *)
                        ///< \param decomp_flags (int)
                        ///< \return \ref MERR_
                        ///< This is an opportunity to inline other ranges.

  hxe_inlining_func,    ///< A set of ranges is going to be inlined.
                        ///< \param cdg (codegen_t *)
                        ///< \param blk (int) the block containing call/jump to inline
                        ///< \param mbr (mba_ranges_t *) the range to inline

  hxe_inlined_func,     ///< A set of ranges got inlined.
                        ///< \param cdg (codegen_t *)
                        ///< \param blk (int) the block containing call/jump to inline
                        ///< \param mbr (mba_ranges_t *) the range to inline
                        ///< \param i1  (int) blknum of the first inlined block
                        ///< \param i2  (int) blknum of the last inlined block (excluded)

  hxe_collect_warnings, ///< Collect warning messages from plugins.
                        ///< These warnings will be displayed at the function header,
                        ///< after the user-defined comments.
                        ///< \param warnings (qstrvec_t *)
                        ///< \param cfunc (cfunc_t *)

  // User interface related events:

  hxe_open_pseudocode=100,
                        ///< New pseudocode view has been opened.
                        ///< \param vu (vdui_t *)

  hxe_switch_pseudocode,///< Existing pseudocode view has been reloaded
                        ///< with a new function. Its text has not been
                        ///< refreshed yet, only cfunc and mba pointers are ready.
                        ///< \param vu (vdui_t *)

  hxe_refresh_pseudocode,///< Existing pseudocode text has been refreshed.
                        ///< Adding/removing pseudocode lines is forbidden in this event.
                        ///< \param vu (vdui_t *)
                        ///< See also hxe_text_ready, which happens earlier

  hxe_close_pseudocode, ///< Pseudocode view is being closed.
                        ///< \param vu (vdui_t *)

  hxe_keyboard,         ///< Keyboard has been hit.
                        ///< \param vu (vdui_t *)
                        ///< \param key_code (int) VK_...
                        ///< \param shift_state (int)
                        ///< Should return: 1 if the event has been handled

  hxe_right_click,      ///< Mouse right click.
                        ///< Use hxe_populating_popup instead, in case you
                        ///< want to add items in the popup menu.
                        ///< \param vu (vdui_t *)

  hxe_double_click,     ///< Mouse double click.
                        ///< \param vu (vdui_t *)
                        ///< \param shift_state (int)
                        ///< Should return: 1 if the event has been handled

  hxe_curpos,           ///< Current cursor position has been changed.
                        ///< (for example, by left-clicking or using keyboard)\n
                        ///< \param vu (vdui_t *)

  hxe_create_hint,      ///< Create a hint for the current item.
                        ///< \see ui_get_custom_viewer_hint
                        ///< \param vu (vdui_t *)
                        ///< \param hint (qstring *)
                        ///< \param important_lines (int *)
                        ///< Possible return values:
                        ///< \retval 0 continue collecting hints with other subscribers
                        ///< \retval 1 stop collecting hints

  hxe_text_ready,       ///< Decompiled text is ready.
                        ///< \param vu (vdui_t *)
                        ///< This event can be used to modify the output text (sv).
                        ///< Obsolete. Please use hxe_func_printed instead.

  hxe_populating_popup, ///< Populating popup menu. We can add menu items now.
                        ///< \param widget (TWidget *)
                        ///< \param popup_handle (TPopupMenu *)
                        ///< \param vu (vdui_t *)

  lxe_lvar_name_changed,///< Local variable got renamed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param name (const char *)
                        ///< \param is_user_name (bool)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_type_changed,///< Local variable type got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param tinfo (const tinfo_t *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_cmt_changed, ///< Local variable comment got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param v (lvar_t *)
                        ///< \param cmt (const char *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  lxe_lvar_mapping_changed, ///< Local variable mapping got changed.
                        ///< \param vu (vdui_t *)
                        ///< \param from (lvar_t *)
                        ///< \param to (lvar_t *)
                        ///< Please note that it is possible to read/write
                        ///< user settings for lvars directly from the idb.

  hxe_cmt_changed,      ///< Comment got changed.
                        ///< \param cfunc (cfunc_t *)
                        ///< \param loc (const treeloc_t *)
                        ///< \param cmt (const char *)

  hxe_mba_maturity,     ///< Maturity level of an MBA was changed.
                        ///< \param mba (mba_t *)
                        ///< \param reqmat (mba_maturity_t) requested maturity level
                        ///< \return \ref MERR_
};

/// Handler of decompiler events.
/// \param ud user data. the value specified at the handler installation time
///           is passed here.
/// \param event decompiler event code
/// \param va additional arguments
/// \return as a rule the callback must return 0 unless specified otherwise
///         in the event description.

typedef ssize_t idaapi hexrays_cb_t(void *ud, hexrays_event_t event, va_list va);


/// Install handler for decompiler events.
/// \param callback handler to install
/// \param ud user data. this pointer will be passed to your handler by the decompiler.
/// \return false if failed

bool hexapi install_hexrays_callback(hexrays_cb_t *callback, void *ud);

/// Uninstall handler for decompiler events.
/// \param callback handler to uninstall
/// \param ud user data. if nullptr, all handler corresponding to \c callback is uninstalled.
///             if not nullptr, only the callback instance with the specified \c ud value is uninstalled.
/// \return number of uninstalled handlers.

int hexapi remove_hexrays_callback(hexrays_cb_t *callback, void *ud);


//---------------------------------------------------------------------------
/// \defgroup vdui User interface definitions
///@{

/// Type of the input device.
/// How the user command has been invoked
enum input_device_t
{
  USE_KEYBOARD = 0,     ///< Keyboard
  USE_MOUSE = 1,        ///< Mouse
};
///@}

//---------------------------------------------------------------------------
/// Cursor position in the output text (pseudocode).
struct ctext_position_t
{
  int lnnum;            ///< Line number
  int x;                ///< x coordinate of the cursor within the window
  int y;                ///< y coordinate of the cursor within the window
  /// Is the cursor in the variable/type declaration area?
  /// \param hdrlines Number of lines of the declaration area
  bool in_ctree(int hdrlines) const { return lnnum >= hdrlines; }
  /// Comparison operators
  DECLARE_COMPARISONS(ctext_position_t)
  {
    if ( lnnum < r.lnnum ) return -1;
    if ( lnnum > r.lnnum ) return  1;
    if ( x < r.x ) return -1;
    if ( x > r.x ) return  1;
    return 0;
  }
  ctext_position_t(int _lnnum=-1, int _x=0, int _y=0)
    : lnnum(_lnnum), x(_x), y(_y) {}
};

/// Navigation history item.
/// Holds information about interactive decompilation history.
/// Currently this is not saved in the database.
struct history_item_t : public ctext_position_t
{
  ea_t func_ea;         ///< The entry address of the decompiled function
  ea_t curr_ea;         ///< Current address
  ea_t end = BADADDR;   ///< BADADDR-decompile a function; otherwise end of the range
  history_item_t(ea_t fea=BADADDR, ea_t cea=BADADDR, int _lnnum=-1, int _x=0, int _y=0)
    : ctext_position_t(_lnnum, _x, _y), func_ea(fea), curr_ea(cea) {}
  history_item_t(ea_t fea, ea_t cea, const ctext_position_t &p)
    : ctext_position_t(p), func_ea(fea), curr_ea(cea) {}
};

/// Navigation history.
typedef qstack<history_item_t> history_t;

/// Comment types
typedef int cmt_type_t;
const cmt_type_t
  CMT_NONE   = 0x0000,  ///< No comment is possible
  CMT_TAIL   = 0x0001,  ///< Indented comment
  CMT_BLOCK1 = 0x0002,  ///< Anterioir block comment
  CMT_BLOCK2 = 0x0004,  ///< Posterior block comment
  CMT_LVAR   = 0x0008,  ///< Local variable comment
  CMT_FUNC   = 0x0010,  ///< Function comment
  CMT_ALL    = 0x001F;  ///< All comments

//---------------------------------------------------------------------------
/// Information about the pseudocode window
struct vdui_t
{
  int flags = 0;        ///< \ref VDUI_
/// \defgroup VDUI_ Properties of pseudocode window
/// Used in vdui_t::flags
///@{
#define VDUI_VISIBLE 0x0001     ///< is visible?
#define VDUI_VALID   0x0002     ///< is valid?
///@}

  /// Is the pseudocode window visible?
  /// if not, it might be invisible or destroyed
  bool visible() const { return (flags & VDUI_VISIBLE) != 0; }
  /// Does the pseudocode window contain valid code?
  /// It can become invalid if the function type gets changed in IDA.
  bool valid() const { return (flags & VDUI_VALID) != 0; }
  /// Does the pseudocode window contain valid code?
  /// We lock windows before modifying them, to avoid recursion due to
  /// the events generated by the IDA kernel.
  /// \retval true The window is locked and may have stale info
  bool locked() const { return cfunc != nullptr && cfunc->locked(); }
  void set_visible(bool v) { setflag(flags, VDUI_VISIBLE, v); }
  void set_valid(bool v)   { setflag(flags, VDUI_VALID, v); }
  bool hexapi set_locked(bool v); // returns true-redecompiled

  int view_idx;         ///< pseudocode window index (0..)
  TWidget *ct = nullptr;///< pseudocode view
  TWidget *toplevel = nullptr;

  mba_t *mba;           ///< pointer to underlying microcode
  cfuncptr_t cfunc;     ///< pointer to function object
  merror_t last_code;   ///< result of the last user action. See \ref MERR_

  // The following fields are valid after get_current_item():
  ctext_position_t cpos;        ///< Current ctext position
  ctree_item_t head;            ///< First ctree item on the current line (for block comments)
  ctree_item_t item;            ///< Current ctree item
  ctree_item_t tail;            ///< Tail ctree item on the current line (for indented comments)

  vdui_t();                 // do not create your own vdui_t objects

  /// Refresh pseudocode window.
  /// This is the highest level refresh function.
  /// It causes the most profound refresh possible and can lead to redecompilation
  /// of the current function. Please consider using refresh_ctext()
  /// if you need a more superficial refresh.
  /// \param redo_mba true means to redecompile the current function\n
  ///                 false means to rebuild ctree without regenerating microcode
  /// \sa refresh_ctext()
  void hexapi refresh_view(bool redo_mba);

  /// Refresh pseudocode window.
  /// This function refreshes the pseudocode window by regenerating its text
  /// from cfunc_t. Instead of this function use refresh_func_ctext(), which
  /// refreshes all pseudocode windows for the function.
  /// \sa refresh_view(), refresh_func_ctext()
  void hexapi refresh_ctext(bool activate=true); // deprecated

  /// Display the specified pseudocode.
  /// This function replaces the pseudocode window contents with the
  /// specified cfunc_t.
  /// \param f pointer to the function to display.
  /// \param activate should the pseudocode window get focus?
  void hexapi switch_to(cfuncptr_t f, bool activate);

  /// Is the current item a statement?
  //// \return false if the cursor is in the local variable/type declaration area\n
  ///          true if the cursor is in the statement area
  bool in_ctree() const { return cpos.in_ctree(cfunc->hdrlines); }

  /// Get current number.
  /// If the current item is a number, return pointer to it.
  /// \return nullptr if the current item is not a number
  /// This function returns non-null for the cases of a 'switch' statement
  /// Also, if the current item is a casted number, then this function will succeed.
  cnumber_t *hexapi get_number();

  /// Get current label.
  /// If there is a label under the cursor, return its number.
  /// \return -1 if there is no label under the cursor.
  /// prereq: get_current_item() has been called
  int hexapi get_current_label();

  /// Clear the pseudocode window.
  /// It deletes the current function and microcode.
  void hexapi clear();

  /// Refresh the current position.
  /// This function refreshes the \ref cpos field.
  /// \return false if failed
  /// \param idv keyboard or mouse
  bool hexapi refresh_cpos(input_device_t idv);

  /// Get current item.
  /// This function refreshes the \ref cpos, \ref item, \ref tail fields.
  /// \return false if failed
  /// \param idv keyboard or mouse
  /// \sa cfunc_t::get_line_item()
  bool hexapi get_current_item(input_device_t idv);

  /// Rename local variable.
  /// This function displays a dialog box and allows the user to rename a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_rename_lvar(lvar_t *v);

  /// Rename local variable.
  /// This function permanently renames a local variable.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param name new variable name
  /// \param is_user_name use true to save the new name into the database.
  ///                     use false to delete the saved name.
  /// \sa ::rename_lvar()
  bool hexapi rename_lvar(lvar_t *v, const char *name, bool is_user_name);

  /// Set type of a function call
  /// This function displays a dialog box and allows the user to change
  /// the type of a function call
  /// \return false if failed or cancelled
  /// \param e pointer to call expression
  bool hexapi ui_set_call_type(const cexpr_t *e);

  /// Set local variable type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_set_lvar_type(lvar_t *v);

  /// Set local variable type.
  /// This function permanently sets a local variable type and clears
  /// NOPTR flag if it was set before by function 'set_noptr_lvar'
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param type new variable type
  bool hexapi set_lvar_type(lvar_t *v, const tinfo_t &type);

  /// Inform that local variable should have a non-pointer type
  /// This function permanently sets a corresponding variable flag (NOPTR)
  /// and removes type if it was set before by function 'set_lvar_type'
  /// \return false if failed
  /// \param v pointer to local variable
  bool hexapi set_noptr_lvar(lvar_t *v);

  /// Set local variable comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_edit_lvar_cmt(lvar_t *v);

  /// Set local variable comment.
  /// This function permanently sets a variable comment.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param cmt new comment
  bool hexapi set_lvar_cmt(lvar_t *v, const char *cmt);

  /// Map a local variable to another.
  /// This function displays a variable list and allows the user to select mapping.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_map_lvar(lvar_t *v);

  /// Unmap a local variable.
  /// This function displays list of variables mapped to the specified variable
  /// and allows the user to select a variable to unmap.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_unmap_lvar(lvar_t *v);

  /// Forbid variable propagation.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool hexapi ui_noprop_lvar(lvar_t *v);

  /// Map a local variable to another.
  /// This function permanently maps one lvar to another.
  /// All occurrences of the mapped variable are replaced by the new variable
  /// \return false if failed
  /// \param from the variable being mapped
  /// \param to the variable to map to. if nullptr, unmaps the variable
  bool hexapi map_lvar(lvar_t *from, lvar_t *to);

  /// Set structure field type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a structure field.
  /// \return false if failed or cancelled
  /// \param udt_type structure/union type
  /// \param udm_idx index of the structure/union member
  bool hexapi set_udm_type(tinfo_t &udt_type, int udm_idx);

  /// Rename structure field.
  /// This function displays a dialog box and allows the user to rename
  /// a structure field.
  /// \return false if failed or cancelled
  /// \param udt_type structure/union type
  /// \param udm_idx index of the structure/union member
  bool hexapi rename_udm(tinfo_t &udt_type, int udm_idx);

  /// Set global item type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool hexapi set_global_type(ea_t ea);

  /// Rename global item.
  /// This function displays a dialog box and allows the user to rename
  /// a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool hexapi rename_global(ea_t ea);

  /// Rename a label.
  /// This function displays a dialog box and allows the user to rename
  /// a statement label.
  /// \return false if failed or cancelled
  /// \param label label number
  bool hexapi rename_label(int label);

  /// Process the Enter key.
  /// This function jumps to the definition of the item under the cursor.
  /// If the current item is a function, it will be decompiled.
  /// If the current item is a global data, its disassemly text will be displayed.
  /// \return false if failed
  /// \param idv what cursor must be used, the keyboard or the mouse
  /// \param omflags OM_NEWWIN: new pseudocode window will open, 0: reuse the existing window
  bool hexapi jump_enter(input_device_t idv, int omflags);

  /// Jump to disassembly.
  /// This function jumps to the address in the disassembly window
  /// which corresponds to the current item. The current item is determined
  /// based on the current keyboard cursor position.
  /// \return false if failed
  bool hexapi ctree_to_disasm();

  /// Check if the specified line can have a comment.
  /// Due to the coordinate system for comments:
  /// (https://hex-rays.com/blog/coordinate-system-for-hex-rays)
  /// some function lines cannot have comments. This function checks if a
  /// comment can be attached to the specified line.
  /// \return possible comment types
  /// \param lnnum line number (0 based)
  /// \param cmttype comment types to check
  cmt_type_t hexapi calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const;

  /// Edit an indented comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment for the specified ctree location.
  /// \return false if failed or cancelled
  /// \param loc comment location
  bool hexapi edit_cmt(const treeloc_t &loc);

  /// Edit a function comment.
  /// This function displays a dialog box and allows the user to edit
  /// the function comment.
  /// \return false if failed or cancelled
  bool hexapi edit_func_cmt();

  /// Delete all orphan comments.
  /// Delete all orphan comments and refresh the screen.
  /// \return true
  bool hexapi del_orphan_cmts();

  /// Change number base.
  /// This function changes the current number representation.
  /// \return false if failed
  /// \param base number radix (10 or 16)\n
  ///             0 means a character constant
  bool hexapi set_num_radix(int base);

  /// Convert number to symbolic constant.
  /// This function displays a dialog box and allows the user to select
  /// a symbolic constant to represent the number.
  /// \return false if failed or cancelled
  bool hexapi set_num_enum();

  /// Convert number to structure field offset.
  /// Currently not implemented.
  /// \return false if failed or cancelled
  bool hexapi set_num_stroff();

  /// Negate a number.
  /// This function negates the current number.
  /// \return false if failed.
  bool hexapi invert_sign();

  /// Bitwise negate a number.
  /// This function inverts all bits of the current number.
  /// \return false if failed.
  bool hexapi invert_bits();

  /// Collapse/uncollapse item.
  /// This function collapses the current item.
  /// \return false if failed.
  bool hexapi collapse_item(bool hide);

  /// Collapse/uncollapse local variable declarations.
  /// \return false if failed.
  bool hexapi collapse_lvars(bool hide);

  /// Split/unsplit item.
  /// This function splits the current assignment expression.
  /// \return false if failed.
  bool hexapi split_item(bool split);

};

//---------------------------------------------------------------------------
/// Select UDT for the operands using "Select offsets" widget

/// Operand represention
struct ui_stroff_op_t
{
  qstring text;   ///< any text for the column "Operand" of widget
  uval_t offset;  ///< operand offset, will be used when calculating the UDT path
  bool operator==(const ui_stroff_op_t &r) const
  {
    return text == r.text && offset == r.offset;
  }
  bool operator!=(const ui_stroff_op_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(ui_stroff_op_t);
typedef qvector<ui_stroff_op_t> ui_stroff_ops_t;

/// Callback to apply the selection
/// \return success
struct ui_stroff_applicator_t
{
  virtual ~ui_stroff_applicator_t() {}
  /// \param opnum   operand ordinal number, see below
  /// \param path    path describing the union selection, maybe empty
  /// \param top_tif tinfo_t of the selected toplevel UDT
  /// \param spath   selected path
  virtual bool idaapi apply(size_t opnum, const intvec_t &path, const tinfo_t &top_tif, const char *spath) = 0;
};

/// Select UDT
/// \param udts list of UDT tinfo_t for the selection,
///             if nullptr or empty then UDTs from the "Local types" will be used
/// \param ops  operands
/// \param applicator callback will be called to apply the selection for every operand
int hexapi select_udt_by_offset(
        const qvector<tinfo_t> *udts,
        const ui_stroff_ops_t &ops,
        ui_stroff_applicator_t &applicator);


#ifdef __NT__
#pragma warning(pop)
#endif
