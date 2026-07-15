/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef FUNCS_HPP
#define FUNCS_HPP
#include <functional>
#include <range.hpp>
#include <bytes.hpp>

/*! \file funcs.hpp

  \brief Routines for working with functions within the disassembled program.

  This file also contains routines for working with library signatures
  (e.g. FLIRT).

  Each function consists of function chunks. At least one function chunk
  must be present in the function definition - the function entry chunk.
  Other chunks are called function tails. There may be several of them
  for a function.

  A function tail is a continuous range of addresses.
  It can be used in the definition of one or more functions.
  One function using the tail is singled out and called the tail owner.
  This function is considered as 'possessing' the tail.
  get_func() on a tail address will return the function possessing the tail.
  You can enumerate the functions using the tail by using ::func_parent_iterator_t.

  Each function chunk in the disassembly is represented as an "range" (a range
  of addresses, see range.hpp for details) with characteristics.

  A function entry must start with an instruction (code) byte.
*/

struct stkpnt_t;                // #include <frame.hpp>
struct regvar_t;                // #include <frame.hpp>
struct llabel_core_t;
class insn_t;                   // #include <ua.hpp>

idaman void ida_export free_regarg(struct regarg_t *v);

struct regarg_t;
#define DECLARE_REGARG_T_HELPERS(decl)\
decl int ida_export regarg_t__compare(const regarg_t &l, const regarg_t &r); \

DECLARE_REGARG_T_HELPERS(idaman)

/// Register argument description.
/// regargs are destroyed when the full function type is determined.
struct regarg_t
{
  int reg = 0;
  type_t *type = nullptr;
  char *name = nullptr;

  regarg_t() {}
  regarg_t(const regarg_t &r) : reg(r.reg)
  {
    type = (type_t *)::qstrdup((char *)r.type);
    name = ::qstrdup(r.name);
  }
  ~regarg_t() { free_regarg(this); }
  regarg_t &operator=(const regarg_t &r)
  {
    if ( this != &r )
    {
      free_regarg(this);
      new (this) regarg_t(r);
    }
    return *this;
  }
  void swap(regarg_t &r)
  {
    std::swap(reg, r.reg);
    std::swap(type, r.type);
    std::swap(name, r.name);
  }

  DECLARE_COMPARISONS(regarg_t) { return regarg_t__compare(*this, r); }

  void serialize(bytevec_t *out) const
  {
    out->pack_dd(reg);
    out->pack_ds((char*)type);
    out->pack_ds(name);
  }
  bool deserialize(memory_deserializer_t &mmdsr)
  {
    reg  = mmdsr.unpack_dd();
    type = (type_t*)mmdsr.unpack_ds(true);
    name = mmdsr.unpack_ds(true);
    return true;
  }
  DECLARE_REGARG_T_HELPERS(friend)
};
DECLARE_TYPE_AS_MOVABLE(regarg_t);
typedef qvector<regarg_t> regargs_t;

//------------------------------------------------------------------------
/// A function is a set of continuous ranges of addresses with characteristics
class func_t : public range_t
{
public:
  uint64 flags;                        ///< \ref FUNC_
/// \defgroup FUNC_ Function flags
/// Used by func_t::flags
///@{
#define FUNC_NORET      0x00000001     ///< Function doesn't return
#define FUNC_FAR        0x00000002     ///< Far function
#define FUNC_LIB        0x00000004     ///< Library function

#define FUNC_STATICDEF  0x00000008     ///< Static function

#define FUNC_FRAME      0x00000010     ///< Function uses frame pointer (BP)
#define FUNC_USERFAR    0x00000020     ///< User has specified far-ness
                                       ///< of the function
#define FUNC_HIDDEN     0x00000040     ///< A hidden function chunk
#define FUNC_THUNK      0x00000080     ///< Thunk (jump) function
#define FUNC_BOTTOMBP   0x00000100     ///< BP points to the bottom of the stack frame
#define FUNC_NORET_PENDING 0x00200     ///< Function 'non-return' analysis must be performed.
                                       ///< This flag is verified upon func_does_return()
#define FUNC_SP_READY   0x00000400     ///< SP-analysis has been performed.
                                       ///< If this flag is on, the stack
                                       ///< change points should not be not
                                       ///< modified anymore. Currently this
                                       ///< analysis is performed only for PC
#define FUNC_FUZZY_SP   0x00000800     ///< Function changes SP in untraceable way,
                                       ///< for example: and esp, 0FFFFFFF0h
#define FUNC_PROLOG_OK  0x00001000     ///< Prolog analysis has been performed
                                       ///< by last SP-analysis
#define FUNC_PURGED_OK  0x00004000     ///< 'argsize' field has been validated.
                                       ///< If this bit is clear and 'argsize'
                                       ///< is 0, then we do not known the real
                                       ///< number of bytes removed from
                                       ///< the stack. This bit is handled
                                       ///< by the processor module.
#define FUNC_TAIL       0x00008000     ///< This is a function tail.
                                       ///< Other bits must be clear
                                       ///< (except #FUNC_HIDDEN).
#define FUNC_LUMINA     0x00010000     ///< Function info is provided by Lumina.
#define FUNC_OUTLINE    0x00020000     ///< Outlined code, not a real function.
#define FUNC_REANALYZE  0x00040000     ///< Function frame changed, request to
                                       ///< reanalyze the function after the last
                                       ///< insn is analyzed.
#define FUNC_UNWIND     0x00080000     ///< function is an exception unwind handler
#define FUNC_CATCH      0x00100000     ///< function is an exception catch handler

#define FUNC_RESERVED   0x8000000000000000LL ///< Reserved (for internal usage)
///@}

  /// Is a far function?
  bool is_far(void) const { return (flags & FUNC_FAR) != 0; }
  /// Does function return?
  bool does_return(void) const { return (flags & FUNC_NORET) == 0; }
  /// Has SP-analysis been performed?
  bool analyzed_sp(void) const { return (flags & FUNC_SP_READY) != 0; }
  /// Needs prolog analysis?
  bool need_prolog_analysis(void) const { return (flags & FUNC_PROLOG_OK) == 0; }
#ifndef SWIG
  union
  {
    /// attributes of a function entry chunk
    struct
    {
#endif // SWIG
      //
      // Stack frame of the function. It is represented as a structure:
      //
      //    +------------------------------------------------+
      //    | function arguments                             |
      //    +------------------------------------------------+
      //    | return address (isn't stored in func_t)        |
      //    +------------------------------------------------+
      //    | saved registers (SI, DI, etc - func_t::frregs) |
      //    +------------------------------------------------+ <- typical BP
      //    |                                                |  |
      //    |                                                |  | func_t::fpd
      //    |                                                |  |
      //    |                                                | <- real BP
      //    | local variables (func_t::frsize)               |
      //    |                                                |
      //    |                                                |
      //    +------------------------------------------------+ <- SP
      //
      uval_t frame;        ///< netnode id of frame structure - see frame.hpp
      asize_t frsize;      ///< size of local variables part of frame in bytes.
                           ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                           ///< (EBP) is assumed to point to the top of the local
                           ///< variables range.
      ushort frregs;       ///< size of saved registers in frame. This range is
                           ///< immediately above the local variables range.
      asize_t argsize;     ///< number of bytes purged from the stack
                           ///< upon returning
      asize_t fpd;         ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                           ///< use update_fpd() to modify it.

      bgcolor_t color;     ///< user defined function color

        // the following fields should not be accessed directly:

      uint32 pntqty;       ///< number of SP change points
      stkpnt_t *points;    ///< array of SP change points.
                           ///< use ...stkpnt...() functions to access this array.

      int regvarqty;       ///< number of register variables (-1-not read in yet)
                           ///< use find_regvar() to read register variables
      regvar_t *regvars;   ///< array of register variables.
                           ///< this array is sorted by: start_ea.
                           ///< use ...regvar...() functions to access this array.

      int llabelqty;       ///< number of local labels
      llabel_core_t *llabels; ///< local labels array.
                           ///< this array shouldn't be modified directly; name.hpp's
                           ///< SN_LOCAL should be used instead.

      int regargqty;       ///< number of register arguments.
                           ///< During analysis IDA tries to guess the register
                           ///< arguments. It stores store the guessing outcome
                           ///< in this field. As soon as it determines the final
                           ///< function prototype, regargqty is set to zero.
      regarg_t *regargs;   ///< unsorted array of register arguments.
                           ///< use ...regarg...() functions to access this array.
                           ///< regargs are destroyed when the full function
                           ///< type is determined.

      int tailqty;         ///< number of function tails
      range_t *tails;      ///< array of tails, sorted by ea.
                           ///< use func_tail_iterator_t to access function tails.
#ifndef SWIG
    };
    /// attributes of a function tail chunk
    struct
    {
#endif // SWIG
      ea_t owner;          ///< the address of the main function possessing this tail
      int refqty;          ///< number of referers
      ea_t *referers;      ///< array of referers (function start addresses).
                           ///< use func_parent_iterator_t to access the referers.
#ifndef SWIG
    };
  };
#endif // SWIG

  func_t(ea_t start=0, ea_t end=0, flags64_t f=0)
    : range_t(start, end), flags(f|FUNC_NORET_PENDING), frame(BADNODE),
      frsize(0), frregs(0), argsize(0), fpd(0), color(DEFCOLOR),
      pntqty(0), points(nullptr),
      regvarqty(0), regvars(nullptr),
      llabelqty(0), llabels(nullptr),
      regargqty(0), regargs(nullptr),
      tailqty(0), tails(nullptr)
  {
  }
#ifndef SWIG
  DECLARE_COMPARISONS(func_t);
#endif
};
DECLARE_TYPE_AS_MOVABLE(func_t);

/// Does function describe a function entry chunk?
/// \deprecated Use is_function_entry() for safer access.
DEPRECATED inline bool is_func_entry(const func_t *pfn) { return pfn != nullptr && (pfn->flags & FUNC_TAIL) == 0; }
/// Does function describe a function tail chunk?
/// \deprecated Use is_function_tail() for safer access.
DEPRECATED inline bool is_func_tail(const func_t *pfn) { return pfn != nullptr && (pfn->flags & FUNC_TAIL) != 0; }


/// Lock function pointer
/// Locked pointers are guaranteed to remain valid until they are unlocked.
/// Ranges with locked pointers cannot be deleted or moved.
/// \deprecated Use lock_func_range_ea() for safer access.

idaman DEPRECATED void ida_export lock_func_range(const func_t *pfn, bool lock);

/// Is the function pointer locked?
/// \deprecated Use is_func_locked_ea() for safer access.

idaman DEPRECATED bool ida_export is_func_locked(const func_t *pfn);

//--------------------------------------------------------------------
//      F U N C T I O N S
//--------------------------------------------------------------------
/// Get pointer to function structure by address.
/// \param ea  any address in a function
/// \return ptr to a function or nullptr.
/// This function returns a function entry chunk.
/// \deprecated Use get_func_start() or get_func_entry_info() for safer access.

idaman DEPRECATED func_t *ida_export get_func(ea_t ea);


/// Get the containing tail chunk of 'ea'.
/// \retval -1   means 'does not contain ea'
/// \retval  0   means the 'pfn' itself contains ea
/// \retval >0   the number of the containing function tail chunk
/// \deprecated Use get_func_chunknum_ea() for safer access.

idaman DEPRECATED int ida_export get_func_chunknum(func_t *pfn, ea_t ea);

/// Get pointer to function structure by number.
/// \param n  number of function, is in range 0..get_func_qty()-1
/// \return ptr to a function or nullptr.
/// This function returns a function entry chunk.
/// \deprecated Use get_func_ea_by_num() or get_func_entry_info_by_num() for safer access.

idaman DEPRECATED func_t *ida_export getn_func(size_t n);


/// Get total number of functions in the program

idaman size_t ida_export get_func_qty(void);


/// Get ordinal number of a function.
/// \param ea  any address in the function
/// \return number of function (0..get_func_qty()-1).
/// -1 means 'no function at the specified address'.

idaman int ida_export get_func_num(ea_t ea);


/// Get pointer to the previous function.
/// \param ea  any address in the program
/// \return ptr to function or nullptr if previous function doesn't exist
/// \deprecated Use get_prev_func_ea() for safer access.

idaman DEPRECATED func_t *ida_export get_prev_func(ea_t ea);


/// Get pointer to the next function.
/// \param ea  any address in the program
/// \return ptr to function or nullptr if next function doesn't exist
/// \deprecated Use get_next_func_ea() for safer access.

idaman DEPRECATED func_t *ida_export get_next_func(ea_t ea);


/// Get function ranges.
/// \param ranges buffer to receive the range info
/// \param pfn    ptr to function structure
/// \return end address of the last function range (BADADDR-error)
/// \deprecated Use get_func_ranges_ea() for safer access.

idaman DEPRECATED ea_t ida_export get_func_ranges(rangeset_t *ranges, func_t *pfn);


/// Get function comment.
/// \param buf         buffer for the comment
/// \param pfn         ptr to function structure
/// \param repeatable  get repeatable comment?
/// \return size of comment or -1
/// In fact this function works with function chunks too.
/// \deprecated Use get_func_cmt_ea() for safer access.

idaman DEPRECATED ssize_t ida_export get_func_cmt(qstring *buf, const func_t *pfn, bool repeatable);


/// Set function comment.
/// This function works with function chunks too.
/// \param pfn         ptr to function structure
/// \param cmt         comment string, may be multiline (with '\n').
///                    Use empty str ("") to delete comment
/// \param repeatable  set repeatable comment?
/// \deprecated Use set_func_cmt_ea() for safer access.

idaman DEPRECATED bool ida_export set_func_cmt(const func_t *pfn, const char *cmt, bool repeatable);


/// Update information about a function in the database (::func_t).
/// You must not change the function start and end addresses using this function.
/// Use set_func_start() and set_func_end() for it.
/// \param pfn         ptr to function structure
/// \return success
/// \deprecated Use set_func_entry_info() for safer access.

idaman DEPRECATED bool ida_export update_func(func_t *pfn);


/// Add a new function.
/// \deprecated Use add_function_ex() for safer access.
/// If the fn->end_ea is #BADADDR, then IDA will try to determine the
/// function bounds by calling find_func_bounds(..., #FIND_FUNC_DEFINE).
/// \param pfn  ptr to filled function structure
/// \return success

idaman DEPRECATED bool ida_export add_func_ex(func_t *pfn);


/// Delete a function.
/// \param ea  any address in the function entry chunk
/// \return success

idaman bool ida_export del_func(ea_t ea);


/// Move function chunk start address.
/// \param ea        any address in the function
/// \param newstart  new end address of the function
/// \return \ref MOVE_FUNC_

idaman int ida_export set_func_start(ea_t ea, ea_t newstart);
/// \defgroup MOVE_FUNC_ Function move result codes
/// Return values for set_func_start()
///@{
#define MOVE_FUNC_OK            0  ///< ok
#define MOVE_FUNC_NOCODE        1  ///< no instruction at 'newstart'
#define MOVE_FUNC_BADSTART      2  ///< bad new start address
#define MOVE_FUNC_NOFUNC        3  ///< no function at 'ea'
#define MOVE_FUNC_REFUSED       4  ///< a plugin refused the action
///@}


/// Move function chunk end address.
/// \param ea      any address in the function
/// \param newend  new end address of the function
/// \return success

idaman bool ida_export set_func_end(ea_t ea, ea_t newend);


/// Reanalyze a function.
/// This function plans to analyzes all chunks of the given function.
/// Optional parameters (ea1, ea2) may be used to narrow the analyzed range.
/// \param pfn              pointer to a function
/// \param ea1              start of the range to analyze
/// \param ea2              end of range to analyze
/// \param analyze_parents  meaningful only if pfn points to a function tail.
///                         if true, all tail parents will be reanalyzed.
///                         if false, only the given tail will be reanalyzed.
/// \deprecated Use reanalyze_function_ea() for safer access.

idaman DEPRECATED void ida_export reanalyze_function(
        func_t *pfn,
        ea_t ea1=0,
        ea_t ea2=BADADDR,
        bool analyze_parents=false);


/// Determine the boundaries of a new function.
/// \deprecated Use find_function_bounds() for safer access.
/// This function tries to find the start and end addresses of a new function.
/// It calls the module with \ph{func_bounds} in order to fine tune
/// the function boundaries.
/// \param nfn    structure to fill with information
/// \             nfn->start_ea points to the start address of the new function.
/// \param flags  \ref FIND_FUNC_F
/// \return \ref FIND_FUNC_R

idaman DEPRECATED int ida_export find_func_bounds(func_t *nfn, int flags);

/// \defgroup FIND_FUNC_F Find function bounds flags
/// Passed as 'flags' parameter to find_func_bounds() and find_function_bounds()
///@{
#define FIND_FUNC_NORMAL   0x0000 ///< stop processing if undefined byte is encountered
#define FIND_FUNC_DEFINE   0x0001 ///< create instruction if undefined byte is encountered
#define FIND_FUNC_IGNOREFN 0x0002 ///< ignore existing function boundaries.
                                  ///< by default the function returns function boundaries
                                  ///< if ea belongs to a function.
#define FIND_FUNC_KEEPBD   0x0004 ///< do not modify incoming function boundaries,
                                  ///< just create instructions inside the boundaries.
///@}

/// \defgroup FIND_FUNC_R Find function bounds result codes
/// Return values for find_func_bounds() and find_function_bounds()
///@{
#define FIND_FUNC_UNDEF 0         ///< function has instructions that pass execution flow to unexplored bytes.
                                  ///< nfn->end_ea will have the address of the unexplored byte.
#define FIND_FUNC_OK    1         ///< ok, 'nfn' is ready for add_func()
#define FIND_FUNC_EXIST 2         ///< function exists already.
                                  ///< its bounds are returned in 'nfn'.
///@}


/// Get function name.
/// \param out      buffer for the answer
/// \param ea       any address in the function
/// \return length of the function name

idaman ssize_t ida_export get_func_name(qstring *out, ea_t ea);


/// Calculate function size.
/// This function takes into account all fragments of the function.
/// \param pfn    ptr to function structure
/// \deprecated Use calc_func_size_ea() for safer access.

idaman DEPRECATED asize_t ida_export calc_func_size(func_t *pfn);


/// Get function bitness (which is equal to the function segment bitness).
/// pfn==nullptr => returns 0
/// \retval 0  16
/// \retval 1  32
/// \retval 2  64
/// \deprecated Use get_func_bitness_ea() for safer access.

idaman DEPRECATED int ida_export get_func_bitness(const func_t *pfn);

/// Set visibility of function
/// \deprecated Use set_visible_func_ea() for safer access.

idaman DEPRECATED void ida_export set_visible_func(func_t *pfn, bool visible);


/// Give a meaningful name to function if it consists of only 'jump' instruction.
/// \param pfn      pointer to function (may be nullptr)
/// \param oldname  old name of function.
///                 if old name was in "j_..." form, then we may discard it
///                 and set a new name.
///                 if oldname is not known, you may pass nullptr.
/// \return success
/// \deprecated Use set_function_name_if_jumpfunc() for safer access.

idaman DEPRECATED int ida_export set_func_name_if_jumpfunc(func_t *pfn, const char *oldname);


/// Calculate target of a thunk function.
/// \param pfn   pointer to function (may not be nullptr)
/// \param fptr  out: will hold address of a function pointer (if indirect jump)
/// \return the target function or #BADADDR
/// \deprecated Use calc_thunk_function_target() for safer access.

idaman DEPRECATED ea_t ida_export calc_thunk_func_target(func_t *pfn, ea_t *fptr);


/// Does the function return?
/// To calculate the answer, #FUNC_NORET flag and is_noret() are consulted
/// The latter is required for imported functions in the .idata section.
/// Since in .idata we have only function pointers but not functions, we have
/// to introduce a special flag for them.

idaman bool ida_export func_does_return(ea_t callee);


/// Plan to reanalyze noret flag.
/// This function does not remove FUNC_NORET if it is already present.
/// It just plans to reanalysis.

idaman bool ida_export reanalyze_noret_flag(ea_t ea);


/// Signal a non-returning instruction.
/// This function can be used by the processor module to tell the kernel
/// about non-returning instructions (like call exit). The kernel will
/// perform the global function analysis and find out if the function
/// returns at all. This analysis will be done at the first call to func_does_return()
/// \return true if the instruction 'noret' flag has been changed

idaman bool ida_export set_noret_insn(ea_t insn_ea, bool noret);


//--------------------------------------------------------------------
//      F U N C T I O N   C H U N K S
//--------------------------------------------------------------------
/// Get pointer to function chunk structure by address.
/// \param ea  any address in a function chunk
/// \return ptr to a function chunk or nullptr.
///         This function may return a function entry as well as a function tail.
/// \deprecated Use get_fchunk_start() or get_fchunk_info() for safer access.

idaman DEPRECATED func_t *ida_export get_fchunk(ea_t ea);


/// Get pointer to function chunk structure by number.
/// \param n  number of function chunk, is in range 0..get_fchunk_qty()-1
/// \return ptr to a function chunk or nullptr.
///         This function may return a function entry as well as a function tail.
/// \deprecated Use get_fchunk_ea_by_num() for safer access.

idaman DEPRECATED func_t *ida_export getn_fchunk(int n);


/// Get total number of function chunks in the program

idaman size_t ida_export get_fchunk_qty(void);


/// Get ordinal number of a function chunk in the global list of function chunks.
/// \param ea  any address in the function chunk
/// \return number of function chunk (0..get_fchunk_qty()-1).
///         -1 means 'no function chunk at the specified address'.

idaman int ida_export get_fchunk_num(ea_t ea);


/// Get pointer to the previous function chunk in the global list.
/// \param ea  any address in the program
/// \return ptr to function chunk or nullptr if previous function chunk doesn't exist
/// \deprecated Use get_prev_fchunk_ea() for safer access.

idaman DEPRECATED func_t *ida_export get_prev_fchunk(ea_t ea);


/// Get pointer to the next function chunk in the global list.
/// \param ea  any address in the program
/// \return ptr to function chunk or nullptr if next function chunk doesn't exist
/// \deprecated Use get_next_fchunk_ea() for safer access.

idaman DEPRECATED func_t *ida_export get_next_fchunk(ea_t ea);


//--------------------------------------------------------------------
// Functions to manipulate function chunks

/// Append a new tail chunk to the function definition.
/// If the tail already exists, then it will simply be added to the function tail list
/// Otherwise a new tail will be created and its owner will be set to be our function
/// If a new tail cannot be created, then this function will fail.
/// \param pfn  pointer to the function
/// \param ea1  start of the tail. If a tail already exists at the specified address
///             it must start at 'ea1'
/// \param ea2  end of the tail. If a tail already exists at the specified address
///             it must end at 'ea2'. If specified as BADADDR, IDA will determine
///             the end address itself.
/// \deprecated Use append_func_tail_ea() for safer access.

idaman DEPRECATED bool ida_export append_func_tail(func_t *pfn, ea_t ea1, ea_t ea2);


/// Remove a function tail.
/// If the tail belongs only to one function, it will be completely removed.
/// Otherwise if the function was the tail owner, the first function using
/// this tail becomes the owner of the tail.
/// \param pfn  pointer to the function
/// \param tail_ea any address inside the tail to remove
/// \deprecated Use remove_func_tail_ea() for safer access.

idaman DEPRECATED bool ida_export remove_func_tail(func_t *pfn, ea_t tail_ea);


/// Set a new owner of a function tail.
/// The new owner function must be already referring to the tail (after append_func_tail).
/// \param fnt  pointer to the function tail
/// \param new_owner the entry point of the new owner function
/// \deprecated Use set_tail_owner_ea() for safer access.

idaman DEPRECATED bool ida_export set_tail_owner(func_t *fnt, ea_t new_owner);


//--------------------------------------------------------------------
/// \name
/// Functions to work with temporary register argument definitions
///@{
idaman void ida_export read_regargs(func_t *pfn);
/// \deprecated Use add_func_regarg() for safer access.
idaman DEPRECATED void ida_export add_regarg(func_t *pfn, int reg, const tinfo_t &tif, const char *name);
///@}

//--------------------------------------------------------------------
//      L I B R A R Y   M O D U L E   S I G N A T U R E S
//--------------------------------------------------------------------

/// \defgroup IDASGN_ Error codes for signature functions:
/// See calc_idasgn_state() and del_idasgn()
///@{
#define IDASGN_OK       0       ///< ok
#define IDASGN_BADARG   1       ///< bad number of signature
#define IDASGN_APPLIED  2       ///< signature is already applied
#define IDASGN_CURRENT  3       ///< signature is currently being applied
#define IDASGN_PLANNED  4       ///< signature is planned to be applied
///@}

/// Add a signature file to the list of planned signature files.
/// \param fname  file name. should not contain directory part.
/// \return 0 if failed, otherwise number of planned (and applied) signatures

idaman int ida_export plan_to_apply_idasgn(const char *fname); // plan to use library


/// Apply a signature file to the specified address.
/// \param signame     short name of signature file (the file name without path)
/// \param ea          address to apply the signature
/// \param is_startup  if set, then the signature is treated as a startup one
///                    for startup signature ida doesn't rename the first
///                    function of the applied module.
/// \return \ref LIBFUNC_

idaman int ida_export apply_idasgn_to(const char *signame, ea_t ea, bool is_startup);


/// Get number of signatures in the list of planned and applied signatures.
/// \return 0..n

idaman int ida_export get_idasgn_qty(void);


/// Get number of the current signature.
/// \return 0..n-1

idaman int ida_export get_current_idasgn(void);


/// Get state of a signature in the list of planned signatures
/// \param n  number of signature in the list (0..get_idasgn_qty()-1)
/// \return state of signature or #IDASGN_BADARG

idaman int ida_export calc_idasgn_state(int n);


/// Remove signature from the list of planned signatures.
/// \param n  number of signature in the list (0..get_idasgn_qty()-1)
/// \return #IDASGN_OK, #IDASGN_BADARG, #IDASGN_APPLIED

idaman int ida_export del_idasgn(int n);


/// Get information about a signature in the list.
/// \param signame      buffer for the name of the signature.
///                     (short form, only base name without the directory part
///                      will be stored).
///                     if signame == nullptr, then the name won't be returned.
/// \param optlibs      buffer for the names of the optional libraries
///                     if optlibs == nullptr, then the optional libraries are not returned
/// \param n            number of signature in the list (0..get_idasgn_qty()-1)
/// \return number of successfully recognized modules using this signature.
///          -1 means the 'n' is a bad argument, i.e. no signature with this
///              number exists..

idaman int32 ida_export get_idasgn_desc(
        qstring *signame,
        qstring *optlibs,
        int n);

/// Get full description of the signature by its short name.
/// \param buf      the output buffer
/// \param name     short name of a signature
/// \return size of signature description or -1

idaman ssize_t ida_export get_idasgn_title(
        qstring *buf,
        const char *name);

/// Determine compiler/vendor using the startup signatures.
/// If determined, then appropriate signature files are included into
/// the list of planned signature files.

idaman void ida_export determine_rtl(void);


/// Apply a startup signature file to the specified address.
/// \param ea       address to apply the signature to; usually \inf{start_ea}
/// \param startup  the name of the signature file without path and extension
/// \return true if successfully applied the signature

idaman bool ida_export apply_startup_sig(ea_t ea, const char *startup);


/// Apply the currently loaded signature file to the specified address.
/// If a library function is found, then create a function and name
/// it accordingly.
/// \param ea  any address in the program
/// \return \ref LIBFUNC_

idaman int ida_export try_to_add_libfunc(ea_t ea);


/// \defgroup LIBFUNC_ Library function codes
/// Return values for try_to_add_libfunc() and apply_idasgn_to()
///@{
#define LIBFUNC_FOUND   0               ///< ok, library function is found
#define LIBFUNC_NONE    1               ///< no, this is not a library function
#define LIBFUNC_DELAY   2               ///< no decision because of lack of information
///@}

//--------------------------------------------------------------------
//      E A - B A S E D   F U N C T I O N   A P I
//--------------------------------------------------------------------

/// \defgroup ea_func_api ea-based function API
/// These functions use ea_t instead of func_t pointers, avoiding
/// pointer-lifetime issues. The pointer can be invalidated by del_func(),
/// add_func(), set_func_start/end(), undo operations, and recursive
/// IDB event callbacks.
///@{

/// \name ea-based navigation
/// Get function/chunk addresses without using pointers.
///@{

/// Get start address of the function containing 'ea'.
/// If ea is in a tail chunk, returns the owning function's start address.
/// \param ea  any address in a function
/// \return function start_ea, or BADADDR if no function at ea

idaman ea_t ida_export get_func_start(ea_t ea);


/// Get start address of the previous function.
/// \param ea  any address in the program
/// \return previous function start_ea, or BADADDR if none

idaman ea_t ida_export get_prev_func_ea(ea_t ea);


/// Get start address of the next function.
/// \param ea  any address in the program
/// \return next function start_ea, or BADADDR if none

idaman ea_t ida_export get_next_func_ea(ea_t ea);


/// Get start address of the function chunk containing 'ea'.
/// Unlike get_func_start(), does not follow tail owners.
/// \param ea  any address in a function chunk
/// \return chunk start_ea, or BADADDR if no chunk at ea

idaman ea_t ida_export get_fchunk_start(ea_t ea);


/// Get start address of the previous function chunk.
/// \param ea  any address in the program
/// \return previous chunk start_ea, or BADADDR if none

idaman ea_t ida_export get_prev_fchunk_ea(ea_t ea);


/// Get start address of the next function chunk.
/// \param ea  any address in the program
/// \return next chunk start_ea, or BADADDR if none

idaman ea_t ida_export get_next_fchunk_ea(ea_t ea);


/// Get function start address by ordinal number.
/// \param n  number of function, is in range 0..get_func_qty()-1
/// \return function start_ea, or BADADDR if n is out of range

idaman ea_t ida_export get_func_ea_by_num(size_t n);


/// Get function chunk start address by ordinal number.
/// \param n  number of function chunk, is in range 0..get_fchunk_qty()-1
/// \return chunk start_ea, or BADADDR if n is out of range

idaman ea_t ida_export get_fchunk_ea_by_num(int n);

///@}

/// \name ea-based property accessors
/// Read/write function properties by address.
///@{

/// Get function chunk flags.
/// \param ea  any address in a function chunk
/// \return flags, or 0 if no chunk at ea

idaman uint64 ida_export get_func_flags(ea_t ea);


/// Is the function visible (not hidden)?

inline bool is_visible_func(ea_t ea)
{
  return get_func_start(ea) != BADADDR && (get_func_flags(ea) & FUNC_HIDDEN) == 0;
}


/// Is the function visible (event after considering #SCF_SHHID_FUNC)?
inline bool is_finally_visible_func(ea_t ea)
{
  return (inf_get_cmtflg() & SCF_SHHID_FUNC) != 0 || is_visible_func(ea);
}


/// Is the function visible (not hidden)?
/// \deprecated
DEPRECATED inline bool is_visible_func(func_t *pfn) { return pfn != nullptr && is_visible_func(pfn->start_ea); }


/// Is the function visible (event after considering #SCF_SHHID_FUNC)?
/// \deprecated
DEPRECATED inline bool is_finally_visible_func(func_t *pfn) { return pfn != nullptr && is_finally_visible_func(pfn->start_ea); }


/// Set function chunk flags.
/// \param ea     start address of the function chunk
/// \param flags  new flags value
/// \return success

idaman bool ida_export set_func_flags(ea_t ea, uint64 flags);


/// Set or clear a single function chunk flag.
/// \param ea     start address of the function chunk
/// \param flag   flag bit(s) to modify (e.g. #FUNC_NORET)
/// \param on_off true to set, false to clear
/// \return success

idaman bool ida_export set_func_flag(ea_t ea, uint64 flag, bool on_off=true);


/// Is there a function entry chunk at 'ea'?

idaman bool ida_export is_function_entry(ea_t ea);


/// Is there a function tail chunk at 'ea'?

idaman bool ida_export is_function_tail(ea_t ea);


/// Get the owner function of a tail chunk.
/// \param tail_ea  any address inside the tail chunk
/// \return owner function start_ea, or BADADDR if not a tail

idaman ea_t ida_export get_tail_owner(ea_t tail_ea);


///@}

/// \name ea-based wrappers
/// ea_t versions of functions that previously required func_t pointers.
///@{

/// Get function comment by address.
/// \param buf         buffer for the comment
/// \param ea          any address in a function chunk
/// \param repeatable  get repeatable comment?
/// \return size of comment or -1

idaman ssize_t ida_export get_func_cmt_ea(qstring *buf, ea_t ea, bool repeatable);


/// Set function comment by address.
/// \param ea          any address in a function chunk
/// \param cmt         comment string, may be multiline (with '\\n').
///                    Use empty str ("") to delete comment
/// \param repeatable  set repeatable comment?
/// \return success

idaman bool ida_export set_func_cmt_ea(ea_t ea, const char *cmt, bool repeatable);


/// Get function bitness by address.
/// \param ea  any address in a function
/// \retval 0  16bit or if no function at ea
/// \retval 1  32bit
/// \retval 2  64bit

idaman int ida_export get_func_bitness_ea(ea_t ea);


/// Get number of bits in the function addressing
inline int idaapi get_func_bits_ea(ea_t ea)
{
  return 1 << (get_func_bitness_ea(ea)+4);
}


/// Get number of bytes in the function addressing
inline int idaapi get_func_bytes_ea(ea_t ea)
{
  return get_func_bits_ea(ea)/8;
}


/// Get number of bits in the function addressing
/// \deprecated
DEPRECATED inline int idaapi get_func_bits(const func_t *pfn) { return pfn != nullptr ? get_func_bits_ea(pfn->start_ea) : 16; }


/// Get number of bytes in the function addressing
/// \deprecated
DEPRECATED inline int idaapi get_func_bytes(const func_t *pfn) { return pfn != nullptr ? get_func_bytes_ea(pfn->start_ea) : 2; }


/// Calculate function size by address.
/// This function takes into account all fragments of the function.
/// \param ea  any address in a function
/// \return total function size, or 0 if no function at ea

idaman asize_t ida_export calc_func_size_ea(ea_t ea);


/// Get function ranges by address.
/// \param ranges  buffer to receive the range info
/// \param ea      any address in a function
/// \return end address of the last function range (BADADDR-error)

idaman ea_t ida_export get_func_ranges_ea(rangeset_t *ranges, ea_t ea);


/// Set function visibility by address.
/// \param ea       any address in a function
/// \param visible  new visibility state

idaman void ida_export set_visible_func_ea(ea_t ea, bool visible);


/// Give a meaningful name to function if it consists of only 'jump' instruction.
/// \param func_ea  start address of the function (may be BADADDR)
/// \param oldname  old name of function.
///                 if old name was in "j_..." form, then we may discard it
///                 and set a new name.
///                 if oldname is not known, you may pass nullptr.
/// \return success

idaman bool ida_export set_function_name_if_jumpfunc(ea_t func_ea, const char *oldname);


/// Reanalyze function by address.
/// This function plans to analyze all chunks of the given function.
/// Optional parameters (ea1, ea2) may be used to narrow the analyzed range.
/// \param func_ea          start address of the function
/// \param ea1              start of the range to analyze
/// \param ea2              end of range to analyze
/// \param analyze_parents  meaningful only if func_ea points to a function tail.
///                         if true, all tail parents will be reanalyzed.
///                         if false, only the given tail will be reanalyzed.

idaman void ida_export reanalyze_function_ea(
        ea_t func_ea,
        ea_t ea1=0,
        ea_t ea2=BADADDR,
        bool analyze_parents=false);


/// Add a temporary register argument definition.
/// \param func_ea  start address of the function
/// \param reg      register number
/// \param tif      type of the register argument
/// \param name     name of the register argument

idaman void ida_export add_func_regarg(ea_t func_ea, int reg, const tinfo_t &tif, const char *name);


/// Get the number of register arguments for a function.
/// Register arguments are transient: they are destroyed when the full function
/// type is determined. This function ensures they are loaded before returning.
/// \param func_ea  function start address
/// \return number of register arguments, or 0

idaman size_t ida_export get_func_regarg_qty(ea_t func_ea);


/// Get a register argument by index.
/// Register arguments are transient: they are destroyed when the full function
/// type is determined. This function ensures they are loaded before returning.
/// \param out      output regarg_t (caller owns memory, use free_regarg to clean up)
/// \param func_ea  function start address
/// \param n        0-based index
/// \return success

idaman bool ida_export get_func_regarg(regarg_t *out, ea_t func_ea, size_t n);


/// Get all register arguments for a function.
/// Register arguments are transient: they are destroyed when the full function
/// type is determined. This function ensures they are loaded before returning.
/// \param out      output vector of regarg_t
/// \param func_ea  function start address
/// \return success

idaman bool ida_export get_func_regargs(regargs_t *out, ea_t func_ea);

///@}

/// \name ea-based chunk manipulation
/// Manipulate function tail chunks using addresses instead of pointers.
///@{

/// Append a new tail chunk to the function at func_ea.
/// If the tail already exists, then it will simply be added to the function tail list.
/// Otherwise a new tail will be created and its owner will be set to the function.
/// If a new tail cannot be created, then this function will fail.
/// \param func_ea  start address of the function
/// \param ea1      start of the tail
/// \param ea2      end of the tail

idaman bool ida_export append_func_tail_ea(ea_t func_ea, ea_t ea1, ea_t ea2);


/// Remove a function tail.
/// If the tail belongs only to one function, it will be completely removed.
/// Otherwise if the function was the tail owner, the first function using
/// this tail becomes the owner of the tail.
/// \param func_ea  start address of the function
/// \param tail_ea  any address inside the tail to remove

idaman bool ida_export remove_func_tail_ea(ea_t func_ea, ea_t tail_ea);


/// Set a new owner of a function tail.
/// The new owner function must be already referring to the tail (after append_func_tail).
/// \param tail_ea    any address inside the tail
/// \param new_owner  the entry point of the new owner function

idaman bool ida_export set_tail_owner_ea(ea_t tail_ea, ea_t new_owner);


/// Get the containing chunk number.
/// \param func_ea  start address of the function
/// \param ea       address to check
/// \retval -1   does not contain ea
/// \retval  0   the entry chunk contains ea
/// \retval >0   the number of the containing function tail chunk

idaman int ida_export get_func_chunknum_ea(ea_t func_ea, ea_t ea);


/// Get the number of function tail chunks.
/// \param func_ea  function start address
/// \return number of tail chunks, or 0

idaman size_t ida_export get_func_tail_qty(ea_t func_ea);


/// Get all function tail ranges.
/// \param out      output vector of ranges
/// \param func_ea  function start address
/// \return success

idaman bool ida_export get_func_tails(rangevec_t *out, ea_t func_ea);


/// Does the function at func_ea contain ea?
inline bool function_contains(ea_t func_ea, ea_t ea)
{
  return get_func_chunknum_ea(func_ea, ea) >= 0;
}


/// Do two addresses belong to the same function?
inline bool is_same_func(ea_t ea1, ea_t ea2) { return function_contains(ea1, ea2); }


/// Do two addresses belong to the same function chunk?
/// \param ea1  first address
/// \param ea2  second address
/// \return true if both addresses are in the same chunk

idaman bool ida_export is_same_fchunk(ea_t ea1, ea_t ea2);


/// Does the given function contain the given address?
/// \deprecated Use function_contains() for safer access.
DEPRECATED inline bool func_contains(func_t *pfn, ea_t ea) { return pfn != nullptr && function_contains(pfn->start_ea, ea); }


/// Callback type for iterate_func_chunks_ea().
/// \param chunk_start  start address of the chunk
/// \param chunk_end    end address of the chunk (exclusive)
typedef std::function<void(ea_t chunk_start, ea_t chunk_end)> func_chunk_visitor_t;


/// Function to iterate function chunks (all of them including the entry chunk)
/// \param fchunk_ea        address inside of the function chunk
/// \param visitor          callback to invoke for each chunk
/// \param include_parents  meaningful only if FCHUNK_EA points to a function tail.
///                         if true, all tail parents will be iterated.
///                         if false, only the given tail will be iterated.

idaman void ida_export iterate_func_chunks_ea(
        ea_t fchunk_ea,
        const func_chunk_visitor_t &visitor,
        bool include_parents=false);


/// Get previous address belonging to the function, respecting linear ordering.
/// Unlike function_item_iterator_t which always enumerates the main function
/// chunk first, this function respects linear address ordering.
/// \param func_ea  any address of the function
/// \param ea       current address
/// \return previous address in the function, or BADADDR if none

idaman ea_t ida_export get_prev_function_addr(ea_t func_ea, ea_t ea);


/// Get next address belonging to the function, respecting linear ordering.
/// Unlike function_item_iterator_t which always enumerates the main function
/// chunk first, this function respects linear address ordering.
/// \param func_ea  any address of the function
/// \param ea       current address
/// \return next address in the function, or BADADDR if none

idaman ea_t ida_export get_next_function_addr(ea_t func_ea, ea_t ea);

///@}

/// \name ea-based locking
/// Lock function ranges by address to prevent invalidation.
///@{

/// Lock function range by address.
/// Locked ranges are guaranteed to remain valid until they are unlocked.
/// Ranges with locked pointers cannot be deleted or moved.
/// \param ea    any address in a function chunk
/// \param lock  true to lock, false to unlock

idaman void ida_export lock_func_range_ea(ea_t ea, bool lock);


/// Is the function at ea locked?
/// \param ea  any address in a function chunk

idaman bool ida_export is_func_locked_ea(ea_t ea);


/// RAII helper to lock a function by address.
class lock_func_ea
{
  ea_t func_ea;
public:
  lock_func_ea(ea_t ea) : func_ea(ea) { lock_func_range_ea(ea, true); }
  ~lock_func_ea() { lock_func_range_ea(func_ea, false); }
};

/// Helper class to lock a function pointer so it stays valid
/// \deprecated Use lock_func_ea instead.
class DEPRECATED lock_func
{
  ea_t ea = BADADDR;
public:
  lock_func(const func_t *pfn)
  {
    if ( pfn != nullptr )
    {
      ea = pfn->start_ea;
      lock_func_range_ea(ea, true);
    }
  }
  ~lock_func(void)
  {
    if ( ea != BADADDR )
      lock_func_range_ea(ea, false);
  }
};

//lint -esym(1788, lock_func_with_tails_t) referenced only by ctr/dtr
class lock_func_with_tails_t
{
  rangeset_t func_ranges;
  void lock_ranges(bool lock)
  {
    for ( const auto &r : func_ranges )
      lock_func_range_ea(r.start_ea, lock);
  }

public:
  /// \deprecated
  DEPRECATED lock_func_with_tails_t(func_t *pfn)
  {
    if ( pfn != nullptr )
    {
      get_func_ranges_ea(&func_ranges, pfn->start_ea);
      lock_ranges(true);
    }
  }
  lock_func_with_tails_t(ea_t ea)
  {
    get_func_ranges_ea(&func_ranges, ea);
    lock_ranges(true);
  }
  ~lock_func_with_tails_t() { lock_ranges(false); }
};

///@}


//--------------------------------------------------------------------
// I T E R A T O R S

// Auxiliary function(s) to be used in func_..._iterator_t

class func_parent_iterator_t;
class func_tail_iterator_t;
class func_item_iterator_t;
class function_tail_iterator_t;
class function_parent_iterator_t;
class function_item_iterator_t;

/// Declare helper functions for ::func_item_iterator_t
#define DECLARE_FUNC_ITERATORS(prefix) \
prefix bool ida_export func_tail_iterator_set(func_tail_iterator_t *fti, func_t *pfn, ea_t ea);\
prefix bool ida_export func_tail_iterator_set_ea(func_tail_iterator_t *fti, ea_t ea);\
prefix bool ida_export func_parent_iterator_set(func_parent_iterator_t *fpi, func_t *pfn);\
prefix bool ida_export func_item_iterator_next(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_prev(func_item_iterator_t *fii, testf_t *testf, void *ud);\
prefix bool ida_export func_item_iterator_decode_prev_insn(func_item_iterator_t *fii, insn_t *out); \
prefix bool ida_export func_item_iterator_decode_preceding_insn(func_item_iterator_t *fii, eavec_t *visited, bool *p_farref, insn_t *out); \
prefix bool ida_export func_item_iterator_succ(func_item_iterator_t *fii, testf_t *testf, void *ud); \
prefix bool ida_export function_tail_iterator_set(function_tail_iterator_t *fti, ea_t func_ea, ea_t ea); \
prefix bool ida_export function_tail_iterator_set_ea(function_tail_iterator_t *fti, ea_t ea); \
prefix bool ida_export function_tail_iterator_set_range(function_tail_iterator_t *fti, ea_t ea1, ea_t ea2); \
prefix void ida_export function_tail_iterator_chunk(range_t *out, const function_tail_iterator_t *fti); \
prefix bool ida_export function_tail_iterator_first(function_tail_iterator_t *fti); \
prefix bool ida_export function_tail_iterator_last(function_tail_iterator_t *fti); \
prefix bool ida_export function_tail_iterator_next(function_tail_iterator_t *fti); \
prefix bool ida_export function_tail_iterator_prev(function_tail_iterator_t *fti); \
prefix bool ida_export function_tail_iterator_main(function_tail_iterator_t *fti); \
prefix bool ida_export function_parent_iterator_set(function_parent_iterator_t *fpi, ea_t tail_ea); \
prefix ea_t ida_export function_parent_iterator_parent(const function_parent_iterator_t *fpi); \
prefix bool ida_export function_parent_iterator_first(function_parent_iterator_t *fpi); \
prefix bool ida_export function_parent_iterator_last(function_parent_iterator_t *fpi); \
prefix bool ida_export function_parent_iterator_next(function_parent_iterator_t *fpi); \
prefix bool ida_export function_parent_iterator_prev(function_parent_iterator_t *fpi); \
prefix bool ida_export function_item_iterator_next(function_item_iterator_t *fii, testf_t *testf, void *ud); \
prefix bool ida_export function_item_iterator_prev(function_item_iterator_t *fii, testf_t *testf, void *ud); \
prefix bool ida_export function_item_iterator_succ(function_item_iterator_t *fii, testf_t *testf, void *ud); \
prefix bool ida_export function_item_iterator_decode_prev_insn(function_item_iterator_t *fii, insn_t *out); \
prefix bool ida_export function_item_iterator_decode_preceding_insn(function_item_iterator_t *fii, eavec_t *visited, bool *p_farref, insn_t *out); \

DECLARE_FUNC_ITERATORS(idaman)

/// Helper function to accept any address
inline THREAD_SAFE bool idaapi f_any(flags64_t, void *) { return true; }

/// Class to enumerate all function tails sorted by addresses.
/// Enumeration is started with main(), first(), or last().
/// If first() is used, the function entry chunk will be excluded from the enumeration.
/// Otherwise it will be included in the enumeration (for main() and last()).
/// The loop may continue until the next() or prev() function returns false.
/// These functions return false when the enumeration is over.
/// The tail chunks are always sorted by their addresses.
///
/// Sample code:
/// \code
///      func_tail_iterator_t fti(pfn);
///      for ( bool ok=fti.first(); ok; ok=fti.next() )
///        const range_t &a = fti.chunk();
///        ....
/// \endcode
///
/// If the 'ea' parameter is used in the constructor, then the iterator is positioned
/// at the chunk containing the specified 'ea'. Otherwise it is positioned at the
/// function entry chunk.
/// If 'pfn' is specified as nullptr then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// The function main chunk is locked during the iteration.
/// It is also possible to enumerate one single arbitrary range using set_range()
/// This function is mainly designed to be used from ::func_item_iterator_t.
/// \deprecated Use function_tail_iterator_t for safer ea-based access.
class DEPRECATED func_tail_iterator_t
{
  friend struct kdata_t;
  friend class func_item_iterator_t;
  func_t *pfn;
  int idx;
  range_t seglim;        // valid and used only if pfn == nullptr
public:
  func_tail_iterator_t(void) : pfn(nullptr), idx(-1) {}
  func_tail_iterator_t(func_t *_pfn, ea_t ea=BADADDR) : pfn(nullptr) { set(_pfn, ea); }
  ~func_tail_iterator_t(void)
  {
    // if was iterating over function chunks, unlock the main chunk
    if ( pfn != nullptr )
      lock_func_range_ea(pfn->start_ea, false);
  }
  bool set(func_t *_pfn, ea_t ea=BADADDR) { return func_tail_iterator_set(this, _pfn, ea); }
  bool set_ea(ea_t ea) { return func_tail_iterator_set_ea(this, ea); }
  // set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2)
  {
    this->~func_tail_iterator_t();
    pfn = nullptr;
    idx = -1;
    seglim = range_t(ea1, ea2);
    return !seglim.empty();
  }
  const range_t &chunk(void) const
  {
    if ( pfn == nullptr )
      return seglim;
    return idx >= 0 && idx < pfn->tailqty ? pfn->tails[idx] : *(range_t*)pfn;
  }
  bool first(void) { if ( pfn != nullptr ) { idx = 0; return pfn->tailqty > 0; } return false; } // get only tail chunks
  bool last(void) { if ( pfn != nullptr ) { idx = pfn->tailqty - 1; return true; } return false; }  // get all chunks (the entry chunk last)
  bool next(void) { if ( pfn != nullptr && idx+1 < pfn->tailqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx >= 0 ) { idx--; return true; } return false; }
  bool main(void) { idx = -1; return pfn != nullptr; }  // get all chunks (the entry chunk first)
};


/// Function to iterate function chunks (all of them including the entry chunk)
/// \param pfn              pointer to the function
/// \param func             function to call for each chunk
/// \param ud               user data for 'func'
/// \param include_parents  meaningful only if pfn points to a function tail.
///                         if true, all tail parents will be iterated.
///                         if false, only the given tail will be iterated.
/// \deprecated Use iterate_func_chunks_ea() for safer access.

idaman DEPRECATED void ida_export iterate_func_chunks(
        func_t *pfn,
        void (idaapi *func)(ea_t ea1, ea_t ea2, void *ud),
        void *ud=nullptr,
        bool include_parents=false);


/// Class to enumerate all function instructions and data sorted by addresses.
/// The function entry chunk items are enumerated first regardless of their addresses
///
/// Sample code:
/// \code
///      func_item_iterator_t fii;
///      for ( bool ok=fii.set(pfn, ea); ok; ok=fii.next_addr() )
///        ea_t ea = fii.current();
///        ....
/// \endcode
///
/// If 'ea' is not specified in the call to set(), then the enumeration starts at
/// the function entry point.
/// If 'pfn' is specified as nullptr then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// It is also possible to enumerate addresses in an arbitrary range using set_range().
/// \deprecated Use function_item_iterator_t for safer ea-based access.
class DEPRECATED func_item_iterator_t
{
  friend struct kdata_t;
  GCC_DIAG_OFF(deprecated-declarations)
  MSC_DIAG_OFF(4996)  // member type and methods are deprecated; suppress
                      // C4996 across the whole class body -- external uses of
                      // the class still emit the deprecation warning.
  func_tail_iterator_t fti;
  ea_t ea;
public:
  func_item_iterator_t(void) : ea(BADADDR) {}
  func_item_iterator_t(func_t *pfn, ea_t _ea=BADADDR) { set(pfn, _ea); }
  /// Set a function range. if pfn == nullptr then a segment range will be set.
  bool set(func_t *pfn, ea_t _ea=BADADDR)
  {
    ea = (_ea != BADADDR || pfn == nullptr) ? _ea : pfn->start_ea;
    return fti.set(pfn, _ea);
  }
  /// Set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2) { ea = ea1; return fti.set_range(ea1, ea2); }
  bool first(void) { if ( !fti.main() ) return false; ea=fti.chunk().start_ea; return true; }
  bool last(void) { if ( !fti.last() ) return false; ea=fti.chunk().end_ea; return true; }
  ea_t current(void) const { return ea; }
  bool set_ea(ea_t _ea)
  {
    if ( !fti.set_ea(_ea) )
      return false;
    ea = _ea;
    return true;
  }
  const range_t &chunk(void) const { return fti.chunk(); }
  bool next(testf_t *func, void *ud) { return func_item_iterator_next(this, func, ud); }
  bool prev(testf_t *func, void *ud) { return func_item_iterator_prev(this, func, ud); }
  bool next_addr(void) { return next(f_any, nullptr); }
  bool next_head(void) { return next(f_is_head, nullptr); }
  bool next_code(void) { return next(f_is_code, nullptr); }
  bool next_data(void) { return next(f_is_data, nullptr); }
  bool next_not_tail(void) { return next(f_is_not_tail, nullptr); }
  bool prev_addr(void) { return prev(f_any, nullptr); }
  bool prev_head(void) { return prev(f_is_head, nullptr); }
  bool prev_code(void) { return prev(f_is_code, nullptr); }
  bool prev_data(void) { return prev(f_is_data, nullptr); }
  bool prev_not_tail(void) { return prev(f_is_not_tail, nullptr); }
  bool decode_prev_insn(insn_t *out) { return func_item_iterator_decode_prev_insn(this, out); }
  bool decode_preceding_insn(eavec_t *visited, bool *p_farref, insn_t *out)
    { return func_item_iterator_decode_preceding_insn(this, visited, p_farref, out); }
  /// Similar to next(), but succ() iterates the chunks from low to high
  /// addresses, while next() iterates through chunks starting at the
  /// function entry chunk
  bool succ(testf_t *func, void *ud) { return func_item_iterator_succ(this, func, ud); }
  bool succ_code(void) { return succ(f_is_code, nullptr); }
  MSC_DIAG_ON(4996)
  GCC_DIAG_ON(deprecated-declarations)
};

/// Class to enumerate all function parents sorted by addresses.
/// Enumeration is started with first() or last().
/// The loop may continue until the next() or prev() function returns false.
/// The parent functions are always sorted by their addresses.
/// The tail chunk is locked during the iteration.
///
/// Sample code:
/// \code
///      func_parent_iterator_t fpi(fnt);
///      for ( bool ok=fpi.first(); ok; ok=fpi.next() )
///        ea_t parent = fpi.parent();
///        ....
/// \endcode
/// \deprecated Use function_parent_iterator_t for safer ea-based access.
class DEPRECATED func_parent_iterator_t
{
  friend struct kdata_t;
  func_t *fnt;
  int idx;
public:
  func_parent_iterator_t(void) : fnt(nullptr), idx(0) {}
  func_parent_iterator_t(func_t *_fnt) : fnt(nullptr) { set(_fnt); }
  ~func_parent_iterator_t(void)
  {
    if ( fnt != nullptr )
      lock_func_range_ea(fnt->start_ea, false);
  }
  bool set(func_t *_fnt) { return func_parent_iterator_set(this, _fnt); }
  ea_t parent(void) const { return fnt->referers[idx]; }
  bool first(void) { idx = 0; return fnt != nullptr && is_function_tail(fnt->start_ea) && fnt->refqty > 0; }
  bool last(void) { idx = fnt->refqty - 1; return idx >= 0; }
  bool next(void) { if ( idx+1 < fnt->refqty ) { idx++; return true; } return false; }
  bool prev(void) { if ( idx > 0 ) { idx--; return true; } return false; }
  void reset_fnt(func_t *_fnt) { fnt = _fnt; } // for internal use only!
};


/// \name Get prev/next address in function
/// Unlike func_item_iterator_t which always enumerates the main function
/// chunk first, these functions respect linear address ordering.
///@{

/// \deprecated Use get_prev_function_addr() for safer access.
idaman DEPRECATED ea_t ida_export get_prev_func_addr(func_t *pfn, ea_t ea);

/// \deprecated Use get_next_function_addr() for safer access.
idaman DEPRECATED ea_t ida_export get_next_func_addr(func_t *pfn, ea_t ea);
///@}

//--------------------------------------------------------------------
//      C O P Y - B A S E D   F U N C T I O N   I N F O   T Y P E S
//--------------------------------------------------------------------

/// \defgroup GFI_ Flags for get_func_entry_info()
/// Specify which optional string fields to populate
///@{
#define GFI_NAME     0x0001  ///< Populate the function name
#define GFI_CMT      0x0002  ///< Populate the regular comment
#define GFI_CMT_RPT  0x0004  ///< Populate the repeatable comment
#define GFI_COMMENTS (GFI_CMT|GFI_CMT_RPT)  ///< Populate both comments
#define GFI_ALL      (GFI_NAME|GFI_COMMENTS) ///< Populate all optional fields
///@}

/// Describes a function chunk (entry or tail).
/// A lightweight descriptor with range and flags, without
/// entry-specific or tail-specific details.
class fchunk_info_t : public range_t
{
public:
  fchunk_info_t(ea_t start=0, ea_t end=0)
    : range_t(start, end)
  {}

  /// Is the function chunk info valid?
  bool is_valid() const { return !empty(); }

  /// Is this a tail chunk?
  bool is_tail() const { return (flags_ & FUNC_TAIL) != 0; }

  /// Is this an entry chunk?
  bool is_entry() const { return !is_tail(); }

  /// Function chunk flags \ref FUNC_
  uint64 get_flags() const { return flags_; }
  void set_flags(uint64 v) { flags_ = v; }

  /// Is a far function?
  bool is_far() const { return (flags_ & FUNC_FAR) != 0; }
  /// Does function return?
  bool does_return() const { return (flags_ & FUNC_NORET) == 0; }
  /// Has SP-analysis been performed?
  bool analyzed_sp() const { return (flags_ & FUNC_SP_READY) != 0; }
  /// Needs prolog analysis?
  bool need_prolog_analysis() const { return (flags_ & FUNC_PROLOG_OK) == 0; }

protected:
  uint64 flags_ = 0;

  friend struct kdata_t;
};


/// Get the range of the function chunk (entry or tail) containing 'ea'.
/// \param out  pointer to output buffer, may be nullptr
/// \param ea   any address in a function chunk
/// \return true if a chunk was found at ea

idaman bool ida_export get_fchunk_info(fchunk_info_t *out, ea_t ea);


/// Get the previous function chunk before the one containing 'ea'.
/// \param out  pointer to output buffer, may be nullptr
/// \param ea   any address in the program
/// \return true if a previous chunk was found

idaman bool ida_export get_prev_fchunk_info(fchunk_info_t *out, ea_t ea);


/// Get the next function chunk after the one containing 'ea'.
/// \param out  pointer to output buffer, may be nullptr
/// \param ea   any address in the program
/// \return true if a next chunk was found

idaman bool ida_export get_next_fchunk_info(fchunk_info_t *out, ea_t ea);


/// Describes a function entry chunk.
/// Call set_func_entry_info() to apply modifications to the database.
class func_entry_info_t : public fchunk_info_t
{
public:
  func_entry_info_t(ea_t start=0, ea_t end=0)
    : fchunk_info_t(start, end)
  { flags_ = FUNC_NORET_PENDING; }

  /// Check if a string field was populated by get_func_entry_info().
  /// \param gfi_flags  combination of \ref GFI_ flags to check
  /// \return true if all specified fields are available
  bool has(int gfi_flags) const { return (filled_ & gfi_flags) == gfi_flags; }

  /// Function flags \ref FUNC_
  void set_flags(uint64 v) { flags_ = v; updated_ |= FEI_FLAGS; }

  /// Set or clear function flag \ref FUNC_
  void set_flag(uint64 v, bool cnd=true) { setflag(flags_, v, cnd); updated_ |= FEI_FLAGS; }

  /// Netnode id of frame structure
  uval_t get_frame_id() const { return frame_; }

  /// Size of local variables part of frame in bytes
  asize_t get_frsize() const { return frsize_; }
  void set_frsize(asize_t v) { frsize_ = v; updated_ |= FEI_FRSIZE; }

  /// Size of saved registers in frame
  ushort get_frregs() const { return frregs_; }
  void set_frregs(ushort v) { frregs_ = v; updated_ |= FEI_FRREGS; }

  /// Number of bytes purged from the stack upon returning
  asize_t get_argsize() const { return argsize_; }
  void set_argsize(asize_t v) { argsize_ = v; updated_ |= FEI_ARGSIZE; }

  /// Frame pointer delta
  asize_t get_fpd() const { return fpd_; }
  void set_fpd(asize_t v) { fpd_ = v; updated_ |= FEI_FPD; }

  /// User defined function color
  bgcolor_t get_color() const { return color_; }
  void set_color(bgcolor_t v) { color_ = v; updated_ |= FEI_COLOR; }

  /// Function name (requires GFI_NAME flag)
  const char *get_name() const { return name_.c_str(); }

  /// Function comment (requires GFI_CMT flag)
  const char *get_cmt() const { return cmt_.c_str(); }

  /// Repeatable function comment (requires GFI_CMT_RPT flag)
  const char *get_cmt_rpt() const { return cmt_rpt_.c_str(); }

private:
  uint64 updated_ = 0;
  int filled_ = 0;
  uval_t frame_ = BADNODE;
  asize_t frsize_ = 0;
  ushort frregs_ = 0;
  asize_t argsize_ = 0;
  asize_t fpd_ = 0;
  bgcolor_t color_ = DEFCOLOR;
  qstring name_;
  qstring cmt_;
  qstring cmt_rpt_;

  friend struct kdata_t;

  /// \defgroup FEI_ Entry info field bitmasks
  /// Used by set_func_entry_info() to track which fields to update
  ///@{
  enum
  {
    FEI_FLAGS   = 0x01,  ///< Update flags field
    FEI_FRSIZE  = 0x02,  ///< Update frsize field
    FEI_FRREGS  = 0x04,  ///< Update frregs field
    FEI_ARGSIZE = 0x08,  ///< Update argsize field
    FEI_FPD     = 0x10,  ///< Update fpd field
    FEI_COLOR   = 0x20,  ///< Update color field
    FEI_ENTIRE  = 0x3F,  ///< update all fields
  };
  ///@}
};


/// Get function entry info by address.
/// \param out    pointer to output buffer, may be nullptr
/// \param ea     any address in a function
/// \param flags  combination of \ref GFI_ flags to control which optional
///               string fields to populate
/// \return true if a function entry was found at the given address

idaman bool ida_export get_func_entry_info(func_entry_info_t *out, ea_t ea, int flags=0);


/// Get function entry info by ordinal number.
/// \param out    pointer to output buffer, may be nullptr
/// \param n      number of function, is in range 0..get_func_qty()-1
/// \param flags  combination of \ref GFI_ flags
/// \return true if a function with the given number exists

idaman bool ida_export get_func_entry_info_by_num(func_entry_info_t *out, size_t n, int flags=0);


/// Update function entry info in the database.
/// You cannot use this function to change the range boundaries.
/// Uses start_ea to identify the function, applies only modified fields.
/// \param fi  entry info to update
/// \return success

idaman bool ida_export set_func_entry_info(const func_entry_info_t *fi);


/// Add a new function using func_entry_info_t.
/// If fi->end_ea is #BADADDR, then IDA will try to determine the
/// function bounds by calling find_func_bounds(..., #FIND_FUNC_DEFINE).
/// Uses fi->start_ea, fi->end_ea, and fi->get_flags().
/// On success, \p fi is updated with the resulting function properties.
/// \param fi  entry info describing the function to create
/// \return success

idaman bool ida_export add_function_ex(func_entry_info_t *fi);


/// Add a new function.
/// If the function end address is #BADADDR, then IDA will try to determine
/// the function bounds by calling find_func_bounds(..., #FIND_FUNC_DEFINE).
/// \param ea1  start address
/// \param ea2  end address
/// \return success

inline bool add_func(ea_t ea1, ea_t ea2=BADADDR)
{
  func_entry_info_t fn(ea1, ea2);
  return add_function_ex(&fn);
}


/// Determine the boundaries of a new function.
/// This function tries to find the start and end addresses of a new function.
/// It calls the module with \ph{func_bounds} in order to fine tune
/// the function boundaries.
/// \param fi     entry info to fill with information.
/// \             fi->start_ea points to the start address of the new function.
/// \param flags  \ref FIND_FUNC_F
/// \return \ref FIND_FUNC_R.
///         On success, \p fi is updated with the resulting function properties.

idaman int ida_export find_function_bounds(func_entry_info_t *fi, int flags);


/// Calculate thunk function target.
/// \param fi    function entry info
/// \param fptr  out: will hold address of a function pointer (if indirect jump)
/// \return the target function or BADADDR

idaman ea_t ida_export calc_thunk_function_target(func_entry_info_t *fi, ea_t *fptr);


/// Describes a function tail chunk.
/// Tail chunks are shared ranges that can belong to multiple functions.
/// Use func_parent_iterator_t to enumerate all parent functions.
class func_tail_info_t : public fchunk_info_t
{
public:
  func_tail_info_t(ea_t start=0, ea_t end=0)
    : fchunk_info_t(start, end)
  {}

  /// Primary owner function start_ea
  ea_t get_owner() const { return owner_; }

  /// Number of refering functions (for quick checks without iterating)
  int get_refqty() const { return refqty_; }

private:
  using fchunk_info_t::set_flags;
  ea_t owner_ = BADADDR;
  int refqty_ = 0;

  friend struct kdata_t;
};


/// Get function tail info by address.
/// \param out  pointer to output buffer, may be nullptr
/// \param ea   any address in a function tail chunk
/// \return true if a tail chunk was found at the given address

idaman bool ida_export get_func_tail_info(func_tail_info_t *out, ea_t ea);


/// Get the number of referers (parent functions) for a tail chunk.
/// \param tail_ea  any address in a function tail chunk
/// \return number of referers, or 0

idaman size_t ida_export get_tail_referer_qty(ea_t tail_ea);


/// Get a tail chunk referer by index.
/// \param tail_ea  any address in a function tail chunk
/// \param n        0-based index
/// \return referer (function start address), or BADADDR

idaman ea_t ida_export get_tail_referer(ea_t tail_ea, size_t n);


/// Get all referers (parent functions) for a tail chunk.
/// \param out      output vector of ea_t (function start addresses)
/// \param tail_ea  any address in a function tail chunk
/// \return success

idaman bool ida_export get_tail_referers(eavec_t *out, ea_t tail_ea);


/// Class to enumerate all function tails sorted by addresses.
/// Enumeration is started with main(), first(), or last().
/// If first() is used, the function entry chunk will be excluded from the enumeration.
/// Otherwise it will be included in the enumeration (for main() and last()).
/// The loop may continue until the next() or prev() function returns false.
/// These functions return false when the enumeration is over.
/// The tail chunks are always sorted by their addresses.
///
/// Sample code:
/// \code
///      function_tail_iterator_t fti(func_ea);
///      range_t a;
///      for ( bool ok=fti.first(); ok; ok=fti.next() )
///      {
///        fti.chunk(&a);
///        ....
/// \endcode
///
/// If the 'ea' parameter is used in the constructor, then the iterator is positioned
/// at the chunk containing the specified 'ea'. Otherwise it is positioned at the
/// function entry chunk.
/// If 'func_ea' is specified as BADADDR then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// The function main chunk is locked during the iteration.
/// It is also possible to enumerate one single arbitrary range using set_range()
/// This function is mainly designed to be used from ::function_item_iterator_t.
/// Iterator for function tail chunks using ea_t-based API.
class function_tail_iterator_t
{
  ea_t func_ea_ = BADADDR;
  int idx_ = -1;
  range_t seglim_;
  range_t main_;
  rangevec_t tails_;
  friend struct kdata_t;

public:
  function_tail_iterator_t() {}
  function_tail_iterator_t(ea_t func_ea, ea_t ea=BADADDR) { set(func_ea, ea); }
  ~function_tail_iterator_t()
  {
    if ( func_ea_ != BADADDR )
      lock_func_range_ea(func_ea_, false);
  }
  bool set(ea_t func_ea, ea_t ea=BADADDR) { return function_tail_iterator_set(this, func_ea, ea); }
  bool set_ea(ea_t ea) { return function_tail_iterator_set_ea(this, ea); }
  bool set_range(ea_t ea1, ea_t ea2) { return function_tail_iterator_set_range(this, ea1, ea2); }
  void chunk(range_t *out) const { function_tail_iterator_chunk(out, this); }
  bool first() { return function_tail_iterator_first(this); }
  bool last() { return function_tail_iterator_last(this); }
  bool next() { return function_tail_iterator_next(this); }
  bool prev() { return function_tail_iterator_prev(this); }
  bool main() { return function_tail_iterator_main(this); }
};


/// Class to enumerate all function parents sorted by addresses.
/// Enumeration is started with first() or last().
/// The loop may continue until the next() or prev() function returns false.
/// The parent functions are always sorted by their addresses.
/// The tail chunk is locked during the iteration.
/// Iterator for function parent referers using ea_t-based API.
///
/// Sample code:
/// \code
///   function_parent_iterator_t fpi(tail_ea);
///   for ( bool ok = fpi.first(); ok; ok = fpi.next() )
///     msg("parent: %a\n", fpi.parent());
/// \endcode
class function_parent_iterator_t
{
  ea_t tail_ea_ = BADADDR;
  int idx_ = 0;
  eavec_t parents_;
  friend struct kdata_t;

public:
  function_parent_iterator_t() {}
  function_parent_iterator_t(ea_t tail_ea) { set(tail_ea); }
  ~function_parent_iterator_t()
  {
    if ( tail_ea_ != BADADDR )
      lock_func_range_ea(tail_ea_, false);
  }
  bool set(ea_t tail_ea) { return function_parent_iterator_set(this, tail_ea); }
  ea_t parent() const { return function_parent_iterator_parent(this); }
  bool first() { return function_parent_iterator_first(this); }
  bool last() { return function_parent_iterator_last(this); }
  bool next() { return function_parent_iterator_next(this); }
  bool prev() { return function_parent_iterator_prev(this); }
};


/// Class to enumerate all function instructions and data sorted by addresses.
/// The function entry chunk items are enumerated first regardless of their addresses
///
/// Sample code:
/// \code
///   function_item_iterator_t fii;
///   for ( bool ok = fii.set(func_ea); ok; ok = fii.next_addr() )
///     msg("ea: %a\n", fii.current());
/// \endcode
///
/// If 'ea' is not specified in the call to set(), then the enumeration starts at
/// the function entry point.
/// If 'func_ea' is specified as BADADDR then the set() function will fail,
/// but it is still possible to use the class. In this case the iteration will be
/// limited by the segment boundaries.
/// It is also possible to enumerate addresses in an arbitrary range using set_range().
class function_item_iterator_t
{
  function_tail_iterator_t fti_;
  ea_t ea_ = BADADDR;
  friend struct kdata_t;

public:
  function_item_iterator_t() {}
  function_item_iterator_t(ea_t func_ea, ea_t ea=BADADDR) { set(func_ea, ea); }
  /// Set a function range. if func_ea == BADADDR then a segment range will be set.
  bool set(ea_t func_ea, ea_t ea=BADADDR)
  {
    func_ea = get_func_start(func_ea);
    ea_ = (ea != BADADDR || func_ea == BADADDR) ? ea : func_ea;
    return fti_.set(func_ea, ea_);
  }
  /// Set an arbitrary range
  bool set_range(ea_t ea1, ea_t ea2) { ea_ = ea1; return fti_.set_range(ea1, ea2); }
  bool first()
  {
    if ( !fti_.main() )
      return false;
    range_t r;
    fti_.chunk(&r);
    ea_ = r.start_ea;
    return true;
  }
  bool last()
  {
    if ( !fti_.last() )
      return false;
    range_t r;
    fti_.chunk(&r);
    ea_ = r.end_ea;
    return true;
  }
  ea_t current() const { return ea_; }
  bool set_ea(ea_t ea)
  {
    if ( !fti_.set_ea(ea) )
      return false;
    ea_ = ea;
    return true;
  }
  void chunk(range_t *out) const { fti_.chunk(out); }
  bool next(testf_t *func, void *ud) { return function_item_iterator_next(this, func, ud); }
  bool prev(testf_t *func, void *ud) { return function_item_iterator_prev(this, func, ud); }
  bool next_addr() { return next(f_any, nullptr); }
  bool next_head() { return next(f_is_head, nullptr); }
  bool next_code() { return next(f_is_code, nullptr); }
  bool next_data() { return next(f_is_data, nullptr); }
  bool next_not_tail() { return next(f_is_not_tail, nullptr); }
  bool prev_addr() { return prev(f_any, nullptr); }
  bool prev_head() { return prev(f_is_head, nullptr); }
  bool prev_code() { return prev(f_is_code, nullptr); }
  bool prev_data() { return prev(f_is_data, nullptr); }
  bool prev_not_tail() { return prev(f_is_not_tail, nullptr); }
  bool decode_prev_insn(insn_t *out) { return function_item_iterator_decode_prev_insn(this, out); }
  bool decode_preceding_insn(eavec_t *visited, bool *p_farref, insn_t *out)
    { return function_item_iterator_decode_preceding_insn(this, visited, p_farref, out); }
  /// Similar to next(), but succ() iterates the chunks from low to high
  /// addresses, while next() iterates through chunks starting at the
  /// function entry chunk
  bool succ(testf_t *func, void *ud) { return function_item_iterator_succ(this, func, ud); }
  bool succ_code() { return succ(f_is_code, nullptr); }
};

///@} ea_func_api

#endif
