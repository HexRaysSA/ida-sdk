/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _FRAME_HPP
#define _FRAME_HPP
#include <idp.hpp>

/*! \file frame.hpp

  \brief Routines to manipulate function stack frames, stack
  variables, register variables and local labels.

  The frame is represented as a structure:
  <pre>
    +------------------------------------------------+
    | function arguments                             |
    +------------------------------------------------+
    | return address (isn't stored in func_t)        |
    +------------------------------------------------+
    | saved registers (SI, DI, etc - func_t::frregs) |
    +------------------------------------------------+ <- typical BP
    |                                                |  |
    |                                                |  | func_t::fpd
    |                                                |  |
    |                                                | <- real BP
    | local variables (func_t::frsize)               |
    |                                                |
    |                                                |
    +------------------------------------------------+ <- SP
  </pre>

  To access the structure of a function frame and stack variables, use:
    - tinfo_t::get_func_frame(const func_t *pfn) (the preferred way)
    - get_func_frame(tinfo_t *out, const func_t *pfn)
    - tinfo_t::get_udt_details() gives info about stack variables: their type,
      names, offset, etc
*/

// name of stkvar to denote the return address slot
#define FRAME_UDM_NAME_R "__return_address"
// name of stkvar to denote the saved register slots
#define FRAME_UDM_NAME_S "__saved_registers"

class op_t;

// We need to trace value of SP register. For this we introduce
// an array of SP register change points.

// SP register change point
//
// NOTE: To manipulate/modify stack points, please use the specialized
// functions provided below in this file (stack pointer change points)

struct stkpnt_t
{
  ea_t ea;              // linear address
  sval_t spd;           // here we keep a cumulative difference from [BP-frsize]

  DECLARE_COMPARISONS(stkpnt_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(stkpnt_t);
// we declare a struct to be able to forward declare it in other files
struct stkpnts_t : public qvector<stkpnt_t>
{
  DECLARE_COMPARISONS(stkpnts_t) { return compare_containers(*this, r); }
};

/// Local label
struct llabel_t
{
  ea_t ea = BADADDR;          ///< linear address
  qstring name;               ///< label name

  DECLARE_COMPARISONS(llabel_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(llabel_t);
typedef qvector<llabel_t> llabels_t;

//--------------------------------------------------------------------------
//      F R A M E   M A N I P U L A T I O N
//--------------------------------------------------------------------------

/// Add function frame.
/// \deprecated Use add_frame_ea() for safer access.
/// \param pfn      pointer to function structure
/// \param frsize   size of function local variables
/// \param frregs   size of saved registers
/// \param argsize  size of function arguments range which will be purged upon return.
///                 this parameter is used for __stdcall and __pascal calling conventions.
///                 for other calling conventions please pass 0.
/// \retval 1  ok
/// \retval 0  failed (no function, frame already exists)

idaman DEPRECATED bool ida_export add_frame(
        func_t *pfn,
        sval_t frsize,
        ushort frregs,
        asize_t argsize);


/// Delete a function frame.
/// \deprecated Use del_frame_ea() for safer access.
/// \param pfn  pointer to function structure
/// \return success

idaman DEPRECATED bool ida_export del_frame(func_t *pfn);


/// Set size of function frame.
/// \deprecated Use set_frame_size_ea() for safer access.
/// Note: The returned size may not include all stack arguments. It does so
/// only for __stdcall and __fastcall calling conventions. To get the entire
/// frame size for all cases use frame.get_func_frame(pfn).get_size()
/// \param pfn      pointer to function structure
/// \param frsize   size of function local variables
/// \param frregs   size of saved registers
/// \param argsize  size of function arguments that will be purged
///                 from the stack upon return
/// \return success

idaman DEPRECATED bool ida_export set_frame_size(
        func_t *pfn,
        asize_t frsize,
        ushort frregs,
        asize_t argsize);


/// Get full size of a function frame.
/// \deprecated Use get_frame_size_ea() for safer access.
/// This function takes into account size of local variables + size of
/// saved registers + size of return address + number of purged bytes.
/// The purged bytes correspond to the arguments of the functions with
/// __stdcall and __fastcall calling conventions.
/// \param pfn  pointer to function structure, may be nullptr
/// \return size of frame in bytes or zero

idaman DEPRECATED asize_t ida_export get_frame_size(const func_t *pfn);


/// Get size of function return address.
/// \deprecated Use get_frame_retsize_ea() for safer access.
/// \param pfn  pointer to function structure, can't be nullptr

idaman DEPRECATED int ida_export get_frame_retsize(const func_t *pfn);

/// Parts of a frame
enum frame_part_t
{
  FPC_ARGS,
  FPC_RETADDR,
  FPC_SAVREGS,
  FPC_LVARS,
};

/// Get offsets of the frame part in the frame.
/// \deprecated Use get_frame_part_ea() for safer access.
/// \param range  pointer to the output buffer with the frame part
///               start/end(exclusive) offsets, can't be nullptr
/// \param pfn    pointer to function structure, can't be nullptr
/// \param part   frame part

idaman DEPRECATED void ida_export get_frame_part(range_t *range, const func_t *pfn, frame_part_t part);

/// Get type of function frame
/// \deprecated Use get_func_frame_ea() for safer access.
/// \param[out] out  type info
/// \param      pfn  pointer to function structure
/// \return success

idaman DEPRECATED bool ida_export get_func_frame(tinfo_t *out, const func_t *pfn);


/// Convert struct offsets into fp-relative offsets.
/// \deprecated Use soff_to_fpoff_ea() for safer access.
/// This function converts the offsets inside the udt_type_data_t object
/// into the frame pointer offsets (for example, EBP-relative).

DEPRECATED inline sval_t soff_to_fpoff(func_t *pfn, uval_t soff)
{
  return pfn != nullptr ? soff - pfn->frsize + pfn->fpd : soff;
}


/// Update frame pointer delta.
/// \deprecated Use update_fpd_ea() for safer access.
/// \param pfn  pointer to function structure
/// \param fpd  new fpd value.
///             cannot be bigger than the local variable range size.
/// \return success

idaman DEPRECATED bool ida_export update_fpd(func_t *pfn, asize_t fpd);


/// Set the number of purged bytes for a function or data item (funcptr).
/// This function will update the database and plan to reanalyze items
/// referencing the specified address. It works only for processors
/// with #PR_PURGING bit in 16 and 32 bit modes.
/// \param ea                   address of the function of item
/// \param nbytes               number of purged bytes
/// \param override_old_value   may overwrite old information about purged bytes
/// \return success

idaman bool ida_export set_purged(ea_t ea, int nbytes, bool override_old_value);


//--------------------------------------------------------------------------
//      S T A C K   V A R I A B L E S
//--------------------------------------------------------------------------

/// Automatically add stack variable.
/// Processor modules should use insn_t::create_stkvar().
/// \param insn   the instruction
/// \param x      reference to instruction operand
/// \param v      immediate value in the operand (usually x.addr)
/// \param stkvar_flags  \ref STKVAR_1
/// \return success

idaman bool ida_export add_stkvar(
        const insn_t &insn,
        const op_t &x,
        sval_t v,
        int stkvar_flags);

/// \defgroup STKVAR_1 Add stkvar flags
/// Passed as 'flags' parameter to add_stkvar()
///@{
#define STKVAR_VALID_SIZE       0x0001 ///< x.dtype contains correct variable type
                                       ///< (for insns like 'lea' this bit must be off).
                                       ///< In general, dr_O references do not allow
                                       ///< to determine the variable size
#define STKVAR_KEEP_EXISTING    0x0002 ///< if a stack variable for this operand already
                                       ///< exists then we do not create a new variable
///@}

/// Define/redefine a stack variable.
/// \deprecated Use define_stkvar_ea() for safer access.
/// \param pfn     pointer to function
/// \param name    variable name, nullptr means autogenerate a name
/// \param off     offset of the stack variable in the frame.
///                negative values denote local variables, positive - function arguments.
/// \param tif     variable type
/// \param repr    variable representation
/// \return success

idaman DEPRECATED bool ida_export define_stkvar(
        func_t *pfn,
        const char *name,
        sval_t off,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr);


/// Add member to the frame type
/// \deprecated Use add_frame_member_ea() for safer access.
/// \param pfn     pointer to function
/// \param name    variable name, nullptr means autogenerate a name
/// \param offset  member offset in the frame structure, in bytes
/// \param tif     variable type
/// \param repr    variable representation
/// \param etf_flags \see ETF_
/// \return success

idaman DEPRECATED bool ida_export add_frame_member(
        const func_t *pfn,
        const char *name,
        uval_t offset,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr,
        uint etf_flags=0);


/// Is member name prefixed with "anonymous"?

inline THREAD_SAFE bool is_anonymous_member_name(const char *name)
{
  return name == nullptr
      || strncmp(name, "anonymous", 9) == 0;
}


/// Is member name an auto-generated name?

inline THREAD_SAFE bool is_dummy_member_name(const char *name)
{
  return name == nullptr
      || strncmp(name, "arg_", 4) == 0
      || strncmp(name, "var_", 4) == 0
      || is_anonymous_member_name(name);
}


/// Is stkvar with TID the return address slot or the saved registers slot ?
/// \param tid  frame member type id
/// return address or saved registers member?

idaman bool ida_export is_special_frame_member(tid_t tid);


/// Change type of the frame member
/// \deprecated Use set_frame_member_type_ea() for safer access.
/// \param pfn     pointer to function
/// \param offset  member offset in the frame structure, in bytes
/// \param tif     variable type
/// \param repr    variable representation
/// \param etf_flags \see ETF_
/// \return success

idaman DEPRECATED bool ida_export set_frame_member_type(
        const func_t *pfn,
        uval_t offset,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr,
        uint etf_flags=0);


/// Delete frame members
/// \deprecated Use delete_frame_members_ea() for safer access.
/// \param pfn           pointer to function
/// \param start_offset  member offset to start deletion from, in bytes
/// \param end_offset    member offset which not included in the deletion, in bytes
/// \return success

idaman DEPRECATED bool ida_export delete_frame_members(
        const func_t *pfn,
        uval_t start_offset,
        uval_t end_offset);


/// Build automatic stack variable name.
/// \deprecated Use build_stkvar_name_ea() for safer access.
/// \param buf  pointer to buffer
/// \param pfn  pointer to function (can't be nullptr!)
/// \param v    value of variable offset
/// \return length of stack variable name or -1

idaman DEPRECATED ssize_t ida_export build_stkvar_name(
        qstring *buf,
        const func_t *pfn,
        sval_t v);


/// Calculate offset of stack variable in the frame structure.
/// \deprecated Use calc_stkvar_struc_offset_ea() for safer access.
/// \param pfn  pointer to function (cannot be nullptr)
/// \param insn the instruction
/// \param n    0..#UA_MAXOP-1 operand number
///              -1 if error, return #BADADDR
/// \return #BADADDR if some error (issue a warning if stack frame is bad)

idaman DEPRECATED ea_t ida_export calc_stkvar_struc_offset(
        func_t *pfn,
        const insn_t &insn,
        int n);


/// Calculate the offset of stack variable in the frame.
/// \deprecated Use calc_frame_offset_ea() for safer access.
/// \param pfn  pointer to function (cannot be nullptr)
/// \param off  the offset relative to stack pointer or frame pointer
/// \param insn the instruction
/// \param op   the operand
/// \return     the offset in the frame

idaman DEPRECATED sval_t ida_export calc_frame_offset(
        func_t *pfn,
        sval_t off,
        const insn_t *insn = nullptr,
        const op_t *op = nullptr);


/// Find and delete wrong frame info.
/// \deprecated Use delete_wrong_frame_info_ea() for safer access.
/// Namely, we delete:
///   - unreferenced stack variable definitions
///   - references to dead stack variables (i.e. operands displayed in red)
///     these operands will be untyped and most likely displayed in hex.
///
/// We also plan to reanalyze instruction with the stack frame references
/// \param pfn  pointer to the function
/// \param should_reanalyze callback to determine which instructions to reanalyze
/// \return number of deleted definitions

idaman DEPRECATED int ida_export delete_wrong_frame_info(
        func_t *pfn,
        bool idaapi should_reanalyze(const insn_t &insn));


//--------------------------------------------------------------------------
//      R E G I S T E R   V A R I A B L E S
//--------------------------------------------------------------------------
struct regvar_t;
#define DECLARE_REGVAR_T_HELPERS(decl)\
decl int ida_export regvar_t__compare(const regvar_t &l, const regvar_t &r); \

DECLARE_REGVAR_T_HELPERS(idaman)

/// \defgroup regvar Register variables
/// Definition of ::regvar_t and related functions
///@{

idaman void ida_export free_regvar(struct regvar_t *v);

/// A register variable allows the user to rename a general processor register
/// to a meaningful name.
/// IDA doesn't check whether the target assembler supports the register renaming.
/// All register definitions will appear at the beginning of the function.
struct regvar_t : public range_t
{
  char *canon = nullptr; ///< canonical register name (case-insensitive)
  char *user = nullptr;  ///< user-defined register name
  char *cmt = nullptr;   ///< comment to appear near definition

  regvar_t() {}
  regvar_t(const regvar_t &r) : range_t(r)
  {
    canon = ::qstrdup(r.canon);
    user = ::qstrdup(r.user);
    cmt = ::qstrdup(r.cmt);
  }
  ~regvar_t() { free_regvar(this); }
  regvar_t &operator=(const regvar_t &r)
  {
    if ( this != &r )
    {
      free_regvar(this);
      new (this) regvar_t(r);
    }
    return *this;
  }
  void swap(regvar_t &r)
  {
    std::swap(start_ea, r.start_ea);
    std::swap(end_ea, r.end_ea);
    std::swap(canon, r.canon);
    std::swap(user, r.user);
    std::swap(cmt, r.cmt);
  }

  DECLARE_COMPARISONS(regvar_t) { return regvar_t__compare(*this, r); }

  DECLARE_REGVAR_T_HELPERS(friend)
};
DECLARE_TYPE_AS_MOVABLE(regvar_t);
typedef qvector<regvar_t> regvars_t;

/// Define a register variable.
/// \deprecated Use add_func_regvar() for safer access.
/// \param pfn      function in which the definition will be created
/// \param ea1,ea2  range of addresses within the function where the definition
///                 will be used
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \param cmt      comment for the definition
/// \return \ref REGVAR_ERROR_

idaman DEPRECATED int ida_export add_regvar(
        func_t *pfn,
        ea_t ea1,
        ea_t ea2,
        const char *canon,
        const char *user,
        const char *cmt);

/// Find a register variable definition (powerful version).
/// \deprecated Use find_func_regvar() for safer access.
/// One of 'canon' and 'user' should be nullptr.
/// If both 'canon' and 'user' are nullptr it returns the first regvar
/// definition in the range.
/// \param pfn      function in question
/// \param ea1,ea2  range of addresses to search.
///                 ea1==BADADDR means the entire function
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \return nullptr-not found, otherwise ptr to regvar_t

idaman DEPRECATED regvar_t *ida_export find_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon, const char *user);


/// Rename a register variable.
/// \deprecated Use rename_regvar_ea() for safer access.
/// \param pfn   function in question
/// \param v     variable to rename
/// \param user  new user-defined name for the register
/// \return \ref REGVAR_ERROR_

idaman DEPRECATED int ida_export rename_regvar(func_t *pfn, regvar_t *v, const char *user);


/// Set comment for a register variable.
/// \deprecated Use set_regvar_cmt_ea() for safer access.
/// \param pfn  function in question
/// \param v    variable to rename
/// \param cmt  new comment
/// \return \ref REGVAR_ERROR_

idaman DEPRECATED int ida_export set_regvar_cmt(func_t *pfn, regvar_t *v, const char *cmt);


/// Delete a register variable definition.
/// \deprecated Use del_func_regvar() for safer access.
/// \param pfn      function in question
/// \param ea1,ea2  range of addresses within the function where the definition holds
/// \param canon    name of a general register
/// \return \ref REGVAR_ERROR_

idaman DEPRECATED int ida_export del_regvar(func_t *pfn, ea_t ea1, ea_t ea2, const char *canon);

///@} regvar

//--------------------------------------------------------------------------
//      S P   R E G I S T E R   C H A N G E   P O I N T S
//--------------------------------------------------------------------------

/// Add automatic SP register change point.
/// \deprecated Use add_func_auto_stkpnt() for safer access.
/// \param pfn    pointer to the function. may be nullptr.
/// \param ea     linear address where SP changes.
///               usually this is the end of the instruction which
///               modifies the stack pointer (\cmd{ea}+\cmd{size})
/// \param delta  difference between old and new values of SP
/// \return success

idaman DEPRECATED bool ida_export add_auto_stkpnt(func_t *pfn, ea_t ea, sval_t delta);


/// Add user-defined SP register change point.
/// \param ea     linear address where SP changes
/// \param delta  difference between old and new values of SP
/// \return success

idaman bool ida_export add_user_stkpnt(ea_t ea, sval_t delta);


/// Delete SP register change point.
/// \deprecated Use del_func_stkpnt() for safer access.
/// \param pfn  pointer to the function. may be nullptr.
/// \param ea   linear address
/// \return success

idaman DEPRECATED bool ida_export del_stkpnt(func_t *pfn, ea_t ea);


/// Get difference between the initial and current values of ESP.
/// \deprecated Use get_func_spd() for safer access.
/// \param pfn  pointer to the function. may be nullptr.
/// \param ea   linear address of the instruction
/// \return 0 or the difference, usually a negative number.
///         returns the sp-diff before executing the instruction.

idaman DEPRECATED sval_t ida_export get_spd(func_t *pfn, ea_t ea);


/// Get effective difference between the initial and current values of ESP.
/// \deprecated Use get_func_effective_spd() for safer access.
/// This function returns the sp-diff used by the instruction.
/// The difference between get_spd() and get_effective_spd() is present only
/// for instructions like "pop [esp+N]": they modify sp and use the modified value.
/// \param pfn  pointer to the function. may be nullptr.
/// \param ea   linear address
/// \return 0 or the difference, usually a negative number

idaman DEPRECATED sval_t ida_export get_effective_spd(func_t *pfn, ea_t ea);


/// Get modification of SP made at the specified location
/// \deprecated Use get_func_sp_delta() for safer access.
/// \param pfn  pointer to the function. may be nullptr.
/// \param ea   linear address
/// \return 0 if the specified location doesn't contain a SP change point.
///         otherwise return delta of SP modification.

idaman DEPRECATED sval_t ida_export get_sp_delta(func_t *pfn, ea_t ea);


/// Add such an automatic SP register change point so that at EA the new
/// cumulative SP delta (that is, the difference between the initial and
/// current values of SP) would be equal to NEW_SPD.
/// \deprecated Use set_func_auto_spd() for safer access.
/// \param pfn      pointer to the function. may be nullptr.
/// \param ea       linear address of the instruction
/// \param new_spd  new value of the cumulative SP delta
/// \return success

idaman DEPRECATED bool ida_export set_auto_spd(func_t *pfn, ea_t ea, sval_t new_spd);


/// Recalculate SP delta for an instruction that stops execution.
/// The next instruction is not reached from the current instruction.
/// We need to recalculate SP for the next instruction.
///
/// This function will create a new automatic SP register change
/// point if necessary. It should be called from the emulator (emu.cpp)
/// when auto_state == ::AU_USED if the current instruction doesn't pass
/// the execution flow to the next instruction.
/// \param cur_ea  linear address of the current instruction
/// \retval 1  new stkpnt is added
/// \retval 0  nothing is changed

idaman bool ida_export recalc_spd(ea_t cur_ea);


/// Recalculate SP delta for the current instruction.
/// \deprecated Use recalc_func_spd_for_basic_block() for safer access.
/// The typical code snippet to calculate SP delta in a proc module is:
///
/// <pre>
/// if ( may_trace_sp() && pfn != nullptr )
///   if ( !recalc_spd_for_basic_block(pfn, insn.ea) )
///     trace_sp(pfn, insn);
/// </pre>
///
/// where trace_sp() is a typical name for a function
/// that emulates the SP change of an instruction.
///
/// \param pfn     pointer to the function
/// \param cur_ea  linear address of the current instruction
/// \retval true   the cumulative SP delta is set
/// \retval false  the instruction at CUR_EA passes flow to the next
///                instruction. SP delta must be set as a result of
///                emulating the current instruction.

idaman DEPRECATED bool ida_export recalc_spd_for_basic_block(func_t *pfn, ea_t cur_ea);


/// An xref to an argument or variable located in a function's stack frame
struct xreflist_entry_t
{
  ea_t ea;     ///< Location of the insn referencing the stack frame member
  uchar opnum; ///< Number of the operand of that instruction
  uchar type;  ///< The type of xref (::cref_t & ::dref_t)

  DECLARE_COMPARISONS(xreflist_entry_t)
  {
    int code = ::compare(ea, r.ea);
    if ( code == 0 )
    {
      code = ::compare(type, r.type);
      if ( code == 0 )
        code = ::compare(opnum, r.opnum);
    }
    return code;
  }
};
DECLARE_TYPE_AS_MOVABLE(xreflist_entry_t);
typedef qvector<xreflist_entry_t> xreflist_t; ///< vector of xrefs to variables in a function's stack frame

/// Fill 'out' with a list of all the xrefs made from function 'pfn' to
/// specified range of the pfn's stack frame.
/// \deprecated Use build_stkvar_xrefs_ea() for safer access.
/// \param out   the list of xrefs to fill.
/// \param pfn   the function to scan.
/// \param start_offset  start frame structure offset, in bytes
/// \param end_offset    end frame structure offset, in bytes

idaman DEPRECATED void ida_export build_stkvar_xrefs(xreflist_t *out, func_t *pfn, uval_t start_offset, uval_t end_offset);


//--------------------------------------------------------------------
//      E A - B A S E D   F R A M E   A P I
//--------------------------------------------------------------------
/// \defgroup ea_frame_api ea-based frame API
/// These functions replace the func_t*-based frame API with ea_t-based
/// equivalents. Using ea_t (the function's start address) as a stable
/// handle avoids pointer lifetime issues: func_t pointers can be
/// invalidated by del_func(), add_func(), undo, and recursive IDB
/// event callbacks.
///@{

//--------------------------------------------------------------------------
//      E A - B A S E D   F R A M E   M A N I P U L A T I O N
//--------------------------------------------------------------------------
/// \defgroup ea_frame_manip ea-based frame manipulation
///@{

/// Add function frame.
/// \param func_ea  any address of the function
/// \param frsize   size of function local variables
/// \param frregs   size of saved registers
/// \param argsize  size of function arguments range which will be purged upon return.
///                 this parameter is used for __stdcall and __pascal calling conventions.
///                 for other calling conventions please pass 0.
/// \retval 1  ok
/// \retval 0  failed (no function at func_ea, frame already exists)

idaman bool ida_export add_frame_ea(
        ea_t func_ea,
        sval_t frsize,
        ushort frregs,
        asize_t argsize);


/// Delete a function frame.
/// \param func_ea  any address of the function
/// \return success

idaman bool ida_export del_frame_ea(ea_t func_ea);


/// Set size of function frame.
/// \param func_ea   any address of the function
/// \param frsize    size of function local variables
/// \param frregs    size of saved registers
/// \param argsize   size of function arguments that will be purged
///                  from the stack upon return
/// \return success

idaman bool ida_export set_frame_size_ea(
        ea_t func_ea,
        asize_t frsize,
        ushort frregs,
        asize_t argsize);


/// Get full size of a function frame.
/// This function takes into account size of local variables + size of
/// saved registers + size of return address + number of purged bytes.
/// \param func_ea  any address of the function
/// \return size of frame in bytes or zero

idaman asize_t ida_export get_frame_size_ea(ea_t func_ea);


/// Get size of function return address.
/// \param func_ea  any address of the function
/// \return return address size or 0

idaman int ida_export get_frame_retsize_ea(ea_t func_ea);


/// Get offsets of the frame part in the frame.
/// \param[out] range  pointer to the output buffer with the frame part
///                    start/end(exclusive) offsets, can't be nullptr
/// \param func_ea     any address of the function
/// \param part        frame part
/// \return false if no function at func_ea

idaman bool ida_export get_frame_part_ea(range_t *range, ea_t func_ea, frame_part_t part);


/// Get starting address of arguments section
/// \param func_ea  any address of the function
/// \return offset in frame or BADADDR on failure

inline ea_t frame_off_args_ea(ea_t func_ea)
{
  range_t range;
  if ( !get_frame_part_ea(&range, func_ea, FPC_ARGS) )
    return BADADDR;
  return range.start_ea;
}

/// Get starting address of return address section
/// \param func_ea any address of the function
/// \return offset in frame or BADADDR on failure

inline ea_t frame_off_retaddr_ea(ea_t func_ea)
{
  range_t range;
  if ( !get_frame_part_ea(&range, func_ea, FPC_RETADDR) )
    return BADADDR;
  return range.start_ea;
}

/// Get starting address of saved registers section
/// \param func_ea  any address of the function
/// \return offset in frame or BADADDR on failure

inline ea_t frame_off_savregs_ea(ea_t func_ea)
{
  range_t range;
  if ( !get_frame_part_ea(&range, func_ea, FPC_SAVREGS) )
    return BADADDR;
  return range.start_ea;
}

/// Get start address of local variables section
/// \param func_ea  any address of the function
/// \return offset in frame or BADADDR on failure

inline ea_t frame_off_lvars_ea(ea_t func_ea)
{
  range_t range;
  if ( !get_frame_part_ea(&range, func_ea, FPC_LVARS) )
    return BADADDR;
  return range.start_ea;
}

/// Does the given offset lie within the arguments section?
/// \param func_ea   any address of the function
/// \param frameoff  offset in frame

inline bool processor_t::is_funcarg_off_ea(ea_t func_ea, uval_t frameoff) const
{
  range_t args;
  if ( !get_frame_part_ea(&args, func_ea, FPC_ARGS) )
    return false;
  return stkup()
       ? frameoff < args.end_ea
       : frameoff >= args.start_ea;
}

/// Does the given offset lie within the local variables section?
/// \param func_ea   any address of the function
/// \param frameoff  offset in frame

inline sval_t processor_t::lvar_off_ea(ea_t func_ea, uval_t frameoff) const
{
  range_t lvars;
  if ( !get_frame_part_ea(&lvars, func_ea, FPC_LVARS) )
    return 0;
  return stkup()
       ? frameoff - lvars.start_ea
       : lvars.end_ea - frameoff;
}

/// Get starting address of arguments section
/// \deprecated Use frame_off_args_ea() for safer access.

DEPRECATED inline ea_t frame_off_args(const func_t *pfn) { return pfn != nullptr ? frame_off_args_ea(pfn->start_ea) : BADADDR; }

/// Get starting address of return address section
/// \deprecated Use frame_off_retaddr_ea() for safer access.

DEPRECATED inline ea_t frame_off_retaddr(const func_t *pfn) { return pfn != nullptr ? frame_off_retaddr_ea(pfn->start_ea) : BADADDR; }

/// Get starting address of saved registers section
/// \deprecated Use frame_off_savregs_ea() for safer access.

DEPRECATED inline ea_t frame_off_savregs(const func_t *pfn) { return pfn != nullptr ? frame_off_savregs_ea(pfn->start_ea) : BADADDR; }

/// Get start address of local variables section
/// \deprecated Use frame_off_lvars_ea() for safer access.

DEPRECATED inline ea_t frame_off_lvars(const func_t *pfn) { return pfn != nullptr ? frame_off_lvars_ea(pfn->start_ea) : BADADDR; }

/// Does the given offset lie within the arguments section?
/// \deprecated Use processor_t::is_funcarg_off_ea() for safer access.

DEPRECATED inline bool processor_t::is_funcarg_off(const func_t *pfn, uval_t frameoff) const
{
  if ( pfn == nullptr )
    return false;
  range_t args;
  if ( !get_frame_part_ea(&args, pfn->start_ea, FPC_ARGS) )
    return false;
  return stkup()
       ? frameoff < args.end_ea
       : frameoff >= args.start_ea;
}

/// Does the given offset lie within the local variables section?
/// \deprecated Use processor_t::lvar_off_ea() for safer access.

DEPRECATED inline sval_t processor_t::lvar_off(const func_t *pfn, uval_t frameoff) const
{
  if ( pfn == nullptr )
    return 0;
  range_t lvars;
  if ( !get_frame_part_ea(&lvars, pfn->start_ea, FPC_LVARS) )
    return 0;
  return stkup()
       ? frameoff - lvars.start_ea
       : lvars.end_ea - frameoff;
}

/// Get type of function frame
/// \param[out] out   type info
/// \param func_ea    any address of the function
/// \return success

idaman bool ida_export get_func_frame_ea(tinfo_t *out, ea_t func_ea);

inline bool get_func_frame(tinfo_t *tif, ea_t ea) { return get_func_frame_ea(tif, ea); }


/// Convert struct offsets into fp-relative offsets.
/// \param func_ea  any address of the function
/// \param soff     struct offset
/// \return fp-relative offset, or soff if no function at func_ea

idaman sval_t ida_export soff_to_fpoff_ea(ea_t func_ea, uval_t soff);


/// Update frame pointer delta.
/// \param func_ea  any address of the function
/// \param fpd      new fpd value.
///                 cannot be bigger than the local variable range size.
/// \return success

idaman bool ida_export update_fpd_ea(ea_t func_ea, asize_t fpd);

///@} ea_frame_manip


//--------------------------------------------------------------------------
//      E A - B A S E D   S T A C K   V A R I A B L E S
//--------------------------------------------------------------------------
/// \defgroup ea_frame_stkvar ea-based stack variables
///@{

/// Define/redefine a stack variable.
/// \param func_ea  any address of the function
/// \param name     variable name, nullptr means autogenerate a name
/// \param off      offset of the stack variable in the frame.
///                 negative values denote local variables, positive - function arguments.
/// \param tif      variable type
/// \param repr     variable representation
/// \return success

idaman bool ida_export define_stkvar_ea(
        ea_t func_ea,
        const char *name,
        sval_t off,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr);


/// Add member to the frame type
/// \param func_ea    any address of the function
/// \param name       variable name, nullptr means autogenerate a name
/// \param offset     member offset in the frame structure, in bytes
/// \param tif        variable type
/// \param repr       variable representation
/// \param etf_flags  \see ETF_
/// \return success

idaman bool ida_export add_frame_member_ea(
        ea_t func_ea,
        const char *name,
        uval_t offset,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr,
        uint etf_flags=0);


/// Change type of the frame member
/// \param func_ea    any address of the function
/// \param offset     member offset in the frame structure, in bytes
/// \param tif        variable type
/// \param repr       variable representation
/// \param etf_flags  \see ETF_
/// \return success

idaman bool ida_export set_frame_member_type_ea(
        ea_t func_ea,
        uval_t offset,
        const tinfo_t &tif,
        const struct value_repr_t *repr=nullptr,
        uint etf_flags=0);


/// Delete frame members
/// \param func_ea        any address of the function
/// \param start_offset   member offset to start deletion from, in bytes
/// \param end_offset     member offset which not included in the deletion, in bytes
/// \return success

idaman bool ida_export delete_frame_members_ea(
        ea_t func_ea,
        uval_t start_offset,
        uval_t end_offset);


/// Build automatic stack variable name.
/// \param buf      pointer to buffer
/// \param func_ea  any address of the function
/// \param v        value of variable offset
/// \return length of stack variable name or -1

idaman ssize_t ida_export build_stkvar_name_ea(
        qstring *buf,
        ea_t func_ea,
        sval_t v);


/// Calculate offset of stack variable in the frame structure.
/// \param func_ea  any address of the function
/// \param insn     the instruction
/// \param n        0..#UA_MAXOP-1 operand number
///                  -1 if error, return #BADADDR
/// \return #BADADDR if some error (issue a warning if stack frame is bad)

idaman ea_t ida_export calc_stkvar_struc_offset_ea(
        ea_t func_ea,
        const insn_t &insn,
        int n);


/// Calculate the offset of stack variable in the frame.
/// \param func_ea  any address of the function
/// \param off      the offset relative to stack pointer or frame pointer
/// \param insn     the instruction
/// \param op       the operand
/// \return the offset in the frame

idaman sval_t ida_export calc_frame_offset_ea(
        ea_t func_ea,
        sval_t off,
        const insn_t *insn=nullptr,
        const op_t *op=nullptr);


/// Find and delete wrong frame info.
/// Namely, we delete:
///   - unreferenced stack variable definitions
///   - references to dead stack variables (i.e. operands displayed in red)
///     these operands will be untyped and most likely displayed in hex.
///
/// We also plan to reanalyze instruction with the stack frame references
/// \param func_ea  any address of the function
/// \param should_reanalyze callback to determine which instructions to reanalyze
/// \return number of deleted definitions or -1 if no function

idaman int ida_export delete_wrong_frame_info_ea(
        ea_t func_ea,
        bool idaapi should_reanalyze(const insn_t &insn));


/// Fill 'out' with a list of all the xrefs from a function to
/// the specified range of the function's stack frame.
/// \param out           the list of xrefs to fill
/// \param func_ea       any address of the function
/// \param start_offset  start frame structure offset, in bytes
/// \param end_offset    end frame structure offset, in bytes

idaman void ida_export build_stkvar_xrefs_ea(
        xreflist_t *out,
        ea_t func_ea,
        uval_t start_offset,
        uval_t end_offset);

///@} ea_frame_stkvar


//--------------------------------------------------------------------------
//      E A - B A S E D   R E G I S T E R   V A R I A B L E S
//--------------------------------------------------------------------------
/// \defgroup ea_frame_regvar ea-based register variables
///@{

/// Define a register variable.
/// \param func_ea  any address of the function
/// \param ea1,ea2  range of addresses within the function where the definition
///                 will be used
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \param cmt      comment for the definition
/// \return \ref REGVAR_ERROR_

idaman int ida_export add_func_regvar(
        ea_t func_ea,
        ea_t ea1,
        ea_t ea2,
        const char *canon,
        const char *user,
        const char *cmt);
/// \defgroup REGVAR_ERROR_ Register variable error codes
/// Return values for functions in described in \ref regvar
///@{
#define REGVAR_ERROR_OK         0     ///< all ok
#define REGVAR_ERROR_ARG        (-1)  ///< function arguments are bad
#define REGVAR_ERROR_RANGE      (-2)  ///< the definition range is bad
#define REGVAR_ERROR_NAME       (-3)  ///< the provided name(s) can't be accepted
///@}


/// Find a register variable definition (powerful version).
/// One of 'canon' and 'user' should be nullptr.
/// If both 'canon' and 'user' are nullptr it returns the first regvar
/// definition in the range.
/// \param func_ea  any address of the function
/// \param ea1,ea2  range of addresses to search.
///                 ea1==BADADDR means the entire function
/// \param canon    name of a general register
/// \param user     user-defined name for the register
/// \return nullptr-not found, otherwise ptr to regvar_t

idaman regvar_t *ida_export find_func_regvar(
        ea_t func_ea,
        ea_t ea1,
        ea_t ea2,
        const char *canon,
        const char *user);


/// Find a register variable definition.
/// \param func_ea  any address of the function
/// \param ea       current address
/// \param canon    name of a general register
/// \return nullptr-not found, otherwise ptr to regvar_t

inline regvar_t *find_func_regvar(ea_t func_ea, ea_t ea, const char *canon)
{
  return find_func_regvar(func_ea, ea, ea+1, canon, nullptr);
}


/// Is there a register variable definition?
/// \param func_ea  any address of the function
/// \param ea       current address

inline bool has_func_regvar(ea_t func_ea, ea_t ea)
{
  return find_func_regvar(func_ea, ea, ea+1, nullptr, nullptr) != nullptr;
}


/// Find a register variable definition.
/// \deprecated Use find_func_regvar(ea_t, ea_t, const char*) for safer access.
/// \param pfn    function in question
/// \param ea     current address
/// \param canon  name of a general register
/// \return nullptr-not found, otherwise ptr to regvar_t

DEPRECATED inline regvar_t *find_regvar(func_t *pfn, ea_t ea, const char *canon) { return pfn != nullptr ? find_func_regvar(pfn->start_ea, ea, canon) : nullptr; }


/// Is there a register variable definition?
/// \deprecated Use has_func_regvar() for safer access.
/// \param pfn    function in question
/// \param ea     current address

DEPRECATED inline bool has_regvar(func_t *pfn, ea_t ea) { return pfn != nullptr && has_func_regvar(pfn->start_ea, ea); }


/// Rename a register variable.
/// \param func_ea  any address of the function
/// \param v        variable to rename
/// \param user     new user-defined name for the register
/// \return \ref REGVAR_ERROR_

idaman int ida_export rename_regvar_ea(ea_t func_ea, regvar_t *v, const char *user);


/// Set comment for a register variable.
/// \param func_ea  any address of the function
/// \param v        variable to rename
/// \param cmt      new comment
/// \return \ref REGVAR_ERROR_

idaman int ida_export set_regvar_cmt_ea(ea_t func_ea, regvar_t *v, const char *cmt);


/// Delete a register variable definition.
/// \param func_ea  any address of the function
/// \param ea1,ea2  range of addresses within the function where the definition holds
/// \param canon    name of a general register
/// \return \ref REGVAR_ERROR_

idaman int ida_export del_func_regvar(ea_t func_ea, ea_t ea1, ea_t ea2, const char *canon);


/// Get the number of register variables for a function.
/// \param func_ea  function start address
/// \return number of register variables, or 0

idaman size_t ida_export get_func_regvar_qty(ea_t func_ea);


/// Get all register variables for a function.
/// \param out      output vector of regvar_t
/// \param func_ea  function start address
/// \return success

idaman bool ida_export get_func_regvars(regvars_t *out, ea_t func_ea);

///@} ea_frame_regvar


//--------------------------------------------------------------------------
//      E A - B A S E D   S P   C H A N G E   P O I N T S
//--------------------------------------------------------------------------
/// \defgroup ea_frame_sp ea-based SP change points
///@{

/// Add automatic SP register change point.
/// \param func_ea  any address of the function, may be BADADDR to auto-resolve
/// \param ea       linear address where SP changes.
///                 usually this is the end of the instruction which
///                 modifies the stack pointer (\cmd{ea}+\cmd{size})
/// \param delta    difference between old and new values of SP
/// \return success

idaman bool ida_export add_func_auto_stkpnt(ea_t func_ea, ea_t ea, sval_t delta);


/// Delete SP register change point.
/// \param func_ea  any address of the function, may be BADADDR to auto-resolve
/// \param ea       linear address
/// \return success

idaman bool ida_export del_func_stkpnt(ea_t func_ea, ea_t ea);


/// Get difference between the initial and current values of ESP.
/// \param func_ea  any address of the function, may be BADADDR to auto-resolve
/// \param ea       linear address of the instruction
/// \return 0 or the difference, usually a negative number.
///         returns the sp-diff before executing the instruction.

idaman sval_t ida_export get_func_spd(ea_t func_ea, ea_t ea);


/// Get effective difference between the initial and current values of ESP.
/// This function returns the sp-diff used by the instruction.
/// The difference between get_func_spd() and get_func_effective_spd() is present only
/// for instructions like "pop [esp+N]": they modify sp and use the modified value.
/// \param func_ea  any address of the function, may be BADADDR to auto-resolve
/// \param ea       linear address
/// \return 0 or the difference, usually a negative number

idaman sval_t ida_export get_func_effective_spd(ea_t func_ea, ea_t ea);


/// Get modification of SP made at the specified location
/// \param func_ea  any address of the function, may be BADADDR to auto-resolve
/// \param ea       linear address
/// \return 0 if the specified location doesn't contain a SP change point.
///         otherwise return delta of SP modification.

idaman sval_t ida_export get_func_sp_delta(ea_t func_ea, ea_t ea);


/// Set the cumulative SP delta at the given address.
/// \param func_ea   any address of the function, may be BADADDR to auto-resolve
/// \param ea        linear address of the instruction
/// \param new_spd   new value of the cumulative SP delta
/// \return success

idaman bool ida_export set_func_auto_spd(ea_t func_ea, ea_t ea, sval_t new_spd);


/// Recalculate SP delta for the current instruction.
/// The typical code snippet to calculate SP delta in a proc module is:
///
/// <pre>
/// ea_t func_ea = get_func_start(insn.ea);
/// if ( may_trace_sp() && func_ea != BADADDR )
///   if ( !recalc_func_spd_for_basic_block(func_ea, insn.ea) )
///     trace_sp(func_ea, insn);
/// </pre>
///
/// \param func_ea  any address of the function
/// \param cur_ea   linear address of the current instruction
/// \retval true    the cumulative SP delta is set
/// \retval false   the instruction at CUR_EA passes flow to the next
///                 instruction. SP delta must be set as a result of
///                 emulating the current instruction.

idaman bool ida_export recalc_func_spd_for_basic_block(ea_t func_ea, ea_t cur_ea);


/// Get the number of SP change points for a function.
/// \param func_ea  function start address
/// \return number of SP change points, or 0 if no function / no points

idaman size_t ida_export get_func_stkpnt_qty(ea_t func_ea);


/// Get all SP change points for a function.
/// \param out      output vector of stkpnt_t
/// \param func_ea  function start address
/// \return success

idaman bool ida_export get_func_stkpnts(stkpnts_t *out, ea_t func_ea);

///@} ea_frame_sp


//--------------------------------------------------------------------------
//      E A - B A S E D   L O C A L   L A B E L S
//--------------------------------------------------------------------------
/// \defgroup ea_frame_llabel ea-based local labels
///@{

/// Get the number of local labels for a function.
/// \param func_ea  function start address
/// \return number of local labels, or 0

idaman size_t ida_export get_func_llabel_qty(ea_t func_ea);


/// Get all local labels for a function.
/// \param out      output vector of llabel_t
/// \param func_ea  function start address
/// \return success

idaman bool ida_export get_func_llabels(llabels_t *out, ea_t func_ea);

///@} ea_frame_llabel

///@} ea_frame_api

#endif // _FRAME_HPP
