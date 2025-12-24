#pragma once
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif
#include <map>
#include <set>
#include <deque>
#include <queue>

#include <pro.h>
#include <fpro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <gdl.hpp>
#include <ieee.h>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>

#include <qset.hpp>
#include <qmap.hpp>
#define hexapi ///< Public functions are marked with this keyword 


// Lint suppressions:
//lint -sem(mop_t::_make_cases, custodial(1))
//lint -sem(mop_t::_make_pair, custodial(1))
//lint -sem(mop_t::_make_callinfo, custodial(1))
//lint -sem(mop_t::_make_insn, custodial(1))
//lint -sem(mop_t::make_insn, custodial(1))

// Microcode level forward definitions:
class lvar_t;
class lvars_t;
class mop_t;            // microinstruction operand
class mop_pair_t;       // pair of operands.      example, :(edx.4,eax.4).8
class mop_addr_t;       // address of an operand. example: &global_var
class mcallinfo_t;      // function call info.    example: <cdecl:"int x" #10.4>.8
class mcases_t;         // jump table cases.      example: {0 => 12, 1 => 13}
class minsn_t;          // microinstruction
class mblock_t;         // basic block
class mba_t;            // array of blocks, represents microcode for a function
class codegen_t;        // helper class to generate the initial microcode
class mbl_graph_t;      // control flow graph of microcode
class control_graph_t;  // the result of structural analysis
class edge_mapper_t;
struct vdui_t;          // widget representing the pseudocode window
struct mba_stats_t;     // statistics about decompilation of a function
struct mlist_t;         // list of memory and register locations
struct voff_t;          // value offset (microregister number or stack offset)
typedef qset<voff_t> voff_set_t;
struct vivl_t;          // value interval (register or stack range)
struct fnumber_t;
typedef int mreg_t;     ///< Micro register
struct hexrays_failure_t;

// Ctree level forward definitions:
struct cfunc_t;         // result of decompilation, the highest level object
struct citem_t;         // base class for cexpr_t and cinsn_t
struct cexpr_t;         // C expression
struct cinsn_t;         // C statement
struct cblock_t;        // C statement block (sequence of statements)
struct cswitch_t;       // C switch statement
struct carg_t;          // call argument
struct carglist_t;      // vector of call arguments
struct ctry_t;          // C++ try-statement
struct cthrow_t;        // C++ throw-statement
struct vc_printer_t;

typedef std::set<ea_t> easet_t;
typedef qset<minsn_t *> minsn_ptr_set_t;
typedef qset<qstring> strings_t;
typedef qvector<minsn_t*> minsnptrs_t;
typedef qvector<mop_t*> mopptrs_t;
typedef qvector<mop_t> mopvec_t;
typedef qvector<uint64> uint64vec_t;
typedef qvector<mreg_t> mregvec_t;
typedef qrefcnt_t<cfunc_t> cfuncptr_t;

// Function frames must be smaller than this value, otherwise
// the decompiler will bail out with MERR_HUGESTACK
#define MAX_SUPPORTED_STACK_SIZE 0x100000 // 1MB

//-------------------------------------------------------------------------
// Original version of macro DEFINE_MEMORY_ALLOCATION_FUNCS
// (uses decompiler-specific memory allocation functions)
#define HEXRAYS_PLACEMENT_DELETE void operator delete(void *, void *) {}
#define HEXRAYS_MEMORY_ALLOCATION_FUNCS()                          \
  void *operator new  (size_t _s) { return hexrays_alloc(_s); }    \
  void *operator new[](size_t _s) { return hexrays_alloc(_s); }    \
  void *operator new(size_t /*size*/, void *_v) { return _v; }     \
  void operator delete  (void *_blk) { hexrays_free(_blk); }       \
  void operator delete[](void *_blk) { hexrays_free(_blk); }       \
  HEXRAYS_PLACEMENT_DELETE

//-------------------------------------------------------------------------
/// \defgroup DECOMP_ decompile() flags
///@{
#define DECOMP_NO_WAIT      0x0001 ///< do not display waitbox
#define DECOMP_NO_CACHE     0x0002 ///< do not use decompilation cache (snippets are never cached)
#define DECOMP_NO_FRAME     0x0004 ///< do not use function frame info (only snippet mode)
#define DECOMP_WARNINGS     0x0008 ///< display warnings in the output window
#define DECOMP_ALL_BLKS     0x0010 ///< generate microcode for unreachable blocks
#define DECOMP_NO_HIDE      0x0020 ///< do not close display waitbox. see close_hexrays_waitbox()
#define DECOMP_GXREFS_DEFLT 0x0000 ///< the default behavior: do not update the
                                   ///< global xrefs cache upon decompile() call,
                                   ///< but when the pseudocode text is generated
                                   ///< (e.g., through cfunc_t.get_pseudocode())
#define DECOMP_GXREFS_NOUPD 0x0040 ///< do not update the global xrefs cache
#define DECOMP_GXREFS_FORCE 0x0080 ///< update the global xrefs cache immediately
#define DECOMP_VOID_MBA     0x0100 ///< return empty mba object (to be used with gen_microcode)
#define DECOMP_OUTLINE  0x80000000 ///< generate code for an outline
///@}

void *hexapi hexrays_alloc(size_t size);
void hexapi  hexrays_free(void *ptr);

//-------------------------------------------------------------------------
/// Operand locator.
/// It is used to denote a particular operand in the ctree, for example,
/// when the user right clicks on a constant and requests to represent it, say,
/// as a hexadecimal number.
struct operand_locator_t
{
private:
  // forbid the default constructor, force the user to initialize objects of this class.
  operand_locator_t() {}
public:
  ea_t ea;              ///< address of the original processor instruction
  int opnum;            ///< operand number in the instruction
  operand_locator_t(ea_t _ea, int _opnum) : ea(_ea), opnum(_opnum) {}
  DECLARE_COMPARISONS(operand_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
/// Number representation.
/// This structure holds information about a number format.
struct number_format_t
{
  flags_t flags32 = 0;    ///< low 32-bit of flags (for compatibility)
  char opnum;             ///< operand number: 0..UA_MAXOP
  char props = 0;         ///< properties: combination of NF_ bits (\ref NF_)
/// \defgroup NF_ Number format property bits
/// Used in number_format_t::props
///@{
#define NF_FIXED    0x01  ///< number format has been defined by the user
#define NF_NEGDONE  0x02  ///< temporary internal bit: negation has been performed
#define NF_BINVDONE 0x04  ///< temporary internal bit: inverting bits is done
#define NF_NEGATE   0x08  ///< The user asked to negate the constant
#define NF_BITNOT   0x10  ///< The user asked to invert bits of the constant
#define NF_VALID    0x20  ///< internal bit: stroff or enum is valid
                          ///< for enums: this bit is set immediately
                          ///< for stroffs: this bit is set at the end of decompilation
///@}
  uchar serial = 0;       ///< for enums: constant serial number
  char org_nbytes = 0;    ///< original number size in bytes
  qstring type_name;      ///< for stroffs: structure for offsetof()\n
                          ///< for enums: enum name
  flags64_t flags = 0;    ///< ida flags, which describe number radix, enum, etc
  /// Contructor
  number_format_t(int _opnum=0) : opnum(char(_opnum)) {}
  /// Get number radix
  /// \return 2,8,10, or 16
  int get_radix() const { return ::get_radix(flags, opnum); }
  /// Is number representation fixed?
  /// Fixed representation cannot be modified by the decompiler
  bool is_fixed() const { return props != 0; }
  /// Is a hexadecimal number?
  bool is_hex() const { return ::is_numop(flags, opnum) && get_radix() == 16; }
  /// Is a decimal number?
  bool is_dec() const { return ::is_numop(flags, opnum) && get_radix() == 10; }
  /// Is a octal number?
  bool is_oct() const { return ::is_numop(flags, opnum) && get_radix() == 8; }
  /// Is a symbolic constant?
  bool is_enum() const { return ::is_enum(flags, opnum); }
  /// Is a character constant?
  bool is_char() const { return ::is_char(flags, opnum); }
  /// Is a structure field offset?
  bool is_stroff() const { return ::is_stroff(flags, opnum); }
  /// Is a number?
  bool is_numop() const { return !is_enum() && !is_char() && !is_stroff(); }
  /// Does the number need to be negated or bitwise negated?
  /// Returns true if the user requested a negation but it is not done yet
  bool needs_to_be_inverted() const
  {
    return (props & (NF_NEGATE|NF_BITNOT)) != 0      // the user requested it
        && (props & (NF_NEGDONE|NF_BINVDONE)) == 0;  // not done yet
  }
  // symbolic constants and struct offsets cannot easily change
  // their sign or size without a cast. only simple numbers can do that.
  // for example, by modifying the expression type we can convert:
  // 10u -> 10
  // but replacing the type of a symbol constant would lead to an inconsistency.
  bool has_unmutable_type() const
  {
    return (props & NF_VALID) != 0 && (is_stroff() || is_enum());
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

// Number formats are attached to (ea,opnum) pairs
typedef qmap<operand_locator_t, number_format_t> user_numforms_t;

//-------------------------------------------------------------------------
/// Ranges to decompile. Either a function or an explicit vector of ranges.
struct mba_ranges_t
{
  func_t *pfn = nullptr; ///< function to decompile. if not null, then function mode.
  rangevec_t ranges;     ///< snippet mode: ranges to decompile.
                         ///< function mode: list of outlined ranges
  mba_ranges_t(func_t *_pfn=nullptr) : pfn(_pfn) {}
  mba_ranges_t(const rangevec_t &r) : ranges(r) {}
  ea_t start() const { return (pfn != nullptr ? *pfn : ranges[0]).start_ea; }
  bool empty() const { return pfn == nullptr && ranges.empty(); }
  void clear() { pfn = nullptr; ranges.clear(); }
  bool is_snippet() const { return pfn == nullptr; }
  bool hexapi range_contains(ea_t ea) const;
  bool is_fragmented() const
  {
    int n_frags = ranges.size();
    if ( pfn != nullptr )
      n_frags += pfn->tailqty + 1;
    return n_frags > 1;
  }
};

//-------------------------------------------------------------------------
/// \defgroup MERR_ Microcode error code
///@{
enum merror_t
{
  MERR_OK        = 0,   ///< ok
  MERR_BLOCK     = 1,   ///< no error, switch to new block
  MERR_INTERR    = -1,  ///< internal error
  MERR_INSN      = -2,  ///< cannot convert to microcode
  MERR_MEM       = -3,  ///< not enough memory
  MERR_BADBLK    = -4,  ///< bad block found
  MERR_BADSP     = -5,  ///< positive sp value has been found
  MERR_PROLOG    = -6,  ///< prolog analysis failed
  MERR_SWITCH    = -7,  ///< wrong switch idiom
  MERR_EXCEPTION = -8,  ///< exception analysis failed
  MERR_HUGESTACK = -9,  ///< stack frame is too big
  MERR_LVARS     = -10, ///< local variable allocation failed
  MERR_BITNESS   = -11, ///< 16-bit functions cannot be decompiled
  MERR_BADCALL   = -12, ///< could not determine call arguments
  MERR_BADFRAME  = -13, ///< function frame is wrong
  MERR_UNKTYPE   = -14, ///< undefined type %s (currently unused error code)
  MERR_BADIDB    = -15, ///< inconsistent database information
  MERR_SIZEOF    = -16, ///< wrong basic type sizes in compiler settings
  MERR_REDO      = -17, ///< redecompilation has been requested
  MERR_CANCELED  = -18, ///< decompilation has been cancelled
  MERR_RECDEPTH  = -19, ///< max recursion depth reached during lvar allocation
  MERR_OVERLAP   = -20, ///< variables would overlap: %s
  MERR_PARTINIT  = -21, ///< partially initialized variable %s
  MERR_COMPLEX   = -22, ///< too complex function
  MERR_LICENSE   = -23, ///< no license available
  MERR_ONLY32    = -24, ///< only 32-bit functions can be decompiled for the current database
  MERR_ONLY64    = -25, ///< only 64-bit functions can be decompiled for the current database
  MERR_BUSY      = -26, ///< already decompiling a function
  MERR_FARPTR    = -27, ///< far memory model is supported only for pc
  MERR_EXTERN    = -28, ///< special segments cannot be decompiled
  MERR_FUNCSIZE  = -29, ///< too big function
  MERR_BADRANGES = -30, ///< bad input ranges
  MERR_BADARCH   = -31, ///< current architecture is not supported
  MERR_DSLOT     = -32, ///< bad instruction in the delay slot
  MERR_STOP      = -33, ///< no error, stop the analysis
  MERR_CLOUD     = -34, ///< cloud: %s
  MERR_EMULATOR  = -35, ///< emulator: %s
  MERR_MAX_ERR   = 35,
  MERR_LOOP      = -36, ///< internal code: redo last loop (never reported)
};
///@}

//-------------------------------------------------------------------------
/// Warning ids
enum warnid_t
{
  WARN_VARARG_REGS,   ///<  0 cannot handle register arguments in vararg function, discarded them
  WARN_ILL_PURGED,    ///<  1 odd caller purged bytes %d, correcting
  WARN_ILL_FUNCTYPE,  ///<  2 invalid function type '%s' has been ignored
  WARN_VARARG_TCAL,   ///<  3 cannot handle tail call to vararg
  WARN_VARARG_NOSTK,  ///<  4 call vararg without local stack
  WARN_VARARG_MANY,   ///<  5 too many varargs, some ignored
  WARN_ADDR_OUTARGS,  ///<  6 cannot handle address arithmetics in outgoing argument area of stack frame -- unused
  WARN_DEP_UNK_CALLS, ///<  7 found interdependent unknown calls
  WARN_ILL_ELLIPSIS,  ///<  8 erroneously detected ellipsis type has been ignored
  WARN_GUESSED_TYPE,  ///<  9 using guessed type %s;
  WARN_EXP_LINVAR,    ///< 10 failed to expand a linear variable
  WARN_WIDEN_CHAINS,  ///< 11 failed to widen chains
  WARN_BAD_PURGED,    ///< 12 inconsistent function type and number of purged bytes
  WARN_CBUILD_LOOPS,  ///< 13 too many cbuild loops
  WARN_NO_SAVE_REST,  ///< 14 could not find valid save-restore pair for %s
  WARN_ODD_INPUT_REG, ///< 15 odd input register %s
  WARN_ODD_ADDR_USE,  ///< 16 odd use of a variable address
  WARN_MUST_RET_FP,   ///< 17 function return type is incorrect (must be floating point)
  WARN_ILL_FPU_STACK, ///< 18 inconsistent fpu stack
  WARN_SELFREF_PROP,  ///< 19 self-referencing variable has been detected
  WARN_WOULD_OVERLAP, ///< 20 variables would overlap: %s
  WARN_ARRAY_INARG,   ///< 21 array has been used for an input argument
  WARN_MAX_ARGS,      ///< 22 too many input arguments, some ignored
  WARN_BAD_FIELD_TYPE,///< 23 incorrect structure member type for %s::%s, ignored
  WARN_WRITE_CONST,   ///< 24 write access to const memory at %a has been detected
  WARN_BAD_RETVAR,    ///< 25 wrong return variable
  WARN_FRAG_LVAR,     ///< 26 fragmented variable at %s may be wrong
  WARN_HUGE_STKOFF,   ///< 27 exceedingly huge offset into the stack frame
  WARN_UNINITED_REG,  ///< 28 reference to an uninitialized register has been removed: %s
  WARN_FIXED_INSN,    ///< 29 fixed broken insn
  WARN_WRONG_VA_OFF,  ///< 30 wrong offset of va_list variable
  WARN_CR_NOFIELD,    ///< 31 CONTAINING_RECORD: no field '%s' in struct '%s' at %d
  WARN_CR_BADOFF,     ///< 32 CONTAINING_RECORD: too small offset %d for struct '%s'
  WARN_BAD_STROFF,    ///< 33 user specified stroff has not been processed: %s
  WARN_BAD_VARSIZE,   ///< 34 inconsistent variable size for '%s'
  WARN_UNSUPP_REG,    ///< 35 unsupported processor register '%s'
  WARN_UNALIGNED_ARG, ///< 36 unaligned function argument '%s'
  WARN_BAD_STD_TYPE,  ///< 37 corrupted or unexisting local type '%s'
  WARN_BAD_CALL_SP,   ///< 38 bad sp value at call
  WARN_MISSED_SWITCH, ///< 39 wrong markup of switch jump, skipped it
  WARN_BAD_SP,        ///< 40 positive sp value %a has been found
  WARN_BAD_STKPNT,    ///< 41 wrong sp change point
  WARN_UNDEF_LVAR,    ///< 42 variable '%s' is possibly undefined
  WARN_JUMPOUT,       ///< 43 control flows out of bounds
  WARN_BAD_VALRNG,    ///< 44 values range analysis failed
  WARN_BAD_SHADOW,    ///< 45 ignored the value written to the shadow area of the succeeding call
  WARN_OPT_VALRNG,    ///< 46 conditional instruction was optimized away because %s
  WARN_RET_LOCREF,    ///< 47 returning address of temporary local variable '%s'
  WARN_BAD_MAPDST,    ///< 48 too short map destination '%s' for variable '%s'
  WARN_BAD_INSN,      ///< 49 bad instruction
  WARN_ODD_ABI,       ///< 50 encountered odd instruction for the current ABI
  WARN_UNBALANCED_STACK, ///< 51 unbalanced stack, ignored a potential tail call
  WARN_OPT_VALRNG2,   ///< 52 mask 0x%X is shortened because %s <= 0x%X"
  WARN_OPT_VALRNG3,   ///< 53 masking with 0X%X was optimized away because %s <= 0x%X
  WARN_OPT_USELESS_JCND,  ///< 54 simplified comparisons for '%s': %s became %s
  WARN_SUBFRAME_OVERFLOW, ///< 55 call arguments overflow the function chunk frame
  WARN_OPT_VALRNG4,   ///< 56 the cases %s were optimized away because %s
  WARN_FRAME_ACCESS,  ///< 57 illegal frame access
  WARN_MAX,           ///< may be used in notes as a placeholder when the
                      ///< warning id is not available
};

/// Warning instances
struct hexwarn_t
{
  ea_t ea;            ///< Address where the warning occurred
  warnid_t id;        ///< Warning id
  qstring text;       ///< Fully formatted text of the warning
  DECLARE_COMPARISONS(hexwarn_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    if ( id < r.id )
      return -1;
    if ( id > r.id )
      return 1;
    return strcmp(text.c_str(), r.text.c_str());
  }
};
DECLARE_TYPE_AS_MOVABLE(hexwarn_t);
typedef qvector<hexwarn_t> hexwarns_t;

//-------------------------------------------------------------------------
/// Microcode maturity levels
enum mba_maturity_t
{
  MMAT_ZERO,         ///< microcode does not exist
  MMAT_GENERATED,    ///< generated microcode
  MMAT_PREOPTIMIZED, ///< preoptimized pass is complete
  MMAT_LOCOPT,       ///< local optimization of each basic block is complete.
                     ///< control flow graph is ready too.
  MMAT_CALLS,        ///< detected call arguments. see also hxe_calls_done
  MMAT_GLBOPT1,      ///< performed the first pass of global optimization
  MMAT_GLBOPT2,      ///< most global optimization passes are done
  MMAT_GLBOPT3,      ///< completed all global optimization. microcode is fixed now.
  MMAT_LVARS,        ///< allocated local variables
};

//-------------------------------------------------------------------------
/// Base helper class to convert binary data structures into text.
/// Other classes are derived from this class.
struct vd_printer_t
{
  qstring tmpbuf;
  int hdrlines = 0;     ///< number of header lines (prototype+typedef+lvars)
                        ///< valid at the end of print process
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of printed string
  AS_PRINTF(3, 4) virtual int hexapi print(int indent, const char *format, ...);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Helper class to convert cfunc_t into text.
struct vc_printer_t : public vd_printer_t
{
  const cfunc_t *func;          ///< cfunc_t to generate text for
  char lastchar = 0;            ///< internal: last printed character
  /// Constructor
  vc_printer_t(const cfunc_t *f) : func(f) {}
  /// Are we generating one-line text representation?
  /// \return \c true if the output will occupy one line without line breaks
  virtual bool idaapi oneliner() const newapi { return false; }
};

/// Helper class to convert binary data structures into text and put into a file.
struct file_printer_t : public vd_printer_t
{
  FILE *fp;                     ///< Output file pointer
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of printed string
  AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...) override;
  /// Constructor
  file_printer_t(FILE *_fp) : fp(_fp) {}
};

/// Helper class to convert cfunc_t into a text string
struct qstring_printer_t : public vc_printer_t
{
  bool with_tags;               ///< Generate output with color tags
  qstring &s;                   ///< Reference to the output string
  /// Constructor
  qstring_printer_t(const cfunc_t *f, qstring &_s, bool tags)
    : vc_printer_t(f), with_tags(tags), s(_s) {}
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  /// \return length of the printed string
  AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...) override;
};
#ifdef __NT__
#pragma warning(pop)
#endif
