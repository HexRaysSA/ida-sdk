#pragma once
#include <hexrays_defs.hpp>

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif
/*!
 * \page vmpage Virtual Machine used by Microcode
 *      We can imagine a virtual micro machine that executes microcode.
 *      This virtual micro machine has many registers.
 *      Each register is 8 bits wide. During translation of processor
 *      instructions into microcode, multibyte processor registers are mapped
 *      to adjacent microregisters. Processor condition codes are also
 *      represented by microregisters. The microregisters are grouped
 *      into following groups:
 *       - 0..7: condition codes
 *       - 8..n: all processor registers (including fpu registers, if necessary)
 *               this range may also include temporary registers used during
 *               the initial microcode generation
 *       - n.. : so called kernel registers; they are used during optimization
 *               see is_kreg()
 *
 *      Each micro-instruction (minsn_t) has zero to three operands.
 *      Some of the possible operands types are:
 *        - immediate value
 *        - register
 *        - memory reference
 *        - result of another micro-instruction
 *
 *      The operands (mop_t) are l (left), r (right), d (destination).
 *      An example of a microinstruction:
 *
 *              add r0.4, #8.4, r2.4
 *
 *      which means 'add constant 8 to r0 and place the result into r2'.
 *      where
 *       - the left operand is 'r0', its size is 4 bytes (r0.4)
 *       - the right operand is a constant '8', its size is 4 bytes (#8.4)
 *       - the destination operand is 'r2', its size is 4 bytes (r2.4)
 *      Note that 'd' is almost always the destination but there are exceptions.
 *      See mcode_modifies_d(). For example, stx does not modify 'd'.
 *      See the opcode map below for the list of microinstructions and their
 *      operands. Most instructions are very simple and do not need
 *      detailed explanations. There are no side effects in microinstructions.
 *
 *      Each operand has a size specifier. The following sizes can be used in
 *      practically all contexts: 1, 2, 4, 8, 16 bytes. Floating types may have
 *      other sizes. Functions may return objects of arbitrary size, as well as
 *      operations upon UDT's (user-defined types, i.e. are structs and unions).
 *
 *      Memory is considered to consist of several segments.
 *      A memory reference is made using a (selector, offset) pair.
 *      A selector is always 2 bytes long. An offset can be 4 or 8 bytes long,
 *      depending on the bitness of the target processor.
 *      Currently the selectors are not used very much. The decompiler tries to
 *      resolve (selector, offset) pairs into direct memory references at each
 *      opportunity and then operates on mop_v operands. In other words,
 *      while the decompiler can handle segmented memory models, internally
 *      it still uses simple linear addresses.
 *
 *      The following memory regions are recognized:
 *        - GLBLOW   global memory: low part, everything below the stack
 *        - LVARS    stack: local variables
 *        - RETADDR  stack: return address
 *        - SHADOW   stack: shadow arguments
 *        - ARGS     stack: regular stack arguments
 *        - GLBHIGH  global memory: high part, everything above the stack
 *      Any stack region may be empty. Objects residing in one memory region
 *      are considered to be completely distinct from objects in other regions.
 *      We allocate the stack frame in some memory region, which is not
 *      allocated for any purposes in IDA. This permits us to use linear addresses
 *      for all memory references, including the stack frame.
 *
 *      If the operand size is bigger than 1 then the register
 *      operand references a block of registers. For example:
 *
 *              ldc   #1.4, r8.4
 *
 *      loads the constant 1 to registers 8, 9, 10, 11:
 *
 *               #1  ->  r8
 *               #0  ->  r9
 *               #0  ->  r10
 *               #0  ->  r11
 *
 *      This example uses little-endian byte ordering.
 *      Big-endian byte ordering is supported too. Registers are always little-
 *      endian, regardless of the memory endianness.
 *
 *      Each instruction has 'next' and 'prev' fields that are used to form
 *      a doubly linked list. Such lists are present for each basic block (mblock_t).
 *      Basic blocks have other attributes, including:
 *        - dead_at_start: list of dead locations at the block start
 *        - maybuse:  list of locations the block may use
 *        - maybdef:  list of locations the block may define (or spoil)
 *        - mustbuse: list of locations the block will certainly use
 *        - mustbdef: list of locations the block will certainly define
 *        - dnu:      list of locations the block will certainly define
 *                    but will not use (registers or non-aliasable stkack vars)
 *
 *      These lists are represented by the mlist_t class. It consists of 2 parts:
 *        - rlist_t: list of microregisters (possibly including virtual stack locations)
 *        - ivlset_t: list of memory locations represented as intervals
 *                    we use linear addresses in this list.
 *      The mlist_t class is used quite often. For example, to find what an operand
 *      can spoil, we build its 'maybe-use' list. Then we can find out if this list
 *      is accessed using the is_accessed() or is_accessed_globally() functions.
 *
 *      All basic blocks of the decompiled function constitute an array called
 *      mba_t (array of microblocks). This is a huge class that has too
 *      many fields to describe here (some of the fields are not visible in the sdk)
 *      The most importants ones are:
 *        - stack frame: frregs, stacksize, etc
 *        - memory: aliased, restricted, and other ranges
 *        - type: type of the current function, its arguments (argidx) and
 *                local variables (vars)
 *        - natural: array of pointers to basic blocks. the basic blocks
 *                   are also accessible as a doubly linked list starting from 'blocks'.
 *        - bg: control flow graph. the graph gives access to the use-def
 *                   chains that describe data dependencies between basic blocks
 *
 *   Facilities for debugging decompiler plugins:
 *      Many decompiler objects have a member function named dstr().
 *      These functions create a text representation of the object and return
 *      a pointer to it. They are very convenient to use in a debugger instead of
 *      inspecting class fields manually. The mba_t object does not have the
 *      dstr() function because its text representation very long. Instead, we
 *      provide the mba_t::dump_mba() and mba_t::dump() functions.
 *
 *      To ensure that your plugin manipulates the microcode in a correct way,
 *      please call mba_t::verify() before returning control to the decompiler.
 *
 */

#pragma once



typedef uint64 uvlr_t;
typedef int64 svlr_t;
enum { MAX_VLR_SIZE = sizeof(uvlr_t) };
const uvlr_t MAX_VLR_VALUE = uvlr_t(-1);
const svlr_t MAX_VLR_SVALUE = svlr_t(uvlr_t(-1) >> 1);
const svlr_t MIN_VLR_SVALUE = ~MAX_VLR_SVALUE;

//-------------------------------------------------------------------------
inline uvlr_t max_vlr_value(int size)
{
  return size == MAX_VLR_SIZE
       ? MAX_VLR_VALUE
       : (uvlr_t(1) << (size * 8)) - 1;
}
inline uvlr_t min_vlr_svalue(int size)
{
  return size == MAX_VLR_SIZE
       ? MIN_VLR_SVALUE
       : (uvlr_t(1) << (size * 8 - 1));
}
inline uvlr_t max_vlr_svalue(int size)
{
  return size == MAX_VLR_SIZE
       ? MAX_VLR_SVALUE
       : (uvlr_t(1) << (size * 8 - 1)) - 1;
}

enum cmpop_t
{ // the order of comparisons is the same as in microcode opcodes
  CMP_NZ,
  CMP_Z,
  CMP_AE,
  CMP_B,
  CMP_A,
  CMP_BE,
  CMP_GT,
  CMP_GE,
  CMP_LT,
  CMP_LE,
};
inline bool is_unsigned_cmpop(cmpop_t cmpop)
{
  return cmpop >= CMP_AE && cmpop <= CMP_BE;
}
inline bool is_signed_cmpop(cmpop_t cmpop)
{
  return cmpop >= CMP_GT && cmpop <= CMP_LE;
}
inline bool is_cmpop_with_eq(cmpop_t cmpop)
{
  return cmpop == CMP_AE
      || cmpop == CMP_BE
      || cmpop == CMP_GE
      || cmpop == CMP_LE;
}
inline bool is_cmpop_without_eq(cmpop_t cmpop)
{
  return cmpop == CMP_A
      || cmpop == CMP_B
      || cmpop == CMP_GT
      || cmpop == CMP_LT;
}

//-------------------------------------------------------------------------
// value-range class to keep possible operand value(s).
class valrng_t
{
protected:
  int flags;
#define VLR_TYPE 0x0F     // valrng_t type
#define   VLR_NONE   0x00 //   no values
#define   VLR_ALL    0x01 //   all values
#define   VLR_IVLS   0x02 //   union of disjoint intervals
#define   VLR_RANGE  0x03 //   strided range
#define   VLR_SRANGE 0x04 //   strided range with signed bound
#define   VLR_BITS   0x05 //   known bits
#define   VLR_SECT   0x06 //   intersection of sub-ranges
                          //   each sub-range should be simple or union
#define   VLR_UNION  0x07 //   union of sub-ranges
                          //   each sub-range should be simple or
                          //   intersection
#define   VLR_UNK    0x08 //   unknown value (like 'null' in SQL)
  int size;               // operand size: 1..8 bytes
                          // all values must fall within the size
  union
  {
    struct                // VLR_RANGE/VLR_SRANGE
    {                     // values that are between VALUE and LIMIT
                          // and conform to: value+stride*N
      uvlr_t value;       // initial value
      uvlr_t limit;       // final value
                          // we adjust LIMIT to be on the STRIDE lattice
      svlr_t stride;      // stride between values
    };
    struct                // VLR_BITS
    {
      uvlr_t zeroes;      // bits known to be clear
      uvlr_t ones;        // bits known to be set
    };
    char reserved[sizeof(qvector<int>)];
                          // VLR_IVLS/VLR_SECT/VLR_UNION
  };
  void hexapi clear();
  void hexapi copy(const valrng_t &r);
  valrng_t &hexapi assign(const valrng_t &r);

public:
  explicit valrng_t(int size_ = MAX_VLR_SIZE)
    : flags(VLR_NONE), size(size_), value(0), limit(0), stride(0) {}
  valrng_t(const valrng_t &r) { copy(r); }
  ~valrng_t() { clear(); }
  valrng_t &operator=(const valrng_t &r) { return assign(r); }
  void swap(valrng_t &r) { qswap(*this, r); }
  DECLARE_COMPARISONS(valrng_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  void set_none() { clear(); }
  void set_all() { clear(); flags = VLR_ALL; }
  void set_unk() { clear(); flags = VLR_UNK; }
  void hexapi set_eq(uvlr_t v);
  void hexapi set_cmp(cmpop_t cmp, uvlr_t _value);

  // reduce size
  // it takes the low part of size NEW_SIZE
  // it returns "true" if size is changed successfully.
  // e.g.: valrng_t vr(2); vr.set_eq(0x1234);
  //       vr.reduce_size(1);
  //       uvlr_t v; vr.cvt_to_single_value(&v);
  //       assert(v == 0x34);
  bool hexapi reduce_size(int new_size);

  // Perform intersection or union or inversion.
  // \return did we change something in THIS?
  bool hexapi intersect_with(const valrng_t &r);
  bool hexapi unite_with(const valrng_t &r);
  void hexapi inverse(); // works for VLR_IVLS only

  bool empty() const { return flags == VLR_NONE; }
  bool all_values() const { return flags == VLR_ALL; }
  bool is_unknown() const { return flags == VLR_UNK; }
  bool hexapi has(uvlr_t v) const;

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;

  bool hexapi cvt_to_single_value(uvlr_t *v) const;
  bool hexapi cvt_to_cmp(cmpop_t *cmp, uvlr_t *val) const;

  int get_size() const { return size; }
  uvlr_t max_value()  const { return max_vlr_value(size);  }
  uvlr_t min_svalue() const { return min_vlr_svalue(size); }
  uvlr_t max_svalue() const { return max_vlr_svalue(size); }
};
DECLARE_TYPE_AS_MOVABLE(valrng_t);


/// Get textual description of an error code
/// \param out  the output buffer for the error description
/// \param code \ref MERR_
/// \param mba  the microcode array
/// \return the error address

ea_t hexapi get_merror_desc(qstring *out, merror_t code, mba_t *mba);

//-------------------------------------------------------------------------
/// Exception object: decompiler failure information
struct hexrays_failure_t
{
  merror_t code = MERR_OK;      ///< \ref MERR_
  ea_t errea = BADADDR;         ///< associated address
  qstring str;                  ///< string information
  hexrays_failure_t() {}
  hexrays_failure_t(merror_t c, ea_t ea, const char *buf=nullptr) : code(c), errea(ea), str(buf) {}
  hexrays_failure_t(merror_t c, ea_t ea, const qstring &buf) : code(c), errea(ea), str(buf) {}
  qstring hexapi desc() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler exception
struct vd_failure_t : public std::exception
{
  hexrays_failure_t hf;
  vd_failure_t() {}
  vd_failure_t(merror_t code, ea_t ea, const char *buf=nullptr) : hf(code, ea, buf) {}
  vd_failure_t(merror_t code, ea_t ea, const qstring &buf) : hf(code, ea, buf) {}
  vd_failure_t(const hexrays_failure_t &_hf) : hf(_hf) {}
  qstring desc() const { return hf.desc(); }
#ifndef SWIG
  virtual const char *what() const noexcept override { return "decompilation failure"; }
#endif
#ifdef __GNUC__
  ~vd_failure_t() throw() {}
#endif
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler internal error
struct vd_interr_t : public vd_failure_t
{
  vd_interr_t(ea_t ea, const qstring &buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
  vd_interr_t(ea_t ea, const char *buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
};

//-------------------------------------------------------------------------
// List of microinstruction opcodes.
// The order of setX and jX insns is important, it is used in the code.

// Instructions marked with *F may have the FPINSN bit set and operate on fp values
// Instructions marked with +F must have the FPINSN bit set. They always operate on fp values
// Other instructions do not operate on fp values.

enum mcode_t
{
  m_nop    = 0x00, // nop                       // no operation
  m_stx    = 0x01, // stx  l,    {r=sel, d=off} // store register to memory     *F
  m_ldx    = 0x02, // ldx  {l=sel,r=off}, d     // load register from memory    *F
  m_ldc    = 0x03, // ldc  l=const,     d       // load constant
  m_mov    = 0x04, // mov  l,           d       // move                         *F
  m_neg    = 0x05, // neg  l,           d       // negate
  m_lnot   = 0x06, // lnot l,           d       // logical not
  m_bnot   = 0x07, // bnot l,           d       // bitwise not
  m_xds    = 0x08, // xds  l,           d       // extend (signed)
  m_xdu    = 0x09, // xdu  l,           d       // extend (unsigned)
  m_low    = 0x0A, // low  l,           d       // take low part
  m_high   = 0x0B, // high l,           d       // take high part
  m_add    = 0x0C, // add  l,   r,      d       // l + r -> dst
  m_sub    = 0x0D, // sub  l,   r,      d       // l - r -> dst
  m_mul    = 0x0E, // mul  l,   r,      d       // l * r -> dst
  m_udiv   = 0x0F, // udiv l,   r,      d       // l / r -> dst
  m_sdiv   = 0x10, // sdiv l,   r,      d       // l / r -> dst
  m_umod   = 0x11, // umod l,   r,      d       // l % r -> dst
  m_smod   = 0x12, // smod l,   r,      d       // l % r -> dst
  m_or     = 0x13, // or   l,   r,      d       // bitwise or
  m_and    = 0x14, // and  l,   r,      d       // bitwise and
  m_xor    = 0x15, // xor  l,   r,      d       // bitwise xor
  m_shl    = 0x16, // shl  l,   r,      d       // shift logical left
  m_shr    = 0x17, // shr  l,   r,      d       // shift logical right
  m_sar    = 0x18, // sar  l,   r,      d       // shift arithmetic right
  m_cfadd  = 0x19, // cfadd l,  r,    d=carry   // calculate carry    bit of (l+r)
  m_ofadd  = 0x1A, // ofadd l,  r,    d=overf   // calculate overflow bit of (l+r)
  m_cfshl  = 0x1B, // cfshl l,  r,    d=carry   // calculate carry    bit of (l<<r)
  m_cfshr  = 0x1C, // cfshr l,  r,    d=carry   // calculate carry    bit of (l>>r)
  m_sets   = 0x1D, // sets  l,          d=byte  SF=1          Sign
  m_seto   = 0x1E, // seto  l,  r,      d=byte  OF=1          Overflow of (l-r)
  m_setp   = 0x1F, // setp  l,  r,      d=byte  PF=1          Unordered/Parity        *F
  m_setnz  = 0x20, // setnz l,  r,      d=byte  ZF=0          Not Equal               *F
  m_setz   = 0x21, // setz  l,  r,      d=byte  ZF=1          Equal                   *F
  m_setae  = 0x22, // setae l,  r,      d=byte  CF=0          Unsigned Above or Equal *F
  m_setb   = 0x23, // setb  l,  r,      d=byte  CF=1          Unsigned Below          *F
  m_seta   = 0x24, // seta  l,  r,      d=byte  CF=0 & ZF=0   Unsigned Above          *F
  m_setbe  = 0x25, // setbe l,  r,      d=byte  CF=1 | ZF=1   Unsigned Below or Equal *F
  m_setg   = 0x26, // setg  l,  r,      d=byte  SF=OF & ZF=0  Signed Greater
  m_setge  = 0x27, // setge l,  r,      d=byte  SF=OF         Signed Greater or Equal
  m_setl   = 0x28, // setl  l,  r,      d=byte  SF!=OF        Signed Less
  m_setle  = 0x29, // setle l,  r,      d=byte  SF!=OF | ZF=1 Signed Less or Equal
  m_jcnd   = 0x2A, // jcnd   l,         d       // d is mop_v or mop_b
  m_jnz    = 0x2B, // jnz    l, r,      d       // ZF=0          Not Equal               *F
  m_jz     = 0x2C, // jz     l, r,      d       // ZF=1          Equal                   *F
  m_jae    = 0x2D, // jae    l, r,      d       // CF=0          Unsigned Above or Equal *F
  m_jb     = 0x2E, // jb     l, r,      d       // CF=1          Unsigned Below          *F
  m_ja     = 0x2F, // ja     l, r,      d       // CF=0 & ZF=0   Unsigned Above          *F
  m_jbe    = 0x30, // jbe    l, r,      d       // CF=1 | ZF=1   Unsigned Below or Equal *F
  m_jg     = 0x31, // jg     l, r,      d       // SF=OF & ZF=0  Signed Greater
  m_jge    = 0x32, // jge    l, r,      d       // SF=OF         Signed Greater or Equal
  m_jl     = 0x33, // jl     l, r,      d       // SF!=OF        Signed Less
  m_jle    = 0x34, // jle    l, r,      d       // SF!=OF | ZF=1 Signed Less or Equal
  m_jtbl   = 0x35, // jtbl   l, r=mcases        // Table jump
  m_ijmp   = 0x36, // ijmp       {r=sel, d=off} // indirect unconditional jump
  m_goto   = 0x37, // goto   l                  // l is mop_v or mop_b
  m_call   = 0x38, // call   l          d       // l is mop_v or mop_b or mop_h
  m_icall  = 0x39, // icall  {l=sel, r=off} d   // indirect call
  m_ret    = 0x3A, // ret
  m_push   = 0x3B, // push   l
  m_pop    = 0x3C, // pop               d
  m_und    = 0x3D, // und               d       // undefine
  m_ext    = 0x3E, // ext  in1, in2,  out1      // external insn, not microcode *F
  m_f2i    = 0x3F, // f2i    l,    d       int(l) => d; convert fp -> integer   +F
  m_f2u    = 0x40, // f2u    l,    d       uint(l)=> d; convert fp -> uinteger  +F
  m_i2f    = 0x41, // i2f    l,    d       fp(l)  => d; convert integer -> fp   +F
  m_u2f    = 0x42, // i2f    l,    d       fp(l)  => d; convert uinteger -> fp  +F
  m_f2f    = 0x43, // f2f    l,    d       l      => d; change fp precision     +F
  m_fneg   = 0x44, // fneg   l,    d       -l     => d; change sign             +F
  m_fadd   = 0x45, // fadd   l, r, d       l + r  => d; add                     +F
  m_fsub   = 0x46, // fsub   l, r, d       l - r  => d; subtract                +F
  m_fmul   = 0x47, // fmul   l, r, d       l * r  => d; multiply                +F
  m_fdiv   = 0x48, // fdiv   l, r, d       l / r  => d; divide                  +F
#define m_max 0x49 // first unused opcode
};

/// Must an instruction with the given opcode be the last one in a block?
/// Such opcodes are called closing opcodes.
/// \param mcode instruction opcode
/// \param including_calls should m_call/m_icall be considered as the closing opcodes?
/// If this function returns true, the opcode cannot appear in the middle
/// of a block. Calls are a special case: unknown calls (\ref is_unknown_call)
/// are considered as closing opcodes.

THREAD_SAFE bool hexapi must_mcode_close_block(mcode_t mcode, bool including_calls);


/// May opcode be propagated?
/// Such opcodes can be used in sub-instructions (nested instructions)
/// There is a handful of non-propagatable opcodes, like jumps, ret, nop, etc
/// All other regular opcodes are propagatable and may appear in a nested
/// instruction.

THREAD_SAFE bool hexapi is_mcode_propagatable(mcode_t mcode);


// Is add or sub instruction?
inline THREAD_SAFE bool is_mcode_addsub(mcode_t mcode) { return mcode == m_add || mcode == m_sub; }
// Is xds or xdu instruction? We use 'xdsu' as a shortcut for 'xds or xdu'
inline THREAD_SAFE bool is_mcode_xdsu(mcode_t mcode) { return mcode == m_xds || mcode == m_xdu; }
// Is a 'set' instruction? (an instruction that sets a condition code)
inline THREAD_SAFE bool is_mcode_set(mcode_t mcode) { return mcode >= m_sets && mcode <= m_setle; }
// Is a 1-operand 'set' instruction? Only 'sets' is in this group
inline THREAD_SAFE bool is_mcode_set1(mcode_t mcode) { return mcode == m_sets; }
// Is a 1-operand conditional jump instruction? Only 'jcnd' is in this group
inline THREAD_SAFE bool is_mcode_j1(mcode_t mcode) { return mcode == m_jcnd; }
// Is a conditional jump?
inline THREAD_SAFE bool is_mcode_jcond(mcode_t mcode) { return mcode >= m_jcnd && mcode <= m_jle; }
// Is a 'set' instruction that can be converted into a conditional jump?
inline THREAD_SAFE bool is_mcode_convertible_to_jmp(mcode_t mcode) { return mcode >= m_setnz && mcode <= m_setle; }
// Is a conditional jump instruction that can be converted into a 'set'?
inline THREAD_SAFE bool is_mcode_convertible_to_set(mcode_t mcode) { return mcode >= m_jnz && mcode <= m_jle; }
// Is a call instruction? (direct or indirect)
inline THREAD_SAFE bool is_mcode_call(mcode_t mcode) { return mcode == m_call || mcode == m_icall; }
// Must be an FPU instruction?
inline THREAD_SAFE bool is_mcode_fpu(mcode_t mcode) { return mcode >= m_f2i; }
// Is a commutative instruction?
inline THREAD_SAFE bool is_mcode_commutative(mcode_t mcode)
{
  return mcode == m_add
      || mcode == m_mul
      || mcode == m_or
      || mcode == m_and
      || mcode == m_xor
      || mcode == m_setz
      || mcode == m_setnz
      || mcode == m_cfadd
      || mcode == m_ofadd;
}
// Is a shift instruction?
inline THREAD_SAFE bool is_mcode_shift(mcode_t mcode)
{
  return mcode == m_shl
      || mcode == m_shr
      || mcode == m_sar;
}
// Is a kind of div or mod instruction?
inline THREAD_SAFE bool is_mcode_divmod(mcode_t op)
{
  return op == m_udiv || op == m_sdiv || op == m_umod || op == m_smod;
}
// Is an instruction with the selector/offset pair?
inline THREAD_SAFE bool has_mcode_seloff(mcode_t op)
{
  return op == m_ldx || op == m_stx || op == m_icall || op == m_ijmp;
}

// Convert setX opcode into corresponding jX opcode
// This function relies on the order of setX and jX opcodes!
inline THREAD_SAFE mcode_t set2jcnd(mcode_t code)
{
  return mcode_t(code - m_setnz + m_jnz);
}

// Convert setX opcode into corresponding jX opcode
// This function relies on the order of setX and jX opcodes!
inline THREAD_SAFE mcode_t jcnd2set(mcode_t code)
{
  return mcode_t(code + m_setnz - m_jnz);
}

// Negate a conditional opcode.
// Conditional jumps can be negated, example: jle -> jg
// 'Set' instruction can be negated, example: seta -> setbe
// If the opcode cannot be negated, return m_nop
THREAD_SAFE mcode_t hexapi negate_mcode_relation(mcode_t code);


// Swap a conditional opcode.
// Only conditional jumps and set instructions can be swapped.
// The returned opcode the one required for swapped operands.
// Example "x > y" is the same as "y < x", therefore swap(m_jg) is m_jl.
// If the opcode cannot be swapped, return m_nop

THREAD_SAFE mcode_t hexapi swap_mcode_relation(mcode_t code);

// Return the opcode that performs signed operation.
// Examples: jae -> jge; udiv -> sdiv
// If the opcode cannot be transformed into signed form, simply return it.

THREAD_SAFE mcode_t hexapi get_signed_mcode(mcode_t code);


// Return the opcode that performs unsigned operation.
// Examples: jl -> jb; xds -> xdu
// If the opcode cannot be transformed into unsigned form, simply return it.

THREAD_SAFE mcode_t hexapi get_unsigned_mcode(mcode_t code);

// Does the opcode perform a signed operation?
inline THREAD_SAFE bool is_signed_mcode(mcode_t code) { return get_unsigned_mcode(code) != code; }
// Does the opcode perform a unsigned operation?
inline THREAD_SAFE bool is_unsigned_mcode(mcode_t code) { return get_signed_mcode(code) != code; }


// Does the 'd' operand gets modified by the instruction?
// Example: "add l,r,d" modifies d, while instructions
// like jcnd, ijmp, stx does not modify it.
// Note: this function returns 'true' for m_ext but it may be wrong.
// Use minsn_t::modifies_d() if you have minsn_t.

THREAD_SAFE bool hexapi mcode_modifies_d(mcode_t mcode);


// Processor condition codes are mapped to the first microregisters
// The order is important, see mop_t::is_cc()
const mreg_t mr_none  = mreg_t(-1);
const mreg_t mr_cf    = mreg_t(0);      // carry bit
const mreg_t mr_zf    = mreg_t(1);      // zero bit
const mreg_t mr_sf    = mreg_t(2);      // sign bit
const mreg_t mr_of    = mreg_t(3);      // overflow bit
const mreg_t mr_pf    = mreg_t(4);      // parity bit
const int    cc_count = mr_pf - mr_cf + 1; // number of condition code registers
const mreg_t mr_cc    = mreg_t(5);       // synthetic condition code, used internally
const mreg_t mr_first = mreg_t(8);       // the first processor specific register

//-------------------------------------------------------------------------
//-------------------------------------------------------------------------
/// \defgroup type Type string related declarations
/// Type related functions and class.
///@{

/// Print the specified type info.
/// This function can be used from a debugger by typing "tif->dstr()"

const char *hexapi dstr(const tinfo_t *tif);


/// Verify a type string.
/// \return true if type string is correct

bool hexapi is_type_correct(const type_t *ptr);


/// Is a small structure or union?
/// \return true if the type is a small UDT (user defined type).
///              Small UDTs fit into a register (or pair or registers) as a rule.

bool hexapi is_small_udt(const tinfo_t &tif);


/// Is definitely a non-boolean type?
/// \return true if the type is a non-boolean type (non bool and well defined)

bool hexapi is_nonbool_type(const tinfo_t &type);


/// Is a boolean type?
/// \return true if the type is a boolean type

bool hexapi is_bool_type(const tinfo_t &type);


/// Is a pointer or array type?
inline THREAD_SAFE bool is_ptr_or_array(type_t t)
{
  return is_type_ptr(t) || is_type_array(t);
}

/// Is a pointer, array, or function type?
inline THREAD_SAFE bool is_paf(type_t t)
{
  return is_ptr_or_array(t) || is_type_func(t);
}

/// Is struct/union/enum definition (not declaration)?
inline THREAD_SAFE bool is_inplace_def(const tinfo_t &type)
{
  return type.is_decl_complex() && !type.is_typeref();
}

/// Calculate number of partial subtypes.
/// \return number of partial subtypes. The bigger is this number, the uglier is the type.

int hexapi partial_type_num(const tinfo_t &type);


/// Get a type of a floating point value with the specified width
/// \return type info object
/// \param width width of the desired type

tinfo_t hexapi get_float_type(int width);


/// Create a type info by width and sign.
/// Returns a simple type (examples: int, short) with the given width and sign.
/// \param srcwidth size of the type in bytes
/// \param sign sign of the type

tinfo_t hexapi get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign);


/// Create a partial type info by width.
/// Returns a partially defined type (examples: _DWORD, _BYTE) with the given width.
/// \param size size of the type in bytes

tinfo_t hexapi get_unk_type(int size);


/// Generate a dummy pointer type
///  \param ptrsize size of pointed object
///  \param isfp is floating point object?

tinfo_t hexapi dummy_ptrtype(int ptrsize, bool isfp);


/// Create a pointer type.
/// This function performs the following conversion: "type" -> "type*"
/// \param type object type.
/// \return "type*". for example, if 'char' is passed as the argument,
//          the function will return 'char *'

tinfo_t hexapi make_pointer(const tinfo_t &type);


/// Create a reference to a named type.
/// \param name type name
/// \return type which refers to the specified name. For example, if name is "DWORD",
///             the type info which refers to "DWORD" is created.

tinfo_t hexapi create_typedef(const char *name);


/// Create a reference to an ordinal type.
/// \param n ordinal number of the type
/// \return type which refers to the specified ordinal. For example, if n is 1,
///             the type info which refers to ordinal type 1 is created.

inline tinfo_t create_typedef(int n)
{
  tinfo_t tif;
  tif.create_typedef(nullptr, n);
  return tif;
}

/// Type source (where the type information comes from)
enum type_source_t
{
  GUESSED_NONE,  // not guessed, specified by the user
  GUESSED_WEAK,  // not guessed, comes from idb
  GUESSED_FUNC,  // guessed as a function
  GUESSED_DATA,  // guessed as a data item
  TS_NOELL   = 0x8000000, // can be used in set_type() to avoid merging into ellipsis
  TS_SHRINK  = 0x4000000, // can be used in set_type() to prefer smaller arguments
  TS_DONTREF = 0x2000000, // do not mark type as referenced (referenced_types)
  TS_MASK    = 0xE000000, // all high bits
};


/// Get a global type.
/// Global types are types of addressable objects and struct/union/enum types
/// \param id address or id of the object
/// \param tif buffer for the answer
/// \param guess what kind of types to consider
/// \return success

bool hexapi get_type(uval_t id, tinfo_t *tif, type_source_t guess);


/// Set a global type.
/// \param id address or id of the object
/// \param tif new type info
/// \param source where the type comes from
/// \param force true means to set the type as is, false means to merge the
///        new type with the possibly existing old type info.
/// \return success

bool hexapi set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force=false);

///@}

//-------------------------------------------------------------------------
// We use our own class to store argument and variable locations.
// It is called vdloc_t that stands for 'vd location'.
// 'vd' is the internal name of the decompiler, it stands for 'visual decompiler'.
// The main differences between vdloc and argloc_t:
//   ALOC_REG1: the offset is always 0, so it is not used. the register number
//              uses the whole ~VLOC_MASK field.
//   ALOC_STACK: stack offsets are always positive because they are based on
//              the lowest value of sp in the function.
class vdloc_t : public argloc_t
{
  int regoff(); // inaccessible & undefined: regoff() should not be used
public:
  // Get the register number.
  // This function works only for ALOC_REG1 and ALOC_REG2 location types.
  // It uses all available bits for register number for ALOC_REG1
  int reg1() const { return atype() == ALOC_REG2 ? argloc_t::reg1() : get_reginfo(); }

  // Set vdloc to point to the specified register without cleaning it up.
  // This is a dangerous function, use set_reg1() instead unless you understand
  // what it means to cleanup an argloc.
  void _set_reg1(int r1) { argloc_t::_set_reg1(r1, r1>>16); }

  // Set vdloc to point to the specified register.
  void set_reg1(int r1) { cleanup_argloc(this); _set_reg1(r1); }

  // Use member functions of argloc_t for other location types.

  // Return textual representation.
  // Note: this and all other dstr() functions can be used from a debugger.
  // It is much easier than to inspect the memory contents byte by byte.
  const char *hexapi dstr(int width=0) const;
  DECLARE_COMPARISONS(vdloc_t);
  bool hexapi is_aliasable(const mba_t *mb, int size) const;
};

/// Print vdloc.
/// Since vdloc does not always carry the size info, we pass it as NBYTES..
void hexapi print_vdloc(qstring *vout, const vdloc_t &loc, int nbytes);

//-------------------------------------------------------------------------
/// Do two arglocs overlap?
bool hexapi arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2);

/// Local variable locator.
/// Local variables are located using definition ea and location.
/// Each variable must have a unique locator, this is how we tell them apart.
struct lvar_locator_t
{
  vdloc_t location;     ///< Variable location.
  ea_t defea = BADADDR; ///< Definition address. Usually, this is the address
                        ///< of the instruction that initializes the variable.
                        ///< In some cases it can be a fictional address.

  lvar_locator_t() {}
  lvar_locator_t(const vdloc_t &loc, ea_t ea) : location(loc), defea(ea) {}
  /// Get offset of the varialbe in the stack frame.
  /// \return a non-negative value for stack variables. The value is
  ///         an offset from the bottom of the stack frame in terms of
  ///         vd-offsets.
  ///         negative values mean error (not a stack variable)
  sval_t get_stkoff() const
  {
    return location.is_stkoff() ? location.stkoff() : -1;
  }
  /// Is variable located on one register?
  bool is_reg1() const { return  location.is_reg1(); }
  /// Is variable located on two registers?
  bool is_reg2() const { return  location.is_reg2(); }
  /// Is variable located on register(s)?
  bool is_reg_var() const { return location.is_reg(); }
  /// Is variable located on the stack?
  bool is_stk_var() const { return location.is_stkoff(); }
  /// Is variable scattered?
  bool is_scattered() const { return location.is_scattered(); }
  /// Get the register number of the variable
  mreg_t get_reg1() const { return location.reg1(); }
  /// Get the number of the second register (works only for ALOC_REG2 lvars)
  mreg_t get_reg2() const { return location.reg2(); }
  /// Get information about scattered variable
  const scattered_aloc_t &get_scattered() const { return location.scattered(); }
        scattered_aloc_t &get_scattered()       { return location.scattered(); }
  DECLARE_COMPARISONS(lvar_locator_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  // Debugging: get textual representation of a lvar locator.
  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(lvar_locator_t);
typedef qvector<lvar_locator_t> lvar_locators;

/// Definition of a local variable (register or stack) #var #lvar
class lvar_t : public lvar_locator_t
{
  friend class mba_t;
  int flags;                    ///< \ref CVAR_
/// \defgroup CVAR_ Local variable property bits
/// Used in lvar_t::flags
///@{
#define CVAR_USED    0x00000001 ///< is used in the code?
#define CVAR_TYPE    0x00000002 ///< the type is defined?
#define CVAR_NAME    0x00000004 ///< has nice name?
#define CVAR_MREG    0x00000008 ///< corresponding mregs were replaced?
#define CVAR_NOWD    0x00000010 ///< width is unknown
#define CVAR_UNAME   0x00000020 ///< user-defined name
#define CVAR_UTYPE   0x00000040 ///< user-defined type
#define CVAR_RESULT  0x00000080 ///< function result variable
#define CVAR_ARG     0x00000100 ///< function argument
#define CVAR_FAKE    0x00000200 ///< fake variable (return var or va_list)
#define CVAR_OVER    0x00000400 ///< overlapping variable
#define CVAR_FLOAT   0x00000800 ///< used in a fpu insn
#define CVAR_SPOILED 0x00001000 ///< internal flag, do not use: spoiled var
#define CVAR_MAPDST  0x00002000 ///< other variables are mapped to this var
#define CVAR_PARTIAL 0x00004000 ///< variable type is partialy defined
#define CVAR_THISARG 0x00008000 ///< 'this' argument of c++ member functions
#define CVAR_SPLIT   0x00010000 ///< variable was created by an explicit request
                                ///< otherwise we could reuse an existing var
#define CVAR_REGNAME 0x00020000 ///< has a register name (like _RAX): if lvar
                                ///< is used by an m_ext instruction
#define CVAR_NOPTR   0x00040000 ///< variable cannot be a pointer (user choice)
#define CVAR_DUMMY   0x00080000 ///< dummy argument (added to fill a hole in
                                ///< the argument list)
#define CVAR_NOTARG  0x00100000 ///< variable cannot be an input argument
#define CVAR_AUTOMAP 0x00200000 ///< variable was automatically mapped
#define CVAR_BYREF   0x00400000 ///< the address of the variable was taken
#define CVAR_INASM   0x00800000 ///< variable is used in instructions translated
                                ///< into __asm {...}
#define CVAR_UNUSED  0x01000000 ///< user-defined __unused attribute
                                ///< meaningful only if: is_arg_var() && !mba->final_type
#define CVAR_SHARED  0x02000000 ///< variable is mapped to several chains
#define CVAR_SCARG   0x04000000 ///< variable is a stack argument that was
                                ///< transformed from a scattered one
#define CVAR_NOPROP  0x08000000 ///< forbidden to propagate the variable
///@}

public:
  qstring name;          ///< variable name.
                         ///< use mba_t::set_nice_lvar_name() and
                         ///< mba_t::set_user_lvar_name() to modify it
  qstring cmt;           ///< variable comment string
  tinfo_t tif;           ///< variable type
  int width = 0;         ///< variable size in bytes
  int defblk = -1;       ///< first block defining the variable.
                         ///< 0 for args, -1 if unknown
  uint64 divisor = 0;    ///< max known divisor of the variable

  lvar_t() : flags(CVAR_USED) {}
  lvar_t(const qstring &n, const vdloc_t &l, ea_t e, const tinfo_t &t, int w, int db)
    : lvar_locator_t(l, e), flags(CVAR_USED), name(n), tif(t), width(w), defblk(db)
  {
  }
  // Debugging: get textual representation of a local variable.
  const char *hexapi dstr() const;

  /// Is the variable used in the code?
  bool used()  const { return (flags & CVAR_USED) != 0; }
  /// Has the variable a type?
  bool typed() const { return (flags & CVAR_TYPE) != 0; }
  /// Have corresponding microregs been replaced by references to this variable?
  bool mreg_done() const { return (flags & CVAR_MREG) != 0; }
  /// Does the variable have a nice name?
  bool has_nice_name() const { return (flags & CVAR_NAME) != 0; }
  /// Do we know the width of the variable?
  bool is_unknown_width() const { return (flags & CVAR_NOWD) != 0; }
  /// Has any user-defined information?
  bool has_user_info() const
  {
    return (flags & (CVAR_UNAME|CVAR_UTYPE|CVAR_NOPTR|CVAR_UNUSED|CVAR_NOPROP)) != 0
        || !cmt.empty();
  }
  /// Has user-defined name?
  bool has_user_name() const { return (flags & CVAR_UNAME) != 0; }
  /// Has user-defined type?
  bool has_user_type() const { return (flags & CVAR_UTYPE) != 0; }
  /// Is the function result?
  bool is_result_var() const { return (flags & CVAR_RESULT) != 0; }
  /// Is the function argument?
  bool is_arg_var() const { return (flags & CVAR_ARG) != 0; }
  /// Is the promoted function argument?
  bool hexapi is_promoted_arg() const;
  /// Is fake return variable?
  bool is_fake_var() const { return (flags & CVAR_FAKE) != 0; }
  /// Is overlapped variable?
  bool is_overlapped_var() const { return (flags & CVAR_OVER) != 0; }
  /// Used by a fpu insn?
  bool is_floating_var() const { return (flags & CVAR_FLOAT) != 0; }
  /// Is spoiled var? (meaningful only during lvar allocation)
  bool is_spoiled_var() const { return (flags & CVAR_SPOILED) != 0; }
  /// Variable type should be handled as a partial one
  bool is_partialy_typed() const { return (flags & CVAR_PARTIAL) != 0; }
  /// Variable type should not be a pointer
  bool is_noptr_var() const { return (flags & CVAR_NOPTR) != 0; }
  /// Other variable(s) map to this var?
  bool is_mapdst_var() const { return (flags & CVAR_MAPDST) != 0; }
  /// Is 'this' argument of a C++ member function?
  bool is_thisarg() const { return (flags & CVAR_THISARG) != 0; }
  /// Is a split variable?
  bool is_split_var() const { return (flags & CVAR_SPLIT) != 0; }
  /// Has a register name? (like _RAX)
  bool has_regname() const { return (flags & CVAR_REGNAME) != 0; }
  /// Is variable used in an instruction translated into __asm?
  bool in_asm() const { return (flags & CVAR_INASM) != 0; }
  /// Is a dummy argument (added to fill a hole in the argument list)
  bool is_dummy_arg() const { return (flags & CVAR_DUMMY) != 0; }
  /// Is a local variable? (local variable cannot be an input argument)
  bool is_notarg() const { return (flags & CVAR_NOTARG) != 0; }
  /// Was the variable automatically mapped to another variable?
  bool is_automapped() const { return (flags & CVAR_AUTOMAP) != 0; }
  /// Was the address of the variable taken?
  bool is_used_byref() const { return (flags & CVAR_BYREF) != 0; }
  /// Was declared as __unused by the user? See CVAR_UNUSED
  bool is_decl_unused() const { return (flags & CVAR_UNUSED) != 0; }
  /// Is lvar mapped to several chains
  bool is_shared() const { return (flags & CVAR_SHARED) != 0; }
  /// Was lvar transformed from a scattered argument?
  bool was_scattered_arg() const { return (flags & CVAR_SCARG) != 0; }
  /// Is it forbidden to propagate the variable?
  bool is_noprop() const { return (flags & CVAR_NOPROP) != 0; }
  void set_used() { flags |= CVAR_USED; }
  void clear_used() { flags &= ~CVAR_USED; }
  void set_typed() { flags |= CVAR_TYPE; clr_noptr_var(); }
  void set_non_typed() { flags &= ~CVAR_TYPE; }
  void clr_user_info() { flags &= ~(CVAR_UNAME|CVAR_UTYPE|CVAR_NOPTR); }
  void set_user_name() { flags |= CVAR_NAME|CVAR_UNAME; }
  void set_user_type() { flags |= CVAR_TYPE|CVAR_UTYPE; }
  void clr_user_type() { flags &= ~CVAR_UTYPE; }
  void clr_user_name() { flags &= ~CVAR_UNAME; }
  void set_mreg_done() { flags |= CVAR_MREG; }
  void clr_mreg_done() { flags &= ~CVAR_MREG; }
  void set_unknown_width() { flags |= CVAR_NOWD; }
  void clr_unknown_width() { flags &= ~CVAR_NOWD; }
  void set_arg_var() { flags |= CVAR_ARG; }
  void clr_arg_var() { flags &= ~(CVAR_ARG|CVAR_THISARG); }
  void set_fake_var() { flags |= CVAR_FAKE; }
  void clr_fake_var() { flags &= ~CVAR_FAKE; }
  void set_overlapped_var() { flags |= CVAR_OVER; }
  void clr_overlapped_var() { flags &= ~CVAR_OVER; }
  void set_floating_var() { flags |= CVAR_FLOAT; }
  void clr_floating_var() { flags &= ~CVAR_FLOAT; }
  void set_spoiled_var() { flags |= CVAR_SPOILED; }
  void clr_spoiled_var() { flags &= ~CVAR_SPOILED; }
  void set_mapdst_var() { flags |= CVAR_MAPDST; }
  void clr_mapdst_var() { flags &= ~CVAR_MAPDST; }
  void set_partialy_typed() { flags |= CVAR_PARTIAL; }
  void clr_partialy_typed() { flags &= ~CVAR_PARTIAL; }
  void set_noptr_var() { flags |= CVAR_NOPTR; }
  void clr_noptr_var() { flags &= ~CVAR_NOPTR; }
  void set_thisarg() { flags |= CVAR_THISARG; }
  void clr_thisarg() { flags &= ~CVAR_THISARG; }
  void set_split_var() { flags |= CVAR_SPLIT; }
  void clr_split_var() { flags &= ~CVAR_SPLIT; }
  void set_dummy_arg() { flags |= CVAR_DUMMY; }
  void clr_dummy_arg() { flags &= ~CVAR_DUMMY; }
  void set_notarg() { clr_arg_var(); flags |= CVAR_NOTARG; }
  void clr_notarg() { flags &= ~CVAR_NOTARG; }
  void set_automapped() { flags |= CVAR_AUTOMAP; }
  void clr_automapped() { flags &= ~CVAR_AUTOMAP; }
  void set_used_byref() { flags |= CVAR_BYREF; }
  void clr_used_byref() { flags &= ~CVAR_BYREF; }
  void set_decl_unused() { flags |= CVAR_UNUSED; }
  void clr_decl_unused() { flags &= ~CVAR_UNUSED; }
  void set_shared() { flags |= CVAR_SHARED; }
  void clr_shared() { flags &= ~CVAR_SHARED; }
  void set_scattered_arg() { flags |= CVAR_SCARG; }
  void clr_scattered_arg() { flags &= ~CVAR_SCARG; }
  void set_noprop() { flags |= CVAR_NOPROP; }
  void clr_noprop() { flags &= ~CVAR_NOPROP; }

  /// Do variables overlap?
  bool has_common(const lvar_t &v) const
  {
    return arglocs_overlap(location, width, v.location, v.width);
  }
  /// Does the variable overlap with the specified location?
  bool has_common_bit(const vdloc_t &loc, asize_t width2) const
  {
    return arglocs_overlap(location, width, loc, width2);
  }
  /// Get variable type
  const tinfo_t &type() const { return tif; }
  tinfo_t &type() { return tif; }

  /// Check if the variable accept the specified type.
  /// Some types are forbidden (void, function types, wrong arrays, etc)
  bool hexapi accepts_type(const tinfo_t &t, bool may_change_thisarg=false);
  /// Set variable type
  /// Note: this function does not modify the idb, only the lvar instance
  /// in the memory. For permanent changes see modify_user_lvars()
  /// Also, the variable type is not considered as final by the decompiler
  /// and may be modified later by the type derivation.
  /// In some cases set_final_var_type() may work better, but it does not
  /// do persistent changes to the database neither.
  /// \param t new type
  /// \param may_fail if false and type is bad, interr
  /// \return success
  bool hexapi set_lvar_type(const tinfo_t &t, bool may_fail=false);

  /// Set final variable type.
  void set_final_lvar_type(const tinfo_t &t)
  {
    set_lvar_type(t);
    set_typed();
  }

  /// Change the variable width.
  /// We call the variable size 'width', it is represents the number of bytes.
  /// This function may change the variable type using set_lvar_type().
  /// \param w new width
  /// \param svw_flags combination of SVW_... bits
  /// \return success
  bool hexapi set_width(int w, int svw_flags=0);
#define SVW_INT   0x00 // integer value
#define SVW_FLOAT 0x01 // floating point value
#define SVW_SOFT  0x02 // may fail and return false;
                       // if this bit is not set and the type is bad, interr

  /// Append local variable to mlist.
  /// \param mba ptr to the current mba_t
  /// \param lst list to append to
  /// \param pad_if_scattered if true, append padding bytes in case of scattered lvar
  void hexapi append_list(const mba_t *mba, mlist_t *lst, bool pad_if_scattered=false) const;

  /// Is the variable aliasable?
  /// \param mba ptr to the current mba_t
  /// Aliasable variables may be modified indirectly (through a pointer)
  bool is_aliasable(const mba_t *mba) const
  {
    return location.is_aliasable(mba, width);
  }

};
DECLARE_TYPE_AS_MOVABLE(lvar_t);

/// Vector of local variables
class lvars_t : public qvector<lvar_t>
{
public:
  /// Find an input variable at the specified location.
  /// \param argloc variable location
  /// \param _size variable size in bytes
  /// \return -1 if failed, otherwise an index into 'vars'
  int find_input_lvar(const vdloc_t &argloc, int _size) { return find_lvar(argloc, _size, 0); }


  /// Find an input register variable.
  /// \param reg   register to find
  /// \param _size variable size in bytes
  /// \return -1 if failed, otherwise an index into 'vars'
  int find_input_reg(int reg, int _size=1)
  {
    vdloc_t rloc;
    rloc._set_reg1(reg);
    return find_input_lvar(rloc, _size);
  }


  /// Find a stack variable at the specified location.
  /// \param spoff offset from the minimal sp
  /// \param width variable size in bytes
  /// \return -1 if failed, otherwise an index into 'vars'
  int hexapi find_stkvar(sval_t spoff, int width);


  /// Find a variable at the specified location.
  /// \param ll variable location
  /// \return pointer to variable or nullptr
  lvar_t *hexapi find(const lvar_locator_t &ll);


  /// Find a variable at the specified location.
  /// \param location variable location
  /// \param width variable size in bytes
  /// \param defblk definition block of the lvar. -1 means any block
  /// \return -1 if failed, otherwise an index into 'vars'
  int hexapi find_lvar(const vdloc_t &location, int width, int defblk=-1) const;
};

/// Saved user settings for local variables: name, type, comment.
struct lvar_saved_info_t
{
  lvar_locator_t ll;            ///< Variable locator
  qstring name;                 ///< Name
  tinfo_t type;                 ///< Type
  qstring cmt;                  ///< Comment
  ssize_t size = BADSIZE;       ///< Type size (if not initialized then -1)
  uint32 flags = 0;             ///< \ref LVINF_
/// \defgroup LVINF_ saved user lvar info property bits
/// Used in lvar_saved_info_t::flags
///@{
#define LVINF_KEEP   0x0001     ///< preserve saved user settings regardless of vars
                                ///< for example, if a var loses all its
                                ///< user-defined attributes or even gets
                                ///< destroyed, keep its lvar_saved_info_t.
                                ///< this is used for ephemeral variables that
                                ///< get destroyed by macro recognition.
#define LVINF_SPLIT  0x0002     ///< split allocation of a new variable.
                                ///< forces the decompiler to create a new
                                ///< variable at ll.defea
#define LVINF_NOPTR  0x0004     ///< variable type should not be a pointer
#define LVINF_NOMAP  0x0008     ///< forbid automatic mapping of the variable
#define LVINF_UNUSED 0x0010     ///< unused argument, corresponds to CVAR_UNUSED
#define LVINF_NOPROP 0x0020     ///< don't propagate assignments to this lvar (CVAR_NOPROP)
///@}
  bool has_info() const
  {
    return !name.empty()
        || !type.empty()
        || !cmt.empty()
        || is_split_lvar()
        || is_noptr_lvar()
        || is_nomap_lvar()
        || is_noprop_lvar();
  }
  bool operator==(const lvar_saved_info_t &r) const
  {
    return name == r.name
        && cmt == r.cmt
        && ll == r.ll
        && type == r.type;
  }
  bool operator!=(const lvar_saved_info_t &r) const { return !(*this == r); }
  bool is_kept() const { return (flags & LVINF_KEEP) != 0; }
  void clear_keep() { flags &= ~LVINF_KEEP; }
  void set_keep() { flags |= LVINF_KEEP; }
  bool is_split_lvar() const { return (flags & LVINF_SPLIT) != 0; }
  void set_split_lvar() { flags |= LVINF_SPLIT; }
  void clr_split_lvar() { flags &= ~LVINF_SPLIT; }
  bool is_noptr_lvar() const { return (flags & LVINF_NOPTR) != 0; }
  void set_noptr_lvar() { flags |= LVINF_NOPTR; }
  void clr_noptr_lvar() { flags &= ~LVINF_NOPTR; }
  bool is_nomap_lvar() const { return (flags & LVINF_NOMAP) != 0; }
  void set_nomap_lvar() { flags |= LVINF_NOMAP; }
  void clr_nomap_lvar() { flags &= ~LVINF_NOMAP; }
  bool is_unused_lvar() const { return (flags & LVINF_UNUSED) != 0; }
  void set_unused_lvar() { flags |= LVINF_UNUSED; }
  void clr_unused_lvar() { flags &= ~LVINF_UNUSED; }
  bool is_noprop_lvar() const { return (flags & LVINF_NOPROP) != 0; }
  void set_noprop_lvar() { flags |= LVINF_NOPROP; }
  void clr_noprop_lvar() { flags &= ~LVINF_NOPROP; }
};
DECLARE_TYPE_AS_MOVABLE(lvar_saved_info_t);
typedef qvector<lvar_saved_info_t> lvar_saved_infos_t;

/// Local variable mapping (is used to merge variables)
typedef qmap<lvar_locator_t, lvar_locator_t> lvar_mapping_t;

/// All user-defined information about local variables
struct lvar_uservec_t
{
  /// User-specified names, types, comments for lvars. Variables without
  /// user-specified info are not present in this vector.
  lvar_saved_infos_t lvvec;

  /// Local variable mapping (used for merging variables)
  lvar_mapping_t lmaps;

  /// Delta to add to IDA stack offset to calculate Hex-Rays stack offsets.
  /// Should be set by the caller before calling save_user_lvar_settings();
  uval_t stkoff_delta = 0;

/// \defgroup ULV_ lvar_uservec_t property bits
/// Used in lvar_uservec_t::ulv_flags
///@{
#define ULV_PRECISE_DEFEA 0x0001        ///< Use precise defea's for lvar locations
///@}
  /// Various flags. Possible values are from \ref ULV_
  int ulv_flags = ULV_PRECISE_DEFEA;

  void swap(lvar_uservec_t &r)
  {
    lvvec.swap(r.lvvec);
    lmaps.swap(r.lmaps);
    std::swap(stkoff_delta, r.stkoff_delta);
    std::swap(ulv_flags, r.ulv_flags);
  }
  void clear()
  {
    lvvec.clear();
    lmaps.clear();
    stkoff_delta = 0;
    ulv_flags = ULV_PRECISE_DEFEA;
  }
  bool empty() const
  {
    return lvvec.empty()
        && lmaps.empty()
        && stkoff_delta == 0
        && ulv_flags == ULV_PRECISE_DEFEA;
  }

  /// find saved user settings for given var
  lvar_saved_info_t *find_info(const lvar_locator_t &vloc)
  {
    for ( lvar_saved_infos_t::iterator p=lvvec.begin(); p != lvvec.end(); ++p )
    {
      if ( p->ll == vloc )
        return p;
    }
    return nullptr;
  }

  /// Preserve user settings for given var
  void keep_info(const lvar_t &v)
  {
    lvar_saved_info_t *p = find_info(v);
    if ( p != nullptr )
      p->set_keep();
  }
};

/// Restore user defined local variable settings in the database.
/// \param func_ea entry address of the function
/// \param lvinf ptr to output buffer
/// \return success

bool hexapi restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea);


/// Save user defined local variable settings into the database.
/// \param func_ea entry address of the function
/// \param lvinf user-specified info about local variables

void hexapi save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf);


/// Helper class to modify saved local variable settings.
struct user_lvar_modifier_t
{
  virtual ~user_lvar_modifier_t() {}
  /// Modify lvar settings.
  /// Returns: true-modified
  virtual bool idaapi modify_lvars(lvar_uservec_t *lvinf) = 0;
};

/// Modify saved local variable settings.
/// \param entry_ea         function start address
/// \param mlv              local variable modifier
/// \return true if modified variables

bool hexapi modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv);


/// Modify saved local variable settings of one variable.
/// \param func_ea          function start address
/// \param info             local variable info attrs
/// \param mli_flags        bits that specify which attrs defined by INFO are to be set
/// \return true if modified, false if invalid MLI_FLAGS passed

bool hexapi modify_user_lvar_info(
        ea_t func_ea,
        uint mli_flags,
        const lvar_saved_info_t &info);

/// \defgroup MLI_ user info bits
///@{
#define MLI_NAME        0x01 ///< apply lvar name
#define MLI_TYPE        0x02 ///< apply lvar type
#define MLI_CMT         0x04 ///< apply lvar comment
#define MLI_SET_FLAGS   0x08 ///< set LVINF_... bits
#define MLI_CLR_FLAGS   0x10 ///< clear LVINF_... bits
///@}


/// Find a variable by name.
/// \param out              output buffer for the variable locator
/// \param func_ea          function start address
/// \param varname          variable name
/// \return success
/// Since VARNAME is not always enough to find the variable, it may decompile
/// the function.

bool hexapi locate_lvar(
        lvar_locator_t *out,
        ea_t func_ea,
        const char *varname);


/// Rename a local variable.
/// \param func_ea          function start address
/// \param oldname          old name of the variable
/// \param newname          new name of the variable
/// \return success
/// This is a convenience function.
/// For bulk renaming consider using modify_user_lvars.

inline bool rename_lvar(
        ea_t func_ea,
        const char *oldname,
        const char *newname)
{
  lvar_saved_info_t info;
  if ( !locate_lvar(&info.ll, func_ea, oldname) )
    return false;
  info.name = newname;
  return modify_user_lvar_info(func_ea, MLI_NAME, info);
}

//-------------------------------------------------------------------------
/// User-defined function calls
struct udcall_t
{
  qstring name;         // name of the function
  tinfo_t tif;          // function prototype
  DECLARE_COMPARISONS(udcall_t)
  {
    int code = ::compare(name, r.name);
    if ( code == 0 )
      code = ::compare(tif, r.tif);
    return code;
  }

  bool empty() const { return name.empty() && tif.empty(); }
};

// All user-defined function calls
typedef qmap<ea_t, udcall_t> udcall_map_t;

/// Restore user defined function calls from the database.
/// \param udcalls ptr to output buffer
/// \param func_ea entry address of the function
/// \return success

bool hexapi restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea);


/// Save user defined local function calls into the database.
/// \param func_ea entry address of the function
/// \param udcalls user-specified info about user defined function calls

void hexapi save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls);


/// Convert function type declaration into internal structure
/// \param udc    - pointer to output structure
/// \param decl   - function type declaration
/// \param silent - if TRUE: do not show warning in case of incorrect type
/// \return success

bool hexapi parse_user_call(udcall_t *udc, const char *decl, bool silent);


/// try to generate user-defined call for an instruction
/// \return \ref MERR_ code:
///   MERR_OK      - user-defined call generated
///   else         - error (MERR_INSN == inacceptable udc.tif)

merror_t hexapi convert_to_user_call(const udcall_t &udc, codegen_t &cdg);


//-------------------------------------------------------------------------
/// Generic microcode generator class.
/// An instance of a derived class can be registered to be used for
/// non-standard microcode generation. Before microcode generation for an
/// instruction all registered object will be visited by the following way:
///   if ( filter->match(cdg) )
///     code = filter->apply(cdg);
///   if ( code == MERR_OK )
///     continue;     // filter generated microcode, go to the next instruction
struct microcode_filter_t
{
  virtual ~microcode_filter_t() {}
  /// check if the filter object is to be applied
  /// \return success
  virtual bool match(codegen_t &cdg) = 0;

  /// generate microcode for an instruction
  /// \return MERR_... code:
  ///   MERR_OK      - user-defined microcode generated, go to the next instruction
  ///   MERR_INSN    - not generated - the caller should try the standard way
  ///   else         - error
  virtual merror_t apply(codegen_t &cdg) = 0;
};

/// register/unregister non-standard microcode generator
/// \param filter  - microcode generator object
/// \param install - TRUE - register the object, FALSE - unregister
/// \return success
bool hexapi install_microcode_filter(microcode_filter_t *filter, bool install=true);

//-------------------------------------------------------------------------
/// Abstract class: User-defined call generator
/// derived classes should implement method 'match'
class udc_filter_t : public microcode_filter_t
{
  udcall_t udc;

public:
  ~udc_filter_t() { cleanup(); }

  /// Cleanup the filter
  /// This function properly clears type information associated to this filter.
  void hexapi cleanup();

  /// return true if the filter object should be applied to given instruction
  virtual bool match(codegen_t &cdg) override = 0;

  bool hexapi init(const char *decl);
  virtual merror_t hexapi apply(codegen_t &cdg) override;

  bool empty() const { return udc.empty(); }
};

//-------------------------------------------------------------------------
typedef size_t mbitmap_t;
const size_t bitset_width = sizeof(mbitmap_t) * CHAR_BIT;
const size_t bitset_align = bitset_width - 1;
const size_t bitset_shift = 6;

/// Bit set class. See https://en.wikipedia.org/wiki/Bit_array
class bitset_t
{
  mbitmap_t *bitmap = nullptr; ///< pointer to bitmap
  size_t high = 0;             ///< highest bit+1 (multiply of bitset_width)

public:
  bitset_t() {}
  hexapi bitset_t(const bitset_t &m);          // copy constructor
  ~bitset_t()
  {
    qfree(bitmap);
    bitmap = nullptr;
  }
  void swap(bitset_t &r)
  {
    std::swap(bitmap, r.bitmap);
    std::swap(high, r.high);
  }
  bitset_t &operator=(const bitset_t &m) { return copy(m); }
  bitset_t &hexapi copy(const bitset_t &m);    // assignment operator
  bool hexapi add(int bit);                    // add a bit
  bool hexapi add(int bit, int width);         // add bits
  bool hexapi add(const bitset_t &ml);         // add another bitset
  bool hexapi sub(int bit);                    // delete a bit
  bool hexapi sub(int bit, int width);         // delete bits
  bool hexapi sub(const bitset_t &ml);         // delete another bitset
  bool hexapi cut_at(int maxbit);              // delete bits >= maxbit
  void hexapi shift_down(int shift);           // shift bits down
  bool hexapi has(int bit) const;       // test presence of a bit
  bool hexapi has_all(int bit, int width) const; // test presence of bits
  bool hexapi has_any(int bit, int width) const; // test presence of bits
  void print(
        qstring *vout,
        int (*get_bit_name)(qstring *out, int bit, int width, void *ud)=nullptr,
        void *ud=nullptr) const;
  const char *hexapi dstr() const;
  bool hexapi empty() const;        // is empty?
  int hexapi count() const;         // number of set bits
  int hexapi count(int bit) const;  // get number set bits starting from 'bit'
  int hexapi last() const;          // get the number of the last bit (-1-no bits)
  void clear() { high = 0; }        // make empty
  void hexapi fill_with_ones(int maxbit);
  bool hexapi fill_gaps(int total_nbits);
  bool hexapi has_common(const bitset_t &ml) const; // has common elements?
  bool hexapi intersect(const bitset_t &ml);    // intersect sets. returns true if changed
  bool hexapi is_subset_of(const bitset_t &ml) const; // is subset of?
  bool includes(const bitset_t &ml) const { return ml.is_subset_of(*this); }
  void extract(intvec_t &out) const;
  DECLARE_COMPARISONS(bitset_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  class iterator
  {
    friend class bitset_t;
    int i;
  public:
    iterator(int n=-1) : i(n) {}
    bool operator==(const iterator &n) const { return i == n.i; }
    bool operator!=(const iterator &n) const { return i != n.i; }
    int operator*() const { return i; }
  };
  typedef iterator const_iterator;
  iterator itat(int n) const { return iterator(goup(n)); }
  iterator begin() const { return itat(0); }
  iterator end()   const { return iterator(high); }
  int front()      const { return *begin(); }
  int back()       const { return *end(); }
  void inc(iterator &p, int n=1) const { p.i = goup(p.i+n); }
private:
  int hexapi goup(int reg) const;
};
DECLARE_TYPE_AS_MOVABLE(bitset_t);
typedef qvector<bitset_t> array_of_bitsets;

//-------------------------------------------------------------------------
// set of graph nodes as a bitset
class node_bitset_t : public bitset_t
{
public:
  node_bitset_t() {}
  node_bitset_t(int node) { add(node); }
};
DECLARE_TYPE_AS_MOVABLE(node_bitset_t);

class array_of_node_bitset_t : public qvector<node_bitset_t> {};

//-------------------------------------------------------------------------
struct ivl_t // an interval
{
public:
  uint64 off;
  uint64 size;

  ivl_t(uint64 _off=0, uint64 _size=0) : off(_off), size(_size) {}
  bool empty() const { return size == 0; }
  bool valid() const { return last() >= off; }
  uint64 end() const { return off + size; }
  uint64 last() const { return off + size - 1; }
  void clear() { size = 0; }
  void print(qstring *vout) const;
  const char *hexapi dstr() const;

  bool extend_to_cover(const ivl_t &r) // extend interval to cover 'r'
  {
    uint64 new_end = end();
    bool changed = false;
    if ( off > r.off )
    {
      off = r.off;
      changed = true;
    }
    if ( new_end < r.end() )
    {
      new_end = r.end();
      changed = true;
    }
    if ( changed )
      size = new_end - off;
    return changed;
  }
  void intersect(const ivl_t &r)
  {
    uint64 new_off = qmax(off, r.off);
    uint64 new_end = end();
    if ( new_end > r.end() )
      new_end = r.end();
    if ( new_off < new_end )
    {
      off = new_off;
      size = new_end - off;
    }
    else
    {
      size = 0;
    }
  }

  // do *this and ivl overlap?
  bool overlap(const ivl_t &ivl) const
  {
    return interval::overlap(off, size, ivl.off, ivl.size);
  }
  // does *this include ivl?
  bool includes(const ivl_t &ivl) const
  {
    return interval::includes(off, size, ivl.off, ivl.size);
  }
  // does *this contain off2?
  bool contains(uint64 off2) const
  {
    return interval::contains(off, size, off2);
  }

  DECLARE_COMPARISONS(ivl_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  static const ivl_t allmem;
#define ALLMEM ivl_t::allmem
};
DECLARE_TYPE_AS_MOVABLE(ivl_t);

//-------------------------------------------------------------------------
struct ivl_with_name_t
{
  ivl_t ivl;
  const char *whole;            // name of the whole interval
  const char *part;             // prefix to use for parts of the interval (e.g. sp+4)
  ivl_with_name_t(): ivl(0, BADADDR), whole("<unnamed inteval>"), part(nullptr) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
struct ivlset_visitor_t
{
  virtual int visit_ivl(const ivl_t &ivl) = 0;
};

//-------------------------------------------------------------------------
/// Set of intervals.
/// Bit arrays are efficient only for small sets. Potentially huge
/// sets, like memory ranges, require another representation.
/// ivlset_t is used for a list of memory locations in our decompiler.
class ivlset_t
{
public:
  typedef qvector<ivl_t> bag_t;

protected:
  bag_t bag;
  bool verify() const;
  // we do not store the empty intervals in bag so size == 0 denotes
  // MAX_VALUE<uint64>+1, e.g. 0x1'00000000'00000000
  static bool ivl_all_values(const ivl_t &ivl) { return ivl.off == 0 && ivl.size == 0; }

public:
  ivlset_t() {}
  ivlset_t(const ivl_t &ivl) { if ( ivl.valid() ) bag.push_back(ivl); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  void swap(ivlset_t &r) { bag.swap(r.bag); }
  const ivl_t &getivl(int idx) const { return bag[idx]; }
  const ivl_t &lastivl() const { return bag.back(); }
  size_t nivls() const { return bag.size(); }
  bool empty() const { return bag.empty(); }
  void clear() { bag.clear(); }
  void qclear() { bag.qclear(); }
  bool all_values() const { return nivls() == 1 && ivl_all_values(bag[0]); }
  void set_all_values() { clear(); bag.push_back(ivl_t(0, 0)); }
  bool single_value() const { return nivls() == 1 && bag[0].size == 1; }
  bool single_value(uint64 v) const { return single_value() && bag[0].off == v; }

  bool hexapi add(const ivl_t &ivl);
  bool add(ea_t ea, asize_t size) { return add(ivl_t(ea, size)); }
  bool hexapi add(const ivlset_t &ivs);
  bool hexapi addmasked(const ivlset_t &ivs, const ivl_t &mask);
  bool hexapi sub(const ivl_t &ivl);
  bool sub(ea_t ea, asize_t size) { return sub(ivl_t(ea, size)); }
  bool hexapi sub(const ivlset_t &ivs);
  asize_t hexapi count() const; // sum of the interval sizes
  bool hexapi has_common(const ivlset_t &ivs) const;
  bool hexapi has_common(const ivl_t &ivl, bool strict=false) const;
  bool hexapi contains(uint64 off) const;
  bool hexapi includes(const ivlset_t &ivs) const;
  bool hexapi intersect(const ivlset_t &ivs);
  bool is_subset_of(const ivlset_t &ivs) const { return ivs.includes(*this); }
  DECLARE_COMPARISONS(ivlset_t);
  bool operator==(const ivl_t &v) const { return nivls() == 1 && bag[0] == v; }
  bool operator!=(const ivl_t &v) const { return !(*this == v); }

  typedef typename bag_t::iterator iterator;
  typedef typename bag_t::const_iterator const_iterator;
  const_iterator begin() const { return bag.begin(); }
  const_iterator end()   const { return bag.end(); }
  iterator begin() { return bag.begin(); }
  iterator end()   { return bag.end(); }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;

};
DECLARE_TYPE_AS_MOVABLE(ivlset_t);

typedef qvector<ivlset_t> array_of_ivlsets;
//-------------------------------------------------------------------------
// We use bitset_t to keep list of registers.
// This is the most optimal storage for them.
class rlist_t : public bitset_t
{
public:
  rlist_t() {}
  rlist_t(const rlist_t &m) : bitset_t(m) {}
  rlist_t(mreg_t reg, int width) { add(reg, width); }
  ~rlist_t() {}
  rlist_t &operator=(const rlist_t &) = default;
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(rlist_t);

//-------------------------------------------------------------------------
// Microlist: list of register and memory locations
struct mlist_t
{
  rlist_t reg;         // registers
  ivlset_t mem;        // memory locations

  mlist_t() {}
  mlist_t(const ivl_t &ivl) : mem(ivl) {}
  mlist_t(mreg_t r, int size) : reg(r, size) {}

  void swap(mlist_t &r) { reg.swap(r.reg); mem.swap(r.mem); }
  bool hexapi addmem(ea_t ea, asize_t size);
  bool add(mreg_t r, int size) { return add(mlist_t(r, size)); } // also see append_def_list()
  bool add(const rlist_t &r)   { return reg.add(r); }
  bool add(const ivl_t &ivl)   { return add(mlist_t(ivl)); }
  bool add(const mlist_t &lst)
  {
    bool changed = reg.add(lst.reg);
    if ( mem.add(lst.mem) )
      changed = true;
    return changed;
  }
  bool sub(mreg_t r, int size) { return sub(mlist_t(r, size)); }
  bool sub(const ivl_t &ivl)   { return sub(mlist_t(ivl)); }
  bool sub(const mlist_t &lst)
  {
    bool changed = reg.sub(lst.reg);
    if ( mem.sub(lst.mem) )
      changed = true;
    return changed;
  }
  asize_t count() const { return reg.count() + mem.count(); }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  bool empty() const { return reg.empty() && mem.empty(); }
  void clear() { reg.clear(); mem.clear(); }
  bool has(mreg_t r) const { return reg.has(r); }
  bool has_all(mreg_t r, int size) const { return reg.has_all(r, size); }
  bool has_any(mreg_t r, int size) const { return reg.has_any(r, size); }
  bool has_memory() const { return !mem.empty(); }
  bool has_allmem() const { return mem == ALLMEM; }
  bool has_common(const mlist_t &lst) const { return reg.has_common(lst.reg) || mem.has_common(lst.mem); }
  bool includes(const mlist_t &lst) const { return reg.includes(lst.reg) && mem.includes(lst.mem); }
  bool intersect(const mlist_t &lst)
  {
    bool changed = reg.intersect(lst.reg);
    if ( mem.intersect(lst.mem) )
      changed = true;
    return changed;
  }
  bool is_subset_of(const mlist_t &lst) const { return lst.includes(*this); }

  DECLARE_COMPARISONS(mlist_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(mlist_t);
typedef qvector<mlist_t> mlistvec_t;
DECLARE_TYPE_AS_MOVABLE(mlistvec_t);

//-------------------------------------------------------------------------
// Are we looking for 'must access' or 'may access' information?
// 'must access' means that the code will always access the specified location(s)
// 'may access' means that the code may in some cases access the specified location(s)
// Example:     ldx cs.2, r0.4, r1.4
//      MUST_ACCESS: r0.4 and r1.4, usually displayed as r0.8 because r0 and r1 are adjacent
//      MAY_ACCESS: r0.4 and r1.4, and all aliasable memory, because
//                  ldx may access any part of the aliasable memory
typedef int maymust_t;
const maymust_t
  // One of the following two bits should be specified:
  MUST_ACCESS = 0x00, // access information we can count on
  MAY_ACCESS  = 0x01, // access information we should take into account
  // Optionally combined with the following bits:
  MAYMUST_ACCESS_MASK = 0x01,

  ONE_ACCESS_TYPE = 0x20,      // for find_first_use():
                               // use only the specified maymust access type
                               // (by default it inverts the access type for def-lists)
  INCLUDE_SPOILED_REGS = 0x40, // for build_def_list() with MUST_ACCESS:
                               // include spoiled registers in the list
  EXCLUDE_PASS_REGS = 0x80,    // for build_def_list() with MAY_ACCESS:
                               // exclude pass_regs from the list
  FULL_XDSU = 0x100,           // for build_def_list():
                               // if xds/xdu source and targets are the same
                               // treat it as if xdsu redefines the entire destination
  WITH_ASSERTS = 0x200,        // for find_first_use():
                               // do not ignore assertions
  EXCLUDE_VOLATILE = 0x400,    // for build_def_list():
                               // exclude volatile memory from the list
  INCLUDE_UNUSED_SRC = 0x800,  // for build_use_list():
                               // do not exclude unused source bytes for m_and/m_or insns
  INCLUDE_DEAD_RETREGS = 0x1000, // for build_def_list():
                               // include dead returned registers in the list
  INCLUDE_RESTRICTED = 0x2000,// for MAY_ACCESS: include restricted memory
  CALL_SPOILS_ONLY_ARGS = 0x4000;// for build_def_list() & MAY_ACCESS:
                               // do not include global memory into the
                               // spoiled list of a call

inline THREAD_SAFE bool is_may_access(maymust_t maymust)
{
  return (maymust & MAYMUST_ACCESS_MASK) != MUST_ACCESS;
}

//-------------------------------------------------------------------------
/// Get list of temporary registers.
/// Tempregs are temporary registers that are used during code generation.
/// They do not map to regular processor registers. They are used only to
/// store temporary values during execution of one instruction.
/// Tempregs may not be used to pass a value from one block to another.
/// In other words, at the end of a block all tempregs must be dead.
const mlist_t &hexapi get_temp_regs();

/// Is a kernel register?
/// Kernel registers are temporary registers that can be used freely.
/// They may be used to store values that cross instruction or basic block
/// boundaries. Kernel registers do not map to regular processor registers.
/// See also \ref mba_t::alloc_kreg()
bool hexapi is_kreg(mreg_t r);

/// Map a processor register to a microregister.
/// \param reg   processor register number
/// \return microregister register id or mr_none
mreg_t hexapi reg2mreg(int reg);

/// Map a microregister to a processor register.
/// \param reg   microregister number
/// \param width size of microregister in bytes
/// \return processor register id or -1
int hexapi mreg2reg(mreg_t reg, int width);

/// Get the microregister name.
/// \param out   output buffer, may be nullptr
/// \param reg   microregister number
/// \param width size of microregister in bytes. may be bigger than the real
///              register size.
/// \param ud    reserved, must be nullptr
/// \return width of the printed register. this value may be less than
///         the WIDTH argument.

int hexapi get_mreg_name(qstring *out, mreg_t reg, int width, void *ud=nullptr);

//-------------------------------------------------------------------------
/// User defined callback to optimize individual microcode instructions
struct optinsn_t
{
  virtual ~optinsn_t() {}
  /// Optimize an instruction.
  /// \param blk current basic block. maybe nullptr, which means that
  ///            the instruction must be optimized without context
  /// \param ins instruction to optimize; it is always a top-level instruction.
  ///            the callback may not delete the instruction but may
  ///            convert it into nop (see mblock_t::make_nop). to optimize
  ///            sub-instructions, visit them using minsn_visitor_t.
  ///            sub-instructions may not be converted into nop but
  ///            can be converted to "mov x,x". for example:
  ///               add x,0,x => mov x,x
  ///            this callback may change other instructions in the block,
  ///            but should do this with care, e.g. to no break the
  ///            propagation algorithm if called with OPTI_NO_LDXOPT.
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes made to the instruction.
  ///         if after this call the instruction's use/def lists have changed,
  ///         you must mark the block level lists as dirty (see mark_lists_dirty)
  virtual int idaapi func(mblock_t *blk, minsn_t *ins, int optflags) = 0;
};

/// Install an instruction level custom optimizer
/// \param opt an instance of optinsn_t. cannot be destroyed before calling
///        remove_optinsn_handler().
void hexapi install_optinsn_handler(optinsn_t *opt);

/// Remove an instruction level custom optimizer
bool hexapi remove_optinsn_handler(optinsn_t *opt);

/// User defined callback to optimize microcode blocks
struct optblock_t
{
  virtual ~optblock_t() {}
  /// Optimize a block.
  /// This function usually performs the optimizations that require analyzing
  /// the entire block and/or its neighbors. For example it can recognize
  /// patterns and perform conversions like:
  /// b0:                                 b0:
  ///    ...                                 ...
  ///    jnz x, 0, @b2      =>               jnz x, 0, @b2
  /// b1:                                 b1:
  ///    add x, 0, y                         mov x, y
  ///    ...                                 ...
  /// \param blk Basic block to optimize as a whole.
  /// \return number of changes made to the block. See also mark_lists_dirty.
  virtual int idaapi func(mblock_t *blk) = 0;
};

/// Install a block level custom optimizer.
/// \param opt an instance of optblock_t. cannot be destroyed before calling
///        remove_optblock_handler().
void hexapi install_optblock_handler(optblock_t *opt);

/// Remove a block level custom optimizer
bool hexapi remove_optblock_handler(optblock_t *opt);

//-------------------------------------------------------------------------
// abstract graph interface
class simple_graph_t : public gdl_graph_t
{
  // does a path from 'm' to 'n' exist?
  bool path_exists(node_bitset_t &visited, int m, int n) const;
protected:
  void calc_outgoing_edges(const intvec_t &sub, edgevec_t &el) const;
  void compute_dominator_info(struct dominator_info_t &di);
  bool is_connected_without(const edge_t &forbidden_edge, const intvec_t &dead_nodes) const;
public:
  qstring title;
  bool colored_gdl_edges = false;

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  // this call is used to exclude edges in worklist_iterate... functions()
  virtual bool ignore_edge(int /*src*/, int /*dst*/ ) const newapi { return false; }

  void hexapi compute_dominators(array_of_node_bitset_t &domin, bool post=false) const;
  void hexapi compute_immediate_dominators(
        const array_of_node_bitset_t &domin,
        intvec_t &idomin,
        bool post=false) const;
  int hexapi depth_first_preorder(node_ordering_t *pre) const; // returns number of visited nodes
  int hexapi depth_first_postorder(node_ordering_t *post) const; // returns number of visited nodes
#ifndef SWIG
  void depth_first_postorder(node_ordering_t *post, edge_mapper_t *et) const;
  void depth_first_postorder_for_all_entries(node_ordering_t *post) const;
  intvec_t find_dead_nodes() const;

  // find nodes reaching 'n'
  void find_reaching_nodes(int n, node_bitset_t &reaching) const;

  // does a path from 'm' to 'n' exist?
  bool path_exists(int m, int n) const;

  // is there a path from M to N which terminates with a back edge to N?
  bool path_back(const array_of_node_bitset_t &domin, int m, int n) const;
  bool path_back(const edge_mapper_t &et, int m, int n) const;
#endif

  class iterator
  {
    friend class simple_graph_t;
    int i;
    iterator(int n) : i(n) {}
  public:
    bool operator==(const iterator &n) const { return i == n.i; }
    bool operator!=(const iterator &n) const { return i != n.i; }
    int operator*() const { return i; }
  };
  typedef iterator const_iterator;
  iterator begin() const { return iterator(goup(0)); }
  iterator end()   const { return iterator(size()); }
  int front()      const { return *begin(); }
  void inc(iterator &p, int n=1) const { p.i = goup(p.i+n); }
  virtual int hexapi goup(int node) const newapi;
};

//-------------------------------------------------------------------------
// Since our data structures are quite complex, we use the visitor pattern
// in many of our algorthims. This functionality is available for plugins too.
// https://en.wikipedia.org/wiki/Visitor_pattern

// All our visitor callbacks return an integer value.
// Visiting is interrupted as soon an the return value is non-zero.
// This non-zero value is returned as the result of the for_all_... function.
// If for_all_... returns 0, it means that it successfully visited all items.

/// The context info used by visitors
struct op_parent_info_t
{
  mba_t *mba;          // current microcode
  mblock_t *blk;       // current block
  minsn_t *topins;     // top level instruction (parent of curins or curins itself)
  minsn_t *curins;     // currently visited instruction

  op_parent_info_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : mba(_mba), blk(_blk), topins(_topins), curins(nullptr) {}
  virtual ~op_parent_info_t() {}
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool really_alloc() const;
};

/// Micro instruction visitor.
/// See mba_t::for_all_topinsns, minsn_t::for_all_insns,
///     mblock_::for_all_insns, mba_t::for_all_insns
struct minsn_visitor_t : public op_parent_info_t
{
  minsn_visitor_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : op_parent_info_t(_mba, _blk, _topins) {}
  virtual int idaapi visit_minsn() = 0;
};

/// Micro operand visitor.
/// See mop_t::for_all_ops, minsn_t::for_all_ops, mblock_t::for_all_insns,
///     mba_t::for_all_insns
struct mop_visitor_t : public op_parent_info_t
{
  /// Should skip sub-operands of the current operand?
  /// visit_mop() may set 'prune=true' for that.
  bool prune = false;

  mop_visitor_t(
        mba_t *_mba=nullptr,
        mblock_t *_blk=nullptr,
        minsn_t *_topins=nullptr)
    : op_parent_info_t(_mba, _blk, _topins) {}
  virtual int idaapi visit_mop(mop_t *op, const tinfo_t *type, bool is_target) = 0;
};

/// Scattered mop: visit each of the scattered locations as a separate mop.
/// See mop_t::for_all_scattered_submops
struct scif_visitor_t
{
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  virtual ~scif_visitor_t() {}
  virtual int idaapi visit_scif_mop(const mop_t &r, int off) = 0;
};

// Used operand visitor.
// See mblock_t::for_all_uses
struct mlist_mop_visitor_t
{
  minsn_t *topins = nullptr;
  minsn_t *curins = nullptr;
  bool changed = false;
  mlist_t *list = nullptr;
  /// Should skip sub-operands of the current operand?
  /// visit_mop() may set 'prune=true' for that.
  bool prune = false;

  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  virtual ~mlist_mop_visitor_t() {}
  virtual int idaapi visit_mop(mop_t *op) = 0;
};

//-------------------------------------------------------------------------
/// Instruction operand types

typedef uint8 mopt_t;
const mopt_t
  mop_z   = 0,  ///< none
  mop_r   = 1,  ///< register (they exist until MMAT_LVARS)
  mop_n   = 2,  ///< immediate number constant
  mop_str = 3,  ///< immediate string constant (user representation)
  mop_d   = 4,  ///< result of another instruction
  mop_S   = 5,  ///< local stack variable (they exist until MMAT_LVARS)
  mop_v   = 6,  ///< global variable
  mop_b   = 7,  ///< micro basic block (mblock_t)
  mop_f   = 8,  ///< list of arguments
  mop_l   = 9,  ///< local variable
  mop_a   = 10, ///< mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
  mop_h   = 11, ///< helper function
  mop_c   = 12, ///< mcases
  mop_fn  = 13, ///< floating point constant
  mop_p   = 14, ///< operand pair
  mop_sc  = 15; ///< scattered

const int NOSIZE = -1; ///< wrong or unexisting operand size

//-------------------------------------------------------------------------
/// Reference to a local variable. Used by mop_l
struct lvar_ref_t
{
  /// Pointer to the parent mba_t object.
  /// Since we need to access the 'mba->vars' array in order to retrieve
  /// the referenced variable, we keep a pointer to mba_t here.
  /// Note: this means this class and consequently mop_t, minsn_t, mblock_t
  ///       are specific to a mba_t object and cannot migrate between
  ///       them. fortunately this is not something we need to do.
  ///       second, lvar_ref_t's appear only after MMAT_LVARS.
  mba_t *const mba;
  sval_t off;           ///< offset from the beginning of the variable
  int idx;              ///< index into mba->vars
  lvar_ref_t(mba_t *m, int i, sval_t o=0) : mba(m), off(o), idx(i) {}
  lvar_ref_t(const lvar_ref_t &r) : mba(r.mba), off(r.off), idx(r.idx) {}
  lvar_ref_t &operator=(const lvar_ref_t &r)
  {
    off = r.off;
    idx = r.idx;
    return *this;
  }
  DECLARE_COMPARISONS(lvar_ref_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void swap(lvar_ref_t &r)
  {
    std::swap(off, r.off);
    std::swap(idx, r.idx);
  }
  lvar_t &hexapi var() const;       ///< Retrieve the referenced variable
};

//-------------------------------------------------------------------------
/// Reference to a stack variable. Used for mop_S
struct stkvar_ref_t
{
  /// Pointer to the parent mba_t object.
  /// We need it in order to retrieve the referenced stack variable.
  /// See notes for lvar_ref_t::mba.
  mba_t *const mba;

  /// Offset to the stack variable from the bottom of the stack frame.
  /// It is called 'decompiler stkoff' and it is different from IDA stkoff.
  /// See a note and a picture about 'decompiler stkoff' below.
  sval_t off;

  stkvar_ref_t(mba_t *m, sval_t o) : mba(m), off(o) {}
  DECLARE_COMPARISONS(stkvar_ref_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void swap(stkvar_ref_t &r)
  {
    std::swap(off, r.off);
  }
  /// Retrieve the referenced stack variable.
  /// \param[out] udm  stkvar, may be nullptr
  /// \param p_idaoff if specified, will hold IDA stkoff after the call.
  /// \return index of stkvar in the frame or -1
  ssize_t hexapi get_stkvar(udm_t *udm=nullptr, uval_t *p_idaoff=nullptr) const;
};

//-------------------------------------------------------------------------
/// Scattered operand info. Used for mop_sc
struct scif_t : public vdloc_t
{
  /// Pointer to the parent mba_t object.
  /// Some operations may convert a scattered operand into something simpler,
  /// (a stack operand, for example). We will need to create stkvar_ref_t at
  /// that moment, this is why we need this pointer.
  /// See notes for lvar_ref_t::mba.
  mba_t *mba;

  /// Usually scattered operands are created from a function prototype,
  /// which has the name information. We preserve it and use it to name
  /// the corresponding local variable.
  qstring name;

  /// Scattered operands always have type info assigned to them
  /// because without it we won't be able to manipulte them.
  tinfo_t type;

  scif_t(mba_t *_mba, tinfo_t *tif, qstring *n=nullptr) : mba(_mba)
  {
    if ( n != nullptr )
      n->swap(name);
    tif->swap(type);
  }
  scif_t &operator =(const vdloc_t &loc)
  {
    *(vdloc_t *)this = loc;
    return *this;
  }
};

//-------------------------------------------------------------------------
/// An integer constant. Used for mop_n
/// We support 64-bit values but 128-bit values can be represented with mop_p
struct mnumber_t : public operand_locator_t
{
  uint64 value;
  uint64 org_value;     // original value before changing the operand size
  mnumber_t(uint64 v, ea_t _ea=BADADDR, int n=0)
    : operand_locator_t(_ea, n), value(v), org_value(v) {}
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(mnumber_t)
  {
    if ( value < r.value )
      return -1;
    if ( value > r.value )
      return -1;
    return 0;
  }
  // always use this function instead of manually modifying the 'value' field
  void update_value(uint64 val64)
  {
    value = val64;
    org_value = val64;
  }
};

//-------------------------------------------------------------------------
/// Floating point constant. Used for mop_fn
/// For more details, please see the ieee.h file from IDA SDK.
struct fnumber_t
{
  fpvalue_t fnum;       ///< Internal representation of the number
  int nbytes;           ///< Original size of the constant in bytes
  operator       uint16 *()       { return fnum.w; }
  operator const uint16 *() const { return fnum.w; }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(fnumber_t)
  {
    return ecmp(fnum, r.fnum);
  }
  int calc_max_exp() const
  {
    return nbytes <= 4 ? MAXEXP_FLOAT
         : nbytes <= 8 ? MAXEXP_DOUBLE
         : MAXEXP_LNGDBL;
  }
  bool is_nan() const
  {
    return get_fpvalue_kind(fnum, calc_max_exp()) == FPV_NAN;
  }
};

//-------------------------------------------------------------------------
/// \defgroup SHINS_ Bits to control how we print instructions
///@{
#define SHINS_NUMADDR 0x01 ///< display definition addresses for numbers
#define SHINS_VALNUM  0x02 ///< display value numbers
#define SHINS_SHORT   0x04 ///< do not display use-def chains and other attrs
#define SHINS_LDXEA   0x08 ///< display address of ldx expressions (not used)
///@}

//-------------------------------------------------------------------------
/// How to handle side effect of change_size()
/// Sometimes we need to create a temporary operand and change its size in order
/// to check some hypothesis. If we revert our changes, we do not want that the
/// database (global variables, stack frame, etc) changes in any manner.
enum side_effect_t
{
  NO_SIDEFF,          ///< change operand size but ignore side effects
                      ///< if you decide to keep the changed operand,
                      ///< handle_new_size() must be called
  WITH_SIDEFF,        ///< change operand size and handle side effects
  ONLY_SIDEFF,        ///< only handle side effects
  ANY_REGSIZE = 0x80, ///< any register size is permitted
  ANY_FPSIZE = 0x100, ///< any size of floating operand is permitted
};

//-------------------------------------------------------------------------
/// A microinstruction operand.
/// This is the smallest building block of our microcode.
/// Operands will be part of instructions, which are then grouped into basic blocks.
/// The microcode consists of an array of such basic blocks + some additional info.
class mop_t
{
  void hexapi copy(const mop_t &rop);
public:
  /// Operand type.
  mopt_t t;

  /// Operand properties.
  uint8 oprops;
#define OPROP_IMPDONE 0x01 ///< imported operand (a pointer) has been dereferenced
#define OPROP_UDT     0x02 ///< a struct or union
#define OPROP_FLOAT   0x04 ///< possibly floating value
#define OPROP_CCFLAGS 0x08 ///< mop_n: a pc-relative value
                           ///< mop_a: an address obtained from a relocation
                           ///< else: value of a condition code register (like mr_cc)
#define OPROP_UDEFVAL 0x10 ///< uses undefined value
#define OPROP_LOWADDR 0x20 ///< a low address offset
#define OPROP_ABI     0x40 ///< is used to organize arg/retval of a call
                           ///< such operands should be combined more carefully
                           ///< than others at least on BE platforms

  /// Value number.
  /// Zero means unknown.
  /// Operands with the same value number are equal.
  uint16 valnum;

  /// Operand size.
  /// Usually it is 1,2,4,8 or NOSIZE but for UDTs other sizes are permitted
  int size;

  /// The following union holds additional details about the operand.
  /// Depending on the operand type different kinds of info are stored.
  /// You should access these fields only after verifying the operand type.
  /// All pointers are owned by the operand and are freed by its destructor.
  union
  {
    mreg_t r;           // mop_r   register number
    mnumber_t *nnn;     // mop_n   immediate value
    minsn_t *d;         // mop_d   result (destination) of another instruction
    stkvar_ref_t *s;    // mop_S   stack variable
    ea_t g;             // mop_v   global variable (its linear address)
    int b;              // mop_b   block number (used in jmp,call instructions)
    mcallinfo_t *f;     // mop_f   function call information
    lvar_ref_t *l;      // mop_l   local variable
    mop_addr_t *a;      // mop_a   variable whose address is taken
    char *helper;       // mop_h   helper function name
    char *cstr;         // mop_str utf8 string constant, user representation
    mcases_t *c;        // mop_c   cases
    fnumber_t *fpc;     // mop_fn  floating point constant
    mop_pair_t *pair;   // mop_p   operand pair
    scif_t *scif;       // mop_sc  scattered operand info
  };
  // -- End of data fields, member function declarations follow:

  void set_impptr_done() { oprops |= OPROP_IMPDONE; }
  void set_udt()         { oprops |= OPROP_UDT; }
  void set_undef_val()   { oprops |= OPROP_UDEFVAL; }
  void set_lowaddr()     { oprops |= OPROP_LOWADDR; }
  void set_for_abi()     { oprops |= OPROP_ABI; }
  bool is_impptr_done() const { return (oprops & OPROP_IMPDONE) != 0; }
  bool is_udt()         const { return (oprops & OPROP_UDT) != 0; }
  bool probably_floating() const { return (oprops & OPROP_FLOAT) != 0; }
  bool is_undef_val()   const { return (oprops & OPROP_UDEFVAL) != 0; }
  bool is_lowaddr()     const { return (oprops & OPROP_LOWADDR) != 0; }
  bool is_for_abi()     const { return (oprops & OPROP_ABI) != 0; }
  bool is_ccflags() const
  {
    return (oprops & OPROP_CCFLAGS) != 0
        && (t == mop_l || t == mop_v || t == mop_S || t == mop_r);
  }
  bool is_pcval() const
  {
    return t == mop_n && (oprops & OPROP_CCFLAGS) != 0;
  }
  bool is_glbaddr_from_fixup() const
  {
    return is_glbaddr() && (oprops & OPROP_CCFLAGS) != 0;
  }

  mop_t() { zero(); }
  mop_t(const mop_t &rop) { copy(rop); }
  mop_t(mreg_t _r, int _s) : t(mop_r), oprops(0), valnum(0), size(_s), r(_r) {}
  mop_t &operator=(const mop_t &rop) { return assign(rop); }
  mop_t &hexapi assign(const mop_t &rop);
  ~mop_t()
  {
    erase();
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void zero() { t = mop_z; oprops = 0; valnum = 0; size = NOSIZE; nnn = nullptr; }
  void hexapi swap(mop_t &rop);
  void hexapi erase();
  void erase_but_keep_size() { int s2 = size; erase(); size = s2; }

  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const; // use this function for debugging

  //-----------------------------------------------------------------------
  // Operand creation
  //-----------------------------------------------------------------------
  /// Create operand from mlist_t.
  /// Example: if LST contains 4 bits for R0.4, our operand will be
  ///          (t=mop_r, r=R0, size=4)
  /// \param mba pointer to microcode
  /// \param lst list of locations
  /// \param fullsize mba->fullsize
  /// \return success
  bool hexapi create_from_mlist(mba_t *mba, const mlist_t &lst, sval_t fullsize);

  /// Create operand from ivlset_t.
  /// Example: if IVS contains [glbvar..glbvar+4), our operand will be
  ///          (t=mop_v, g=&glbvar, size=4)
  /// \param mba pointer to microcode
  /// \param ivs set of memory intervals
  /// \param fullsize mba->fullsize
  /// \return success
  bool hexapi create_from_ivlset(mba_t *mba, const ivlset_t &ivs, sval_t fullsize);

  /// Create operand from vdloc_t.
  /// Example: if LOC contains (type=ALOC_REG1, r=R0), our operand will be
  ///          (t=mop_r, r=R0, size=_SIZE)
  /// \param mba pointer to microcode
  /// \param loc location
  /// \param _size operand size
  /// Note: this function cannot handle scattered locations.
  /// \return success
  void hexapi create_from_vdloc(mba_t *mba, const vdloc_t &loc, int _size);

  /// Create operand from scattered vdloc_t.
  /// Example: if LOC is (ALOC_DIST, {EAX.4, EDX.4}) and TYPE is _LARGE_INTEGER,
  /// our operand will be
  ///          (t=mop_sc, scif={EAX.4, EDX.4})
  /// \param mba pointer to microcode
  /// \param name name of the operand, if available
  /// \param type type of the operand, must be present
  /// \param loc a scattered location
  /// \return success
  void hexapi create_from_scattered_vdloc(
        mba_t *mba,
        const char *name,
        tinfo_t type,
        const vdloc_t &loc);

  /// Create operand from an instruction.
  /// This function creates a nested instruction that can be used as an operand.
  /// Example: if m="add x,y,z", our operand will be (t=mop_d,d=m).
  /// The destination operand of 'add' (z) is lost.
  /// \param m instruction to embed into operand. may not be nullptr.
  void hexapi create_from_insn(const minsn_t *m);

  /// Create an integer constant operand.
  /// \param _value value to store in the operand
  /// \param _size size of the value in bytes (1,2,4,8)
  /// \param _ea   address of the processor instruction that made the value
  /// \param opnum operand number of the processor instruction
  void hexapi make_number(uint64 _value, int _size, ea_t _ea=BADADDR, int opnum=0);

  /// Create a floating point constant operand.
  /// \param bytes pointer to the floating point value as used by the current
  ///              processor (e.g. for x86 it must be in IEEE 754)
  /// \param _size number of bytes occupied by the constant.
  /// \return success
  bool hexapi make_fpnum(const void *bytes, size_t _size);

  /// Create a register operand without erasing previous data.
  /// \param reg  micro register number
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_reg(mreg_t reg)
  {
    t = mop_r;
    r = reg;
  }
  void _make_reg(mreg_t reg, int _size)
  {
    t = mop_r;
    r = reg;
    size = _size;
  }
  /// Create a register operand.
  void make_reg(mreg_t reg) { erase(); _make_reg(reg); }
  void make_reg(mreg_t reg, int _size) { erase(); _make_reg(reg, _size); }

  /// Create a local variable operand.
  /// \param mba pointer to microcode
  /// \param idx index into mba->vars
  /// \param off offset from the beginning of the variable
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_lvar(mba_t *mba, int idx, sval_t off=0)
  {
    t = mop_l;
    l = new lvar_ref_t(mba, idx, off);
  }

  /// Create a global variable operand without erasing previous data.
  /// \param ea  address of the variable
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void hexapi _make_gvar(ea_t ea);
  /// Create a global variable operand.
  void hexapi make_gvar(ea_t ea);

  /// Create a stack variable operand.
  /// \param mba pointer to microcode
  /// \param off decompiler stkoff
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_stkvar(mba_t *mba, sval_t off)
  {
    t = mop_S;
    s = new stkvar_ref_t(mba, off);
  }
  void make_stkvar(mba_t *mba, sval_t off) { erase(); _make_stkvar(mba, off); }

  /// Create pair of registers.
  /// \param loreg register holding the low part of the value
  /// \param hireg register holding the high part of the value
  /// \param halfsize the size of each of loreg/hireg
  void hexapi make_reg_pair(int loreg, int hireg, int halfsize);

  /// Create a nested instruction without erasing previous data.
  /// \param ins pointer to the instruction to encapsulate into the operand
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  /// See also create_from_insn, which is higher level
  void _make_insn(minsn_t *ins);
  /// Create a nested instruction.
  void make_insn(minsn_t *ins) { erase(); _make_insn(ins); }

  /// Create a block reference operand without erasing previous data.
  /// \param blknum block number
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_blkref(int blknum)
  {
    t = mop_b;
    b = blknum;
  }
  /// Create a global variable operand.
  void make_blkref(int blknum) { erase(); _make_blkref(blknum); }

  /// Create a helper operand.
  /// A helper operand usually keeps a built-in function name like "va_start"
  /// It is essentially just an arbitrary identifier without any additional info.
  void hexapi make_helper(const char *name);

  /// Create a constant string operand.
  void _make_strlit(const char *str)
  {
    t = mop_str;
    cstr = ::qstrdup(str);
  }
  void _make_strlit(qstring *str) // str is consumed
  {
    t = mop_str;
    cstr = str->extract();
  }

  /// Create a call info operand without erasing previous data.
  /// \param fi callinfo
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_callinfo(mcallinfo_t *fi)
  {
    t = mop_f;
    f = fi;
  }

  /// Create a 'switch cases' operand without erasing previous data.
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_cases(mcases_t *_cases)
  {
    t = mop_c;
    c = _cases;
  }

  /// Create a pair operand without erasing previous data.
  /// Note: this function does not erase the previous contents of the operand;
  ///       call erase() if necessary
  void _make_pair(mop_pair_t *_pair)
  {
    t = mop_p;
    pair = _pair;
  }

  //-----------------------------------------------------------------------
  // Various operand tests
  //-----------------------------------------------------------------------
  bool empty() const { return t == mop_z; }
  /// Is a global variable?
  bool is_glbvar() const { return t == mop_v; }
  /// Is a stack variable?
  bool is_stkvar() const { return t == mop_S; }
  /// Is a register operand?
  /// See also get_mreg_name()
  bool is_reg() const { return t == mop_r; }
  /// Is the specified register?
  bool is_reg(mreg_t _r) const { return t == mop_r && r == _r; }
  /// Is the specified register of the specified size?
  bool is_reg(mreg_t _r, int _size) const { return t == mop_r && r == _r && size == _size; }
  /// Is a list of arguments?
  bool is_arglist() const { return t == mop_f; }
  /// Is a condition code?
  bool is_cc() const { return is_reg() && r >= mr_cf && r < mr_first; }
  /// Is a bit register?
  /// This includes condition codes and eventually other bit registers
  static bool hexapi is_bit_reg(mreg_t reg);
  bool is_bit_reg() const { return is_reg() && is_bit_reg(r); }
  /// Is a kernel register?
  bool is_kreg() const;
  /// Is a block reference?
  bool is_mblock() const { return t == mop_b; }
  /// Is a block reference to the specified block?
  bool is_mblock(int serial) const { return is_mblock() && b == serial; }
  /// Is a scattered operand?
  bool is_scattered() const { return t == mop_sc; }
  /// Is address of a global memory cell?
  bool is_glbaddr() const;
  /// Is address of the specified global memory cell?
  bool is_glbaddr(ea_t ea) const;
  /// Is address of a stack variable?
  bool is_stkaddr() const;
  /// Is a sub-instruction?
  bool is_insn() const { return t == mop_d; }
  /// Is a sub-instruction with the specified opcode?
  bool is_insn(mcode_t code) const;
  /// Has any side effects?
  /// \param include_ldx_and_divs consider ldx/div/mod as having side effects?
  bool has_side_effects(bool include_ldx_and_divs=false) const;
  /// Is it possible for the operand to use aliased memory?
  bool hexapi may_use_aliased_memory() const;

  /// Are the possible values of the operand only 0 and 1?
  /// This function returns true for 0/1 constants, bit registers,
  /// the result of 'set' insns, etc.
  bool hexapi is01() const;

  /// Does the high part of the operand consist of the sign bytes?
  /// \param nbytes number of bytes that were sign extended.
  ///               the remaining size-nbytes high bytes must be sign bytes
  /// Example: is_sign_extended_from(xds.4(op.1), 1) -> true
  ///          because the high 3 bytes are certainly sign bits
  bool hexapi is_sign_extended_from(int nbytes) const;

  /// Does the high part of the operand consist of zero bytes?
  /// \param nbytes number of bytes that were zero extended.
  ///               the remaining size-nbytes high bytes must be zero
  /// Example: is_zero_extended_from(xdu.8(op.1), 2) -> true
  ///          because the high 6 bytes are certainly zero
  bool hexapi is_zero_extended_from(int nbytes) const;

  /// Does the high part of the operand consist of zero or sign bytes?
  bool is_extended_from(int nbytes, bool is_signed) const
  {
    if ( is_signed )
      return is_sign_extended_from(nbytes);
    else
      return is_zero_extended_from(nbytes);
  }

  //-----------------------------------------------------------------------
  // Comparisons
  //-----------------------------------------------------------------------
  /// Compare operands.
  /// This is the main comparison function for operands.
  /// \param rop     operand to compare with
  /// \param eqflags combination of \ref EQ_ bits
  bool hexapi equal_mops(const mop_t &rop, int eqflags) const;
  bool operator==(const mop_t &rop) const { return  equal_mops(rop, 0); }
  bool operator!=(const mop_t &rop) const { return !equal_mops(rop, 0); }

  /// Lexographical operand comparison.
  /// It can be used to store mop_t in various containers, like qset
  bool operator <(const mop_t &rop) const { return lexcompare(rop) < 0; }
  friend int lexcompare(const mop_t &a, const mop_t &b) { return a.lexcompare(b); }
  int hexapi lexcompare(const mop_t &rop) const;

  //-----------------------------------------------------------------------
  // Visiting operand parts
  //-----------------------------------------------------------------------
  /// Visit the operand and all its sub-operands.
  /// This function visits the current operand as well.
  /// \param mv        visitor object
  /// \param type      operand type
  /// \param is_target is a destination operand?
  int hexapi for_all_ops(
        mop_visitor_t &mv,
        const tinfo_t *type=nullptr,
        bool is_target=false);

  /// Visit all sub-operands of a scattered operand.
  /// This function does not visit the current operand, only its sub-operands.
  /// All sub-operands are synthetic and are destroyed after the visitor.
  /// This function works only with scattered operands.
  /// \param sv        visitor object
  int hexapi for_all_scattered_submops(scif_visitor_t &sv) const;

  //-----------------------------------------------------------------------
  // Working with mop_n operands
  //-----------------------------------------------------------------------
  /// Retrieve value of a constant integer operand.
  /// These functions can be called only for mop_n operands.
  /// See is_constant() that can be called on any operand.
  uint64 value(bool is_signed) const { return extend_sign(nnn->value, size, is_signed); }
  int64 signed_value() const { return value(true); }
  uint64 unsigned_value() const { return value(false); }
  void update_numop_value(uint64 val)
  {
    nnn->update_value(extend_sign(val, size, false));
  }

  /// Retrieve value of a constant integer operand.
  /// \param out pointer to the output buffer
  /// \param is_signed should treat the value as signed
  /// \return true if the operand is mop_n
  bool hexapi is_constant(uint64 *out=nullptr, bool is_signed=true) const;

  bool is_equal_to(uint64 n, bool is_signed=true) const
  {
    uint64 v;
    return is_constant(&v, is_signed) && v == n;
  }
  bool is_zero() const { return is_equal_to(0, false); }
  bool is_one() const { return is_equal_to(1, false); }
  bool is_positive_constant() const
  {
    uint64 v;
    return is_constant(&v, true) && int64(v) > 0;
  }
  bool is_negative_constant() const
  {
    uint64 v;
    return is_constant(&v, true) && int64(v) < 0;
  }

  //-----------------------------------------------------------------------
  // Working with mop_S operands
  //-----------------------------------------------------------------------
  /// Retrieve the referenced stack variable.
  /// \param[out] udm  stkvar, may be nullptr
  /// \param p_idaoff if specified, will hold IDA stkoff after the call.
  /// \return index of stkvar in the frame or -1
  ssize_t get_stkvar(udm_t *udm=nullptr, uval_t *p_idaoff=nullptr) const
  {
    return s->get_stkvar(udm, p_idaoff);
  }

  /// Get the referenced stack offset.
  /// This function can also handle mop_sc if it is entirely mapped into
  /// a continuous stack region.
  /// \param p_vdoff the output buffer
  /// \return success
  bool hexapi get_stkoff(sval_t *p_vdoff) const;

  //-----------------------------------------------------------------------
  // Working with mop_d operands
  //-----------------------------------------------------------------------
  /// Get subinstruction of the operand.
  /// If the operand has a subinstruction with the specified opcode, return it.
  /// \param code desired opcode
  /// \return pointer to the instruction or nullptr
  const minsn_t *get_insn(mcode_t code) const;
        minsn_t *get_insn(mcode_t code);

  //-----------------------------------------------------------------------
  // Transforming operands
  //-----------------------------------------------------------------------
  /// Make the low part of the operand.
  /// This function takes into account the memory endianness (byte sex)
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_low_half(int width);

  /// Make the high part of the operand.
  /// This function takes into account the memory endianness (byte sex)
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_high_half(int width);

  /// Make the first part of the operand.
  /// This function does not care about the memory endianness
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_first_half(int width);

  /// Make the second part of the operand.
  /// This function does not care about the memory endianness
  /// \param width the desired size of the operand part in bytes
  /// \return success
  bool hexapi make_second_half(int width);

  /// Shift the operand.
  /// This function shifts only the beginning of the operand.
  /// The operand size will be changed.
  /// Examples: shift_mop(AH.1, -1) -> AX.2
  ///           shift_mop(qword_00000008.8, 4) -> dword_0000000C.4
  ///           shift_mop(xdu.8(op.4), 4) -> #0.4
  ///           shift_mop(#0x12345678.4, 3) -> #12.1
  /// \param offset shift count (the number of bytes to shift)
  /// \return success
  bool hexapi shift_mop(int offset);

  /// Change the operand size.
  /// Examples: change_size(AL.1, 2) -> AX.2
  ///           change_size(qword_00000008.8, 4) -> dword_00000008.4
  ///           change_size(xdu.8(op.4), 4) -> op.4
  ///           change_size(#0x12345678.4, 1) -> #0x78.1
  /// \param nsize  new operand size
  /// \param sideff may modify the database because of the size change?
  /// \return success
  bool hexapi change_size(int nsize, side_effect_t sideff=WITH_SIDEFF);
  bool double_size(side_effect_t sideff=WITH_SIDEFF) { return change_size(size*2, sideff); }

  /// Move subinstructions with side effects out of the operand.
  /// If we decide to delete an instruction operand, it is a good idea to
  /// call this function. Alternatively we should skip such operands
  /// by calling mop_t::has_side_effects()
  /// For example, if we transform: jnz x, x, @blk => goto @blk
  /// then we must call this function before deleting the X operands.
  /// \param blk  current block
  /// \param top  top level instruction that contains our operand
  /// \param moved_calls pointer to the boolean that will track if all side
  ///                    effects get handled correctly. must be false initially.
  /// \return false failed to preserve a side effect, it is not safe to
  ///               delete the operand
  ///         true  no side effects or successfully preserved them
  bool hexapi preserve_side_effects(
        mblock_t *blk,
        minsn_t *top,
        bool *moved_calls=nullptr);

  /// Apply a unary opcode to the operand.
  /// \param mcode   opcode to apply. it must accept 'l' and 'd' operands
  ///                but not 'r'. examples: m_low/m_high/m_xds/m_xdu
  /// \param ea      value of minsn_t::ea for the newly created insruction
  /// \param newsize new operand size
  /// Example: apply_ld_mcode(m_low) will convert op => low(op)
  void hexapi apply_ld_mcode(mcode_t mcode, ea_t ea, int newsize);
  void apply_xdu(ea_t ea, int newsize) { apply_ld_mcode(m_xdu, ea, newsize); }
  void apply_xds(ea_t ea, int newsize) { apply_ld_mcode(m_xds, ea, newsize); }
};
DECLARE_TYPE_AS_MOVABLE(mop_t);

/// Pair of operands
class mop_pair_t
{
public:
  mop_t lop;            ///< low operand
  mop_t hop;            ///< high operand
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

/// Address of an operand (mop_l, mop_v, mop_S, mop_r)
class mop_addr_t : public mop_t
{
public:
  int insize = NOSIZE;  // how many bytes of the pointed operand can be read
  int outsize = NOSIZE; // how many bytes of the pointed operand can be written

  mop_addr_t() {}
  mop_addr_t(const mop_addr_t &ra)
    : mop_t(ra), insize(ra.insize), outsize(ra.outsize) {}
  mop_addr_t(const mop_t &ra, int isz, int osz)
    : mop_t(ra), insize(isz), outsize(osz) {}

  mop_addr_t &operator=(const mop_addr_t &rop)
  {
    *(mop_t *)this = mop_t(rop);
    insize = rop.insize;
    outsize = rop.outsize;
    return *this;
  }
  int lexcompare(const mop_addr_t &ra) const
  {
    int code = mop_t::lexcompare(ra);
    return code    != 0          ? code
         : insize  != ra.insize  ? (insize-ra.insize)
         : outsize != ra.outsize ? (outsize-ra.outsize)
         :                         0;
  }
};

/// A call argument
class mcallarg_t : public mop_t // #callarg
{
public:
  ea_t ea = BADADDR;            ///< address where the argument was initialized.
                                ///< BADADDR means unknown.
  tinfo_t type;                 ///< formal argument type
  qstring name;                 ///< formal argument name
  argloc_t argloc;              ///< ida argloc
  uint32 flags = 0;             ///< FAI_...

  mcallarg_t() {}
  mcallarg_t(const mop_t &rarg) : mop_t(rarg) {}
  void copy_mop(const mop_t &op) { *(mop_t *)this = op; }
  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const;
  void hexapi set_regarg(mreg_t mr, int sz, const tinfo_t &tif);
  void set_regarg(mreg_t mr, const tinfo_t &tif)
  {
    set_regarg(mr, tif.get_size(), tif);
  }
  void set_regarg(mreg_t mr, char dt, type_sign_t sign = type_unsigned)
  {
    int sz = get_dtype_size(dt);
    set_regarg(mr, sz, get_int_type_by_width_and_sign(sz, sign));
  }
  void make_int(int val, ea_t val_ea, int opno = 0)
  {
    type = tinfo_t(BTF_INT);
    make_number(val, inf_get_cc_size_i(), val_ea, opno);
  }
  void make_uint(int val, ea_t val_ea, int opno = 0)
  {
    type = tinfo_t(BTF_UINT);
    make_number(val, inf_get_cc_size_i(), val_ea, opno);
  }
};
DECLARE_TYPE_AS_MOVABLE(mcallarg_t);
typedef qvector<mcallarg_t> mcallargs_t;

/// Function roles.
/// They are used to calculate use/def lists and to recognize functions
/// without using string comparisons.
enum funcrole_t
{
  ROLE_UNK,                  ///< unknown function role
  ROLE_EMPTY,                ///< empty, does not do anything (maybe spoils regs)
  ROLE_MEMSET,               ///< memset(void *dst, uchar value, size_t count);
  ROLE_MEMSET32,             ///< memset32(void *dst, uint32 value, size_t count);
  ROLE_MEMSET64,             ///< memset64(void *dst, uint64 value, size_t count);
  ROLE_MEMCPY,               ///< memcpy(void *dst, const void *src, size_t count);
  ROLE_STRCPY,               ///< strcpy(char *dst, const char *src);
  ROLE_STRLEN,               ///< strlen(const char *src);
  ROLE_STRCAT,               ///< strcat(char *dst, const char *src);
  ROLE_TAIL,                 ///< char *tail(const char *str);
  ROLE_BUG,                  ///< BUG() helper macro: never returns, causes exception
  ROLE_ALLOCA,               ///< alloca() function
  ROLE_BSWAP,                ///< bswap() function (any size)
  ROLE_PRESENT,              ///< present() function (used in patterns)
  ROLE_CONTAINING_RECORD,    ///< CONTAINING_RECORD() macro
  ROLE_FASTFAIL,             ///< __fastfail()
  ROLE_READFLAGS,            ///< __readeflags, __readcallersflags
  ROLE_IS_MUL_OK,            ///< is_mul_ok
  ROLE_SATURATED_MUL,        ///< saturated_mul
  ROLE_BITTEST,              ///< [lock] bt
  ROLE_BITTESTANDSET,        ///< [lock] bts
  ROLE_BITTESTANDRESET,      ///< [lock] btr
  ROLE_BITTESTANDCOMPLEMENT, ///< [lock] btc
  ROLE_VA_ARG,               ///< va_arg() macro
  ROLE_VA_COPY,              ///< va_copy() function
  ROLE_VA_START,             ///< va_start() function
  ROLE_VA_END,               ///< va_end() function
  ROLE_ROL,                  ///< rotate left
  ROLE_ROR,                  ///< rotate right
  ROLE_CFSUB3,               ///< carry flag after subtract with carry
  ROLE_OFSUB3,               ///< overflow flag after subtract with carry
  ROLE_ABS,                  ///< integer absolute value
  ROLE_3WAYCMP0,             ///< 3-way compare helper, returns -1/0/1
  ROLE_3WAYCMP1,             ///< 3-way compare helper, returns 0/1/2
  ROLE_WMEMCPY,              ///< wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)
  ROLE_WMEMSET,              ///< wchar_t *wmemset(wchar_t *dst, wchar_t wc, size_t n)
  ROLE_WCSCPY,               ///< wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);
  ROLE_WCSLEN,               ///< size_t wcslen(const wchar_t *s)
  ROLE_WCSCAT,               ///< wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
  ROLE_SSE_CMP4,             ///< e.g. _mm_cmpgt_ss
  ROLE_SSE_CMP8,             ///< e.g. _mm_cmpgt_sd
};

/// \defgroup FUNC_NAME_ Well known function names
///@{
#define FUNC_NAME_MEMCPY   "memcpy"
#define FUNC_NAME_WMEMCPY  "wmemcpy"
#define FUNC_NAME_MEMSET   "memset"
#define FUNC_NAME_WMEMSET  "wmemset"
#define FUNC_NAME_MEMSET32 "memset32"
#define FUNC_NAME_MEMSET64 "memset64"
#define FUNC_NAME_STRCPY   "strcpy"
#define FUNC_NAME_WCSCPY   "wcscpy"
#define FUNC_NAME_STRLEN   "strlen"
#define FUNC_NAME_WCSLEN   "wcslen"
#define FUNC_NAME_STRCAT   "strcat"
#define FUNC_NAME_WCSCAT   "wcscat"
#define FUNC_NAME_TAIL     "tail"
#define FUNC_NAME_VA_ARG   "va_arg"
#define FUNC_NAME_EMPTY    "$empty"
#define FUNC_NAME_PRESENT  "$present"
#define FUNC_NAME_CONTAINING_RECORD "CONTAINING_RECORD"
#define FUNC_NAME_MORESTACK "runtime_morestack"
///@}


// the default 256 function arguments is too big, we use a lower value
#undef MAX_FUNC_ARGS
#define MAX_FUNC_ARGS 64

/// Information about a call
class mcallinfo_t               // #callinfo
{
public:
  ea_t callee;                  ///< address of the called function, if known
  int solid_args;               ///< number of solid args.
                                ///< there may be variadic args in addtion
  int call_spd = 0;             ///< sp value at call insn
  int stkargs_top = 0;          ///< first offset past stack arguments
  callcnv_t cc = CM_CC_INVALID; ///< calling convention
  mcallargs_t args;             ///< call arguments
  mopvec_t retregs;             ///< return register(s) (e.g., AX, AX:DX, etc.)
                                ///< this vector is built from return_regs
  tinfo_t return_type;          ///< type of the returned value
  argloc_t return_argloc;       ///< location of the returned value

  mlist_t return_regs;          ///< list of values returned by the function
  mlist_t spoiled;              ///< list of spoiled locations (includes return_regs)
  mlist_t pass_regs;            ///< passthrough registers: registers that depend on input
                                ///< values (subset of spoiled)
  ivlset_t visible_memory;      ///< what memory is visible to the call?
  mlist_t dead_regs;            ///< registers defined by the function but never used.
                                ///< upon propagation we do the following:
                                ///<   - dead_regs += return_regs
                                ///<   - retregs.clear() since the call is propagated
  int flags = 0;                ///< combination of \ref FCI_... bits
/// \defgroup FCI_ Call properties
///@{
#define FCI_PROP    0x001       ///< call has been propagated
#define FCI_DEAD    0x002       ///< some return registers were determined dead
#define FCI_FINAL   0x004       ///< call type is final, should not be changed
#define FCI_NORET   0x008       ///< call does not return
#define FCI_PURE    0x010       ///< pure function
#define FCI_NOSIDE  0x020       ///< call does not have side effects
#define FCI_SPLOK   0x040       ///< spoiled/visible_memory lists have been
                                ///< optimized. for some functions we can reduce them
                                ///< as soon as information about the arguments becomes
                                ///< available. in order not to try optimize them again
                                ///< we use this bit.
#define FCI_HASCALL 0x080       ///< A function is an synthetic helper combined
                                ///< from several instructions and at least one
                                ///< of them was a call to a real functions
#define FCI_HASFMT  0x100       ///< A variadic function with recognized
                                ///< printf- or scanf-style format string
#define FCI_EXPLOCS 0x400       ///< all arglocs are specified explicitly
///@}
  funcrole_t role = ROLE_UNK;   ///< function role
  type_attrs_t fti_attrs;       ///< extended function attributes

  mcallinfo_t(ea_t _callee=BADADDR, int _sargs=0)
    : callee(_callee), solid_args(_sargs)
  {
  }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  int hexapi lexcompare(const mcallinfo_t &f) const;
  bool hexapi set_type(const tinfo_t &type);
  tinfo_t hexapi get_type() const;
  bool is_vararg() const { return is_vararg_cc(cc); }
  void hexapi print(qstring *vout, int size=-1, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;
  const char *hexapi dstr() const;
};

/// List of switch cases and targets
class mcases_t                  // #cases
{
public:
  casevec_t values;             ///< expression values for each target
  intvec_t targets;             ///< target block numbers

  void swap(mcases_t &r) { values.swap(r.values); targets.swap(r.targets); }
  DECLARE_COMPARISONS(mcases_t);
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool empty() const { return targets.empty(); }
  size_t size() const { return targets.size(); }
  void resize(int s) { values.resize(s); targets.resize(s); }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};

//-------------------------------------------------------------------------
/// Value offset (microregister number or stack offset)
struct voff_t
{
  sval_t off = -1;     ///< register number or stack offset
  mopt_t type = mop_z; ///< mop_r - register, mop_S - stack, mop_z - undefined

  voff_t() {}
  voff_t(mopt_t _type, sval_t _off) : off(_off), type(_type) {}
  voff_t(const mop_t &op)
  {
    if ( op.is_reg() || op.is_stkvar() )
      set(op.t, op.is_reg() ? op.r : op.s->off);
  }

  void set(mopt_t _type, sval_t _off) { type = _type; off = _off; }
  void set_stkoff(sval_t stkoff)      { set(mop_S, stkoff); }
  void set_reg(mreg_t mreg)           { set(mop_r, mreg); }
  void undef()                        { set(mop_z, -1); }

  bool defined()      const { return type != mop_z; }
  bool is_reg()       const { return type == mop_r; }
  bool is_stkoff()    const { return type == mop_S; }
  mreg_t get_reg()    const { QASSERT(51892, is_reg()); return off; }
  sval_t get_stkoff() const { QASSERT(51893, is_stkoff()); return off; }

  void inc(sval_t delta)              { off += delta; }
  voff_t add(int width) const         { return voff_t(type, off+width); }
  sval_t diff(const voff_t &r) const  { QASSERT(51894, type == r.type); return off - r.off; }

  DECLARE_COMPARISONS(voff_t)
  {
    int code = ::compare(type, r.type);
    return code != 0 ? code : ::compare(off, r.off);
  }
};

//-------------------------------------------------------------------------
/// Value interval (register or stack range)
struct vivl_t : voff_t
{
  int size;     ///< Interval size in bytes

  vivl_t(mopt_t _type = mop_z, sval_t _off = -1, int _size = 0)
    : voff_t(_type, _off), size(_size) {}
  vivl_t(const class chain_t &ch);
  vivl_t(const mop_t &op) : voff_t(op), size(op.size) {}

  // Make a value interval
  void set(mopt_t _type, sval_t _off, int _size = 0)
    { voff_t::set(_type, _off); size = _size; }
  void set(const voff_t &voff, int _size)
    { set(voff.type, voff.off, _size); }
  void set_stkoff(sval_t stkoff, int sz = 0) { set(mop_S, stkoff, sz); }
  void set_reg   (mreg_t mreg,   int sz = 0) { set(mop_r, mreg,   sz); }

  /// Extend a value interval using another value interval of the same type
  /// \return success
  bool hexapi extend_to_cover(const vivl_t &r);

  /// Intersect value intervals the same type
  /// \return size of the resulting intersection
  uval_t hexapi intersect(const vivl_t &r);

  /// Do two value intervals overlap?
  bool overlap(const vivl_t &r) const
  {
    return type == r.type
        && interval::overlap(off, size, r.off, r.size);
  }
  /// Does our value interval include another?
  bool includes(const vivl_t &r) const
  {
    return type == r.type
        && interval::includes(off, size, r.off, r.size);
  }

  /// Does our value interval contain the specified value offset?
  bool contains(const voff_t &voff2) const
  {
    return type == voff2.type
        && interval::contains(off, size, voff2.off);
  }

  // Comparisons
  DECLARE_COMPARISONS(vivl_t)
  {
    int code = voff_t::compare(r);
    return code; //return code != 0 ? code : ::compare(size, r.size);
  }
  bool operator==(const mop_t &mop) const
  {
    return type == mop.t && off == (mop.is_reg() ? mop.r : mop.s->off);
  }
  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
};

//-------------------------------------------------------------------------
/// ud (use->def) and du (def->use) chain.
/// We store in chains only the block numbers, not individual instructions
/// See https://en.wikipedia.org/wiki/Use-define_chain
class chain_t : public intvec_t // sequence of block numbers
{
  voff_t k;             ///< Value offset of the chain.
                        ///< (what variable is this chain about)

public:
  int width = 0;        ///< size of the value in bytes
  int varnum = -1;      ///< allocated variable index (-1 - not allocated yet)
  uchar flags;          ///< combination \ref CHF_ bits
/// \defgroup CHF_ Chain properties
///@{
#define CHF_INITED     0x01 ///< is chain initialized? (valid only after lvar allocation)
#define CHF_REPLACED   0x02 ///< chain operands have been replaced?
#define CHF_OVER       0x04 ///< overlapped chain
#define CHF_FAKE       0x08 ///< fake chain created by widen_chains()
#define CHF_PASSTHRU   0x10 ///< pass-thru chain, must use the input variable to the block
#define CHF_TERM       0x20 ///< terminating chain; the variable does not survive across the block
///@}
  chain_t() : flags(CHF_INITED) {}
  chain_t(mopt_t t, sval_t off, int w=1, int v=-1)
    : k(t, off), width(w), varnum(v), flags(CHF_INITED) {}
  chain_t(const voff_t &_k, int w=1)
    : k(_k), width(w), varnum(-1), flags(CHF_INITED) {}
  void set_value(const chain_t &r)
    { width = r.width; varnum = r.varnum; flags = r.flags; *(intvec_t *)this = (intvec_t &)r; }
  const voff_t &key() const { return k; }
  bool is_inited() const { return (flags & CHF_INITED) != 0; }
  bool is_reg() const { return k.is_reg(); }
  bool is_stkoff() const { return k.is_stkoff(); }
  bool is_replaced() const { return (flags & CHF_REPLACED) != 0; }
  bool is_overlapped() const { return (flags & CHF_OVER) != 0; }
  bool is_fake() const { return (flags & CHF_FAKE) != 0; }
  bool is_passreg() const { return (flags & CHF_PASSTHRU) != 0; }
  bool is_term() const { return (flags & CHF_TERM) != 0; }
  void set_inited(bool b) { setflag(flags, CHF_INITED, b); }
  void set_replaced(bool b) { setflag(flags, CHF_REPLACED, b); }
  void set_overlapped(bool b) { setflag(flags, CHF_OVER, b); }
  void set_term(bool b) { setflag(flags, CHF_TERM, b); }
  mreg_t get_reg() const { return k.get_reg(); }
  sval_t get_stkoff() const { return k.get_stkoff(); }
  bool overlap(const chain_t &r) const
    { return k.type == r.k.type && interval::overlap(k.off, width, r.k.off, r.width); }
  bool includes(const chain_t &r) const
    { return k.type == r.k.type && interval::includes(k.off, width, r.k.off, r.width); }
  const voff_t endoff() const { return k.add(width); }

  bool operator<(const chain_t &r) const { return key() < r.key(); }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  /// Append the contents of the chain to the specified list of locations.
  void hexapi append_list(const mba_t *mba, mlist_t *list) const;
  void clear_varnum() { varnum = -1; set_replaced(false); }
};

//-------------------------------------------------------------------------
/// Chains of one block.
class block_chains_t : public qset<chain_t>
{
  int serial = -1;   ///< block number
public:
  using base_t = qset<chain_t>;
  using typename base_t::iterator;
  using typename base_t::const_iterator;
  using typename base_t::reverse_iterator;
  using typename base_t::const_reverse_iterator;

  /// Get chain for the specified register
  /// \param reg   register number
  /// \param width size of register in bytes
  const chain_t *get_reg_chain(mreg_t reg, int width=1) const
    { return get_chain((chain_t(mop_r, reg, width))); }
  chain_t *get_reg_chain(mreg_t reg, int width=1)
    { return get_chain((chain_t(mop_r, reg, width))); }

  /// Get chain for the specified stack offset
  /// \param off   stack offset
  /// \param width size of stack value in bytes
  const chain_t *get_stk_chain(sval_t off, int width=1) const
    { return get_chain(chain_t(mop_S, off, width)); }
  chain_t *get_stk_chain(sval_t off, int width=1)
    { return get_chain(chain_t(mop_S, off, width)); }

  /// Get chain for the specified value offset.
  /// \param k     value offset (register number or stack offset)
  /// \param width size of value in bytes
  const chain_t *get_chain(const voff_t &k, int width=1) const
    { return get_chain(chain_t(k, width)); }
  chain_t *get_chain(const voff_t &k, int width=1)
    { return (chain_t*)((const block_chains_t *)this)->get_chain(k, width); }

  /// Get chain similar to the specified chain
  /// \param ch    chain to search for. only its 'k' and 'width' are used.
  const chain_t *hexapi get_chain(const chain_t &ch) const;
  chain_t *get_chain(const chain_t &ch)
    { return (chain_t*)((const block_chains_t *)this)->get_chain(ch); }

  void hexapi print(qstring *vout) const;
  const char *hexapi dstr() const;
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};
//-------------------------------------------------------------------------
/// Chain visitor class
struct chain_visitor_t
{
  block_chains_t *parent = nullptr; ///< parent of the current chain
  virtual ~chain_visitor_t() {}
  virtual int idaapi visit_chain(int nblock, chain_t &ch) = 0;
};

//-------------------------------------------------------------------------
/// Graph chains.
/// This class represents all ud and du chains of the decompiled function
typedef qvector<block_chains_t> block_chains_vec_t;
class graph_chains_t : public block_chains_vec_t
{
  int lock = 0;         ///< are chained locked? (in-use)
public:
  ~graph_chains_t() { QASSERT(50444, !lock); }
  /// Visit all chains
  /// \param cv chain visitor
  /// \param gca_flags combination of GCA_ bits
  int hexapi for_all_chains(chain_visitor_t &cv, int gca_flags);
  /// \defgroup GCA_ chain visitor flags
  //@{
#define GCA_EMPTY  0x01 ///< include empty chains
#define GCA_SPEC   0x02 ///< include chains for special registers
#define GCA_ALLOC  0x04 ///< enumerate only allocated chains
#define GCA_NALLOC 0x08 ///< enumerate only non-allocated chains
#define GCA_OFIRST 0x10 ///< consider only chains of the first block
#define GCA_OLAST  0x20 ///< consider only chains of the last block
  //@}
  /// Are the chains locked?
  /// It is a good idea to lock the chains before using them. This ensures
  /// that they won't be recalculated and reallocated during the use.
  /// See the \ref chain_keeper_t class for that.
  bool is_locked() const { return lock != 0; }
  /// Lock the chains
  void acquire() { lock++; }
  /// Unlock the chains
  void hexapi release();
  void swap(graph_chains_t &r)
  {
    qvector<block_chains_t>::swap(r);
    std::swap(lock, r.lock);
  }
};
//-------------------------------------------------------------------------
/// Microinstruction class #insn
class minsn_t
{
  void hexapi init(ea_t _ea);
  void hexapi copy(const minsn_t &m);
public:
  mcode_t opcode;       ///< instruction opcode
  int iprops;           ///< combination of \ref IPROP_ bits
  minsn_t *next;        ///< next insn in doubly linked list. check also nexti()
  minsn_t *prev;        ///< prev insn in doubly linked list. check also previ()
  ea_t ea;              ///< instruction address
  mop_t l;              ///< left operand
  mop_t r;              ///< right operand
  mop_t d;              ///< destination operand

  /// \defgroup IPROP_ instruction property bits
  //@{
  // bits to be used in patterns:
#define IPROP_OPTIONAL  0x0001 ///< optional instruction
#define IPROP_PERSIST   0x0002 ///< persistent insn; they are not destroyed
#define IPROP_WILDMATCH 0x0004 ///< match multiple insns

  // instruction attributes:
#define IPROP_CLNPOP    0x0008 ///< the purpose of the instruction is to clean stack
                               ///< (e.g. "pop ecx" is often used for that)
#define IPROP_FPINSN    0x0010 ///< floating point insn
#define IPROP_FARCALL   0x0020 ///< call of a far function using push cs/call sequence
#define IPROP_TAILCALL  0x0040 ///< tail call
#define IPROP_ASSERT    0x0080 ///< assertion: usually mov #val, op.
                               ///< assertions are used to help the optimizer.
                               ///< assertions are ignored when generating ctree

  // instruction history:
#define IPROP_SPLIT     0x0700 ///< the instruction has been split:
#define IPROP_SPLIT1    0x0100 ///<   into 1 byte
#define IPROP_SPLIT2    0x0200 ///<   into 2 bytes
#define IPROP_SPLIT4    0x0300 ///<   into 4 bytes
#define IPROP_SPLIT8    0x0400 ///<   into 8 bytes
#define IPROP_COMBINED  0x0800 ///< insn has been modified because of a partial reference
#define IPROP_EXTSTX    0x1000 ///< this is m_ext propagated into m_stx
#define IPROP_IGNLOWSRC 0x2000 ///< low part of the instruction source operand
                               ///< has been created artificially
                               ///< (this bit is used only for 'and x, 80...')
#define IPROP_INV_JX    0x4000 ///< inverted conditional jump
#define IPROP_WAS_NORET 0x8000 ///< was noret icall
#define IPROP_MULTI_MOV 0x10000 ///< the minsn was generated as part of insn that moves multiple registers
                                ///< (example: STM on ARM may transfer multiple registers)

                                ///< bits that can be set by plugins:
#define IPROP_DONT_PROP 0x20000 ///< may not propagate
#define IPROP_DONT_COMB 0x40000 ///< may not combine this instruction with others
#define IPROP_MBARRIER  0x80000 ///< this instruction acts as a memory barrier
                                ///< (instructions accessing memory may not be reordered past it)
#define IPROP_UNMERGED 0x100000 ///< 'goto' instruction was transformed info 'call'
#define IPROP_UNPAIRED 0x200000 ///< instruction is a result of del_dest_pairs() transformation
  //@}

  bool is_optional()     const { return (iprops & IPROP_OPTIONAL)  != 0; }
  bool is_combined()     const { return (iprops & IPROP_COMBINED)  != 0; }
  bool is_farcall()      const { return (iprops & IPROP_FARCALL)   != 0; }
  bool is_cleaning_pop() const { return (iprops & IPROP_CLNPOP)    != 0; }
  bool is_extstx()       const { return (iprops & IPROP_EXTSTX)    != 0; }
  bool is_tailcall()     const { return (iprops & IPROP_TAILCALL)  != 0; }
  bool is_fpinsn()       const { return (iprops & IPROP_FPINSN)    != 0; }
  bool is_assert()       const { return (iprops & IPROP_ASSERT)    != 0; }
  bool is_persistent()   const { return (iprops & IPROP_PERSIST)   != 0; }
  bool is_wild_match()   const { return (iprops & IPROP_WILDMATCH) != 0; }
  bool is_propagatable() const { return (iprops & IPROP_DONT_PROP) == 0; }
  bool is_ignlowsrc()    const { return (iprops & IPROP_IGNLOWSRC) != 0; }
  bool is_inverted_jx()  const { return (iprops & IPROP_INV_JX)    != 0; }
  bool was_noret_icall() const { return (iprops & IPROP_WAS_NORET) != 0; }
  bool is_multimov()     const { return (iprops & IPROP_MULTI_MOV) != 0; }
  bool is_combinable()   const { return (iprops & IPROP_DONT_COMB) == 0; }
  bool was_split()       const { return (iprops & IPROP_SPLIT)     != 0; }
  bool is_mbarrier()     const { return (iprops & IPROP_MBARRIER)  != 0; }
  bool was_unmerged()    const { return (iprops & IPROP_UNMERGED)  != 0; }
  bool was_unpaired()    const { return (iprops & IPROP_UNPAIRED)  != 0; }

  void set_optional() { iprops |= IPROP_OPTIONAL; }
  void hexapi set_combined();
  void clr_combined() { iprops &= ~IPROP_COMBINED; }
  void set_farcall()  { iprops |= IPROP_FARCALL; }
  void set_cleaning_pop() { iprops |= IPROP_CLNPOP; }
  void set_extstx()   { iprops |= IPROP_EXTSTX; }
  void set_tailcall() { iprops |= IPROP_TAILCALL; }
  void clr_tailcall() { iprops &= ~IPROP_TAILCALL; }
  void set_fpinsn()   { iprops |= IPROP_FPINSN; }
  void clr_fpinsn()   { iprops &= ~IPROP_FPINSN; }
  void set_assert()   { iprops |= IPROP_ASSERT; }
  void clr_assert()   { iprops &= ~IPROP_ASSERT; }
  void set_persistent() { iprops |= IPROP_PERSIST; }
  void set_wild_match() { iprops |= IPROP_WILDMATCH; }
  void clr_propagatable() { iprops |= IPROP_DONT_PROP; }
  void set_ignlowsrc() { iprops |= IPROP_IGNLOWSRC; }
  void clr_ignlowsrc() { iprops &= ~IPROP_IGNLOWSRC; }
  void set_inverted_jx() { iprops |= IPROP_INV_JX; }
  void set_noret_icall() { iprops |= IPROP_WAS_NORET; }
  void clr_noret_icall() { iprops &= ~IPROP_WAS_NORET; }
  void set_multimov() { iprops |= IPROP_MULTI_MOV; }
  void clr_multimov() { iprops &= ~IPROP_MULTI_MOV; }
  void set_combinable() { iprops &= ~IPROP_DONT_COMB; }
  void clr_combinable() { iprops |= IPROP_DONT_COMB; }
  void set_mbarrier() { iprops |= IPROP_MBARRIER; }
  void set_unmerged() { iprops |= IPROP_UNMERGED; }
  void set_split_size(int s)
  { // s may be only 1,2,4,8. other values are ignored
    iprops &= ~IPROP_SPLIT;
    iprops |= (s == 1 ? IPROP_SPLIT1
             : s == 2 ? IPROP_SPLIT2
             : s == 4 ? IPROP_SPLIT4
             : s == 8 ? IPROP_SPLIT8 : 0);
  }
  int get_split_size() const
  {
    int cnt = (iprops & IPROP_SPLIT) >> 8;
    return cnt == 0 ? 0 : 1 << (cnt-1);
  }

  /// Constructor
  minsn_t(ea_t _ea) { init(_ea); }
  minsn_t(const minsn_t &m) { next = prev = nullptr; copy(m); }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()

  /// Assignment operator. It does not copy prev/next fields.
  minsn_t &operator=(const minsn_t &m) { copy(m); return *this; }

  /// Swap two instructions.
  /// The prev/next fields are not modified by this function
  /// because it would corrupt the doubly linked list.
  void hexapi swap(minsn_t &m);


  /// Generate insn text into the buffer
  void hexapi print(qstring *vout, int shins_flags=SHINS_SHORT|SHINS_VALNUM) const;

  /// Get displayable text without tags in a static buffer
  const char *hexapi dstr() const;

  /// Change the instruction address.
  /// This function modifies subinstructions as well.
  void hexapi setaddr(ea_t new_ea);

  /// Optimize one instruction without context.
  /// This function does not have access to the instruction context (the
  /// previous and next instructions in the list, the block number, etc).
  /// It performs only basic optimizations that are available without this info.
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes, 0-unchanged
  /// See also mblock_t::optimize_insn()
  int optimize_solo(int optflags=0) { return optimize_subtree(nullptr, nullptr, nullptr, nullptr, optflags); }
  /// \defgroup OPTI_ optimization flags
  //@{
#define OPTI_ADDREXPRS 0x0001 ///< optimize all address expressions (&x+N; &x-&y)
#define OPTI_MINSTKREF 0x0002 ///< may update minstkref
#define OPTI_COMBINSNS 0x0004 ///< may combine insns (only for optimize_insn)
#define OPTI_NO_LDXOPT 0x0008 ///< the function is called after the
                              ///< propagation attempt, we do not optimize
                              ///< low/high(ldx) in this case
#define OPTI_NO_VALRNG 0x0010 ///< forbid using valranges
  //@}

  /// Optimize instruction in its context.
  /// Do not use this function, use mblock_t::optimize()
  int hexapi optimize_subtree(
        mblock_t *blk,
        minsn_t *top,
        minsn_t *parent,
        ea_t *converted_call,
        int optflags=OPTI_MINSTKREF);

  /// Visit all instruction operands.
  /// This function visits subinstruction operands as well.
  /// \param mv operand visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all instructions.
  /// This function visits the instruction itself and all its subinstructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Convert instruction to nop.
  /// This function erases all info but the prev/next fields.
  /// In most cases it is better to use mblock_t::make_nop(), which also
  /// marks the block lists as dirty.
  void hexapi _make_nop();

  /// Compare instructions.
  /// This is the main comparison function for instructions.
  /// \param m       instruction to compare with
  /// \param eqflags combination of \ref EQ_ bits
  bool hexapi equal_insns(const minsn_t &m, int eqflags) const; // intelligent comparison
  /// \defgroup EQ_ comparison bits
  //@{
#define EQ_IGNSIZE 0x0001      ///< ignore source operand sizes
#define EQ_IGNCODE 0x0002      ///< ignore instruction opcodes
#define EQ_CMPDEST 0x0004      ///< compare instruction destinations
#define EQ_OPTINSN 0x0008      ///< optimize mop_d operands
  //@}

  /// Lexographical comparison
  /// It can be used to store minsn_t in various containers, like qset
  bool operator <(const minsn_t &ri) const { return lexcompare(ri) < 0; }
  int hexapi lexcompare(const minsn_t &ri) const;

  //-----------------------------------------------------------------------
  // Call instructions
  //-----------------------------------------------------------------------
  /// Is a non-returing call?
  /// \param flags combination of NORET_... bits
  bool hexapi is_noret_call(int flags=0);
#define NORET_IGNORE_WAS_NORET_ICALL 0x01 // ignore was_noret_icall() bit
#define NORET_FORBID_ANALYSIS        0x02 // forbid additional analysis

  /// Is an unknown call?
  /// Unknown calls are calls without the argument list (mcallinfo_t).
  /// Usually the argument lists are determined by mba_t::analyze_calls().
  /// Unknown calls exist until the MMAT_CALLS maturity level.
  /// See also \ref mblock_t::is_call_block
  bool is_unknown_call() const { return is_mcode_call(opcode) && d.empty(); }

  /// Is a helper call with the specified name?
  /// Helper calls usually have well-known function names (see \ref FUNC_NAME_)
  /// but they may have any other name. The decompiler does not assume any
  /// special meaning for non-well-known names.
  bool hexapi is_helper(const char *name) const;

  /// Find a call instruction.
  /// Check for the current instruction and its subinstructions.
  /// \param with_helpers consider helper calls as well?
  minsn_t *hexapi find_call(bool with_helpers=false) const;

  /// Does the instruction contain a call?
  bool contains_call(bool with_helpers=false) const { return find_call(with_helpers) != nullptr; }

  /// Does the instruction have a side effect?
  /// \param include_ldx_and_divs consider ldx/div/mod as having side effects?
  ///                    stx is always considered as having side effects.
  /// Apart from ldx/std only call may have side effects.
  bool hexapi has_side_effects(bool include_ldx_and_divs=false) const;

  /// Get the function role of a call
  funcrole_t get_role() const { return d.is_arglist() ? d.f->role : ROLE_UNK; }
  bool is_memcpy() const { return get_role() == ROLE_MEMCPY; }
  bool is_memset() const { return get_role() == ROLE_MEMSET; }
  bool is_alloca() const { return get_role() == ROLE_ALLOCA; }
  bool is_bswap () const { return get_role() == ROLE_BSWAP;  }
  bool is_readflags () const { return get_role() == ROLE_READFLAGS;  }

  //-----------------------------------------------------------------------
  // Misc
  //-----------------------------------------------------------------------
  /// Does the instruction have the specified opcode?
  /// This function searches subinstructions as well.
  /// \param mcode opcode to search for.
  bool contains_opcode(mcode_t mcode) const { return find_opcode(mcode) != nullptr; }

  /// Find a (sub)insruction with the specified opcode.
  /// \param mcode opcode to search for.
  const minsn_t *find_opcode(mcode_t mcode) const { return (CONST_CAST(minsn_t*)(this))->find_opcode(mcode); }
  minsn_t *hexapi find_opcode(mcode_t mcode);

  /// Find an operand that is a subinsruction with the specified opcode.
  /// This function checks only the 'l' and 'r' operands of the current insn.
  /// \param[out] other pointer to the other operand
  ///             (&r if we return &l and vice versa)
  /// \param op   opcode to search for
  /// \return &l or &r or nullptr
  const minsn_t *hexapi find_ins_op(const mop_t **other, mcode_t op=m_nop) const;
  minsn_t *find_ins_op(mop_t **other, mcode_t op=m_nop) { return CONST_CAST(minsn_t*)((CONST_CAST(const minsn_t*)(this))->find_ins_op((const mop_t**)other, op)); }

  /// Find a numeric operand of the current instruction.
  /// This function checks only the 'l' and 'r' operands of the current insn.
  /// \param[out] other pointer to the other operand
  ///             (&r if we return &l and vice versa)
  /// \return &l or &r or nullptr
  const mop_t *hexapi find_num_op(const mop_t **other) const;
  mop_t *find_num_op(mop_t **other) { return CONST_CAST(mop_t*)((CONST_CAST(const minsn_t*)(this))->find_num_op((const mop_t**)other)); }

  bool is_mov() const { return opcode == m_mov || (opcode == m_f2f && l.size == d.size); }
  bool is_like_move() const { return is_mov() || is_mcode_xdsu(opcode) || opcode == m_low; }

  /// Does the instruction modify its 'd' operand?
  /// Some instructions (e.g. m_stx) do not modify the 'd' operand.
  bool hexapi modifies_d() const;
  bool modifies_pair_mop() const { return d.t == mop_p && modifies_d(); }

  /// Is the instruction in the specified range of instructions?
  /// \param m1 beginning of the range in the doubly linked list
  /// \param m2 end of the range in the doubly linked list (excluded, may be nullptr)
  /// This function assumes that m1 and m2 belong to the same basic block
  /// and they are top level instructions.
  bool hexapi is_between(const minsn_t *m1, const minsn_t *m2) const;

  /// Is the instruction after the specified one?
  /// \param m the instruction to compare against in the list
  bool is_after(const minsn_t *m) const { return m != nullptr && is_between(m->next, nullptr); }

  /// Is it possible for the instruction to use aliased memory?
  bool hexapi may_use_aliased_memory() const;

  /// Serialize an instruction
  /// \param b the output buffer
  /// \return the serialization format that was used to store info
  int hexapi serialize(bytevec_t *b) const;

  /// Deserialize an instruction
  /// \param bytes pointer to serialized data
  /// \param nbytes number of bytes to deserialize
  /// \param format_version serialization format version. this value is returned by minsn_t::serialize()
  /// \return success
  bool hexapi deserialize(const uchar *bytes, size_t nbytes, int format_version);

};

/// Skip assertions forward
const minsn_t *hexapi getf_reginsn(const minsn_t *ins);
/// Skip assertions backward
const minsn_t *hexapi getb_reginsn(const minsn_t *ins);
inline minsn_t *getf_reginsn(minsn_t *ins) { return CONST_CAST(minsn_t*)(getf_reginsn(CONST_CAST(const minsn_t *)(ins))); }
inline minsn_t *getb_reginsn(minsn_t *ins) { return CONST_CAST(minsn_t*)(getb_reginsn(CONST_CAST(const minsn_t *)(ins))); }

//-------------------------------------------------------------------------
class intval64_t
{
public:
  uint64 val;
  int size; // in bytes

  intval64_t(uint64 v=0, int _s=1) : val(trunc(v, _s)), size(_s) {}
  int64 sval() const { return extend_sign(val, size, true); }
  uint64 uval() const { return val; }
  void print(qstring *vout) const { vout->sprnt("0x%" FMT_64 "X.%d", val, size); }

  //------------------------------------------------------------------------
  bool operator==(const intval64_t &o) const
  {
    return size == o.size && val == o.val;
  }

  //------------------------------------------------------------------------
  bool operator!=(const intval64_t &o) const
  {
    return !(*this == o);
  }

  //------------------------------------------------------------------------
  bool operator<(const intval64_t &o) const
  {
    QASSERT(52898, size == o.size);
    return val < o.val;
  }

  //------------------------------------------------------------------------
  intval64_t sext(int target_sz) const
  {
    QASSERT(52899, target_sz >= size);
    return intval64_t(sval(), target_sz);
  }

  //------------------------------------------------------------------------
  intval64_t zext(int target_sz) const
  {
    QASSERT(52900, target_sz >= size);
    return intval64_t(val, target_sz);
  }

  //------------------------------------------------------------------------
  intval64_t low(int target_sz) const
  {
    QASSERT(52901, target_sz <= size);
    return intval64_t(val, target_sz);
  }

  //------------------------------------------------------------------------
  intval64_t high(int target_sz) const
  {
    QASSERT(52902, target_sz <= size);
    int bytes_to_remove = size - target_sz;
    return intval64_t(right_ushift<uint64>(val, 8 * bytes_to_remove), target_sz);
  }

  //------------------------------------------------------------------------
  intval64_t operator+(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val + o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator-(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val - o.val, size);
  }

  //-------------------------------------------------------------------------
  intval64_t operator*(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val * o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator/(const intval64_t &o) const
  {
    check_size_equal(o);
    if ( o.val == 0 )
      throw "division by zero occurred when emulating instruction";
    return intval64_t(val / o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t sdiv(const intval64_t &o) const
  {
    check_size_equal(o);
    if ( o.val == 0 )
      throw "division by zero occurred when emulating instruction";
    int64 res;
    uint64 l = val;
    uint64 r = o.val;
    switch ( size )
    {
      case 1: res = int8(l)  / int8(r); break;
      case 2: res = int16(l) / int16(r); break;
      case 4: res = int32(l) / int32(r); break;
      case 8: res = int64(l) / int64(r); break;
      default: INTERR(30666);
    }

    return intval64_t(res, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator%(const intval64_t &o) const
  {
    check_size_equal(o);
    if ( o.val == 0 )
      throw "division by zero occurred when emulating instruction";
    return intval64_t(val % o.val, size);
  }
  //------------------------------------------------------------------------
  intval64_t smod(const intval64_t &o) const
  {
    check_size_equal(o);
    if ( o.val == 0 )
      throw "division by zero occurred when emulating instruction";
    int64 res = -1;
    uint64 l = val;
    uint64 r = o.val;
    switch ( size )
    {
      case 1: res = int8(l)  % int8(r); break;
      case 2: res = int16(l) % int16(r); break;
      case 4: res = int32(l) % int32(r); break;
      case 8: res = int64(l) % int64(r); break;
      default: INTERR(52903);
    }

    return intval64_t(res, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator<<(const intval64_t &o) const
  {
    return intval64_t(left_shift<uint64>(val, o.val), size);
  }

  //------------------------------------------------------------------------
  intval64_t operator>>(const intval64_t &o) const
  {
    return intval64_t(right_ushift<uint64>(val, o.val), size);
  }

  //------------------------------------------------------------------------
  intval64_t sar(const intval64_t &o) const
  {
    return intval64_t(right_sshift<int64>(sval(), o.val), size);
  }

  //------------------------------------------------------------------------
  intval64_t operator|(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val | o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator&(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val & o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator^(const intval64_t &o) const
  {
    check_size_equal(o);
    return intval64_t(val ^ o.val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator-() const
  {
    return intval64_t(0-val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator!() const
  {
    return intval64_t(!val, size);
  }

  //------------------------------------------------------------------------
  intval64_t operator~() const
  {
    return intval64_t(~val, size);
  }

private:
  //------------------------------------------------------------------------
  static uint64 trunc(uint64 v, int w) // truncate v to w bytes
  {
    QASSERT(52904, w == 1 || w == 2 || w == 4 || w == 8);
    return v & make_mask<uint64>(w * 8);
  }

  void check_size_equal(const intval64_t &o) const
  {
    QASSERT(52905, size == o.size);
  }
};

//-------------------------------------------------------------------------
// A simple 64bit emulator that can handle integer microcode instructions.
// This does not include control transfer instructions (except conditional jumps)
// and nop/ldx/stx/setp/...
// If the value cannot be calculated, an exception will be thrown:
//   vd_failure_t(MERR_EMULATOR, ea_if_known, error_message);
class int64_emulator_t
{
public:
  virtual ~int64_emulator_t() {}

  // Retrieve the value assigned to an operand.
  // This function is called for mop_r, mop_S, mop_v, mop_l
  virtual intval64_t get_mop_value(const mop_t &mop) = 0;

  // Calculate the operand value.
  // For register/stack/memory/lvar operands get_mop_value() will be called.
  bool hexapi _mop_value(intval64_t *out, const mop_t &mop, vd_failure_t *vf=nullptr);
  intval64_t mop_value(const mop_t &mop)
  {
    intval64_t v;
    vd_failure_t vf;
    if ( !_mop_value(&v, mop, &vf) )
      throw vf;
    return v;
  }


  // Calculate the result of applying the instruction opcode to its source
  // operands. This function does not store the result to the destination operand.
  // For example: "add r0, #2, ..." will return 3 if r0 contains 1.
  bool hexapi _minsn_value(intval64_t *out, const minsn_t &insn, vd_failure_t *vf=nullptr);
  intval64_t minsn_value(const minsn_t &insn)
  {
    intval64_t v;
    vd_failure_t vf;
    if ( !_minsn_value(&v, insn, &vf) )
      throw vf;
    return v;
  }
};

//-------------------------------------------------------------------------
/// Basic block types
enum mblock_type_t
{
  BLT_NONE = 0, ///< unknown block type
  BLT_STOP = 1, ///< stops execution regularly (must be the last block)
  BLT_0WAY = 2, ///< does not have successors (tail is a noret function)
  BLT_1WAY = 3, ///< passes execution to one block (regular or goto block)
  BLT_2WAY = 4, ///< passes execution to two blocks (conditional jump)
  BLT_NWAY = 5, ///< passes execution to many blocks (switch idiom)
  BLT_XTRN = 6, ///< external block (out of function address)
};

// Maximal bit range
#define MAXRANGE bitrange_t(0, USHRT_MAX)

//-------------------------------------------------------------------------
/// Microcode of one basic block.
/// All blocks are part of a doubly linked list. They can also be addressed
/// by indexing the mba->natural array. A block contains a doubly linked list
/// of instructions, various location lists that are used for data flow
/// analysis, and other attributes.
class mblock_t
{
  friend class codegen_t;
  DECLARE_UNCOPYABLE(mblock_t)
  void hexapi init();
public:
  mblock_t *nextb;              ///< next block in the doubly linked list
  mblock_t *prevb;              ///< previous block in the doubly linked list
  uint32 flags;                 ///< combination of \ref MBL_ bits
  /// \defgroup MBL_ Basic block properties
  //@{
#define MBL_PRIV        0x0001  ///< private block - no instructions except
                                ///< the specified are accepted (used in patterns)
#define MBL_NONFAKE     0x0000  ///< regular block
#define MBL_FAKE        0x0002  ///< fake block
#define MBL_GOTO        0x0004  ///< this block is a goto target
#define MBL_TCAL        0x0008  ///< aritifical call block for tail calls
#define MBL_PUSH        0x0010  ///< needs "convert push/pop instructions"
#define MBL_DMT64       0x0020  ///< needs "demote 64bits"
#define MBL_COMB        0x0040  ///< needs "combine" pass
#define MBL_PROP        0x0080  ///< needs 'propagation' pass
#define MBL_DEAD        0x0100  ///< needs "eliminate deads" pass
#define MBL_LIST        0x0200  ///< use/def lists are ready (not dirty)
#define MBL_INCONST     0x0400  ///< inconsistent lists: we are building them
#define MBL_CALL        0x0800  ///< call information has been built
#define MBL_BACKPROP    0x1000  ///< performed backprop_cc
#define MBL_NORET       0x2000  ///< dead end block: doesn't return execution control
#define MBL_DSLOT       0x4000  ///< block for delay slot
#define MBL_VALRANGES   0x8000  ///< should optimize using value ranges
#define MBL_KEEP       0x10000  ///< do not remove even if unreachable
#define MBL_INLINED    0x20000  ///< block was inlined, not originally part of mbr
#define MBL_EXTFRAME   0x40000  ///< an inlined block with an external frame
  //@}
  ea_t start;                   ///< start address
  ea_t end;                     ///< end address
                                ///< note: we cannot rely on start/end addresses
                                ///<       very much because instructions are
                                ///<       propagated between blocks
  minsn_t *head;                ///< pointer to the first instruction of the block
  minsn_t *tail;                ///< pointer to the last instruction of the block
  mba_t *mba;                   ///< the parent micro block array
  int serial;                   ///< block number
  mblock_type_t type;           ///< block type (BLT_NONE - not computed yet)

  mlist_t dead_at_start;        ///< data that is dead at the block entry
  mlist_t mustbuse;             ///< data that must be used by the block
  mlist_t maybuse;              ///< data that may  be used by the block
  mlist_t mustbdef;             ///< data that must be defined by the block
  mlist_t maybdef;              ///< data that may  be defined by the block
  mlist_t dnu;                  ///< data that is defined but not used in the block

  sval_t maxbsp;                ///< maximal sp value in the block (0...stacksize)
  sval_t minbstkref;            ///< lowest stack location accessible with indirect
                                ///< addressing (offset from the stack bottom)
                                ///< initially it is 0 (not computed)
  sval_t minbargref;            ///< the same for arguments

  intvec_t predset;             ///< control flow graph: list of our predecessors
                                ///< use npred() and pred() to access it
  intvec_t succset;             ///< control flow graph: list of our successors
                                ///< use nsucc() and succ() to access it

  // the exact size of this class is not documented, there may be more fields
  char reserved[];

  void mark_lists_dirty() { flags &= ~MBL_LIST; request_propagation(); }
  void request_propagation() { flags |= MBL_PROP; }
  bool needs_propagation() const { return (flags & MBL_PROP) != 0; }
  void request_demote64() { flags |= MBL_DMT64; }
  bool lists_dirty() const { return (flags & MBL_LIST) == 0; }
  bool lists_ready() const { return (flags & (MBL_LIST|MBL_INCONST)) == MBL_LIST; }
  int make_lists_ready() // returns number of changes
  {
    if ( lists_ready() )
      return 0;
    return build_lists(false);
  }

  /// Get number of block predecessors
  int npred() const { return predset.size(); } // number of xrefs to the block
  /// Get number of block successors
  int nsucc() const { return succset.size(); } // number of xrefs from the block
  // Get predecessor number N
  int pred(int n) const { return predset[n]; }
  // Get successor number N
  int succ(int n) const { return succset[n]; }

  mblock_t() = delete;
  virtual ~mblock_t();
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  bool empty() const { return head == nullptr; }


  /// Print block contents.
  /// \param vp print helpers class. it can be used to direct the printed
  ///           info to any destination
  void hexapi print(vd_printer_t &vp) const;

  /// Dump block info.
  /// This function is useful for debugging, see mba_t::dump for info
  void hexapi dump() const;
  AS_PRINTF(2, 0) void hexapi vdump_block(const char *title, va_list va) const;
  AS_PRINTF(2, 3) void dump_block(const char *title, ...) const
  {
    va_list va;
    va_start(va, title);
    vdump_block(title, va);
    va_end(va);
  }

  /// Verify an instruction.
  /// This function will generate an internal error if something is wrong
  /// with the instruction.
  void hexapi verify_insn(const minsn_t *m) const;

  //-----------------------------------------------------------------------
  // Functions to insert/remove insns during the microcode optimization phase.
  // See codegen_t, microcode_filter_t, udcall_t classes for the initial
  // microcode generation.
  //-----------------------------------------------------------------------
  /// Insert instruction into the doubly linked list
  /// \param nm new instruction
  /// \param om existing instruction, part of the doubly linked list
  ///           if nullptr, then the instruction will be inserted at the beginning
  ///           of the list
  /// NM will be inserted immediately after OM
  /// \return pointer to NM
  minsn_t *hexapi insert_into_block(minsn_t *nm, minsn_t *om);

  /// Remove instruction from the doubly linked list
  /// \param m instruction to remove
  /// The removed instruction is not deleted, the caller gets its ownership
  /// \return pointer to the next instruction
  minsn_t *hexapi remove_from_block(minsn_t *m);

  //-----------------------------------------------------------------------
  // Iterator over instructions and operands
  //-----------------------------------------------------------------------
  /// Visit all instructions.
  /// This function visits subinstructions too.
  /// \param mv instruction visitor
  /// \return zero or the value returned by mv.visit_insn()
  /// See also mba_t::for_all_topinsns()
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Visit all operands.
  /// This function visit subinstruction operands too.
  /// \param mv operand visitor
  /// \return zero or the value returned by mv.visit_mop()
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all operands that use LIST.
  /// \param list ptr to the list of locations. it may be modified:
  ///             parts that get redefined by the instructions in [i1,i2)
  ///             will be deleted.
  /// \param i1   starting instruction. must be a top level insn.
  /// \param i2   ending instruction (excluded). must be a top level insn.
  /// \param mmv  operand visitor
  /// \return zero or the value returned by mmv.visit_mop()
  int hexapi for_all_uses(
        mlist_t *list,
        minsn_t *i1,
        minsn_t *i2,
        mlist_mop_visitor_t &mmv);

  //-----------------------------------------------------------------------
  // Optimization functions
  //-----------------------------------------------------------------------
  /// Optimize one instruction in the context of the block.
  /// \param m pointer to a top level instruction
  /// \param optflags combination of \ref OPTI_ bits
  /// \return number of changes made to the block
  /// This function may change other instructions in the block too.
  /// However, it will not destroy top level instructions (it may convert them
  /// to nop's). This function performs only intrablock modifications.
  /// See also minsn_t::optimize_solo()
  int hexapi optimize_insn(minsn_t *m, int optflags=OPTI_MINSTKREF|OPTI_COMBINSNS);

  /// Optimize a basic block.
  /// Usually there is no need to call this function explicitly because the
  /// decompiler will call it itself if optinsn_t::func or optblock_t::func
  /// return non-zero.
  /// \return number of changes made to the block
  int hexapi optimize_block();

  /// Build def-use lists and eliminate deads.
  /// \param kill_deads do delete dead instructions?
  /// \return the number of eliminated instructions
  /// Better mblock_t::call make_lists_ready() rather than this function.
  int hexapi build_lists(bool kill_deads);

  /// Remove a jump at the end of the block if it is useless.
  /// This function preserves any side effects when removing a useless jump.
  /// Both conditional and unconditional jumps are handled (and jtbl too).
  /// This function deletes useless jumps, not only replaces them with a nop.
  /// (please note that \optimize_insn does not handle useless jumps).
  /// \return number of changes made to the block
  int hexapi optimize_useless_jump();

  //-----------------------------------------------------------------------
  // Functions that build with use/def lists. These lists are used to
  // reprsent list of registers and stack locations that are either modified
  // or accessed by microinstructions.
  //-----------------------------------------------------------------------
  /// Append use-list of an operand.
  /// This function calculates list of locations that may or must be used
  /// by the operand and appends it to LIST.
  /// \param list    ptr to the output buffer. we will append to it.
  /// \param op      operand to calculate the use list of
  /// \param maymust should we calculate 'may-use' or 'must-use' list?
  ///                see \ref maymust_t for more details.
  /// \param mask    if only part of the operand should be considered,
  ///                a bitmask can be used to specify which part.
  ///                example: op=AX,mask=0xFF means that we will consider only AL.
  void hexapi append_use_list(
        mlist_t *list,
        const mop_t &op,
        maymust_t maymust,
        bitrange_t mask=MAXRANGE) const;

  /// Append def-list of an operand.
  /// This function calculates list of locations that may or must be modified
  /// by the operand and appends it to LIST.
  /// \param list    ptr to the output buffer. we will append to it.
  /// \param op      operand to calculate the def list of
  /// \param maymust should we calculate 'may-def' or 'must-def' list?
  ///                see \ref maymust_t for more details.
  void hexapi append_def_list(
        mlist_t *list,
        const mop_t &op,
        maymust_t maymust) const;

  /// Build use-list of an instruction.
  /// This function calculates list of locations that may or must be used
  /// by the instruction. Examples:
  ///   "ldx ds.2, eax.4, ebx.4", may-list: all aliasable memory
  ///   "ldx ds.2, eax.4, ebx.4", must-list: empty
  /// Since LDX uses EAX for indirect access, it may access any aliasable
  /// memory. On the other hand, we cannot tell for sure which memory cells
  /// will be accessed, this is why the must-list is empty.
  /// \param ins     instruction to calculate the use list of
  /// \param maymust should we calculate 'may-use' or 'must-use' list?
  ///                see \ref maymust_t for more details.
  /// \return the calculated use-list
  mlist_t hexapi build_use_list(const minsn_t &ins, maymust_t maymust) const;

  /// Build def-list of an instruction.
  /// This function calculates list of locations that may or must be modified
  /// by the instruction. Examples:
  ///   "stx ebx.4, ds.2, eax.4", may-list: all aliasable memory
  ///   "stx ebx.4, ds.2, eax.4", must-list: empty
  /// Since STX uses EAX for indirect access, it may modify any aliasable
  /// memory. On the other hand, we cannot tell for sure which memory cells
  /// will be modified, this is why the must-list is empty.
  /// \param ins     instruction to calculate the def list of
  /// \param maymust should we calculate 'may-def' or 'must-def' list?
  ///                see \ref maymust_t for more details.
  /// \return the calculated def-list
  mlist_t hexapi build_def_list(const minsn_t &ins, maymust_t maymust) const;

  //-----------------------------------------------------------------------
  // The use/def lists can be used to search for interesting instructions
  //-----------------------------------------------------------------------
  /// Is the list used by the specified instruction range?
  /// \param list list of locations. LIST may be modified by the function:
  ///             redefined locations will be removed from it.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  bool is_used(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const
    { return find_first_use(list, i1, i2, maymust) != nullptr; }

  /// Find the first insn that uses the specified list in the insn range.
  /// \param list list of locations. LIST may be modified by the function:
  ///             redefined locations will be removed from it.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  /// \return pointer to such instruction or nullptr.
  ///         Upon return LIST will contain only locations not redefined
  ///         by insns [i1..result]
  const minsn_t *hexapi find_first_use(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const;
  minsn_t *find_first_use(mlist_t *list, minsn_t *i1, const minsn_t *i2, maymust_t maymust=MAY_ACCESS) const
  {
    return CONST_CAST(minsn_t*)(find_first_use(list,
                                               CONST_CAST(const minsn_t*)(i1),
                                               i2,
                                               maymust));
  }

  /// Is the list redefined by the specified instructions?
  /// \param list list of locations to check.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  bool is_redefined(
        const mlist_t &list,
        const minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const
  {
    return find_redefinition(list, i1, i2, maymust) != nullptr;
  }

  /// Find the first insn that redefines any part of the list in the insn range.
  /// \param list list of locations to check.
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  /// \param maymust should we search in 'may-access' or 'must-access' mode?
  /// \return pointer to such instruction or nullptr.
  const minsn_t *hexapi find_redefinition(
        const mlist_t &list,
        const minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const;
  minsn_t *find_redefinition(
        const mlist_t &list,
        minsn_t *i1,
        const minsn_t *i2,
        maymust_t maymust=MAY_ACCESS) const
  {
    return CONST_CAST(minsn_t*)(find_redefinition(list,
                                                  CONST_CAST(const minsn_t*)(i1),
                                                  i2,
                                                  maymust));
  }

  /// Is the right hand side of the instruction redefined the insn range?
  /// "right hand side" corresponds to the source operands of the instruction.
  /// \param ins instruction to consider
  /// \param i1   starting instruction of the range (must be a top level insn)
  /// \param i2   end instruction of the range (must be a top level insn)
  ///             i2 is excluded from the range. it can be specified as nullptr.
  ///             i1 and i2 must belong to the same block.
  bool hexapi is_rhs_redefined(const minsn_t *ins, const minsn_t *i1, const minsn_t *i2) const;

  /// Find the instruction that accesses the specified operand.
  /// This function search inside one block.
  /// \param op     operand to search for
  /// \param[in,out] parent ptr to ptr to a top level instruction.
  ///               in: denotes the beginning of the search range.
  ///               out: denotes the parent of the found instruction.
  /// \param mend   end instruction of the range (must be a top level insn)
  ///               mend is excluded from the range. it can be specified as nullptr.
  ///               parent and mend must belong to the same block.
  /// \param fdflags combination of \ref FD_ bits
  /// \return       the instruction that accesses the operand. this instruction
  ///               may be a sub-instruction. to find out the top level
  ///               instruction, check out *parent.
  ///               nullptr means 'not found'.
  minsn_t *hexapi find_access(
        const mop_t &op,
        minsn_t **parent,
        const minsn_t *mend,
        int fdflags) const;
  /// \defgroup FD_ bits for mblock_t::find_access
  //@{
#define FD_BACKWARD 0x0000  ///< search direction
#define FD_FORWARD  0x0001  ///< search direction
#define FD_USE      0x0000  ///< look for use
#define FD_DEF      0x0002  ///< look for definition
#define FD_DIRTY    0x0004  ///< ignore possible implicit definitions
                            ///< by function calls and indirect memory access
  //@}

  // Convenience functions:
  minsn_t *find_def(
        const mop_t &op,
        minsn_t **p_i1,
        const minsn_t *i2,
        int fdflags)
  {
    return find_access(op, p_i1, i2, fdflags|FD_DEF);
  }
  minsn_t *find_use(
        const mop_t &op,
        minsn_t **p_i1,
        const minsn_t *i2,
        int fdflags)
  {
    return find_access(op, p_i1, i2, fdflags|FD_USE);
  }

  /// Find possible values for a block.
  /// \param res     set of value ranges
  /// \param vivl    what to search for
  /// \param vrflags combination of \ref VR_ bits
  bool hexapi get_valranges(
        valrng_t *res,
        const vivl_t &vivl,
        int vrflags) const;

  /// Find possible values for an instruction.
  /// \param res     set of value ranges
  /// \param vivl    what to search for
  /// \param m       insn to search value ranges at. \sa VR_ bits
  /// \param vrflags combination of \ref VR_ bits
  bool hexapi get_valranges(
        valrng_t *res,
        const vivl_t &vivl,
        const minsn_t *m,
        int vrflags) const;

  /// \defgroup VR_ bits for get_valranges
  //@{
#define VR_AT_START 0x0000    ///< get value ranges before the instruction or
                              ///< at the block start (if M is nullptr)
#define VR_AT_END   0x0001    ///< get value ranges after the instruction or
                              ///< at the block end, just after the last
                              ///< instruction (if M is nullptr)
#define VR_EXACT    0x0002    ///< find exact match. if not set, the returned
                              ///< valrng size will be >= vivl.size
  //@}

  /// Erase the instruction (convert it to nop) and mark the lists dirty.
  /// This is the recommended function to use because it also marks the block
  /// use-def lists dirty.
  void make_nop(minsn_t *m) { m->_make_nop(); mark_lists_dirty(); }

  /// Calculate number of regular instructions in the block.
  /// Assertions are skipped by this function.
  /// \return Number of non-assertion instructions in the block.
  size_t hexapi get_reginsn_qty() const;

  bool is_call_block() const { return tail != nullptr && is_mcode_call(tail->opcode); }
  bool is_unknown_call() const { return tail != nullptr && tail->is_unknown_call(); }
  bool is_nway() const { return type == BLT_NWAY; }
  bool is_branch() const { return type == BLT_2WAY && tail->d.is_mblock(); }
  bool is_simple_goto_block() const
  {
    return get_reginsn_qty() == 1
        && tail->opcode == m_goto
        && tail->l.is_mblock();
  }
  bool is_simple_jcnd_block() const
  {
    return is_branch()
        && npred() == 1
        && get_reginsn_qty() == 1
        && is_mcode_convertible_to_set(tail->opcode);
  }
};
//-------------------------------------------------------------------------
enum memreg_index_t  ///< memory region types
{
  MMIDX_GLBLOW,      ///< global memory: low part
  MMIDX_LVARS,       ///< stack: local variables
  MMIDX_RETADDR,     ///< stack: return address
  MMIDX_SHADOW,      ///< stack: shadow arguments
  MMIDX_ARGS,        ///< stack: regular stack arguments
  MMIDX_GLBHIGH,     ///< global memory: high part
};

/// Item iterator of arbitrary rangevec items
struct range_item_iterator_t
{
  const rangevec_t *ranges = nullptr;
  const range_t *rptr = nullptr;       // pointer into ranges
  ea_t cur = BADADDR;                  // current address
  bool set(const rangevec_t &r);
  bool next_code();
  ea_t current() const { return cur; }
};

/// Item iterator for mba_ranges_t
struct mba_item_iterator_t
{
  range_item_iterator_t rii;
  func_item_iterator_t fii;
  bool func_items_done = true;
  bool set(const mba_ranges_t &mbr)
  {
    bool ok = false;
    if ( mbr.pfn != nullptr )
    {
      ok = fii.set(mbr.pfn);
      if ( ok )
        func_items_done = false;
    }
    if ( rii.set(mbr.ranges) )
      ok = true;
    return ok;
  }
  bool next_code()
  {
    bool ok = false;
    if ( !func_items_done )
    {
      ok = fii.next_code();
      if ( !ok )
        func_items_done = true;
    }
    if ( !ok )
      ok = rii.next_code();
    return ok;
  }
  ea_t current() const
  {
    return func_items_done ? rii.current() : fii.current();
  }
};

/// Chunk iterator of arbitrary rangevec items
struct range_chunk_iterator_t
{
  const range_t *rptr = nullptr;          // pointer into ranges
  const range_t *rend = nullptr;
  bool set(const rangevec_t &r) { rptr = r.begin(); rend = r.end(); return rptr != rend; }
  bool next() { return ++rptr != rend; }
  const range_t &chunk() const { return *rptr; }
};

/// Chunk iterator for mba_ranges_t
struct mba_range_iterator_t
{
  range_chunk_iterator_t rii;
  func_tail_iterator_t fii;     // this is used if rii.rptr==nullptr
  bool is_snippet() const { return rii.rptr != nullptr; }
  bool set(const mba_ranges_t &mbr)
  {
    if ( mbr.is_snippet() )
      return rii.set(mbr.ranges);
    else
      return fii.set(mbr.pfn);
  }
  bool next()
  {
    if ( is_snippet() )
      return rii.next();
    else
      return fii.next();
  }
  const range_t &chunk() const
  {
    return is_snippet() ? rii.chunk() : fii.chunk();
  }
};

//-------------------------------------------------------------------------
/// Array of micro blocks representing microcode for a decompiled function.
/// The first micro block is the entry point, the last one is the exit point.
/// The entry and exit blocks are always empty. The exit block is generated
/// at MMAT_LOCOPT maturity level.
class mba_t
{
  DECLARE_UNCOPYABLE(mba_t)
  uint32 flags;
  uint32 flags2;

public:
                     // bits to describe the microcode, set by the decompiler
#define MBA_PRCDEFS  0x00000001 ///< use precise defeas for chain-allocated lvars
#define MBA_NOFUNC   0x00000002 ///< function is not present, addresses might be wrong
#define MBA_PATTERN  0x00000004 ///< microcode pattern, callinfo is present
#define MBA_LOADED   0x00000008 ///< loaded gdl, no instructions (debugging)
#define MBA_RETFP    0x00000010 ///< function returns floating point value
#define MBA_SPLINFO  0x00000020 ///< (final_type ? idb_spoiled : spoiled_regs) is valid
#define MBA_PASSREGS 0x00000040 ///< has mcallinfo_t::pass_regs
#define MBA_THUNK    0x00000080 ///< thunk function
#define MBA_CMNSTK   0x00000100 ///< stkvars+stkargs should be considered as one area

                     // bits to describe analysis stages and requests
#define MBA_PREOPT   0x00000200 ///< preoptimization stage complete
#define MBA_CMBBLK   0x00000400 ///< request to combine blocks
#define MBA_ASRTOK   0x00000800 ///< assertions have been generated
#define MBA_CALLS    0x00001000 ///< callinfo has been built
#define MBA_ASRPROP  0x00002000 ///< assertion have been propagated
#define MBA_SAVRST   0x00004000 ///< save-restore analysis has been performed
#define MBA_RETREF   0x00008000 ///< return type has been refined
#define MBA_GLBOPT   0x00010000 ///< microcode has been optimized globally
#define MBA_LVARS0   0x00040000 ///< lvar pre-allocation has been performed
#define MBA_LVARS1   0x00080000 ///< lvar real allocation has been performed
#define MBA_DELPAIRS 0x00100000 ///< pairs have been deleted once
#define MBA_CHVARS   0x00200000 ///< can verify chain varnums

                     // bits that can be set by the caller:
#define MBA_SHORT    0x00400000 ///< use short display
#define MBA_COLGDL   0x00800000 ///< display graph after each reduction
#define MBA_INSGDL   0x01000000 ///< display instruction in graphs
#define MBA_NICE     0x02000000 ///< apply transformations to c code
#define MBA_REFINE   0x04000000 ///< may refine return value size
#define MBA_WINGR32  0x10000000 ///< use wingraph32
#define MBA_NUMADDR  0x20000000 ///< display definition addresses for numbers
#define MBA_VALNUM   0x40000000 ///< display value numbers

#define MBA_INITIAL_FLAGS  (MBA_INSGDL|MBA_NICE|MBA_CMBBLK|MBA_REFINE\
        |MBA_PRCDEFS|MBA_WINGR32|MBA_VALNUM)

#define MBA2_LVARNAMES_OK  0x00000001 ///< may verify lvar_names?
#define MBA2_LVARS_RENAMED 0x00000002 ///< accept empty names now?
#define MBA2_OVER_CHAINS   0x00000004 ///< has overlapped chains?
#define MBA2_VALRNG_DONE   0x00000008 ///< calculated valranges?
#define MBA2_IS_CTR        0x00000010 ///< is constructor?
#define MBA2_IS_DTR        0x00000020 ///< is destructor?
#define MBA2_ARGIDX_OK     0x00000040 ///< may verify input argument list?
#define MBA2_NO_DUP_CALLS  0x00000080 ///< forbid multiple calls with the same ea
#define MBA2_NO_DUP_LVARS  0x00000100 ///< forbid multiple lvars with the same ea
#define MBA2_UNDEF_RETVAR  0x00000200 ///< return value is undefined
#define MBA2_ARGIDX_SORTED 0x00000400 ///< args finally sorted according to ABI
                                      ///< (e.g. reverse stkarg order in Borland)
#define MBA2_CODE16_BIT    0x00000800 ///< the code16 bit got removed
#define MBA2_STACK_RETVAL  0x00001000 ///< the return value (or its part) is on the stack
#define MBA2_HAS_OUTLINES  0x00002000 ///< calls to outlined code have been inlined
#define MBA2_NO_FRAME      0x00004000 ///< do not use function frame info (only snippet mode)
#define MBA2_PROP_COMPLEX  0x00008000 ///< allow propagation of more complex variable definitions

#define MBA2_DONT_VERIFY   0x80000000 ///< Do not verify microcode. This flag
                                      ///< is recomended to be set only when
                                      ///< debugging decompiler plugins

#define MBA2_INITIAL_FLAGS  (MBA2_LVARNAMES_OK|MBA2_LVARS_RENAMED)

#define MBA2_ALL_FLAGS    0x0001FFFF

  bool precise_defeas() const { return (flags & MBA_PRCDEFS) != 0; }
  bool optimized()      const { return (flags & MBA_GLBOPT) != 0; }
  bool short_display()  const { return (flags & MBA_SHORT ) != 0; }
  bool show_reduction() const { return (flags & MBA_COLGDL) != 0; }
  bool graph_insns()    const { return (flags & MBA_INSGDL) != 0; }
  bool loaded_gdl()     const { return (flags & MBA_LOADED) != 0; }
  bool should_beautify()const { return (flags & MBA_NICE  ) != 0; }
  bool rtype_refined()  const { return (flags & MBA_RETREF) != 0; }
  bool may_refine_rettype() const { return (flags & MBA_REFINE) != 0; }
  bool use_wingraph32() const { return (flags & MBA_WINGR32) != 0; }
  bool display_numaddrs() const { return (flags & MBA_NUMADDR) != 0; }
  bool display_valnums() const { return (flags & MBA_VALNUM) != 0; }
  bool is_pattern()     const { return (flags & MBA_PATTERN) != 0; }
  bool is_thunk()       const { return (flags & MBA_THUNK) != 0; }
  bool saverest_done()  const { return (flags & MBA_SAVRST) != 0; }
  bool callinfo_built() const { return (flags & MBA_CALLS) != 0; }
  bool really_alloc()   const { return (flags & MBA_LVARS0) != 0; }
  bool lvars_allocated()const { return (flags & MBA_LVARS1) != 0; }
  bool chain_varnums_ok()const { return (flags & MBA_CHVARS) != 0; }
  bool returns_fpval()  const { return (flags & MBA_RETFP) != 0; }
  bool has_passregs()   const { return (flags & MBA_PASSREGS) != 0; }
  bool generated_asserts() const { return (flags & MBA_ASRTOK) != 0; }
  bool propagated_asserts() const { return (flags & MBA_ASRPROP) != 0; }
  bool deleted_pairs() const { return (flags & MBA_DELPAIRS) != 0; }
  bool common_stkvars_stkargs() const { return (flags & MBA_CMNSTK) != 0; }
  bool lvar_names_ok() const { return (flags2 & MBA2_LVARNAMES_OK) != 0; }
  bool lvars_renamed() const { return (flags2 & MBA2_LVARS_RENAMED) != 0; }
  bool has_over_chains() const { return (flags2 & MBA2_OVER_CHAINS) != 0; }
  bool valranges_done() const { return (flags2 & MBA2_VALRNG_DONE) != 0; }
  bool argidx_ok() const { return (flags2 & MBA2_ARGIDX_OK) != 0; }
  bool argidx_sorted() const { return (flags2 & MBA2_ARGIDX_SORTED) != 0; }
  bool code16_bit_removed() const { return (flags2 & MBA2_CODE16_BIT) != 0; }
  bool has_stack_retval() const { return (flags2 & MBA2_STACK_RETVAL) != 0; }
  bool has_outlines() const { return (flags2 & MBA2_HAS_OUTLINES) != 0; }
  bool is_ctr() const { return (flags2 & MBA2_IS_CTR) != 0; }
  bool is_dtr() const { return (flags2 & MBA2_IS_DTR) != 0; }
  bool is_cdtr() const { return (flags2 & (MBA2_IS_CTR|MBA2_IS_DTR)) != 0; }
  bool prop_complex() const { return (flags2 & MBA2_PROP_COMPLEX) != 0; }
  int  get_mba_flags() const { return flags; }
  int  get_mba_flags2() const { return flags2; }
  void set_mba_flags(int f) { flags |= f; }
  void clr_mba_flags(int f) { flags &= ~f; }
  void set_mba_flags2(int f) { flags2 |= f; }
  void clr_mba_flags2(int f) { flags2 &= ~f; }
  void clr_cdtr() { flags2 &= ~(MBA2_IS_CTR|MBA2_IS_DTR); }
  int calc_shins_flags() const
  {
    int shins_flags = 0;
    if ( short_display() )
      shins_flags |= SHINS_SHORT;
    if ( display_valnums() )
      shins_flags |= SHINS_VALNUM;
    if ( display_numaddrs() )
      shins_flags |= SHINS_NUMADDR;
    return shins_flags;
  }

/*
                     +-----------+ <- inargtop
                     |   prmN    |
                     |   ...     | <- minargref
                     |   prm0    |
                     +-----------+ <- inargoff
                     |shadow_args|
                     +-----------+
                     |  retaddr  |
     frsize+frregs   +-----------+ <- initial esp  |
                     |  frregs   |                 |
           +frsize   +-----------+ <- typical ebp  |
                     |           |  |              |
                     |           |  | fpd          |
                     |           |  |              |
                     |  frsize   | <- current ebp  |
                     |           |                 |
                     |           |                 |
                     |           |                 | stacksize
                     |           |                 |
                     |           |                 |
                     |           | <- minstkref    |
 stkvar base off 0   +---..      |                 |    | current
                     |           |                 |    | stack
                     |           |                 |    | pointer
                     |           |                 |    | range
                     |tmpstk_size|                 |    | (what getspd() returns)
                     |           |                 |    |
                     |           |                 |    |
                     +-----------+ <- minimal sp   |    | offset 0 for the decompiler (vd)

  There is a detail that may add confusion when working with stack variables.
  The decompiler does not use the same stack offsets as IDA.
  The picture above should explain the difference:
  - IDA stkoffs are displayed on the left, decompiler stkoffs - on the right
  - Decompiler stkoffs are always >= 0
  - IDA stkoff==0 corresponds to stkoff==tmpstk_size in the decompiler
  - See stkoff_vd2ida and stkoff_ida2vd below to convert IDA stkoffs to vd stkoff

*/

  // convert a stack offset used in vd to a stack offset used in ida stack frame
  sval_t hexapi stkoff_vd2ida(sval_t off) const;
  // convert a ida stack frame offset to a stack offset used in vd
  sval_t hexapi stkoff_ida2vd(sval_t off) const;
  sval_t argbase() const
  {
    return retsize + stacksize;
  }
  static vdloc_t hexapi idaloc2vd(const argloc_t &loc, int width, sval_t spd);
  vdloc_t hexapi idaloc2vd(const argloc_t &loc, int width) const;

  static argloc_t hexapi vd2idaloc(const vdloc_t &loc, int width, sval_t spd);
  argloc_t hexapi vd2idaloc(const vdloc_t &loc, int width) const;

  bool is_stkarg(const lvar_t &v) const
  {
    return v.is_stk_var() && v.get_stkoff() >= inargoff;
  }
  ssize_t get_stkvar(
        udm_t *udm,
        sval_t vd_stkoff,
        uval_t *p_idaoff=nullptr,
        tinfo_t *p_frame=nullptr) const;
  // get lvar location
  argloc_t get_ida_argloc(const lvar_t &v) const
  {
    return vd2idaloc(v.location, v.width);
  }
  mba_ranges_t mbr;
  ea_t entry_ea = BADADDR;
  ea_t last_prolog_ea = BADADDR;
  ea_t first_epilog_ea = BADADDR;
  int qty = 0;                  ///< number of basic blocks
  int npurged = -1;             ///< -1 - unknown
  callcnv_t cc = CM_CC_UNKNOWN; ///< calling convention
  sval_t tmpstk_size = 0;       ///< size of the temporary stack part
                                ///< (which dynamically changes with push/pops)
  sval_t frsize = 0;            ///< size of local stkvars range in the stack frame
  sval_t frregs = 0;            ///< size of saved registers range in the stack frame
  sval_t fpd = 0;               ///< frame pointer delta
  int pfn_flags = 0;            ///< copy of func_t::flags
  int retsize = 0;              ///< size of return address in the stack frame
  int shadow_args = 0;          ///< size of shadow argument area
  sval_t fullsize = 0;          ///< Full stack size including incoming args
  sval_t stacksize = 0;         ///< The maximal size of the function stack including
                                ///< bytes allocated for outgoing call arguments
                                ///< (up to retaddr)
  sval_t inargoff = 0;          ///< offset of the first stack argument;
                                ///< after fix_scattered_movs() INARGOFF may
                                ///< be less than STACKSIZE
  sval_t minstkref = 0;         ///< The lowest stack location whose address was taken
  ea_t minstkref_ea = BADADDR;  ///< address with lowest minstkref (for debugging)
  sval_t minargref = 0;         ///< The lowest stack argument location whose address was taken
                                ///< This location and locations above it can be aliased
                                ///< It controls locations >= inargoff-shadow_args
  sval_t spd_adjust = 0;        ///< If sp>0, the max positive sp value
  ivlset_t gotoff_stkvars;      ///< stkvars that hold .got offsets. considered to be unaliasable
  ivlset_t restricted_memory;
  ivlset_t aliased_memory = ALLMEM; ///< aliased_memory+restricted_memory=ALLMEM
  mlist_t nodel_memory;         ///< global dead elimination may not delete references to this area
  rlist_t consumed_argregs;     ///< registers converted into stack arguments, should not be used as arguments

  mba_maturity_t maturity = MMAT_ZERO; ///< current maturity level
  mba_maturity_t reqmat = MMAT_ZERO;   ///< required maturity level

  bool final_type = false;      ///< is the function type final? (specified by the user)
  tinfo_t idb_type;             ///< function type as retrieved from the database
  reginfovec_t idb_spoiled;     ///< MBA_SPLINFO && final_type: info in ida format
  mlist_t spoiled_list;         ///< MBA_SPLINFO && !final_type: info in vd format
  int fti_flags = 0;            ///< FTI_... constants for the current function

#define NALT_VD 2               ///< this index is not used by ida

  qstring label;                ///< name of the function or pattern (colored)
  lvars_t vars;                 ///< local variables
  intvec_t argidx;              ///< input arguments (indexes into 'vars')
  int retvaridx = -1;           ///< index of variable holding the return value
                                ///< -1 means none

  ea_t error_ea = BADADDR;      ///< during microcode generation holds ins.ea
  qstring error_strarg;

  mblock_t *blocks = nullptr;   ///< double linked list of blocks
  mblock_t **natural = nullptr; ///< natural order of blocks

  ivl_with_name_t std_ivls[6];  ///< we treat memory as consisting of 6 parts
                                ///< see \ref memreg_index_t

  mutable hexwarns_t notes;
  mutable uchar occurred_warns[32]; // occurred warning messages
                                    // (even disabled warnings are taken into account)
  bool write_to_const_detected() const
  {
    return test_bit(occurred_warns, WARN_WRITE_CONST);
  }
  bool bad_call_sp_detected() const
  {
    return test_bit(occurred_warns, WARN_BAD_CALL_SP);
  }
  bool regargs_is_not_aligned() const
  {
    return test_bit(occurred_warns, WARN_UNALIGNED_ARG);
  }
  bool has_bad_sp() const
  {
    return test_bit(occurred_warns, WARN_BAD_SP);
  }

  // the exact size of this class is not documented, there may be more fields
  char reserved[];
  mba_t(); // use gen_microcode() or create_empty_mba() to create microcode objects
  ~mba_t() { term(); }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
  void hexapi term();
  func_t *hexapi get_curfunc() const;
  bool use_frame() const { return get_curfunc() != nullptr; }
  bool range_contains(ea_t ea) const { return mbr.range_contains(map_fict_ea(ea)); }
  bool is_snippet() const { return mbr.is_snippet(); }

  /// Set maturity level.
  /// \param mat new maturity level
  /// \return error code
  /// Plugins may use this function to skip some parts of the analysis.
  /// The maturity level cannot be decreased.
  merror_t hexapi set_maturity(mba_maturity_t mat);

  /// Optimize each basic block locally
  /// \param locopt_bits combination of \ref LOCOPT_ bits
  /// \return number of changes. 0 means nothing changed
  /// This function is called by the decompiler, usually there is no need to
  /// call it explicitly.
  int hexapi optimize_local(int locopt_bits);
  /// \defgroup LOCOPT_ Bits for optimize_local()
  //@{
#define LOCOPT_ALL     0x0001 ///< redo optimization for all blocks. if this bit
                              ///< is not set, only dirty blocks will be optimized
#define LOCOPT_REFINE  0x0002 ///< refine return type, ok to fail
#define LOCOPT_REFINE2 0x0004 ///< refine return type, try harder
  //@}

  /// Build control flow graph.
  /// This function may be called only once. It calculates the type of each
  /// basic block and the adjacency list. optimize_local() calls this function
  /// if necessary. You need to call this function only before MMAT_LOCOPT.
  /// \return error code
  merror_t hexapi build_graph();

  /// Get control graph.
  /// Call build_graph() if you need the graph before MMAT_LOCOPT.
  mbl_graph_t *hexapi get_graph();

  /// Analyze calls and determine calling conventions.
  /// \param acflags permitted actions that are necessary for successful detection
  ///                of calling conventions. See \ref ACFL_
  /// \return number of calls. -1 means error.
  int hexapi analyze_calls(int acflags);
  /// \defgroup ACFL_ Bits for analyze_calls()
  //@{
#define ACFL_LOCOPT  0x01 ///< perform local propagation (requires ACFL_BLKOPT)
#define ACFL_BLKOPT  0x02 ///< perform interblock transformations
#define ACFL_GLBPROP 0x04 ///< perform global propagation
#define ACFL_GLBDEL  0x08 ///< perform dead code eliminition
#define ACFL_GUESS   0x10 ///< may guess calling conventions
  //@}

  /// Optimize microcode globally.
  /// This function applies various optimization methods until we reach the
  /// fixed point. After that it preallocates lvars unless reqmat forbids it.
  /// \return error code
  merror_t hexapi optimize_global();

  /// Allocate local variables.
  /// Must be called only immediately after optimize_global(), with no
  /// modifications to the microcode. Converts registers,
  /// stack variables, and similar operands into mop_l. This call will not fail
  /// because all necessary checks were performed in optimize_global().
  /// After this call the microcode reaches its final state.
  void hexapi alloc_lvars();

  /// Dump microcode to a file.
  /// The file will be created in the directory pointed by IDA_DUMPDIR envvar.
  /// Dump will be created only if IDA is run under debugger.
  void hexapi dump() const;
  AS_PRINTF(3, 0) void hexapi vdump_mba(bool _verify, const char *title, va_list va) const;
  AS_PRINTF(3, 4) void dump_mba(bool _verify, const char *title, ...) const
  {
    va_list va;
    va_start(va, title);
    vdump_mba(_verify, title, va);
    va_end(va);
  }

  /// Print microcode to any destination.
  /// \param vp print sink
  void hexapi print(vd_printer_t &vp) const;

  /// Verify microcode consistency.
  /// \param always if false, the check will be performed only if ida runs
  ///               under debugger
  /// If any inconsistency is discovered, an internal error will be generated.
  /// We strongly recommend you to call this function before returing control
  /// to the decompiler from your callbacks, in the case if you modified
  /// the microcode. If the microcode is inconsistent, this function will
  /// generate an internal error. We provide the source code of this function
  /// in the plugins/hexrays_sdk/verifier directory for your reference.
  void hexapi verify(bool always) const;

  /// Mark the microcode use-def chains dirty.
  /// Call this function is any inter-block data dependencies got changed
  /// because of your modifications to the microcode. Failing to do so may
  /// cause an internal error.
  void hexapi mark_chains_dirty();

  /// Get basic block by its serial number.
  const mblock_t *get_mblock(uint n) const { QASSERT(52719, n < qty); return natural[n]; }
  mblock_t *get_mblock(uint n) { return CONST_CAST(mblock_t*)((CONST_CAST(const mba_t *)(this))->get_mblock(n)); }

  /// Insert a block in the middle of the mbl array.
  /// The very first block of microcode must be empty, it is the entry block.
  /// The very last block of microcode must be BLT_STOP, it is the exit block.
  /// Therefore inserting a new block before the entry point or after the exit
  /// block is not a good idea.
  /// \param bblk the new block will be inserted before BBLK
  /// \return ptr to the new block
  mblock_t *hexapi insert_block(int bblk);

  /// Split a block: insert a new one after the block, move some instructions
  /// to new block
  /// \param blk        block to be split
  /// \param start_insn all instructions to be moved to new block: starting with this one up to the end
  /// \return ptr to the new block
  mblock_t *hexapi split_block(mblock_t *blk, minsn_t *start_insn);

  /// Delete a block.
  /// \param blk block to delete
  /// \return true if at least one of the other blocks became empty or unreachable
  bool hexapi remove_block(mblock_t *blk);
  bool hexapi remove_blocks(int start_blk, int end_blk); // end_blk is excluded

  /// Make a copy of a block.
  /// This function makes a simple copy of the block. It does not fix the
  /// predecessor and successor lists, they must be fixed if necessary.
  /// \param blk         block to copy
  /// \param new_serial  position of the copied block
  /// \param cpblk_flags combination of \ref CPBLK_... bits
  /// \return pointer to the new copy
  mblock_t *hexapi copy_block(mblock_t *blk, int new_serial, int cpblk_flags=3);
/// \defgroup CPBLK_ Batch decompilation bits
///@{
#define CPBLK_FAST   0x0000     ///< do not update minbstkref and minbargref
#define CPBLK_MINREF 0x0001     ///< update minbstkref and minbargref
#define CPBLK_OPTJMP 0x0002     ///< del the jump insn at the end of the block
                                ///< if it becomes useless
///@}

  /// Delete all empty and unreachable blocks.
  /// Blocks marked with MBL_KEEP won't be deleted.
  bool hexapi remove_empty_and_unreachable_blocks();

  /// Merge blocks.
  /// This function merges blocks constituting linear flow.
  /// It calls remove_empty_and_unreachable_blocks() as well.
  /// \return true if changed any blocks
  bool hexapi merge_blocks();

  /// Visit all operands of all instructions.
  /// \param mv operand visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_ops(mop_visitor_t &mv);

  /// Visit all instructions.
  /// This function visits all instruction and subinstructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_insns(minsn_visitor_t &mv);

  /// Visit all top level instructions.
  /// \param mv instruction visitor
  /// \return non-zero value returned by mv.visit_mop() or zero
  int hexapi for_all_topinsns(minsn_visitor_t &mv);

  /// Find an operand in the microcode.
  /// This function tries to find the operand that matches LIST.
  /// Any operand that overlaps with LIST is considered as a match.
  /// \param[out] ctx context information for the result
  /// \param ea       desired address of the operand. BADADDR means to accept any address.
  /// \param is_dest  search for destination operand? this argument may be
  ///                 ignored if the exact match could not be found
  /// \param list     list of locations the correspond to the operand
  /// \return pointer to the operand or nullptr.
  mop_t *hexapi find_mop(op_parent_info_t *ctx, ea_t ea, bool is_dest, const mlist_t &list);

  /// Create a call of a helper function.
  /// \param ea       The desired address of the instruction
  /// \param helper   The helper name
  /// \param rettype  The return type (nullptr or empty type means 'void')
  /// \param callargs The helper arguments (nullptr-no arguments)
  /// \param out      The operand where the call result should be stored.
  ///                 If this argument is not nullptr, "mov helper_call(), out"
  ///                 will be generated. Otherwise "call helper()" will be
  ///                 generated. Note: the size of this operand must be equal
  ///                 to the RETTYPE size
  /// \return pointer to the created instruction or nullptr if error
  minsn_t *hexapi create_helper_call(
        ea_t ea,
        const char *helper,
        const tinfo_t *rettype=nullptr,
        const mcallargs_t *callargs=nullptr,
        const mop_t *out=nullptr);

  /// Prepare the lists of registers & memory that are defined/killed by a
  /// function
  /// \param[out] return_regs  defined regs to return (eax,edx)
  /// \param[out] spoiled      spoiled regs (flags,ecx,mem)
  /// \param      type         the function type
  /// \param      call_ea      the call insn address (if known)
  /// \param      tail_call    is it the tail call?
  void hexapi get_func_output_lists(
        mlist_t *return_regs,
        mlist_t *spoiled,
        const tinfo_t &type,
        ea_t call_ea=BADADDR,
        bool tail_call=false);

  /// Get input argument of the decompiled function.
  /// \param n argument number (0..nargs-1)
  lvar_t &hexapi arg(int n);
  const lvar_t &arg(int n) const { return CONST_CAST(mba_t*)(this)->arg(n); }

  /// Allocate a fictional address.
  /// This function can be used to allocate a new unique address for a new
  /// instruction, if re-using any existing address leads to conflicts.
  /// For example, if the last instruction of the function modifies R0
  /// and falls through to the next function, it will be a tail call:
  ///    LDM R0!, {R4,R7}
  ///    end of the function
  ///    start of another function
  /// In this case R0 generates two different lvars at the same address:
  ///   - one modified by LDM
  ///   - another that represents the return value from the tail call
  ///
  /// Another example: a third-party plugin makes a copy of an instruction.
  /// This may lead to the generation of two variables at the same address.
  /// Example 3: fictional addresses can be used for new instructions created
  /// while modifying the microcode.
  /// This function can be used to allocate a new unique address for a new
  /// instruction or a variable.
  /// The fictional address is selected from an unallocated address range.
  /// \param real_ea real instruction address (BADADDR is ok too)
  /// \return a unique fictional address
  ea_t hexapi alloc_fict_ea(ea_t real_ea);

  /// Resolve a fictional address.
  /// This function provides a reverse of the mapping made by alloc_fict_ea().
  /// \param fict_ea fictional definition address
  /// \return the real instruction address
  ea_t hexapi map_fict_ea(ea_t fict_ea) const;

  /// Get information about various memory regions.
  /// We map the stack frame to the global memory, to some unused range.
  const ivl_t &get_std_region(memreg_index_t idx) const;
  const ivl_t &get_lvars_region() const;
  const ivl_t &get_shadow_region() const;
  const ivl_t &get_args_region() const;
  ivl_t get_stack_region() const; // get entire stack region

  /// Serialize mbl array into a sequence of bytes.
  void hexapi serialize(bytevec_t *vout) const;

  /// Deserialize a byte sequence into mbl array.
  /// \param bytes pointer to the beginning of the byte sequence.
  /// \param nbytes number of bytes in the byte sequence.
  /// \return new mbl array
  WARN_UNUSED_RESULT static mba_t *hexapi deserialize(const uchar *bytes, size_t nbytes);

  /// Create and save microcode snapshot
  void hexapi save_snapshot(const char *description);

  /// Allocate a kernel register.
  /// \param size size of the register in bytes
  /// \param check_size if true, only the sizes that correspond to a size of
  ///                   a basic type will be accepted.
  /// \return allocated register. mr_none means failure.
  mreg_t hexapi alloc_kreg(size_t size, bool check_size=true);

  /// Free a kernel register.
  /// If wrong arguments are passed, this function will generate an internal error.
  /// \param reg a previously allocated kernel register
  /// \param size size of the register in bytes
  void hexapi free_kreg(mreg_t reg, size_t size);

/// \defgroup INLINE_ inline_func() flags
///@{
#define INLINE_EXTFRAME 0x0001 ///< Inlined function has its own (external) frame
#define INLINE_DONTCOPY 0x0002 ///< Do not reuse old inlined copy even if it exists
///@}
  /// Inline a range.
  /// This function may be called only during the initial microcode generation phase.
  /// \param cdg the codegenerator object
  /// \param blknum the block contaning the call/jump instruction to inline
  /// \param ranges the set of ranges to inline. in the case of multiple calls
  ///               to inline_func(), ranges will be compared using their start
  ///               addresses. if two ranges have the same address, they will be
  ///               considered the same.
  /// \param decomp_flags combination of \ref DECOMP_ bits
  /// \param inline_flags combination of \ref INLINE_ bits
  /// \return error code
  merror_t hexapi inline_func(
        codegen_t &cdg,
        int blknum,
        mba_ranges_t &ranges,
        int decomp_flags=0,
        int inline_flags=0);

  // Find a sp change point.
  // returns stkpnt p, where p->ea <= ea
  const stkpnt_t *hexapi locate_stkpnt(ea_t ea) const;

  bool hexapi set_lvar_name(lvar_t &v, const char *name, int flagbits);
  bool set_nice_lvar_name(lvar_t &v, const char *name) { return set_lvar_name(v, name, CVAR_NAME); }
  bool set_user_lvar_name(lvar_t &v, const char *name) { return set_lvar_name(v, name, CVAR_NAME|CVAR_UNAME); }
};
using mbl_array_t = mba_t;
//-------------------------------------------------------------------------

/// Generate microcode of an arbitrary code snippet
/// \param mbr          snippet ranges
/// \param hf           extended error information (if failed)
/// \param retlist      list of registers the snippet returns
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \param reqmat       required microcode maturity
/// \return pointer to  the microcode, nullptr if failed.

mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
        int decomp_flags=0,
        mba_maturity_t reqmat=MMAT_GLBOPT3);


/// Create an empty microcode object
inline mba_t *create_empty_mba(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr)
{
  return gen_microcode(mbr, hf, nullptr, DECOMP_VOID_MBA);
}

//-------------------------------------------------------------------------
/// Convenience class to release graph chains automatically.
/// Use this class instead of using graph_chains_t directly.
class chain_keeper_t
{
  graph_chains_t *gc;
  chain_keeper_t &operator=(const chain_keeper_t &); // not defined
public:
  chain_keeper_t(graph_chains_t *_gc) : gc(_gc) { QASSERT(50446, gc != nullptr); gc->acquire(); }
  ~chain_keeper_t()
  {
    gc->release();
  }
  block_chains_t &operator[](size_t idx) { return (*gc)[idx]; }
  block_chains_t &front() { return gc->front(); }
  block_chains_t &back() { return gc->back(); }
  operator graph_chains_t &() { return *gc; }
  int for_all_chains(chain_visitor_t &cv, int gca) { return gc->for_all_chains(cv, gca); }
  HEXRAYS_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
/// Kind of use-def and def-use chains
enum gctype_t
{
  GC_REGS_AND_STKVARS, ///< registers and stkvars (restricted memory only)
  GC_ASR,              ///< all the above and assertions
  GC_XDSU,             ///< only registers calculated with FULL_XDSU
  GC_END,              ///< number of chain types
  GC_DIRTY_ALL = (1 << (2*GC_END))-1, ///< bitmask to represent all chains
};

//-------------------------------------------------------------------------
/// Control flow graph of microcode.
class mbl_graph_t : public simple_graph_t
{
  mba_t *mba;          ///< pointer to the mbl array
  int dirty = GC_DIRTY_ALL; ///< what kinds of use-def chains are dirty?
  int chain_stamp = 0; ///< we increment this counter each time chains are recalculated
  graph_chains_t gcs[2*GC_END]; ///< cached use-def chains
  bool exclude_never_jumping_edges = true;

  /// Is LIST accessed between two instructions?
  /// This function can analyze all path between the specified instructions
  /// and find if the specified list is used in any of them. The instructions
  /// may be located in different basic blocks. This function does not use
  /// use-def chains but use the graph for analysis. It may be slow in some
  /// cases but its advantage is that is does not require building the use-def
  /// chains.
  /// \param list list to verify
  /// \param b1   starting block
  /// \param b2   ending block. may be -1, it means all possible paths from b1
  /// \param m1   starting instruction (in b1)
  /// \param m2   ending instruction (in b2). excluded. may be nullptr.
  /// \param access_type read or write access?
  /// \param maymust may access or must access?
  /// \return true if found an access to the list
  bool hexapi is_accessed_globally(
        const mlist_t &list,   // list to verify
        int b1,                // starting block
        int b2,                // ending block
        const minsn_t *m1,     // starting instruction (in b1)
        const minsn_t *m2,     // ending instruction (in b2)
        access_type_t access_type,
        maymust_t maymust) const;
  int get_ud_gc_idx(gctype_t gctype) const { return (gctype << 1); }
  int get_du_gc_idx(gctype_t gctype) const { return (gctype << 1)+1; }
  int get_ud_dirty_bit(gctype_t gctype) { return 1 << get_ud_gc_idx(gctype); }
  int get_du_dirty_bit(gctype_t gctype) { return 1 << get_du_gc_idx(gctype); }

public:
  /// Is the use-def chain of the specified kind dirty?
  bool is_ud_chain_dirty(gctype_t gctype)
  {
    int bit = get_ud_dirty_bit(gctype);
    return (dirty & bit) != 0;
  }

  /// Is the def-use chain of the specified kind dirty?
  bool is_du_chain_dirty(gctype_t gctype)
  {
    int bit = get_du_dirty_bit(gctype);
    return (dirty & bit) != 0;
  }
  int get_chain_stamp() const { return chain_stamp; }

  /// Get use-def chains.
  graph_chains_t *hexapi get_ud(gctype_t gctype);

  /// Get def-use chains.
  graph_chains_t *hexapi get_du(gctype_t gctype);

  /// Is LIST redefined in the graph?
  bool is_redefined_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, maymust_t maymust=MAY_ACCESS) const
    { return is_accessed_globally(list, b1, b2, m1, m2, WRITE_ACCESS, maymust); }

  /// Is LIST used in the graph?
  bool is_used_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, maymust_t maymust=MAY_ACCESS) const
    { return is_accessed_globally(list, b1, b2, m1, m2, READ_ACCESS, maymust); }

  mblock_t *get_mblock(int n) const { return mba->get_mblock(n); }
};

//-------------------------------------------------------------------------
// Helper for codegen_t. It takes into account delay slots
struct cdg_insn_iterator_t
{
  const mba_t *mba;       // to check range
  ea_t ea = BADADDR;      // next insn to decode
  ea_t end = BADADDR;     // end of the block
  ea_t dslot = BADADDR;   // address of the insn in the delay slot
  insn_t dslot_insn;      // instruction in the delay slot
  ea_t severed_branch = BADADDR; // address of the severed branch insn
                          // (when this branch insn ends the previous block)
  bool is_likely_dslot = false; // execute delay slot only when jumping

  cdg_insn_iterator_t(const mba_t *mba_) : mba(mba_) {}
  cdg_insn_iterator_t(const cdg_insn_iterator_t &r) = default;
  cdg_insn_iterator_t &operator=(const cdg_insn_iterator_t &r) = default;

  bool ok() const { return ea < end; }
  bool has_dslot() const { return dslot != BADADDR; }
  bool dslot_with_xrefs() const { return dslot >= end; }
  // the current insn is the severed delayed insn (when this starts a block)
  bool is_severed_dslot() const { return severed_branch != BADADDR; }
  void start(const range_t &rng)
  {
    ea = rng.start_ea;
    end = rng.end_ea;
  }
  merror_t hexapi next(insn_t *ins);
};

//-------------------------------------------------------------------------
/// Helper class to generate the initial microcode
class codegen_t
{
public:
  mba_t *mba;             // ptr to mbl array
  mblock_t *mb = nullptr; // current basic block
  insn_t insn;            // instruction to generate microcode for
  char ignore_micro = IM_NONE; // value of get_ignore_micro() for the insn
  cdg_insn_iterator_t ii; // instruction iterator
  size_t reserved[4];

  codegen_t() = delete;
  virtual ~codegen_t()
  {
    clear();
  }
  void hexapi clear(); // does not clear everything yet

  /// Analyze prolog/epilog of the function to decompile.
  /// If prolog is found, allocate and fill 'mba->pi' structure.
  /// \param fc flow chart
  /// \param reachable bitmap of reachable blocks
  /// \return error code
  virtual merror_t idaapi analyze_prolog(
        const class qflow_chart_t &fc,
        const class bitset_t &reachable) = 0;

  /// Generate microcode for one instruction.
  /// The instruction is in INSN
  /// \return MERR_OK     - all ok
  ///         MERR_BLOCK  - all ok, need to switch to new block
  ///         MERR_BADBLK - delete current block and continue
  ///         other error codes are fatal
  virtual merror_t idaapi gen_micro() = 0;

  /// Generate microcode to load one operand.
  /// \param opnum number of INSN operand
  /// \param flags reserved for future use
  /// \return register containing the operand.
  virtual mreg_t idaapi load_operand(int opnum, int flags=0) = 0;

  /// This method is called when the microcode generation is done
  virtual void idaapi microgen_completed() {}

  /// Setup internal data to handle new instruction.
  /// This method should be called before calling gen_micro().
  /// Usually gen_micro() is called by the decompiler. You have to call this
  /// function explicitly only if you yourself call gen_micro().
  /// The instruction is in INSN
  /// \return MERR_OK     - all ok
  ///         other error codes are fatal
  virtual merror_t idaapi prepare_gen_micro() { return MERR_OK; }

  /// Generate microcode to calculate the address of a memory operand.
  /// \param n     - number of INSN operand
  /// \param flags - reserved for future use
  /// \return register containing the operand address.
  ///         mr_none - failed (not a memory operand)
  virtual mreg_t idaapi load_effective_address(int n, int flags=0) = 0;

  /// Generate microcode to store an operand.
  /// In case of success an arbitrary number of instructions can be
  /// generated (and even no instruction if the source and target are the same)
  /// \param n      - number of target INSN operand
  /// \param mop    - operand to be stored
  /// \param flags  - reserved for future use
  /// \param outins - (OUT) the last generated instruction
  //                  (nullptr if no instruction was generated)
  /// \return success
  virtual bool idaapi store_operand(int n, const mop_t &mop, int flags=0, minsn_t **outins=nullptr);

  /// Emit one microinstruction.
  /// The L, R, D arguments usually mean the register number. However, they depend
  /// on CODE. For example:
  ///   - for m_goto and m_jcnd L is the target address
  ///   - for m_ldc L is the constant value to load
  ///
  /// \param code  instruction opcode
  /// \param width operand size in bytes
  /// \param l     left operand
  /// \param r     right operand
  /// \param d     destination operand
  /// \param offsize for ldx/stx, the size of the offset operand
  ///                for ldc, operand number of the constant value
  ///                -1, set the FP instruction (e.g. for m_mov)
  /// \return created microinstruction. can be nullptr if the instruction got
  ///         immediately optimized away.
  minsn_t *hexapi emit(mcode_t code, int width, uval_t l, uval_t r, uval_t d, int offsize);

  /// Emit one microinstruction.
  /// This variant takes a data type not a size.
  minsn_t *idaapi emit_micro_mvm(
        mcode_t code,
        op_dtype_t dtype,
        uval_t l,
        uval_t r,
        uval_t d,
        int offsize)
  {
    return emit(code, get_dtype_size(dtype), l, r, d, offsize);
  }

  /// Emit one microinstruction.
  /// This variant accepts pointers to operands. It is more difficult to use
  /// but permits to create virtually any instruction. Operands may be nullptr
  /// when it makes sense. The ownership of the operands is not transferred
  /// to the decompiler, so it is ok to destroy them after this call.
  minsn_t *hexapi emit(mcode_t code, const mop_t *l, const mop_t *r, const mop_t *d);

};

//-------------------------------------------------------------------------
/// Parse DIRECTIVE and update the current configuration variables.
/// For the syntax see hexrays.cfg
bool hexapi change_hexrays_config(const char *directive);

//-------------------------------------------------------------------------
inline void mop_t::_make_insn(minsn_t *ins)
{
  t = mop_d;
  d = ins;
}

inline bool mop_t::has_side_effects(bool include_ldx_and_divs) const
{
  return is_insn() && d->has_side_effects(include_ldx_and_divs);
}

inline bool mop_t::is_kreg() const
{
  return is_reg() && ::is_kreg(r);
}

inline minsn_t *mop_t::get_insn(mcode_t code)
{
  return is_insn(code) ? d : nullptr;
}
inline const minsn_t *mop_t::get_insn(mcode_t code) const
{
  return is_insn(code) ? d : nullptr;
}

inline bool mop_t::is_insn(mcode_t code) const
{
  return is_insn() && d->opcode == code;
}

inline bool mop_t::is_glbaddr() const
{
  return t == mop_a && a->is_glbvar();
}

inline bool mop_t::is_glbaddr(ea_t ea) const
{
  return is_glbaddr() && a->g == ea;
}

inline bool mop_t::is_stkaddr() const
{
  return t == mop_a && a->is_stkvar();
}

inline vivl_t::vivl_t(const chain_t &ch)
  : voff_t(ch.key().type, ch.is_reg() ? ch.get_reg() : ch.get_stkoff()),
    size(ch.width)
{
}

// The following memory regions exist
//          start                     length
//          ------------------------  ---------
// lvars    spbase                    stacksize
// retaddr  spbase+stacksize          retsize
// shadow   spbase+stacksize+retsize  shadow_args
// args     inargoff                  MAX_FUNC_ARGS*sp_width-shadow_args
// globals  data_segment              sizeof_data_segment
// heap     everything else?

inline const ivl_t &mba_t::get_std_region(memreg_index_t idx) const
{
  return std_ivls[idx].ivl;
}

inline const ivl_t &mba_t::get_lvars_region() const
{
  return get_std_region(MMIDX_LVARS);
}

inline const ivl_t &mba_t::get_shadow_region() const
{
  return get_std_region(MMIDX_SHADOW);
}

inline const ivl_t &mba_t::get_args_region() const
{
  return get_std_region(MMIDX_ARGS);
}

inline ivl_t mba_t::get_stack_region() const
{
  return ivl_t(std_ivls[MMIDX_LVARS].ivl.off, fullsize);
}

//-------------------------------------------------------------------------
/// Get decompiler version.
/// The returned string is of the form <major>.<minor>.<revision>.<build-date>
/// \return pointer to version string. For example: "2.0.0.140605"

const char *hexapi get_hexrays_version();

/// \defgroup OPF_ open_pseudocode flags
/// Used in open_pseudocode
///@{
#define OPF_REUSE        0x00  ///< reuse existing window
#define OPF_NEW_WINDOW   0x01  ///< open new window
#define OPF_REUSE_ACTIVE 0x02  ///< reuse existing window, only if the
                               ///< currently active widget is a pseudocode view
#define OPF_NO_WAIT      0x08  ///< do not display waitbox if decompilation happens
///@}

#define OPF_WINDOW_MGMT_MASK 0x07


/// Open pseudocode window.
/// The specified function is decompiled and the pseudocode window is opened.
/// \param ea function to decompile
/// \param flags: a combination of OPF_ flags
/// \return false if failed

vdui_t *hexapi open_pseudocode(ea_t ea, int flags);


/// Close pseudocode window.
/// \param f pointer to window
/// \return false if failed

bool hexapi close_pseudocode(TWidget *f);


/// Get the vdui_t instance associated to the TWidget
/// \param f pointer to window
/// \return a vdui_t *, or nullptr

vdui_t *hexapi get_widget_vdui(TWidget *f);


/// \defgroup VDRUN_ Batch decompilation bits
///@{
#define VDRUN_NEWFILE 0x00000000  ///< Create a new file or overwrite existing file
#define VDRUN_APPEND  0x00000001  ///< Create a new file or append to existing file
#define VDRUN_ONLYNEW 0x00000002  ///< Fail if output file already exists
#define VDRUN_SILENT  0x00000004  ///< Silent decompilation
#define VDRUN_SENDIDB 0x00000008  ///< Send problematic databases to hex-rays.com
#define VDRUN_MAYSTOP 0x00000010  ///< The user can cancel decompilation
#define VDRUN_CMDLINE 0x00000020  ///< Called from ida's command line
#define VDRUN_STATS   0x00000040  ///< Print statistics into vd_stats.txt
#define VDRUN_LUMINA  0x00000080  ///< Use lumina server
#define VDRUN_PERF    0x00200000  ///< Print performance stats to ida.log
///@}

/// Batch decompilation.
/// Decompile all or the specified functions
/// \return true if no internal error occurred and the user has not cancelled decompilation
/// \param outfile name of the output file
/// \param funcaddrs list of functions to decompile.
///                  If nullptr or empty, then decompile all nonlib functions
/// \param flags \ref VDRUN_

bool hexapi decompile_many(const char *outfile, const eavec_t *funcaddrs, int flags);


/// Send the database to Hex-Rays.
/// This function sends the current database to the Hex-Rays server.
/// The database is sent in the compressed form over an encrypted (SSL) connection.
/// \param err failure description object. Empty hexrays_failure_t object can
///            be used if error information is not available.
/// \param silent if false, a dialog box will be displayed before sending the database.

void hexapi send_database(const hexrays_failure_t &err, bool silent);

/// Result of get_current_operand()
struct gco_info_t
{
  qstring name;         ///< register or stkvar name
  union
  {
    sval_t stkoff;      ///< if stkvar, stack offset
    int regnum;         ///< if register, the register id
  };
  int size;             ///< operand size
  int flags;
#define GCO_STK 0x0000  ///< a stack variable
#define GCO_REG 0x0001  ///< is register? otherwise a stack variable
#define GCO_USE 0x0002  ///< is source operand?
#define GCO_DEF 0x0004  ///< is destination operand?
  bool is_reg() const { return (flags & GCO_REG) != 0; }
  bool is_use() const { return (flags & GCO_USE) != 0; }
  bool is_def() const { return (flags & GCO_DEF) != 0; }

  /// Append operand info to LIST.
  /// This function converts IDA register number or stack offset to
  /// a decompiler list.
  /// \param list list to append to
  /// \param mba microcode object
  bool hexapi append_to_list(mlist_t *list, const mba_t *mba) const;

  /// Convert operand info to VIVL.
  /// The returned VIVL can be used, for example, in a call of
  /// get_valranges().
  vivl_t cvt_to_ivl() const
  {
    vivl_t ret;
    if ( is_reg() )
      ret.set_reg(regnum, size);
    else
      ret.set_stkoff(stkoff, size);
    return ret;
  }
};

/// Get the instruction operand under the cursor.
/// This function determines the operand that is under the cursor in the active
/// disassembly listing. If the operand refers to a register or stack variable,
/// it returns true.
/// \param out[out] output buffer
bool hexapi get_current_operand(gco_info_t *out);

#ifdef __NT__
#pragma warning(pop)
#endif
