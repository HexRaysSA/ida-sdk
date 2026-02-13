#ifndef __NECV850_INC__
#define __NECV850_INC__

#include "../idaidp.hpp"
#include <list>
#include <pro.h>
#include <fpro.h>
#include <idd.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <idp.hpp>
#include <fixup.hpp>
#include <regfinder.hpp>
#include <segregs.hpp>
#include <ieee.h>
#include <typeinf.hpp>
#include "ins.hpp"
#include "../spcfuncs.hpp"

#define PROCMOD_NAME            nec850
#define PROCMOD_NODE_NAME       "$ prog pointers"

constexpr int PROC_MAXOP = 4; // max number of operands
CASSERT(PROC_MAXOP <= UA_MAXOP);


 #ifndef SIGN_EXTEND
   #define SIGN_EXTEND(type, var, nbits) \
     if ( var & (1 << (nbits-1)) ) \
       var |= ~type((1 << nbits)-1)
 #endif


//----------------------------------------------------------------------
// Specific flags

//
// Used in op_t.specflag1
#define N850F_USEBRACKETS       0x01  // o_reg: use [reg] for the operand
                                      //        (JMP, DISPOSE, JARL)
#define N850F_OUTSIGNED         0x02  // output as signed value
#define N850F_VAL32             0x04  // value/addr is wider than 16-bit
#define N850F_POST_INCREMENT    0x08  // [reg]+
#define N850F_POST_DECREMENT    0x10  // [reg]-
#define N850F_MODULO_ADRESSING  0x20  // [reg]%
#define N850F_BIT_REV_ADRESSING 0x40  // [reg]!

#define o_reglist               o_idpspec1      // Register list (for DISPOSE)
                                                // reglist_t is in .value
//
// Used in insn.auxpref
#define N850F_SP                 0x00000001 // instruction modifies the stack pointer
#define N850F_FP                 0x00000010 // instruction works with floating-point data

#define o_cond                 o_idpspec2      // Condition code as operand (for CMOV/CMPF)
                                               // condition stored in 'value' field

#define o_regrange             o_idpspec3      // Register range (rl-rh, for PUSHSP/POPSP)
#define regrange_low           specval_shorts.low   // low register (rl)
#define regrange_high          specval_shorts.high  // high  register (rh)

//----------------------------------------------------------------------
// Registers def
enum NEC850_regnum_t
{
  rZERO, rR1,   rR2,
  rSP /* r3 */, rGP /* r4 */, rTP /* r5 */,
  rR6,   rR7,   rR8,
  rR9,   rR10,  rR11,  rR12,
  rR13,  rR14,  rR15,  rR16,
  rR17,  rR18,  rR19,  rR20,
  rR21,  rR22,  rR23,  rR24,
  rR25,  rR26,  rR27,  rR28,
  rR29,  rEP,   rR31,
  rLP = rR31,

  // system registers start here
  rSR0,
  rEIP=rSR0, rEIPSW, rFEPC, rFEPSW,
  rECR,   rPSW,    rSR6,   rSR7,
  rSR8,   rSR9,    rSR10,  rSR11,
  rSR12,  rSR13,   rSR14,  rSR15,
  rCTPC,  rCTPSW,  rSR18,  rSR19,
  rCTBP,  rSR21,   rSR22,  rSR23,
  rSR24,  rSR25,   rSR26,  rSR27,
  rSR28,  rSR29,   rSR30,  rSR31,

  // fixed point vector registers
  rVR0, rVR1, rVR2, rVR3, rVR4,
  rVR5, rVR6, rVR7, rVR8, rVR9,
  rVR10, rVR11, rVR12, rVR13, rVR14,
  rVR15, rVR16, rVR17, rVR18, rVR19,
  rVR20, rVR21, rVR22, rVR23, rVR24,
  rVR25, rVR26, rVR27, rVR28, rVR29,
  rVR30, rVR31,

  // floating point vector registers
  rWR0, rWR1, rWR2, rWR3, rWR4,
  rWR5, rWR6, rWR7, rWR8, rWR9,
  rWR10, rWR11, rWR12, rWR13, rWR14,
  rWR15, rWR16, rWR17, rWR18, rWR19,
  rWR20, rWR21, rWR22, rWR23, rWR24,
  rWR25, rWR26, rWR27, rWR28, rWR29,
  rWR30, rWR31,

  // E1F FPU registers
  EFG, ECT,

  // segment registers
  rVcs, rVds,
  srGP,
  srTP,
  srCTBP,
  srEP,

  rLastRegister
};
inline bool is_gpr(int reg)   { return reg >= rZERO && reg <= rR31; }
inline bool is_sysr(int reg)  { return reg >= rSR0 && reg <= rSR31; }
inline bool is_fixvr(int reg) { return reg >= rVR0 && reg <= rVR31; }
inline bool is_fpvr(int reg)  { return reg >= rWR0 && reg <= rWR31; }

enum NEC850_CCode // for CMOV
{
  CC_V,   // 0000: Overflow (OV=1)
  CC_CL,  // 0001: Carry (CY=1)
  CC_Z,   // 0010: Zero (Z=1)
  CC_NH,  // 0011: Not higher (Less than or equal) ((CY or Z) = 1)
  CC_SN,  // 0100: Negative) S=1
  CC_T,   // 0101: Always (true)
  CC_LT,  // 0110: Less than signed (S xor OV) = 1
  CC_LE,  // 0111: Less than or equal signed (((S xor OV) or Z) = 1)
  CC_NV,  // 1000: no overflow (OV=0)
  CC_NCNL,// 1001: no carry (CY=0)
  CC_NZ,  // 1010: not zero (Z=0)
  CC_H,   // 0011: Higher (Greater than) ((CY or Z) = 0)
  CC_NSP, // 0100: Positive (S=0)
  CC_SAT, // 1101: Saturated (SAT=1)
  CC_GE,  // 1110: Greater than or equal signed (S xor OV) = 0
  CC_GT,  // 1111: Greater than signed (((S xor OV) or Z) = 0)
};

enum proctype_t
{
  V850,   // including V850
  V850E,  //
  V850ES, // including V850E1
  V850E2M,// including V850E2
  RH850,  //
};
//----------------------------------------------------------------------
// Prototypes

// prototypes -- out.cpp
void idaapi nec850_header(outctx_t &ctx);
void idaapi nec850_segstart(outctx_t &ctx, segment_t *seg);
void idaapi nec850_segend(outctx_t &ctx, segment_t *seg);

// prototypes -- ana.cpp
int  detect_inst_len(uint16 w);
int  fetch_instruction(uint32 *w);

// prototypes -- emu.cpp
int  nec850_is_sp_based(const insn_t &insn, const op_t &x);
int get_imm_outf(const insn_t &insn, const op_t &x);
int get_displ_outf(const insn_t &insn, const op_t &x, flags64_t F);
bool is_branch_insn(const insn_t &insn);
size_t v850_is_align_insn(ea_t ea);

// prototypes -- switch.cpp
bool nec850_is_switch(const insn_t &insn);

extern const char *const RegNames[];

typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

//-------------------------------------------------------------------------
// does an instruction have the ability to be a call?
// is the instruction an indirect call or jump?
inline bool is_call_or_jump(uint16 itype)
{
  return itype == NEC850_JMP
      || itype == NEC850_JARL
      || itype == NEC850_CALLT;
}

//----------------------------------------------------------------------
inline bool is_ret_itype(const insn_t &insn)
{
  return insn.itype == NEC850_RETI
      || insn.itype == NEC850_DBRET
      || insn.itype == NEC850_EIRET
      || insn.itype == NEC850_FERET
      || insn.itype == NEC850_CTRET
      || insn.itype == NEC850_DISPOSE_r && insn.Op3.is_reg(rLP)
      || insn.itype == NEC850_JMP && insn.Op1.is_reg(rLP);
}

//-------------------------------------------------------------------------
// the list of registers
struct reglist_t : public reglist_base_t<reglist_t>
{
  constexpr reglist_t() {}
  template<typename... Args>
  constexpr reglist_t(Args... args) { add(args...); }
  reglist_t(const op_t &x) { add_reglist(x); }
  void add_reglist(const op_t &x)
  {
    QASSERT(10522, x.type == o_reglist && (x.value & ~0xFFFFFFFF) == 0);
    regs |= x.value;
  }
  static reglist_t make_list12(uint32 opcode);

  void invert_gprs() { regs ^= 0xFFFFFFFF; }

protected:
  friend reglist_base_t<reglist_t>;
  // low bits 0..31 - GPRs
  uint64 encode(int regnum) const
  {
    return is_gpr(regnum) ? 1ull << (regnum - rZERO) : 0ull;
  }
  int decode(int bitnum) const
  {
    return bitnum <= 31 ? rZERO + bitnum : -1;
  }
};

//-------------------------------------------------------------------------
// for PREPARE/DISPOSE
int calc_stack_delta(const insn_t &insn);

//-------------------------------------------------------------------------
constexpr uint16 IDP_MACRO_HIDDEN_R1 = 0x0001; // allow modification of rR1 in macros
constexpr uint16 IDP_GP_CALLEE_SAVED = 0x0002; // the GP register is callee-saved
constexpr uint16 IDP_TP_CALLEE_SAVED = 0x0004; // the TP register is callee-saved
constexpr uint16 IDP_EP_CALLEE_SAVED = 0x0008; // the EP register is callee-saved
constexpr uint16 IDP_R2_CALLEE_SAVED = 0x0010; // the R2 register is callee-saved

//-------------------------------------------------------------------------
enum nec850_abi_t ENUM_SIZE(uint32)
{
  // the core differences (from https://gcc.gnu.org/onlinedocs/gcc/V850-Options.html)
  // the RH850 version of the V850 ABI:
  // - Integer sized structures and unions are returned via a memory pointer rather than a register.
  // - Large structures and unions (more than 8 bytes in size) are passed by value.
  // the old GCC version of the V850 ABI:
  // - Integer sized structures and unions are returned in register r10.
  // - Large structures and unions (more than 8 bytes in size) are passed by reference.
  ABI_RH850,  // as described in CC-RH Compiler User's Manual
  ABI_OLDGCC, // as described in https://www.filibeto.org/unix/tru64/lib/ossc/doc/cygnus_doc-99r1/html/6_embed/embV850.html
  ABI_LAST,
};

//-------------------------------------------------------------------------
struct pushreg_t
{
  ea_t ea;              // instruction ea
  sval_t off;           // negative offset from the frame top (sp delta)
  uval_t width;         // register width
  NEC850_regnum_t reg;  // register number
  DECLARE_COMPARISONS(pushreg_t);
};
typedef qvector<pushreg_t> pushregs_t;

//-------------------------------------------------------------------------
struct nec850_t;
// registers saved (pushed) in function prolog
struct pushinfo_t : public pushregs_t
{
  enum { PUSHINFO_VERSION = 1 };

  uint32 flags = 0; // for the future use

  DECLARE_COMPARISONS(pushinfo_t);
  void serialize(bytevec_t *packed, ea_t entry_ea) const;
  bool deserialize(memory_deserializer_t *mmdsr, ea_t entry_ea);

  void save_to_idb(nec850_t &pm, ea_t ea) const;
  bool restore_from_idb(nec850_t &pm, ea_t ea);
};
//-------------------------------------------------------------------------
DECLARE_PROC_LISTENER(pm_idb_listener_t, nec850_t);

//-------------------------------------------------------------------------
struct nec850_reg_finder_t;
nec850_reg_finder_t *alloc_reg_finder(const nec850_t &pm);
void free_reg_finder(nec850_reg_finder_t *rf);

//-------------------------------------------------------------------------
struct nec850_t : public procmod_t
{
  netnode helper;
  static constexpr nodeidx_t CTBP_EA_IDX = 2;
  static constexpr nodeidx_t GP_EA_IDX   = 1;
  static constexpr nodeidx_t TP_EA_IDX   = 3;
  static constexpr nodeidx_t EP_EA_IDX   = 4;
  static constexpr uchar PUSHINFO_TAG = 's';
  static constexpr size_t V850_MODULE_VERSION = 1;
  // eaget_idx(CTBP_EA_IDX) : the CALLT base pointer
  // eaget_idx(GP_EA_IDX)   : the global pointer
  // eaget_idx(TP_EA_IDX)   : the text pointer
  // eaget_idx(EP_EA_IDX)   : the element pointer
  // blob(ea, PUSHINFO_TAG) : packed pushinf_t
  // altval(-1)             : idpflags
  // altval(-2)             : the module version

  pm_idb_listener_t idb_listener = pm_idb_listener_t(*this);
  ea_t g_ctbp_ea = BADADDR; // the CALLT base pointer
  ea_t g_gp_ea = BADADDR;   // the global pointer
  ea_t g_tp_ea = BADADDR;   // the text pointer
  ea_t g_ep_ea = BADADDR;   // the element pointer
  uint16 idpflags = IDP_MACRO_HIDDEN_R1;
  bool macro_hidden_r1() const
  {
    return (idpflags & IDP_MACRO_HIDDEN_R1) != 0;
  }
  bool is_gp_callee_saved() const
  {
    return g_gp_ea != BADADDR || (idpflags & IDP_GP_CALLEE_SAVED) != 0;
  }
  bool is_tp_callee_saved() const
  {
    return g_tp_ea != BADADDR || (idpflags & IDP_TP_CALLEE_SAVED) != 0;
  }
  bool is_ep_callee_saved() const
  {
    return g_ep_ea != BADADDR || (idpflags & IDP_EP_CALLEE_SAVED) != 0;
  }
  bool is_r2_callee_saved() const
  {
    return (idpflags & IDP_R2_CALLEE_SAVED) != 0;
  }

  int ptype = 0;

  nec850_reg_finder_t *reg_finder = nullptr;

  fixup_handler_t cfh_ha16;
  fixup_type_t cfh_ha16_id = -1;
  int ref_ha16_id = -1;
  void init_custom_refs();
  void term_custom_refs();

  nec850_abi_t abi = ABI_LAST;
  // 'double' and 'long long' to be aligned to 8-byte boundaries
  bool abi_align8 = false;
  void nec850_set_abi(bool init_inf_bits);

  bool inline idaapi is_v850e() const   { return ptype >= (int)V850E; }
  bool inline idaapi is_v850es() const  { return ptype >= (int)V850ES; }
  bool inline idaapi is_v850e1() const  { return is_v850es(); }
  bool inline idaapi is_v850e1f() const { return is_v850e1(); }
  bool inline idaapi is_v850e2m() const { return ptype >= (int)V850E2M; }
  bool inline idaapi is_v850e2() const  { return is_v850e2m(); }
  bool inline idaapi is_rh850() const   { return ptype >= (int)RH850; }

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  // to implement nec850_module_t::ev_get_*p_register
  ssize_t get_global_register(
        ea_t reg_value,
        uint32 callee_saved_flag) const;
  // to implement nec850_module_t::ev_set_*p_register
  void set_global_register(
        ea_t *reg_value,
        uint32 callee_saved_flag,
        int srnum,
        va_list va);
  void update_global_register(
        ea_t *reg_value,
        ea_t new_value,
        uint32 callee_saved_flag,
        int srnum);

  bool decode_instruction(const uint32 w, insn_t *ins);
  bool decode_ext_simd(const uint32 lower_w, insn_t *ins);
  bool decode_coprocessor(const uint32 w, insn_t *ins) const;
  int nec850_ana(insn_t *pinsn);

  // what registers are spoiled by the instruction?
  void spoils(reglist_t *regs, const insn_t &insn) const;
  // does the instruction spoil REG?
  inline bool spoils(const insn_t &insn, int reg) const
  {
    reglist_t regs;
    spoils(&regs, insn);
    return regs.has(reg);
  }
  bool is_call_insn(const insn_t &insn) const;
  // registers that should be preserved by a call
  reglist_t callee_saved_regs() const;
  // what registers are used by the instruction?
  void uses(reglist_t *regs, const insn_t &insn) const;

  struct def_insn_t // info about the defining insn
  {
    ea_t ea;
    uint16 itype;
    def_insn_t() : ea(BADADDR), itype(0) {}
    def_insn_t(const reg_value_def_t &val)
      : ea(val.def_ea), itype(val.def_itype) {}
    // set offset for defining insns (including HIGH1/LOWW)
    bool apply_offset(const nec850_t &pm, ea_t target) const;
  };
  bool find_reg_definition(
        ea_t *val,
        ea_t ea,
        int reg,
        def_insn_t *def_insn = nullptr,
        bool only_linear = false) const;

  ea_t get_base(ea_t ea, int reg, reg_value_info_t *rvi = nullptr) const;
  ea_t get_fixed_sreg(ea_t ea, int reg) const;
  ea_t get_callt_ea(const insn_t &insn) const;
  bool handle_call_or_jump(const insn_t &insn) const;
  void handle_operand(const insn_t &insn, const op_t &op, bool isRead) const;
  bool handle_immop_for_addi(const insn_t &insn, const op_t &op) const;
  bool handle_displ(const insn_t &insn, const op_t &op) const;
  int nec850_emu(const insn_t &insn) const;
  bool is_sane_insn(const insn_t &insn, int no_crefs) const;
  sval_t regval(
        const op_t &op,
        getreg_t *getreg,
        const regval_t *rv) const;
  void trace_sp(func_t *pfn, const insn_t &insn) const;
  int calc_stack_delta(const insn_t &insn) const;

  int  may_be_func(const insn_t &insn) const;
  bool is_return_insn(const insn_t &insn, bool strict) const;

  // emu_frame.cpp
  bool create_func_frame(func_t *pfn, bool reanalyze=false);

  // ana.cpp
  bool build_macro(insn_t *insn, bool may_go_forward) const;
  bool ld_st_case(insn_t *insn, insn_t *insn2) const;
  bool mov_case(insn_t *insn, insn_t *insn2) const;
  bool cmd_case(insn_t *insn, insn_t *insn2) const;
  bool is_reg_used_after_insn(
        const insn_t &start,
        int reg,
        int def_reg = -1) const;

  // tinfo.cpp
  void use_nec850_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);
  bool set_op_type(
        insn_t *insn,
        eavec_t *visited, // for recursive calls
        const op_t &x,
        const tinfo_t &type,
        const char *name);
  int use_nec850_regarg_type(ea_t ea, const funcargvec_t &rargs);
  bool calc_nec850_arglocs(func_type_data_t *fti, int nfixed);
  bool calc_nec850_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc);
  void nec850_lower_func_arg_types(
        intvec_t *argnums,
        const func_type_data_t &fti);
  bool get_nec850_cc_regs(callregs_t *callregs, callcnv_t cc);

  // regfinder.cpp
  bool find_regval(uval_t *value, ea_t ea, int reg) const;
  bool find_sp_value(sval_t *spval, ea_t ea, int reg = rSP) const;
  bool find_rvi(
        reg_value_info_t *rvi,
        ea_t ea,
        int reg,
        int max_depth = 0,
        size_t linear_insns = 0) const;

  // spcfuncs.cpp
  // is INSN is a call of a save/return function?
  // \param[out] regs    the list of saved/restored registers,
  //                     REGS may be nullptr
  // \param[out] locals  the size of local variables (in bytes),
  //                     LOCALS may be nullptr
  // \param[in]  insn    the instruction to check
  // \return     SPF_NONE or the special function kind
  special_func_t is_special_func_call(
        reglist_t *regs,
        uval_t *locals,
        const insn_t &insn) const;
  // what registers does a call of a save/return function spoil?
  // \param[out] regs    the list of spoiled registers
  // \return     is INSN a special_func_t function call?
  bool special_func_spoils(reglist_t *regs, const insn_t &insn) const;
  bool is_special_save_func(const insn_t &insn) const;
  bool is_special_save_alloc_func(const insn_t &insn) const;
  bool is_special_save_r29_func(const insn_t &insn) const;
  bool is_special_return_func(const insn_t &insn) const;
  // create the call table at EA
  void check_call_table(ea_t ea) const;

  // debugger functions
  ea_t nec850_next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues) const;
  ea_t nec850_calc_step_over(ea_t ip) const;
  bool nec850_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues);
  bool nec850_get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname);
  int nec850_get_reg_index(const char *name) const; // static

  void nec850_footer(outctx_t &ctx) const;

  void save_all_options();
  void load_from_idb();
};
extern int data_id;

#endif
