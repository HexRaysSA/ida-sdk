/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2012-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      ARC (Argonaut RISC Core) processor module
 *
 *      Based on code contributed by by Felix Domke <tmbinc@gmx.net>
 */

#ifndef _ARC_HPP
#define _ARC_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <typeinf.hpp>
#include <diskio.hpp>
#include "../iohandler.hpp"

#define PROCMOD_NAME            arc
#define PROCMOD_NODE_NAME       "$ arc"

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

enum processor_subtype_t
{
  prc_arc = 0,                  // ARCTangent-A4 (old 32-bit ISA)
  prc_arcompact = 1,            // ARCtangent-A5 and later (32/16-bit mixed)
  prc_arcv2 = 2,                // ARC EM (ARCompact successor)
};

//------------------------------------------------------------------------
enum RegNo
{
  R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
  R8,   R9,   R10,  R11,  R12,  R13,  R14,  R15,
  R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
  R24,  R25,  R26,  R27,  R28,  R29,  R30,  R31,

  R32,  R33,  R34,  R35,  R36,  R37,  R38,  R39,
  R40,  R41,  R42,  R43,  R44,  R45,  R46,  R47,
  R48,  R49,  R50,  R51,  R52,  R53,  R54,  R55,
  R56,  R57,  R58,  R59,  R60,  R61,  R62,  R63,

  CF, ZF, NF, VF,

  // registers used for indexed instructions
  // keep these consecutive
  NEXT_PC,
  LDI_BASE, JLI_BASE, EI_BASE,

  GP_SEG,          // virtual segment register for global pointer value

  rVcs, rVds,      // virtual registers for code and data segments

  // aliases

  GP = R26,        // Global Pointer
  FP = R27,        // Frame Pointer
  SP = R28,        // Stack Pointer
  ILINK1 = R29,    // Level 1 interrupt link register
  ILINK2 = R30,    // Level 2 interrupt link register
  BLINK  = R31,    // Branch link register
  LP_COUNT = R60,  // Loop count register
  PCL = R63,       // 32-bit aligned PC value (ARCompact)

  // optional extension
  MLO  = R57,      // Multiply low 32 bits, read only
  MMID = R58,      // Multiply middle 32 bits, read only
  MHI  = R59,      // Multiply high 32 bits, read only
};

#define SHIMM_F 61 // Short immediate data indicator setting flags
#define LIMM    62 // Long immediate data indicator
#define SHIMM   63 // Short immediate data indicator not setting flags (NB: not used in ARCompact)
#define LIMM5   30 // 5-bit long immediate data indicator (used in ARCv2)

//------------------------------------------------------------------------
const ioport_t *find_port(ea_t address);

#define PROC_MAXOP 4  // max number of operands
CASSERT(PROC_MAXOP <= UA_MAXOP);

//---------------------------------

inline int getreg(const op_t &x)
{
  return x.type == o_reg ? x.reg : -1;
}

inline bool isreg(const op_t &x, int reg)
{
  return getreg(x) == reg;
}

inline bool issp(const op_t &x) { return isreg(x, SP); }

//---------------------------------
// cmd.auxpref bits
// instructions that use condition flags (Bcc, Jcc)
#define aux_f           0x0100  // Flags set field (.f postfix)
#define aux_nmask       0x0060  // Jump/Call nullify instruction mode
#define    aux_nd         0x00  // No Delayed instruction slot (only execute next instruction when not jumping)
#define    aux_d          0x20  // Delayed instruction slot (always execute next instruction)
#define    aux_jd         0x40  // Jump Delayed instruction slot (only execute next instruction when jumping)
#define aux_cmask       0x001F  // condition code mask
// load/store instructions flags (Di.AA.ZZ.X)
#define aux_di          0x0020  // direct to memory (cache bypass) (.di suffix)
#define aux_amask       0x0018  // Address write-back
#define     aux_anone     0x00  // no writeback
#define     aux_a         0x08  // pre-increment (.a or .aw)
#define     aux_ab        0x10  // post-increment (.ab)
#define     aux_as        0x18  // scaled access (.as)
#define aux_zmask       0x0006  // size mask
#define     aux_l          0x0  // long size (no suffix)
#define     aux_w          0x4  // word size (.w suffix)
#define     aux_b          0x2  // byte size (.b suffix)
#define aux_x           0x0001  // Sign extend field (.x suffix)

#define aux_pcload      0x0200  // converted pc-relative to memory load (used when ARC_INLINECONST is set)
#define aux_bhint       0x0400  // non-default static branch prediction hint (.t or .nt suffix)
#define aux_s           0x0800  // 16-bit encoded instruction

// Operand types:
#define o_reglist       o_idpspec0      // register list for enter/leave

#define reglist         specval         // o_reglist: registers to save/restore
#define REGLIST_REGS    0x0F            // number of core registers to save/restore
#define   REGLISTR_MAX  0x0E            // max number of core registers to save/restore
#define REGLIST_FP      0x10            // save/restore stack frame
#define REGLIST_BLINK   0x20            // save/restore blink register
#define REGLIST_PCL     0x40            // jump to blink register after restore (leave only)

// o_phrase
#define secreg          specflag1       // o_phrase: the second register is here: [op.phrase, op.secreg]

// o_displ
#define membase         specflag1       // o_displ: if set, displacement is the base value: [op.addr, op.reg]
                                        // this is important for scaled loads, e.g. ld.as r1, [0x23445, r2]
// o_reg
#define regpair         specflag1       // o_reg: if set, this operand is the second register of a register pair
                                        // the previous operand contains the other register of the pair
// o_mem
#define immdisp         specval         // o_mem: immediate displacement to immediate address.
                                        // addr contains the already displaced address.
                                        // addr - get_scale_factor(insn) * immdisp is the base address for immdisp

//------------------------------------------------------------------
// Condition codes:
enum cond_t
{
  cAL=0, cRA=0,        // Always                                                      1 0x00
  cEQ=1, cZ=1,         // Zero                                                        Z 0x01
  cNE=2, cNZ=2,        // Non-Zero                                                   /Z 0x02
  cPL=3, cP=3,         // Positive                                                   /N 0x03
  cMI=4, cN=4,         // Negative                                                    N 0x04
  cCS=5, cC=5,  cLO=5, // Carry set, lower than (unsigned)                            C 0x05
  cCC=6, cNC=6, cHS=6, // Carry clear, higher or same (unsigned)                     /C 0x06
  cVS=7, cV=7,         // Over-flow set                                               V 0x07
  cVC=8, cNV=8,        // Over-flow clear                                            /V 0x08
  cGT=9,               // Greater than (signed)  (N and V and /Z) or (/N and /V and /Z) 0x09
  cGE=0x0A,            // Greater than or equal to (signed)    (N and V) or (/N and /V) 0x0A
  cLT=0x0B,            // Less than (signed)                   (N and /V) or (/N and V) 0x0B
  cLE=0x0C,            // Less than or equal to (signed)  Z or (N and /V) or (/N and V) 0x0C
  cHI=0x0D,            // Higher than (unsigned)                              /C and /Z 0x0D
  cLS=0x0E,            // Lower than or same (unsigned)                          C or Z 0x0E
  cPNZ=0x0F,           // Positive non-zero                                   /N and /Z 0x0F
  cLAST
};
inline uint8 get_cond(const insn_t &insn)
{
  if ( insn.itype <= ARC_store_instructions )
    return cAL;
  return uint8(insn.auxpref & aux_cmask);
}
inline bool has_cond(const insn_t &insn)
{
  if ( insn.itype <= ARC_store_instructions )
    return false;
  return (insn.auxpref & aux_cmask) != cAL;
}
inline cond_t get_core_cond(const insn_t &insn)
{
  if ( insn.itype <= ARC_store_instructions )
    return cAL;
  uint8 cond = insn.auxpref & aux_cmask;
  if ( cond >= cLAST )
    return cLAST;
  return cond_t(cond);
}
inline bool has_core_cond(const insn_t &insn)
{
  if ( insn.itype <= ARC_store_instructions )
    return false;
  uint8 cond = insn.auxpref & aux_cmask;
  return cond != cAL && cond < cLAST;
}
inline cond_t invert_cond(cond_t cond)
{
  switch ( cond )
  {
    case cNE: return cEQ;
    case cEQ: return cNE;
    case cCC: return cCS;
    case cCS: return cCC;
    case cPL: return cMI;
    case cMI: return cPL;
    case cVC: return cVS;
    case cVS: return cVC;
    case cHI: return cLS;
    case cLS: return cHI;
    case cGE: return cLT;
    case cLT: return cGE;
    case cGT: return cLE;
    case cLE: return cGT;
    default:  return cLAST;
  }
}

// ARC ABI conventions from gdb/arc-tdep.h
#define ARC_ABI_GLOBAL_POINTER                 26
#define ARC_ABI_FRAME_POINTER                  27
#define ARC_ABI_STACK_POINTER                  28

#define ARC_ABI_FIRST_CALLEE_SAVED_REGISTER    13
#define ARC_ABI_LAST_CALLEE_SAVED_REGISTER     26

#define ARC_ABI_FIRST_ARGUMENT_REGISTER         0
#define ARC_ABI_LAST_ARGUMENT_REGISTER          7

#define ARC_ABI_RETURN_REGNUM                   0
#define ARC_ABI_RETURN_LOW_REGNUM               0
#define ARC_ABI_RETURN_HIGH_REGNUM              1

//------------------------------------------------------------------------
// does 'ins' have a delay slot? (next instruction is executed before branch/jump)
inline bool has_dslot(const insn_t &ins)
{
  // EXCEPTION: jl.jd <addr> uses delay slot to
  // hide the long immediate used for the address
  if ( ins.itype == ARC_jl
    && (ins.auxpref & aux_nmask) == aux_jd
    && ins.Op1.type == o_near )
    return false;
  return ins.itype > ARC_store_instructions && (ins.auxpref & aux_nmask) != 0;
}

//------------------------------------------------------------------------
// Scale factor for indexed memory access
inline int get_scale_factor(const insn_t &ins)
{
  switch ( ins.itype )
  {
    case ARC_st:
    case ARC_ld:
      if ( (ins.auxpref & aux_amask) == aux_as )
      {
        if ( (ins.auxpref & aux_zmask) == aux_w )
          return 2;
        if ( (ins.auxpref & aux_zmask) == aux_l )
          return 4;
      }
      break;

    case ARC_bih:
      return 2;

    case ARC_bi:
    case ARC_ldi:
    case ARC_jli:
    case ARC_ei:
      return 4;
  }
  return 1;
}

//------------------------------------------------------------------------
// Should the register be hidden when used as base in o_displ/o_phrase?
//
//  0  output normally
//  1  hide base reg
// -1  hide base reg and output as immediate
inline int is_hidden_base_reg(int reg)
{
  if ( reg >= NEXT_PC && reg <= EI_BASE )
  {
    return reg == JLI_BASE || reg == EI_BASE ? -1 : 1;
  }
  return 0;
}

//------------------------------------------------------------------------
// The sreg that contains the current value for the given register
//
// Returns -1 if there is no such sreg
inline int get_base_sreg(int reg)
{
  if ( reg == GP )
    return GP_SEG;
  else if ( reg >= LDI_BASE && reg <= GP_SEG )
    return reg;
  return -1;
}

//------------------------------------------------------------------------
void idaapi arc_header(outctx_t &ctx);
void idaapi arc_footer(outctx_t &ctx);

int idaapi is_sp_based(const insn_t &insn, const op_t & x);
bool idaapi create_func_frame(func_t * pfn);
int idaapi arc_get_frame_retsize(const func_t * pfn);
bool is_arc_return_insn(const insn_t &insn);
bool arc_is_switch(switch_info_t *si, const insn_t &insn);
inline bool is_arc_simple_branch(uint16 itype)
{
  return itype == ARC_bl
      || itype == ARC_jl
      || itype == ARC_b
      || itype == ARC_j;
}
inline bool is_forbidden_in_arc_dslot(const insn_t &dslot_insn)
{
  // doc: "The Illegal Instruction Sequence type also occurs when any of the
  // following instructions are attempted in an executed delay slot of a
  // jump or branch:
  // * Another jump or branch instruction (Bcc, BLcc, Jcc, JLcc)
  // * Conditional loop instruction (LPcc)
  // * Return from interrupt (RTIE)
  // * Any instruction with long-immediate data as a source operand"
  return is_arc_simple_branch(dslot_insn.itype)
      || dslot_insn.itype == ARC_lp
      || dslot_insn.itype == ARC_rtie
      || dslot_insn.size > 4
      || dslot_insn.itype == ARC_br    // ARCompact instructions
      || dslot_insn.itype == ARC_bbit0
      || dslot_insn.itype == ARC_bbit1;
}

int get_arc_fastcall_regs(const int **regs);
bool calc_arc_arglocs(func_type_data_t *fti);
bool calc_arc_varglocs(
        func_type_data_t *fti,
        regobjs_t *regargs,
        int nfixed);
bool calc_arc_retloc(argloc_t *retloc, const tinfo_t &tif, cm_t cc);
void use_arc_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);

//------------------------------------------------------------------------
struct arc_iohandler_t : public iohandler_t
{
  struct arc_t &pm;
  arc_iohandler_t(arc_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual const char *iocallback(const ioports_t &iop, const char *line) override;
  virtual void get_cfg_filename(char *buf, size_t bufsize) override;
};

DECLARE_PROC_LISTENER(pm_idb_listener_t, struct arc_t);

struct arc_t : public procmod_t
{
  netnode helper;           // altval(-1): idp flags
#define CALLEE_TAG   'A'    // altval(ea): callee address for indirect calls
#define DXREF_TAG    'd'    // altval(ea): resolved address for complex calculation (e.g. ADD R1, PC)
#define DSLOT_TAG    's'    // altval(ea): 1: delay slot of an unconditional jump/branch
                            //             2: delay slot of a conditional jump/branch
                            //             3: delay slot of a jl/bl
  inline void set_callee(ea_t ea, ea_t callee) { helper.easet(ea, callee, CALLEE_TAG); }
  inline ea_t get_callee(ea_t ea) { return helper.eaget(ea, CALLEE_TAG); }
  inline void del_callee(ea_t ea) { helper.eadel(ea, CALLEE_TAG); }

  inline void set_dxref(ea_t ea, ea_t dxref) { helper.easet(ea, dxref, DXREF_TAG); }
  inline ea_t get_dxref(ea_t ea) { return helper.eaget(ea, DXREF_TAG); }
  inline void del_dxref(ea_t ea) { helper.eadel(ea, DXREF_TAG); }

  instruc_t Instructions[ARC_last];

  ioports_t auxregs;
  arc_iohandler_t ioh = arc_iohandler_t(*this, helper);
  pm_idb_listener_t idb_listener = pm_idb_listener_t(*this);

  processor_subtype_t ptype = prc_arc;
  inline bool is_a4() { return ptype == prc_arc; }
  inline bool is_arcv2() { return ptype == prc_arcv2; }

  int arc_respect_info = IORESP_ALL;

  int ref_arcsoh_id = 0;
  int ref_arcsol_id = 0;

#define ARC_SIMPLIFY    0x01
#define ARC_INLINECONST 0x02
#define ARC_TRACKREGS   0x04
  ushort idpflags = ARC_SIMPLIFY | ARC_INLINECONST | ARC_TRACKREGS;

  int g_limm = 0;
  bool got_limm = false;

  std::set<ea_t> renamed;
  int islast = 0;

  // is 'ea' in a delay slot of a branch/jump?
  inline bool is_dslot(ea_t ea, bool including_calls = true)
  {
    nodeidx_t v = helper.altval_ea(ea, DSLOT_TAG);
    if ( including_calls )
      return v != 0;
    else
      return v == 1 || v == 2;
  }

  inline bool is_imm(int regno)
  {
    if ( regno == LIMM )
      return true;
    if ( regno == SHIMM_F || regno == SHIMM )
      return is_a4();
    return false;
  }

  arc_t();
  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();

  bool select_device(int resp_info);
  void add_dxref(const insn_t &insn, ea_t target);
  bool is_good_target(ea_t ea) const;
  int emu(const insn_t &insn);
  bool is_arc_basic_block_end(
        const insn_t &insn,
        bool call_insn_stops_block);
  void del_insn_info(ea_t ea);
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);
  void set_codeseqs() const;
  void set_instruc_names();
  void ptype_changed();
  void doIndirectOperand(const insn_t &insn, int b, int c, op_t &op, int d, int li, bool special);
  void doBranchOperand(const insn_t &insn, op_t &op, int l) const;
  void doRegisterInstruction(insn_t &insn, uint32 code);
  int ana_old(insn_t &insn);
  void opbranch(const insn_t &insn, op_t &x, sval_t delta) const;
  void inline_const(insn_t &insn) const;
  void doBranchInstruction(insn_t &insn, uint32 code) const;
  void decode_operand(
        insn_t &insn,
        uint32 code,
        int &op_pos,
        uint32 opkind);
  int analyze_compact(insn_t &insn, uint32 code, int idx, const struct arcompact_opcode_t *table);
  int ana_compact(insn_t &insn);
  int ana(insn_t *_insn);
  int is_align_insn(ea_t ea) const;
  bool good_target(const insn_t &insn, ea_t target) const;
  bool copy_insn_optype(const insn_t &insn, const op_t &x, ea_t ea, void *value = nullptr, bool force = false) const;
  void handle_operand(const insn_t &insn, const op_t & x, bool loading);
  int get_limm(insn_t &insn);
  inline void opreg(insn_t &insn, op_t &x, int rgnum, int limm=LIMM);
  inline void opdisp(insn_t &insn, op_t &x, int rgnum, ea_t disp);
  void rename_if_not_set(ea_t ea, const char *name);
  bool check_ac_pop_chain(int *regno, ea_t ea);
  bool detect_millicode(qstring *mname, ea_t ea);
  bool is_millicode(ea_t ea, sval_t *spdelta=nullptr);
  sval_t calc_sp_delta(const insn_t &insn);
  void trace_sp(const insn_t &insn);
  bool arc_calc_spdelta(sval_t *spdelta, const insn_t &insn);
  int arc_may_be_func(const insn_t &insn, int state);
  void force_offset(
        ea_t ea,
        int n,
        ea_t base,
        bool issub = false,
        int scale = 1);
  bool spoils(const insn_t &insn, int reg) const;
  int spoils(const insn_t &insn, const uint32 *regs, int n) const;
  bool is_arc_call_insn(const insn_t &insn);
  bool find_op_value_ex(
        const insn_t &insn,
        const op_t &x,
        struct ldr_value_info_t *lvi,
        bool /*check_fbase_reg*/);
  bool find_ldr_value_ex(
        const insn_t &insn,
        ea_t ea,
        int reg,
        struct ldr_value_info_t *lvi,
        bool /*check_fbase_reg*/);
  bool find_op_value(
        const insn_t &insn,
        const op_t &x,
        uval_t *p_val,
        ea_t *p_val_ea=nullptr,
        bool check_fbase_reg=true,
        bool *was_const_load=nullptr);
  bool find_ldr_value(
        const insn_t &insn,
        ea_t ea,
        int reg,
        uval_t *p_val,
        ea_t *p_val_ea=nullptr,
        bool check_fbase_reg=true,
        bool *was_const_load=nullptr);
  int use_arc_regarg_type(ea_t ea, const funcargvec_t &rargs);
  bool arc_set_op_type(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name,
        eavec_t *visited);
  void use_arc_arg_types(ea_t ea, func_type_data_t *fti, funcargvec_t *rargs);

  void arc_segstart(outctx_t &ctx, segment_t *Sarea) const;
};
extern int data_id;

#endif
