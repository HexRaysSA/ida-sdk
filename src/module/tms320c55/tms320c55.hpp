/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _TMS320C55_HPP
#define _TMS320C55_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

// #define TMS320C55_NO_NAME_NO_REF

//------------------------------------------------------------------
enum regnum_t ENUM_SIZE(uint16)
{
  AC0,    // Accumulator
  AC1,    // Accumulator
  AC2,    // Accumulator
  AC3,    // Accumulator
  T0,     // Temporary register
  T1,     // Temporary register
  T2,     // Temporary register
  T3,     // Temporary register
  AR0,    // Auxiliary register
  AR1,    // Auxiliary register
  AR2,    // Auxiliary register
  AR3,    // Auxiliary register
  AR4,    // Auxiliary register
  AR5,    // Auxiliary register
  AR6,    // Auxiliary register
  AR7,    // Auxiliary register

  AC0L,   // Accumulator
  AC0H,   // Accumulator
  AC0G,   // Accumulator
  AC1L,   // Accumulator
  AC1H,   // Accumulator
  AC1G,   // Accumulator
  AC2L,   // Accumulator
  AC2H,   // Accumulator
  AC2G,   // Accumulator
  AC3L,   // Accumulator
  AC3H,   // Accumulator
  AC3G,   // Accumulator
  BK03,   // Circular buffer size register
  BK47,   // Circular buffer size register
  BKC,    // Circular buffer size register
  BRC0,   // Block-repeat counter
  BRC1,   // Block-repeat counter
  BRS1,   // BRC1 save register
  BSA01,  // Circulat buffer start address register
  BSA23,  // Circulat buffer start address register
  BSA45,  // Circulat buffer start address register
  BSA67,  // Circulat buffer start address register
  BSAC,   // Circulat buffer start address register
  CDP,    // Coefficient data pointer (low part of XCDP)
  CDPH,   // High part of XCDP
  CFCT,   // Control-flow contect register
  CSR,    // Computed single-repeat register
  DBIER0, // Debug interrupt enable register
  DBIER1, // Debug interrupt enable register
  // DP      Data page register (low part of XDP)
  // DPH     High part of XDP
  IER0,   // Interrupt enable register
  IER1,   // Interrupt enable register
  IFR0,   // Interrupt flag register
  IFR1,   // Interrupt flag register
  IVPD,
  IVPH,
  PC,     // Program counter
  // PDP     Peripheral data page register
  PMST,
  REA0,   // Block-repeat end address register
  REA0L,  // Block-repeat end address register
  REA0H,  // Block-repeat end address register
  REA1,   // Block-repeat end address register
  REA1L,  // Block-repeat end address register
  REA1H,  // Block-repeat end address register
  RETA,   // Return address register
  RPTC,   // Single-repeat counter
  RSA0,   // Block-repeat start address register
  RSA0L,  // Block-repeat start address register
  RSA0H,  // Block-repeat start address register
  RSA1,   // Block-repeat start address register
  RSA1L,  // Block-repeat start address register
  RSA1H,  // Block-repeat start address register
  SP,     // Data stack pointer
  SPH,    // High part of XSP and XSSP
  SSP,    // System stack pointer
  ST0,    // Status register
  ST1,    // Status register
  ST0_55, // Status register
  ST1_55, // Status register
  ST2_55, // Status register
  ST3_55, // Status register
  TRN0,   // Transition register
  TRN1,   // Transition register

  XAR0,   // Extended auxiliary register
  XAR1,   // Extended auxiliary register
  XAR2,   // Extended auxiliary register
  XAR3,   // Extended auxiliary register
  XAR4,   // Extended auxiliary register
  XAR5,   // Extended auxiliary register
  XAR6,   // Extended auxiliary register
  XAR7,   // Extended auxiliary register

  XCDP,   // Extended coefficient data pointer
  XDP,    // Extended data page register
  XPC,    // Extended program counter
  XSP,    // Extended data stack pointer
  XSSP,   // Extended system stack pointer

  // these seem to be an old way of what is now DPH/CDPH/AR0H..AR7H
  // i.e. supply bits 22:16 of the address for specific situations)
  MDP,    // Main Data page pointer (direct memory access / indirect from CDP)
  MDP05,  // Main Data page pointer (indirect AR[0-5])
  MDP67,  // Main Data page pointer (indirect AR[6-7])

  // flags
  ACOV2,
  ACOV3,
  TC1,
  TC2,
  CARRY,
  ACOV0,
  ACOV1,
  BRAF,
  XF,
  HM,
  INTM,
  M40,
  SATD,
  SXMD,
  C16,
  FRCT,
  C54CM,
  DBGM,
  EALLOW,
  RDM,
  CDPLC,
  AR7LC,
  AR6LC,
  AR5LC,
  AR4LC,
  AR3LC,
  AR2LC,
  AR1LC,
  AR0LC,
  CAFRZ,
  CAEN,
  CACLR,
  HINT,
  CBERR,
  MPNMC,
  SATA,
  CLKOFF,
  SMUL,
  SST,

  BORROW,

  // segment registers
  ARMS,   // AR indirect operands available
  CPL,    // Compiler mode
  DP,     // Data page pointer
  DPH,    // Data page
  PDP,    // Peripheral data page register
  rVcs, rVds,  // virtual registers for code and data segments
};

//------------------------------------------------------------------
// specific condition codes
#define COND_A 0x0
#define COND_B 0x8

#define COND_GEQ 0x2
#define COND_LT  0x3
#define COND_NEQ 0x4
#define COND_EQ  0x5
#define COND_GT  0x6
#define COND_LEQ 0x7


#define COND4_AGEQ (COND_A | COND_GEQ)
#define COND4_ALT  (COND_A | COND_LT)
#define COND4_ANEQ (COND_A | COND_NEQ)
#define COND4_AEQ  (COND_A | COND_EQ)
#define COND4_AGT  (COND_A | COND_GT)
#define COND4_ALEQ (COND_A | COND_LEQ)

#define COND4_BGEQ (COND_B | COND_GEQ)
#define COND4_BLT  (COND_B | COND_LT)
#define COND4_BNEQ (COND_B | COND_NEQ)
#define COND4_BEQ  (COND_B | COND_EQ)
#define COND4_BGT  (COND_B | COND_GT)
#define COND4_BLEQ (COND_B | COND_LEQ)


#define COND8_FROM_COND4 0x40

#define COND8_UNC  0x00
#define COND8_NBIO 0x02
#define COND8_BIO  0x03
#define COND8_NC   0x08
#define COND8_C    0x0C
#define COND8_NTC  0x20
#define COND8_TC   0x30
#define COND8_AGEQ (COND8_FROM_COND4 | COND4_AGEQ)
#define COND8_ALT  (COND8_FROM_COND4 | COND4_ALT)
#define COND8_ANEQ (COND8_FROM_COND4 | COND4_ANEQ)
#define COND8_AEQ  (COND8_FROM_COND4 | COND4_AEQ)
#define COND8_AGT  (COND8_FROM_COND4 | COND4_AGT)
#define COND8_ALEQ (COND8_FROM_COND4 | COND4_ALEQ)
#define COND8_ANOV 0x60
#define COND8_AOV  0x70
#define COND8_BGEQ (COND8_FROM_COND4 | COND4_BGEQ)
#define COND8_BLT  (COND8_FROM_COND4 | COND4_BLT)
#define COND8_BNEQ (COND8_FROM_COND4 | COND4_BNEQ)
#define COND8_BEQ  (COND8_FROM_COND4 | COND4_BEQ)
#define COND8_BGT  (COND8_FROM_COND4 | COND4_BGT)
#define COND8_BLEQ (COND8_FROM_COND4 | COND4_BLEQ)
#define COND8_BNOV (COND_B | COND8_ANOV)
#define COND8_BOV  (COND_B | COND8_AOV)

//------------------------------------------------------------------
#define Parallel segpref // number of operands for the first line of a parallel instruction
 #define TMS_PARALLEL_BIT -1
#define SpecialModes auxpref_u8[0]
 #define TMS_MODE_USER_PARALLEL          0x1 // user parallel bit (E) is set
 #define TMS_MODE_LR                     0x2 // LR postfix
 #define TMS_MODE_CR                     0x4 // CR postfix
 #define TMS_MODE_SIMULATE_USER_PARALLEL 0x8 // the instruction simulate two instructions linked by a user parallelism
#define OpMem auxpref_u8[1]

// complex operands

// for o_reg, o_imm, o_mem
#define tms_shift specval_shorts.low // operand << value
 #define TMS_OP_SHIFT_NULL  0 // no shift
 #define TMS_OP_SHIFT_TYPE 0x7FFF
  #define TMS_OP_SHIFTL_IMM  1 // operand << #...
  #define TMS_OP_SHIFTL_REG  2 // operand << reg
  #define TMS_OP_SHIFTR_IMM  3 // operand >> #...
  #define TMS_OP_EQ          4 // operand == #...
  #define TMS_OP_NEQ         5 // operand != #...
 #define TMS_OP_SHIFT_OUT  0x8000 // functions(...) << ... (default = functions(... << ...))

#define tms_shift_value specval_shorts.high

// for o_reg, o_mem
#define tms_modifier specflag2
 #define TMS_MODIFIER_NULL              0
 // o_reg
 #define TMS_MODIFIER_REG               1 // *reg
 #define TMS_MODIFIER_REG_P             2 // *reg+
 #define TMS_MODIFIER_REG_M             3 // *reg-
 #define TMS_MODIFIER_REG_P_T0          4 // *(reg+T0)
 #define TMS_MODIFIER_REG_P_T1          5 // *(reg+T1)
 #define TMS_MODIFIER_REG_M_T0          6 // *(reg-T0)
 #define TMS_MODIFIER_REG_M_T1          7 // *(reg-T1)
 #define TMS_MODIFIER_REG_T0            8 // *reg(T0)
 #define TMS_MODIFIER_REG_OFFSET        9 // *reg(#value)
 #define TMS_MODIFIER_P_REG_OFFSET     10 // *+reg(#value)
 #define TMS_MODIFIER_REG_SHORT_OFFSET 11 // *reg(short(#value))
 #define TMS_MODIFIER_REG_T1           12 // *reg(T1)
 #define TMS_MODIFIER_P_REG            13 // *+reg
 #define TMS_MODIFIER_M_REG            14 // *-reg
 #define TMS_MODIFIER_REG_P_T0B        15 // *(reg+T0B)
 #define TMS_MODIFIER_REG_M_T0B        16 // *(reg-T0B)
 // o_mem, o_io
 #define TMS_MODIFIER_DMA               1 // @addr
 #define TMS_MODIFIER_ABS16             2 // *abs16(#addr)
 #define TMS_MODIFIER_PTR               3 // *(#addr)
 #define TMS_MODIFIER_MMAP              4 // mmap()
 #define TMS_MODIFIER_PORT              5 // port(#addr)
 #define TMS_MODIFIER_PORT_AT           6 // port(@addr)

// for o_reg, o_mem, o_io
#define tms_operator1 specflag3 // operators sorted by priority order
#define tms_operator2 specflag4
 #define TMS_OPERATORS_SIZE 13
 #define TMS_OPERATOR_NULL 0x0000
 #define TMS_OPERATOR_T3   0x0001 // T3=xxx
 #define TMS_OPERATOR_NOT  0x0002 // !xxx
 #define TMS_OPERATOR_UNS  0x0004 // uns(xxx)
 #define TMS_OPERATOR_DBL  0x0008 // dbl(xxx)
 #define TMS_OPERATOR_RND  0x0010 // rnd(xxx)
 #define TMS_OPERATOR_PAIR 0x0020 // pair(xxx)
 #define TMS_OPERATOR_LO   0x0040 // lo(xxx)
 #define TMS_OPERATOR_HI   0x0080 // hi(xxx)
 #define TMS_OPERATOR_LB   0x0100 // low_byte(xxx)
 #define TMS_OPERATOR_HB   0x0200 // high_byte(xxx)
 #define TMS_OPERATOR_SAT  0x0400 // saturate(xxx)
 #define TMS_OPERATOR_DUAL 0x0800 // dual(xxx)
 #define TMS_OPERATOR_PORT 0x1000 // port(xxx)

// for o_imm
#define tms_signed specflag1
#define tms_prefix specflag2

// for o_mem (real address = tms_reg_h : tms_reg_p + addr)
#define tms_regH value_shorts.low
#define tms_regP value_shorts.high

#define o_cond o_idpspec0
#define o_shift o_idpspec1
#define o_relop o_idpspec2
 #define tms_relop specflag1 // relational operator
 #define tms_relop_type specflag2 // o_reg, o_imm
  #define TMS_RELOP_REG 1 // operand << #...
  #define TMS_RELOP_IMM 2 // operand << reg
 // value will contain register or immediate
#define o_io o_idpspec3

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t TMS320C55 = 0;

//------------------------------------------------------------------
#define TAG_SDUAL   '2'     // helper.altval(ea, '2') == length of the first part of sdual instruction

#define TMS320C55_IO           0x0001  // use I/O definitions
#define TMS320C55_MMR          0x0002  // use memory mapped registers

//------------------------------------------------------------------
const char *const cfgname = "tms320c55.cfg";

struct tms320c55_iohandler_t : public iohandler_t
{
  struct tms320c55_t &pm;
  qstring errbuf;

  tms320c55_iohandler_t(tms320c55_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  void get_cfg_filename(char *buf, size_t bufsize) override
  {
    qstrncpy(buf, cfgname, bufsize);
  }
};

struct mask_t;
class bytes_c;
struct tms320c55_t : public procmod_t
{
  netnode helper;
  tms320c55_iohandler_t ioh = tms320c55_iohandler_t(*this, helper);
  ushort idpflags = TMS320C55_IO|TMS320C55_MMR;
  proctype_t ptype = TMS320C55;    // contains processor type
  bool flow = false;
  char optional_op = -1; // ana: index of an optional operand

  ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  const char *find_sym(ea_t address);
  const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);

  int ana(insn_t *insn);
  void process_masks(
        insn_t &insn,
        const mask_t *masks,
        ushort itype_null,
        bytes_c &bytes,
        char lbytesize = 8);
  bool process_masks_operand(
        insn_t &insn,
        const mask_t *mask,
        int64 code,
        int64 op_mask_n,
        unsigned *p_opnum,
        bool bTest);

  int emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &op, flags64_t F, bool use);
  int get_mapped_register(ea_t ea) const;

  void assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void segstart(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;
  void gen_stkvar_def(outctx_t &ctx, const udm_t *mptr, sval_t v) const;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ tms320c54"
#define PROCMOD_NAME tms320c55


const char *find_sym(ea_t address);
//------------------------------------------------------------------
void idaapi header(outctx_t &ctx);

void idaapi segend(outctx_t &ctx, segment_t *seg);

void idaapi data(outctx_t &ctx);

bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_align_insn(ea_t ea);
bool idaapi can_have_type(const op_t &op);

ea_t calc_io_mem(const insn_t &insn, const op_t &op);
ea_t calc_data_mem(const insn_t &insn, const op_t &op);
inline ea_t calc_code_mem(const insn_t &insn, ea_t ea)
{
  return to_ea(insn.cs, ea);
}

#endif // _TMS320C55_HPP
