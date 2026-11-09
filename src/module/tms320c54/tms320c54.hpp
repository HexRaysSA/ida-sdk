/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _TMS320C54_HPP
#define _TMS320C54_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"
#include <merge.hpp>

// #define TMS320C54_NO_NAME_NO_REF

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  PC,  // program counter
  A,   // accumulator
  B,   // accumulator

  // flags
  ASM, // 5-bit accumulator shift mode field in ST1
  ARP, // auxiliary register pointer
  TS,  // shift value (bits 5-0 of T)
  OVB,
  OVA,
  C,
  TC,
  CMPT,
  FRCT,
  C16,
  SXM,
  OVM,
  INTM,
  HM,
  XF,
  BRAF,

  // CPU memory mapped registers
  IMR,
  IFR,
  ST0,
  ST1,
  AL,
  AH,
  AG,
  BL,
  BH,
  BG,
  T,   // temporary register
  TRN, // transition register
  AR0,
  AR1,
  AR2,
  AR3,
  AR4,
  AR5,
  AR6,
  AR7,
  SP,  // stack pointer
  BK,
  BRC,
  RSA,
  REA,
  PMST,

  // segment registers
  XPC, // program counter extension register
  CPL, // compiler mode
  DP,  // data page pointer
  rVcs, rVds,  // virtual registers for code and data segments
  rnone = 0xFF,   // no register
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
// specific processor records

#define o_bit    o_idpspec0
#define o_cond8  o_idpspec1
#define o_cond2  o_idpspec2
#define o_local  o_idpspec3
#define o_mmr    o_idpspec4
#define o_farmem o_idpspec5

#define Op4_type  auxpref_u8[0]
#define Op4_value auxpref_u8[1]
#define IsParallel segpref

// != 0 => MOD = IndirectAddressingMOD-1
#define IndirectAddressingMOD specflag1
#define ABSOLUTE_INDIRECT_ADRESSING 0xF // special "indirect" adressing
                                        // (in fact absolute adressing)
#define Signed specflag1
#define NoCardinal specflag2
#define IOimm specflag3

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t TMS320C54 = 0;

#define TMS320C54_IO           0x0001  // use I/O definitions
#define TMS320C54_MMR          0x0002  // use memory mapped registers

//------------------------------------------------------------------
const char *const cfgname = "tms320c54.cfg";

struct tms320c54_iohandler_t : public iohandler_t
{
  tms320c54_iohandler_t(netnode &nn) : iohandler_t(nn) {}
  void get_cfg_filename(char *buf, size_t bufsize) override
  {
    qstrncpy(buf, cfgname, bufsize);
  }
};

struct tms320c54_t : public procmod_t
{
  netnode helper;
  tms320c54_iohandler_t ioh = tms320c54_iohandler_t(helper);

  ea_t dataseg;
  ushort idpflags = TMS320C54_IO|TMS320C54_MMR;
  proctype_t ptype = TMS320C54;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *find_sym(ea_t address);
  void apply_symbols(void);
  const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);

  int ana(insn_t *insn);

  int emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, flags64_t F, bool use);
  ea_t calc_data_mem(const insn_t &insn, ea_t ea, bool is_mem) const;
  bool create_func_frame(func_t *pfn) const;
  regnum_t get_mapped_register(ea_t ea) const;

  void assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void segstart(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;
  void gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void save_dataseg()  { helper.altset(0, dataseg); }
  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ tms320c54"
#define PROCMOD_NAME tms320c54

ea_t calc_code_mem(const insn_t &insn, ea_t ea, bool is_near = true);

const char *get_cond8(char value);

//------------------------------------------------------------------
void idaapi header(outctx_t &ctx);

void idaapi segend(outctx_t &ctx, segment_t *seg);

void idaapi data(ea_t ea);

int idaapi tms_get_frame_retsize(const func_t *pfn);
int idaapi is_align_insn(ea_t ea);
bool is_basic_block_end(const insn_t &insn); // 0-no, 2-yes

#endif // _TMS320C54_HPP
