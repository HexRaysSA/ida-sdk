/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _F2MC_HPP
#define _F2MC_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

//------------------------------------------------------------------
enum regnum_t
{
  A,         // accumulator
  AL,        // accumulator
  AH,        // accumulator
  PC,        // program counter
  SP,        // stack pointer
  R0,
  R1,
  R2,
  R3,
  R4,
  R5,
  R6,
  R7,
  RW0,
  RW1,
  RW2,
  RW3,
  RW4,
  RW5,
  RW6,
  RW7,
  RL0,
  RL1,
  RL2,
  RL3,

  PCB,        // program bank register
  DTB,        // data bank register
  ADB,        // additional data bank register
  SSB,        // system stack bank register
  USB,        // user stack bank register
  CCR,        // condition code register
  DPR,        // direct page register
  rVcs, rVds, // virtual registers for code and data segments

  SPB,       // stack pointer bank register
  PS,        // processor status
  ILM,       // interrupt level mask register
  RP         // register bank pointer
};

//------------------------------------------------------------------
// specific processor records

#define default_bank segpref
#define prefix_bank auxpref_u8[1]
#define op_bank auxpref_u8[0]
// o_phrase = @reg+(f2mc_index) (f2mc_index if PHRASE_INDEX)
 #define at_qty specflag1 // number of @ indirections (dtype @ = op.dtype)
 #define special_mode specflag2
  #define MODE_INC 1
  #define MODE_INDEX 2
 #define f2mc_index specval_shorts.high
#define o_reglist o_idpspec0
// o_disp = @reg+value
#define addr_dtyp specflag3
 #define MODE_BIT 1
  #define byte_bit specflag4

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t F2MC16L  = 0;
const proctype_t F2MC16LX = 1;

extern ea_t dataseg;
//------------------------------------------------------------------
#define F2MC_MACRO  0x0001  // use instruction macros
inline ea_t calc_code_mem(const insn_t &insn, ea_t ea) { return to_ea(insn.cs, ea); }
inline ea_t calc_data_mem(ea_t ea) { return (get_sreg(ea, DTB) << 16) | ea; }

int get_signed(int byte, int mask);

ea_t map_port(ea_t from);
int calc_outf(const op_t &x);
//------------------------------------------------------------------
void idaapi f2mc_segend(outctx_t &ctx, segment_t *seg);

bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);

//------------------------------------------------------------------
struct f2mc_iohandler_t : public iohandler_t
{
  struct f2mc_t &pm;
  f2mc_iohandler_t(f2mc_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual const char *aux_segm() const override { return "FSR"; }
  virtual bool area_processing(ea_t /*start*/, ea_t /*end*/, const char * /*name*/, const char * /*aclass*/) override;
  virtual const char *iocallback(const ioports_t &iop, const char *line) override;
};

struct f2mc_t : public procmod_t
{
  netnode helper;
  f2mc_iohandler_t ioh = f2mc_iohandler_t(*this, helper);
  const char *cfgname = nullptr;
  proctype_t ptype = F2MC16LX;    // contains processor type
  ushort idpflags = F2MC_MACRO;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void load_symbols(int _respect_info);
  const char *find_sym(ea_t address);
  const char *find_bit(ea_t address, int bit);
  bool exist_bits(ea_t ea, int bitl, int bith);
  void f2mc_set_device_name(int _respect_info);
  void choose_and_set_device(int flags);
  inline void choose_device();
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  void adjust_ea_bit(ea_t &ea, int &bit);
  void handle_operand(const insn_t &insn, const op_t &x, bool use);
  int emu(const insn_t &insn);

  void ana_F2MC16LX(insn_t &insn);
  int ana(insn_t *_insn);

  void f2mc_header(outctx_t &ctx);
  void f2mc_assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void f2mc_segstart(outctx_t &ctx, segment_t *Srange) const;
  void f2mc_footer(outctx_t &ctx) const;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ f2mc"
#define PROCMOD_NAME f2mc

#endif // _F2MC_HPP
