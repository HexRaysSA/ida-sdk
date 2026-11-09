/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _I960_HPP
#define _I960_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

// Absolute offset (<4096)       offset                   exp                 MEMA o_imm
// Absolute displacement         disp                     exp                 MEMB o_imm
// Register Indirect             abase                    (reg)               o_phrase, index=-1, scale=1
//   with offset                 abase+offset             exp(reg)            o_displ, index=-1,scale=1
//   with displacement           abase+disp               exp(reg)            o_displ, index=-1,scale=1
//   with index                  abase+(index*scale)      (reg)[reg*scale]    o_phrase, index=index
//   with index and displacement abase+(index*scale)+disp exp(reg)[reg*scale] o_displ
// Index with displacement       (index*scale) + disp     exp[reg*scale]      o_displ, reg=index, index=-1
// IP with displacement          IP+disp+8                exp(IP)             o_near

#define index   specflag1           // o_displ, o_phrase
#define scale   specflag2           // o_displ, o_phrase

#define aux_t  0x0001           // .t suffix
#define aux_f  0x0002           // .f suffix
#define aux_ip 0x0004           // ip relative addressing

//------------------------------------------------------------------
enum regnum_t
{
  LR0, LR1, LR2,  LR3,  LR4,  LR5,  LR6,  LR7,
  LR8, LR9, LR10, LR11, LR12, LR13, LR14, LR15,
  GR0, GR1, GR2,  GR3,  GR4,  GR5,  GR6,  GR7,
  GR8, GR9, GR10, GR11, GR12, GR13, GR14, GR15,
  SF0, SF31=SF0+31,
  PC,  AC,  IP,  TC,
  FP0, FP1, FP2, FP3,
  ds, cs,
  MAXREG = cs,
  PFP    = LR0,
  SP     = LR1,
  RIP    = LR2,
  FP     = GR15,
  IPND   = SF0+0,
  IMSK   = SF0+1,
  DMAC   = SF0+2,
};

//------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea); // map virtual to physical ea
//------------------------------------------------------------------
void idaapi i960_header(outctx_t &ctx);

void idaapi i960_segend(outctx_t &ctx, segment_t *seg);
void idaapi i960_assumes(outctx_t &ctx);         // function to produce assume directives

int  idaapi is_align_insn(ea_t ea);

//------------------------------------------------------------------
struct tabent_t
{
  ushort itype;
  char opnum;
  char dtype;
};

//------------------------------------------------------------------
struct i960_iohandler_t : public iohandler_t
{
  struct i960_t &pm;
  i960_iohandler_t(i960_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
};

struct i960_t : public procmod_t
{
  netnode helper;
  i960_iohandler_t ioh = i960_iohandler_t(*this, helper);

  ushort idpflags;
#define IDP_STRICT      0x0001  // Strictly adhere to instruction encodings
  inline bool is_strict(void) { return (idpflags & IDP_STRICT) != 0; }
  void save_idpflags() { helper.altset(-1, idpflags); }

#define REG_MIN 0x580
#define REG_MAX 0x7f4
  struct tabent_t reg_tab_buf[REG_MAX - REG_MIN + 1];
  struct tabent_t *reg_tab = nullptr;

  bool flow;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void load_symbols(void);
  const char *find_sym(ea_t address);
  void choose_device();
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  bool ctrl(insn_t &insn, uint32 code);
  bool opmemory(insn_t &insn, op_t &x, uint32 code, char dtype);
  bool mem(insn_t &insn, uint32 code);

  inline void opnear(op_t &x, uval_t addr) const;
  bool cobr(insn_t &insn, uint32 code) const;
  int i960_ana(insn_t *_insn);
  bool reg(insn_t &insn, uint32 code);

  void handle_operand(const insn_t &insn, const op_t &x, bool isload);
  int i960_emu(const insn_t &insn);

  void i960_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void i960_footer(outctx_t &ctx) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ i960"
#define PROCMOD_NAME i960
#endif // _I960_HPP
