/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _TMS320C3X_HPP
#define _TMS320C3X_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include <merge.hpp>


enum regnum_t
{
  // Extended-precision registers
  r0 = 0,
  r1,
  r2,
  r3,
  r4,
  r5,
  r6,
  r7,
  // Auxiliary registers
  ar0,
  ar1,
  ar2,
  ar3,
  ar4,
  ar5,
  ar6,
  ar7,

  // Index register n
  ir0,
  ir1,
  bk,     // Block-size register
  sp,     // System-stack pointer
  st,     // Status register
  ie,     // CPU/DMA interrupt-enable register
  if_reg, // CPU interrupt flag
  iof,    // I/O flag
  rs,     // Repeat start-address
  re,     // Repeat end-address
  rc,     // Repeat counter
  // segment registers
  dp,     // DP register
  rVcs, rVds  // virtual registers for code and data segments
};


//------------------------------------------------------------------
// specific processor records

#define phtype    specflag1 // o_phrase: phrase type
// 0     "*+arn(NN)"
// 1     "*-arn(NN)"
// 2     "*++arn(NN)"
// 3     "*--arn(NN)"
// 4     "*arn++(NN)"
// 5     "*arn--(NN)"
// 6     "*arn++(NN)%%"
// 7     "*arn--(NN)%%"
// 8     "*+arn(ir0)"
// 9     "*-arn(ir0)"
// a     "*++arn(ir0)"
// b     "*--arn(ir0)"
// c     "*arn++(ir0)"
// d     "*arn--(ir0)"
// e     "*arn++(ir0)%%"
// f     "*arn--(ir0)%%"
// 10    "*+arn(ir1)"
// 11    "*-arn(ir1)"
// 12    "*++arn(ir1)"
// 13    "*--arn(ir1)"
// 14    "*arn++(ir1)"
// 15    "*arn--(ir1)"
// 16    "*arn++(ir1)%%"
// 17    "*arn--(ir1)%%"
// 18    "*arn"
// 19    "*arn++(ir0)B"

#define itype2 segpref  // 2-nd command type (within parallel instruction)
#define i2op insnpref   // number of first operand that belong to 2-nd insn of parallel instruction
// auxpref flags:
#define DBrFlag 0x80    // Delayed branch flag
#define ImmFltFlag 0x40 // Imm float Value

#include "../iohandler.hpp"

//------------------------------------------------------------------
struct tms320c3x_iohandler_t : public iohandler_t
{
  tms320c3x_iohandler_t(netnode &nn) : iohandler_t(nn) {}
  virtual bool entry_processing(ea_t &ea, const char *name, const char *cmt) override;
};

struct ctx_t;
struct opcode_t;
struct tms320c3_table_t
{
  opcode_t *entries;
  int size;
  opcode_t &operator[](size_t i);
  void create(const opcode_t src_table[], int src_table_size);
  ~tms320c3_table_t();
};

struct tms320c3x_t : public procmod_t
{
  netnode helper;
  tms320c3x_iohandler_t ioh = tms320c3x_iohandler_t(helper);

  tms320c3_table_t table;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  bool select_device(int lrespect_info);
  const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);

  int ana(insn_t *insn);
  void init_analyzer(void);
  void gen_masks(void);
  int run_functions(ctx_t &ctx, int value, int entry, int start, int end);
  int run_functions2(ctx_t &ctx, int value, int entry, int start, int end);

  int emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, flags64_t F, bool use);

  void header(outctx_t &ctx);
  void assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void segstart(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;
  void gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ tms320c3x"
#define PROCMOD_NAME tms320c3x

//------------------------------------------------------------------
ea_t calc_code_mem(const insn_t &insn, const op_t &x);
ea_t calc_data_mem(const insn_t &insn, const op_t &x);

regnum_t get_mapped_register(ea_t ea);
const char *get_cond8(char value);
int get_signed(int byte, int mask);

//------------------------------------------------------------------
void idaapi segend(outctx_t &, segment_t *seg);

void idaapi data(outctx_t &ctx);

bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_align_insn(ea_t ea);
bool is_basic_block_end(const insn_t &insn);
bool idaapi can_have_type(const op_t &op);

#endif // _TMS320C3X_HPP
