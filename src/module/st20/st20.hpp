/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _ST20_HPP
#define _ST20_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

#define PROCMOD_NAME            st20
#define PROCMOD_NODE_NAME       "$ st20"

//------------------------------------------------------------------
enum regnum_t
{
  Areg,       // Evaluation stack register A
  Breg,       // Evaluation stack register B
  Creg,       // Evaluation stack register C
  Iptr,       // Instruction pointer register, pointing to the next instruction to be executed
  Status,     // Status register
  Wptr,       // Work space pointer, pointing to the stack of the currently executing process
  Tdesc,      // Task descriptor
  IOreg,      // Input and output register
  cs,
  ds,

};

//------------------------------------------------------------------
#define PROC_C1 0
#define PROC_C4 1

//------------------------------------------------------------------
struct st20_iohandler_t : public iohandler_t
{
  st20_iohandler_t(netnode &nn) : iohandler_t(nn) {}
};

struct st20_t : public procmod_t
{
  netnode helper;
  st20_iohandler_t ioh = st20_iohandler_t(helper);

  int procnum;
  bool flow;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);

  int st20_ana(insn_t *insn);

  int st20_emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, bool isload);

  bool isc4(void) { return procnum == PROC_C4; }

  void st20_footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;

ea_t calc_mem(const insn_t &insn, ea_t ea); // map virtual to physical ea
//------------------------------------------------------------------
void idaapi st20_header(outctx_t &ctx);

void idaapi st20_segstart(outctx_t &ctx, segment_t *seg);
void idaapi st20_segend(outctx_t &ctx, segment_t *seg);
void idaapi st20_assumes(outctx_t &ctx);         // function to produce assume directives

int  idaapi is_align_insn(ea_t ea);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn);           // can a function start here?

#endif // _ST20_HPP
