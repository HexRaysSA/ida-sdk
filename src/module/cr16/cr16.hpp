/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _CR16_HPP
#define _CR16_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#define near
#define far
#include "ins.hpp"
#include "../iohandler.hpp"

// ============================================================
// specflags1 bits
//-----------------------------------------------
#define URR_PAIR        (0x01)  // indirect reference via reg pair

//------------------------------------------------------------------------
// processor registers
enum CR16_registers
{
  rNULLReg,
  rR0, rR1, rR2, rR3, rR4, rR5, rR6, rR7,
  rR8, rR9, rR10, rR11, rR12, rR13, rRA, rSP,
  // special registers
  rPC, rISP, rINTBASE, rPSR, rCFG, rDSR, rDCR,
  rCARL, rCARH, rINTBASEL, rINTBASEH,
  rVcs, rVds
};

//------------------------------------------------------------------------
int     idaapi CR16_ana(insn_t *_insn);
int     idaapi CR16_emu(const insn_t &insn);

//------------------------------------------------------------------------
struct cr16_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool flow = false;               // flow stop flag

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void CR16_header(outctx_t &ctx);
  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  int CR16_emu(const insn_t &insn);

  void CR16_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void CR16_footer(outctx_t &ctx) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ CR16"
#define PROCMOD_NAME cr16

#endif
