/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _C39_HPP
#define _C39_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#define near
#define far
#include "ins.hpp"
#include "../iohandler.hpp"

// ============================================================
// aditional bits for specflags1 (specflag2 not used)
//-----------------------------------------------
// additional bits for memory access
#define URR_IND         (0x01)  // indirect via a register

//------------------------------------------------------------------------
// list of processor registers
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum C39_registers ENUM8BIT
{
  rNULLReg,
  rA,
  rX, rY,
  rVcs, rVds
};

//------------------------------------------------------------------------
int     idaapi C39_ana(insn_t *insn);
int     idaapi C39_emu(const insn_t &insn);
void    idaapi C39_data(outctx_t &ctx, bool analyze_only);

//------------------------------------------------------------------------
struct c39_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool flow = false;        // stop flag

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void C39_header(outctx_t &ctx);
  void handle_operand(
        const insn_t &insn,
        const op_t &x,
        bool is_forced,
        bool isload);
  int C39_emu(const insn_t &insn);

  void C39_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void C39_footer(outctx_t &ctx) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ C39"
#define PROCMOD_NAME c39

#endif
