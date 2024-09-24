/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _PAN_HPP
#define _PAN_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"
#include "../iohandler.hpp"

//-----------------------------------------------
// additional bits (specflag1)
#define URB_ADDR        0x1     // immediate operand is an address

//------------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
// list of processor registers
enum mn102_registers ENUM8BIT
{
  rNULLReg,
  rD0, rD1, rD2, rD3,
  rA0, rA1, rA2, rA3,
  rMDR,rPSW, rPC,
  rVcs, rVds
};

//------------------------------------------------------------------------
int     idaapi mn102_ana(insn_t *_insn);

void    idaapi mn102_data(outctx_t &ctx, bool analyze_only);

//------------------------------------------------------------------------
struct mn102_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool flow = false;        // code flow continues flag

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  int mn102_emu(const insn_t &insn);

  void mn102_header(outctx_t &ctx);
  void mn102_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void mn102_footer(outctx_t &ctx) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ MN102"
#define PROCMOD_NAME mn102

#endif
