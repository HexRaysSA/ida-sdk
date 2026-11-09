/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _TOSH_HPP
#define _TOSH_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include "../iohandler.hpp"
#define PROCMOD_NAME            tlcs900
#define PROCMOD_NODE_NAME       "$ TLCS900"

//-----------------------------------------------
// Increment/decrement
#define URB_DECR        (0x80)  // decrement
#define URB_DCMASK      (0x07)  // mask or decrement
#define URB_UDEC        (0x40)  // singleton decrement
#define URB_UINC        (0x20)  // signleto increment

// specflag1 bits
#define URB_WORD        (1)     // second index register is word
#define URB_LDA         (2)     // insn uses address not the content
#define URB_LDA2        (4)     // same, but may constant!

//------------------------------------------------------------------------
enum T900_registers
{
  rNULLReg,
  rW, rA, rB, rC, rD, rE, rH, rL,
  rWA, rBC, rDE, rHL, rIX, rIY, rIZ, rSP,
  rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP,
  rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH,
  rVcs, rVds
};

// phrases
enum T900_phrases
{
  rNULLPh,
  fCF,fCLT,fCLE,fCULE,fCPE,fCMI,fCZ,fCC,
  fCT,fCGE,fCGT,fCUGT,fCPO,fCPL,fCNZ,fCNC,
  fSF,fSF1,
  fSR, fPC
};

//------------------------------------------------------------------
struct tlcs900_iohandler_t : public iohandler_t
{
  tlcs900_iohandler_t(netnode &nn) : iohandler_t(nn) {}
};

struct tlcs900_t : public procmod_t
{
  netnode helper;
  tlcs900_iohandler_t ioh = tlcs900_iohandler_t(helper);
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);

  int T900_emu(const insn_t &insn);
  void T900_header(outctx_t &ctx);
  void T900_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void T900_footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;

//------------------------------------------------------------------------
int  idaapi T900_ana(insn_t *_insn);

void idaapi T900_data(outctx_t &ctx, bool analyze_only);

#endif
