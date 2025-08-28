/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _78K0_HPP
#define _78K0_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"
#include "../iohandler.hpp"

struct nec78k0_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool flow = false;       // stop flag

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  bool nec_find_ioport_bit(outctx_t &ctx, int port, int bit);
  void N78K_header(outctx_t &ctx);
  int N78K_emu(const insn_t &insn);
  void handle_operand(const op_t &x, bool forced_op, bool isload, const insn_t &insn);
  void N78K_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void N78K_footer(outctx_t &ctx) const;

  void load_from_idb();
};
bool idaapi out_opnd(outctx_t &ctx, const op_t &x);

extern int data_id;
#define PROCMOD_NODE_NAME "$ 78k0"
#define PROCMOD_NAME nec78k0

// subtype of out format
#define FormOut       specflag1
// o_mem, o_near
#define FORM_OUT_VSK    (0x01)
// o_mem, o_reg, o_near
#define FORM_OUT_SKOBA  (0x02)
// o_reg
#define FORM_OUT_PLUS   (0x04)
#define FORM_OUT_DISP   (0x08)
#define FORM_OUT_REG    (0x10)
// o_bit
#define FORM_OUT_HL             (0x04)
#define FORM_OUT_PSW    (0x08)
#define FORM_OUT_A              (0x10)
#define FORM_OUT_SFR    (0x20)
#define FORM_OUT_S_ADDR (0x40)
// o_reg
#define SecondReg       specflag2

// bit operand
#define o_bit           o_idpspec0

//------------------------------------------------------------------------
enum N78K_registers { rX, rA, rC, rB, rE, rD, rL, rH, rAX, rBC, rDE, rHL,
                     rPSW, rSP, bCY, rRB0, rRB1, rRB2, rRB3,
                     rVcs, rVds };

//------------------------------------------------------------------------
int  idaapi N78K_ana(insn_t *_insn);
int  idaapi N78K_emu(const insn_t &insn);

#endif

