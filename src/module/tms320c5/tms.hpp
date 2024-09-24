/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef _TMS_HPP
#define _TMS_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:
#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1
#define o_cond          o_idpspec2

#define sib     specflag1
#define Cond    reg

#define PT_TMS320C5     0
#define PT_TMS320C2     1

//------------------------------------------------------------------------
struct tms320c5_t : public procmod_t
{
  int nprc = 0;        // processor number
  int tmsfunny = -1;
  uint code;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  int ana(insn_t *insn);
  int op_iaa(const insn_t &insn, op_t &o) const;
  int op_indir(op_t &o);
  int op_maa(const insn_t &insn, op_t &o) const;
  void op_short(op_t &o) const;
  int op_cond(op_t &o) const;
  void op_bit(op_t &o) const;
  int ana_c2(insn_t &insn);

  int emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, bool isload);
  int find_ar(const insn_t &insn, ea_t *res) const;
  bool can_flow(const insn_t &insn) const;

  bool isC2(void) const { return nprc == PT_TMS320C2; }

  void segstart(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;
  void tms_assumes(outctx_t &ctx) const;
};


//------------------------------------------------------------------------
enum TMS_registers { rAcc,rP,rBMAR,rAr0,rAr1,rAr2,rAr3,rAr4,rAr5,rAr6,rAr7,rVcs,rVds,rDP };

enum TMS_bits { bit_intm,bit_ovm,bit_cnf,bit_sxm,bit_hm,bit_tc,bit_xf,bit_c };

//------------------------------------------------------------------------
struct predefined_t
{
  uchar addr;
  const char *name;
  const char *cmt;
};

bool is_mpy(const insn_t &insn);
ea_t prevInstruction(ea_t ea);
//------------------------------------------------------------------------
void idaapi header(outctx_t &ctx);
#endif
