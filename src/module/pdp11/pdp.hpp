/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PDP_HPP
#define _PDP_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include "pdp_ml.h"
//-V::536 octal

#define UAS_SECT        0x0001          // Segments are named .SECTION

//----------------------------------------------------------------------
// Redefine temporary names
//
#define         bytecmd    auxpref_u8[0]

#define         segval     specval_shorts.low
#define         addr16     addr_shorts.low
#define         ill_imm    specflag1

#define         o_fpreg    o_idpspec0
#define         o_number   o_idpspec1
//------------------------------------------------------------------------
enum pdp_registers
{
  rR0, rR1, rR2, rR3, rR4, rR5, rSP, rPC,
  rAC0, rAC1, rAC2, rAC3, rAC4, rAC5,
  rVcs, rVds
};

//------------------------------------------------------------------------
void idaapi pdp_header(outctx_t &ctx);

//------------------------------------------------------------------------
struct pdp11_t : public procmod_t
{
  netnode ovrtrans;
  pdp_ml_t ml = { uint32(BADADDR), 0, 0, 0 };
  bool flow = false;
  ushort emuR0 = 0xFFFF;
  //lint -e708 'union initialization'
  union
  {
    ushort w;
    uchar b[2];
  } emuR0data = { 0xFFFF };

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void jmpoper(insn_t &insn, op_t *Op, uint16 nibble);
  int ana(insn_t *_insn);

  void pdp_segstart(outctx_t &ctx, segment_t *seg);

  void loadR0data(const insn_t &insn, const op_t *x, int sme);
  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  int emu(const insn_t &insn);

  void pdp_footer(outctx_t &ctx) const;
  bool out_equ(outctx_t &ctx, ea_t ea) const;
  void pdp_data(outctx_t &ctx, bool analyze_only) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ pdp-11 overlay translations"
#define PROCMOD_NAME pdp11
#endif
