/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef _M65_HPP
#define _M65_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

struct m6502_t : public procmod_t
{
  bool is_cmos = false;     // is CMOS (otherwise, NMOS)

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  int ana(insn_t *_insn);
  int emu(const insn_t &insn) const;
  void handle_operand(const op_t &x, bool isload, const insn_t &insn, bool *flow) const;

  void header(outctx_t &ctx) const;
  void segstart(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;
};
extern int data_id;

// Is indirect memory reference?

#define indirect        auxpref

#define UAS_SECT        0x0002          // Segments are named .SECTION
#define UAS_NOSEG       0x0004          // No 'segment' directives
#define UAS_SELSG       0x0010          // Segment should be selected by its name
#define UAS_CDSEG       0x0080          // Only DSEG, CSEG, XSEG
#define UAS_NOENS       0x0200          // don't specify start addr in the .end directive
//------------------------------------------------------------------------
enum M65_registers { rA, rX, rY, rVcs, rVds, riX, riY, zX, zY };

//------------------------------------------------------------------------
int     idaapi ana(insn_t *insn);
int     idaapi emu(const insn_t &insn);
void    idaapi assumes(outctx_t &ctx, ea_t ea);
int     m65_opflags(const op_t &x);


#endif
