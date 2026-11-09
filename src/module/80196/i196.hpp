/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#ifndef _I196_HPP
#define _I196_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:

#define o_indirect      o_idpspec0      // [addr]
#define o_indirect_inc  o_idpspec1      // [addr]+
#define o_indexed       o_idpspec2      // addr[value]
#define o_bit           o_idpspec3

//------------------------------------------------------------------------

enum i196_registers { rVcs, rVds, WSR, WSR1 };

typedef struct
{
  uchar addr;
  const char *name;
  const char *cmt;
} predefined_t;

//------------------------------------------------------------------------
void idaapi i196_header(outctx_t &ctx);
void idaapi i196_footer(outctx_t &ctx);

void idaapi i196_segend(outctx_t &ctx, segment_t *seg);

//------------------------------------------------------------------------
struct i196_t : public procmod_t
{
  int extended = 0;
  int flow = false;

  inline uint32 truncate(ea_t x)
  {
    return x & (extended ? 0xFFFFF : 0xFFFF);
  }

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  ea_t map(ea_t iea, ea_t v) const;
  void aop(insn_t &insn, uint code, op_t &op);
  int ld_st(insn_t &insn, ushort itype, char dtype, bool indirect, op_t &reg, op_t &mem);
  int ana(insn_t *_insn);

  void handle_operand(const insn_t &insn, const op_t &x, int isload);
  int emu(const insn_t &insn);

  void i196_segstart(outctx_t &ctx, segment_t *Sarea) const;
};

#endif
