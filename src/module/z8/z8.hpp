/*
* .org
* .word
 .equ
* .end
* .ascii
* .byte
* .block

*+ IM     o_imm     12h
*  Ir     o_ind_reg @R1
*  r      o_reg     R1
*  Irr    o_ind_reg @RR1
*  RR     o_reg     RR1
*  cond   o_phrase
*+ IRR    o_ind_mem @INTMEM_12
*+ IR     o_ind_mem @INTMEM_12
*+ DA/RA  o_near    loc_1234
*+ R      o_mem     INTMEM_12
*+ X      o_displ   INTMEM_12(R1)

 *
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#ifndef _Z8_HPP
#define _Z8_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>
#include <diskio.hpp>
#include "../iohandler.hpp"

#define PROCMOD_NAME            z8
#define PROCMOD_NODE_NAME       "$ Zilog Z8"

//------------------------------------------------------------------
struct z8_iohandler_t : public iohandler_t
{
  z8_iohandler_t(netnode &nn) : iohandler_t(nn) {}
  virtual bool area_processing(ea_t start, ea_t end, const char *name, const char *aclass) override;
};

struct z8_t : public procmod_t
{
  netnode helper;
  z8_iohandler_t ioh = z8_iohandler_t(helper);
  ea_t intmem = BADADDR; // linear EA of the internal memory/registers segment
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *find_ioport(uval_t port);
  void setup_data_segment_pointers(void);
  bool select_device(int resp_info);
  const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  void load_from_idb();

  // ana.cpp
  int  z8_ana(insn_t *insn);

  // emu.cpp
  int  z8_emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, bool isload);
  ea_t map_addr(const insn_t &insn, asize_t off, int opnum, bool isdata) const;

  // out.cpp
  void out_reg(outctx_t &ctx, int rgnum);
  bool out_opnd(outctx_t &ctx, const op_t &x);
  void z8_header(outctx_t &ctx);
  void z8_footer(outctx_t &ctx);
  void z8_segstart(outctx_t &ctx, segment_t *seg);
  void z8_segend(outctx_t &ctx, segment_t *seg);
  void z8_data(outctx_t &ctx, bool analyze_only);
  void z8_assumes(outctx_t &ctx);
};
extern int data_id;

//------------------------------------------------------------------------
// customization of insn_t structure:

#define o_ind_mem   o_idpspec0      // @intmem
#define o_ind_reg   o_idpspec1      // @Rx

//------------------------------------------------------------------------

enum z8_registers
{
  rR0,  rR1,  rR2,   rR3,   rR4,   rR5,   rR6,   rR7,
  rR8,  rR9,  rR10,  rR11,  rR12,  rR13,  rR14,  rR15,
  rRR0, rRR1, rRR2,  rRR3,  rRR4,  rRR5,  rRR6,  rRR7,
  rRR8, rRR9, rRR10, rRR11, rRR12, rRR13, rRR14, rRR15,
  rVcs, rVds, rRp,
};

enum z8_phrases
{
  fF, fLT, fLE, fULE, fOV, fMI, fZ, fC,
  fTrue, fGE, fGT, fUGT, fNOV, fPL, fNZ, fNC
};

struct predefined_t
{
  uchar addr;
  const char *name;
  const char *cmt;
};

//------------------------------------------------------------------------
inline uint16 get_rp(ea_t ea)
{
  sel_t t = get_sreg(ea, rRp);
  return t != BADSEL ? t : 0;
}

#endif
