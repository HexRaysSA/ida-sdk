/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _ST7_HPP
#define _ST7_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

#define PROCMOD_NAME            st7
#define PROCMOD_NODE_NAME       "$ st7"

// o_void  Inherent      nop
// o_imm   Immediate     ld A,#$55
// o_mem   Direct        ld A,$55
// o_displ Indexed       ld A,($55,X)
// o_mem   Indirect      ld A,([$55],X)
// o_near  Relative      jrne loop
// o_mem   Bit operation bset byte,#5

//  type            Mode                    Syntax             Destination Ptradr PtrSz Len
// ------- --------------------------- ------------------------ ---------- ------ ---- ---
// o_void  Inherent                    nop                                             + 0
// o_imm   Immediate                   ld A,#$55                                       + 1
// o_mem   Short     Direct            ld A,$10                 00..FF                 + 1
// o_mem   Long      Direct            ld A,$1000               0000..FFFF             + 2
// o_phras No Offset Direct   Indexed  ld A,(X)                 00..FF                 + 0
// o_displ Short     Direct   Indexed  ld A,($10,X)             00..1FE                + 1
// o_displ Long      Direct   Indexed  ld A,($1000,X)           0000..FFFF             + 2
// o_mem   Short     Indirect          ld A,[$10]               00..FF     00..FF byte + 2
// o_mem   Long      Indirect          ld A,[$10.w]             0000..FFFF 00..FF word + 2
// o_mem   Short     Indirect Indexed  ld A,([$10],X)           00..1FE    00..FF byte + 2
// o_mem   Long      Indirect Indexed  ld A,([$10.w],X)         0000..FFFF 00..FF word + 2
// o_near  Relative  Direct            jrne loop                PC+/-127               + 1
// o_mem   Relative  Indirect          jrne [$10]               PC+/-127   00..FF byte + 2
// o_mem   Bit       Direct            bset $10,#7              00..FF                 + 1
// o_mem   Bit       Indirect          bset [$10],#7            00..FF     00..FF byte + 2
// o_mem   Bit       Direct   Relative btjt $10,#7,skip         00..FF                 + 2
// o_mem   Bit       Indirect Relative btjt [$10],#7,skip       00..FF     00..FF byte + 3

#define aux_long       0x0001  // long addressing mode
#define aux_indir      0x0002  // o_mem: indirect addressing mode
#define aux_index      0x0004  // o_mem: indexed addressing mode
#define aux_16         0x0008  // 16bit displacement

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  A, X, Y, CC, S,
  ds, cs,
};

//------------------------------------------------------------------
struct st7_iohandler_t : public iohandler_t
{
  st7_iohandler_t(netnode &nn) : iohandler_t(nn) {}
};

struct st7_t : public procmod_t
{
  netnode helper;
  st7_iohandler_t ioh = st7_iohandler_t(helper);

  bool flow;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const ioport_t *find_sym(ea_t address);
  void create_words(void);
  const char *idaapi set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);

  int st7_emu(const insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, bool isload);

  void st7_footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;

//------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea); // map virtual to physical ea

//------------------------------------------------------------------
void idaapi st7_header(outctx_t &ctx);

void idaapi st7_segstart(outctx_t &ctx, segment_t *seg);
void idaapi st7_segend(outctx_t &ctx, segment_t *seg);
void idaapi st7_assumes(outctx_t &ctx);         // function to produce assume directives

int  idaapi st7_ana(insn_t *insn);

int  idaapi is_align_insn(ea_t ea);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn);  // can a function start here?

#endif // _ST7_HPP
