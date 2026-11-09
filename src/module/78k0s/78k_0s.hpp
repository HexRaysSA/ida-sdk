/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _NEC78K0S_HPP
#define _NEC78K0S_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include "../iohandler.hpp"

struct nec78k0s_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  bool nec_find_ioport_bit(outctx_t &ctx, int port, int bit);
  void nec78k0s_header(outctx_t &ctx);
  int emu(const insn_t &insn);
  void handle_operand(const op_t &x, bool forced_op, bool isload, const insn_t &insn);
  void nec78k0s_footer(outctx_t &ctx) const;

  void load_from_idb();
};
bool idaapi out_opnd(outctx_t &ctx, const op_t &x);

extern int data_id;
#define PROCMOD_NODE_NAME "$ 78k0s"
#define PROCMOD_NAME nec78k0s

#define UAS_NOSPA        0x0001         // no space after comma
//#define UAS_ZVBIT        0x0002         // '*' prefixes name in bit command
//#define UAS_AREAS        0x0004         // '.area' segment directive
//#define UAS_CCR          0x0008         // "ccr" register is named "cc"
//                                        // "dpr" register is named "dp"
//                                        // "pcr" register is named "pc"
//#define UAS_ORA          0x0010         // ORAA is named ORA
//                                        // ORAB is named ORB
//#define UAS_CODE         0x0020         // "code", "data", "bss" directives
//#define UAS_AUTOPC       0x0040         // Automatic relative addressing by PC
//                                        // (no need to substract PC value)
//#define UAS_ALL          0x0080         // "all" keyword is recognized as
//                                        // a synonim for all registers
//#define UAS_OS9          0x0100         // has OS9 directive
//----------------------------------------------------------------------
// Redefine temporary names
//
#define         exten       segpref
#define         xmode       specflag1
#define         prepost     specflag2
#define         addr16      specflag3

// bit operand
#define         regmode       specflag1
#define         regdata       specflag2

// callt
#define         form         specflag1

#define         o_bit       o_idpspec0
//------------------------------------------------------------------------
enum nec_registers { rX, rA, rC, rB, rE, rD, rL, rH, rAX, rBC, rDE, rHL,
                     rPSW, rSP, rS, rCC, rDPR,
                     bCY,
                     Rcs, Rds };

enum bitOper { SADDR=0, SFR, A, PSW, HL, CY };
//------------------------------------------------------------------------
extern qstring deviceparams;
extern qstring device;

struct ioport_bit_t;
bool nec_find_ioport_bit(outctx_t &ctx, int port, int bit);
uint32 Get_Data_16bits();
//------------------------------------------------------------------------
void idaapi nec78k0s_header(outctx_t &ctx);
void idaapi nec78k0s_footer(outctx_t &ctx);

void idaapi nec78k0s_segstart(outctx_t &ctx, segment_t *seg);

int  idaapi ana(insn_t *_insn);
int  idaapi emu(const insn_t &insn);


#endif

