/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#ifndef _AVR_HPP
#define _AVR_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <fixup.hpp>
#include "../iohandler.hpp"
#include "../../ldr/elf/elfr_avr.h"
extern int data_id;

#define PROCMOD_NAME            avr
#define PROCMOD_NODE_NAME       AVR_INFO_NODENAME

//---------------------------------
// Operand types:

enum phrase_t ENUM_SIZE(uint16)
{
  PH_X,         // X
  PH_XPLUS,     // X+
  PH_MINUSX,    // -X
  PH_Y,         // Y
  PH_YPLUS,     // Y+
  PH_MINUSY,    // -Y
  PH_Z,         // Z
  PH_ZPLUS,     // Z+
  PH_MINUSZ,    // -Z
};


#define reg_pair specflag1      // o_reg: operand is 16bit a register pair (even register is in op.reg)
#define o_port  o_idpspec0      // port number in x.addr

//------------------------------------------------------------------
enum RegNo
{
  R0,   R1,  R2,  R3,  R4,  R5,  R6,  R7,
  R8,   R9,  R10, R11, R12, R13, R14, R15,
  R16,  R17, R18, R19, R20, R21, R22, R23,
  R24,  R25, R26, R27, R28, R29, R30, R31,
  rVcs, rVds,    // virtual registers for code and data segments
};

//------------------------------------------------------------------
void idaapi avr_segend(outctx_t &ctx, segment_t *seg);
void idaapi avr_assumes(outctx_t &ctx);         // function to produce assume directives

int  idaapi is_align_insn(ea_t ea);

//------------------------------------------------------------------
struct avr_iohandler_t : public iohandler_t
{
  struct avr_t &pm;
  avr_iohandler_t(avr_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual const char *iocallback(const ioports_t &iop, const char *line) override;
  virtual bool entry_processing(ea_t &, const char * /*word*/, const char * /*cmt*/) override;
  virtual bool check_ioresp() const override;
};

DECLARE_PROC_LISTENER(idb_listener_t, struct avr_t);

struct avr_t : public procmod_t
{
  netnode helper;
  avr_iohandler_t ioh = avr_iohandler_t(*this, helper);
  idb_listener_t idb_listener = idb_listener_t(*this);

  //--------------------------------------------------------------------------
  // not tested
  fixup_handler_t cfh_avr16 =
  {
    sizeof(fixup_handler_t),
    "AVR16",                      // Format name, must be unique
    0,                            // props
    2, 16, 0, 0,                  // size, width, shift
    REFINFO_CUSTOM,               // reftype
    nullptr,                      // apply, will be inited in processor_t::ev_init
    nullptr,                         // get_value
    nullptr,                         // patch_value
  };
  fixup_type_t cfh_avr16_id = 0;
  int ref_avr16_id = 0;

  int subarch = 0;

  // memory configuration
  ea_t ram = BADADDR;
  uint32 ramsize = 0;
  uint32 romsize = 0;
  uint32 eepromsize = 0;

  bool imageFile = false;
  bool nonBinary = false;

  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const ioport_t *find_port(ea_t address);
  const char *find_bit(ea_t address, size_t bit);
  void setup_avr_device(int resp_info);
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);
  bool set_param_by_arch(void);
  bool is_possible_subarch(int addr) const;

  void handle_operand(const insn_t &insn, const op_t &x, bool isAlt, bool isload);
  int emu(const insn_t &insn);

  void avr_header(outctx_t &ctx);

  inline void opimm(const insn_t &insn, op_t &x, int value) const;
  inline uint32 code_address(const insn_t &insn, signed int delta) const;
  int ana(insn_t *_insn);

  void avr_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void avr_footer(outctx_t &ctx) const;

  void load_from_idb();
};

#endif // _AVR_HPP
