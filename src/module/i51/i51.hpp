/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#ifndef _I51_HPP
#define _I51_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include "../iohandler.hpp"

//------------------------------------------------------------------
enum processor_subtype_t
{
                // odd types are binary mode
                // even types are source modes
  prc_51 = 0,                      // plain 8051
  prc_251_bin,                     // 80251 in binary mode
  prc_251 = prc_251_bin,           // the same... (a shortcut)
  prc_251_src,                     // 80251 in source mode
  prc_930_bin,                     // 8x930 in source mode
  prc_930 = prc_930_bin,           // the same... (a shortcut)
  prc_930_src,                     // 8x930 in source mode
  prc_51mx,
};

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

// 8051 bit references:

#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1

// fRi indirect register number (for o_phrase):
#define indreg          specflag1

// displacement is an immediate number (print #) (for o_displ):
#define imm_disp        specflag1

// 80251 bit references (bit address in x.addr):

#define o_bit251        o_idpspec2
#define b251_bit        specflag1               // bit number
#define b251_bitneg     specflag2               // negate?


// cmd.auxpref bits:

#define aux_0ext      0x0001  // high bit 0-extension immediate value
#define aux_1ext      0x0002  // high bit 1-extension immediate value


// ash.uflag bit meanings:

#define UAS_PSAM        0x0001          // PseudoSam: use funny form of
                                        // equ for intmem
#define UAS_SECT        0x0002          // Segments are named .SECTION
#define UAS_NOSEG       0x0004          // No 'segment' directives
#define UAS_NOBIT       0x0008          // No bit.# names, use bit_#
#define UAS_SELSG       0x0010          // Segment should be selected by its name
#define UAS_EQCLN       0x0020          // ':' in EQU directives
#define UAS_AUBIT       0x0040          // Don't use BIT directives -
                                        // assembler generates bit names itself
#define UAS_CDSEG       0x0080          // Only DSEG,CSEG,XSEG
#define UAS_NODS        0x0100          // No .DS directives in Code segment
#define UAS_NOENS       0x0200          // don't specify start addr in the .end directive
#define UAS_PBIT        0x0400          // assembler knows about predefined bits
#define UAS_PBYTNODEF   0x0800          // do not define predefined byte names

//------------------------------------------------------------------------
// Registers
enum i51_registers
{
  rAcc, rAB, rB,
  rR0, rR1, rR2, rR3, rR4, rR5, rR6, rR7,
  rR8, rR9, r10, r11, rR12, rR13, rR14, rR15,
  rWR0,  rWR2,  rWR4,  rWR6,  rWR8,  rWR10, rWR12, rWR14,
  rWR16, rWR18, rWR20, rWR22, rWR24, rWR26, rWR28, rWR30,
  rDR0,  rDR4,  rDR8,  rDR12, rDR16, rDR20, rDR24, rDR28,
  rDR32, rDR36, rDR40, rDR44, rDR48, rDR52, rDR56, rDR60,
  rDptr, rC, rPC,
  rEptr, rPR0, rPR1,    // 51mx registers
  rVcs, rVds            // these 2 registers are required by the IDA kernel
};

// Indirect addressing modes without a displacement:
enum i51_phrases
{
  fR0,                  // @R0
  fR1,                  // @R1
  fDptr,                // @DPTR
  fAdptr,               // @A+DPTR
  fApc,                 // @A+PC
  fRi,                  // @WRj or @DRj, reg number in indreg
  fEptr,                // @EPTR
  fAeptr,               // @A+EPTR
  fPr0,                 // @PR0
  fPr1,                 // @PR1
};

//------------------------------------------------------------------------
bool is_sane_insn(const insn_t &insn, int reason);

//------------------------------------------------------------------
struct i51_iohandler_t : public iohandler_t
{
  struct i51_t &pm;
  i51_iohandler_t(i51_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual bool check_ioresp() const override;
  virtual void apply_io_port(ea_t ea, const char *name, const char *cmt) override;
  virtual void get_cfg_filename(char *buf, size_t bufsize) override;
  virtual bool segment_created(ea_t /*start*/, ea_t /*end*/, const char * /*name*/, const char * /*aclass*/) override;
};

DECLARE_PROC_LISTENER(idb_listener_t, struct i51_t);

struct i51_t : public procmod_t
{
  netnode helper;
  i51_iohandler_t ioh = i51_iohandler_t(*this, helper);
  idb_listener_t idb_listener = idb_listener_t(*this);
  processor_subtype_t ptype = prc_51;
  ea_t intmem = 0;    // address of the internal memory
  ea_t sfrmem = 0;    // address of SFR memory
  bool flow = false;
  bool allow_proc_change = true;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  const ioport_bit_t *find_bit(ea_t address, int bit);
  bool IsPredefined(const char *name);
  ea_t AdditionalSegment(size_t size, size_t offset, const char *name) const;
  uint32 truncate(uval_t addr) const;
  int ana_extended(insn_t &insn);
  void attach_bit_comment(const insn_t &insn, ea_t addr, int bit);
  void setup_data_segment_pointers(void);
  void i51_header(outctx_t &ctx);
  int out_equ(outctx_t &ctx);
  void i51_data(outctx_t &ctx, bool analyze_only);
  ea_t i51_map_data_ea(const insn_t &insn, ea_t addr, int opnum) const;
  void handle_operand(const insn_t &insn, const op_t &x, bool loading);
  int emu(const insn_t &insn);
  int ana_basic(insn_t &insn);
  int ana(insn_t *_insn);
  void i51_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void i51_footer(outctx_t &ctx) const;
  void do_out_equ(outctx_t &ctx, const char *name, const char *equ, uchar off) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ intel 8051"
#define PROCMOD_NAME i51
#endif
