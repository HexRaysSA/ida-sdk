/************************************************************************/
/* Disassembler for Samsung SAM8 processors                             */
/************************************************************************/
#ifndef _SAM8_HPP
#define _SAM8_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

// special insn definitions
#define fl_workingReg specflag1
#define fl_regPair specflag2
#define v_bit specval
#define v_phrase_reg specval_shorts.low
#define v_phrase_idxreg specval_shorts.high
#define c_condition auxpref_u8[0]
#define o_cmem o_mem
#define o_cmem_ind o_idpspec1    // @code address in first 256 bytes
#define o_emem o_idpspec2
#define o_reg_bit o_idpspec3

// offset to code segment
#define SAM8_CODESEG_START 0
#define SAM8_CODESEG_SIZE 0x10000

// offset to external data segment
#define SAM8_EDATASEG_START 0x800000
#define SAM8_EDATASEG_SIZE 0x10000

// utility stuff
#define top_nibble(VALUE) ((VALUE & 0xf0) >> 4)
#define bottom_nibble(VALUE) (VALUE & 0xf)
extern const char *const ccNames[];



/************************************************************************/
/* Registers (we'll be handling these with custom code )                */
/************************************************************************/
enum sam8_registers
{
  rVcs, rVds           // these 2 registers are required by the IDA kernel
};


/************************************************************************/
/* Indirect addressing modes without a displacement                     */
/************************************************************************/
enum sam8_phrases
{
  fIndReg,                 // @register
  fIdxReg,                 // #reg[Rn]
  fIdxEAddr,               // #addr[rr] (DATA)
  fIdxCAddr,               // #addr[rr] (CODE)
};


/************************************************************************/
/* Condition codes                                                      */
/************************************************************************/
enum sam8_cc
{
  ccNone = 0xff,
  ccF = 0,
  ccLT,
  ccLE,
  ccULE,
  ccOV,
  ccMI,
  ccEQ,  // == Z
  ccC,   // == ULT
  ccT,
  ccGE,
  ccGT,
  ccUGT,
  ccNOV,
  ccPL,
  ccNE,  // == NZ
  ccUGE, // == NC
  cc_last,
};


/************************************************************************/
/* Common functions                                                     */
/************************************************************************/
void idaapi sam8_header(outctx_t &ctx);
int idaapi ana(insn_t *_insn);
void idaapi sam8_out_data(outctx_t &ctx, bool analyze_only);

/************************************************************************/
struct sam8_t : public procmod_t
{
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void handle_operand(const insn_t &insn, const op_t &x, bool loading);
  int emu(const insn_t &insn);
  void sam8_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void sam8_footer(outctx_t &ctx) const;
};
#endif
