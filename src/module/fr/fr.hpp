
#ifndef __FR_HPP
#define __FR_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include "../iohandler.hpp"

// uncomment this for the final release
//#define __DEBUG__

// FR registers
enum fr_registers
{
  // general purpose registers :

  rR0,
  rR1,
  rR2,
  rR3,
  rR4,
  rR5,
  rR6,
  rR7,
  rR8,
  rR9,
  rR10,
  rR11,
  rR12,
  rR13,
  rR14,
  rR15,

  // coprocessor registers :

  rCR0,
  rCR1,
  rCR2,
  rCR3,
  rCR4,
  rCR5,
  rCR6,
  rCR7,
  rCR8,
  rCR9,
  rCR10,
  rCR11,
  rCR12,
  rCR13,
  rCR14,
  rCR15,

  // dedicated registers :

  rPC,        // program counter
  rPS,        // program status
  rTBR,       // table base register
  rRP,        // return pointer
  rSSP,       // system stack pointer
  rUSP,       // user stack pointer
  rMDL,       // multiplication/division register (LOW)
  rMDH,       // multiplication/division register (HIGH)

  // system use dedicated registers
  rReserved6,
  rReserved7,
  rReserved8,
  rReserved9,
  rReserved10,
  rReserved11,
  rReserved12,
  rReserved13,
  rReserved14,
  rReserved15,

  // these 2 registers are required by the IDA kernel :

  rVcs,
  rVds
};

enum fr_phrases
{
  fIGR,       // indirect general register
  fIRA,       // indirect relative address
  fIGRP,      // indirect general register with post-increment
  fIGRM,      // indirect general register with pre-decrement
  fR13RI,     // indirect displacement between R13 and a general register
};

// shortcut for a new operand type
#define o_reglist              o_idpspec0

// flags for insn.auxpref
#define INSN_DELAY_SHOT        0x00000001           // postfix insn mnem by ":D"

// flags for opt.specflag1
#define OP_DISPL_IMM_R14       0x00000001           // @(R14, #i)
#define OP_DISPL_IMM_R15       0x00000002           // @(R15, #i)
#define OP_ADDR_R              0x00000010           // read-access to memory
#define OP_ADDR_W              0x00000012           // write-access to memory

inline bool op_displ_imm_r14(const op_t &op) { return (op.specflag1 & OP_DISPL_IMM_R14) != 0; }
inline bool op_displ_imm_r15(const op_t &op) { return (op.specflag1 & OP_DISPL_IMM_R15) != 0; }

// exporting our routines
int  idaapi ana(insn_t *_insn);
bool idaapi create_func_frame(func_t *pfn);
int idaapi is_sp_based(const insn_t &, const op_t &x);
int idaapi is_align_insn(ea_t ea);

struct fr_t : public procmod_t
{
  netnode helper;
  iohandler_t ioh = iohandler_t(helper);
  bool print_comma = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  int choose_device();
  const ioport_t *find_sym(ea_t address);
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  void fr_header(outctx_t &ctx);

  int emu(const insn_t &insn) const;
  bool is_stop(const insn_t &insn) const;

  void fr_footer(outctx_t &ctx) const;
  void fr_segstart(outctx_t &ctx, segment_t *Sarea) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ fr"
#define PROCMOD_NAME fr

#endif /* __FR_HPP */
