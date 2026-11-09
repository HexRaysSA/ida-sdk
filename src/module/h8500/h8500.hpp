/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _H8500_HPP
#define _H8500_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>
#include <diskio.hpp>

#define PROCMOD_NAME      h8500
#define PROCMOD_NODE_NAME "$ h8/500"

//---------------------------------
// Operand types:

/*
o_reg    1 Register direct Rn
           x.reg
o_phrase 2 Register indirect @Rn
           x.phrase contains register number
           x.phtype contains phrase type (normal, post, pre)
o_displ  3 Register indirect with displacement @(d:8,Rn)/@(d:16,Rn)
           x.reg, x.addr, aux_disp16, aux_disp32
o_mem    5 Absolute address @aa:8/@aa:16/@aa:24
           x.page, x.addr
o_imm    6 Immediate #xx:8/#xx:16/#xx:32
           x.value
o_displ  7 Program-counter relative @(d:8,PC)/@(d:16,PC)
o_reglist  Register list
           x.reg
*/

#define o_reglist       o_idpspec0

#define phtype          specflag1       // phrase type:
const int ph_normal = 0;                // just simple indirection
const int ph_pre    = 1;                // predecrement
const int ph_post   = 2;                // postincrement

#define page            specflag1       // o_mem, page number if aux_page
//------------------------------------------------------------------
#define aux_byte        0x0001          // .b postfix
#define aux_word        0x0002          // .w postfix
#define aux_disp8       0x0004          //  8bit displacement
#define aux_disp16      0x0008          // 16bit displacement
#define aux_disp24      0x0010          // 24bit displacement
#define aux_page        0x0020          // implicit page using BR
#define aux_f           0x0040          // /f postfix
#define aux_ne          0x0080          // /ne postfix
#define aux_eq          0x0100          // /eq postfix
#define aux_mov16       0x0200          // mov #xx:16, ...

//------------------------------------------------------------------
enum regnum_t
{
  R0, R1, R2, R3, R4, R5, R6, FP=R6, R7, SP=R7,
  SR, CCR, RES1, BR, EP, DP, CP, TP, // RES1 is forbidden
};


ea_t calc_mem(const insn_t &insn, const op_t &x); // map virtual to physical ea
//------------------------------------------------------------------
int calc_opimm_flags(const insn_t &insn);
int calc_opdispl_flags(const insn_t &insn);

void idaapi h8500_header(outctx_t &ctx);

void idaapi h8500_segend(outctx_t &ctx, segment_t *seg);

int  idaapi is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);

int idaapi h8500_get_frame_retsize(const func_t *);
int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn); // can a function start here?

//------------------------------------------------------------------
struct h8500_t : public procmod_t
{
  netnode helper;
  ioports_t ports;
#define IDP_SAMESIZE   0x0001  // do not disassemble mixed size insns
  ushort idpflags = 0;
  bool is_mixed_size_insns() const { return (idpflags & IDP_SAMESIZE) == 0; }
  bool flow = false;
  char show_sizer = -1;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void load_symbols(const char *file);
  const char *find_sym(int address);
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);

  inline void d8(insn_t &insn, op_t &x) const;
  int h8500_ana(insn_t *_insn);

  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  int h8500_emu(const insn_t &insn);

  void h8500_assume(outctx_t &ctx);
  void h8500_segstart(outctx_t &ctx, segment_t *Srange) const;
  void h8500_footer(outctx_t &ctx) const;

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};
extern int data_id;

#endif // _H8500_HPP
