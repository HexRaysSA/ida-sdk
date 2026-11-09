
#ifndef _OAKDSP_HPP
#define _OAKDSP_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include "../iohandler.hpp"

//------------------------------------------------------------------

#define aux_cc                  0x000F   // condition code
#define aux_comma_cc            0x0010   // comma before cond
#define aux_iret_context        0x0020

#define cmd_cycles insnpref

#define phtype     specflag1 // o_phrase: phrase type
// 0 (Rn)
// 1 (Rn)+1
// 2 (Rn)-1
// 3 (Rn)+s
// 4 (any_reg)

#define amode           specflag2 // addressing options & other
#define amode_short     0x01
#define amode_long      0x02
#define amode_x         0x04  // X:
#define amode_p         0x08  // P:
#define amode_neg       0x10  // -
#define amode_signed    0x10  // - if x<0


#define o_textphrase    o_idpspec0 // text type
#define o_local         o_idpspec1

#define textphtype      specflag1  // o_texttype: phrase type

#define text_swap       0x01
// (a0, b0)
// (a0, b1)
// (a1, b0)
// (a1, b1)
// (a0, b0), (a1, b1)
// (a0, b1), (a1, b0)
// (a0, b0, a1)
// (a0, b1, a1)
// (a1, b0, a0)
// (a1, b1, a0)
// (b0, a0, b1)
// (b0, a1, b1)
// (b1, a0, b0)
// (b1, a1, b0)

#define text_banke      0x02
//[r0], [r1], [r4], [cfgi]

#define text_cntx       0x03
// s
// r

#define text_dmod       0x04
// dmod

#define text_eu         0x05
// eu

#define mix_mode        0x80000000      // Func rrrrr should use both input value and param

//------------------------------------------------------------------
#define UAS_GNU 0x0001          // GNU assembler
//------------------------------------------------------------------
enum RegNo
{
  R0, R1, R2, R3, R4, R5,         // DAAU Registers
  RB,                             // Base Register
  Y,                              // Input Register
  ST0, ST1, ST2,                  // Status Registers
  P,                              // Output Register
  PC,                             // Program Counter
  SP,                             // Software Stack Pointer
  CFGI, CFGJ,                     // DAAU Configuration Registers
  B0H, B1H, B0L, B1L,             // Accumulator B
  EXT0, EXT1, EXT2, EXT3,         // External registers
  A0, A1, A0L, A1L, A0H, A1H,     // Accumulator A
  LC,                             // Loop Counter
  SV,                             // Shift Value Register
  X,                              // Input Register
  DVM,                            // Data Value Match Register
  MIXP,                           // Minimal/Maximal Pointer Register
  ICR,                            // Internal Configuration Register
  PS,                             // Product Shifter Control
  REPC,                           // Internal Repeat Counter
  B0, B1,                         // Accumulator B
  MODI,MODJ,                      // Modulo Modifier
  STEPI, STEPJ,                   // Linear (Step) Modifier
  PAGE,                           // Short Direct Addressing Mode Page
  vCS, vDS,                       // virtual registers for code and data segments
};


//------------------------------------------------------------------
// condition codes
enum cc_t
{
  cc_true,      // Always
  cc_eq,        // Equal to zero Z = 1
  cc_neq,       // Not equal to zero Z = 0
  cc_gt,        // Greater than zero M = 0 and Z = 0
  cc_ge,        // Greater than or equal to zero M = 0
  cc_lt,        // Less than zero M =1
  cc_le,        // Less than or equal to zero M = 1 or Z = 1
  cc_nn,        // Normalized flag is cleared N = 0
  cc_v,         // Overflow flag is set V = 1
  cc_c,         // Carry flag is set C = 1
  cc_e,         // Extension flag is set E = 1
  cc_l,         // Limit flag is set L = 1
  cc_nr,        // flag is cleared R = 0
  cc_niu0,      // Input user pin 0 is cleared
  cc_iu0,       // Input user pin 0 is set
  cc_iu1,       // Input user pin 1 is set
};

//------------------------------------------------------------------
void interr(const insn_t &insn, const char *module);

int  idaapi is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);
int  idaapi OAK_get_frame_retsize(const func_t *pfn);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int may_be_func(const insn_t &insn); // can a function start here?

//------------------------------------------------------------------
struct opcode_t;

struct oakdsp_iohandler_t : public iohandler_t
{
  struct oakdsp_t &pm;
  oakdsp_iohandler_t(oakdsp_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual const char *iocallback(const ioports_t &iop, const char *line) override;
};

struct oakdsp_t : public procmod_t
{
  netnode helper;
  oakdsp_iohandler_t ioh = oakdsp_iohandler_t(*this, helper);
  ea_t xmem = BADADDR;
  int xmemsize = 0x1000;
  int procnum = -1;

  op_t *op = nullptr;       // current operand

  bool flow = false;
  bool delayed = false;
  int cycles = 0;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const ioport_t *find_port(ea_t address);
  void create_xmem(void);
  void select_device(const char *dname, int lrespect_info);
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  ea_t add_data_segm(size_t size, int offset, const char *name) const;

  inline void opreg(int reg);
  void make_o_mem(const insn_t &insn);
  bool rrrrr(insn_t &, int value, int param);
  bool sdirect(insn_t &insn, int value, int);
  bool ldirect(insn_t &insn, int value,int);
  bool A(insn_t &insn, int value,int);
  bool B(insn_t &insn, int value,int);
  bool mmnnn(insn_t &, int value,int);
  bool nnn(insn_t &insn, int value, int);
  bool ALU_ALM(insn_t &insn, int value, int param);
  bool ALB(insn_t &insn, int value, int);
  bool MUL(insn_t &insn, int value, int param);
  bool MODA_B(insn_t &insn, int value, int param);
  bool s_Imm(insn_t &insn, int value, int);
  bool s_ImmS(insn_t &, int value, int param);
  bool l_Imm(insn_t &insn, int value, int);
  bool rb_rel_short(insn_t &, int value, int);
  bool rb_rel_long(insn_t &insn, int value, int);
  bool Cond(insn_t &insn, int value, int param);
  bool xe_xt(insn_t &insn, int value, int param);
  bool lim_xx(insn_t &, int value, int);
  bool rJ_rI(insn_t &, int value,int param);
  bool rI(insn_t &, int value,int);
  bool AB(insn_t &, int value,int);
  bool ABLH(insn_t &, int value,int);
  bool indir_reg(insn_t &, int value,int param);
  bool laddr_pgm(insn_t &insn, int value,int);
  bool addr_rel_pgm(insn_t &insn, int value, int);
  bool ext_XX(insn_t &insn, int value, int);
  bool context(insn_t &insn, int value,int);
  bool swap(insn_t &, int value,int);
  bool banke(insn_t &, int value,int);
  bool cntx(insn_t &, int value,int);
  bool dmod(insn_t &, int value,int);
  bool eu(insn_t &, int,int);
  bool use_table(insn_t &insn, const opcode_t &ptr, uint code, int start, int end);
  void reset_ops(insn_t &insn);
  int ana(insn_t *_insn);

  void init_emu(void);
  ea_t calc_mem(const insn_t &insn, const op_t &x) const;
  int is_sane_insn(const insn_t &insn, int nocrefs) const;
  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  void add_near_ref(const insn_t &insn, const op_t &x, ea_t ea);
  int emu(const insn_t &insn);

  void oakdsp_header(outctx_t &ctx);
  void oakdsp_assumes(outctx_t &ctx);
  void print_segment_register(outctx_t &ctx, int reg, sel_t value);
  void oakdsp_segstart(outctx_t &ctx, segment_t *Srange) const;
  void oakdsp_segend(outctx_t &ctx, segment_t *Srange) const;
  void oakdsp_footer(outctx_t &ctx) const;
  void gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const;

  void load_from_idb();
};

extern int data_id;
#define PROCMOD_NODE_NAME "$ oakdsp"
#define PROCMOD_NAME oakdsp
#endif // _OAKDSP_HPP
