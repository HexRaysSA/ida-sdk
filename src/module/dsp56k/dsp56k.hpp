
#ifndef _DSP56K_HPP
#define _DSP56K_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include "../iohandler.hpp"
#define PROCMOD_NAME            dsp56k
#define PROCMOD_NODE_NAME       "$ " QSTRINGIZE(PROCMOD_NAME)

//------------------------------------------------------------------
// DSP56K instruction may have many operands. We keep them separately
// in the following structure.

struct addargs_t
{
  ea_t ea;
  int nargs;
  op_t args[4][2];

  addargs_t() : ea(BADADDR), nargs(0) { memset(args, 0, sizeof(args)); }
};

//------------------------------------------------------------------
struct dsp56k_iohandler_t : public iohandler_t
{
  struct dsp56k_t &pm;
  dsp56k_iohandler_t(dsp56k_t &_pm, netnode &nn) : iohandler_t(nn), pm(_pm) {}
  virtual const char *iocallback(const ioports_t &iop, const char *line) override;
};

struct dsp56k_t : public procmod_t
{
  netnode helper;
  dsp56k_iohandler_t ioh = dsp56k_iohandler_t(*this, helper);
  ea_t xmem = BADADDR;
  ea_t ymem = BADADDR;
  op_t *op = nullptr;       // current operand
  addargs_t aa;
  int xmemsize = 0x10000;
  int ymemsize = 0x10000;
  int procnum = -1;   // 0 - dsp56k, 1 - dsp561xx, 2 - dsp563xx, 3 - dsp566xx
  bool flow = false;

  inline bool is561xx(void) const { return procnum == 1; }
  inline bool is563xx(void) const { return procnum == 2; }
  inline bool is566xx(void) const { return procnum == 3; }

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  const ioport_t *find_port(ea_t address);
  void create_xmem_ymem(void);
  void select_device(const char *dname, int resp_info);
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  ea_t calc_mem(const insn_t &insn, const op_t &x) const;
  ea_t AdditionalSegment(asize_t size, int offset, const char *name) const;
  void handle_operand(
        const insn_t &insn,
        const op_t &x,
        flags64_t F,
        bool is_forced,
        bool isload);
  int emu(const insn_t &insn);
  void header(outctx_t &ctx);
  void set_cpu(int procno);
  bool D_EE(insn_t &insn, int value);
  bool D_DDDDD(insn_t &insn, int value);
  bool D_ff(const insn_t &insn, int value, int reg_bank);
  bool D_df(insn_t &insn, int value, int reg_bank);
  bool S_xi(insn_t &, int value);
  bool D_ximm(insn_t &insn, int /*value*/);
  bool S_ximm(insn_t &insn, int value);
  bool S_sssss(insn_t &, int value);
  bool S_ssss(insn_t &, int value);
  bool D_xih(insn_t &, int value);
  bool S_xih(insn_t &insn, int value);
  bool SD_d(insn_t &insn, int value);
  bool SS_JJJd(insn_t &insn, int value);
  bool SD_JJJd(insn_t &insn, int value);
  bool SD_Jd(insn_t &insn, int value);
  bool D_d(insn_t &insn, int value);
  bool S_S(insn_t &insn, int value);
  bool SD_JJd(insn_t &insn, int value);
  bool D_dddd(insn_t &insn, int value);
  bool D_ddddd(insn_t &insn, int value);
  bool S_ddddd(insn_t &insn, int value);
  bool D_LLL(insn_t &insn, int value);
  bool D_sss(insn_t &insn, int value);
  bool S_sss(insn_t &insn, int value);
  bool D_qqq(insn_t &insn, int value);
  bool S_qqq(insn_t &insn, int value);
  bool S_qq(insn_t &insn, int value);
  bool S_QQ(insn_t &insn, int value);
  bool S_gggd(insn_t &insn, int value);
  bool D_MMRRR(insn_t &, int value);
  bool S_MMRRR(insn_t &insn, int value);
  bool D_MMRRR_XY(insn_t &, int value);
  bool D_pppppp(insn_t &, int value);
  bool S_pppppp(insn_t &insn, int value);
  bool D_qqqqqq(insn_t &, int value);
  bool S_qqqqqq(insn_t &insn, int value);
  bool D_qXqqqqq(insn_t &insn, int value);
  bool D_DDDDDD(insn_t &insn, int value);
  bool S_DDDDDD(insn_t &insn, int value);
  bool D_DDDD(insn_t &insn, int value);
  bool D_RRR(insn_t &insn, int value);
  bool S_RRR(insn_t &insn, int value);
  void make_o_mem(insn_t &insn);
  bool D_mMMMRRR(insn_t &insn, int value);
  bool S_mMMMRRR(insn_t &insn, int value);
  bool D_aaaaaa(insn_t &insn, int value);
  bool S_aaaaaa(insn_t &insn, int value);
  bool D_MMMRRR(insn_t &insn, int value);
  bool S_MMMRRR(insn_t &insn, int value);
  bool P_type(insn_t &, int);
  bool AAE(insn_t &insn, int);
  bool D_PC_dispL(insn_t &insn, int value);
  bool S_PC_dispL(insn_t &insn, int value);
  bool D_PC_dispS(insn_t &insn, int value);
  bool D_PC_RRR(insn_t &, int value);
  bool D_RRR_dispL(insn_t &insn, int value);
  bool D_RRR_dispS(insn_t &, int value);
  bool S_RR_dispS(insn_t &, int value);
  bool AA(insn_t &, int value);
  bool D_F(insn_t &insn, int value);
  bool S_F(insn_t &insn, int value);
  bool CCCC(insn_t &insn, int value);
  bool s(insn_t &insn, int value);
  bool ss(insn_t &insn, int value);
  bool SD_IIII(insn_t &insn, int value);
  bool D_zRR(insn_t &, int value);
  bool D_mRR(insn_t &, int value);
  bool D_RRm(insn_t &insn, int value);
  bool D_RR11m(insn_t &insn, int value);
  bool D_MMRR(insn_t &, int value);
  bool S_MMRR(insn_t &insn, int value);
  bool D_RR0MM(insn_t &insn, int value);
  bool D_qRR(insn_t &, int value);
  bool D_HHH(insn_t &, int value);
  bool D_HH(insn_t &, int value);
  bool SD_mWRRHHH(insn_t &insn, int value);
  bool S_FJJJ(insn_t &insn, int value);
  bool S_QQQ(insn_t &, int value);
  bool S_QQ2(insn_t &, int value);
  bool S_QQQQ(insn_t &, int value);
  bool S_Fh0h(insn_t &insn, int value);
  bool S_uFuuu_add(insn_t &insn, int value);
  bool S_uFuuu_sub(insn_t &insn, int value);
  bool D_RR(insn_t &insn, int value);
  bool D_NN(insn_t &insn, int value);
  bool DB_RR(insn_t &, int value);
  bool D_PC_RR(insn_t &, int value);
  bool DX_RR(insn_t &insn, int value);
  bool S_RR(insn_t &insn, int value);
  bool m_A_B(insn_t &, int /*value*/);
  bool IF(insn_t &, int /*value*/);
  bool IFU(insn_t &, int /*value*/);
  bool S_i(insn_t &insn, int value);
  bool SD_TT(insn_t &insn, int value);
  bool S_BBBiiiiiiii(insn_t &, int value);
  bool D_Pppppp(insn_t &insn, int value);
  bool D_ppppp(insn_t &insn, int value);
  bool D_aaaaa(insn_t &insn, int value);
  bool S_DDDDD(insn_t &insn, int value);
  bool D_xi(insn_t &, int value);
  bool D_xi16(insn_t &, int value);
  bool D_xi_adr_16(insn_t &insn, int value);
  bool D_DD(insn_t &insn, int value);
  bool S_DD(insn_t &insn, int value);
  bool D_Z(insn_t &, int value);
  bool D_t(insn_t &insn, int value);
  bool SD_F00J(insn_t &insn, int value);
  bool D_PC_eeeeee(insn_t &insn, int value);
  bool D_PC_aaaaaaaa(insn_t &insn, int value);
  bool D_BBBBBBBB(insn_t &, int value);
  bool is_valid_insn(ushort proc);
  bool disassemble_parallel_move(insn_t &insn, int i, int value);
  bool decode_XY_R_mem(insn_t &insn, int value);
  bool recognize_parallel_move_class1(insn_t &insn, int value);
  bool recognize_parallel_move_class1_3(insn_t &insn, int value);
  bool recognize_parallel_move_class2(insn_t &insn, int value);
  bool recognize_parallel_move_class3(insn_t &insn, int value);
  bool is_parallel_move(insn_t &insn, int value);
  bool use_table(
        insn_t &insn,
        const struct opcode_t *table,
        uint32 code,
        int entry,
        int start,
        int end);
  int ana_61(insn_t &insn);
  int ana_6x(insn_t &insn);
  int ana(insn_t *_insn);
  bool X_type(insn_t &, int);
  bool Y_type(insn_t &, int);
  bool mem_type(insn_t &, int value);
  bool space(insn_t &insn, int);
  bool sign(insn_t &, int value);
  int is_sane_insn(const insn_t &insn, int /*nocrefs*/) const;
  void fill_additional_args(const insn_t &insn) const;
  void switch_to_additional_args(insn_t &);
  inline void opreg(insn_t &, int reg);
  void reset_ops(insn_t &insn);
  void add_near_ref(const insn_t &insn, const op_t &x, ea_t ea);

  void segstart(outctx_t &ctx, segment_t *seg) const;
  void segend(outctx_t &ctx, segment_t *seg) const;
  void footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;

//------------------------------------------------------------------

#define aux_cc     0x000F   // condition code
#define aux_su     0x0003   // sign/unsing code

#define phtype    specflag1 // o_phrase: phrase type
// 0 (Rn)-n
// 1 (Rn)+Nn
// 2 (Rn)-
// 3 (Rn)+
// 4 (Rn)
// 5 (Rn+Nn)
// 7 -(Rn)
// 8 $+Rn
// 9 (a1)
// 10 (b1)

#define amode           specflag2 // addressing mode
#define amode_ioshort   0x01  // <<
#define amode_short     0x02  // <
#define amode_long      0x04  // >
#define amode_neg       0x08  // -
#define amode_x         0x10  // X:
#define amode_y         0x20  // Y:
#define amode_p         0x40  // P:
#define amode_l         0x80  // L:

#define imode           specflag3 // IF mode
#define imode_if        0x01 // IFcc
#define imode_ifu       0x02 // IFUcc

#define o_iftype        o_idpspec0 // IF type

#define o_vsltype       o_idpspec1 // VSL 2-nd operand type

//------------------------------------------------------------------
#define UAS_GNU 0x0001          // GNU assembler
//------------------------------------------------------------------
enum RegNo ENUM_SIZE(uint16)
{
  // data arithmetic logic unit
  X, X0, X1,
  Y, Y0, Y1,
  // accumulator registers
  A, A0, A1, A2,
  B, B0, B1, B2,
  AB,    // a1:b1
  BA,    // b1:a1
  A10,   // a1:a0
  B10,   // b1:b0
  // address generation unit (AGU)
  R0, R1, R2, R3, R4, R5, R6, R7,  // pointers
  N0, N1, N2, N3, N4, N5, N6, N7,  // offsets
  M0, M1, M2, M3, M4, M5, M6, M7,  // modifiers
  // Program Control Unit
  PC,  // Program Counter (16 Bits)
  MR,  // Mode Register (8 Bits)
  CCR, // Condition Code Register (8 Bits)
  SR,  // Status Register (MR:CCR, 16 Bits)
  OMR, // Operating Mode Register (8 Bits)
  LA,  // Hardware Loop Address Register (16 Bits)
  LC,  // Hardware Loop Counter (16 Bits)
  SP,  // System Stack Pointer (6 Bits)
  SS,  // System Stack RAM (15X32 Bits)
  SSH, // Upper 16 Bits of the Contents of the Current Top of Stack
  SSL, // Lower 16 Bits of the Contents of the Current Top of Stack
  SZ,  // Stack Size register
  SC,  // Stack Counter register
  EP,  // Extension Pointer register
  VBA, // Vector Base Address Register

  vCS, vDS,       // virtual registers for code and data segments

};


//------------------------------------------------------------------
// condition codes
enum cc_t
{
  cc_CC, // carry clear (higher or same) C=0
  cc_GE, // greater than or equal N xor V=0
  cc_NE, // not equal Z=0
  cc_PL, // plus N=0
  cc_NN, // not normalized Z+(^U&^E)=0
  cc_EC, // extension clear E=0
  cc_LC, // limit clear L=0
  cc_GT, // greater than Z+(N xor V)=0
  cc_CS, // carry set (lower) C=1
  cc_LT, // less than N xor V=1
  cc_EQ, // equal Z=1
  cc_MI, // minus N=1
  cc_NR, // normalized Z+(^U&^E)=1
  cc_ES, // extension set E=1
  cc_LS, // limit set L=1
  cc_LE, // less than or equal Z+(N xor V)=1
};

//------------------------------------------------------------------

enum PMoveClass
{
  cl_0 = 0,     // No Parallel move
  cl_1,         // X Memory Data Move (common)
  cl_1_3,       // X Memory Data Move with short displacement
  cl_2,         // Dual X Memory Data Read
  cl_3,         // X Memory Data Write and Register Data Move
};

//------------------------------------------------------------------
// signed/unsigned codes
enum su_t
{
  s_SS, // signed * signed
  s_SU, // signed * unsigned
  s_UU, // unsigned * unsigned
};

// Make sure that the 'aa' structure is up to date.
void fill_additional_args(const insn_t &insn);

//------------------------------------------------------------------
void interr(const insn_t *insn, const char *module);

int  idaapi ana(insn_t *insn);
int  idaapi emu(const insn_t &insn);

int  idaapi is_align_insn(ea_t ea);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);

#endif // _DSP56K_HPP
