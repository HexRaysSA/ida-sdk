/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _H8_HPP
#define _H8_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"
#include "../iohandler.hpp"

#define PROCMOD_NAME      h8
#define PROCMOD_NODE_NAME "$ h8"

//------------------------------------------------------------------
// processor types

typedef uint16 proctype_t;

static const proctype_t none  = 0;
static const proctype_t P300  = 0x0001;     // H8/300, H8/300H
static const proctype_t P2000 = 0x0002;     // H8S/2000
static const proctype_t P2600 = 0x0004;     // H8S/2600
static const proctype_t PSX   = 0x0008;     // H8SX

// assume 'Normal mode' as the default
static const proctype_t MODE_MASK= 0xF000;
static const proctype_t MODE_MID = 0x1000;  // H8SX
static const proctype_t MODE_ADV = 0x2000;  // H8/300H (!), H8S, H8SX
static const proctype_t MODE_MAX = 0x3000;  // H8SX

// submodel
static const proctype_t SUBM_MASK= 0x0F00;
static const proctype_t SUBM_TINY= 0x0100;  // H8/300H Tiny model
                                            // full insn set and normal mode

static const proctype_t P30A = P300  | MODE_ADV;
static const proctype_t P26A = P2600 | MODE_ADV;

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  R0,    R1,    R2,    R3,    R4,    R5,    R6,    R7, SP=R7,
  E0,    E1,    E2,    E3,    E4,    E5,    E6,    E7,
  R0H,   R1H,   R2H,   R3H,   R4H,   R5H,   R6H,   R7H,
  R0L,   R1L,   R2L,   R3L,   R4L,   R5L,   R6L,   R7L,
  ER0,   ER1,   ER2,   ER3,   ER4,   ER5,   ER6,   ER7,
  // don't change registers order above this line
  MACL, MACH,
  PC,
  CCR, EXR,
  rVcs, rVds,   // virtual registers for code and data segments
  VBR, SBR,     // base or segment registers
};

//---------------------------------
// Operand types:

/*
o_reg     1 Register direct
            Rn
            x.reg
o_phrase  2 Register indirect
            @ERn
            x.phrase contains register number
            x.phtype contains phrase type (normal, post, pre)
o_displ   3 Register indirect with displacement
            @(d:2,ERn)/@(d:16,ERn)/@(d:32,ERn)
            x.reg, x.addr, disp_16, disp_32, disp_2
o_displ   4 Index register indirect with displacement
            @(d:16, RnL.B)/@(d:16,Rn.W)/@(d:16,ERn.L)
            @(d:32, RnL.B)/@(d:32,Rn.W)/@(d:32,ERn.L)
            x.displtype = dt_regidx,
            x.reg,
            x.addr - disp_16, disp_32, idx_byte/word/long
o_phrase  5 Register indirect with post-inc/pre-dec/pre-inc/post-dec
            @ERn+/@-ERn/@+ERn/@ERn-
o_mem     6 Absolute address
            @aa:8/@aa:16/@aa:24/@aa:32
            x.memtype = @aa:8 ? mem_sbr : mem_direct
            x.addr
o_imm     7 Immediate
            #x:2/#xx:3/#xx:4/#xx:5/#xx:8/#xx:16/#xx:32
            #1/#2/#4/#8/#16
            x.value
o_near    8 Program-counter relative
            @(d:8,PC)/@(d:16,PC)
o_pcidx   9 Program-counter relative with index register
            @(RnL.B,PC)/@(Rn.W,PC)/@(ERn.L,PC)
            x.reg
o_mem    10 Memory indirect
            @@aa:8
            x.memtype = mem_ind
            x.addr
o_mem    11 Extended memory indirect
            @@vec:7
            x.memtype = mem_vec7
            x.addr
o_reglist   Register list
            x.reg, x.nregs
o_displ     first operand of MOVA insn
            @(d16,<EA>.[BW])/@(d32:<EA>.[BW])
            x.displtype = dt_movaop1,
            x.addr,
            x.szfl - disp_16/disp_32/idx_byte/idx_word
            x.idxt - <EA> type
            <EA> type:
            o_reg - x.reg EQ to o_regidx
            o_phrase - x.phrase,x.idxdt
            o_displ - x.reg,x.value,x.idxsz,x.idxdt
            o_regidx - x.reg,x.value,x.idxsz,x.idxdt
            o_mem - x.value,x.idsz,x.idxdt
*/

#define o_reglist       o_idpspec0
#define o_pcidx         o_idpspec1

#define phtype          specflag1       // phrase type:
const int ph_normal     = 0;            // just simple indirection
const int ph_pre_dec    = 0x10;         // -@Rn ^ 3 -> @Rn+
const int ph_post_inc   = 0x13;         // @Rn+
const int ph_pre_inc    = 0x11;         // +@ERn
const int ph_post_dec   = 0x12;         // @ERn-

#define displtype       specflag1       // displ type:
const int dt_normal     = 0;            // Register indirect with displacement
const int dt_regidx     = 1;            // Index register indirect with displacement
const int dt_movaop1    = 2;            // first operand of MOVA insn

#define szfl            specflag2       // various operand size flags
                                        // index target
const int idx_byte      = 0x01;         // .b
const int idx_word      = 0x02;         // .w
const int idx_long      = 0x04;         // .l
                                        // size of operand displ
const int disp_16       = 0x10;         // 16bit displacement
const int disp_24       = 0x20;         // 24bit displacement
const int disp_32       = 0x40;         // 32bit displacement
const int disp_2        = 0x80;         //  2bit displacement

#define memtype         specflag1       // mem type:
const int mem_direct    = 0;            // x.addr - direct memory ref
const int mem_sbr       = 1;            // SBR based @aa:8
const int mem_vec7      = 2;            // @@vec:7
const int mem_ind       = 3;            // @@aa:8

#define nregs           specflag1       // o_reglist: number of registers

// MOVA Op1 store
#define idxt            specflag3       // MOVA: optype_t of index
#define idxsz           specflag4       // MOVA: size of index
#define idxdt           specval         // MOVA: index phtype,displtype,memtype

//------------------------------------------------------------------
const uint16 aux_none = 0;              // no postfix
const uint16 aux_byte = 1;              // .b postfix
const uint16 aux_word = 2;              // .w postfix
const uint16 aux_long = 3;              // .l postfix

//------------------------------------------------------------------
#define UAS_HEW         0x0001  // HEW assembler

//------------------------------------------------------------------
ea_t calc_mem(const insn_t &insn, ea_t ea); // map virtual to physical ea
ea_t calc_mem_sbr_based(const insn_t &insn, ea_t ea); // map virtual @aa:8 physical ea

void idaapi h8_segend(outctx_t &ctx, segment_t *seg);

int  idaapi h8_is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const insn_t &insn, const op_t &x);
bool idaapi is_return_insn(const insn_t &insn);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int may_be_func(const insn_t &insn);           // can a function start here?
int is_sane_insn(const insn_t &insn, int nocrefs);
bool idaapi h8_is_switch(switch_info_t *si, const insn_t &insn);

//------------------------------------------------------------------
struct h8_iohandler_t : public iohandler_t
{
  h8_iohandler_t(netnode &nn) : iohandler_t(nn) {}
  virtual void get_cfg_filename(char *buf, size_t bufsize) override;
};

struct h8_t : public procmod_t
{
  netnode helper;
  h8_iohandler_t ioh = h8_iohandler_t(helper);
  proctype_t ptype = none;   // contains all bits which correspond
                             // to the supported processors set
  char show_sizer = -1;
  uchar code = 0;
  uchar code3 = 0;
  bool flow = false;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  inline bool advanced(void) { return (ptype & MODE_MASK) != 0; }
  inline bool is_h8s(void)   { return (ptype & (P2000|P2600)) != 0; }
  inline bool is_h8sx(void)  { return (ptype & PSX) != 0; }
  inline bool is_tiny(void)  { return (ptype & SUBM_TINY) != 0; }

  inline regnum_t r0(void) { return advanced() ? ER0 : R0; }

  inline bool is_hew_asm(void) const
  {
    return (ash.uflag & UAS_HEW) != 0;
  }

  void load_symbols(void);
  const char *find_sym(ea_t address);
  const char *set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/);
  void set_cpu(int cpuno);
  int get_displ_outf(const op_t &x, flags64_t F);
  ea_t trim_ea_branch(ea_t ea) const;   // trim address according to proc mode
  void h8_header(outctx_t &ctx);
  void trimaddr(op_t &x);
  void opatHL(op_t &x, op_dtype_t dtyp);
  void opdsp16(insn_t &insn, op_t &x, op_dtype_t dtyp);
  void opdsp32(insn_t &insn, op_t &x, op_dtype_t dtyp);
  bool read_operand(insn_t &insn, op_t &x, ushort flags);
  bool map014(insn_t &insn);
  bool map4(insn_t &insn);
  int ana(insn_t *pinsn);
  int exit_40(insn_t &insn);
  int exit_54_56(insn_t &insn, uint8 rts, uint8 rtsl);
  int exit_59_5D(insn_t &insn, uint16 jump, uint16 branch);
  int exit_7B(insn_t &insn);
  int h8sx_03(insn_t &insn);
  int h8sx_0A(insn_t &insn);
  int h8sx_1A(insn_t &insn);
  int h8sx_6A(insn_t &insn);
  void handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload);
  int h8sx_6B(insn_t &insn);
  int h8sx_78(insn_t &insn);
  int h8sx_79(insn_t &insn);
  int h8sx_7A(insn_t &insn);
  bool h8sx_010D(insn_t &insn);
  bool h8sx_010E(insn_t &insn);
  bool insn_ldc(insn_t &insn, uint8 byte2, regnum_t reg);
  bool h8sx_01_exr(insn_t &insn);
  bool insn_mova(insn_t &insn);
  int insn_mova_reg(insn_t &insn, uint8 opcode, uint8 rs, bool is_reg_equal);
  bool h8sx_01_other(insn_t &insn);
  bool insn_addx_imm(insn_t &insn, op_t &x, uint8 byte2, uint8 byte3, uint16 mask, bool check_byte3);
  bool insn_bra(insn_t &insn, uint8 byte2, uint8 byte3);
  bool insn_bfld_bfst(insn_t &insn, uint8 byte2, uint8 byte3, bool is_bfld);
  bool use_leaf_map(insn_t &insn, const struct map_t *m, uint8 idx);
  bool op_from_byte(insn_t &insn, op_t &x, uint8 byte2);
  bool read_1st_op(insn_t &insn, uint8 byte2, uint8 byte3_hiNi);
  bool op_phrase(const insn_t &insn, op_t &x, uint8 reg, int pht, op_dtype_t dtype=dt_byte);
  bool op_displ_regidx(insn_t &insn, op_t &x, uint8 selector, bool is_32, uint8 reg);
  int emu(const insn_t &insn);
  int h8_get_frame_retsize(const func_t *);
  int h8sx_7C(insn_t &insn);
  int h8sx_7D(insn_t &insn);
  bool h8sx_010_01dd(insn_t &insn, uint16 postfix);
  bool h8sx_ldm(insn_t &insn);
  bool insn_mac(insn_t &insn);
  bool insn_tas(insn_t &insn);
  bool op_phrase_prepost(const insn_t &insn, op_t &x, uint8 reg, uint8 selector);
  bool op_phrase_displ2(const insn_t &insn, op_t &x, uint8 reg, uint8 displ);
  int h8sx_01(insn_t &insn);
  bool h8sx_010_00dd(insn_t &insn);
  int h8sx_7E(insn_t &insn);
  int h8sx_7F(insn_t &insn);
  int unpack_8bit_shift(const map_t *m, insn_t &insn, uint16 itype, uint16 itype2);
  int h8sx_10(insn_t &insn);
  int h8sx_11(insn_t &insn);
  bool h8sx_0108(insn_t &insn);
  bool h8sx_0109_010A(insn_t &insn,op_t &regop, op_t &genop);
  int h8sx_0F(insn_t &insn);
  int h8sx_1F(insn_t &insn);
  void add_code_xref(const insn_t &insn, const op_t &x, ea_t ea);

  void h8_assumes(outctx_t &ctx);
  void trace_sp(const insn_t &insn) const;
  bool get_op_value(uval_t *value, const insn_t &_insn, const op_t &x) const;
  bool spoils(const insn_t &insn, int reg) const;
  void check_base_reg_change_value(const insn_t &insn) const;
  void h8_segstart(outctx_t &ctx, segment_t *Srange) const;
  void h8_gen_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v) const;
  void h8_footer(outctx_t &ctx) const;

  void load_from_idb();
};
extern int data_id;

#endif // _H8_HPP
