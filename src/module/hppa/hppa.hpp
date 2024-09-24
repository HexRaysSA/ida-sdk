
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _HPPA_HPP
#define _HPPA_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <segregs.hpp>
#include <typeinf.hpp>
#include <diskio.hpp>
#include <fixup.hpp>

#define PROCMOD_NAME            hppa
#define PROCMOD_NODE_NAME       "$ hppa"

//------------------------------------------------------------------
#define PROC_MAXOP 5  // max number of operands
CASSERT(PROC_MAXOP <= UA_MAXOP);

#define aux_cndc   0x0007   // condition bits c
#define aux_cndf   0x0008   // condition bits f
#define aux_cndd   0x0010   // condition bits d
#define aux_space  0x0020   // space register present

#define o_based   o_idpspec2    // (%r5)
                                // o_phrase: %r4(%r5)
                                // o_displ:  55(%r5)
#define sid        specflag1
#define secreg     specflag2    // for o_phrase, the index register
//------------------------------------------------------------------
enum RegNo
{
  // general registers
  R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
  R8,   R9,   R10,  R11,  R12,  R13,  R14,  R15,
  R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
  R24,  R25,  R26,  DP,   R28,  R29,  SP,   R31,
  // space registers
  SR0,  SR1,  SR2,  SR3,  SR4,  SR5,  SR6,  SR7,
  // control registers
  CR0,   CR1,   CR2,   CR3,   CR4,   CR5,   CR6,   CR7,
  CR8,   CR9,   CR10,  CR11,  CR12,  CR13,  CR14,  CR15,
  CR16,  CR17,  CR18,  CR19,  CR20,  CR21,  CR22,  CR23,
  CR24,  CR25,  CR26,  CR27,  CR28,  CR29,  CR30,  CR31,
  // floating-point registers
  F0,   F1,   F2,   F3,   F4,   F5,   F6,   F7,
  F8,   F9,   F10,  F11,  F12,  F13,  F14,  F15,
  F16,  F17,  F18,  F19,  F20,  F21,  F22,  F23,
  F24,  F25,  F26,  F27,  F28,  F29,  F30,  F31,
  // register halves (valid only for fmpyadd/sub)
  F16L, F17L, F18L, F19L, F20L, F21L, F22L, F23L,
  F24L, F25L, F26L, F27L, F28L, F29L, F30L, F31L,
  F16R, F17R, F18R, F19R, F20R, F21R, F22R, F23R,
  F24R, F25R, F26R, F27R, F28R, F29R, F30R, F31R,
  // condition bits
  CA0, CA1, CA2, CA3, CA4, CA5, CA6,

  DPSEG, rVcs, rVds,    // virtual registers for code and data segments
};

//------------------------------------------------------------------
// Bit definitions.
// Note that the bit order is unusual: the LSB is BIT31
// This is a so-called big-endian bit order.
#define BIT31   0x00000001
#define BIT30   0x00000002
#define BIT29   0x00000004
#define BIT28   0x00000008
#define BIT27   0x00000010
#define BIT26   0x00000020
#define BIT25   0x00000040
#define BIT24   0x00000080
#define BIT23   0x00000100
#define BIT22   0x00000200
#define BIT21   0x00000400
#define BIT20   0x00000800
#define BIT19   0x00001000
#define BIT18   0x00002000
#define BIT17   0x00004000
#define BIT16   0x00008000
#define BIT15   0x00010000
#define BIT14   0x00020000
#define BIT13   0x00040000
#define BIT12   0x00080000
#define BIT11   0x00100000
#define BIT10   0x00200000
#define BIT9    0x00400000
#define BIT8    0x00800000
#define BIT7    0x01000000
#define BIT6    0x02000000
#define BIT5    0x04000000
#define BIT4    0x08000000
#define BIT3    0x10000000
#define BIT2    0x20000000
#define BIT1    0x40000000
#define BIT0    0x80000000

//------------------------------------------------------------------
ea_t calc_mem(ea_t ea);         // map virtual to phisycal ea

typedef int proc_t;
const proc_t PROC_HPPA = 0;    // HPPA big endian

//------------------------------------------------------------------
void interr(const insn_t &insn, const char *module);

void idaapi hppa_header(outctx_t &ctx);

void idaapi hppa_segend(outctx_t &ctx, segment_t *seg);

int  idaapi is_align_insn(ea_t ea);
int  idaapi hppa_get_frame_retsize(const func_t *);

int idaapi is_sp_based(const insn_t &insn, const op_t &x);
int is_sane_insn(const insn_t &insn, int nocrefs);
int may_be_func(const insn_t &insn);           // can a function start here?
bool is_basic_block_end(const insn_t &insn);

//--------------------------------------------------------------------------
// functions to get various fields from the instruction code
inline int opcode(uint32 code) { return (code>>26) & 0x3F; }
inline int r06(uint32 code) { return (code>>21) & 0x1F; }
inline int r11(uint32 code) { return (code>>16) & 0x1F; }
inline int r22(uint32 code) { return (code>> 5) & 0x1F; }
inline int r27(uint32 code) { return (code>> 0) & 0x1F; }
inline int get11(uint32 code)  // 11bit field for branches
{
  return ((code>>3) & 0x3FF) | ((code&4)<<(10-2));
}
inline int32 get17(uint32 code)
{
  return ((code&1) << 16)
       | (r11(code) << 11)
       | get11(code);
}
inline sval_t as21(uint32 x)
{
  //           1         2
  // 012345678901234567890  bit number
  // 2         1
  // 098765432109876543210  shift amount
  x =    (((x>>12) & 0x003) << 0)  //  2: x{7..8}
       | (((x>>16) & 0x01F) << 2)  //  5: x{0..4}
       | (((x>>14) & 0x003) << 7)  //  2: x{5..6}
       | (((x>> 1) & 0x7FF) << 9)  // 11: x{9..19}
       | (((x>> 0) & 0x001) <<20); //  1: x{20}
  return int32(x << 11);
}
//--------------------------------------------------------------------------
// type system functions
bool calc_hppa_arglocs(func_type_data_t *fti);
int use_hppa_regarg_type(ea_t ea, const funcargvec_t &rargs);
void use_hppa_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);

//--------------------------------------------------------------------------
struct hppa_cf_t;
struct hppa_t : public procmod_t
{
  // altval(-1) -> idpflags
  // altval(ea) -> function frame register or 0
  netnode helper;

  ioports_t syscalls;

#define IDP_SIMPLIFY 0x0001     // simplify instructions
#define IDP_PSW_W    0x0002     // W-bit in PSW is set
#define IDP_MNEMONIC 0x0004     // use mnemonic register names
  ushort idpflags = IDP_SIMPLIFY;
  inline bool dosimple(void)      { return (idpflags & IDP_SIMPLIFY) != 0; }
  inline bool psw_w(void)         { return (idpflags & IDP_PSW_W) != 0; }
  inline bool mnemonic(void)      { return (idpflags & IDP_MNEMONIC) != 0; }
  inline int assemble_16(int x, int y)
  {
    if ( psw_w() )
    {
      int r = 0;
      if ( y & 1 )
      {
        x ^= 3;
        r = 0x8000;
      }
      return ((y>>1) & 0x1FFF) | (x<<13) | r;
    }
    return ((y>>1) & 0x1FFF) | ((y&1) ? 0xE000 : 0);
  }
  inline int get_ldo(uint32 code) { return assemble_16((code>>14)&3,code & 0x3FFF); }

  int ptype = 0;    // processor type
  ea_t got = BADADDR;
  // custom fixups and refinfo
  hppa_cf_t *hppa_cf = nullptr;

  bool flow = false;
  ea_t oldea = BADADDR;
  int oldreg = -1;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *get_syscall_name(int syscall);
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);
  void handle_new_flags(bool save=true);
  void init_custom_refs();
  void term_custom_refs();
  void setup_got(void);
  int ana(insn_t *_insn);
  int emu(const insn_t &insn);
  bool is_frreg(const insn_t &insn, int reg);
  void process_operand(const insn_t &insn, const op_t &x, bool isAlt, bool isload);
  void trace_sp(const insn_t &insn);
  bool create_func_frame(func_t *pfn);
  void add_near_ref(const insn_t &insn, const op_t &x, ea_t ea);
  ea_t get_dp(const insn_t &insn) const;
  ea_t calc_possible_memref(const insn_t &insn, const op_t &x);
  uval_t idaapi r11_get_value(const fixup_handler_t * /*fh*/, ea_t ea);
  char *build_insn_completer(const insn_t &insn, uint32 code, char *buf, size_t bufsize);
  void hppa_assumes(outctx_t &ctx);   // function to produce assume directives
  void hppa_segstart(outctx_t &ctx, segment_t *Srange) const;
  void hppa_footer(outctx_t &ctx) const;
  void use_hppa_arg_types(ea_t ea, func_type_data_t *fti, funcargvec_t *rargs);

  void save_idpflags() { helper.altset(-1, idpflags); }
  void load_from_idb();
};
extern int data_id;

#endif // _HPPA_HPP
