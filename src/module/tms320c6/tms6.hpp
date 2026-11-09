/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#ifndef _TMS6_HPP
#define _TMS6_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

#define PROCMOD_NAME            tms6
#define PROCMOD_NODE_NAME       "$ tms"

//-------------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct tms6_t);

//--------------------------------------------------------------------------
struct tmsinsn_t;
struct tms6_t : public procmod_t
{
  netnode helper; // supval(ea) -> branch/call info, see tgtinfo_t
  idb_listener_t idb_listener = idb_listener_t(*this);
  bool flow = false;

  ssize_t idaapi on_event(ssize_t msgid, va_list va);
  int emu(const insn_t &insn);
  void footer(outctx_t &ctx) const;
  bool outspec(outctx_t &ctx, uchar stype) const;

  void op_near(
        const insn_t &insn,
        op_t &x,
        uint32 code,
        int shift,
        uval_t mask) const;
  int make_op(
        const insn_t &insn,
        op_t &x,
        uint32 code,
        uchar optype,
        int32 v,
        bool isother) const;
  void make_pseudo(insn_t &insn) const;
  int table_insns(
        insn_t &insn,
        uint32 code,
        const tmsinsn_t *tinsn,
        bool isother) const;
  int l_ops(insn_t &insn, uint32 code) const;
  int m_ops(insn_t &insn, uint32 code) const;
  int d_ops(insn_t &insn, uint32 code) const;
  int handle_dx(insn_t &insn, const tmsinsn_t *table, uint32 code) const;
  int dx_ops(insn_t &insn, uint32 code) const;
  int dxc_ops(insn_t &insn, uint32 code) const;
  int ld_common(insn_t &insn, uint32 code, bool use_bit8) const;
  int ld15(insn_t &insn, uint32 code) const;
  int ldbase(insn_t &insn, uint32 code) const;
  int s_ops(insn_t &insn, uint32 code) const;
  int addk(insn_t &insn, uint32 code) const;
  int field_ops(insn_t &insn, uint32 code) const;
  int mvk(insn_t &insn, uint32 code) const;
  int bcond(insn_t &insn, uint32 code) const;
  int nopred(insn_t &insn, uint32 code) const;
  int ana(insn_t *_insn);
  int ana_classic(insn_t *_insn) const;
  int ana_compact(insn_t *_insn, uint32 fph) const;
  void upgrade_tnode(const netnode &old_tnode);
};
extern int data_id;

//-------------------------------------------------------------------------
struct tgtinfo_t
{
  enum type_t { CALL, BRANCH, IND_CALL, IND_BRANCH };
  type_t type;
  ea_t target;
  bool has_target() const { return type == CALL || type == BRANCH; }
  const char *get_type_name() const;
  void save_to_idb(tms6_t &pm, ea_t ea) const;
  bool restore_from_idb(const tms6_t &pm, ea_t ea);
};

//---------------------------------
// Functional units:

#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum funit_t ENUM8BIT
{
  FU_NONE,                      // No unit (NOP, IDLE)
  FU_L1, FU_L2,                 // 32/40-bit arithmetic and compare operations
                                // Leftmost 1 or 0 bit counting for 32 bits
                                // Normalization count for 32 and 40 bits
                                // 32-bit logical operations

  FU_S1, FU_S2,                 // 32-bit arithmetic operations
                                // 32/40-bit shifts and 32-bit bit-field operations
                                // 32-bit logical operations
                                // Branches
                                // Constant generation
                                // Register transfers to/from the control register file (.S2 only)

  FU_M1, FU_M2,                 // 16 x 16 bit multiply operations

  FU_D1, FU_D2,                 // 32-bit add, subtract, linear and circular address calculation
                                // Loads and stores with a 5-bit constant offset
                                // Loads and stores with 15-bit constant offset (.D2 only)
};

//---------------------------------
// Operand types:
#define o_regpair       o_idpspec0      // Register pair (A1:A0..B15:B14)
                                        // Register pair is denoted by its
                                        // even register in op.reg
                                        // (Odd register keeps MSB)

#define o_spmask        o_idpspec1      // unit mask (reg)
#define o_stgcyc        o_idpspec2      // fstg/fcyc (value)


// o_phrase: the second register is held in secreg (specflag1)
#define secreg          specflag1
// o_phrase, o_displ: mode
#define mode            specflag2

#define src2            specflag2       // for field instructions

//------------------------------------------------------------------
#define funit           segpref            // Functional unit for insn
#define cond            auxpref_u8[0]      // The condition code of instruction
#define cflags          auxpref_u8[1]      // Various bit definitions:
#  define aux_para      0x0001  // parallel execution with the next insn
#  define aux_src2      0x0002  // src2 register for immediate form of
                                // field instructions is present at "Op1.src2"
#  define aux_xp        0x0004  // X path is used
#  define aux_pseudo    0x0008  // Pseudo instruction

//------------------------------------------------------------------
// condition codes:
#define cAL  0x0 // unconditional
#define cB0  0x2 // B0
#define cnB0 0x3 // !B0
#define cB1  0x4 // B1
#define cnB1 0x5 // !B1
#define cB2  0x6 // B2
#define cnB2 0x7 // !B2
#define cA1  0x8 // A1
#define cnA1 0x9 // !A1
#define cA2  0xA // A2
#define cnA2 0xB // !A2

//------------------------------------------------------------------
// Bit definitions. Just for convenience:
#define BIT0    0x00000001
#define BIT1    0x00000002
#define BIT2    0x00000004
#define BIT3    0x00000008
#define BIT4    0x00000010
#define BIT5    0x00000020
#define BIT6    0x00000040
#define BIT7    0x00000080
#define BIT8    0x00000100
#define BIT9    0x00000200
#define BIT10   0x00000400
#define BIT11   0x00000800
#define BIT12   0x00001000
#define BIT13   0x00002000
#define BIT14   0x00004000
#define BIT15   0x00008000
#define BIT16   0x00010000
#define BIT17   0x00020000
#define BIT18   0x00040000
#define BIT19   0x00080000
#define BIT20   0x00100000
#define BIT21   0x00200000
#define BIT22   0x00400000
#define BIT23   0x00800000
#define BIT24   0x01000000
#define BIT25   0x02000000
#define BIT26   0x04000000
#define BIT27   0x08000000
#define BIT28   0x10000000
#define BIT29   0x20000000
#define BIT30   0x40000000
#define BIT31   0x80000000

//------------------------------------------------------------------
enum RegNo ENUM8BIT
{
  rA0, rA1,  rA2, rA3,  rA4,  rA5,  rA6,  rA7,
  rA8, rA9, rA10, rA11, rA12, rA13, rA14, rA15,
  rA16, rA17, rA18, rA19, rA20, rA21, rA22, rA23,
  rA24, rA25, rA26, rA27, rA28, rA29, rA30, rA31,
  rB0, rB1, rB2,  rB3,  rB4,  rB5,  rB6,  rB7,
  rB8, rB9, rB10, rB11, rB12, rB13, rB14, rB15,
  rB16, rB17, rB18, rB19, rB20, rB21, rB22, rB23,
  rB24, rB25, rB26, rB27, rB28, rB29, rB30, rB31,
  rAMR,
  rCSR,
  rIFR,
  rISR,
  rICR,
  rIER,
  rISTP,
  rIRP,
  rNRP,
  rACR,
  rADR,
  rPCE1,
  rFADCR,
  rFAUCR,
  rFMCR,
  rTSCL,
  rTSCH,
  rILC,
  rRILC,
  rREP,
  rDNUM,
  rSSR,
  rGPLYA,
  rGPLYB,
  rGFPGFR,
  rTSR,
  rITSR,
  rNTSR,
  rECR,
  rEFR,
  rIERR,
  rVcs, rVds,            // virtual registers for code and data segments
};

//------------------------------------------------------------------
// XXX this assumes the non-compact encoding
inline bool is_mvk_scst16_form(ea_t ea)
{
  return ((get_dword(ea) >> 2) & 0x1F) == 0xA;
}

//------------------------------------------------------------------
void idaapi header(outctx_t &ctx);

void idaapi segstart(outctx_t &ctx, segment_t *seg);
void idaapi segend(outctx_t &ctx, segment_t *seg);

void idaapi data(outctx_t &ctx, bool analyze_only);

int  idaapi ana(insn_t *insn);

int  idaapi is_align_insn(ea_t ea);

ea_t find_first_insn_in_packet(ea_t ea);

#endif // _TMS6_HPP
