/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef __I860_HPP
#define __I860_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

                                // Intel 860 insn.auxpref bits:
#define aux_dual        0x1     // is dual
#define aux_sdbl        0x2     // source double
#define aux_rdbl        0x4     // result double

#define _PT_860XR       0x01                    // Intel 860 XR
#define _PT_860XP       0x02                    // Intel 860 XP

#define PT_860XP         _PT_860XP
#define PT_860XR        (PT_860XP | _PT_860XR)

//------------------------------------------------------------------------

enum i860RegNo
{
  R_r0,  R_r1,  R_r2,  R_r3,  R_r4,  R_r5,  R_r6,  R_r7,
  R_r8,  R_r9,  R_r10, R_r11, R_r12, R_r13, R_r14, R_r15,
  R_r16, R_r17, R_r18, R_r19, R_r20, R_r21, R_r22, R_r23,
  R_r24, R_r25, R_r26, R_r27, R_r28, R_r29, R_r30, R_r31,

  R_f0,  R_f1,  R_f2,  R_f3,  R_f4,  R_f5,  R_f6,  R_f7,
  R_f8,  R_f9,  R_f10, R_f11, R_f12, R_f13, R_f14, R_f15,
  R_f16, R_f17, R_f18, R_f19, R_f20, R_f21, R_f22, R_f23,
  R_f24, R_f25, R_f26, R_f27, R_f28, R_f29, R_f30, R_f31,

  R_fir,
  R_psr,
  R_dirbase,
  R_db,
  R_fsr,
  R_epsr,
  R_bear,
  R_ccr,
  R_p0,
  R_p1,
  R_p2,
  R_p3,
  R_vcs,R_vds           // virtual segment registers
};

#define bit0    (1<<0)
#define bit1    (1<<1)
#define bit2    (1<<2)
#define bit3    (1<<3)
#define bit4    (1<<4)
#define bit5    (1<<5)
#define bit6    (1<<6)
#define bit7    (1<<7)
#define bit8    (1<<8)
#define bit9    (1<<9)
#define bit10   (1<<10)
#define bit11   (1<<11)
#define bit12   (1<<12)
#define bit13   (1<<13)
#define bit14   (1<<14)
#define bit15   (1<<15)
#define bit16   (1<<16)
#define bit17   (1<<17)
#define bit18   (1<<18)
#define bit19   (1<<19)
#define bit20   (1<<20)
#define bit21   (1<<21)
#define bit22   (1<<22)
#define bit23   (1<<23)
#define bit24   (1<<24)
#define bit25   (1<<25)
#define bit26   (1<<26)
#define bit27   (1<<27)
#define bit28   (1<<28)
#define bit29   (1<<29)
#define bit30   (1<<30)
#define bit31   (1<<31)

#define Rbit    bit7            // Result is double precision
#define Sbit    bit8            // Source is double precision
#define Dbit    bit9            // Dual Instruction
#define Pbit    bit10           // Pipelining

void    idaapi i860_header(outctx_t &ctx);
int     idaapi i860_ana(insn_t *_insn);

//------------------------------------------------------------------------
struct i860_t : public procmod_t
{
  int pflag = 0;
  inline int is860XP(void) { return (pflag & PT_860XP) != 0; }

  uint32 code = 0;
  inline uint16 op_s1(void) {  return int((code>>11)) & 31; }
  inline uint16 op_ds(void) {  return int((code>>16)) & 31; }
  inline uint16 op_s2(void) {  return int((code>>21)) & 31; }
  inline int isDS(void)   { return (code & (Sbit|Rbit)) == Sbit; }   // prec .ds
  inline int isSSDD(void) { return (code & Sbit) == (code & Rbit); } // prec .ss .dd
  inline int isSDDD(void) { return (code & Rbit) != 0; }             // prec .sd .dd

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  int op_ctl(op_t &x);
  void set_cpu(int procnum);
  void COREunit(insn_t &insn);
  int i860_ana(insn_t *_insn);
  void op_s1ni(op_t &x);
  void op_s2(op_t &x);
  void op_fs1(op_t &x);
  void op_fs2(op_t &x);
  void op_s1s(op_t &x);
  void op_s1u(op_t &x);
  void op_s1s2(op_t &x);
  void op_dest(op_t &x);
  void op_fdest(op_t &x);
  char dsize_28_0(void) const;
  char dsize_1_2(void) const;
  char dsize_10_9(void) const;
  void op_stoff(op_t &x);
  void op_bteoff(insn_t &insn, op_t &x);
  void op_lbroff(insn_t &insn, op_t &x) const;
  void op_ainc(op_t &x);
  void FPunit(insn_t &insn);

  int i860_emu(const insn_t &insn) const;
  bool handle_operand(const insn_t &insn, const op_t &x, bool isload) const;
  void i860_segstart(outctx_t &ctx, segment_t *Sarea) const;
  void i860_footer(outctx_t &ctx) const;
};
#endif
