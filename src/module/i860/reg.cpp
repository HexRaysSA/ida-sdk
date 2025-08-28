/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i860.hpp"

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
              // r0 == 0 always
              // r3 - stack frame pointer
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10","r11","r12","r13","r14","r15",
  "r16","r17","r18","r19","r20","r21","r22","r23",
  "r24","r25","r26","r27","r28","r29","r30","r31",
              // f0,f1 == 0 always
  "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
  "f8", "f9", "f10","f11","f12","f13","f14","f15",
  "f16","f17","f18","f19","f20","f21","f22","f23",
  "f24","f25","f26","f27","f28","f29","f30","f31",
  "fir",      // Fault Instruction Register (read-only)
  "psr",      // Processor Status Register                 Can Modify
              // 0 - BR       Break Read                   only supervisor
              // 1 - BW       Break Write                  only supervisor
              // 2 - CC       Condition Code
              // 3 - LCC      Loop Condition Code
              // 4 - IM       Interrupt Mode               only supervisor
              //                ena/disa external intrs
              //                on INT pin
              // 5 - PIM      Previous Interrupt Mode      only supervisor
              // 6 - U        User Mode                    only supervisor
              //                1 - user mode
              //                0 - supervisor
              // 7 - PU       Previous User Mode           only supervisor
              // 8 - IT       Instruction Trap             only supervisor
              // 9 - IN       Interrupt                    only supervisor
              // 10- IAT      Instruction Access Trap      only supervisor
              // 11- DAT      Data Access Trap             only supervisor
              // 12- FT       Floating Point Trap          only supervisor
              // 13- DS       Delayed Switch               only supervisor
              // 14- DIM      Dual Instruction Mode        only supervisor
              // 15- KNF      Kill Next FP Instruction     only supervisor
              // 16-          Reserved
              // 17-21 SC     Shift Count
              // 22-23 PS     Pixel Size
              //                      00 - 8
              //                      01 - 16
              //                      10 - 32
              //                      11 - undefined
              // 24-31 PM     Pixel Mask
  "dirbase",  // Directory Base Register
              // 0  ATE       Address Translation Enable
              // 1-3 DPS      DRAM Page Size
              //               ignore 12+DPS bits
              // 4  BL        Bus Lock
              // 5  ITI       Cache and TLB Invalidate
              // 6  LB        Late Back-off Mode
              // 7  CS8       Code Size 8-bit
              // 8-9 RB       Replacement Block
              // 10-11 RC     Replacement Control
              // 12-31 DTB    Directory Table Base
  "db",       // Data Breakpoint Register
  "fsr",      // Floating Point Status Register
              // 0   FZ       Flush Zero
              // 1   TI       Trap Inexact
              // 2-3 RM       Rounding Mode
              //                      0 - nearest or even
              //                      1 - down
              //                      2 - up
              //                      3 - chop
              // 4   U        Update Bit
              // 5   FTE      Floating Point Trap Enable
              // 6            Reserved
              // 7   SI       Sticky Inexact
              // 8   SE       Source Exception
              // 9   MU       Multiplier Underflow
              // 10  MO       Multiplier Overflow
              // 11  MI       Multiplier Inexact
              // 12  MA       Multiplier Add-One
              // 13  AU       Adder Underflow
              // 14  AO       Adder Overflow
              // 15  AI       Adder Inexact
              // 16  AA       Adder Add-One
              // 17-21 RR     Result Register
              // 22-24 AE     Adder Exponent
              // 25-26 LRP    Load Pipe Result Precision
              // 27  IRP      Integer (Graphics) Pipe Result Precision
              // 28  MRP      Multiplier Pipe Result Precision
              // 29  ARP      Adder Pipe Result Precision
              // 30           Reserved
              // 31           Reserved
  "epsr",     // Extended Processor Status Register
              // 0-7          Processor Type
              //               = 2 for i860 XP
              // 8-12         Stepping Number
              // 13 IL        InterLock
              // 14 WP        Write Protect
              // 15 PEF       Parity Error Flag
              // 16 BEF       Bus Error Flag
              // 17 INT       Interrupt
              // 18-21 DCS    Data Cache Size = 2**(12+DCS)
              // 22 PBM       Page-Table Bit Mode
              // 23 BE        Big Endian
              //               0 - little endian
              //               1 - big endian
              // 24 OF        Overflow Flag
              // 25 BS        BEF or PEF In Supervisor Mode
              // 26 DI        Trap On Delayed Instruction
              // 27 TAI       Trap On AutoIncrement Instruction
              // 28 PT        Trap On Pipeline Use
              // 29 PI        Pipeline Instruction
              // 30 SO        Strong Ordering
              // 31           Reserved
  "bear",     // Bus Error Address Register (read-only)
  "ccr",      // Concurrency Control Register
              // 0-1          Reserved
              // 2            Detached Only
              // 3            CCU on
              // 4-11         Reserved
              // 12           Zero
              // 13-31        CCUBASE
  "p0",       // Privileged Register 0 (any purpose)
  "p1",       // Privileged Register 1 (any purpose)
  "p2",       // Privileged Register 2 (any purpose)
  "p3",       // Privileged Register 3 (any purpose)
  "cs","ds"
};

//----------------------------------------------------------------------
void i860_t::set_cpu(int procnum)
{
  pflag = procnum ? _PT_860XP : _PT_860XR;
}
//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new i860_t);
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi i860_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_ending_undo:
      // restore ptype
      set_cpu(ph.get_proc_index());
      break;

    case processor_t::ev_newprc:
      set_cpu(va_arg(va, int));
      // bool keep_cfg = va_argi(va, bool);
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i860_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i860_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        i860_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return i860_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return i860_emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    default:
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
//      aIntel860,
//      Generic for Intel 860
//-----------------------------------------------------------------------
static const asm_t i860 =
{
  AS_COLON | ASH_HEXF3,
  0,
  "Generic for Intel 860",
  0,
  nullptr,
  "org",
  nullptr,

  "//",         // comment string
  '\"',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".byte",      // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  "[#d] #v",    // arrays (#h,#d,#v,#s(...)
  ".byte [%s]", // uninited arrays
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  nullptr,    // and
  nullptr,    // or
  nullptr,    // xor
  nullptr,    // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};

const asm_t *const i860asms[] = { &i860, nullptr };
//-----------------------------------------------------------------------
#define FAMILY "Intel 860 processors:"

static const char *const shnames[] =
{
  "860xr",
  "860xp",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Intel 860 XR",
  "Intel 860 XP",
  nullptr
};

//--------------------------------------------------------------------------
static const bytes_t retcodes[] =
{
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Intel 860XP processor definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_I860,              // id
                          // flag
  PR_USE32,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  i860asms,

  notify,

  RegNames,                     // Regsiter names
  R_vds+1,                      // Number of registers

  R_vcs,R_vds,
  0,                            // size of a segment register
  R_vcs,R_vds,

  nullptr,                         // No known code start sequences
  retcodes,

  0,I860_last,
  Instructions,                 // instruc
};
