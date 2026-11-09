/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#include "avr.hpp"
#include "../../ldr/elf/elfr_avr.h"

//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), n) )
    return;
  switch ( insn.itype )
  {
    case AVR_andi:
    case AVR_ori:
      op_num(insn.ea, n);
  }
}

//----------------------------------------------------------------------
void avr_t::handle_operand(const insn_t &insn, const op_t &x, bool isforced, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
      break;
    case o_imm:
      if ( !isload )
        goto WRONG_CALL;
      set_immd_bit(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, OOF_SIGNED);
      break;
    case o_displ:
      set_immd_bit(insn, x.n);
      if ( !isforced && op_adds_xrefs(get_flags(insn.ea), x.n) )
      {
        int outf = OOF_ADDR|OOFS_NEEDSIGN|OOFW_32;
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, outf);
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
      }
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea_t ea = to_ea(insn.cs, x.addr);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
      }
      break;
    case o_port:
      if ( ram != BADADDR )
      {
        ea_t ea = ram + x.addr;
        if ( subarch < E_AVR_MACH_TINY )
          ea += 0x20; // skip 32 mapped GPRs for legacy archs
        // verify that the calculated address corresponds to the register name
        const ioport_t *port = find_port(x.addr);
        if ( port == nullptr || port->name.empty() )
          break;
        ea_t rev = get_name_ea(BADADDR, port->name.c_str());
        if ( rev != ea )
          break;
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      }
      break;
    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      }
      break;
    default:
WRONG_CALL:
      if ( insn.itype != AVR_lpm && insn.itype != AVR_elpm )
        warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static bool may_be_skipped(const insn_t &insn)
{
  if ( insn.ea == 0 )
    return false;
  ea_t ea = insn.ea - 1;
  if ( is_code(get_flags(ea)) )
  {
    int code = get_wide_byte(ea);
    switch ( code & 0xFC00 )
    {
// 0001 00rd dddd rrrr     cpse    rd, rr  4  Compare, Skip if Equal
      case 0x1000:
// 1111 110r rrrr xbbb     sbrc    rr, b      Skip if Bit in I/O Register Cleared
// 1111 111r rrrr xbbb     sbrs    rr, b      Skip if Bit in I/O Register Set
      case 0xFC00:
        return true;
// 1001 1001 pppp pbbb     sbic    p, b       Skip if Bit in Register Cleared
// 1001 1011 pppp pbbb     sbis    p, b       Skip if Bit in Register Set
      case 0x9800:
        return (code & 0x0100) != 0;
    }
  }
  return false;
}

//----------------------------------------------------------------------

int avr_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_USE3 ) handle_operand(insn, insn.Op3, flag3, true);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);
  if ( Feature & CF_CHG3 ) handle_operand(insn, insn.Op3, flag3, false);

//
//      Determine if the next instruction should be executed
//
  if ( !flow )
    flow = may_be_skipped(insn);
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea,insn.ea+insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  decode_insn(&insn, ea);
  switch ( insn.itype )
  {
    case AVR_mov:
      if ( insn.Op1.reg == insn.Op2.reg )
        break;
    default:
      return 0;
    case AVR_nop:
      break;
  }
  return insn.size;
}
