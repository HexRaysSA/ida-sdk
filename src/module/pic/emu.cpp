/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "pic.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//------------------------------------------------------------------------
bool pic_t::is_banked_reg(ea_t addr, int value) const
{
  // on PIC12, bank size is 0x20
  // on PIC14, bank size is 0x80
  if ( ptype == PIC12 )
    return (addr & 0x1F ) == value;
  if ( ptype == PIC14 )
    return (addr & 0x7F ) == value;
  return false;
}

//------------------------------------------------------------------------
// is pcl register?
bool pic_t::is_pcl(const insn_t &insn) const
{
  if ( insn.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12:
      case PIC14: return is_banked_reg(insn.Op1.addr, 0x2);
      case PIC16: return insn.Op1.addr == PIC16_PCL;
    }
  }
  return false;
}

//------------------------------------------------------------------------
// is bank (status or bsr (PIC18Cxx)) register?
bool pic_t::is_bank(const insn_t &insn) const
{
  if ( insn.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12:
      case PIC14: return is_banked_reg(insn.Op1.addr, 0x3);
      case PIC16: return insn.Op1.addr == PIC16_BANK;
    }
  }
  return false;
}

//------------------------------------------------------------------------
// is pclath register?
bool pic_t::is_pclath(const insn_t &insn) const
{
  if ( insn.Op1.type == o_mem )
  {
    switch ( ptype )
    {
      case PIC12: return false;
      case PIC14: return is_banked_reg(insn.Op1.addr, 0xA);
      case PIC16: return insn.Op1.addr == PIC16_PCLATH;
    }
  }
  return false;
}

//------------------------------------------------------------------------
void pic_t::process_immediate_number(const insn_t &insn, int n) const
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), n) )
    return;
  switch ( insn.itype )
  {
    case PIC_iorlw:
    case PIC_andlw:
    case PIC_xorlw:
      op_num(insn.ea, n);
      break;
    case PIC_lfsr2:
      // FSRs are used to address the data memory
      if ( dataseg != BADADDR )
        op_offset(insn.ea, n, REF_OFF16, BADADDR, dataseg);
      break;
  }
}

//----------------------------------------------------------------------
void pic_t::destroy_if_unnamed_array(ea_t ea) const
{
  flags64_t lF = get_flags(ea);
  if ( is_tail(lF) && segtype(ea) == SEG_IMEM )
  {
    ea_t head = prev_not_tail(ea);
    if ( !has_user_name(get_flags(head)) )
    {
      del_items(head, DELIT_SIMPLE);
      create_byte(head, ea-head);
      ea_t end = next_that(ea, inf_get_max_ea(), f_is_head);
      if ( end == BADADDR )
        end = getseg(ea)->end_ea;
      create_byte(ea+1, end-ea-1);
    }
  }
}

//----------------------------------------------------------------------
// propagate the bank/pclath register value to the destination
void pic_t::propagate_sreg(const insn_t &insn, ea_t ea, int reg) const
{
  if ( is_loaded(ea) )
  {
    sel_t v = get_sreg(insn.ea, reg);
    split_sreg_range(ea, reg, v, SR_auto);
  }
}

//----------------------------------------------------------------------
void pic_t::handle_operand(const insn_t &insn, const op_t &x, int, bool isload)
{
  if ( insn.Op2.type == o_reg && insn.Op2.reg == F || insn.itype == PIC_swapf )
    isload = 0;
  switch ( x.type )
  {
    case o_reg:
      return;
    case o_imm:
      if ( !isload )
        error("interr: emu");
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, calc_outf(x));
      break;
    case o_near:
      {
        cref_t ftype = fl_JN;
        ea_t ea = calc_code_mem(insn, x.addr);
        if ( has_insn_feature(insn.itype, CF_CALL) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          ftype = fl_CN;
        }
        insn.add_cref(ea, x.offb, ftype);
        propagate_sreg(insn, ea, BANK);
        propagate_sreg(insn, ea, PCLATH);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_data_mem(x.addr);
        destroy_if_unnamed_array(ea);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
        if ( may_create_stkvars() )
        {
          if ( x.addr == PIC16_INDF2 )
          {
            func_t *pfn = get_func(insn.ea);
            if ( pfn != nullptr && (pfn->flags & FUNC_FRAME) != 0 )
            {
              insn.create_stkvar(insn.Op1, 0, STKVAR_VALID_SIZE);
            }
          }
          else if ( x.addr == PIC16_PLUSW2 )
          {
            insn_t l = insn;
            if ( decode_prev_insn(&l, l.ea) != BADADDR
              && l.itype == PIC_movlw )
            {
              func_t *pfn = get_func(l.ea);
              if ( pfn != nullptr && (pfn->flags & FUNC_FRAME) != 0 )
              {
                if ( l.create_stkvar(l.Op1, l.Op1.value, STKVAR_VALID_SIZE) )
                  op_stkvar(l.ea, l.Op1.n);
              }
            }
          }
        }
      }
      break;
    case o_displ:
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, OOF_ADDR | OOFW_8);
      break;
    default:
      INTERR(10310);
  }
}

//----------------------------------------------------------------------
// change value of virtual register "BANK" and switch to another bank
void pic_t::split(const insn_t &insn, int reg, sel_t v)
{
  if ( reg == -1 )
  {
    flow = 0;
    if ( v != BADSEL )
    {
      sel_t pclath = get_sreg(insn.ea, PCLATH) & 0x1F;
      ea_t ea = calc_code_mem(insn, uchar(v) | (pclath<<8));
      add_cref(insn.ea, ea, fl_JN);
      propagate_sreg(insn, ea, BANK);
      propagate_sreg(insn, ea, PCLATH);
    }
  }
  else
  {
    if ( v == BADSEL )
      v = 0;     // assume bank0 if bank is unknown
    split_sreg_range(get_item_end(insn.ea), reg, v, SR_auto);
  }
}

//----------------------------------------------------------------------
//   tris PORTn  (or movwf TRISn)
bool pic_t::is_load_tris_reg(const insn_t &insn)
{
  ea_t addr;
  const char *key;
  switch ( insn.itype )
  {
    case PIC_tris:
      addr = insn.Op1.value;
      key = "port";
      break;
    case PIC_movwf:
      addr = insn.Op1.addr;
      key = "tris";
      break;
    default:
      return false;
  }
  qstring name;
  addr = calc_data_mem(addr);
  if ( get_name(&name, addr, GN_NOT_DUMMY) <= 0 )
    return false;
  return strnieq(name.begin(), key, 4);
}

//------------------------------------------------------------------
inline void pic_t::set_plain_offset(ea_t insn_ea, int n, ea_t base) const
{
  if ( base == BADADDR )
    base = calc_offset_base(insn_ea, n);
  if ( base != BADADDR )
    op_plain_offset(insn_ea, n, base);
}

//----------------------------------------------------------------------
int pic_t::emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  flow = (Feature & CF_STOP) == 0;

  int bit = CF_USE1;
  bool use = true;
  while ( true )
  {
    for ( int i=0; i < 3; i++,bit<<=1 )
    {
      if ( (Feature & bit) == 0 )
        continue;
      bool forced = is_forced_operand(insn.ea, i);
      handle_operand(insn, insn.ops[i], forced, use);
    }
    if ( !use )
      break;
    use = false;
    bit = CF_CHG1;
  }

  // Check for:
  //   - the register bank changes
  //   - PCLATH changes
  //   - PCL changes
  bool check_regs = false;
  switch ( insn.itype )
  {
    case PIC_movlp: // Move literal to PCLATH
      split(insn, PCLATH, insn.Op1.value);
      break;
    case PIC_movlb: // Move literal to BSR
      split(insn, BANK, insn.Op1.value);
      break;
    default:
      check_regs = true;
      break;
  }

  for ( int i=0; check_regs && i < 3; i++ )
  {
    int reg = 0;
    switch ( i )
    {
      case 0:
        reg = BANK;
        if ( !is_bank(insn) )
          continue;
        break;
      case 1:
        reg = PCLATH;
        if ( !is_pclath(insn) )
          continue;
        break;
      case 2:
        reg = -1;
        if ( !is_pcl(insn) )
          continue;
        break;
    }
    sel_t v = (reg == -1) ? insn.ip : get_sreg(insn.ea, reg);
    if ( insn.Op2.type == o_reg && insn.Op2.reg == F )
    {
//      split(insn, reg, v);
    }
    else
    {
      switch ( insn.itype )
      {
        case PIC_bcf:
        case PIC_bcf3:
        case PIC_bsf:
        case PIC_bsf3:
          if ( (ptype == PIC12 && insn.Op2.value == 5)  // bank selector (PA0)
            || (ptype == PIC14
             && ((reg == BANK && (insn.Op2.value == 5 || insn.Op2.value == 6)) // bank selector (RP1:RP0)
              || (reg == PCLATH && (insn.Op2.value == 3 || insn.Op2.value == 4))))
            || (ptype == PIC16 && sval_t(insn.Op2.value) >= 0 && insn.Op2.value <= 3) )
          {
            if ( v == BADSEL )
              v = 0;
            int shift = 0;
            if ( (ptype == PIC14 || ptype == PIC12) && reg == BANK ) // we use bank selector bits as the bank value
              shift = 5;
            if ( insn.itype == PIC_bcf )
              v = v & ~(sel_t(1) << (insn.Op2.value-shift));
            else
              v = v | (sel_t(1) << (insn.Op2.value-shift));
            split(insn, reg, v);
          }
          break;
        case PIC_clrf:
        case PIC_clrf2:
          split(insn, reg, 0);
          break;
        case PIC_swapf:
        case PIC_swapf3:
          split(insn, reg, ((v>>4) & 15) | ((v & 15) << 4));
          break;
        case PIC_movwf:
        case PIC_movwf2:
        case PIC_addlw:
        case PIC_andlw:
        case PIC_iorlw:
        case PIC_sublw:
        case PIC_xorlw:
          {
            insn_t l = insn;
            if ( decode_prev_insn(&l, l.ea) != BADADDR
              && l.itype == PIC_movlw )
            {
              switch ( insn.itype )
              {
                case PIC_movwf:
                case PIC_movwf2:
                  v = l.Op1.value;
                  break;
                case PIC_addlw:
                  v += l.Op1.value;
                  break;
                case PIC_andlw:
                  v &= l.Op1.value;
                  break;
                case PIC_iorlw:
                  v |= l.Op1.value;
                  break;
                case PIC_sublw:
                  v -= l.Op1.value;
                  break;
                case PIC_xorlw:
                  v ^= l.Op1.value;
                  break;
              }
            }
            else
            {
              v = BADSEL;
            }
          }
          split(insn, reg, v);
          break;
        case PIC_movlw:
          split(insn, reg, insn.Op2.value);
          break;
      }
    }
  }

// Such as, IDA doesn't seem to convert the following:
// tris 6
// into
// tris PORTB ( or whatever )

  flags64_t flags = get_flags(insn.ea);
  if ( insn.itype == PIC_tris && !is_defarg0(flags) )
    set_plain_offset(insn.ea, 0, dataseg);

//   movlw value
// followed by a
//   movwf FSR
// should convert value into an offset , because FSR is used as a pointer to
// the INDF (indirect addressing file)

  if ( insn.itype == PIC_movwf
    && insn.Op1.type == o_mem
    && is_banked_reg(insn.Op1.addr, 0x4) )    // FSR
  {
    insn_t l = insn;
    if ( decode_prev_insn(&l, l.ea) != BADADDR
      && l.itype == PIC_movlw )
    {
      set_plain_offset(l.ea, 0, dataseg);
    }
  }

// Also - it seems to make sense to me that a
//   movlw value
// followed by a
//   tris PORTn  (or movwf TRISn)
// should convert value into a binary , because the bits indicate whether a
// port is defined for input or output.

  if ( is_load_tris_reg(insn) )
  {
    insn_t l;
    if ( decode_prev_insn(&l, insn.ea) != BADADDR
      && l.itype == PIC_movlw )
    {
      op_bin(l.ea, 0);
    }
  }

// Move litteral to BSR

  if ( insn.itype == PIC_movlb1 )
    split(insn, BANK, insn.Op1.value);

//
//      Determine if the next instruction should be executed
//
  if ( !flow )
  {
    flags = get_flags(insn.ea);
    flow = conditional_insn(insn, flags);
  }
  if ( segtype(insn.ea) == SEG_XTRN )
    flow = false;
  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
bool pic_t::create_func_frame(func_t *pfn) const
{
  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->start_ea;
      if ( ea + 12 < pfn->end_ea ) // minimum 4 + 4 + 2 + 2 bytes needed
      {
        insn_t insn[4];
        for ( int i=0; i < 4; i++ )
        {
          int len = decode_insn(&insn[i], ea);
          ea += len > 0 ? len : 0;
        }
        if ( insn[0].itype == PIC_movff2 // movff FSR2L,POSTINC1
          && insn[0].Op1.addr == PIC16_FSR2L && insn[0].Op2.addr == PIC16_POSTINC1
          && insn[1].itype == PIC_movff2 // movff FSR1L,FSR2L
          && insn[1].Op1.addr == PIC16_FSR1L && insn[1].Op2.addr == PIC16_FSR2L
          && insn[2].itype == PIC_movlw  // movlw <size>
          && insn[3].itype == PIC_addwf3 // addwf FSR1L,f
          && insn[3].Op1.addr == PIC16_FSR1L && insn[3].Op2.reg == F )
        {
          pfn->flags |= FUNC_FRAME;
          return add_frame(pfn, insn[2].Op1.value, 0, 0);
        }
      }
    }
  }
  return 0;
}
