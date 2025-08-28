/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"

//------------------------------------------------------------------------
void pdp11_t::loadR0data(const insn_t &insn, const op_t *x, int sme)
{
  if ( insn.Op2.type == o_void )
  {
    if ( insn.itype != pdp_clr )
      goto undefdat;
    if ( sme )
    {
      if ( !insn.bytecmd )
        goto undefdat;
      emuR0data.b[1] = 0;
      return;
    }
    if ( insn.bytecmd )
      emuR0data.b[0] = 0;
    else
      emuR0data.w = 0;
    return;
  }
  if ( x != &insn.Op2 )
    return;
  if ( insn.Op1.type == o_imm )
  {
    if ( insn.itype == pdp_mov )
    {
      if ( !insn.bytecmd )
      {
        if ( sme )
          goto undefdat;
        emuR0data.w = (ushort)insn.Op1.value;
        return;
      }
      if ( !sme )
        emuR0data.b[0] = (uchar)insn.Op1.value;
      else
        emuR0data.b[1] = (uchar)insn.Op1.value;
      return;
    }
    if ( !insn.bytecmd )
      goto undefdat;
undefbyt:
   if ( !sme )
     emuR0data.b[0] = 0xFF;
   else
     emuR0data.b[1] = 0xFF;
   return;
  }
  if ( insn.bytecmd )
    goto undefbyt;
undefdat:
  emuR0data.w = 0xFFFF;
}

//------------------------------------------------------------------------
void pdp11_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  ea_t jmpa;
  switch ( x.type )
  {
    case o_near:       // Jcc/ [jmp/call 37/67]
    case o_mem:        // 37/67/77
    case o_far:
      jmpa = x.type == o_far
           ? to_ea(x.segval, x.addr16)
           : map_code_ea(insn, x.addr16, x.n);
      if ( x.phrase == 0 )
      {
        insn.add_cref(jmpa, x.offb, fl_JN); // Jcc
        break;
      }
extxref:
      if ( (x.phrase & 070) == 070 )
        goto xrefset;
      if ( insn.itype == pdp_jmp )
        insn.add_cref(jmpa, x.offb, fl_JF);
      else if ( insn.itype == pdp_jsr || insn.itype == pdp_call )
      {
        insn.add_cref(jmpa, x.offb, fl_CF);
        if ( !func_does_return(jmpa) )
          flow = false;
      }
      else
      {
xrefset:
        insn.create_op_data(jmpa, x);
        insn.add_dref(jmpa, x.offb, isload ? dr_R : dr_W);
      }
      break;
    case o_displ:     // 6x/7x (!67/!77)
      set_immd(insn.ea);
      if ( !isload && x.phrase == (060 + rR0) && x.addr16 <= 1 )
        loadR0data(insn, &x, x.addr16);
      if ( !is_forced
        && is_off(get_flags(insn.ea), x.n)
        && (jmpa = get_offbase(insn.ea, x.n)) != BADADDR )
      {
        jmpa += x.addr16;
        goto extxref;
      }
      break;
    case o_imm:        // 27
      if ( !x.ill_imm )
      {
        set_immd(insn.ea);
        if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
          insn.add_off_drefs(x, dr_O, OOF_SIGNED);
      }
      break;
    case o_number:      // EMT/TRAP/MARK/SPL
      if ( insn.itype == pdp_emt && get_cmt(nullptr, insn.ea, false) <= 0 )
      {
        insn_t tmp = insn;
        op_t &tmpx = tmp.ops[x.n];
        if ( tmpx.value >= 0374 && tmpx.value <= 0375 )
        {
          tmp.Op2.value = (tmpx.value == 0375) ? emuR0data.b[1] : (emuR0 >> 8);
          tmp.Op2.type = o_imm;
        }
        qstring qbuf;
        if ( get_predef_insn_cmt(&qbuf, tmp) > 0 )
          set_cmt(tmp.ea, qbuf.c_str(), false);
      }
      break;
    case o_reg:        // 0
      if ( x.reg == rR0 )
      {
        if ( insn.Op2.type == o_void ) // one operand insn
        {
          if ( insn.itype != pdp_clr )
            goto undefall;
          if ( insn.bytecmd )
            emuR0 &= 0xFF00;
          else
            emuR0 = 0;
          goto undefdata;
        }
        if ( &x == &insn.Op2 )
        {
          if ( insn.itype != pdp_mov )
          {
            if ( insn.bytecmd )
            {
              emuR0 |= 0xFF;
              goto undefdata;
            }
            goto undefall;
          }
          if ( insn.bytecmd )
            goto undefall;
          if ( insn.Op1.type == o_imm )
          {
            if ( (emuR0 = (ushort)insn.Op1.value) & 1 )
              goto undefdata;
            emuR0data.w = get_word(to_ea(insn.cs, emuR0));
          }
          else
          {
undefall:
            emuR0 = 0xFFFF;
undefdata:
            emuR0data.w = 0xFFFF;
          }
        }
      }
      break;
    case o_phrase:     // 1x/2x/3x/4x/5x (!27/!37)
      if ( (x.phrase & 7) == rR0 )
      {
        if ( !isload && x.phrase == (010 + rR0) )
          loadR0data(insn, &x, 0);
        else if ( insn.Op2.type == o_void || &x == &insn.Op2 )
          goto undefall;
      }
    case o_fpreg:      // FPP
      break;
    default:
      warning("%" FMT_EA "o (%s): bad optype %d", insn.ip, insn.get_canon_mnem(ph), x.type);
      break;
  }
}

//----------------------------------------------------------------------
int pdp11_t::emu(const insn_t &insn)
{
  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);

  uint32 Feature = insn.get_canon_feature(ph);
  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, flag1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, flag2, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, flag1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, flag2, false);

  ea_t newEA = insn.ea + insn.size;
  if ( insn.itype == pdp_emt && insn.Op1.value == 0376 )
  {
    create_byte(newEA, 2);
    goto prompt2;
  }
  else if ( flow && !(insn.itype == pdp_emt && insn.Op1.value == 0350) )
  {
    if ( insn.Op1.type == o_imm && insn.Op1.ill_imm )
      newEA += 2;
    if ( insn.Op2.type == o_imm && insn.Op2.ill_imm )
    {
prompt2:
      newEA += 2;
    }
    add_cref(insn.ea, newEA, fl_F);
  }
  return 1;
}
