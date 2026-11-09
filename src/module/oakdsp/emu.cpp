
#include "oakdsp.hpp"
#include <segregs.hpp>
#include <frame.hpp>

//----------------------------------------------------------------------
ea_t oakdsp_t::calc_mem(const insn_t &insn, const op_t &x) const
{
  uint xaddr;

  if ( x.amode & amode_x )
  {
    if ( x.amode & amode_short )
    {
      sel_t dpage = get_sreg(insn.ea, PAGE);
      if ( dpage == BADSEL )
        return BADSEL;
      xaddr = ((dpage & 0xFF) << 8) | uint(x.addr);
    }
    else
    {
      xaddr = (uint)x.addr;
    }
    return xmem == BADADDR ? BADADDR : xmem + xaddr;
  }

  return to_ea(insn.cs, x.addr);

}
//------------------------------------------------------------------------
void oakdsp_t::init_emu(void)
{
  delayed = false;
  cycles = 0;
}

//------------------------------------------------------------------------
inline bool is_stkreg(int r)
{
  return r == SP;
}

//------------------------------------------------------------------------
int idaapi is_sp_based(const insn_t &, const op_t &x)
{
  return OP_SP_ADD | (x.phrase == SP ? OP_SP_BASED : OP_FP_BASED);
}

//------------------------------------------------------------------------
static void process_immediate_number(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), n) )
    return;
  switch ( insn.itype )
  {
    case OAK_Dsp_shfi:
    case OAK_Dsp_movsi:

      op_dec(insn.ea, n);
      break;

    case OAK_Dsp_lpg:
    case OAK_Dsp_mpyi:
    case OAK_Dsp_mov:
    case OAK_Dsp_rets:
    case OAK_Dsp_rep:
    case OAK_Dsp_load:
    case OAK_Dsp_push:
    case OAK_Dsp_bkrep:
    case OAK_Dsp_msu:
    case OAK_Dsp_tstb:
    case OAK_Dsp_or:
    case OAK_Dsp_and:
    case OAK_Dsp_xor:
    case OAK_Dsp_add:
    case OAK_Dsp_alm_tst0:
    case OAK_Dsp_alm_tst1:
    case OAK_Dsp_cmp:
    case OAK_Dsp_sub:
    case OAK_Dsp_alm_msu:
    case OAK_Dsp_addh:
    case OAK_Dsp_addl:
    case OAK_Dsp_subh:
    case OAK_Dsp_subl:
    case OAK_Dsp_sqr:
    case OAK_Dsp_sqra:
    case OAK_Dsp_cmpu:
    case OAK_Dsp_set:
    case OAK_Dsp_rst:
    case OAK_Dsp_chng:
    case OAK_Dsp_addv:
    case OAK_Dsp_alb_tst0:
    case OAK_Dsp_alb_tst1:
    case OAK_Dsp_cmpv:
    case OAK_Dsp_subv:
    case OAK_Dsp_mpy:
    case OAK_Dsp_mpysu:
    case OAK_Dsp_mac:
    case OAK_Dsp_macus:
    case OAK_Dsp_maa:
    case OAK_Dsp_macuu:
    case OAK_Dsp_macsu:
    case OAK_Dsp_maasu:

      op_num(insn.ea, n);
      break;
  }
}

//----------------------------------------------------------------------
void oakdsp_t::add_near_ref(const insn_t &insn, const op_t &x, ea_t ea)
{
  cref_t ftype = fl_JN;
  if ( has_insn_feature(insn.itype, CF_CALL) )
  {
    if ( !func_does_return(ea) )
      flow = false;
    ftype = fl_CN;
  }
  insn.add_cref(ea, x.offb, ftype);
}

//----------------------------------------------------------------------
void oakdsp_t::handle_operand(const insn_t &insn, const op_t &x, bool is_forced, bool isload)
{
  switch ( x.type )
  {
    case o_reg:
    default:
      break;
    case o_imm:
      process_immediate_number(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_O, x.amode & amode_signed ? OOF_SIGNED : 0);
      break;

    case o_phrase:
      if ( !is_forced && op_adds_xrefs(get_flags(insn.ea), x.n) )
      {
        ea_t ea = insn.add_off_drefs(x, isload ? dr_R : dr_W, OOF_ADDR|OOFW_16);
        if ( ea != BADADDR )
          insn.create_op_data(ea, x);
      }
      break;
    case o_mem:
      {
        ea_t ea = calc_mem(insn, x);
        insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
        insn.create_op_data(ea, x);
      }
      break;
    case o_near:
      add_near_ref(insn, x, calc_mem(insn, x));
      break;
    case o_textphrase:
      break;

    case o_local: // local variables
      if ( may_create_stkvars() )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr
          && (pfn->flags & FUNC_FRAME) != 0
          && insn.create_stkvar(x, x.addr, STKVAR_VALID_SIZE) )
        {
          op_stkvar(insn.ea, x.n);
        }
      }
      break;

  }
}

//----------------------------------------------------------------------
static bool add_stkpnt(const insn_t &insn, sval_t delta)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  return add_auto_stkpnt(pfn, insn.ea+insn.size, delta);
}

//----------------------------------------------------------------------
static void trace_sp(const insn_t &insn)
{

  int16 frame;

  // trace SP changes

  switch ( insn.itype )
  {
    case OAK_Dsp_reti_u:
    case OAK_Dsp_retid:
    case OAK_Dsp_reti:
      add_stkpnt(insn, 1);
      break;

    case OAK_Dsp_ret_u:
    case OAK_Dsp_retd:
    case OAK_Dsp_ret:
      add_stkpnt(insn, 1);
      break;

    case OAK_Dsp_rets:
      add_stkpnt(insn, 1 + insn.Op1.value);
      break;

    case OAK_Dsp_pop:
      add_stkpnt(insn, 1);
      break;

    case OAK_Dsp_push:
      add_stkpnt(insn, -1);
      break;

    case OAK_Dsp_addv:
      if ( insn.Op1.type == o_imm
        && insn.Op2.type == o_reg
        && insn.Op2.reg == SP )
      {
        frame = (uint16)insn.Op1.value;
        add_stkpnt(insn, frame);
      }
      break;

    case OAK_Dsp_subv:
      if ( insn.Op1.type == o_imm
        && insn.Op2.type == o_reg
        && insn.Op2.reg == SP )
      {
        frame = (uint16)insn.Op1.value;
        add_stkpnt(insn, -frame);
      }
      break;


  }
}

//----------------------------------------------------------------------
int oakdsp_t::emu(const insn_t &insn)
{
  if ( segtype(insn.ea) == SEG_XTRN )
    return 1;

  bool flag1 = is_forced_operand(insn.ea, 0);
  bool flag2 = is_forced_operand(insn.ea, 1);
  bool flag3 = is_forced_operand(insn.ea, 2);

  // Determine if the next instruction should be executed
  flow = !has_insn_feature(insn.itype, CF_STOP);

  if ( has_insn_feature(insn.itype,CF_USE1) ) handle_operand(insn, insn.Op1, flag1, true);
  if ( has_insn_feature(insn.itype,CF_USE2) ) handle_operand(insn, insn.Op2, flag2, true);
  if ( has_insn_feature(insn.itype,CF_USE3) ) handle_operand(insn, insn.Op3, flag3, true);

  if ( has_insn_feature(insn.itype,CF_CHG1) ) handle_operand(insn, insn.Op1, flag1, false);
  if ( has_insn_feature(insn.itype,CF_CHG2) ) handle_operand(insn, insn.Op2, flag2, false);
  if ( has_insn_feature(insn.itype,CF_CHG3) ) handle_operand(insn, insn.Op3, flag3, false);


  // check for DP changes
  if ( insn.itype == OAK_Dsp_lpg )
    split_sreg_range(get_item_end(insn.ea), PAGE, insn.Op1.value & 0xFF, SR_auto);
  if ( insn.itype == OAK_Dsp_mov
    && insn.Op1.type == o_imm
    && insn.Op2.type == o_reg
    && insn.Op2.reg == ST1 )
  {
    split_sreg_range(get_item_end(insn.ea), PAGE, insn.Op1.value & 0xFF, SR_auto);
  }

  // Delayed Return

  cycles = insn.cmd_cycles;
  delayed = false;

  insn_t prev_ins;
  if ( decode_prev_insn(&prev_ins, insn.ea) != BADADDR )
  {
    if ( prev_ins.itype == OAK_Dsp_retd || prev_ins.itype == OAK_Dsp_retid )
      delayed = true;
    else
      cycles += prev_ins.cmd_cycles;

    if ( !delayed )
      if ( decode_prev_insn(&prev_ins, prev_ins.ea) != BADADDR )
        if ( prev_ins.itype == OAK_Dsp_retd || prev_ins.itype == OAK_Dsp_retid )
          delayed = true;
  }

  if ( delayed && (cycles > 1) )
    flow = false;

  // mov #imm, pc

  if ( insn.itype == OAK_Dsp_mov && insn.Op2.type == o_reg && insn.Op2.reg == PC )
    flow = false;

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  if ( may_trace_sp() )
  {
    if ( !flow )
      recalc_spd(insn.ea);     // recalculate SP register for the next insn
    else
      trace_sp(insn);
  }

  return 1;
}

//----------------------------------------------------------------------
int may_be_func(const insn_t &) // can a function start here?
                                // arg: none, the instruction is in 'insn'
                                // returns: probability 0..100
{
  return 0;
}

//----------------------------------------------------------------------
int oakdsp_t::is_sane_insn(const insn_t &insn, int /*nocrefs*/) const
{
  // disallow jumps to nowhere
  if ( insn.Op1.type == o_near && !is_mapped(calc_mem(insn, insn.Op1)) )
    return 0;

  // disallow many nops in a now
  int i = 0;
  for ( ea_t ea=insn.ea; i < 32; i++,ea++ )
    if ( get_byte(ea) != 0 )
      break;
  if ( i == 32 )
    return 0;

  return 1;
}

//----------------------------------------------------------------------
int idaapi is_align_insn(ea_t ea)
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return 0;
  switch ( insn.itype )
  {
    case OAK_Dsp_nop:
      break;
    default:
      return 0;
  }
  return insn.size;
}

//----------------------------------------------------------------------
bool idaapi create_func_frame(func_t *pfn)     // create frame of newly created function
{
  bool std_vars_func = true;

  if ( pfn != nullptr )
  {
    if ( pfn->frame == BADNODE )
    {
      ea_t ea = pfn->start_ea;
      int regsize = 0;

      insn_t insn;
      while ( ea < pfn->end_ea ) // check for register pushes
      {
        decode_insn(&insn, ea);
        ea += insn.size;         // count pushes
        if ( (insn.itype == OAK_Dsp_push) && (insn.Op1.type == o_reg) )
          regsize++;
        else
          break;
      }

      ea = pfn->start_ea;
      int16 localsize = 0;
      while ( ea < pfn->end_ea ) // check for frame creation
      {
        decode_insn(&insn, ea);
        ea += insn.size; // try to detect ADDV #,SP
        if ( (insn.itype == OAK_Dsp_addv) && (insn.Op1.type == o_imm) && (insn.Op2.type == o_reg) && (insn.Op2.reg == SP) )
        {
          localsize = (uint16)insn.Op1.value;
          break;
        }

        // if found mov #, rb  --> do not create frame
        if ( (insn.itype == OAK_Dsp_mov) && (insn.Op1.type == o_imm) && (insn.Op2.type == o_reg) && (insn.Op2.reg == RB) )
        {
          std_vars_func = false;
          break;
        }

      }

      if ( std_vars_func )
      {
        pfn->flags |= FUNC_FRAME;
        update_func(pfn);
      }

      add_frame(pfn, -localsize, (ushort)regsize, 0);

    }
  }
  return 0;
}

//----------------------------------------------------------------------
int idaapi OAK_get_frame_retsize(const func_t * /*pfn*/)
{
  return 1;     // 1 'byte' for the return address
}
