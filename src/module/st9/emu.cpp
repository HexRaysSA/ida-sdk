
#include "st9.hpp"
#include <typeinf.hpp>

//----------------------------------------------------------------------
static sel_t calc_page(ea_t insn_ea, ushort addr)
{
  return get_sreg(insn_ea, rDPR0+(addr>>14));
}

//----------------------------------------------------------------------
static ea_t calc_data_mem_without_mapping(ea_t insn_ea, ea_t addr)
{
  sel_t page = calc_page(insn_ea, (ushort)addr);
  if ( page == BADSEL )
    return BADADDR;
  ea_t ea = use_mapping((page<<14) + (addr & 0x3FFF));
  return ea;
}

//----------------------------------------------------------------------
ea_t get_dest_addr(const insn_t &insn, const op_t &x)
{
  if ( x.type == o_far )
    return x.addr;
  else if ( x.type == o_mem )
    return calc_data_mem_without_mapping(insn.ea, x.addr);
  else if ( x.type == o_near )
    return to_ea(insn.cs, x.addr);
  else
    return BADADDR;
}

//----------------------------------------------------------------------
// Emulate an operand.
void st9_t::handle_operand(const insn_t &insn, const op_t &op, bool lwrite)
{
  switch ( op.type )
  {
    // Code address
    case o_near:
    case o_far:
      {
        cref_t mode;
        ea_t ea = get_dest_addr(insn, op);

        // call or jump ?
        if ( is_call_insn(insn) )
        {
          if ( !func_does_return(ea) )
            flow = false;
          mode = op.type == o_near ? fl_CN: fl_CF;
        }
        else
        {
          mode = op.type == o_near ? fl_JN: fl_JF;
        }
        insn.add_cref(ea, op.offb, mode);
      }
      break;

    // Memory address
    case o_mem:
      {
        ea_t ea = get_dest_addr(insn, op);
        insn.add_dref(ea, op.offb, lwrite ? dr_W : dr_R);
        insn.create_op_data(ea, op);
      }
      break;

    // Immediate value
    case o_imm:
      {
        set_immd(insn.ea);
        flags64_t F = get_flags(insn.ea);
        // create a comment if this immediate is represented in the .cfg file
        {
          const ioport_t * port = find_sym(op.value);
          if ( port != nullptr && !has_cmt(F) )
            set_cmt(insn.ea, port->cmt.c_str(), false);
        }
        // if the value was converted to an offset, then create a data xref:
        if ( op_adds_xrefs(F, op.n) )
          insn.add_off_drefs(op, dr_O, 0);
      }
      break;

    // Displacement
    case o_displ:
      {
        set_immd(insn.ea);
        flags64_t F = get_flags(insn.ea);
        if ( op_adds_xrefs(F, op.n) )
        {
          ea_t ea = insn.add_off_drefs(op, dr_O, OOF_ADDR);
          insn.create_op_data(ea, op);
        }

        // create stack variables if required
        if ( may_create_stkvars() && !is_defarg(F, op.n) && op.reg == rrr14 )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != nullptr && pfn->flags & FUNC_FRAME )
          {
            adiff_t displ = (int16)op.addr;
            if ( insn.create_stkvar(op, displ, STKVAR_VALID_SIZE) )
            {
              op_stkvar(insn.ea, op.n);
              if ( insn.Op2.type == o_reg )
              {
                regvar_t *r = find_regvar(pfn, insn.ea, ph.reg_names[insn.Op2.reg]);
                if ( r != nullptr )
                {
                  tinfo_t frame;
                  ssize_t stkvar_idx = frame.get_stkvar(nullptr, insn, &op, displ);
                  if ( !frame.empty() && stkvar_idx != -1 )
                  {
                    char b[20];
                    qsnprintf(b, sizeof b, "%scopy", r->user);
                    frame.rename_udm(stkvar_idx, b);
                  }
                }
              }
            }
          }
        }
      }
      break;

    // Register - Phrase - Void: do nothing
    case o_reg:
    case o_phrase:
    case o_void:
      break;

    default:
      INTERR(10076);
  }
}

//----------------------------------------------------------------------
// Emulate an instruction.
int st9_t::st9_emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  flow = ((feature & CF_STOP) == 0);
  // is it "jump always"?
  if ( is_jmp_cc(insn.itype) && insn.auxpref == cT )
    flow = false;

  if ( insn.Op1.type != o_void) handle_operand(insn, insn.Op1, (feature & CF_CHG1) != 0);
  if ( insn.Op2.type != o_void) handle_operand(insn, insn.Op2, (feature & CF_CHG2) != 0);
  if ( insn.Op3.type != o_void) handle_operand(insn, insn.Op3, (feature & CF_CHG3) != 0);

  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  //  Following code will update the current value of the two virtual
  //  segment registers: RW (register window) and RP (register page).

  bool rw_has_changed = false;
  bool rp_has_changed = false;

  switch ( insn.itype )
  {
    case st9_srp:
      {
        sel_t val = insn.Op1.value;
        if ( val % 2 )
          val--;     // even reduced
        split_sreg_range(insn.ea+insn.size, rRW, val | (val << 8), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_srp0:
      {
        sel_t RW = get_sreg(insn.ea, rRW);
        split_sreg_range(insn.ea+insn.size, rRW, insn.Op1.value | (RW & 0xFF00), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_srp1:
      {
        sel_t RW = get_sreg(insn.ea, rRW);
        split_sreg_range(insn.ea+insn.size, rRW, (insn.Op1.value << 8) | (RW & 0x00FF), SR_auto);
      }
      rw_has_changed = true;
      break;

    case st9_spp:
      split_sreg_range(insn.ea+insn.size, rRP, insn.Op1.value, SR_auto);
      rp_has_changed = true;
      break;
  }

  // If RW / RP registers have changed, print a comment which explains the new mapping of
  // the general registers.

  flags64_t F = get_flags(insn.ea);
  if ( rw_has_changed && !has_cmt(F) )
  {
    char buf[MAXSTR];
    sel_t RW = get_sreg(insn.ea+insn.size, rRW);
    int low = RW & 0x00FF;
    int high = (RW & 0xFF00) >> 8;

    low *= 8;
    high *= 8;

    const char *const fmt =
      "r0 -> R%d, r1 -> R%d, r2 -> R%d, r3 -> R%d, r4 -> R%d, r5 -> R%d, r6 -> R%d, r7 -> R%d,\n"
      "r8 -> R%d, r9 -> R%d, r10 -> R%d, r11 -> R%d, r12 -> R%d, r13 -> R%d, r14 -> R%d, r15 -> R%d";

    qsnprintf(buf, sizeof buf, fmt,
        0 + low,
        1 + low,
        2 + low,
        3 + low,
        4 + low,
        5 + low,
        6 + low,
        7 + low,
        8 + high,
        9 + high,
        10 + high,
        11 + high,
        12 + high,
        13 + high,
        14 + high,
        15 + high);

    set_cmt(insn.ea, buf, false);
  }

  if ( rp_has_changed && !has_cmt(F) )
  {
    char buf[MAXSTR];
    int rpval = get_sreg(insn.ea+insn.size, rRP);
    qsnprintf(buf, sizeof buf, "Registers R240-R255 will now be referred to the page %d of paged registers",
              rpval);
    set_cmt(insn.ea, buf, false);
  }

  // reanalyze switch info
  if ( insn.itype == st9_jp && get_auto_state() == AU_USED )
  {
    switch_info_t si;
    if ( get_switch_info(&si, insn.ea) > 0 && !si.is_user_defined() )
    {
      delete_switch_table(insn.ea, si);
      // use the IDP event to allow plugins to handle the switch
      switch ( processor_t::is_switch(&si, insn) )
      {
        case 1:
          set_switch_info(insn.ea, si);
          create_switch_table(insn.ea, si);
          break;
        case -1:
          del_switch_info(insn.ea);
          break;
        default:
          // never because this processor module handle it
          break;
      }
    }
  }

  return 1;
}

//----------------------------------------------------------------------
// Analyze an instruction
static ea_t next_insn(insn_t *insn, ea_t ea)
{
  if ( decode_insn(insn, ea) == 0 )
    return 0;
  ea += insn->size;
  return ea;
}

//------------------------------------------------------------------------
// does a far return instruction precede 'ea'?
static bool is_far_return(ea_t ea)
{
  insn_t insn;
  if ( decode_prev_insn(&insn, ea) != BADADDR )
    return insn.itype == st9_rets;
  return false;
}

//----------------------------------------------------------------------
// if a function ends with a far return, mark it as such
// NB: we only handle regular (non-chunked) functions
static void setup_far_func(func_t *pfn)
{
  if ( (pfn->flags & FUNC_FAR) == 0 )
  {
    if ( is_far_return(pfn->end_ea) )
    {
      pfn->flags |= FUNC_FAR;
      update_func(pfn);
    }
  }
}


//----------------------------------------------------------------------
// Create a function frame
bool st9_t::create_func_frame(func_t *pfn) const
{
  setup_far_func(pfn);

  ea_t ea = pfn->start_ea;

  insn_t insn;
  ea = next_insn(&insn, ea);
  if ( !ea )
    return 0;

  /*
   * Get the total frame size
   *
   * LINK rr14, #size
   */

  if ( insn.itype != st9_link )
    return 0;

  int link_register = insn.Op1.reg;
  size_t total_size = (size_t)insn.Op2.value;

  /*
   * Get arguments size
   *
   * LDW 0x??(rr14), RR???        a word
   * LD  ''                       a byte
   */

  int args_size = 0;

  for ( int i = 0; true; i++ )
  {
    insn_t ldi;
    ea = next_insn(&ldi, ea);
    if ( !ea )
      return 0;

    if ( ldi.Op1.type != o_displ || ldi.Op2.type != o_reg )
      break;

    if ( ldi.Op1.reg != link_register )
      break;

    if ( ldi.itype == st9_ld ) // byte
      args_size++;
    else if ( ldi.itype == st9_ldw ) // word
      args_size += 2;
    else
      break;

    char regvar[10];
    qsnprintf(regvar, sizeof regvar, "arg_%d", i);
    int err = add_regvar(pfn, ldi.ea, ldi.ea + ldi.size,
                         ph.reg_names[ldi.Op2.reg], regvar, nullptr);
    if ( err )
      msg("add_regvar() failed : error %d\n", err);
  }

  //msg("LOCAL: %d\nARGS: %d\n", total_size - args_size, args_size);

  pfn->flags |= FUNC_FRAME;
  return add_frame(pfn, total_size - args_size, 0, args_size);
}

//------------------------------------------------------------------------
/*
GCC?-produced switch:

                ldw     ridx, rin [optional]
                cpw     rin, #n
                jpugt   default | jrugt  default
                addw    ridx, ridx
                spm
                ldw     rjmp, jtbl(ridx)
                sdm
                jp      (rjmp)
jtbl:           .word case0, case1, ...
*/

static ea_t check_prev_insn(int itype, insn_t &insn)
{
  ea_t ea = decode_prev_insn(&insn, insn.ea);
  if ( ea == BADADDR || insn.itype != itype )
    return BADADDR;
  return ea;
}

//--------------------------------------------------------------------------
static bool is_gcc_switch(switch_info_t *_si, insn_t &insn)
{
  switch_info_t &si = *_si;
  int rjmp, ridx;
  // si.flags |= SWI_J32;
  ea_t ea, jtbl_insn;
  //
  //      Check jump insn and get register number
  //      jp (rjmp)
  if ( insn.itype != st9_jp
    || insn.Op1.type != o_reg
    || !is_ind(insn.Op1) )
  {
    return false;
  }
  rjmp = insn.Op1.reg;
  // sdm
  ea = check_prev_insn(st9_sdm, insn);
  if ( ea == BADADDR )
    return false;
  // ldw     rjmp, jtbl(ridx)
  ea = check_prev_insn(st9_ldw, insn);
  if ( ea == BADADDR
    || !insn.Op1.is_reg(rjmp)
    || insn.Op2.type != o_displ )
    return false;
  ridx = insn.Op2.reg;
  jtbl_insn = ea;
  // this addr is offset in current code segment because of spm
  si.jumps = to_ea(insn.cs, insn.Op2.addr);
  // spm
  ea = check_prev_insn(st9_spm, insn);
  if ( ea == BADADDR )
    return false;

  // addw  ridx, ridx
  ea = check_prev_insn(st9_addw, insn);
  if ( ea == BADADDR
    || !insn.Op1.is_reg(ridx)
    || !insn.Op2.is_reg(ridx) )
    return false;

  // jpugt   default | jrugt  default
  ea = decode_prev_insn(&insn, ea);
  if ( ea != BADADDR
    && is_jmp_cc(insn.itype)
    && insn.auxpref == cUGT )
  {
    si.defjump = get_dest_addr(insn, insn.Op1);
    // cpw     rin, #n
    ea = check_prev_insn(st9_cpw, insn);
    if ( ea == BADADDR
      || insn.Op2.type != o_imm )
      return false;
    int rin = insn.Op1.reg;
    si.ncases = ushort(insn.Op2.value+1);
    // is rin the same as ridx?
    bool ok = insn.Op1.is_reg(ridx);
    if ( !ok )
    {
      // check for preceding  ldw ridx, rin
      ea_t ea2 = decode_prev_insn(&insn, ea);
      if ( ea2 != BADADDR
        && insn.itype == st9_ldw
        && insn.Op1.is_reg(ridx)
        && insn.Op2.is_reg(rin) )
        ok = true;
    }
    if ( !ok )
      return false;
    si.set_expr(rin, insn.Op1.dtype);
  }
  //
  //      Everything ok.
  //
  msg("SWITCH %a: gcc_switch\n", insn.ea);
  si.startea = ea;
  si.set_jtable_element_size(2);
  si.set_shift(0);
  op_num(ea, 1);  // cpw rin, #n
  op_plain_offset(jtbl_insn, 1, to_ea(insn.cs, 0)); // ldw     rjmp, jtbl(ridx)
  return true;
}

bool st9_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype == st9_jp )
  {
    insn_t copy = insn;
    return is_gcc_switch(si, copy);
  }
  return false;
}


