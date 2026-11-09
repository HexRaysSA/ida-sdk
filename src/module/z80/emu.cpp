/*
 *      Interactive disassembler (IDA).
 *      Version 3.06
 *      Copyright (c) 1990-96 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "i5.hpp"
#include <idd.hpp>

//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn, int n)
{
  set_immd(insn.ea);
  if ( !is_defarg(get_flags(insn.ea), n) )
  {
    switch ( insn.itype )
    {
      case I5_ani:
      case I5_xri:
      case I5_ori:
      case I5_in:
      case I5_out:
      case I5_rst:

      case HD_in0:
      case HD_out0:
      case HD_tstio:
        op_num(insn.ea,-1);
        break;
    }
  }
}

//----------------------------------------------------------------------
void z80_t::load_operand(const insn_t &insn, const op_t &x)
{
  dref_t xreftype;
  switch ( x.type )
  {
    case o_reg:
    case o_phrase:
    default:
      break;

    case o_imm:
      xreftype = dr_O;
MakeImm:
      set_immd_bit(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, xreftype, 0);
      break;
    case o_displ:
      xreftype = dr_R;
      goto MakeImm;

    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        insn.add_dref(ea, x.offb, dr_R);
        insn.create_op_data(ea, x);
      }
      break;

    case o_near:
      {
        ea_t ea = map_code_ea(insn, x);
        ea_t segbase = (ea - x.addr) >> 4;
        ea_t thisseg = insn.cs;
        int iscall = has_insn_feature(insn.itype,CF_CALL);
        insn.add_cref(
                ea,
                x.offb,
                iscall ? (segbase == thisseg ? fl_CN : fl_CF)
                       : (segbase == thisseg ? fl_JN : fl_JF));
        if ( iscall && !func_does_return(ea) )
          flow = false;
      }
      break;
  }
}

//----------------------------------------------------------------------
static void save_operand(const insn_t &insn, const op_t &x)
{
  switch ( x.type )
  {
    case o_reg:
      break;
    case o_mem:
      {
        ea_t ea = map_data_ea(insn, x);
        insn.create_op_data(ea, x);
        insn.add_dref(ea, x.offb, dr_W);
      }
      break;
    case o_displ:
      set_immd_bit(insn, x.n);
      if ( op_adds_xrefs(get_flags(insn.ea), x.n) )
        insn.add_off_drefs(x, dr_W, OOF_ADDR);
    case o_phrase:
      break;
    default:
      switch ( insn.itype )
      {
        case Z80_in0:
        case Z80_outaw:
          break;
        default:
          break;
      }
      break;
  }
}

//----------------------------------------------------------------------
int z80_t::i5_emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature(ph);
  flow = ((Feature & CF_STOP) == 0);

  if ( (Feature & CF_USE1) )
    load_operand(insn, insn.Op1);
  if ( (Feature & CF_USE2) )
    load_operand(insn, insn.Op2);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  switch ( insn.itype )
  {
    case I5_mov:
    case I5_mvi:
    case Z80_ld:
      break;
    case Z80_jp:
    case Z80_jr:                // Z80
    case Z80_ret:               // Z80
      if ( insn.Op1.Cond != oc_not )
        break;
      // no break
    case I5_jmp:
      if ( insn.Op2.type == o_phrase )
        remember_problem(PR_JUMP, insn.ea);
      // no break
    case I5_ret:
      flow = false;
      break;
    case I5_rstv:
      add_cref(insn.ea, map_code_ea(insn, 0x40, 0), fl_CN);
      break;
    case I5_rst:
      {
        int mul = isZ80() ? 1 : 8;
        ushort offset = ushort(insn.Op1.value * mul);
        add_cref(insn.ea, map_code_ea(insn, offset, 0), fl_CN);
      }
    case I5_call:
    case I5_cc:
    case I5_cnc:
    case I5_cz:
    case I5_cnz:
    case I5_cpe:
    case I5_cpo:
    case I5_cp:
    case I5_cm:
    case Z80_exx:               // Z80
//      i5_CPUregs.bc.undef();
//      i5_CPUregs.de.undef();
//      i5_CPUregs.hl.undef();
//      i5_CPUregs.af.undef();
//      i5_CPUregs.ix.undef();
//      i5_CPUregs.iy.undef();
      break;
    default:
//      R1.undef();
//      R2.undef();
      break;
  }

  if ( Feature & CF_CHG1 )
    save_operand(insn, insn.Op1);
  if ( Feature & CF_CHG2 )
    save_operand(insn, insn.Op2);

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
sval_t z80_t::named_regval(
        const char *regname,
        getreg_t *getreg,
        const regval_t *rv)
{
  // Get register info.
  const char *main_regname;
  bitrange_t bitrange;
  if ( !get_reg_info(&main_regname, &bitrange, regname) )
    return 0;

  // Get main register value and apply bitrange.
  sval_t ret = getreg(main_regname, rv).ival;
  ret >>= bitrange.bitoff();
  ret &= (1ULL << bitrange.bitsize()) - 1;
  return ret;
}

//----------------------------------------------------------------------
sval_t z80_t::regval(const op_t &op, getreg_t *getreg, const regval_t *rv)
{
  // Check for bad register number.
  if ( op.reg > R_a2 )
    return 0;
  return named_regval(ph.reg_names[op.reg], getreg, rv);
}

//----------------------------------------------------------------------
bool z80_t::check_cond(
        uint16_t cc,
        getreg_t *getreg,
        const regval_t *regvalues)
{
  uint16_t F = named_regval("F", getreg, regvalues);
  bool C   = (F & (1 << 0)) != 0;
  bool PV  = (F & (1 << 2)) != 0;
  bool Z   = (F & (1 << 6)) != 0;
  bool S   = (F & (1 << 7)) != 0;
  switch ( cc )
  {
    case oc_nz:  return !Z;  // non-zero
    case oc_z:   return Z;   // zero
    case oc_nc:  return !C;  // no carry
    case oc_c:   return C;   // carry
    case oc_po:  return !PV; // parity odd
    case oc_pe:  return PV;  // parity even
    case oc_p:   return !S;  // sign positive
    case oc_m:   return S;   // sign negative
    case oc_not: return true;
  }
  return false;
}

//----------------------------------------------------------------------
ea_t z80_t::next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues)
{
  // Decode instruction at ea.
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return BADADDR;

  // Get next address to be executed.
  ea_t target = BADADDR;
  switch ( insn.itype )
  {
    case Z80_jp:
    case Z80_jr:
    case Z80_call:
      if ( check_cond(insn.Op1.Cond, getreg, regvalues) )
      {
        if ( insn.Op2.type == o_near )
          target = insn.Op2.addr;
        else if ( insn.Op2.type == o_phrase )
          target = regval(insn.Op2, getreg, regvalues);
      }
      break;

    case Z80_djnz:
      {
        uint8_t B = named_regval("B", getreg, regvalues);
        if ( (B-1) != 0 )
          target = insn.Op1.addr;
      }
      break;

    case Z80_ret:
      if ( !check_cond(insn.Op1.Cond, getreg, regvalues) )
        break;
      // fallthrough
    case Z80_reti:
    case Z80_retn:
      {
        uint16_t SP = named_regval("SP", getreg, regvalues);
        target = get_word(SP);
      }
      break;
  }

  return target;
}

//----------------------------------------------------------------------
ea_t z80_t::calc_step_over(ea_t ip) const
{
  insn_t insn;
  if ( ip == BADADDR || decode_insn(&insn, ip) < 1 )
    return BADADDR;

  // Allow stepping over call instructions and djnz.
  bool step_over = is_call_insn(insn)
                || insn.itype == Z80_djnz;
  if ( step_over )
    return insn.ea + insn.size;

  return BADADDR;
}

//----------------------------------------------------------------------
bool z80_t::get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues)
{
  // No Z80 instruction has operand number greater than 2.
  if ( n < 0 || n > 2 )
    return false;

  // Decode instruction at ea.
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return false;

  // Check the instruction features to see if the operand is modified.
  opinf->modified = has_cf_chg(insn.get_canon_feature(ph), n);

  // Get operand value (possibly an ea).
  uint64 v = 0;
  const op_t &op = insn.ops[n];
  switch ( op.type )
  {
    case o_reg:
      // We use the getreg function (along with regvalues) to retrieve
      // the value of the register specified in op.reg.
      v = regval(op, getreg, regvalues);
      break;
    case o_mem:
    case o_near:
      // Memory addresses are stored in op.addr.
      opinf->ea = op.addr;
      break;
    case o_phrase:
      // Memory references using register value.
      opinf->ea = regval(op, getreg, regvalues);
      break;
    case o_displ:
      // Memory references using register and address value.
      opinf->ea = regval(op, getreg, regvalues) + op.addr;
      break;
    case o_imm:
      // Immediates are stored in op.value.
      v = op.value;
      break;
    case o_cond:
      // This is just a condition code type (see opcond_t). There is no
      // meaningful value to return.
      return false;
    default:
      return false;
  }
  opinf->value._set_int(v);
  opinf->value_size = get_dtype_size(op.dtype);

  return true;
}

//----------------------------------------------------------------------
bool z80_t::get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname)
{
  // Sanity checks.
  if ( regname == nullptr || regname[0] == '\0' )
    return false;

  static const char *const subregs[][3] =
  {
    { "af",  "a",  "f"  },
    { "bc",  "b",  "c"  },
    { "de",  "d",  "e"  },
    { "hl",  "h",  "l"  },
    { "af'", "a'", "f'" },
    { "bc'", "b'", "c'" },
    { "de'", "d'", "e'" },
    { "hl'", "h'", "l'" },
    { "ix",  nullptr, nullptr },
    { "iy",  nullptr, nullptr },
    { "sp",  nullptr, nullptr },
    { "pc",  nullptr, nullptr },
  };

  // Check if we are dealing with paired or single registers and return
  // the appropriate information.
  for ( size_t i = 0; i < qnumber(subregs); i++ )
  {
    for ( size_t j = 0; j < 3; j++ )
    {
      if ( subregs[i][j] == nullptr )
        break;
      if ( strieq(regname, subregs[i][j]) )
      {
        if ( main_regname != nullptr )
          *main_regname = subregs[i][0];
        if ( bitrange != nullptr )
        {
          switch ( j )
          {
            case 0: *bitrange = bitrange_t(0, 16); break;
            case 1: *bitrange = bitrange_t(8,  8); break;
            case 2: *bitrange = bitrange_t(0,  8); break;
          }
        }
        return true;
      }
    }
  }

  return false;
}
