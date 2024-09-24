#include <ida.hpp>
#include <idd.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include <allins.hpp>

//----------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  plugin_ctx_t()
  {
    hook_event_listener(HT_IDP, this);
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }
  virtual bool idaapi run(size_t) override { return false; }
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//----------------------------------------------------------------------
static bool z80_get_reg_info(
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

//----------------------------------------------------------------------
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

//----------------------------------------------------------------------
static sval_t named_regval(
        const char *regname,
        getreg_t *getreg,
        const regval_t *rv)
{
  // Get register info.
  const char *main_regname;
  bitrange_t bitrange;
  if ( !z80_get_reg_info(&main_regname, &bitrange, regname) )
    return 0;

  // Get main register value and apply bitrange.
  sval_t ret = getreg(main_regname, rv).ival;
  ret >>= bitrange.bitoff();
  ret &= (1ULL << bitrange.bitsize()) - 1;
  return ret;
}

//----------------------------------------------------------------------
static sval_t regval(
        const op_t &op,
        getreg_t *getreg,
        const regval_t *rv)
{
  // Check for bad register number.
  processor_t &ph = PH;
  if ( op.reg > ph.regs_num )
    return 0;
  return named_regval(ph.reg_names[op.reg], getreg, rv);
}

//----------------------------------------------------------------------
static bool z80_get_operand_info(
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
  processor_t &ph = PH;
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
    default:
      return false;
  }
  opinf->value._set_int(v);
  opinf->value_size = get_dtype_size(op.dtype);

  return true;
}

//------------------------------------------------------------------
enum opcond_t          // condition code types
{
  oc_nz,
  oc_z,
  oc_nc,
  oc_c,
  oc_po,
  oc_pe,
  oc_p,
  oc_m,
  oc_not
};

//----------------------------------------------------------------------
static bool z80_check_cond(
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
static ea_t z80_next_exec_insn(
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
      if ( z80_check_cond(insn.Op1.reg, getreg, regvalues) )
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
      if ( !z80_check_cond(insn.Op1.reg, getreg, regvalues) )
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

//-------------------------------------------------------------------------
static ea_t z80_calc_step_over(ea_t ip)
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

//-------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case processor_t::ev_next_exec_insn:
      {
        ea_t *target              = va_arg(va, ea_t *);
        ea_t ea                   = va_arg(va, ea_t);
        int tid                   = va_arg(va, int);
        getreg_t *getreg          = va_arg(va, getreg_t *);
        const regval_t *regvalues = va_arg(va, const regval_t *);
        qnotused(tid);
        *target = z80_next_exec_insn(ea, getreg, regvalues);
        return 1;
      }
    case processor_t::ev_calc_step_over:
      {
        ea_t *target = va_arg(va, ea_t *);
        ea_t ip      = va_arg(va, ea_t);
        *target = z80_calc_step_over(ip);
        return 1;
      }
    case processor_t::ev_get_idd_opinfo:
      {
        idd_opinfo_t *opinf       = va_arg(va, idd_opinfo_t *);
        ea_t ea                   = va_arg(va, ea_t);
        int n                     = va_arg(va, int);
        int thread_id             = va_arg(va, int);
        getreg_t *getreg          = va_arg(va, getreg_t *);
        const regval_t *regvalues = va_arg(va, const regval_t *);
        qnotused(thread_id);
        return z80_get_operand_info(opinf, ea, n, getreg, regvalues) ? 1 : 0;
      }
    case processor_t::ev_get_reg_info:
      {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange      = va_arg(va, bitrange_t *);
        const char *regname       = va_arg(va, const char *);
        return z80_get_reg_info(main_regname, bitrange, regname) ? 1 : -1;
      }
  }
  return 0;                     // event is not processed
}

//-------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_Z80 )
    return nullptr;
  return new plugin_ctx_t;
}

//-------------------------------------------------------------------------
static const char comment[] = "Z80 debugger processor extension";
static const char help[] =
  "Z80 debugger module\n"
  "\n"
  "This plugin extends the Z80 processor module to support debugging.\n";
static const char wanted_name[] = "Z80 debugger processor extension";
static const char wanted_hotkey[] = "";
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI          // The plugin can work with multiple idbs in parallel
  | PLUGIN_PROC,        // Load plugin when a processor module is loaded
  init,                 // Initialize plugin
  nullptr,
  nullptr,
  comment,              // Long comment about the plugin
  help,                 // Multiline help about the plugin
  wanted_name,          // The preferred short name of the plugin
  wanted_hotkey         // The preferred hotkey to run the plugin
};
