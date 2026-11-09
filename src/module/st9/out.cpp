
#include "st9.hpp"

//----------------------------------------------------------------------
class out_st9_t : public outctx_t
{
  out_st9_t(void) = delete; // not used
  st9_t &pm() { return *static_cast<st9_t *>(procmod); }

public:
  const char *get_general_register_description(const ushort reg) const;
  void out_reg(ushort reg);
  void out_reg(const op_t &op);
  void out_imm(const op_t &op, bool no_shift = false);
  void out_addr(const op_t &op, bool find_label = true);
  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_st9_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_st9_t)

//--------------------------------------------------------------------------
// Get description for a given general register.
// Description may change according to the current number of the registers page.
const char *out_st9_t::get_general_register_description(const ushort reg) const
{
  if ( reg <= rRR239 && reg >= rRR224 )
  {
    // pairs of system registers (group E)
    switch ( reg )
    {
      case rRR236: return "User Stack Pointer";
      case rRR238: return "System Stack Pointer";
      default: return nullptr;
    }
  }
  if ( reg <= rR239 && reg >= rR224 )
  {
    // system registers (group E)
    switch ( reg )
    {
      case rR224: return "Port 0 Data Register (EMR2.5 == 0) or Data Page Register 0 (EMR2.5 == 1)";
      case rR225: return "Port 1 Data Register (EMR2.5 == 0) or Data Page Register 1 (EMR2.5 == 1)";
      case rR226: return "Port 2 Data Register (EMR2.5 == 0) or Data Page Register 2 (EMR2.5 == 1)";
      case rR227: return "Port 3 Data Register (EMR2.5 == 0) or Data Page Register 3 (EMR2.5 == 1)";
      case rR228: return "Port 4 Data Register";
      case rR229: return "Port 5 Data Register";
      case rR230: return "Central Interrupt Control Register";
      case rR231: return "Flag Register";
      case rR232: return "Pointer 0 Register";
      case rR233: return "Pointer 1 Register";
      case rR234: return "Page Pointer Register";
      case rR235: return "Mode Register";
      case rR236: return "User Stack Pointer High Register";
      case rR237: return "User Stack Pointer Low Register";
      case rR238: return "System Stack Pointer High Register";
      case rR239: return "System Stack Pointer Low Register";
    }
  }

  // only handle paged register below (group F)
  if ( reg < rR240 || reg > rR255 )
    return nullptr;

  switch ( get_sreg(insn.ea, rRP) )
  {
    // page: N/A
    case BADSEL:
      break;

    // page: 0
    case 0:
      switch ( reg )
      {
        case rR241: return "Minor Register";
        case rR242: return "External Interrupt Trigger Register";
        case rR243: return "External Interrupt Pending Register";
        case rR244: return "External Interrupt Mask-bit Register";
        case rR245: return "External Interrupt Priority Level Register";
        case rR246: return "External Interrupt Vector Register";
        case rR247: return "Nested Interrupt Control";
        case rR248: return "Watchdog Timer High Register";
        case rR249: return "Watchdog Timer Low Register";
        case rR250: return "Watchdog Timer Prescaler Register";
        case rR251: return "Watchdog Timer Control Register";
        case rR252: return "Wait Control Register";
        case rR253: return "SPI Data Register";
        case rR254: return "SPI Control Register";
      }
      break;

    // page: 2
    case 2:
      switch ( reg )
      {
        case rR240: return "Port 0 Configuration Register 0";
        case rR241: return "Port 0 Configuration Register 1";
        case rR242: return "Port 0 Configuration Register 2";
        case rR244: return "Port 1 Configuration Register 0";
        case rR245: return "Port 1 Configuration Register 1";
        case rR246: return "Port 1 Configuration Register 2";
        case rR248: return "Port 2 Configuration Register 0";
        case rR249: return "Port 2 Configuration Register 1";
        case rR250: return "Port 2 Configuration Register 2";
      }
      break;

    // page: 3
    case 3:
      switch ( reg )
      {
        case rR240: return "Port 4 Configuration Register 0";
        case rR241: return "Port 4 Configuration Register 1";
        case rR242: return "Port 4 Configuration Register 2";
        case rR244: return "Port 5 Configuration Register 0";
        case rR245: return "Port 5 Configuration Register 1";
        case rR246: return "Port 5 Configuration Register 2";
        case rR248: return "Port 6 Configuration Register 0";
        case rR249: return "Port 6 Configuration Register 1";
        case rR250: return "Port 6 Configuration Register 2";
        case rR251: return "Port 6 Data Register";
        case rR252: return "Port 7 Configuration Register 0";
        case rR253: return "Port 7 Configuration Register 1";
        case rR254: return "Port 7 Configuration Register 2";
        case rR255: return "Port 7 Data Register";
      }
      break;

    // page: 8, 10 or 12
    case 8:
    case 10:
    case 12:
      switch ( reg )
      {
        case rR240: return "Capture Load Register 0 High";
        case rR241: return "Capture Load Register 0 Low";
        case rR242: return "Capture Load Register 1 High";
        case rR243: return "Capture Load Register 1 Low";
        case rR244: return "Compare 0 Register High";
        case rR245: return "Compare 0 Register Low";
        case rR246: return "Compare 1 Register High";
        case rR247: return "Compare 1 Register Low";
        case rR248: return "Timer Control Register";
        case rR249: return "Timer Mode Register";
        case rR250: return "External Input Control Register";
        case rR251: return "Prescaler Register";
        case rR252: return "Output A Control Register";
        case rR253: return "Output B Control Register";
        case rR254: return "Flags Register";
        case rR255: return "Interrupt/DMA Mask Register";
      }
      break;

    // page: 9
    case 9:
      switch ( reg )
      {
        case rR240:
        case rR244: return "DMA Counter Pointer Register";
        case rR241:
        case rR245: return "DMA Address Pointer Register";
        case rR242:
        case rR246: return "Interrupt Vector Register";
        case rR243:
        case rR247: return "Interrupt/DMA Control Register";
        case rR248: return "I/O Connection Register";
      }
      break;

    // page: 11
    case 11:
      switch ( reg )
      {
        case rR240: return "Counter High Byte Register";
        case rR241: return "Counter Low Byte Register";
        case rR242: return "Standard Timer Prescaler Register";
        case rR243: return "Standard Timer Control Register";
      }
      break;

    // page: 13
    case 13:
      switch ( reg )
      {
        case rR244: return "DMA Counter Pointer Register";
        case rR245: return "DMA Address Pointer Register";
        case rR246: return "Interrupt Vector Register";
        case rR247: return "Interrupt/DMA Control Register";
      }
      break;

    // page: 21
    case 21:
      switch ( reg )
      {
        case rR240: return "Data Page Register 0";
        case rR241: return "Data Page Register 1";
        case rR242: return "Data Page Register 2";
        case rR243: return "Data Page Register 3";
        case rR244: return "Code Segment Register";
        case rR248: return "Interrupt Segment Register";
        case rR249: return "DMA Segment Register";
        case rR245: return "External Memory Register 1";
        case rR246: return "External Memory Register 2";
      }
      break;

    // page: 24 or 25
    case 24:
    case 25:
      switch ( reg )
      {
        case rR240: return "Receiver DMA Transaction Counter Pointer";
        case rR241: return "Receiver DMA Source Address Pointer";
        case rR242: return "Transmitter DMA Transaction Counter Pointer";
        case rR243: return "Transmitter DMA Source Address Pointer";
        case rR244: return "Interrupt Vector Register";
        case rR245: return "Address/Data Compare Register";
        case rR246: return "Interrupt Mask Register";
        case rR247: return "Interrupt Status Register";
        case rR248: return "Receive/Transmitter Buffer Register";
        case rR249: return "Interrupt/DMA Priority Register";
        case rR250: return "Character Configuration Register";
        case rR251: return "Clock Configuration Register";
        case rR252: return "Baud Rate Generator High Register";
        case rR253: return "Baud Rate Generator Low Register";
        case rR254: return "Synchronous Input Control";
        case rR255: return "Synchronous Output Control";
      }
      break;

    // page: 43
    case 43:
      switch ( reg )
      {
        case rR248: return "Port 8 Configuration Register 0";
        case rR249: return "Port 8 Configuration Register 1";
        case rR250: return "Port 8 Configuration Register 2";
        case rR251: return "Port 8 Data Register";
        case rR252: return "Port 9 Configuration Register 0";
        case rR253: return "Port 9 Configuration Register 1";
        case rR254: return "Port 9 Configuration Register 2";
        case rR255: return "Port 9 Data Register";
      }
      break;

    // page: 55
    case 55:
      switch ( reg )
      {
        case rR240: return "Clock Control Register";
        case rR242: return "Clock Flag Register";
        case rR246: return "PLL Configuration Register";
      }
      break;

    // page: 63
    case 63:
      switch ( reg )
      {
        case rR240: return "Channel 0 Data Register";
        case rR241: return "Channel 1 Data Register";
        case rR242: return "Channel 2 Data Register";
        case rR243: return "Channel 3 Data Register";
        case rR244: return "Channel 4 Data Register";
        case rR245: return "Channel 5 Data Register";
        case rR246: return "Channel 6 Data Register";
        case rR247: return "Channel 7 Data Register";
        case rR248: return "Channel 6 Lower Threshold Register";
        case rR249: return "Channel 6 Lower Threshold Register";
        case rR250: return "Channel 7 Upper Threshold Register";
        case rR251: return "Channel 7 Upper Threshold Register";
        case rR252: return "Compare Result Register";
        case rR253: return "Control Logic Register";
        case rR254: return "Interrupt Control Register";
        case rR255: return "Interrupt Vector Register";
      }
      break;
  }
  return nullptr;
}

//--------------------------------------------------------------------------
// Output a register
void out_st9_t::out_reg(ushort reg)
{
  out_register(ph.reg_names[reg]);
  if ( !has_cmt(F) )
  {
    const char *cmt = get_general_register_description(reg);
    if ( cmt != nullptr )
      pm().gr_cmt = cmt;
  }
}

//--------------------------------------------------------------------------
// Output an operand as a register
void out_st9_t::out_reg(const op_t &op)
{
  out_reg(op.reg);
}

//--------------------------------------------------------------------------
// Output an operand as an immediate value
void out_st9_t::out_imm(const op_t &op, bool no_shift)
{
  if ( !is_imm_no_shift(op) && !no_shift )
    out_symbol('#');
  out_value(op, OOFW_IMM);
}

//--------------------------------------------------------------------------
// Output an operand as an address
void out_st9_t::out_addr(const op_t &op, bool find_label)
{
  ea_t full_addr = get_dest_addr(insn, op);
  if ( !find_label || !out_name_expr(op, full_addr, BADADDR) )
    out_value(op, OOF_ADDR | OOFS_NOSIGN | OOFW_16);
}

//--------------------------------------------------------------------------
// Generate disassembly header
void idaapi st9_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX);
}

//--------------------------------------------------------------------------
// Generate disassembly footer
void st9_t::st9_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      ctx.out_char(' ');
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}

#define BEG_TAG(x)     if ( is_ind(x)) out_symbol('(' )
#define END_TAG(x)     if ( is_ind(x)) out_symbol(')' )

//--------------------------------------------------------------------------
// Output an operand
bool out_st9_t::out_operand(const op_t &op)
{
  switch ( op.type )
  {
    // Data / Code memory address
    case o_near:
    case o_far:
    case o_mem:
      BEG_TAG(op);
      out_addr(op);
      END_TAG(op);
      break;

    // Immediate value
    case o_imm:
      BEG_TAG(op);
      {
        const ioport_t *port = pm().find_sym(op.value);
        // this immediate is represented in the .cfg file
        if ( port != nullptr ) // otherwise, simply print the value
          out_line(port->name.c_str(), COLOR_IMPNAME);
        else // otherwise, simply print the value
          out_imm(op);
      }
      END_TAG(op);
      break;

    // Displacement
    case o_displ:
      out_addr(op, false);
      out_symbol('(');
      out_reg(op);
      out_symbol(')');
      break;

    // Register
    case o_reg:
      BEG_TAG(op);
      out_reg(op);
      END_TAG(op);
      if ( is_reg_with_bit(op) )
      {
        out_symbol('.');
        if ( is_bit_compl(op) )
          out_symbol('!');
        out_imm(op, true);
      }
      break;

    // Phrase
    case o_phrase:
      switch ( op.specflag2 )
      {
        case fPI:   // post increment
          out_symbol('(');
          out_reg(op);
          out_symbol(')');
          out_symbol('+');
          break;

        case fPD:   // pre decrement
          out_symbol('-');
          out_symbol('(');
          out_reg(op);
          out_symbol(')');
          break;

        case fDISP: // displacement
          out_reg(op);
          out_symbol('(');
          {
            ushort reg = op.specflag2 << 8;
            reg |= op.specflag3;
            out_reg(reg);
          }
          out_symbol(')');
          break;

        default:
          INTERR(10077);
      }
      break;

    // No operand
    case o_void:
      break;

    default:
      INTERR(10078);
  }
  return 1;
}

//--------------------------------------------------------------------------
void out_st9_t::out_proc_mnem(void)
{
  char postfix[5];
  postfix[0] = '\0';

  if ( is_jmp_cc(insn.itype) )
    qstrncpy(postfix, ConditionCodes[insn.auxpref], sizeof(postfix));

  out_mnem(8, postfix);
}

//--------------------------------------------------------------------------
// Output an instruction
void out_st9_t::out_insn(void)
{
  out_mnemonic();

  //
  // print insn operands
  //

  out_one_operand(0); // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(1);
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    out_char(' ');
    out_one_operand(2);
  }

  // output a character representation of the immediate values
  // embedded in the instruction as comments
  out_immchar_cmts();

  if ( pm().gr_cmt != nullptr )
  {
    out_char(' ');
    out_line(ash.cmnt, COLOR_AUTOCMT);
    out_char(' ');
    out_line(pm().gr_cmt, COLOR_AUTOCMT);
    if ( ash.cmnt2 != nullptr )
    {
      out_char(' ');
      out_line(ash.cmnt2, COLOR_AUTOCMT);
    }
    pm().gr_cmt = nullptr;
  }
  flush_outbuf();
}

//--------------------------------------------------------------------------
// Generate a segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Sarea) could be made const
void st9_t::st9_segstart(outctx_t &ctx, segment_t *Sarea) const
{
  qstring sname;
  get_visible_segm_name(&sname, Sarea);

  const char *segname = sname.c_str();
  if ( *segname == '_' )
    segname++;

  if ( ash.uflag & UAS_ASW )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), segname);
  else
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".section .%s", SCOLOR_ASMDIR), segname);

  ea_t orgbase = ctx.insn_ea - get_segm_para(Sarea);

  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void st9_t::st9_assumes(outctx_t &ctx)
{
  ea_t ea = ctx.insn_ea;
  segment_t *sega = getseg(ea);

  if ( (inf_get_outflags() & OFLG_GEN_ASSUME) == 0 || sega == nullptr )
    return;
  bool seg_started = (ea == sega->start_ea);

  for ( int i = rRW; i <= rDPR3; ++i )
  {
    if ( i == rCSR )
      continue;

    sreg_range_t sra;
    if ( !get_sreg_range(&sra, ea, i) || sra.val == BADSEL )
      continue;
    bool show = sra.start_ea == ea;
    if ( show )
    {
      sreg_range_t prev_sra;
      if ( get_prev_sreg_range(&prev_sra, ea, i) )
        show = sra.val != prev_sra.val;
    }
    if ( seg_started || show )
    {
      sel_t r = sra.val;
      if ( i == rRW )
      {
        int rwhi = (r >> 8) & 0xFF;
        int rwlo = r & 0xFF;
        ctx.gen_cmt_line("Register window: (%d, %d)", rwhi, rwlo);
      }
      else if ( i == rRP )
      {
        ctx.gen_cmt_line("Register page: %d", (int)r);
      }
      else
      {
        char buf[MAX_NUMBUF];
        btoa(buf, sizeof(buf), r);
        ctx.gen_cmt_line("assume %s: %s (page 0x%a)",
          ph.reg_names[i],
          buf,
          (r << 14));
      }
    }
  }
}
