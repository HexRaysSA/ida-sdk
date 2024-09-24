
#include <ida.hpp>
#include <idp.hpp>
#include <segregs.hpp>
#include <diskio.hpp>
#include <cvt64.hpp>

#include "m65816.hpp"
int data_id;

#include "../../ldr/snes/addr.cpp"
//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "A",  // Accumulator
  "X",  // Index
  "Y",  // Index
  "S",  // Stack register (used?)
  "cs",
  "ds",

  "B",  // Data bank
  "D",  // Direct page register (used?)

  "m", // Holds accumulator-is-8-bits flag
  "x", // Holds indices-are-8-bits flag
  "e", // Holds emulation mode flag

  "PB" // Program bank
};


// ---------------------------------------------------------------------------
ea_t m65816_t::xlat(ea_t address)
{
  return sa->xlat(address);
}

// ---------------------------------------------------------------------------
m65816_t::m65816_t()
{
  cartridge = new SuperFamicomCartridge;
  sa = new snes_addr_t;
}

// ---------------------------------------------------------------------------
m65816_t::~m65816_t()
{
  delete cartridge;
  cartridge = nullptr;
  delete sa;
  sa = nullptr;
}

// ---------------------------------------------------------------------------
// Handler for: get_autocmt.
// Will possibly store a comment in 'buf',
// depending on whether an autocmt is deemed necessary
// for the current line.
//
// For the moment this will just print, in a user-friendly
// way, information about the addressing mode, if needed.
static bool make_insn_cmt(qstring *buf, const insn_t &insn)
{
  uint8 opcode = get_byte(insn.ea);
  const struct opcode_info_t &opcode_info = get_opcode_info(opcode);
  static const bool addressing_info_required[] =
  {
    false, // ABS
    false, // ABS_IX,
    false, // ABS_IY,
    false, // ABS_IX_INDIR,
    false, // ABS_INDIR,
    false, // ABS_INDIR_LONG,
    false, // ABS_LONG,
    false, // ABS_LONG_IX,
    false, // ACC,
    true,  // BLK_MOV,
    false, // DP,
    false, // DP_IX,
    false, // DP_IY,
    false, // DP_IX_INDIR,
    false, // DP_INDIR,
    false, // DP_INDIR_LONG,
    false, // DP_INDIR_IY,
    false, // DP_INDIR_LONG_IY,
    false, // IMM,
    false, // IMPLIED,
    true,  // PC_REL,
    true,  // PC_REL_LONG,
    false, // STACK_ABS,
    false, // STACK_DP_INDIR,
    false, // STACK_INT,
    false, // STACK_PC_REL,
    false, // STACK_PULL,
    false, // STACK_PUSH,
    false, // STACK_RTI,
    false, // STACK_RTL,
    false, // STACK_RTS,
    false, // STACK_REL,
    false  // STACK_REL_INDIR_IY,
  };

  if ( !addressing_info_required[opcode_info.addr] )
    return false;

  const struct addrmode_info_t &addrmode_info = AddressingModes[opcode_info.addr];
  *buf = addrmode_info.name;
  return true;
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::sgr_changed:
      {
        ea_t start_ea = va_arg(va, ea_t);
        ea_t dummy   = va_arg(va, ea_t); qnotused(dummy);
        int regnum   = va_arg(va, int);
        sel_t value  = va_arg(va, sel_t);
        if ( regnum == rB )
        {
//        sel_t d2 = va_arg(va, sel_t); qnotused(d2);
          if ( value == BADSEL )
            split_sreg_range(start_ea, rDs, BADSEL, SR_auto);
          else
            split_sreg_range(start_ea, rDs, value << 12, SR_auto);
        }
        else if ( regnum == rPB )
        {
          uint16 offset = start_ea & 0xffff;
          ea_t newEA = pm.xlat((value << 16) + offset);
          if ( start_ea != newEA )
            warning("Inconsistent program bank number ($%02X:%04X != $%02X:%04X)",
                    uint32(start_ea >> 16),
                    offset,
                    uint8(value),
                    offset);
        }
      }
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
void m65816_t::load_from_idb()
{
  cartridge->read_hash(helper);
  //cartridge.print();
  if ( !sa->addr_init(*cartridge) )
    warning("Unsupported mapper: %s", cartridge->mapper_string());
  ioh.restore_device(IORESP_NONE);
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(m65816_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi m65816_t::on_event(ssize_t msgid, va_list va)
{
  int retcode = 1;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create(PROCMOD_NODE_NAME);
      break;
    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;
    case processor_t::ev_newprc:
      break;
    case processor_t::ev_creating_segm:
      {
        segment_t *sptr = va_arg(va, segment_t *);

        // default DS is equal to CS
        sptr->defsr[rDs - ph.reg_first_sreg] = sptr->sel;

        // detect SNES bank 0
        if ( xlat(0) == (sptr->start_ea & 0xff0000) )
        {
          // initial bank must be $00 (especially important on HiROM)
          // Example: Donkey Kong Country 2 - Emulation_mode_RESET
          sptr->defsr[rB  - ph.reg_first_sreg] = 0;
          sptr->defsr[rPB - ph.reg_first_sreg] = 0;
        }
        else
        {
          // otherwise, set the default bank number from EA
          uint8 pb = sptr->start_ea >> 16;
          sptr->defsr[rB  - ph.reg_first_sreg] = pb;
          sptr->defsr[rPB - ph.reg_first_sreg] = pb;
        }
      }
      break;
    case processor_t::ev_newfile:
      {
        cartridge->read_hash(helper);
        //cartridge.print();
        if ( !sa->addr_init(*cartridge) )
          warning("Unsupported mapper: %s", cartridge->mapper_string());

        const char *device_ptr = nullptr;
        if ( cartridge->has_superfx )
          device_ptr = "superfx";
        else if ( cartridge->has_sa1 )
          device_ptr = "sa1";
        else if ( cartridge->has_cx4 )
          device_ptr = "cx4";
        else if ( cartridge->has_spc7110 )
          device_ptr = "spc7110";
        else if ( cartridge->has_sdd1 )
          device_ptr = "sdd1";
        else if ( cartridge->has_sharprtc )
          device_ptr = "sharprtc";
        else if ( cartridge->has_epsonrtc )
          device_ptr = "epsonrtc";
        else if ( cartridge->has_obc1 )
          device_ptr = "obc1";
        else if ( cartridge->has_dsp1 )
          device_ptr = "dsp1";
        else if ( cartridge->has_dsp2 )
          device_ptr = "dsp2";
        else if ( cartridge->has_dsp3 )
          device_ptr = "dsp3";
        else if ( cartridge->has_dsp4 )
          device_ptr = "dsp4";
        else if ( cartridge->has_st010 )
          device_ptr = "st010";
        else if ( cartridge->has_st011 )
          device_ptr = "st011";
        else if ( cartridge->has_st018 )
          device_ptr = "st018";
        qstring loader_device;
        if ( device_ptr == nullptr )
        {
          ssize_t len = helper.hashstr(&loader_device, "device");
          if ( len <= 0 )
            device_ptr = "65816";
          else
            device_ptr = loader_device.c_str();
        }
        ioh.set_device_name(device_ptr, IORESP_ALL);

        set_default_sreg_value(nullptr, rFm, 1);
        set_default_sreg_value(nullptr, rFx, 1);
        set_default_sreg_value(nullptr, rFe, 1);
        set_default_sreg_value(nullptr, rD,  0);

        // see processor_t::ev_creating_segm for the following registers
        //set_default_sreg_value(nullptr, rPB, 0);
        //set_default_sreg_value(nullptr, rB,  0);
        //set_default_sreg_value(nullptr, rDs, 0);

        if ( inf_get_start_ip() != BADADDR )
        {
          ea_t reset_ea = xlat(inf_get_start_ip());
          ea_t sea = getseg(reset_ea)->start_ea;
          split_sreg_range(reset_ea, rFm, get_sreg(sea, rFm), SR_auto);
          split_sreg_range(reset_ea, rFx, get_sreg(sea, rFx), SR_auto);
          split_sreg_range(reset_ea, rFe, get_sreg(sea, rFe), SR_auto);
          split_sreg_range(reset_ea, rPB, 0,                  SR_auto);
          split_sreg_range(reset_ea, rB,  0,                  SR_auto);
          split_sreg_range(reset_ea, rD,  get_sreg(sea, rD),  SR_auto);
        }
      }
      break;
    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      {
        load_from_idb();
        if ( msgid == processor_t::ev_oldfile )
        { // read rommode_t for backward compatibility
          nodeidx_t mode = helper.hashval_long("rommode_t");
          if ( mode != 0 )
          {
            switch ( mode )
            {
              case 0x20:
                cartridge->mapper = SuperFamicomCartridge::LoROM;
                break;

              case 0x21:
                cartridge->mapper = SuperFamicomCartridge::HiROM;
                break;
            }
            helper.hashdel("rommode_t");
            cartridge->write_hash(helper);
          }
        }
      }
      break;
    case processor_t::ev_get_autocmt:
      {
        qstring *buf       = va_arg(va, qstring *);
        const insn_t *insn = va_arg(va, insn_t *);
        if ( make_insn_cmt(buf, *insn) )
          retcode = 1;
      }
      break;
    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        retcode = 0;
        ea_t cref_addr;
        for ( cref_addr = get_first_cref_to(insn->ea);
              cref_addr != BADADDR;
              cref_addr = get_next_cref_to(insn->ea, cref_addr) )
        {
          uint8 opcode = get_byte(cref_addr);
          const struct opcode_info_t &opinfo = get_opcode_info(opcode);
          if ( opinfo.itype == M65816_jsl
            || opinfo.itype == M65816_jsr
            || opinfo.itype == M65816_jml )
          {
            retcode = 100;
            break;
          }
        }
      }
      break;
    case processor_t::ev_is_call_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        const struct opcode_info_t &opinfo = get_opcode_info(get_byte(insn->ea));
        if ( opinfo.itype == M65816_jsr
          || opinfo.itype == M65816_jsl )
          retcode = 1;
        else
          retcode = -1;
      }
      break;
    case processor_t::ev_is_ret_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        const struct opcode_info_t &opinfo = get_opcode_info(get_byte(insn->ea));
        if ( opinfo.itype == M65816_rti
          || opinfo.itype == M65816_rtl
          || opinfo.itype == M65816_rts )
          retcode = 1;
        else
          retcode = -1;
      }
      break;
    case processor_t::ev_is_indirect_jump:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        const struct opcode_info_t &opinfo = get_opcode_info(get_byte(insn->ea));
        if ( opinfo.itype == M65816_jmp
          || opinfo.itype == M65816_jml )
        {
          if ( opinfo.addr == ABS_INDIR
            || opinfo.addr == ABS_IX_INDIR
            || opinfo.addr == ABS_INDIR_LONG )
            retcode = 2;
          else
            retcode = 1;
        }
        else
          retcode = 0;
      }
      break;
    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m65816_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m65816_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m65816_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m65816_assumes(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
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

    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_std_procmod_handlers(*md);
      }
      break;

    case processor_t::ev_privrange_changed:
      // recreate node as it was migrated
      helper.create(PROCMOD_NODE_NAME);
      break;

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        static const cvt64_node_tag_t node_info[] =
        {
          CVT64_NODE_DEVICE,
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }

    case processor_t::ev_cvt64_hashval:
      {
        nodeidx_t node = va_arg(va, nodeidx_t);
        uchar tag = va_argi(va, uchar);
        const char *name = va_arg(va, const char *);
        if ( helper == node && tag == htag && streq(name, "rom_size") )
        {
          cartridge->read_hash(helper);
          cartridge->write_hash(helper);
          return 1;
        }
      }
      break;
#endif

    default:
      retcode = 0;
      break;
  }
  return retcode;
}


//-----------------------------------------------------------------------
//                           CA65 ASSEMBLER
//
// http://www.cc65.org/doc/ca65-4.html#ss4.1
//-----------------------------------------------------------------------
static const asm_t ca65asm =
{
  AS_COLON | ASH_HEXF4, // Assembler features
  0,                    // User-defined flags
  "CA65 ASSEMBLER",     // Name
  0,
  nullptr,                 // headers
  ".ORG",               // origin directive
  ".END",               // end directive

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "\\'",        // special symbols in char and string constants

  ".BYTE",      // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
};

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *const ps_headers[] =
{
  ".code",
  nullptr
};

static const asm_t pseudosam =
{
  AS_COLON | ASH_HEXF1 | AS_N2CHR | AS_NOXRF,
  UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
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

//-----------------------------------------------------------------------
//      SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988
//-----------------------------------------------------------------------
static const asm_t svasm =
{
  AS_COLON | ASH_HEXF4,
  UAS_NOSEG,
  "SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988",
  0,
  nullptr,         // headers
  "* = ",
  ".END",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "\\'",        // special symbols in char and string constants

  ".BYTE",      // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
};

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static const asm_t tasm =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  nullptr,         // headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
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
  nullptr,     // mod
  "and",    // and
  "or",     // or
  nullptr,    // xor
  "not",    // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};


//-----------------------------------------------------------------------
//      Avocet assembler definiton
//-----------------------------------------------------------------------
static const asm_t avocet =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Avocet Systems 2500AD 6502 Assembler",
  0,
  nullptr,         // headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".fcc",       // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".ds %s",     // uninited arrays
};

static const asm_t *const asms[] =
{
  &ca65asm,

  // 6502 asm_t; imported from the 6502 CPU module.
  &svasm,
  &tasm,
  &pseudosam,
  &avocet,
  nullptr
};

//-----------------------------------------------------------------------
#define FAMILY "MOS Technology 658xx series:"
static const char *const shnames[] = { "m65816", "m65c816", nullptr };
static const char *const lnames[] = { FAMILY"MOS Technology 65816", "MOS Technology 65C816", nullptr };

static const uchar retcode_1[] = { 0x60 }; // RTS
static const uchar retcode_2[] = { 0x40 }; // RTI
static const uchar retcode_3[] = { 0x6b }; // RTL

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_65C816,            // id
                          // flag
    PR_SEGS
  | PR_SEGTRANS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                     // Register names
  qnumber(RegNames),            // Number of registers

  rCs,                          // first segreg
  rPB,                          // last  segreg
  0,                            // size of a segment register
  rCs,                          // number of CS register
  rDs,                          // number of DS register

  nullptr,                         // No known code start sequences
  retcodes,

  0,
  M65816_last,
  Instructions,                 // instruc
  3,                    // int tbyte_size;  -- doesn't exist

  { 0, 0, 0, 0 },       // char real_width[4];
                            // number of symbols after decimal point
                            // 2byte float (0-does not exist)
                            // normal float
                            // normal double
                            // long double
  M65816_rts,           // Icode of return instruction. It is ok to give any of possible return instructions
};

