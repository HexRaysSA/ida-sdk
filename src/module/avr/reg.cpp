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
#include <segregs.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <fixup.hpp>
#include <cvt64.hpp>
#include "notify_codes.hpp"
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
  "r24", "r25", "XL", "XH", "YL", "YH", "ZL", "ZH",
  "cs","ds",       // virtual registers for code and data segments
};

//-----------------------------------------------------------------------
//           AVR assembler
//-----------------------------------------------------------------------
static const char *const avr_header[] =
{
  ".equ XL, 26",
  ".equ XH, 27",
  ".equ YL, 28",
  ".equ YH, 29",
  ".equ ZL, 30",
  ".equ ZH, 31",
  nullptr
};

static const asm_t avrasm =
{
  AS_COLON|AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF0|AS_ONEDUP,
  0,
  "AVR Assembler",
  0,
  avr_header,   // header lines
  ".org",       // org
  ".exit",      // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  ".dd",        // double words
  nullptr,         // no qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".byte %s",   // uninited arrays
  ".equ",       // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  nullptr,         // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // "public" name keyword
  nullptr,         // "weak"   name keyword
  nullptr,         // "extrn"  name keyword
  nullptr,         // "comm" (communal variable)
  nullptr,         // get_type_name
  nullptr,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  nullptr,         // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
};

static const asm_t *const asms[] = { &avrasm, nullptr };

//--------------------------------------------------------------------------
static const char cfgname[] = "avr.cfg";

//--------------------------------------------------------------------------
bool avr_iohandler_t::entry_processing(ea_t &ea1, const char * /*word*/, const char * /*cmt*/)
{
  pm.helper.altset_ea(ea1, 1);
  create_insn(ea1);
  ea_t ea = get_first_fcref_from(ea1);
  if ( ea != BADADDR )
    ea1 = ea;
  return false; // continue processing
}

//--------------------------------------------------------------------------
bool avr_iohandler_t::check_ioresp() const
{
  return inf_like_binary() || pm.imageFile;
}

//--------------------------------------------------------------------------
bool avr_t::is_possible_subarch(int addr) const
{
  // old version of gcc-arm don't use 31/51/etc subarches - only 3/5/... :(
  // maybe make option?
  return subarch == 0 || subarch == addr || (addr/10 == subarch);
}

//--------------------------------------------------------------------------
const char *avr_iohandler_t::iocallback(const ioports_t &_ports, const char *line)
{
  int addr;
  char word[MAXSTR];
  word[MAXSTR-1] = '\0';
  CASSERT(MAXSTR == 1024);
  if ( qsscanf(line, "%1023[^=] = %d", word, &addr) == 2 )
  {
    if ( streq(word, "RAM") )
    {
      pm.ramsize = addr;
      return nullptr;
    }
    if ( streq(word, "ROM") )
    {
      pm.romsize = addr >> 1;
      return nullptr;
    }
    if ( streq(word, "EEPROM") )
    {
      pm.eepromsize = addr;
      return nullptr;
    }
    if ( streq(word, "SUBARCH") )
    {
      // set pm.subarch based on SUBARCH in the config file
      // it is needed to do XMEGA specific things for non-elf files
      pm.subarch = addr;
      return pm.is_possible_subarch(addr) ? nullptr : IOPORT_SKIP_DEVICE;
    }
  }
  return standard_callback(_ports, line);
}

//--------------------------------------------------------------------------
struct avr_ioport_parser_t : public choose_ioport_parser_t
{
  avr_t &pm;

  avr_ioport_parser_t(avr_t &_pm) : pm(_pm) {}
  virtual bool parse(qstring *, const char *line) override
  {
    int addr;
    char word[MAXSTR];
    word[MAXSTR-1] = '\0';
    CASSERT(MAXSTR == 1024);
    bool skip = qsscanf(line, "%1023[^=] = %d", word, &addr) == 2
             && strcmp(word, "SUBARCH") == 0
             && !pm.is_possible_subarch(addr);
    return !skip;
  }
};

//--------------------------------------------------------------------------
const ioport_t *avr_t::find_port(ea_t address)
{
  return find_ioport(ioh.ports, address);
}

//--------------------------------------------------------------------------
const char *avr_t::find_bit(ea_t address, size_t bit)
{
  const ioport_bit_t *b = find_ioport_bit(ioh.ports, address, bit);
  return b ? b->name.c_str() : nullptr;
}

//--------------------------------------------------------------------------
void avr_t::setup_avr_device(int resp_info)
{
  if ( !choose_ioport_device(&ioh.device, cfgname) )
    return;

  ioh.set_device_name(ioh.device.c_str(), resp_info);
  if ( get_first_seg() == nullptr )  // set processor options before load file
    return;
  plan_range(0, BADADDR); // reanalyze program

  // resize the ROM segment
  {
    segment_t *s = getseg(node2ea(helper.altval(-1)));
    if ( s == nullptr )
      s = get_first_seg();  // for the old databases
    if ( s != nullptr )  //-V547 's != 0' is always true
    {
      if ( s->size() > romsize )
        warning("The input file is bigger than the ROM size of the current device");
      set_segm_end(s->start_ea, s->start_ea+romsize, SEGMOD_KILL);
    }
  }
  // resize the RAM segment
  {
    segment_t *s = get_segm_by_name("RAM");
    if ( s == nullptr && ramsize != 0 )
    {
      ea_t start = (inf_get_max_ea() + 0xFFFFF) & ~0xFFFFF;
      add_segm(start>>4, start, start+ramsize, "RAM", "DATA");
      s = getseg(start);
    }
    ram = BADADDR;
    if ( s != nullptr )
    {
      int i;
      // offset added to I/O port address to get RAM address
      int ram_offset = 0;
      ram = s->start_ea;
      set_segm_end(ram, ram+ramsize, SEGMOD_KILL);

      if ( subarch < E_AVR_MACH_TINY )
      {
        // legacy devices start with 32 GPRs
        // 0x20 needs to be added to the port address
        ram_offset = 0x20;
       // set register names for aliases in data memory
        for ( i=0; i < 32; i++ )
          if ( !has_any_name(get_flags(ram+i)) )
            set_name(ram+i, register_names[i], SN_NODUMMY);
      }

      // set I/O port names
      for ( i=0; i < ioh.ports.size(); i++ )
      {
        const ioport_t &p = ioh.ports[i];
        set_name(ram+p.address+ram_offset, p.name.c_str(), SN_NODUMMY);
        set_cmt(ram+p.address+ram_offset, p.cmt.c_str(), true);
      }
    }
  }
}

//--------------------------------------------------------------------------
const char *avr_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded)
{
  if ( keyword == nullptr )
  {
    setup_avr_device(IORESP_INT);
    return IDPOPT_OK;
  }
  else if ( strcmp(keyword, "AVR_MCPU") == 0 )
  {
    if ( value_type != IDPOPT_STR )
      return IDPOPT_BADTYPE;

    ioh.device = (const char *) value;
    if ( idb_loaded )
      ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
    return IDPOPT_OK;
  }

  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
bool avr_t::set_param_by_arch(void)
{
  int max_rom, max_ram, max_eeprom;
  // preset MAXIMUM's of memory size's by mcpu subtype
  switch ( subarch )
  {
    default:
      subarch = 0;
      return false; // LOGICAL ERROR?

    // at90s1200, attiny10, attiny11, attiny12, attiny15, attiny28
    case E_AVR_MACH_AVR1: // ROM<=1k
      max_rom     = 1024;
      max_ram     = 32;
      max_eeprom  = 64;
      break;
    // at90s2313, at90s2323, at90s2333, at90s2343, attiny22, attiny26,
    // at90s4414 /* XXX -> 8515 */, at90s4433, at90s4434 /* XXX -> 8535 */,
    // at90s8515, at90c8534, at90s8535
    case E_AVR_MACH_AVR2: // ROM<=8k
    // attiny13, attiny13a, attiny2313, attiny24, attiny44, attiny84,
    // attiny25, attiny45, attiny85, attiny261, attiny461, attiny861,
    // attiny43u, attiny48, attiny88, at86rf401
  // PASS THRU
    case E_AVR_MACH_AVR25:  // ROM<=8k
      max_rom     = 8*1024;
      max_ram     = 512;
      max_eeprom  = 512;
      break;
      // at43usb355, at76c711
    case E_AVR_MACH_AVR3:   // ROM>=8k<=64k
      max_rom     = 64*1024;
      max_ram     = 1024;
      max_eeprom  = 0;
      break;
    // atmega103,  at43usb320,
    case E_AVR_MACH_AVR31:  // ROM>=65k&&<=128k, (RAM=65k, EEPROM=4k)
      max_rom     = 128*1024;
      max_ram     = 4*1024;
      max_eeprom  = 4*1024;
      break;
    // attiny167, at90usb82, at90usb162
    case E_AVR_MACH_AVR35:  // ROM>=8k&&<=64k,
      max_rom     = 64*1024;
      max_ram     = 512;
      max_eeprom  = 512;
      break;
    // atmega8, atmega48, atmega48p, atmega88, atmega88p, atmega8515,
    // atmega8535, atmega8hva, at90pwm1, at90pwm2, at90pwm2b, at90pwm3,
    // at90pwm3b
    case E_AVR_MACH_AVR4:   // ROM<=8k
      max_rom     = 8*1024;
      max_ram     = 1024;
      max_eeprom  = 512;
      break;
    // atmega16, atmega161, atmega162, atmega163, atmega164p, atmega165,
    // atmega165p, atmega168, atmega168p, atmega169, atmega169p, atmega32,
    // atmega323, atmega324p, atmega325, atmega325p, atmega3250, atmega3250p,
    // atmega328p, atmega329, atmega329p, atmega3290, atmega3290p, atmega406,
    // atmega64, atmega640, atmega644, atmega644p, atmega645, atmega649,
    // atmega6450, atmega6490, atmega16hva, at90can32, at90can64, at90pwm216,
    // at90pwm316, atmega32c1, atmega32m1, atmega32u4, at90usb646, at90usb647,
    // at94k
    case E_AVR_MACH_AVR5:   // ROM>=8k&&<=64k
      max_rom     = 64*1024;
      max_ram     = 4*1024;
      max_eeprom  = 2*1024;
      break;
    // atmega128, atmega1280, atmega1281, atmega1284p,
    // at90can128, at90usb1286, at90usb1287
    case E_AVR_MACH_AVR51:  // ROM=128k
      max_rom     = 128*1024;
      max_ram     = 16*1024;
      max_eeprom  = 4*1024;
      break;
    // atmega2560, atmega2561
    case E_AVR_MACH_AVR6:   // ROM=256k (3-byte pc -- is supported?)
      max_rom     = 256*1024;
      max_ram     = 8*1024;
      max_eeprom  = 4*1024;
      break;
    case E_AVR_MACH_XMEGA1: // ROM < 8K, ram=?
      max_rom     = 8*1024;
      max_ram     = 1024;
      max_eeprom  = 512;
      break;
    // ATxmega16A4, ATxmega16D4, ATxmega32D4
    case E_AVR_MACH_XMEGA2: // 8K < FLASH <= 64K, RAM <= 64K
      max_rom     = 64*1024;
      max_ram     = 64*1024;
      max_eeprom  = 1024;
      break;
    // ATxmega32A4
    case E_AVR_MACH_XMEGA3: // 8K < FLASH <= 64K, RAM > 64K
      max_rom     = 64*1024;
      max_ram     = 128*1024; // ?
      max_eeprom  = 1024;
      break;
    // ATxmega64A3, ATxmega64D3
    case E_AVR_MACH_XMEGA4: // 64K < FLASH <= 128K, RAM <= 64K
      max_rom     = 128*1024;
      max_ram     = 64*1024;
      max_eeprom  = 2048;
      break;
    // ATxmega64A1
    case E_AVR_MACH_XMEGA5: // 64K < FLASH <= 128K, RAM > 64K
      max_rom     = 128*1024;
      max_ram     = 128*1024;
      max_eeprom  = 2048;
      break;
    // ATxmega128A3, ATxmega128D3, ATxmega192A3, ATxmega192D3,
    // ATxmega256A3B, ATxmega256A3, ATxmega256D3
    case E_AVR_MACH_XMEGA6: // 128K < FLASH <= 256K, RAM <= 64K
      max_rom     = 256*1024;
      max_ram     = 64*1024;
      max_eeprom  = 4096;
      break;
    // ATxmega128A1
    case E_AVR_MACH_XMEGA7: // 128K < FLASH <= 256K, RAM > 64K
      max_rom     = 256*1024;
      max_ram     = 128*1024;
      max_eeprom  = 4096;
      break;
  }
  avr_ioport_parser_t parser(*this);
  if ( !choose_ioport_device2(&ioh.device, cfgname, &parser) )
  {
    ioh.device.sprnt("avr%d", subarch);
    ioh.device[sizeof("avrX")-1] = '\0';
    romsize    = max_rom >> 1;
    ramsize    = max_ram;
    eepromsize = max_eeprom;
  }
  else
  {
    ioh.set_device_name(ioh.device.c_str(), IORESP_INT);
    plan_range(0, BADADDR); // reanalyze program
  }
  return true;
}

//--------------------------------------------------------------------------
static inline ea_t get16bit(ea_t ea)
{
  if ( segtype(ea) == SEG_CODE )
    return get_wide_byte(ea);

  return get_word(ea);
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::segm_added:
      {
        segment_t *s = va_arg(va, segment_t *);
        qstring sclass;
        if ( get_segm_class(&sclass, s) > 0 && sclass == "DATA" )
          set_default_dataseg(s->sel);
      }
      break;

    case idb_event::segm_moved: // A segment is moved
                                // Fix processor dependent address sensitive information
      {
        ea_t from    = va_arg(va, ea_t);
        ea_t to      = va_arg(va, ea_t);
        asize_t size = va_arg(va, asize_t);
        //bool changed_netmap = va_argi(va, bool);

        nodeidx_t ndx1 = ea2node(from);
        nodeidx_t ndx2 = ea2node(to);
        pm.helper.altshift(ndx1, ndx2, size); // move address information
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static bool idaapi avr16_apply(
        const fixup_handler_t *fh,
        ea_t item_ea,
        ea_t fixup_ea,
        int opnum,
        bool /*is_macro*/,
        const fixup_data_t &fd)
{
  avr_t &pm = *GET_MODULE_DATA(avr_t);
  if ( !pm.nonBinary
    || fd.has_base()
    || fd.is_unused()
    || fd.displacement != 0 )
  {
    msg("%a: Unexpected or incorrect CUSTOM_FIXUP\n", fixup_ea);
    return false;
  }

  if ( is_unknown(get_flags(item_ea)) )
    create_16bit_data(item_ea, 2);

  refinfo_t ri;
  ri.flags  = fh->reftype;
  ri.base   = fd.get_base();
  ri.target = ri.base + fd.off;
  ri.tdelta = fd.displacement;
  op_offset_ex(item_ea, opnum, &ri);
  return true;
}

//--------------------------------------------------------------------------
//lint -e{818} could be declared const
static int idaapi avr16_gen_expr(
        qstring * /*buf*/,
        qstring * /*format*/,
        ea_t ea,
        int numop,
        const refinfo_t &ri,
        ea_t /*from*/,
        adiff_t *opval,
        ea_t * /*target*/,
        ea_t * /*fullvalue*/,
        int /*getn_flags*/)
{
  avr_t &pm = *GET_MODULE_DATA(avr_t);
  if ( !pm.nonBinary
    || numop != 0
    || ri.type() == (pm.ref_avr16_id | REFINFO_CUSTOM)
    || ri.tdelta != 0
    || ri.target == BADADDR
    || *opval != get16bit(ea) )
  {
    msg("%a: Unexpected or incorrect CUSTOM offset\n", ea);
    return 0;
  }
  return 3; // process as a regular fixup
}

//--------------------------------------------------------------------------
static const custom_refinfo_handler_t ref_avr16 =
{
  sizeof(custom_refinfo_handler_t),
  "AVR16",
  "AVR 16-bit offset",
  0,                    // properties (currently 0)
  avr16_gen_expr,       // gen_expr
  nullptr,                 // calc_reference_data
  nullptr,                 // get_format
};

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(avr_t));
  return 0;
}

//----------------------------------------------------------------------
void avr_t::load_from_idb()
{
  ioh.restore_device();
  segment_t *s = get_segm_by_name("RAM");
  if ( s != nullptr )
    ram = s->start_ea;
}

//--------------------------------------------------------------------------
ssize_t idaapi avr_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      cfh_avr16.apply = avr16_apply;
      cfh_avr16_id = register_custom_fixup(&cfh_avr16);
      ref_avr16_id = register_custom_refinfo(&ref_avr16);
      cfh_avr16.reftype = REFINFO_CUSTOM | ref_avr16_id;
      break;

    case processor_t::ev_term:
      cfh_avr16.reftype = REFINFO_CUSTOM;
      unregister_custom_refinfo(ref_avr16_id);
      unregister_custom_fixup(cfh_avr16_id);
      unhook_event_listener(HT_IDB, &idb_listener);
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case avr_module_t::ev_set_machine_type:   // elf-loader 'set machine type' and file type
      subarch   = va_arg(va, int);
      imageFile = va_argi(va, bool);
      nonBinary = true;
      break;

    case processor_t::ev_newfile:   // new file loaded
      // remember the ROM segment
      {
        segment_t *s = get_first_seg();
        if ( s != nullptr )
        {
          if ( subarch == 0 )
            set_segm_name(s, "ROM");
          helper.altset(-1, ea2node(s->start_ea));
        }
      }
      if ( subarch != 0 && set_param_by_arch() )
        break;
      setup_avr_device(/*IORESP_AREA|*/IORESP_INT); // allow the user to select the device
      if ( subarch != 0 )
        break;
      // create additional segments
      {
        ea_t start = (inf_get_max_ea() + 0xFFFFF) & ~0xFFFFF;
        if ( eepromsize != 0 )
        {
          char *file = ask_file(false, "*.bin", "Please enter the binary EEPROM image file");
          if ( file != nullptr )
          {
            add_segm(start>>4, start, start+eepromsize, "EEPROM", "DATA");
            linput_t *li = open_linput(file, false);
            if ( li != nullptr )
            {
              uint64 size = qlsize(li);
              if ( size > eepromsize )
                size = eepromsize;
              file2base(li, 0, start, start+size, FILEREG_NOTPATCHABLE);
              close_linput(li);
            }
          }
        }
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:   // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_newprc:    // new processor type
      break;

    case processor_t::ev_newasm:    // new assembler type
      break;

    case processor_t::ev_out_label: // The kernel is going to generate an instruction
                                 // label line or a function header
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        if ( helper.altval_ea(ctx->insn_ea) ) // if entry point
        {
          char buf[MAX_NUMBUF];
          btoa(buf, sizeof(buf), ctx->insn_ea);
          ctx->gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
        }
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        avr_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        avr_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        avr_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        avr_segend(*ctx, seg);
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

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char **errmsg = va_arg(va, const char **);
        bool idb_loaded = va_argi(va, bool);
        const char *ret = set_idp_options(keyword, value_type, value, idb_loaded);
        if ( ret == IDPOPT_OK )
          return 1;
        if ( errmsg != nullptr )
          *errmsg = ret;
        return -1;
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
          { helper, atag|NETMAP_VAL|NETMAP_VAL_NDX, nodeidx_t(-1) },
          { helper, atag|NETMAP_VAL, 0 },
          { helper, ELF_AVR_TAG|NETMAP_V8, 0 },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
// 1001 0101 0xx0 1000     ret
// 1001 0101 0xx1 1000     reti
static const uchar retcode_1[] = { 0x08, 0x95 };  // ret
static const uchar retcode_2[] = { 0x18, 0x95 };  // reti
static const uchar retcode_3[] = { 0x28, 0x95 };  // ret
static const uchar retcode_4[] = { 0x38, 0x95 };  // reti
static const uchar retcode_5[] = { 0x48, 0x95 };  // ret
static const uchar retcode_6[] = { 0x58, 0x95 };  // reti
static const uchar retcode_7[] = { 0x68, 0x95 };  // ret
static const uchar retcode_8[] = { 0x78, 0x95 };  // reti

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { sizeof(retcode_4), retcode_4 },
  { sizeof(retcode_5), retcode_5 },
  { sizeof(retcode_6), retcode_6 },
  { sizeof(retcode_7), retcode_7 },
  { sizeof(retcode_8), retcode_8 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
#define FAMILY "Atmel AVR series:"

static const char *const shnames[] =
{
  "AVR",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Atmel AVR",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_AVR,               // id
                          // flag
    PRN_HEX
  | PR_RNAMESOK,
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  16,                     // 16 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  AVR_null,
  AVR_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, },               // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  AVR_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
};
