/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "pic.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>

// default size of data/FSR area for PIC12/14
#define PIC_DATA_SIZE_SMALL 0x0200

// full size of FSR area for PIC14 (enhanced midrange, 32 banks)
#define PIC_DATA_SIZE_FULL  0x1000

int data_id;


//--------------------------------------------------------------------------
static const char *const register_names_pic12[] =
{
  "w", "f",
  "ACCESS",        // register for PIC18Cxx
  "BANKED",        // register for PIC18Cxx
  "FAST",          // register for PIC18Cxx
  "FSR0",          // register for PIC18Cxx
  "FSR1",          // register for PIC18Cxx
  "FSR2",          // register for PIC18Cxx
  "bank",
  "cs","ds",       // virtual registers for code and data segments
  "status",
  "pclatu"         // register for PIC18Cxx
};

static const char *const register_names_pic14[] =
{
  "w", "f",
  "ACCESS",        // register for PIC18Cxx
  "BANKED",        // register for PIC18Cxx
  "FAST",          // register for PIC18Cxx
  "FSR0",          // register for PIC18Cxx
  "FSR1",          // register for PIC18Cxx
  "FSR2",          // register for PIC18Cxx
  "bank",
  "cs","ds",       // virtual registers for code and data segments
  "pclath",
  "pclatu"         // register for PIC18Cxx
};

static const char *const register_names_pic16[] =
{
  "w", "f",
  "ACCESS",        // register for PIC18Cxx
  "BANKED",        // register for PIC18Cxx
  "FAST",          // register for PIC18Cxx
  "FSR0",          // register for PIC18Cxx
  "FSR1",          // register for PIC18Cxx
  "FSR2",          // register for PIC18Cxx
  "bsr",
  "cs","ds",       // virtual registers for code and data segments
  "pclath",
  "pclatu"         // register for PIC18Cxx
};

//--------------------------------------------------------------------------
// 11 01xx kkkk kkkk RETLW   k           Return with literal in W
static const uchar retcode_0[] = { 0x08, 0x00 };  // return
static const uchar retcode_1[] = { 0x09, 0x00 };  // retfie
static const uchar retcode_2[] = { 0x00, 0x34 };  // retlw 0
static const uchar retcode_3[] = { 0x01, 0x34 };  // retlw 1

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Microchip's MPALC
//-----------------------------------------------------------------------
static const asm_t mpalc =
{
  ASH_HEXF2|ASD_DECF3|ASB_BINF5|ASO_OCTF5|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "Microchip's MPALC",
  0,
  nullptr,         // header lines
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  "data",       // ascii string directive
  "byte",       // byte directive
  "data",       // word directive
  nullptr,         // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "res %s",     // uninited arrays
  "equ",        // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // "public" name keyword
  nullptr,         // "weak"   name keyword
  nullptr,         // "extrn"  name keyword
  nullptr,         // "comm" (communal variable)
  nullptr,         // get_type_name
  nullptr,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
};

static const asm_t *const asms[] = { &mpalc, nullptr };

//--------------------------------------------------------------------------
void pic_t::free_mappings(void)
{
  map.clear();
}

void pic_t::add_mapping(ea_t from, ea_t to)
{
  if ( from != to )
  {
    deb(IDA_DEBUG_IDP, "add_mapping %a -> %a\n", from, to);
    portmap_t &p = map.push_back();
    p.from = from;
    p.to = to;
  }
}

ea_t pic_t::map_port(ea_t from)
{
  for ( int i=0; i < map.size(); i++ )
    if ( map[i].from == from )
      return map[i].to;
  return from;
}

//--------------------------------------------------------------------------
void pic_iohandler_t::get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, pm.cfgname, bufsize);
}

// create the mapping table
void pic_t::create_mappings(void)
{
  free_mappings();
  for ( int i=0; i < ioh.ports.size(); i++ )
  {
    const char *name = ioh.ports[i].name.c_str();
    ea_t nameea = get_name_ea(BADADDR, name);
    if ( nameea != BADADDR && nameea > dataseg )
      add_mapping(ioh.ports[i].address, nameea-dataseg);
  }
}

//----------------------------------------------------------------------
static ea_t AddSegment(ea_t start, size_t size, ea_t base, const char *name, uchar type)
{
  segment_t s;
  s.start_ea = start;
  s.end_ea   = start + size;
  s.sel     = allocate_selector(base >> 4);
  s.type    = type;
  s.align   = saRelByte;
  s.comb    = scPub;
  add_segm_ex(&s, name, nullptr, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea;
}

//----------------------------------------------------------------------
// special handling for 16-bit PICs
// for CODE segments use addresses as-is
// for DATA segments, start from dataseg base
bool pic_iohandler_t::area_processing(ea_t start, ea_t end, const char *name, const char *aclass)
{
  if ( pm.ptype != PIC16 )
    return false;
  if ( strcmp(aclass, "CODE") == 0 )
  {
    AddSegment(start, end-start, 0, name, SEG_CODE);
  }
  else if ( strcmp(aclass, "DATA") == 0 )
  {
    if ( pm.dataseg == BADADDR )
    {
      pm.dataseg = find_free_chunk(0, 0x1000, 0xF);
      pm.save_dataseg();
    }
    uchar type = stristr(name, "FSR") != nullptr ? SEG_IMEM : SEG_DATA;
    AddSegment(pm.dataseg + start, end-start, pm.dataseg, name, type);
  }
  else
  {
    return false;
  }
  return true;
}

void pic_t::load_symbols_without_infotype(int _respect_info)
{
  ioh.ports.clear();
  ioh.respect_info = _respect_info;
  iohandler_t::ioports_loader_t ldr(&ioh);
  read_ioports(&ioh.ports, &ioh.device, cfgname, &ldr);
  create_mappings();
}

void pic_t::load_symbols(int _respect_info)
{
  if ( ioh.display_infotype_dialog(IORESP_ALL, &_respect_info, cfgname) )
    load_symbols_without_infotype(_respect_info);
}

const char *pic_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? port->name.c_str() : nullptr;
}

const ioport_bits_t *pic_t::find_bits(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? (&port->bits) : nullptr;
}

const char *pic_t::find_bit(ea_t address, int bit)
{
  address = map_port(address);
  const ioport_bit_t *b = find_ioport_bit(ioh.ports, address, bit);
  return b ? b->name.c_str() : nullptr;
}

//----------------------------------------------------------------------
void pic_t::apply_symbols(void)
{
  free_mappings();
  if ( dataseg != BADADDR )
  {
    for ( int i=0; i < ioh.ports.size(); i++ )
    {
      ea_t ea = calc_data_mem(ioh.ports[i].address);
      segment_t *s = getseg(ea);
      if ( s == nullptr && ea > dataseg )
      {
        // probably the default dataseg size (0x200) is too small for this device
        s = getseg(dataseg);
        if ( s == nullptr )
          return;
        if ( s->size() == PIC_DATA_SIZE_SMALL )
          set_segm_end(dataseg, dataseg+PIC_DATA_SIZE_FULL, SEGMOD_KEEP);
        s = getseg(ea);
      }
      if ( s == nullptr || s->type != SEG_IMEM )
        continue;
      create_byte(ea, 1);
      const char *name = ioh.ports[i].name.c_str();
      if ( !set_name(ea, name, SN_NOCHECK|SN_NOWARN|SN_NODUMMY) )
        set_cmt(ea, name, 0);
    }
    for ( segment_t *d = getseg(dataseg); d != nullptr; d = get_next_seg(d->start_ea) )
    {
      if ( d->type != SEG_IMEM )
        continue;
      ea_t ea = d->start_ea;
      ea_t dataend = d->end_ea;
      while ( 1 )
      {
        ea = next_unknown(ea, dataend);
        if ( ea == BADADDR )
          break;
        ea_t end = next_that(ea, dataend, f_is_head);
        if ( end == BADADDR )
          end = dataend;
        create_byte(ea, end-ea);
      }
    }
    create_mappings();
  }
}

//------------------------------------------------------------------
void pic_t::setup_device(int lrespect_info)
{
  iohandler_t::parse_area_line0_t cb(ioh);
  if ( choose_ioport_device2(&ioh.device, cfgname, &cb) )
  {
    if ( ioh.device != NONEPROC )
      helper.supset(-1, ioh.device.c_str());
    // we don't pass IORESP_PORT because that would rename bytes in the code segment
    // we'll handle port renaming ourselves
    if ( ioh.display_infotype_dialog(IORESP_ALL, &lrespect_info, cfgname) )
    {
      ioh.set_device_name(ioh.device.c_str(), lrespect_info & ~IORESP_PORT);
      if ( (lrespect_info & IORESP_PORT) != 0 )
        apply_symbols();
    }
  }
}

//----------------------------------------------------------------------
ea_t pic_t::AdditionalSegment(size_t size, ea_t offset, const char *name) const
{
  ea_t start = find_free_chunk(0, size, 0xF);
  return AddSegment(start, size, start - offset, name, SEG_IMEM) - offset;
}

//--------------------------------------------------------------------------
static const proctype_t ptypes[] =
{
  PIC12,
  PIC14,
  PIC16
};

//-------------------------------------------------------------------------
static const cfgopt_t options[] =
{ //   name               varptr    type/bit
  CFGOPT_B("PIC_SIMPLIFY", pic_t, idpflags, ushort(IDP_SIMPLIFY)),
};

//--------------------------------------------------------------------------
static const cfgopt_t *find_option(const char *name)
{
  for ( int i=0; i < qnumber(options); i++ )
    if ( streq(options[i].name, name) )
      return &options[i];
  return nullptr;
}

//--------------------------------------------------------------------------
int idaapi optionscb(int field_id, form_actions_t &fa)
{
  // ensure that instruction simplification can't be turned off
  // if macros are enabled
  if ( field_id == CB_INIT )
    fa.enable_field(1, !inf_macros_enabled());
  return 1;
}

//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &fa)
{
  pic_t &pm = *(pic_t *)fa.get_ud();
  if ( choose_ioport_device(&pm.ioh.device, pm.cfgname) )
  {
    pm.helper.supset(-1, pm.ioh.device.c_str());
    pm.load_symbols(IORESP_ALL);
    pm.apply_symbols();
  }
  return 0;
}

const char *pic_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  if ( keyword == nullptr )
  {
    if ( ptype != PIC16 )
    {
      static const char form[] =
"HELP\n"
"PIC specific options\n"
"\n"
" Simplify instructions\n"
"\n"
"       If this option is on, IDA will simplify instructions and replace\n"
"       them by clearer macro-instructions\n"
"       For example,\n"
"\n"
"               btfsc   3,0\n"
"\n"
"       will be replaced by\n"
"\n"
"               skpnc\n"
"\n"
"       If macros are enabled, this options should be turned on.\n"
"ENDHELP\n"
"PIC specific options\n"
"%/%*\n"
" <~S~implify instructions:C1>>\n"
"\n"
" <~C~hoose device name:B:0::>\n"
"\n"
"\n";
      if ( inf_macros_enabled() )
        setflag(idpflags, IDP_SIMPLIFY, true);
      CASSERT(sizeof(idpflags) == sizeof(ushort));
      if ( ask_form(form, optionscb, this, &idpflags, choose_device) == ASKBTN_YES )
      {
SAVE:
        if ( idb_loaded )
          save_idpflags();
      }
    }
    else
    {
      static const char form[] =
        "PIC specific options\n"
        "%*\n"
        " <~C~hoose device name:B:0::>\n"
        "\n"
        "\n";
      ask_form(form, this, choose_device);
    }
    return IDPOPT_OK;
  }
  else
  {
    const cfgopt_t *opt = find_option(keyword);
    if ( opt == nullptr )
      return IDPOPT_BADKEY;
    const char *errmsg = opt->apply(value_type, value, this);
    if ( errmsg != IDPOPT_OK )
      return errmsg;
    // if macros are enabled, we should simplify insns
    if ( ph.supports_macros() && inf_macros_enabled() )
      setflag(idpflags, IDP_SIMPLIFY, true);
    goto SAVE;
  }
}

//--------------------------------------------------------------------------
void pic_t::set_cpu(int n)
{
  if ( ptypes[n] != ptype )
  {
    ptype = ptypes[n];
    ph.cnbits = 12 + 2*n;
  }
  switch ( ptype )
  {
    case PIC12:
      ph.reg_names = register_names_pic12;
      cfgname = "pic12.cfg";
      break;
    case PIC14:
      ph.reg_names = register_names_pic14;
      cfgname = "pic14.cfg";
      break;
    case PIC16:
      ph.reg_names = register_names_pic16;
      cfgname = "pic16.cfg";
      ph.cnbits = 8;
      ph.reg_last_sreg = PCLATU;
      break;
    default:
      INTERR(10311);
  }
  setflag(ph.flag2, PR2_MACRO, ptype != PIC16);
}

//----------------------------------------------------------------------
void pic_t::check_pclath(segment_t *s) const
{
  if ( s == nullptr )
    return;
  if ( s->defsr[PCLATH-ph.reg_first_sreg] == BADSEL )
    s->defsr[PCLATH-ph.reg_first_sreg] = 0;
}

//----------------------------------------------------------------------
void pic_t::load_from_idb()
{
  idpflags = (ushort)helper.altval(-1);
  dataseg  = node2ea(helper.altval(0));
  ioh.upgrade_device_index();
  helper.supstr(&ioh.device, -1);
  load_symbols_without_infotype(IORESP_PORT);
  ioh.respect_info = sav_respect_info;
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(pic_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi pic_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  sav_respect_info = ioh.respect_info;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      free_mappings();
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      {
        segment_t *s0 = get_first_seg();
        if ( s0 != nullptr )
        {
          ea_t firstEA = s0->start_ea;
          if ( ptype == PIC12 || ptype == PIC14 )
          {
            set_segm_name(s0, "CODE");
            dataseg = AdditionalSegment(PIC_DATA_SIZE_SMALL, 0, "DATA");
            setup_device(IORESP_INT|IORESP_PORT);
          }
          else
          {
            setup_device(IORESP_ALL);
          }
          s0 = getseg(firstEA);
          if ( s0 != nullptr )
          {
            set_default_sreg_value(s0, BANK, 0);
            set_default_sreg_value(s0, PCLATH, 0);
            set_default_sreg_value(s0, PCLATU, 0);
          }
          segment_t *s1 = getseg(dataseg);
          if ( s1 != nullptr )
          {
            set_default_sreg_value(s1, BANK, 0);
            set_default_sreg_value(s1, PCLATH, 0);
            set_default_sreg_value(s1, PCLATU, 0);
          }
        }
      }
      // save info to idb
      save_dataseg();
      save_idpflags();
      break;

    case processor_t::ev_ending_undo:
      set_cpu(ph.get_proc_index());
      ioh.respect_info = IORESP_NONE;
      //fall through
    case processor_t::ev_oldfile:   // old file loaded
      load_from_idb();
      // init PCLATH for very old IDBs
      check_pclath(get_first_seg());
      check_pclath(getseg(dataseg));
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        int n = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        if ( set )
          return 0;
        set = true;
        set_cpu(n);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        pic_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        pic_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pic_assumes(*ctx);
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

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        pic_data(*ctx, analyze_only);
        return 1;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        *mode = OP_SP_ADD | OP_FP_BASED;
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        *frsize = 0;
        return 1;
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
          CVT64_NODE_IDP_FLAGS,
          { helper, atag|NETMAP_VAL|NETMAP_VAL_NDX, 0 },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "Microchip PIC:"
static const char *const shnames[] =
{ "PIC12Cxx",
  "PIC16Cxx",
  "PIC18Cxx",
  nullptr
};
static const char *const lnames[] =
{ FAMILY "Microchip PIC12Cxx - 12 bit instructions",
  "Microchip PIC16Cxx - 14 bit instructions",
  "Microchip PIC18Cxx - 16 bit instructions",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_PIC,               // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_STACK_UP
  | PR_RNAMESOK,
                          // flag2
    PR2_IDP_OPTS          // the module has processor-specific configuration options
  | PR2_MACRO,            // try to combine several instructions into a macro instruction
  12,                     // 12/14/16 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names_pic14, // Register names
  qnumber(register_names_pic14), // Number of registers

  BANK,                 // first
  PCLATH,               // last
  0,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  PIC_null,
  PIC_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  PIC_return,           // Icode of return instruction. It is ok to give any of possible return instructions
};
