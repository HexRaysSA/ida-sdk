
#include "m7700.hpp"
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

// 740 registers names
static const char *const RegNames[] =
{
  "A",        // accumulator A
  "B",        // accumulator B
  "X",        // index register X
  "Y",        // index register Y
  "S",        // stack pointer
  "PC",       // program counter
  "PG",       // program bank register
  "DT",       // data bank register
  "PS",       // processor status register
  "DPR",      // direct page register
  "fM",       // data length flag
  "fX",       // index register length flag
  "cs", "ds"  // these 2 registers are required by the IDA kernel
};

static const char cfgname[] = "m7700.cfg";

void m7700_iohandler_t::get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

//--------------------------------------------------------------------------
bool m7700_t::choose_device()
{
  bool ok = choose_ioport_device(&ioh.device, cfgname);
  if ( !ok )
    ioh.device = NONEPROC;
  return ok;
}

//--------------------------------------------------------------------------
const ioport_bit_t *m7700_t::find_bit(ea_t address, size_t bit)
{
  return find_ioport_bit(ioh.ports, address, bit);
}

//--------------------------------------------------------------------------
const char *m7700_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;

  if ( !choose_ioport_device(&ioh.device, cfgname)
    && ioh.device == NONEPROC )
  {
    warning("No devices are defined in the configuration file %s", cfgname);
  }
  else
  {
    if ( ioh.device != NONEPROC )
      ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
  }
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::sgr_changed:
      {
        ea_t ea1 = va_arg(va, ea_t);
        ea_t ea2 = va_arg(va, ea_t);
        int reg  = va_arg(va, int);
        sel_t v  = va_arg(va, sel_t);
        sel_t ov = va_arg(va, sel_t);
        if ( (reg == rfM || reg == rfX) && v != ov )
          set_sreg_at_next_code(ea1, ea2, reg, ov);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static const char *const m7700_help_message =
  "AUTOHIDE REGISTRY\n"
  "You have loaded a file for the Mitsubishi 7700 family processor.\n\n"\
  "This processor can be used in two different 'length modes' : 8-bit and 16-bit.\n"\
  "IDA allows to specify the encoding mode for every single instruction.\n"\
  "For this, IDA uses two virtual segment registers : \n"\
  "   - fM, used to specify the data length;\n"\
  "   - fX, used to specify the index register length.\n\n"\
  "Switching their state from 0 to 1 will switch the disassembly from 16-bit to 8-bit.\n"\
  "You can change their value using the 'change segment register value' command\n"\
  "(the canonical hotkey is Alt-G).\n\n"\
  "Note : in the real design, those registers are represented as flags in the\n"\
  "processor status register.\n";

//----------------------------------------------------------------------
void m7700_t::load_from_idb()
{
  ioh.restore_device(IORESP_NONE);
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(m7700_t));
  return 0;
}

ssize_t idaapi m7700_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      clr_module_data(data_id);
      unhook_event_listener(HT_IDB, &idb_listener);
      break;

    case processor_t::ev_newfile:
      if ( choose_device() )
        ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
      else
        ioh.set_device_name(NONEPROC, IORESP_NONE);
      //  Set the default segment register values :
      //      -1 (badsel) for DR
      //      0 for fM and fX
      for ( segment_t *s=get_first_seg(); s != nullptr; s=get_next_seg(s->start_ea) )
      {
        set_default_sreg_value(s, rDR, BADSEL);
        set_default_sreg_value(s, rfM, 0);
        set_default_sreg_value(s, rfX, 0);
      }
      info(m7700_help_message);
      break;

    case processor_t::ev_newprc:
      ptype = processor_subtype_t(va_arg(va, int));
      break;

    case processor_t::ev_ending_undo:
      // restore ptype
      ptype = processor_subtype_t(ph.get_proc_index());
      //fall through
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m7700_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7700_assumes(*ctx);
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

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = idp_get_frame_retsize(pfn);
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
        static const cvt64_node_tag_t node_info[] = { CVT64_NODE_DEVICE };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return code;
}

static const asm_t as_asm =
{
  AS_COLON
 |ASH_HEXF4     // hex $123 format
 |ASB_BINF3     // bin 0b010 format
 |ASO_OCTF5     // oct 123q format
 |AS_1TEXT,     // 1 text per line, no bytes
  UAS_SEGM|UAS_INDX_NOSPACE,
  "Alfred Arnold's Macro Assembler",
  0,
  nullptr,         // no headers
  "ORG",        // origin directive
  "END",        // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "DB",         // ascii string directive
  "DB",         // byte directive
  "DW",         // word directive
  "DD",         // dword  (4 bytes)
  "DQ",         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  "DT",         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
  0,            // flag2 ???
  nullptr,         // comment close string
  nullptr,         // low8 op
  nullptr,         // high8 op
  nullptr,         // low16 op
  nullptr          // high16 op
};

//
//  Mitsubishi Macro Assembler for 7700 Family
//

//--------------------------------------------------------------------------
// gets a function name
//lint -e{818} could be declared const
static bool mits_get_func_name(qstring *name, func_t *pfn)
{
  ea_t ea = pfn->start_ea;
  if ( get_demangled_name(name, ea, inf_get_long_demnames(), DEMNAM_NAME) <= 0 )
    return false;

  tag_addr(name, ea, true);
  return true;
}

//--------------------------------------------------------------------------
// prints function header
static void idaapi mits_func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  qstring name;
  if ( mits_get_func_name(&name, pfn) )
  {
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".FUNC %s", SCOLOR_ASMDIR), name.begin());
    ctx.gen_printf(0, COLSTR("%s:", SCOLOR_ASMDIR), name.begin());
    ctx.ctxflags |= CTXF_LABEL_OK;
  }
}

//--------------------------------------------------------------------------
// prints function footer
static void idaapi mits_func_footer(outctx_t &ctx, func_t *pfn)
{
  qstring name;
  if ( mits_get_func_name(&name, pfn) )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".ENDFUNC %s", SCOLOR_ASMDIR), name.begin());
}

static const asm_t mitsubishi_asm =
{
  AS_COLON
 |ASH_HEXF0     // hex 123h format
 |ASB_BINF0     // bin 10100011b format
 |ASO_OCTF0     // oct 123o format
 |AS_1TEXT,     // 1 text per line, no bytes
  UAS_END_WITHOUT_LABEL|UAS_DEVICE_DIR|UAS_BITMASK_LIST,
  "Mitsubishi Macro Assembler for 7700 Family",
  0,
  nullptr,         // no headers
  ".ORG",       // origin directive
  ".END",       // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".BYTE",       // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
  ".DWORD",     // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".BLKB %s",   // uninited arrays
  ".EQU",       // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  mits_func_header,    // func_header
  mits_func_footer,    // func_footer
  ".PUB",       // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  "<<",         // shl
  ">>",         // shr
  "SIZEOF",     // sizeof
  0,            // flag2 ???
  nullptr,         // comment close string
  nullptr,         // low8 op
  nullptr,         // high8 op
  nullptr,         // low16 op
  nullptr          // high16 op
};

// Supported assemblers
static const asm_t *const asms[] = { &mitsubishi_asm, &as_asm, nullptr };

// Short and long name for our module
#define FAMILY "Mitsubishi 16-BIT 7700 family:"

static const char *const shnames[] =
{
  "m7700",
  "m7750",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Mitsubishi 16-BIT 7700 family",
  "Mitsubishi 16-BIT 7700 family (7750 series)",
  nullptr
};

static const uchar retcode_1[] = { 0x40 };    // rti
static const uchar retcode_2[] = { 0x60 };    // rts
static const uchar retcode_3[] = { 0x6B };    // rtl

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }                            // nullptr terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_M7700,             // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM             // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
  | PR_SEGS               // has segment registers?
  | PR_SGROTHER,          // the segment registers don't contain
                          // the segment selectors, something else
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rDR, rVds,
  2,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  0, m7700_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  m7700_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
