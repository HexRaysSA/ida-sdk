/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"
#include <diskio.hpp>
#include <typeinf.hpp>
#include <ieee.h>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "pfp", "sp", "rip", "r3",  "r4",  "r5",  "r6",  "r7",
  "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "g0",  "g1", "g2",  "g3",  "g4",  "g5",  "g6",  "g7",
  "g8",  "g9", "g10", "g11", "g12", "g13", "g14", "fp",
  "sf0",  "sf1", "sf2",  "sf3",  "sf4",  "sf5",  "sf6",  "sf7",
  "sf8",  "sf9", "sf10", "sf11", "sf12", "sf13", "sf14", "sf15",
  "sf16", "sf17","sf18", "sf19", "sf20", "sf21", "sf22", "sf23",
  "sf24", "sf25","sf26", "sf27", "sf28", "sf29", "sf30", "sf31",
  "pc",   "ac",  "ip",   "tc",
  "fp0",  "fp1", "fp2",  "fp3",
  "ds", "cs",
};

//--------------------------------------------------------------------------
static const bytes_t retcodes[] =
{
// { sizeof(retcode0), retcode0 },
 { 0, nullptr }
};

//-----------------------------------------------------------------------
//      GNU assembler
//-----------------------------------------------------------------------
static const asm_t gnuasm =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  nullptr,         // end

  "#",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  ".quad",      // qwords
  ".octa",      // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  ".extended",  // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  ".fill #d, #s(1,2,4,8), #v", // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  ".",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  ".global",    // "public" name keyword
  nullptr,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  nullptr,         // get_type_name
  ".align",     // "align" keyword
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

static const asm_t *const asms[] = { &gnuasm, nullptr };

//--------------------------------------------------------------------------
static const char *const cfgname = "i960.cfg";

void i960_t::load_symbols(void)
{
  ioh.ports.clear();
  read_ioports(&ioh.ports, &ioh.device, cfgname);
}

const char *i960_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? port->name.c_str() : nullptr;
}

//--------------------------------------------------------------------------
void i960_t::choose_device()
{
  if ( choose_ioport_device(&ioh.device, cfgname) )
  {
    ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
    load_symbols();
  }
}

//--------------------------------------------------------------------------
static int idaapi choose_device_cb(int, form_actions_t &fa)
{
  i960_t &pm = *(i960_t *)fa.get_ud();
  pm.choose_device();
  return 0;
}

//--------------------------------------------------------------------------
const char *i960_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  static const char form[] =
    "HELP\n"
    "Intel 960 specific options\n"
    "\n"
    " Choose device name\n"
    "       Here you may select a specific Intel 960 device\n"
    "       IDA will use the definitions in the I960.CFG file for\n"
    "       the i/o port names\n"
    "\n"
    " Strictly adhere to instruction encodings\n"
    "       If this option is on, IDA will check that unused fields\n"
    "       of instructions are filled by zeroes. If they are not,\n"
    "       it will refuse to disassemble the instruction.\n"
    "\n"
    "ENDHELP\n"
    "Intel 960 specific options\n"
    "%*\n"
    " <~C~hoose device name:B:0:::>\n"
    "\n"
    " <~S~trictly adhere to instruction encodings:C>>\n"
    "\n"
    "\n";

  if ( keyword == nullptr )
  {
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    ask_form(form, this, choose_device_cb, &idpflags);
OK:
    if ( idb_loaded )
      save_idpflags();
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "I960_STRICT") == 0 )
    {
      setflag(idpflags, IDP_STRICT, *(int*)value != 0);
      goto OK;
    }
  }
  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
void i960_t::load_from_idb()
{
  // restore ptype
  int n = ph.get_proc_index();
  inf_set_be((n > 1));
  idpflags = helper.altval(-1);
  ioh.restore_device();
  load_symbols();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(i960_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi i960_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      choose_device();
      save_idpflags();
      break;

    case processor_t::ev_oldfile:   // old file loaded
      ioh.upgrade_device_index();
      // fall through
    case processor_t::ev_ending_undo:
      load_from_idb();
      break;

    case processor_t::ev_newprc:
      {
        int n = va_arg(va, int);
        bool keep_cfg = va_argi(va, bool);
        if ( !keep_cfg )
          inf_set_be((n > 1));
      }
      break;

// +++ TYPE CALLBACKS
    case processor_t::ev_calc_arglocs:
      return -1;

    case processor_t::ev_use_regarg_type:
      return -1;

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        cm_t cc = va_argi(va, cm_t);
        if ( cc == CM_CC_FASTCALL
          || cc == CM_CC_THISCALL
          || cc == CM_CC_SWIFT )
        {
          callregs->reset();
          return 1;
        }
      }
      break;

    case processor_t::ev_calc_cdecl_purged_bytes:// calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 0;
      }

// --- TYPE CALLBACKS

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i960_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i960_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        i960_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        i960_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return i960_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return i960_emu(*insn) ? 1 : -1;
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

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return is_align_insn(ea);
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
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
#define FAMILY "Intel 960:"

static const char *const shnames[] =
{
  "i960",
  "i960l",
  "i960b",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Intel 960 little endian (default)",
  "Intel 960 little endian",
  "Intel 960 big endian",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_I960,              // id
                          // flag
    PRN_HEX
  | PR_RNAMESOK
  | PR_SEGS
  | PR_USE32
  | PR_DEFSEG32
  | PR_TYPEINFO,
                          // flag2
    PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  ds,                   // first
  cs,                   // last
  2,                    // size of a segment register
  cs, ds,

  nullptr,                 // No known code start sequences
  retcodes,

  I960_null,
  I960_last,
  Instructions,         // instruc
  10,                   // int tbyte_size (0-doesn't exist)
  { 0, 7, 15, 18 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double (80-bit)
  I960_ret,             // Icode of return instruction. It is ok to give any of possible return instructions
};
