/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st7.hpp"
#include <diskio.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "a", "x", "y", "cc", "s",
  "ds", "cs",
};

//--------------------------------------------------------------------------
static const uchar retcode0[] = { 0x80 }; // iret  80
static const uchar retcode1[] = { 0x81 }; // ret   81
static const bytes_t retcodes[] =
{
  { sizeof(retcode0), retcode0 },
  { sizeof(retcode1), retcode1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      STMicroelectronics - Assembler - rel. 4.10
//      We support Motorola format
//-----------------------------------------------------------------------
static const char *const st7_headers[] =
{
  "st7/",
  "",
  nullptr
};

static const asm_t stasm =
{
  ASH_HEXF4     // $1234
 |ASD_DECF0     // 1234
 |ASB_BINF2     // %1010
 |ASO_OCTF6     // ~1234
 |AS_NOXRF      // Disable xrefs during the output file generation
 |AS_ONEDUP,    // one array definition per line
  0,
  "STMicroelectronics - Assembler",
  0,
  st7_headers,  // header lines
  "org",        // org
  "end",        // end

  ";",          // comment string
  '\"',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  "dc.b",       // ascii string directive
  "dc.b",       // byte directive
  "dc.w",       // word directive
  "dc.l",       // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  "skip#s( )#d, #v", // arrays (#h,#d,#v,#s(...)  ONLY BYTE ARRAYS!!!
  "ds.b %s",    // uninited arrays
  "equ",        // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "*",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  "public",     // "public" name keyword
  nullptr,         // "weak"   name keyword
  "extern",     // "extrn"  name keyword
                // .extern directive requires an explicit object size
  nullptr,         // "comm" (communal variable)
  nullptr,         // get_type_name
  nullptr,         // "align" keyword
  '{', '}',     // lbrace, rbrace
  nullptr,         // mod
  "and",        // and
  "or",         // or
  "xor",        // xor
  nullptr,         // not
  "shl",        // shl
  "shr",        // shr
  nullptr,         // sizeof
  AS2_BRACE,
};

static const asm_t *const asms[] = { &stasm, nullptr };

//--------------------------------------------------------------------------
//static const char cfgname[] = "st7.cfg";

//----------------------------------------------------------------------
const ioport_t *st7_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port;
}

//----------------------------------------------------------------------
void st7_t::create_words(void)
{
  for ( int i=0; i < ioh.ports.size(); i++ )
  {
    ea_t ea = ioh.ports[i].address;
    if ( is_tail(get_flags(ea)) )
      del_items(ea, DELIT_SIMPLE);
    create_word(ea, 2);
  }
}

//--------------------------------------------------------------------------
const char *st7_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(&ioh.device, cfgfile) )
    ioh.set_device_name(ioh.device.c_str(), IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
void st7_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(st7_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi st7_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:  // new file loaded
      {
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(&ioh.device, cfgfile) )
          ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
        create_words();
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:  // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        return is_jump_func(pfn, jump_target);
      }

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        return is_sane_insn(*insn, no_crefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        st7_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        st7_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        st7_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        st7_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return st7_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return st7_emu(*insn) ? 1 : -1;
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
        static const cvt64_node_tag_t node_info[] = { CVT64_NODE_DEVICE };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "SGS-Thomson ST7:"
static const char *const shnames[] = { "st7", nullptr };
static const char *const lnames[] =
{
  FAMILY"SGS-Thomson ST7",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_ST7,               // id
                          // flag
    PRN_HEX
  | PR_RNAMESOK,
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

  ST7_null,
  ST7_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  ST7_ret,              // Icode of return instruction. It is ok to give any of possible return instructions
};
