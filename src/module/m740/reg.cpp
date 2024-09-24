
#include "m740.hpp"
#include <cvt64.hpp>
int data_id;

// 740 registers names
static const char *const RegNames[] =
{
  "A",                // accumulator
  "X",                // index register X
  "Y",                // index register Y
  "S",                // stack pointer
  "PS",               // processor status register
  "cs", "ds"          // these 2 registers are required by the IDA kernel
};

const char *m740_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;

  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&ioh.device, cfgfile) )
  {
    if ( ioh.device == NONEPROC )
      warning("No devices are defined in the configuration file %s", cfgfile);
  }
  else
  {
    ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
  }
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
void m740_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(m740_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi m740_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      set_idp_options(nullptr, 0, nullptr, true);
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m740_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m740_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m740_segstart(*ctx, seg);
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

  "BYT",        // ascii string directive
  "BYT",        // byte directive (alias: DB)
  nullptr,         // word directive (alias: DW)
  nullptr,         // dword  (4 bytes, alias: DD)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
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

static const asm_t iar_asm =
{
  AS_COLON
 |ASH_HEXF4     // hex $123 format
 |ASB_BINF3     // bin 0b010 format
 |ASO_OCTF5     // oct 123q format
 |AS_1TEXT,     // 1 text per line, no bytes
  UAS_RSEG,
  "IAR 740 Assembler",
  0,
  nullptr,         // no headers
  "ORG",        // origin directive
  "END",        // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "BYTE",       // ascii string directive
  "BYTE",       // byte directive (alias: DB)
  "WORD",       // word directive (alias: DW)
  "DWORD",      // dword  (4 bytes, alias: DD)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "BLKB %s",     // uninited arrays
  "EQU",        // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  nullptr,         // func_header
  nullptr,         // func_footer
  "PUBLIC",     // public
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
static const asm_t *const asms[] = { &as_asm, &iar_asm, nullptr };

// Short and long name for our module
#define FAMILY "Mitsubishi 8-BIT 740 family:" // MELPS 740, Renesas 740

static const char *const shnames[] =
{
  "m740",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY "Mitsubishi 8-BIT 740 family",
  nullptr
};

static const uchar retcode_1[] = { 0x40 };    // rti
static const uchar retcode_2[] = { 0x60 };    // rts

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, nullptr }                            // nullptr terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_M740,              // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM,            // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
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

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  0, m740_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  m740_rts,             // Icode of return instruction. It is ok to give any of possible return instructions
};
