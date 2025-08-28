#include "fr.hpp"
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

// FR registers names
static const char *const RegNames[] =
{
  // general purpose registers :

  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",

  // coprocessor registers :

  "cr0",
  "cr1",
  "cr2",
  "cr3",
  "cr4",
  "cr5",
  "cr6",
  "cr7",
  "cr8",
  "cr9",
  "cr10",
  "cr11",
  "cr12",
  "cr13",
  "cr14",
  "cr15",

  // dedicated registers :

  "pc",        // program counter
  "ps",        // program status
  "tbr",       // table base register
  "rp",        // return pointer
  "ssp",       // system stack pointer
  "usp",       // user stack pointer
  "mdl",       // multiplication/division register (LOW)
  "mdh",       // multiplication/division register (HIGH)

  // system use dedicated registers
  "reserved6",
  "reserved7",
  "reserved8",
  "reserved9",
  "reserved10",
  "reserved11",
  "reserved12",
  "reserved13",
  "reserved14",
  "reserved15",

  // these 2 registers are required by the IDA kernel :

  "cs",
  "ds"
};

int fr_t::choose_device()
{
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( choose_ioport_device(&ioh.device, cfgfile) )
    ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
  return 0;
}

// returns a pointer to a ioport_t object if address was found in the config file.
// otherwise, returns nullptr.
const ioport_t *fr_t::find_sym(ea_t address)
{
  return find_ioport(ioh.ports, address);
}

const char *fr_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;

  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&ioh.device, cfgfile)
    && ioh.device == NONEPROC )
  {
    warning("No devices are defined in the configuration file %s", cfgfile);
  }
  else
  {
    ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
  }
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
void fr_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(fr_t));
  return 0;
}

ssize_t idaapi fr_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(true);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      choose_device();
      ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
      break;

    case processor_t::ev_ending_undo:
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
        fr_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        fr_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        fr_segstart(*ctx, seg);
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

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
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
  return 0;
}

//
//  GNU assembler for fujitsu FR
//

//-----------------------------------------------------------------------
// gets a function's name
//lint -e{818} could be declared const
static bool fr_get_func_name(qstring *name, func_t *pfn)
{
  ea_t ea = pfn->start_ea;
  if ( get_demangled_name(name, ea, inf_get_long_demnames(), DEMNAM_NAME) <= 0 )
    return false;

  tag_addr(name, ea, true);
  return true;
}

//-----------------------------------------------------------------------
// prints function header
static void idaapi gnu_func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  qstring namebuf;
  if ( fr_get_func_name(&namebuf, pfn) )
  {
    const char *name = namebuf.begin();
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".type %s, @function", SCOLOR_ASMDIR), name);
    ctx.gen_printf(0, COLSTR("%s:", SCOLOR_ASMDIR), name);
    ctx.ctxflags |= CTXF_LABEL_OK;
  }
}

//-----------------------------------------------------------------------
// prints function footer
static void idaapi gnu_func_footer(outctx_t &ctx, func_t *pfn)
{
  qstring namebuf;
  if ( fr_get_func_name(&namebuf, pfn) )
  {
    const char *name = namebuf.begin();
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".size %s, .-%s", SCOLOR_ASMDIR), name, name);
  }
}

//-----------------------------------------------------------------------
static const asm_t gnu_asm =
{
  AS_COLON
 |ASH_HEXF3    // hex 0x123 format
 |ASB_BINF0    // bin 0110b format
 |ASO_OCTF1    // oct 012345 format
  // don't display the final 0 in string declarations
 |/*AS_1TEXT |*/ AS_NCMAS,
  0,
  "GNU Assembler for the Fujitsu FR Family",
  0,
  nullptr,         // no headers
  ".org",       // origin directive
  nullptr,         // end directive
  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants
  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // current IP (instruction pointer) symbol in assembler
  gnu_func_header,     // func_header
  gnu_func_footer,     // func_footer
  ".globl",     // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  ".align",     // align
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
// Supported assemblers :
//

static const asm_t *const asms[] = { &gnu_asm, nullptr };

//
// Short and long name for our module
//
#define FAMILY "Fujitsu FR 32-Bit Family:"

static const char *const shnames[] =
{
  "fr",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Fujitsu FR 32-Bit Family",
  nullptr
};

static const uchar retcode_1[] = { 0x97, 0x20 };    // ret
static const uchar retcode_2[] = { 0x9F, 0x20 };    // ret with delay shot
static const uchar retcode_3[] = { 0x9F, 0x30 };    // reti

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
  PLFM_FR,                // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_USE32              // supports 32-bit addressing
  | PR_DEFSEG32           // segments are 32-bit by default
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

  rVcs, rVds,
  0,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  0, fr_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  fr_ret,               // Icode of return instruction. It is ok to give any of possible return instructions
};
