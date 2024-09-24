#include "oakdsp.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "r0", "r1", "r2", "r3", "r4", "r5",           // DAAU Registers
  "rb",                                         // Base Register
  "y",                                          // Input Register
  "st0", "st1", "st2",                          // Status Registers
  "p",                                          // Output Register
  "pc",                                         // Program Counter
  "sp",                                         // Software Stack Pointer
  "cfgi", "cfgj",                               // DAAU Configuration Registers
  "b0h", "b1h",  "b0l",  "b1l",                 // Accumulator B
  "ext0","ext1", "ext2", "ext3",                // External registers
  "a0", "a1", "a0l", "a1l", "a0h", "a1h",       // Accumulator A
  "lc",                                         // Loop Counter
  "sv",                                         // Shift Value Register
  "x",                                          // Input Register
  "dvm",                                        // Data Value Match Register
  "mixp",                                       // Minimal/Maximal Pointer Register
  "icr",                                        // Internal Configuration Register
  "ps",                                         // Product Shifter Control
  "repc",                                       // Internal Repeat Counter
  "b0",   "b1",                                 // Accumulator B
  "modi", "modj",                               // Modulo Modifier
  "stepi","stepj",                              // Linear (Step) Modifier
  "page",                                       // Short Direct Addressing Mode Page
  "cs","ds",                                    // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x45, 0xc0 };
static const uchar retcode_1[] = { 0x45, 0xd0 };
static const uchar retcode_2[] = { 0x45, 0x80 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Dsp Group OAK DSP Assembler
//-----------------------------------------------------------------------
static const asm_t oakasm =
{
  ASH_HEXF4    // $34
 |ASD_DECF0    // 34
 |ASB_BINF2    // %01010
 |ASO_OCTF1    // 0123
 |AS_COLON
 |AS_N2CHR
 |AS_NCMAS
 |AS_ONEDUP,
  0,
  "Dsp Group OAK DSP Assembler",
  0,
  nullptr,         // header lines
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  "dc",         // ascii string directive
  "dcb",        // byte directive
  "dc",         // word directive
  nullptr,         // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  "bs#s(c,) #d, #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "*",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  "global",     // "public" name keyword
  nullptr,         // "weak"   name keyword
  "xref",       // "extrn"  name keyword
                // .extern directive requires an explicit object size
  nullptr,         // "comm" (communal variable)
  nullptr,         // const char *(*get_type_name)(int32 flag,uint32 id);
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
  AS2_BYTE1CHAR,// One symbol per processor byte
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC
 |ASH_HEXF4    // $34
 |ASD_DECF0    // 34
 |ASB_BINF3    // 0b01010
 |ASO_OCTF1    // 0123
 |AS_COLON
 |AS_N2CHR
 |AS_NCMAS
 |AS_ONEDUP,
  UAS_GNU,
  "GNU-like hypothetical assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  nullptr,         // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
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
  nullptr,         // const char *(*get_type_name)(int32 flag,uint32 id);
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "mod",        // mod
  "and",        // and
  "or",         // or
  "xor",        // xor
  "not",        // not
  "shl",        // shl
  "shr",        // shr
  nullptr,         // sizeof
  AS2_BYTE1CHAR,// One symbol per processor byte
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &oakasm, &gas, nullptr };

//----------------------------------------------------------------------
ea_t oakdsp_t::add_data_segm(size_t size, int offset, const char *name) const
{
  segment_t s;
  s.start_ea = find_free_chunk(0x1000000, size, 0xF);
  s.end_ea   = s.start_ea + size;
  s.sel     = allocate_selector((s.start_ea-offset) >> 4);
  s.type    = SEG_DATA;
  s.bitness = ph.dnbits > 16;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea - offset;
}

inline ea_t get_start(const segment_t *s)
{  return s ? s->start_ea : BADADDR; }

//--------------------------------------------------------------------------
const char *oakdsp_iohandler_t::iocallback(const ioports_t &lports, const char *line)
{
  int size;
  if ( qsscanf(line, "XMEMSIZE = %i", &size) == 1 )
  {
    pm.xmemsize = size;
    pm.ioh.deviceparams.sprnt("XMEM=0x%X", pm.xmemsize);
    return nullptr;
  }
  return standard_callback(lports, line);
}

const ioport_t *oakdsp_t::find_port(ea_t address)
{
  return find_ioport(ioh.ports, address);
}

//--------------------------------------------------------------------------
void oakdsp_t::create_xmem(void)
{
  if ( xmem == BADADDR )
    xmem = add_data_segm(xmemsize, 0, "XMEM");
}

//--------------------------------------------------------------------------
void oakdsp_t::select_device(const char *dname, int lrespect_info)
{
  ioh.set_device_name(dname, lrespect_info);

  create_xmem();

  for ( int i=0; i < ioh.ports.size(); i++ )
  {
    const ioport_t &p = ioh.ports[i];
    ea_t ea = xmem + p.address;
    const char *name = p.name.c_str();
    ea_t nameea = get_name_ea(BADADDR, name);
    if ( nameea != ea )
    {
      set_name(nameea, "");
      if ( !set_name(ea, name, SN_NOCHECK|SN_NOWARN|SN_NODUMMY) )
        set_cmt(ea, name, 0);
    }
  }
}

//--------------------------------------------------------------------------
const char *oakdsp_t::set_idp_options(
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
    select_device(ioh.device.c_str(), IORESP_INT);
  return IDPOPT_OK;
}

//-----------------------------------------------------------------------
// We always return "yes" because of the messy problem that
// there are additional operands with a wrong operand number (always 1)
static bool idaapi can_have_type(const op_t &)
{
  return true;
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(oakdsp_t));
  return 0;
}

//--------------------------------------------------------------------------
void oakdsp_t::load_from_idb()
{
  xmem = get_start(get_segm_by_name("XMEM"));
  char dev[MAXSTR];
  char *pdev = helper.supstr(-1, dev, sizeof(dev)) > 0 ? dev : nullptr;
  select_device(pdev, IORESP_NONE);
}

//--------------------------------------------------------------------------
ssize_t idaapi oakdsp_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      init_emu();
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:      // new file loaded
      {
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
          select_device(ioh.device.c_str(), IORESP_AREA|IORESP_INT);
        else
          create_xmem();

        segment_t *s0 = get_first_seg();
        if ( s0 != nullptr )
        {
          segment_t *s1 = get_next_seg(s0->start_ea);
          for ( int i = PAGE; i <= vDS; i++ )
          {
            set_default_sreg_value(s0, i, BADSEL);
            set_default_sreg_value(s1, i, BADSEL);
          }
        }
      }
      break;

    case processor_t::ev_ending_undo:
      procnum = ph.get_proc_index();
      //fall through
    case processor_t::ev_oldfile:      // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        int n = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        if ( procnum == -1 )
        {
          procnum = n;
        }
        else if ( procnum != n )  // can't change the processor type
        {                         // after the initial set up
          warning("Sorry, processor type cannot be changed after loading");
          code = -1;
          break;
        }
      }
      break;


    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int nocrefs = va_arg(va, int);
        return is_sane_insn(*insn, nocrefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
                                // can a function start here?
                                // arg: instruction
                                // returns: probability 0..100
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        oakdsp_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        oakdsp_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        oakdsp_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        oakdsp_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        oakdsp_assumes(*ctx);
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
        const op_t *_op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *_op) ? 1 : -1;
      }

    case processor_t::ev_can_have_type:
      {
        const op_t *_op = va_arg(va, const op_t *);
        return can_have_type(*_op) ? 1 : -1;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *_op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *_op);
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
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = OAK_get_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_gen_stkvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const udm_t *stkvar = va_arg(va, const udm_t *);
        sval_t v = va_arg(va, sval_t);
        gen_stkvar_def(*ctx, stkvar, v);
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
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "Atmel OAK DSP:"

static const char *const shnames[] =
{
  "oakdsp",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Dsp Group OAK DSP",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_OAKDSP,            // id
                          // flag
    PRN_HEX
  | PR_SEGS               // has segment registers
  | PR_ALIGN              // data items must be aligned
  | PR_BINMEM             // module knows about memory organization
  | PR_ALIGN_INSN,        // allow align instructions
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  16,                     // 16 bits in a byte for code segments
  16,                     // 16 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  PAGE,                 // first
  vDS,                  // last
  1,                    // size of a segment register
  vCS, vDS,

  nullptr,                 // No known code start sequences
  retcodes,

  OAK_Dsp_null,
  OAK_Dsp_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  OAK_Dsp_ret,          // Icode of return instruction. It is ok to give any of possible return instructions
};
