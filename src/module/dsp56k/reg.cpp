
#include "dsp56k.hpp"
#include <diskio.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  // data arithmetic logic unit
  "x", "x0", "x1",
  "y", "y0", "y1",
  // accumulator registers
  "a", "a0", "a1", "a2",
  "b", "b0", "b1", "b2",
  "ab",  // a1:b1
  "ba",  // b1:a1
  "a10", // a1:a0
  "b10", // b1:b0
  // address generation unit (AGU)
  "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",  // pointers
  "n0",  "n1",  "n2",  "n3",  "n4",  "n5",  "n6",  "n7",  // offsets
  "m0",  "m1",  "m2",  "m3",  "m4",  "m5",  "m6",  "m7",  // modifiers
  // Program Control Unit
  "pc",  // Program Counter (16 Bits)
  "mr",  // Mode Register (8 Bits)
  "ccr", // Condition Code Register (8 Bits)
  "sr",  // Status Register (MR:CCR, 16 Bits)
  "omr", // Operating Mode Register (8 Bits)
  "la",  // Hardware Loop Address Register (16 Bits)
  "lc",  // Hardware Loop Counter (16 Bits)
  "sp",  // System Stack Pointer (6 Bits)
  "ss",  // System Stack RAM (15X32 Bits)
  "ssh", // Upper 16 Bits of the Contents of the Current Top of Stack
  "ssl", // Lower 16 Bits of the Contents of the Current Top of Stack
  "sz",  // Stack Size register
  "sc",  // Stack Counter register
  "ep",  // Extension Pointer register
  "vba", // Vector Base Address Register

  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
// 6x
static const uchar retcode_0[] = { 0x0C, 0x00, 0x00 };
static const uchar retcode_1[] = { 0x04, 0x00, 0x00 };
// 61
static const uchar retcode_2[] = { 0x06, 0x00 };
static const uchar retcode_3[] = { 0x07, 0x00 };

static const bytes_t retcodes6x[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

static const bytes_t retcodes61[] =
{
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Motorola DSP56000 Assembler
//-----------------------------------------------------------------------
static const asm_t motasm =
{
//   AS_ASCIIC
   ASH_HEXF4    // $34
  |ASD_DECF0    // 34
  |ASB_BINF2    // %01010
  |ASO_OCTF1    // 0123
  |AS_COLON
  |AS_N2CHR
  |AS_NCMAS
  |AS_ONEDUP,
  0,
  "Motorola DSP56K Assembler",
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
  nullptr,         // get_type_name
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

static const asm_t *const asms[] = { &motasm, &gas, nullptr };

//----------------------------------------------------------------------
ea_t dsp56k_t::AdditionalSegment(asize_t size, int offset, const char *name) const
{
  segment_t s;
  int step = is561xx() ? 0xF : 0x1000000-1;
  s.start_ea = find_free_chunk(0x1000000, size, step);
  s.end_ea   = s.start_ea + size;
  s.sel     = allocate_selector((s.start_ea-offset) >> 4);
  s.type    = SEG_DATA;
  s.bitness = ph.dnbits > 16;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea - offset;
}

inline ea_t get_start(const segment_t *s)
{
  return s ? s->start_ea : BADADDR;
}

//--------------------------------------------------------------------------
const char *dsp56k_iohandler_t::iocallback(const ioports_t &iop, const char *line)
{
  int size;
  if ( qsscanf(line, "XMEMSIZE = %i", &size) == 1 )
  {
    pm.xmemsize = size;
RETOK:
    pm.ioh.deviceparams.sprnt("XMEM=0x%X YMEM=0x%X", pm.xmemsize, pm.ymemsize);
    return nullptr;
  }
  if ( !pm.is561xx() && qsscanf(line, "YMEMSIZE = %i", &size) == 1 )
  {
    pm.ymemsize = size;
    goto RETOK;
  }
  return pm.ioh.standard_callback(iop, line);
}

const ioport_t *dsp56k_t::find_port(ea_t address)
{
  return find_ioport(ioh.ports, address);
}

//--------------------------------------------------------------------------
void dsp56k_t::create_xmem_ymem(void)
{
  if ( xmem == BADADDR )
  {
    xmem = AdditionalSegment(xmemsize, 0, "XMEM");

    if ( !is561xx() )
      ymem = AdditionalSegment(ymemsize, 0, "YMEM");
  }
}

//--------------------------------------------------------------------------
void dsp56k_t::select_device(const char *dname, int resp_info)
{
  ioh.set_device_name(dname, resp_info);

  create_xmem_ymem();

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
const char *dsp56k_t::set_idp_options(
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

//--------------------------------------------------------------------------
void dsp56k_t::set_cpu(int procno)
{
  procnum = procno;
  ph.cnbits = (is561xx()             ) ? 16 : 24;
  ph.dnbits = (is561xx() || is566xx()) ? 16 : 24;
  ph.retcodes = (is561xx()           ) ? retcodes61 : retcodes6x;
}

//----------------------------------------------------------------------
void dsp56k_t::load_from_idb()
{
  xmem = get_start(get_segm_by_name("XMEM"));
  if ( !is561xx() )
    ymem = get_start(get_segm_by_name("YMEM"));
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(dsp56k_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi dsp56k_t::on_event(ssize_t msgid, va_list va)
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

    case processor_t::ev_newfile:      // new file loaded
      {
        // data memory could already be present, check it
        xmem = get_start(get_segm_by_name("XMEM"));
        if ( !is561xx() )
          ymem = get_start(get_segm_by_name("YMEM"));

        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
          select_device(ioh.device.c_str(), IORESP_AREA|IORESP_INT);
        else
          create_xmem_ymem();
      }
      break;

    case processor_t::ev_ending_undo:
      // restore ptype
      set_cpu(ph.get_proc_index());
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
          set_cpu(n);
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
        const insn_t &insn = *va_arg(va, const insn_t *);
        int nocrefs = va_arg(va, int);
        return is_sane_insn(insn, nocrefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        segend(*ctx, seg);
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
#define FAMILY "Motorola DSP 5600x:"

static const char *const shnames[] =
{
  "dsp56k",
  "dsp561xx",
  "dsp563xx",
  "dsp566xx",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Motorola DSP 5600x",
  "Motorola DSP 561xx",
  "Motorola DSP 563xx",
  "Motorola DSP 566xx",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_DSP56K,            // id
                          // flag
    PRN_HEX
  | PR_ALIGN
  | PR_BINMEM,
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  24,                     // 24 bits in a byte for code segments
  24,                     // 24 bits in a byte for other segments
  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  vCS,                  // first
  vDS,                  // last
  0,                    // size of a segment register
  vCS, vDS,

  nullptr,                 // No known code start sequences
  retcodes6x,

  DSP56_null,
  DSP56_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  DSP56_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
