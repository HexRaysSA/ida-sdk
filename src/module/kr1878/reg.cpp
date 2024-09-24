
#include <ctype.h>
#include "kr1878.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  // data arithmetic logic unit
  "SR0", "SR1", "SR2", "SR3",
  "SR4", "SR5", "SR6", "SR7",
  "DSP", "ISP",
  "a", "b", "c", "d",
  "cs","ds",       // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x0c, 0x00 };
static const uchar retcode_1[] = { 0x0d, 0x00 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//--------------------------------------------------------------------------
struct interrupt_t
{
  int offset;
  const char *name; //lint !e958 padding is required to align members
};

static const interrupt_t ints[] =
{
  { 0x0000, "HRESET"                            },  // Hardware RESET
  { 0x0001, "WDOG"                              },
  { 0x0002, "STOVF"                             },
  { 0x0003, "TIMER"                             },
  { 0x0006, "PORTA"                             },
  { 0x0007, "PORTB"                             },
  { 0x000F, "EEPWr"                             },
};

//-----------------------------------------------------------------------
//      Angstrem KR1878VE1 Assembler
//-----------------------------------------------------------------------
static const asm_t motasm =
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
  "Angstrem KR1878VE1 Assembler",
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
  0,            // flag2
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &motasm, &gas, nullptr };

//----------------------------------------------------------------------
static ea_t AdditionalSegment(int size, int offset, const char *name)
{
  segment_t s;
  s.start_ea = find_free_chunk(0x100000, size, 0xF);
  s.end_ea   = s.start_ea + size;
  s.sel     = allocate_selector((s.start_ea-offset) >> 4);
  s.type    = SEG_DATA;
  add_segm_ex(&s, name, "DATA", ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea - offset;
}

inline ea_t get_start(const segment_t *s)
{
  return s ? s->start_ea : BADADDR;
}

//--------------------------------------------------------------------------
const ioport_t *kr1878_t::find_port(ea_t address)
{
  return find_ioport(ports, address);
}

void kr1878_t::read_kr1878_cfg(void)
{
  read_ioports(&ports, &device, "kr1878.cfg");
  for ( size_t i=0; i < ports.size(); i++ )
  {
    const ioport_t &p = ports[i];
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

void kr1878_t::set_device_name(const char *dev)
{
  if ( dev )
  {
    device = dev;
    helper.supset(-1, dev);
    read_kr1878_cfg();
  }
}

const char *kr1878_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  if ( choose_ioport_device(&device, "kr1878.cfg") )
    set_device_name(device.c_str());
  return IDPOPT_OK;
}

//-----------------------------------------------------------------------
// We always return "yes" because of the messy problem that
// there are additional operands with wrong operand number (always 1)
static bool idaapi can_have_type(const op_t &)
{
  return true;
}

//----------------------------------------------------------------------
void kr1878_t::load_from_idb()
{
  xmem = get_start(get_segm_by_name("MEM"));
  if ( helper.supstr(&device, -1) > 0 )
    read_kr1878_cfg();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(kr1878_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi kr1878_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      helper.create(PROCMOD_NODE_NAME);
      init_analyzer();
      inf_set_gen_tryblks(true);
      break;

    case processor_t::ev_term:
      ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:      // new file loaded
      {
        for ( int i=0; i < qnumber(ints); i++ )
        {
          ea_t ea = inf_get_min_ea() + ints[i].offset;
          if ( !is_loaded(ea) )
            continue;
          add_entry(ea, ea, ints[i].name, true);
        }

        segment_t *s0 = get_first_seg();
        if ( s0 != nullptr )
        {
          segment_t *s1 = get_next_seg(s0->start_ea);
          set_segm_name(s0, "CODE");
          for ( int i = as; i <= vDS; i++ )
          {
            set_default_sreg_value(s0, i, BADSEL);
            set_default_sreg_value(s1, i, BADSEL);
          }
        }
        xmem = AdditionalSegment(0x100, 0, "MEM");
      }
      read_kr1878_cfg();
      break;

    case processor_t::ev_oldfile:      // old file loaded
      {
        qstring old_device;
        if ( helper.supstr(&old_device, 0) >= 0 )
        {
          helper.supset(-1, old_device.c_str());
          helper.supdel(0);
        }
      }
      // fall through
    case processor_t::ev_ending_undo:
      load_from_idb();
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
        kr1878_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        kr1878_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        kr1878_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        kr1878_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        kr1878_assumes(*ctx);
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
        nodeidx_t node = va_arg(va, nodeidx_t);
        uchar tag = va_argi(va, uchar);
        nodeidx_t idx = va_arg(va, nodeidx_t);
        if ( helper == node && tag == stag && idx == nodeidx32_t(-1) )
        {
          helper.supset(-1, device.c_str());
          return 1;
        }
      }
      break;
#endif

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "Angstrem KR1878:"
static const char *const shnames[] = { "kr1878", nullptr };
static const char *const lnames[] =
{
  FAMILY"Angstrem KR1878",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_KR1878,            // id
                          // flag
    PRN_HEX               // hex numbers
  | PR_ALIGN              // data items must be aligned
  | PR_BINMEM             // segmentation is done by the processor mode
  | PR_SEGS,              // has segment registers
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

  as,                   // first
  vDS,                  // last
  1,                    // size of a segment register
  vCS, vDS,

  nullptr,                 // No known code start sequences
  retcodes,

  KR1878_null,
  KR1878_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  KR1878_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
