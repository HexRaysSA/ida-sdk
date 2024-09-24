/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"
#include <diskio.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "R0",  "R1",  "R2",   "R3",   "R4",   "R5",   "R6",   "R7",
  "R8",  "R9",  "R10",  "R11",  "R12",  "R13",  "R14",  "R15",
  "RR0", "RR1", "RR2",  "RR3",  "RR4",  "RR5",  "RR6",  "RR7",
  "RR8", "RR9", "RR10", "RR11", "RR12", "RR13", "RR14", "RR15",
  "cs",  "ds",  "rp",
};

//----------------------------------------------------------------------
typedef struct
{
  int off;
  const char *name; //lint !e958 padding is required to align members
  const char *cmt;
} entry_t;

static const entry_t entries[] =
{
  {  0, "irq0", "DAV0, IRQ0, Comparator" },
  {  2, "irq1", "DAV1, IRQ1" },
  {  4, "irq2", "DAV2, IRQ2, TIN, Comparator" },
  {  6, "irq3", "IRQ3, Serial in" },
  {  8, "irq4", "T0, Serial out" },
  { 10, "irq5", "T1" },
};

//----------------------------------------------------------------------
static ea_t AdditionalSegment(size_t size, size_t offset, const char *name, const char *sclass, uchar stype)
{
  segment_t s;
  s.start_ea = find_free_chunk(0, size, 0xF);
  s.end_ea   = s.start_ea + size;
  s.sel     = allocate_selector((s.start_ea-offset) >> 4);
  s.type    = stype;
  add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea - offset;
}

//----------------------------------------------------------------------
// special handling for areas
bool z8_iohandler_t::area_processing(ea_t start, ea_t end, const char *name, const char *aclass)
{
  if ( start >= end )
  {
    warning("Error in definition of segment %s %s", aclass, name);
    return false;
  }
  if ( strcmp(aclass, "CODE") == 0 )
  {
    AdditionalSegment(end-start, start, name, aclass, SEG_CODE);
  }
  else if ( strcmp(aclass, "DATA") == 0 )
  {
    uchar type = stristr(name, "FSR") != nullptr ? SEG_IMEM : SEG_DATA;
    AdditionalSegment(end-start, start, name, aclass, type);
  }
  else
  {
    return false;
  }
  return true;
}

//------------------------------------------------------------------
const char *z8_t::find_ioport(uval_t port)
{
  const ioport_t *p = ::find_ioport(ioh.ports, port);
  return p ? p->name.c_str() : nullptr;
}

//----------------------------------------------------------------------
static ea_t specialSeg(sel_t sel, bool make_imem = true)
{
  segment_t *s = get_segm_by_sel(sel);

  if ( s != nullptr )
  {
    if ( make_imem && s->type != SEG_IMEM )
    {
      s->type = SEG_IMEM;
      s->update();
    }
    return s->start_ea;
  }
  return BADADDR;
}

//----------------------------------------------------------------------
void z8_t::setup_data_segment_pointers(void)
{
  sel_t sel;
  if ( atos(&sel, "INTMEM") || atos(&sel, "RAM") )
    intmem = specialSeg(sel);
  else
    intmem = BADADDR;
}

//----------------------------------------------------------------------
bool z8_t::select_device(int resp_info)
{
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&ioh.device, cfgfile) )
  {
    ioh.device = NONEPROC;
    return false;
  }

  if ( !ioh.display_infotype_dialog(IORESP_ALL, &resp_info, cfgfile) )
    return false;

  ioh.set_device_name(ioh.device.c_str(), resp_info & ~IORESP_PORT);
  setup_data_segment_pointers();

  if ( (resp_info & IORESP_PORT) != 0 )
  {
    if ( intmem == BADADDR )
    {
      AdditionalSegment(0x1000, 0, "INTMEM", nullptr, SEG_IMEM);
      setup_data_segment_pointers();
    }
    for ( int i=0; i < ioh.ports.size(); i++ )
    {
      const ioport_t &p = ioh.ports[i];
      ea_t ea = p.address + intmem;
      ea_t oldea = get_name_ea(BADADDR, p.name.c_str());
      if ( oldea != ea )
      {
        if ( oldea != BADADDR )
          set_name(oldea, nullptr);
        del_items(ea, DELIT_EXPAND);
        set_name(ea, p.name.c_str(), SN_NODUMMY);
      }
      if ( !p.cmt.empty() )
        set_cmt(ea, p.cmt.c_str(), true);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
const char *z8_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  select_device(IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
void z8_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(z8_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi z8_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);                                 // MSB first
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      {
        segment_t *sptr = get_first_seg();
        if ( sptr != nullptr )
        {
          if ( sptr->start_ea - get_segm_base(sptr) == 0 )
          {
            inf_set_start_ea(sptr->start_ea + 0xC);
            inf_set_start_ip(0xC);
            if ( !inf_like_binary() )
            {
              // set default entries
              for ( int i = 0; i < qnumber(entries); i++ )
              {
                ea_t ea = sptr->start_ea + entries[i].off;
                if ( is_mapped(ea) )
                {
                  create_word(ea, 2);
                  op_plain_offset(ea, 0, sptr->start_ea);
                  ea_t ea1 = sptr->start_ea + get_word(ea);
                  auto_make_proc(ea1);
                  set_name(ea, entries[i].name, SN_NODUMMY);
                  set_cmt(sptr->start_ea+get_word(ea), entries[i].cmt, 1);
                }
              }
            }
          }
          set_segm_class(sptr, "CODE");
        }

        select_device(IORESP_ALL);

        if ( intmem == BADADDR )
        {
          AdditionalSegment(0x1000, 0, "INTMEM", nullptr, SEG_IMEM);
          setup_data_segment_pointers();
        }
      }
      break;

    case processor_t::ev_oldfile:
      load_from_idb();
      setup_data_segment_pointers();
      break;

    case processor_t::ev_creating_segm:
      {                 // default DS is equal to CS
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[rVds-ph.reg_first_sreg] = sptr->sel;
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        z8_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        z8_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        z8_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        z8_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        z8_assumes(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return z8_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return z8_emu(*insn) ? 1 : -1;
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
        z8_data(*ctx, analyze_only);
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
      helper.create(PROCMOD_NODE_NAME);   // recreate node as it was migrated
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

//--------------------------------------------------------------------------
static const asm_t Z8asm =
{
  AS_COLON,
  0,
  "Zilog Z8 assembler",
  0,
  nullptr,
  ".org",
  ".end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",       // Equ
  nullptr,         // seg prefix
  "$",
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  nullptr,    // and
  nullptr,    // or
  nullptr,    // xor
  nullptr,    // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};

static const asm_t *const asms[] = { &Z8asm, nullptr };

//--------------------------------------------------------------------------

#define FAMILY "Zilog Z8 series:"
static const char *const shnames[] = { "Z8", nullptr };
static const char *const lnames[]  = { FAMILY"Zilog Z8 MCU", nullptr };

//--------------------------------------------------------------------------

static const uchar retcode[]  = { 0xAF };   // ret
static const uchar iretcode[] = { 0xBF };   // iret

static const bytes_t retcodes[] =
{
  { sizeof(retcode),  retcode },
  { sizeof(iretcode), iretcode },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_Z8,                // id
                          // flag
    PRN_HEX
  | PR_RNAMESOK           // can use register names for byte names
  | PR_SEGTRANS           // segment translation is supported (map_code_ea)
  | PR_BINMEM             // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
  | PR_SEGS               // has segment registers?
  | PR_SGROTHER,          // the segment registers don't contain
                          // the segment selectors, something else
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,    // short processor names (null term)
  lnames,     // long processor names (null term)

  asms,       // array of enabled assemblers

  notify,     // Various messages:

  RegNames,             // Register names
  qnumber(RegNames),    // Number of registers

  rVcs,rRp,
  1,                    // size of a segment register
  rVcs,rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  0, Z8_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  Z8_ret,               // Icode of return instruction. It is ok to give any of possible return instructions
};
