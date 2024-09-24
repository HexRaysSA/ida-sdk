/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE","HL",
  "PSW", "SP", "CY", "RB0", "RB1", "RB2", "RB3",
  "cs", "ds"
};

//----------------------------------------------------------------------
static const asm_t nec78k0 =
{
  AS_COLON | ASB_BINF4 | AS_N2CHR,
  0,
  "NEC 78K0 Assembler",
  0,
  nullptr,
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".db",    // ascii string directive
  ".db",    // byte directive
  ".dw",    // word directive
  ".dd",     // no double words
  nullptr,     // no qwords
  nullptr,     // oword  (16 bytes)
  nullptr,     // no float
  nullptr,     // no double
  nullptr,     // no tbytes
  nullptr,     // no packreal
  "#d dup(#v)",     //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s",// uninited data (reserve space)
  ".equ",
  nullptr,    // seg prefix
  "$",     // a_curip

  nullptr,    // returns function header line
  nullptr,    // returns function footer line
  nullptr,    // public
  nullptr,    // weak
  nullptr,    // extrn
  nullptr,    // comm
  nullptr,    // get_type_name
  nullptr,    // align

  '(', ')',// lbrace, rbrace
  nullptr,    // mod
  nullptr,    // and
  nullptr,    // or
  nullptr,    // xor
  nullptr,    // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};


//----------------------------------------------------------------------
#define FAMILY "NEC series:"
static const char *const shnames[] =
{
  "78k0",
  nullptr
};
static const char *const lnames[] =
{
  FAMILY"NEC 78K0",
  nullptr
};

static const asm_t *const asms[] =
{
  &nec78k0,
  nullptr
};

//--------------------------------------------------------------------------
static const uchar retcNEC78K0_0[] = { 0xAF };    // ret
static const uchar retcNEC78K0_1[] = { 0x9F };    // retb
static const uchar retcNEC78K0_2[] = { 0x8F };    // reti
static const uchar retcNEC78K0_3[] = { 0xBF };    // brk
static const bytes_t retcodes[] =
{
  { sizeof(retcNEC78K0_0), retcNEC78K0_0 },
  { sizeof(retcNEC78K0_1), retcNEC78K0_1 },
  { sizeof(retcNEC78K0_2), retcNEC78K0_2 },
  { sizeof(retcNEC78K0_3), retcNEC78K0_3 },
  { 0, nullptr }
};


//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(nec78k0_t));
  return 0;
}

//------------------------------------------------------------------
bool nec78k0_t::nec_find_ioport_bit(outctx_t &ctx, int port, int bit)
{

  const ioport_bit_t *b = find_ioport_bit(ioh.ports, port, bit);
  if ( b != nullptr && !b->name.empty() )
  {
    ctx.out_line(b->name.c_str(), COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------

void set_dopolnit_info(void)
{
  for ( int banknum = 0; banknum < 4; banknum++ )
  {
    for ( int Regs = 0; Regs < 8; Regs++ )
    {
      char temp[100];
      qsnprintf(temp, sizeof(temp), "Bank%d_%s", banknum, RegNames[Regs]);
      ushort Addr = ushort(0xFEE0+((banknum*8)+Regs));
      set_name(Addr, temp);
      qsnprintf(temp, sizeof(temp), "Internal high-speed RAM (Bank %d registr %s)", banknum, RegNames[Regs]);
      set_cmt(Addr, temp, true);
    }
  }
}

//----------------------------------------------------------------------
void nec78k0_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
ssize_t idaapi nec78k0_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(false);
      inf_set_gen_lzero(true);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      {
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
          ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
        set_dopolnit_info();
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        N78K_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        N78K_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        N78K_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return N78K_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return N78K_emu(*insn) ? 1 : -1;
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

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_NEC_78K0,
                          // flag
    PRN_HEX
  | PR_SEGTRANS
  | PR_SEGS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                                             // Regsiter names
  qnumber(RegNames),            // Number of registers

  rVcs, rVds,
  2,                            // size of a segment register
  rVcs, rVds,
  nullptr,
  retcodes,
  0, NEC_78K_0_last,
  Instructions,                 // instruc
  3,
  { 0,0,0,0 },
  0,
  nullptr,                         // micro virtual mashine
};
