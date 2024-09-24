/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
// registers
static const char *const RegNames[] =
{
  // zero reg
  "",
  // byte regs
  "W", "A", "B", "C", "D", "E", "H", "L",
  // word regs
  "WA", "BC", "DE", "HL", "IX", "IY", "IZ", "SP",
  // Double word regs
  "XWA", "XBC", "XDE", "XHL", "XIX", "XIY", "XIZ", "XSP",
  // strange regs
  "IXL", "IXH", "IYL", "IYH", "IZL", "IZH", "SPL", "SPH",
  // pesudo-seg regs
  "cs", "ds"
};

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(tlcs900_t));
  return 0;
}

//----------------------------------------------------------------------
void tlcs900_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
ssize_t idaapi tlcs900_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(false);
      inf_set_gen_lzero(true);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      {
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
          ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
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
        T900_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        T900_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        T900_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return T900_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return T900_emu(*insn) ? 1 : -1;
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
        T900_data(*ctx, analyze_only);
        return 1;
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
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam =
{
  AS_COLON | AS_UDATA | ASH_HEXF3,
  0,
  "Generic IAR-style assembler",
  0,
  nullptr,
  "org",
  "end",

  ";",
  '"',
  '\'',
  "\\\"'",

  "db",                                 // ascii string directive
  "DB",                                 // byte directive
  "DW",                                 // word directive
  "DL",                                 // dword  (4 bytes)
  nullptr,                                 // qword  (8 bytes)
  nullptr,     // oword  (16 bytes)
  nullptr,                                 // float  (4 bytes)
  nullptr,                                 // double (8 bytes)
  nullptr,                                 // tbyte  (10/12 bytes)
  nullptr,                                 // packed decimal real
  "#d dup(#v)",                         // arrays (#h,#d,#v,#s(...)
  "db ?",                               // uninited arrays
  ".equ",                               // equ
  nullptr,                                 // seg prefix
  "$",
  nullptr,
  nullptr,
  nullptr,                                 // public
  nullptr,                                 // weak
  nullptr,                                 // extrn
  nullptr,                                 // comm
  nullptr,
  "align",
  '(',     // lbrace
  ')',     // rbrace
  nullptr,    // mod
  nullptr,    // and
  nullptr,    // or
  nullptr,    // xor
  nullptr,    // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};

static const asm_t *const asms[] = { &pseudosam, nullptr };
//-----------------------------------------------------------------------
#define FAMILY "Toshiba TLCS-900 series:"
static const char *const shnames[] = { "TLCS900", nullptr };
static const char *const lnames[] = { FAMILY"Toshiba TLCS900", nullptr };

//--------------------------------------------------------------------------
static const uchar retcode_1[] = { 0x0E };    // ret
static const uchar retcode_2[] = { 0x0F };    // ret d
static const uchar retcode_3[] = { 0x07 };    // reti
static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TLCS900,           // id
                          // flag
    PR_USE32
  | PR_BINMEM
  | PR_SEGTRANS
  | PR_DEFSEG32,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                     // Regsiter names
  qnumber(RegNames),            // Number of registers

  rVcs, rVds,
  2,                            // size of a segment register
  rVcs, rVds,
  nullptr,
  retcodes,
  T900_null, T900_last,
  Instructions,                 // instruc
  3,                            // tbyte - 24 bit
  {0,0,0,0},
  0,
  nullptr,
};
