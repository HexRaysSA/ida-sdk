/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  // empty place
  "",
  // general registers
  "A","X","Y",
  // pseudo-segment registers
  "cs","ds"
};

//----------------------------------------------------------------------
void c39_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(c39_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi c39_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
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
        C39_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        C39_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        C39_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return C39_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return C39_emu(*insn) ? 1 : -1;
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
        C39_data(*ctx, analyze_only);
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
  return 0;
}

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam =
{
  AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0,
  0,
  "Generic C39 assembler", // Assembler name
  0,                       // Help screen number, 0 - no help
  nullptr,                    // array of automatically generated header lines
  "org",                   // ORG
  "end",                   // end

  ";",                     // comment
  '"',                     // string literal delimiter
  '\'',                    // char constant delimiter
  "\\\"'",                 // special chars that cannot appear

  "db",                    // ascii string directive
  ".DATA.B",               // byte directive
  ".DATA.W",               // word directive
  ".DATA.L",               // dword  (4 bytes)
  nullptr,                    // qword  (8 bytes)
  nullptr,                    // oword  (16 bytes)
  nullptr,                    // float  (4 bytes)
  nullptr,                    // double (8 bytes)
  nullptr,                    // tbyte  (10/12 bytes)
  nullptr,                    // packed decimal real
  "#d dup(#v)",            // arrays (#h,#d,#v,#s(...)
  "db ?",                  // uninited arrays
  ".equ",                  // equ
  nullptr,                    // seg prefix
  "$",                     // current IP
  nullptr,                    // Generate function header lines
  nullptr,                    // Generate function footer lines
  nullptr,                    // public
  nullptr,                    // weak
  nullptr,                    // extrn
  nullptr,                    // comm
  nullptr,                    // Get name of type of item at ea or id
  ".ALIGN",                // align
  '(', ')',                // lbrace, rbrace
  nullptr,                    // mod
  nullptr,                    // and
  nullptr,                    // or
  nullptr,                    // xor
  nullptr,                    // not
  nullptr,                    // shl
  nullptr,                    // shr
  nullptr,                    // sizeof
};

static const asm_t *const asms[] = { &pseudosam, nullptr };
//-----------------------------------------------------------------------
#define FAMILY "Rockwell C39:"
static const char *const shnames[] = { "C39", nullptr };
static const char *const lnames[] = { FAMILY"Rockwell C39", nullptr };

//--------------------------------------------------------------------------
static const uchar retcode_1[] = { 0x00, 0x0B };    // RTS
static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,   // version
  PLFM_C39,                // processor's id
                           // flag
    PR_USE32
  | PR_BINMEM
  | PR_SEGTRANS,
                           // flag2
  0,
  8,                       // 8 bits in a byte for code segments
  8,                       // 8 bits in a byte

  shnames,                 // short processor names
  lnames,                  // long processor names

  asms,                    // assembler definitions

  notify,                  // Event notification handler

  RegNames,                // Regsiter names
  qnumber(RegNames),       // Number of registers

  rVcs,rVds,
  2,                       // size of a segment register
  rVcs,rVds,
  nullptr,                    // typical code start sequences
  retcodes,                // 'return' instruction opcodes
  0,C39_last,              // icode of the first and the last instruction
  Instructions,            // instruc
  3,                       // Size of long double (tbyte) - 24  bits
  {0,0,0,0},               // Number of digits in floating numbers after the decimal point
  0,                       // Icode of return instruction
  nullptr,                    // Reserved, currently equals to nullptr
};
