
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
// list of registers
static const char *const RegNames[] =
{
  // empty
  "",
  // general purpose
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "ra", "sp",
  // special
  "pc", "isp", "intbase", "psr", "cfg", "dsr", "dcr", "carl", "carh",
  "intbaseh", "intbasel",

  // pseudo segments
  "cs", "ds"
};

//----------------------------------------------------------------------
void cr16_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(cr16_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi cr16_t::on_event(ssize_t msgid, va_list va)
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
      // ask for a  processor from the config file
      // use it to handle ports and registers
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
        CR16_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        CR16_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        CR16_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return CR16_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return CR16_emu(*insn) ? 1 : -1;
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
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam =
{
  AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0,
  // user flags
  0,
  "Generic CR16 assembler",     // title
  0,                            // help id
  nullptr,                         // header
  "org",                        // ORG directive
  "end",                        // end directive

  ";",                          // comment
  '"',                          // string delimiter
  '\'',                         // character constant
  "\\\"'",                      // special characters

  "db",                         // ascii string directive
  ".byte",                      // byte directive
  ".word",                      // word directive
  nullptr,                         // dword  (4 bytes)
  nullptr,                         // qword  (8 bytes)
  nullptr,                         // oword  (16 bytes)
  nullptr,                         // float  (4 bytes)
  nullptr,                         // double (8 bytes)
  nullptr,                         // tbyte  (10/12 bytes)
  nullptr,                         // packed decimal real
  "#d dup(#v)",                 // arrays (#h,#d,#v,#s(...)
  "db ?",                       // uninited arrays
  ".equ",                       // equ
  nullptr,                         // seg prefix
  "$",                          // current IP (instruction pointer) symbol in assembler
  nullptr,                         // Generate function header lines
  nullptr,                         // Generate function footer lines
  nullptr,                         // public
  nullptr,                         // weak
  nullptr,                         // extrn
  nullptr,                         // comm
  nullptr,                         // Get name of type of item at ea or id
  ".ALIGN",                     // align
  '(', ')',                     // lbrace, rbrace
  nullptr,                         // mod
  nullptr,                         // and
  nullptr,                         // or
  nullptr,                         // xor
  nullptr,                         // not
  nullptr,                         // shl
  nullptr,                         // shr
  nullptr,                         // sizeof
};

// list of assemblers
static const asm_t *const asms[] = { &pseudosam, nullptr };

//-----------------------------------------------------------------------
#define FAMILY "NSC CR16:"

// short names
static const char *const shnames[] = { "CR16", nullptr };

// long names
static const char *const lnames[] = { FAMILY"NSC CR16", nullptr };

//--------------------------------------------------------------------------
// return instructions
static const uchar retcode_1[] = { 0x00, 0x0B };      // RTS

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
  IDP_INTERFACE_VERSION,  // version
  PLFM_CR16,              // processor ID
                          // flag
    PR_USE32
  | PR_BINMEM
  | PR_SEGTRANS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for data segments

  shnames,                // short processor names (nullptr terminated)
  lnames,                 // long processor names (nullptr terminated)

  asms,                   // assemblers

  notify,                 // Event notification handler

  RegNames,               // Regsiter names
  qnumber(RegNames),      // Number of registers

  rVcs, rVds,
  2,                      // size of a segment register
  rVcs, rVds,
  nullptr,                   // Array of typical code start sequences
  retcodes,               // Array of 'return' instruction opcodes
  0, CR16_last,           // icode of the first and the last instruction
  Instructions,           // instruc
  3,                      // Size of long double (tbyte) for this processor - 24 bits
  {0, 0, 0, 0},           // Number of digits in floating numbers after the decimal point
  0,                      // Icode of return instruction
  nullptr,                   // micro virtual mashine
};
