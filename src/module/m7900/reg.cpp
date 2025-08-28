/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include <ctype.h>
#include "7900.hpp"
#include <diskio.hpp>
#include <entry.hpp>
#include <cvt64.hpp>
int data_id;

//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "A", "B", "E", "X", "Y", "PC",  "S",
  "fIPL", "fN", "fV", "fD", "fI", "fZ", "fC",
  "DT", "PG", "DPReg", "DPR0","DPR1", "DPR2","DPR3","fM", "fX",
  "cs", "ds"
};




//----------------------------------------------------------------------
static const asm_t AS79 =
{
  AS_COLON    // create colons after data names ?
              // ASCII directives:
 |AS_1TEXT    //   1 text per line, no bytes
 |ASH_HEXF0   // format of hex numbers://   34h
 |ASD_DECF0   // format of dec numbers://   34
 |ASB_BINF0   // format of binary numbers://   010101b
 |AS_ONEDUP,  // One array definition per line

  UAS_NOSPA | UAS_SEGM,
  "Mitsubishi AS79 V4.10",
  0,
  nullptr,       // header
  ".org",
  ".end",

  ";",        // comment string
  '"',        // string delimiter
  '\'',       // char delimiter
  "'\"",      // special symbols in char and string constants

  ".BYTE",    // ascii string directive
  ".BYTE",    // byte directive
  ".WORD",    // word directive
  ".DWORD",   // no double words
  nullptr,       // no qwords
  nullptr,       // oword  (16 bytes)
  nullptr,       // no float
  nullptr,       // no double
  nullptr,       // no tbytes
  nullptr,       // no packreal
  nullptr,       //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s",     // uninited data (reserve space)
  ".equ",
  nullptr,         // seg prefix
  "*",          // a_curip
  nullptr,         // returns function header line
  nullptr,         // returns function footer line
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
//----------------------------------------------------------------------
//----------------------------------------------------------------------
#define FAMILY "Mitsubishi series:"

static const char *const shnames[] =
{
  "m7900",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Mitsubishi 7700 Family / 7900 Series",
  nullptr
};


static const asm_t *const asms[] =
{
  &AS79,
  nullptr
};

//--------------------------------------------------------------------------
static const uchar retc_0[] = { 0xF1 };        // rti
static const uchar retc_1[] = { 0x94 };        // rtl
static const uchar retc_2[] = { 0x1C, 0x77 };  // rtld 0
static const uchar retc_3[] = { 0x2C, 0x77 };  // rtld 1
static const uchar retc_4[] = { 0x4C, 0x77 };  // rtld 2
static const uchar retc_5[] = { 0x8C, 0x77 };  // rtld 3
static const uchar retc_6[] = { 0x84 };        // rts
static const uchar retc_7[] = { 0x18, 0x77 };  // rtsd 0
static const uchar retc_8[] = { 0x28, 0x77 };  // rtsd 1
static const uchar retc_9[] = { 0x48, 0x77 };  // rtsd 2
static const uchar retc_10[] = { 0x88, 0x77 }; // rtsd 3
static const uchar retc_11[] = { 0x00, 0x74 }; // brk

static const bytes_t retcodes[] =
{
  { sizeof(retc_0), retc_0 },
  { sizeof(retc_1), retc_1 },
  { sizeof(retc_2), retc_2 },
  { sizeof(retc_3), retc_3 },
  { sizeof(retc_4), retc_4 },
  { sizeof(retc_5), retc_5 },
  { sizeof(retc_6), retc_6 },
  { sizeof(retc_6), retc_7 },
  { sizeof(retc_6), retc_8 },
  { sizeof(retc_9), retc_9 },
  { sizeof(retc_10), retc_10 },
  { sizeof(retc_11), retc_11 },
  { 0, nullptr }
};


//----------------------------------------------------------------------
#define ADDRRESET 0xFFFE

const char *m7900_t::set_idp_options(
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

  ioh.set_device_name(ioh.device.c_str(), IORESP_PORT|IORESP_INT);

  return IDPOPT_OK;
}


//------------------------------------------------------------------
bool m7900_t::choose_device()
{
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  iohandler_t::parse_area_line0_t cb(ioh);
  bool ok = choose_ioport_device2(&ioh.device, cfgfile, &cb);
  if ( !ok )
  {
    ioh.device = NONEPROC;

    segment_t *sptr = get_first_seg();
    if ( sptr != nullptr )
    {
      //inf_set_start_ea(sptr->start_ea);
      //inf_set_start_ip(0);

      // No processor selected, so create RESET.
      // According to 7900 manual RESET resides at 0xFFFE address
      create_word(ADDRRESET, 2);
      ea_t proc = get_word(ADDRRESET);
      if ( proc != 0xFFFF && is_mapped(proc) )
      {
        op_plain_offset(ADDRRESET, 0, 0);
        add_entry(proc, proc, "__RESET", true);
        set_cmt(ADDRRESET, "RESET", false);
      }
    }
  }
  return ok;
}

//--------------------------------------------------------------------------
void m7900_t::load_from_idb()
{
  ioh.restore_device(IORESP_NONE);
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t notification_code, va_list va)
{
  switch ( notification_code )
  {
    case idb_event::sgr_changed:
      // In case of fM or fX segment registers undefine data above current address
      {
        int reg  = va_arg(va, int);
        if ( reg == rfM || reg == rfX || reg == rDT || reg == rPG )
        {
//        msg("Deleting instructions in range %08a..%08a\n",ea1, ea2);
//        for (ea_t x = ea1; x < ea2; x = next_that(x, ea2, is_code))
//          del_items(x, DELIT_SIMPLE);
        }
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static const char *const m7900_help_message =
  "AUTOHIDE REGISTRY\n"
  "You have loaded a file for the Mitsubishi 7900 family processor.\n\n"\
  "This processor can be used in two different 'length modes' : 8-bit and 16-bit.\n"\
  "IDA allows to specify the encoding mode for every single instruction.\n"\
  "For this, IDA uses two virtual segment registers : \n"\
  "   - rDPReg(1),  - rDPR0(0), rDPR1(0), rDPR2(0), rDPR3(0) \n"\
  "   - rDT(0),  rPG(0),  rPC(0),  rPS(0)   \n"\
  "   - fM, used to specify the data length;(0)\n"\
  "   - fX, used to specify the index register length.(0)\n\n"\
  "Switching their state from 0 to 1 will switch the disassembly from 16-bit to 8-bit.\n"\
  "You can change their value using the 'change segment register value' command"\
  "(the canonical hotkey is Alt-G).\n\n"\
  "Note : in the real design, those registers are represented as flags in the\n"\
  "processor status register.\n";


//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(m7900_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi m7900_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {

    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_newfile:
      if ( choose_device() )
        ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);

      //  Set the default segment register values :
      //      -1 (badsel) for DR
      //      0 for fM and fX
      for ( segment_t *s=get_first_seg(); s != nullptr; s=get_next_seg(s->start_ea) )
      {
        set_default_sreg_value(s, rDPR0, 0x0);
        set_default_sreg_value(s, rDPR1, 0x0);
        set_default_sreg_value(s, rDPR2, 0x0);
        set_default_sreg_value(s, rDPR3, 0x0);
        set_default_sreg_value(s, rDT, 0x0);
        set_default_sreg_value(s, rPG, 0x0);
        set_default_sreg_value(s, rPC, 0xFFFE);
        set_default_sreg_value(s, rPS, 0x0FFF);

        set_default_sreg_value(s, rfI, 1);
        set_default_sreg_value(s, rfD, 0);
        set_default_sreg_value(s, rfX, 0);
        set_default_sreg_value(s, rfM, 0);
        set_default_sreg_value(s, rfIPL, 0);

        set_default_sreg_value(s, rDPReg, 1);
      }
      info(m7900_help_message);
      break;

    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;


    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
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
        m7900_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        m7900_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        m7900_segstart(*ctx, seg);
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

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_M7900,             // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM             // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
  | PR_SEGS               // has segment registers?
  | PR_SGROTHER,          // the segment registers don't contain
                          // the segment selectors, something else
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rDT,
  Rds,
  0,                    // size of a segment register
  Rcs,Rds,

  nullptr,                 // No known code start sequences
  retcodes,

  0,
  m7900_last,
  Instructions,         // instruc
  3,                    // int tbyte_size;  -- doesn't exist

  { 0, 0, 0, 0 },       // char real_width[4];
                            // number of symbols after decimal point
                            // 2byte float (0-does not exist)
                            // normal float
                            // normal double
                            // long double
  m7900_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
