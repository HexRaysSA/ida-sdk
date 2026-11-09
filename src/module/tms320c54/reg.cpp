/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c54.hpp"
#include "notify_codes.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <ieee.h>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "PC",  // program counter
  "A",   // accumulator
  "B",   // accumulator

  // flags
  "ASM", // 5-bit accumulator shift mode field in ST1
  "ARP", // auxiliary register pointer
  "TS",  // shift value (bits 5-0 of T)
  "OVB",
  "OVA",
  "C",
  "TC",
  "CMPT",
  "FRCT",
  "C16",
  "SXM",
  "OVM",
  "INTM",
  "HM",
  "XF",
  "BRAF",

  // CPU memory mapped registers
  "IMR",
  "IFR",
  "ST0",
  "ST1",
  "AL",
  "AH",
  "AG",
  "BL",
  "BH",
  "BG",
  "T",   // temporary register
  "TRN", // transition register
  "AR0",
  "AR1",
  "AR2",
  "AR3",
  "AR4",
  "AR5",
  "AR6",
  "AR7",
  "SP",  // stack pointer
  "BK",
  "BRC",
  "RSA",
  "REA",
  "PMST",

  // segment registers
  "XPC", // program counter extension register
  "CPL", // compiler mode
  "DP",  // data page pointer
  "cs","ds", // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0xF4, 0xE4 }; // fret
static const uchar retcode_1[] = { 0xF6, 0xE4 }; // fretd
static const uchar retcode_2[] = { 0xF4, 0xE5 }; // frete
static const uchar retcode_3[] = { 0xF6, 0xE5 }; // freted
static const uchar retcode_4[] = { 0xFC }; // rc
static const uchar retcode_5[] = { 0xFE }; // rcd
static const uchar retcode_6[] = { 0xFC, 0x00 }; // ret
static const uchar retcode_7[] = { 0xFE, 0x00 }; // retd
static const uchar retcode_8[] = { 0xF4, 0xEA }; // rete
static const uchar retcode_9[] = { 0xF6, 0xEA }; // reted
static const uchar retcode_10[] = { 0xF4, 0x9A }; // retf
static const uchar retcode_11[] = { 0xF6, 0x9A }; // retfd

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { sizeof(retcode_4), retcode_4 },
  { sizeof(retcode_5), retcode_5 },
  { sizeof(retcode_6), retcode_6 },
  { sizeof(retcode_7), retcode_7 },
  { sizeof(retcode_8), retcode_8 },
  { sizeof(retcode_9), retcode_9 },
  { sizeof(retcode_10), retcode_10 },
  { sizeof(retcode_11), retcode_11 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      TMS320C54 ASM
//-----------------------------------------------------------------------
static const asm_t fasm =
{
  AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON,
  0,
  "ASM500",
  0,
  nullptr,         // header lines
  nullptr,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  nullptr,         // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".space 16*%s",// uninited arrays
  ".asg",       // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  ".global",    // "public" name keyword
  nullptr,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  nullptr,         // "comm" (communal variable)
  nullptr,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
  AS2_STRINV    // invert string byte order
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gnuasm =
{
  AS_N2CHR|ASH_HEXF3|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP|AS_COLON|AS_ASCIIC,
  0,
  "GNU assembler",
  0,
  nullptr,         // header lines
  nullptr,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  nullptr,         // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".zero 2*%s", // uninited arrays
  ".asg",       // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  ".global",    // "public" name keyword
  ".weak",      // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
  nullptr,         // "comm" (communal variable)
  nullptr,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  nullptr,         // sizeof
  AS2_STRINV,   // invert string byte order
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &fasm, &gnuasm, nullptr };

//--------------------------------------------------------------------------

const char *tms320c54_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? port->name.c_str() : nullptr;
}

//----------------------------------------------------------------------
void tms320c54_t::apply_symbols(void)
{
  insn_t dummy;
  for ( int i=0; i < ioh.ports.size(); i++ )
  {
    ea_t ea = calc_data_mem(dummy, ioh.ports[i].address, false);
    segment_t *s = getseg(ea);
    if ( s == nullptr || s->type != SEG_IMEM )
      continue;
    create_byte(ea, 1);
    const char *name = ioh.ports[i].name.c_str();
    if ( !set_name(ea, name, SN_NOCHECK|SN_NOWARN|SN_NODUMMY) )
      set_cmt(ea, name, 0);
  }
}

//--------------------------------------------------------------------------
inline void swap(unsigned char &c1, unsigned char &c2)
{
  unsigned char tmp = c1;
  c1 = c2;
  c2 = tmp;
}

fpvalue_error_t idaapi tms_realcvt(void *m, fpvalue_t *e, ushort swt)
{
  fpvalue_error_t ret;
  switch ( swt )
  {
    case 1:                // float to e
      {
        unsigned char p[4];
        memcpy(p, m, 4);
        swap(p[0], p[1]);
        swap(p[2], p[3]);
        ret = ieee_realcvt(p, e, swt);
        break;
      }
    case 011:              // float output    //-V536 octal
      {
        ret = ieee_realcvt(m, e, swt);
        unsigned char *p = (unsigned char*)m;
        swap(p[0], p[1]);
        swap(p[2], p[3]);
        break;
      }
    default:
      ret = ieee_realcvt(m, e, swt);
      break;
  }
  return ret;
}

//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &fa)
{
  tms320c54_t &pm = *(tms320c54_t *)fa.get_ud();
  if ( choose_ioport_device(&pm.ioh.device, cfgname) )
    pm.ioh.set_device_name(pm.ioh.device.c_str(), IORESP_ALL);
  return 0;
}

//--------------------------------------------------------------------------
const char *tms320c54_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  if ( keyword == nullptr )
  {
    static const char form[] =
      "HELP\n"
      "TMS320C54 specific options\n"
      "\n"
      " Use I/O definitions\n"
      "\n"
      "       If this option is on, IDA will use I/O definitions\n"
      "       from the configuration file into a macro instruction.\n"
      "\n"
      " Detect memory mapped registers\n"
      "\n"
      "       If this option is on, IDA will replace addresses\n"
      "       by an equivalent memory mapped register.\n"
      "\n"
      " Device name\n"
      "\n"
      "       Choose the exact device name for the processor.\n"
      "       If you don't see the name you want, you can add\n"
      "       a section about it to the tms320c54.cfg file\n"
      "\n"
      " Data segment address\n"
      "\n"
      "       The data segment linear address.\n"
      "\n"
      "ENDHELP\n"
      "TMS320C54 specific options\n"
      "%*\n"
      " <Use ~I~/O definitions:C>\n"
      " <Detect memory mapped ~r~egisters:C>>\n"
      "\n"
      " <~C~hoose device name:B:0:::>\n"
      "\n"
      " <~D~ata segment address:N::18::>\n"
      "\n";
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    CASSERT(sizeof(dataseg) == sizeof(ea_t));
    ask_form(form, this, &idpflags, choose_device, &dataseg);
  }
  else
  {
    if ( strcmp(keyword, "TMS320C54_DSEG") == 0 )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      dataseg = *(uval_t *)value;
    }
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "TMS320C54_IO") == 0 )
    {
      setflag(idpflags, TMS320C54_IO, *(int*)value != 0);
    }
    else if ( strcmp(keyword, "TMS320C54_MMR") == 0 )
    {
      setflag(idpflags, TMS320C54_MMR, *(int*)value != 0);
    }
    else
    {
      return IDPOPT_BADKEY;
    }
  }
  if ( idb_loaded )
  {
    save_idpflags();
    save_dataseg();
  }
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
static const proctype_t ptypes[] =
{
  TMS320C54
};

void tms320c54_t::load_from_idb()
{
  ptype = ptypes[ph.get_proc_index()];
  ioh.restore_device();
  if ( ioh.device.empty() )
  {
    read_ioports(&ioh.ports, &ioh.device, cfgname);
    helper.supset(-1, ioh.device.c_str());
  }
  inf_set_wide_high_byte_first(false);
  idpflags = (ushort)helper.altval(-1);
  dataseg = helper.altval(0);
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(tms320c54_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi tms320c54_t::on_event(ssize_t msgid, va_list va)
{
MSC_DIAG_OFF(4063)
  int code = 0;
  switch ( msgid ) // Cast to avoid lint complaining.
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true); // MSB first
      inf_set_wide_high_byte_first(true);
      dataseg = helper.altval(0);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      read_ioports(&ioh.ports, &ioh.device, cfgname);
      helper.supset(-1, ioh.device.c_str());
      save_idpflags();
      save_dataseg();
      inf_set_wide_high_byte_first(false);
      {
        segment_t *s = get_first_seg();
        if ( s != nullptr )
          apply_symbols();
        while ( s != nullptr )
        {
          qstring sclas;
          get_segm_class(&sclas, s);
          for ( int i = XPC; i <= rVds; i++ )
            set_default_sreg_value(s, i, BADSEL);
          if ( sclas == "CODE" )
            set_default_sreg_value(s, XPC, s->start_ea >> 16);
          s = get_next_seg(s->start_ea);
        }
      }
      break;

    case tms320c54_module_t::ev_set_dataseg:
      dataseg = va_arg(va, ea_t);
      save_dataseg();
      break;

    case processor_t::ev_oldfile:   // old file loaded
      ioh.upgrade_device_index();
      //fall through
    case processor_t::ev_ending_undo:
      load_from_idb();
      break;

    case processor_t::ev_newbinary:
      inf_set_wide_high_byte_first(true);
      break;
    case processor_t::ev_endbinary:
      inf_set_wide_high_byte_first(false);
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        // bool keep_cfg = va_argi(va, bool);
        switch ( ptype )
        {
          case TMS320C54:
            break;
          default:
            error("interr: setprc");
        }
      }
      break;

    case processor_t::ev_newasm:    // new assembler type
      break;

    case processor_t::ev_creating_segm:    // new segment
      break;

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return is_basic_block_end(*insn) ? 1 : -1;
      }

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        int no_crefs = va_arg(va, int);
        // add 0, a is not a sane instruction without crefs to it
        code = no_crefs && get_wide_byte(insn->ea) == 0 ? -1 : 1;
      }
      break;

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

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        assumes(*ctx);
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

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        fpvalue_t *e = va_arg(va, fpvalue_t *);
        uint16 swt = va_argi(va, uint16);
        return tms_realcvt(m, e, swt);
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
        *frsize = tms_get_frame_retsize(pfn);
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
        static const cvt64_node_tag_t node_info[] =
        {
          CVT64_NODE_DEVICE,
          CVT64_NODE_IDP_FLAGS,
          { helper, atag|NETMAP_VAL, 0 },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
MSC_DIAG_ON(4063)
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "TMS320C54x Series:"
static const char *const shnames[] =
{
  "TMS32054",
  nullptr
};
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C54",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS320C54,         // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_ALIGN,
                          // flag2
    PR2_MAPPINGS            // use memory mapping
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  16,                     // 16 bits in a byte for code segments
  16,                     // 16 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  XPC,                  // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  TMS320C54_null,
  TMS320C54_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 18 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double (80-bit)
  TMS320C54_ret,        // Icode of return instruction. It is ok to give any of possible return instructions
};
