/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ctype.h>
#include "tms320c55.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <ieee.h>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "AC0",    // Accumulator
  "AC1",    // Accumulator
  "AC2",    // Accumulator
  "AC3",    // Accumulator
  "T0",     // Temporary register
  "T1",     // Temporary register
  "T2",     // Temporary register
  "T3",     // Temporary register
  "AR0",    // Auxiliary register
  "AR1",    // Auxiliary register
  "AR2",    // Auxiliary register
  "AR3",    // Auxiliary register
  "AR4",    // Auxiliary register
  "AR5",    // Auxiliary register
  "AR6",    // Auxiliary register
  "AR7",    // Auxiliary register

  "AC0L",   // Accumulator
  "AC0H",   // Accumulator
  "AC0G",   // Accumulator
  "AC1L",   // Accumulator
  "AC1H",   // Accumulator
  "AC1G",   // Accumulator
  "AC2L",   // Accumulator
  "AC2H",   // Accumulator
  "AC2G",   // Accumulator
  "AC3L",   // Accumulator
  "AC3H",   // Accumulator
  "AC3G",   // Accumulator
  "BK03",   // Circular buffer size register
  "BK47",   // Circular buffer size register
  "BKC",    // Circular buffer size register
  "BRC0",   // Block-repeat counter
  "BRC1",   // Block-repeat counter
  "BRS1",   // BRC1 save register
  "BSA01",  // Circulat buffer start address register
  "BSA23",  // Circulat buffer start address register
  "BSA45",  // Circulat buffer start address register
  "BSA67",  // Circulat buffer start address register
  "BSAC",   // Circulat buffer start address register
  "CDP",    // Coefficient data pointer (low part of XCDP)
  "CDPH",   // High part of XCDP
  "CFCT",   // Control-flow contect register
  "CSR",    // Computed single-repeat register
  "DBIER0", // Debug interrupt enable register
  "DBIER1", // Debug interrupt enable register
  // DP        Data page register (low part of XDP)
  // DPH       High part of XDP
  "IER0",   // Interrupt enable register
  "IER1",   // Interrupt enable register
  "IFR0",   // Interrupt flag register
  "IFR1",   // Interrupt flag register
  "IVPD",
  "IVPH",
  "PC",     // Program counter
  // PDP       Peripheral data page register
  "PMST",
  "REA0",   // Block-repeat end address register
  "REA0L",  // Block-repeat end address register
  "REA0H",  // Block-repeat end address register
  "REA1",   // Block-repeat end address register
  "REA1L",  // Block-repeat end address register
  "REA1H",  // Block-repeat end address register
  "RETA",   // Return address register
  "RPTC",   // Single-repeat counter
  "RSA0",   // Block-repeat start address register
  "RSA0L",  // Block-repeat start address register
  "RSA0H",  // Block-repeat start address register
  "RSA1",   // Block-repeat start address register
  "RSA1L",  // Block-repeat start address register
  "RSA1H",  // Block-repeat start address register
  "SP",     // Data stack pointer
  "SPH",    // High part of XSP and XSSP
  "SSP",    // System stack pointer
  "ST0",    // Status register
  "ST1",    // Status register
  "ST0_55", // Status register
  "ST1_55", // Status register
  "ST2_55", // Status register
  "ST3_55", // Status register
  "TRN0",   // Transition register
  "TRN1",   // Transition register

  "XAR0",   // Extended auxiliary register
  "XAR1",   // Extended auxiliary register
  "XAR2",   // Extended auxiliary register
  "XAR3",   // Extended auxiliary register
  "XAR4",   // Extended auxiliary register
  "XAR5",   // Extended auxiliary register
  "XAR6",   // Extended auxiliary register
  "XAR7",   // Extended auxiliary register

  "XCDP",   // Extended coefficient data pointer
  "XDP",    // Extended data page register
  "XPC",    // Extended program counter
  "XSP",    // Extended data stack pointer
  "XSSP",   // Extended system stack pointer

  "MDP",    // Main Data page pointer (direct memory access / indirect from CDP)
  "MDP05",  // Main Data page pointer (indirect AR[0-5])
  "MDP67",  // Main Data page pointer (indirect AR[6-7])

  // flags
  "ACOV2",
  "ACOV3",
  "TC1",
  "TC2",
  "CARRY",
  "ACOV0",
  "ACOV1",
  "BRAF",
  "XF",
  "HM",
  "INTM",
  "M40",
  "SATD",
  "SXMD",
  "C16",
  "FRCT",
  "C54CM",
  "DBGM",
  "EALLOW",
  "RDM",
  "CDPLC",
  "AR7LC",
  "AR6LC",
  "AR5LC",
  "AR4LC",
  "AR3LC",
  "AR2LC",
  "AR1LC",
  "AR0LC",
  "CAFRZ",
  "CAEN",
  "CACLR",
  "HINT",
  "CBERR",
  "MPNMC",
  "SATA",
  "CLKOFF",
  "SMUL",
  "SST",

  "BORROW",

  // segment registers
  "ARMS",   // AR indirect operands available
  "CPL",    // Compiler mode
  "DP",     // Data page pointer
  "DPH",    // Data page
  "PDP",    // Peripheral data page register
  "cs","ds" // virtual registers for code and data segments
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x48, 0x04 }; // ret
static const uchar retcode_1[] = { 0x48, 0x05 }; // reti

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      TMS320C55 ASM
//-----------------------------------------------------------------------
static const asm_t masm55 =
{
  AS_COLON|AS_N2CHR|ASH_HEXF0|ASD_DECF0|ASO_OCTF5|ASB_BINF0|AS_ONEDUP,
  0,
  "MASM55",
  0,
  nullptr,         // header lines
  nullptr,         // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".pstring",   // ascii string directive
  "MY_BYTE",    // byte directive
  ".word",      // word directive
  ".long",      // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".space 8*%s",// uninited arrays
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

static const asm_t *const asms[] = { &masm55, nullptr };

//--------------------------------------------------------------------------
const char *tms320c55_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? port->name.c_str() : nullptr;
}

//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &fa)
{
  tms320c55_t &pm = *(tms320c55_t *)fa.get_ud();
  if ( choose_ioport_device(&pm.ioh.device, cfgname) )
    pm.ioh.set_device_name(pm.ioh.device.c_str(), IORESP_ALL);
  return 0;
}

//--------------------------------------------------------------------------
const char *tms320c55_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded)
{
  if ( keyword == nullptr )
  {
    static const char form[] =
      "HELP\n"
      "TMS320C55 specific options\n"
      "\n"
      " Use I/O definitions \n"
      "\n"
      "       If this option is on, IDA will use I/O definitions\n"
      "       from the configuration file into a macro instruction.\n"
      "\n"
      " Detect memory mapped registers \n"
      "\n"
      "       If this option is on, IDA will replace addresses\n"
      "       by an equivalent memory mapped register.\n"
      "\n"
      "ENDHELP\n"
      "TMS320C55 specific options\n"
      "%*\n"
      " <Use ~I~/O definitions:C>\n"
      " <Detect memory mapped ~r~egisters:C>>\n"
      "\n"
      " <~C~hoose device name:B:0::>\n"
      "\n"
      "\n";
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    ask_form(form, this, &idpflags, choose_device);
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "TMS320C55_IO") == 0 )
    {
      setflag(idpflags, TMS320C55_IO, *(int*)value != 0);
    }
    else if ( strcmp(keyword, "TMS320C55_MMR") == 0 )
    {
      setflag(idpflags, TMS320C55_MMR, *(int*)value != 0);
    }
    else
    {
      return IDPOPT_BADKEY;
    }
  }
  if ( idb_loaded )
    save_idpflags();
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
static const proctype_t ptypes[] =
{
  TMS320C55
};

//--------------------------------------------------------------------------
void tms320c55_t::load_from_idb()
{
  ptype = ptypes[ph.get_proc_index()];
  ioh.restore_device();
  if ( ioh.device.empty() )
  {
    read_ioports(&ioh.ports, &ioh.device, cfgname);
    helper.supset(-1, ioh.device.c_str());
  }
  idpflags = (ushort)helper.altval(-1);
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(tms320c55_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi tms320c55_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true); // MSB first
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      {
        read_ioports(&ioh.ports, &ioh.device, cfgname);
        helper.supset(-1, ioh.device.c_str());
        save_idpflags();
        {
          set_default_sreg_value(nullptr, ARMS, 0);
          set_default_sreg_value(nullptr, CPL, 1);
          for ( int i = DP; i <= rVds; i++ )
            set_default_sreg_value(nullptr, i, 0);
        }
        static const char *const informations =
          "AUTOHIDE REGISTRY\n"
          "Default values of flags and registers:\n"
          "\n"
          "ARMS bit = 0 (DSP mode operands).\n"
          "CPL  bit = 1 (SP direct addressing mode).\n"
          "DP register = 0 (Data Page register)\n"
          "DPH register = 0 (High part of EXTENDED Data Page Register)\n"
          "PDP register = 0 (Peripheral Data Page register)\n"
          "\n"
          "You can change the register values by pressing Alt-G\n"
          "(Edit, Segments, Change segment register value)\n";
        info(informations);
        break;
      }

    case processor_t::ev_oldfile:   // old file loaded
      ioh.upgrade_device_index();
      // fall through
    case processor_t::ev_ending_undo:
      load_from_idb();
      break;

    case processor_t::ev_newprc:    // new processor type
      {
        ptype = ptypes[va_arg(va, int)];
        // bool keep_cfg = va_argi(va, bool);
        switch ( ptype )
        {
          case TMS320C55:
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

    case processor_t::ev_get_stkvar_scale_factor:
      return 2;

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

    case processor_t::ev_can_have_type:
      {
        const op_t *op = va_arg(va, const op_t *);
        return can_have_type(*op) ? 1 : -1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
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
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
#define FAMILY "TMS320C55x Series:"
static const char *const shnames[] =
{ "TMS32055",
  nullptr
};
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C55",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS320C55,         // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_SCALE_STKVARS,
                          // flag2
    PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  ARMS,                 // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  TMS320C55_null,
  TMS320C55_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 18 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double (80-bit)
  TMS320C55_ret,        // Icode of return instruction. It is ok to give any of possible return instructions
};
