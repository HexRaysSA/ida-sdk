/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "hppa.hpp"
#include "hppa_cfh.cpp"
#include <diskio.hpp>
#include <typeinf.hpp>
#include "notify_codes.hpp"
#include <cvt64.hpp>

#include <ieee.h>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names_plain[] =
{
  // general registers (r0 is always 0)
  // r31 is for BLE instruction
  "%r0",  "%r1",  "%rp",  "%r3",  "%r4",  "%r5",  "%r6",  "%r7",
  "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
  "%r16", "%r17", "%r18", "%r19", "%r20", "%r21", "%r22", "%r23",
  "%r24", "%r25", "%r26", "%dp",  "%r28", "%r29", "%sp",  "%r31",
  // space registers
  "%sr0", "%sr1", "%sr2", "%sr3", "%sr4", "%sr5", "%sr6", "%sr7",
  // control registers
  "%rctr", "%cr1",   "%cr2",  "%cr3",  "%cr4",   "%cr5",  "%cr6",  "%cr7",
  "%pidr1","%pidr2", "%ccr",  "%sar",  "%pidr3", "%pidr4","%iva",  "%eiem",
  "%itmr", "%pcsq",  "pcoq",  "%iir",  "%isr",   "%ior",  "%ipsw", "%eirr",
  "%tr0",  "%tr1",   "%tr2",  "%tr3",  "%tr4",   "%tr5",  "%tr6",  "%tr7",
  // floating-point registers
  "%fpsr", "%fr1",  "%fr2",  "%fr3",  "%fr4",  "%fr5",  "%fr6",  "%fr7",
  "%fr8",  "%fr9",  "%fr10", "%fr11", "%fr12", "%fr13", "%fr14", "%fr15",
  "%fr16", "%fr17", "%fr18", "%fr19", "%fr20", "%fr21", "%fr22", "%fr23",
  "%fr24", "%fr25", "%fr26", "%fr27", "%fr28", "%fr29", "%fr30", "%fr31",
  // register halves
  "%fr16l", "%fr17l", "%fr18l", "%fr19l", "%fr20l", "%fr21l", "%fr22l", "%fr23l",
  "%fr24l", "%fr25l", "%fr26l", "%fr27l", "%fr28l", "%fr29l", "%fr30l", "%fr31l",
  "%fr16r", "%fr17r", "%fr18r", "%fr19r", "%fr20r", "%fr21r", "%fr22r", "%fr23r",
  "%fr24r", "%fr25r", "%fr26r", "%fr27r", "%fr28r", "%fr29r", "%fr30r", "%fr31r",
  // condition bits
  "%ca0", "%ca1", "%ca2", "%ca3", "%ca4", "%ca5", "%ca6",

  "dp",            // segment register to represent DP
  "cs","ds",       // virtual registers for code and data segments
};

static const char *const register_names_mnemonic[] =
{
  // general registers (r0 is always 0)
  // r31 is for BLE instruction
  "%r0",   "%r1",   "%rp",   "%r3",  "%r4",   "%r5",  "%r6",  "%r7",
  "%r8",   "%r9",   "%r10",  "%r11", "%r12",  "%r13", "%r14", "%r15",
  "%r16",  "%r17",  "%r18",  "%r19", "%r20",  "%r21", "%r22", "%arg3",
  "%arg2", "%arg1", "%arg0", "%dp",  "%ret0", "%r29", "%sp",  "%r31",
  // space registers
  "%sr0", "%sr1", "%sr2", "%sr3", "%sr4", "%sr5", "%sr6", "%sr7",
  // control registers
  "%rctr", "%cr1",   "%cr2",  "%cr3",  "%cr4",   "%cr5",  "%cr6",  "%cr7",
  "%pidr1","%pidr2", "%ccr",  "%sar",  "%pidr3", "%pidr4","%iva",  "%eiem",
  "%itmr", "%pcsq",  "pcoq",  "%iir",  "%isr",   "%ior",  "%ipsw", "%eirr",
  "%tr0",  "%tr1",   "%tr2",  "%tr3",  "%tr4",   "%tr5",  "%tr6",  "%tr7",
  // floating-point registers
  "%fpsr", "%fr1",  "%fr2",  "%fr3",  "%fr4",  "%fr5",  "%fr6",  "%fr7",
  "%fr8",  "%fr9",  "%fr10", "%fr11", "%fr12", "%fr13", "%fr14", "%fr15",
  "%fr16", "%fr17", "%fr18", "%fr19", "%fr20", "%fr21", "%fr22", "%fr23",
  "%fr24", "%fr25", "%fr26", "%fr27", "%fr28", "%fr29", "%fr30", "%fr31",
  // register halves
  "%fr16l", "%fr17l", "%fr18l", "%fr19l", "%fr20l", "%fr21l", "%fr22l", "%fr23l",
  "%fr24l", "%fr25l", "%fr26l", "%fr27l", "%fr28l", "%fr29l", "%fr30l", "%fr31l",
  "%fr16r", "%fr17r", "%fr18r", "%fr19r", "%fr20r", "%fr21r", "%fr22r", "%fr23r",
  "%fr24r", "%fr25r", "%fr26r", "%fr27r", "%fr28r", "%fr29r", "%fr30r", "%fr31r",
  // condition bits
  "%ca0", "%ca1", "%ca2", "%ca3", "%ca4", "%ca5", "%ca6",

  "dp",            // segment register to represent DP
  "cs","ds",       // virtual registers for code and data segments
};
CASSERT(qnumber(register_names_plain) == qnumber(register_names_mnemonic));

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0xE8, 0x40, 0xC0, 0x00 };  // bv %r0(%rp)

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU-like hypothetical assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  nullptr,         // end

  "#",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".string",    // ascii string directive
  ".byte",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  ".quad",      // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
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
  nullptr,         // vstruc_fmt
  nullptr,         // rva
};

static const asm_t *const asms[] = { &gas, nullptr };

//------------------------------------------------------------------
// read all procmod data from the idb
void hppa_t::load_from_idb()
{
  idpflags = (ushort)helper.altval(-1);
  handle_new_flags(/*save*/ false);
}

//--------------------------------------------------------------------------
void hppa_t::setup_got(void)
{
  got = get_gotea();
  if ( got == BADADDR )
    got = get_name_ea(BADADDR, "_GLOBAL_OFFSET_TABLE_");
  if ( got == BADADDR )
  {
    segment_t *s = get_segm_by_name(".got");
    if ( s != nullptr )
      got = s->start_ea;
  }
  msg("DP is assumed to be %08a\n", got);
}

//--------------------------------------------------------------------------
void hppa_t::handle_new_flags(bool save)
{
  if ( mnemonic() )
    ph.reg_names = register_names_mnemonic;
  else
    ph.reg_names = register_names_plain;
  if ( save )
    save_idpflags();
}

//--------------------------------------------------------------------------
const char *hppa_t::get_syscall_name(int syscall)
{
  const ioport_t *p = find_ioport(syscalls, syscall);
  return p == nullptr ? nullptr : p->name.c_str();
}

//--------------------------------------------------------------------------
const char *hppa_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  static const char form[] =
    "HELP\n"
    "HP PA-RISC specific options\n"
    "\n"
    " Simplify instructions\n"
    "\n"
    "       If this option is on, IDA will simplify instructions and replace\n"
    "       them by clearer pseudo-instructions\n"
    "       For example,\n"
    "\n"
    "               or      0, 0, 0\n"
    "\n"
    "       will be replaced by\n"
    "\n"
    "               nop\n"
    "\n"
    " PSW bit W is on\n"
    "\n"
    "       If this option is on, IDA will disassemble instructions as if\n"
    "       PSW W bit is on, i.e. addresses are treated as 64bit. In fact,\n"
    "       IDA still will truncate them to 32 bit, but this option changes\n"
    "       disassembly of load/store instructions.\n"
    "\n"
    " Use mnemonic register names\n"
    "\n"
    "       If checked, IDA will use mnemonic names of the registers:\n"
    "         %r26:  %arg0\n"
    "         %r25:  %arg1\n"
    "         %r24:  %arg2\n"
    "         %r23:  %arg3\n"
    "         %r28:  %ret0\n"
    "\n"
    "\n"
    "ENDHELP\n"
    "HPPA specific options\n"
    "\n"
    " <~S~implify instructions:C>\n"
    " <PSW bit W is on (for 64-bit):C>\n"
    " <Use ~m~nemonic register names:C>>\n"
    "\n"
    "\n";

  if ( keyword == nullptr )
  {
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    ask_form(form, &idpflags);
OK:
    handle_new_flags(idb_loaded);
    return IDPOPT_OK;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "HPPA_SIMPLIFY") == 0 )
    {
      setflag(idpflags, IDP_SIMPLIFY, *(int*)value != 0);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_MNEMONIC") == 0 )
    {
      setflag(idpflags, IDP_MNEMONIC, *(int*)value != 0);
      goto OK;
    }
    if ( strcmp(keyword, "HPPA_PSW_W") == 0 )
    {
      setflag(idpflags, IDP_PSW_W, *(int*)value != 0);
      goto OK;
    }
    return IDPOPT_BADKEY;
  }
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(hppa_t));
  return 0;
}

ssize_t idaapi hppa_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);         // always big endian
      read_ioports(&syscalls, nullptr, "hpux.cfg");
      init_custom_refs();
      break;

    case processor_t::ev_term:
      term_custom_refs();
      syscalls.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:      // new file loaded
      handle_new_flags();
      setup_got();
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:      // old file loaded
      load_from_idb();
      setup_got();
      break;

    case processor_t::ev_newprc:    // new processor type
      break;

    case processor_t::ev_newasm:    // new assembler type
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[ rVds-ph.reg_first_sreg] = find_selector(sptr->sel);
        sptr->defsr[DPSEG-ph.reg_first_sreg] = 0;
      }
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int nocrefs = va_arg(va, int);
        return is_sane_insn(*insn, nocrefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return is_basic_block_end(*insn) ? 1 : -1;
      }

// +++ TYPE CALLBACKS (only 32-bit programs for the moment)
    case processor_t::ev_calc_arglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_hppa_arglocs(fti) ? 1 : -1;
      }

    case processor_t::ev_use_regarg_type:
      {
        int *used                 = va_arg(va, int *);
        ea_t ea                   = va_arg(va, ea_t);
        const funcargvec_t *rargs = va_arg(va, const funcargvec_t *);
        *used = use_hppa_regarg_type(ea, *rargs);
        return 1;
      }

    case processor_t::ev_use_arg_types:
      {
        ea_t ea               = va_arg(va, ea_t);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        funcargvec_t *rargs   = va_arg(va, funcargvec_t *);
        use_hppa_arg_types(ea, fti, rargs);
        return 1;
      }

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        cm_t cc = va_argi(va, cm_t);
        static const int fastcall_regs[] = { R26, R25, R24, R23, -1 };
        if ( cc == CM_CC_FASTCALL )
          callregs->set(ARGREGS_INDEPENDENT, fastcall_regs, nullptr);
        else if ( cc == CM_CC_THISCALL || cc == CM_CC_SWIFT )
          callregs->reset();
        else
          break;
        return 1;
      }

    case processor_t::ev_calc_cdecl_purged_bytes:
                                // calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 0;
      }

    case processor_t::ev_get_stkarg_area_info:
      {
        stkarg_area_info_t *out = va_arg(va, stkarg_area_info_t *);
        // cm_t cc = va_argi(va, cm_t);
        out->stkarg_offset = -0x34;
        return 1;
      }

// --- TYPE CALLBACKS

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        hppa_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        hppa_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        hppa_assumes(*ctx);
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


    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
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
        *frsize = hppa_get_frame_retsize(pfn);
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
          CVT64_NODE_IDP_FLAGS,
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    case hppa_module_t::ev_is_psw_w:
      return psw_w() ? 1 : -1;

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
static const char *const shnames[] = { "hppa", nullptr };
static const char *const lnames[] =
{
  "PA-RISC",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_HPPA,              // id
                          // flag
    PRN_HEX               // hex numbers
  | PR_ALIGN              // data items should be aligned
  | PR_USE32              // 32-bit mode is supported
  | PR_DEFSEG32           // 32-bit segments by default
#ifdef __EA64__
  | PR_USE64              // 64-bit mode is supported
#endif
  | PR_SEGS               // has segment registers
  | PR_SGROTHER           // segment register mean something unknown to the kernel
  | PR_STACK_UP           // stack grows up
  | PR_TYPEINFO           // type system is supported
  | PR_USE_ARG_TYPES      // use ph.use_arg_types()
  | PR_DELAYED,           // has delayed jumps and calls
                          // flag2
    PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names_plain,   // Register names
  qnumber(register_names_plain), // Number of registers

  DPSEG,                // first
  rVds,                 // last
  8,                    // size of a segment register
  rVcs,rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  HPPA_null,
  HPPA_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  HPPA_rfi,             // Icode of return instruction. It is ok to give any of possible return instructions
};
