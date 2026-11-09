/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <fpro.h>
#include <diskio.hpp>
#include <cvt64.hpp>

#include <ieee.h>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "fp",  "sp",
  "sr",   "ccr",  "?",   "br",  "ep",  "dp",  "cp",  "tp",
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x56, 0x70 };  // rte
static const uchar retcode_1[] = { 0x54, 0x70 };  // rts

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//------------------------------------------------------------------
static void idaapi func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  if ( ctx.curlabel.empty() )
    return;

  ctx.gen_printf(0, "%s" COLSTR(":", SCOLOR_SYMBOL) " "
                 SCOLOR_ON SCOLOR_AUTOCMT
                 "%s %s"
                 SCOLOR_OFF SCOLOR_AUTOCMT,
                 ctx.curlabel.begin(),
                 ASH.cmnt,
                 (pfn->flags & FUNC_FAR) != 0 ? "far" : "near");
  ctx.ctxflags |= CTXF_LABEL_OK;
}

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  nullptr,         // end

  "!",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  nullptr,         // current IP (instruction pointer)
  func_header,  // func_header
  nullptr,         // func_footer
  ".globl",     // "public" name keyword
  nullptr,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
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
  AS2_COLONSUF, // flag2
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &gas, nullptr };

//--------------------------------------------------------------------------
void h8500_t::load_symbols(const char *file)
{
  ports.clear();

  // KLUDGE: read_ioports() will complain if the file is
  // not present, but we don't want that.
  char cfgpath[QMAXPATH];
  const char *rfile = getsysfile(cfgpath, sizeof(cfgpath), file, CFG_SUBDIR);
  if ( rfile != nullptr )
    read_ioports(&ports, nullptr, file);
}

//--------------------------------------------------------------------------
const char *h8500_t::find_sym(int address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port != nullptr ? port->name.c_str() : nullptr;
}

//-------------------------------------------------------------------------
void h8500_t::load_from_idb()
{
  // in old databases we store 0 for the "mixed size" flag and -1 for the
  // "same size" flag. Now we store 1 for the latter.
  uval_t flags = helper.altval(-1);
  idpflags = flags == 0 ? 0 : IDP_SAMESIZE;
}

//------------------------------------------------------------------
const char *h8500_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  static const char form[] =
    "HELP\n"
    "H8/500 specific analyzer options\n"
    "\n"
    "Disassemble mixed size instructions\n"
    "\n"
    "        According to the documentation, instructions like\n"
    "\n"
    "        cmp:g.b #1:16, @0x222:16\n"
    "\n"
    "        are not allowed. The correct instruction is:\n"
    "\n"
    "        cmp:g.b #1:8, @0x222:16\n"
    "\n"
    "        The size of the first operand should agree with the size\n"
    "        of the instruction. (exception mov:g)\n"
    "\n"
    "ENDHELP\n"
    "H8/500 specific analyzer options\n"
    "\n"
    // m
    " <Disassemble ~m~ixed size instructions:C>>\n"
    "\n"
    "\n";

  if ( keyword != nullptr )
  {
    if ( streq(keyword, "H8500_MIXED_SIZE") )
    {
      if ( value_type != IDPOPT_BIT )
        return IDPOPT_BADTYPE;
      // we store in IDPFLAGS the negation of the mixed size flag
      setflag(idpflags, IDP_SAMESIZE, *(int*)value == 0);
    }
    else
    {
      return IDPOPT_BADKEY;
    }
  }
  else
  {
    // we store in IDPFLAGS the negation of the mixed size flag
    ushort flags = 0;
    if ( is_mixed_size_insns() )
      flags |= 1;
    ask_form(form, &flags);
    idpflags = 0;
    if ( (flags & 1) == 0 )
      idpflags |= IDP_SAMESIZE;
  }
  if ( idb_loaded )
    save_idpflags();
  return IDPOPT_OK;

}

//-----------------------------------------------------------------------
#define FAMILY "Hitachi H8/500:"
static const char *const shnames[] = { "h8500", nullptr };
static const char *const lnames[] =
{
  FAMILY"Hitachi H8/500",
  nullptr
};

//-----------------------------------------------------------------------
// temporary solution for v4.7
static ea_t idaapi h8_extract_address(ea_t screen_ea, const char *string, size_t x)
{
  size_t len = strlen(string);
  if ( len == 0 || x > len )
    return BADADDR;
  if ( x == len )
    x--;
  const char *ptr = string + x;
  while ( ptr > string && qisxdigit(ptr[-1]) )
    ptr--;
  const char *start = ptr;
  while ( qisxdigit(ptr[0]) )
    ptr++;
  len = ptr - start;
  char buf[MAXSTR];
  memcpy(buf, start, len);
  buf[len] = '\0';
  ea_t ea = BADADDR;
  str2ea(&ea, buf, screen_ea);
  return ea;
}

//------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:
    case o_reg:
    case o_reglist:
      return false;
    case o_phrase:
      return x.phtype == ph_normal;
  }
  return true;
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(h8500_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi h8500_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);
      load_symbols("h8500.cfg");
      break;

    case processor_t::ev_term:
      ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      save_idpflags();
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:   // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[BR-ph.reg_first_sreg] = 0;
        sptr->defsr[DP-ph.reg_first_sreg] = 0;
      }
      break;

    case processor_t::ev_is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        return is_jump_func(pfn, jump_target);
      }

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        return is_sane_insn(*insn, no_crefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8500_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8500_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_assume(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return h8500_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return h8500_emu(*insn) ? 1 : -1;
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

    case processor_t::ev_extract_address:
      {
        ea_t *out_ea = va_arg(va, ea_t *);
        ea_t screen_ea = va_arg(va, ea_t);
        const char *str = va_arg(va, const char *);
        size_t pos = va_arg(va, size_t);
        ea_t ea = h8_extract_address(screen_ea, str, pos);
        if ( ea == BADADDR )
          return -1;
        if ( ea == (BADADDR-1) )
          return 0;
        *out_ea = ea;
        return 1;
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
        *frsize = h8500_get_frame_retsize(pfn);
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
  PLFM_H8500,             // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER,
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

  BR,                   // first
  TP,                   // last
  1,                    // size of a segment register
  CP, DP,

  nullptr,                 // No known code start sequences
  retcodes,

  H8500_null,
  H8500_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  H8500_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
