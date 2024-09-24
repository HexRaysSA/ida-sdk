/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@datarescue.com
 *
 */

#include "h8.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>

#include <ieee.h>
int data_id;

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
  "e0",   "e1",   "e2",  "e3",  "e4",  "e5",  "e6",  "e7",
  "r0h",  "r1h",  "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
  "r0l",  "r1l",  "r2l", "r3l", "r4l", "r5l", "r6l", "r7l",
  "er0",  "er1",  "er2", "er3", "er4", "er5", "er6", "er7",
  "macl", "mach",
  "pc",
  "ccr", "exr",
  "cs","ds",       // virtual registers for code and data segments
  "vbr", "sbr",
};

//--------------------------------------------------------------------------
static const char *const register_names_sp_er7[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "sp",
  "e0",   "e1",   "e2",  "e3",  "e4",  "e5",  "e6",  "e7",
  "r0h",  "r1h",  "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
  "r0l",  "r1l",  "r2l", "r3l", "r4l", "r5l", "r6l", "r7l",
  "er0",  "er1",  "er2", "er3", "er4", "er5", "er6", "er7",
  "macl", "mach",
  "pc",
  "ccr", "exr",
  "cs","ds",       // virtual registers for code and data segments
  "vbr", "sbr",
};

//--------------------------------------------------------------------------
static const char *const register_names_r7_sp[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
  "e0",   "e1",   "e2",  "e3",  "e4",  "e5",  "e6",  "e7",
  "r0h",  "r1h",  "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
  "r0l",  "r1l",  "r2l", "r3l", "r4l", "r5l", "r6l", "r7l",
  "er0",  "er1",  "er2", "er3", "er4", "er5", "er6", "sp",
  "macl", "mach",
  "pc",
  "ccr", "exr",
  "cs","ds",       // virtual registers for code and data segments
  "vbr", "sbr",
};

//--------------------------------------------------------------------------
static const uchar startcode_0[] = { 0x01, 0x00, 0x6D, 0xF3 };  // push.l  er3
static const uchar startcode_1[] = { 0x6D, 0xF3 };              // push.w  r3

static const bytes_t startcodes[] =
{
  { sizeof(startcode_0), startcode_0 },
  { sizeof(startcode_1), startcode_1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  nullptr,         // end

  ";",          // comment string
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
  ".double",    // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  nullptr,         // current IP (instruction pointer)
  nullptr,         // func_header
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
  nullptr,         // sizeof_fmt
  0,            // flag2
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
  nullptr,         // a_vstruc_fmt
  nullptr,         // a_rva
  nullptr,         // a_yword
};

//-----------------------------------------------------------------------
//      HEW ASM
//-----------------------------------------------------------------------
const asm_t hew =
{
  AS_ASCIIC|AS_ALIGN2|ASH_HEXF1|ASD_DECF0|ASO_OCTF7|ASB_BINF4|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  UAS_HEW,
  "HEW assembler",
  0,
  nullptr,         // header lines
  ".org",       // org
  ".end",       // end

  ";",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".sdata",     // ascii string directive
  ".data.b",    // byte directive
  ".data.w",    // word directive
  ".data.l",    // double words
  nullptr,         // qwords
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".res %s",    // uninited arrays
  ": .assign",  // equ that allows set/reset values
//": .equ",     // equ          (does not allow for reuse)
//": .reg (%s)",// equ for regs (does not allow for reuse)
//": .bequ",    // equ for bits (does not allow for reuse)
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  ".global",    // "public" name keyword
  nullptr,         // "weak"   name keyword
  ".global",    // "extrn"  name keyword
  ".comm",      // "comm" (communal variable)
  nullptr,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "~",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  "sizeof",     // sizeof_fmt
  0,            // flag2
  nullptr,         // cmnt2
  "low",        // low8
  "high",       // high8
  "lword",      // low16
  "hword",      // high16
  ".include \"%s\"",  // a_include_fmt
  nullptr,         // a_vstruc_fmt
  nullptr,         // a_rva
  nullptr,         // a_yword
};

static const asm_t *const asms[] = { &gas, &hew, nullptr };

//--------------------------------------------------------------------------
static const char cfgname[] = "h8.cfg";

void h8_iohandler_t::get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

//--------------------------------------------------------------------------
const char *h8_t::find_sym(ea_t address)
{
  const ioport_t *port = find_ioport(ioh.ports, address);
  return port ? port->name.c_str() : nullptr;
}

//-------------------------------------------------------------------------
void h8_t::load_from_idb()
{
  ioh.restore_device();
}

//--------------------------------------------------------------------------
const char *h8_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  if ( choose_ioport_device(&ioh.device, cfgname) )
    ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
  return IDPOPT_OK;
}

//--------------------------------------------------------------------------
static const proctype_t ptypes[] =
{
  P300,                                     // h8300
  P300 | MODE_ADV,                          // h8300a
  P300            | P2000 | P2600,          // h8s300
  P300 | MODE_ADV | P2000 | P2600,          // h8s300a
  P300            | P2000 | P2600 | PSX,    // h8sxn
  P300 | MODE_MID | P2000 | P2600 | PSX,    // h8sxm
  P300 | MODE_ADV | P2000 | P2600 | PSX,    // h8sxa
  P300 | MODE_MAX | P2000 | P2600 | PSX,    // h8sx
  P300 | MODE_ADV | SUBM_TINY,              // h8368
};

//--------------------------------------------------------------------------
void h8_t::set_cpu(int cpuno)
{
  ptype = ptypes[cpuno];
  // bool keep_cfg = va_argi(va, bool);
  if ( advanced() && !is_tiny() )
  {
    ph.flag |= PR_DEFSEG32;
  }
  if ( is_h8sx() )
  {
    ph.flag |= PR_SEGS;
    ph.reg_last_sreg = SBR;
    ph.segreg_size = 4;
  }
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(h8_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi h8_t::on_event(ssize_t msgid, va_list va)
{
  int ret = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newasm:    // new assembler type selected
      {
        int asmnum = va_arg(va, int);
        bool hew_asm = asmnum == 1;
        if ( advanced() )
          ph.reg_names = hew_asm ? register_names : register_names_r7_sp;
        else
          ph.reg_names = hew_asm ? register_names : register_names_sp_er7;
      }
      break;

    case processor_t::ev_newfile:   // new file loaded
      if ( choose_ioport_device(&ioh.device, cfgname) )
        ioh.set_device_name(ioh.device.c_str(), IORESP_NONE);
      if ( is_h8sx() )
      {
        set_default_sreg_value(nullptr, VBR, 0);
        set_default_sreg_value(nullptr, SBR, 0xFFFFFF00);
      }
      break;

    case processor_t::ev_ending_undo:
      // restore ptype
      set_cpu(ph.get_proc_index());
      //fall through
    case processor_t::ev_oldfile:   // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_newprc:    // new processor type
      set_cpu(va_arg(va, int));
      break;

    case processor_t::ev_creating_segm:    // new segment
      break;

    case processor_t::ev_is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        ret = is_jump_func(pfn, jump_target);
      }
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        ret = is_sane_insn(insn, no_crefs) == 1 ? 1 : -1;
      }
      break;

    case processor_t::ev_may_be_func:
                                // can a function start here?
                                // arg: none, the instruction is in 'cmd'
                                // returns: probability 0..100
                                // 'cmd' structure is filled upon the entrace
                                // the idp module is allowed to modify 'cmd'
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        ret = may_be_func(insn);
      }
      break;

    case processor_t::ev_gen_regvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        regvar_t *v = va_arg(va, regvar_t*);
        if ( is_hew_asm() )
        {
          ctx->gen_printf(0,
                          COLSTR("%s", SCOLOR_REG)
                          COLSTR(": .reg (", SCOLOR_SYMBOL)
                          COLSTR("%s", SCOLOR_REG)
                          COLSTR(")", SCOLOR_SYMBOL),
                          v->user, v->canon);
          ret = 1;
        }
      }
      break;

    case processor_t::ev_is_ret_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        ret = is_return_insn(insn) ? 1 : -1;
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
        h8_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8_assumes(*ctx);
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

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return h8_is_switch(si, *insn) ? 1 : -1;
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
        *frsize = h8_get_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_gen_stkvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const udm_t *stkvar = va_arg(va, const udm_t *);
        sval_t v = va_arg(va, sval_t);
        h8_gen_stkvar_def(*ctx, stkvar, v);
        return 1;
      }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char **errmsg = va_arg(va, const char **);
        bool idb_loaded = va_argi(va, bool);
        const char *retstr = set_idp_options(keyword, value_type, value, idb_loaded);
        if ( retstr == IDPOPT_OK )
          return 1;
        if ( errmsg != nullptr )
          *errmsg = retstr;
        return -1;
      }

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return h8_is_align_insn(ea);
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
  return ret;
}

//-----------------------------------------------------------------------
#define FAMILY "Hitachi H8:"
static const char *const shnames[] =
{
  "h8300", "h8300a", "h8s300", "h8s300a",
  "h8sxn", "h8sxm", "h8sxa", "h8sx", "h8368", nullptr
};
static const char *const lnames[] =
{
  FAMILY"Hitachi H8/300H normal",
  "Hitachi H8/300H advanced",
  "Hitachi H8S normal",
  "Hitachi H8S advanced",
  "Hitachi H8SX normal",
  "Hitachi H8SX middle",
  "Hitachi H8SX advanced",
  "Hitachi H8SX maximum",
  "Renesas H8/3687 Group",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_H8,                // id
                          // flag
    PRN_HEX
  | PR_USE32
  | PR_WORD_INS,
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

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  startcodes,           // start sequences
  nullptr,                 // see is_ret_insn callback in the notify() function

  H8_null,
  H8_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  H8_rts,               // Icode of return instruction. It is ok to give any of possible return instructions
};
