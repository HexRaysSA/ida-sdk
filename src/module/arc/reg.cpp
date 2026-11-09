
/*
 * Interactive disassembler (IDA).
 * Copyright (c) 1990-98 by Ilfak Guilfanov.
 * ALL RIGHTS RESERVED.
 *
 * E-mail: ig@estar.msk.su, ig@datarescue.com
 * FIDO:    2:5020/209
 *
 */

#include "arc.hpp"
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",       // 0 .. 7
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", // 8 .. 15
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",       // 16 .. 23
  "r24", "r25", "gp", "fp", "sp", "ilink1", "ilink2", "blink",  // 23 .. 31

  "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",       // 31 .. 39
  "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",       // 40 .. 47
  "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",       // 48 .. 55
  "r56", "mlo", "mmid", "mhi","lp_count", "r61", "<limm>", "pcl",  // 56 .. 63
  // condition codes
  "CF", "ZF", "NF", "VF",

  // registers used for indexed instructions
  "next_pc",
  "ldi_base", "jli_base", "ei_base",

  "gp_base",

  "cs", "ds"
};

static const uchar codeseq_arcompact[] = { 0xF1, 0xC0 };  // push blink
static const uchar codeseq_arctg4[]    = { 0x04, 0x3E, 0x0E, 0x10 }; // st blink, [sp,4]

static const bytes_t codestart_arcompact[] =
{
  { sizeof(codeseq_arcompact), codeseq_arcompact },
  { 0, nullptr }
};

static const bytes_t codestart_arctg4[] =
{
  { sizeof(codeseq_arctg4), codeseq_arctg4 },
  { 0, nullptr }
};

//----------------------------------------------------------------------
void arc_t::set_codeseqs() const
{
  switch ( ptype )
  {
    case prc_arc:
      ph.codestart = codestart_arctg4;
      break;
    case prc_arcompact:
    case prc_arcv2:
      ph.codestart = codestart_arcompact;
      break;
  }
}

//-----------------------------------------------------------------------
// new names for old instructions in ARCv2
//lint -e{958} padding of 6 bytes needed to align member on a 8 byte boundary
struct instruc_alt_name_t
{
  uint16 itype;
  const char *old_name; // ARCompact name
  const char *new_name; // ARCv2 name
};

static const instruc_alt_name_t InstructionNamesARCv2[] =
{
  { ARC_mpyh,  "mpyh",  "mpym"  },
  { ARC_mpyhu, "mpyhu", "mpymu" },
  { ARC_sexw,  "sexw",  "sexh"  },
  { ARC_extw,  "extw",  "exth"  },
  { ARC_sat16, "sat16", "sath"  },
  { ARC_rnd16, "rnd16", "rndh"  },
  { ARC_abssw, "abssw", "abssh" },
  { ARC_negsw, "negsw", "negsh" },
  { ARC_normw, "normw", "normh" },
  { ARC_fadd,  "fadd",  "fsadd" },
  { ARC_fmul,  "fmul",  "fsmul" },
  { ARC_fsub,  "fsub",  "fssub" },
};

//----------------------------------------------------------------------
arc_t::arc_t()
{
  memcpy(Instructions, ::Instructions, sizeof(Instructions));
  ph.instruc = Instructions;
}

//----------------------------------------------------------------------
// updates names in Instruction array to match the subtype
void arc_t::set_instruc_names()
{
  for ( int i = 0; i < qnumber(InstructionNamesARCv2); ++i )
  {
    const instruc_alt_name_t &name = InstructionNamesARCv2[i];
    Instructions[name.itype].name = is_arcv2() ? name.new_name : name.old_name;
  }
}

//----------------------------------------------------------------------
// updates affected global state after a ptype change
void arc_t::ptype_changed()
{
  set_codeseqs();
  set_instruc_names();
}

//--------------------------------------------------------------------------
// handler for some IDB events
ssize_t idaapi pm_idb_listener_t::on_event(ssize_t notification_code, va_list va)
{
  switch ( notification_code )
  {
    case idb_event::op_type_changed:
      // An operand type (offset, hex, etc...) has been set or deleted
      {
        ea_t ea = va_arg(va, ea_t);
        int n = va_arg(va, int);
        if ( n >= 0 && n < UA_MAXOP && is_code(get_flags(ea)) )
        {
          insn_t insn;
          decode_insn(&insn, ea);
          op_t &x = insn.ops[n];
          if ( x.type == o_mem )
          {
            ea = to_ea(insn.cs, x.addr);
            pm.copy_insn_optype(insn, x, ea, nullptr, true);
          }
        }
      }
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
//      ASMI
//-----------------------------------------------------------------------
static const asm_t gnuas =
{
  AS_COLON | AS_N2CHR | AS_1TEXT | ASH_HEXF3 | ASO_OCTF1 | ASB_BINF3
 |AS_ONEDUP | AS_ASCIIC,
  0,
  "GNU assembler",
  0,
  nullptr,                         // no headers
  ".org",                       // org directive
  0,                            // end directive
  "#",                          // comment string
  '"',                          // string delimiter
  '\'',                         // char delimiter
  "\\\"'",                      // special symbols in char and string constants

  ".ascii",                     // ascii string directive
  ".byte",                      // byte directive
  ".short",                     // word directive
  ".long",                      // dword        (4 bytes)
  ".quad",                      // qword        (8 bytes)
  nullptr,                         // oword        (16 bytes)
  ".float",                     // float        (4 bytes)
  ".double",                    // double (8 bytes)
  nullptr,                         // tbyte        (10/12 bytes)
  nullptr,                         // packed decimal real
  ".ds.#s(b,w,l,d) #d, #v",     // arrays (#h,#d,#v,#s(...)
  ".space %s",                  // uninited arrays
  "=",                          // equ
  nullptr,                         // seg prefix
  ".",                          // curent ip
  nullptr,                         // func_header
  nullptr,                         // func_footer
  ".global",                    // public
  nullptr,                         // weak
  ".extern",                    // extrn
  ".comm",                      // comm
  nullptr,                         // get_type_name
  ".align",                     // align
  '(', ')',                     // lbrace, rbrace
  "%",                          // mod
  "&",                          // and
  "|",                          // or
  "^",                          // xor
  "!",                          // not
  "<<",                         // shl
  ">>",                         // shr
  nullptr,                         // sizeof
};


static const asm_t *const asms[] = { &gnuas, nullptr };

static int idaapi choose_device(int, form_actions_t &);

//-----------------------------------------------------------------------
const char *arc_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded)
{
  if ( keyword == nullptr )
  {
    static const char form[] =
      "HELP\n"
      "ARC specific options\n"
      "\n"
      " Simplify instructions\n"
      "\n"
      "      If this option is on, IDA will simplify instructions and replace\n"
      "      them by more natural pseudo-instructions or alternative mnemonics.\n"
      "      For example,\n"
      "\n"
      "                    sub.f   0, a, b\n"
      "\n"
      "     will be replaced by\n"
      "\n"
      "                    cmp a, b\n"
      "\n"
      "\n"
      " Inline constant pool loads\n"
      "\n"
      "     If this option is on, IDA will use =label syntax for\n"
      "     pc-relative loads (commonly used to load constants)\n"
      "     For example,\n"
      "\n"
      "                   ld      r1, [pcl,0x1C]\n"
      "                   ...\n"
      "                   .long 0x2051D1C8\n"
      "\n"
      "     will be replaced by\n"
      "\n"
      "                   ld      r1, =0x2051D1C8\n"
      "\n"
      "\n"
      " Track register accesses\n"
      "\n"
      "     This option tells IDA to track values loaded\n"
      "     into registers and use it to improve the listing.\n"
      "     For example,\n"
      "\n"
      "                   mov     r13, 0x172C\n"
      "                   ...\n"
      "                   add     r0, r13, 0x98\n"
      "\n"
      "     will be replaced by\n"
      "\n"
      "                   add     r0, r13, (dword_17C4 - 0x172C)\n"
      "\n"
      "\n"
      "ENDHELP\n"
      "ARC specific options\n"
      "%*\n"
      " <~S~implify instructions:C>\n"
      " <~I~nline constant pool loads:C>\n"
      " <Track ~r~egister accesses:C>>\n"
      " <~C~hoose core variant:B:0::>\n"
      "\n";
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    ask_form(form, this, &idpflags, choose_device);
    goto SAVE;
  }
  else
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    if ( strcmp(keyword, "ARC_SIMPLIFY") == 0 )
    {
      setflag(idpflags, ARC_SIMPLIFY, *(int*)value != 0);
    }
    else if ( strcmp(keyword, "ARC_INLINECONST") == 0 )
    {
      setflag(idpflags, ARC_INLINECONST, *(int*)value != 0);
    }
    else if ( strcmp(keyword, "ARC_TRACKREGS") == 0 )
    {
      setflag(idpflags, ARC_TRACKREGS, *(int*)value != 0);
    }
    else
    {
      return IDPOPT_BADKEY;
    }
SAVE:
    if ( idb_loaded )
      save_idpflags();
    return IDPOPT_OK;
  }
}

//-----------------------------------------------------------------------
// The short and long names of the supported processors
#define FAMILY "Argonaut RISC Core:"

static const char *const shnames[] =
{
  "arc",
  "arcmpct",
  "arcv2",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Argonaut RISC Core ARCtangent-A4",
  "Argonaut RISC Core ARCompact",
  "Argonaut RISC Core ARCv2",
  nullptr
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//                      - if an instruction has the "return" opcode, its autogenerated label
//                              will be "locret" rather than "loc".
//                      - IDA will use the first "return" opcode to create empty subroutines.

static const bytes_t retcodes[] =
{
  { 0, nullptr }                    // nullptr terminated array
};

//--------------------------------------------------------------------------
void arc_iohandler_t::get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, "arc.cfg", bufsize);
}

//--------------------------------------------------------------------------
const char *arc_iohandler_t::iocallback(const ioports_t &iop, const char *line)
{
  int len;
  sval_t ea1;
  char word[MAXSTR];
  word[MAXSTR-1] = '\0';
  CASSERT(MAXSTR == 1024);
  if ( qsscanf(line, "aux %1023s %" FMT_EA "i%n", word, &ea1, &len) == 2 )
  {
    const char *cmt = &line[len];
    cmt = skip_spaces(cmt);
    ioport_t &port = pm.auxregs.push_back();
    port.address = ea1;
    port.name = word;
    if ( cmt[0] != '\0' )
      port.cmt = cmt;
    return nullptr;
  }
  return standard_callback(iop, line);
}

//--------------------------------------------------------------------------
bool arc_t::select_device(int resp_info)
{
  char cfgfile[QMAXFILE];
  arc_respect_info = resp_info;
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&ioh.device, cfgfile) )
  {
    ioh.device = NONEPROC;
    return false;
  }

  if ( !ioh.display_infotype_dialog(IORESP_ALL, &arc_respect_info, cfgfile) )
    return false;

  ioh.set_device_name(ioh.device.c_str(), arc_respect_info);
  return true;
}


//--------------------------------------------------------------------------
static int idaapi choose_device(int, form_actions_t &fa)
{
  arc_t &pm = *(arc_t *)fa.get_ud();
  if ( pm.select_device(IORESP_ALL) )
  {
    // load_symbols(IORESP_ALL);
    // apply_symbols();
  }
  return 0;
}

//--------------------------------------------------------------------------
static int idaapi arcso_gen_scaled_expr(
        qstring * /*buf*/,
        qstring *format,
        ea_t /*ea*/,
        int /*numop*/,
        const refinfo_t &ri,
        ea_t /*from*/,
        adiff_t * /*opval*/,
        ea_t * /*target*/,
        ea_t * /*fullvalue*/,
        int /*getn_flags*/)
{
  arc_t &pm = *GET_MODULE_DATA(arc_t);
  int scale = ri.type() == pm.ref_arcsoh_id ? 2 : 4;
  format->sprnt("%%s " COLSTR("/", SCOLOR_SYMBOL) " %i", scale);
  return 4; // normal processing with custom format
}

//--------------------------------------------------------------------------
static bool idaapi arcso_calc_reference_data(
        ea_t *target,
        ea_t *base,
        ea_t from,
        const refinfo_t &ri,
        adiff_t opval)
{
  arc_t &pm = *GET_MODULE_DATA(arc_t);
  qnotused(from);
  if ( ri.base == BADADDR || ri.is_subtract() )
    return false;

  int scale = ri.type() == pm.ref_arcsoh_id ? 2 : 4;

  *base = ri.base;
  *target = ri.base + scale * opval;

  if ( ri.target != BADADDR && ri.target != *target )
    return false;

  return true;
}

//--------------------------------------------------------------------------
static const custom_refinfo_handler_t ref_arcsoh =
{
  sizeof(custom_refinfo_handler_t),
  "ARCSOH",
  "ARC 16-bit scaled offset",
  RHF_TGTOPT,                // properties: target be calculated using operand value
  arcso_gen_scaled_expr,     // gen_expr
  arcso_calc_reference_data, // calc_reference_data
  nullptr,                      // get_format
};

//--------------------------------------------------------------------------
static const custom_refinfo_handler_t ref_arcsol =
{
  sizeof(custom_refinfo_handler_t),
  "ARCSOL",
  "ARC 32-bit scaled offset",
  RHF_TGTOPT,                // properties: target be calculated using operand value
  arcso_gen_scaled_expr,     // gen_expr
  arcso_calc_reference_data, // calc_reference_data
  nullptr,                      // get_format
};


//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(arc_t));
  return 0;
}

//----------------------------------------------------------------------
void arc_t::load_from_idb()
{
  ptype = processor_subtype_t(ph.get_proc_index());
  ptype_changed();
  idpflags = (ushort)helper.altval(-1);
  ioh.restore_device();
}

//----------------------------------------------------------------------
ssize_t idaapi arc_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(false);               // Set little-endian mode of the IDA kernel
      set_codeseqs();
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      ref_arcsol_id = register_custom_refinfo(&ref_arcsol);
      ref_arcsoh_id = register_custom_refinfo(&ref_arcsoh);
      break;

    case processor_t::ev_term:
      unregister_custom_refinfo(ref_arcsoh_id);
      unregister_custom_refinfo(ref_arcsol_id);
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      save_idpflags();
      set_codeseqs();
      if ( inf_like_binary() )
      {
        // ask the user
        select_device(IORESP_ALL);
      }
      else
      {
        // load the default AUX regs
        ioh.set_device_name(is_a4() ? "ARC4": "ARCompact", IORESP_NONE);
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:
      break;

    case processor_t::ev_newprc:
      ptype = va_argi(va, processor_subtype_t);
      // bool keep_cfg = va_argi(va, bool);
      if ( uint(ptype) > prc_arcv2 )    //lint !e685 //-V547 is always false
      {
        code = -1;
        break;
      }
      ptype_changed();
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_is_call_insn:
                                // Is the instruction a "call"?
                                // ea_t ea  - instruction address
                                // returns: 1-unknown, 0-no, 2-yes
      {
        const insn_t *insn = va_arg(va, insn_t *);
        code = is_arc_call_insn(*insn) ? 1 : -1;
        return code;
      }

    case processor_t::ev_is_ret_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
//        bool strict = va_argi(va, bool);
        code = is_arc_return_insn(*insn) ? 1 : -1;
        return code;
      }

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        bool call_insn_stops_block = va_argi(va, bool);
        return is_arc_basic_block_end(*insn, call_insn_stops_block) ? 1 : -1;
      }

    case processor_t::ev_delay_slot_insn:
                                // Get delay slot instruction
                                // ea_t *ea     in: instruction address in question,
                                //                it may point to the instruction with a
                                //                delay slot or to the delay slot
                                //                instruction itself
                                //              out: (if the answer is positive)
                                //                if the delay slot contains valid insn:
                                //                  the address of the delay slot insn
                                //                else:
                                //                  BADADDR (invalid insn, e.g. a branch)
                                // bool *bexec  execute slot if jumping
                                // bool *fexec  execute slot if not jumping
                                // returns: 1   positive answer
                                //          <=0 ordinary insn
      {
        ea_t *ea = va_arg(va, ea_t *);
        bool *bexec = va_arg(va, bool *);
        bool *fexec = va_arg(va, bool *);
        insn_t insn;
        if ( decode_insn(&insn, *ea) == 0 )
          return -1;
        if ( has_dslot(insn) )
        {
          // the current instruction is a delayed slot instruction
          // set EA to the address of the delay slot
          *ea = insn.ea + insn.size;
          // check the insn in the delay slot
          // doc: "The Illegal Instruction Sequence type also occurs when
          // any of the following instructions are attempted in an executed
          // delay slot of a jump or branch:
          // * Another jump or branch instruction (Bcc, BLcc, Jcc, JLcc)
          // * Conditional loop instruction (LPcc)
          // * Return from interrupt (RTIE)
          // * Any instruction with long-immediate data as a source operand"
          insn_t dslot_insn;
          if ( decode_insn(&dslot_insn, *ea) == 0
            || is_forbidden_in_arc_dslot(dslot_insn) )
          {
            *ea = BADADDR;
          }
        }
        else
        {
          if ( !is_flow(get_flags(*ea))
            || decode_prev_insn(&insn, *ea) == BADADDR
            || !has_dslot(insn) )
          {
            return -1;
          }
          // the previous instruction is a delayed slot instruction
          // EA already has the address of the delay slot
        }
        *bexec = true;
        *fexec = (insn.auxpref & aux_nmask) != aux_jd;
        return 1;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return arc_is_switch(si, *insn) ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
                                // can a function start here?
                                ///< \param insn  (const ::insn_t*) the instruction
                                ///< \param state (int)  autoanalysis phase
                                ///<   0: creating functions
                                ///<   1: creating chunks
                                ///< \return probability 0..100
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int state = va_arg(va, int);
        return arc_may_be_func(*insn, state);
      }

    case processor_t::ev_undefine:
      {
        // an item is being undefined; delete data attached to it
        ea_t ea = va_arg(va, ea_t);
        del_insn_info(ea);
      }
      return 1;

// +++ TYPE CALLBACKS
    case processor_t::ev_calc_arglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_arc_arglocs(fti) ? 1 : -1;
      }

    case processor_t::ev_calc_varglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        regobjs_t *regargs    = va_arg(va, regobjs_t *);
        /*relobj_t *stkargs =*/ va_arg(va, relobj_t *);
        int nfixed = va_arg(va, int);
        return calc_arc_varglocs(fti, regargs, nfixed) ? 1 : -1;
      }

    case processor_t::ev_calc_retloc:
      {
        argloc_t *retloc    = va_arg(va, argloc_t *);
        const tinfo_t *type = va_arg(va, const tinfo_t *);
        cm_t cc             = va_argi(va, cm_t);
        return calc_arc_retloc(retloc, *type, cc) ? 1 : -1;
      }

    case processor_t::ev_use_regarg_type:
      {
        int *used                 = va_arg(va, int *);
        ea_t ea                   = va_arg(va, ea_t);
        const funcargvec_t *rargs = va_arg(va, const funcargvec_t *);
        *used = use_arc_regarg_type(ea, *rargs);
        return 1;
      }

    case processor_t::ev_use_arg_types:
      {
        ea_t ea               = va_arg(va, ea_t);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        funcargvec_t *rargs   = va_arg(va, funcargvec_t *);
        use_arc_arg_types(ea, fti, rargs);
        return 1;
      }

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        cm_t cc = va_argi(va, cm_t);
        if ( cc == CM_CC_FASTCALL || cc == CM_CC_ELLIPSIS )
        {
          const int *regs;
          get_arc_fastcall_regs(&regs);
          callregs->set(ARGREGS_INDEPENDENT, regs, nullptr);
          return 1;
        }
        else if ( cc == CM_CC_THISCALL || cc == CM_CC_SWIFT )
        {
          callregs->reset();
          return 1;
        }
      }
      break;

    case processor_t::ev_calc_cdecl_purged_bytes:
                                // calculate number of purged bytes after call
      {
        // ea_t ea                     = va_arg(va, ea_t);
        return 0;
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
          { helper, CALLEE_TAG|NETMAP_VAL|NETMAP_VAL_NDX, 0 }, // atag
          { helper, DXREF_TAG |NETMAP_VAL|NETMAP_VAL_NDX, 0 },
          { helper, DSLOT_TAG |NETMAP_VAL, 0 },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

// --- TYPE CALLBACKS

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        arc_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        arc_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        arc_segstart(*ctx, seg);
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

   case processor_t::ev_calc_spdelta:
     {
       sval_t *spdelta = va_arg(va, sval_t *);
       const insn_t *insn = va_arg(va, const insn_t *);
       return arc_calc_spdelta(spdelta, *insn);
     }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = arc_get_frame_retsize(pfn);
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

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
//                      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_ARC,               // id
                          // flag
    PR_USE32              // 32-bit processor
  | PR_DEFSEG32           // create 32-bit segments by default
  | PRN_HEX               // Values are hexadecimal by default
  | PR_TYPEINFO           // Support the type system notifications
  | PR_CNDINSNS           // Has conditional instructions
  | PR_DELAYED            // Has delay slots
  | PR_USE_ARG_TYPES      // use ph.use_arg_types callback
  | PR_RNAMESOK           // register names can be reused for location names
  | PR_SEGS               // has segment registers
  | PR_SGROTHER,          // the segment registers don't contain the segment selectors.
                          // flag2
  PR2_IDP_OPTS,           // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,                      // array of short processor names
  // the short names are used to specify the processor
  // with the -p command line switch)
  lnames,                       // array of long processor names
  // the long names are used to build the processor type
  // selection menu

  asms,                         // array of target assemblers

  notify,                       // the kernel event notification callback

  RegNames,                     // Register names
  qnumber(RegNames),            // Number of registers

  LDI_BASE,                     // first
  rVds,                         // last
  4,                            // size of a segment register
  rVcs, rVds,

  codestart_arcompact,          // code start sequences
  retcodes,

  0, ARC_last,
  Instructions,                 // instruc
  0,                            // size of tbyte
  {0},                          // real width
  0,                            // Icode of a return instruction
  nullptr,                         // Micro virtual machine description
};
