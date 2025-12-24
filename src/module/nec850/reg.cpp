/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor description structures
 *
 */
#include "necv850.hpp"
#include "notify_codes.hpp"
#include "ins.hpp"
#include <loader.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>

int data_id;

//-------------------------------------------------------------------------
void nec850_t::save_all_options()
{
  helper.altset(GP_EA_IDX, ea2node(g_gp_ea));
  helper.altset(CTBP_EA_IDX, ea2node(g_ctbp_ea));
  helper.altset(TP_EA_IDX, ea2node(g_tp_ea));
}

//-------------------------------------------------------------------------
// read all procmod data from the idb
void nec850_t::load_from_idb()
{
  g_gp_ea = node2ea(helper.altval(GP_EA_IDX));
  g_ctbp_ea = node2ea(helper.altval(CTBP_EA_IDX));
  g_tp_ea = node2ea(helper.altval(TP_EA_IDX));
}

//------------------------------------------------------------------
const char *nec850_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  ea_t new_gp_ea = g_gp_ea;
  ea_t new_ctbp_ea = g_ctbp_ea;
  ea_t new_tp_ea = g_tp_ea;
  if ( keyword != nullptr )
  {
    if ( streq(keyword, "GP_EA") )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      new_gp_ea = *((uval_t *)value);
      goto SAVE;
    }
    if ( streq(keyword, "CTBP_EA") )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      new_ctbp_ea = *((uval_t *)value);
      goto SAVE;
    }
    if ( streq(keyword, "TP_EA") )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      new_tp_ea = *((uval_t *)value);
      goto SAVE;
    }
    return IDPOPT_BADKEY;
  }

  static const char form[] =
    "NEC V850x analyzer options\n"
    "\n"
    " <~G~lobal Pointer address:$::18::>\n"
    " <CALLT ~B~ase pointer    :$::18::>\n"
    " <~T~ext Pointer address  :$::18::>\n"
    "\n"
    "\n"
    "\n";
  CASSERT(sizeof(new_gp_ea) == sizeof(ea_t));
  CASSERT(sizeof(new_ctbp_ea) == sizeof(ea_t));
  CASSERT(sizeof(new_tp_ea) == sizeof(ea_t));
  if ( ask_form(form, &new_gp_ea, &new_ctbp_ea, &new_tp_ea) == ASKBTN_YES )
  {
SAVE:
    set_canonical_sreg(new_gp_ea, g_gp_ea, srGP);
    set_canonical_sreg(new_ctbp_ea, g_ctbp_ea, srCTBP);
    set_canonical_sreg(new_tp_ea, g_tp_ea, srTP);
    if ( idb_loaded )
      save_all_options();
  }

  return IDPOPT_OK;
}

//----------------------------------------------------------------------
#define DEF_RELOC(name) COLSTR(name, SCOLOR_KEYWORD) \
                        COLSTR("(", SCOLOR_SYMBOL)   \
                        "%s"                         \
                        COLSTR(")", SCOLOR_SYMBOL)
static const char reloc_low[]   = DEF_RELOC("LOW");
static const char reloc_high[]  = DEF_RELOC("HIGH");
static const char reloc_loww[]  = DEF_RELOC("LOWW");
static const char reloc_highw[] = DEF_RELOC("HIGHW");
static const asm_t nec850_asm =
{
  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,  // flags
  0,                                // user flags
  "NEC V850 Assembler",             // assembler name
  0,                                // help
  nullptr,                          // array of automatically generated header lines
  ".org",                           // org directive
  ".end",                           // end directive
  "--",                             // comment string
  '"',                              // string delimiter
  '\'',                             // char delimiter
  "'\"",                            // special symbols in char and string constants
  ".str",                           // ascii string directive
  ".byte",                          // byte directive
  ".hword",                         // halfword (16 bits)   [IDA: word]
  ".word",                          // word (32 bits)       [IDA: dword]
  ".dword",                         // doubleword (64 bits) [IDA: qword]
  nullptr,                          // oword (16 bytes)
  ".float",                         // float (4-byte)
  ".double",                        // double (8-byte)
  nullptr,                          // no tbytes
  nullptr,                          // no packreal
  "#d dup(#v)",                     //".db.#s(b,w) #d,#v"
  ".byte (%s) ?",                   // uninited data (reserve space) ;?
  ".set",                           // 'equ' Used if AS_UNEQU is set
  nullptr,                          // seg prefix
  "PC",                             // a_curip
  nullptr,                          // returns function header line
  nullptr,                          // returns function footer line
  ".globl",                         // public
  nullptr,                          // weak
  ".extern",                        // extrn
  ".comm",                          // comm
  nullptr,                          // get_type_name
  ".align",                         // align
  '(',                              // lbrace
  ')',                              // rbrace
  nullptr,                          // mod
  "&",                              // bit-and
  "|",                              // or
  "^",                              // xor
  "!",                              // not
  "<<",                             // shl
  ">>",                             // shr
  nullptr,                          // sizeof
  0,                                // flags2
  nullptr,                          // cmnt2
  reloc_low,                        // low8 operation, should contain %s for the operand
  reloc_high,                       // high8
  reloc_loww,                       // low16
  reloc_highw,                      // high16
  ".include %s",                    // a_include_fmt
  nullptr,                          // if a named item is a structure and displayed
  nullptr                           // 'rva' keyword for image based offsets
};

static const asm_t *const asms[] = { &nec850_asm, nullptr };

//----------------------------------------------------------------------
#define FAMILY "NEC/Renesas 850 series:"

static const char *const shnames[] =
{
  "V850",
  "V850E",
  "V850E1",
  "V850E2M",
  "RH850",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"NEC V850",
  "NEC V850E",
  "NEC/Renesas V850E1/ES",
  "NEC/Renesas V850E2/E2M",
  "Renesas RH850",
  nullptr
};

//-------------------------------------------------------------------------
static void nec850_get_abi_info(qstrvec_t *names, qstrvec_t *opts)
{
  names->push_back("rh850-8byte_align");
  names->push_back("ghs");
  names->push_back("oldgcc-8byte_align");
  opts->push_back(
    "8byte_align:"
    "'double' and 'long long' types to be aligned on 8-byte boundaries"
    "#8-byte types alignment");
}

//--------------------------------------------------------------------------
ssize_t idaapi pm_idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    // all options are saved immediately after the change
    // case idb_event::savebase:

    case idb_event::segm_moved: // A segment is moved
                                // Fix processor dependent address sensitive information
      // {
      //   ea_t from           = va_arg(va, ea_t);
      //   ea_t to             = va_arg(va, ea_t);
      //   asize_t size        = va_arg(va, asize_t);
      //   bool changed_netmap = va_argi(va, bool);
      //   // adjust gp_ea
      // }
      break;

    case idb_event::func_added:
    case idb_event::func_deleted:
    case idb_event::set_func_start:
    case idb_event::set_func_end:
    case idb_event::func_tail_appended:
    case idb_event::func_tail_deleted:
    case idb_event::tail_owner_changed:
    case idb_event::frame_deleted:
      invalidate_regfinder_cache();
      break;

    case idb_event::compiler_changed:
      {
        bool adjust_inf_fields = va_argi(va, bool);
        pm.nec850_set_abi(adjust_inf_fields);
      }
      invalidate_regfinder_cache();
      break;

    default:
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(nec850_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi nec850_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      init_custom_refs();
      inf_set_be(false);
      reg_finder = alloc_reg_finder(*this);
      break;

    case processor_t::ev_term:
      term_custom_refs();
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      free_reg_finder(reg_finder);
      break;

    case processor_t::ev_newfile:
      nec850_set_abi(true);
      save_all_options();
      break;

    case processor_t::ev_newprc:
      {
        int procnum = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        ptype = procnum;
        break;
      }

    case processor_t::ev_ending_undo:
      // restore ptype
      ptype = ph.get_proc_index();
      invalidate_regfinder_cache();
      [[fallthrough]];
    case processor_t::ev_oldfile:
      nec850_set_abi(false);
      load_from_idb();
      break;

    case processor_t::ev_is_sane_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        code = nec850_is_sane_insn(insn, no_crefs) == 1 ? 1 : -1;
        break;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        code = nec850_may_be_func(insn);
      }
      break;

    case processor_t::ev_is_call_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return is_call_insn(*insn) ? 1 : -1;
      }

    case processor_t::ev_is_ret_insn:
      {
        const insn_t &insn = *va_arg(va, insn_t *);
        uchar flags = va_argi(va, uchar);
        bool strict = (flags & IRI_RET_LITERALLY) != 0;
        code = nec850_is_return(insn, strict) ? 1 : -1;
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec850_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec850_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        nec850_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        nec850_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return nec850_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return nec850_emu(*insn) ? 1 : -1;
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

    // case processor_t::ev_is_switch:
    // this proc module recognizes switch only in emu()

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = nec850_is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_analyze_prolog:
      {
        ea_t ea = va_arg(va, ea_t);
        func_t *pfn = get_func(ea);
        if ( pfn != nullptr )
          create_func_frame(pfn, true);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        // const func_t *pfn = va_arg(va, const func_t *);
        // NEC850 doesn't use stack for function return addresses
        *frsize = 0;
        return 1;
      }

    case processor_t::ev_lower_func_type:
      {
        intvec_t *argnums = va_arg(va, intvec_t *);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        nec850_lower_func_arg_types(argnums, *fti);
        return 1;
      }

    case processor_t::ev_calc_arglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_nec850_arglocs(fti, 0) ? 1 : -1;
      }

    case processor_t::ev_calc_varglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        /*regobjs_t *regargs =*/ va_arg(va, regobjs_t *);
        /*relobj_t *stkargs =*/ va_arg(va, relobj_t *);
        int nfixed = va_arg(va, int);
        return calc_nec850_arglocs(fti, nfixed) ? 1 : -1;
      }

    case processor_t::ev_calc_retloc:
      {
        argloc_t *retloc = va_arg(va, argloc_t *);
        const tinfo_t *type = va_arg(va, const tinfo_t *);
        callcnv_t cc        = va_arg(va, callcnv_t);
        return calc_nec850_retloc(retloc, *type, cc) ? 1 : -1;
      }

    case processor_t::ev_use_arg_types:
      {
        ea_t ea               = va_arg(va, ea_t);
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        funcargvec_t *rargs   = va_arg(va, funcargvec_t *);
        use_nec850_arg_types(ea, fti, rargs);
        return 1;
      }

    case processor_t::ev_use_regarg_type:
      {
        int *used                 = va_arg(va, int *);
        ea_t ea                   = va_arg(va, ea_t);
        const funcargvec_t *rargs = va_arg(va, const funcargvec_t *);
        *used = use_nec850_regarg_type(ea, *rargs);
        return 1;
      }

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        callcnv_t cc = va_arg(va, callcnv_t);
        if ( !get_nec850_cc_regs(callregs, cc) )
          break;
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

    case processor_t::ev_get_abi_info:
      {
        qstrvec_t *names = va_arg(va, qstrvec_t *);
        qstrvec_t *opts  = va_arg(va, qstrvec_t *);
        // comp_t comp = va_argi(va, comp_t);
        nec850_get_abi_info(names, opts);
      }
      return 1;

    case processor_t::ev_add_cref:  // A code reference is being created.
      {
        ea_t from = va_arg(va, ea_t);
        ea_t to = va_arg(va, ea_t);
        cref_t ft = va_argi(va, cref_t);
        invalidate_regfinder_cache(to, from, ft);
        break;
      }
    case processor_t::ev_del_cref:  // A code reference is being deleted.
      {
        ea_t from = va_arg(va, ea_t);
        ea_t to = va_arg(va, ea_t);
        invalidate_regfinder_cache(to, from);
        break;
      }

    case processor_t::ev_get_regfinder:
      return reinterpret_cast<ssize_t>(reg_finder);

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
          { helper, atag|NETMAP_VAL|NETMAP_VAL_NDX, GP_EA_IDX },
          { helper, atag|NETMAP_VAL|NETMAP_VAL_NDX, CTBP_EA_IDX },
          { helper, atag|NETMAP_VAL|NETMAP_VAL_NDX, TP_EA_IDX },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif

    // START OF DEBUGGER CALLBACKS
    case processor_t::ev_next_exec_insn:
      {
        ea_t *target              = va_arg(va, ea_t *);
        ea_t ea                   = va_arg(va, ea_t);
        int tid                   = va_arg(va, int);
        getreg_t *getreg          = va_arg(va, getreg_t *);
        const regval_t *regvalues = va_arg(va, const regval_t *);
        qnotused(tid);
        *target = nec850_next_exec_insn(ea, getreg, regvalues);
        return 1;
      }

    case processor_t::ev_calc_step_over:
      {
        ea_t *target = va_arg(va, ea_t *);
        ea_t ip      = va_arg(va, ea_t);
        *target = nec850_calc_step_over(ip);
        return 1;
      }

    case processor_t::ev_get_idd_opinfo:
      {
        idd_opinfo_t *opinf       = va_arg(va, idd_opinfo_t *);
        ea_t ea                   = va_arg(va, ea_t);
        int n                     = va_arg(va, int);
        int thread_id             = va_arg(va, int);
        getreg_t *getreg          = va_arg(va, getreg_t *);
        const regval_t *regvalues = va_arg(va, const regval_t *);
        qnotused(thread_id);
        return nec850_get_operand_info(opinf, ea, n, getreg, regvalues) ? 1 : 0;
      }

    case processor_t::ev_get_reg_info:
      {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange      = va_arg(va, bitrange_t *);
        const char *regname       = va_arg(va, const char *);
        return nec850_get_reg_info(main_regname, bitrange, regname) ? 1 : -1;
      }
    // END OF DEBUGGER CALLBACKS

    case nec850_module_t::ev_get_gp_register:
      {
        // TODO add a new GP_REGISTER option.
        // it can be: "fixed", "callee-saved", "free".
        // when the GP_EA option is set this option should be "fixed".
        // this option can be set automatically for ELF binaries using
        // EF_RH850_GP_*FIX bits and '.sda*' sections.
        return g_gp_ea != BADADDR
             ? nec850_module_t::FIXED
             : nec850_module_t::FREE;
      }

    case nec850_module_t::ev_get_gp_ea:
      {
        ea_t *gpval = va_arg(va, ea_t *);
        ea_t ea = va_arg(va, ea_t);
        *gpval = get_sreg(ea, srGP);
        return 1;
      }

    case nec850_module_t::ev_get_tp_register:
      {
        // TODO add a new TP option.
        // it can be: "fixed", "callee-saved", "free".
        // when the TP_EA option is set this option should be "fixed".
        // this option can be set automatically for ELF binaries using
        // EF_RH850_TP_*FIX bits and '.rosda*' sections.
        return g_tp_ea != BADADDR
             ? nec850_module_t::FIXED
             : nec850_module_t::FREE;
      }

    case nec850_module_t::ev_get_tp_ea:
      {
        ea_t *tpval = va_arg(va, ea_t *);
        ea_t ea = va_arg(va, ea_t);
        *tpval = get_sreg(ea, srTP);
        return 1;
      }

    case nec850_module_t::ev_get_ep_register:
      {
        // TODO add a new EP option.
        // it can be: "fixed", "callee-saved", "free".
        // when the EP_EA option is set this option should be "fixed".
        // this option can be set automatically for ELF binaries using
        // EF_RH850_EP_*FIX bits and '.tda*' sections.
        return nec850_module_t::FREE;
      }

    case nec850_module_t::ev_get_ep_ea:
      {
        // TODO add a new EP_EA option and new srEP segment register.
        ea_t *epval = va_arg(va, ea_t *);
        // ea_t ea = va_arg(va, ea_t);
        *epval = BADADDR; // TODO get_sreg(ea, srEP);
        return 1;
      }

    case nec850_module_t::ev_restore_pushinfo:
      {
        pushinfo_t *pi = va_arg(va, pushinfo_t *);
        ea_t func_ea = va_arg(va, ea_t);
        if ( pi->restore_from_idb(*this, func_ea) )
          return 1;
      }
      break;

    case nec850_module_t::ev_save_pushinfo:
      {
        ea_t func_ea = va_arg(va, ea_t);
        const pushinfo_t *pi = va_arg(va, pushinfo_t *);
        pi->save_to_idb(*this, func_ea);
        return 1;
      }

    case nec850_module_t::ev_serialize_pushinfo:
      {
        bytevec_t *buf = va_arg(va, bytevec_t *);
        ea_t func_ea = va_arg(va, ea_t);
        const pushinfo_t *pi = va_arg(va, pushinfo_t *);
        // int flags = va_arg(va, int);
        pi->serialize(buf, func_ea);
        return 1;
      }

    case nec850_module_t::ev_deserialize_pushinfo:
      {
        pushinfo_t *pi = va_arg(va, pushinfo_t *);
        memory_deserializer_t *buf = va_arg(va, memory_deserializer_t *);
        ea_t func_ea = va_arg(va, ea_t);
        // int flags = va_arg(va, int);
        if ( pi->deserialize(buf, func_ea) )
          return 1;
        break;
      }

    case nec850_module_t::ev_is_special_func_call:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return v850_is_special_func_call(nullptr, *insn);
      }

    default:
      break;
  }
  return code;
}

//-------------------------------------------------------------------------
void nec850_t::nec850_set_abi(bool init_inf_bits)
{
  qstring qbuf;
  get_abi_name(&qbuf);
  qstrvec_t opts;
  qbuf.split(&opts, "-", SSF_DROP_EMPTY);

  bool good_abi = true;
  if ( opts.empty() )
    good_abi = false;
  else if ( opts[0] == "rh850" || opts[0] == "ghs" )
    abi = ABI_RH850;
  else if ( opts[0] == "oldgcc" || opts[0] == "gcc" )
    abi = ABI_OLDGCC;
  else
    good_abi = false;
  if ( !good_abi )
  {
    if ( opts.empty() )
      msg("No ABI name\n");
    else
      msg("ABI name '%s' is unknown, ignored\n", opts[0].c_str());
    // set default ABI
    set_abi_name(is_rh850() ? "rh850" : "oldgcc");
    return;
  }
  // GHS compiler aligns to 8-byte
  // doc: "If the second argument requires 8-byte alignment and its offset
  // would not otherwise be a multiple of eight bytes, the second argument's
  // offset is increased by four bytes."
  abi_align8 = opts[0] == "ghs"
            || opts.size() > 1 && opts[1] == "8byte_align";
  if ( init_inf_bits )
  {
    inf_set_mem_aligned4(!abi_align8);
    // to guess a prototype in the decompiler
    // for such an ABI, only scalar types are aligned.
    // since the decompiler can only guess scalar types in the prototype,
    // this condition is automatically satisfied.
    // Old GCC aligns scalars to 8-byte
    // doc: "Alignment of parameters within the parameter list is the same
    // as their basic alignment."
    inf_set_big_arg_align(abi_align8 || abi == ABI_OLDGCC);
  }
}

//-----------------------------------------------------------------------
//      Registers Definition
//-----------------------------------------------------------------------
const char *const RegNames[rLastRegister] =
{
  "r0",
  "r1",
  "r2",
  "sp",
  "gp",
  "r5", // tp
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "r16",
  "r17",
  "r18",
  "r19",
  "r20",
  "r21",
  "r22",
  "r23",
  "r24",
  "r25",
  "r26",
  "r27",
  "r28",
  "r29",
  "ep",
  "lp",

  // system registers start here
  "eipc",
  "eipsw",
  "fepc",
  "fepsw",
  "ecr",
  "psw",
  "sr6",
  "sr7",
  "sr8",
  "sr9",
  "sr10",
  "sr11",
  "sr12",
  "sr13",
  "sr14",
  "sr15",
  "sr16",
  "sr17",
  "sr18",
  "sr19",
  "ctbp",
  "sr21",
  "sr22",
  "sr23",
  "sr24",
  "sr25",
  "sr26",
  "sr27",
  "sr28",
  "sr29",
  "sr30",
  "sr31",

  "vr0",
  "vr1",
  "vr2",
  "vr3",
  "vr4",
  "vr5",
  "vr6",
  "vr7",
  "vr8",
  "vr9",
  "vr10",
  "vr11",
  "vr12",
  "vr13",
  "vr14",
  "vr15",
  "vr16",
  "vr17",
  "vr18",
  "vr19",
  "vr20",
  "vr21",
  "vr22",
  "vr23",
  "vr24",
  "vr25",
  "vr26",
  "vr27",
  "vr28",
  "vr29",
  "vr30",
  "vr31",

  "wr0",
  "wr1",
  "wr2",
  "wr3",
  "wr4",
  "wr5",
  "wr6",
  "wr7",
  "wr8",
  "wr9",
  "wr10",
  "wr11",
  "wr12",
  "wr13",
  "wr14",
  "wr15",
  "wr16",
  "wr17",
  "wr18",
  "wr19",
  "wr20",
  "wr21",
  "wr22",
  "wr23",
  "wr24",
  "wr25",
  "wr26",
  "wr27",
  "wr28",
  "wr29",
  "wr30",
  "wr31",

  "EFG", "ECT",

  "cs", "ds", "gp", "tp", "callt",
};
CASSERT(qnumber(RegNames) == rLastRegister);

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_NEC_V850X,         // id
                          // flag
    PR_USE32              // supports 32-bit addressing
  | PR_DEFSEG32           // create 32-bit segments by default
  | PRN_HEX               // values are hexadecimal by default
  | PR_SEGS               // has segment registers
  | PR_TYPEINFO           // support the tinfo_t object (type system)
  | PR_USE_ARG_TYPES      // use ph.use_arg_types callback
  | PR_RNAMESOK,          // register names can be reused for location names
                          // flag2
    PR2_IDP_OPTS | PR2_MACRO,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,                // short processor names
  lnames,                 // long processor names

  asms,                   // assemblers

  notify,

  RegNames,               // Regsiter names
  rLastRegister,          // Number of registers

  rVcs,                   // number of first segment register
  srCTBP,                // number of last segment register
  0 /*4*/,                // size of a segment register
  rVcs,
  rVds,
  nullptr,                // No known code start sequences
  nullptr,                // Array of 'return' instruction opcodes
  NEC850_NULL,
  NEC850_LAST_INSTRUCTION,
  Instructions,
  0,                      // size of tbyte
  {0, 7, 15, 0},          // real width
  0,                      // icode_return
  nullptr,                // Micro virtual machine description
};
