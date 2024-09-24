/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "java.hpp"
#include <diskio.hpp>
#include <ieee.h>
#include "npooluti.hpp"
#include "notify_codes.hpp"
int data_id;

//-----------------------------------------------------------------------
#ifdef __debug__
NORETURN void _destroyed(const char *from)
{
  error("Database is corrupted! [at: %s]", from);
}

//-----------------------------------------------------------------------
NORETURN void _faterr(uchar mode, const char *from)
{
  error("Internal error (%s) [at: %s]",
        mode ? "compatibility" : "idp",
        from);
}
#else
//-----------------------------------------------------------------------
NORETURN void _destroyed(void)
{
  error("Database is corrupted!");
}

//-----------------------------------------------------------------------
NORETURN void _faterr(uchar mode)
{
  error("Internal error (%s)", mode ? "compatibility" : "idp");
}
#endif

//-----------------------------------------------------------------------
void java_t::sm_validate(const SegInfo *si)
{
  ea_t segTopEA = si->start_ea + si->CodeSize;
  netnode temp(si->smNode);
  nodeidx_t nid = temp.supfirst();

  if ( (ea_t)nid < si->start_ea )
    goto destroyed;

  do
  {
    if ( (ea_t)nid >= segTopEA )
      goto destroyed;
    if ( temp.supval(nid, nullptr, 0) != sizeof(sm_info_t) )
      goto destroyed;
    if ( !is_head(get_flags((ea_t)nid)) )
    {
      remember_problem(PR_HEAD, (ea_t)nid);
      if ( !displayed_nl )
      {
        displayed_nl = true;
        msg("\n");
      }
      msg("StackMap refers to nonHead offset %X in Method#%u\n",
          (uint32)((ea_t)nid - si->start_ea), si->id.Number);
    }
    nid = temp.supnext(nid);
  }
  while ( nid != BADNODE );
  return;

destroyed:
  DESTROYED("sm_validate");
}

//----------------------------------------------------------------------
// visble for upgrade ONLY
void java_t::coagulate_unused_data(const SegInfo *ps)
{
  uint size = 0;
  ea_t ea = ps->DataBase;
  ea_t top = ea + ps->DataSize;
  for ( ; ea < top; ea++ )
  {
    if ( is_head(get_flags(ea))
      && get_first_dref_to(ea) == BADADDR )
    {
      ConstantNode.chardel(ea, UR_TAG);  // unicode renaming support
      del_global_name(ea);
      del_items(ea, DELIT_SIMPLE);
      ++size;
      ea_t to;
      while ( (to=get_first_dref_from(ea)) != BADADDR )
        del_dref(ea, to);
    }
    else if ( size )
    {
      create_data(ea-size, align_flag(), size, BADNODE);
      size = 0;
    }
  }
  if ( size )
    create_data(ea-size, align_flag(), size, BADNODE);
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
static int idaapi out_asm_file(
        FILE *fp,
        const qstring &line,
        bgcolor_t,
        bgcolor_t)
{
  qstring qbuf;
  tag_remove(&qbuf, line);
  size_t len = qbuf.length();
  size_t chk = len;

  if ( qbuf.last() == '\\' )
    --len;
  if ( qfwrite(fp, qbuf.c_str(), len) != len )
    return 0;
  if ( chk == len && qfputc('\n', fp) == EOF )
    return 0;
  return 1;
}

//----------------------------------------------------------------------
static void idaapi func_header(outctx_t &ctx, func_t *) { ctx.ctxflags |= CTXF_LABEL_OK; }
static void idaapi func_footer(outctx_t &, func_t *) {}
static bool idaapi java_specseg(outctx_t &ctx, uchar)    { java_data(ctx, false); return false; }

//----------------------------------------------------------------------
//  floating point conversion
fpvalue_error_t j_realcvt(void *m, fpvalue_t *e, ushort swt)
{
  return ieee_realcvt(m, e, swt | 0x80);
}

//----------------------------------------------------------------------
// Set IDP options. Either from the configuration file either allow the user
// to specify them in a dialog box.
const char *java_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded)
{
  static const char form[] =
    "HELP\n"
    "JAVA specific options\n"
    "\n"
    " Multiline .debug\n"
    "\n"
    "       If this option is on, IDA forces new .debug directive at every\n"
    "       LR ('\\n') in the input string\n"
    "\n"
    " Hide StackMap(s)\n"
    "\n"
    "       If this option is on, IDA hides .stack verification declarations\n"
    "\n"
    " Auto strings\n"
    "\n"
    "       If this option is on, IDA makes 'prompt-string' after every CR in\n"
    "       the quoted-string operand\n"
    "\n"
    " Save to jasmin\n"
    "\n"
    "      If this option is on, IDA creates asm-file in the jasmin-\n"
    "      compatibe form: concatenates 'prompted' string, reserved names\n"
    "      will be enclosed in quotes.\n"
    "      Also when this option is on IDA changes unicode-to-oem encoding to\n"
    "      unicode-to-ansi encoding because jasmin expects ansi encoding.\n"
    "\n"
    " Enable encoding\n"
    "\n"
    "       If this option is on, IDA converts unicode characters which\n"
    "       can't be represented in current locale to ascii characters.\n"
    "\n"
    " Nopath .attribute\n"
    "      If this option is on, IDA prints filename in '.attribute'\n"
    "      directives without the path part.\n"
    "\n"
    "\n"
    " Bad index as string\n"
    "      If this option is on, IDA will show invalid name/type references\n"
    "      as a quoted string.\n"
    "ENDHELP\n"
    "JAVA specific options\n"
    "\n"
    " <~M~ultilne .debug   :C>\n"
    " <~H~ide StackMap(s)  :C>\n"
    " <~A~uto strings      :C>\n"
    " <~S~ave to jasmin    :C>\n"
    " <~E~nable encoding   :C>\n"
    " <~N~opath .attribute :C>>\n"
    "\n"
    " <~B~ad index as string :C>>\n"
    "\n"
    "\n";

  if ( !keyword )
  {
    ushort tmp = (idpflags >> 16) & IDM__REQMASK;
    ushort flags = idpflags;
    if ( ask_form(form, &flags, &tmp) )
    {
      int32 old = idpflags;
      idpflags = (flags & ~(IDM__REQMASK << 16)) | (tmp << 16);
      if ( (idpflags ^ old) & IDF_ENCODING )
        rename_uninames(-1);
    }
    goto SAVE;
  }

  if ( value_type != IDPOPT_BIT )
    return IDPOPT_BADTYPE;

  struct keyword_info_t
  {
    const char *name;
    int bit;
  };
  static const keyword_info_t keywords[] =
  {
    { "JAVA_MULTILINE_DEBUG",  IDF_MULTDEB  },
    { "JAVA_HIDE_STACKMAP",    IDF_HIDESM   },
    { "JAVA_AUTO_STRING",      IDF_AUTOSTR  },
    { "JAVA_ASMFILE_CONVERT",  IDF_CONVERT  },
    { "JAVA_ENABLE_ENCODING",  IDF_ENCODING },
    { "JAVA_NOPATH_ATTRIBUTE", IDF_NOPATH   },
    { "JAVA_UNKATTR_REQUEST",  IDM_REQUNK   },
    { "JAVA_UNKATTR_WARNING",  IDM_WARNUNK  },
  };

  for ( int i=0; i < qnumber(keywords); i++ )
  {
    if ( strcmp(keywords[i].name, keyword) == 0 )
    {
      setflag(idpflags, keywords[i].bit, *(int*)value != 0);
      goto SAVE;
    }
  }

  if ( streq(keyword, "JAVA_STARTASM_LIST") )
  {
    start_asm_list = *(int*)value;
    return IDPOPT_OK;
  }
  else
  {
    return IDPOPT_BADKEY;
  }
SAVE:
  if ( idb_loaded )
    ConstantNode.altset(CNA_IDPFLAGS, (ushort)idpflags);
  return IDPOPT_OK;

}

//----------------------------------------------------------------------
static const asm_t jasmin_asm =
{
  AS_COLON | ASH_HEXF3 | ASO_OCTF1 | ASD_DECF0 | AS_ONEDUP | ASB_BINF3,
  UAS_JASMIN,
  "Jasmin assembler",
  0,        // no help screen
  nullptr,     // header
  nullptr,     // origin
  nullptr,     // end of file

  ";",      // comment string
  '"',      // string delimiter
  '\'',     // char delimiter
  "\"'\\",  // special symbols in char and string constants

  "",         // ascii string directive
  "",         // byte directive
  nullptr,       // word directive
  nullptr,       // double words
  nullptr,       // qwords
  nullptr,       // oword  (16 bytes)
  nullptr,       // float
  nullptr,       // double
  nullptr,       // no tbytes
  nullptr,       // no packreal
  nullptr,     // arrays:
            // #h - header(.byte,.word)
            // #d - size of array
            // #v - value of array elements
  nullptr,         //".reserv  %s",  // uninited data (reserve space)
  " = ",        // equ
  nullptr,         // seg prefix
  nullptr,         // a_curip
  func_header,  // func header
  func_footer,  // func footer
  "",     // public (disable ouput)
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  nullptr,    // sizeof
  0,       // flag2
  nullptr,    // cmnt2
  nullptr,    // low8
  nullptr,    // high8
  nullptr,    // low16
  nullptr,    // high16
  nullptr,    // a_include_fmt
  nullptr,    // a_vstruc_fmt
  nullptr,    // a_rva
};

//----------------------------------------------------------------------
static const asm_t list_asm =
{
  AS_COLON | ASH_HEXF3 | ASO_OCTF1 | ASD_DECF0 | AS_ONEDUP | ASB_BINF3,
  0,
  "User friendly listing",
  0,        // no help screen
  nullptr,     // header
  nullptr,     // origin
  nullptr,     // end of file

  "//",     // comment string
  '"',      // string delimiter
  '\'',     // char delimiter
  "\"'\\",  // special symbols in char and string constants

  "",         // ascii string directive
  "",         // byte directive
  nullptr,       // word directive
  nullptr,       // double words
  nullptr,       // qwords
  nullptr,       // oword  (16 bytes)
  nullptr,       // float
  nullptr,       // double
  nullptr,       // no tbytes
  nullptr,       // no packreal
  nullptr,     // arrays:
            // #h - header(.byte,.word)
            // #d - size of array
            // #v - value of array elements
  nullptr,         //".reserv  %s",  // uninited data (reserve space)
  " = ",        // equ
  nullptr,         // seg prefix
  nullptr,         // a_curip
  func_header,  // func header
  func_footer,  // func footer
  "",     // public (disable ouput)
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  nullptr,    // sizeof
  0,       // flag2
  nullptr,    // cmnt2
  nullptr,    // low8
  nullptr,    // high8
  nullptr,    // low16
  nullptr,    // high16
  nullptr,    // a_include_fmt
  nullptr,    // a_vstruc_fmt
  nullptr,    // a_rva
};

//-----------------------------------------------------------------------
static const asm_t *const asms[] = { &jasmin_asm, &list_asm, nullptr };

static const char *const RegNames[] = { "vars", "optop", "frame", "cs", "ds" };

#define FAMILY "Java Virtual Machine:"

static const char *const shnames[] =
{
  "java",
#ifdef __debug__
  "_javaPC",
#endif
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Java",
#ifdef __debug__
  "Java full (IBM PC, debug mode)",
#endif
  nullptr
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { j_ret };
static const uchar retcode_1[] = { j_ireturn };
static const uchar retcode_2[] = { j_lreturn };
static const uchar retcode_3[] = { j_freturn };
static const uchar retcode_4[] = { j_dreturn };
static const uchar retcode_5[] = { j_areturn };
static const uchar retcode_6[] = { j_return  };
static const uchar retcode_7[] = { j_wide, j_ret };

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
  { 0, nullptr }
};

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
  switch ( code )
  {
    case idb_event::closebase:
      memset(&pm.curClass, 0, sizeof(pm.curClass));
      // no break
    case idb_event::savebase:
      pm.ConstantNode.altset(CNA_IDPFLAGS, (ushort)pm.idpflags);
      break;

    case idb_event::auto_empty:
      if ( !(pm.curClass.extflg & XFL_C_DONE) ) // kernel BUGs
      {
        pm.curClass.extflg |= XFL_C_DONE;
        msg("JavaLoader finalization stage...");
        for ( int n = pm.curClass.MethodCnt; n; n-- )
        {
          SegInfo si;
          if ( pm.ClassNode.supval(-n, &si, sizeof(si)) != sizeof(si) )
            DESTROYED("postprocess");
          if ( si.smNode || si.DataSize )
          {
            show_addr(si.start_ea);
            if ( si.smNode )
              pm.sm_validate(&si);
            if ( si.DataSize )
              pm.coagulate_unused_data(&si);
          }
        }
        pm.ConstantNode.supset(CNS_CLASS, &pm.curClass, sizeof(pm.curClass));  // all chgs
        pm.sm_node = smn_ok;
        msg("OK\n");
      }
      break;
  }
  return 0;
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(java_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi java_t::on_event(ssize_t msgid, va_list va)
{
  int retcode = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      inf_set_be(true);       // reverse byte!
      break;

    case processor_t::ev_rename:
      va_arg(va, ea_t);
      for ( char const *pn, *p = va_arg(va, const char *);
            (pn = strchr(p, '\\')) != nullptr;
            p = pn+1 )
      {
        if ( *++pn != 'u' )
        {
inv_name:
          --retcode;  // 0
          warning("Backslash is accepted only as a unicode escape sequence in names");
          break;
        }
        for ( int i = 0; i < 4; i++ )
          if ( !qisxdigit((uchar)*++pn) )
            goto inv_name;
      }
      break;

    case processor_t::ev_newfile:
      if ( inf_get_filetype() != f_LOADER )
      {
        set_database_flag(DBFL_KILL);    // clean up the database files
        error("The input file does not have a supported Java file format");
      }
      database_loaded (va_arg(va, char *));
      inf_set_lowoff(BADADDR);
      inf_set_highoff(BADADDR);
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      database_loaded(nullptr);
      break;

    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      qfree(tsPtr);
      qfree(smBuf);
      qfree(annBuf);
      clr_module_data(data_id);
      break;

#ifdef __debug__
    case processor_t::ev_newprc:
      {
        int procnum = va_arg(va, int);
        bool keep_cfg = va_argi(va, bool);
        if ( procnum == 1 )     // debug mode
        {
          ph.flag &= ~(PR_DEFNUM | PR_NOCHANGE);
          ph.flag |= PRN_HEX;
          if ( inf_get_margin() == 77 && !inf.bin_prefix_size && !inf.show_line_pref() )
          {
            if ( !keep_cfg )
              inf_set_show_line_pref(true);
            --debugmode;
          }
          else
          {
            ++debugmode;
          }
        }
        else                            // normal node
        {
          ph.flag &= ~PR_DEFNUM;
          ph.flag |= PRN_DEC;
          if ( debugmode == -1
            && inf.show_line_pref()
            && !inf.bin_prefix_size
            && inf_get_margin() == 77
            && !keep_cfg )
          {
            inf.show_line_pref(false);
          }
          debugmode = 0;
        }
      }
      break;
#endif

    case java_module_t::ev_load_file:
      {
        linput_t *li = va_arg(va, linput_t *);
        FILE *f = qlfile(li);
        QASSERT(10082, f != nullptr);
        bool manual = va_argi(va, bool);
        loader(f, manual);
        retcode = 0;
      }
      if ( start_asm_list )
        set_target_assembler(1);
      break;

    case processor_t::ev_gen_src_file_lnnum:
      if ( jasmin() )
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        va_arg(va, const char *); // skip file name
        size_t lineno = va_arg(va, size_t);
        ctx->gen_printf(2, COLSTR(".line %" FMT_Z, SCOLOR_ASMDIR), lineno);
        retcode = 1;
      }
      break;

    case processor_t::ev_gen_asm_or_lst:
      {
        if ( va_argi(va, bool) )          // starting (else end of generation )
        {
          va_arg(va, FILE *);             // output file (skip)
          bool isasm = va_argi(va, bool); // assembler-true, listing-false
          if ( isasm && (idpflags & IDF_CONVERT) )
          {
            va_arg(va, int);              // flags of gen_file() (skip)
            *va_arg(va, gen_outline_t**) = out_asm_file;
            idpflags |= IDM_OUTASM;
          }
          if ( isasm == jasmin() )
            break;    // need change mode?
        }
        else                              // end of generation.
        {
          idpflags &= ~IDM_OUTASM;
          if ( !mode_changed )
            break;        // mode changed?
        }
        mode_changed = !mode_changed;
        set_target_assembler(!inf_get_asmtype());
      }
      break;

    case processor_t::ev_get_autocmt:
      {
        qstring *buf = va_arg(va, qstring *);
        const insn_t *insn = va_arg(va, insn_t *);
        if ( make_locvar_cmt(buf, *insn) )
          retcode = 1;
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
        java_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        java_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        java_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        java_segend(*ctx, seg);
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

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        java_data(*ctx, analyze_only);
        return 1;
      }

    case processor_t::ev_can_have_type:
      {
        const op_t *op = va_arg(va, const op_t *);
        return can_have_type(*op) ? 1 : -1;
      }

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        fpvalue_t *e = va_arg(va, fpvalue_t *);
        uint16 swt = va_argi(va, uint16);
        return j_realcvt(m, e, swt);
      }

    case processor_t::ev_gen_map_file:
      {
        int *nlines = va_arg(va, int *);
        FILE *fp = va_arg(va, FILE *);
        int code = gen_map_file(fp);
        if ( code == -1 )
          return -1;
        *nlines = code;
        return 1;
      }

    case processor_t::ev_extract_address:
      {
        ea_t *out_ea = va_arg(va, ea_t *);
        ea_t screen_ea = va_arg(va, ea_t);
        const char *str = va_arg(va, const char *);
        size_t pos = va_arg(va, size_t);
        ea_t ea = get_ref_addr(screen_ea, str, pos);
        if ( ea == BADADDR )
          return -1;
        if ( ea == (BADADDR-1) )
          return 0;
        *out_ea = ea;
        return 1;
      }

    case processor_t::ev_out_special_item:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        uchar seg_type = va_argi(va, uchar);
        java_specseg(*ctx, seg_type);
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

    case processor_t::ev_privrange_changed:
      {
        va_arg(va, range_t *);
        va_arg(va, adiff_t);
        qstring *errmsg = va_arg(va, qstring *);
        if ( errmsg != nullptr )
          *errmsg = "moving of 'private netnode range' is not supported";
        return -1;
      }

    default:
      break;
  }
  return retcode;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_JAVA,              // id
                          // flag
    PRN_DEC
  | PR_RNAMESOK
  | PR_NO_SEGMOVE,
                          // flag2
  PR2_IDP_OPTS,           // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,           // Regsiter names
  qnumber(RegNames),  // Number of registers

  rVcs,rVds,
  0,                  // size of a segment register
  rVcs,rVds,

  nullptr,               // No known code start sequences
  retcodes,

  0,j_last,
  Instructions,       // instruc
  0,                  // size of tbyte
  {0,7,15,0},         // real width
  j_ret,              // icode_return
  nullptr,               // Micro virtual machine description
};
