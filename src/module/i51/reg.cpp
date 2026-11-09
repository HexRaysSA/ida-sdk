/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:50620/209
 *
 */

#include "i51.hpp"
#include <entry.hpp>
#include <segregs.hpp>
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "A", "AB", "B",
  "R0", "R1", "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
  "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
  "WR0",  "WR2",  "WR4",  "WR6",  "WR8",  "WR10", "WR12", "WR14",
  "WR16", "WR18", "WR20", "WR22", "WR24", "WR26", "WR28", "WR30",
  "DR0",  "DR4",  "DR8",  "DR12", "DR16", "DR20", "DR24", "DR28",
  "DR32", "DR36", "DR40", "DR44", "DR48", "DR52", "DPX",  "SPX",
  "DPTR","C", "PC",
  "EPTR", "PR0", "PR1",
  "cs","ds"
};

//----------------------------------------------------------------------
static const char cfgname[] = "i51.cfg";

void i51_iohandler_t::get_cfg_filename(char *buf, size_t bufsize)
{
  qstrncpy(buf, cfgname, bufsize);
}

bool i51_iohandler_t::check_ioresp() const
{
  return true;
}

void i51_iohandler_t::apply_io_port(ea_t ea, const char *name, const char *cmt)
{
  if ( ea >= 0x80 && ea < 0x100 )
  {
    // special mapping alg for i51 FSR regs
    segment_t *s = get_segm_by_name("FSR");
    if ( s != nullptr )
    {
      ea_t map = ea + s->start_ea - 0x80;
      if ( is_mapped(map) )
        ea = map;
    }
  }
  set_name(ea, name, SN_NODUMMY);
  set_cmt(ea, cmt, true);
}

bool i51_iohandler_t::segment_created(ea_t start, ea_t end, const char *word, const char *)
{
  // if segment already exists then don't create it
  segment_t *s = get_segm_by_name(word);
  if ( s != nullptr )
    return true;
  if ( stristr(word, "FSR") != nullptr || stristr(word, "RAM") != nullptr )
  {
    pm.AdditionalSegment(end-start, start, word);
    return true;
  }
  // create segment externally
  return false;
}

//------------------------------------------------------------------
const char *i51_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  iohandler_t::parse_area_line0_t cb(ioh);
  if ( choose_ioport_device2(&ioh.device, cfgname, &cb) )
  {
    int lrespect_info = IORESP_PORT | IORESP_INT;
    if ( ioh.display_infotype_dialog(lrespect_info, &lrespect_info, cfgname) )
    {
      ioh.set_device_name(ioh.device.c_str(), lrespect_info & ~IORESP_AREA);
    }
  }
  return IDPOPT_OK;
}

//------------------------------------------------------------------
const ioport_bit_t *i51_t::find_bit(ea_t address, int bit)
{
  return find_ioport_bit(ioh.ports, address, bit);
}

//----------------------------------------------------------------------
bool i51_t::IsPredefined(const char *name)
{
  for ( int i=0; i < ioh.ports.size(); i++ )
  {
    const ioport_t &p = ioh.ports[i];
    if ( p.name == name )
      return true;
    for ( int j=0; j < p.bits.size(); j++ )
      if ( p.bits[j].name == name )
        return true;
  }
  return false;
}

//----------------------------------------------------------------------
// Get linear address of a special segment
//      sel - selector of the segment
static ea_t specialSeg(segment_t *s)
{
  if ( s->type != SEG_IMEM )          // is the segment type correct? - no
  {
    s->type = SEG_IMEM;               // fix it
    s->update();
  }
  return s->start_ea;
}

//----------------------------------------------------------------------
ea_t i51_t::AdditionalSegment(size_t size, size_t offset, const char *name) const
{
  segment_t s;
  s.start_ea = (ptype > prc_51)
                   ? (inf_get_max_ea() + 0xF) & ~0xF
                   : find_free_chunk(0, size, 0xF);
  s.end_ea  = s.start_ea + size;
  s.sel     = allocate_selector((s.start_ea-offset) >> 4);
  s.type    = SEG_IMEM;                         // internal memory
  add_segm_ex(&s, name, nullptr, ADDSEG_NOSREG|ADDSEG_OR_DIE);
  return s.start_ea - offset;
}

//----------------------------------------------------------------------
void i51_t::setup_data_segment_pointers(void)
{
  segment_t *s = get_segm_by_name("INTMEM");
  if ( s == nullptr )
    s = get_segm_by_name("RAM");
  if ( s != nullptr )
    intmem = specialSeg(s);

  s = get_segm_by_name("SFR");
  if ( s == nullptr )
    s = get_segm_by_name("FSR");
  if ( s != nullptr )
    sfrmem = specialSeg(s) - 0x80;
}

//--------------------------------------------------------------------------
void i51_t::load_from_idb()
{
  ioh.restore_device();
  // restore ptype
  ptype = processor_subtype_t(ph.get_proc_index());
  setup_data_segment_pointers();
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
  switch ( code )
  {
    case idb_event::segm_moved: // A segment is moved
                                // Fix processor dependent address sensitive information
      {
        // ea_t from    = va_arg(va, ea_t);
        // ea_t to      = va_arg(va, ea_t);
        // asize_t size = va_arg(va, asize_t);
        // bool changed_netmap = va_argi(va, bool);

        // Add commands to adjust your internal variables here
        // Most of the time this callback will be empty
        //
        // If you keep information in a netnode's altval array, you can use
        //      node.altshift(from, s->start_ea, s->end_ea - s->start_ea);
        //
        // If you have a variables pointing to somewhere in the disassembled program memory,
        // you can adjust it like this:
        //
        //      if ( var >= from && var < from+size )
        //        var += to - from;
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
    return size_t(SET_MODULE_DATA(i51_t));
  return 0;
}

ssize_t idaapi i51_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true);       // Set a big endian mode of the IDA kernel
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      {
        segment_t *sptr = get_first_seg();
        if ( sptr != nullptr )
        {
          if ( sptr->start_ea-get_segm_base(sptr) == 0 )
          {
            inf_set_start_ea(sptr->start_ea);
            inf_set_start_ip(0);
          }
        }
        segment_t *scode = get_first_seg();
        set_segm_class(scode, "CODE");

        if ( ptype > prc_51 )
        {
          AdditionalSegment(0x10000-256-128, 256+128, "RAM");
          if ( scode != nullptr )
          {
            ea_t align = (scode->end_ea + 0xFFF) & ~0xFFF;
            if ( getseg(align-7) == scode )     // the code segment size is
            {                                   // multiple of 4K or near it
              uchar b0 = get_byte(align-8);
              // 251:
              //  0  : 1-source, 0-binary mode
              //  6,7: must be 1s
              // 82930:
              //  0  : 1-source, 0-binary mode
              //  7  : must be 1s
//              uchar b1 = get_byte(align-7);
              // 251
              //  0: eprommap 0 - FE2000..FE4000 is mapped into 00E000..100000
              //              1 - .............. is not mapped ...............
              //  1: must be 1
              //  3:
              //  2: must be 1
              //  4: intr 1 - upon interrupt PC,PSW are pushed into stack
              //          0 - upon interrupt only PC is pushed into stack
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
              // 82930:
              //  3: must be 1
              //  5: must be 1
              //  6: must be 1
              //  7: must be 1
//                msg("b0=%x b1=%x\n", b0, b1);
//              if ( (b0 & 0x80) == 0x80 && (b1 & 0xEA) == 0xEA )
              {                         // the init bits are correct
                char pname[IDAINFO_PROCNAME_SIZE];
                inf_get_procname(pname, sizeof(pname));
                char ntype = (b0 & 1) ? 's' : 'b';
                char *ptr = tail(pname)-1;
                if ( ntype != *ptr
                  && ask_yn(ASKBTN_YES,
                            "HIDECANCEL\n"
                            "The input file seems to be for the %s mode of the processor.\n"
                            "Do you want to change the current processor type?",
                            ntype == 's' ? "source" : "binary") > 0 )
                {
                  *ptr = ntype;
                  allow_proc_change = true;
                  set_processor_type(pname, SETPROC_USER);
                }
              }
            }
          }
          allow_proc_change = false;
        }

        // the default data segment will be INTMEM
        {
          segment_t *s = getseg(intmem);
          if ( s != nullptr )
            set_default_dataseg(s->sel);
        }

        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgname, &cb) )
        {
          int lrespect_info = IORESP_ALL;
          if ( ioh.display_infotype_dialog(lrespect_info, &lrespect_info, cfgname) )
          {
            ioh.set_device_name(ioh.device.c_str(), lrespect_info);
          }
        }
        else
        {
          ioh.device = NONEPROC;
        }

        if ( get_segm_by_name("RAM") == nullptr )
          AdditionalSegment(256, 0, "RAM");
        if ( get_segm_by_name("FSR") == nullptr )
          AdditionalSegment(128, 128, "FSR");
        setup_data_segment_pointers();
      }
      break;

    case processor_t::ev_oldfile:
      allow_proc_change = false;
      // no break
    case processor_t::ev_ending_undo:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:
        // make the default DS point to INTMEM
        // (8051 specific issue)
      {
        segment_t *newseg = va_arg(va, segment_t *);
        segment_t *intseg = getseg(intmem);
        if ( intseg != nullptr )
          newseg->defsr[rVds-ph.reg_first_sreg] = intseg->sel;
      }
      break;

    case processor_t::ev_newprc:
      {
        processor_subtype_t prcnum = processor_subtype_t(va_arg(va, int));
        // bool keep_cfg = va_argi(va, bool);
        if ( !allow_proc_change && prcnum != ptype )
        {
          warning("Sorry, it is not possible to change" // (this is 8051 specific)
                  " the processor mode on the fly."
                  " Please reload the input file"
                  " if you want to change the processor.");
          code = -1;
          break;
        }
        ptype = prcnum;
      }
      break;

    case processor_t::ev_newasm:    // new assembler type
      ioh.restore_device();
      break;

    case processor_t::ev_is_sane_insn:
                                // is the instruction sane for the current file type?
                                // arg:  int no_crefs
                                // 1:  the instruction has no code refs to it.
                                //     ida just tries to convert unexplored bytes
                                //     to an instruction (but there is no other
                                //     reason to convert them into an instruction)
                                // -1: the instruction is created because
                                //     of some coderef, user request or another
                                //     weighty reason.
                                // The instruction is in 'cmd'
                                // returns: 1-ok, <=0-no, the instruction isn't
                                // likely to appear in the program
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int reason = va_arg(va, int);
        return is_sane_insn(*insn, reason) == 1 ? 1 : -1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i51_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i51_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        i51_segstart(*ctx, seg);
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
        i51_data(*ctx, analyze_only);
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
//                   ASMI
//-----------------------------------------------------------------------
static const asm_t asmi =
{
  AS_COLON | ASH_HEXF3 | AS_1TEXT | AS_NCHRE | ASO_OCTF1 | AS_RELSUP,
  UAS_PSAM | UAS_NOSEG | UAS_AUBIT | UAS_PBIT | UAS_NOENS,
  "ASMI",
  0,
  nullptr,         // no headers
  ".equ $, ",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".byte 0xFF;(array %s)", // uninited arrays
  ".equ",       // equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  "%",    // mod
  "&",    // and
  "|",    // or
  "^",    // xor
  "!",    // not
  "<<",   // shl
  ">>",   // shr
  nullptr,   // sizeof
};

//-----------------------------------------------------------------------
//                   8051 Macro Assembler   -   Version 4.02a
//                Copyright (C) 1985 by 2500 A.D. Software, Inc.
//-----------------------------------------------------------------------
static const asm_t adasm =
{
  AS_COLON | ASH_HEXF0,
  UAS_PBIT | UAS_SECT,
  "8051 Macro Assembler by 2500 A.D. Software",
  0,
  nullptr,         // no headers
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "long",       // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "reg",        // equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,         // mod
  nullptr,         // and
  nullptr,         // or
  nullptr,         // xor
  nullptr,         // not
  nullptr,         // shl
  nullptr,         // shr
  nullptr,         // sizeof
  0,            // flag2
  nullptr,         // close comment
  COLSTR("<", SCOLOR_SYMBOL) "%s", // low8
  COLSTR(">", SCOLOR_SYMBOL) "%s", // high8
  nullptr,         // low16
  nullptr,         // high16
};

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *const ps_headers[] =
{
  ".code",
  nullptr
};

static const asm_t pseudosam =
{
  AS_COLON | ASH_HEXF1 | AS_N2CHR,
  UAS_PBIT | UAS_PSAM | UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
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

//-----------------------------------------------------------------------
//      Cross-16 assembler definiton
//-----------------------------------------------------------------------
static const char *const cross16_headers[] =
{
  "cpu \"8051.tbl\"",
  nullptr
};

static const asm_t cross16 =
{
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_PBIT | UAS_NOSEG | UAS_NOBIT | UAS_EQCLN,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16_headers,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwm",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
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

//-----------------------------------------------------------------------
//      8051 Cross-Assembler by MetaLink Corporation
//-----------------------------------------------------------------------
static const asm_t mcross =
{
  AS_COLON | ASH_HEXF0 | AS_NHIAS,
  UAS_NOSEG | UAS_CDSEG | UAS_AUBIT | UAS_NODS | UAS_NOENS,
  "8051 Cross-Assembler by MetaLink Corporation",
  0,
  nullptr,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // Equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
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

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static const char *const tasm_headers[] =
{
  ".msfirst",
  nullptr
};

static const asm_t tasm =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_PBIT | UAS_NOENS | UAS_EQCLN | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  tasm_headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  "and",   // and
  "or",    // or
  nullptr,    // xor
  "not",   // not
  nullptr,    // shl
  nullptr,    // shr
  nullptr,    // sizeof
};

static const asm_t *const asms[] =
{
  &asmi, &adasm, &pseudosam, &cross16, &mcross, &tasm, nullptr
};

//-----------------------------------------------------------------------
// The short and long names of the supported processors
#define FAMILY "Intel 51 series:"

static const char *const shnames[] =
{
  "8051",
  "80251b",
  "80251s",
  "80930b",
  "80930s",
  "8051mx",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Intel 8051",
  "Intel 80251 in binary mode",
  "Intel 80251 in source mode",
  "Intel 80930 in binary mode",
  "Intel 80930 in source mode",
  "Intel 8051MX",
  nullptr
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static const uchar retcode_1[] = { 0x22 };
static const uchar retcode_2[] = { 0x32 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, nullptr }                            // nullptr terminated array
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_8051,              // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_SEGTRANS           // segment translation is supported (map_code_ea)
  | PR_BINMEM,            // The module creates RAM/ROM segments for binary files
                          // (the kernel shouldn't ask the user about their sizes and addresses)
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  0,I51_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  I51_ret,              // Icode of return instruction. It is ok to give any of possible return instructions

};
