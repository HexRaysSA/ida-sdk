/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *
 *      TMS320C6xx - VLIW (very long instruction word) architecture
 *
 */

#include "tms6.hpp"
#include <cvt64.hpp>
int data_id;

//--------------------------------------------------------------------------
// B14 - data page pointer
// B15 - stack pointer
static const char *const RegNames[] =
{
  "A0", "A1",  "A2", "A3",  "A4",  "A5",  "A6",  "A7",
  "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15",
  "A16", "A17", "A18", "A19", "A20", "A21", "A22", "A23",
  "A24", "A25", "A26", "A27", "A28", "A29", "A30", "A31",
  "B0", "B1", "B2",  "B3",  "B4",  "B5",  "B6",  "B7",
  "B8", "B9", "B10", "B11", "B12", "B13", "B14", "B15",
  "B16", "B17", "B18", "B19", "B20", "B21", "B22", "B23",
  "B24", "B25", "B26", "B27", "B28", "B29", "B30", "B31",
  "AMR",
  "CSR",
  "IFR",
  "ISR",
  "ICR",
  "IER",
  "ISTP",
  "IRP",
  "NRP",
  "ACR",  // undocumented, info from Jeff Bailey <jeff_bailey@infinitek.com>
  "ADR",  // undocumented, info from Jeff Bailey <jeff_bailey@infinitek.com>
  "PCE1",
  "FADCR",
  "FAUCR",
  "FMCR",
  "TSCL",
  "TSCH",
  "ILC",
  "RILC",
  "REP",
  "DNUM",
  "SSR",
  "GPLYA",
  "GPLYB",
  "GFPGFR",
  "TSR",
  "ITSR",
  "NTSR",
  "ECR",
  "EFR",
  "IERR",
  "CS", "DS"
};

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::segm_moved: // A segment is moved
                                // Fix processor dependent address sensitive information
      {
        ea_t from           = va_arg(va, ea_t);
        ea_t to             = va_arg(va, ea_t);
        asize_t size        = va_arg(va, asize_t);
        bool changed_netmap = va_argi(va, bool);
        if ( !changed_netmap )
        {
          nodeidx_t ndx1 = ea2node(from);
          nodeidx_t ndx2 = ea2node(to);
          pm.helper.altshift(ndx1, ndx2, size);
          // like altadjust()
          for ( nodeidx_t ndx = pm.helper.supfirst();
                ndx != BADADDR;
                ndx = pm.helper.supnext(ndx) )
          {
            tgtinfo_t tgt;
            ea_t ea = node2ea(ndx);
            tgt.restore_from_idb(pm, ea);
            if ( tgt.has_target() )
            {
              tgt.target = correct_address(tgt.target, from, to, size);
              tgt.save_to_idb(pm, ea);
            }
          }
        }
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
    return size_t(SET_MODULE_DATA(tms6_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi tms6_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;

    case processor_t::ev_oldfile:
      {
        netnode old_tnode("$ tms node");
        if ( old_tnode != BADNODE )
        {
          upgrade_tnode(old_tnode);
          old_tnode.kill();
        }
      }
      // no break
    case processor_t::ev_ending_undo:
    case processor_t::ev_newfile:
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
        data(*ctx, analyze_only);
        return 1;
      }

    case processor_t::ev_out_special_item:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        uchar seg_type = va_argi(va, uchar);
        outspec(*ctx, seg_type);
        return 1;
      }

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return is_align_insn(ea);
      }

    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_merge_handlers(*md);
      }
      break;

    case processor_t::ev_privrange_changed:
      // recreate node as it was migrated
      helper.create(PROCMOD_NODE_NAME);
      break;

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        nodeidx_t node = va_arg(va, nodeidx_t);
        uchar tag = va_argi(va, uchar);
        nodeidx_t idx = va_arg(va, nodeidx_t);
        if ( helper == node && tag == stag )
        {
          tgtinfo_t tgt;
          ea_t ea = node2ea(idx);
          tgt.restore_from_idb(*this, ea);
          tgt.save_to_idb(*this, ea);
          return 1;
        }
      }
      break;
#endif

    default:
      break;
  }
  return code;
}

//-------------------------------------------------------------------------
void tms6_t::upgrade_tnode(const netnode &old_tnode)
{
  // copy branch/call info to HELPER
  for ( nodeidx_t ndx = old_tnode.altfirst();
        ndx != BADADDR;
        ndx = old_tnode.altnext(ndx) )
  {
    nodeidx_t ndx2 = old_tnode.altval(ndx);
    if ( ndx2 == 0 )
      continue;
    tgtinfo_t tgt;
    switch ( ndx2 )
    {
      case 1:
        tgt.type = tgtinfo_t::IND_BRANCH;
        break;
      case 2:
        tgt.type = tgtinfo_t::IND_CALL;
        break;
      default:
        {
          ea_t target = node2ea(ndx2);
          tgt.type = (target & 1) != 0
                   ? tgtinfo_t::BRANCH
                   : tgtinfo_t::CALL;
          tgt.target = target & ~1;
        }
        break;
    }
    tgt.save_to_idb(*this, node2ea(ndx));
  }
}

//-------------------------------------------------------------------------
const char *tgtinfo_t::get_type_name() const
{
  switch ( type )
  {
    case tgtinfo_t::CALL:       return "CALL";
    case tgtinfo_t::BRANCH:     return "BRANCH";
    case tgtinfo_t::IND_CALL:   return "INDIRECT CALL";
    case tgtinfo_t::IND_BRANCH: return "INDIRECT BRANCH";
  }
  return "";
}

//-------------------------------------------------------------------------
#define TGTINFO_MAX_SIZE (1 + ea_packed_size)
void tgtinfo_t::save_to_idb(tms6_t &pm, ea_t ea) const
{
  uchar buf[TGTINFO_MAX_SIZE];
  uchar *ptr = buf;
  uchar *end = buf + sizeof(buf);
  ptr = pack_db(ptr, end, uchar(type));
  if ( has_target() )
    ptr = pack_ea(ptr, end, ea2node(target));
  pm.helper.supset_ea(ea, buf, ptr - buf);
}

//-------------------------------------------------------------------------
bool tgtinfo_t::restore_from_idb(const tms6_t &pm, ea_t ea)
{
  uchar buf[TGTINFO_MAX_SIZE];
  ssize_t code = pm.helper.supval_ea(ea, buf, sizeof(buf));
  if ( code < 1 )
    return false;
  memory_deserializer_t mmdsr(buf, code);
  uchar t = mmdsr.unpack_db();
  if ( t > IND_BRANCH )
    return false;
  type = type_t(t);
  if ( has_target() )
  {
    ea_t tgt = mmdsr_unpack_ea(mmdsr);
    target = node2ea(tgt);
  }
  return true;
}

//-----------------------------------------------------------------------
//           TMS320C6x COFF Assembler
//-----------------------------------------------------------------------
static const asm_t dspasm =
{
  AS_COLON | ASH_HEXF0 | ASD_DECF0 | ASB_BINF0 | ASO_OCTF5,
  0,
  "TMS320C6x COFF Assembler",
  0,
  nullptr,         // header lines
  nullptr,         // org
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".string",    // ascii string directive
  ".char",      // byte directive
  ".short",     // word directive
  ".long",      // double words
  nullptr,         // no qwords
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  ".set",       // equ
  nullptr,         // 'seg' prefix (example: push seg seg001)
  "$",          // current IP (instruction pointer)
  nullptr,         // func_header
  nullptr,         // func_footer
  ".def",       // "public" name keyword
  nullptr,         // "weak"   name keyword
  ".ref",       // "extrn"  name keyword
  ".usect",     // "comm" (communal variable)
  nullptr,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "!",     // not
  "<<",    // shl
  ">>",    // shr
  nullptr,    // sizeof
};


static const asm_t *const asms[] = { &dspasm, nullptr };
//-----------------------------------------------------------------------
#define FAMILY "TMS320C6 series:"
static const char *const shnames[] = { "TMS320C6", nullptr };
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C6xxx",
  nullptr
};

//--------------------------------------------------------------------------
static const uchar retcode_1[] = { 0x62, 0x63, 0x0C, 0x00 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMSC6,             // id
                          // flag
    PR_USE32
  | PR_DEFSEG32
  | PR_DELAYED
  | PR_ALIGN_INSN,        // allow align instructions
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,             // Register names
  qnumber(RegNames),    // Number of registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  TMS6_null,
  TMS6_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;
  { 2, 4, 8, 12 },      // char real_width[4];
  TMS6_null,            // Icode of return instruction. It is ok to give any of possible return instructions
};
