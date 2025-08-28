/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <math.h>
#include "tms320c3x.hpp"
#include <diskio.hpp>
#include <segregs.hpp>
#include <ieee.h>
#include <cvt64.hpp>
int data_id;

static const char *const register_names[] =
{
  // Extended-precision registers
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  // Auxiliary registers
  "ar0",
  "ar1",
  "ar2",
  "ar3",
  "ar4",
  "ar5",
  "ar6",
  "ar7",

  // Index register n
  "ir0",
  "ir1",

  "bk",   // Block-size register
  "sp",   // System-stack pointer
  "st",   // Status register
  "ie",   // CPU/DMA interrupt-enable register
  "if",   // CPU interrupt flag
  "iof",  // I/O flag
  "rs",   // Repeat start-address
  "re",   // Repeat end-address
  "rc",   // Repeat counter

  // segment registers
  "dp",      // Data-page pointer
  "cs","ds", // virtual registers for code and data segments

};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x78, 0x80, 0x00, 0x00 }; // 0x78800000    //retsu
static const uchar retcode_1[] = { 0x78, 0x00, 0x00, 0x00 }; // 0x78000000    //retiu

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      TMS320C3X ASM
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
  ".space 32*%s",// uninited arrays
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
  AS2_BYTE1CHAR,// one character per byte
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
  AS2_BYTE1CHAR,// one character per byte
  nullptr,         // cmnt2
  nullptr,         // low8
  nullptr,         // high8
  nullptr,         // low16
  nullptr,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &fasm, &gnuasm, nullptr };

//--------------------------------------------------------------------------
bool tms320c3x_iohandler_t::entry_processing(ea_t &ea, const char *name, const char *cmt)
{
  set_name(ea, name, SN_NODUMMY);
  set_cmt(ea, cmt, 0);
  return true;
}

//----------------------------------------------------------------------
bool tms320c3x_t::select_device(int lrespect_info)
{
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  if ( !choose_ioport_device(&ioh.device, cfgfile) )
  {
    ioh.device = NONEPROC;
    return false;
  }

  if ( !ioh.display_infotype_dialog(IORESP_ALL, &lrespect_info, cfgfile) )
    return false;

  ioh.set_device_name(ioh.device.c_str(), lrespect_info);
  return true;
}

//----------------------------------------------------------------------
static float conv32(int32 A)   // convertion of 32 bit TMS float -> double
{
  int32 mask, f, i, s;
  float mant;
  int8 e;

  // exponent, signed 8 bit
  e = A >> 24;

  // sign, boolean 1 bit
  s = (A & 0x00800000) >> 23;

  // fraction, unsigned 23 bit
  f =  A & 0x007FFFFF;

  // NaN, Inf
  if ( (e & 0xFF) == 0xFF )
  {
    uint32 i32 = (s << 31) | (0xFF << 23) | f;

    return *reinterpret_cast<float*>(&i32);
  }

  if ( s )
  {
    f ^= 0x007FFFFF;
    f++;
  }

  mant = 1;             // mantissa (1<M<2)
  mask = 0x00800000;    // bit mask of the current bit,
                        // started from the sign position

  for ( i = 0; i <= 23; i++ )
  {
    if ( f & mask )
      mant += (float)pow(double(2), -i);
    mask >>= 1;
  }

  if ( e == -128 && f == 0 && s == 0 )
    mant = 0;

  return float(pow(double(-1), s) * mant * pow(double(2), e));
}

//----------------------------------------------------------------------
// A short floating-point format for immediate floating-point operands, consisting
// of a 4-bit exponent, a sign bit, and an 11-bit fraction
// x = 01.f * 2^e if s = 0
// x = 10.f * 2^e if s = 1
// x = 0          if e = -8
static float conv16(int16 A)   // Convertion of 16 bit TMS float to double
{
  int16 mask, f, i, s;
  float mant;
  int8 e;

  // exponent, signed 4 bit
  e = A >> 12;

  // sign, boolean 1 bit
  s = (A & 0x0800) >> 11;

  // fraction, unsigned 11 bit
  f =  A & 0x07FF;

  // Apparently the 16-bit format does not include
  // NaN of Inf at all (the exponent is too small anyway);
  // though this is a guess by omission (the documentation
  // mention appropriate conversions for 32-bits but not for 16-bits).
  // I think the 16-bit format is intended for short immediate values
  // rather than FPU operations, so it makes some sense.
  //
  // Therefore, no account for NaN of Inf is done in the 16-bit format.

  if ( s )
  {
    f ^= 0x07FF;
    f++;
  }

  mant = 1;         // mantissa (1<M<2)
  mask = 0x0800;    // bit mask for the current bit

  for ( i = 0; i <= 11; i++ )
  {
    if ( f & mask )
      mant += (float)pow(double(2), -i);
    mask >>= 1;
  }

  if ( e == -8 && f == 0 && s == 0 )
    mant = 0;

  return float(pow(double(-1), s) * mant * pow(double(2), e));
}

//--------------------------------------------------------------------------
//lint -esym(818, m)
fpvalue_error_t idaapi tms_realcvt(void *m, fpvalue_t *e, ushort swt)
{
  fpvalue_error_t ret;
  int32 A;
  int16 B;

  union
  {
    float pfl;
    int32 pint;
  };

  switch ( swt )
  {
    case 0:                // TmsFloat 16bit to e
      memcpy(&B, m, 2);
      pfl = conv16(B);
      pint = swap32(pint);
      ret = ieee_realcvt(&pint, e, 1);
      break;

    case 1:                // TmsFloat 32bit to e
      memcpy(&A, m, 4);
      pfl = conv32(A);
      pint = swap32(pint);
      ret = ieee_realcvt(&pint, e, 1);
      break;

    default:
      msg("real_cvt_error swt = %d \n", swt);
      return REAL_ERROR_FORMAT;
  }
  return ret;
}

//--------------------------------------------------------------------------
const char *tms320c3x_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  select_device(IORESP_PORT|IORESP_INT);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
void tms320c3x_t::load_from_idb()
{
  inf_set_wide_high_byte_first(false);
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(tms320c3x_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi tms320c3x_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      inf_set_be(true); // MSB first
      inf_set_wide_high_byte_first(true);
      init_analyzer();
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:   // new file loaded
      inf_set_wide_high_byte_first(false);
      if ( inf_like_binary() )
      {
        segment_t *s0 = get_first_seg();
        if ( s0 != nullptr )
        {
          set_segm_name(s0, "CODE");
          segment_t *s1 = get_next_seg(s0->start_ea);
          for ( int i = dp; i <= rVds; i++ )
          {
            set_default_sreg_value(s0, i, BADSEL);
            set_default_sreg_value(s1, i, BADSEL);
          }
        }
        select_device(IORESP_ALL);
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:   // old file loaded
      load_from_idb();
      break;

    case processor_t::ev_is_basic_block_end:
      {
        const insn_t &insn = *va_arg(va, const insn_t *);
        return is_basic_block_end(insn) ? 1 : 0;
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
#define FAMILY "TMS320C3x Series:"
static const char *const shnames[] =
{
  "TMS320C3",
  nullptr
};
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C3X",
  nullptr
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS320C3,          // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER
  | PR_ALIGN
  | PR_USE32
  | PR_DEFSEG32
  | PR_DELAYED,
                          // flag2
  PR2_IDP_OPTS,           // the module has processor-specific configuration options
  32,                     // 32 bits in a byte for code segments
  32,                     // 32 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  dp,                   // first
  rVds,                 // last
  1,                    // size of a segment register
  rVcs, rVds,

  nullptr,                 // No known code start sequences
  retcodes,

  TMS320C3X_null,
  TMS320C3X_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 4, 7, 15, 18 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double (80-bit)
  TMS320C3X_RETSU,      // Icode of return instruction. It is ok to give any of possible return instructions
};
