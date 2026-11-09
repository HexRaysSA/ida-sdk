/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#include "i5.hpp"
#include <diskio.hpp>
#include <cvt64.hpp>

int data_id;

static const char *const RegNames[] =
{
  "b",  "c",  "d", "e", "h", "l", "m", "a",           // 0..7
  "bc", "de", "hl","psw","sp","ix","iy","af'",        // 8..15
  "r",  "i",  "f", "xl", "xh","yl","yh",              // 16..22

  "w", "lw", "ixl", "ixu", "dsr", "xsr", "iyl",
  "iyu", "ysr", "sr", "ib", "iw", "xm", "lck",
  "bc'", "de'", "hl'","ix'","iy'",
  "b'",  "c'",  "d'", "e'", "h'", "l'", "m'", "a'",

  "cs","ds"
};

//-----------------------------------------------------------------------
//      PseudoSam assembler definiton
//-----------------------------------------------------------------------
static const char *const ps_headers[] =
{
  ".code",
  nullptr
};

static const asm_t pseudosam =
{
  AS_COLON | ASH_HEXF1 | AS_N2CHR,
  0,
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
  ".drw",       // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      TASM assembler definiton for 8085
//-----------------------------------------------------------------------
static const char tasmname[] = "Table Driven Assembler (TASM) by Speech Technology Inc.";
static const asm_t tasm =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NPAIR | UAS_NOENS,
  tasmname,
  0,
  nullptr,
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
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      TASM assembler definiton for Z80
//-----------------------------------------------------------------------
static const asm_t tasmz80 =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_TOFF,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  nullptr,
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
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Cross-16 assembler definiton (8085)
//-----------------------------------------------------------------------
static const char *const cross16_headers[] =
{
  "cpu \"8085.tbl\"",
  nullptr
};

static const asm_t cross16 =
{
  AS_COLON | AS_NHIAS,
  UAS_NPAIR,
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
  "dwl",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Cross-16 assembler definiton (z80)
//-----------------------------------------------------------------------
static const char *const cross16z80_headers[] =
{
  "cpu \"z80.tbl\"",
  nullptr
};

static const asm_t cross16z80 =
{
  AS_COLON | AS_NHIAS,
  UAS_MKIMM,
  "Cross-16 by Universal Cross-Assemblers",
  0,
  cross16z80_headers,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\0',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  "dfb",        // ascii string directive
  "dfb",        // byte directive
  "dwl",        // word directive
  nullptr,         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  nullptr,         // arrays (#h,#d,#v,#s(...)
  "dfs %s",     // uninited arrays
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      A80 assembler definiton
//-----------------------------------------------------------------------
static const asm_t a80 =
{
  AS_COLON | ASD_DECF1 | ASH_HEXF2 | AS_UNEQU,
  UAS_NPAIR,
  "A80 by ANTA electronics",
  0,
  nullptr,
  "org",
  nullptr,

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "'",          // special symbols in char and string constants

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
  nullptr,         // uninited arrays
  "equ",
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      A80 assembler definiton (Z80)
//-----------------------------------------------------------------------
static const asm_t a80z =
{
  AS_COLON | ASD_DECF1 | ASH_HEXF2 | AS_UNEQU,
  UAS_NPAIR | UAS_UNDOC | UAS_FUNNY,
  "A80 by ANTA electronics",
  0,
  nullptr,
  "adr",
  nullptr,

  ";",          // comment string
  '\'',         // string delimiter
  '\0',         // char delimiter (no char consts)
  "'",          // special symbols in char and string constants

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
  nullptr,         // uninited arrays
  "equ",
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Avocet Macro Preprocessor v1.0 by Avocet Systems, Inc.
//-----------------------------------------------------------------------
static const char *const avocet_headers[] =
{
  "; $chip(HD64180) ; please uncomment and place as first line for HD64180",
  "       defseg allseg, absolute ; make avocet think that we have",
  "       seg allseg              ; one big absolute segment",
  nullptr
};

static const asm_t avocet =
{
  AS_NHIAS,
  0,
  "Avocet Macro Preprocessor v1.0 by Avocet Systems, Inc.",
  0,
  avocet_headers,
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

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
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      ASxxxx by Alan R. Baldwin
//-----------------------------------------------------------------------
static const char *const asxxxx_headers[] =
{
  "       .area   idaseg (ABS)",
  "       .hd64 ; this is needed only for HD64180",
  nullptr
};

static const asm_t asxxxx =
{
  AS_NHIAS | AS_COLON | AS_NCHRE | AS_N2CHR | AS_1TEXT | ASH_HEXF3,
  UAS_MKIMM | UAS_MKOFF | UAS_CNDUP,
  "ASxxxx by Alan R. Baldwin v1.5",
  0,
  asxxxx_headers,
  ".org",
  nullptr,

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

  ".ascii",     // ascii string directive
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
  ".ds %s",     // uninited arrays
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      X-M-80 by Leo Sandy, (8080)
//-----------------------------------------------------------------------
static const char *const xm80_headers[] =
{
  ".8080",
  nullptr
};

static const asm_t xm80 =
{
  AS_COLON | AS_NHIAS,
  UAS_CSEGS,
  "X-M-80 by Leo Sandy",
  0,
  xm80_headers,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

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
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      X-M-80 by Leo Sandy, (Z80)
//-----------------------------------------------------------------------
static const char *const xm80z_headers[] =
{
  ".Z80",
  nullptr
};

static const asm_t xm80z =
{
  AS_COLON | AS_NHIAS,
  UAS_CSEGS,
  "X-M-80 by Leo Sandy",
  0,
  xm80z_headers,
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'",          // special symbols in char and string constants

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
  nullptr,         // equ
  nullptr,         // seg prefix
  nullptr,         // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
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
//      Zilog Macro Assembler (ZMASM)
//-----------------------------------------------------------------------
static const asm_t zmasm =
{
  ASH_HEXF0     //   34h
 |ASD_DECF0     //   34
 |ASO_OCTF0     //   123o
 |ASB_BINF0     //   010101b
 |AS_N2CHR      // can't have 2 byte char consts
 |AS_COLON      //   ':' after all labels
 |AS_ASCIIC     // ascii directive accepts C-like strings
 |AS_ONEDUP,    // one dup directive per line
  UAS_ZMASM,
  "Zilog Macro Assembler",
  0,
  nullptr,         // headers
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "dl",         // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  "#h [ #d ], #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  nullptr,         // seg prefix
  "$",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  "public",     // public
  nullptr,         // weak
  "extern",     // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  "align",      // align
  ' ', ' ',     // lbrace, rbrace
  "%",     // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "~",     // not
  "<<",    // shl
  ">>",    // shr
  nullptr,    // sizeof
};

//-----------------------------------------------------------------------
//      RGBAsm v1.11 (part of ASMotor 1.10)
//-----------------------------------------------------------------------
static const asm_t rgbasm =
{
  ASH_HEXF4     //   $34
 |ASD_DECF0     //   34
 |ASO_OCTF3     //   @123 (in fact this should be &123)
 |ASB_BINF2     //   %010101
 |AS_N2CHR      // can't have 2 byte char consts
 |AS_COLON,     //   ':' after all labels
  UAS_GBASM,
  "RGBAsm (part of ASMotor)",
  0,
  nullptr,         // headers
  "org",
  nullptr,         // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "'\"",        // special symbols in char and string constants

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
  "equ",        // equ
  nullptr,         // seg prefix
  "@",          // curip
  nullptr,         // func_header
  nullptr,         // func_footer
  "export",     // public
  nullptr,         // weak
  "import",     // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  nullptr,         // align
  ' ', ' ',     // lbrace, rbrace
  "%",     // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "~",     // not
  "<<",    // shl
  ">>",    // shr
  nullptr,    // sizeof
};

static const asm_t *const i8085asms[]   = { &tasm,    &xm80,   &pseudosam, &cross16, &a80, nullptr };
static const asm_t *const Z80asms[]     = { &zmasm, &tasmz80, &xm80z,  &pseudosam, &cross16z80, &a80z, &avocet, &asxxxx, nullptr };
static const asm_t *const HD64180asms[] = { &zmasm, &tasmz80, &avocet, &asxxxx, nullptr };
static const asm_t *const GBasms[]      = { &rgbasm, nullptr };

//------------------------------------------------------------------
const char *z80_t::find_ioport(uval_t port)
{
  const ioport_t *p = ::find_ioport(ioh.ports, port);
  return p ? p->name.c_str() : nullptr;
}

//------------------------------------------------------------------
const char *z80_t::find_ioport_bit(int port, int bit)
{
  const ioport_bit_t *p = ::find_ioport_bit(ioh.ports, port, bit);
  return p ? p->name.c_str() : nullptr;
}

//------------------------------------------------------------------
void z80_t::choose_device(int respinfo)
{
  char cfgfile[QMAXFILE];
  ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
  iohandler_t::parse_area_line0_t cb(ioh);
  if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
    ioh.set_device_name(ioh.device.c_str(), respinfo);
}

//------------------------------------------------------------------
const char *z80_t::set_idp_options(
        const char *keyword,
        int /*value_type*/,
        const void * /*value*/,
        bool /*idb_loaded*/)
{
  if ( keyword != nullptr )
    return IDPOPT_BADKEY;
  choose_device(IORESP_NONE);
  return IDPOPT_OK;
}

//-----------------------------------------------------------------------
static bool idaapi can_have_type(const op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:        // No Operand
    case o_reg:         // General Register
    case o_phrase:      // Base Reg + Index Reg
    case o_cond:        // FPP register
      return 0;
  }
  return 1;
}


//----------------------------------------------------------------------
static char const features[] = { _PT_8085, _PT_Z80, _PT_64180, _PT_Z180, _PT_Z380, _PT_GB };

//----------------------------------------------------------------------
void z80_t::set_cpu(int np)
{
  pflag = features[np];
  ph.assemblers = i8085asms;
  if ( isZ80() )
    ph.assemblers = Z80asms;
  if ( is64180() )
    ph.assemblers = HD64180asms;
  if ( isGB() )
    ph.assemblers = GBasms;
}

//----------------------------------------------------------------------
void z80_t::load_from_idb()
{
  set_cpu(ph.get_proc_index());
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(z80_t));
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi z80_t::on_event(ssize_t msgid, va_list va)
{
  int _code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      clr_module_data(data_id);
      break;

    case processor_t::ev_newprc:
      {
        int np = va_arg(va, int);
        // bool keep_cfg = va_argi(va, bool);
        set_cpu(np);
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_newfile:
      if ( inf_get_procname() == "z180" )
        choose_device(IORESP_AREA);
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i5_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        i5_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        i5_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return i5_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return i5_emu(*insn) ? 1 : -1;
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
      helper.create(PROCMOD_NODE_NAME);   // recreate node as it was migrated
      break;

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        static const cvt64_node_tag_t node_info[] = { CVT64_NODE_DEVICE };
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
        *target = next_exec_insn(ea, getreg, regvalues);
        return 1;
      }

    case processor_t::ev_calc_step_over:
      {
        ea_t *target = va_arg(va, ea_t *);
        ea_t ip      = va_arg(va, ea_t);
        *target = calc_step_over(ip);
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
        return get_operand_info(opinf, ea, n, getreg, regvalues) ? 1 : 0;
      }

    case processor_t::ev_get_reg_info:
      {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange      = va_arg(va, bitrange_t *);
        const char *regname       = va_arg(va, const char *);
        return get_reg_info(main_regname, bitrange, regname) ? 1 : -1;
      }
    // END OF DEBUGGER CALLBACKS

    default:
      break;
  }
  return _code;
}

//-----------------------------------------------------------------------
#define FAMILY "Z80 processors:"

static const char *const shnames[] =
{
  "8085",
  "z80",
  "64180",
  "z180",
  "z380",
  "gb",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Intel 8085",
  "Zilog 80",
  "Hitachi HD64180",
  "Zilog Z180",
  "Zilog Z380",
  "GameBoy",
  nullptr
};

//-----------------------------------------------------------------------
static const uchar retcode_1[] = { 0xC9 };
static const uchar retcode_2[] = { 0xED, 0x45 };
static const uchar retcode_3[] = { 0xED, 0x4D };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

//-----------------------------------------------------------------------
//      Intel 8080/8085 processor definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_Z80,               // id
                          // flag
    PRN_HEX
  | PR_SEGTRANS,
                          // flag2
  PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  i8085asms,

  notify,

  RegNames,
  R_vds+1,              // number of registers

  R_vcs,R_vds,          // first, last
  0,                    // size of a segment register
  R_vcs,R_vds,          // CS,DS

  nullptr,                 // No known code start sequences
  retcodes,             // 'Return' instruction codes

  0,I5_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 0, 0, 0 },       // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  I5_ret,               // Icode of return instruction. It is ok to give any of possible return instructions
};
