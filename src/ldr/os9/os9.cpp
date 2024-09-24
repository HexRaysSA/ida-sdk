/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov <ig@datarescue.com>
 *      ALL RIGHTS RESERVED.
 *
 *      This file is able to load:
 *              - OS9 object files
 *              - FLEX STX files
 *      for 6809
 *
 */

#include "../idaldr.h"
#include "../../module/mc68xx/notify_codes.hpp"
#include "os9.hpp"

//----------------------------------------------------------------------
static void swap_os9_header(os9_header_t &h)
{
#if __MF__
  qnotused(h);
#else
  h.magic   = swap16(h.magic);
  h.size    = swap16(h.size);
  h.name    = swap16(h.name);
  h.start   = swap16(h.start);
  h.storage = swap16(h.storage);
#endif
}

//----------------------------------------------------------------------
// calc header parity
static uchar calc_os9_parity(os9_header_t &h)
{
  uchar *ptr = (uchar *)&h;
  int parity = 0;
  for ( int i=0; i < 8; i++ )
    parity ^= *ptr++;
  return (uchar)~parity;
}

//----------------------------------------------------------------------
static const char object_name[] = "OS9 object file for 6809";
static bool is_os9_object_file(qstring *fileformatname, linput_t *li)
{
  os9_header_t h;
  qlseek(li, 0);
  if ( qlread(li,&h,sizeof(os9_header_t)) != sizeof(os9_header_t) )
    return false;
  swap_os9_header(h);
  if ( h.magic == OS9_MAGIC
    && calc_os9_parity(h) == h.parity
    && (h.type_lang & OS9_LANG) == OS9_LANG_OBJ )
  {
    *fileformatname = object_name;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static const char flex_name[] = "FLEX STX file";
static bool is_os9_flex_file(qstring *fileformatname, linput_t *li)
{
  qlseek(li, 0);
  int64 fsize = qlsize(li);
  int nrec2 = 0;
  qoff64_t fpos = 0;
  while ( 1 )
  {
    if ( fpos > fsize )
      return false;
    qlseek(li, fpos, SEEK_SET);
    int c = qlgetc(li);
    if ( c == EOF )
      break;
    if ( fpos == 0 && c != 0x2 )
      return false;  // the first byte must be 0x2
    switch ( c )
    {
      case 0:
        fpos++;
        break;
      case 0x2:
        {
          c = qlgetc(li);
          int adr = (c<<8) | qlgetc(li);
          if ( adr == EOF )
            return false;
          c = qlgetc(li);        // number of bytes
          if ( c == 0 || c == EOF )
            return false;
          fpos += c+4;
          nrec2++;
        }
        break;
      case 0x16:
        fpos += 3;
        break;
      default:
        return false;
    }
  }
  if ( nrec2 == 0 )
    return false;
  *fileformatname = flex_name;
  return true;
}

//----------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  if ( is_os9_object_file(fileformatname, li) // OS9
    || is_os9_flex_file(fileformatname, li) ) // FLEX
  {
    *processor = "6809";
    return 1;
  }
  return 0;
}

//----------------------------------------------------------------------
static const char *get_os9_type_name(uchar type)
{
  switch ( type )
  {
    case OS9_TYPE_ILL: return "illegal";
    case OS9_TYPE_PRG: return "Program module";
    case OS9_TYPE_SUB: return "Subroutine module";
    case OS9_TYPE_MUL: return "Multi-Module (for future use)";
    case OS9_TYPE_DAT: return "Data module";
    case OS9_TYPE_SYS: return "OS-9 System Module";
    case OS9_TYPE_FIL: return "OS-9 File Manager Module";
    case OS9_TYPE_DRV: return "OS-9 Device Driver Module";
    case OS9_TYPE_DDM: return "OS-9 Device Descriptor Module";
    default:           return "unknown";
  }
}

//----------------------------------------------------------------------
static const char *get_os9_lang_name(uchar lang)
{
  switch ( lang )
  {
    case OS9_LANG_DAT: return "Data (not executable)";
    case OS9_LANG_OBJ: return "6809 object code";
    case OS9_LANG_BAS: return "BASIC09 I-Code";
    case OS9_LANG_PAS: return "PASCAL P-Code";
    case OS9_LANG_C:   return "C I-Code";
    case OS9_LANG_CBL: return "COBOL I-Code";
    case OS9_LANG_FTN: return "FORTRAN I-Code";
    default:           return "unknown";
  }
}

//--------------------------------------------------------------------------
static void create32(
        sel_t sel,
        ea_t start_ea,
        ea_t end_ea,
        const char *name,
        const char *classname)
{
  set_selector(sel, 0);

  segment_t s;
  s.sel     = sel;
  s.start_ea = start_ea;
  s.end_ea   = end_ea;
  s.align   = saRelByte;
  s.comb    = scPub;
  if ( !add_segm_ex(&s, name, classname, ADDSEG_NOSREG|ADDSEG_SPARSE) )
    loader_failure();
}

//----------------------------------------------------------------------
#define LOADING_OFFSET 0x1000

void load_obj_file(linput_t *li)
{
  os9_header_t h;
  qlseek(li, 0);
  lread(li, &h, sizeof(os9_header_t));
  swap_os9_header(h);

  set_processor_type("6809", SETPROC_LOADER);
  set_target_assembler(5);

  uint64 fsize = qlsize(li);
  qoff64_t fpos = qltell(li);
  uint64 rest = fsize - fpos;
  ea_t start = to_ea(inf_get_baseaddr(), LOADING_OFFSET);
  ea_t end   = start + h.size;
  if ( end <= start || fsize < fpos || fsize-fpos < rest )
    loader_failure("Corrupted input file");

  file2base(li, 0, start, end, FILEREG_PATCHABLE);
  create32(inf_get_baseaddr(), start, start + h.size, "TEXT", "CODE");

  create_filename_cmt();
  ea_t ea = start;
  set_name(ea, "magic", SN_IDBENC);
  create_word(ea, 2);
  op_num(ea,0);

  ea += 2;
  set_name(ea, "size", SN_IDBENC);
  create_word(ea, 2);
  op_num(ea,0);

  ea += 2;
  set_name(ea, "name", SN_IDBENC);
  create_word(ea, 2);
  if ( h.name < h.size )
    op_plain_offset(ea,0, start);

  ea += 2;
  set_name(ea, "type_lang", SN_IDBENC);
  create_byte(ea, 1);
  op_num(ea,0);
  append_cmt(ea, get_os9_type_name(h.type_lang & OS9_TYPE), 0);
  append_cmt(ea, get_os9_lang_name(h.type_lang & OS9_LANG), 0);

  ea += 1;
  set_name(ea, "attrib", SN_IDBENC);
  create_byte(ea, 1);
  op_num(ea,0);
  if ( h.attrib & OS9_SHARED )
    append_cmt(ea, "Shared module", 0);

  ea += 1;
  set_name(ea, "parity", SN_IDBENC);
  create_byte(ea, 1);
  op_num(ea,0);

  ea += 1;
  set_name(ea, "start_ptr", SN_IDBENC);
  create_word(ea, 2);
  op_plain_offset(ea,0, start);

  ea += 2;
  set_name(ea, "storage", SN_IDBENC);
  create_word(ea, 2); op_num(ea,0);

  inf_set_start_ip(LOADING_OFFSET + h.start);
  inf_set_start_cs(inf_get_baseaddr());
}

//----------------------------------------------------------------------
void load_flex_file(linput_t *li)
{
  qlseek(li, 0);

  set_processor_type("6809", SETPROC_LOADER);
  set_target_assembler(5);

  ea_t bottom = BADADDR;
  ea_t top = 0;
  while ( 1 )
  {
    int c = qlgetc(li);
    if ( c == EOF )
      break;
    switch ( c )
    {
      case 0:
        break;
      case 0x2:
        {
          c = qlgetc(li);
          int adr = (c<<8) | qlgetc(li);
          c = qlgetc(li);        // number of bytes
          ea_t start = to_ea(inf_get_baseaddr(), adr);
          ea_t end   = start + c;
          file2base(li, qltell(li), start, end, FILEREG_PATCHABLE);
          if ( bottom > start )
            bottom = start;
          if ( top < end )
            top = end;
        }
        break;
      case 0x16:
        c = qlgetc(li);
        inf_set_start_ip(int(c<<8) | qlgetc(li));
        inf_set_start_cs(inf_get_baseaddr());
        break;
      default:
        INTERR(20065);
    }
  }
  create32(inf_get_baseaddr(), bottom, top, "TEXT", "CODE");
  create_filename_cmt();
  mc68xx_module_t::notify_flex_format();   // tell the module that the file has FLEX format
}

//----------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char *fileformatname)
{
  if ( strcmp(fileformatname, object_name) == 0 )
    load_obj_file(li);
  else
    load_flex_file(li);
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  nullptr,
//      take care of a moved segment (fix up relocations, for example)
  nullptr,
  nullptr,
};
