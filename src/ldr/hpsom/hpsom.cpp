/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "../idaldr.h"
#include <typeinf.hpp>
#include "hpsom.hpp"

#include "common.cpp"

static int first_text_subspace_idx = -1;
static int32 first_text_subspace_fpos = -1;
static char *dl_strings = nullptr;
static size_t dl_ssize = 0;
static ea_t data_start = 0;
static int64 fsize = 0;
//--------------------------------------------------------------------------
static void complain_fixup(void)
{
  static bool complained = false;
  if ( !complained )
  {
    warning("The input file contains relocation information.\n"
            "Currently IDA doesn't handle relocation information,\n"
            "so it will be skipped");
    complained = true;
  }
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  header h;
  qlseek(li, 0);
  if ( qlread(li, &h, sizeof(h)) != sizeof(h) )
    return 0;
  if ( compute_som_checksum(&h) != 0 )
    return 0;
  h.swap();
  const char *type;
  switch ( h.a_magic )
  {
    case EXELIB_MAGIC  : type = "Executable Library";                   break;
    case REL_MAGIC     : type = "Relocatable";                          break;
    case EXE_MAGIC     : type = "Non-sharable, executable";             break;
    case SHREXE_MAGIC  : type = "Sharable, executable";                 break;
    case SHREXELD_MAGIC: type = "Sharable, demand-loadable executable"; break;
    case DLL_MAGIC     : type = "Dynamic Load Library";                 break;
    case SHLIB_MAGIC   : type = "Shared Library";                       break;
    case RELLIB_MAGIC  : type = "Relocatable Library";                  break;
    default:             return 0;
  }
  fileformatname->sprnt("HP-UX SOM (%s)", type);
  *processor = "hppa";

  return 1;
}

//--------------------------------------------------------------------------
static void load_aux_headers(linput_t *li, int32 fpos, size_t size)
{
  if ( size == 0 )
    return;

  size_t rest = fsize - fpos;
  if ( rest <= size )
    loader_failure("Wrong header::aux_header_size");
  qlseek(li, fpos);

  while ( size > 0 )
  {
    char buf[4096];
    CASSERT(sizeof(buf) >= sizeof(aux_id));
    aux_id &aih = *(aux_id *)buf;
    lread(li, &aih, sizeof(aih));
    aih.swap();
    size_t total = sizeof(aih) + aih.length;
    if ( total < sizeof(aih) || total >= sizeof(buf) )
      loader_failure("Wrong aux_header size %" FMT_Z, total);
    if ( total > size )
      return; // loader_failure("Illegal aux header size %u, rest %u", total, size);
    size -= total;
    lread(li, &aih+1, aih.length);
    switch ( aih.type )
    {
      case HPUX_AUX_ID:
        {
          som_exec_auxhdr *p = (som_exec_auxhdr*)buf;
          p->swap();
          inf_set_start_cs(0);
          inf_set_start_ip(p->exec_entry);
          data_start = p->exec_dmem;
        }
        break;
      case VERSION_AUX_ID:
      case COPYRIGHT_AUX_ID:
      case SHLIB_VERSION_AUX_ID:
      default:
        break;
    }
  }
}

//--------------------------------------------------------------------------
static char *get_name(linput_t *li, int32 tableoff, size_t tablesize, int32 nidx, char *buf, size_t bufsize)
{
  if ( nidx >= tablesize )
  {
    APPZERO(buf, buf+bufsize);
  }
  else
  {
    qoff64_t fpos = qltell(li);
    qlseek(li, tableoff+nidx-4);
    uint32 len;
    lread(li, &len, sizeof(len));
    len = swap32(len);
    if ( len >= bufsize )
      len = uint32(bufsize-1);
    lread(li, buf, len);
    buf[len] = '\0';
    qlseek(li, fpos);
  }
  return buf;
}

//--------------------------------------------------------------------------
inline char *get_space_name(linput_t *li, const header &h, int32 nidx, char *buf, size_t bufsize)
{
  return get_name(li,
                  h.space_strings_location,
                  h.space_strings_size,
                  nidx,
                  buf,
                  bufsize);
}

inline char *get_symbol_name(linput_t *li, const header &h, int32 nidx, char *buf, size_t bufsize)
{
  return get_name(li,
                  h.symbol_strings_location,
                  h.symbol_strings_size,
                  nidx,
                  buf,
                  bufsize);
}

//--------------------------------------------------------------------------
static void load_spaces(linput_t *li, const header &h, int32 fpos, int n)
{
  if ( n == 0 )
    return;

  qlseek(li, fpos);
  space_dictionary_record sr;
  validate_array_count_or_die(li, n, sizeof(sr), "Number of spaces", fpos);
  for ( int i=0; i < n; i++ )
  {
    lread(li, &sr, sizeof(sr));
    sr.swap();
    char buf[MAXSTR];
    get_space_name(li, h, sr.name.n_strx, buf, sizeof(buf));
    if ( streq(buf, "$TEXT$") )
      first_text_subspace_idx = sr.subspace_index;
  }
}

//--------------------------------------------------------------------------
static void load_subspaces(linput_t *li, const header &h, qoff64_t fpos, int n)
{
  if ( n == 0 )
    return;
  subspace_dictionary_record sr;
  validate_array_count_or_die(li, n, sizeof(sr), "Number of subspaces", fpos);
  for ( int i=0; i < n; i++,fpos+=sizeof(sr) )
  {
    qlseek(li, fpos);
    lread(li, &sr, sizeof(sr));
    sr.swap();

    if ( !sr.is_loadable() || !sr.subspace_length )
      continue;
    if ( sr.fixup_request_quantity )
      complain_fixup();
    ea_t start = sr.subspace_start;
    ea_t end = start + sr.initialization_length;
    qoff64_t fpos2 = sr.file_loc_init_value;
    if ( end < start || fpos2 > fsize || fsize-fpos2 < end-start )
      loader_failure("Wrong segment size %a..%a", start, end);
    file2base(li, fpos2, start, end, FILEREG_PATCHABLE);
    char buf[MAXSTR];
    char *name = get_space_name(li, h, sr.name.n_strx, buf, sizeof(buf));
    set_selector(i, 0);
    const char *sclass = strstr(name, "CODE") != nullptr ? CLASS_CODE : CLASS_DATA;

    segment_t s;
    s.sel      = setup_selector(i);
    s.start_ea = start;
    s.end_ea   = start + sr.subspace_length;
    s.align    = saRelByte;
    s.comb     = scPub;
    s.bitness  = 1; // 32-bit
    if ( !add_segm_ex(&s, name, sclass, ADDSEG_NOSREG|ADDSEG_SPARSE) )
      loader_failure("Failed to create segment %a..%a", s.start_ea, s.end_ea);

    if ( i == first_text_subspace_idx )
      first_text_subspace_fpos = sr.file_loc_init_value;
//    sr.alignment,
  }
}

//--------------------------------------------------------------------------
static void load_symbols(linput_t *li, const header &h, int32 fpos, int n)
{
  if ( n == 0 )
    return;
  qlseek(li, fpos);
  symbol_dictionary_record sr;
  validate_array_count_or_die(li, n, sizeof(sr), "Number of symbols", fpos);
  for ( int i=0; i < n; i++ )
  {
    lread(li, &sr, sizeof(sr));
    sr.swap();
    if ( sr.symbol_scope() == SS_UNSAT )
      continue;
    char buf[MAXSTR];
    char *name = get_symbol_name(li, h, sr.name.n_strx, buf, sizeof(buf));
    ea_t ea = sr.symbol_value & ~3;
    switch ( sr.symbol_type() )
    {
      case ST_NULL:
      case ST_ABSOLUTE:
        break;
      case ST_DATA:
        force_name(ea, name, SN_IDBENC);
        break;
      case ST_STUB:
        append_cmt(ea, "STUB", false);
        // fallthrough
      case ST_CODE:
      case ST_ENTRY:
      case ST_MILLICODE:
      case ST_MILLI_EXT:
        add_entry(ea, ea, name, true, AEF_IDBENC);
        add_entry(ea, ea, name, true, AEF_IDBENC);
        break;
      case ST_PRI_PROG:
      case ST_STORAGE:
      case ST_MODULE:
      case ST_SYM_EXT:
      case ST_ARG_EXT:
      case ST_PLABEL:
      case ST_OCT_DIS:
      case ST_TSTORAGE:
        break;
    }
  }
}

//--------------------------------------------------------------------------
static char *get_text_name(int nidx, char *buf, size_t bufsize)
{
  if ( nidx == -1 )
    return nullptr;
  if ( nidx >= 0 && nidx < dl_ssize )
    qstrncpy(buf, dl_strings + nidx, bufsize);
  else
    qsnprintf(buf, bufsize, "0x%08X", nidx);
  return buf;
}

//--------------------------------------------------------------------------
static void load_imports(linput_t *li, const dl_header &dl)
{
  if ( dl.import_list_count == 0 )
    return;
  qoff64_t fpos = first_text_subspace_fpos + dl.import_list_loc;
  qlseek(li, fpos);
  ea_t ea = data_start + dl.dlt_loc;
  int n = dl.dlt_count;
  import_entry ie;
  validate_array_count_or_die(li, dl.import_list_count, sizeof(ie), "Number of imports", fpos);
  for ( int i=0; i < dl.import_list_count; i++ )
  {
    lread(li, &ie, sizeof(ie));
    ie.swap();
    if ( n == 0 )
      ea = data_start + dl.plt_loc;
    n--;
    char buf[MAXSTR];
    buf[0] = '.';
    get_text_name(ie.name, &buf[1], sizeof(buf)-1);
    force_name(ea, buf, SN_IDBENC);
    create_dword(ea, 4);
    op_plain_offset(ea, 0, 0);
    if ( n > 0 )
    {
      ea += 4;
    }
    else
    {
      ea_t ea2 = get_dword(ea);
      force_name(ea2, &buf[1], SN_IDBENC);
      add_func(ea2);
      set_func_cmt(get_func(ea2), "THUNK", false);
      create_dword(ea+4, 4);
      ea += 8;
    }
  }
}

//--------------------------------------------------------------------------
static void load_exports(linput_t *li, const dl_header &dl)
{
  if ( dl.export_list_count == 0 )
    return;
  export_entry ee;
  qoff64_t fpos = first_text_subspace_fpos + dl.export_list_loc;
  qlseek(li, fpos);
  validate_array_count_or_die(li, dl.export_list_count, sizeof(ee), "Number of exports", fpos);
  for ( int i=0; i < dl.export_list_count; i++ )
  {
    lread(li, &ee, sizeof(ee));
    ee.swap();
    char buf[MAXSTR];
    const char *name = get_text_name(ee.name, buf, sizeof(buf));
    add_entry(ee.value, ee.value, name, ee.type == ST_CODE, AEF_IDBENC);
  }
}

//--------------------------------------------------------------------------
static void load_dl_header(linput_t *li)
{
  if ( first_text_subspace_fpos == -1 )
    return;
  qlseek(li, first_text_subspace_fpos);
  dl_header dl;
  lread(li, &dl, sizeof(dl));
  dl.swap();
  switch ( dl.hdr_version )
  {
    case OLD_HDR_VERSION: break;
    case HDR_VERSION:     break;
    default:
      msg("Unknown DL header version, skipping...\n");
  }
  if ( dl.string_table_size != 0 )
  {
    qoff64_t fpos = first_text_subspace_fpos + dl.string_table_loc;
    qlseek(li, fpos);
    dl_ssize = dl.string_table_size;
    validate_array_count_or_die(li, dl_ssize, 1, "String table size", fpos);
    dl_strings = (char *)qalloc(dl_ssize);
    if ( dl_strings == nullptr )
      nomem("dl_strings");
    lread(li, dl_strings, dl_ssize);
  }
  if ( dl.dreloc_count != 0 )
    complain_fixup();

  load_imports(li, dl);
  load_exports(li, dl);

  qfree(dl_strings);
  dl_strings = nullptr;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  set_processor_type("hppa", SETPROC_LOADER);

  header h;
  qlseek(li, 0);
  lread(li, &h, sizeof(h));
  h.swap();
  inf_set_baseaddr(0);

  fsize = qlsize(li);
  load_aux_headers(li, h.aux_header_location, h.aux_header_size);
  load_spaces(li, h, h.space_location, h.space_total);
  load_subspaces(li, h, h.subspace_location, h.subspace_total);
  load_symbols(li, h, h.symbol_location, h.symbol_total);
  load_dl_header(li);
  create_filename_cmt();

  size_t dp = h.presumed_dp;
  if ( dp == 0 )
  {
//  23 61 28 00   ldil            ...., %dp
//  37 7B 01 60   ldo             0xB0(%dp), %dp
    insn_t insn;
    if ( decode_insn(&insn, inf_get_start_ip()) > 0
      && insn.Op1.type == o_imm
      && insn.Op2.type == o_reg )
    {
      uval_t v = insn.Op1.value;
      if ( decode_insn(&insn, insn.ea+4) && insn.Op1.type == o_displ )
        dp = size_t(v + insn.Op1.addr);
    }
  }

  if ( dp != 0 )
    set_gotea(dp);

  add_til("hpux", ADDTIL_DEFAULT);

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
