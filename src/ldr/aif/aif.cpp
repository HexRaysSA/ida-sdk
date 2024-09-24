/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 *      ARM Image File (AIF) Loader
 *      ---------------------------
 *      This module allows IDA to load ARM image files into
 *      its database and to disassemble them correctly.
 *
 *      NOTE: Compressed image files are not supported
 *            Self-relocating image files are not supported
 *            Thumb image files are not supported
 *            Only 32-bit image files are supported
 *
 *      This module automatically detects the byte sex and sets inf.mf
 *      variable accrodingly.
 *
 *      The debug information is partially processed.
 *
 */

#include <stddef.h>
#include "../idaldr.h"
#include "aif.h"
#include "../aof/aof.h"

// the following function is defined to be used by aifcmn.cpp
// included below (see also efd/aif.cpp)
inline bool is_mf()  { return inf_is_be(); }

#include "aifcmn.cpp"

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  if ( !is_aif_file(li) )
    return 0;

  *fileformatname = "ARM Image File";
  *processor      = "arm";
  return 1;
}

//--------------------------------------------------------------------------
// Create a section.
static void create_section(
        ushort sel,
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
  s.bitness = 1; // 32-bit
  int flags = ADDSEG_SPARSE | ADDSEG_NOSREG | ADDSEG_NOTRUNC;
  if ( !add_segm_ex(&s, name, classname, flags) )
    loader_failure();

  segment_t *sptr = getseg(start_ea);
  set_arm_segm_flags(start_ea, 2 << 10); // alignment
  sptr->update();
}

//--------------------------------------------------------------------------
// The assembler and the compiler generate lots of meaningless symbols.
// We will ignore them.
static bool special_name(const char *name)
{
  int i;
  if ( name[0] == '\0' )
    return true;
  if ( name[0] == '$' )
    return true;
  const char *ptr = strchr(name,'$');
  if ( ptr != nullptr && ptr[1] == '$' )
    return true;

  static const char *const ex[] =
  {
    "_etext",
    "_edata",
    "_end",
    "!!!"
  };
  for ( i=0; i < qnumber(ex); i++ )
    if ( strcmp(ex[i],name) == 0 )
      return true;

  static const char *const data_names[] = { "x$constdata", "x$litpool" };
  for ( i=0; i < qnumber(data_names); i++ )
    if ( strncmp(name, data_names[i], strlen(data_names[i])) == 0 )
      return true;

  return false;
}

//--------------------------------------------------------------------------
// The debug information says that "xlitpool" symbols have "CODE" type.
// We cannot base on this because doing so we would convert
// xlitpools to instructions.
// So, we will look at the names and if a location has
// "xlitpool" or similar name, we will not convert it to instructions
// even it is marked as "CODE".
//
// Later: I decided not to use all those names at all.

static bool is_true_text_symbol(dsym_t *ds, const char *name)
{
  if ( ds->is_text() )
  {
    static const char *const data_names[] = { "x$constdata", "x$litpool" };
    for ( int i=0; i < qnumber(data_names); i++ )
      if ( strncmp(name,data_names[i],strlen(data_names[i])) == 0 )
        return false;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Process debugging information item and try to incorporate it into
// the database.
// NOTE: This function does not process all debugging information.
//        It knows only about some types of debugingo.
static size_t process_item(uchar *di, size_t disize, section_t *sect)
{
  uchar *const end = di + disize;
  if ( disize < 4 )
    return 0;
  uint32 fw = *(uint32 *)di;
  if ( inf_is_be() )
    fw = swap32(fw);
  size_t len = fw >> 16;
  if ( len == 0 || len > disize )
    return 0;
  switch ( fw & 0xFFFF )
  {
    case AIF_DEB_SECT:  // section
      if ( disize < sizeof(section_t) )
        return 0;
      sect = (section_t *)di;
      if ( inf_is_be() )
        swap_section(sect);
      if ( sect->debugsize != 0 )
      {
        len = sect->debugsize;
        if ( len > disize )
          return 0;
      }
      switch ( sect->lang )
      {
        case LANG_C:
          add_extra_cmt(sect->codestart, true, "C source level debugging data is present");
          break;
        case LANG_PASCAL:
          add_extra_cmt(sect->codestart, true, "Pascal source level debugging data is present");
          break;
        case LANG_FORTRAN:
          add_extra_cmt(sect->codestart, true, "Fortran-77 source level debugging data is present");
          break;
        case LANG_ASM:
          add_extra_cmt(sect->codestart, true, "ARM assembler line number data is present");
          break;
      }
      if ( sect->lang == LANG_NONE )
      {
        size_t nsyms = size_t(sect->name);
        dsym_t *ds = (dsym_t *)(sect+1);
        char *str = (char *)(ds+nsyms);
        if ( !is_mul_ok(nsyms, sizeof(dsym_t)) || ds+nsyms < ds || str >= (char *)end )
          return 0;
        bool use_pascal = swap_symbols(ds, str, end, nsyms);
        for ( int i=0; i < nsyms; i++,ds++ )
        {
          if ( ds->sym & ASD_16BITSYM )
            continue;
          size_t off = size_t(ds->sym & ASD_SYMOFF);
          char *name = str + off + use_pascal;
          if ( name < str || name >= (char *)end )
            continue;
          if ( special_name(name) )
            continue;
          if ( ds->sym == ASD_ABSSYM ) // if the symbol is absolute
          {
            add_pgm_cmt("%s = 0x%X", name, ds->value);
          }
          else if ( is_mapped(ds->value) )
          {
            if ( ds->sym & ASD_GLOBSYM )
            {
              add_entry(ds->value, ds->value, name, is_true_text_symbol(ds, name), AEF_IDBENC);
            }
            else
            {
              force_name(ds->value, name, SN_IDBENC);
              if ( is_true_text_symbol(ds, name) )
                auto_make_code(ds->value);
            }
          }
        }
      }
      else
      {
        char name[64];
        const uchar *nptr = (const uchar *)&sect->name;
        size_t namelen = *nptr++;
        if ( namelen > end-nptr || namelen >= sizeof(name) )
          return 0;
        qstrncpy(name, (const char *)nptr, sizeof(name));
        name[namelen] = '\0';
        if ( sect->codestart != 0 )
          add_extra_cmt(sect->codestart, true, "Section \"%s\", size 0x%X",name,sect->codesize);
        if ( sect->datastart != 0 )
          add_extra_cmt(sect->datastart, true, "Section \"%s\", size 0x%X",name,sect->datasize);
      }
#if 0
      if ( sect->fileinfo != 0 ) // fileinfo is present?
        process_item(di+size_t(sect->fileinfo),sect);
#endif
      break;
    case AIF_DEB_FDEF:  // procedure/function definition
      deb(IDA_DEBUG_LDR, "procedure/function definition\n");
      break;
    case AIF_DEB_ENDP:  // endproc
      deb(IDA_DEBUG_LDR, "endproc\n");
      break;
    case AIF_DEB_VAR:   // variable
      deb(IDA_DEBUG_LDR, "variable\n");
      break;
    case AIF_DEB_TYPE:  // type
      deb(IDA_DEBUG_LDR, "type\n");
      break;
    case AIF_DEB_STRU:  // struct
      deb(IDA_DEBUG_LDR, "struct\n");
      break;
    case AIF_DEB_ARRAY: // array
      deb(IDA_DEBUG_LDR, "array\n");
      break;
    case AIF_DEB_RANGE: // subrange
      deb(IDA_DEBUG_LDR, "subrange\n");
      break;
    case AIF_DEB_SET:   // set
      deb(IDA_DEBUG_LDR, "set\n");
      break;
    case AIF_DEB_FILE:  // fileinfo
      deb(IDA_DEBUG_LDR, "fileinfo\n");
      break;
    case AIF_DEB_CENUM: // contiguous enumeration
      deb(IDA_DEBUG_LDR, "contiguous enumeration\n");
      break;
    case AIF_DEB_DENUM: // discontiguous enumeration
      deb(IDA_DEBUG_LDR, "discontiguous enumeration\n");
      break;
    case AIF_DEB_FDCL:  // procedure/function declaration
      deb(IDA_DEBUG_LDR, "procedure/function declaration\n");
      break;
    case AIF_DEB_SCOPE: // begin naming scope
      deb(IDA_DEBUG_LDR, "begin naming scope\n");
      break;
    case AIF_DEB_ENDS:  // end naming scope
      deb(IDA_DEBUG_LDR, "end naming scope\n");
      break;
    case AIF_DEB_BITF:  // bitfield
      deb(IDA_DEBUG_LDR, "bitfield\n");
      break;
    case AIF_DEB_MACRO: // macro definition
      deb(IDA_DEBUG_LDR, "macro definition\n");
      break;
    case AIF_DEB_ENDM:  // macro undefinition
      deb(IDA_DEBUG_LDR, "macro undefinition\n");
      break;
    case AIF_DEB_CLASS: // class
      deb(IDA_DEBUG_LDR, "class\n");
      break;
    case AIF_DEB_UNION: // union
      deb(IDA_DEBUG_LDR, "union\n");
      break;
    case AIF_DEB_FPMAP: // FP map fragment
      deb(IDA_DEBUG_LDR, "FP map fragment\n");
      break;
    default:
      msg("unknown (0x%u.)!!!\n", fw & 0xFFFF);
      break;
  }
  return len;
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
  aif_header_t hd;
  inf_set_app_bitness(32);
  set_processor_type("arm", SETPROC_LOADER);
  lread(li, &hd, sizeof(hd));
  inf_set_be(match_zero_code(&hd) != 1);
  if ( (hd.address_mode & 0xFF) != 32 )
  {
    if ( (hd.address_mode & 0xFF) != 0 )
      loader_failure("26-bit modules are not supported");
    msg("Old AIF format file...");
  }
  if ( hd.decompress_code != NOP )
    loader_failure("Compressed modules are not supported");
  if ( hd.self_reloc_code != NOP )
    loader_failure("Self-relocating modules are not supported");

  inf_set_baseaddr(0);
  int isexec = is_bl(hd.entry_point);
  qoff64_t offset = sizeof(aif_header_t);
  ea_t start = hd.image_base;
  if ( isexec )
  {
    start += sizeof(aif_header_t);
    hd.readonly_size -= sizeof(aif_header_t);
  }
  uint64 rest = qlsize(li) - offset;
  if ( rest < hd.readonly_size )
BAD_FILE:
    loader_failure("Corrupted file");
  ea_t end = start + hd.readonly_size;
  file2base(li, offset, start, end, FILEREG_PATCHABLE);
  create_section(1, start, end, NAME_CODE, CLASS_CODE);
  offset += hd.readonly_size;
  if ( hd.readwrite_size != 0 )
  {
    rest = qlsize(li) - offset;
    if ( rest < hd.readwrite_size )
      goto BAD_FILE;
    start = (hd.address_mode & AIF_SEP_DATA) ? hd.data_base : end;
    end = start + hd.readwrite_size;
    file2base(li, offset, start, end, FILEREG_PATCHABLE);
    create_section(2, start, end, NAME_DATA, CLASS_DATA);
    offset += hd.readwrite_size;
  }
  if ( hd.zero_init_size != 0 )
  {
    start = end;
    end = start + hd.zero_init_size;
    create_section(3, start, end, NAME_BSS, CLASS_BSS);
  }
  create_filename_cmt();

  if ( isexec )
    hd.entry_point = hd.image_base
                   + offsetof(aif_header_t,entry_point)
                   + ((hd.entry_point & ~BLMASK) << 2)
                   + 8;
  inf_set_start_cs(1);
  inf_set_start_ip(hd.entry_point);
  inf_set_start_ea(hd.entry_point);

  validate_array_count(li, &hd.debug_size, 1, "Size of debug info", offset);
  if ( hd.debug_size != 0 )
  {
    msg("Debugging information is present (%u bytes at file offset 0x%" FMT_64 "X)...\n",
                                                        hd.debug_size, offset);
    uchar *di = qalloc_array<uchar>(size_t(hd.debug_size));
    if ( di == nullptr )
      nomem("AIF debugging info");
    qlseek(li, offset);
    lread(li, di, size_t(hd.debug_size));
    uchar *ptr = di;
    uchar *diend = di + size_t(hd.debug_size);
    section_t *sect = nullptr;
    while ( ptr < diend )
    {
      size_t len = process_item(ptr, diend-ptr, sect);
      if ( len == 0 )
      {
        warning("Corrupted debug info");
        break;
      }
      ptr += len;
    }
    qfree(di);
  }
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
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
