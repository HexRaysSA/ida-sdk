
// read elf symbols

#include <fpro.h>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"
#include "debmod.h"
#include "symelf.hpp"

#include "../../ldr/elf/common.cpp"
#include "../../ldr/elf/reader.cpp"

inline uint32 low(uint32 x) { return x; }

uval_t imagebase;

//--------------------------------------------------------------------------
//lint -e{1764} could be declared const ref
static int handle_symbol(
        reader_t &reader,
        int shndx,
        int _info,
        uint32 st_name,
        uval_t st_value,
        slice_type_t slice_type,
        symbol_visitor_t &sv)
{
  if ( shndx == SHN_UNDEF
    || shndx == SHN_LOPROC
    || shndx == SHN_HIPROC
    || shndx == SHN_ABS )
  {
    return 0;
  }

  int type = ELF_ST_TYPE(_info);
  if ( type != STT_OBJECT && type != STT_FUNC )
    return 0;

  if ( st_name == 0 )
    return 0;

  if ( imagebase != uval_t(-1) )
    st_value -= imagebase;

  qstring name;
  reader.get_name(&name, slice_type, st_name);
  return sv.visit_symbol(st_value, name.c_str());
}

//--------------------------------------------------------------------------
static int load_symbols(
        reader_t &reader,
        const elf_shdr_t &section,
        slice_type_t slice_type,
        symbol_visitor_t &sv)
{
  int code = 0;
  sym_rel *sym;
  buffered_input_t<sym_rel> symbols_input(reader, section);
  for ( elf_sym_idx_t i = 0; code == 0 && symbols_input.next(sym); ++i )
  {
    if ( i == 0 ) // skip _UNDEF
      continue;

    code = handle_symbol(reader,
                         sym->original.st_shndx,
                         sym->original.st_info,
                         sym->original.st_name,
                         sym->original.st_value,
                         slice_type,
                         sv);
  }
  return code;
}

//--------------------------------------------------------------------------
static bool map_pht(reader_t &reader)
{
  if ( !reader.read_program_headers() )
    return false;

  imagebase = reader.pheaders.get_image_base();
  return true;
}

//----------------------------------------------------------------------------
static bool silent_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  return reader.is_warning(code); // resume after warnings
}

//--------------------------------------------------------------------------
static int _load_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  reader_t reader(li);
  reader.set_handler(silent_handler);
  if ( !reader.read_ident() || !reader.read_header() )
    return -1;

  const elf_ident_t &ident = reader.get_ident();
  uint8 elf_class = ident.elf_class;
  if ( elf_class != ELFCLASS32 && elf_class != ELFCLASS64 )
    return -1;

  uint8 elf_data_ord = ident.bytesex;
  if ( elf_data_ord != ELFDATA2LSB && elf_data_ord != ELFDATA2MSB )
    return -1;

  section_headers_t &sections = reader.sections;
  dynamic_linking_tables_t dlt;

  int code = 0;
  elf_ehdr_t &header = reader.get_header();
  if ( header.has_pht() && !map_pht(reader) )
    return -1;

  reader.read_section_headers();

  // Try and acquire dynamic linking tables info.
  dlt = reader.sections.get_dynamic_linking_tables_info();
  if ( !dlt.is_valid() )
    dlt = reader.pheaders.get_dynamic_linking_tables_info();

  // Parse dynamic info if available
  dynamic_info_t di;
  if ( dlt.is_valid() )
  {
    reader_t::dyninfo_tags_t dyninfo_tags;
    dyninfo_tags.reserve(10);
    if ( reader.read_dynamic_info_tags(&dyninfo_tags, dlt)
      && reader.parse_dynamic_info(&di, dyninfo_tags)
      && (sv.velf & VISIT_DYNINFO) != 0 )
    {
      reader.set_di_strtab(reader.dyn_strtab, di.strtab());
      typedef reader_t::dyninfo_tags_t::const_iterator const_it;
      for ( const_it dyn = dyninfo_tags.begin();
            dyn != dyninfo_tags.end();
            ++dyn )
      {
        qstring name;
        switch ( dyn->d_tag )
        {
          case DT_SONAME:
          case DT_RPATH:
          case DT_RUNPATH:
          case DT_NEEDED:
            reader.get_name(&name, reader.dyn_strtab, uint32(dyn->d_un));
            break;
        }
        if ( sv.visit_dyninfo(dyn->d_tag, name.c_str(), dyn->d_un) != 0 )
          break;
      };
    }
  }

  if ( (sv.velf & VISIT_INTERP) != 0 )
  {
    elf_shdr_t *interp_sh = reader.sections.get_wks(WKS_INTERP);
    if ( interp_sh != nullptr )
    {
      qstring name;
      reader.get_string_at(&name, interp_sh->sh_offset);
      code = sv.visit_interp(name.c_str());
      if ( code != 0 )
        return code;
    }
  }

  if ( (sv.velf & VISIT_SYMBOLS) != 0 )
  {
    elf_shndx_t symtab = sections.get_index(WKS_SYMTAB);
    elf_shndx_t dynsym = sections.get_index(WKS_DYNSYM);
    elf_shdr_t fake_section;
    if ( symtab != 0 || dynsym != 0 )
    {
      // Loading symbols
      if ( symtab != 0 )
        code = load_symbols(reader, *sections.getn(symtab), SLT_SYMTAB, sv);
      if ( code == 0 && dynsym != 0 )
        code = load_symbols(reader, *sections.getn(dynsym), SLT_DYNSYM, sv);
    }
    else if ( di.fill_section_header(&fake_section, DIT_SYMTAB) )
    {
      code = load_symbols(reader, fake_section, SLT_DYNSYM, sv);
    }
  }

  notes_t notes(&reader);
  if ( (sv.velf & VISIT_BUILDID) != 0 && reader.read_notes(&notes) )
  {
    qstring id;
    if ( notes.get_build_id(&id) )
    {
      code = sv.visit_buildid(id.c_str());
      if ( code != 0 )
        return code;
    }
  }

  if ( (sv.velf & VISIT_DBGLINK ) != 0 )
  {
    uint32 crc;
    qstring debuglink;
    if ( sections.is_initialized()
      && sections.read_gnu_debuglink(&debuglink, &crc) )
    {
      code = sv.visit_debuglink(debuglink.c_str(), crc);
      if ( code != 0 )
        return code;
    }
  }

  return code;
}

//--------------------------------------------------------------------------
static int load_linput_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  if ( li == nullptr )
    return -1;
  int code;
  // there is thread unsafe code in elf handling, so use locks
  lock_begin();
  {
    code = _load_elf_symbols(li, sv);
  }
  lock_end();
  close_linput(li);
  return code;
}

//--------------------------------------------------------------------------
int load_elf_symbols(const char *fname, symbol_visitor_t &sv, bool remote)
{
  return load_linput_elf_symbols(open_linput(fname, remote), sv);
}
