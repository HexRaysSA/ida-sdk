
#ifndef ELF_READER_CPP
#define ELF_READER_CPP

#include <functional>

#include <pro.h>
#include <diskio.hpp>

#include "elfbase.h"
#include "elf.h"
#include "elfr_arm.h"
#include "elfr_mips.h"
#include "elfr_ia64.h"
#include "elfr_ppc.h"
#include "../idaldr.h"

//----------------------------------------------------------------------------
ssize_t reader_t::prepare_error_string(
        char *buf,
        size_t bufsize,
        reader_t::errcode_t code,
        va_list va) const
{
  int len;
  switch ( code )
  {
    case BAD_CLASS:
      {
        int eclass = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "Unknown ELF class %d (should be %d for 32-bit, %d for 64-bit)",
                        eclass,
                        ELFCLASS32,
                        ELFCLASS64);
      }
      break;
    case BAD_ENDIANNESS:
      {
        int endian = va_arg(va, int);
        if ( endian != ELFDATA2LSB && endian != ELFDATA2MSB )
          len = qsnprintf(buf, bufsize,
                          "Unknown ELF byte sex %d (should be %d for LSB, %d for MSB)",
                          endian,
                          ELFDATA2LSB,
                          ELFDATA2MSB);
        else
          len = qsnprintf(buf, bufsize,
                          "Bad ELF byte sex %d for the indicated machine",
                          endian);
      }
      break;
    case BAD_EHSIZE:
      {
        int sz = va_arg(va, int);
        int fb = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "The ELF header entry size is invalid (%d, expected %d)",
                        sz, fb);
      }
      break;
    case BAD_PHENTSIZE:
      {
        int sz = va_arg(va, int);
        int fb = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "PHT entry size is invalid: %d. Falling back to %d",
                        sz, fb);
      }
      break;
    case BAD_PHLOC:
      len = qstpncpy(buf, "The PHT table size or offset is invalid", bufsize) - buf;
      break;
    case BAD_SHENTSIZE:
      len = qstpncpy(buf, "The SHT entry size is invalid", bufsize) - buf;
      break;
    case BAD_SHLOC:
      len = qstpncpy(buf, "SHT table size or offset is invalid", bufsize) - buf;
      break;
    case BAD_DYN_PLT_TYPE:
      len = qsnprintf(buf, bufsize, "Bad DT_PLTREL value (%d)", va_arg(va, int));
      break;
    case CONFLICTING_FILE_TYPE:
      len = qstpncpy(buf, "ELF file with PHT cannot be ET_REL", bufsize) - buf;
      break;
    case BAD_SHSTRNDX:
      {
        uint idx = va_arg(va, uint);
        uint num = va_arg(va, uint);
        len = qsnprintf(buf, bufsize,
                        "Section header string table index %u is out of bounds",
                        idx);
        if ( num > 0 )
          len += qsnprintf(buf + len, bufsize - len,
                           " (max %u)", num - 1);
      }
      break;
    case ERR_READ:
      {
        size_t d1 = va_arg(va, size_t); // size
        size_t d2 = va_arg(va, size_t); // return code
        qnotused(d1);
        qnotused(d2);
        len = qsnprintf(buf, bufsize,
                        "Bad file structure or read error (offset %" FMT_64 "u)",
                        va_arg(va, int64));
      }
      break;
    default:
      if ( is_error(code) )
        INTERR(20034);
      len = qsnprintf(buf, bufsize, "Unknown ELF warning %d", code);
      break;
  }
  return len;
}

//----------------------------------------------------------------------------
static bool default_error_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  va_list va;
  va_start(va, code);
  char buf[MAXSTR];
  reader.prepare_error_string(buf, sizeof(buf), code, va);
  va_end(va);

  warning("%s", buf);
  return reader.is_warning(code); // resume after warnings
}

//----------------------------------------------------------------------------
const qstring &sym_rel::get_original_name(const reader_t &reader) const
{
  if ( original_name.empty() )
  {
    symrel_idx_t sym_idx = reader.symbols.get_idx(this);
    reader.get_name(&original_name, sym_idx.type, original.st_name);
  }

  return original_name;
}

//----------------------------------------------------------------------------
ea_t sym_rel::get_ea(const reader_t &reader, ea_t _debug_segbase) const
{
  ea_t ea = value;
  if ( reader.is_valid_rel_file() || is_psp_file(reader) )
  {
    const elf_shdr_t *sh = reader.sections.getn(sec);
    if ( sh != nullptr )
      ea += sh->sh_addr;
  }
  else
  {
    ea += _debug_segbase;
  }
  return ea;
}

//----------------------------------------------------------------------------
void sym_rel::set_section_index(const reader_t &reader)
{
  sec = 0;
  if ( original.st_shndx == SHN_XINDEX )
  {
    symrel_idx_t sym_idx = reader.symbols.get_idx(this);
    const elf_shdr_t *sh_shndx;
    switch ( sym_idx.type )
    {
      case SLT_SYMTAB:
        sh_shndx = reader.sections.get_wks(WKS_SYMTAB_SHNDX);
        break;
      case SLT_DYNSYM:
        sh_shndx = reader.sections.get_wks(WKS_DYNSYM_SHNDX);
        break;
      default:
        INTERR(20088);
    }
    // doc: "The section is an array of Elf32_Word values."
    uint64 offset = sym_idx.idx * sizeof(uint32);
    if ( sh_shndx != nullptr
      && sh_shndx->sh_offset != 0
      && offset < sh_shndx->sh_size )
    {
      sec = reader.get_shndx_at(sh_shndx->sh_offset + offset);
    }
    if ( sec == 0 )
    {
      warning("AUTOHIDE SESSION\n"
              "Illegal section indirect index for symbol %u",
              sym_idx.idx);
    }
  }
  else if ( original.st_shndx < SHN_LORESERVE )
  {
    sec = original.st_shndx;
  }
}

//----------------------------------------------------------------------------
reader_t::reader_t(linput_t *_li, int64 _start_in_file)
    : pheaders(this),
      sections(this),
      sym_strtab(),
      dyn_strtab(),
      li(_li),
      sif(_start_in_file),
      mappings(),
      arch_specific(nullptr),
      load_bias(0),
      eff_msb(false),
      eff_64(false),
      seg_64(false)
{
  set_handler(default_error_handler);
  filesize = qlsize(li);
}

//----------------------------------------------------------------------------
bool reader_t::is_warning(errcode_t code) const
{
  return code <= LAST_WARNING;
}

//----------------------------------------------------------------------------
bool reader_t::is_error(errcode_t code) const
{
  QASSERT(20035, code <= LAST_ERROR);
  return code > LAST_WARNING;
}

//-------------------------------------------------------------------------
static bool _silent_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  return reader.is_warning(code); // resume after warnings
}

//----------------------------------------------------------------------------
void reader_t::set_handler(bool (*_handler)(const reader_t &reader, errcode_t code, ...))
{
  handle_error = _handler == nullptr ? _silent_handler : _handler;
}

bool reader_t::read_ident()
{
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(0) == -1 )
    return false;

  uint64 fsize = size();
  uint64 fpos = tell();
  if ( fpos >= fsize )
    return false;
  uint64 bytes_left = fsize - fpos;
  if ( bytes_left < sizeof(elf_ident_t) )
    return false;

  memset(&header, 0, sizeof(header));

  if ( qlread(li, &header.e_ident, sizeof(elf_ident_t)) != sizeof(elf_ident_t) )
    return false;

  if ( !header.e_ident.is_valid() )
    return false;

  size_t ehdr_sz = is_64() ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
  if ( bytes_left < ehdr_sz )
    return false;

  return true;
}

//----------------------------------------------------------------------------
int reader_t::safe_read(void *buf, size_t sz, bool apply_endianness) const
{
  int rc = lreadbytes(li, buf, sz, apply_endianness && is_msb());
  if ( rc < 0 )
    handle_error(*this, ERR_READ, sz, size_t(rc), qltell(li));
  return rc;
}

//----------------------------------------------------------------------------
int reader_t::read_addr(void *buf) const
{
  return safe_read(buf, stdsizes.types.elf_addr);
}

//----------------------------------------------------------------------------
int reader_t::read_off(void *buf) const
{
  return safe_read(buf, stdsizes.types.elf_off);
}

//----------------------------------------------------------------------------
int reader_t::read_xword(void *buf) const
{
  return safe_read(buf, stdsizes.types.elf_xword);
}

//----------------------------------------------------------------------------
int reader_t::read_sxword(void *buf) const
{
  return safe_read(buf, stdsizes.types.elf_sxword);
}

//----------------------------------------------------------------------------
int reader_t::read_word(uint32 *buf) const
{
  return safe_read(buf, 4);
}

//----------------------------------------------------------------------------
int reader_t::read_half(uint16 *buf) const
{
  return safe_read(buf, 2);
}

//----------------------------------------------------------------------------
int reader_t::read_byte(uint8 *buf) const
{
  return safe_read(buf, 1);
}

//-------------------------------------------------------------------------
int reader_t::read_symbol(elf_sym_t *buf) const
{
#define _safe(expr) if ( (expr) < 0 ) goto FAILED_RS
  if ( is_64() )
  {
    _safe(read_word(&buf->st_name));
    _safe(read_byte(&buf->st_info));
    _safe(read_byte(&buf->st_other));
    _safe(read_half(&buf->st_shndx));
    _safe(read_addr(&buf->st_value));
    _safe(read_xword(&buf->st_size));
  }
  else
  {
    _safe(read_word(&buf->st_name));
    _safe(read_addr(&buf->st_value));
    _safe(read_word((uint32 *) &buf->st_size));
    _safe(read_byte(&buf->st_info));
    _safe(read_byte(&buf->st_other));
    _safe(read_half(&buf->st_shndx));
  }
  return 0;
FAILED_RS:
  return -1;
#undef _safe
}

#define IS_EXEC_OR_DYN(x) ((x) == ET_EXEC || (x) == ET_DYN)

struct linuxcpu_t
{
  uint16 machine;
  bool msb;
  bool _64;
};

static const linuxcpu_t lincpus[] =
{
// machine      msb   64
  { EM_386,    false, false },
  { EM_486,    false, false },
  { EM_X86_64, false, true  },
};

//----------------------------------------------------------------------------
// Linux kernel loader ignores class and endian fields for some(?) processors.
// check for such situation and set the effective endiannes/bitness
bool reader_t::check_ident()
{
  for ( size_t i = 0; i < qnumber(lincpus); i++ )
  {
    bool swap;
    if ( eff_msb == lincpus[i].msb
      && header.e_machine == lincpus[i].machine
      && IS_EXEC_OR_DYN(header.e_type) )
    {
      swap = false;
    }
    else if ( eff_msb != lincpus[i].msb
           && swap16(header.e_machine) == lincpus[i].machine
           && IS_EXEC_OR_DYN(swap16(header.e_type)) )
    {
      swap = true;
    }
    else
    {
      continue;
    }
    // Found the matching machine
    if ( swap )
    {
      header.e_machine = swap16(header.e_machine);
      header.e_type    = swap16(header.e_type);
      if ( !handle_error(*this, BAD_ENDIANNESS, header.e_ident.bytesex) )
        return false;
      eff_msb = lincpus[i].msb;
    }
    // segment bitness can be different from elf bitness: apparently there
    // are some files like that in the wild (see pc_odd_bitness_64.elf)
    seg_64 = lincpus[i]._64;
    // assume elf32 for EM_386/EM_486
    if ( !seg_64 )
      eff_64 = false;
    break;
  }
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_header()
{
  // 32/64
  uint8 elf_class = get_ident().elf_class;
  if ( elf_class != ELFCLASS32
    && elf_class != ELFCLASS64 )
  {
    if ( !handle_error(*this, BAD_CLASS, elf_class) )
      return false;
  }
  // lsb/msb
  uint8 elf_do = get_ident().bytesex;
  if ( elf_do != ELFDATA2LSB
    && elf_do != ELFDATA2MSB )
  {
    if ( !handle_error(*this, BAD_ENDIANNESS, elf_do) )
      return false;
  }

  input_status_t save_excursion(*this);
  if ( save_excursion.seek(sizeof(elf_ident_t)) == -1 )
    return false;

  // set the default values from ident
  eff_msb = elf_do == ELFDATA2MSB;
  eff_64  = elf_class == ELFCLASS64;
  seg_64  = eff_64;

  // Read the type and machine
#define _safe(expr) if ( (expr) < 0 ) goto FAILED
  _safe(read_half(&header.e_type));
  _safe(read_half(&header.e_machine));

  if ( !check_ident() )
    return false;

  _eah.setup(eff_64);

  // Define sizes
  if ( !is_64() )
  {
    stdsizes.ehdr           = sizeof(Elf32_Ehdr);
    stdsizes.phdr           = sizeof(Elf32_Phdr);
    stdsizes.shdr           = sizeof(Elf32_Shdr);
    stdsizes.entries.sym    = sizeof(Elf32_Sym);
    stdsizes.entries.dyn    = sizeof(Elf32_Dyn);
    stdsizes.entries.rel    = sizeof(Elf32_Rel);
    stdsizes.entries.rela   = sizeof(Elf32_Rela);
    stdsizes.types.elf_addr = 4;
    stdsizes.types.elf_off  = 4;
    stdsizes.types.elf_xword= 4;
    stdsizes.types.elf_sxword=4;
  }
  else
  {
    stdsizes.ehdr           = sizeof(Elf64_Ehdr);
    stdsizes.phdr           = sizeof(Elf64_Phdr);
    stdsizes.shdr           = sizeof(Elf64_Shdr);
    stdsizes.entries.sym    = sizeof(Elf64_Sym);
    stdsizes.entries.dyn    = sizeof(Elf64_Dyn);
    stdsizes.entries.rel    = sizeof(Elf64_Rel);
    stdsizes.entries.rela   = sizeof(Elf64_Rela);
    stdsizes.types.elf_addr = 8;
    stdsizes.types.elf_off  = 8;
    stdsizes.types.elf_xword= 8;
    stdsizes.types.elf_sxword=8;
  }
  stdsizes.dyn.sym  = stdsizes.entries.sym;
  stdsizes.dyn.rel  = stdsizes.entries.rel;
  stdsizes.dyn.rela = stdsizes.entries.rela;

  // Read the rest of the header
  _safe(read_word(&header.e_version));
  _safe(read_addr(&header.e_entry));
  _safe(read_off (&header.e_phoff));
  _safe(read_off (&header.e_shoff));
  _safe(read_word(&header.e_flags));
  _safe(read_half(&header.e_ehsize));
  _safe(read_half(&header.e_phentsize));
  _safe(read_half(&header.e_phnum));
  _safe(read_half(&header.e_shentsize));
  _safe(read_half(&header.e_shnum));
  _safe(read_half(&header.e_shstrndx));
#undef _safe

  if ( header.e_ehsize != stdsizes.ehdr )
    if ( !handle_error(*this, BAD_EHSIZE, header.e_ehsize, stdsizes.ehdr) )
    {
FAILED:
      return false;
    }

  // Sanitize PHT parameters
  if ( (header.e_phnum == 0) != (header.e_phoff == 0) )
  {
    if ( !handle_error(*this, BAD_PHLOC, header.e_phnum, header.e_phoff) )
      goto FAILED;
    header.set_no_pht();
  }
  if ( header.has_pht() && header.e_phentsize != stdsizes.phdr )
  {
    if ( !handle_error(*this, BAD_PHENTSIZE, header.e_phentsize, stdsizes.phdr)
      || header.e_phentsize < stdsizes.phdr )
    {
      goto FAILED;
    }
    header.e_phentsize = stdsizes.phdr;
  }

  // process large number of sections
  // "System V Application Binary Interface - DRAFT - 19 October 2010"
  // If the number of sections is greater than or equal to SHN_LORESERVE
  // (0xff00), this member has the value zero and the actual number of
  // section header table entries is contained in the sh_size field of the
  // section header at index 0. (Otherwise, the sh_size member of the
  // initial entry contains 0.)
  elf_shdr_t sh0;
  bool is_sh0_read;
  if ( header.e_shnum == 0
    && header.e_shoff != 0
    && seek(header.e_shoff) != -1
    && read_section_header(&sh0)
    && sh0.sh_type == SHT_NULL )
  {
    is_sh0_read = true;
    header.real_shnum = sh0.sh_size;
  }
  else
  {
    is_sh0_read = false;
    header.real_shnum = header.e_shnum;
  }

  // Sanitize SHT parameters
  if ( (header.real_shnum == 0) != (header.e_shoff == 0) )
  {
    if ( !handle_error(*this, BAD_SHLOC, header.real_shnum, header.e_shoff, size()) )
      goto FAILED;
    header.set_no_sht(); // do not use sht
  }
  if ( header.has_sht() && header.e_shentsize != stdsizes.shdr )
  {
    if ( !handle_error(*this, BAD_SHENTSIZE, header.e_shentsize, stdsizes.shdr)
      || header.e_shentsize < stdsizes.shdr )
    {
      header.set_no_sht(); // do not use sht
    }
  }
  {
    uint64 sections_start  = header.e_shoff;
    uint64 sections_finish = header.e_shoff + uint64(header.real_shnum) * header.e_shentsize;
    if ( sections_start > sections_finish || sections_finish > size() )
    {
      if ( !handle_error(*this, BAD_SHLOC, header.real_shnum, header.e_shoff, size()) )
        goto FAILED;
      header.set_no_sht(); // do not use sht
    }
  }

  if ( header.has_sht() )
  {
    // process large section name string table section index
    // "System V Application Binary Interface - DRAFT - 19 October 2010"
    // If the section name string table section index is greater than or equal
    // to SHN_LORESERVE (0xff00), this member has the value SHN_XINDEX
    // (0xffff) and the actual index of the section name string table section
    // is contained in the sh_link field of the section header at index 0.
    // (Otherwise, the sh_link member of the initial entry contains 0.)
    if ( header.e_shstrndx == SHN_XINDEX && is_sh0_read && sh0.sh_link != 0 )
      header.real_shstrndx = sh0.sh_link;
    else
      header.real_shstrndx = header.e_shstrndx;

    // Sanitize SHT string table index
    if ( header.real_shstrndx > 0
      && header.real_shstrndx >= header.real_shnum )
    {
      if ( !handle_error(*this, BAD_SHSTRNDX, uint(header.real_shstrndx), uint(header.real_shnum)) )
        goto FAILED;
      header.real_shstrndx = 0;
    }
  }

  //
  if ( header.has_pht() && header.e_type == ET_REL )
  {
    if ( !handle_error(*this, CONFLICTING_FILE_TYPE) )
      goto FAILED;
  }

  //
  switch ( header.e_machine )
  {
    case EM_AARCH64:
      // AARCH64 files must use 64-bit segments even for ELF32 (ILP32)
      seg_64 = true;
      // fallthrough
    case EM_ARM:
      delete arch_specific;
      arch_specific = new arm_arch_specific_t;
      break;
    case EM_MIPS:
    case EM_CISCO7200: // Cisco 7200 Series Router (MIPS)
    case EM_CISCO3620: // Cisco 3620/3640 Router (MIPS)
      if ( (header.e_flags & EF_MIPS_ABI) == E_MIPS_ABI_O64 )
        seg_64 = true;
      arch_specific = new arch_specific_t; // Dummy
      break;
    default:
      arch_specific = new arch_specific_t; // Dummy
      break;
  }
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_section_header(elf_shdr_t *sh)
{
#define _safe(expr) if ( expr < 0 ) return false;
  _safe(read_word (&sh->sh_name));
  _safe(read_word (&sh->sh_type));
  _safe(read_xword(&sh->sh_flags));
  _safe(read_addr (&sh->sh_addr));
  _safe(read_off  (&sh->sh_offset));
  _safe(read_xword(&sh->sh_size));
  _safe(read_word (&sh->sh_link));
  _safe(read_word (&sh->sh_info));
  _safe(read_xword(&sh->sh_addralign));
  _safe(read_xword(&sh->sh_entsize));
#undef _safe
  return true;
}

//-------------------------------------------------------------------------
bool reader_t::read_compression_header(elf_chdr_t *out)
{
#define _safe(expr) if ( expr < 0 ) return false;
  _safe(read_word(&out->ch_type));
  if ( is_64() )
    _safe(read_word(&out->ch_reserved));
  _safe(read_xword(&out->ch_size));
  _safe(read_xword(&out->ch_addralign));
#undef _safe
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_section_headers()
{
  if ( !header.has_sht() )
    return false;
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(header.e_shoff) == -1 )
    return false;

  sections.resize(header.real_shnum);

  sections.initialized = true;

  for ( elf_shndx_t i = 0; i < header.real_shnum; i++ )
  {
    if ( !seek_to_section_header(i) )
      return false;

    elf_shdr_t *sh = sections.getn(i);
    if ( !read_section_header(sh) )
      return false;
  }

  // in the first pass we store WKS_SYMTAB/WKS_DYNSYM to process sections
  // of type SHT_SYMTAB_SHNDX in the second pass
  typedef elf_shdrs_t::const_iterator const_iter;
  const_iter it  = sections.begin();
  const_iter end = sections.end();
  for ( elf_shndx_t i = 0; it != end; ++it, ++i )
  {
    if ( i == 0 ) // Skip first header
      continue;
    const elf_shdr_t &sh = *it;
    if ( sh.sh_size == 0 )
      continue;

    switch ( sh.sh_type )
    {
      case SHT_SYMTAB:
        {
          sections.set_index(WKS_SYMTAB, i);
          elf_shdr_t *strtab_sh = sections.getn(sh.sh_link);
          if ( strtab_sh == nullptr )
          {
            msg("Illegal link section %d of the string table "
                "for symbols\n",
                sh.sh_link);
          }
          else
          {
            set_sh_strtab(sym_strtab, *strtab_sh, true);
          }
        }
        break;

      case SHT_DYNSYM:
        {
          sections.set_index(WKS_DYNSYM, i);
          elf_shdr_t *strtab_sh = sections.getn(sh.sh_link);
          if ( strtab_sh == nullptr )
          {
            msg("Illegal link section %d of the string table "
                "for dynamic linking symbols\n",
                sh.sh_link);
          }
          else
          {
            set_sh_strtab(dyn_strtab, *strtab_sh, true);
          }
        }
        break;

      case SHT_DYNAMIC:
        {
          elf_shdr_t *strtab_sh = sections.getn(sh.sh_link);
          if ( strtab_sh == nullptr )
          {
            msg("Illegal link section %d of the dynamic linking "
                "information section\n",
                sh.sh_link);
          }
          else if ( strtab_sh->sh_type == SHT_DYNSYM )
          {
            // OAT file: .dynamic section links to .dynsym section
            strtab_sh->sh_link = 0;
          }
          else
          {
            set_sh_strtab(dyn_strtab, *strtab_sh, true);
          }
        }
        break;
    }
  }

  // initialize the section name string table
  if ( header.real_shstrndx != 0 )
  {
    elf_shdr_t *shstrtab = sections.getn(header.real_shstrndx);
    if ( shstrtab != nullptr )
    {
      // we do not check type of this section here
      // (in some cases it may be not SHT_STRTAB)
      sections.strtab.offset = shstrtab->sh_offset;
      sections.strtab.addr = shstrtab->sh_addr;
      sections.strtab.size = shstrtab->sh_size;
    }
  }

  qstring name;
  it = sections.begin();
  for ( elf_shndx_t i = 0; it != end; ++it, ++i )
  {
    if ( i == 0 ) // Skip first header
      continue;

    const elf_shdr_t &sh = *it;
    if ( sh.sh_size == 0 )
      continue;

    name.qclear();
    sections.get_name(&name, &sh);
    switch ( sh.sh_type )
    {
      case SHT_STRTAB:
        // we specify replace = false as this section has less priority
        // compared to the sh_link section
        if ( name == ".strtab" )
          set_sh_strtab(sym_strtab, sh, false);
        else if ( name == ".dynstr" )
          set_sh_strtab(dyn_strtab, sh, false);
        break;

      case SHT_SYMTAB_SHNDX:
        if ( sh.sh_link != 0 )
        {
          if ( sh.sh_link == sections.get_index(WKS_SYMTAB) )
            sections.set_index(WKS_SYMTAB_SHNDX, i);
          if ( sh.sh_link == sections.get_index(WKS_DYNSYM) )
            sections.set_index(WKS_DYNSYM_SHNDX, i);
        }
        break;

      case SHT_GNU_verdef:
        sections.set_index(WKS_VERDEF, i);
        break;
      case SHT_GNU_verneed:
        sections.set_index(WKS_VERNEED, i);
        break;
      case SHT_GNU_versym:
        sections.set_index(WKS_VERSYM, i);
        break;

      case SHT_PROGBITS:
        if ( name == ".interp" )
        {
          sections.set_index(WKS_INTERP, i);
          break;
        }
        else if ( name == ".got" )
        {
          sections.set_index(WKS_GOT, i);
          sections.set_got_original();
          break;
        }
        else if ( name == ".got.plt" )
        {
          sections.set_index(WKS_GOTPLT, i);
          break;
        }
        else if ( name == ".plt.got" )
        {
          sections.set_index(WKS_PLTGOT, i);
          break;
        }
        else if ( name == ".plt.sec" )
        {
          sections.set_index(WKS_PLTSEC, i);
          break;
        }
        else if ( name == ".gnu_debugdata" )
        {
          sections.set_index(WKS_GNU_DEBUGDATA, i);
          break;
        }
        else if ( name == ".eh_frame" )
        {
          sections.set_index(WKS_EH_FRAME, i);
          break;
        }
        // function pointers for PPC64 (may be for IA64, HPPA64)
        else if ( is_64() && name == ".opd" )
        {
          sections.set_index(WKS_OPD, i);
          break;
        }
        // no break
      case SHT_NOBITS:
        if ( name == ".plt" )
          sections.set_index(WKS_PLT, i);
        break;
    }
  }

  if ( sections.get_index(WKS_GOTPLT) == 0 )
    sections.set_index(WKS_GOTPLT, sections.get_index(WKS_GOT));
  else if ( sections.get_index(WKS_GOT) == 0 )
    sections.set_index(WKS_GOTPLT, 0);  // unsupported format

  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_program_headers()
{
  if ( !header.has_pht() )
    return false;
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(header.e_phoff) == -1 )
    return false;

  int count = header.e_phnum;
  validate_array_count_or_die(get_linput(), count, header.e_phentsize, "PHT entries");
  pheaders.resize(count);

  pheaders.initialized = true;

  elf_phdr_t *dyn_phdr = nullptr;
  for ( int i = 0; i < count; i++ )
  {
    if ( !seek_to_program_header(i) )
      return false;

    elf_phdr_t *phdr = pheaders.get(i);
#define _safe(expr)                             \
    do                                          \
    {                                           \
      if ( expr < 0 )                           \
      {                                         \
        pheaders.resize(i == 0 ? 0 : i-1);      \
        return false;                           \
      }                                         \
    } while ( false )
    _safe(read_word(&phdr->p_type));
    if ( is_64() )
      _safe(read_word(&phdr->p_flags));
    _safe(read_off(&phdr->p_offset));
    _safe(read_addr(&phdr->p_vaddr));
    _safe(read_addr(&phdr->p_paddr));
    _safe(read_xword(&phdr->p_filesz));
    _safe(read_xword(&phdr->p_memsz));
    if ( !is_64() )
      _safe(read_word(&phdr->p_flags));
    _safe(read_xword(&phdr->p_align));
#undef _safe

    switch ( phdr->p_type )
    {
      case PT_LOAD:
        add_mapping(*phdr);

        // ELF_Format.pdf page 2-4
        // The base address in ELF is "the lowest virtual address associated
        // with the memory image of the program's object file".
        if ( phdr->p_vaddr < pheaders.get_image_base() )
        {
          // NOTE The default maximum page size is processor specific.
          //      The ELF standard vaguely mentions ("Program Loading")
          //      that 4 KB is the maximum page size for the SYSTEM V
          //      architecture, so we use this value.
          const ea_t maximum_page_size = 0x1000;
          // Truncate the memory address to the nearest multiple of the
          // maximum page size.
          ea_t image_base = phdr->p_vaddr & ~(maximum_page_size - 1);
          pheaders.set_image_base(image_base);
        }

        break;
      case PT_DYNAMIC:
        dyn_phdr = phdr;
        break;
    }
  }

  if ( dyn_phdr != nullptr )
  {
    // in some files, p_filesz is 0, so take max of the two
    // TODO: use the size of the surrounding PT_LOAD segment,
    // since the dynamic loader does not use the size field
    size_t dsize = qmax(dyn_phdr->p_filesz, dyn_phdr->p_memsz);
    // p_offset may be wrong, always use p_vaddr
    size_t fileoff = file_offset(dyn_phdr->p_vaddr);
    pheaders.set_dynlink_table_info(fileoff, dyn_phdr->p_vaddr, dsize, -1);
  }

  return true;
}

//----------------------------------------------------------------------------
void reader_t::set_sh_strtab(
        dynamic_info_t::entry_t &strtab,
        const elf_shdr_t &strtab_sh,
        bool replace)
{
  // we don't check that type of section should be SHT_STRTAB,
  // we just reject illegal section type
  if ( strtab_sh.sh_type == SHT_NULL
    || strtab_sh.sh_type == SHT_REL
    || strtab_sh.sh_type == SHT_RELA
    || strtab_sh.sh_type == SHT_DYNAMIC
    || strtab_sh.sh_type == SHT_DYNSYM
    || strtab_sh.sh_type == SHT_SYMTAB )
  {
    msg("Illegal type %s of the string table section\n",
        sections.sh_type_qstr(strtab_sh.sh_type).c_str());
    return;
  }
  if ( strtab_sh.sh_offset == 0 )
  {
    msg("Illegal offset of the string table section\n");
    return;
  }
  // store the string table info
  if ( strtab.is_valid() )
  {
    if ( strtab.offset == strtab_sh.sh_offset )
      return;
    warning("AUTOHIDE SESSION\n"
            "More than one string table for %ssymbols, "
            "using one at offset %08" FMT_64 "X",
            &strtab == &dyn_strtab ? "dynamic linking " : "",
            replace ? strtab_sh.sh_offset : strtab.offset);
    if ( !replace )
      return;
  }
  strtab.offset = strtab_sh.sh_offset;
  strtab.addr = strtab_sh.sh_addr;
  strtab.size = strtab_sh.sh_size;
}

//----------------------------------------------------------------------------
void reader_t::set_di_strtab(
        dynamic_info_t::entry_t &strtab,
        const dynamic_info_t::entry_t &strtab_di)
{
  if ( !strtab_di.is_valid() )
    return;
  if ( strtab.is_valid() )
  {
    if ( strtab.offset == strtab_di.offset )
      return;
    warning("The dynamic section string table "
            "from section header (%08" FMT_64 "X) differs "
            "from DT_STRTAB's one (%08" FMT_64 "X), "
            "using the latter",
            strtab.offset,
            strtab_di.offset);
  }
  strtab = strtab_di;
}

//----------------------------------------------------------------------------
bool reader_t::read_notes(notes_t *notes)
{
  notes->clear();

  if ( sections.initialized )
  {
    for ( elf_shdrs_t::const_iterator p=sections.begin(); p != sections.end(); ++p )
    {
      const elf_shdr_t &sh = *p;
      if ( sh.sh_type != SHT_NOTE )
        continue;
      bytevec_t buf;
      sections.read_file_contents(&buf, sh);
      notes->add(buf);
    }
  }

  if ( pheaders.initialized )
  {
    for ( elf_phdrs_t::const_iterator q=pheaders.begin(); q != pheaders.end(); ++q )
    {
      const elf_phdr_t &p = *q;
      if ( p.p_type != PT_NOTE )
        continue;
      bytevec_t buf;
      pheaders.read_file_contents(&buf, p);
      notes->add(buf);
    }
  }

  notes->initialized = true;
  return true;
}

//----------------------------------------------------------------------------
elf_sym_idx_t reader_t::rel_info_index(const elf_rela_t &r) const
{
  if ( is_64() && !is_msb() && is_mips() )
  {
    // MIPS64 does not use 64-bit r_info but always puts symbol index at low address
    // so for LE we need to return low part of r_info
    return uint32(r.r_info);
  }
  if ( is_64() )
    return ELF64_R_SYM(r.r_info);
  else
    return ELF32_R_SYM(r.r_info);
}

//----------------------------------------------------------------------------
uint32 reader_t::rel_info_type(const elf_rela_t &r) const
{
  if ( is_64() && !is_msb() && is_mips() )
  {
    // MIPS64 does not use a 64-bit r_info but always puts symbol index at low address
    // so in case of LE we need to return the high part of r_info
    // we also need to convert it to BE
    // so that macros like  ELF64_MIPS_R_TYPE work properly
    return swap32(r.r_info>>32);
  }
  if ( is_64() )
    return ELF64_R_TYPE(r.r_info);
  else
    return ELF32_R_TYPE(r.r_info);
}

//----------------------------------------------------------------------------
void reader_t::set_rel_info_index(elf_rela_t *r, uint32 symidx) const
{
  if ( !is_64() )
  {
    r->r_info = ELF32_R_INFO(uint64(symidx), ELF32_R_TYPE(r->r_info));
  }
  else if ( !is_msb() && is_mips() )
  {
    // MIPS64 does not use the 64-bit r_info, but always puts the symbol
    // index at the low address, so for LE we need to update the low part of
    // r_info
    r->r_info &= ~0xFFFFFFFF;
    r->r_info |= uint64(symidx) << 32;
  }
  else
  {
    r->r_info &= 0xFFFFFFFF;
    r->r_info |= symidx;
  }
}

//----------------------------------------------------------------------------
void reader_t::set_rel_info_type(elf_rela_t *r, uint32 type) const
{
  if ( !is_64() )
  {
    r->r_info = ELF32_R_INFO(ELF32_R_SYM(r->r_info), type);
  }
  else if ( !is_msb() && is_mips() )
  {
    // MIPS64 does not use the 64-bit r_info, but always puts the symbol
    // index at the low address, so for LE we need to update the high part
    // of r_info.
    // we also need to convert it to BE
    r->r_info &= 0xFFFFFFFF;
    r->r_info |= uint64(swap32(type)) << 32;
  }
  else
  {
    r->r_info &= ~0xFFFFFFFF;
    r->r_info |= type;
  }
}

//----------------------------------------------------------------------------
const char *reader_t::file_type_str() const
{
  const char *file_type = "Unknown";
  switch ( header.e_type )
  {
    case ET_NONE:     file_type = "None";                    break;
    case ET_REL:      file_type = "Relocatable";             break;
    case ET_EXEC:     file_type = "Executable";              break;
    case ET_DYN:      file_type = "Shared object";           break;
    case ET_CORE:     file_type = "Core file";               break;
    case ET_LOPROC:   file_type = "Processor specific";      break;
    case ET_HIPROC:   file_type = "Processor specific";      break;
    case ET_IRX:
      if ( is_mips() )
        file_type = "PS2 IRX";
      break;
    case ET_PSPEXEC:
      if ( is_mips() )
        file_type = "PSP executable";
      break;
    case ET_PS3PRX:
      if ( header.e_machine == EM_PPC64 )
        file_type = "Sony PS3 PRX file";
      break;
  }
  return file_type;
}

//----------------------------------------------------------------------------
const char *reader_t::os_abi_str() const
{
  uint8 os_abi = get_ident().osabi;
  const char *abi;
  switch ( os_abi )
  {
    case ELFOSABI_NONE:       abi = "UNIX System V ABI";                 break;
    case ELFOSABI_HPUX:       abi = "HP-UX operating system";            break;
    case ELFOSABI_NETBSD:     abi = "NetBSD";                            break;
    case ELFOSABI_LINUX:      abi = "GNU/Linux";                         break;
    case ELFOSABI_HURD:       abi = "GNU/Hurd";                          break;
    case ELFOSABI_SOLARIS:    abi = "Solaris";                           break;
    case ELFOSABI_AIX:        abi = "AIX";                               break;
    case ELFOSABI_IRIX:       abi = "IRIX";                              break;
    case ELFOSABI_FREEBSD:    abi = "FreeBSD";                           break;
    case ELFOSABI_TRU64:      abi = "TRU64 UNIX";                        break;
    case ELFOSABI_MODESTO:    abi = "Novell Modesto";                    break;
    case ELFOSABI_OPENBSD:    abi = "OpenBSD";                           break;
    case ELFOSABI_OPENVMS:    abi = "OpenVMS";                           break;
    case ELFOSABI_NSK:        abi = "Hewlett-Packard Non-Stop Kernel";   break;
    case ELFOSABI_AROS:       abi = "Amiga Research OS";                 break;
    case ELFOSABI_ARM:        abi = "ARM";                               break;
    case ELFOSABI_STANDALONE: abi = "Standalone (embedded) application"; break;
    case ELFOSABI_CELLOSLV2:
      if ( header.e_machine == EM_PPC64 )
      {
        abi = "PS3 Cell OS lv2";
        break;
      }
      // fall through
    default:
      abi = "Unknown";
      break;
  }
  return abi;
}

//----------------------------------------------------------------------------
const char *reader_t::machine_name_str() const
{
  uint32 m = get_header().e_machine;
  switch ( m )
  {
    case EM_NONE:           return "<No machine>";
    case EM_M32:            return "AT & T WE 32100";
    case EM_SPARC:          return "SPARC";
    case EM_386:            return "Intel 386";
    case EM_68K:            return "Motorola 68000";
    case EM_88K:            return "Motorola 88000";
    case EM_486:            return "Intel 486";
    case EM_860:            return "Intel 860";
    case EM_MIPS:           return "MIPS";
    case EM_S370:           return "IBM System370";
    case EM_MIPS_RS3_BE:    return "MIPS R3000 Big Endian";
    case EM_PARISC:         return "PA-RISC";
    case EM_VPP550:         return "Fujitsu VPP500";
    case EM_SPARC32PLUS:    return "SPARC v8+";
    case EM_I960:           return "Intel 960";
    case EM_PPC:            return "PowerPC";
    case EM_PPC64:          return "PowerPC 64";
    case EM_S390:           return "IBM S/390";
    case EM_S390_OLD:       return "IBM S/390 (old magic)";
    case EM_SPU:            return "Cell BE SPU";
    case EM_CISCO7200:      return "Cisco 7200 Series Router (MIPS)";
    case EM_CISCO3620:      return "Cisco 3620/3640 Router (MIPS)";
    case EM_V800:           return "NEC V800 or Renesas RH850";
    case EM_FR20:           return "Fujitsu FR20";
    case EM_RH32:           return "TRW RH-22";
    case EM_MCORE:          return "Motorola M*Core";
    case EM_ARM:            return "ARM";
    case EM_OLD_ALPHA:      return "Digital Alpha";
    case EM_SH:             return "SuperH";
    case EM_SPARC64:        return "SPARC 64";
    case EM_TRICORE:        return "Siemens Tricore";
    case EM_ARC:            return "ARC";
    case EM_H8300:          return "H8/300";
    case EM_H8300H:         return "H8/300H";
    case EM_H8S:            return "Hitachi H8S";
    case EM_H8500:          return "H8/500";
    case EM_IA64:           return "Itanium IA64";
    case EM_MIPS_X:         return "Stanford MIPS-X";
    case EM_COLDFIRE:       return "Coldfire";
    case EM_6812:           return "MC68HC12";
    case EM_MMA:            return "Fujitsu MMA";
    case EM_PCP:            return "Siemens PCP";
    case EM_NCPU:           return "Sony nCPU";
    case EM_NDR1:           return "Denso NDR1";
    case EM_STARCORE:       return "Star*Core";
    case EM_ME16:           return "Toyota ME16";
    case EM_ST100:          return "ST100";
    case EM_TINYJ:          return "TinyJ";
    case EM_X86_64:         return "x86-64";
    case EM_PDSP:           return "PDSP";
    case EM_PDP10:          return "DEC PDP-10";
    case EM_PDP11:          return "DEC PDP-11";
    case EM_FX66:           return "Siemens FX66";
    case EM_ST9:            return "ST9+";
    case EM_ST7:            return "ST7";
    case EM_68HC16:         return "MC68HC16";
    case EM_6811:           return "MC68HC11";
    case EM_68HC08:         return "MC68HC08";
    case EM_68HC05:         return "MC68HC05";
    case EM_SVX:            return "Silicon Graphics SVx";
    case EM_ST19:           return "ST19";
    case EM_VAX:            return "VAX";
    case EM_CRIS:           return "CRIS";
    case EM_JAVELIN:        return "Infineon Javelin";
    case EM_FIREPATH:       return "Element 14 Firepath";
    case EM_ZSP:            return "ZSP";
    case EM_MMIX:           return "MMIX";
    case EM_HUANY:          return "Harvard HUANY";
    case EM_PRISM:          return "SiTera Prism";
    case EM_AVR:            return "Atmel";
    case EM_FR:             return "Fujitsu FR";
    case EM_D10V:           return "Mitsubishi D10V";
    case EM_D30V:           return "Mitsubishi D30V";
    case EM_V850:  // (GNU compiler)
    case EM_CYGNUS_V850:
    case EM_NECV850:        return "NEC V850"; // (NEC compilers)
    case EM_NECV850E:       return "NEC v850E";
    case EM_NECV850E2:      return "NEC v850E2";
    case EM_NECV850ES:      return "NEC v850ES";
    case EM_NECV850E2R1:    return "NEC v850E2R1";
    case EM_NECV850E2R2:    return "NEC v850E2R2";
    case EM_NECV850E2R3:    return "NEC v850E2R3";
    case EM_NECV850E2R4:    return "NEC v850E2R4";
    case EM_NECV850E3V5:    return "NEC v850E3V5";
    case EM_M32R:           return "M32R";
    case EM_MN10300:        return "MN10300";
    case EM_MN10200:        return "MN10200";
    case EM_PJ:             return "picoJava";
    case EM_OPENRISC :      return "OpenRISC";
    case EM_ARCOMPACT:      return "ARCompact";
    case EM_XTENSA:         return "Xtensa";
    case EM_VIDEOCORE:      return "VideoCore";
    case EM_TMM_GPP:        return "Thompson GPP";
    case EM_NS32K:          return "NS 32000";
    case EM_TPC:            return "TPC";
    case EM_SNP1K:          return "SNP 1000";
    case EM_ST200:          return "ST200";
    case EM_IP2K:           return "IP2022";
    case EM_MAX:            return "MAX";
    case EM_CR:             return "CompactRISC";
    case EM_F2MC16:         return "F2MC16";
    case EM_MSP430:         return "MSP430";
    case EM_BLACKFIN:       return "ADI Blackfin";
    case EM_SE_C33:         return "S1C33";
    case EM_SEP:            return "SEP";
    case EM_ARCA:           return "Arca";
    case EM_UNICORE:        return "Unicore";
    case EM_EXCESS:         return "eXcess";
    case EM_DXP:            return "Icera DXP";
    case EM_ALTERA_NIOS2:   return "Nios II";
    case EM_CRX:            return "CRX";
    case EM_XGATE:          return "XGATE";
    case EM_C166:           return "C16x/XC16x/ST10";
    case EM_M16C:           return "M16C";
    case EM_DSPIC30F:       return "dsPIC30F";
    case EM_CE:             return "Freescale Communication Engine";
    case EM_M32C:           return "Renesas  M32C";
    case EM_TSK3000:        return "TSK3000";
    case EM_RS08:           return "Freescale RS08";
    case EM_SHARC:          return "Analog Devices SHARC";
    case EM_ECOG2:          return "Cyan Technology eCOG2";
    case EM_SCORE:          return "Sunplus S+core7";
    case EM_DSP24:          return "NJR DSP24";
    case EM_VIDEOCORE3:     return "VideoCore III";
    case EM_LATTICEMICO32:  return "Lattice Mico32";
    case EM_SE_C17:         return "C17";
    case EM_MMDSP_PLUS:     return "MMDSP";
    case EM_CYPRESS_M8C:    return "M8C";
    case EM_R32C:           return "R32C";
    case EM_TRIMEDIA:       return "TriMedia";
    case EM_QDSP6:          return "QDSP6";
    case EM_8051:           return "i8051";
    case EM_STXP7X:         return "STxP7x";
    case EM_NDS32:          return "NDS32";
    case EM_ECOG1X:         return "eCOG1X";
    case EM_MAXQ30:         return "MAXQ30";
    case EM_XIMO16:         return "NJR XIMO16";
    case EM_MANIK:          return "M2000";
    case EM_CRAYNV2:        return "Cray NV2";
    case EM_RX:             return "RX";
    case EM_METAG:          return "Imagination Technologies META";
    case EM_MCST_ELBRUS:    return "MCST Elbrus";
    case EM_ECOG16:         return "eCOG16";
    case EM_CR16:           return "CompactRISC 16-bit";
    case EM_ETPU:           return "Freescale ETPU";
    case EM_SLE9X:          return "SLE9X";
    case EM_L1OM:           return "Intel L1OM";
    case EM_K1OM:           return "Intel K1OM";
    case EM_INTEL182:       return "Intel Reserved (182)";
    case EM_AARCH64:        return "ARM64";
    case EM_ARM184:         return "ARM Reserved (184)";
    case EM_AVR32:          return "AVR32";
    case EM_STM8:           return "STM8";
    case EM_TILE64:         return "Tilera TILE64";
    case EM_TILEPRO:        return "Tilera TILEPro";
    case EM_MICROBLAZE:     return "MicroBlaze";
    case EM_CUDA:           return "CUDA";
    case EM_TILEGX:         return "Tilera TILE-Gx";
    case EM_CLOUDSHIELD:    return "CloudShield";
    case EM_COREA_1ST:      return "Core-A 1st gen";
    case EM_COREA_2ND:      return "Core-A 2nd gen";
    case EM_ARC_COMPACT2:   return "ARCompactV2";
    case EM_OPEN8:          return "Open8";
    case EM_RL78:           return "RL78";
    case EM_VIDEOCORE5:     return "VideoCore V";
    case EM_78K0R:          return "78K0R";
    case EM_56800EX:        return "Freescale 56800EX";
    case EM_BA1:            return "Beyond BA1";
    case EM_BA2:            return "Beyond BA2";
    case EM_XCORE:          return "XMOS xCORE";
    case EM_CYGNUS_POWERPC: return "PowerPC";
    case EM_ALPHA:          return "DEC Alpha";
    case EM_TI_C6000:       return "TMS320C6";
    case EM_RISCV:          return "Risc-V";
    case EM_NANOMIPS:       return "nanoMIPS";
    default:                return nullptr;
  }
}

//----------------------------------------------------------------------------
qstring reader_t::get_machine_name() const
{
  qstring s = machine_name_str();
  if ( s.empty() )
    s.sprnt("Unknown CPU [%u]", get_header().e_machine);
  return s;
}

//----------------------------------------------------------------------------
bool reader_t::read_prelink_base(uint32 *base)
{
  int64 fsize = size();
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(fsize - 4) == -1 )
    return false;

  char tag[4];
  bool ok = false;
  if ( qlread(li, tag, 4) == 4 )
  {
    if ( memcmp(tag, "PRE ", 4) == 0 )
    {
      if ( qlseek(li, fsize - 8) != -1 && read_word(base) >= 0 )
        ok = true;
    }
  }

  return ok;
}

//----------------------------------------------------------------------------
bool reader_t::get_string_at(qstring *out, uint64 offset) const
{
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(offset) == -1 )
  {
    out->sprnt("bad offset %08x", low(offset));
    return false;
  }

  bool ret = true;
  out->clear();
  char buffer[100];
  while ( true )
  {
    int read = qlread(li, buffer, sizeof(buffer));
    if ( read < 0 )
    {
      out->append("{truncated name}");
      ret = false;
      break;
    }

    // Find the position of the trailing zero
    int pos;
    for ( pos = 0; pos < read && buffer[pos] != '\0'; pos++ )
      ;

    out->append(buffer, pos);
    if ( pos < sizeof(buffer) )
      break;
  }
  return ret;
}

//----------------------------------------------------------------------------
elf_shndx_t reader_t::get_shndx_at(uint64 offset) const
{
  input_status_t save_excursion(*this);
  if ( save_excursion.seek(offset) == -1 )
    return 0;
  CASSERT(sizeof(elf_shndx_t) == sizeof(uint32));
  uint32 res;
  if ( read_word(&res) < 0 )
    return 0;
  return res;
}

//--------------------------------------------------------------------------
// Fills 'out' with either a fake entry from the DHT or an entry from the SHT.
static bool get_versym_section(
        elf_shdr_t *out,
        slice_type_t *slice_type,
        const reader_t &reader,
        wks_t sht_idx,
        const dynamic_info_t &di,
        dynamic_info_type_t dht_idx,
        bool use_pht)
{
  *slice_type = SLT_INVALID;
  if ( use_pht )
  {
    if ( di.fill_section_header(out, dht_idx) )
      *slice_type = SLT_DYNSYM;
  }
  else
  {
    const elf_shdr_t *sht_entry = reader.sections.get_wks(sht_idx);
    if ( sht_entry != nullptr )
    {
      *out = *sht_entry;
      if ( sht_entry->sh_link == reader.sections.get_index(WKS_SYMTAB)
        && reader.symbols.slice_size(SLT_SYMTAB) != 0 )
      {
        *slice_type = SLT_SYMTAB;
      }
      else if ( sht_entry->sh_link == reader.sections.get_index(WKS_DYNSYM)
             && reader.symbols.slice_size(SLT_DYNSYM) != 0 )
      {
        *slice_type = SLT_DYNSYM;
      }
    }
  }
  return *slice_type != SLT_INVALID;
}

//----------------------------------------------------------------------------
// Helper class for reading version info sections. DT_VERDEF and DT_VERNEED
// have similar structures for reading main and auxiliary entries.
template <class T_entry, class T_aux>
struct elf_ver_parser_t
{
  const reader_t &reader;

  elf_ver_parser_t(const reader_t &_reader)
    : reader(_reader)
  {}

  virtual void entry_cb(const T_entry &, int64, size_t) = 0;
  virtual void aux_cb(const T_aux &, int64, size_t) = 0;

  void parse(int64 offset, size_t size)
  {
    int64 orig_offset = offset;
    input_status_t save_excursion(reader);
    int64 end = offset + size;
    size_t entry_idx = 0;
    std::set<int64> entry_seen;
    while ( offset < end && entry_seen.insert(offset).second )
    {
      T_entry entry;
      if ( save_excursion.seek(offset) == -1 || !entry.read(reader) )
        break;

      entry_cb(entry, offset - orig_offset, entry_idx++);

      int64 aux_offset = offset + entry.aux();
      size_t aux_idx = 0;
      std::set<int64> aux_seen;
      while ( aux_offset < end
           && aux_seen.insert(aux_offset).second
           && aux_idx < entry.cnt() )
      {
        T_aux aux;
        if ( save_excursion.seek(aux_offset) == -1 || !aux.read(reader) )
          break;

        aux_cb(aux, aux_offset - orig_offset, aux_idx++);

        aux_offset += aux.next();
      }

      offset += entry.next();
    }
  }
};

//----------------------------------------------------------------------------
bool reader_t::read_symbol_versions(
        elf_symbol_version_t *symver,
        const dynamic_info_t &di,
        bool use_pht)
{
  elf_shdr_t sh;
  slice_type_t st;

  // Read version requirement entries from DT_VERNEED
  struct elf_verneed_parser_t
    : public elf_ver_parser_t<elf_verneed_t, elf_vernaux_t>
  {
    typedef elf_ver_parser_t<elf_verneed_t, elf_vernaux_t> inherited;

    elf_symbol_version_t &symver;
    slice_type_t st;
    elf_verneed_parser_t(
            const reader_t &_reader,
            elf_symbol_version_t &_symver,
            slice_type_t _st)
      : inherited(_reader),
        symver(_symver),
        st(_st)
    {
    }

    virtual void entry_cb(const elf_verneed_t &verneed, int64 offset, size_t) override
    {
      symbol_verneed_t &reqfile = symver.reqs.push_back();
      reqfile.offset = offset;
      // TODO check verneed.vn_version
      reqfile.name = symver.file_names.size();
      qstring &fname = symver.file_names.push_back();
      reader.get_name(&fname, st, verneed.vn_file);
    }

    virtual void aux_cb(const elf_vernaux_t &vernaux, int64 offset, size_t) override
    {
      symbol_verneed_t &reqfile = symver.reqs.back();
      symbol_vernaux_t &reqver = reqfile.auxs.push_back();
      reqver.offset = offset;

      reqver.name = symver.version_names.size();
      qstring &vname = symver.version_names.push_back();
      reader.get_name(&vname, st, vernaux.vna_name);

      uint16 idx = vernaux.vna_other & ~0x8000;
      if ( idx != 0 )
      {
        vermap_item_t &vermap_item = symver.vermap[idx];
        vermap_item.fname_idx = reqfile.name;
        vermap_item.vname_idx = reqver.name;
      }
    }
  };

  if ( get_versym_section(&sh, &st, *this, WKS_VERNEED, di, DIT_VERNEED, use_pht) )
  {
    elf_verneed_parser_t parser(*this, *symver, st);
    parser.parse(sh.sh_offset, sh.sh_size);
  }

  // Read version definition entries from DT_VERDEF
  struct elf_verdef_parser_t
    : public elf_ver_parser_t<elf_verdef_t, elf_verdaux_t>
  {
    typedef elf_ver_parser_t<elf_verdef_t, elf_verdaux_t> inherited;

    elf_symbol_version_t &symver;
    slice_type_t st;
    elf_verdef_parser_t(
            const reader_t &_reader,
            elf_symbol_version_t &_symver,
            slice_type_t _st)
      : inherited(_reader),
        symver(_symver),
        st(_st)
    {
    }

    virtual void entry_cb(const elf_verdef_t &verdef, int64 offset, size_t) override
    {
      symbol_verdef_t &deffile = symver.defs.push_back();
      deffile.offset = offset;
      // TODO check verdef.vd_version
      deffile.flags = verdef.vd_flags;
      deffile.ndx = verdef.vd_ndx;
    }

    virtual void aux_cb(const elf_verdaux_t &verdaux, int64 offset, size_t) override
    {
      symbol_verdef_t &deffile = symver.defs.back();
      symbol_verdaux_t &defver = deffile.auxs.push_back();
      defver.offset = offset;

      if ( (deffile.flags & VER_FLG_BASE) != 0 )
      {
        symver.def_base = symver.file_names.size();
        qstring &fname = symver.file_names.push_back();
        reader.get_name(&fname, st, verdaux.vda_name);
      }

      defver.name = symver.version_names.size();
      qstring &vname = symver.version_names.push_back();
      reader.get_name(&vname, st, verdaux.vda_name);

      uint16 idx = deffile.ndx;
      if ( idx != 0 && deffile.auxs.size() == 1 )
      {
        vermap_item_t &vermap_item = symver.vermap[idx];
        vermap_item.fname_idx = symver.def_base;
        vermap_item.vname_idx = defver.name;
      }
    }
  };

  if ( get_versym_section(&sh, &st, *this, WKS_VERDEF, di, DIT_VERDEF, use_pht) )
  {
    elf_verdef_parser_t parser(*this, *symver, st);
    parser.parse(sh.sh_offset, sh.sh_size);
  }

  // Read version symbol entries from DT_VERSYM
  if ( get_versym_section(&sh, &st, *this, WKS_VERSYM, di, DIT_VERSYM, use_pht) )
  {
    input_status_t save_excursion(*this);
    if ( save_excursion.seek(sh.sh_offset) != -1 )
      for ( size_t i = 0; i < sh.sh_size / sizeof(uint16); i++ )
        if ( read_half(&symver->symbols.push_back()) < 0 )
          break;
  }

  return true;
}

//----------------------------------------------------------------------------
inline void upd_loc(uint32 *loc, uint32 *op, uint32 offset)
{
  if ( loc != nullptr )
    *loc += offset;
  else
    INTERR(20142);
  *op = *loc;
}

//----------------------------------------------------------------------------
static bool read_cfi(
        cfi_vec_t *cfi_vec,
        const uchar **start,
        const uchar *end,
        const cie_frame_t cief,
        bool is_msb,
        uint32 *location = nullptr)
{
  const uchar *ptr = *start;
  if ( ptr >= end )
    return false;

  cfi_t frame;
  uchar insn = *ptr++;
  switch ( insn & 0xC0 )
  {
    case DW_CFA_advance_loc:
      frame.insn = DW_CFA_advance_loc;
      frame.uop1 = insn & 0x3F;
      if ( location == nullptr )
        return false;
      *location += frame.uop1;
      frame.uop2 = *location;
      break;
    case DW_CFA_offset:
      frame.insn = DW_CFA_offset;
      frame.uop1 = insn & 0x3F;
      if ( !unpack_uleb128(&frame.uop2, &ptr, end) )
        return false;
      frame.sop = frame.uop2 * cief.data_alignment_factor;
      break;
    case DW_CFA_restore:
      frame.insn = DW_CFA_restore;
      frame.uop1 = insn & 0x3F;
      break;
    default:
      frame.insn = insn;
      switch ( insn )
      {
        case DW_CFA_nop:
        case DW_CFA_remember_state:
        case DW_CFA_restore_state:
        case DW_CFA_lo_user:
          break;
        case DW_CFA_offset_extended:
        case DW_CFA_register:
        case DW_CFA_def_cfa:
        case DW_CFA_val_offset:
          if ( !unpack_uleb128(&frame.uop2, &ptr, end) )
            return false;
          // fallthrough
        case DW_CFA_restore_extended:
        case DW_CFA_undefined:
        case DW_CFA_same_value:
        case DW_CFA_def_cfa_register:
        case DW_CFA_def_cfa_offset:
          if ( !unpack_uleb128(&frame.uop1, &ptr, end) )
            return false;
          break;
        case DW_CFA_GNU_args_size:
          if ( !unpack_uleb128(&frame.uop1, &ptr, end) )
            return false;
          break;
        case DW_CFA_def_cfa_expression:
          {
            size_t blocksize;
            if ( !unpack_uleb128(&blocksize, &ptr, end) )
              return false;
            frame.block.append(ptr, blocksize);
            ptr += blocksize;
          }
          break;
        case DW_CFA_advance_loc4:
          if ( is_msb )
            frame.uop1 = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
          else
            frame.uop1 = (ptr[3] << 24) | (ptr[2] << 16) | (ptr[1] << 8) | ptr[0];
          upd_loc(location, &frame.uop2, frame.uop1);
          ptr += 4;
          break;
        case DW_CFA_advance_loc2:
          if ( is_msb )
            frame.uop1 = (ptr[0] << 8) + ptr[1];
          else
            frame.uop1 = (ptr[1] << 8) + ptr[0];
          upd_loc(location, &frame.uop2, frame.uop1);
          ptr += 2;
          break;
        case DW_CFA_advance_loc1:
          frame.uop1 = *ptr;
          upd_loc(location, &frame.uop2, frame.uop1);
          ptr++;
          break;
        default:
          return false;
      }
  }
  cfi_vec->push_back(frame);
  *start = ptr;
  return true;
}

//----------------------------------------------------------------------------
// see also: https://www.cs.dartmouth.edu/~sergey/battleaxe/hackito_2011_oakley_bratus.pdf
bool reader_t::read_eh_frame(cie_frame_vec_t *cie_vec, fde_frame_vec_t *fde_vec)
{
  elf_shdr_t *eh_frame_sh = sections.get_wks(WKS_EH_FRAME);
  if ( eh_frame_sh == nullptr )
    return false;
  seek(eh_frame_sh->sh_offset);

  fde_frame_t fde_frame;
  bool is_msb = get_ident().is_msb();
  while ( fde_frame.offset < eh_frame_sh->sh_size )
  {
    safe_read(&fde_frame.size, sizeof(fde_frame.size));
    if ( fde_frame.size == 0 )
    {
      fde_vec->push_back(fde_frame);
      break;
    }
    if ( fde_frame.size >= 0xfffffff0 )
      return false; // this also indicates 64b eh_frame
    bytevec_t framedata;
    safe_read(&fde_frame.cie_ptr_delta, sizeof(fde_frame.cie_ptr_delta));
    if ( fde_frame.cie_ptr_delta == 0 )
    {
      cie_frame_t cie_frame;
      cie_frame.offset = fde_frame.offset;
      cie_frame.size = fde_frame.size;
      cie_frame.id = fde_frame.cie_ptr_delta;
      safe_read(&cie_frame.version, sizeof(cie_frame.version));
      if ( cie_frame.size < 5 )
        return false; // wrong frame size
      size_t remaining_size = cie_frame.size - 5;
      framedata.resize(remaining_size);
      safe_read(framedata.begin(), remaining_size);
      if ( is_msb )
        memrev(framedata.begin(), remaining_size);
      cie_frame.augmentation.qclear();
      const uchar *ptr = framedata.begin();
      const uchar *end = framedata.end();
      while ( ptr < end )
      {
        uchar c = *ptr++;
        cie_frame.augmentation.append(c);
        if ( c == '\0' )
          break;
      }
      if ( !unpack_uleb128(&cie_frame.code_alignment_factor, &ptr, end) )
        return false; // corrupted data
      if ( !unpack_sleb128(&cie_frame.data_alignment_factor, &ptr, end) )
        return false; // corrupted data
      if ( !unpack_uleb128(&cie_frame.return_address_column, &ptr, end) )
        return false; // corrupted data
      if ( cie_frame.augmentation[0] == 'z' ) // read augmentation data
      {
        uint32 aug_data_length;
        if ( !unpack_uleb128(&aug_data_length, &ptr, end) )
          return false; // corrupted data
        cie_frame.augment_data.append(ptr, aug_data_length);
        ptr += aug_data_length;
      }
      cie_frame.cfis.qclear();
      while ( ptr < end )
      {
        if ( !read_cfi(&cie_frame.cfis, &ptr, end, cie_frame, is_msb) )
          return false;
      }
      cie_vec->push_back(cie_frame);
      fde_frame.offset += cie_frame.size + 4;
    }
    else
    {
      // fde length, cie_ptr, initial_location, address_range
      int64 base = tell();
      fde_frame.initial_location = 0;
      fde_frame.cie_ptr = fde_frame.offset - fde_frame.cie_ptr_delta + 4;
      int32 initial_location;
      int32 address_range;
      safe_read(&initial_location, sizeof(initial_location));
      safe_read(&address_range, sizeof(address_range));
      if ( fde_frame.size < 12 )
        return false; // wrong frame size
      size_t remaining_size = fde_frame.size - 12;
      if ( remaining_size > 0 )
      {
        framedata.resize(remaining_size);
        safe_read(framedata.begin(), remaining_size);
        if ( is_msb )
          memrev(framedata.begin(), remaining_size);

        cie_frame_vec_t::const_iterator pc = cie_vec->begin();
        cie_frame_vec_t::const_iterator endc = cie_vec->end();
        for ( ; pc < endc; pc++ )
          if ( pc->offset == fde_frame.cie_ptr )
            break; // we have found it
        if ( pc == endc )
          return false; // we did not find it

        const uchar *ptr = framedata.begin();
        const uchar *end = framedata.end();
        if ( pc->augmentation[0] == 'z' ) // read augmentation data
        {
          uint32 aug_data_length;
          if ( !unpack_uleb128(&aug_data_length, &ptr, end) )
            return false; // corrupted data
          fde_frame.augment_data.qclear();
          fde_frame.augment_data.append(ptr, aug_data_length);
          ptr += aug_data_length;
        }
        // if there is an 'R', the aug string start with 'z'
        if ( pc->augmentation.find("R", 1) != qstring::npos )
          // TODO check initial_location == 0.
          fde_frame.initial_location = base + initial_location;
        else
          fde_frame.initial_location = initial_location;

        fde_frame.final_location = fde_frame.initial_location + address_range;
        fde_frame.cfis.qclear();
        uint32 location = fde_frame.initial_location;
        while ( ptr < end )
        {
          if ( !read_cfi(&fde_frame.cfis, &ptr, end, *pc, is_msb, &location) )
            return false;
        }
      }
      fde_vec->push_back(fde_frame);
      fde_frame.offset += fde_frame.size + 4;
    }
  }
  return true;
}

//----------------------------------------------------------------------------
void reader_t::validate_section_size(
        uint64 *count,
        size_t *entsize,
        const elf_shdr_t &section,
        const char *counter_name)
{
  *entsize = section.sh_entsize == 0 ? 1 : section.sh_entsize;
  *count = section.sh_size / *entsize;
  validate_array_count(
          get_linput(),
          count,
          *entsize,
          counter_name,
          section.sh_offset);
}

//----------------------------------------------------------------------------
bool reader_t::read_dynamic_info_tags(
        dyninfo_tags_t *dyninfo_tags,
        const dynamic_linking_tables_t &dlt)
{
  // assert: dlt.is_valid()
  if ( dlt.size == 0 )
    return false;

  // read all 'elf_dyn_t' entries
  elf_dyn_t *d;
  const size_t isize = stdsizes.entries.dyn;
  elf_shdr_t fake_section;
  fake_section.sh_type    = SHT_DYNAMIC;
  fake_section.sh_offset  = dlt.offset;
  fake_section.sh_size    = dlt.size;
  fake_section.sh_entsize = isize;
  uint64 count;
  size_t entsize;
  validate_section_size(&count, &entsize, fake_section, "Dynamic info size");
  if ( count == 0 )
    return false;
  buffered_input_t<elf_dyn_t> dyn_input(*this, fake_section.sh_offset, count, entsize);
  while ( dyn_input.next(d) )
  {
    dyninfo_tags->push_back(*d);
    if ( d->d_tag == DT_NULL )
      break;
  }
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::parse_dynamic_info(
        dynamic_info_t *dyninfo,
        const dyninfo_tags_t &dyninfo_tags)
{
  dyninfo->initialize(*this);

  sizevec_t offsets;

  // populate dyninfo structure
  for ( dyninfo_tags_t::const_iterator dyn = dyninfo_tags.begin();
        dyn != dyninfo_tags.end();
        ++dyn )
  {
    dynamic_info_type_t di_type = DIT_TYPE_COUNT;
    switch ( dyn->d_tag )
    {
      case DT_STRTAB:        di_type = DIT_STRTAB;        break;
      case DT_SYMTAB:        di_type = DIT_SYMTAB;        break;
      case DT_REL:           di_type = DIT_REL;           break;
      case DT_RELA:          di_type = DIT_RELA;          break;
      case DT_JMPREL:        di_type = DIT_PLT;           break;
      case DT_HASH:          di_type = DIT_HASH;          break;
      case DT_GNU_HASH:      di_type = DIT_GNU_HASH;      break;
      case DT_PREINIT_ARRAY: di_type = DIT_PREINIT_ARRAY; break;
      case DT_INIT_ARRAY:    di_type = DIT_INIT_ARRAY;    break;
      case DT_FINI_ARRAY:    di_type = DIT_FINI_ARRAY;    break;
      case DT_VERDEF:        di_type = DIT_VERDEF;        break;
      case DT_VERNEED:       di_type = DIT_VERNEED;       break;
      case DT_VERSYM:        di_type = DIT_VERSYM;        break;
      case DT_ANDROID_REL:
        if ( is_arm() )
          di_type = DIT_ANDROID_REL;
        break;
      case DT_ANDROID_RELA:
        if ( is_arm() )
          di_type = DIT_ANDROID_RELA;
        break;
    }
    if ( di_type != DIT_TYPE_COUNT )
    {
      dynamic_info_t::entry_t &entry = dyninfo->entries[di_type];
      entry.offset = file_offset(dyn->d_un);
      offsets.push_back(entry.offset);
      entry.addr = dyn->d_un;
      continue;
    }

    switch ( dyn->d_tag )
    {
      case DT_STRSZ:           di_type = DIT_STRTAB;        break;
      case DT_RELSZ:           di_type = DIT_REL;           break;
      case DT_RELASZ:          di_type = DIT_RELA;          break;
      case DT_ANDROID_RELSZ:   di_type = DIT_ANDROID_REL;   break;
      case DT_ANDROID_RELASZ:  di_type = DIT_ANDROID_RELA;  break;
      case DT_PLTRELSZ:        di_type = DIT_PLT;           break;
      case DT_PREINIT_ARRAYSZ: di_type = DIT_PREINIT_ARRAY; break;
      case DT_INIT_ARRAYSZ:    di_type = DIT_INIT_ARRAY;    break;
      case DT_FINI_ARRAYSZ:    di_type = DIT_FINI_ARRAY;    break;
    }
    if ( di_type != DIT_TYPE_COUNT )
    {
      dyninfo->entries[di_type].size = dyn->d_un;
      continue;
    }

    switch ( dyn->d_tag )
    {
      case DT_SYMENT:  di_type = DIT_SYMTAB; break;
      case DT_RELENT:  di_type = DIT_REL;    break;
      case DT_RELAENT: di_type = DIT_RELA;   break;
    }
    if ( di_type != DIT_TYPE_COUNT )
    {
      dyninfo->entries[di_type].entsize = dyn->d_un;
      continue;
    }

    switch ( dyn->d_tag )
    {
      case DT_VERDEFNUM:  di_type = DIT_VERDEF;  break;
      case DT_VERNEEDNUM: di_type = DIT_VERNEED; break;
    }
    if ( di_type != DIT_TYPE_COUNT )
    {
      dyninfo->entries[di_type].info = dyn->d_un;
      continue;
    }

    switch ( dyn->d_tag )
    {
      case DT_PLTREL:
        dyninfo->plt_rel_type = uint32(dyn->d_un);
        if ( dyninfo->plt_rel_type != DT_REL && dyninfo->plt_rel_type != DT_RELA )
        {
          if ( !handle_error(*this, BAD_DYN_PLT_TYPE, dyninfo->plt_rel_type) )
            return false;
        }
        continue;

      case DT_INIT:
      case DT_FINI:
      case DT_PLTGOT:
        offsets.push_back(file_offset(dyn->d_un));
        continue;

      default:
        continue;

      case DT_NULL:
        break; // end of list
    }
    break;
  }

  // Guess size of sections that don't have an explicit size
  dyninfo->symtab().guess_size(offsets);
  dyninfo->hash().guess_size(offsets);
  dyninfo->gnu_hash().guess_size(offsets);
  dyninfo->verdef().guess_size(offsets);
  dyninfo->verneed().guess_size(offsets);
  dyninfo->versym().guess_size(offsets);

  return true;
}

//----------------------------------------------------------------------------
void reader_t::add_mapping(const elf_phdr_t &p)
{
  mapping_t &m = mappings.push_back();
  m.offset = p.p_offset;
  m.size   = p.p_filesz;
  m.ea     = p.p_vaddr;
}

//----------------------------------------------------------------------------
int64 reader_t::file_offset(uint64 ea) const
{
  for ( int i=0; i < mappings.size(); i++ )
  {
    const mapping_t &cur = mappings[i];
    if ( cur.ea <= ea && (cur.ea + cur.size) > ea )
      return low(ea - cur.ea) + cur.offset;
  }

  return -1;
}

//----------------------------------------------------------------------------
ea_t reader_t::file_vaddr(uint64 offset) const
{
  for ( int i=0; i < mappings.size(); i++ )
  {
    const mapping_t &cur = mappings[i];
    if ( cur.offset <= offset && (cur.offset + cur.size) > offset )
      return low(offset - cur.offset) + cur.ea;
  }

  return BADADDR;
}

//----------------------------------------------------------------------------
elf_shndx_t section_headers_t::get_index(wks_t wks) const
{
  QASSERT(20054, wks >= WKS_BSS && wks < WKS_LAST);
  return wks_lut[int(wks)];
}

//----------------------------------------------------------------------------
void section_headers_t::set_index(wks_t wks, elf_shndx_t index)
{
  QASSERT(20055, wks >= WKS_BSS && wks < WKS_LAST);
  wks_lut[int(wks)] = index;
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::getn(elf_shndx_t index) const
{
  assert_initialized();

  if ( index >= headers.size() )
    return nullptr;
  else
    return &headers[index];
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::get(uint32 sh_type, const char *name) const
{
  assert_initialized();

  qstring n2;
  for ( qvector<elf_shdr_t>::const_iterator it=begin(); it != end(); it++ )
  {
    const elf_shdr_t &cur = *it;
    if ( cur.sh_type == sh_type )
    {
      n2.qclear();
      get_name(&n2, &cur);
      if ( n2 == name )
        return &cur;
    }
  }
  return nullptr;
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::get_rel_for(elf_shndx_t index, bool *is_rela) const
{
  assert_initialized();
  if ( is_rela != nullptr )
    *is_rela = false;

  QASSERT(20056, index > 0);
  for ( elf_shdrs_t::const_iterator it=begin(); it != end(); it++ )
  {
    // for REL/RELA sections, sh_info contains the index to which the relocations apply
    if ( it->sh_info == index
      && (it->sh_type == SHT_RELA || it->sh_type == SHT_REL) )
    {
      // found it
      if ( is_rela != nullptr )
        *is_rela = it->sh_type == SHT_RELA;
      return it;
    }
  }
  return nullptr;
}

//----------------------------------------------------------------------------
int section_headers_t::add(const elf_shdr_t &section)
{
  headers.push_back(section);
  return headers.size() - 1;
}

//----------------------------------------------------------------------------
bool section_headers_t::get_name(qstring *out, elf_shndx_t index) const
{
  assert_initialized();

  if ( index >= headers.size() )
    return false;
  else
    return get_name(out, &headers[index]);
}

//----------------------------------------------------------------------------
bool section_headers_t::get_name(qstring *out, const elf_shdr_t *sh) const
{
  if ( sh == nullptr || !strtab.is_valid() )
    return false;
  return reader->get_name(out, strtab, sh->sh_name);
}

//----------------------------------------------------------------------------
bool reader_t::get_name(
        qstring *out,
        const dynamic_info_t::entry_t &strtab,
        uint32 name_idx) const
{
  if ( !strtab.is_valid() )
    *out = "{no string table}";
  // cisco ios files have size 0 for the string section
  else if ( strtab.size != 0 && name_idx >= strtab.size )
    out->sprnt("bad offset %08x", low(strtab.offset + name_idx));
  else
    return get_string_at(out, strtab.offset + name_idx);
  return false;
}

//----------------------------------------------------------------------------
bool reader_t::get_name(
        qstring *out,
        slice_type_t slice_type,
        uint32 name_idx) const
{
  const dynamic_info_t::entry_t *strtab;
  switch ( slice_type )
  {
    case SLT_SYMTAB:
      strtab = &sym_strtab;
      break;
    case SLT_DYNSYM:
      strtab = &dyn_strtab;
      break;
    default:
      INTERR(20086);
  }
  return get_name(out, *strtab, name_idx);  //-V614 Potentially uninitialized pointer 'strtab' used
}

//----------------------------------------------------------------------------
const char *section_headers_t::sh_type_str(uint32 sh_type) const
{
#define NM(tp) case SHT_##tp: return #tp
#define NM2(tp, nm) case SHT_##tp: return #nm

  // OS-specific types
  uint8 os_abi = reader->get_ident().osabi;
  if ( os_abi == ELFOSABI_SOLARIS )
  {
    switch ( sh_type )
    {
      NM(SUNW_ancillary);
      NM(SUNW_capchain);
      NM(SUNW_capinfo);
      NM(SUNW_symsort);
      NM(SUNW_tlssort);
      NM(SUNW_LDYNSYM);
      NM(SUNW_dof);
      NM(SUNW_cap);
      NM(SUNW_SIGNATURE);
      NM(SUNW_ANNOTATE);
      NM(SUNW_DEBUGSTR);
      NM(SUNW_DEBUG);
      NM(SUNW_move);
      NM(SUNW_COMDAT);
      NM(SUNW_syminfo);
      NM2(SUNW_verdef,  VERDEF);
      NM2(SUNW_verneed, VERNEEDED);
      NM2(SUNW_versym,  VERSYMBOL);
    }
  }
  else
  {
    switch ( sh_type )
    {
      NM(GNU_INCREMENTAL_INPUTS);
      NM(GNU_INCREMENTAL_SYMTAB);
      NM(GNU_INCREMENTAL_RELOCS);
      NM(GNU_INCREMENTAL_GOT_PLT);
      NM(GNU_ATTRIBUTES);
      NM(GNU_HASH);
      NM(GNU_LIBLIST);
      NM2(GNU_verdef,  VERDEF);
      NM2(GNU_verneed, VERNEEDED);
      NM2(GNU_versym,  VERSYMBOL);
    }
  }

  switch ( sh_type )
  {
    NM(NULL); // ok:NULL
    NM(PROGBITS);
    NM(SYMTAB);
    NM(STRTAB);
    NM(RELA);
    NM(HASH);
    NM(DYNAMIC);
    NM(NOTE);
    NM(NOBITS);
    NM(REL);
    NM(SHLIB);
    NM(DYNSYM);
    NM(COMDAT);
    NM(INIT_ARRAY);
    NM(FINI_ARRAY);
    NM(PREINIT_ARRAY);
    NM(GROUP);
    NM(SYMTAB_SHNDX);
    default:
      {
        if ( reader->is_arm() )
        {
          switch ( sh_type )
          {
            NM(ARM_EXIDX);
            NM(ARM_PREEMPTMAP);
            NM(ARM_ATTRIBUTES);
            NM(ARM_DEBUGOVERLAY);
            NM(ARM_OVERLAYSECTION);
            NM(ANDROID_REL);
            NM(ANDROID_RELA);
          }
        }
        else if ( reader->is_mips() )
        {
          switch ( sh_type )
          {
            NM(MIPS_LIBLIST);
            NM(MIPS_MSYM);
            NM(MIPS_CONFLICT);
            NM(MIPS_GPTAB);
            NM(MIPS_UCODE);
            NM(MIPS_DEBUG);
            NM(MIPS_REGINFO);
            NM(MIPS_IFACE);
            NM(MIPS_CONTENT);
            NM(MIPS_OPTIONS);
            NM(MIPS_DWARF);
            NM(MIPS_SYMBOL_LIB);
            NM(MIPS_EVENTS);
            NM2(DVP_OVERLAY_TABLE, MIPS_DVP_OVERLAY_TABLE);
            NM2(DVP_OVERLAY,       MIPS_DVP_OVERLAY);
            NM(MIPS_IOPMOD);
            NM(MIPS_PSPREL);
          }
        }
        else if ( reader->get_header().e_machine == EM_PPC64 )
        {
          switch ( sh_type )
          {
            NM2(PS3PRX_RELA, PRXRELA);
          }
        }
        break;
      }
  }
  return nullptr;
#undef NM2
#undef NM
}

//-------------------------------------------------------------------------
qstring section_headers_t::sh_type_qstr(uint32 sh_type) const
{
  qstring s = sh_type_str(sh_type);
  if ( s.empty() )
    s.sprnt("%X", sh_type);
  return s;
}

//-------------------------------------------------------------------------
uint64 section_headers_t::get_size_in_file(const elf_shdr_t &sh) const
{
  if ( sh.sh_type == SHT_NOBITS )
    return 0;
  uint64 next_boundary = reader->size();
  // It may happen that we receive a section header that is _not_ part
  // of the list of original section headers. E.g., when we load symbols
  // from the dynamic-provided information.
  const elf_shdr_t *next_sh = &sh + 1;
  if ( next_sh >= begin()
    && next_sh < end()
    && next_sh->sh_offset < next_boundary
    && next_sh->sh_offset >= sh.sh_offset )
  {
    next_boundary = next_sh->sh_offset;
  }
  if ( sh.sh_offset >= next_boundary )
    return 0;
  return qmin(sh.sh_size, next_boundary - sh.sh_offset);
}

//-------------------------------------------------------------------------
void section_headers_t::read_file_contents(
        bytevec_t *out,
        const elf_shdr_t &sh) const
{
  uint64 nbytes = sh.sh_size;
  qstring hdrname = "?";
  get_name(&hdrname, sh);
  qstring text;
  text.sprnt("Size of %s", hdrname.c_str());
  validate_array_count(
        reader->get_linput(),
        &nbytes,
        1,
        text.c_str(),
        sh.sh_offset);
  out->resize(nbytes);
  reader->seek(sh.sh_offset);
  reader->safe_read(out->begin(), nbytes, /*apply_endianness=*/ false);
}

//-------------------------------------------------------------------------
bool section_headers_t::read_gnu_debuglink(
        qstring *out_link,
        uint32 *out_crc) const
{
  const elf_shdr_t *s = get(SHT_PROGBITS, ".gnu_debuglink");
  bool found = s != nullptr;
  if ( found )
  {
    bytevec_t buf;
    read_file_contents(&buf, *s);
    size_t sz = buf.size();
    found = sz > 4;
    if ( found )
    {
      if ( out_crc != nullptr )
      {
        uint32 crc = *(uint32 *)(buf.begin() + (sz - 4));
        if ( reader->get_ident().bytesex == ELFDATA2MSB )
          crc = swap32(crc);
        *out_crc = crc;
      }
      sz -= 4;
      if ( out_link != nullptr )
      {
        out_link->reserve(sz);
        for ( size_t i=0; i < sz; ++i )
        {
          uchar ch = buf[i];
          if ( ch == 0 )
            break;
          out_link->append(ch);
        }
      }
    }
  }
  return found;
}

//-------------------------------------------------------------------------
//                          program_headers_t
//----------------------------------------------------------------------------
const char *program_headers_t::p_type_str(uint32 p_type) const
{
#define NM(tp) case PT_##tp: return #tp
#define NM2(tp, nm) case PT_##tp: return #nm

  // OS-specific types
  uint8 os_abi = reader->get_ident().osabi;
  if ( os_abi == ELFOSABI_SOLARIS )
  {
    switch ( p_type )
    {
      NM2(SUNW_UNWIND,   UNWIND);
      NM2(SUNW_EH_FRAME, EH_FRAME);
      NM(SUNWBSS);
      NM2(SUNWSTACK,     STACK);
      NM2(SUNWDTRACE,    DTRACE);
      NM(SUNWCAP);
    }
  }
  else
  {
    switch ( p_type )
    {
      NM2(GNU_EH_FRAME, EH_FRAME);
      NM2(GNU_STACK, STACK);
      NM2(GNU_RELRO, RO-AFTER);
    }
  }

  switch ( p_type )
  {
    NM(NULL); // ok:NULL
    NM(LOAD);
    NM(DYNAMIC);
    NM(INTERP);
    NM(NOTE);
    NM(SHLIB);
    NM(PHDR);
    NM(TLS);

    NM2(PAX_FLAGS, PAX-FLAG);

    default:
      {
        uint32 m = reader->get_header().e_machine;
        if ( m == EM_ARM )
        {
          switch ( p_type )
          {
            NM2(ARM_ARCHEXT, ARCHEXT);
            NM2(ARM_EXIDX, EXIDX);
          }
        }
        else if ( m == EM_AARCH64 )
        {
          switch ( p_type )
          {
            NM2(AARCH64_ARCHEXT, ARCHEXT);
            NM2(AARCH64_UNWIND, EXIDX);
          }
        }
        else if ( m == EM_IA64 )
        {
          switch ( p_type )
          {
            NM(HP_TLS);
            NM(HP_CORE_NONE);
            NM(HP_CORE_VERSION);
            NM(HP_CORE_KERNEL);
            NM(HP_CORE_COMM);
            NM(HP_CORE_PROC);
            NM(HP_CORE_LOADABLE);
            NM(HP_CORE_STACK);
            NM(HP_CORE_SHM);
            NM(HP_CORE_MMF);
            NM(HP_PARALLEL);
            NM(HP_FASTBIND);
            NM(HP_OPT_ANNOT);
            NM(HP_HSL_ANNOT);
            NM(HP_STACK);
            NM(HP_CORE_UTSNAME);
            NM(HP_LINKER_FOOTPRINT);
            NM(IA_64_ARCHEXT);
            NM(IA_64_UNWIND);
          }
        }
        else if ( m == EM_MIPS )
        {
          switch ( p_type )
          {
            NM2(MIPS_IOPMOD, IOPMOD);
            NM2(MIPS_EEMOD, EEMOD);
            NM2(MIPS_PSPREL, PSPREL);
            NM2(MIPS_PSPREL2, PSPREL2);
            NM2(MIPS_REGINFO, REGINFO);
            NM2(MIPS_RTPROC, RTPROC);
            NM2(MIPS_OPTIONS, OPTIONS);
            NM2(MIPS_ABIFLAGS, ABIFLAGS);
          }
        }
        else if ( m == EM_PPC64 )
        {
          switch ( p_type )
          {
            case PHT_PS3PRX_RELA : return "PRXRELA";
          }
        }
        return nullptr;
      }
  }
#undef NM2
#undef NM
}

//----------------------------------------------------------------------------
qstring program_headers_t::p_type_qstr(uint32 p_type) const
{
  qstring s = p_type_str(p_type);
  if ( s.empty() )
    s.sprnt("%08X", p_type);
  return s;
}

//----------------------------------------------------------------------------
uint64 program_headers_t::get_size_in_file(const elf_phdr_t &p) const
{
  assert_initialized();
  if ( p.p_type != PT_LOAD
    && p.p_type != PT_INTERP
    && p.p_type != PT_NOTE
    && p.p_type != PT_PHDR )
  {
    return 0;
  }

  uint64 next_boundary = reader->size();
  if ( p.p_offset >= next_boundary )
    return 0;

  int idx = &p - begin();
  if ( idx > -1 && (idx+1) < pheaders.size() )
  {
    const elf_phdr_t *np = CONST_CAST(program_headers_t*)(this)->get(idx+1);
    if ( np->p_offset >= p.p_offset )
      next_boundary = np->p_offset;
  }
  return qmin(p.p_filesz, next_boundary - p.p_offset);
}

//----------------------------------------------------------------------------
void program_headers_t::read_file_contents(
        bytevec_t *out,
        const elf_phdr_t &p) const
{
  assert_initialized();

  uint64 nbytes = p.p_filesz;
  qstring text;
  text.sprnt("Size of %s", p_type_qstr(p.p_type).c_str());
  validate_array_count(
        reader->get_linput(),
        &nbytes,
        1,
        text.c_str(),
        p.p_offset);
  out->resize(nbytes);
  reader->seek(p.p_offset);
  reader->safe_read(out->begin(), nbytes, /*apply_endianness=*/ false);
}

//----------------------------------------------------------------------------
// Note Section
//
bool elf_note_t::unpack_sz(
        size_t *out,
        size_t *pstart,
        const bytevec_t &buf,
        bool mf)
{
  const size_t start = *pstart;
  const size_t szel = sizeof(uint32);
  if ( !is_add_ok(start, szel) || start + szel > buf.size() )
    return false;

  if ( out != nullptr )
  {
    uint32 res = *(uint32 *)&buf[start];
    if ( mf )
      res = swap32(res);
    *out = res;
  }
  *pstart += szel;
  return true;
}

//----------------------------------------------------------------------------
bool elf_note_t::unpack_mem(
        qstring *out,
        const bytevec_t &buf,
        size_t start,
        size_t len,
        bool as_strz)
{
  if ( !is_add_ok(start, len) || start + len > buf.size() )
    return false;
  out->qclear();
  if ( as_strz )
  {
    out->reserve(len);
    for ( int i=0; i < len; ++i )
    {
      char ch = buf[start + i];
      if ( ch == '\0' )
        break;
      out->append(ch);
    }
  }
  else
  {
    out->resize(len, '\0');
    memcpy(out->begin(), &buf[start], len);
  }
  return true;
}

//----------------------------------------------------------------------------
bool elf_note_t::unpack_strz(
        qstring *out,
        const bytevec_t &buf,
        size_t start,
        size_t len)
{
  return unpack_mem(out, buf, start, len, /*as_strz=*/ true);
}

//----------------------------------------------------------------------------
bool elf_note_t::unpack(
        elf_note_t *entry,
        size_t *start,
        const bytevec_t &buf,
        bool mf)
{
  size_t end = *start;
  size_t namesz;
  size_t descsz;
  size_t type;
  if ( !elf_note_t::unpack_sz(&namesz, &end, buf, mf)
    || !elf_note_t::unpack_sz(&descsz, &end, buf, mf)
    || !elf_note_t::unpack_sz(&type, &end, buf, mf) )
  {
    return false;
  }

  qstring name;
  if ( !elf_note_t::unpack_strz(&name, buf, end, namesz) )
    return false;
  end += align_up(namesz, 4);

  qstring desc;
  if ( !elf_note_t::unpack_mem(&desc, buf, end, descsz) )
    return false;
  end += align_up(descsz, 4);

  if ( entry != nullptr )
  {
    entry->name = name;
    entry->desc = desc;
    entry->type = type;
  }
  *start = end;
  return true;
}

//----------------------------------------------------------------------------
void notes_t::add(const bytevec_t &buf)
{
  bool mf = reader->is_msb();
  size_t start = 0;
  while ( start < buf.size() )
  {
    elf_note_t &n = notes.push_back();
    if ( !elf_note_t::unpack(&n, &start, buf, mf) )
    {
      notes.pop_back();
      break;
    }
  }
}

//----------------------------------------------------------------------------
bool notes_t::get_build_id(qstring *out) const
{
  assert_initialized();

  for ( elf_notes_t::const_iterator p=notes.begin(); p != notes.end(); ++p )
  {
    const elf_note_t &en = *p;
    if ( en.name == NT_NAME_GNU && en.type == NT_GNU_BUILD_ID )
    {
      int sz = en.desc.length();
      out->qclear();
      out->reserve(2*sz);
      for ( int i=0; i < sz; ++i )
        out->cat_sprnt("%02x", (unsigned char)en.desc[i]);
      return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------------
const char *d_note_gnu_type_str(uint64 type)
{
#define NM(tp) case tp: return #tp
  switch ( type )
  {
    NM(NT_GNU_ABI_TAG);
    NM(NT_GNU_HWCAP);
    NM(NT_GNU_BUILD_ID);
    NM(NT_GNU_GOLD_VERSION);
    NM(NT_GNU_PROPERTY_TYPE_0);
  }
  return nullptr;
#undef NM
}

//----------------------------------------------------------------------------
const char *d_note_linux_type_str(uint64 type)
{
#define NM(tp) case tp: return #tp
  switch ( type )
  {
    NM(NT_PRXFPREG);
    NM(NT_PPC_VMX);
    NM(NT_PPC_VSX);
    NM(NT_PPC_TAR);
    NM(NT_PPC_PPR);
    NM(NT_PPC_DSCR);
    NM(NT_PPC_EBB);
    NM(NT_PPC_PMU);
    NM(NT_PPC_TM_CGPR);
    NM(NT_PPC_TM_CFPR);
    NM(NT_PPC_TM_CVMX);
    NM(NT_PPC_TM_CVSX);
    NM(NT_PPC_TM_SPR);
    NM(NT_PPC_TM_CTAR);
    NM(NT_PPC_TM_CPPR);
    NM(NT_PPC_TM_CDSCR);
    NM(NT_386_TLS);
    NM(NT_386_IOPERM);
    NM(NT_X86_XSTATE);
    NM(NT_S390_HIGH_GPRS);
    NM(NT_S390_TIMER);
    NM(NT_S390_TODCMP);
    NM(NT_S390_TODPREG);
    NM(NT_S390_CTRS);
    NM(NT_S390_PREFIX);
    NM(NT_S390_LAST_BREAK);
    NM(NT_S390_SYSTEM_CALL);
    NM(NT_S390_TDB);
    NM(NT_S390_VXRS_LOW);
    NM(NT_S390_VXRS_HIGH);
    NM(NT_S390_GS_CB);
    NM(NT_S390_GS_BC);
    NM(NT_ARM_VFP);
    NM(NT_ARM_TLS);
    NM(NT_ARM_HW_BREAK);
    NM(NT_ARM_HW_WATCH);
    NM(NT_ARM_SVE);
  }
  return nullptr;
#undef NM
}

//----------------------------------------------------------------------------
const char *d_note_core_type_str(uint64 type)
{
#define NM(tp) case tp: return #tp
  switch ( type )
  {
    NM(NT_PRSTATUS);
    NM(NT_FPREGSET);
    NM(NT_PRPSINFO);
    NM(NT_TASKSTRUCT);
    NM(NT_AUXV);
    NM(NT_SIGINFO);
    NM(NT_FILE);
    NM(NT_PSTATUS);
    NM(NT_FPREGS);
    NM(NT_PSINFO);
    NM(NT_LWPSTATUS);
    NM(NT_LWPSINFO);
    NM(NT_WIN32PSTATUS);
  }
  return nullptr;
#undef NM
}

//----------------------------------------------------------------------------
template<> void buffered_input_t<sym_rel>::start_reading()
{
  reader.get_arch_specific()->on_start_symbols(reader);
}

//----------------------------------------------------------------------------
template<> bool buffered_input_t<sym_rel>::read_item(sym_rel &storage)
{
  storage = sym_rel();

  elf_sym_t &orig = storage.original;
#define _safe(expr) \
  do                \
  {                 \
    if ( expr < 0 ) \
      return false; \
  } while ( 0 )
  _safe(reader.read_symbol(&orig));

  ushort bind = ELF_ST_BIND(orig.st_info);
  // assert: bind <= STB_HIPROC
  if ( bind > STB_WEAK )
  {
    CASSERT(STB_LOCAL < STB_WEAK && STB_GLOBAL < STB_WEAK);   //-V590 expression is excessive
    if ( reader.get_header().e_machine == EM_ARM && bind == STB_LOPROC+1 )
      // codewarrior for arm seems to use this binding type similar to local or weak
      bind = STB_WEAK;
    else if ( bind < STB_LOOS )
      bind = STB_INVALID;
  }

  storage.bind  = (uchar) bind;
  storage.sec   = 0;
  storage.type  = ELF_ST_TYPE(orig.st_info);
  storage.value = orig.st_value + reader.get_load_bias();
  storage.size  = orig.st_size;
  return true;
}

//----------------------------------------------------------------------------
static inline void swap_64_at(uint64 *ptr)
{
  *ptr = swap64(*ptr);
}

//----------------------------------------------------------------------------
static inline void swap_64_at(int64 *ptr)
{
  *ptr = swap64(*ptr);
}

//----------------------------------------------------------------------------
#define swap_addr(ptr)  swap_64_at(ptr);
#define swap_xword(ptr) swap_64_at(ptr);
#define swap_sxword(ptr) swap_64_at(ptr);

//----------------------------------------------------------------------------
template<> ssize_t buffered_input_t<elf_rel_t>::read_items(size_t max)
{
  if ( isize != sizeof(Elf32_Rel) && isize != sizeof(Elf64_Rel) )
    return 0;
  if ( !is_mul_ok<uint64>(read, isize) || !is_mul_ok(max, isize) )
    return 0;
  input_status_t save_excursion(reader);
  if ( save_excursion.seek(offset + (read * isize)) == -1 )
    return 0;
  ssize_t bytes = max * isize;
  if ( qlread(reader.get_linput(), buffer.begin(), bytes) != bytes )
    return 0;

#if __MF__
  bool swap = !reader.is_msb();
#else
  bool swap = reader.is_msb();
#endif

  if ( isize == sizeof(Elf32_Rel) )
  {
    Elf32_Rel *rel32 = (Elf32_Rel *) buffer.begin();
    Elf64_Rel *rel64 = (Elf64_Rel *) buffer.begin();
    rel32 += max - 1;
    rel64 += max - 1;
    uint64 inf64, off64;
    for ( size_t i = 0; i < max; i++, rel32--, rel64-- )
    {
      if ( swap )
      {
        inf64 = swap32(rel32->r_info);
        off64 = swap32(rel32->r_offset);
      }
      else
      {
        inf64 = rel32->r_info;
        off64 = rel32->r_offset;
      }
      rel64->r_info   = inf64;
      rel64->r_offset = off64;
    }
  }
  else
  {
    if ( swap )
    {
      elf_rel_t *rel64 = (elf_rel_t *)buffer.begin();
      for ( size_t i = 0; i < max; i++, rel64++ )
      {
        swap_addr(&rel64->r_offset);
        swap_xword(&rel64->r_info);
      }
    }
  }

  return max;
}

//----------------------------------------------------------------------------
template<> ssize_t buffered_input_t<elf_rela_t>::read_items(size_t max)
{
  if ( isize != sizeof(Elf32_Rela) && isize != sizeof(Elf64_Rela) )
    return 0;
  if ( !is_mul_ok<uint64>(read, isize) || !is_mul_ok(max, isize) )
    return 0;
  input_status_t save_excursion(reader);
  if ( save_excursion.seek(offset + (read * isize)) == -1 )
    return 0;
  ssize_t bytes = max * isize;
  if ( qlread(reader.get_linput(), buffer.begin(), bytes) != bytes )
    return 0;

#if __MF__
  bool swap = !reader.is_msb();
#else
  bool swap = reader.is_msb();
#endif

  if ( isize == sizeof(Elf32_Rela) )
  {
    Elf32_Rela *rela32 = (Elf32_Rela *) buffer.begin();
    Elf64_Rela *rela64 = (Elf64_Rela *) buffer.begin();
    rela32 += max - 1;
    rela64 += max - 1;
    uint64 inf64, off64;
    int64 addend;
    for ( size_t i = 0; i < max; i++, rela32--, rela64-- )
    {
      if ( swap )
      {
        inf64  = swap32(rela32->r_info);
        off64  = swap32(rela32->r_offset);
        addend = swap32(rela32->r_addend);
      }
      else
      {
        inf64  = rela32->r_info;
        off64  = rela32->r_offset;
        addend = rela32->r_addend;
      }
      rela64->r_info   = inf64;
      rela64->r_offset = off64;
      rela64->r_addend = addend;
    }
  }
  else
  {
    if ( swap )
    {
      elf_rela_t *rela64 = (elf_rela_t *)buffer.begin();
      for ( size_t i = 0; i < max; i++, rela64++ )
      {
        swap_addr(&rela64->r_offset);
        swap_xword(&rela64->r_info);
        swap_sxword(&rela64->r_addend);
      }
    }
  }

  return max;
}

//--------------------------------------------------------------------------
class aps2_unpacker_t
{
  enum
  {
    RELOCATION_GROUPED_BY_INFO_FLAG = 1,
    RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2,
    RELOCATION_GROUPED_BY_ADDEND_FLAG = 4,
    RELOCATION_GROUP_HAS_ADDEND_FLAG = 8
  };

  const uchar *ptr;
  const uchar *end;
  int flags;
  bool ok;

  bool grouped_by_offset_delta() const { return (flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0; }
  bool grouped_by_info() const         { return (flags & RELOCATION_GROUPED_BY_INFO_FLAG) != 0; }
  bool grouped_by_addend() const       { return (flags & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0; }
  bool group_has_addend() const        { return (flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0; }
  int64 getval()
  {
    int64 v;
    if ( !unpack_sleb128(&v, &ptr, end) )
      ok = false;
    return v;
  }

public:
  aps2_unpacker_t(const uchar *p, const uchar *e)
    : ptr(p), end(e), flags(0), ok(true) {}

  //--------------------------------------------------------------------------
  void unpack(elf_rela_vec_t *out, int64 nrelocs)
  {
    elf_rela_t rela;
    rela.r_offset = getval();
    rela.r_addend = 0;
    rela.r_info = 0;

    out->resize(nrelocs);
    size_t n = 0;

    while ( ok ) // repeat for all groups
    {
      int64 nrels = getval(); // number of relocs in the group
      flags = getval(); // flags for the group

      int64 offset_delta = 0;
      if ( grouped_by_offset_delta() )
        offset_delta = getval();

      if ( grouped_by_info() )
        rela.r_info = getval();

      if ( grouped_by_addend() && group_has_addend() )
        rela.r_addend += getval();
      else if ( !group_has_addend() )
        rela.r_addend = 0;

      // unpack all relocs in the group
      for ( int64 i=0; i < nrels; i++ )
      {
        if ( !grouped_by_offset_delta() )
          offset_delta = getval();
        rela.r_offset += offset_delta;

        if ( !grouped_by_info() )
          rela.r_info = getval();

        if ( group_has_addend() && !grouped_by_addend() )
          rela.r_addend += getval();

        if ( !ok )
        { // some kind of error occurred, remove the uninitialized relocs
          out->resize(n);
          return;
        }
        if ( n == nrelocs )
          return; // safety check
        out->at(n++) = rela;
      }
    }
  }
};

//----------------------------------------------------------------------------
bool buffered_rela_t::next(elf_rela_t *&storage)
{
  if ( !packed )
    return inherited::next(storage);

  if ( cur >= end )
  {
    if ( end != 0 )
      return false;

    // read everything at once and unpack
    bytevec_t bytes;
    bytes.resize(count);
    input_status_t save_excursion(reader);
    if ( save_excursion.seek(offset) == -1 )
      return false;
    ssize_t nread = qlread(reader.get_linput(), bytes.begin(), count);
    if ( nread < count )
    {
      msg("READ ERROR: read only %" FMT_ZS " bytes instead of %" FMT_64 "d bytes\n",
          nread, count);
      if ( nread <= 8 )
        return false;
      bytes.resize(nread);
    }
    if ( bytes.size() < sizeof(uint32) )
      return false;

    const uchar *ptr = bytes.begin();
    const uchar *endp = bytes.end();
    uint32 magic = *(uint32*)ptr;
    ptr += 4;

#define PKREL_APR1 MC4('A','P','R','1')
#define PKREL_APA1 MC4('A','P','A','1')
#define PKREL_APS2 MC4('A','P','S','2')

    int64 n;
    if ( !unpack_sleb128(&n, &ptr, endp) )
      return false;
    if ( n <= 0 || n >= count ) // sanity check
      return false;

    switch ( magic )
    {
      default: // unknown magic
//      case PKREL_APR1:
//      case PKREL_APA1:
        ask_for_feedback(
          "The relocation packing method '%4.4s' is not supported yet.",
          (const char *)bytes.begin());
        return false;
      case PKREL_APS2:
        aps2_unpacker_t unp(ptr, endp);
        unp.unpack(&buffer, n);
        break;
    }

    end = n;
  }
  storage = &buffer[cur++];
  return true;
}

//----------------------------------------------------------------------------
template<> bool buffered_input_t<elf_dyn_t>::read_item(elf_dyn_t &storage)
{
  // FIXME: Load bias?
  memset(&storage, 0, sizeof(storage));
  _safe(reader.read_sxword(&storage.d_tag));
  _safe(reader.read_addr(&storage.d_un));
#undef _safe
  return true;
}

//-------------------------------------------------------------------------
void dynamic_info_t::initialize(const reader_t &reader)
{
  symtab().entsize = reader.stdsizes.entries.sym;
  rel().entsize = reader.stdsizes.dyn.rel;
  rela().entsize = reader.stdsizes.dyn.rela;
  QASSERT(20037, symtab().entsize != 0 && rel().entsize != 0 && rela().entsize != 0);
}

//----------------------------------------------------------------------------
bool dynamic_info_t::fill_section_header(
        elf_shdr_t *sh,
        dynamic_info_type_t type) const
{
  int shtype;
  switch ( type )
  {
    case DIT_SYMTAB:       shtype = SHT_DYNSYM;      break;
    case DIT_REL:          shtype = SHT_REL;         break;
    case DIT_RELA:         shtype = SHT_RELA;        break;
    case DIT_ANDROID_REL:  shtype = SHT_REL;         break;
    case DIT_ANDROID_RELA: shtype = SHT_RELA;        break;
    case DIT_VERDEF:       shtype = SHT_GNU_verdef;  break;
    case DIT_VERNEED:      shtype = SHT_GNU_verneed; break;
    case DIT_VERSYM:       shtype = SHT_GNU_versym;  break;
    case DIT_PLT:
      shtype = plt_rel_type == DT_RELA ? SHT_RELA : SHT_REL;
      break;
    default:
      QASSERT(20101, false);
  };
  const entry_t &entry = entries[type];
  if ( !entry.is_valid() )
    return false;
  memset(sh, 0, sizeof(*sh));
  sh->sh_addr    = entry.addr;
  sh->sh_offset  = entry.offset;
  sh->sh_size    = entry.size;
  sh->sh_info    = entry.info;
  sh->sh_type    = shtype;
  if ( type != DIT_ANDROID_REL && type != DIT_ANDROID_RELA )
  {
    sh->sh_entsize = sh->sh_type == SHT_DYNSYM ? entry.entsize
                   : sh->sh_type == SHT_RELA   ? rela().entsize
                   :                             rel().entsize;
  }
  return true;
}

//----------------------------------------------------------------------------
qstring dynamic_info_t::d_tag_str_ext(const reader_t &reader, int64 d_tag)
{
  qstring buf = d_tag_str(reader, d_tag);
  if ( buf.empty() )
  {
    buf.sprnt("DT_????     Unknown (%08" FMT_64 "X)", d_tag);
    return buf;
  }
  if ( buf.length() < 12 )
    buf.resize(12, ' ');

  uint16 e_machine = reader.get_header().e_machine;
  const char *ext = nullptr;
  switch ( d_tag )
  {
    case DT_NULL:
      ext = "end of _DYNAMIC array";
      break;
    case DT_NEEDED:
      ext = "str-table offset name to needed library";
      break;
    case DT_PLTRELSZ:
      ext = "tot.size in bytes of relocation entries";
      break;
    case DT_HASH:
      ext = "addr. of symbol hash table";
      break;
    case DT_STRTAB:
      ext = "addr of string table";
      break;
    case DT_SYMTAB:
      ext = "addr of symbol table";
      break;
    case DT_RELA:
      ext = "addr of relocation table";
      break;
    case DT_RELASZ:
      ext = "size in bytes of DT_RELA table";
      break;
    case DT_RELAENT:
      ext = "size in bytes of DT_RELA entry";
      break;
    case DT_STRSZ:
      ext = "size in bytes of string table";
      break;
    case DT_SYMENT:
      ext = "size in bytes of symbol table entry";
      break;
    case DT_INIT:
      ext = "addr. of initialization function";
      break;
    case DT_FINI:
      ext = "addr. of termination function";
      break;
    case DT_SONAME:
      ext = "offs in str.-table - name of shared object";
      break;
    case DT_RPATH:
      ext = "offs in str-table - search path";
      break;
    case DT_RUNPATH:
      ext = "array of search pathes";
      break;
    case DT_SYMBOLIC:
      ext = "start search of shared object";
      break;
    case DT_REL:
      ext = "addr of relocation table";
      break;
    case DT_RELSZ:
      ext = "tot.size in bytes of DT_REL";
      break;
    case DT_RELENT:
      ext = "size in bytes of DT_REL entry";
      break;
    case DT_PLTREL:
      ext = "type of relocation (DT_REL or DT_RELA)";
      break;
    case DT_DEBUG:
      ext = "not specified";
      break;
    case DT_TEXTREL:
      ext = "segment permisson";
      break;
    case DT_PLTGOT:
      if ( e_machine == EM_PPC )
        ext = "addr of PLT";
      break;
    case DT_JMPREL:
      if ( e_machine == EM_PPC )
        ext = "addr of JMP_SLOT relocation table";
      else
        ext = "addr of dlt procedure (if present)";
      break;
    case DT_PPC_GOT:
      if ( e_machine == EM_PPC )
        ext = "addr of _GLOBAL_OFFSET_TABLE_";
      break;
  }
  if ( ext == nullptr && reader.is_arm() )
  {
    switch ( d_tag )
    {
      case DT_ANDROID_REL:
        ext = " offset of packed REL data";
        break;
      case DT_ANDROID_RELSZ:
        ext = " size of DT_ANDROID_REL";
        break;
      case DT_ANDROID_RELA:
        ext = " offset of packed RELA data";
        break;
      case DT_ANDROID_RELASZ:
        ext = " size of DT_ANDROID_RELA";
        break;
    }
  }
  buf.append(ext);
  return buf;
}

//----------------------------------------------------------------------------
const char *dynamic_info_t::d_tag_str(const reader_t &reader, int64 d_tag)
{
  uint16 e_machine = reader.get_header().e_machine;
#define NM(tp) case tp: return #tp

  // OS-specific types
  uint8 os_abi = reader.get_ident().osabi;
  if ( os_abi == ELFOSABI_SOLARIS )
  {
    switch ( d_tag )
    {
      NM(DT_SUNW_AUXILIARY);
//      NM(DT_SUNW_RTLDINF);
      NM(DT_SUNW_FILTER);
      NM(DT_SUNW_CAP);
      NM(DT_SUNW_SYMTAB);
      NM(DT_SUNW_SYMSZ);
      NM(DT_SUNW_ENCODING);
//      NM(DT_SUNW_SORTENT);
      NM(DT_SUNW_SYMSORT);
      NM(DT_SUNW_SYMSORTSZ);
      NM(DT_SUNW_TLSSORT);
      NM(DT_SUNW_TLSSORTSZ);
      NM(DT_SUNW_CAPINFO);
      NM(DT_SUNW_STRPAD);
      NM(DT_SUNW_CAPCHAIN);
      NM(DT_SUNW_LDMACH);
      NM(DT_SUNW_CAPCHAINENT);
      NM(DT_SUNW_CAPCHAINSZ);
      NM(DT_SUNW_PARENT);
      NM(DT_SUNW_ASLR);
      NM(DT_SUNW_RELAX);
      NM(DT_SUNW_NXHEAP);
      NM(DT_SUNW_NXSTACK);
    }
  }

  switch ( d_tag )
  {
    NM(DT_NULL);
    NM(DT_NEEDED);
    NM(DT_PLTRELSZ);
    NM(DT_HASH);
    NM(DT_STRTAB);
    NM(DT_SYMTAB);
    NM(DT_RELA);
    NM(DT_RELASZ);
    NM(DT_RELAENT);
    NM(DT_STRSZ);
    NM(DT_SYMENT);
    NM(DT_INIT);
    NM(DT_FINI);
    NM(DT_SONAME);
    NM(DT_RPATH);
    NM(DT_RUNPATH);
    NM(DT_SYMBOLIC);
    NM(DT_REL);
    NM(DT_RELSZ);
    NM(DT_RELENT);
    NM(DT_PLTREL);
    NM(DT_DEBUG);
    NM(DT_TEXTREL);

    NM(DT_PLTGOT);
    NM(DT_JMPREL);

    NM(DT_BIND_NOW);
    NM(DT_PREINIT_ARRAY);
    NM(DT_INIT_ARRAY);
    NM(DT_FINI_ARRAY);
    NM(DT_INIT_ARRAYSZ);
    NM(DT_FINI_ARRAYSZ);
    NM(DT_PREINIT_ARRAYSZ);
    NM(DT_FLAGS);

    NM(DT_VALRNGLO);
    NM(DT_GNU_PRELINKED);
    NM(DT_GNU_CONFLICTSZ);
    NM(DT_GNU_LIBLISTSZ);
    NM(DT_CHECKSUM);
    NM(DT_PLTPADSZ);
    NM(DT_MOVEENT);
    NM(DT_MOVESZ);
    NM(DT_FEATURE);
    NM(DT_POSFLAG_1);
    NM(DT_SYMINSZ);
    NM(DT_SYMINENT);
//    NM(DT_VALRNGHI);
    NM(DT_ADDRRNGLO);
    NM(DT_GNU_HASH);
    NM(DT_TLSDESC_PLT);
    NM(DT_TLSDESC_GOT);
    NM(DT_GNU_CONFLICT);
    NM(DT_GNU_LIBLIST);
    NM(DT_CONFIG);
    NM(DT_DEPAUDIT);
    NM(DT_AUDIT);
    NM(DT_PLTPAD);
    NM(DT_MOVETAB);
    NM(DT_SYMINFO);
//    NM(DT_ADDRRNGHI);
    NM(DT_RELACOUNT);
    NM(DT_RELCOUNT);
    NM(DT_FLAGS_1);
    NM(DT_VERDEF);
    NM(DT_VERDEFNUM);
    NM(DT_VERNEED);
    NM(DT_VERNEEDNUM);
    NM(DT_VERSYM);

    NM(DT_AUXILIARY);
    NM(DT_USED);
    NM(DT_FILTER);
  }
  if ( reader.is_mips() )
  {
    switch ( d_tag )
    {
      NM(DT_MIPS_RLD_VERSION);
      NM(DT_MIPS_TIME_STAMP);
      NM(DT_MIPS_ICHECKSUM);
      NM(DT_MIPS_IVERSION);
      NM(DT_MIPS_FLAGS);
      NM(DT_MIPS_BASE_ADDRESS);
      NM(DT_MIPS_MSYM);
      NM(DT_MIPS_CONFLICT);
      NM(DT_MIPS_LIBLIST);
      NM(DT_MIPS_LOCAL_GOTNO);
      NM(DT_MIPS_CONFLICTNO);
      NM(DT_MIPS_LIBLISTNO);
      NM(DT_MIPS_SYMTABNO);
      NM(DT_MIPS_UNREFEXTNO);
      NM(DT_MIPS_GOTSYM);
      NM(DT_MIPS_HIPAGENO);
      NM(DT_MIPS_RLD_MAP);
      NM(DT_MIPS_DELTA_CLASS);
      NM(DT_MIPS_DELTA_CLASS_NO);
      NM(DT_MIPS_DELTA_INSTANCE);
      NM(DT_MIPS_DELTA_INSTANCE_NO);
      NM(DT_MIPS_DELTA_RELOC);
      NM(DT_MIPS_DELTA_RELOC_NO);
      NM(DT_MIPS_DELTA_SYM);
      NM(DT_MIPS_DELTA_SYM_NO);
      NM(DT_MIPS_DELTA_CLASSSYM);
      NM(DT_MIPS_DELTA_CLASSSYM_NO);
      NM(DT_MIPS_CXX_FLAGS);
      NM(DT_MIPS_PIXIE_INIT);
      NM(DT_MIPS_SYMBOL_LIB);
      NM(DT_MIPS_LOCALPAGE_GOTIDX);
      NM(DT_MIPS_LOCAL_GOTIDX);
      NM(DT_MIPS_HIDDEN_GOTIDX);
      NM(DT_MIPS_PROTECTED_GOTIDX);
      NM(DT_MIPS_OPTIONS);
      NM(DT_MIPS_INTERFACE);
      NM(DT_MIPS_DYNSTR_ALIGN);
      NM(DT_MIPS_INTERFACE_SIZE);
      NM(DT_MIPS_RLD_TEXT_RESOLVE_ADDR);
      NM(DT_MIPS_PERF_SUFFIX);
      NM(DT_MIPS_COMPACT_SIZE);
      NM(DT_MIPS_GP_VALUE);
      NM(DT_MIPS_AUX_DYNAMIC);
      NM(DT_MIPS_PLTGOT);
      NM(DT_MIPS_RWPLT);
    }
  }
  else if ( e_machine == EM_IA64 )
  {
    switch ( d_tag )
    {
      NM(DT_HP_LOAD_MAP);
      NM(DT_HP_DLD_FLAGS);
      NM(DT_HP_DLD_HOOK);
      NM(DT_HP_UX10_INIT);
      NM(DT_HP_UX10_INITSZ);
      NM(DT_HP_PREINIT);
      NM(DT_HP_PREINITSZ);
      NM(DT_HP_NEEDED);
      NM(DT_HP_TIME_STAMP);
      NM(DT_HP_CHECKSUM);
      NM(DT_HP_GST_SIZE);
      NM(DT_HP_GST_VERSION);
      NM(DT_HP_GST_HASHVAL);
      NM(DT_HP_EPLTREL);
      NM(DT_HP_EPLTRELSZ);
      NM(DT_HP_FILTERED);
      NM(DT_HP_FILTER_TLS);
      NM(DT_HP_COMPAT_FILTERED);
      NM(DT_HP_LAZYLOAD);
      NM(DT_HP_BIND_NOW_COUNT);
      NM(DT_PLT);
      NM(DT_PLT_SIZE);
      NM(DT_DLT);
      NM(DT_DLT_SIZE);
      NM(DT_HP_SYM_CHECKSUM);
      NM(DT_IA_64_PLT_RESERVE);
    }
  }
  else if ( e_machine == EM_PPC )
  {
    switch ( d_tag )
    {
      NM(DT_PPC_GOT);
    }
  }
  else if ( reader.is_arm() )
  {
    switch ( d_tag )
    {
      NM(DT_ANDROID_REL);
      NM(DT_ANDROID_RELSZ);
      NM(DT_ANDROID_RELA);
      NM(DT_ANDROID_RELASZ);
    }
  }

#undef NM
  return nullptr;
}

//----------------------------------------------------------------------------
qstring dynamic_info_t::d_un_str(const reader_t &reader, int64 d_tag, int64 d_un)
{
  qstring name;
  switch ( d_tag )
  {
    case DT_SONAME:
    case DT_RPATH:
    case DT_RUNPATH:
    case DT_NEEDED:
    case DT_AUXILIARY:
    case DT_FILTER:
    case DT_CONFIG:
    case DT_DEPAUDIT:
    case DT_AUDIT:
      reader.get_name(&name, reader.dyn_strtab, uint32(d_un));
      break;
  }
  return name;
}

//----------------------------------------------------------------------------
size_t symrel_cache_t::slice_start(slice_type_t t) const
{
  check_type(t);
  return t == SLT_DYNSYM ? dynsym_index : 0;
}

//----------------------------------------------------------------------------
size_t symrel_cache_t::slice_end(slice_type_t t) const
{
  check_type(t);
  return t == SLT_SYMTAB ? dynsym_index : storage.size();
}

//----------------------------------------------------------------------------
sym_rel &symrel_cache_t::append(slice_type_t t)
{
  check_type(t);
  size_t idx = slice_end(t);
  if ( t == SLT_SYMTAB )
    ++dynsym_index;
  if ( idx == storage.size() )
  {
    return storage.push_back();
  }
  else
  {
    QASSERT(20133, idx <= storage.size());
    qvector<sym_rel>::iterator it = storage.begin() + idx;
    storage.insert(it, sym_rel());
    return *it;
  }
}

// ===========================================================================
//                           ARM-specific code.
// ===========================================================================

//----------------------------------------------------------------------------
bool arm_arch_specific_t::is_mapping_symbol(const char *name) const
{
  if ( name == nullptr )
    return false;

  if ( name[0] == '$'
    && name[1] != '\0'
    && (name[2] == '\0' || name[2] == '.') )
  {
    switch ( name[1] )
    {
      case 'a':   // labels the first byte of a sequence of ARM instructions. Its type is STT_FUNC.
      case 't':   // labels the first byte of a sequence of Thumb instructions. Its type is STT_FUNC.
      case 'b':   // labels a Thumb BL instruction. Its type is STT_FUNC.
      case 'd':   // labels the first byte of a sequence of data items. Its type is STT_OBJECT.
      case 'p':   // labels the final, PC-modifying instruction of an
                  // indirect function call. Its type is STT_FUNC.
                  // (An indirect call is a call through a function pointer
                  // variable). $p does not label the PC-modifying
                  // instruction of a function return sequence.
      case 'f':   // labels a function pointer constant (static pointer to code).
                  // Its type is STT_OBJECT.
      case 'x':   // Start of a sequence of A64 instructions
        return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::on_start_symbols(reader_t &)
{
  has_mapsym = false;
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::on_symbol_read(reader_t &reader, sym_rel &sym)
{
  const char *name = sym.get_original_name(reader).c_str();
  if ( is_mapping_symbol(name) )
  {
    has_mapsym = true;

    // assert: name != nullptr
    char name1 = name[1];
    if ( name1 == 'a' || name1 == 't' || name1 == 'x' )
    {
      isa_t isa = name1 == 'a' || name1 == 'x' ? isa_arm : isa_thumb;
      if ( name1 == 't' )
        sym.set_flag(thumb_function);
      notify_isa(reader, sym, isa, true);
      if ( is_mapping_symbols_tracking() )
        set_isa(sym, isa);
    }
  }
  else
  {
    uchar bind = sym.bind;

    // Keep going _only_ if function
    ushort orig_type = ELF_ST_TYPE(sym.original.st_info);
    if ( (orig_type != STT_FUNC
       && orig_type != STT_ARM_TFUNC
       && orig_type != STT_ARM_16BIT )
      || (bind != STB_GLOBAL
       && bind != STB_LOCAL
       && bind != STB_WEAK) )
    {
      return;
    }

    sym.value &= ~1;

    // If original type is ARM_TFUNC, make it FUNC,
    // so it gets treated as a regular FUNC by
    // upstream code.
    if ( orig_type == STT_ARM_TFUNC )
      sym.type = STT_FUNC;

    if ( (orig_type == STT_ARM_TFUNC
       || orig_type == STT_ARM_16BIT
       || (sym.original.st_value & 1) != 0) )
    {
      sym.set_flag(thumb_function);
      notify_isa(reader, sym, isa_thumb, false);
    }

    if ( !sym.has_flag(thumb_function)
      && is_mapping_symbols_tracking()
      && get_isa(sym) == isa_thumb )
    {
      sym.set_flag(thumb_function);
      notify_isa(reader, sym, isa_thumb, false);
    }

    if ( !sym.has_flag(thumb_function) )
      notify_isa(reader, sym, isa_arm, false);
  }
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::set_isa(const sym_rel &symbol, isa_t isa)
{
  isa_ranges_t::iterator it = isa_ranges.find(symbol.sec);
  if ( it == isa_ranges.end() )
  {
    isa_ranges[symbol.sec] = section_isa_ranges_t();
    it = isa_ranges.find(symbol.sec);
  }

  section_isa_ranges_t &section_isa_ranges = it->second;
  section_isa_ranges[symbol.original.st_value] = isa;
}

//----------------------------------------------------------------------------
arm_arch_specific_t::isa_t arm_arch_specific_t::get_isa(const sym_rel &symbol) const
{
  isa_t current_isa = isa_arm;
  isa_ranges_t::const_iterator it = isa_ranges.find(symbol.sec);
  if ( it != isa_ranges.end() )
  {
    const section_isa_ranges_t &section_isa_ranges = it->second;
    section_isa_ranges_t::const_iterator p;
    section_isa_ranges_t::const_iterator end = section_isa_ranges.end();
    for ( p = section_isa_ranges.begin(); p != end; ++p )
    {
      uint64 offset_in_section = p->first;
      if ( offset_in_section > symbol.original.st_value )
        break;

      current_isa = p->second;
    }
  }
  return current_isa;
}

#endif // ELF_READER_CPP
