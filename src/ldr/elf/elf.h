#ifndef __ELF_H__
#define __ELF_H__

#include <diskio.hpp>
#include <fixup.hpp>
#include <idp.hpp>

#pragma pack(push, 4)

// gcc does not allow to initialize indexless arrays for some reason
// put an arbitrary number here. the same with visual c++
#if defined(__GNUC__) || defined(_MSC_VER)
#define MAXRELSYMS 64
#else
#define MAXRELSYMS
#endif

struct elf_loader_t;
struct elf_file_info_t;
typedef Elf64_Shdr elf_shdr_t;
typedef Elf64_Phdr elf_phdr_t;
struct elf_sym_t : public Elf64_Sym
{
  elf_sym_t()
  {
    st_name  = 0;
    st_info  = 0;
    st_other = 0;
    st_shndx = 0;
    st_value = 0;
    st_size  = 0;
  }
};
typedef Elf64_Dyn  elf_dyn_t;
typedef Elf64_Rel  elf_rel_t;
struct elf_rela_t : public Elf64_Rela
{
  elf_rela_t()
  {
    r_offset = 0;
    r_info = 0;
    r_addend = 0;
  }
};

typedef qvector<elf_rela_t> elf_rela_vec_t;

class reader_t;
struct sym_rel;
typedef uint32 elf_sym_idx_t;
struct elf_symbol_version_t;
struct dynamic_info_t;

typedef uint32 elf_shndx_t;
typedef qvector<elf_shdr_t> elf_shdrs_t;
typedef qvector<elf_phdr_t> elf_phdrs_t;

//----------------------------------------------------------------------------
struct elf_ehdr_t : public Elf64_Ehdr
{
  elf_shndx_t real_shnum;     // number of entries in the SHT
                              // (may be greater than 0xFF00)
  elf_shndx_t real_shstrndx;  // section name string table section index
                              // (may be greater than 0xFF00)

  bool has_pht() const { return e_phoff != 0; }
  void set_no_pht()
  {
    e_phoff = 0;
    e_phnum = 0;
  }

  bool has_sht() const { return e_shoff != 0; }
  void set_no_sht()
  {
    e_shoff = 0;
    e_shnum = 0;
    real_shnum = 0;
  }
  bool is_valid_shndx(elf_shndx_t idx) const
  {
    return idx < real_shnum;
  }

  bool has_shstrtab() const { return real_shstrndx != 0; }

  bool is_64bit_machine() const
  {
    switch ( e_machine )
    {
      case EM_AARCH64:
      case EM_PPC64:
      case EM_X86_64:
      case EM_ALPHA:
      case EM_IA64:
        return true;
      default:
        return false;
    }
  }
};

//-------------------------------------------------------------------------
typedef Elf64_Chdr elf_chdr_t;

//----------------------------------------------------------------------------
// rel_data_t holds whatever relocation information appears to be common
// to most ELF relocation "algorithms", as defined in the per-CPU
// addenda.
// Note: Most comments below were picked from the abi386.pdf file.
struct rel_data_t
{
  // Relocation type: R_<processor>_<reloc-type>.
  uint32 type;

  // abi386.pdf: This means the place (section offset or address) of
  // the storage unit being relocated (computed using r_offset).
  ea_t   P;

  // abi386.pdf: This means the value of the symbol whose index
  // resides in the relocation entry.
  uval_t S;

  // S, plus addend
  ea_t Sadd;

  // Whether the 'reloc' parameter passed to 'proc_handle_reloc()'
  // is a REL, or a RELA (the actual reloc entry object
  // itself will always be a elf_rela_t instance).
  enum rel_entry_t
  {
    re_rel,
    re_rela
  };
  rel_entry_t rel_entry;
  bool is_rel() const { return rel_entry == re_rel; }
  bool is_rela() const { return !is_rel(); }
};


//--------------------------------------------------------------------------
enum slice_type_t
{
  SLT_INVALID = 0,
  SLT_SYMTAB  = 1,
  SLT_DYNSYM  = 2,
  SLT_WHOLE   = 3,
};
struct symrel_idx_t
{
  symrel_idx_t() : type(SLT_INVALID), idx(0) {}
  symrel_idx_t(slice_type_t t, elf_sym_idx_t i) : type(t), idx(i) {}

  slice_type_t type;
  elf_sym_idx_t idx;

  bool operator==(const symrel_idx_t &other) const
  {
    return other.type == type
        && other.idx  == idx;
  }
  bool operator<(const symrel_idx_t &other) const
  {
    if ( type < other.type )
      return true;
    if ( type > other.type )
      return false;
    return idx < other.idx;
  }
};

//----------------------------------------------------------------------------
struct got_access_t : public range_t
{
  elf_loader_t &ldr;
  // the name _GLOBAL_OFFSET_TABLE_
  static const char gtb_name[];

  // is the given symbol the _GLOBAL_OFFSET_TABLE_?
  static bool is_symbol_got(const sym_rel &sym, const char *name);

  got_access_t(elf_loader_t &_ldr) : range_t(0, 0), ldr(_ldr) {}

  // Get the start address of the GOT.
  // If no GOT currently exists, and 'create' is true, one will
  // be created in a segment called ".got".
  // If no GOT exists or an error occurred while creating .got segment,
  // the function returns 0.
  ea_t get_start_ea(elf_file_info_t &finfo, bool create = false);

  //
  void set_start_ea(ea_t ea) { start_ea = ea; }

  // get .got segment using the storage of well-known sections.
  // If it didn't exist and the flag `create' is set then create an empty
  // ".got" segment with the given initial size.
  // Set the flag `create' if such segment is just created.
  // If .got segment doesn't exist or an error occurred while creating it,
  // the function returns nullptr.
  segment_t *get_got_segment(elf_file_info_t &finfo, bool *create, uint32 init_size = 0) const;

  // Some relocations, such as ARM's R_ARM_TLS_IE32, require that a got entry
  // be present in the linked file, in order to point to that entry.
  // However, when we are loading a simple relocatable ELF object file,
  // there's no GOT present. This is problematic because,
  // although we _could_ be taking a shortcut and patch the fixup to refer
  // to the extern:__variable directly, it is semantically different.
  // As as example, when we meet:
  //   LDR    R3, #00000000                     ; R_ARM_TLS_IE32; Offset in GOT to __libc_errno
  // generating:
  //   LDR    R3, [__libc_errno_tls_offset]
  // is not the same as:
  //   LDR    R3, [address, in got, of libc_errno_tls_offset]
  //
  // This is obviously the last formatting that's correct, as we don't
  // even *know* what the address of __libc_errno_tls_offset is; we just
  // know where to go and look for it.
  //
  // The solution is to create a .got section anyway, and allocate an entry
  // in there with the name of the symbol, suffixed with '_tpoff'.
  //
  // - finfo   : The elf file info (reader, ...)
  // - sym     : The symbol. We create the one entry for each symbol of
  //             each GOT-type.
  // - suffix  : A suffix, to be added to the symbol name. We consider
  //             the suffix as a GOT-type of the entry. It is sometimes
  //             necessary to create multiple entries for the symbol.
  //             E.g., '_tpoff', '_ptr', ...
  // - created : The flag indicating the allocation of the new entry.
  // - n       : The number of allocated entries.
  // - returns : An address in the .got segment.
  //             0 is returned in the case of error.
  ea_t allocate_entry(
        elf_file_info_t &finfo,
        const sym_rel &sym,
        const char *suffix,
        bool *created = nullptr,
        size_t n = 1);

  // Get the ea in the GOT section, corresponding
  // the the 'A' addend.
  //
  // * If the file already had a GOT section, then
  //   the returned ea is simply got_segment->start_ea + A.
  // * On the other hand, if this file had no GOT
  //   this calls #allocate_got_entry().
  //
  // - finfo   : The elf file info (reader, ...)
  // - A       : The 'addend' (i.e., displacement) in the GOT.
  //             Ignored if the original file had *no* GOT.
  // - sym     : The symbol.
  //             Ignored if the original file *did* have a GOT.
  // - suffix  : A suffix, to be added to the symbol name. E.g., '_tpoff', '_ptr', ...
  //             Ignored if the original file *did* have a GOT.
  //
  // - returns : An address in the GOT segment, possibly creating one.
  //             0 is returned in the case of error.
  ea_t get_or_allocate_entry(
        elf_file_info_t &finfo,
        uval_t A,
        const sym_rel &sym,
        const char *suffix);

  // create GOT entry for the address (used in MIPS local entries)
  ea_t allocate_entry(
        elf_file_info_t &finfo,
        ea_t addr,
        bool *created = nullptr,
        size_t n = 1);

private:
  // used only when original file has no GOT.
  // an unique id of the symbol's GOT entry
  struct symrel_id_t
  {
    symrel_idx_t idx;   // symbol
    const char *suffix; // subtype of the GOT-entry
    symrel_id_t(symrel_idx_t idx_, const char *suffix_)
      : idx(idx_), suffix(suffix_) {}
    bool operator<(const symrel_id_t &rhs) const
    {
      if ( idx < rhs.idx )
        return true;
      if ( !(idx == rhs.idx) )
        return false;
      return strcmp(suffix, rhs.suffix) < 0;
    }
  };
  std::map<symrel_id_t,ea_t> allocated_sym_entries;
  std::map<ea_t,ea_t> allocated_addr_entries;
};


//----------------------------------------------------------------------------
struct reloc_tools_t
{
  // dynamic information
  const dynamic_info_t *di;
  // reader_t container, with preprocessed data
  elf_file_info_t *finfo;
  // GOT accessor/creator.
  got_access_t got;
  ea_t load_base;

  reloc_tools_t(elf_loader_t &_ldr, const dynamic_info_t *di_,
                elf_file_info_t *finfo_, const ea_t load_base);
  bool section_header_overlaps(elf_shndx_t sh_idx) const;
  bool has_dlt() const;
};

//--------------------------------------------------------------------------
// GOT support for the relocatable files.
// the addend of the GOT reloc is applied to the insn,
// 'P - A' should point to the current or to the next insn
bool check_got_addend(ea_t P, adiff_t A, adiff_t good_addend);
bool check_got_addend(ea_t P, adiff_t A, adiff_t good1, adiff_t good2);

//--------------------------------------------------------------------------
namespace tls_relocs_t
{
  // generic TLS relocs
  enum type_t
  {
    BAD,
    NTPOFF,   // variant 2: @ntpoff(x) (x86) or @tpoff(x) (x64), calculates
              // the negative TLS offset relative to the TLS block end;
              // variant 1: TPREL(S+A), resolves to the offset from the
              // current thread pointer (TP) of the thread local variable.
    DTPOFF,   // @dtpoff(x), calculates the TLS offset relative to the
              // TLS block;
              // DTPREL(S+A), resolves to the offset from its module's TLS
              // block of the thread local variable.
    PTPOFF,   // $x@tpoff (x86 only), calculates the _positive_ TLS
              // offset relative to the TLS block end.
    DTPMOD,   // @dtpmod(x), calculates the object identifier of the
              // object containing a TLS symbol;
              // LDM(S), resolves to the load module index of the symbol S.
    DESC,     // TLSDESC(S+A), resolves to a contiguous pair of 64-bit
              // values which contain a 'tlsdesc' structure describing the
              // thread local variable. The first entry holds a pointer to
              // the variable's TLS descriptor resolver function and the
              // second entry holds a platform-specific offset or pointer.
    GOTGD,    // @tlsgd(x) (x86) or @tlsgd(%rip) (x64), allocates two
              // contiguous entries in the GOT to hold a `tls_index'
              // structure, uses the offset of the first entry.
    GOTLD,    // @tlsldm(x) (x86) or @tlsld(%rip) (x64), allocates two
              // contiguous entries in the GOT to hold a `tls_index'
              // structure, uses the offset of the first entry. The
              // `ti_tlsoffset' field of the `tls_index' is set to 0.
    GOTIE,    // @gotntpoff(x) (x86) or @gottpoff(%rip) (x64), allocates
              // an entry in the GOT, uses the offset of this entry. The
              // entry holds a variable offset in the initial TLS block.
              // This negative offset is relative to the TLS blocks end.
              // GTPREL(S+A), represents a 64-bit entry in the GOT for the
              // offset from the current thread pointer (TP) of the
              // thread local variable, see TPREL(S+A).
              // @indntpoff(x) (x86), like GOTIE but uses the absolute
              // GOT slot address (got_mode_t::ABS).
    GOTIEP,   // @tpoff(x) (x86 only), allocates an entry in the GOT,
              // uses the offset of this entry. The entry holds a
              // variable offset in the initial TLS block. This
              // _positive_ offset is relative to the TLS blocks end.
    GOTDESC,  // GTLSDESC(S+A), represents a consecutive pair of 64-bit
              // entries in the GOT which contain a 'tlsdesc' structure.
  };
  inline bool is_got_reloc(type_t type)
  {
    return type >= GOTGD;
  }

  // GOT slot addressing mode
  enum got_mode_t
  {
    GOT,  // offset in GOT
    ABS,  // absolute address
    RIP,  // offset relative to P-A (the linker sets the addend
          // so that it points to the next insn)
  };
};

//--------------------------------------------------------------------------
struct proc_def_t
{
  elf_loader_t &ldr;
  reader_t &reader;
  uint32 relsyms[MAXRELSYMS] = { 0 }; // relocation types which must be to loaded symbols

#define E_RELOC_PATCHING  (const char *)1
#define E_RELOC_UNKNOWN   (const char *)2
#define E_RELOC_UNIMPL    (const char *)3
#define E_RELOC_UNTESTED  (const char *)4
#define E_RELOC_NOSYM     (const char *)5
#define E_RELOC_LAST      (const char *)6
  const char *stubname = nullptr;

  // order in which relocations should be applied. A name denotes a section
  // to which we are applying relocations. nullptr means all other sections.
  enum { MAXRELORDERS = 5 };
  const char *relsecord[MAXRELORDERS] = { nullptr };

  // types of supported special segments
  enum spec_type_t
  {
    SPEC_XTRN,
    SPEC_COMM,
    SPEC_ABS,
    SPEC_TLS,
    NSPEC_SEGMS
  };
  // additional reserved indexes of special segments (see MIPS)
  uint16 additional_spec_secidx[NSPEC_SEGMS] = { 0 };

  // TLS support of the static access model (0 - no static model)
  // TP - static thread pointer, TCB - thread control block
  // variant 1 (if tls_tcb_size < 0):
  // +---+---+-----------------------
  // |TCB|xxx|
  // +---+---+-----------------------
  // ^ TP    ^ TLS offset of modules
  // variant 2 (if tls_tcb_size > 0):
  // +----------------------+---+---+
  // |                      |xxx|TCB|
  // +----------------------+---+---+
  // ^ TLS offset of modules    ^ TP
  int tls_tcb_size = 0;
  int tls_tcb_align = 0;  // if bit 0 set then store TP at the start of TCB

#define AUTO_NO_CTOR  0x01   // disbale ctor/dtor renaming
#define AUTO_NO_DATA  0x02   // disable data coagulation
#define AUTO_NO_NAME  0x04   // disable Alternative name storing
#define AUTO_NO_THUNK 0x08   // disable plt-thunk renaming
// see set_reloc_cmt() for other bits
#define AUTO_NO_CTBL_MASK (AUTO_NO_DATA | AUTO_NO_CTOR)
  ushort auto_mode = AUTO_NO_DATA;
  ushort patch_mode = 0;

  proc_def_t(elf_loader_t &_ldr, reader_t &_reader) : ldr(_ldr), reader(_reader) {}
  virtual ~proc_def_t() {}

  // the sequence of callbacks during the call of elf_load_file()
  // proc_is_acceptable_image_type
  // proc_on_start_data_loading
  //   proc_should_load_section*   (for each section before load)
  //   proc_load_unknown_sec*      (for each section with unknown type)
  //   proc_on_create_section*  (for each section before defining segment)
  // proc_handle_dynamic_tag*        (for each dynamic tag)
  // proc_describe_flag_bit*           (for each flag from header.e_flags)
  // proc_on_loading_symbols*       (for each symbol table)
  //   proc_handle_special_symbol*      (for each symbol from unknown section)
  //   proc_handle_symbol*   (for each symbol)
  // proc_handle_reloc*            (for each relocation)
  // proc_create_got_offsets*        ( TODO )
  // proc_perform_patching*          (up to 2 times, see above)
  // proc_convert_pic_got*        ( TODO )
  // proc_adjust_entry*   (for init_ea, fini_ea, header.e_entry)
  // proc_on_end_data_loading

  virtual bool proc_supports_relocs() const { return true; }

  // Relocator function.
  // Note: symbol might be nullptr
  virtual const char *proc_handle_reloc(
        const rel_data_t & /*rel_data*/,
        const sym_rel * /*symbol*/,
        const elf_rela_t * /*reloc*/,
        reloc_tools_t * /*tools*/)
  {
    return nullptr;
  }

  // Force conversion of all GOT entries to offsets
  virtual bool proc_create_got_offsets(
        const elf_shdr_t * /*gotps*/,
        reloc_tools_t * /*tools*/)
  {
    return false;
  }

  // Patcher function
  // There are 2 passes distinguishable by function argument gotps:
  // 1. ELF_RPL_PTEST   nullptr - check ".plt" section
  // 2. pass 2          gotplt
  virtual bool proc_perform_patching(
        const elf_shdr_t * /*plt*/,
        const elf_shdr_t * /*gotps*/)
  {
    return 0;
  }

  // Convert PIC form of loading '_GLOBAL_OFFSET_TABLE_[]' of address
  virtual bool proc_can_convert_pic_got() const { return false; }
  virtual size_t proc_convert_pic_got(
        const segment_t * /*gotps*/,
        reloc_tools_t * /*tools*/)
  {
    return 0;
  }

  // Return a bit description from e_flags and remove it.
  // This function may be called in a loop to document all bits.
  virtual const char *proc_describe_flag_bit(uint32 * /*e_flags*/)
  {
    return nullptr;
  }

  // called for processor-specific section types
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force)
  {
#ifdef IDA_DEBUG_LDR
    deb(IDA_DEBUG_LDR,
        "Unsupported or unknown section type 0x%X, skipped\n", sh->sh_type);
#endif
    return force;
  }

  // called for each dynamic tag. It returns nullptr to continue with a
  // standard tag processing, or "" to finish tag processing, or the
  // description of the tag to show.
  virtual const char *proc_handle_dynamic_tag(const Elf64_Dyn * /*dyn*/)
  {
    return nullptr;
  }

  virtual bool proc_is_acceptable_image_type(ushort /*filetype*/)
  {
    return false;
  }

  // called after header loading (before load_pht/load_simage)
  virtual void proc_on_start_data_loading(elf_ehdr_t & /*header*/) {}

  // called after loading data from the input file
  virtual bool proc_on_end_data_loading()
  {
    return true; // success
  }
  virtual void proc_on_loading_symbols() {}

  virtual bool proc_handle_symbol(sym_rel & /*sym*/, const char * /*symname*/)
  {
    return true;
  }

  // Handle a dynamic symbol
  virtual void proc_handle_dynsym(
        const sym_rel & /*symrel*/,
        elf_sym_idx_t /*isym*/,
        const char * /*symname*/)
  {}

  // 0-reaccept, 1-set name only, else: non-existing section
  virtual int proc_handle_special_symbol(
        sym_rel * /*st*/,
        const char * /*name*/,
        ushort /*type*/)
  {
    return 0;
  }

  // called from a function should_load_segment for _every_ section.
  // It returns 'false' to skip loading of the given section.
  virtual bool proc_should_load_section(
        const elf_shdr_t &sh,
        elf_shndx_t /*idx*/,
        const qstring & /*name*/)
  {
    // skip sections without flags like .comment/.debug/.line
    if ( sh.sh_type == SHT_PROGBITS
      && (sh.sh_flags & (SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR|SHF_TLS)) == 0 )
    {
      return false;
    }
    return true;
  }

  // called before the segment creation. It may set <sa> to the ea at
  // which a given section should be loaded. In the other case the
  // default segment ea computation is used. Also it may return 'false'
  // to skip creation of a segment for this section.
  virtual bool proc_on_create_section(
        const elf_shdr_t & /*sh*/,
        const qstring & /*name*/,
        ea_t * /*sa*/)
  {
    return true;
  }

  virtual const char *calc_procname(uint32 * /*e_flags*/, const char *procname)
  {
    return procname;
  }

  // for some 64-bit architectures e_entry holds not a real entry point
  // but a function descriptor
  // E.g. 64-bit PowerPC ELF Application Binary Interface Supplement 1.9
  // section 4.1. ELF Header
  // "The e_entry field in the ELF header holds the address of a function
  // descriptor. This function descriptor supplies both the address of the
  // function entry point and the initial value of the TOC pointer
  // register."
  // this callback should translate this address to the real entry.
  virtual ea_t proc_adjust_entry(ea_t entry)
  {
    return entry;
  }

  // helper functions
  bool in_relsyms(uint32 r_type) const
  {
    for ( int i=0; i < MAXRELSYMS; ++i )
    {
      if ( relsyms[i] == 0 )
        break;
      if ( relsyms[i] == r_type )
        return true;
    }
    return false;
  }

  bool section_in_relsecord(const qstring &name) const
  {
    for ( int i = 0; i < MAXRELORDERS; ++i )
    {
      if ( relsecord[i] == nullptr )
        return false;
      if ( name == relsecord[i] )
        return true;
    }
    return false;
  }

  // Note: this function should be used only for complex cases.
  //       For simple relocations it is recommended to use
  //       set_reloc_fixup().
  void set_reloc(
        ea_t P,                  // The ea of the data to be modified.
        ea_t target_ea,          // The ea that the instruction would point to,
                                 // if it were interpreted by the CPU.
        uval_t patch_data,       // The data to be inserted at 'P'. Depending on whether
                                 // 'type' is a 64-bit fixup type or not, either the
                                 // first 32-bits, or the full 64 bits of 'data' will be
                                 // put in the database. Of course, this patch data
                                 // must hold the possible instruction bits, if they
                                 // are interleaved w/ the address data
                                 // (e.g., R_ARM_THM_MOVW_ABS_NC, ...).
        adiff_t displ,
        fixup_type_t type,       // The type of the relocation, see fixup.hpp's FIXUP_*.
                                 // It may be standard or custom.
        uval_t offbase = 0,      // base of the relative fixup
        uint32 flags = 0,        // The flags of the relocation, see fixup.hpp's FIXUPF_*.
                                 // You can specify additional flags:
#define FIXUPF_ELF_DO_NOT_PATCH 0x80000000 // do not patch at all
#define FIXUPF_ELF_FIXUP_PATCH  0x40000000 // do not use patch_data, patch
                                           // using patch_fixup_value()
#define FIXUPF_ELF_DISPLACEMENT 0x20000000 // set displacement flag
                                           // (even rel_mode == 1)
#define FIXUPF_ELF_SET_RELATIVE 0x10000000 // set fixup base
                                           // (even offbase == 0)
        adiff_t fixup_offset=0); // offset of the fixup relative to P

  // this function patches the relocatable field using patch_fixup_value()
  // and store the fixup.
  // It set the displacement taking in account the addend, the fact that
  // the symbol is external or it is a section.
  // It uses static variables REL_MODE and PRGEND.
  // It is recommended to use set_reloc_fixup() instead of set_reloc(),
  // because it makes the code clearer.
  void set_reloc_fixup(
        ea_t P,                    // ea of the reloc
        ea_t S,                    // symbol of the reloc
        adiff_t A,                 // addend of the reloc
        fixup_type_t type,         // the type of the fixup to store, see fixup.hpp's FIXUP_*.
                                   // It may be standard or custom.
        bool do_not_patch = false, // do not patch at all
        uval_t offbase = 0,        // base of the relative fixup
        adiff_t fixup_offset = 0); // offset of the fixup relative to P

  void process_TLS(
        tls_relocs_t::type_t type,
        tls_relocs_t::got_mode_t got_mode,
        fixup_type_t fixup_type,
        const char *cfh_name,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        const elf_rela_t &reloc_info,
        reloc_tools_t *tools);

  // allocate GOT-entry and return it in GOT_ENTRY_EA
  // \param P  relocation address (to show in messages)
  // \param S  data to place in the entry
  // \param symbol  symbol of the entry,
  //                we allocate the single entry for the symbol,
  //                we create a label for the entry if the symbol has a name,
  //                if it is nullptr we allocate the entry for the S address
  bool process_GOT(
        ea_t *got_ea,           // may be nullptr
        ea_t *got_entry_ea,     // not nullptr
        ea_t P,
        ea_t S,
        const sym_rel *symbol,
        reloc_tools_t *tools);

  enum reloc_cmt_id_t
  {
    RCM_NONE = -1,
    RCM_PIC  = 0,
    RCM_ATT  = 1,
    RCM_COPY = 2,
    RCM_TLS  = 3,
    RCM_IREL = 4,
  };
  void set_reloc_cmt(ea_t ea, reloc_cmt_id_t cmt) const;
  void set_thunk_name(
        ea_t ea,
        ea_t name_ea,
        const char *prefix = ".",
        const char *postfix = "");
};

//----------------------------------------------------------------------------
// Our loaders override two virtual functions with a non-trivial implementation.
// This class serves only the purpose of making proc_def_t easily instantiatable
// from plugins.
struct hexrays_procdef_t : public proc_def_t
{
  hexrays_procdef_t(elf_loader_t &_ldr, reader_t &r) : proc_def_t(_ldr, r) {}
  virtual int proc_handle_special_symbol(
        sym_rel *st,
        const char *,
        ushort type) override;
  virtual ea_t proc_adjust_entry(ea_t entry) override;
};

//----------------------------------------------------------------------------
struct arm_base_t : public hexrays_procdef_t
{
  bool already_parsed = false;

  arm_base_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force) override;
  virtual void proc_on_loading_symbols() override;
  virtual bool proc_handle_symbol(sym_rel &sym, const char *symname) override;
};

//----------------------------------------------------------------------------
struct elf_arm_t : public arm_base_t
{
  fixup_type_t prel31_reltype = FIXUP_CUSTOM;

  elf_arm_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual bool proc_perform_patching(
        const elf_shdr_t *plt,
        const elf_shdr_t *gotps) override;
  virtual bool proc_can_convert_pic_got() const override { return true; }
  virtual size_t proc_convert_pic_got(
        const segment_t *gotps,
        reloc_tools_t *tools) override;
  virtual void proc_on_start_data_loading(elf_ehdr_t &header) override;
  virtual bool proc_on_create_section(
        const elf_shdr_t &sh,
        const qstring &name,
        ea_t *sa) override;
};

//----------------------------------------------------------------------------
struct elf_aarch64_t : public arm_base_t
{
  elf_aarch64_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual bool proc_perform_patching(
        const elf_shdr_t *plt,
        const elf_shdr_t *gotps) override;
#ifndef __EA64__
  virtual bool proc_supports_relocs() const override { return false; }
#endif
private:
  bool aarch64_process_TLS(
        int rel_type,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        const elf_rela_t &reloc_info,
        reloc_tools_t *tools);
};

//----------------------------------------------------------------------------
struct elf_alpha_t : public hexrays_procdef_t
{
  const elf_shdr_t *sh_plt = nullptr; // for R_ALPHA_JMP_SLOT

  elf_alpha_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force) override;
  virtual bool proc_should_load_section(
        const elf_shdr_t &sh,
        elf_shndx_t idx,
        const qstring &name) override;
};

//----------------------------------------------------------------------------
struct elf_avr_t : public hexrays_procdef_t
{
  netnode avr_helper;
  fixup_type_t avr16_reltype = FIXUP_CUSTOM;

  elf_avr_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//--------------------------------------------------------------------------
struct elf_c166_t : public hexrays_procdef_t
{
  elf_c166_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
};

//----------------------------------------------------------------------------
struct arc_base_t : public hexrays_procdef_t
{
  arc_base_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual void proc_handle_dynsym(
        const sym_rel &symrel,
        elf_sym_idx_t isym,
        const char *symname) override;
};

//----------------------------------------------------------------------------
struct elf_arcompact_t : public arc_base_t
{
  elf_arcompact_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_arc_t : public arc_base_t
{
  elf_arc_t(elf_loader_t &l, reader_t &r) : arc_base_t(l, r) {}
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_h8_t : public hexrays_procdef_t
{
  elf_h8_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
};

//----------------------------------------------------------------------------
struct elf_fr_t : public hexrays_procdef_t
{
  elf_fr_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//----------------------------------------------------------------------------
struct elf_i960_t : public hexrays_procdef_t
{
  elf_i960_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_ia64_t : public hexrays_procdef_t
{
  elf_ia64_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force) override;
};

//----------------------------------------------------------------------------
struct elf_hppa_t : public hexrays_procdef_t
{
  fixup_type_t l21_reltype = FIXUP_CUSTOM;
  fixup_type_t r11_reltype = FIXUP_CUSTOM;

  elf_hppa_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force) override;
};

//----------------------------------------------------------------------------
struct ppc_base_t : public hexrays_procdef_t
{
  fixup_type_t ha16_reltype = FIXUP_CUSTOM;

  // PLT support
  enum plt_type_t
  {
    PLT_UNKNOWN,
    PLT_SKIP,     // illegal .plt section
    PLT_BSS,      // PLT entry contains executable code
    PLT_SECURE,   // PLT entry contains address
    PLT_FARCALL,  // PLT_BSS + should add .plt_farcall
    PLT_64,       // PLT entry contains function description
    PLT_64V2,     // PLT entry contains global entry point
  };
  plt_type_t plt_type = PLT_UNKNOWN;
  ea_t plt_start = BADADDR;
  asize_t plt_size = 0;
  bool is_dt_ppc_got_present = false;

  ppc_base_t(elf_loader_t &ldr, reader_t &reader);
  virtual bool proc_should_load_section(
        const elf_shdr_t &sh,
        elf_shndx_t idx,
        const qstring &name) override;
  virtual bool proc_on_end_data_loading() override;
protected:
  const char *process_JMP_SLOT(const sym_rel *symbol, ea_t P, ea_t target_ea);
  int32 calc_plt_entry(adiff_t off) const;
  asize_t calc_plt_size(uint32 n) const;
};

//----------------------------------------------------------------------------
struct elf_ppc_t : public ppc_base_t
{
  elf_ppc_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_perform_patching(
        const elf_shdr_t *plt,
        const elf_shdr_t *gotps) override;
  virtual const char *proc_handle_dynamic_tag(const Elf64_Dyn *dyn) override;
  virtual void proc_on_start_data_loading(elf_ehdr_t &header) override;
  virtual bool proc_handle_symbol(sym_rel &sym, const char *symname) override;
public:
  const char *process_EMB_SDA21(ea_t P, ea_t target_ea, uint32 insn);
  const char *process_GOT(
        uchar type,
        ea_t P,
        ea_t S,
        const sym_rel *symbol,
        reloc_tools_t *tools,
        reloc_cmt_id_t got_entry_cmt = RCM_NONE);
};

//----------------------------------------------------------------------------
struct elf_ppc64_t : public ppc_base_t
{
  // how did we define the `toc_base_ea`?
  // Doc: "To support position-independent code, a Global Offset Table (GOT)
  // shall be constructed by the link editor in the data segment when linking
  // code that contains any of the various R_PPC64_GOT* relocations or when
  // linking code that references the **.TOC.** address. The GOT consists of
  // an 8-byte header that contains **the TOC base** (the first TOC base when
  // multiple TOCs are present), followed by an array of 8-byte addresses."
  enum toc_type_t
  {
    TOC_UNK,
    // For the relocatable object file:
    TOC_CREATED,  // it points to the created .tocstart section
    // For the executable or shared object file:
    TOC_SECTION,  // it points to the first TOC's section
    TOC_GOT,      // we got it as the first GOT entry
    TOC_SYMBOL,   // it points to the .TOC. symbol
  };
  toc_type_t toc_type = TOC_UNK;

  symrel_idx_t toc_sym_idx; // index of the .TOC. symbol

  // the TOC base
  // We prepare this address for a relocatable object file because for an
  // executable or shared object the linker already defines and uses such
  // a symbol. Doc: "relocation types that refer to .TOC. may only appear
  // in relocatable object files, not in executables or shared objects".
  // For an executable or shared object we get this address in the same way
  // but we overwrite it using the .TOC. symbol or the first GOT entry.
  ea_t toc_base_ea = BADADDR;

  // offset of the TOC base from the TOC start
  adiff_t toc_base_offset = 0x8000;

  bool got_already_checked = false;

  elf_ppc64_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_on_end_data_loading() override;
  virtual bool proc_handle_symbol(sym_rel &sym, const char *symname) override;
  virtual bool proc_on_create_section(
        const elf_shdr_t &sh,
        const qstring &name,
        ea_t *sa) override;
  virtual ea_t proc_adjust_entry(ea_t entry) override;
private:
  const char *process_TOC16(
        uchar type,
        ea_t P,
        ea_t S,
        adiff_t A);
  void set_offset_to_toc(ea_t ea) const;
  void improve_toc_using_got();
};

//--------------------------------------------------------------------------
struct pc_base_t : public hexrays_procdef_t
{
  bool plt_warned = false;
  pc_base_t(elf_loader_t &ldr, reader_t &reader);
  bool patch_jmp_slot_target(
        const reloc_tools_t *reloc_tools,
        bool is_64,
        ea_t fixup_ea,
        ea_t final_ea);
  bool patch_irelative_target(
        bool is_64,
        ea_t fixup_ea,
        ea_t final_ea,
        const reloc_tools_t *reloc_tools);
};

//--------------------------------------------------------------------------
struct elf_pc_t : public pc_base_t
{
  elf_pc_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
private:
  bool convert_got32x(
        ea_t P,
        ea_t S,
        reloc_tools_t *tools);
  bool convert_call_jmp(ea_t P, ea_t S);
  bool convert_mov_mem_to_imm(ea_t P, ea_t S);
  bool convert_test(ea_t P, ea_t S);
  bool convert_binop(ea_t P, ea_t S, uchar opcode);
  bool convert_mov_to_lea(ea_t P, ea_t S, reloc_tools_t *tools);
  bool patch_glob_dat_target(
        ea_t fixup_ea,
        ea_t final_ea,
        const reloc_tools_t *tools);
  bool intel_process_TLS(
        int rel_type,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        const elf_rela_t &reloc_info,
        reloc_tools_t *tools);
};

//----------------------------------------------------------------------------
struct elf_m16c_t : public hexrays_procdef_t
{
  elf_m16c_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_on_create_section(
        const elf_shdr_t &sh,
        const qstring &name,
        ea_t *sa) override;
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
};

//----------------------------------------------------------------------------
struct elf_m32r_t : public hexrays_procdef_t
{
  elf_m32r_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
};

//----------------------------------------------------------------------------
struct elf_rx_t : public hexrays_procdef_t
{
  elf_rx_t(elf_loader_t &ldr, reader_t &reader);
    virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_mc12_t : public hexrays_procdef_t
{
  elf_mc12_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_mc68k_t : public hexrays_procdef_t
{
  elf_mc68k_t(elf_loader_t &ldr, reader_t &reader);
  virtual bool proc_supports_relocs() const override { return false; }
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//----------------------------------------------------------------------------
struct elf_s390_t : public hexrays_procdef_t
{
  fixup_type_t pc16_reltype = FIXUP_CUSTOM;
  fixup_type_t pc32_reltype = FIXUP_CUSTOM;
  fixup_type_t lo12_reltype = FIXUP_CUSTOM;
  fixup_type_t lo20_reltype = FIXUP_CUSTOM;

  elf_s390_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual bool proc_on_end_data_loading() override;
private:
  bool s390_process_TLS(
        int rel_type,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        const elf_rela_t &reloc_info,
        reloc_tools_t *tools);
  bool handle_plt1_64(ea_t ea);
};

//----------------------------------------------------------------------------
struct elf_mips_t : public hexrays_procdef_t
{
  fixup_type_t ha16_reltype  = FIXUP_CUSTOM;
  fixup_type_t lo16_reltype  = FIXUP_CUSTOM;
  fixup_type_t off16_reltype = FIXUP_CUSTOM;
  fixup_type_t b26_reltype   = FIXUP_CUSTOM;
  fixup_type_t mips16_b26_reltype   = FIXUP_CUSTOM;
  fixup_type_t mips16_ha16_reltype  = FIXUP_CUSTOM;
  fixup_type_t mips16_lo16_reltype  = FIXUP_CUSTOM;
  fixup_type_t mips16_off16_reltype = FIXUP_CUSTOM;
  fixup_type_t mmips_b26_reltype   = FIXUP_CUSTOM;
  fixup_type_t mmips_ha16_reltype  = FIXUP_CUSTOM;
  fixup_type_t mmips_lo16_reltype  = FIXUP_CUSTOM;
  fixup_type_t mmips_off16_reltype = FIXUP_CUSTOM;
  fixup_type_t mmips_b16_reltype   = FIXUP_CUSTOM;
  fixup_type_t mmips_b10_reltype   = FIXUP_CUSTOM;
  fixup_type_t mmips_b7_reltype    = FIXUP_CUSTOM;

  ea_t save_rsolve = BADADDR;
  bool isPS2IRX = false;
  bool isPSP = false;
  bool use_relocs = true;
  // The g_localgotno node will be used twice:
  //  1) When processing SHT_DYNSYM syms, to associate a symbol with a .got slot
  //  2) After processing symbols, during the 'patch' phase, to create
  //     all relocs in all "local" .got entries at the beginning of the .got.
  int g_localgotno = 0;
  elf_sym_idx_t g_gotsym = 0;
  // offset of the gp value from the GOT start
  const adiff_t gpval_offset = 0x7FF0;
  // initial value of GP (GP0)
  // for executable and shared objects it is the actual gp value
  // for relocatable objects it is the offset of the gp value from the global area start
  ea_t initial_gp = BADADDR;
  // start of the global data area. this area should be addressable using $gp.
  ea_t global_data_ea = BADADDR;

  ea_t last_hi16_ea = BADADDR;
  adiff_t last_hi16_addend = 0;
  uchar last_hi16_rel_type = 0;
  bool last_hi16_done = false;

  bool got_inited = false;

  elf_mips_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual bool proc_create_got_offsets(
        const elf_shdr_t *gotps,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual bool proc_load_unknown_sec(Elf64_Shdr *sh, bool force) override;
  virtual int proc_handle_special_symbol(
        sym_rel *st,
        const char *name,
        ushort type) override;
  virtual const char *proc_handle_dynamic_tag(const Elf64_Dyn *dyn) override;
  virtual bool proc_is_acceptable_image_type(ushort filetype) override;
  virtual void proc_on_start_data_loading(elf_ehdr_t &header) override;
  virtual bool proc_on_end_data_loading() override;
  virtual bool proc_handle_symbol(sym_rel &sym, const char *symname) override;
  virtual void proc_handle_dynsym(
        const sym_rel &symrel,
        elf_sym_idx_t isym,
        const char *symname) override;
  virtual bool proc_on_create_section(
        const elf_shdr_t &sh,
        const qstring &name,
        ea_t *sa) override;
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
private:
  void relocate_psp_section1(
        off_t file_offset,
        size_t sec_size,
        const sym_rel *symbol);
  void set_initial_gp(uint64 offset, bool options=true);
  ea_t get_final_gp(reloc_tools_t *tools);

  typedef fixup_type_t (elf_mips_t::*get_rel_type_t)();
  static const get_rel_type_t hlo_relocs[3][3];
  fixup_type_t get_ha16_reltype();
  fixup_type_t get_lo16_reltype();
  fixup_type_t get_off16_reltype();
  fixup_type_t get_b26_reltype();
  fixup_type_t get_mips16_b26_reltype();
  fixup_type_t get_mips16_ha16_reltype();
  fixup_type_t get_mips16_lo16_reltype();
  fixup_type_t get_mips16_off16_reltype();
  fixup_type_t get_mmips_b26_reltype();
  fixup_type_t get_mmips_ha16_reltype();
  fixup_type_t get_mmips_lo16_reltype();
  fixup_type_t get_mmips_off16_reltype();
  fixup_type_t get_mmips_b16_reltype();
  fixup_type_t get_mmips_b10_reltype();
  fixup_type_t get_mmips_b7_reltype();

  enum reloc_kind_t { RK_NONE, RK_MIPS, RK_MIPS16, RK_MICROMIPS };
  enum reloc_hlo_t { HA16, LO16, OFF16 };
  static reloc_kind_t find_reloc16_kind(uchar rel_type);
  fixup_type_t get_reloc16_fixup(
        reloc_hlo_t hlo,
        reloc_kind_t reloc_kind);

  enum symkind_t { SYM, LOCALGP, GPDISP };
  void process_ahl_reloc(
        uchar rel_type,
        ea_t P,
        ea_t S,
        symkind_t symkind,
        bool is_rela,
        adiff_t A,
        reloc_tools_t *tools);
  bool get_ssym_ea(ea_t *ssym_ea, uint8 ssym, ea_t P) const;
  bool is_inside_got(reloc_tools_t *tools, ea_t P);

  // convenient function to use instead of proc_def_t::set_reloc()
  void _set_reloc(
        ea_t P,
        fixup_type_t type,
        ea_t target_ea,
        adiff_t displ = 0,
        uval_t offbase = 0);
};

//----------------------------------------------------------------------------
struct elf_v800_t : public hexrays_procdef_t
{
  elf_v800_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//----------------------------------------------------------------------------
struct elf_v850_t : public hexrays_procdef_t
{
  elf_v850_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
};

//----------------------------------------------------------------------------
struct elf_sparc_t : public hexrays_procdef_t
{
  fixup_type_t hi22_reltype = FIXUP_CUSTOM;
  fixup_type_t lo10_reltype = FIXUP_CUSTOM;

  elf_sparc_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
  virtual void proc_on_start_data_loading(elf_ehdr_t &header) override;
  virtual bool proc_can_convert_pic_got() const override { return true; }
  virtual size_t proc_convert_pic_got(
        const segment_t *gotps,
        reloc_tools_t *tools) override;

  fixup_type_t get_hi22_reltype();
  fixup_type_t get_lo10_reltype();
};

//----------------------------------------------------------------------------
struct elf_mn10200_t : public hexrays_procdef_t
{
  elf_mn10200_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
};

//----------------------------------------------------------------------------
struct elf_mn10300_t : public hexrays_procdef_t
{
  elf_mn10300_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//----------------------------------------------------------------------------
struct elf_riscv_t : public hexrays_procdef_t
{
  fixup_type_t hi20_reltype = FIXUP_CUSTOM;
  fixup_type_t got20_reltype = FIXUP_CUSTOM;
  fixup_type_t lo12i_reltype = FIXUP_CUSTOM;
  fixup_type_t lo12s_reltype = FIXUP_CUSTOM;
  fixup_type_t call_reltype = FIXUP_CUSTOM;
  std::map<ea_t,ea_t> symtable;

  elf_riscv_t(elf_loader_t &ldr, reader_t &reader);

  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;

  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual bool proc_handle_symbol(sym_rel &sym, const char *symname) override;
  virtual bool proc_on_create_section(
        const elf_shdr_t &sh,
        const qstring &name,
        ea_t *sa) override;

  fixup_type_t get_hi20_reltype();
  fixup_type_t get_got20_reltype();
  fixup_type_t get_lo12i_reltype();
  fixup_type_t get_lo12s_reltype();
  fixup_type_t get_call_reltype();
};

//----------------------------------------------------------------------------
struct elf_sh_t : public hexrays_procdef_t
{
  elf_sh_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *calc_procname(uint32 *e_flags, const char *procname) override;
  virtual void proc_handle_dynsym(
        const sym_rel &symrel,
        elf_sym_idx_t isym,
        const char *symname) override;
};

//----------------------------------------------------------------------------
struct elf_st9_t : public hexrays_procdef_t
{
  elf_st9_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
};

//----------------------------------------------------------------------------
struct elf_x64_t : public pc_base_t
{
  // TODO use this custom fixup in RIP-based relocs
  fixup_type_t rip_reltype = FIXUP_CUSTOM;

  elf_x64_t(elf_loader_t &ldr, reader_t &reader);
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
private:
  bool convert_gotpcrelx(int rel_type, ea_t P, ea_t S);
  bool x64_process_TLS(
        int rel_type,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        const elf_rela_t &reloc_info,
        reloc_tools_t *tools);
  bool convert_call_jmp(ea_t P, ea_t S);
  bool convert_mov_to_lea(ea_t P, ea_t S);
  bool convert_mov_mem_to_imm(int rel_type, ea_t P, ea_t S);
  bool convert_test_binop(int rel_type, ea_t P, ea_t S, uchar opcode);
};

//----------------------------------------------------------------------------
struct elf_tricore_t : public hexrays_procdef_t
{
  fixup_type_t ha16_reltype = FIXUP_CUSTOM;

  elf_tricore_t(elf_loader_t &l, reader_t &r) : hexrays_procdef_t(l, r) {}
  virtual const char *proc_handle_reloc(
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools) override;
  virtual const char *proc_describe_flag_bit(uint32 *e_flags) override;
private:
  void make_reloc(
        const rel_data_t &rel_data,
        ea_t target_ea,
        uval_t patch_data,
        fixup_type_t type,
        bool nodispl = false);
  void tricore_handle_reloc(const rel_data_t &rel_data, ea_t target_ea);
  void tricore_reloc_relB(const rel_data_t &rel_data, ea_t target_ea);
  void tricore_reloc_absB(const rel_data_t &rel_data, ea_t target_ea);
  void tricore_reloc_abs(const rel_data_t &rel_data, ea_t target_ea);
  void tricore_reloc_br(const rel_data_t &rel_data, ea_t target_ea);
  void tricore_reloc_rlc(
        const rel_data_t &rel_data,
        uint32 patch_data,
        fixup_type_t fixup_type);
  void tricore_reloc_bol(
        const rel_data_t &rel_data,
        uint32 patch_data,
        fixup_type_t fixup_type);
};

//----------------------------------------------------------------------------
struct sym_rel;
class symrel_cache_t
{
public:

  symrel_cache_t()
    : storage(),
      dynsym_index(0) {}

  static void check_type(slice_type_t t)
  {
    QASSERT(20098, t > SLT_INVALID && t <= SLT_WHOLE);
  }

  elf_sym_idx_t slice_size(slice_type_t t) const { return elf_sym_idx_t(slice_end(t) - slice_start(t)); }
  const sym_rel &get(slice_type_t t, elf_sym_idx_t idx) const { return storage[slice_start(t) + idx]; }
  sym_rel &get(slice_type_t t, elf_sym_idx_t idx) { return storage[slice_start(t) + idx]; }
  sym_rel &append(slice_type_t t);

  void qclear(uint64 room)
  {
    // the number in the section header may be too big (see
    // pc_bad_nyms_elf.elf) so we limit it
    if ( room > 65536 )
      room = 65536;
    storage.qclear();
    storage.reserve(room);
  }

  symrel_idx_t get_idx(const sym_rel *symbol) const;

  // this method is used in pattern/pelf.cpp
  struct ptr_t : public symrel_idx_t
  {
    ptr_t() : symrel_idx_t(), symbols(nullptr) {}
    ptr_t(symrel_cache_t *s, symrel_idx_t i)
      : symrel_idx_t(i),
        symbols(s) {}
    symrel_cache_t *symbols;
    sym_rel &deref() const { return symbols->get(type, idx); }
  };
  ptr_t get_ptr(const sym_rel &sym)
  {
    return ptr_t(this, get_idx(&sym));
  }

private:
  qvector<sym_rel> storage;
  size_t dynsym_index;
  size_t slice_start(slice_type_t t) const;
  size_t slice_end(slice_type_t t) const;
};

//--------------------------------------------------------------------------
// relocation speed
struct sym_rel
{
  mutable qstring original_name;
  qstring name;         // temporary for NOTYPE only
  elf_sym_t original;
  uint64 size;
  uval_t value;         // absolute value or addr
  elf_shndx_t sec;      // index of the section to which this symbol
                        // applies. For special sections it is 0 (see
                        // original.st_shndx).
  uchar bind;           // binding
  char type;            // type (-1 - not defined,
                        // -2 UNDEF SYMTAB symbol which probably is
                        //    the same as the DYNSYM symbol,
                        // -3 to add an additional comment to relocs to
                        //    unloaded symbols)
  uchar flags;

  sym_rel()
  : original(),
    size(0),
    value(0),
    sec(0),
    bind(0),
    type(0),
    flags(0) {}

  sym_rel(const sym_rel &r)
  {
    original_name = r.original_name;
    name          = r.name;
    original      = r.original;
    size          = r.size;
    value         = r.value;
    sec           = r.sec;
    bind          = r.bind;
    type          = r.type;
    flags         = r.flags;
  }

  sym_rel &operator=(const sym_rel &r)
  {
    if ( this == &r )
      return *this;
    this->~sym_rel();
    new (this) sym_rel(r);
    return *this;
  }

  void swap(sym_rel &r)
  {
    qswap(*this, r);
  }

  void set_section_index(const reader_t &reader);
  bool defined_in_special_section() const
  {
    CASSERT(SHN_HIRESERVE == 0xFFFF);
    // assert: original.st_shndx <= SHN_HIRESERVE
    return sec == 0 && original.st_shndx >= SHN_LORESERVE;
  }
  // for debug purpose
  const char *get_section_str(char *buf, size_t bufsize) const
  {
    if ( defined_in_special_section() )
      qsnprintf(buf, bufsize, "%04X", uint(original.st_shndx));
    else
      qsnprintf(buf, bufsize, "%u", sec);
    return buf;
  }

  bool overlaps(elf_shndx_t section_index, uint64 offset) const
  {
    return sec == section_index
        && offset >= value
        && offset <  value + size;
  }

  void set_name(const qstring &n)
  {
    set_name(n.c_str());
  }

  void set_name(const char *n)
  {
    name.qclear();
    if ( n != nullptr && n[0] != '\0' )
      name = n;
  }

  ea_t get_ea(const reader_t &reader, ea_t _debug_segbase=0) const;

  const qstring &get_original_name(const reader_t &reader) const;

  void set_flag(uchar flag) { flags |= flag; }
  bool has_flag(uchar flag) const { return (flags & flag) != 0; }
  void clr_flag(uchar flag) { flags &= ~flag; }
};
DECLARE_TYPE_AS_MOVABLE(sym_rel);

//--------------------------------------------------------------------------
inline symrel_idx_t symrel_cache_t::get_idx(const sym_rel *symbol) const
{
  qvector<sym_rel>::const_iterator beg = storage.begin();
  if ( symbol == nullptr || symbol < beg || symbol > storage.end() )
    return symrel_idx_t();
  size_t idx = symbol - beg;
  if ( idx < dynsym_index )
    return symrel_idx_t(SLT_SYMTAB, elf_sym_idx_t(idx));
  else
    return symrel_idx_t(SLT_DYNSYM, elf_sym_idx_t(idx - dynsym_index));
}

void overflow(ea_t fixaddr, ea_t ea);
void std_handle_dynsym(const sym_rel &symrel, elf_sym_idx_t, const char *symname);

#define CASE_NAME(n) case n: return # n
const char *get_reloc_name(const reader_t &reader, int type);

void parse_attributes(reader_t &reader, uint32 offset, size_t size);
int  elf_machine_2_proc_module_id(reader_t &reader);

//--------------------------------------------------------------------------
// user parameters. these definitions and the input form are interdependent
// if you change the 'dialog_form' string, change these definitions too!
// (and don't forget to update the environment variables in the hints files)

// IDA_ELF_LOAD_OPTS (may be set by environment variable)
#define ELF_USE_PHT   0x0001 // Use PHT if available
#define ELF_USE_SHT   0x0002 // Use SHT if available
#define ELF_LD_CHNK   0x0004 // Load huge segments by chunks

// IDA_ELF_PATCH_MODE (may be set by environment variable)
#define ELF_RPL_PLP   0x0001 // Replace PIC form of 'Procedure Linkage Table' to non PIC form
#define ELF_RPL_PLD   0x0002 // Direct jumping from PLT (without GOT) irrespective of its form
#define ELF_RPL_GL    0x0004 // Convert PIC form of loading '_GLOBAL_OFFSET_TABLE_[]' of address
#define ELF_RPL_GOTX  0x0010 // Convert PIC form of name@GOT
#define ELF_AT_LIB    0x0020 // Mark 'allocated' objects as library-objects (MIPS only)
#define ELF_BUG_GOT   0x0040 // Force conversion of all GOT entries to offsets
#define ELF_FORM_MASK 0x0FFF // Mask for 'dialog_form' options

// noform bits
#define ELF_DIS_GPLT  0x4000 // disable search got reference in plt
#define ELF_DIS_OFFW  0x8000 // can present offset bypass segment's

#define ELF_RPL_PTEST  (ELF_RPL_PLP | ELF_RPL_PLD)

#define FLAGS_CMT(bit, text)  if ( *e_flags & bit ) \
                              {                     \
                                *e_flags &= ~bit;   \
                                return text;        \
                              }

//--------------------------------------------------------------------------
inline uval_t make64(uval_t oldval, uval_t newval, uval_t mask)
{
  return (oldval & ~mask) | (newval & mask);
}

//--------------------------------------------------------------------------
inline uint32 make32(uint32 oldval, uint32 newval, uint32 mask)
{
  return (oldval & ~mask) | (newval & mask);
}

#define MASK(x) ((uval_t(1) << x) - 1)

const uval_t M32 = uint32(-1);
const uval_t M24 = MASK(24);
const uval_t M16 = MASK(16);
const uval_t M8  = MASK(8);

inline uval_t extend_sign(uval_t value, uint bits)
{
  uval_t mask = make_mask<uval_t>(bits);
  return (value & left_shift<uval_t>(1, bits-1)) != 0
       ? value | ~mask
       : value & mask;
}

#undef MASK

#pragma pack(pop)

//----------------------------------------------------------------------------
struct dynamic_linking_tables_t
{
  dynamic_linking_tables_t()
    : offset(0),
      addr(0),
      size(0),
      link(0) {}

  dynamic_linking_tables_t(size_t _o, ea_t _a, size_t _s, elf_shndx_t _l)
    : offset(_o),
      addr(_a),
      size(_s),
      link(_l) {}

  bool is_valid() const { return offset != 0; }

  size_t offset;
  ea_t addr;
  size_t size;
  elf_shndx_t link;
};

//----------------------------------------------------------------------------
class dynamic_linking_tables_provider_t
{
public:
  dynamic_linking_tables_provider_t()
    : dlt() {}
  const dynamic_linking_tables_t &get_dynamic_linking_tables_info() const { return dlt; }
  bool has_valid_dynamic_linking_tables_info() const { return dlt.is_valid(); }
  void set_dynlink_table_info(size_t offset, ea_t addr, size_t size, int link)
  {
    dlt = dynamic_linking_tables_t(offset, addr, size, link);
  }

private:
  dynamic_linking_tables_t dlt;
};

//----------------------------------------------------------------------------
enum dynamic_info_type_t
{
  DIT_STRTAB,
  DIT_SYMTAB,
  DIT_REL,
  DIT_RELA,
  DIT_ANDROID_REL,
  DIT_ANDROID_RELA,
  DIT_PLT,
  DIT_HASH,
  DIT_GNU_HASH,
  DIT_PREINIT_ARRAY,
  DIT_INIT_ARRAY,
  DIT_FINI_ARRAY,
  DIT_VERDEF,
  DIT_VERNEED,
  DIT_VERSYM,
  DIT_TYPE_COUNT,       // number of dyninfo types
};

//----------------------------------------------------------------------------
// various information parsed from the .dynamic section or DYNAMIC segment
struct dynamic_info_t
{
  dynamic_info_t()
  {
    memset(this, 0, sizeof(dynamic_info_t));
  }

  void initialize(const reader_t &reader);

  struct entry_t
  {
    entry_t() { clear(); }
    bool is_valid() const { return offset > 0 && size != 0; }
    int64 offset;
    uint64 addr;
    uint64 size;
    uint16 entsize;
    uint32 info;

    void clear()
    {
      offset = 0;
      addr = 0;
      size = 0;
      entsize = 0;
      info = 0;
    }

    void guess_size(const sizevec_t &offsets)
    {
      size = BADADDR;
      for ( int i = 0; i < offsets.size(); i++ )
      {
        size_t off = offsets[i];
        if ( offset != 0 && off > offset )
          size = qmin(size, off - offset);
      }
      if ( size == BADADDR )
        size = 0;
    }
  } entries[DIT_TYPE_COUNT];

  entry_t &strtab() { return entries[DIT_STRTAB]; }
  entry_t &symtab() { return entries[DIT_SYMTAB]; }
  const entry_t &strtab() const { return entries[DIT_STRTAB]; }
  const entry_t &symtab() const { return entries[DIT_SYMTAB]; }
  entry_t &rel() { return entries[DIT_REL]; }
  entry_t &rela() { return entries[DIT_RELA]; }
  entry_t &plt() { return entries[DIT_PLT]; }
  entry_t &hash() { return entries[DIT_HASH]; }
  entry_t &gnu_hash() { return entries[DIT_GNU_HASH]; }
  entry_t &preinit_array() { return entries[DIT_PREINIT_ARRAY]; }
  entry_t &init_array() { return entries[DIT_INIT_ARRAY]; }
  entry_t &fini_array() { return entries[DIT_FINI_ARRAY]; }
  entry_t &verdef() { return entries[DIT_VERDEF]; }
  entry_t &verneed() { return entries[DIT_VERNEED]; }
  entry_t &versym() { return entries[DIT_VERSYM]; }

  const entry_t &rel() const { return entries[DIT_REL]; }
  const entry_t &rela() const { return entries[DIT_RELA]; }
  const entry_t &plt() const { return entries[DIT_PLT]; }

  uint32 plt_rel_type; // type of entries in the PLT relocation table (DT_RELENT)

  static qstring d_un_str(const reader_t &reader, int64 d_tag, int64 d_un);
  static const char *d_tag_str(const reader_t &reader, int64 d_tag); // may return null
  static qstring d_tag_str_ext(const reader_t &reader, int64 d_tag);

  // Fill a "fake" header, typically to be used w/
  // a buffered_input_t.
  bool fill_section_header(elf_shdr_t *sh, dynamic_info_type_t type) const;
};

//--------------------------------------------------------------------------
// extract from dwarf.h
// Canonical Frame Address (CFA).
// CFA operator compaction (a space saving measure, see
// the DWARF standard) means DW_CFA_extended and DW_CFA_nop
// have the same value here.
#define DW_CFA_advance_loc        0x40
#define DW_CFA_offset             0x80
#define DW_CFA_restore            0xc0
#define DW_CFA_extended           0

#define DW_CFA_nop              0x00
#define DW_CFA_set_loc          0x01
#define DW_CFA_advance_loc1     0x02
#define DW_CFA_advance_loc2     0x03
#define DW_CFA_advance_loc4     0x04
#define DW_CFA_offset_extended  0x05
#define DW_CFA_restore_extended 0x06
#define DW_CFA_undefined        0x07
#define DW_CFA_same_value       0x08
#define DW_CFA_register         0x09
#define DW_CFA_remember_state   0x0a
#define DW_CFA_restore_state    0x0b
#define DW_CFA_def_cfa          0x0c
#define DW_CFA_def_cfa_register 0x0d
#define DW_CFA_def_cfa_offset   0x0e
#define DW_CFA_def_cfa_expression 0x0f     /* DWARF3 */
#define DW_CFA_expression       0x10       /* DWARF3 */
#define DW_CFA_offset_extended_sf 0x11     /* DWARF3 */
#define DW_CFA_def_cfa_sf       0x12       /* DWARF3 */
#define DW_CFA_def_cfa_offset_sf 0x13      /* DWARF3 */
#define DW_CFA_val_offset        0x14      /* DWARF3f */
#define DW_CFA_val_offset_sf     0x15      /* DWARF3f */
#define DW_CFA_val_expression    0x16      /* DWARF3f */
#define DW_CFA_lo_user           0x1c

#define DW_CFA_GNU_args_size     0x2e /* GNU  */
#define DW_CFA_GNU_negative_offset_extended  0x2f /* GNU */

#define DW_CFA_hi_user           0x3f

//----------------------------------------------------------------------------
// CFI: Call Frame Information
struct cfi_t
{
  bytevec_t block;
  uint32 uop1;
  uint32 uop2;
  int32 sop;
  uchar insn;
};
DECLARE_TYPE_AS_MOVABLE(cfi_t);
typedef qvector<cfi_t> cfi_vec_t;

//----------------------------------------------------------------------------
// CIE: Common Information Entity
struct cie_frame_t
{
  bytevec_t augment_data;
  cfi_vec_t cfis;
  qstring augmentation;
  int32 offset = 0;
  int32 size = 0;
  int32 id = 0;
  uint32 code_alignment_factor = 0;
  int32 data_alignment_factor = 0;
  uint32 return_address_column = 0;
  uchar version = 0;
};
DECLARE_TYPE_AS_MOVABLE(cie_frame_t);
typedef qvector<cie_frame_t> cie_frame_vec_t;

//----------------------------------------------------------------------------
// FDE: Frame Description Entity
struct fde_frame_t
{
  bytevec_t augment_data;
  int32 offset = 0;
  int32 size = 0;
  int32 cie_ptr_delta = 0;
  int32 cie_ptr = 0;
  uint32 initial_location = 0;
  uint32 final_location = 0;
  cfi_vec_t cfis;
};
DECLARE_TYPE_AS_MOVABLE(fde_frame_t);
typedef qvector<fde_frame_t> fde_frame_vec_t;

//----------------------------------------------------------------------------
// Well-known sections
enum wks_t
{
  WKS_BSS = 1,
  WKS_BORLANDCOMMENT,
  WKS_COMMENT,
  WKS_DATA,
  WKS_DYNAMIC,
  WKS_DYNSYM,
  WKS_GOT,
  WKS_GOTPLT,
  WKS_HASH,
  WKS_INTERP,
  WKS_NOTE,
  WKS_PLT,
  WKS_RODATA,
  WKS_SYMTAB,
  WKS_TEXT,
  WKS_OPD,
  WKS_SYMTAB_SHNDX,
  WKS_DYNSYM_SHNDX,
  WKS_PLTGOT,
  WKS_VERDEF,
  WKS_VERNEED,
  WKS_VERSYM,
  WKS_PLTSEC,
  WKS_GNU_DEBUGDATA,
  WKS_EH_FRAME,
  WKS_LAST
};

class section_headers_t : public dynamic_linking_tables_provider_t
{
  elf_shdrs_t headers;
  uint32 wks_lut[WKS_LAST];
  reader_t *reader;
  bool initialized;
  bool got_is_original;   // Was .got section present in the input file?
  dynamic_info_t::entry_t strtab;

  friend class reader_t;

  section_headers_t(reader_t *_r)
    : reader(_r), initialized(false), got_is_original(false), strtab()
  {
    memset(wks_lut, 0, sizeof(wks_lut));
  }
  void assert_initialized() const
  {
    QASSERT(20099, initialized);
  }
public:
  bool is_initialized() const { return initialized; }
  const elf_shdr_t *getn(elf_shndx_t index) const;
  const elf_shdr_t *get_wks(wks_t wks) const
  {
    elf_shndx_t index = get_index(wks);
    return index == 0 ? nullptr : getn(index);
  }
  const elf_shdr_t *get(uint32 sh_type, const char *name) const;

#define CONST_THIS CONST_CAST(const section_headers_t*)(this)
#define NCONST_SHDR(x) CONST_CAST(elf_shdr_t *)(x)
  elf_shdr_t *getn(elf_shndx_t index) { return NCONST_SHDR(CONST_THIS->getn(index)); }
  elf_shdr_t *get_wks(wks_t wks) { return NCONST_SHDR(CONST_THIS->get_wks(wks)); }
  elf_shdr_t *get(uint32 sh_type, const char *name) { return NCONST_SHDR(CONST_THIS->get(sh_type, name)); }
#undef CONST_THIS
#undef NCONST_SHDR

  // Look for '.rel.<section_name>', or '.rela.<section_name>'.
  const elf_shdr_t *get_rel_for(elf_shndx_t index, bool *is_rela = nullptr) const;
  elf_shndx_t get_index(wks_t wks) const;
  void set_index(wks_t wks, elf_shndx_t index);
  int add(const elf_shdr_t &);
  void clear() // FIXME: This shouldn't be part of the public API
  {
    headers.clear();
    memset(wks_lut, 0, sizeof(wks_lut));
  }
  bool empty() const { return headers.empty(); }
  void resize(size_t size) { headers.resize(size); } // FIXME: This shouldn't be part of the public API
  bool get_name(qstring *out, elf_shndx_t index) const;
  bool get_name(qstring *out, const elf_shdr_t*) const;
  bool get_name(qstring *out, const elf_shdr_t &sh) const { return get_name(out, &sh); }
  elf_shdrs_t::const_iterator begin() const { return headers.begin(); }
  elf_shdrs_t::const_iterator end  () const { return headers.end(); }
  elf_shdrs_t::iterator begin() { return headers.begin(); }
  elf_shdrs_t::iterator end  () { return headers.end(); }
  size_t size() { return headers.size(); }

  const char *sh_type_str(uint32 sh_type) const; // may return null
  qstring sh_type_qstr(uint32 sh_type) const;

  bool is_got_original(void) const { return got_is_original; }
  void set_got_original(void) { got_is_original = true; }

  // Get the size of the section. That is, the minimum between
  // what is advertized (sh_size) and the number of bytes between
  // this, and the next section.
  uint64 get_size_in_file(const elf_shdr_t &sh) const;

  // Read the section contents into the 'out' byte vector.
  // This doesn't blindly rely on sh.sh_size, but will use
  // get_size_in_file() instead.
  // Also, the position of the linput_t will be preserved.
  void read_file_contents(bytevec_t *out, const elf_shdr_t &sh) const;

  bool read_gnu_debuglink(qstring *out_link, uint32 *out_crc) const;
};

//----------------------------------------------------------------------------
class program_headers_t : public dynamic_linking_tables_provider_t
{
  elf_phdrs_t pheaders;
  ea_t image_base;
  reader_t *reader;
  bool initialized;
public:
  program_headers_t(reader_t *_r)
    : image_base(BADADDR), reader(_r), initialized(false)
  {
  }
  elf_phdrs_t::const_iterator begin() const { return pheaders.begin(); }
  elf_phdrs_t::const_iterator end  () const { return pheaders.end(); }
  elf_phdrs_t::iterator begin() { return pheaders.begin(); }
  elf_phdrs_t::iterator end  () { return pheaders.end(); }
  elf_phdr_t *get(uint32 index) { assert_initialized(); return &pheaders[index]; }
  ea_t get_image_base() const { return image_base; }
  void set_image_base(ea_t ea) { image_base = ea; }
  inline size_t size() const { return pheaders.size(); }
  void resize(size_t sz) { pheaders.resize(sz); } // FIXME: This shouldn't be part of the pu
  const char *p_type_str(uint32 p_type) const; // may return null
  qstring p_type_qstr(uint32 p_type) const;

  // Get the size of the segment. That is, the minimum between
  // what is advertized (p_filesz) and the number of bytes between
  // this, and the next segment.
  uint64 get_size_in_file(const elf_phdr_t &p) const;

  // Read the segment contents into the 'out' byte vector.
  // This doesn't blindly rely on p.p_size, but will use
  // get_size_in_file() instead.
  // Also, the position of the linput_t will be preserved.
  void read_file_contents(bytevec_t *out, const elf_phdr_t &p) const;

private:
  friend class reader_t;
  void assert_initialized() const { QASSERT(20100, initialized); }
};

//----------------------------------------------------------------------------
// Note Section
// Sections of type SHT_NOTE and program header elements of type PT_NOTE

// entry
struct elf_note_t
{
  qstring name;   // entry owner or originator
  qstring desc;   // descriptor
  uint32 type;    // interpretation of descriptor

  // fill entry and return new start offset
  static bool unpack(elf_note_t *entry, size_t *start, const bytevec_t &buf, bool mf);

private:
  static bool unpack_sz(size_t *out, size_t *start, const bytevec_t &buf, bool mf);
  static bool unpack_strz(qstring *out, const bytevec_t &buf, size_t start, size_t len);
  static bool unpack_mem(qstring *out, const bytevec_t &buf, size_t start, size_t len, bool as_strz=false);
};
typedef qvector<elf_note_t> elf_notes_t;

// entry originators and types
#define NT_NAME_GNU "GNU"
#define NT_GNU_BUILD_ID 3

class notes_t
{
public:
  notes_t(reader_t *_r) : reader(_r), initialized(false)
  {}

  elf_notes_t::const_iterator begin() const { return notes.begin(); }
  elf_notes_t::const_iterator end  () const { return notes.end(); }
  void clear(void) { notes.clear(); }
  void add(const bytevec_t &buf);

  // convenience functions

  // Build ID
  bool get_build_id(qstring *out) const;

private:
  reader_t *reader;
  elf_notes_t notes;
  bool initialized;

  friend class reader_t;
  void assert_initialized() const { QASSERT(20082, initialized); }
};

const char *d_note_gnu_type_str(uint64 type);
const char *d_note_linux_type_str(uint64 type);
const char *d_note_core_type_str(uint64 type);

//----------------------------------------------------------------------------
class arch_specific_t
{
public:
  virtual ~arch_specific_t() {}
  virtual void on_start_symbols(reader_t &/*reader*/) {}
  virtual void on_symbol_read(reader_t &/*reader*/, sym_rel &/*sym*/) {}
};

//----------------------------------------------------------------------------
//-V:reader_t:730 Not all members of a class are initialized inside the constructor
class reader_t
{
public:
  // Type definitions
  // DOCME
  enum unhandled_section_handling_t
  {
    ush_none = 0,
    ush_load,
    ush_skip
  };

  /*
   * The list of notifications to which the user of the reader
   * can react.
   * It is documented as follows:
   *  1) a short description of the notification, and possibly a hint
   *     on how it should be considered/treated.
   *  2) the list of arguments, to be consumed in a vararg fashion.
   */
  enum errcode_t
  {
    /*
     * The "class" of the ELF module is not properly defined. It
     * should really be one of (ELFCLASS32, ELFCLASS64).
     * We will fallback to the ELFCLASS32 class.
     *   - uint8: the ELF class, as defined in the file.
     */
    BAD_CLASS = 1,

    /*
     * The size of the ELF header conflicts with what was expected.
     *   - uint16: the size of the ELF header, as defined in the file
     *             (i.e., eh_ehsize)
     *   - uint16: the expected size.
     */
    BAD_EHSIZE,

    /*
     * The byte ordering is not properly defineed. It should
     * really be one of (ELFDATA2LSB, ELFDATA2MSB).
     * We will fallback to the ELFDATA2LSB ordering.
     *   - uint8: the byte ordering, as defined in the file.
     */
    BAD_ENDIANNESS,

    /*
     * The ELF module defines there are Program Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for program header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a program header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_PHENTSIZE,

    /*
     * The ELF module either:
     * 1) defines an offset for the Program Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Program Header entries data but a
     *    count of 1+ entries.
     * We will not use the program header table.
     *   - uint16: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     */
    BAD_PHLOC,

    /*
     * The ELF module defines there are Section Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for section header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a section header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_SHENTSIZE,

    /*
     * The ELF module:
     * 1) defines an offset for the Section Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Section Header entries data but a
     *    count of 1+ entries, or
     * 3) defines too many entries, which would cause an EOF to occur
     *    while reading those.
     * We will not use the section header table.
     *   - uint32: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     *   - int64 : the size of the file.
     */
    BAD_SHLOC,

    /*
     * The reader has encountered an unhandled section.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     * If handled, this notification should return a
     * "unhandled_section_handling_t", specifying how the
     * reader should proceed with it.
     */
    UNHANDLED_SECHDR,

    /*
     * The reader has encountered an unhandled section,
     * which even the reader instance user couldn't handle.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    UNKNOWN_SECHDR,

    /*
     * The reader has spotted that the section's address
     * in memory (i.e., sh_addr) is not aligned on the
     * specified alignment (i.e., sh_addralign).
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    BAD_SECHDR_ALIGN,

    /*
     * The section header 0 is supposed to be SHT_NULL. But it wasn't.
     */
    BAD_SECHDR0,

    /*
     * The type of file (e_type) appears to be ET_CORE, and the
     * machine is SPARC. Those files usually have wrong SHT's. We
     * will rather opt for the PHT view.
     */
    USING_PHT_SPARC_CORE,

    /*
     * TLS definitions occurred more than once in the file.
     */
    EXCESS_TLS_DEF,

    /*
     * The section with the given name is being redefined.
     *   - const char *: The name of the section
     */
    SECTION_REDEFINED,

    /*
     * While parsing the dynamic_info_t, the reader spotted
     * an invalid value for the DT_PLTREL entry.
     *   - uint32: The 'value' of that entry.
     */
    BAD_DYN_PLT_TYPE,

    /*
     * One of the symbols in the symbols tables has a bad binding.
     *   - unsigned char: The binding.
     */
    BAD_SYMBOL_BINDING,

    /*
     * The ELF module has a Section Header String Table index, but
     * it is out-of-bounds.
     *   - uint32: the section header string table index;
     *   - uint16: the number of section header entries;
     */
    BAD_SHSTRNDX,

    /*
     * The ELF module has Program Header entries, which means it's
     * ready to be loaded as a process image, but claims it is of
     * type ET_REL which makes it a relocatable object file.
     */
    CONFLICTING_FILE_TYPE,

    LAST_WARNING = CONFLICTING_FILE_TYPE,

    /*
     * Couldn't read as many bytes as required.
     * This is a fatal issue, and should be treated as such.
     *  - size_t: expected bytes.
     *  - size_t: actually read.
     *  - int32 : position in file when reading was initiated.
     */
    ERR_READ,

    LAST_ERROR = ERR_READ
  };

  // Data members
  program_headers_t pheaders;
  section_headers_t sections;
  symrel_cache_t symbols;
  dynamic_info_t::entry_t sym_strtab;  // for SYMTAB
  dynamic_info_t::entry_t dyn_strtab;  // for DYNSYM

  struct standard_sizes_in_file_t
  {
    int ehdr;
    int phdr;
    int shdr;

    struct
    {
      uint sym;
      int dyn;
      int rel;
      int rela;
    } entries;

    struct
    {
      uint sym;         // DT_SYMENT
      uint rel;         // DT_RELENT
      uint rela;        // DT_RELAENT
    } dyn;

    struct
    {
      int elf_addr;
      int elf_off;
      int elf_xword;
      int elf_sxword;
    } types;
  } stdsizes;

  ea_helper_t _eah;

  DEFINE_EA_HELPER_FUNCS(_eah)
  inline ea_t trunc_segm_end(ea_t end) const;

private:
  linput_t *li;
  int64 sif; // ELF start in file
  uint64 filesize;
  // Handle an error. If this function returns false, the reader will stop.
  bool (*handle_error)(const reader_t &reader, errcode_t notif, ...);
  elf_ehdr_t header;

  struct mapping_t
  {
    uint64 offset;
    uint64 size;
    uint64 ea;
  };
  qvector<mapping_t> mappings;

  arch_specific_t *arch_specific;
  adiff_t load_bias; // An offset to apply to the ea's
                     // when loading the program in memory.
  // real endianness and bitness of the file
  // some loaders (e.g. Linux) ignore values in the ident header
  // so we set the effective ones here
  bool eff_msb;
  bool eff_64;          // is elf64?
  bool seg_64;          // segments are 32bit or 64bit?

  bool check_ident();
public:
  reader_t(linput_t *_li, int64 _start_in_file = 0);
  ~reader_t()
  {
    delete arch_specific;
  }
  void set_linput(linput_t *_li) { li = _li; }
  linput_t *get_linput() const { return li; }
  void set_load_bias(adiff_t lb) { load_bias = lb; }
  adiff_t get_load_bias() const { return load_bias; }

  bool is_warning(errcode_t notif) const;
  bool is_error(errcode_t notif) const;
  ssize_t prepare_error_string(char *buf, size_t bufsize, reader_t::errcode_t notif, va_list va) const;

  void set_handler(bool (*_handler)(const reader_t &reader, errcode_t notif, ...));

  int read_addr(void *buf) const;
  int read_off(void *buf) const;
  int read_xword(void *buf) const;
  int read_sxword(void *buf) const;
  int read_word(uint32 *buf) const;
  int read_half(uint16 *buf) const;
  int read_byte(uint8  *buf) const;
  int read_symbol(elf_sym_t *buf) const;
  int safe_read(void *buf, size_t size, bool apply_endianness = true) const;

  bool read_ident(); // false - bad elf file

  // Is the file a valid relocatable file? That is, it must have
  // the ET_REL ehdr e_type, and have a proper section table.
  bool is_valid_rel_file() const
  {
    return sections.initialized && !sections.empty() && get_header().e_type == ET_REL;
  }
  const elf_ident_t &get_ident() const { return header.e_ident; }

  bool read_header();
        elf_ehdr_t &get_header () { return header; }
  const elf_ehdr_t &get_header () const { return header; }

  bool read_section_headers();
  bool read_program_headers();
  bool read_notes(notes_t *notes);

  // Android elf files can have a prelink.
  // If such a prelink was found, this will return 'true' and
  // '*base' will be set to that prelink address.
  bool read_prelink_base(uint32 *base);

  int64 get_start_in_file() const { return sif; }

  // Seek to section header #index.
  // (Note that this does not seek to the section's contents!)
  bool seek_to_section_header(elf_shndx_t index)
  {
    uint64 pos = header.e_shoff + uint64(index) * uint64(header.e_shentsize);
    if ( pos < header.e_shoff )
      return false;
    if ( seek(pos) == -1 )
      return false;
    return true;
  }

  // read the section header from the current position
  // (should be called after seek_to_section_header)
  bool read_section_header(elf_shdr_t *sh);

  // Seek to program header #index.
  // (Note that this does not seek to the segment's contents!)
  bool seek_to_program_header(uint32 index)
  {
    uint64 pos = header.e_phoff + uint64(index) * uint64(header.e_phentsize);
    if ( pos < header.e_phoff )
      return false;
    if ( seek(pos) == -1 )
      return false;
    return true;
  }

  // read the compression header from the current position
  // (should be called after seek_to_compression_header)
  bool read_compression_header(elf_chdr_t *out);

  // Get the current position, in the elf module (which could
  // start at an offset different than 0 in the file).
  int64 tell() const { return qltell(li) - sif; }
  int64 size() const { return filesize - sif; }

  // Seek in the elf module, at the given position. If the elf module has an
  // offset in the file, it will be added to 'pos' to compose the final
  // position in file.
  qoff64_t seek(int64 pos) const { return qlseek(li, sif+pos); }

  //
  elf_sym_idx_t rel_info_index(const elf_rela_t &r) const;
  uint32 rel_info_type(const elf_rela_t &r) const;
  void set_rel_info_index(elf_rela_t *r, uint32 symidx) const;
  void set_rel_info_type(elf_rela_t *r, uint32 type) const;

  void add_mapping(const elf_phdr_t &p);
  // Searches all defined mappings for one that would
  // encompass 'ea'. Returns -1 if not found.
  int64 file_offset(uint64 ea) const;
  // Searches all defined mappings for one that would
  // encompass file offset 'offset'. Returns BADADDR if not found.
  ea_t file_vaddr(uint64 offset) const;

  elf_shndx_t get_shndx_at(uint64 offset) const;

  // string tables
  void set_sh_strtab(
        dynamic_info_t::entry_t &strtab,
        const elf_shdr_t &strtab_sh,
        bool replace);
  void set_di_strtab(
        dynamic_info_t::entry_t &strtab,
        const dynamic_info_t::entry_t &strtab_di);
  bool get_string_at(qstring *out, uint64 offset) const;
  bool get_name(
        qstring *out,
        const dynamic_info_t::entry_t &strtab,
        uint32 name_idx) const;
  bool get_name(qstring *out, slice_type_t slice_type, uint32 name_idx) const;

  // Sets the dynamic info
  typedef qvector<elf_dyn_t> dyninfo_tags_t;
  bool read_dynamic_info_tags(
        dyninfo_tags_t *dyninfo_tags,
        const dynamic_linking_tables_t &dlt);
  bool parse_dynamic_info(
        dynamic_info_t *dyninfo,
        const dyninfo_tags_t &dyninfo_tags);

  // Symbol versions
  bool read_symbol_versions(
        elf_symbol_version_t *symver,
        const dynamic_info_t &di,
        bool use_pht);

  // eh_frame reader
  bool read_eh_frame(cie_frame_vec_t *cie_vec, fde_frame_vec_t *fde_vec);

  arch_specific_t *get_arch_specific() const { return arch_specific; }

  // Human-friendly representations of
  // header (or ident) values.
  const char *file_type_str()    const;
  const char *os_abi_str()       const;
  const char *machine_name_str() const; // may return nullptr
  qstring get_machine_name() const;

  // effective endianness
  bool is_msb() const { return eff_msb; }
  // effective bitness (elf32 or elf64)
  bool is_64() const { return eff_64; }
  // effective bitness for segments
  int get_seg_bitness() const { return seg_64 ? 2 : 1; }

  // pointer size for some 64bit ABIs may be 32bit
  bool is_32_ptr() const
  {
    return !is_64()
        || header.e_machine == EM_PPC64
        && header.e_ident.osabi == ELFOSABI_CELLOSLV2
        || header.e_machine == EM_X86_64
        && header.e_ident.osabi == ELFOSABI_NACL;
  }

  bool is_arm() const
  {
    return header.e_machine == EM_ARM || header.e_machine == EM_AARCH64;
  }
  bool is_mips() const
  {
    return header.e_machine == EM_MIPS;
  }

  // validate section size and return number of elements
  void validate_section_size(
        uint64 *count,
        size_t *entsize,
        const elf_shdr_t &section,
        const char *counter_name);
};

//----------------------------------------------------------------------------
struct input_status_t
{
  input_status_t(const reader_t &_reader)
    : reader(_reader),
      pos(reader.tell())
  {
  }

  qoff64_t seek(int64 new_pos)
  {
    return reader.seek(new_pos);
  }

  ~input_status_t()
  {
    reader.seek(pos);
  }
private:
  const reader_t &reader;
  int64 pos;
  input_status_t();
};

//----------------------------------------------------------------------------
#define _safe(expr) if ( (expr) < 0 ) return false
struct elf_verdef_t : public Elf_Verdef
{
  bool read(const reader_t &reader)
  {
    _safe(reader.read_half(&vd_version));
    _safe(reader.read_half(&vd_flags));
    _safe(reader.read_half(&vd_ndx));
    _safe(reader.read_half(&vd_cnt));
    _safe(reader.read_word(&vd_hash));
    _safe(reader.read_word(&vd_aux));
    _safe(reader.read_word(&vd_next));
    return true;
  }
  uint16 cnt()
  {
    return vd_cnt;
  }
  uint32 aux()
  {
    return vd_aux;
  }
  uint32 next()
  {
    return vd_next;
  }
};

//----------------------------------------------------------------------------
struct elf_verdaux_t : public Elf_Verdaux
{
  bool read(const reader_t &reader)
  {
    _safe(reader.read_word(&vda_name));
    _safe(reader.read_word(&vda_next));
    return true;
  }
  uint32 next()
  {
    return vda_next;
  }
};

//----------------------------------------------------------------------------
struct elf_verneed_t : public Elf_Verneed
{
  bool read(const reader_t &reader)
  {
    _safe(reader.read_half(&vn_version));
    _safe(reader.read_half(&vn_cnt));
    _safe(reader.read_word(&vn_file));
    _safe(reader.read_word(&vn_aux));
    _safe(reader.read_word(&vn_next));
    return true;
  }
  uint16 cnt()
  {
    return vn_cnt;
  }
  uint32 aux()
  {
    return vn_aux;
  }
  uint32 next()
  {
    return vn_next;
  }
};

//----------------------------------------------------------------------------
struct elf_vernaux_t : public Elf_Vernaux
{
  bool read(const reader_t &reader)
  {
    _safe(reader.read_word(&vna_hash));
    _safe(reader.read_half(&vna_flags));
    _safe(reader.read_half(&vna_other));
    _safe(reader.read_word(&vna_name));
    _safe(reader.read_word(&vna_next));
    return true;
  }
  uint32 next()
  {
    return vna_next;
  }
#undef _safe
};

//----------------------------------------------------------------------------
struct symbol_verdaux_t
{
  int64 offset;
  size_t name;          // index in symver.version_names
};
DECLARE_TYPE_AS_MOVABLE(symbol_verdaux_t);
typedef qvector<symbol_verdaux_t> symbol_verdaux_vec_t;

//----------------------------------------------------------------------------
struct symbol_verdef_t
{
  int64 offset;
  symbol_verdaux_vec_t auxs;
  uint16 flags;
  uint16 ndx;
};
DECLARE_TYPE_AS_MOVABLE(symbol_verdef_t);
typedef qvector<symbol_verdef_t> symbol_verdef_vec_t;

//----------------------------------------------------------------------------
struct symbol_vernaux_t
{
  int64 offset;
  size_t name;          // index in symver.version_names
  uint16 other;
};
DECLARE_TYPE_AS_MOVABLE(symbol_vernaux_t);
typedef qvector<symbol_vernaux_t> symbol_vernaux_vec_t;

//----------------------------------------------------------------------------
struct symbol_verneed_t
{
  int64 offset;
  size_t name;          // index in symver.file_names
  symbol_vernaux_vec_t auxs;
};
DECLARE_TYPE_AS_MOVABLE(symbol_verneed_t);
typedef qvector<symbol_verneed_t> symbol_verneed_vec_t;

//----------------------------------------------------------------------------
struct vermap_item_t
{
  size_t fname_idx;     // index in symver.file_names
  size_t vname_idx;     // index in symver.version_names
};

//----------------------------------------------------------------------------
typedef std::map<uint16, vermap_item_t> symbol_version_map_t;

//----------------------------------------------------------------------------
struct elf_symbol_version_t
{
  // from DT_VERDEF
  symbol_verdef_vec_t defs;
  // from DT_VERNEED
  symbol_verneed_vec_t reqs;
  // from DT_VERSYM
  qvector<uint16> symbols;

  // item with VER_FLG_BASE in verdaux
  size_t def_base;      // index in file_names

  // file and version strings referenced throughout this structure
  qstrvec_t file_names;
  qstrvec_t version_names;

  // map for entries in DT_VERSYM
  symbol_version_map_t vermap;

  elf_symbol_version_t()
    : def_base(0)
  {}
};

//----------------------------------------------------------------------------
template<typename T> class buffered_input_t
{
protected:
  reader_t &reader;
  uint64 offset;
  uint64 count;
  size_t isize; // entry size

  qvector<T> buffer;
  uint64 read;  // number of items we already read from the input
  uint32 cur;   // ptr to the next item in 'buffer' to be served
  uint32 end;   // number of items in 'buffer'

public:
  buffered_input_t(reader_t &_reader, const elf_shdr_t &section)
    : reader(_reader),
      offset(section.sh_offset),
      count (0),
      isize (section.sh_entsize),
      read  (0),
      cur   (0),
      end   (0)
  {
    count = reader.sections.get_size_in_file(section);
    if ( isize != 0 )
      count /= isize;
  }
  buffered_input_t(
          reader_t &_reader,
          uint64 _offset,
          uint64 _count,
          size_t entsize)
    : reader(_reader),
      offset(_offset),
      count (_count),
      isize (entsize),
      read  (0),
      cur   (0),
      end   (0) {}
  virtual ~buffered_input_t() {}

  virtual bool next(T *&storage) newapi
  {
    if ( cur >= end )
    {
      uint64 left = count - read;
      if ( left == 0 )
        return false;
      buffer.resize(left);

      cur = 0;
      if ( read == 0 )
        start_reading();
      end = read_items(left);
      if ( end == 0 )
        return false;
      read += end;
    }

    if ( cur >= end )
      return false;

    storage = &buffer[cur];
    cur++;
    return true;
  }

private:
  buffered_input_t();
  // default and dumb implementation of read_items()
  // it reads items one by one from the input.
  // see other implementations in template specializations
  ssize_t read_items(size_t max)
  {
    size_t i = 0;
    if ( is_mul_ok<uint64>(read, isize) && is_mul_ok(max, isize) )
    {
      input_status_t save_excursion(reader);
      if ( save_excursion.seek(offset + (read * isize)) != -1 )
        for ( ; i < max; i++ )
          if ( !read_item(buffer[i]) )
            break;
    }
    return i;
  }

  bool read_item(T &) { return false; }
  void start_reading() {}
};

class buffered_rel_t : public buffered_input_t<elf_rel_t>
{
  typedef buffered_input_t<elf_rel_t> inherited;
  elf_rela_t rela; // to return from next_rela()

public:
  buffered_rel_t(reader_t &_reader, const elf_shdr_t &section)
    : inherited(_reader, section) {}
  buffered_rel_t(
          reader_t &_reader,
          uint64 _offset,
          uint64 _count,
          size_t entsize)
    : inherited(_reader, _offset, _count, entsize) {}
  bool next_rela(elf_rela_t *&storage)
  {
    elf_rel_t *rel;
    if ( !inherited::next(rel) )
      return false;
    rela.r_offset = rel->r_offset;
    rela.r_info = rel->r_info;
    rela.r_addend = 0;
    storage = &rela;
    return true;
  }
};

class buffered_rela_t : public buffered_input_t<elf_rela_t>
{
  typedef buffered_input_t<elf_rela_t> inherited;

  bool packed;
public:
  buffered_rela_t(reader_t &_reader, const elf_shdr_t &section, bool _packed)
    : inherited(_reader, section), packed(_packed) {}
  buffered_rela_t(
          reader_t &_reader,
          uint64 _offset,
          uint64 _count,
          size_t entsize,
          bool _packed)
    : inherited(_reader, _offset, _count, entsize), packed(_packed) {}
  virtual bool next(elf_rela_t *&storage) override;
  bool next_rela(elf_rela_t *&storage) { return next(storage); }
};

//--------------------------------------------------------------------------
struct shdr_def_t
{
  range_t range;
  sel_t sel;            // selectors of loaded sections,
                        // BADSEL-section not loaded
  bool may_overlap;     // may overlap with other sections.
                        // no warning is shown, but sh_overlaps is still set.

  shdr_def_t() : sel(BADSEL), may_overlap(false) {}
  shdr_def_t(const elf_shdr_t *sh, bool may_overlap_ = false)
    : range(ea_t(sh->sh_offset), ea_t(sh->sh_offset + sh->sh_size)),
      sel(BADSEL),
      may_overlap(may_overlap_) {}
};
DECLARE_TYPE_AS_MOVABLE(shdr_def_t);
typedef qvector<shdr_def_t> shdr_defs_t;

//--------------------------------------------------------------------------
// description of special segments
struct elf_spec_segm_t
{
  //lint --e{958} Padding of ... is required to align member on ... boundary
  // description
  const char *seg_name = nullptr;
  uint16 shn_type = 0;
  uchar seg_type = 0;
  // allocation
  uint32 nsyms = 0;
  ea_t start = 0;
  ea_t end = 0;
  ea_t cur = 0;

  elf_spec_segm_t(uchar seg_type_=0, const char *seg_name_=nullptr, uint16 shn_type_=0)
    : seg_name(seg_name_),
      shn_type(shn_type_),
      seg_type(seg_type_)
  {
  }

  static proc_def_t::spec_type_t symbol2spec(
        const proc_def_t *pd,
        uint16 secidx,
        ushort type);
  bool not_allocated() const { return start == 0 && end == 0; }

  bool allocate_spec_segm(elf_loader_t &ldr, reader_t &reader);

  // it shrinks the segment and returns its new end
  ea_t end_seg();
};

//-------------------------------------------------------------------------
struct elf_range_info_t
{
  ea_t start;
  ea_t end;
  int64 offset;
};
DECLARE_TYPE_AS_MOVABLE(elf_range_info_t);
typedef std::map<ea_t, elf_range_info_t> range_info_map_t;
typedef range_info_map_t::const_iterator range_info_map_citerator_t;

class loaded_ranges_t
{
  rangeset_t ranges;
  range_info_map_t range_info_map;

public:
  bool add(int64 offset, ea_t start, ea_t _end)
  {
    bool ok = ranges.add(start, _end);
    if ( ok )
    {
      elf_range_info_t &info = range_info_map[start];
      info.start = start;
      info.end = _end;
      info.offset = offset;
    }
    return ok;
  }
  const range_t *find_range(ea_t ea) const
  {
    return ranges.find_range(ea);
  }
  ea_t next_range(ea_t ea) const
  {
    return ranges.next_range(ea);
  }
  const elf_range_info_t *range_info(ea_t ea) const
  {
    const range_t *range = ranges.find_range(ea);
    if ( range == nullptr )
      return nullptr;
    range_info_map_citerator_t it = range_info_map.find(range->start_ea);
    if ( it == range_info_map.end() )
      return nullptr;
    return &it->second;
  }
};

//--------------------------------------------------------------------------
class tlsinfo2_public_t
{
  friend struct process_tls_t;
  friend struct elf_loader_t;
  struct tlsinfo2_t *pimpl;
public:
  tlsinfo2_public_t(elf_loader_t &l);
  tlsinfo2_public_t();
  ~tlsinfo2_public_t();
  void set_env(reader_t &reader_, elf_spec_segm_t &spec_tls_);
  void set_from_ph(const elf_phdr_t &p);
  // should be called after set_from_ph()
  void set_from_tdata_sh(
        const elf_shdr_t &sh,
        elf_shndx_t secidx,
        const char *name);
  // should be called after set_from_ph()
  void set_from_tbss_sh(
        const elf_shdr_t &sh,
        elf_shndx_t secidx,
        const char *name);
  void create_tls_template();
  // define 'tls_index' structures
  void analyze_tis();
  ea_t get_tls_end() const;
  ea_t symbol2ea(const sym_rel &symrel) const;
};

//----------------------------------------------------------------------------
class gnu_debugdata_t
{
public:
  enum xz_ret_t
  {
    XZRET_OK,
    XZRET_OUT_OF_MEMORY,
    XZRET_DECODE_ERROR,
    XZRET_CHECKSUM_ERROR,
    XZRET_BAD_HEADERS
  };

private:
  bytevec_t decompressed;
  linput_t *li = nullptr;
  elf_file_info_t *finfo = nullptr;
  xz_ret_t xz_comment = XZRET_OK;

public:
  ~gnu_debugdata_t()
  {
    clear_finfo();
    clear_li();
  }

  elf_file_info_t *file_info() { return finfo; }

  xz_ret_t comment() const { return xz_comment; }

  bool init();
  bool create_reader(const bytevec_t &compressed);

private:
  void clear_li();
  void clear_finfo();

protected:
  xz_ret_t xz_decompress_memory(bytevec_t *buf_out, const bytevec_t &buf_in);
};

//--------------------------------------------------------------------------
struct elf_loader_t
{
  linput_t *li = nullptr;
  struct processor_t &ph;
  elf_spec_segm_t spec_segms[proc_def_t::NSPEC_SEGMS];

  sel_t cursel = 0;
  sel_t datasel = 0;

  elf_shndx_t ct_sec = 0;
  elf_shndx_t dt_sec = 0;
  ea_t init_ea = 0;
  ea_t fini_ea = 0;
  ea_t init_proc_ea = 0;
  ea_t fini_proc_ea = 0;

  tlsinfo2_public_t tlsinfo2;

  proc_def_t *pd = nullptr;

  qstrvec_t implibs;
  netnode impnode = BADNODE;

  qstring interpreter;

  netnode elfnode;

  // The program end. Does *not* contain the 'extern' segment. It does,
  // however, contain .bss and .tbss data.
  ea_t prgend = 0;

  // index of the _GLOBAL_OFFSET_TABLE_ symbol for the relocatable files
  symrel_idx_t got_sym_idx;

  // This symbol is used only for debugging purposes.
  // It specifies the segment base to be used for all segments.
  // Usually it is zero (ELF files use flat memory without any segments)
  uval_t debug_segbase = 0;

  loaded_ranges_t loaded_ranges;
  size_t overlapped_range_cnt = 0;

  // structure ids for VERDEF, VERDAUX, etc
  tid_t verdef_sid = BADADDR;
  tid_t verdaux_sid = BADADDR;
  tid_t vernaux_sid = BADADDR;
  tid_t verneed_sid = BADADDR;
  tid_t prstatus_sid = BADADDR;
  tid_t prpsinfo_sid = BADADDR;
  tid_t elf_sym_sid = BADADDR;
  tid_t elf_rel_sid = BADADDR;
  tid_t elf_rela_sid = BADADDR;

  size_t stubsize = 0;
  ea_t topaddr = 0;

  ushort neflags;
  fixup_type_t ptpoff_reltype = FIXUP_CUSTOM;

  bool broken_output_warning_displayed = false;
  bool widebyte = false;
  bool was_empty_idb = false;
  bool gnuunx_loaded = false;  // loaded gnuunx.til?
  bool rel_present = false;
  char rel_mode = 0;  // 1 - STT_SECTION
                      // 0 - !STT_SECTION
                      //-1 - STT_NOTYPE or undefined

  gnu_debugdata_t gnu_debugdata;

  elf_loader_t(linput_t *li, ushort neflags);
  ~elf_loader_t();
  void load_file();
  ushort ana_hdr(reader_t &reader);
  void collect_loader_options(struct elf_load_options *load_opts);
  const char *get_processor_name(
        reader_t &reader,
        const elf_ehdr_t &header,
        bool msb);
  size_t max_loaded_size(ea_t ea, size_t size) const;
  bool is_range_loaded(ea_t ea, size_t size) const;
  bool load_section_headers(reader_t &reader);
  elf_file_info_t *find_companion_file(
        const reader_t &main_reader,
        const notes_t &notes,
        const elf_load_options &load_opts,
        rangevec_t *loaded_notes);
  ea_t preload_pht(reader_t &reader);
  void load_pht(
        reader_t &reader,
        const elf_load_options &load_opts,
        rangevec_t *loaded_notes);
  bool should_load_segment(
        reader_t &reader,
        const elf_shdr_t *sh,
        elf_shndx_t idx,
        const qstring &name);
  bool is_uniform(reader_t &reader, size_t offset, asize_t size);
  void find_and_load_gaps(reader_t &reader);
  void load_section_contents(
        elf_file_info_t &finfo,
        rangevec_t *loaded_notes);
  bool belongs_to_skipped_section(
        elf_file_info_t &finfo,
        const sym_rel &sym);
  void detect_overlapping_pht(int64 offset, ea_t startaddr, ea_t endaddr);
  void validate_dynamic_info(reader_t &reader, dynamic_info_t *di) const;
  void annotate_headers(reader_t &reader);
  void annotate_loaded_notes(reader_t &reader, const rangevec_t &loaded_notes);
  void annotate_note_core(reader_t &reader, const struct print_note_t &note);
  void make_verdef_section(
        reader_t &reader,
        const dynamic_info_t::entry_t &entry,
        const elf_symbol_version_t &symver);
  void make_verneed_section(
        reader_t &reader,
        const dynamic_info_t::entry_t &entry,
        const elf_symbol_version_t &symver);
  void make_versym_section(
        reader_t &reader,
        const dynamic_info_t::entry_t &entry,
        const elf_symbol_version_t &symver);
  void make_rel_section(
        reader_t &reader,
        const dynamic_info_t::entry_t &entry,
        bool is_rela,
        const char *name);
  void make_symtab_section(reader_t &reader, const dynamic_info_t::entry_t &entry);
  void adjust_widebyte_code_segment(segment_t *seg) const;
  ea_t unwide_ea(ea_t ea, const char *diagn) const;
  void preprocess_symbols(
        elf_file_info_t &finfo,
        const elf_load_options &load_opts);
  bool extract_gnu_debugdata(reader_t &main_reader);
  int load_symbols(
        elf_file_info_t &finfo,
        slice_type_t slice_type,
        uint32 section_symbols_count,
        bool skip_undef_symbols);
  void apply_file_symbols(elf_file_info_t &finfo);
  void check_notype_symbols(
        elf_file_info_t &finfo,
        slice_type_t slice_type);
  void define_gotnode(elf_file_info_t &finfo, const elf_dyn_t &dyn);
  void describe_public(
        ea_t ea,
        ushort bind,
        int entry_flag,
        const char *name,
        const elf_symbol_version_t *symver=nullptr,
        elf_sym_idx_t symidx=0);
  ea_t create_addonce_var(
        ea_t ea,
        uint64 valsiz,
        uchar seg_typ,
        ushort type,
        ushort bind,
        bool isfunc,
        const char *name,
        const elf_symbol_version_t *symver,
        elf_sym_idx_t symidx);
  ea_t declare_spec(
        reader_t &reader,
        uint16 secidx,
        uint64 size,
        ushort type,
        ushort bind,
        bool isfunc,
        const char *name,
        const elf_symbol_version_t *symver=nullptr,
        elf_sym_idx_t symidx=0);
  void count_spec_symbols(
        reader_t &reader,
        slice_type_t slice_type,
        bool skip_undef_symbols);
  bool call_add_segm_ex(
        segment_t *s,
        const char *name,
        const char *sclass,
        int flags) const;
  bool add_or_merge_segm(
        segment_t *s,
        const char *name,
        const char *sclass,
        int flags);
  bool do_define_segment(
        reader_t &reader,
        ea_t *out_sa,
        ea_t *out_topseg,
        elf_shdr_t &sh,
        const qstring &name);
  bool define_segment(
        elf_file_info_t &finfo,
        elf_shdr_t &sh,
        elf_shndx_t idx,
        const qstring &name,
        bool force_load,
        ea_t *startaddr = nullptr,
        asize_t *_size = nullptr);
  void load_huge_segment(
        reader_t &reader,
        const segment_t &s,
        const elf_phdr_t &p,
        const char *sclass,
        const char *name,
        int flags);
  // create a new segment where a previous segment ended (at the top).
  // Allocate new selector for the new segment. If the flag use_cursel is
  // set then use currently allocated segment selector and allocate a new
  // one after creation.
  segment_t *create_segment_at_top(
        reader_t &reader,
        uchar type,
        const char *name,
        asize_t size,
        uchar align,
        bool use_cursel = false);
  void look_for_prgend_symbols(reader_t &reader);
  // for the relocation object file calculate a start address of the
  // segment where previous segment ended (at the top). For executable or
  // shared objects this function returns the address from <sh>.
  ea_t get_default_segment_ea(reader_t &reader, const elf_shdr_t &sh) const;
  bool should_rename(ushort type, const char *name) const;
  void check_for_gnuc(const char *name);
  void convert_sub_table(reader_t &reader, const elf_shdr_t *pps, char lsym);
  void elf_get_rebased_eas(reader_t &reader, ea_t *pimagebase, ea_t *pload_base);
  void load_ids_info(void);
  // get fixup for PTPOFF generic TLS reloc,
  // it returns FIXUP_CUSTOM if this reloc isn't supported
  fixup_type_t get_ptpoff_reltype();
  void comment_rename(ea_t ea, const char *name);
  void broken_output_warning(void);
  asize_t map_range_from_file(
        reader_t &reader,
        int64 offset,
        ea_t startaddr,
        ea_t endaddr,
        const elf_phdr_t *pht_entry = nullptr);
  // FIXME this is wrong! it will be replaced by process_TLS()
  // It is assumed the 'in_out_offset' is relative to the start of
  // the TLS block at runtime. Since those blocks have the following layout:
  // +---------------+
  // |               |
  // |     .tdata    |
  // |               |
  // +---------------+
  // |               |
  // |     .tbss     |
  // |               |
  // +---------------+
  // we'll associate 'in_out_offset' to either the '.tdata' segment,
  // or the '.tbss' one, depending on whether it overflows
  // .tdata or not.
  //
  // As a side-effect, note that the value pointed to by 'in_out_offset' will
  // be different after this function returns, in case it lands into '.tbss'.
  // (it will be: in_out_offset_after = in_out_offset - segment_size(".tdata"))
  ea_t get_tls_ea_by_offset(uint32 *in_out_offset);
  void relocate_rela(
        reader_t &reader,
        const elf_rela_t &rel,
        bool is_rela,
        int reloc_idx, // Current index in relocation section
        slice_type_t slice_type,
        uint32 info_idx,
        const char *segname,
        reloc_tools_t &tools);
  void relocate_section_mips(
        reader_t &reader,
        const elf_shdr_t &section,
        const char *segname,
        slice_type_t slice_type,
        reloc_tools_t &tools,
        bool packed,
        int info_idx,
        uint64 count,
        size_t entsize);
  void relocate_section(
        elf_file_info_t &finfo,
        const elf_shdr_t &section,
        const char *segname,
        slice_type_t slice_type,
        reloc_tools_t &tools,
        bool packed);
  void process_relocations(
        elf_file_info_t &finfo,
        const dynamic_info_t &di,
        reloc_tools_t &tools);
  bool use_displ_for_symbol(ea_t S, adiff_t A)
  {
    if ( S >= prgend )
      return true;
    if ( rel_mode == 1 ) // symbol is STT_SECTION ?
    {
      segment_t *s = getseg(S);
      return s == nullptr || A < 0 || A >= s->size();
    }
    return false;
  }
};

//--------------------------------------------------------------------------
inline int check_alignment(uint64 align)
{
  if ( align > 1 && align <= 4096 && is_pow2(align) )
    return align;
  return 1; // ignore alignment
}

//--------------------------------------------------------------------------
inline ea_t reader_t::trunc_segm_end(ea_t end) const
{
  // 0x1'0000'0000 is the valid segment end in ida64
  return end == ea_space_end() ? end : trunc_uval(end);
}

ushort get_algn_value(uval_t algn);
void get_versioned_symbol_name(
        qstring *out,
        const char *symname,
        const elf_symbol_version_t &symver,
        uint16 idx);
void annotate_got0(const reader_t &reader, ea_t got0);
void annotate_loaded_notes(
        const reader_t &reader,
        const rangevec_t &loaded_notes);
void set_got_entry(ea_t ea, const char *name, int flags, const char *suffix = "_ptr");

#endif
