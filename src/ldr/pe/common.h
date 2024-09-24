#ifndef _PE_LDR_COMMON_H_
#define _PE_LDR_COMMON_H_

#include <netnode.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>

#define PAGE_SIZE 0x1000
//------------------------------------------------------------------------
struct pe_section_visitor_t
{
  virtual int idaapi visit_section(const pesection_t &, off_t /*file_offset*/) { return 0; }
  virtual int idaapi load_all() { return 0; }
  virtual ~pe_section_visitor_t(void) {}
};

//------------------------------------------------------------------------
//-V:pe_import_visitor_t:730 not all members of a class are initialized inside the constructor
struct pe_import_visitor_t
{
  bool withbase;
  int elsize;  // initialized by process_import_table()
  peimpdir_t id;
  dimpdir_t did;

  pe_import_visitor_t(void) : withbase(false) {}
  virtual int idaapi visit_module(const char * /*dll*/, ea_t /*iat_start*/, ea_t /*int_rva*/) { return 0; }
  virtual int idaapi leave_module(uint32 /*nprocessed_imports*/) { return 0; }
  // buf==nullptr:by ordinal
  virtual int idaapi visit_import(ea_t impea, uint32 ordinal, const char *buf) = 0;
  virtual int idaapi impdesc_error(off_t /*file_offset*/) { return 0; }
  virtual ~pe_import_visitor_t(void) {}
};

//------------------------------------------------------------------------
struct pe_export_visitor_t
{
  // this function will be called once at the start.
  // it must return 0 to continue
  virtual int idaapi visit_expdir(const peexpdir_t & /*ed*/, const char * /*modname*/) { return 0; }
  // this function is called for each export. name is never nullptr, forwarder may point to the forwarder function
  // it must return 0 to continue
  virtual int idaapi visit_export(uint32 rva, uint32 ord, const char *name, const char *forwarder) = 0;
  virtual ~pe_export_visitor_t(void) {}
};

//------------------------------------------------------------------------
class pe_loader_t
{
  int process_import_table(
        linput_t *li,
        ea_t atable,
        ea_t ltable,
        pe_import_visitor_t &piv);
  template <class T>
  T varead(linput_t *li, uint32 rva, bool *ok)
  {
    T x = 0;
    bool _ok = vseek(li, rva) && qlread(li, &x, sizeof(x)) == sizeof(x);
    if ( ok != nullptr )
      *ok = _ok;
    return x;
  }
public:
  struct transl_t
  {
    ea_t start;
    ea_t end;
    off_t pos;
    size_t psize;
  };
  typedef qvector<transl_t> transvec_t;
  transvec_t transvec;
  union
  {
    exehdr exe;
    teheader_t te;
  };
  peheader_t pe;
  peheader64_t pe64;    // original 64bit header, should not be used
                        // because all fields are copied to pe
                        // nb: imagebase is truncated during the copy!
  ea_t load_imagebase;  // imagebase used during loading; initialized from the PE header but can be changed by the user
  off_t peoff;          // offset to pe header
  bool link_ulink;      // linked with unilink?

  // low level functions

//------------------------------------------------------------------------
// NB! We need to walk the mapping backwards, because
// the later sections take priority over earlier ones
//
// e.g. consider
// section 0: start=1000, end=5000, pos=1000
// section 1: start=3000, end=4000, pos=5000
// for byte at RVA 3500:
// section 0 maps it from the file offset 3500
// but section 1 overrides it with the byte from file offset 5500!
//
  inline ea_t map_ea(ea_t rva, const transl_t **tl=nullptr)
  {
    for ( ssize_t i=transvec.size()-1; i >= 0; i-- )
    {
      const transl_t &trans = transvec[i];
      if ( trans.start <= rva && trans.end > rva )
      {
        if ( tl != nullptr )
          *tl = &trans;
        return rva-trans.start + trans.pos;
      }
    }
    return BADADDR;
  }
  ea_t get_imagebase(void) const { return load_imagebase; }
  void set_imagebase(ea_t newimagebase) { load_imagebase=newimagebase; }
  virtual bool vseek(linput_t *li, uint32 rva);
  inline uint16 vashort(linput_t *li, uint32 addr, bool *ok) { return varead<uint16>(li, addr, ok); }
  inline uint32 valong(linput_t *li, uint32 addr, bool *ok) { return varead<uint32>(li, addr, ok); }
  inline uint64 vaint64(linput_t *li, uint32 addr, bool *ok) { return varead<uint64>(li, addr, ok); }
  char *asciiz(linput_t *li, uint32 rva, char *buf, size_t bufsize, bool *ok);
  char *asciiz2(linput_t *li, uint32 rva, char *buf, size_t bufsize, bool *ok);
  int process_sections(linput_t *li, off_t fist_sec_pos, int nojbs, pe_section_visitor_t &psv);
  int process_sections(linput_t *li, pe_section_visitor_t &psv);
  // If 'zero_bad_data==true' (i.e., the default), extra 'directories'
  // in the pe/pe64 headers will be set to zero.
  bool read_header(linput_t *li, off_t _peoff, bool silent, bool zero_bad_data = true);

  // high level functions
  bool read_header(linput_t *li, bool silent=false, bool zero_bad_data = true);
  int process_sections(linput_t *li);

  int process_delayed_imports(linput_t *li, pe_import_visitor_t &il);
  int process_imports(linput_t *li, pe_import_visitor_t &piv);
  int process_exports(linput_t *li, pe_export_visitor_t &pev);
  bool vmread(linput_t *li, uint32 rva, void *buf, size_t sz);

  bool read_strtable(qstring *out, linput_t *li);

  virtual ~pe_loader_t(void) {}
};

//------------------------------------------------------------------------
struct import_loader_t : public pe_import_visitor_t
{
  struct dllinfo_t
  {
    qstring orig_name;
    qstring name;
    netnode node;       // will be used by import_module()
    bool imported_module;

    dllinfo_t()
      : imported_module(false)
    {}
  };
  typedef qvector<dllinfo_t> dllinfo_vec_t;

  processor_t &ph;
  peheader_t &pe;
  const ea_helper_t &_eah;
  dllinfo_vec_t dlls;   // visited modules
  range_t imprange;
  ea_t astart;
  ea_t last_imp;
  ea_t int_rva;
  int ndid;             // number of delayed import dirs
  bool displayed;
  bool got_new_imports;
  bool delayed_imports;

  inline void preprocess(void);
  inline bool has_module(const char *mod) const
  {
    size_t ndlls = dlls.size();
    for ( size_t i = 0; i < ndlls; i++ )
      if ( !stricmp(dlls[i].orig_name.c_str(), mod) )
        return true;
    return false;
  }
  int idaapi visit_module(const char *dll, ea_t iat_start, ea_t _int_rva) override;
  int idaapi visit_import(ea_t impea, uint32 ordinal, const char *buf) override;
  int idaapi leave_module(uint32 nprocessed_imports) override;
  int idaapi impdesc_error(off_t off) override;
  inline void postprocess(void);

  import_loader_t(processor_t &_ph, peheader_t &_pe, const ea_helper_t &_eh, bool di)
    : ph(_ph), pe(_pe), _eah(_eh),
      astart(BADADDR), last_imp(BADADDR), int_rva(0),
      ndid(0),
      displayed(false), got_new_imports(false), delayed_imports(di)
  {
    imprange.start_ea = BADADDR;
    imprange.end_ea   = 0;
  }

  DEFINE_EA_HELPER_FUNCS(_eah)
};

#ifdef __EA64__

struct function_entry_x64
{
  uint32 BeginAddress;
  uint32 EndAddress;
  uint32 UnwindData;
  bool operator<(const function_entry_x64 &r) const { return BeginAddress < r.BeginAddress; }
  bool operator!=(const function_entry_x64 &r) const
  {
    return BeginAddress != r.BeginAddress
        || EndAddress != r.EndAddress
        || UnwindData != r.UnwindData;
  }
};

struct unwind_info_x64
{
  uint8 Version_Flags;
  uint8 SizeOfProlog; //lint -e754 local structure member not referenced
  uint8 CountOfCodes;
  uint8 FrameRegister_Offset;
};

#endif

//------------------------------------------------------------------------
struct ida_loader_t : public pe_loader_t
{
  processor_t &ph;
  const ea_helper_t &_eah;
  eavec_t asked_eas;
  import_loader_t imploader;  // used in load_imports()
  import_loader_t didloader;  // used in load_delayed_imports()
  bool loaded_header = false;
  bool vseek_asked = false;
  bool has_embedded_pdb = false;

  virtual bool vseek(linput_t *li, uint32 rva) override
  {
    ea_t fpos;
    if ( get_linput_type(li) == LINPUT_PROCMEM )
    {
      fpos = rva;
    }
    else
    {
      fpos = map_ea(rva);
      if ( fpos == BADADDR && rva < peoff+pe.allhdrsize )
        fpos = rva;
    }
    if ( fpos != BADADDR )
    {
      qoff64_t p2 = qlseek(li, qoff64_t(fpos));
      return p2 != -1;
    }
    if ( !vseek_asked
      && ask_yn(ASKBTN_YES,
                "HIDECANCEL\n"
                "Can't find translation for relative virtual address %08X, continue?",
                rva) <= ASKBTN_NO )
    {
      loader_failure();
    }
    vseek_asked = true;
    qlseek(li, rva, SEEK_SET);
    return false;
  }
  ida_loader_t(void) //lint !e1401 non-static data member 'pe_loader_t::*' not initialized by constructor
    : ph(PH),
      _eah(EAH),
      imploader(ph, pe, eah(), false),
      didloader(ph, pe, eah(), true)
  {}

  void setup_entry_and_dgroup(linput_t *li, sel_t dgroup);
  bool make_beginning_loaded(linput_t *li, ea_t begin);
  sel_t load_sections(linput_t *li, bool aux, const qstring *strtable=nullptr);
  void load_tls(linput_t *li);
  void load_exports(linput_t *li);
  void load_imports(linput_t *li);
  void load_delayed_imports(linput_t *li);
  void read_and_save_fixups(linput_t *li);
  bool has_imports_by_ordinal(linput_t *li);
  void load_cli_module(linput_t *_li);
  void load_pdata(linput_t *li);
  void pe_convert_idata();
  void comment_impexp(linput_t *li);
  void load_loadconfig(linput_t *li);
  void load_header_section(linput_t *li, bool visible);
  void load_debug_info(linput_t *li);
  bool has_ntdll() const { return imploader.has_module("ntdll.dll"); }
#ifdef __EA64__
  int check_chained_uw(linput_t *li, uint32 rva, function_entry_x64 *chained, int nest_count = 0);
  void load_pdata_x64(linput_t *li, uint32 pdata_rva, asize_t psize);
  bool has_bad_uwopcodes(linput_t *li, uint32 uw_rva, ea_t funcstart);
#endif
  DEFINE_EA_HELPER_FUNCS(_eah)
  ea_t trunc_segm_end(ea_t end) const
  {
    // 0x1'0000'0000 is the valid segment end in ida64
    return end == ea_space_end() ? end : trunc_uval(end);
  }
};

#endif
