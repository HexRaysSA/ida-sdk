#include <idp.hpp>
#include <loader.hpp>

#define UUNP_NODE_NAME "$ uunp"

//----------------------------------------------------------------------
struct uunp_ctx_t;
DECLARE_LISTENER(dbg_listener_t, uunp_ctx_t, ctx);

struct uunp_ctx_t : public plugmod_t
{
  dbg_listener_t dbg_listener = dbg_listener_t(*this);

  ea_t bp_gpa = BADADDR;            // address of GetProcAddress()
  range_t curmod;                   // current module range
  bool wait_box_visible = false;
  range_t oep_range;                // original entry point range
  qstring resfile;                  // resource file name
  ea_t an_imported_func = BADADDR;  // an imported function
  bool success = false;
  bool is_9x = false;
  ea_t bpt_ea = BADADDR;            // our bpt address

  // win9x.cpp
  typedef std::map<ea_t, ea_t> thunks_t;
  thunks_t thunks;

  // resext.cpp
  FILE *fr = nullptr;
  ea_t ResBase = 0;
  uint32 ResTop = 0;
  asize_t ImgSize = 0;
  struct
  {
    union
    {
      wchar_t *name = nullptr;
      uint16 Id;
    };
    uint32 len = 0;
  } Names[3];

#pragma pack(push, 1)
  struct rhdr_end_t
  {
    uint32 DataVersion;
    uint16 MemoryFlags;
    uint16 LanguageId;
    uint32 Version;
    uint32 Characteristrics;
  };
  union rhdr_name_t
  {
    struct
    {
      uint16 prefix;  // = 0xFFFF if number entry
      uint16 Id;      // for number entry
    };
    wchar_t Name[1];  // zero terminated
  };
#pragma pack()
  rhdr_end_t  re = { 0 };
  rhdr_name_t zname = { { 0xFFFF } };

  // on_event()
  int stage = 0;
  bool is_dll = false;
  char needed_file[QMAXPATH] = "";

  uunp_ctx_t();
  ~uunp_ctx_t();
  virtual bool idaapi run(size_t) override;
  ssize_t idaapi on_dbg_event(ssize_t code, va_list va);

  inline void set_wait_box(const char *mesg);
  inline void _hide_wait_box();

  // Windows9x specific functions
  void win9x_resolve_gpa_thunk();
  ea_t win9x_find_thunk(ea_t ea);
  void find_thunked_imports();

  // Resource extractor function
  void extract_resource(const char *fname);
  void store(const void *Data, uint32 size);
};

extern int data_id;

