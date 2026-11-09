//---------------------------------------------------------------------------
// Hex view sample plugin

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <cvt64.hpp>
void register_hex_place();

//---------------------------------------------------------------------------
// hex data
class hex_data_t : public plugmod_t, public event_listener_t
{
  TWidget *cv = nullptr;
  TWidget *hexview = nullptr;

  FILE *f = nullptr;
  uint64 sz = 10000;
  const uint align = 16;

public:

  hex_data_t()
  {
    hook_event_listener(HT_VIEW, this);
    register_hex_place();
  }
  ~hex_data_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
    close();
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  bool open(const char *fname)
  {
    close();
    f = qfopen(fname, "rb");
    if ( f == nullptr )
      return false;
    // 64 bit functions could be used instead
    qfseek(f, 0, SEEK_END);
    sz = qftell(f);
    return true;
  }

  void close()
  {
    cv = nullptr;
    hexview = nullptr;
    if ( f != nullptr )
    {
      qfclose(f);
      f = nullptr;
      sz = 0;
    }
  }

  bool read(uint64 pos, void *buf, size_t bufsize)
  {
    // 64 bit functions could be used instead
    if ( qfseek(f, pos, SEEK_SET) != 0 )
      return false;
    return qfread(f, buf, bufsize) == bufsize;
  }

  uint64 size() const
  {
    return sz;
  }

  int alignment() const
  {
    return align;
  }

  uval_t pos_to_line(uint64 pos) const
  {
    return pos / align;
  }

  uval_t maxline() const
  {
    return pos_to_line(sz - 1);
  }
};

//---------------------------------------------------------------------------
// hex place
define_place_exported_functions(hex_place_t)

//-------------------------------------------------------------------------
class hex_place_t : public place_t
{
public:
  hex_data_t *d;
  uval_t n;
  hex_place_t() : d(nullptr), n(0) { lnnum = 0; }
  hex_place_t(hex_data_t *_d, uint64 pos = 0) : d(_d)
  {
    n = d->pos_to_line(pos);
    lnnum = 0;
  }
  define_place_virtual_functions(hex_place_t)
};
#include "hexplace.cpp"

//--------------------------------------------------------------------------
ssize_t idaapi hex_data_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case ui_widget_invisible:
      {
        TWidget *w = va_arg(va, TWidget *);
        if ( w == hexview || w == cv )
        {
          close();
          unhook_event_listener(HT_UI, this);
        }
      }
      break;
  }
  return 0;
}

//---------------------------------------------------------------------------
// Create a custom view window
bool idaapi hex_data_t::run(size_t)
{
  static const char title[] = "Sample hexview";
  TWidget *widget = find_widget(title);
  if ( widget != nullptr )
  {
    warning("Hexview already open. Switching to it.");
    activate_widget(widget, true);
    return true;
  }

  // ask the user to select a file
  char *filename = ask_file(false, nullptr, "Select a file to display...");
  if ( filename == nullptr || filename[0] == 0 )
    return true;
  // open the file
  if ( !open(filename) )
    return true;

  // create two place_t objects: for the minimal and maximal locations
  hex_place_t s1(this);
  hex_place_t s2(this, size() - 1);
  // create a custom viewer
  cv = create_custom_viewer(title, &s1, &s2, &s1, nullptr, this, nullptr, nullptr);
  // create a code viewer container for the custom view
  hexview = create_code_viewer(cv);
  // set the radix and alignment for the offsets
  set_code_viewer_lines_radix(hexview, 16);
  set_code_viewer_lines_alignment(hexview, size() > 0xFFFFFFFF ? 16 : 8);
  // also set the ui event callback
  hook_event_listener(HT_UI, this);
  // finally display the form on the screen
  display_widget(hexview, WOPN_DP_TAB|WOPN_RESTORE);
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new hex_data_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Sample hexview",     // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
