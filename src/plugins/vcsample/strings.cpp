/*
 *  This is a sample plugin module
 *
 *  It can be compiled by any of the supported compilers:
 *
 *      - Visual C++
 *      - GCC
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//#define INSTALL_SAMPLE_CALLBACK
//#define HAS_USER_DEFINED_PREFIX

//--------------------------------------------------------------------------
//lint -e754 struct member not referenced
struct plugin_data_t : public plugmod_t, public event_listener_t
{
  ea_t old_ea = BADADDR;
  int old_lnnum = -1;
  virtual ssize_t idaapi on_event(ssize_t event_id, va_list) override;
  virtual bool idaapi run(size_t arg) override;

  idaapi ~plugin_data_t();
};

//--------------------------------------------------------------------------
// Example of a user-defined IDC function in C++

//#define DEFINE_IDC_FUNC
#ifdef DEFINE_IDC_FUNC
static error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
{
  msg("myfunc is called with arg0=%x and arg1=%s\n", argv[0].num, argv[1].c_str());
  res->num = 5;     // let's return 5
  return eOk;
}
static const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
static const ext_idcfunc_t myfunc5_desc =
{
  { "MyFunc5", myfunc5, myfunc5_args, nullptr, 0, 0 }
};
#endif // DEFINE_IDC_FUNC

//--------------------------------------------------------------------------
// This callback is called for UI notification events
ssize_t idaapi plugin_data_t::on_event(ssize_t event_id, va_list)
{
  if ( event_id != ui_msg     // avoid recursion
    && event_id != ui_refreshmarked ) // ignore uninteresting events
  {
    msg("ui_callback %" FMT_ZS "\n", event_id);
  }
  return 0; // 0 means "continue processing the event"
            // otherwise the event is considered as processed
}

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
#ifdef HAS_USER_DEFINED_PREFIX
static const int prefix_width = 8;

struct sample_prefix_t : public user_defined_prefix_t
{
  plugin_data_t *pd;
  sample_prefix_t(plugin_data_t *d) :
    user_defined_prefix_t(prefix_width, d), pd(d) {}
  virtual void idaapi get_user_defined_prefix(
        qstring *out,
        ea_t ea,
        const insn_t & /*insn*/,
        int lnnum,
        int indent,
        const char *line) override
  {
    out->qclear();        // empty prefix by default

    // We want to display the prefix only the lines which
    // contain the instruction itself

    if ( indent != -1 )           // a directive
      return;

    if ( line[0] == '\0' )        // empty line
      return;

    if ( tag_advance(line,1)[-1] == ash.cmnt[0] ) // comment line...
      return;

    // We don't want the prefix to be printed again for other lines of the
    // same instruction/data. For that we remember the line number
    // and compare it before generating the prefix

    if ( pd->old_ea == ea && pd->old_lnnum == lnnum )
      return;

    // Ok, seems that we found an instruction line.

    // Let's display the size of the current item as the user-defined prefix
    asize_t our_size = get_item_size(ea);

    // We don't bother about the width of the prefix
    // because it will be padded with spaces by the kernel

    out->sprnt(" %" FMT_64 "d", our_size);

    // Remember the address and line number we produced the line prefix for:
    pd->old_ea = ea;
    pd->old_lnnum = lnnum;
  }
};
#endif // HAS_USER_DEFINED_PREFIX

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( inf_get_filetype() == f_ELF )
    return nullptr; // we do not want to work with this idb

  plugin_data_t *pd = new plugin_data_t;

  // notifications
#ifdef INSTALL_SAMPLE_CALLBACK
  hook_event_listener(HT_UI, pd, pd);
#endif // INSTALL_SAMPLE_CALLBACK

  // user-defined prefix. will be automatically uninstalled by the kernel
  // when our plugin gets unloaded.
#ifdef HAS_USER_DEFINED_PREFIX
  new sample_prefix_t(pd);
#endif // HAS_USER_DEFINED_PREFIX

  // custom IDC function
#ifdef DEFINE_IDC_FUNC
  add_idc_func(myfunc5_desc);
#endif // DEFINE_IDC_FUNC

  // an example how to retrieve plugin options
  const char *options = get_plugin_options("vcsample");
  if ( options != nullptr )
    warning("command line options: %s", options);

  return pd;
}

//--------------------------------------------------------------------------
plugin_data_t::~plugin_data_t()
{
#ifdef DEFINE_IDC_FUNC
  del_idc_func(myfunc5_desc.name);
#endif
}

//--------------------------------------------------------------------------
bool idaapi plugin_data_t::run(size_t arg)
{
  warning("vcsample plugin has been called with arg %" FMT_Z, arg);
  // msg("just fyi: the current screen address is: %a\n", get_screen_ea());
  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "This is a sample plugin. It does nothing useful";

static const char help[] =
  "A sample plugin module\n"
  "\n"
  "This module shows you how to create plugin modules.\n"
  "\n"
  "It does nothing useful - just prints a message that is was called\n"
  "and shows the current address.\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

static const char wanted_name[] = "Sample plugin";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

static const char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // plugin flags
  init,                 // initialize

  nullptr,              // terminate. this pointer may be nullptr.

  nullptr,              // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
