// Debugger IDC Helper
// Executes IDC script when the process is launched
// In fact, this approach can be used to hook IDC scripts to various debugger
// events.

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include <mergemod.hpp>
int data_id;

//--------------------------------------------------------------------------
// The plugin stores the IDC file name in the database
// It will create a node for this purpose
static const char node_name[] = "$ debugger idc file";


//--------------------------------------------------------------------------
struct plugin_ctx_t;

DECLARE_LISTENER(dbg_listener_t, plugin_ctx_t, ctx);
DECLARE_LISTENER(idp_listener_t, plugin_ctx_t, ctx);

struct plugin_ctx_t : public plugmod_t
{
  dbg_listener_t dbg_listener = dbg_listener_t(*this);
  idp_listener_t idp_listener = idp_listener_t(*this);
  plugin_ctx_t()
  {
    hook_event_listener(HT_DBG, &dbg_listener);
    hook_event_listener(HT_IDP, &idp_listener);
    set_module_data(&data_id, this);
  }
  ~plugin_ctx_t()
  {
    clr_module_data(data_id);
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
// Get the IDC file name from the database
static bool get_idc_name(char *buf, size_t bufsize)
{
  // access the node
  netnode mynode(node_name);
  // retrieve the value
  return mynode.valstr(buf, bufsize) > 0;
}

//--------------------------------------------------------------------------
// Store the IDC file name in the database
static void set_idc_name(const char *idc)
{
  // access the node
  netnode mynode;
  // if it doesn't exist yet, create it
  // otherwise get its id
  mynode.create(node_name);
  // store the value
  mynode.set(idc, strlen(idc)+1);
}

//--------------------------------------------------------------------------
ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi dbg_listener_t::on_event(ssize_t code, va_list /*va*/)
{
  switch ( code )
  {
    case dbg_process_start:
    case dbg_process_attach:
      // it is time to run the script
      char idc[QMAXPATH];
      if ( get_idc_name(idc, sizeof(idc)) )
      {
        qstring errbuf;
        if ( !exec_idc_script(nullptr, idc, "main", nullptr, 0, &errbuf) )
          warning("%s", errbuf.c_str());
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  // retrieve the old IDC name from the database
  char idc[QMAXPATH];
  if ( !get_idc_name(idc, sizeof(idc)) )
    qstrncpy(idc, "*.idc", sizeof(idc));

  char *newidc = ask_file(false, idc, "Specify the script to run upon debugger launch");
  if ( newidc != nullptr )
  {
    // store it back in the database
    set_idc_name(newidc);
    msg("Script %s will be run when the debugger is launched\n", newidc);
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // Our plugin works only for x86 PE executables
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 || inf_get_filetype() != f_PE )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Specify Debugger IDC Script";
static const char wanted_hotkey[] = "";

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
  wanted_name,          // long comment about the plugin
  wanted_name,          // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
