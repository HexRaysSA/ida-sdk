/*
 *  This plugin demonstrates how to customize navigation band colors.
 *  Launch the plugin like so:
 *    - to install: ida_loader.load_and_run_plugin("navcolor", 1)
 *    - to uninstall: ida_loader.load_and_run_plugin("navcolor", 0)
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>


//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  nav_colorizer_t *old_col_fun = nullptr;
  void *old_col_ud = nullptr;
  bool installed = false;

  //lint -esym(1540, plugin_ctx_t::old_col_fun, plugin_ctx_t::old_col_ud)
  ~plugin_ctx_t()
  {
    // uninstall our callback for navigation band, otherwise ida will crash
    maybe_uninstall();
  }
  virtual bool idaapi run(size_t) override;

  bool maybe_install();
  bool maybe_uninstall();
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t code)
{
  return code == 1 ? maybe_install() : maybe_uninstall();
}

//--------------------------------------------------------------------------
// Callback that calculates the pixel color given the address and the number of bytes
static uint32 idaapi my_colorizer(ea_t ea, asize_t nbytes, void *ud)
{
  plugin_ctx_t &ctx = *(plugin_ctx_t *)ud;
  // you are at your own here. just for the sake of illustrating how things work
  // we will invert all colors
  uint32 color = ctx.old_col_fun(ea, nbytes, ctx.old_col_ud);
  return ~color;
}

//-------------------------------------------------------------------------
bool plugin_ctx_t::maybe_install()
{
  bool ok = !installed;
  if ( ok )
  {
    set_nav_colorizer(&old_col_fun, &old_col_ud, my_colorizer, this);
    installed = true;
  }
  return ok;
}

//-------------------------------------------------------------------------
bool plugin_ctx_t::maybe_uninstall()
{
  bool ok = installed;
  if ( ok )
  {
    set_nav_colorizer(nullptr, nullptr, old_col_fun, old_col_ud);
    installed = false;
  }
  return ok;
}

//--------------------------------------------------------------------------
// initialize the plugin
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

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
  "Modify navigation band colors",// the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
