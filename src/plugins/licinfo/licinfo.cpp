/*
        This is a sample plugin.

        It illustrates how to query the active license
        through the License class from license.hpp:
        it prints the license details and checks whether
        the HEXX64 add-on (the x64 decompiler) is usable.
*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <license.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  License lic;
  qstring id = lic.id();
  if ( id.empty() )
  {
    msg("No active license\n");
    return true;
  }

  msg("License %s: %s (%s)\n",
      id.c_str(), lic.product().c_str(), lic.edition().c_str());
  msg("%s\n", lic.description().c_str());
  msg("Usable: %s\n", lic.valid() ? "yes" : "no");

  int64 end = lic.end();
  if ( end == 0 )
  {
    msg("Activation period: no expiry\n");
  }
  else
  {
    char buf[64];
    qstrftime(buf, sizeof(buf), "%Y-%m-%d", time_t(end));
    msg("Activation period ends: %s\n", buf);
  }

  for ( const qstring &code : lic.add_ons() )
    msg("Usable add-on: %s\n", code.c_str());
  for ( const qstring &name : lic.features() )
    msg("Feature: %s\n", name.c_str());

  if ( lic.has_add_on("HEXX64") )
    msg("The HEXX64 add-on is usable\n");
  else
    msg("The HEXX64 add-on is not usable\n");

  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "License info",       // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
