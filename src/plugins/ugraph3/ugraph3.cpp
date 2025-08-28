/*
 *  This is a sample plugin module.
 *  It demonstrates how to generate ida graphs for arbitrary ranges.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  ea_t ea1, ea2;
  if ( !read_range_selection(nullptr, &ea1, &ea2) )
  {
    warning("Please select a range before running the plugin");
    return true;
  }
  unmark_selection();

  // fixme: how to specify multiple ranges?

  rangevec_t ranges;
  ranges.push_back(range_t(ea1, ea2));
  open_disasm_window("Selected range", &ranges);
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // unload us if text mode, no graph are there
  if ( !is_idaq() )
    return nullptr;
  return new plugin_ctx_t;
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
  "Generate graph for selection",
  nullptr,              // the preferred hotkey to run the plugin
};
