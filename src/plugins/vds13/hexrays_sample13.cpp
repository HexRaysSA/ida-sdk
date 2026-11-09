/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It generates microcode for selection and dumps it to the output window.
 */

#include <hexrays.hpp>
#include <frame.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  ~plugin_ctx_t()
  {
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  ea_t ea1, ea2;
  if ( !read_range_selection(nullptr, &ea1, &ea2) )
  {
    warning("Please select a range of addresses to analyze");
    return true;
  }

  flags64_t F = get_flags(ea1);
  if ( !is_code(F) )
  {
    warning("The selected range must start with an instruction");
    return true;
  }

  // generate microcode
  hexrays_failure_t hf;
  mba_ranges_t mbr;
  mbr.ranges.push_back(range_t(ea1, ea2));
  mba_t *mba = gen_microcode(mbr, &hf, nullptr, DECOMP_WARNINGS);
  if ( mba == nullptr )
  {
    warning("%a: %s", hf.errea, hf.desc().c_str());
    return true;
  }

  msg("Successfully generated microcode for %a..%a\n", ea1, ea2);
  vd_printer_t vp;
  mba->print(vp);

  // We must explicitly delete the microcode array
  delete mba;
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr; // no decompiler
  const char *hxver = get_hexrays_version();
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      hxver, PLUGIN.wanted_name);
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample13 plugin for Hex-Rays decompiler";

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
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Dump microcode for selected range", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
