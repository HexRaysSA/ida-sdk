/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows how to add dynamic comments to the pseudocode.
 *      Such comments are just displayed on the screen but they are not
 *      stored in the database and not editable by the user.
 *
 *      Please note that this is a very simple plugin. If you want to modify
 *      the output in a more profound way, please ensure that the color
 *      tags are preserved correctly.
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
static ssize_t idaapi callback(void *, hexrays_event_t event, va_list va)
{
  switch ( event )
  {
    case hxe_func_printed:
      {
        cfunc_t *cfunc = va_arg(va, cfunc_t*);
        int ln = 0;
        for ( auto &str : cfunc->sv )
        { // append a dummy comment to each line.
          str.line.cat_sprnt("  " COLSTR("// my comment %d", SCOLOR_NUMBER), ++ln);
        }
      }
      break;

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
struct vds20_t : public plugmod_t
{
  vds20_t();
  virtual ~vds20_t();
  virtual bool idaapi run(size_t) override;
};

//-------------------------------------------------------------------------
vds20_t::vds20_t()
{
  install_hexrays_callback(callback, this);
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      get_hexrays_version(),
      PLUGIN.wanted_name);
}

//-------------------------------------------------------------------------
vds20_t::~vds20_t()
{
  remove_hexrays_callback(callback, this);
}

//--------------------------------------------------------------------------
bool idaapi vds20_t::run(size_t arg)
{
  if ( arg == 1 )
  {
    remove_hexrays_callback(callback, this);
    msg("%s disabled\n", PLUGIN.wanted_name);
  }
  else if ( arg == 2 )
  {
    install_hexrays_callback(callback, this);
    msg("%s enabled\n", PLUGIN.wanted_name);
  }
  else
  {
    msg("The %d arg is unknown (1 disable, 2 enable)\n", int(arg));
  }
  return false;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return init_hexrays_plugin() ? new vds20_t : nullptr;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample20 plugin for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,    // plugin flags
  init,                          // initialize
  nullptr,
  nullptr,
  comment,                       // long comment about the plugin
                                 // it could appear in the status line
                                 // or as a hint
  "",                            // multiline help about the plugin
  "Add dynamic comments", // the preferred short name of the plugin
  ""                             // the preferred hotkey to run the plugin
};
