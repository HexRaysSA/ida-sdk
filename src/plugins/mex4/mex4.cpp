/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      This file contains the common part of all merge examples.
 *      It includes a regular plugin functionality and boilerplate code.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <mergemod.hpp>         // merge functionality
#include "mex.hpp"

int data_id;    // A unique data id that is assigned by the kernel to the plugin.

//-------------------------------------------------------------------------
ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    // This event occurs when IDA is performing a 3-way merge (for IDA Teams)
    // Our plugins should create and register merge handler(s) for its data.
    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_merge_handlers(*md);
      }
      break;

    // A well behaving plugin should restore its state from the database
    // upon ev_ending_undo. Otherwise its state may be conflicting with the
    // database.
    case processor_t::ev_ending_undo:
      ctx.restore_from_idb();
      break;

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
// Regular plugin implementation below.
// For example, in our case the plugin asks for 2 bit values and a string value.
// Then the plugin stores this data in the database.
bool idaapi mex_ctx_t::run(size_t)
{
  static const char form[] =
    "Merge example " MEX_NUMBER "\n"
    "\n"
    "<Flag 0:C1>\n"
    "<Flag 1:C2>>\n"
    "<Ident prefix:q:10:10::>\n";

  CASSERT(sizeof(flags) == sizeof(ushort));
  CASSERT(IS_QSTRING(ident));
  if ( ask_form(form, &flags, &ident) == 1 )
    save_to_idb();

  return true;
}

//-------------------------------------------------------------------------
// Restore plugin variables from the idb.
void mex_ctx_t::restore_from_idb()
{
  netnode options(MEX_NODE_NAME);
  bytevec_t packed;
  if ( exist(options) && options.getblob(&packed, 0, MEX_BLOB_TAG) > 0 )
  {
    memory_deserializer_t d(packed);
    flags = d.unpack_dw();
    d.unpack_str(&ident);
  }
}

//-------------------------------------------------------------------------
// Save the plugin state to the idb.
void mex_ctx_t::save_to_idb() const
{
  netnode options;
  options.create(MEX_NODE_NAME);
  bytevec_t packed;
  packed.pack_dw(flags);
  packed.pack_str(ident);
  options.setblob(&packed[0], packed.size(), 0, MEX_BLOB_TAG);
}

//-------------------------------------------------------------------------
// Create a plugin context and return it to the kernel.
static plugmod_t *idaapi init()
{
  return new mex_ctx_t;
}

//-------------------------------------------------------------------------
mex_ctx_t::mex_ctx_t()
  : idp_listener(*this)
{
  // A plugin that supports merge must register a data_id for its data.
  set_module_data(&data_id, this);

  // Restore the plugin data from the database into the memory.
  restore_from_idb();
  // Hook an event listener, to catch the merge-related event(s).
  hook_event_listener(HT_IDP, &idp_listener);
}

//-------------------------------------------------------------------------
mex_ctx_t::~mex_ctx_t()
{
  clr_module_data(data_id);
  // Listeners are uninstalled automatically when the owner module is unloaded.
}

//-------------------------------------------------------------------------
static const char comment[] = "An example " MEX_NUMBER " how to implement IDA merge functionality";
static const char wanted_name[] = "Merge example " MEX_NUMBER;
static const char wanted_hotkey[] = "";

//-------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI          // Can work with multiple databases. A must for the plugins
                        // that support IDA Teams. Such plugins must keep all
                        // their data in the plugin context (global data variables
                        // cannot be used because they are not database dependent).
 |PLUGIN_MOD,           // Plugin may modify the database.
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
