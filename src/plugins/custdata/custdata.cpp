/* Custom data type sample plugin.
 * Copyright (c) 2010-2024 Hex-Rays, support@hex-rays.com
 * Feel free to do whatever you want with this code.
 *
 * This sample plugin demonstates how to install a custom data type
 * and a custom data format in IDA v5.7
 *
 * Custom data types can be used to create your own data types.
 * A custom data type basically defines the data size. It can be fixed
 * or variable. This plugin defines a variable size data type: a pascal
 * string. Pascal strings start with a count byte:
 *      db len, '....'
 *
 * Custom data formats are used to render data values on the screen.
 * Multiple data formats can be registered for a custom data type.
 * The data formats with non-nullptr menu_names will be listed in the 'Operand type'
 * menu and the user will be able to select them.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

struct plugin_ctx_t : public plugmod_t
{
  int psid = 0;            // id of the 'pascal string' data type
  int psfid = 0;           // id of the 'pascal string' data format

  plugin_ctx_t();
  ~plugin_ctx_t();
  virtual bool idaapi run(size_t) override { return false; }
};

//---------------------------------------------------------------------------
// We define a variable size data type. For fixed size types this function
// must be omitted.
static asize_t idaapi calc_pascal_string_length(void *, ea_t ea, asize_t maxsize)
{
  qstring memname;
  if ( get_tid_name(&memname, ea) && get_udm_by_fullname(nullptr, memname.c_str()) )
  { // Custom data types may be used in structure definitions. If this case
    // ea is a member id. Check for this situation and return 1
    return 1;
  }
  ushort n = get_byte(ea);
  if ( n+1 > maxsize )
    return 0; // string would be too big
  return n+1; // ok, we accept any pascal string
}

//---------------------------------------------------------------------------
// Definition of the data type
static const data_type_t pascal_string_type =
{
  sizeof(data_type_t),          // size of this structure
  nullptr,                         // user defined data
  0,                            // properties
  "pascal_string",              // internal name of the data type
                                // must be unique for the current database
  "Pascal string",              // Menu name. If nullptr, the type won't be visible in the Edit menu.
  nullptr,                         // Hotkey
  "pstr",                       // Keyword to use in the assembly listing
  2,                            // value size. For varsize types, specify the
                                // minimal size of the value
  nullptr,                         // may_create_at? nullptr means the type can be created anywhere
  calc_pascal_string_length,    // for varsize types: calculate the exact size of an item
};

//---------------------------------------------------------------------------
// Print contents of a pascal string
static bool idaapi print_pascal_string(
        void *,                         // user defined data, not used here
        qstring *out,                   // output buffer. may be nullptr
        const void *value,              // value to print. may not be nullptr
        asize_t size,                   // value size in bytes
        ea_t,                           // current ea
        int,                            // operand number
        int)                            // data type id
{
  const char *vptr = (const char *)value;
  int n = *vptr++;
  if ( n+1 > size )
    return false;

  if ( out != nullptr )
  {
    *out = "\"";
    for ( int i=0; i < n; i++ )
    {
      if ( qisprint(*vptr) )
        out->append(*vptr++);
      else
        out->cat_sprnt("\\x%02X", uchar(*vptr++));
    }
    out->append('"');
  }
  return true;
}

//---------------------------------------------------------------------------
// Definition of the data format
static const data_format_t pascal_string_format =
{
  sizeof(data_format_t),        // size of this structure
  nullptr,                         // user defined data
  0,                            // properties
  "pascal_string",              // internal name of the data format
  nullptr,                         // Menu name of the format. nullptr means 'do not create menu item'
  nullptr,                         // Hotkey
  0,                            // value size. 0 means that this format accepts any value size
  0,                            // Text width of the value. Unknown, specify 0
  print_pascal_string,          // callback to render colored text for the data
  nullptr,                         // scan
  nullptr,                         // analyze
};


//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
{
  // Register custom data type
  psid = register_custom_data_type(&pascal_string_type);
  // Register custom data format for it
  psfid = register_custom_data_format(&pascal_string_format);
  attach_custom_data_format(psid, psfid);
}

//--------------------------------------------------------------------------
plugin_ctx_t::~plugin_ctx_t()
{
  // unregister data type
  if ( psid > 0 )
  {
    // IDA would detach the data format automatically.
    unregister_custom_data_type(psid);
  }
  // unregister data format
  if ( psfid > 0 )
    unregister_custom_data_format(psfid);
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // plugin flags
                        // we want the plugin to load as soon as possible
                        // immediately after the processor module
  |PLUGIN_HIDE          // we want to hide the plugin because it there will
                        // be a menu item in the Edit submenu
  |PLUGIN_MULTI,        // this plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "",                   // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  "",                   // multiline help about the plugin

  "Sample custdata",    // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
