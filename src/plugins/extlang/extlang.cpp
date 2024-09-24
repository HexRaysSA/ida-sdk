/*
        This is a sample plugin. It illustrates

          how to register a thid party language interpreter

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static bool idaapi compile_expr(// Compile an expression
        const char *name,       // in: name of the function which will
                                //     hold the compiled expression
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to compile
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(name);
  qnotused(current_ea);
  qnotused(expr);
  // our toy interpreter doesn't support separate compilation/evaluation
  // some entry fields in ida won't be useable (bpt conditions, for example)
  if ( errbuf != nullptr )
    *errbuf = "compilation error";
  return false;
}

//--------------------------------------------------------------------------
static bool idaapi call_func(   // Evaluate a previously compiled expression
        idc_value_t *result,    // out: function result
        const char *name,       // in: function to call
        const idc_value_t args[], // in: input arguments
        size_t nargs,           // in: number of input arguments
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(name);
  qnotused(nargs);
  qnotused(args);
  qnotused(result);
  if ( errbuf != nullptr )
    *errbuf = "evaluation error";
  return false;
}

//--------------------------------------------------------------------------
bool idaapi eval_expr(          // Compile and evaluate expression
        idc_value_t *rv,        // out: expression value
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to evaluation
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(current_ea);
  // we know to parse and decimal and hexadecimal numbers
  int radix = 10;
  const char *ptr = skip_spaces(expr);
  bool neg = false;
  if ( *ptr == '-' )
  {
    neg = true;
    ptr = skip_spaces(ptr+1);
  }
  if ( *ptr == '0' && *(ptr+1) == 'x' )
  {
    radix = 16;
    ptr += 2;
  }
  sval_t value = 0;
  while ( radix == 10 ? qisdigit(*ptr) : qisxdigit(*ptr) )
  {
    int d = *ptr <= '9' ? *ptr-'0' : qtolower(*ptr)-'a'+10;
    value *= radix;
    value += d;
    ptr++;
  }
  if ( neg )
    value = -value;
  ptr = skip_spaces(ptr);
  if ( *ptr != '\0' )
  {
    msg("EVAL FAILED: %s\n", expr);
    if ( errbuf != nullptr )
      *errbuf = "syntax error";
    return false;
  }

  // we have the result, store it in the return value
  if ( rv != nullptr )
  {
    rv->clear();
    rv->num = value;
  }
  msg("EVAL %" FMT_EA "d: %s\n", value, expr);
  return true;
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  extlang_t my_extlang =
  {
    sizeof(extlang_t),            // Size of this structure
    0,                            // Language features, currently 0
    0,                            // refcnt
    "extlang sample",             // Language name
    nullptr,                      // fileext
    nullptr,                      // syntax highlighter
    compile_expr,
    nullptr,                      // compile_file
    call_func,
    eval_expr,
    nullptr,                      // create_object
    nullptr,                      // get_attr
    nullptr,                      // set_attr
    nullptr,                      // call_method
    nullptr,                      // eval_snippet
    nullptr,                      // load_procmod
    nullptr,                      // unload_procmod
  };
  bool installed = false;

  plugin_ctx_t()
  {
    installed = install_extlang(&my_extlang) >= 0;
  }
  ~plugin_ctx_t()
  {
    if ( installed )
      remove_extlang(&my_extlang);
  }

  virtual bool idaapi run(size_t) override { return false; }
};

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  plugin_ctx_t *ctx = new plugin_ctx_t;
  if ( !ctx->installed )
  {
    msg("extlang: install_extlang() failed\n");
    delete ctx;
    ctx = nullptr;
  }
  return ctx;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE           // Plugin should not appear in the Edit, Plugins menu
  | PLUGIN_FIX          // Load plugin when IDA starts and keep it in the
                        // memory until IDA stops
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Sample third party language", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
