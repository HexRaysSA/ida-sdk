/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It automatically replaces zeroes in pointer contexts with NULLs.
 *      For example, expression like
 *
 *              funcptr = 0;
 *
 *      will be displayed as
 *
 *              funcptr = nullptr;
 *
 *      Due to highly dynamic nature of the decompier output, we must
 *      use the decompiler events to accomplish the task. The plugin will
 *      wait for the ctree structure to be ready in the memory and will
 *      replace zeroes in pointer contexts with NULLs.
 *
 */

#include <hexrays.hpp>

static const char nodename[] = "$ hexrays NULLs";
static const char null_type[] = "MACRO_NULL";

//--------------------------------------------------------------------------
// Is the plugin enabled?
// The user can disable it. The plugin will save the on/off switch in the
// current database.
static bool is_enabled(void)
{
  netnode n(nodename); // use a netnode to save the state
  return n.altval(0) == 0; // if the long value is positive, then disabled
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  plugin_ctx_t()
  {
    bool enabled = is_enabled();
    enable_disable(enabled);
    msg("The %s plugin is %s.",
        PLUGIN.wanted_name,
        enabled ? "ENABLED" : "DISABLED");
  }
  ~plugin_ctx_t()
  {
    remove_hexrays_callback(hr_callback, nullptr);
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
  static ssize_t idaapi hr_callback(
        void *ud,
        hexrays_event_t event,
        va_list va);

  static void enable_disable(bool enable)
  {
    if ( enable )
      install_hexrays_callback(hr_callback, nullptr);
    else
      remove_hexrays_callback(hr_callback, nullptr);
  }
};

//--------------------------------------------------------------------------
// If the expression is zero, convert it to nullptr
static void make_null_if_zero(cexpr_t *e)
{
  if ( e->is_zero_const() && !e->type.is_ptr() )
  { // this is plain zero, convert it
    number_format_t &nf = e->n->nf;
    nf.flags = enum_flag();
    nf.serial = 0;
    nf.props |= NF_VALID;
    nf.type_name = null_type;
    e->type.get_named_type(nullptr, null_type, BTF_ENUM);
  }
}

//--------------------------------------------------------------------------
// Convert zeroes of the ctree to NULLs
static void convert_zeroes(cfunc_t *cfunc)
{
  // To represent NULLs, we will use the MACRO_NULL enumeration
  // Normally it is present in the loaded tils but let's verify it
  if ( !get_named_type(nullptr, null_type, NTF_TYPE) )
  {
    msg("%s type is missing, cannot convert zeroes to NULLs\n", null_type);
    return;
  }

  // We derive a helper class from ctree_visitor_t
  // The ctree_visitor_t is a base class to derive
  // ctree walker classes.
  // You have to redefine some virtual functions
  // to do the real job. Here we redefine visit_expr() since we want
  // to examine and modify expressions.
  struct ida_local zero_converter_t : public ctree_visitor_t
  {
    zero_converter_t(void) : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t *e) override
    {
      // verify if the current expression has pointer expressions
      // we handle the following patterns:
      //  A. ptr = 0;
      //  B. func(0); where argument is a pointer
      //  C. ptr op 0 where op is a comparison
      switch ( e->op )
      {
        case cot_asg:   // A
          if ( e->x->type.is_ptr() )
            make_null_if_zero(e->y);
          break;

        case cot_call:  // B
          {
            carglist_t &args = *e->a;
            for ( int i=0; i < args.size(); i++ ) // check all arguments
            {
              carg_t &a = args[i];
              if ( a.formal_type.is_ptr_or_array() )
                make_null_if_zero(&a);
            }
          }
          break;

        case cot_eq:    // C
        case cot_ne:
        case cot_sge:
        case cot_uge:
        case cot_sle:
        case cot_ule:
        case cot_sgt:
        case cot_ugt:
        case cot_slt:
        case cot_ult:
          // check both sides for zeroes
          if ( e->y->type.is_ptr() )
            make_null_if_zero(e->x);
          if ( e->x->type.is_ptr() )
            make_null_if_zero(e->y);
          break;

        default:
          break;

      }
      return 0; // continue walking the tree
    }
  };
  zero_converter_t zc;
  // walk the whole function body
  zc.apply_to(&cfunc->body, nullptr);
}

//--------------------------------------------------------------------------
// This callback will detect when the ctree is ready to be displayed
// and call convert_zeroes() to create NULLs
ssize_t idaapi plugin_ctx_t::hr_callback(
        void *,
        hexrays_event_t event,
        va_list va)
{
  if ( event == hxe_maturity )
  {
    cfunc_t *cfunc = va_arg(va, cfunc_t*);
    ctree_maturity_t mat = va_argi(va, ctree_maturity_t);
    if ( mat == CMAT_FINAL ) // ctree is ready, time to convert zeroes to NULLs
      convert_zeroes(cfunc);
  }
  return 0;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
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
bool idaapi plugin_ctx_t::run(size_t)
{
  // since all real work is done in the callbacks, use the main plugin entry
  // to turn it on and off.
  // display a message explaining the purpose of the plugin:
  static const char *const format =
    "AUTOHIDE NONE\n"
    "Sample plugin for Hex-Rays decompiler.\n"
    "\n"
    "This plugin is fully automatic.\n"
    "It detects zeroes in pointer contexts and converts them into NULLs.\n"
    "\n"
    "The current state of the plugin is: %s";
  int code = ask_buttons("~E~nable",
                         "~D~isable",
                         "~C~lose",
                         -1,
                         format,
                         is_enabled() ? "ENABLED" : "DISABLED");
  switch ( code )
  {
    case -1:    // close
      break;
    case 0:     // disable
    case 1:     // enable
      bool enable = code != 0;
      netnode n;
      n.create(nodename);
      n.altset(0, enable ? 0 : 1);
      enable_disable(enable);
      info("The %s plugin has been %s.",
           PLUGIN.wanted_name,
           enable ? "ENABLED" : "DISABLED");
      break;
  }
  return true;
}

//--------------------------------------------------------------------------
static char comment[] = "Sample2 plugin for Hex-Rays decompiler";

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
  "Hex-Rays NULL converter", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
