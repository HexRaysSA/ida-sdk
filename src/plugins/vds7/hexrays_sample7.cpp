/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for the Hex-Rays Decompiler.
 *      It demonstrates how to use cblock_t::iterator
 *
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  bool inited = true;

  plugin_ctx_t()
  {
    install_hexrays_callback(hr_callback, nullptr);
  }
  ~plugin_ctx_t()
  {
    if ( inited )
    {
      remove_hexrays_callback(hr_callback, nullptr);
      term_hexrays_plugin();
    }
  }
  virtual bool idaapi run(size_t) override { return false; }
  static ssize_t idaapi hr_callback(
        void *ud,
        hexrays_event_t event,
        va_list va);
};


//--------------------------------------------------------------------------
// This callback handles various hexrays events.
ssize_t idaapi plugin_ctx_t::hr_callback(
        void *,
        hexrays_event_t event,
        va_list va)
{
  switch ( event )
  {
    case hxe_maturity:
      {
        cfunc_t *func = va_arg(va, cfunc_t *);
        ctree_maturity_t mat = va_argi(va, ctree_maturity_t);
        if ( mat == CMAT_BUILT )
        {
          struct ida_local cblock_visitor_t : public ctree_visitor_t
          {
            cblock_visitor_t(void) : ctree_visitor_t(CV_FAST) {}
            int idaapi visit_insn(cinsn_t *ins) override
            {
              if ( ins->op == cit_block )
                dump_block(ins->ea, ins->cblock);
              return 0;
            }
            void dump_block(ea_t ea, cblock_t *b)
            {
              // iterate over all block instructions
              msg("dumping block %a\n", ea);
              for ( cblock_t::iterator p=b->begin(); p != b->end(); ++p )
              {
                cinsn_t &i = *p;
                msg("  %a: insn %s\n", i.ea, get_ctype_name(i.op));
              }
            }
          };
          cblock_visitor_t cbv;
          cbv.apply_to(&func->body, nullptr);
        }
      }
      break;
    default:
      break;
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
static char comment[] = "Sample plugin7 for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE           // Plugin should not appear in the Edit, Plugins menu
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Hex-Rays block iterator", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
