/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It installs a custom microcode optimization rule:
 *        call   !DbgRaiseAssertionFailure <fast:>.0
 *      =>
 *        call   !DbgRaiseAssertionFailure <fast:"char *" "assertion text">.0
 *
 *      To see this plugin in action please use arm64_brk.i64
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
struct nt_assert_optimizer_t : public optinsn_t
{
  virtual int idaapi func(mblock_t *, minsn_t *ins, int /*optflags*/) override
  {
    if ( handle_nt_assert(ins) )
      return 1;
    return 0;
  }
  //lint -e{818} ins could be made const
  bool handle_nt_assert(minsn_t *ins) const
  {
    // recognize call   !DbgRaiseAssertionFailure <fast:>.0
    if ( !ins->is_helper("DbgRaiseAssertionFailure") )
      return false;

    // did we already add an argument?
    mcallinfo_t &fi = *ins->d.f;
    if ( !fi.args.empty() )
      return false;

    // use a comment from the disassembly listing as the call argument
    qstring cmt;
    if ( !get_cmt(&cmt, ins->ea, false) )
      return false;

    // remove "NT_ASSERT(" to make the listing nicer
    if ( cmt.starts_with("NT_ASSERT(\"") )
      cmt.remove(0, 11);
    if ( cmt.ends_with("\")") )
      cmt.remove_last(2);

    // all ok, transform the instruction by adding one more call argument
    mcallarg_t &fa = fi.args.push_back();
    fa.t    = mop_str;
    fa.cstr = cmt.extract();
    fa.type = tinfo_t::get_stock(STI_PCCHAR); // const char *
    fa.size = fa.type.get_size();
    return true;
  }
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  nt_assert_optimizer_t nt_assert_optimizer;

  plugin_ctx_t()
  {
    install_optinsn_handler(&nt_assert_optimizer);
  }
  ~plugin_ctx_t()
  {
    remove_optinsn_handler(&nt_assert_optimizer);
    term_hexrays_plugin();
  }
  virtual bool idaapi run(size_t) override;
};

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
bool idaapi plugin_ctx_t::run(size_t arg)
{
  if ( arg == 1 )
  {
    remove_optinsn_handler(&nt_assert_optimizer);
    msg("%s disabled\n", PLUGIN.wanted_name);
  }
  else if ( arg == 2 )
  {
    install_optinsn_handler(&nt_assert_optimizer);
    msg("%s enabled\n", PLUGIN.wanted_name);
  }
  else
  {
    msg("The %d arg is unknown (1 disable, 2 enable)\n", int(arg));
  }
  return false;
}

//--------------------------------------------------------------------------
static const char comment[] = "Sample10 plugin for Hex-Rays decompiler";

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
  "Optimize DbgRaiseAssertionFailure", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
