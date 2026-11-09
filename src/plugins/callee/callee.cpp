/*
 *  Change the callee address for constructions like
 *
 *  call esi    ; LocalFree
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <segregs.hpp>
#define T 20

struct callee_vars_t : public plugmod_t
{
  virtual bool idaapi run(size_t arg) override;
};

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_386 && ph.id != PLFM_MIPS && ph.id != PLFM_ARM )
    return nullptr; // only for x86, MIPS and ARM
  return new callee_vars_t();
}

//--------------------------------------------------------------------------
static const char comment[] = "Change the callee address";
static const char help[] =
  "This plugin allows the user to change the address of the called function\n"
  "in constructs like\n"
  "\n"
  "       call esi\n"
  "\n"
  "You can enter a function name instead of its address\n";

//--------------------------------------------------------------------------
static const char *const form =
  "HELP\n"
  "%s\n"
  "ENDHELP\n"
  "Enter the callee address\n"
  "\n"
  "  <~C~allee:$::40:::>\n"
  "\n"
  "\n";

bool idaapi callee_vars_t::run(size_t)
{
  const char *nname;
  if ( ph.id == PLFM_MIPS )
    nname = "$ mips";
  else if ( ph.id == PLFM_ARM )
    nname = " $arm";
  else
    nname = "$ vmm functions";
  netnode n(nname);
  ea_t ea = get_screen_ea();    // get current address
  if ( !is_code(get_flags(ea)) )
    return false; // not an instruction
  // get the callee address from the database
  ea_t callee = node2ea(n.altval_ea(ea)-1);
  // remove thumb bit for arm
  if ( ph.id == PLFM_ARM )
    callee &= ~1;
  char buf[MAXSTR];
  qsnprintf(buf, sizeof(buf), form, help);
  if ( ask_form(buf, &callee) )
  {
    if ( callee == BADADDR )
    {
      n.altdel_ea(ea);
    }
    else
    {
      if ( ph.id == PLFM_ARM && (callee & 1) == 0 )
      {
        // if we're calling a thumb function, set bit 0
        sel_t tbit = get_sreg(callee, T);
        if ( tbit != 0 && tbit != BADSEL )
          callee |= 1;
      }
      // save the new address
      n.altset_ea(ea, ea2node(callee)+1);
    }
    gen_idb_event(idb_event::callee_addr_changed, ea, callee);
    plan_ea(ea);                 // reanalyze the current instruction
  }
  return true;
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Change the callee address";
static const char wanted_hotkey[] = "Alt-F11";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // plugin flags
  init,                 // initialize

  nullptr,              // terminate. this pointer may be nullptr.
  nullptr,              // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
