/*
        This is a sample plugin.

        It illustrates how the analysis can be improved

        The plugin checks branch targets for newly created instructions.
        If the target does not exist in the program, the plugin
        forbids the instruction creation.

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  plugin_ctx_t()
  {
    hook_event_listener(HT_IDB, this);
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
// This callback is called by the kernel when database related events happen
ssize_t idaapi plugin_ctx_t::on_event(ssize_t event_id, va_list va)
{
  switch ( event_id )
  {
    case idb_event::make_code:  // An instruction is being created
                                // args: insn_t *
                                // returns: 1-ok, <=0-the kernel should stop
      insn_t *insn = va_arg(va, insn_t *);
      // we are interested in the branch instructions
      if ( insn->itype >= NN_ja && insn->itype <= NN_jmpshort )
      {
        // the first operand contains the jump target
        ea_t target = to_ea(insn->cs, insn->Op1.addr);
        if ( !is_mapped(target) )
          return -1;
      }
  }
  return 0; // event not processed
            // let other plugins handle it
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  // since the plugin is fully automatic, there is nothing to do
  warning("Branch checker is fully automatic");
  return true;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE           // Plugin should not appear in the Edit, Plugins menu
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Branch checker",     // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
