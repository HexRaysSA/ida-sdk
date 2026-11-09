/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2024 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler usage of udc_filter_t
 *      class: decompile svc 0x900001 and svc 0x9000F8 as function calls to
 *      svc_exit() and svc_exit_group() respectively.
 *
 *      The command hotkey is Ctrl+Shift+U.
 *      It is also added into the right-click menu as "Toggle UDC"
 *
 */

#include <hexrays.hpp>
#include <allins.hpp>

#define ACTION_NAME "sample8:udcall"
// Shortcut for the new command
#define ACTION_SHORTCUT "Ctrl+Shift+U"

#define SVC_EXIT       0x900001
#define SVC_EXIT_GROUP 0x9000F8

//--------------------------------------------------------------------------
static ssize_t idaapi callback(void *, hexrays_event_t event, va_list va)
{
  switch ( event )
  {
    case hxe_open_pseudocode:
      {
        vdui_t &vu = *va_arg(va, vdui_t *);
        // Permanently attach that action to that view's context menu.
        attach_action_to_popup(vu.ct, nullptr, ACTION_NAME);
      }
      break;

    default:
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
class udc_exit_t : public udc_filter_t
{
  int code;
  bool installed;

public:
  udc_exit_t() : code(0), installed(false) {}
  bool prepare(int svc_code, const char *name)
  {
    char decl[MAXSTR];
    qsnprintf(decl, sizeof(decl), "int __usercall %s@<R0>(int status@<R1>);", name);
    bool ok = init(decl);
    if ( !ok )
      msg("Could not initialize UDC plugin '%s'\n", name);
    code = svc_code;
    return ok;
  }
  void install()
  {
    install_microcode_filter(this, true);
    installed = true;
  }
  void uninstall()
  {
    install_microcode_filter(this, false);
    installed = false;
  }
  void toggle_install()
  {
    if ( installed )
      uninstall();
    else
      install();
  }
  virtual bool match(codegen_t &cdg) override
  {
    return cdg.insn.itype == ARM_svc && cdg.insn.Op1.value == code;
  }
  virtual ~udc_exit_t() {} // shut up a compiler warning
};

//--------------------------------------------------------------------------
// menu action handler: installs/uninstalls UDC filter and rebuilds pseudocode
struct vds8_t;
struct toggle_udc_ah_t : public action_handler_t
{
  vds8_t *plugmod;

  toggle_udc_ah_t(vds8_t *_plugmod) : plugmod(_plugmod) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;
};

//-------------------------------------------------------------------------
//                                 vds8_t
//-------------------------------------------------------------------------
struct vds8_t : public plugmod_t
{
  udc_exit_t udc_exit;
  udc_exit_t udc_exit_group;
  toggle_udc_ah_t toggle_udc_ah;

  vds8_t();
  virtual ~vds8_t();
  virtual bool idaapi run(size_t) override { return false; }

  bool init_udc_exit();
};

//-------------------------------------------------------------------------
vds8_t::vds8_t()
  : toggle_udc_ah(this)
{
  install_hexrays_callback(callback, this);
  register_action(ACTION_DESC_LITERAL_PLUGMOD(
                          ACTION_NAME,
                          "Toggle UDC",
                          &toggle_udc_ah,
                          this,
                          ACTION_SHORTCUT,
                          nullptr,
                          -1));
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      get_hexrays_version(),
      PLUGIN.wanted_name);
}

//-------------------------------------------------------------------------
vds8_t::~vds8_t()
{
  udc_exit.uninstall();
  udc_exit_group.uninstall();
  remove_hexrays_callback(callback, this);
}

//-------------------------------------------------------------------------
bool vds8_t::init_udc_exit()
{
  return udc_exit.prepare(SVC_EXIT, "svc_exit")
      && udc_exit_group.prepare(SVC_EXIT_GROUP, "svc_exit_group");
}

//-------------------------------------------------------------------------
//                            toggle_udc_ah_t
//-------------------------------------------------------------------------
int idaapi toggle_udc_ah_t::activate(
        action_activation_ctx_t *ctx)
{
  plugmod->udc_exit.toggle_install();
  plugmod->udc_exit_group.toggle_install();
  vdui_t *vu = get_widget_vdui(ctx->widget);
  vu->refresh_view(true);
  return 1;
}

//-------------------------------------------------------------------------
action_state_t idaapi toggle_udc_ah_t::update(
        action_update_ctx_t *ctx)
{
  vdui_t *vu = get_widget_vdui(ctx->widget);
  return vu == nullptr ? AST_DISABLE_FOR_WIDGET : AST_ENABLE_FOR_WIDGET;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  vds8_t *vds8 = nullptr;
  if ( init_hexrays_plugin() )
  {
    processor_t &ph = PH;
    if ( ph.id == PLFM_ARM && !inf_is_64bit() )
    {
      vds8 = new vds8_t;
      if ( !vds8->init_udc_exit() )
      {
        delete vds8;
        vds8 = nullptr;
      }
    }
  }
  return vds8;
}

//--------------------------------------------------------------------------
static const char comment[] = "Convert SVC instructions to exit/exit_group function calls";

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
  "Hex-Rays user-defined calls", // the preferred short name of the plugin
  ""                             // the preferred hotkey to run the plugin
};
