/*
 *  This is a sample plugin demonstrating receiving output window notification callbacks
 *  and using of new output window functions: get_output_curline, get_output_cursor,
 *  get_output_selected_text, add_output_popup
 *
 */

#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//-------------------------------------------------------------------------
struct ht_output_plugin_t : public plugmod_t, public event_listener_t
{
  form_actions_t *fa = nullptr;
  qstring selected_data;

  virtual bool idaapi run(size_t arg) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  void desc_notification(
        const char *notification_name) const;
  ~ht_output_plugin_t();
};

//-------------------------------------------------------------------------
AS_PRINTF(2, 3) static void form_msg(form_actions_t *fa, const char *format, ...)
{
  textctrl_info_t ti;
  fa->get_text_value(1, &ti);
  va_list va;
  va_start(va, format);
  ti.text.cat_vsprnt(format, va);
  va_end(va);
  fa->set_text_value(1, &ti);
}

//---------------------------------------------------------------------------
void ht_output_plugin_t::desc_notification(
        const char *notification_name) const
{
  form_msg(fa, "Received notification from output window: \"%s\"\n",
           notification_name);
}

//-------------------------------------------------------------------------
struct printsel_ah_t : public action_handler_t
{
  ht_output_plugin_t *plugmod;

  printsel_ah_t(ht_output_plugin_t *_plgmod) : plugmod(_plgmod) {}

  virtual int idaapi activate(action_activation_ctx_t *) override
  {
    form_msg(plugmod->fa,
             "User menu item is called for selection: \"%s\"\n",
             plugmod->selected_data.c_str());
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

//---------------------------------------------------------------------------
// Callback for ui notifications
static ssize_t idaapi ui_callback(void *ud, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    // called when IDA is preparing a context menu for a view
    // Here dynamic context-depending user menu items can be added.
    case ui_populating_widget_popup:
      {
        TWidget *f = va_arg(va, TWidget *);
        if ( get_widget_type(f) == BWN_OUTPUT )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          ht_output_plugin_t *plgmod = (ht_output_plugin_t *) ud;
          plgmod->selected_data.qclear();
          if ( get_output_selected_text(&plgmod->selected_data) )
          {
            action_desc_t desc = DYNACTION_DESC_LITERAL(
                    "Print selection",
                    new printsel_ah_t(plgmod),
                    nullptr, nullptr, -1);
            attach_dynamic_action_to_popup(nullptr, p, desc);
          }
          plgmod->desc_notification("msg_popup");
        }
      }
      break;
  }
  return 0;
}

//---------------------------------------------------------------------------
ht_output_plugin_t::~ht_output_plugin_t()
{
  unhook_from_notification_point(HT_UI, ui_callback, this);
}

//---------------------------------------------------------------------------
// Callback for view notifications
ssize_t idaapi ht_output_plugin_t::on_event(
        ssize_t notification_code,
        va_list va)
{
  switch ( notification_code )
  {
    case msg_activated:
      desc_notification("msg_activated");
      break;
    case msg_deactivated:
      desc_notification("msg_deactivated");
      break;
    case msg_keydown:
      {
        desc_notification("msg_keydown");
        int key = va_arg(va, int);
        int state = va_arg(va, int);
        form_msg(fa, "Parameters: Key:%d(\'%c\') State:%d\n", key, key, state);
      }
      break;
    case msg_click:
    case msg_dblclick:
      {
        desc_notification(notification_code == msg_click ? "msg_click" : "msg_dblclick");
        int px = va_arg(va, int);
        int py = va_arg(va, int);
        int state = va_arg(va, int);
        qstring buf;
        if ( get_output_curline(&buf, false) )
          form_msg(fa, "Clicked string: %s\n", buf.c_str());
        int cx,cy;
        get_output_cursor(&cx, &cy);
        msg("Parameters: x:%d, y:%d, state:%d\n", px, py, state);
        msg("Cursor position:(%d, %d)\n", cx, cy);
      }
      break;
    case msg_closed:
      desc_notification("msg_closed");
  }
  return 0;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new ht_output_plugin_t;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our editor form
static int idaapi editor_modcb(int fid, form_actions_t &f_actions)
{
  ht_output_plugin_t *plgmod = (ht_output_plugin_t *) f_actions.get_ud();
  if ( fid == CB_INIT ) // Initialization
  {
    /* set callback for output window notifications */
    hook_to_notification_point(HT_UI, ui_callback, plgmod);
    hook_event_listener(HT_OUTPUT, plgmod, plgmod);
    plgmod->fa = &f_actions;
  }
  else if ( fid == CB_CLOSE )
  {
    unhook_event_listener(HT_OUTPUT, plgmod);
    unhook_from_notification_point(HT_UI, ui_callback, plgmod);
  }
  return 1;
}

//--------------------------------------------------------------------------
bool idaapi ht_output_plugin_t::run(size_t)
{
  static const char formdef[] =
    "BUTTON NO NONE\n"        // we do not want the standard buttons on the form
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Editor form\n"           // the form title. it is also used to refer to the form later
    "\n"
    "%/%*"                    // placeholder for the 'editor_modcb' callback, and its userdata
    "<Text:t1::40:::>\n"      // text edit control
    "\n";

  // structure for text edit control
  textctrl_info_t ti;
  ti.cb = sizeof(textctrl_info_t);
  ti.text = "";

  open_form(formdef, 0, editor_modcb, this, &ti);
  return true;
}

static const char wanted_name[] = "HT_OUTPUT notifications handling example";
static const char wanted_hotkey[] = "Ctrl-Alt-F11";
//--------------------------------------------------------------------------
static const char comment[] = "HT_OUTPUT notifications handling";
static const char help[] =
        "This pluging demonstrates handling of output window\n"
        "notifications: Activation/Desactivation, adding\n"
        "popup menus, keyboard and mouse events, changing of current\n"
        "cursor position and closing of view\n";

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
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
