/*
 *  This is a sample plugin demonstrating usage of the view callbacks
 *  and adding custom menu items to popup menus
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <graph.hpp>

#define ACTION1_NAME "ht_view:Act1"
#define ACTION2_NAME "ht_view:Act2"

//-------------------------------------------------------------------------
struct ht_view_plugin_t : public plugmod_t, public event_listener_t
{
  bool hooked = false;

  ht_view_plugin_t();
  virtual ~ht_view_plugin_t();
  virtual bool idaapi run(size_t arg) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  void desc_notification(
        const char *notification_name,
        TWidget *view) const;
  void desc_mouse_event(
        const view_mouse_event_t *event) const;
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
        TWidget *view = va_arg(va, TWidget *);
        if ( get_widget_type(view) == BWN_DISASM )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          ht_view_plugin_t *plgmod = (ht_view_plugin_t *) ud;
          plgmod->desc_notification("view_popup", view);
          attach_action_to_popup(view, p, ACTION1_NAME);
          attach_action_to_popup(view, p, ACTION2_NAME);
        }
      }
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
struct ahandler_t : public action_handler_t
{
  bool first;
  ahandler_t(bool _first) : first(_first) {}
  virtual int idaapi activate(action_activation_ctx_t *) override
  {
    msg("User %s menu item is called\n", first ? "first" : "second");
    return true;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};
static ahandler_t ah1(true);
static ahandler_t ah2(false);

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new ht_view_plugin_t;
}

//-------------------------------------------------------------------------
ht_view_plugin_t::ht_view_plugin_t()
{
  // Register actions
  const action_desc_t actions[] =
  {
#define ROW(name, label, handler) ACTION_DESC_LITERAL_PLUGMOD(name, label, handler, this, nullptr, nullptr, -1)
    ROW(ACTION1_NAME, "First ht_view's popup menu item", &ah1),
    ROW(ACTION2_NAME, "Second ht_view's popup menu item", &ah2),
#undef ROW
  };

  for ( size_t i = 0, n = qnumber(actions); i < n; ++i )
    register_action(actions[i]);
}

//-------------------------------------------------------------------------
ht_view_plugin_t::~ht_view_plugin_t()
{
  unhook_from_notification_point(HT_UI, ui_callback, this);
}

//-------------------------------------------------------------------------
bool idaapi ht_view_plugin_t::run(size_t)
{
  /* set callback for view notifications */
  if ( !hooked )
  {
    hook_event_listener(HT_VIEW, this);
    hook_to_notification_point(HT_UI, ui_callback, this);
    hooked = true;
    msg("HT_VIEW: installed view notification hook.\n");
  }

  return true;
}

//---------------------------------------------------------------------------
ssize_t idaapi ht_view_plugin_t::on_event(
        ssize_t notification_code,
        va_list va)
{
  TWidget *view = va_arg(va, TWidget *);
  switch ( notification_code )
  {
    case view_activated:
      desc_notification("view_activated", view);
      break;
    case view_deactivated:
      desc_notification("view_deactivated", view);
      break;
    case view_keydown:
      {
        desc_notification("view_keydown", view);
        int key = va_arg(va, int);
        int state = va_arg(va, int);
        msg("Parameters: Key:%d(\'%c\') State:%d\n", key, key, state);
      }
      break;
    case view_click:
    case view_dblclick:
      {
        desc_notification(notification_code == view_click ? "view_click" : "view_dblclick", view);
        desc_mouse_event(va_arg(va, view_mouse_event_t*));
        int cx,cy;
        get_cursor(&cx, &cy);
        msg("Cursor position:(%d, %d)\n", cx, cy);
      }
      break;
    case view_curpos:
      {
        desc_notification("view_curpos", view);
        if ( is_idaview(view) )
        {
          char buf[MAXSTR];
          ea2str(buf, sizeof(buf), get_screen_ea());
          msg("New address: %s\n", buf);
        }
      }
      break;
    case view_mouse_over:
      {
        desc_notification("view_mouse_over", view);
        desc_mouse_event(va_arg(va, view_mouse_event_t*));
      }
      break;
    case view_close:
      desc_notification("view_close", view);
  }
  return 0;
}

//-------------------------------------------------------------------------
void ht_view_plugin_t::desc_notification(
        const char *notification_name,
        TWidget *view) const
{
  qstring buffer;
  get_widget_title(&buffer, view);
  msg("Received notification from view %s: \"%s\"\n",
      buffer.c_str(),
      notification_name);
}

//-------------------------------------------------------------------------
void ht_view_plugin_t::desc_mouse_event(
        const view_mouse_event_t *event) const
{
  int px = event->x;
  int py = event->y;
  int state = event->state;
  qstring over_txt;
  const selection_item_t *item = event->location.item;
  if ( event->rtype != TCCRT_FLAT && item != nullptr )
  {
    if ( item->is_node )
      over_txt.sprnt("node %d", item->node);
    else
      over_txt.sprnt("edge %d -> %d", item->elp.e.src, item->elp.e.dst);
  }
  else
  {
    over_txt = "(nothing)";
  }
  msg("Parameters: x:%d, y:%d, state:%d, over:%s\n", px, py, state, over_txt.c_str());
}


//-------------------------------------------------------------------------
static const char wanted_name[] = "HT_VIEW notification handling example";
static const char wanted_hotkey[] = "";
//--------------------------------------------------------------------------
static const char comment[] = "HT_VIEW notification Handling";
static const char help[] =
        "This pluging demonstrates handling of custom and IdaView\n"
        "notifications: Activation/Desactivation of views, adding\n"
        "popup menus, keyboard and mouse events, changing of current\n"
        "address and closing of view\n";

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
