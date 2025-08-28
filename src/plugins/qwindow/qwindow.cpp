/*
 *  This is a sample plugin module. It demonstrates how to create your
 *  own window and populate it with Qt widgets.
 *
 *  Note: we discourage using this plugin and using Qt widgets from C++.
 *        Such plugins will depends on the exact version of the Qt libraries
 *        and C++ compiler used to build them. Hex-Rays may change
 *        both Qt libraries and C++ compiler at any time used to build IDA,
 *        without an advance warning. Second, IDA uses a custom build of
 *        the Qt libraries, with a namespace.
 *        Please consider using PyQt to create Qt widgets, it is more robust
 *        and does not suffer from these problems.
 */

//lint -e4206 'nodiscard' attribute cannot be applied to types
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219) // implicit conversion from 'int' to 'float', possible loss of data
#pragma warning(disable:5240) // 'nodiscard': attribute is ignored in this syntactic position
#endif // __NT__
#include <QtWidgets>
#ifdef __NT__
#pragma warning(pop)
#endif // __NT__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include "myactions.h"

//--------------------------------------------------------------------------
//lint -e1762
void MyActions::clicked()
{
  info("Button is clicked");
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  TWidget *widget = nullptr;

  plugin_ctx_t()
  {
    hook_event_listener(HT_UI, this);
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
    widget = nullptr; // make lint happy
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  if ( code == ui_widget_visible )
  {
    TWidget *l_widget = va_arg(va, TWidget *);
    if ( l_widget == widget )
    {
      QWidget *w = (QWidget *) widget;
      MyActions *actions = new MyActions(w);

      // create a widget
      QPushButton *b = new QPushButton("Click here", w);

      // connect the button to a slot
      QObject::connect(b, SIGNAL(clicked()), actions, SLOT(clicked()));   //lint !e2666 expression with side effects

      // position and display it
      b->move(50, 50);
      b->show();
      msg("Qt widget is displayed\n");
      //lint -esym(429, actions, b) not freed
    }
  }
  else if ( code == ui_widget_invisible )
  {
    TWidget *l_widget = va_arg(va, TWidget *);
    if ( l_widget == widget )
    {
      // user defined widget is closed, destroy its controls
      // (to be implemented)
      msg("Qt widget is closed\n");
      widget = nullptr;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *g_widget = find_widget("Sample Qt subwindow");
  if ( g_widget == nullptr )
  {
    widget = create_empty_widget("Sample Qt subwindow");
    display_widget(widget, WOPN_DP_TAB|WOPN_RESTORE);
  }
  else
  {
    close_widget(g_widget, WCLS_SAVE);
    widget = nullptr; // make lint happy
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( !is_idaq() )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char comment[] = "This is a sample Qt plugin.";
static const char help[] =
  "A sample plugin module\n"
  "\n"
  "This module shows you how to create a Qt window.";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

static const char wanted_name[] = "Create Qt subwindow";

// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

static const char wanted_hotkey[] = "";

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
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey,        // the preferred hotkey to run the plugin
};
