/*
 *  This is a sample plugin module. It demonstrates how to fully use
 *  the Qt environment in IDA.
 *
 */

//lint -e4206 'nodiscard' attribute cannot be applied to types
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219) // implicit conversion from 'int' to 'float', possible loss of data
#pragma warning(disable:5240) // 'nodiscard': attribute is ignored in this syntactic position
#endif // __NT__

#include <QtGui>
#include <QtWidgets>

#ifdef __NT__
#pragma warning(pop)
#endif // __NT__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

// include your own widget here
#include "graphwidget.h"

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
      // widget is created, create controls

      QWidget *w = (QWidget *) widget;

      QHBoxLayout *mainLayout = new QHBoxLayout();
      mainLayout->setContentsMargins(0, 0, 0, 0);

      GraphWidget *userWidget = new GraphWidget();

      mainLayout->addWidget(userWidget);

      w->setLayout(mainLayout);
      //lint -e429 mainLayout not freed
    }
  }
  if ( code == ui_widget_invisible )
  {
    TWidget *l_widget = va_arg(va, TWidget *);
    if ( l_widget == widget )
    {
      // widget is closed, destroy objects (if required)
      widget = nullptr;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *g_widget = find_widget("Sample Qt Project");
  if ( g_widget == nullptr )
  {
    widget = create_empty_widget("Sample Qt Project");
    display_widget(widget, WOPN_DP_TAB|WOPN_RESTORE);
  }
  else
  {
    close_widget(g_widget, WCLS_SAVE);
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
char comment[] = "This is a sample Qt Project plugin.";

char help[] =
    "A sample plugin module\n"
    "\n"
    "This module shows you how to use fully the Qt environment in IDA.";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

char wanted_name[] = "Qt Project Sample";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

char wanted_hotkey[] = "";


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
