/* Custom viewer sample plugin.
 * Copyright (c) 2007 by Ilfak Guilfanov, ig@hexblog.com
 * Feel free to do whatever you want with this code.
 *
 * This sample plugin demonstates how to create and manipulate a simple
 * custom viewer in IDA v5.1
 *
 * Custom viewers allow you to create a view which displays colored lines.
 * These colored lines are dynamically created by callback functions.
 *
 * Custom viewers are used in IDA itself to display
 * the disassembly listng, structure, and enumeration windows.
 *
 * This sample plugin just displays several sample lines on the screen.
 * It displays a hint with the current line number.
 * The right-click menu contains one sample command.
 * It reacts to one hotkey.
 *
 * This plugin uses the simpleline_place_t class for the locations.
 * Custom viewers can use any decendant of the place_t class.
 * The place_t is responsible for supplying data to the viewer.
 */

//---------------------------------------------------------------------------
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#define TELL_CURRENT_WORD_ACTION_NAME "custview:TellCurrentWord"
#define INSERT_LINE_ACTION_NAME "custview:InsertLine"

struct plugin_ctx_t;
struct base_custview_action_t : public action_handler_t
{
  plugin_ctx_t &plg;
  base_custview_action_t(plugin_ctx_t &p) : plg(p) {}

  virtual action_state_t idaapi update(
        action_update_ctx_t *ctx) override;
};

//-------------------------------------------------------------------------
struct tell_current_word_ah_t : public base_custview_action_t
{
  tell_current_word_ah_t(plugin_ctx_t &p) : base_custview_action_t(p) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
};

//-------------------------------------------------------------------------
struct insert_line_ah_t : public base_custview_action_t
{
  insert_line_ah_t(plugin_ctx_t &p) : base_custview_action_t(p) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
};

//-------------------------------------------------------------------------
static struct
{
  const char *text;
  bgcolor_t color;
} const sample_text[] =
{
  { "This is a sample text",                                         0xFFFFFF },
  { "It will be displayed in the custom view",                       0xFFC0C0 },
  { COLSTR("This line will be colored as erroneous", SCOLOR_ERROR),  0xC0FFC0 },
  { COLSTR("Every", SCOLOR_AUTOCMT) " "
    COLSTR("word", SCOLOR_DNAME) " "
    COLSTR("can", SCOLOR_IMPNAME) " "
    COLSTR("be", SCOLOR_NUMBER) " "
    COLSTR("colored!", SCOLOR_EXTRA),                                0xC0C0FF },
  { "  No limit on the number of lines.",                            0xC0FFFF },
};

//-------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  TWidget *widget = nullptr;
  strvec_t lines;

  tell_current_word_ah_t tell_current_word_ah = tell_current_word_ah_t(*this);
  const action_desc_t tell_current_word = ACTION_DESC_LITERAL_PLUGMOD(
          TELL_CURRENT_WORD_ACTION_NAME,
          "Tell current word",
          &tell_current_word_ah,
          this,
          "N",
          nullptr,
          -1);

  insert_line_ah_t insert_line_ah = insert_line_ah_t(*this);
  const action_desc_t insert_line = ACTION_DESC_LITERAL_PLUGMOD(
          INSERT_LINE_ACTION_NAME,
          "Insert line",
          &insert_line_ah,
          this,
          "I",
          nullptr,
          -1);

  plugin_ctx_t();
  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//-------------------------------------------------------------------------
action_state_t base_custview_action_t::update(
        action_update_ctx_t *ctx)
{
  return ctx->widget == plg.widget
       ? AST_ENABLE_FOR_WIDGET
       : AST_DISABLE_FOR_WIDGET;
}

//---------------------------------------------------------------------------
// get the word under the (keyboard or mouse) cursor
static bool get_current_word(TWidget *v, bool mouse, qstring &word)
{
  // query the cursor position
  int x, y;
  if ( get_custom_viewer_place(v, mouse, &x, &y) == nullptr )
    return false;

  // query the line at the cursor
  qstring buf;
  tag_remove(&buf, get_custom_viewer_curline(v, mouse));
  if ( x >= buf.length() )
    return false;

  // find the beginning of the word
  char *ptr = buf.begin() + x;
  while ( ptr > buf.begin() && !qisspace(ptr[-1]) )
    ptr--;

  // find the end of the word
  char *begin = ptr;
  ptr = buf.begin() + x;
  while ( !qisspace(*ptr) && *ptr != '\0' )
    ptr++;

  word = qstring(begin, ptr-begin);
  return true;
}

//---------------------------------------------------------------------------
int idaapi tell_current_word_ah_t::activate(action_activation_ctx_t *)
{
  qstring word;
  if ( !get_current_word(plg.widget, false, word) )
    return 0;

  info("The current word is: %s", word.c_str());
  return 1;
}

//---------------------------------------------------------------------------
int idaapi insert_line_ah_t::activate(action_activation_ctx_t *)
{
  qstring line;
  bool ok = ask_str(&line, -1, "Please insert line of text");
  if ( ok )
    plg.lines.push_back().line.swap(line);
  return ok;
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
  if ( shift == 0 )
  {
    plugin_ctx_t *plugin = (plugin_ctx_t *) ud;
    switch ( key )
    {
      case 'N':
        warning("The hotkey 'N' has been pressed");
        return true;
      case IK_ESCAPE:
        close_widget(plugin->widget, WCLS_SAVE | WCLS_CLOSE_LATER);
        return true;
    }
  }
  return false;
}

//---------------------------------------------------------------------------
// This callback will be called each time the keyboard cursor position
// is changed
static void idaapi ct_curpos(TWidget *v, void *)
{
  qstring word;
  if ( get_current_word(v, false, word) )
    msg("Current word is: %s\n", word.c_str());
}

//-------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
{
  // Register the actions
  register_action(tell_current_word);
  register_action(insert_line);
}

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    // how to implement a simple hint callback
    case ui_get_custom_viewer_hint:
      {
        qstring &hint = *va_arg(va, qstring *);
        TWidget *viewer = va_arg(va, TWidget *);
        place_t *place = va_arg(va, place_t *);
        int *important_lines = va_arg(va, int *);
        if ( widget == viewer ) // our viewer
        {
          if ( place == nullptr )
            return 0;
          simpleline_place_t *spl = (simpleline_place_t *)place;
          hint.cat_sprnt("Hint for line %u\n", spl->n);
          *important_lines += 1;
        }
        break;
      }
    case ui_widget_invisible:
      {
        TWidget *w = va_arg(va, TWidget *);
        if ( w == widget )
        {
          widget = nullptr;
          lines.qclear();
          unhook_event_listener(HT_UI, this);
        }
      }
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static const custom_viewer_handlers_t handlers(
        ct_keyboard,
        nullptr, // popup
        nullptr, // mouse_moved
        nullptr, // click
        nullptr, // dblclick
        ct_curpos,
        nullptr, // close
        nullptr, // help
        nullptr);// adjust_place

//---------------------------------------------------------------------------
// Create a custom view window
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *w = find_widget("Sample custom view");
  if ( w != nullptr )
  {
    activate_widget(w, true);
    return true;
  }

  // prepare the data to display. we could prepare it on the fly too.
  // but for that we have to use our own custom place_t class decendant.
  for ( int i=0; i < qnumber(sample_text); i++ )
  {
    lines.push_back(simpleline_t("")); // add empty line
    lines.push_back(simpleline_t(sample_text[i].text));
    lines.back().bgcolor = sample_text[i].color;
  }
  // create two place_t objects: for the minimal and maximal locations
  simpleline_place_t s1;
  simpleline_place_t s2(lines.size()-1);
  // create a custom viewer
  widget = create_custom_viewer("Sample custom view", &s1, &s2, &s1, nullptr, &lines, &handlers, this);
  // also set the ui event callback
  hook_event_listener(HT_UI, this);
  // finally display the form on the screen
  display_widget(widget, WOPN_DP_TAB|WOPN_RESTORE);

  // We will always want those actions to be present in the context menu,
  // so instead of relying on `ui_populating_widget_popup` we can attach
  // them once and for all here
  attach_action_to_popup(widget, nullptr, TELL_CURRENT_WORD_ACTION_NAME);
  attach_action_to_popup(widget, nullptr, INSERT_LINE_ACTION_NAME);

  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

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

  "",                   // long comment about the plugin
  "",                   // multiline help about the plugin
  "Sample custview",    // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
