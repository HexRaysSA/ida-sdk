/*
 *  This plugin demonstrates how to use non modal forms.
 *  It creates 2 windows on the screen:
 *      - a window with 4 buttons: dock, undock, show, hide      (CONTROL FORM)
 *      - a window with a text edit control and a list control   (EDITOR FORM)
 *  The buttons of the first window can be used to manage the second window.
 *  We will call the first window 'CONTROL FORM' and the second window 'EDITOR
 *  FORM', just to be able to reference them easily.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//---------------------------------------------------------------------------
// chooser (list view) items
static const char *const names[] =
{
  "Item one",
  "Item two",
  "Item three"
};

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  // the editor form
  TWidget *editor_widget = nullptr;

  // contents of the text field for each item
  qstring txts[qnumber(names)] =
  {
    "Text one:\n This is text for item one",
    "Text two:\n And this is text for item two",
    "Text three:\n And finally text for the last item"
  };

  // Current index for chooser list view
  size_t curidx = 0;
  // Form actions for control dialog
  form_actions_t *control_fa = nullptr;
  // Defines where to place new/existing editor window
  bool dock = false;

  virtual bool idaapi run(size_t) override;

  int editor_modcb(int fid, form_actions_t &fa);
  void open_editor_form(int options = 0);
  void close_editor_form();
  int control_modcb(int fid, form_actions_t &fa);
  void update_buttons(form_actions_t &fa);
};

//---------------------------------------------------------------------------
struct of_chooser_t : public chooser_t
{
public:
  // this object must be allocated using `new`
  // as it used in the non-modal form
  of_chooser_t() : chooser_t()
  {
    columns = 1;
    static const int widths_[] = { 12 };
    static const char *const header_[] = { "Name" };
    widths = widths_;
    header = header_;
  }

  virtual size_t idaapi get_count() const override { return qnumber(names); }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    (*cols)[0] = names[n];
  }
};

// Form actions for editor window
enum editor_form_actions
{
  TEXT_CHANGED  = 1,
  ITEM_SELECTED = 2,
};

// Form actions for control window
enum control_form_actions
{
  BTN_DOCK   = 10,
  BTN_UNDOCK = 11,
  BTN_OPEN   = 12,
  BTN_CLOSE  = 13,
};

//--------------------------------------------------------------------------
inline void enable_button(form_actions_t &fa, int fid, bool enabled)
{
  fa.enable_field(fid, enabled);
}

//--------------------------------------------------------------------------
// Update control window buttons state
void plugin_ctx_t::update_buttons(form_actions_t &fa)
{
  bool visible = editor_widget != nullptr;
  enable_button(fa, 10, !dock && visible);
  enable_button(fa, 11, dock && visible);
  enable_button(fa, 12, !visible);
  enable_button(fa, 13, visible);
}

//--------------------------------------------------------------------------
// this callback is called when the user clicks on a button
static int idaapi btn_cb(int, form_actions_t &)
{
  msg("button has been pressed -> \n");
  return 0;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal editor form
static int idaapi editor_modcb_(int fid, form_actions_t &fa)
{
  plugin_ctx_t &ctx = *(plugin_ctx_t *)fa.get_ud();
  return ctx.editor_modcb(fid, fa);
}
int plugin_ctx_t::editor_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case CB_INIT:     // Initialization
      msg("init editor form\n");
      break;
    case CB_CLOSE:    // Closing the form
      msg("closing editor form\n");
      // mark the form as closed
      editor_widget = nullptr;
      // If control form exists then update buttons
      if ( control_fa != nullptr )
        update_buttons(*control_fa);
      break;
    case TEXT_CHANGED:     // Text changed
      {
        textctrl_info_t ti;
        fa.get_text_value(1, &ti);
        txts[curidx] = ti.text;
      }
      msg("text has been changed\n");
      break;
    case ITEM_SELECTED:    // list item selected
      {
        sizevec_t sel;
        if ( fa.get_chooser_value(2, &sel) )
        {
          curidx = sel[0];
          textctrl_info_t ti;
          ti.cb = sizeof(textctrl_info_t);
          ti.text = txts[curidx];
          fa.set_text_value(1, &ti);
        }
      }
      msg("selection has been changed\n");
      break;
    default:
      msg("unknown id %d\n", fid);
      break;
  }
  return 1;
}
//---------------------------------------------------------------------------
// create and open the editor form
void plugin_ctx_t::open_editor_form(int options)
{
  static const char formdef[] =
    "BUTTON NO NONE\n"        // we do not want the standard buttons on the form
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Editor form\n"           // the form title. it is also used to refer to the form later
    "\n"
    "%/%*"                    // placeholder for the 'editor_modcb' callback
    "\n"
    "<List:E2::30:1::><|><Text:t1::60:::>\n" // text edit control and chooser control separated by splitter
    "\n";
  // structure for text edit control
  textctrl_info_t ti;
  ti.cb = sizeof(textctrl_info_t);
  ti.text = txts[0];
  // structure for chooser list view
  of_chooser_t *ofch = new of_chooser_t();
  // selection for chooser list view
  sizevec_t selected;
  selected.push_back(0);  // first item by default
  editor_widget = open_form(formdef,
                            options,
                            editor_modcb_, this,
                            ofch, &selected,
                            &ti);
} //lint !e429 custodial pointer 'ofch' likely not freed nor returned


//---------------------------------------------------------------------------
void plugin_ctx_t::close_editor_form()
{
  msg("closing editor widget\n");
  close_widget(editor_widget, WCLS_CLOSE_LATER);
  editor_widget = nullptr;
}
//--------------------------------------------------------------------------
inline void dock_form(bool _dock)
{
  set_dock_pos("Editor form",
               "IDA View-A",
               _dock ? DP_TAB : DP_FLOATING);
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal control form
static int idaapi control_modcb_(int fid, form_actions_t &fa)
{
  plugin_ctx_t &ctx = *(plugin_ctx_t *)fa.get_ud();
  return ctx.control_modcb(fid, fa);
}
int plugin_ctx_t::control_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case CB_INIT:   // Initialization
      msg("init control form\n");
      dock = false;
      control_fa = &fa;   // remember the 'fa' for the future
      break;
    case CB_CLOSE:  // Closing
      msg("closing control form\n");
      control_fa = nullptr;
      return 1;
    case BTN_DOCK:
      msg("dock editor form\n");
      dock = true;
      dock_form(dock);
      break;
    case BTN_UNDOCK:
      msg("undock editor form\n");
      dock = false;
      dock_form(dock);
      break;
    case BTN_OPEN:
      msg("open editor form\n");
      open_editor_form(WOPN_DP_TAB|WOPN_RESTORE);
      dock_form(dock);
      break;
    case BTN_CLOSE:
      close_editor_form();
      break;
    default:
      msg("unknown id %d\n", fid);
      return 1;
  }
  update_buttons(fa);
  return 1;
}

//--------------------------------------------------------------------------
// the main function of the plugin
bool idaapi plugin_ctx_t::run(size_t)
{
  // first open the editor form
  open_editor_form(WOPN_RESTORE);

  static const char control_form[] =
    "BUTTON NO NONE\n"          // do not display standard buttons at the bottom
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Control form\n"            // the title. it is used to refer to the form later
    "%/%*"                      // placeholder for control_modcb
    "<Dock:B10:30:::><Undock:B11:30:::><Show:B12:30:::><Hide:B13:30:::>\n"; // Create control buttons

  open_form(control_form,
            WOPN_RESTORE,
            control_modcb_, this,
            btn_cb, btn_cb, btn_cb, btn_cb);
  set_dock_pos("Control form", nullptr, DP_FLOATING, 0, 0, 300, 100);
  return true;
}

//--------------------------------------------------------------------------
// initialize the plugin
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "Open non-modal form sample",// the preferred short name of the plugin
  nullptr,
};
