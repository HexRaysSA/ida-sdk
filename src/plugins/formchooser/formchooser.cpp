/*
 *  This plugin demonstrates how to use choosers inside forms.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#define ACTION_NAME "formchooser:action"
#define TITLE_PFX "Form with choosers"

//--------------------------------------------------------------------------
// raw data of the png icon (16x16)
static const unsigned char icon_data[182] =
{
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF,
  0x61, 0x00, 0x00, 0x00, 0x7D, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0x64, 0xC0, 0x0E, 0xFE,
  0xE3, 0x10, 0x67, 0x24, 0x28, 0x00, 0xD2, 0xFC, 0xF3, 0xAF, 0x36, 0x56, 0xDD, 0xEC, 0xCC, 0x57,
  0x31, 0xF4, 0x20, 0x73, 0xC0, 0xB6, 0xE2, 0xD2, 0x8C, 0x66, 0x08, 0x5C, 0x2F, 0x8A, 0x01, 0x84,
  0x34, 0x63, 0x73, 0x09, 0x23, 0xA9, 0x9A, 0xD1, 0x0D, 0x61, 0x44, 0xD7, 0xCC, 0xCF, 0x02, 0x71,
  0xE2, 0xC7, 0x3F, 0xA8, 0x06, 0x62, 0x13, 0x07, 0x19, 0x42, 0x7D, 0x03, 0x48, 0xF5, 0xC6, 0x20,
  0x34, 0x00, 0xE4, 0x57, 0x74, 0xFF, 0xE3, 0x92, 0x83, 0x19, 0xC0, 0x40, 0x8C, 0x21, 0xD8, 0x34,
  0x33, 0x40, 0xA3, 0x91, 0x01, 0x97, 0x21, 0xC8, 0x00, 0x9B, 0x66, 0x38, 0x01, 0x33, 0x00, 0x44,
  0x50, 0x92, 0x94, 0xB1, 0xBA, 0x04, 0x8B, 0x66, 0x9C, 0x99, 0x09, 0xC5, 0x10, 0x1C, 0xE2, 0x18,
  0xEA, 0x01, 0xA3, 0x65, 0x55, 0x0B, 0x33, 0x14, 0x07, 0x63, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
  0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
};

//-------------------------------------------------------------------------
struct formchooser_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    msg("Menu item clicked. Current selection:");
    for ( size_t i = 0, n = ctx->chooser_selection.size(); i < n; ++i )
      msg(" %" FMT_Z, ctx->chooser_selection[i]);
    msg("\n");
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    bool ok = ctx->widget_type == BWN_CHOOSER;
    if ( ok )
    {
      qstring name;
      ok = get_widget_title(&name, ctx->widget)
        && name.starts_with(TITLE_PFX);
    }
    return ok ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
  }
};

//--------------------------------------------------------------------------
//lint -e{958} padding needed
struct plugin_ctx_t : public plugmod_t
{
  int icon_id = load_custom_icon(icon_data, sizeof(icon_data), "png");

  formchooser_ah_t formchooser_ah;
  const action_desc_t formchooser_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        "Test",
        &formchooser_ah,
        this,
        "Ctrl-K",
        nullptr,
        icon_id);

  int main_current_index = -1;

  virtual bool idaapi run(size_t) override;

  static int idaapi modcb(int fid, form_actions_t &fa);
  void refresh_selection_edit(form_actions_t & fa);
};

//---------------------------------------------------------------------------
struct mainch_chooser_t : public chooser_t
{
protected:
  static const int widths_[];
  static const char *const header_[];
  friend struct auxch_chooser_t;

public:
  // this chooser is embedded into the modal form
  inline mainch_chooser_t(int icon_id);

  virtual size_t idaapi get_count() const override { return 10; }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
};

//---------------------------------------------------------------------------
struct auxch_chooser_t : public chooser_multi_t
{
public:
  plugin_ctx_t &ctx;

  // this chooser is embedded into the modal form
  auxch_chooser_t(plugin_ctx_t &ctx, int icon_id);

  virtual size_t idaapi get_count() const override
  {
    return ctx.main_current_index + 1;
  }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
};

//--------------------------------------------------------------------------
const int mainch_chooser_t::widths_[] = { 40 };
const char *const mainch_chooser_t::header_[] = { "Item" };

//-------------------------------------------------------------------------
inline mainch_chooser_t::mainch_chooser_t(int icon_)
  : chooser_t(CH_KEEP, qnumber(widths_), widths_, header_)
{
  CASSERT(qnumber(widths_) == qnumber(header_));
  icon = icon_;
}

//-------------------------------------------------------------------------
void idaapi mainch_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  qstrvec_t &cols = *cols_;
  cols[0].sprnt("Option %" FMT_Z, n + 1);
  CASSERT(qnumber(header_) == 1);
}

//-------------------------------------------------------------------------
auxch_chooser_t::auxch_chooser_t(plugin_ctx_t &ctx_, int icon_)
  : chooser_multi_t(
            CH_KEEP,
            qnumber(mainch_chooser_t::widths_),
            mainch_chooser_t::widths_,
            mainch_chooser_t::header_),
    ctx(ctx_)
{
  icon = icon_;
}
//-------------------------------------------------------------------------
void idaapi auxch_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  qstrvec_t &cols = *cols_;
  cols[0].sprnt("Item %" FMT_Z, n + 1);
}

//-------------------------------------------------------------------------
void plugin_ctx_t::refresh_selection_edit(form_actions_t & fa)
{
  qstring str;
  if ( main_current_index == -1 )
  {
    str = "No selection";
  }
  else
  {
    str.sprnt("Main %d", main_current_index + 1);

    sizevec_t array;
    fa.get_chooser_value(4, &array);
    if ( array.size() > 0 )
    {
      str.append(" - Aux item(s) ");
      for ( int i = 0; i < array.size(); i++ )
      {
        if ( i != 0 )
          str.append(", ");
        str.cat_sprnt("%" FMT_Z, array[i] + 1);
      }
    }
  }
  fa.set_string_value(5, &str);
}

//--------------------------------------------------------------------------
int idaapi plugin_ctx_t::modcb(int fid, form_actions_t &fa)
{
  plugin_ctx_t &ctx = *(plugin_ctx_t *)fa.get_ud();
  switch ( fid )
  {
    case CB_INIT:
      msg("initializing\n");
      ctx.refresh_selection_edit(fa);
      break;
    case CB_YES:
      msg("terminating\n");
      break;
    // main chooser
    case 3:
      {
        msg("main chooser selection change\n");
        sizevec_t array;
        fa.get_chooser_value(3, &array);
        ctx.main_current_index = !array.empty() ? array[0] : -1;
        // refresh auxiliar chooser
        fa.refresh_field(4);
        ctx.refresh_selection_edit(fa);
      }
      break;
    // auxiliar chooser
    case 4:
      ctx.refresh_selection_edit(fa);
      break;
    // Aux value text control
    case 5:
      break;
    default:
      msg("unknown id %d\n", fid);
      break;
  }

  return 1;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  struct ida_local lambda_t
  {
    static ssize_t idaapi cb(void *, int code, va_list va)
    {
      if ( code == ui_finish_populating_widget_popup )
      {
        TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *popup_handle = va_arg(va, TPopupMenu *);
        // Let the chooser populate itself normally first.
        // We'll add our own stuff on second pass.
        qstring buf;
        if ( get_widget_type(widget) == BWN_CHOOSER
          && get_widget_title(&buf, widget)
          && buf == TITLE_PFX":3" )
        {
          attach_action_to_popup(widget, popup_handle, ACTION_NAME);
        }
      }
      return 0;
    }
  };
  hook_to_notification_point(HT_UI, lambda_t::cb);

  static const char form[] =
    "STARTITEM 0\n"
    TITLE_PFX"\n\n"
    "%/%*"
    "Select an item in the main chooser:\n"
    "\n"
    "<Main chooser:E3::30::><Auxiliar chooser (multi):E4::30::>\n\n"
    "<Selection:q5:1023:40::>\n"
    "\n";

  register_action(formchooser_desc);

  mainch_chooser_t main_ch(icon_id);
  sizevec_t main_sel; // no selection by default
  main_current_index = -1;

  auxch_chooser_t aux_ch(*this, icon_id);
  sizevec_t aux_sel; // no selection by default

  qstring str;

  CASSERT(IS_CHOOSER_BASE_T(main_ch));
  CASSERT(IS_CHOOSER_BASE_T(aux_ch));
  if ( ask_form(form, modcb, this,
                &main_ch, &main_sel,
                &aux_ch, &aux_sel,
                &str) > 0 )
  {
    msg("Selection: %s\n", str.c_str());
  }

  unhook_from_notification_point(HT_UI, lambda_t::cb);
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "Forms chooser sample",// the preferred short name of the plugin
  nullptr,
};
