/*
 *  This plugin demonstrates how to use complex forms.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
static int idaapi btn_cb(int, form_actions_t &)
{
  warning("button pressed");
  return 0;
}

//--------------------------------------------------------------------------
static int idaapi modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case CB_INIT:
      msg("initializing\n");
      break;
    case CB_YES:
      msg("terminating\n");
      break;
    case 5:     // operand
      msg("changed operand\n");
      break;
    case 6:     // check
      msg("changed check\n");
      break;
    case 7:     // button
      msg("changed button\n");
      break;
    case 8:     // color button
      msg("changed color button\n");
      break;
    default:
      msg("unknown id %d\n", fid);
      break;
  }

  bool is_gui = is_idaq();

  qstring buf0;
  if ( !fa.get_string_value(5, &buf0) )
    INTERR(30145);

  if ( buf0 == "on" )
    fa.enable_field(12, true);

  if ( buf0 == "off" )
    fa.enable_field(12, false);

  ushort buf1;
  if ( !fa.get_cbgroup_value(12, &buf1) )
    INTERR(30146);

  fa.show_field(7, (buf1 & 1) != 0);
  fa.enable_field(8, (buf1 & 2) != 0);


  ushort c13;
  if ( !fa.get_checkbox_value(13, &c13) )
    INTERR(30147);
  fa.enable_field(10, c13 != 0);

  ushort c14;
  if ( !fa.get_checkbox_value(14, &c14) )
    INTERR(30148);
  fa.enable_field(5, c14 != 0);

  ushort c15;
  if ( !fa.get_checkbox_value(15, &c15) )
    INTERR(30149);

  if ( (buf1 & 8) != 0 )
  {
    sval_t x, y, w, h;
    fa.get_signed_value(4, &x);
    fa.get_signed_value(3, &y);
    fa.get_signed_value(2, &w);
    fa.get_signed_value(1, &h);
    fa.move_field(5, x, y, w, h);
    if ( x != -1 && c15 )
      fa.move_field(-5, x-7, y, w, h);
  }

  // get_field_value() for buttons must return false always
  if ( fa._get_field_value(7, nullptr) )
    INTERR(30150);

  bgcolor_t bgc = -1;
  if ( is_gui && !fa.get_color_value(8, &bgc) )
    INTERR(30151);
  msg("  op=%s change=%x color=%x\n", buf0.c_str(), buf1, bgc);

  fa.set_label_value(9, buf0.c_str());
  return 1;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  static const char form[] =
    "@0:477[]\n"
    "Manual operand\n"
    "\n"
    "%/Enter alternate string for the %9X operand\n"
    "\n"
    "  <~O~perand:q5:100:40::>\n"
    "  <~X~:D4:100:10::>\n"
    "  <~Y~:D3:100:10::>\n"
    "  <~W~:D2:100:10::>\n"
    "  <~H~:D1:100:10::>\n"
    "\n"
    "  <S~h~ow Button:C10>\n"
    "  <~E~nable color Button:C11>\n"
    "  <~E~nable C10:C13>\n"
    "  <~S~et operand bounds:C6>\n"
    "  <Enable operand:C14>\n"
    "  <Move label:C15>12>\n"
    "\n"
    " <~B~utton:B7:0:::> <~C~olor button:K8::::>\n"
    "\n"
    "\n";
  qstring buf("original");
  ushort check = 0x12;
  bgcolor_t bgc = 0x556677;
  uval_t x = -1;
  uval_t y = -1;
  uval_t w = -1;
  uval_t h = -1;
  CASSERT(IS_FORMCHGCB_T(modcb));
  CASSERT(IS_QSTRING(buf));
  if ( ask_form(form, modcb, buf.c_str(), &buf, &x, &y, &w, &h, &check, btn_cb, &bgc) > 0 )
  {
    msg("operand: %s\n", buf.c_str());
    msg("check = %d\n", check);
    msg("dim = %a %a %a %a\n", x, y, w, h);
    msg("bgc = %x\n", bgc);
  }
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
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "ask_form sample",    // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
