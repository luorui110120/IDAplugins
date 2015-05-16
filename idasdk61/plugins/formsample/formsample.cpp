/*
 *  This plugin demonstrates how to use complex forms.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static int idaapi but(TView *[], int)
{
  warning("button pressed");
  return 0;
}

//--------------------------------------------------------------------------
static int idaapi modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case -1:
      msg("initializing\n");
      break;
    case -2:
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

  bool is_gui = callui(ui_get_hwnd).vptr != NULL || is_idaq();

  char buf0[MAXSTR];
  if ( !fa.get_field_value(5, buf0) )
    INTERR(30145);

  if ( strcmp(buf0, "on") == 0 )
    fa.enable_field(12, true);

  if ( strcmp(buf0, "off") == 0 )
    fa.enable_field(12, false);

  ushort buf1;
  if ( !fa.get_field_value(12, &buf1) )
    INTERR(30146);

  fa.show_field(7, (buf1 & 1) != 0);
  fa.enable_field(8, (buf1 & 2) != 0);


  ushort c13;
  if ( !fa.get_field_value(13, &c13) )
    INTERR(30147);
  fa.enable_field(10, c13);

  ushort c14;
  if ( !fa.get_field_value(14, &c14) )
    INTERR(30148);
  fa.enable_field(5, c14);

  ushort c15;
  if ( !fa.get_field_value(15, &c15) )
    INTERR(30149);

  if ( (buf1 & 8) != 0 )
  {
    uval_t x, y, w, h;
    fa.get_field_value(4, &x);
    fa.get_field_value(3, &y);
    fa.get_field_value(2, &w);
    fa.get_field_value(1, &h);
    fa.move_field(5, x, y, w, h);
    if ( x != -1 && c15 )
      fa.move_field(-5, x-7, y, w, h);
  }

  if ( fa.get_field_value(7, NULL) )
    INTERR(30150);

  bgcolor_t bgc = -1;
  if ( is_gui && !fa.get_field_value(8, &bgc) )
    INTERR(30151);
  msg("  op=%s change=%x color=%x\n", buf0, buf1, bgc);

  fa.set_field_value(9, buf0);
  return 1;
}

//--------------------------------------------------------------------------
static void idaapi run(int)
{
  static const char form[] =
    "@0:477[]\n"
    "Manual operand\n"
    "\n"
    "%/Enter alternate string for the %9D operand\n"
    "\n"
    "  <~O~perand:A5:100:40::>\n"
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
    " <~B~utton:B7:0:::> <~C~olor button:K8:::>\n"
    "\n"
    "\n";
  uval_t ln = 1;
  char buf[MAXSTR];
  qstrncpy(buf, "original operand", sizeof(buf));
  ushort check = 0x12;
  bgcolor_t bgc = 0x556677;
  uval_t x = -1;
  uval_t y = -1;
  uval_t w = -1;
  uval_t h = -1;
  if ( AskUsingForm_c(form, modcb, &ln, buf, &x, &y, &w, &h, &check, but, &bgc) > 0 )
  {
    msg("operand: %s\n", buf);
    msg("check = %d\n", check);
    msg("dim = %a %a %a %a\n", x, y, w, h);
    msg("bgc = %x\n", bgc);
  }
}

//--------------------------------------------------------------------------
static int idaapi init(void)
{
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,
  init,                 // initialize
  NULL,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "AskUsingForm sample",// the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
