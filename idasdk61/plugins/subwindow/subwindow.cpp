/*
 *  This is a sample plugin module
 *
 *  It can be compiled by any of the supported compilers:
 *
 *      - Borland C++, CBuilder, free C++
 *      - Watcom C++ for DOS32
 *      - Watcom C++ for OS/2
 *      - Visual C++
 *
 */

#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static int idaapi ui_callback(void *user_data, int notification_code, va_list va)
{
  if ( notification_code == ui_tform_visible )
  {
    TForm *form = va_arg(va, TForm *);
    if ( form == user_data )
    {
      // user defined form is displayed, populate it with controls
      HWND hwnd   = va_arg(va, HWND);
      HWND hButton= CreateWindow ("BUTTON", "Button",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  10, 10, 100, 40, hwnd, NULL,
                                  NULL, NULL);
      msg("tform is displayed, hbutton=%x\n", hButton);
    }
  }
  if ( notification_code == ui_tform_invisible )
  {
    TForm *form = va_arg(va, TForm *);
    if ( form == user_data )
    {
      // user defined form is closed, destroy its controls
      // (to be implemented)
      msg("tform is closed\n");
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return callui(ui_get_hwnd).vptr != NULL ? PLUGIN_OK : PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_UI, ui_callback);
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  HWND hwnd = NULL;
  TForm *form = create_tform("Sample subwindow", &hwnd);
  if ( hwnd != NULL )
  {
    hook_to_notification_point(HT_UI, ui_callback, form);
    open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU|FORM_RESTORE);
  }
  else
    close_tform(form, FORM_SAVE);
}

//--------------------------------------------------------------------------
char comment[] = "This is a sample plugin.";

char help[] =
        "A sample plugin module\n"
        "\n"
        "This module shows you how to create MDI child window.";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Create IDA subwindow";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
