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

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

extern plugin_t PLUGIN;

//--------------------------------------------------------------------------
// Example of a user-defined IDC function in C++

#if 0
static const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
static error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
{
  msg("myfunc is called with arg0=%x and arg1=%s\n", argv[0].num, argv[1].str);
  res->num = 5;     // let's return 5
  return eOk;
}
#endif

//--------------------------------------------------------------------------
// This callback is called for UI notification events
static int idaapi sample_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
  if ( event_id != ui_msg )     // avoid recursion
    if ( event_id != ui_setstate
      && event_id != ui_showauto
      && event_id != ui_refreshmarked ) // ignore uninteresting events
                    msg("ui_callback %d\n", event_id);
  return 0;                     // 0 means "process the event"
                                // otherwise the event would be ignored
}

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
static const int prefix_width = 8;

#if 0
static void get_user_defined_prefix(ea_t ea,
                                    int lnnum,
                                    int indent,
                                    const char *line,
                                    char *buf,
                                    size_t bufsize)
{
  buf[0] = '\0';        // empty prefix by default

  // We want to display the prefix only the lines which
  // contain the instruction itself

  if ( indent != -1 ) return;           // a directive
  if ( line[0] == '\0' ) return;        // empty line
  if ( tag_advance(line,1)[-1] == ash.cmnt[0] ) return; // comment line...

  // We don't want the prefix to be printed again for other lines of the
  // same instruction/data. For that we remember the line number
  // and compare it before generating the prefix

  static ea_t old_ea = BADADDR;
  static int old_lnnum;
  if ( old_ea == ea && old_lnnum == lnnum ) return;

  // Ok, seems that we found an instruction line.

  // Let's display the size of the current item as the user-defined prefix
  asize_t our_size = get_item_size(ea);

  // We don't bother about the width of the prefix
  // because it will be padded with spaces by the kernel

  qsnprintf(buf, bufsize, " %ld", our_size);

  // Remember the address and line number we produced the line prefix for:
  old_ea = ea;
  old_lnnum = lnnum;

}
#endif

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function every time when the plugin gets
//      loaded in the memory.
//      If this function returns PLGUIN_SKIP when called the first time,
//      IDA will never load it again. If it returns PLUGIN_OK, IDA will
//      unload the plugin but remember that the plugin agreed to work with
//      the database. The plugin will be loaded again if the user invokes
//      it by pressing its hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void)
{
  if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

// Please uncomment the following line to see how the notification works
//  hook_to_notification_point(HT_UI, sample_callback, NULL);
//  PLUGIN.flags &= ~PLUGIN_UNL;

// Please uncomment the following line to see how to the user-defined prefix works
//  set_user_defined_prefix(prefix_width, get_user_defined_prefix);

// Please uncomment the following line to see how to define IDC functions
//  set_idc_func_ex("MyFunc5", myfunc5, myfunc5_args, 0);

  const char *options = get_plugin_options("vcsample");
  if ( options != NULL )
    warning("command line options: %s", options);

  return (PLUGIN.flags & PLUGIN_UNL) ? PLUGIN_OK : PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function before unloading the plugin.

void idaapi term(void)
{
  unhook_from_notification_point(HT_UI, sample_callback);
  set_user_defined_prefix(0, NULL);
  set_idc_func_ex("MyFunc5", NULL, NULL, 0);
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void idaapi run(int arg)
{
  warning("plugin \"line_prefixes\" is called with arg %x\n", arg);

//  msg("just fyi: the current screen address is: %a\n", get_screen_ea());
}

//--------------------------------------------------------------------------
char comment[] = "This is a sample plugin. It does nothing useful";

char help[] =
        "A sample plugin module\n"
        "\n"
        "This module shows you how to create plugin modules.\n"
        "\n"
        "It does nothing useful - just prints a message that is was called\n"
        "and shows the current address.\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Sample plugin";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-0";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,           // plugin flags
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
