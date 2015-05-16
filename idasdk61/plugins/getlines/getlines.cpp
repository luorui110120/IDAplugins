/*
 *  This is a sample plugin module
 *
 *      It demonstrates how to get the disassembly lines for one address
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  ea_t ea = get_screen_ea();
  if ( askaddr(&ea, "Please enter the disassembly address")
    && isEnabled(ea) )                              // address belongs to disassembly
  {
    int flags = calc_default_idaplace_flags();
    linearray_t ln(&flags);
    idaplace_t pl;
    pl.ea = ea;
    pl.lnnum = 0;
    ln.set_place(&pl);
    msg("printing disassembly lines:\n");
    int n = ln.get_linecnt();           // how many lines for this address?
    for ( int i=0; i < n; i++ )         // process all of them
    {
      char *line = ln.down();           // get line
      char buf[MAXSTR];
      tag_remove(line, buf, sizeof(buf)); // remove color codes
      msg("%d: %s\n", i, buf);          // display it on the message window
    }
    msg("total %d lines\n", n);
  }
}

//--------------------------------------------------------------------------
char comment[] = "Generate disassembly lines for one address";

char help[] =
        "Generate disassembly lines for one address\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Disassembly lines sample";


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
