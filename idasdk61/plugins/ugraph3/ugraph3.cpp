/*
 *  This is a sample plugin module.
 *  It demonstrates how to generate ida graphs for arbitrary ranges.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // unload us if text mode, no graph are there
  if ( callui(ui_get_hwnd).vptr == NULL && !is_idaq() )
    return PLUGIN_SKIP;

  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  ea_t ea1, ea2;
  if ( !read_selection(&ea1, &ea2) )
  {
    warning("Please select an area before running the plugin");
    return;
  }
  unmark_selection();

  // fixme: how to specify multiple ranges?

  areavec_t ranges;
  ranges.push_back(area_t(ea1, ea2));
  open_disasm_window("Selected range", &ranges);
}

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
  NULL,
  NULL,
  "Generate graph for selection",
  NULL
};
