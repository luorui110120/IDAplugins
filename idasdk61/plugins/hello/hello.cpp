#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

int idaapi init(void)
{
  return PLUGIN_OK;
}

void idaapi run(int)
{
  warning("Hello, world!");
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,           // plugin flags
  init,                 // initialize
  NULL,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Hello, world",       // the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
