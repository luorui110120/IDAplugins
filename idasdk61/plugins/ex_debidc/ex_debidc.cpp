// Debugger IDC Helper
// Executes IDC script when the process is launched
// In fact, this approach can be used to hook IDC scripts to various debugger
// events.

#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <expr.hpp>
#include <loader.hpp>

//--------------------------------------------------------------------------
// The plugin stores the IDC file name in the database
// It will create a node for this purpose
static const char node_name[] = "$ debugger idc file";

//--------------------------------------------------------------------------
// Get the IDC file name from the database
static bool get_idc_name(char *buf, size_t bufsize)
{
  // access the node
  netnode mynode(node_name);
  // retrieve the value
  return mynode.valstr(buf, bufsize) > 0;
}

//--------------------------------------------------------------------------
// Store the IDC file name in the database
static void set_idc_name(const char *idc)
{
  // access the node
  netnode mynode;
  // if it doesn't exist yet, create it
  // otherwise get its id
  mynode.create(node_name);
  // store the value
  mynode.set(idc, strlen(idc)+1);
}

//--------------------------------------------------------------------------
static int idaapi callback(void * /*user_data*/, int notification_code, va_list /*va*/)
{
  switch ( notification_code )
  {
    case dbg_process_start:
    case dbg_process_attach:
      // it is time to run the script
      char idc[QMAXPATH];
      if ( get_idc_name(idc, sizeof(idc)) )
        dosysfile(true, idc);
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  // retrieve the old IDC name from the database
  char idc[QMAXPATH];
  if ( !get_idc_name(idc, sizeof(idc)) )
    qstrncpy(idc, "*.idc", sizeof(idc));

  char *newidc = askfile_c(false, idc, "Specify the script to run upon debugger launch");
  if ( newidc != NULL )
  {
    // store it back in the database
    set_idc_name(newidc);
    msg("Script %s will be run when the debugger is launched\n", newidc);
  }
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // Our plugin works only for x86 PE executables
  if ( ph.id != PLFM_386 || inf.filetype != f_PE )
    return PLUGIN_SKIP;
  if ( !hook_to_notification_point(HT_DBG, callback, NULL) )
    return PLUGIN_SKIP;
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  // just to be safe
  unhook_from_notification_point(HT_DBG, callback, NULL);
}

//--------------------------------------------------------------------------
char wanted_name[] = "Specify Debugger IDC Script";
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

  wanted_name,          // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  wanted_name,          // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
