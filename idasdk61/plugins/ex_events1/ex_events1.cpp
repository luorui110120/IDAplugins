/*
        This is a sample plugin.

        It illustrates how the analysis can be improved

        The plugin checks branch targets for newly created instructions.
        If the target does not exist in the program, the plugin
        forbids the instruction creation.

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>

//--------------------------------------------------------------------------
// This callback is called by the kernel when processor related events happen
static int idaapi idp_callback(void * /*user_data*/, int event_id, va_list va)
{
  switch ( event_id )
  {
    case processor_t::make_code:// An instruction is being created
                                // args: ea_t ea, asize_t size
                                // returns: 1-ok, <=0-the kernel should stop
     ea_t ea = va_arg(va, ea_t);
     // we are interested in the branch instructions
     // fill the 'cmd' structure
     if ( decode_insn(ea) > 0 )
     {
       if ( cmd.itype >= NN_ja && cmd.itype <= NN_jmpshort )
       {
         // the first operand contains the jump target
         ea_t target = toEA(cmd.cs, cmd.Op1.addr);

         if ( !isEnabled(target) )
           return -1;
       }
     }
  }
  return 0; // event not processed
            // let other plugins or the processor module handle it
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // hook events about database modifications
  hook_to_notification_point(HT_IDP, idp_callback, NULL);
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  // hook events about database modifications
  unhook_from_notification_point(HT_IDP, idp_callback, NULL);
}

//--------------------------------------------------------------------------
void idaapi run(int)
{
  // since the plugin is fully automatic, there is nothing to do
  warning("Branch checker is fully automatic");
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,          // the plugin won't be visible in the menu
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Branch checker",     // the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
