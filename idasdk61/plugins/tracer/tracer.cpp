#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

//--------------------------------------------------------------------------
static int g_nb_insn, g_max_insn = 20;

//--------------------------------------------------------------------------
static int idaapi callback(void * /*user_data*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case dbg_process_start:
      // reset instruction counter
      g_nb_insn = 0;
      break;

    case dbg_run_to:
      msg("tracer: entrypoint reached\n");
      enable_insn_trace(true);
      continue_process();
      break;

    // A step occured (one instruction was executed). This event
    // notification is only generated if step tracing is enabled.
    case dbg_trace:
      {
        /*thid_t tid =*/ va_arg(va, thid_t);
        ea_t ip   = va_arg(va, ea_t);
        msg("[%d] tracing over: %a\n", g_nb_insn, ip);
        if ( g_nb_insn == g_max_insn )
        {
          // stop the trace mode and suspend the process
          disable_step_trace();
          suspend_process();
          msg("process suspended (traced %d instructions)\n", g_max_insn);
        }
        else
        {
          g_nb_insn++;
        }
      }
      break;

    case dbg_process_exit:
      unhook_from_notification_point(HT_DBG, callback, NULL);
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
void idaapi run(int arg) // 1 means run without questions
{
  if ( !hook_to_notification_point(HT_DBG, callback, NULL) )
  {
    warning("Could not hook to notification point\n");
    return;
  }

  if ( dbg == NULL )
    load_debugger("win32", false);

  // Let's start the debugger
  if ( !run_to(inf.beginEA) )
  {
    unhook_from_notification_point(HT_DBG, callback, NULL);
  }
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // Our plugin works only for x86 PE executables
  if ( ph.id != PLFM_386 || inf.filetype != f_PE )
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
  "Instruction tracer sample", // long comment about the plugin
  "", // multiline help about the plugin
  "tracer", // the preferred short name of the plugin
  "" // the preferred hotkey to run the plugin
};
