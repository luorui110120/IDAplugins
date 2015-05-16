#include <pro.h>
#include <err.h>
#include "wince_debmod.h"

#include "xscale/Breakpoint.h"
#include "rpc_server.h"

int wince_debmod_t::kdstub_loaded = -1;

//--------------------------------------------------------------------------
// The only reason why we load and use kernel stub is to ignore
// hardware breakpoints in foreign applications. If the user puts
// a breakpoint in a shared DLL, we don't want other applications
// to be aware of it - exceptions in these applications should be ignored.
static bool load_kdstub(void)
{
  bool ok = false;

  if ( g_global_server == NULL )
    return false;

  __try
  {
    static const char stubname[] = "\\Windows\\ida_kdstub.dll";
    // 01234567 8
    ok = g_global_server->rpc_sync_stub(stubname, &stubname[9]);
    if ( !ok )
    {
      g_global_server->dwarning("Failed to synchronize kernel debugger stub");
    }
    else
    {
      wchar_t wname[80];
      cwstr(wname, stubname, qnumber(wname));
      ok = AttachDebugger(wname);
      if ( !ok )
      {
        //Likely error codes:
        //ERROR_FILE_NOT_FOUND (2) - if LoadKernelLibrary failed
        //  This may happen if the DLL is not found or cannot be
        //  loaded. The DLL will fail to load if it is for a
        //  wrong platform or if it is linked to any other DLL.
        //ERROR_INVALID_PARAMETER (87) -if ConnectDebugger failed
        //  This may happen if IOCTL_DBG_INIT was not called
        //  by the DLL initialization routing or if some module
        //  in the system is marked as non-debuggable
        int code = GetLastError();
        g_global_server->dwarning("Failed to attach kernel debugger stub: %s", winerr(code));
      }
      else
      {
        g_global_server->dmsg("Successfully attached kernel debugger stub\n");
        //          win420_module_t wm;
        //          if ( find_module_by_name("ida_kdstub", (wince_module_t*)&wm) )
        //            msg("%x: kernel stub\n", int(wm.BasePtr)+0x1000);
      }
    }
  }
  __except( EXCEPTION_EXECUTE_HANDLER )
  {
  }
  return ok;
}


//--------------------------------------------------------------------------
bool wince_debmod_t::init_hwbpt_support(void)
{
  if ( kdstub_loaded == -1 )
    kdstub_loaded = load_kdstub();
  return kdstub_loaded;
}

//--------------------------------------------------------------------------
// Set hardware breakpoint for one thread
bool wince_debmod_t::set_hwbpts(HANDLE hThread)
{
  if ( is_xscale )
  {
    uint32 d0 = databpts[0] == BADADDR ? 0 : s0tops(databpts[0]);
    uint32 d1 = databpts[1] == BADADDR ? 0 : s0tops(databpts[1]);
    uint32 c0 = codebpts[0] == BADADDR ? 0 : s0tops(codebpts[0] | 1);
    uint32 c1 = codebpts[1] == BADADDR ? 0 : s0tops(codebpts[1] | 1);
    if ( active_hwbpts() )
    {
      SetDebugControlAndStatus(DEF_GlobalDebugEnabled, DEF_GlobalDebugEnabled);
      SetDataBreakPoint(d0, d1, dbcon);
      SetCodeBreakPoint(c0, c1);
    }
    else
    {
      disable_hwbpts();
    }
    //    msg("set bpts: dcsr=%x code=%a %a data=%a %a dbcon=%a\n",
    //                SetDebugControlAndStatus(0, 0),
    //                c0, c1, d0, d1, dbcon);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
ea_t wince_debmod_t::is_hwbpt_triggered(thid_t id)
{
  if ( is_xscale )
  {
    uint32 dcsr = SetDebugControlAndStatus(0, 0);
    int moe = (dcsr >> 2) & 7;  // method of entry (exception reason)
    //    msg("moe=%d\n", moe);
    switch ( moe )
    {
    case 1: // Instruction Breakpoint Hit
    case 2: // Data Breakpoint Hit
      {
        SetDebugControlAndStatus(0, 7<<2); // clean moe
        CONTEXT Context;
        Context.ContextFlags = CONTEXT_CONTROL;
        HANDLE h = get_thread_handle(id);
        if ( GetThreadContext(h, &Context) )
        {
          ea_t ea = s0tops(Context.Pc);
          if ( s0tops(codebpts[0]) == ea || s0tops(codebpts[1]) == ea )
          {
            //              msg("HARDWARE CODE BREAKPOINT!\n");
            return ea;
          }
          // This is a data breakpoint
          // Set PC to the next instruction since the data bpts always occur
          // AFTER the instruction
#define THUMB_STATE 0x0020
          Context.Pc += (Context.Psr & THUMB_STATE)? 2 : 4;
          SetThreadContext(h, &Context);
        }
        // FIXME: determine which data bpt really caused the exception
        // Currently we just return the first active bpt
        return databpts[0] != BADADDR ? databpts[0] : databpts[1];
      }
    case 0: // Processor Reset
    case 3: // BKPT Instruction Executed
    case 4: // External Debug Event (JTAG Debug Break or SOC Debug Break)
    case 5: // Vector Trap Occurred
    case 6: // Trace Buffer Full Break
    case 7: // Reserved
      break;
    }
  }
  return BADADDR;
}

//--------------------------------------------------------------------------
bool wince_debmod_t::disable_hwbpts()
{
  if ( is_xscale )
  {
    SetDebugControlAndStatus(0, ~(7<<2)); // preserve moe
    SetDataBreakPoint(0, 0, 0);
    SetCodeBreakPoint(0, 0);
  }
  return true;
}

//--------------------------------------------------------------------------
bool wince_debmod_t::enable_hwbpts()
{
  return set_hwbpts(NULL);
}

/*
//--------------------------------------------------------------------------
ea_t wince_debmod_t::pstos0(ea_t ea)        // map process slot to slot 0
{
  if ( (ea & 0xFE000000) == slot ) // redirect our process addresses
    ea  &= ~0xFE000000;            // to slot 0
  return ea;
}

//--------------------------------------------------------------------------
ea_t wince_debmod_t::s0tops(ea_t ea)        // map slot 0 to the process slot
{
  if ( (ea & 0xFE000000) == 0 )
    ea |= slot;
  return ea;
}
*/