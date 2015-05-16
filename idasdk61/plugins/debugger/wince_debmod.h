#ifndef __WINCE_DEBUGGER_MODULE__
#define __WINCE_DEBUGGER_MODULE__

#ifdef __NT__
#  include <windows.h>
#endif

#include "arm_debmod.h"
#include "wince.hpp"

//--------------------------------------------------------------------------
class wince_debmod_t : public arm_debmod_t
{
protected:
  static int kdstub_loaded;

public:
  wince_debmod_t(void) { kdstub_loaded = -1; }

  bool set_hwbpts(HANDLE hThread);
  ea_t is_hwbpt_triggered(thid_t id);

  // overridden base class functions
  virtual bool init_hwbpt_support(void);
  virtual bool disable_hwbpts();
  virtual bool enable_hwbpts();

  // new virtial functions
  virtual HANDLE get_thread_handle(thid_t tid) = 0;
};

#endif
