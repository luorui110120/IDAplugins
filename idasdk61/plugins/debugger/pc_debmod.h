#ifndef __PC_DEBUGGER_MODULE__
#define __PC_DEBUGGER_MODULE__

#ifdef __NT__
#  include <windows.h>
#endif

#include "deb_pc.hpp"
#include "debmod.h"

class pc_debmod_t: public debmod_t
{
  typedef debmod_t inherited;
protected:
  // Hardware breakpoints
  ea_t hwbpt_ea[MAX_BPT];
  bpttype_t hwbpt_type[MAX_BPT];
  uint32 dr6, dr7;
  void read_fpu_registers(regval_t *values, int clsmask, const void *fptr, size_t step);

public:
  pc_debmod_t();
  void cleanup_hwbpts();
  virtual bool refresh_hwbpts() { return false; }
  int find_hwbpt_slot(ea_t ea, bpttype_t type);
  bool del_hwbpt(ea_t ea, bpttype_t type);
  bool add_hwbpt(bpttype_t type, ea_t ea, int len);
#ifdef __NT__
  virtual bool set_hwbpts(HANDLE hThread);
  ea_t is_hwbpt_triggered(thid_t id);
  virtual HANDLE get_thread_handle(thid_t /*tid*/) { return INVALID_HANDLE_VALUE; }
#endif
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len);
  virtual int finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &stk);
  virtual bool should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea);
  virtual bool preprocess_appcall_cleanup(thid_t tid, call_context_t &ctx);
  virtual int get_regidx(const char *regname, int *clsmask);
};

#endif
