#ifndef __ARM_DEBMOD__
#define __ARM_DEBMOD__

#include "deb_arm.hpp"
#include "debmod.h"

//--------------------------------------------------------------------------
class arm_debmod_t : public debmod_t
{
protected:
  bool is_xscale;
  ea_t databpts[2]; bpttype_t dbptypes[2];
  ea_t codebpts[2]; bpttype_t cbptypes[2];
  int dbcon;

public:
  arm_debmod_t();
  void cleanup_hwbpts();

  bool del_hwbpt(ea_t ea, bpttype_t type);
  bool add_hwbpt(bpttype_t type, ea_t ea, int len);
  ea_t is_hwbpt_triggered(thid_t id);

  inline bool active_databpts(void)
  {
    return databpts[0] != BADADDR || databpts[1] != BADADDR;
  }

  inline bool active_codebpts(void)
  {
    return codebpts[0] != BADADDR || codebpts[1] != BADADDR;
  }

  inline bool active_hwbpts(void)
  {
    return active_databpts() || active_codebpts();
  }

  // overridden base class functions
  virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len);
  virtual int finalize_appcall_stack(call_context_t &ctx, regval_map_t &regs, bytevec_t &stk);
#ifdef ENABLE_LOWCNDS
  virtual int dbg_perform_single_step(debug_event_t *dev, const insn_t &insn);
#endif

  // new virtial functions
  virtual bool init_hwbpt_support() { return true; }
  virtual bool disable_hwbpts() { return false; }
  virtual bool enable_hwbpts() { return false; }

  virtual int get_regidx(const char *regname, int *clsmask);
};

#endif
