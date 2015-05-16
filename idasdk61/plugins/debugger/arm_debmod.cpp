#include <pro.h>
#include <nalt.hpp>
#include "arm_debmod.h"

#ifdef ENABLE_LOWCNDS
inline bool has_armv5(void) { return true; }
#include "../../module/arm/opinfo.cpp"
#endif

static arm_debmod_t *ssmod;     // pointer to the current debugger module

//--------------------------------------------------------------------------
arm_debmod_t::arm_debmod_t()
{
  static const uchar bpt[] = ARM_BPT_CODE;
  bpt_code.append(bpt, sizeof(bpt));
  sp_idx = 13;
  pc_idx = 15;
  nregs = qnumber(arm_registers);

  is_xscale = false;
  databpts[0] = databpts[1] = BADADDR;
  codebpts[0] = codebpts[1] = BADADDR;
  dbcon = 0;
}


//--------------------------------------------------------------------------
int idaapi arm_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t /*ea*/, int len)
{
  if ( type == BPT_SOFT )
    return BPT_OK;
  // for some reason hardware instructon breakpoints do not work
  if ( type == BPT_EXEC )
    return BPT_BAD_TYPE;
  if ( len > 4 )
    return BPT_BAD_LEN;
  bool ok = type == BPT_EXEC
    ? (codebpts[0] == BADADDR || codebpts[1] == BADADDR)
    : (databpts[0] == BADADDR || databpts[1] == BADADDR);
  return ok ? BPT_OK : BPT_TOO_MANY;
}

//--------------------------------------------------------------------------
bool arm_debmod_t::add_hwbpt(bpttype_t type, ea_t ea, int len)
{
  //  msg("add_hwbpt %d %a %d\n", type, ea, len);
  if ( !is_xscale || len > 4 )
    return false;

  if ( !init_hwbpt_support() )
    return false;

  if ( type == BPT_EXEC )
  {
    if ( codebpts[0] != BADADDR && codebpts[1] != BADADDR )
      return false;
    int slot = codebpts[0] != BADADDR;
    codebpts[slot] = ea;
    cbptypes[slot] = type;
  }
  else
  {
    if ( databpts[0] != BADADDR && databpts[1] != BADADDR )
      return false;
    int slot = databpts[0] != BADADDR;
    int bits;
    switch ( type )
    {
    case BPT_WRITE:
      bits = 1;               // store only
      break;
    case BPT_RDWR:
      bits = 2;               // load/store
      break;
      //      BPT_READ:               // load only
      //        bits = 3;
      //        break;
    default:
      return false;
    }
    databpts[slot] = ea;
    dbptypes[slot] = type;
    dbcon |= bits << (slot*2);
  }
  return enable_hwbpts();
}

//--------------------------------------------------------------------------
bool arm_debmod_t::del_hwbpt(ea_t ea, bpttype_t type)
{
  //  msg("del_hwbpt %a\n", ea);
  if ( databpts[0] == ea && dbptypes[0] == type )
  {
    databpts[0] = BADADDR;
    dbcon &= ~3;
  }
  else if ( databpts[1] == ea && dbptypes[1] == type )
  {
    databpts[1] = BADADDR;
    dbcon &= ~(3<<2);
  }
  else if ( codebpts[0] == ea && cbptypes[0] == type )
  {
    codebpts[0] = BADADDR;
  }
  else if ( codebpts[1] == ea && cbptypes[1] == type )
  {
    codebpts[1] = BADADDR;
  }
  else
  {
    return false;
  }
  return enable_hwbpts();
}

//--------------------------------------------------------------------------
void arm_debmod_t::cleanup_hwbpts()
{
  databpts[0] = BADADDR;
  databpts[1] = BADADDR;
  codebpts[0] = BADADDR;
  codebpts[1] = BADADDR;
  dbcon = 0;
  // disable all bpts
  if ( is_xscale )
    disable_hwbpts();
}

//--------------------------------------------------------------------------
int arm_debmod_t::finalize_appcall_stack(call_context_t &ctx, regval_map_t &regs, bytevec_t &/*stk*/)
{
  regs[14].ival = ctx.ctrl_ea;
  // return addrsize as the adjustment factor to add to sp
  // we do not need the return address, that's why we ignore the first 4
  // bytes of the prepared stack image
  return addrsize;
}

//--------------------------------------------------------------------------
int arm_debmod_t::get_regidx(const char *regname, int *clsmask)
{
// parallel arrays, must be edited together: arm_debmod_t::get_regidx()
//                                           register_info_t arm_registers[]
  static const char *const regnames[] =
  {
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "SP",
    "LR",
    "PC",
    "PSR",
  };

  for ( int i=0; i < qnumber(regnames); i++ )
  {
    if ( stricmp(regname, regnames[i]) == 0 )
    {
      if ( clsmask != NULL )
        *clsmask = ARM_RC_GENERAL;
      return R_R0 + i;
    }
  }
  return -1;
}

#ifdef ENABLE_LOWCNDS
//--------------------------------------------------------------------------
static const regval_t &idaapi arm_getreg(const char *name, const regval_t *regvals)
{
  int idx = ssmod->get_regidx(name, NULL);
  QASSERT(30182, idx >= 0 && idx < ssmod->nregs);
  return regvals[idx];
}

//--------------------------------------------------------------------------
static uint32 idaapi arm_get_long(ea_t ea)
{
  uint32 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//--------------------------------------------------------------------------
static uint16 idaapi arm_get_word(ea_t ea)
{
  uint16 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//--------------------------------------------------------------------------
static uint8 idaapi arm_get_byte(ea_t ea)
{
  uint8 v = -1;
  ssmod->dbg_read_memory(ea, &v, sizeof(v));
  return v;
}

//----------------------------------------------------------------------
// stripped down version of get_dtyp_size()
static size_t idaapi arm_get_dtyp_size(char dtype)
{
  switch ( dtype )
  {
    case dt_byte:    return 1;          // 8 bit
    case dt_word:    return 2;          // 16 bit
    case dt_dword:
    case dt_float:   return 4;          // 4 byte
    case dt_qword:
    case dt_double:  return 8;          // 8 byte
  }
  return 0;
}

//--------------------------------------------------------------------------
// since arm does not have a single step facility, we have to emulate it
// with a temporary breakpoint.
int arm_debmod_t::dbg_perform_single_step(debug_event_t *dev, const insn_t &insn)
{
  // read register values
  regvals_t values;
  values.resize(nregs);
  int code = dbg_read_registers(dev->tid, ARM_RC_GENERAL, values.begin());
  if ( code <= 0 )
    return code;

  static const opinfo_helpers_t oh =
  {
    arm_getreg,
    arm_get_byte,
    arm_get_word,
    arm_get_long,
    arm_get_dtyp_size,
    NULL,               // InstrIsSet not needed
  };

  // calculate the address of the next executed instruction
  lock_begin();
  ssmod = this;
  ea_t next = calc_next_exec_insn(insn, values.begin(), oh);
  ssmod = NULL;
  lock_end();

  // BADADDR means that the execution flow is linear
  if ( next == BADADDR )
  {
    next = insn.ea + insn.size;
    if ( (values[R_PSR].ival & BIT5) != 0 ) // thumb?
      next |= 1;
  }

  // safety check: self jumping instruction can not be single stepped
  if ( (next & ~1) == insn.ea )
    return 0;

  // add a breakpoint there
  update_bpt_info_t ubi;
  ubi.ea = next;
  ubi.type = BPT_SOFT;
  ubi.code = 0;
  code = dbg_update_bpts(&ubi, 1, 0);
  if ( code <= 0 )
    return code;

  code = resume_app_and_get_event(dev);

  // clean up: delete the temporary breakpoint
  ubi.ea &= ~1; // del_bpt requires an even address
  if ( dbg_update_bpts(&ubi, 0, 1) <= 0 )
  {
    msg("%a: failed to remove single step bpt?!\n", ubi.ea);
    if ( code > 0 )
      code = 0;
  }
  // the caller expects to see STEP after us:
  if ( code > 0 )
    dev->eid = STEP;
  return code;
}

#endif
