#ifdef __NT__
#include <windows.h>
#endif
#include <pro.h>
#include <ua.hpp>
#include "pc_debmod.h"

//--------------------------------------------------------------------------
pc_debmod_t::pc_debmod_t()
{
  static uchar bpt[] = X86_BPT_CODE;
  bpt_code.append(bpt, sizeof(bpt));
  sp_idx = X86_REG_SP;
  pc_idx = X86_REG_IP;
  nregs = X86_NREGS;

  memset(&hwbpt_ea, 0, sizeof(hwbpt_ea));
  dr6 = dr7 = 0;
}

//--------------------------------------------------------------------------
int pc_debmod_t::get_regidx(const char *regname, int *clsmask)
{
  static const char *const regnames[] =
  {
#ifdef __EA64__
   "RAX",
   "RBX",
   "RCX",
   "RDX",
   "RSI",
   "RDI",
   "RBP",
   "RSP",
   "RIP",
   "R8",
   "R9",
   "R10",
   "R11",
   "R12",
   "R13",
   "R14",
   "R15",
#else
   "EAX",
   "EBX",
   "ECX",
   "EDX",
   "ESI",
   "EDI",
   "EBP",
   "ESP",
   "EIP",
#endif
  };

  for ( int i=0; i < qnumber(regnames); i++ )
  {
    if ( stricmp(regname, regnames[i]) == 0 )
    {
      if ( clsmask != NULL )
        *clsmask = X86_RC_GENERAL;
      return R_EAX + i;
    }
  }
  return -1;
}

//--------------------------------------------------------------------------
int idaapi pc_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int /* len */)
{
  if ( type == BPT_SOFT )
    return true;

  return find_hwbpt_slot(ea, type) == -1 ? BPT_TOO_MANY : BPT_OK;
}

//--------------------------------------------------------------------------
// returns -1 if something is wrong
int pc_debmod_t::find_hwbpt_slot(ea_t ea, bpttype_t type)
{
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( hwbpt_ea[i] == ea && hwbpt_type[i] == type ) // another breakpoint is here
      return -1;
    if ( hwbpt_ea[i] == BADADDR ) // empty slot found
      return i;
  }
  return -1;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::add_hwbpt(bpttype_t type, ea_t ea, int len)
{
  int i = find_hwbpt_slot(ea, type);      // get slot number
  if ( i != -1 )
  {
    hwbpt_ea[i] = ea;
    hwbpt_type[i] = type;

    int lenc = 0;                   // length code used by the processor
    //    if ( len == 1 ) lenc = 0;
    if ( len == 2 ) lenc = 1;
    if ( len == 4 ) lenc = 3;

    dr7 |= (1 << (i*2));            // enable local breakpoint
    dr7 |= (type << (16+(i*4)));    // set breakpoint type
    dr7 |= (lenc << (18+(i*4)));    // set breakpoint length

    return refresh_hwbpts();
  }
  return false;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::del_hwbpt(ea_t ea, bpttype_t type)
{
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( hwbpt_ea[i] == ea && hwbpt_type[i] == type )
    {
      hwbpt_ea[i] = BADADDR;            // clean the address
      dr7 &= ~(3 << (i*2));             // clean the enable bits
      dr7 &= ~(0xF << (i*4+16));        // clean the length and type
      return refresh_hwbpts();
    }
  }
  return false;
}


#ifdef __NT__
//--------------------------------------------------------------------------
// Set hardware breakpoint for one thread
bool pc_debmod_t::set_hwbpts(HANDLE hThread)
{
  //  sure_suspend_thread(ti);
  CONTEXT Context;
  Context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

  BOOL ok = GetThreadContext(hThread, &Context);
  if ( !ok )
  {
    deberr("GetThreadContext");
    return false;
  }
  Context.Dr0 = hwbpt_ea[0];
  Context.Dr1 = hwbpt_ea[1];
  Context.Dr2 = hwbpt_ea[2];
  Context.Dr3 = hwbpt_ea[3];
  Context.Dr6 = 0;
  Context.Dr7 = dr7;

  ok = SetThreadContext(hThread, &Context);
  if ( !ok )
  {
    deberr("SetThreadContext");
  }
  //  sure_resume_thread(ti);
  return ok == TRUE;
}

//--------------------------------------------------------------------------
ea_t pc_debmod_t::is_hwbpt_triggered(thid_t id)
{
  CONTEXT Context;
  Context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
  HANDLE h = get_thread_handle(id);
  if ( GetThreadContext(h, &Context) )
  {
    for ( int i=0; i < MAX_BPT; i++ )
    {
      if ( (Context.Dr7 & uint32(1 << (i*2)))
        && (Context.Dr6 & uint32(1 << i)) )  // Local hardware breakpoint 'i'
      {
        ULONG_PTR *dr = NULL;
        switch ( i )
        {
        case 0: dr = &Context.Dr0; break;
        case 1: dr = &Context.Dr1; break;
        case 2: dr = &Context.Dr2; break;
        case 3: dr = &Context.Dr3; break;
        }
        if ( dr == NULL )
          break;
        if ( hwbpt_ea[i] == *dr )
        {
          set_hwbpts(h);             // Clear the status bits
          return hwbpt_ea[i];
        }
        //? TRACING                else
        //                  debdeb("System hardware breakpoint at %08X ???\n", *dr); //?
        // what to do ?:
        // reset it, and continue as if no event were received ?
        // send it to IDA, and let the user setup a "stop on non-debugger hardware breakpoint" option ?
      }
    }
  }
  return BADADDR;
}
#endif // ifdef __NT__

//--------------------------------------------------------------------------
void pc_debmod_t::cleanup_hwbpts()
{
  for ( int i=0; i < MAX_BPT; i++ )
    hwbpt_ea[i] = BADADDR;

  dr6 = 0;
  dr7 = 0x100; // exact local breakpoints
}

//--------------------------------------------------------------------------
int pc_debmod_t::finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &stk)
{
  // pc-specific: add endless loop, so user does not execute unwanted code
  // after manual appcall. we do not really need to write bpt,
  // but it is easy to include it here than skip it
  static const uchar bpt_and_loop[] = { 0xCC, 0xEB, 0xFE };
  stk.append(bpt_and_loop, sizeof(bpt_and_loop));
  return 0;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea)
{
  if ( inherited::should_stop_appcall(tid, event, ea) )
    return true;

  // Check if the current instruction is a "RET" and then dereferences
  // the contents of SP to find the return address. IF it matches, it is
  // time to stop
  regvals_t regs;
  regs.resize(X86_NREGS);
  do
  {
    // Start by reading registers
    if ( dbg_read_registers(tid, X86_RC_GENERAL, regs.begin()) != 1 )
      break;

    // Get the opcodes
    uchar opcode;
    if ( dbg_read_memory((ea_t)regs[X86_REG_IP].ival, &opcode, 1) != 1 )
      break;
    // Check for "RET" and "RET n"
    if ( opcode != 0xC3 && opcode != 0xC2 )
      break;

    // Dereference value at ESP
    ea_t at_sp = BADADDR;
    if ( dbg_read_memory((ea_t)regs[X86_REG_SP].ival, &at_sp, sizeof(at_sp)) != sizeof(at_sp) )
      break;
    return ea == at_sp; // time to stop!
  } while ( false );
  return false;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::preprocess_appcall_cleanup(thid_t, call_context_t &ctx)
{
  // Linux 2.6.24-19 has a bug(?):
  // it doesn't clear trace flag after single-stepping
  // so if we single-step and then make an appcall, we would restore eflags with TF set
  // but next time we resume the program, kernel thinks that TF was set by the user
  // and doesn't clear it, and so our appcall stops immediately
  // to prevent that, we'll always clear trace flag before restoring eflags
  if ( ctx.saved_regs.size() > X86_REG_EFL )
    ctx.saved_regs[X86_REG_EFL].ival &= ~0x100;
  return true; // success
}

//--------------------------------------------------------------------------
int get_x86_reg_class(int idx)
{
  if ( idx >= 0 )
  {
    if ( idx <= R_TAGS )    return X86_RC_FPU;
    if ( idx <= R_SS )      return X86_RC_SEGMENTS;
    if ( idx <= R_EFLAGS )  return X86_RC_GENERAL;
    if ( idx <= R_MXCSR )   return X86_RC_XMM;
    if ( idx <= R_MMX7 )    return X86_RC_MMX;
  }
  return 0; // failed
}

//--------------------------------------------------------------------------
void pc_debmod_t::read_fpu_registers(regval_t *values, int clsmask, const void *fptr, size_t step)
{
  const uchar *vptr = (const uchar *)fptr;
  for ( int i=0; i < 8; i++,vptr+=step )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      regval_t *v = &values[R_ST0+i];
      memcpy(v->fval, vptr, 10);
      v->rvtype = RVT_FLOAT;
    }
    if ( (clsmask & X86_RC_MMX) != 0 )
      values[R_MMX0+i].set_bytes(vptr, 8);
  }
}
