#include "mac_debmod.h"
#include "consts.h"
#include <sys/utsname.h>
#include <mach/mach_vm.h>
#ifndef __arm__
#include <crt_externs.h>
#endif
#include "../../ldr/mach-o/common.h"

#ifdef __arm__
#define THREAD_STATE_NONE 5
#elif defined (__i386__) || defined(__x86_64__)
#define THREAD_STATE_NONE 13
#else
#error unknown platform
#endif

//#define DEBUG_MAC_DEBUGGER
#define local static  // static is used for static data items

#ifdef __arm__
#define BPT_CODE_SIZE ARM_BPT_SIZE
static const uchar dyld_opcode[BPT_CODE_SIZE] = { 0x1E, 0xFF, 0x2F, 0xE1 };
inline void cleanup_hwbpts(void) {}
#else
#define BPT_CODE_SIZE X86_BPT_SIZE
static const uchar dyld_opcode[BPT_CODE_SIZE] = { 0x55 };
#endif

mac_debmod_t::stored_signals_t mac_debmod_t::pending_signals;

mac_debmod_t::mac_debmod_t()
{
#ifdef __arm__
  // use iphone specific bpt code
  static const uchar bpt[4] = { 0x70, 0x00, 0x20, 0xE1 };
  bpt_code = bytevec_t(bpt, 4);
#endif
  exc_port = MACH_PORT_NULL;
  struct utsname name;
  is_leopard = false;
  if ( uname(&name) == 0 )
  {
//    msg("version=%s release=%s\n", name.version, name.release);
    // release: 9.2.2
    int major, minor, build;
    if ( sscanf(name.release, "%d.%d.%d", &major, &minor, &build) == 3 )
    {
//      msg("VER=%d.%d.%d\n", major, minor, build);
      is_leopard = major >= 9;
    }
  }
//  msg("is_leopard: %d\n", is_leopard);
}

mac_debmod_t::~mac_debmod_t()
{
}

local asize_t calc_image_size(const char *fname, ea_t *expected_base);

extern boolean_t exc_server(
                mach_msg_header_t *InHeadP,
                mach_msg_header_t *OutHeadP);

#define COMPLAIN_IF_FAILED(name)                        \
      if ( err != KERN_SUCCESS )                        \
        msg(name ": %s\n", mach_error_string(err))

//--------------------------------------------------------------------------
local const char *get_ptrace_name(int request)
{
  switch ( request )
  {
    case PT_TRACE_ME:    return "PT_TRACE_ME";    /* child declares it's being traced */
    case PT_READ_I:      return "PT_READ_I";      /* read word in child's I space */
    case PT_READ_D:      return "PT_READ_D";      /* read word in child's D space */
    case PT_READ_U:      return "PT_READ_U";      /* read word in child's user structure */
    case PT_WRITE_I:     return "PT_WRITE_I";     /* write word in child's I space */
    case PT_WRITE_D:     return "PT_WRITE_D";     /* write word in child's D space */
    case PT_WRITE_U:     return "PT_WRITE_U";     /* write word in child's user structure */
    case PT_CONTINUE:    return "PT_CONTINUE";    /* continue the child */
    case PT_KILL:        return "PT_KILL";        /* kill the child process */
    case PT_STEP:        return "PT_STEP";        /* single step the child */
    case PT_ATTACH:      return "PT_ATTACH";      /* trace some running process */
    case PT_DETACH:      return "PT_DETACH";      /* stop tracing a process */
    case PT_SIGEXC:      return "PT_SIGEXC";      /* signals as exceptions for current_proc */
    case PT_THUPDATE:    return "PT_THUPDATE";    /* signal for thread# */
    case PT_ATTACHEXC:   return "PT_ATTACHEXC";   /* attach to running process with signal exception */
    case PT_FORCEQUOTA:  return "PT_FORCEQUOTA";  /* Enforce quota for root */
    case PT_DENY_ATTACH: return "PT_DENY_ATTACH";
  }
  return "?";
}

//--------------------------------------------------------------------------
int32 mac_debmod_t::qptrace(int request, pid_t pid, caddr_t addr, int data)
{
  int32 code = ptrace(request, pid, addr, data);
  int saved_errno = errno;
//  if ( (request == PT_CONTINUE || request == PT_STEP) && int(addr) == 1 )
//    addr = (caddr_t)get_ip(pid);
  debdeb("%s(%u, 0x%p, 0x%X) => 0x%X", get_ptrace_name(request), pid, addr, data, code);
  if ( code == -1 )
    deberr("");
  else
    debdeb("\n");
  errno = saved_errno;
  return code;
}

//--------------------------------------------------------------------------
ida_thread_info_t *mac_debmod_t::get_thread(thid_t tid)
{
  threads_t::iterator p = threads.find(tid);
  if ( p == threads.end() )
    return NULL;
  return &p->second;
}

//--------------------------------------------------------------------------
uval_t mac_debmod_t::get_dr(thid_t tid, int idx)
{
#if !defined (__i386__) && !defined(__x86_64__)
  return 0;
#else
  machine_debug_state_t dr_regs;

#if __DARWIN_UNIX03
#define dr0 __dr0
#define dr1 __dr1
#define dr2 __dr2
#define dr3 __dr3
#define dr4 __dr4
#define dr5 __dr5
#define dr6 __dr6
#define dr7 __dr7
#endif

  if ( !get_debug_state(tid, &dr_regs) )
    return 0;

  switch ( idx )
  {
    case 0:
      return dr_regs.dr0;
    case 1:
      return dr_regs.dr1;
    case 2:
      return dr_regs.dr2;
    case 3:
      return dr_regs.dr3;
    case 4:
      return dr_regs.dr4;
    case 5:
      return dr_regs.dr5;
    case 6:
      return dr_regs.dr6;
    case 7:
      return dr_regs.dr7;
  }
  return 0;
#endif
}

//--------------------------------------------------------------------------
static void set_dr(machine_debug_state_t & dr_regs, int idx, uval_t value)
{
  switch ( idx )
  {
    case 0:
      dr_regs.dr0 = value;
      break;
    case 1:
      dr_regs.dr1 = value;
      break;
    case 2:
      dr_regs.dr2 = value;
      break;
    case 3:
      dr_regs.dr3 = value;
      break;
    case 4:
      dr_regs.dr4 = value;
      break;
    case 5:
      dr_regs.dr5 = value;
      break;
    case 6:
      dr_regs.dr6 = value;
      break;
    case 7:
      dr_regs.dr7 = value;
      break;
  }
}

//--------------------------------------------------------------------------
bool mac_debmod_t::set_dr(thid_t tid, int idx, uval_t value)
{
#if !defined (__i386__) && !defined(__x86_64__)
  return false;
#else
  machine_debug_state_t dr_regs;

  if ( !get_debug_state(tid, &dr_regs) )
    return false;

  ::set_dr(dr_regs, idx, value);

  return set_debug_state(tid, &dr_regs);
#undef ds
#undef dr0
#undef dr1
#undef dr2
#undef dr3
#undef dr4
#undef dr5
#undef dr6
#undef dr7
#endif
}

//--------------------------------------------------------------------------
ea_t mac_debmod_t::get_ip(thid_t tid)
{
  machine_thread_state_t state;
  if ( !get_thread_state(tid, &state) )
    return BADADDR;
#ifdef __arm__
  return state.__pc;
#else
  return state.__eip;
#endif
}

//--------------------------------------------------------------------------
local kern_return_t qthread_setsinglestep(ida_thread_info_t &ti)
{
#ifdef __arm__
  QASSERT(30072, !ti.single_step);
  return KERN_SUCCESS;
#else

  machine_thread_state_t cpu;
  mach_port_t port = ti.port;
  mach_msg_type_number_t stateCount = IDA_THREAD_STATE_COUNT;
  kern_return_t err = thread_get_state(
                        port,
                        IDA_THREAD_STATE,
                        (thread_state_t)&cpu,
                        &stateCount);
  QASSERT(30073, stateCount == IDA_THREAD_STATE_COUNT);
//  COMPLAIN_IF_FAILED("thread_get_state");
  if ( err != KERN_SUCCESS )
    return err;

  ti.asked_step = ti.single_step;
  int bit = ti.single_step ? EFLAGS_TRAP_FLAG : 0;
  if ( ((cpu.__eflags ^ bit) & EFLAGS_TRAP_FLAG) == 0 )
    return KERN_SUCCESS;

  if ( ti.single_step )
    cpu.__eflags |= EFLAGS_TRAP_FLAG;
  else
    cpu.__eflags &= ~EFLAGS_TRAP_FLAG;

  err = thread_set_state(port,
                         IDA_THREAD_STATE,
                         (thread_state_t)&cpu,
                         stateCount);
  QASSERT(30074, stateCount == IDA_THREAD_STATE_COUNT);
//  COMPLAIN_IF_FAILED("thread_set_state");
  return err;
#endif
}

//--------------------------------------------------------------------------
void my_mach_msg_t::display(const char *header)
{
#ifdef DEBUG_MAC_DEBUGGER
  msg("%s\n", header);
  msg("         msgh_bits       : 0x%x\n", hdr.msgh_bits);
  msg("         msgh_size       : 0x%x\n", hdr.msgh_size);
  msg("         msgh_remote_port: %d\n", hdr.msgh_remote_port);
  msg("         msgh_local_port : %d\n", hdr.msgh_local_port);
  msg("         msgh_reserved   : %d\n", hdr.msgh_reserved);
  msg("         msgh_id         : 0x%x\n", hdr.msgh_id);
  if ( hdr.msgh_size > 24 )
  {
    const uint32 *buf = ((uint32 *) this) + 6;
    msg("         data            :");
    int cnt = hdr.msgh_size / 4 - 6;
    for ( int i=0; i < cnt; i++ )
      msg(" %08x", buf[i]);
    msg("\n");
  }
#else
  qnotused(header);
#endif
}

// this function won't be called but is declared to avoid linker complaints
kern_return_t catch_exception_raise_state(
        mach_port_t /*exception_port*/,
        exception_type_t /*exception*/,
        const exception_data_t /*code*/,
        mach_msg_type_number_t /*codeCnt*/,
        int * /*flavor*/,
        const thread_state_t /*old_state*/,
        mach_msg_type_number_t /*old_stateCnt*/,
        thread_state_t /*new_state*/,
        mach_msg_type_number_t * /*new_stateCnt*/)
{
  return KERN_FAILURE;
}

// this function won't be called but is declared to avoid linker complaints
kern_return_t catch_exception_raise_state_identity(
        mach_port_t /*exception_port*/,
        mach_port_t /*thread*/,
        mach_port_t /*task*/,
        exception_type_t /*exception*/,
        exception_data_t /*code*/,
        mach_msg_type_number_t /*codeCnt*/,
        int * /*flavor*/,
        thread_state_t /*old_state*/,
        mach_msg_type_number_t /*old_stateCnt*/,
        thread_state_t /*new_state*/,
        mach_msg_type_number_t * /*new_stateCnt*/)
{
  return KERN_FAILURE;
}

// this function will be called by exc_server()
// we use exc_server() for 2 things:
//      - to decode mach message and extract exception information
//      - to actually handle the exception when we resume execution

static bool parse_mach_message;
static bool mask_exception;
static mach_exception_info_t local_exinf;

kern_return_t catch_exception_raise(mach_port_t /*exception_port*/,
                      mach_port_t thread,
                      mach_port_t task,
                      exception_type_t exception,
                      exception_data_t code_vector,
                      mach_msg_type_number_t code_count)
{
  if ( parse_mach_message )
  {
    local_exinf.task_port      = task;
    local_exinf.thread_port    = thread;
    local_exinf.exception_type = exception;
    local_exinf.exception_data = code_vector;
    local_exinf.data_count     = code_count;
    return KERN_SUCCESS;
  }

  // handle the exception for real
  if ( mask_exception )
    return KERN_SUCCESS;

  return KERN_FAILURE;
}

//--------------------------------------------------------------------------
// event->tid is filled upon entry
// returns true: created a new event in 'event'
bool mac_debmod_t::handle_signal(
        int code,
        debug_event_t *event,
        block_type_t block,
        const my_mach_msg_t *excmsg)
{
  ida_thread_info_t *ti = get_thread(event->tid);
  if ( ti == NULL )
  { // there is a rare race condition when a thread gets created just after
    // last call to update_threads(). check it once more
    update_threads();
    ti = get_thread(event->tid);
  }
  QASSERT(30075, ti != NULL);

  ti->block = block;
  if ( block == bl_exception )
    ti->excmsg = *excmsg;

  event->pid          = pid;
  event->handled      = false;
  event->ea           = get_ip(event->tid);
  event->eid          = EXCEPTION;
  event->exc.code     = code;
  event->exc.can_cont = true;
  event->exc.ea       = BADADDR;

  if ( code == SIGSTOP )
  {
    if ( ti->pending_sigstop )
    {
      debdeb("got pending SIGSTOP, good!\n");
      ti->pending_sigstop = false;
      if ( ti->asked_step )
      { // not to lose an asked single step, do it again
        ti->single_step = true;
        qthread_setsinglestep(*ti);
      }
      my_resume_thread(*ti);
      return false;
    }
    if ( run_state == rs_pausing )
    {
      debdeb("successfully paused the process, good!\n");
      run_state = rs_running;
      event->eid = NO_EVENT;
    }
  }
  if ( event->eid == EXCEPTION )
  {
    bool suspend;
    const exception_info_t *ei = find_exception(code);
    if ( ei != NULL )
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got %s signal (%s)", ei->name.c_str(), ei->desc.c_str());
      suspend = ei->break_on();
      event->handled = ei->handle();
      if ( code == SIGKILL && run_state >= rs_exiting )
      {
        event->handled = false;
        suspend = false;
      }
    }
    else
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got unknown signal #%d", code);
      suspend = true;
    }
    if ( code == SIGTRAP )
    {
      // Check for hardware breakpoints first.
      // If we do not handle a hwbpt immediately, dr6 stays set and
      // we discover it later, after resuming. This breaks everything.
      ea_t bpt_ea = event->ea;
#if defined (__i386__) || defined(__x86_64__)
      uval_t dr6 = get_dr(event->tid, 6);
      for ( int i=0; i < MAX_BPT; i++ )
      {
        if ( (dr6 & (1<<i)) != 0 )  // Hardware breakpoint 'i'
        {
          if ( hwbpt_ea[i] == get_dr(event->tid, i) )
          {
            event->eid     = BREAKPOINT;
            event->bpt.hea = hwbpt_ea[i];
            event->bpt.kea = BADADDR;
            set_dr(event->tid, 6, 0); // Clear the status bits
            code = 0;
            break;
          }
        }
      }
      // x86 returns EIP pointing to the next byte after CC. Take it into account:
      bpt_ea--;
#endif
      if ( code != 0 )
      {
        if ( ti->asked_step )
        {
          event->eid = STEP;
          code = 0;
        }
        else if ( bpts.find(bpt_ea) != bpts.end() )
        {
          event->eid     = BREAKPOINT;
          event->bpt.hea = BADADDR;
          event->bpt.kea = BADADDR;
          event->ea = bpt_ea;
          code = 0;
        }
      }
    }
    if ( event->handled )
      code = 0;
    ti->child_signum = code;
    if ( run_state != rs_pausing && evaluate_and_handle_lowcnd(event) )
      return false;
    if ( !suspend && event->eid == EXCEPTION )
    {
      my_resume_thread(*ti);
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::check_for_exception(
        int timeout,
        mach_exception_info_t *exinf,
        my_mach_msg_t *excmsg)
{
  if ( exited() )
    return false;

  int flags = MACH_RCV_MSG;
  if ( timeout != -1 )
    flags |= MACH_RCV_TIMEOUT;
  else
    timeout = MACH_MSG_TIMEOUT_NONE;

//  msg("check for exception, timeout %d, runstate=%d\n", timeout, run_state);

  kern_return_t err = mach_msg(&excmsg->hdr,
                               flags,
                               0,               // send size
                               sizeof(my_mach_msg_t),
                               exc_port,
                               timeout,         // timeout
                               MACH_PORT_NULL); // notify port
  if ( err != MACH_MSG_SUCCESS )
    return false;
  if ( excmsg->hdr.msgh_remote_port == -1 ) // remote task alive?
    return false;
  task_suspend(task);
  excmsg->display("received an exception, details:");

  lock_begin();
  {
    my_mach_msg_t reply_msg;
    parse_mach_message = true;
    memset(&local_exinf, 0, sizeof(local_exinf));
    bool ok = exc_server(&excmsg->hdr, &reply_msg.hdr);
    QASSERT(30076, ok);
    *exinf = local_exinf;
  }
  lock_end();
  return true;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::my_resume_thread(ida_thread_info_t &ti)
{
  bool ok = true;
  // setsinglestep may fail after kill(), ignore the return code
  qthread_setsinglestep(ti);
  switch ( ti.block )
  {
    case bl_signal:
      if ( in_ptrace )
      {
        // we detach from the process and will handle the rest
        // using mach api
#if __arm__
//bool ok = task_resume(task) == KERN_SUCCESS;
        int pt = run_state >= rs_exiting ? PT_CONTINUE : PT_DETACH;
        ok = qptrace(pt, pid, caddr_t(1), 0) == 0;
        in_ptrace = false;
#else
        int pt = ti.single_step ? PT_STEP : PT_CONTINUE;
        ok = qptrace(pt, pid, caddr_t(1), ti.child_signum) == 0;
#endif
      }
      else
      {
        kern_return_t err = thread_resume(ti.tid);
        COMPLAIN_IF_FAILED("thread_resume");
      }
      break;

    case bl_exception:
      // handle the exception with exc_server
      my_mach_msg_t reply_msg;
      lock_begin();
      {
        parse_mach_message = false;
        mask_exception = ti.child_signum == 0;
        ok = exc_server(&ti.excmsg.hdr, &reply_msg.hdr);
      }
      lock_end();

      if ( ok )
      {
        kern_return_t err;
        err = mach_msg(&reply_msg.hdr,
                       MACH_SEND_MSG,
                       reply_msg.hdr.msgh_size, // send size
                       0,
                       reply_msg.hdr.msgh_remote_port,
                       0,                  // timeout
                       MACH_PORT_NULL); // notify port
        COMPLAIN_IF_FAILED("mach_msg");
        ok = (err == KERN_SUCCESS);
      }
      task_resume(task);
      break;

    default:  // nothing to do, the process is already running
      break;
  }
  // syscalls may fail after SIGKILL, do not check the error code
  //QASSERT(30077, ok);
  ti.block = bl_none;
  ti.single_step = false;
  return true;
}

//--------------------------------------------------------------------------
int mac_debmod_t::exception_to_signal(const mach_exception_info_t *exinf)
{
  int code = exinf->exception_data[0];
  int sig = 0;
  switch( exinf->exception_type )
  {
    case EXC_BAD_ACCESS:
      if ( code == KERN_INVALID_ADDRESS )
        sig = SIGSEGV;
      else
        sig = SIGBUS;
      break;

    case EXC_BAD_INSTRUCTION:
      sig = SIGILL;
      break;

    case EXC_ARITHMETIC:
      sig = SIGFPE;
      break;

    case EXC_EMULATION:
      sig = SIGEMT;
      break;

    case EXC_SOFTWARE:
      switch ( code )
      {
//        case EXC_UNIX_BAD_SYSCALL:
//          sig = SIGSYS;
//          break;
//        case EXC_UNIX_BAD_PIPE:
//          sig = SIGPIPE;
//          break;
//        case EXC_UNIX_ABORT:
//          sig = SIGABRT;
//          break;
        case EXC_SOFT_SIGNAL:
          sig = SIGKILL;
          break;
      }
      break;

    case EXC_BREAKPOINT:
      sig = SIGTRAP;
      break;
  }
  return sig;
}

//--------------------------------------------------------------------------
// check if there are any pending signals
bool mac_debmod_t::retrieve_pending_signal(int *status)
{
  bool has_pending_signal = false;
  if ( !pending_signals.empty() )
  {
    lock_begin();
    for ( stored_signals_t::iterator p=pending_signals.begin();
          p != pending_signals.end();
          ++p )
    {
      if ( p->pid == pid )
      {
        *status = p->status;
        pending_signals.erase(p);
        has_pending_signal = true;
        break;
      }
    }
    lock_end();
  }

  return has_pending_signal;
}

//--------------------------------------------------------------------------
pid_t mac_debmod_t::qwait(int *status, bool hang)
{
  pid_t ret;
  lock_begin();
  if ( retrieve_pending_signal(status) )
  {
    ret = pid;
  }
  else
  {
    int flags = hang ? 0 : WNOHANG;
    ret = waitpid(pid, status, flags);
    if ( ret != pid && ret != 0 && ret != -1 )
    {
      stored_signal_t &ss = pending_signals.push_back();
      ss.pid = pid;
      ss.status = *status;
    }
  }
  lock_end();
  return ret;
}

//--------------------------------------------------------------------------
// timeout in milliseconds
// 0 - no timeout, return immediately
// -1 - wait forever
void mac_debmod_t::get_debug_events(int timeout_ms)
{
//  msg("waiting, numpend=%lu timeout=%d...\n", events.size(), timeout_ms);
//  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
//    if ( p->second.blocked() )
//      msg("%d: blocked\n", p->first);

  int status;
  debug_event_t event;
  if ( !retrieve_pending_signal(&status) )
  {
    update_threads();

    // receive info about any exceptions in the program
    // an arbitrary limit of 32 loop iterations is needed if low level breakpoints
    // or automatically handled exceptions occur too often.
    my_mach_msg_t excmsg;
    mach_exception_info_t exinf;
    for ( int i=0;
          i < 32 && check_for_exception(timeout_ms, &exinf, &excmsg);
          i++ )
    {
      event.tid = exinf.thread_port;
      int sig = exception_to_signal(&exinf);
//      msg("got exception for tid=%d sig=%d %s\n", event.tid, sig, strsignal(sig));
      if ( handle_signal(sig, &event, bl_exception, &excmsg) )
      {
        events.enqueue(event, IN_BACK);
        // do not break!
        // collect all exceptions and convert them to debug_event_t
        // if there was a breakpoint hit, convert it to debug_event_t as soon as
        // possible. if we pass control to the ida kernel, it may remove the
        // breakpoint and we won't recognize our breakpoint in the exception.
        // break;
      }
      timeout_ms = 0;
    }
    if ( !events.empty() )
      return;

    // check the signals
    pid_t wpid = qwait(&status, false);
    if ( wpid == -1 || wpid == 0 )
      return;
  }

  event.tid = maintid();
  if ( WIFSTOPPED(status) )
  {
    int code = WSTOPSIG(status);
//    msg("SIGNAL %d: %s (stopped)\n", code, strsignal(code));
    if ( !handle_signal(code, &event, bl_signal, NULL) )
      return;
  }
  else
  {
    if ( WIFSIGNALED(status) )
    {
//      msg("SIGNAL: %s (terminated)\n", strsignal(WSTOPSIG(status)));
      event.exit_code = WSTOPSIG(status);
    }
    else
    {
//      msg("SIGNAL: %d (exited)\n", WEXITSTATUS(status));
      event.exit_code = WEXITSTATUS(status);
    }
    event.pid     = pid;
    event.ea      = BADADDR;
    event.handled = true;
    event.eid     = PROCESS_EXIT;
    run_state = rs_exited;
  }
//  msg("low got event: %s\n", debug_event_str(&event));
  events.enqueue(event, IN_BACK);
}

//--------------------------------------------------------------------------
void mac_debmod_t::handle_dyld_bpt(const debug_event_t *event)
{
//  msg("handle dyld bpt, ea=%a\n", event->ea);
  update_dylib();

  machine_thread_state_t state;
  bool ok = get_thread_state(event->tid, &state);
  QASSERT(30078, ok);

#ifdef __arm__
  // emulate bx lr. we assume the (lr & 1) == 0
  QASSERT(30079, (state.__lr & 1) == 0);
  state.__pc = state.__lr;
#else
  // emulate push ebp
  state.__esp -= addrsize;
  kern_return_t err = write_mem(state.__esp, &state.__ebp, addrsize);
  QASSERT(30080, err == KERN_SUCCESS);
#endif

  ok = set_thread_state(event->tid, &state);
  QASSERT(30081, ok);

  dbg_continue_after_event(event);
}

//--------------------------------------------------------------------------
gdecode_t idaapi mac_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  while ( true )
  {
    // are there any pending events?
    if ( events.retrieve(event) )
    {
      switch ( event->eid )
      {
        // if this is dyld bpt, do not return it to ida
        case BREAKPOINT:
          if ( event->ea == dyri.dyld_notify )
          {
            handle_dyld_bpt(event);
            continue;
          }
          break;

        case PROCESS_ATTACH:
          attaching = false;        // finally attached to it
          break;

        case THREAD_EXIT:           // thread completely disappeared,
                                    // can remove it from the list
          threads.erase(event->tid);
          break;

        default:
          break;
      }
      last_event = *event;
      if ( debug_debugger )
        debdeb("GDE1: %s\n", debug_event_str(event));
      return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
    }

    if ( exited() )
      break;

    get_debug_events(timeout_ms);
    if ( events.empty() )
      break;
  }
  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::suspend_all_threads(void)
{
  /* Suspend the target process */
  kern_return_t err = task_suspend(task);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
void mac_debmod_t::resume_all_threads()
{
  kern_return_t err = task_resume(task);
  QASSERT(30082, err == KERN_SUCCESS);
}

//--------------------------------------------------------------------------
void mac_debmod_t::unblock_all_threads(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    my_resume_thread(p->second);
}

//--------------------------------------------------------------------------
int mac_debmod_t::dbg_freeze_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( p->first != tid )
    {
      kern_return_t err = thread_suspend(p->first);
      if ( err != KERN_SUCCESS )
        return 0;
    }
  }
  return 1;
}

//--------------------------------------------------------------------------
int mac_debmod_t::dbg_thaw_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( p->first != tid )
    {
      kern_return_t err = thread_resume(p->first);
      if ( err != KERN_SUCCESS )
        return 0;
    }
  }
  return 1;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( exited() )
  { // reap the last child status
    if ( pid != -1 )
    {
      debdeb("%d: reaping the child status\n", pid);
      int status;
      qwait(&status, true);
      pid = -1;
    }
    return true;
  }

  if ( event == NULL )
    return 0;

  ida_thread_info_t *ti = get_thread(event->tid);
  if ( debug_debugger )
  {
    debdeb("continue after event %s (%d pending, block type %d, sig#=%d)\n",
           debug_event_str(event),
           int(events.size()),
           ti == NULL ? 0 : ti->block,
           ti == NULL ? 0 : ti->child_signum);
  }

  if ( event->eid != THREAD_START
    && event->eid != THREAD_EXIT
    && event->eid != LIBRARY_LOAD
    && event->eid != LIBRARY_UNLOAD
    && (event->eid != EXCEPTION || event->handled) )
  {
    QASSERT(30083, ti != NULL);
    if ( ti->child_signum != SIGKILL ) // never mask SIGKILL
    {
      debdeb("event->eid=%d, erasing child_signum\n", event->eid);
      ti->child_signum = 0;
    }
  }

  if ( events.empty() && !attaching )
  {
    // if the event queue is empty, we can resume all blocked threads
    // here we resume only the threads blocked because of exceptions or signals
    // if the debugger kernel has suspended a thread for another reason, it
    // will stay suspended.
#ifdef __arm__ // if we suspended all threads, the correct way to unblock them is to
    if ( run_state == rs_suspended )
    {
      run_state = rs_running;
      resume_all_threads();
    }
#endif
    if ( run_state == rs_pausing )
    { // no need to stop anymore, plan to ignore the sigstop
      ti->pending_sigstop = true;
      run_state = rs_running;
    }
    unblock_all_threads();
  }
  return 1;
}

//--------------------------------------------------------------------------
kern_return_t mac_debmod_t::read_mem(ea_t ea, void *buffer, int size)
{
  if ( ea == 0 )
    return KERN_INVALID_ADDRESS;
  mach_vm_size_t data_count = 0;
  kern_return_t err = mach_vm_read_overwrite(task, ea, size, (vm_address_t)buffer, &data_count);
  if ( err == KERN_SUCCESS && data_count != size )
    err = KERN_INVALID_ADDRESS;
  if ( err != KERN_SUCCESS )
    debdeb("vm_read %d: ea=%a size=%d => (%s)\n", task, ea, size, mach_error_string(err));
//  show_hex(buffer, size, "data:\n");
  return err;
}

//--------------------------------------------------------------------------
kern_return_t mac_debmod_t::write_mem(ea_t ea, void *buffer, int size)
{
  kern_return_t err;
/*  vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
printf("buffer=%x size=%x\n", buffer, size);
  err = vm_machine_attribute (mach_task_self(), (vm_offset_t)buffer, size, MATTR_CACHE, &flush);
  QASSERT(30084, err == KERN_SUCCESS); // must succeed since it is our memory
*/
  err = mach_vm_write(task, ea, (vm_offset_t)buffer, size);
  if ( err != KERN_SUCCESS && err != KERN_PROTECTION_FAILURE )
    debdeb("vm_write %d: ea=%a, size=%d => %s\n", task, ea, size, mach_error_string(err));
  return err;
}

//--------------------------------------------------------------------------
inline bool is_shared_address(ea_t ea)
{
  ea &= GLOBAL_SHARED_SEGMENT_MASK;
  return ea == GLOBAL_SHARED_TEXT_SEGMENT || ea == GLOBAL_SHARED_DATA_SEGMENT;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::xfer_page(ea_t ea, void *buffer, int size, bool write)
{
  // get old memory protection
  mach_vm_address_t r_start = ea;
  mach_vm_size_t r_size;
  mach_port_t r_object_name;
  vm_region_basic_info_data_64_t r_data;
  mach_msg_type_number_t r_info_size = VM_REGION_BASIC_INFO_COUNT_64;
  kern_return_t err = mach_vm_region(task, &r_start, &r_size,
                                VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&r_data, &r_info_size,
                                &r_object_name);
  if ( err != KERN_SUCCESS )
  {
    // this call fails for the commpage segment
    debdeb("%" FMT_64 "x: vm_region: %s\n", r_start, mach_error_string(err));
    return false;
  }

  if ( r_start > ea )
  {
    dmsg("%a: region start is higher %" FMT_64 "x\n", ea, r_start);
    return false;
  }

//  dmsg("%a: current=%d max=%d\n", ea, r_data.protection, r_data.max_protection);
  int bit = write ? VM_PROT_WRITE : VM_PROT_READ;
  // max permissions do not allow it? fail
  // strangely enough the kernel allows us to set any protection,
  // including protections bigger than max_protection. but after that it crashes
  // we have to verify it ourselves here.
  if ( (r_data.max_protection & bit) == 0 )
    return false;

  if ( (r_data.protection & bit) == 0 )
  {
    bit |= r_data.protection;
    // set the desired bit
    err = KERN_FAILURE;
    if ( write )
    {
      if ( is_shared_address(r_start) )
      {
#ifndef __arm__
        if ( is_leopard )
          return false; // can not modify shared areas under leopard
#endif
        bit |= VM_PROT_COPY;
      }
//      dmsg("shared: %d b2=%x\n", is_shared_address(r_start), bit);
      err = mach_vm_protect(task, r_start, r_size, 0, bit);
      if ( err != KERN_SUCCESS && (bit & VM_PROT_COPY) == 0 )
      {
        bit |= VM_PROT_COPY; // if failed, make a copy of the page
        goto LASTPROT;
      }
    }
    else
    {
LASTPROT:
      err = mach_vm_protect(task, r_start, r_size, 0, bit);
    }
    if ( err != KERN_SUCCESS )
    {
      debdeb("%d: could not set %s permission at %" FMT_64 "x\n",
                        task, write ? "write" : "read", r_start);
      return false;
    }
  }

  // attempt to xfer
  if ( write )
    err = write_mem(ea, buffer, size);
  else
    err = read_mem(ea, buffer, size);

  bool ok = (err == KERN_SUCCESS);
#if 1
  if ( ok && write )
  {
    // flush the cache
//    vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
    vm_machine_attribute_val_t flush = MATTR_VAL_OFF;
    err = mach_vm_machine_attribute(task, r_start, r_size, MATTR_CACHE, &flush);
    if ( err != KERN_SUCCESS )
    {
      static bool complained = false;
      if ( !complained )
      {
        complained = true;
        dmsg("Unable to flush data/instruction cache ea=0x%" FMT_64 "x size=%ld: %s\n",
                        r_start, long(r_size), mach_error_string(err));
      }
    }
    else
    {
//      msg("Success cache ea=0x%" FMT_64 "x size=%d\n", r_start, r_size);
    }
  }
#endif
  // restore old memory protection
  if ( (r_data.protection & bit) == 0 )
  {
    err = mach_vm_protect(task, r_start, r_size, 0, r_data.protection);
    QASSERT(30085, err == KERN_SUCCESS);
  }
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::xfer_memory(ea_t ea, void *buffer, int size, bool write)
{
  return xfer_page(ea, buffer, size, write);
}

//--------------------------------------------------------------------------
int mac_debmod_t::_read_memory(ea_t ea, void *buffer, int size, bool suspend)
{
  if ( exited() || pid <= 0 || size <= 0 )
    return -1;

//  debdeb("READ MEMORY %a:%d: START\n", ea, size);
  // stop all threads before accessing the process memory
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

//  bool ok = xfer_memory(ea, buffer, size, false);
  kern_return_t err = read_mem(ea, buffer, size);
  bool ok = err == KERN_SUCCESS;

  if ( suspend )
    resume_all_threads();
//  debdeb("READ MEMORY %a:%d: END\n", ea, size);
  return ok ? size : 0;
}

//--------------------------------------------------------------------------
int mac_debmod_t::_write_memory(ea_t ea, const void *buffer, int size, bool suspend)
{
  if ( exited() || pid <= 0 || size <= 0 )
    return -1;

  // stop all threads before accessing the process memory
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

  bool ok = xfer_memory(ea, (void*)buffer, size, true);
  if ( ok && size == BPT_CODE_SIZE ) // might be a breakpoint add/del
  {
    if ( memcmp(buffer, bpt_code.begin(), BPT_CODE_SIZE) == 0 )
      bpts.insert(ea);
    else
      bpts.erase(ea);
  }

  if ( suspend )
    resume_all_threads();

  return ok ? size : 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  return _write_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  return _read_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
void mac_debmod_t::add_dll(ea_t addr, const char *fname)
{
  asize_t size = calc_image_size(fname, NULL);

  debug_event_t ev;
  ev.eid     = LIBRARY_LOAD;
  ev.pid     = pid;
  ev.tid     = maintid();
  ev.ea      = addr;
  ev.handled = true;
  qstrncpy(ev.modinfo.name, fname, sizeof(ev.modinfo.name));
  ev.modinfo.base = addr;
  ev.modinfo.size = size;
  ev.modinfo.rebase_to = BADADDR;
  if ( is_dll && stricmp(fname, input_file_path.c_str()) == 0 )
    ev.modinfo.rebase_to = addr;
  events.enqueue(ev, IN_FRONT);

  image_info_t ii(addr, size, fname);
  dlls.insert(std::make_pair(addr, ii));
  dlls_to_import.insert(addr);
}

//--------------------------------------------------------------------------
inline bool is_zeropage(const segment_command &sg)
{
  return sg.vmaddr == 0 && sg.fileoff == 0 && sg.initprot == 0;
}

//--------------------------------------------------------------------------
inline bool is_text_segment(const segment_command &sg)
{
  if ( is_zeropage(sg) )
    return false;
  const char *name = sg.segname;
  for ( int i=0; i < sizeof(sg.segname); i++, name++ )
    if ( *name != '_' )
      break;
  return strnicmp(name, "TEXT", 4) == 0;
}

//--------------------------------------------------------------------------
local asize_t calc_image_size(const char *fname, ea_t *p_base)
{
  if ( p_base != NULL )
    *p_base = BADADDR;
  linput_t *li = open_linput(fname, false);
  if ( li == NULL )
    return 0;

  asize_t size = calc_macho_image_size(li, p_base);
  close_linput(li);
  return size;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::import_dll(linput_t *li, ea_t base, name_info_t & /*ni*/)
{
  struct ida_local macho_importer_t : public symbol_visitor_t
  {
    mac_debmod_t *md;
    macho_importer_t(mac_debmod_t *_md) : symbol_visitor_t(VISIT_SYMBOLS), md(_md) {}
    int visit_symbol(ea_t ea, const char *name)
    {
      if ( name[0] != '\0' )
      {
        md->save_debug_name(ea, name);
        if ( md->dylib_infos == BADADDR && strcmp(name, "_dyld_all_image_infos") == 0 )
        {
//          md->dmsg("%a: address of dylib raw infos\n", ea);
          md->dylib_infos = ea;
        }
      }
      return 0;
    }
  };
  macho_importer_t mi(this);
  return parse_macho(base, li, mi, false);
}

//--------------------------------------------------------------------------
bool mac_debmod_t::import_dll_to_database(ea_t imagebase, name_info_t &ni)
{
  images_t::iterator p = dlls.find(imagebase);
  if ( p == dlls.end() )
    return false;

  const char *dllname = p->second.name.c_str();

  linput_t *li = open_linput(dllname, false);
  if ( li == NULL )
    return false;

  bool ok = import_dll(li, imagebase, ni);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_write_file(
        int /* fn */,
        uint32 /* off */,
        const void * /* buf */,
        size_t /* size */)
{
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_read_file(
        int /* fn */,
        uint32 /* off */,
        void * /* buf */,
        size_t /* size */)
{
  return 0;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_open_file(
        const char * /* file */,
        uint32 * /* fsize */,
        bool /* readonly */)
{
  return 0;
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_close_file(int /* fn */)
{
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_stopped_at_debug_event(void)
{
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
  name_info_t &ni = *get_debug_names();

  for (easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    import_dll_to_database(*p, ni);
    dlls_to_import.erase(p++);
  }
}

//--------------------------------------------------------------------------
void mac_debmod_t::cleanup(void)
{
  pid = 0;
  is_dll = false;
  run_state = rs_exited;
  dylib = BADADDR;
  dylib_infos = BADADDR;
  dyri.version = 0;  // not inited
  term_exception_ports();

  threads.clear();
  dlls.clear();
  dlls_to_import.clear();
  events.clear();
  attaching = false;
  bpts.clear();

  inherited::cleanup();
}

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERFACE FUNCTIONS
//
//--------------------------------------------------------------------------
void mac_debmod_t::refresh_process_list(void)
{
  processes.clear();

  int sysControl[4];
  sysControl[0] = CTL_KERN;
  sysControl[1] = KERN_PROC;
  sysControl[2] = KERN_PROC_ALL;

  size_t length;
  sysctl(sysControl, 3, NULL, &length, NULL, 0);
  int count = (length / sizeof (struct kinfo_proc));
  if ( count <= 0 )
    return;
  length = sizeof (struct kinfo_proc) * count;

  qvector<struct kinfo_proc> info;
  info.resize(count);
  sysctl(sysControl, 3, info.begin(), &length, NULL, 0);

  for ( int i=0; i < count; i++ )
  {
    mach_port_t port;
    kern_return_t result = task_for_pid(mach_task_self(), info[i].kp_proc.p_pid,  &port);
    if ( result == KERN_SUCCESS )
    {
      process_info_t pi;
      qstrncpy(pi.name, info[i].kp_proc.p_comm, sizeof(pi.name));
      pi.pid = info[i].kp_proc.p_pid;
      processes.push_back(pi);
    }
    else
    {
      debdeb("%d: %s is unavailable for debugging\n", info[i].kp_proc.p_pid, info[i].kp_proc.p_comm);
    }
  }
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
// input is valid only if n==0
int idaapi mac_debmod_t::dbg_process_get_info(int n, const char *input, process_info_t *info)
{
  if ( n == 0 )
  {
    input_file_path = input;
    refresh_process_list();
  }

  if ( n < 0 || n >= processes.size() )
    return false;

  if ( info != NULL )
    *info = processes[n];
  return true;
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
char *get_exec_fname(int pid, char *buf, size_t bufsize)
{
  int mib[3];
  mib[0] = CTL_KERN;
  mib[1] = KERN_ARGMAX;

  int argmax = 0;
  size_t size = sizeof(argmax);

  sysctl(mib, 2, &argmax, &size, NULL, 0);
  if ( argmax <= 0 )
    argmax = QMAXPATH;

  char *args = (char *)qalloc(argmax);
  if ( args == NULL )
    nomem("get_exec_fname");

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROCARGS2;
  mib[2] = pid;

  // obtain the arguments for the target process. this will
  // only work for processes that belong to the current uid,
  // so if you want it to work universally, you need to run
  // as root.
  size = argmax;
  buf[0] = '\0';
  if ( sysctl(mib, 3, args, &size, NULL, 0) != -1 )
  {
    char *ptr = args + sizeof(int);
//    show_hex(ptr, size, "procargs2\n");

    qstrncpy(buf, ptr, bufsize);
  }
  qfree(args);
  return buf;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::thread_exit_event_planned(thid_t tid)
{
  for ( eventlist_t::iterator p=events.begin(); p != events.end(); ++p )
  {
    if ( p->eid == THREAD_EXIT && p->tid == tid )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::update_threads(void)
{
  bool generated_events = false;
  thread_act_port_array_t threadList;
  mach_msg_type_number_t threadCount;
  kern_return_t err = task_threads(task, &threadList, &threadCount);
  std::set<int> live_tids;
  if ( err == KERN_SUCCESS )
  {
    QASSERT(30089, threadCount > 0);
    for ( int i=0; i < threadCount; i++ )
    {
      mach_port_t port = threadList[i];
      int tid = port;
      threads_t::iterator p = threads.find(tid);
      if ( p == threads.end() )
      {
        debug_event_t ev;
        ev.eid     = THREAD_START;
        ev.pid     = pid;
        ev.tid     = tid;
        ev.ea      = BADADDR;
        ev.handled = true;
        events.enqueue(ev, IN_FRONT);
        threads.insert(std::make_pair(tid, ida_thread_info_t(tid, port)));
        generated_events = true;
      }
      live_tids.insert(tid);
    }
    err = mach_vm_deallocate (mach_task_self(), (vm_address_t)threadList, threadCount * sizeof (thread_t));
    QASSERT(30090, err == KERN_SUCCESS);
    // remove dead threads
    for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    {
      thid_t tid = p->first;
      if ( live_tids.find(tid) == live_tids.end() && !thread_exit_event_planned(tid) )
      {
        debug_event_t ev;
        ev.eid     = THREAD_EXIT;
        ev.pid     = pid;
        ev.tid     = tid;
        ev.ea      = BADADDR;
        ev.handled = true;
        events.enqueue(ev, IN_BACK);
        generated_events = true;
      }
    }
  }
  return generated_events;
}

//--------------------------------------------------------------------------
thid_t mac_debmod_t::init_main_thread(void)
{
  thread_act_port_array_t threadList;
  mach_msg_type_number_t threadCount;
  kern_return_t err = task_threads(task, &threadList, &threadCount);
  QASSERT(30091, err == KERN_SUCCESS);
  QASSERT(30092, threadCount > 0);
  mach_port_t port = threadList[0]; // the first thread is the main thread
  thid_t tid = port;
  threads.insert(std::make_pair(tid, ida_thread_info_t(tid, port)));
  threads.begin()->second.block = bl_signal;
  err = mach_vm_deallocate(mach_task_self(), (vm_address_t)threadList, threadCount * sizeof(thread_t));
  QASSERT(30093, err == KERN_SUCCESS);
  return tid;
}

//--------------------------------------------------------------------------
local kern_return_t save_exception_ports(task_t task, mach_exception_port_info_t *info)
{
  info->count = (sizeof (info->ports) / sizeof (info->ports[0]));
  return task_get_exception_ports(task,
                                  EXC_MASK_ALL,
                                  info->masks,
                                  &info->count,
                                  info->ports,
                                  info->behaviors,
                                  info->flavors);
}

local kern_return_t restore_exception_ports (task_t task, const mach_exception_port_info_t *info)
{
  kern_return_t err = KERN_SUCCESS;
  for ( int i = 0; i < info->count; i++ )
  {
    err = task_set_exception_ports(task,
                                   info->masks[i],
                                   info->ports[i],
                                   info->behaviors[i],
                                   info->flavors[i]);
    if ( err != KERN_SUCCESS )
      break;
  }
  return err;
}

void mac_debmod_t::init_exception_ports(void)
{
  kern_return_t err;

  // allocate a new port to receive exceptions
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
  QASSERT(30094, err == KERN_SUCCESS);

  // add the 'send' right to send replies to threads
  err = mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
  QASSERT(30095, err == KERN_SUCCESS);

  // save old exception ports
  err = save_exception_ports(task, &saved_exceptions);
  QASSERT(30096, err == KERN_SUCCESS);

  // set new port for all exceptions
  err = task_set_exception_ports(task, EXC_MASK_ALL, exc_port, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
  QASSERT(30097, err == KERN_SUCCESS);

}

void mac_debmod_t::term_exception_ports(void)
{
  if ( exc_port != MACH_PORT_NULL )
  {
    kern_return_t err = restore_exception_ports(mach_task_self(), &saved_exceptions);
    QASSERT(30098, err == KERN_SUCCESS);
    err = mach_port_deallocate(mach_task_self(), exc_port);
    QASSERT(30099, err == KERN_SUCCESS);
    exc_port = MACH_PORT_NULL;
  }
}

//--------------------------------------------------------------------------
local bool is_setgid_procmod(void)
{
  gid_t gid = getegid();
  struct group *gr = getgrgid(gid);
  if ( gr == NULL )
    return false;
  bool ok = strcmp(gr->gr_name, "procmod") == 0;
  msg("Current group=%s\n", gr->gr_name);
  endgrent();
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::handle_process_start(pid_t _pid)
{
  debdeb("handle process start %d\n", _pid);
  pid = _pid;

  int status;
  debug_debugger = 1;
  int k = qwait(&status, true);
  debdeb("qwait on %d: %x (ret=%d)\n", pid, status, k);
  QASSERT(30190, k == pid);
  debug_debugger = 0;

  if ( !WIFSTOPPED(status) )
  {
    debdeb("not stopped?\n");
    return false;
  }
  if ( WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGSTOP )
  {
    debdeb("got signal %d?\n", WSTOPSIG(status));
    return false;
  }

  /* Get the mach task for the target process */
  int ntries = 10;
  kern_return_t err = task_for_pid(mach_task_self(), pid, &task);
  while ( err == KERN_FAILURE ) // no access?
  {
    if ( !is_setgid_procmod() )
    {
#ifdef __arm__
      const char *program = "iphone_server";
#else
      //int argc = *_NSGetArgc();
      char **argv = *_NSGetArgv();
      const char *program = qbasename(argv[0]);
      if ( strstr(program, "server") == NULL )
        program = NULL; // runing local mac debugger module
#endif
      if ( program != NULL )
        dwarning("File '%s' must be setgid procmod to debug Mac OS X applications.\n"
                 "Please use the following commands to change its permissions:\n"
                 "  sudo chmod +sg %s\n"
                 "  sudo chgrp procmod %s\n", program, program, program);
      else
        dwarning("Please run idal with elevated permissons for local debugging.\n"
                 "Another solution is to run mac_server and use localhost as\n"
                 "the remote computer name");
      return false;
    }
    debdeb("could not determine process %d port: %s\n", pid, mach_error_string(err));
    if ( --ntries > 0 )
      continue;
    usleep(100);
    return false;
  }
  QASSERT(30100, err == KERN_SUCCESS);

  in_ptrace = true;
  thid_t tid = init_main_thread();
  debdeb("initially stopped at %a pid=%d tid=%d task=%d\n", get_ip(tid), pid, tid, task);
  run_state = rs_running;

  debug_event_t ev;
  ev.eid     = PROCESS_START;
  ev.pid     = pid;
  ev.tid     = tid;
  ev.ea      = BADADDR;
  ev.handled = true;
  get_exec_fname(pid, ev.modinfo.name, sizeof(ev.modinfo.name));
  debdeb("gotexe: %s\n", ev.modinfo.name);
  ev.modinfo.size = calc_image_size(ev.modinfo.name, &ev.modinfo.base);
  ev.modinfo.rebase_to = BADADDR;

  // find the real executable base
  // also call get_memory_info() the first time
  // this should find dyld and set its bpt
  meminfo_vec_t miv;
  if ( get_memory_info(miv, false) > 0 && !is_dll )
  {
    for ( int i=0; i < miv.size(); i++ )
    {
      if ( miv[i].name == ev.modinfo.name )
      {
        ev.modinfo.rebase_to = miv[i].startEA;
        break;
      }
    }
  }
  events.enqueue(ev, IN_FRONT);

  init_exception_ports();
  return true;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_start_process(const char *path,
                                const char *args,
                                const char *startdir,
                                int flags,
                                const char *input_path,
                                uint32 input_file_crc32)
{
  // immediately switch to the startdir because path/input_path may be relative.
  if ( startdir[0] != '\0' && chdir(startdir) == -1 )
  {
    dmsg("chdir '%s': %s\n", startdir, winerr(errno));
    return -2;
  }

  // input file specified in the database does not exist
  if ( input_path[0] != '\0' && !qfileexist(input_path) )
    return -2;

  // temporary thing, later we will retrieve the real file name
  // based on the process id
  input_file_path = input_path;
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;

  if ( !qfileexist(path) )
    return -1;

  int mismatch = 0;
  if ( !check_input_file_crc32(input_file_crc32) )
    mismatch = CRC32_MISMATCH;

  qstring errbuf;
  launch_process_params_t lpi;
  lpi.cb = sizeof(lpi);
  lpi.path = path;
  lpi.args = args;
  lpi.flags = LP_TRACE;
  void *child_pid = launch_process(lpi, &errbuf);
  if ( child_pid == NULL )
  {
    dwarning("init_process error: %s", errbuf.c_str());
    return -1;
  }
  if ( !handle_process_start((ssize_t)child_pid) )
  {
    dwarning("handle_process_start error");
    return -1;
  }

  return 1 | mismatch;
}


//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_attach_process(pid_t pid, int /*event_id*/)
{
  if ( qptrace(PT_ATTACH, pid, NULL, NULL) == 0
    && handle_process_start(pid) )
  {
    // generate the attach event
    debug_event_t ev;
    ev.eid     = PROCESS_ATTACH;
    ev.pid     = pid;
    ev.tid     = maintid();
    ev.ea      = get_ip(ev.tid);
    ev.handled = true;
    get_exec_fname(pid, ev.modinfo.name, sizeof(ev.modinfo.name));
    ev.modinfo.base = BADADDR;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;
    events.enqueue(ev, IN_BACK);

    // generate THREAD_START events
    update_threads();

    // block the process until all generated events are processed
    attaching = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_detach_process(void)
{
  if ( dyri.dyld_notify != 0 )
  {
    // remove the dyld breakpoint
    int size = dbg_write_memory(dyri.dyld_notify, dyld_opcode, BPT_CODE_SIZE);
    QASSERT(30101, size == BPT_CODE_SIZE);
    dyri.dyld_notify = 0;
  }
  // cleanup exception ports
  term_exception_ports();
  if ( in_ptrace )
  {
    qptrace(PT_DETACH, pid, 0, 0);
    in_ptrace = false;
  }
  else
  {
    // let the process run
    unblock_all_threads();
  }
  debug_event_t ev;
  ev.eid     = PROCESS_DETACH;
  ev.pid     = pid;
  ev.tid     = maintid();
  ev.ea      = BADADDR;
  ev.handled = true;
  events.enqueue(ev, IN_BACK);
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_prepare_to_pause_process(void)
{
  debdeb("remote_prepare_to_pause_process\n");
  if ( run_state >= rs_exiting )
    return false;
#ifdef __arm__
  // since we detached from ptrace, we can not send signals to inferior
  // simple suspend it and generate a fake event
  if ( !suspend_all_threads() )
    return false;
  run_state = rs_suspended;
  debug_event_t ev;
  ev.eid     = NO_EVENT;
  ev.pid     = pid;
  ev.tid     = maintid();
  ev.ea      = BADADDR;
  ev.handled = true;
  events.enqueue(ev, IN_BACK);
#else
  run_state = rs_pausing;
  kill(pid, SIGSTOP);
#endif
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_exit_process(void)
{
  // since debhtread is retrieving events in advance, we possibly
  // already received the PROCESS_EXIT event. Check for it
  if ( exited() )
  {
    debdeb("%d: already exited\n", pid);
    return true;
  }

  run_state = rs_exiting;
  bool ok = false;
  debdeb("%d: sending SIGKILL\n", pid );
  if ( kill(pid, SIGKILL) == 0 )
  {
    ok = true;
    unblock_all_threads();
  }
  else
  {
    debdeb("SIGKILL %d failed: %s\n", pid, strerror(errno));
  }
  return ok;
}

//--------------------------------------------------------------------------
// Set hardware breakpoints for one thread
bool mac_debmod_t::set_hwbpts(int hThread)
{
#if !defined (__i386__) && !defined(__x86_64__)
  return false;
#else
  machine_debug_state_t dr_regs;

  if ( !get_debug_state(hThread, &dr_regs) )
    return false;

  ::set_dr(dr_regs, 0, hwbpt_ea[0]);
  ::set_dr(dr_regs, 1, hwbpt_ea[1]);
  ::set_dr(dr_regs, 2, hwbpt_ea[2]);
  ::set_dr(dr_regs, 3, hwbpt_ea[3]);
  ::set_dr(dr_regs, 6, 0);
  ::set_dr(dr_regs, 7, dr7);
//  printf("set_hwbpts: DR0=%08lX DR1=%08lX DR2=%08lX DR3=%08lX DR7=%08lX => %d\n",
//         hwbpt_ea[0],
//         hwbpt_ea[1],
//         hwbpt_ea[2],
//         hwbpt_ea[3],
//         dr7,
//         ok);
  return set_debug_state(hThread, &dr_regs);
#endif
}

//--------------------------------------------------------------------------
bool mac_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( !set_hwbpts(p->second.tid) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type == BPT_SOFT )
    return dbg_write_memory(ea, bpt_code.begin(), BPT_CODE_SIZE) == BPT_CODE_SIZE;

#if defined (__i386__) || defined(__x86_64__)
  return add_hwbpt(type, ea, len);
#else
  return false;
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  // we update threads when we delete a breakpoint because it gives
  // better results: new threads are immediately added to the list of
  // known threads and properly suspended before "single step"
  update_threads();
  if ( orig_bytes != NULL )
    return dbg_write_memory(ea, orig_bytes, len) == len;

#if defined (__i386__) || defined(__x86_64__)
  return del_hwbpt(ea, type);
#else
  return false;
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_get_sreg_base(thid_t /*tid*/, int /*sreg_value*/, ea_t *pea)
{
#ifdef __arm__
  qnotused(pea);
  return false;
#else
  // assume all segments are based on zero
  *pea = 0;
  return true;
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_suspend(thid_t tid)
{
  debdeb("remote_thread_suspend %d\n", tid);
  kern_return_t err = thread_suspend(tid);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_continue(thid_t tid)
{
  debdeb("remote_thread_continue %d\n", tid);
  kern_return_t err = thread_resume(tid);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_set_step(thid_t tid)
{
#ifdef __arm__
  qnotused(tid);
  return false;
#else
  ida_thread_info_t *t = get_thread(tid);
  if ( t == NULL )
    return false;
  t->single_step = true;
  return true;
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( values == NULL )
    return false;

  machine_thread_state_t cpu;
  if ( !get_thread_state(tid, &cpu) )
    return false;

#ifdef __arm__  // fixme - add arm logic
  if ( (clsmask & ARM_RC_GENERAL) != 0 )
  {
    values[ 0].ival = uint32(cpu.__r[ 0]);
    values[ 1].ival = uint32(cpu.__r[ 1]);
    values[ 2].ival = uint32(cpu.__r[ 2]);
    values[ 3].ival = uint32(cpu.__r[ 3]);
    values[ 4].ival = uint32(cpu.__r[ 4]);
    values[ 5].ival = uint32(cpu.__r[ 5]);
    values[ 6].ival = uint32(cpu.__r[ 6]);
    values[ 7].ival = uint32(cpu.__r[ 7]);
    values[ 8].ival = uint32(cpu.__r[ 8]);
    values[ 9].ival = uint32(cpu.__r[ 9]);
    values[10].ival = uint32(cpu.__r[10]);
    values[11].ival = uint32(cpu.__r[11]);
    values[12].ival = uint32(cpu.__r[12]);
    values[13].ival = uint32(cpu.__sp);
    values[14].ival = uint32(cpu.__lr);
    values[15].ival = uint32(cpu.__pc);
    values[16].ival = uint32(cpu.__cpsr);
  }
#else
  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
    values[R_EAX   ].ival = uval_t(cpu.__eax);
    values[R_EBX   ].ival = uval_t(cpu.__ebx);
    values[R_ECX   ].ival = uval_t(cpu.__ecx);
    values[R_EDX   ].ival = uval_t(cpu.__edx);
    values[R_ESI   ].ival = uval_t(cpu.__esi);
    values[R_EDI   ].ival = uval_t(cpu.__edi);
    values[R_EBP   ].ival = uval_t(cpu.__ebp);
    values[R_ESP   ].ival = uval_t(cpu.__esp);
    values[R_EIP   ].ival = uval_t(cpu.__eip);
    values[R_EFLAGS].ival = uval_t(cpu.__eflags);
#ifdef __X64__
    values[R64_R8  ].ival = uval_t(cpu.__r8);
    values[R64_R9  ].ival = uval_t(cpu.__r9);
    values[R64_R10 ].ival = uval_t(cpu.__r10);
    values[R64_R11 ].ival = uval_t(cpu.__r11);
    values[R64_R12 ].ival = uval_t(cpu.__r12);
    values[R64_R13 ].ival = uval_t(cpu.__r13);
    values[R64_R14 ].ival = uval_t(cpu.__r14);
    values[R64_R15 ].ival = uval_t(cpu.__r15);
#endif
  }
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS    ].ival = uval_t(cpu.__cs);
    values[R_FS    ].ival = uval_t(cpu.__fs);
    values[R_GS    ].ival = uval_t(cpu.__gs);
#ifdef __X64__
    values[R_DS    ].ival = 0;
    values[R_ES    ].ival = 0;
    values[R_SS    ].ival = 0;
#else
    values[R_DS    ].ival = uval_t(cpu.__ds);
    values[R_ES    ].ival = uval_t(cpu.__es);
    values[R_SS    ].ival = uval_t(cpu.__ss);
#endif
  }

  if ( (clsmask & (X86_RC_FPU|X86_RC_XMM|X86_RC_MMX)) != 0 )
  {
    machine_float_state_t fpu;
    if ( !get_float_state(tid, &fpu) )
      return false;

    if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
    {
      if ( (clsmask & X86_RC_FPU) != 0 )
      {
        values[R_CTRL].ival = *(ushort*)&fpu.__fpu_fcw;
        values[R_STAT].ival = *(ushort*)&fpu.__fpu_fsw;
        values[R_TAGS].ival = fpu.__fpu_ftw;
      }
      read_fpu_registers(values, clsmask, &fpu.__fpu_stmm0, 16);
    }
    if ( (clsmask & X86_RC_XMM) != 0 )
    {
      uchar *xptr = (uchar *)&fpu.__fpu_xmm0;
      for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
        values[i].set_bytes(xptr, 16);
      values[R_MXCSR].ival = fpu.__fpu_mxcsr;
    }
  }
#endif // __i386__
  return true;
}

//--------------------------------------------------------------------------
inline int get_reg_class(int reg_idx)
{
#ifdef __arm__
  return ARM_RC_GENERAL;
#else
  return get_x86_reg_class(reg_idx);
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
static bool patch_reg_context(
        machine_thread_state_t *cpu,
        machine_float_state_t *fpu,
        int reg_idx,
        const regval_t *value)
{
  if ( value == NULL )
    return false;

  int regclass = get_reg_class(reg_idx);
#if defined (__i386__) || defined(__x86_64__)
  if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
    QASSERT(30102, cpu != NULL);
    switch ( reg_idx )
    {
#ifdef __X64__
      case R64_R8:   cpu->__r8     = value->ival; break;
      case R64_R9:   cpu->__r9     = value->ival; break;
      case R64_R10:  cpu->__r10    = value->ival; break;
      case R64_R11:  cpu->__r11    = value->ival; break;
      case R64_R12:  cpu->__r12    = value->ival; break;
      case R64_R13:  cpu->__r13    = value->ival; break;
      case R64_R14:  cpu->__r14    = value->ival; break;
      case R64_R15:  cpu->__r15    = value->ival; break;
      case R_DS:
      case R_ES:
      case R_SS:
        break;
#else
      case R_DS:     cpu->__ds     = value->ival; break;
      case R_ES:     cpu->__es     = value->ival; break;
      case R_SS:     cpu->__ss     = value->ival; break;
#endif
      case R_CS:     cpu->__cs     = value->ival; break;
      case R_FS:     cpu->__fs     = value->ival; break;
      case R_GS:     cpu->__gs     = value->ival; break;
      case R_EAX:    cpu->__eax    = value->ival; break;
      case R_EBX:    cpu->__ebx    = value->ival; break;
      case R_ECX:    cpu->__ecx    = value->ival; break;
      case R_EDX:    cpu->__edx    = value->ival; break;
      case R_ESI:    cpu->__esi    = value->ival; break;
      case R_EDI:    cpu->__edi    = value->ival; break;
      case R_EBP:    cpu->__ebp    = value->ival; break;
      case R_ESP:    cpu->__esp    = value->ival; break;
      case R_EIP:    cpu->__eip    = value->ival; break;
      case R_EFLAGS: cpu->__eflags = value->ival; break;
      default: return false;
    }
  }
  else if ( (regclass & (X86_RC_FPU|X86_RC_MMX|X86_RC_XMM)) != 0 )
  {
    QASSERT(30103, fpu != NULL);
    if ( reg_idx >= R_XMM0 && reg_idx < R_MXCSR )
    {
      uchar *xptr = (uchar *)&fpu->__fpu_xmm0 + (reg_idx - R_XMM0) * 16;
      const void *vptr = value->get_data();
      size_t size = value->get_data_size();
      memcpy(xptr, vptr, qmin(size, 16));
    }
    else if ( reg_idx >= R_MMX0 && reg_idx <= R_MMX7 )
    {
      uchar *xptr = (uchar *)&fpu->__fpu_stmm0 + (reg_idx - R_MMX0) * sizeof(_STRUCT_MMST_REG);
      const void *vptr = value->get_data();
      size_t size = value->get_data_size();
      memcpy(xptr, vptr, qmin(size, 8));
    }
    else if ( reg_idx == R_MXCSR )
    {
      fpu->__fpu_mxcsr = value->ival;
    }
    else if ( reg_idx >= R_ST0+FPU_REGS_COUNT ) // FPU status registers
    {
      switch ( reg_idx )
      {
        case R_CTRL: *(ushort*)&fpu->__fpu_fcw = value->ival; break;
        case R_STAT: *(ushort*)&fpu->__fpu_fsw = value->ival; break;
        case R_TAGS:            fpu->__fpu_ftw = value->ival; break;
      }
    }
    else // FPU floating point registers
    {
      uchar *fptr = (uchar *)&fpu->__fpu_stmm0;
      fptr += (reg_idx - R_ST0) * sizeof(_STRUCT_MMST_REG);
      memcpy(fptr, value->fval, 10);
    }
  }
#else // arm
  switch ( reg_idx )
  {
    case  0: cpu->__r[ 0] = value->ival; break;
    case  1: cpu->__r[ 1] = value->ival; break;
    case  2: cpu->__r[ 2] = value->ival; break;
    case  3: cpu->__r[ 3] = value->ival; break;
    case  4: cpu->__r[ 4] = value->ival; break;
    case  5: cpu->__r[ 5] = value->ival; break;
    case  6: cpu->__r[ 6] = value->ival; break;
    case  7: cpu->__r[ 7] = value->ival; break;
    case  8: cpu->__r[ 8] = value->ival; break;
    case  9: cpu->__r[ 9] = value->ival; break;
    case 10: cpu->__r[10] = value->ival; break;
    case 11: cpu->__r[11] = value->ival; break;
    case 12: cpu->__r[12] = value->ival; break;
    case 13: cpu->__sp    = value->ival; break;
    case 14: cpu->__lr    = value->ival; break;
    case 15: cpu->__pc    = value->ival; break;
    case 16: cpu->__cpsr  = value->ival; break;
    default: return false;
  }
#endif
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  if ( value == NULL )
    return false;

  int regclass = get_reg_class(reg_idx);
  if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
    machine_thread_state_t cpu;
    if ( !get_thread_state(tid, &cpu) )
      return false;

    if ( !patch_reg_context(&cpu, NULL, reg_idx, value) )
      return false;

    return set_thread_state(tid, &cpu);
  }
#if defined (__i386__) || defined(__x86_64__)
  else if ( (regclass & (X86_RC_FPU|X86_RC_XMM)) != 0 )
  {
    machine_float_state_t fpu;
    if ( !get_float_state(tid, &fpu) )
      return false;

    if ( !patch_reg_context(NULL, &fpu, reg_idx, value) )
      return false;

    return set_float_state(tid, &fpu);
  }
#endif
  return false;
}

//--------------------------------------------------------------------------
bool idaapi mac_debmod_t::write_registers(
  thid_t tid,
  int start,
  int count,
  const regval_t *values,
  const int *indices)
{
  machine_thread_state_t cpu;
  bool got_regs = false;
#if defined (__i386__) || defined(__x86_64__)
  machine_float_state_t fpu;
  bool got_i387 = false;
#endif

  for ( int i=0; i < count; i++, values++ )
  {
    int idx = indices != NULL ? indices[i] : start+i;
    int regclass = get_reg_class(idx);
    if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
    { // general register
      if ( !got_regs )
      {
        if ( !get_thread_state(tid, &cpu) )
          return false;
        got_regs = true;
      }
    }
#if defined (__i386__) || defined(__x86_64__)
    else if ( (regclass & (X86_RC_FPU|X86_RC_XMM)) != 0 )
    {
      if ( !got_i387 )
      {
        if ( !get_float_state(tid, &fpu) )
          return false;
        got_i387 = true;
      }
    }
#endif
    if ( !patch_reg_context(&cpu, &fpu, idx, values) )
      return false;
  }

  if ( got_regs && !set_thread_state(tid, &cpu) )
    return false;

#if defined (__i386__) || defined(__x86_64__)
  if ( got_i387 && !set_float_state(tid, &fpu) )
    return false;
#endif

  return true;
}

//--------------------------------------------------------------------------
static mac_debmod_t *md;
static ssize_t read_mem_helper(ea_t ea, void *buffer, int size)
{
  return md->read_mem(ea, buffer, size) == KERN_SUCCESS ? size : 0;
}

bool mac_debmod_t::is_dylib_header(ea_t base, char *filename, size_t namesize)
{
  lock_begin();
  md = this;
  bool ok = ::is_dylib_header(base, read_mem_helper, filename, namesize);
  lock_end();
  return ok;
}

//--------------------------------------------------------------------------
// find a dll in the memory information array
bool mac_debmod_t::exist_dll(const dyriv_t &riv, ea_t base)
{
  // dyld is never unloaded
  if ( base == dylib )
    return true;
  for ( int i=0; i < riv.size(); i++ )
    if ( riv[i].addr == base )
      return true;
  return false;
}

//--------------------------------------------------------------------------
void mac_debmod_t::update_dylib(void)
{
//  dmsg("start: update_dylib at %a\n", dylib_infos);
  if ( read_mem(dylib_infos, &dyri, sizeof(dyri)) == KERN_SUCCESS )
  {
    QASSERT(30104, dyri.version >= 1);

    if ( dyri.num_info > 0 && dyri.info_array != 0 )
    {
      dyriv_t riv;
      riv.resize(dyri.num_info);
      int nbytes = dyri.num_info * sizeof(dyld_raw_info);
      if ( read_mem(dyri.info_array, riv.begin(), nbytes) != KERN_SUCCESS )
        return;

//      show_hex(riv.begin(), nbytes, "riv:\n");
      // remove unexisting dlls
      images_t::iterator p;
      for ( p=dlls.begin(); p != dlls.end(); )
      {
        if ( !exist_dll(riv, p->first) )
        {
          debug_event_t ev;
          ev.eid     = LIBRARY_UNLOAD;
          ev.pid     = pid;
          ev.tid     = maintid();
          ev.ea      = BADADDR;
          ev.handled = true;
          qstrncpy(ev.info, p->second.name.c_str(), sizeof(ev.info));
          events.enqueue(ev, IN_FRONT);
          dlls.erase(p++);
        }
        else
        {
          ++p;
        }
      }
      // add new dlls
      for ( int i=0; i < riv.size(); i++ )
      {
        // address zero is ignored
        if ( riv[i].addr == 0 )
          continue;
        p = dlls.find(riv[i].addr);
        if ( p == dlls.end() )
        {
          char buf[QMAXPATH];
          memset(buf, 0, sizeof(buf));
          read_mem(riv[i].name, buf, sizeof(buf)); // may fail because we don't know exact size
          buf[sizeof(buf)-1] = '\0';
//          dmsg("dll name at %a is '%s'\n", ea_t(riv[i].addr), riv[i].name, buf);
          add_dll(riv[i].addr, buf);
        }
      }
    }
  }
//  dmsg("end: update_dylib\n");
}

//--------------------------------------------------------------------------
void mac_debmod_t::init_dylib(ea_t addr, const char *fname)
{
//  dmsg("%a: located dylib header and file '%s'\n", addr, fname);
  dylib = addr;

  add_dll(addr, fname);
  // immediately process it
  dbg_stopped_at_debug_event();

  // check if we just found the address of dyld raw information
  if ( dyri.version == 0 && dylib_infos != BADADDR )
  {
    read_mem(dylib_infos, &dyri, sizeof(dyri));
    if ( dyri.version > 7 )
    {
      //dwarning("dyld link version (%d) is newer than expected (7).", dyri.version);
    }
    // set a breakpoint for library loads/unloads
    ea_t notify_ea = dyri.dyld_notify; // shut up the compiler
    dmsg("%a: setting bpt for library notifications\n", notify_ea);
    uchar opcode[BPT_CODE_SIZE];
    read_mem(dyri.dyld_notify, opcode, sizeof(opcode));
    if ( memcmp(opcode, dyld_opcode, BPT_CODE_SIZE) != 0 )
      dwarning("Unexpected dyld_opcode in the debugger server (init_dylib): %x", *(uint32*)opcode);
    dbg_add_bpt(BPT_SOFT, dyri.dyld_notify, -1);
  }
}

//--------------------------------------------------------------------------
image_info_t *mac_debmod_t::get_image(ea_t addr, asize_t size)
{
  if ( !dlls.empty() )
  {
    images_t::iterator p = dlls.lower_bound(addr);
    if ( p != dlls.end() )
    {
      image_info_t &ii = p->second;
      if ( interval::overlap(ii.base, ii.imagesize, addr, size) )
        return &ii;
    }
    if ( p != dlls.begin() )
    {
      --p;
      image_info_t &ii = p->second;
      if ( interval::overlap(ii.base, ii.imagesize, addr, size) )
        return &ii;
    }
  }
  return NULL;
}

//--------------------------------------------------------------------------
/*local const char *get_share_mode_name(unsigned char sm, char *buf, size_t bufsize)
{
  switch ( sm )
  {
    case SM_COW:             return "COW";
    case SM_PRIVATE:         return "PRIVATE";
    case SM_EMPTY:           return "EMPTY";
    case SM_SHARED:          return "SHARED";
    case SM_TRUESHARED:      return "TRUESHARED";
    case SM_PRIVATE_ALIASED: return "PRIV_ALIAS";
    case SM_SHARED_ALIASED:  return "SHRD_ALIAS";
  }                               // 1234567890
  qsnprintf(buf, bufsize, "%x", sm);
  return buf;
}*/

//--------------------------------------------------------------------------
int mac_debmod_t::get_memory_info(meminfo_vec_t &miv, bool suspend)
{
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

  mach_vm_size_t size = 0;
  for ( mach_vm_address_t addr = 0; ; addr += size )
  {
    mach_port_t object_name; // unused
    vm_region_top_info_data_t info;
    mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
    kern_return_t code = mach_vm_region(task, &addr, &size, VM_REGION_TOP_INFO,
                        (vm_region_info_t)&info, &count, &object_name);

//    debdeb("task=%d addr=%" FMT_64 "x size=%" FMT_64 "x err=%x\n", task, addr, size, code);
    if ( code != KERN_SUCCESS )
      break;

    // ignore segments at address 0
    if ( addr == 0 )
      continue;

    // find dylib in the memory if not found yet
    char fname[QMAXPATH];
    if ( dylib == BADADDR && is_dylib_header(addr, fname, sizeof(fname)) )
      init_dylib(addr, fname);

    mach_vm_address_t subaddr;
    mach_vm_size_t subsize = 0;
    mach_vm_address_t end = addr + size;
    for ( subaddr=addr; subaddr < end; subaddr += subsize )
    {
      natural_t depth = 1;
      vm_region_submap_info_data_64_t sinfo;
      mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
      kern_return_t code = mach_vm_region_recurse(task, &subaddr, &subsize, &depth,
                                         (vm_region_info_t)&sinfo, &count);
      if ( code != KERN_SUCCESS )
        break;

      memory_info_t &mi = miv.push_back();
      mi.startEA = subaddr;
      mi.endEA   = subaddr + subsize;
#ifdef __X64__
      if ( subaddr == 0x7FFFFFE00000 )
        mi.name = "COMMPAGE";
      mi.bitness = 2; // 64bit
#else
      mi.bitness = 1; // 32bit
#endif
      // check if we have information about this memory chunk
      image_info_t *im = get_image(subaddr, subsize);
      if ( im == NULL )
      {
        // it is not a good idea to hide any addresses because
        // they will be used by the program and the user will be
        // left blind, not seeing the executed instructions.
#if 0
        if ( is_shared_address(subaddr) )
        {
          // hide unloaded shared libraries???
          continue;
        }
#endif
      }
      else
      {
        mi.name = im->name;
      }
      mi.perm = 0;
      if ( sinfo.protection & 1 ) mi.perm |= SEGPERM_READ;
      if ( sinfo.protection & 2 ) mi.perm |= SEGPERM_WRITE;
      if ( sinfo.protection & 4 ) mi.perm |= SEGPERM_EXEC;
//      char buf[40];
//      dmsg("%"FMT_64"x..%"FMT_64"x: share mode %s prot: %x name=%s\n", subaddr, subaddr+subsize, get_share_mode_name(sinfo.share_mode, buf, sizeof(buf)), sinfo.protection, mi.name.c_str());
    }
  }

#if !defined(__arm__) && !defined(__X64__)
  // add hidden dsmos data
  memory_info_t &mi = miv.push_back();
  mi.startEA = 0xFFFF0000;
  mi.endEA   = 0xFFFFF000;
  mi.bitness = 1; // 32bit
  mi.perm = 0;
  mi.name = "COMMPAGE";
#endif

  update_dylib();
  if ( suspend )
    resume_all_threads();
  return 1;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_get_memory_info(meminfo_vec_t &areas)
{
  int code = get_memory_info(areas, true);
  if ( code == 1 )
  {
    if ( same_as_oldmemcfg(areas) )
      code = -2;
    else
      save_oldmemcfg(areas);
  }
  return code;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_init(bool _debug_debugger)
{
  // remember if the input is a dll
  cleanup();
  cleanup_hwbpts();
  debug_debugger = _debug_debugger;
  return 3; // process_get_info, detach
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_term(void)
{
  cleanup();
  cleanup_hwbpts();
}

//--------------------------------------------------------------------------
bool idaapi mac_debmod_t::thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea)
{
  qnotused(tid);
  qnotused(reg_idx);
  qnotused(pea);
  return false;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
  return true;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new mac_debmod_t();
}
