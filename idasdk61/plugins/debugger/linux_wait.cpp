
#include <sys/syscall.h>
#include <pro.h>
#include "linux_debmod.h"

#ifndef WCONTINUED
#define WCONTINUED 8
#endif

// Since it is impossible in linux to wait for a signal with a timeout,
// we create a separate thread for this. It just waits for signals when
// asked by the main thread.
// As soon there is an event, it is reported to the main thread.

//------------------------------------------------------- waitpid thread ---
pid_t waitpid_thread_t::qwait(void)
{
  // debugging: introduce artificial delay
  // qsleep(100);
  while ( true )
  {
    pid_t tid = waitpid(pid, &status, wait_flags);
//    qeprintf("waitpid(%d) => %d %x %s\n", pid, tid, status, tid != -1 ? status_dstr(status) : strerror(errno));
    if ( tid == -1 )
    {
      switch ( errno )
      {
        case EINVAL:
          // probably the OS does not support WCONTINUED or __WALL, try without them
          if ( (wait_flags & WCONTINUED) != 0 )
          {
            wait_flags &= ~WCONTINUED; // do not use WCONTINUED anymore
            continue;
          }
          if ( (wait_flags & __WALL) != 0 )
          {
            wait_flags &= ~__WALL; // do not use __WALL anymore
            continue;
          }
          break;
        case ECHILD:
          tid = waitpid(pid, &status, __WCLONE);
//          qeprintf("  waitpid(%d) => %d %s\n", pid, tid, tid != -1 ? status_dstr(status) : strerror(errno));
          break;
        case EINTR:
          break;
        case EAGAIN:
          continue;
        default:
          break;
      }
    }
    return tid;
  }
}

//------------------------------------------------------- waitpid thread ---
int waitpid_thread_t::run(void)
{
  mytid = syscall(__NR_gettid);
  while ( true )
  {
    qsem_wait(wait_now, -1);
    if ( shutdown )
      break;

    pid = qwait();
    qsem_post(signal_ready);
  }
  return 0;
}

//------------------------------------------------------- waitpid thread ---
static int idaapi waiter_thread(void *ud)
{
  waitpid_thread_t *wpt = (waitpid_thread_t *)ud;
  return wpt->run();
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
//---------------------------------------------------------- main thread ---
waitpid_thread_t::waitpid_thread_t(
        qsemaphore_t _wait_now,
        qsemaphore_t _signal_ready) :
  mytid(-1),
  wait_now(_wait_now),
  signal_ready(_signal_ready),
  shutdown(false),
  waiting(false),
  wait_flags(__WALL | WCONTINUED)
{
  mythread = qthread_create(waiter_thread, this);
}

//---------------------------------------------------------- main thread ---
waitpid_thread_t::~waitpid_thread_t(void)
{
  // if the waiter is waiting for signals, interrupt it
  if ( waiting )
  {
    ignore_sigint = true;
    kill(mytid, SIGINT);
  }

  // tell it to shutdown and wait for it to finish
  shutdown = true;
  qsem_post(wait_now);
  qthread_join(mythread);

  qsem_free(wait_now);
  qsem_free(signal_ready);
}

//---------------------------------------------------------- main thread ---
void linux_debmod_t::enable_waiter(int pid)
{
  if ( wpt == NULL )
  {
    qsemaphore_t wait_now = qsem_create(NULL, 0);
    qsemaphore_t signal_ready = qsem_create(NULL, 0);
    wpt = new waitpid_thread_t(wait_now, signal_ready);
    QASSERT(30189, wait_now != NULL && signal_ready != NULL && wpt->mythread != NULL);
  }

  if ( wpt->waiting )
    return;
  wpt->waiting = true;

  wpt->pid = pid;
  qsem_post(wpt->wait_now);
}

//---------------------------------------------------------- main thread ---
pid_t linux_debmod_t::check_for_signal(int pid, int *status, int timeout_ms)
{
  enable_waiter(pid);

  // debugging: introduce artificial delay
  // qsleep(100);

  if ( !qsem_wait(wpt->signal_ready, timeout_ms) )
    return -1;

  wpt->waiting = false;
  *status = wpt->status;
  return wpt->pid;
}
