/*
 *  This is a sample multi-threaded plugin module
 *
 *  It creates 3 new threads. Each threads sleeps and prints a message in a loop
 *
 */

#ifdef __NT__
#include <windows.h>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#ifdef __NT__
#include <windows.h>
#endif

static qthread_t children[10];
static int nchilds;

//--------------------------------------------------------------------------
static void say_hello(size_t id, qthread_t tid, int cnt)
{
  struct ida_local hello_t : public exec_request_t
  {
    uint64 nsecs;
    size_t id;
    int cnt;
    qthread_t tid;
    int idaapi execute(void)
    {
      uint64 now = 0;
      get_nsec_stamp(&now);
      uint64 delay = now - nsecs;
      msg("Hello %d from thread %ld. tid=%p. current tid=%p (delay=%" FMT_64 "d)\n",
                                         cnt, id, tid, qthread_self(), delay);
      return 0;
    }
    hello_t(size_t _id, qthread_t _tid, int _cnt) : id(_id), cnt(_cnt), tid(_tid)
    {
      get_nsec_stamp(&nsecs);
    }
  };
  hello_t hi(id, tid, cnt);

  int mff;
  switch ( id % 3 )
  {
    case 0: mff = MFF_FAST;  break;
    case 1: mff = MFF_READ;  break;
    default:
    case 2: mff = MFF_WRITE; break;
  }
  execute_sync(hi, mff);
}

//--------------------------------------------------------------------------
static int idaapi thread_func(void *ud)
{
  size_t id = (size_t)ud;
  qthread_t tid = qthread_self();
  int cnt = 0;
  srand(id ^ (size_t)tid);
  while ( true )
  {
    say_hello(id, tid, cnt++);
    int r = rand() % 1000;
    qsleep(r);
  }
#ifdef __GNUC__ // stupid gnuc
  return 0;
#endif
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  if ( nchilds > 0 )
  {
    msg("Killing all threads\n");
    for ( int i=0; i < nchilds; i++ )
      qthread_kill(children[i]);
    msg("Killed all threads\n");
    nchilds = 0;
  }
}

//--------------------------------------------------------------------------
void idaapi run(int)
{
  if ( nchilds == 0 )
  {
    children[nchilds] = qthread_create(thread_func, (void *)nchilds); nchilds++;
    children[nchilds] = qthread_create(thread_func, (void *)nchilds); nchilds++;
    children[nchilds] = qthread_create(thread_func, (void *)nchilds); nchilds++;
    msg("Three new threads have been created. Main thread id %p\n", qthread_self());
    for ( int i=0; i < 5; i++ )
      say_hello(-1, 0, 0);
  }
  else
  {
    term();
  }
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Multi-threaded sample", // the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
