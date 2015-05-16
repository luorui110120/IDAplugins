/*
        Thread support for IDA debugger under Linux.
*/

//#define TDEB     // debug threads

#define local static

//#define MANUALLY_LOAD_THREAD_DB
#ifdef MANUALLY_LOAD_THREAD_DB
// On some systems libthread_db can not be linked statically because only .so files exists.
// Also, linking it statically is probably a bad idea because it is closely
// tied to the thread implementation.
// Therefore we manually load libthread_db.so.

// Prototypes of functions we use from libthread_db.so:
typedef td_err_e td_init_t(void);
typedef td_err_e td_ta_delete_t(td_thragent_t *__ta);
typedef td_err_e td_ta_event_addr_t(const td_thragent_t *__ta, td_event_e __event, td_notify_t *__ptr);
typedef td_err_e td_ta_event_getmsg_t(const td_thragent_t *__ta, td_event_msg_t *__msg);
typedef td_err_e td_ta_map_lwp2thr_t(const td_thragent_t *__ta, lwpid_t __lwpid, td_thrhandle_t *__th);
typedef td_err_e td_ta_new_t(struct ps_prochandle *__ps, td_thragent_t **__ta);
typedef td_err_e td_ta_set_event_t(const td_thragent_t *__ta, td_thr_events_t *__event);
typedef td_err_e td_ta_thr_iter_t(const td_thragent_t *__ta, td_thr_iter_f *__callback, void *__cbdata_p, td_thr_state_e __state, int __ti_pri, sigset_t *__ti_sigmask_p, unsigned int __ti_user_flags);
typedef td_err_e td_thr_event_enable_t(const td_thrhandle_t *__th, int __event);
typedef td_err_e td_thr_get_info_t(const td_thrhandle_t *__th, td_thrinfo_t *__infop);
typedef td_err_e td_thr_setsigpending_t(const td_thrhandle_t *__th, unsigned char __n, const sigset_t *__ss);
typedef td_err_e td_thr_set_event_t(const td_thrhandle_t *__th, td_thr_events_t *__event);

// Pointers to imported functions:
static td_init_t              *p_td_init              = NULL;
static td_ta_delete_t         *p_td_ta_delete         = NULL;
static td_ta_event_addr_t     *p_td_ta_event_addr     = NULL;
static td_ta_event_getmsg_t   *p_td_ta_event_getmsg   = NULL;
static td_ta_map_lwp2thr_t    *p_td_ta_map_lwp2thr    = NULL;
static td_ta_new_t            *p_td_ta_new            = NULL;
static td_ta_set_event_t      *p_td_ta_set_event      = NULL;
static td_ta_thr_iter_t       *p_td_ta_thr_iter       = NULL;
static td_thr_event_enable_t  *p_td_thr_event_enable  = NULL;
static td_thr_get_info_t      *p_td_thr_get_info      = NULL;
static td_thr_setsigpending_t *p_td_thr_setsigpending = NULL;
static td_thr_set_event_t     *p_td_thr_set_event     = NULL;

struct symbol_resolve_info_t
{
  const char *name;
  void **ptr;
};
static symbol_resolve_info_t tdsyms[] =
{
  { "td_init",                (void**)&p_td_init              },
  { "td_ta_delete",           (void**)&p_td_ta_delete         },
  { "td_ta_event_addr",       (void**)&p_td_ta_event_addr     },
  { "td_ta_event_getmsg",     (void**)&p_td_ta_event_getmsg   },
  { "td_ta_map_lwp2thr",      (void**)&p_td_ta_map_lwp2thr    },
  { "td_ta_new",              (void**)&p_td_ta_new            },
  { "td_ta_set_event",        (void**)&p_td_ta_set_event      },
  { "td_ta_thr_iter",         (void**)&p_td_ta_thr_iter       },
  { "td_thr_event_enable",    (void**)&p_td_thr_event_enable  },
  { "td_thr_get_info",        (void**)&p_td_thr_get_info      },
  { "td_thr_setsigpending",   (void**)&p_td_thr_setsigpending },
  { "td_thr_set_event",       (void**)&p_td_thr_set_event     },
};

// These definitions make our source code the same:
#define td_init              p_td_init
#define td_ta_delete         p_td_ta_delete
#define td_ta_event_addr     p_td_ta_event_addr
#define td_ta_event_getmsg   p_td_ta_event_getmsg
#define td_ta_map_lwp2thr    p_td_ta_map_lwp2thr
#define td_ta_new            p_td_ta_new
#define td_ta_set_event      p_td_ta_set_event
#define td_ta_thr_iter       p_td_ta_thr_iter
#define td_thr_event_enable  p_td_thr_event_enable
#define td_thr_get_info      p_td_thr_get_info
#define td_thr_setsigpending p_td_thr_setsigpending
#define td_thr_set_event     p_td_thr_set_event

//--------------------------------------------------------------------------
local bool load_libthread_db_so(void)
{
  if ( p_td_init == NULL )
  {
    const char *file = "libthread_db.so";
    void *lib = dlopen(file, RTLD_NOW);
    if ( lib == NULL )
    {
      msg("dlopen(%s): %s\n", file, dlerror());
      return false;
    }
    for ( int i=0; i < qnumber(tdsyms); i++ )
    {
      *tdsyms[i].ptr = dlsym(lib, tdsyms[i].name);
      const char *err = dlerror();
      if ( err != NULL )
      {
        msg("dlsym(%s.%s): %s\n", file, tdsyms[i].name, err);
        dlclose(lib);
        return false;
      }
    }
  }
  return true;
}
#else   // Automatic loading of libthread_db.so
inline bool load_libthread_db_so(void) { return true; }
#endif

typedef std::map<qstring, ea_t> psnames_t;
static psnames_t psname_cache;

static bool tdb_inited = false;
//--------------------------------------------------------------------------
#define COMPLAIN_IF_FAILED(func, err)          \
  do                                           \
  {                                            \
    if ( err != TD_OK )                        \
      msg("%s: %s\n", func, tdb_strerr(err));  \
  }                                            \
  while ( 0 )

#define DIE_IF_FAILED(func, err)               \
  do                                           \
  {                                            \
    if ( err != TD_OK )                        \
      error("%s: %s\n", func, tdb_strerr(err));\
  }                                            \
  while ( 0 )

local const char *tdb_strerr(td_err_e err)
{
  static char buf[64];
  switch ( err )
  {
    case TD_OK:          return "ok";
    case TD_ERR:         return "generic error";
    case TD_NOTHR:       return "no thread to satisfy query";
    case TD_NOSV:        return "no sync handle to satisfy query";
    case TD_NOLWP:       return "no LWP to satisfy query";
    case TD_BADPH:       return "invalid process handle";
    case TD_BADTH:       return "invalid thread handle";
    case TD_BADSH:       return "invalid synchronization handle";
    case TD_BADTA:       return "invalid thread agent";
    case TD_BADKEY:      return "invalid key";
    case TD_NOMSG:       return "no event message for getmsg";
    case TD_NOFPREGS:    return "FPU register set not available";
    case TD_NOLIBTHREAD: return "application not linked with libthread";
    case TD_NOEVENT:     return "requested event is not supported";
    case TD_NOCAPAB:     return "capability not available";
    case TD_DBERR:       return "debugger service failed";
    case TD_NOAPLIC:     return "operation not applicable to";
    case TD_NOTSD:       return "no thread-specific data for this thread";
    case TD_MALLOC:      return "malloc failed";
    case TD_PARTIALREG:  return "only part of register set was written/read";
    case TD_NOXREGS:     return "X register set not available for this thread";
#ifdef TD_TLSDEFER
    case TD_TLSDEFER:    return "thread has not yet allocated TLS for given module";
#endif
#ifdef TD_VERSION
    case TD_VERSION:     return "versions of libpthread and libthread_db do not match";
#endif
#ifdef TD_NOTLS
    case TD_NOTLS:       return "there is no TLS segment in the given module";
#endif
    default:
      qsnprintf(buf, sizeof(buf), "tdb error %d", err);
      return buf;
  }
}

//--------------------------------------------------------------------------
// Debug print functions
#ifdef TDEB
local const char *tdb_event_name(int ev)
{
  static const char *const names[] =
  {
    "READY",       //  1
    "SLEEP",       //  2
    "SWITCHTO",    //  3
    "SWITCHFROM",  //  4
    "LOCK_TRY",    //  5
    "CATCHSIG",    //  6
    "IDLE",        //  7
    "CREATE",      //  8
    "DEATH",       //  9
    "PREEMPT",     // 10
    "PRI_INHERIT", // 11
    "REAP",        // 12
    "CONCURRENCY", // 13
    "TIMEOUT",     // 14
  };
  if ( ev > 0 && ev <= qnumber(names) )
    return names[ev-1];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", ev);
  return buf;
}

//--------------------------------------------------------------------------
local char *get_thr_events_str(const td_thr_events_t &set)
{
  static char buf[MAXSTR];
  char *ptr = buf;
  char *end = buf + sizeof(buf);
  for ( int i=TD_MIN_EVENT_NUM; i <= TD_MAX_EVENT_NUM; i++ )
  {
    if ( td_eventismember(&set, i) )
    {
      if ( ptr != buf )
        APPCHAR(ptr, end, ' ');
      APPEND(ptr, end, tdb_event_name(i));
    }
  }
  return buf;
}

//--------------------------------------------------------------------------
local const char *get_sigset_str(const sigset_t &set)
{
  static char buf[MAXSTR];
  char *ptr = buf;
  char *end = buf + sizeof(buf);
  for ( int i=0; i <= 32; i++ )
  {
    if ( sigismember(CONST_CAST(sigset_t*)(&set), i) )
    {
      if ( ptr != buf )
        APPCHAR(ptr, end, ' ');
      ptr += qsnprintf(ptr, end-ptr, "%d", i);
    }
  }
  return buf;
}

//--------------------------------------------------------------------------
local const char *get_thread_state_name(td_thr_state_e state)
{
  static const char *const names[] =
  {
    "ANY_STATE",      //  0
    "UNKNOWN",        //  1
    "STOPPED",        //  2
    "RUN",            //  3
    "ACTIVE",         //  4
    "ZOMBIE",         //  5
    "SLEEP",          //  6
    "STOPPED_ASLEEP"  //  7
  };
  if ( state >= 0 && state < qnumber(names) )
    return names[state];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", state);
  return buf;
}

//--------------------------------------------------------------------------
local const char *get_thread_type_name(td_thr_type_e type)
{
  static const char *const names[] =
  {
    "ANY_STATE",      //  0
    "USER",           //  1
    "SYSTEM",         //  2
  };
  if ( type >= 0 && type < qnumber(names) )
    return names[type];

  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%u", type);
  return buf;
}

//--------------------------------------------------------------------------
local void display_thrinfo(const td_thrinfo_t &thi)
{
#ifdef __ANDROID__
  msg("  tid         : %lx\n", thi.ti_tid);
  msg("  kernel pid  : %d\n", thi.ti_lid); // lwpid_t
  msg("  state       : %s\n", get_thread_state_name(thi.ti_state));
#else
  size_t sigmask = *(size_t*)&thi.ti_sigmask;
  msg("  tid         : %lx\n", thi.ti_tid);
  msg("  tls         : %lx\n", (size_t)thi.ti_tls);
  msg("  entry       : %lx\n", (size_t)thi.ti_startfunc);
  msg("  stackbase   : %lx\n", (size_t)thi.ti_stkbase);
  msg("  stacksize   : %lx\n", thi.ti_stksize);
  msg("  state       : %s\n", get_thread_state_name(thi.ti_state));
  msg("  suspended   : %d\n", thi.ti_db_suspended);
  msg("  type        : %s\n", get_thread_type_name(thi.ti_type));
  msg("  priority    : %d\n", thi.ti_pri);
  msg("  kernel pid  : %d\n", thi.ti_lid); // lwpid_t
  msg("  signal mask : %lx\n", sigmask);
  msg("  traceme     : %d\n", thi.ti_traceme);
  msg("  pending sg  : %s\n", get_sigset_str(thi.ti_pending));
  msg("  enabled ev  : %s\n", get_thr_events_str(thi.ti_events));
#endif
}

//--------------------------------------------------------------------------
void linux_debmod_t::display_thrinfo(thid_t tid)
{
  msg("tid=%d\n", tid);
  td_thrhandle_t th;
  td_err_e err = td_ta_map_lwp2thr(ta, tid, &th);
  COMPLAIN_IF_FAILED("td_ta_map_lwp2thr2", err);

  if ( err == 0 )
  {
    td_thrinfo_t thi;
    memset(&thi, 0 ,sizeof(thi));
    err = td_thr_get_info(&th, &thi);
    COMPLAIN_IF_FAILED("td_thr_get_info2", err);

    if ( err == 0 )
      ::display_thrinfo(thi);
  }
}

//--------------------------------------------------------------------------
local int display_thread_cb(const td_thrhandle_t *th_p, void * /*data*/)
{
  td_thrinfo_t ti;
  td_err_e err = td_thr_get_info(th_p, &ti);
  DIE_IF_FAILED("td_thr_get_info", err);

  if ( ti.ti_state == TD_THR_UNKNOWN || ti.ti_state == TD_THR_ZOMBIE )
    return 0;

  display_thrinfo(ti);
  return 0;
}

void linux_debmod_t::display_all_threads()
{
  if ( ta != NULL )
  {
    td_err_e err = td_ta_thr_iter(ta, display_thread_cb, NULL,
                                  TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                                  TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    COMPLAIN_IF_FAILED("td_ta_thr_iter", err);
  }
}

#endif // end of debug print functions


//--------------------------------------------------------------------------
// Helper functions for thread_db
// (it requires ps_... functions to be defined in the debugger)
//--------------------------------------------------------------------------
local linux_debmod_t *find_debugger(ps_prochandle *ph)
{
#ifdef __ANDROID__ // android passes NULL as ph, do not use it
  linux_debmod_t *d = (linux_debmod_t *)g_global_server->get_debugger_instance();
  return d;
#else
  struct ida_local find_debugger_t : public debmod_visitor_t
  {
    int pid;
    linux_debmod_t *found;
    find_debugger_t(int p) : pid(p), found(NULL) {}
    int visit(debmod_t *debmod)
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      if ( ld->process_handle == pid )
      {
        found = ld;
        return 1; // stop
      }
      return 0; // continue
    }
  };
  find_debugger_t fd(ph->pid);
  for_all_debuggers(fd);
//  msg("prochandle: %x, looking for the debugger, found: %x\n", ph, fd.found);
  return fd.found;
#endif
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_pglobal_lookup(
        ps_prochandle *ph,
        const char *obj,
        const char *name,
        psaddr_t *sym_addr)
{
  ea_t ea;
  // cache names for repeated requests. android, for example, requests the
  // same name again and again. without the cache, the name would be gone
  // from the pending name list and become unresolvable.
  psnames_t::iterator p = psname_cache.find(name);
  if ( p != psname_cache.end() )
  {
    ea = p->second;
  }
  else
  {
    linux_debmod_t *ld = find_debugger(ph);
    if ( ld == NULL )
      return PS_BADPID;

    ld->enum_names(obj); // update the name list

    ea = ld->find_pending_name(name);
    if ( ea == BADADDR )
    {
#ifdef TDEB
      msg("FAILED TO FIND name '%s'\n", name);
#endif
      return PS_NOSYM;
    }
    psname_cache[name] = ea;
  }
  *sym_addr = (void*)ea;
#ifdef TDEB
  msg("ps_pglobal_lookup('%s') => %a\n", name, ea);
#endif
  return PS_OK;
}

#ifndef __ANDROID__
//--------------------------------------------------------------------------
idaman ps_err_e ps_pdread(
        ps_prochandle *ph,
        psaddr_t addr,
        void *buf,
        size_t size)
{
#ifdef TDEB
  msg("ps_pdread(%a, %ld)\n", ea_t(addr), size);
#endif
  linux_debmod_t *ld = find_debugger(ph);
  if ( ld == NULL )
  {
#ifdef TDEB
    msg("\t=> bad pid\n");
#endif
    return PS_BADPID;
  }
  if ( ld->thread_handle == INVALID_HANDLE_VALUE
    || ld->_read_memory(ld->thread_handle, size_t(addr), buf, size, false) <= 0 )
  {
#ifdef TDEB
    msg("\t=> read error (1)\n");
#endif
    if ( ld->_read_memory(ph->pid, size_t(addr), buf, size, false) <= 0 )
    {
#ifdef TDEB
      msg("\t=> read error (2)\n");
#endif
      return PS_ERR;
    }
  }
#ifdef TDEB
  msg("\t=> read OK\n");
#endif
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_pdwrite(
        ps_prochandle *ph,
        psaddr_t addr,
        void *buf,
        size_t size)
{
  linux_debmod_t *ld = find_debugger(ph);
  if ( ld == NULL )
    return PS_BADPID;
  if ( ld->_write_memory(ph->pid, size_t(addr), buf, size, false) <= 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lgetregs(ps_prochandle *ph, lwpid_t lwpid, prgregset_t gregset)
{
  qnotused(ph);
  if ( qptrace(PTRACE_GETREGS, lwpid, 0, gregset) != 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lsetregs(ps_prochandle *ph, lwpid_t lwpid, const prgregset_t gregset)
{
  qnotused(ph);
  if ( qptrace(PTRACE_SETREGS, lwpid, 0, (void*)gregset) != 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lgetfpregs(ps_prochandle *ph, lwpid_t lwpid, prfpregset_t *fpregset)
{
  qnotused(ph);
  if ( qptrace(PTRACE_GETFPREGS, lwpid, 0, fpregset) != 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_lsetfpregs(ps_prochandle *ph, lwpid_t lwpid, const prfpregset_t *fpregset)
{
  qnotused(ph);
  if ( qptrace(PTRACE_SETFPREGS, lwpid, 0, (void*)fpregset) != 0 )
    return PS_ERR;
  return PS_OK;
}

//--------------------------------------------------------------------------
idaman pid_t ps_getpid(ps_prochandle *ph)
{
  return ph->pid;
}

//--------------------------------------------------------------------------
idaman ps_err_e ps_get_thread_area(const struct ps_prochandle *ph, lwpid_t lwpid, int idx, void **base)
{
  qnotused(ph);
#ifdef __X64__
  // from <sys/reg.h>
  #define LINUX_FS 25
  #define LINUX_GS 26

  /* The following definitions come from prctl.h, but may be absent
     for certain configurations.  */
  #ifndef ARCH_GET_FS
  #define ARCH_SET_GS 0x1001
  #define ARCH_SET_FS 0x1002
  #define ARCH_GET_FS 0x1003
  #define ARCH_GET_GS 0x1004
  #endif

  switch ( idx )
  {
    case LINUX_FS:
      if ( ptrace(PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_FS) != 0 )
        return PS_ERR;
      break;
    case LINUX_GS:
      if ( ptrace(PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_GS) != 0 )
        return PS_ERR;
      break;
    default:
      return PS_BADADDR;
  }

#else
  #ifndef PTRACE_GET_THREAD_AREA
  #define PTRACE_GET_THREAD_AREA __ptrace_request(25)
  #endif
    unsigned int desc[4];
    if ( ptrace(PTRACE_GET_THREAD_AREA, lwpid, (void *)idx, (size_t)&desc) < 0 )
      return PS_ERR;

    *(int *)base = desc[1];
#endif

  return PS_OK;
}
#endif

//--------------------------------------------------------------------------
// High level interface for the rest of the debugger module
//--------------------------------------------------------------------------
void tdb_init(void)
{
  if ( !tdb_inited )
  {
    if ( !load_libthread_db_so() )
      msg("Thread support is not available\n");
    else if ( td_init() == TD_OK )
      tdb_inited = true;
  }
}

//--------------------------------------------------------------------------
void tdb_term(void)
{
  // no way to uninitialize thread_db
}

//--------------------------------------------------------------------------
struct thrinfo_t : public td_thrinfo_t
{
  const td_thrhandle_t *th_p;
};
typedef qvector<thrinfo_t> thrinfovec_t;

//--------------------------------------------------------------------------
// check if there are pending messages from thread DB
void linux_debmod_t::tdb_handle_messages(int /*tid*/)
{
  if ( ta == NULL )
    return;

  td_event_msg_t tmsg;
  thrinfo_t ti;
  td_err_e err;
#ifndef __ANDROID__
  while ( true )
#endif
  {
    err = td_ta_event_getmsg(ta, &tmsg);
    if ( err != TD_OK )
    {
      if ( err == TD_NOMSG )
        return;
      msg("Cannot get thread event message: %s\n", tdb_strerr(err));
      return;
    }

    err = td_thr_get_info(tmsg.th_p, &ti);
    ti.th_p = tmsg.th_p;
    COMPLAIN_IF_FAILED("td_thr_get_info", err);
    switch ( tmsg.event )
    {
      case TD_CREATE:
        new_thread(&ti, true);
        break;

      case TD_DEATH:
        dead_thread(ti.ti_lid, DYING);
        break;

      default:
        msg("Spurious thread event %d.", tmsg.event);
    }
  }
}

local int update_threads_cb(const td_thrhandle_t *th_p, void *data)
{
  thrinfovec_t &newlist = *(thrinfovec_t *)data;

  thrinfo_t ti;
  td_err_e err = td_thr_get_info(th_p, &ti);
  DIE_IF_FAILED("td_thr_get_info", err);

  if ( ti.ti_state != TD_THR_UNKNOWN && ti.ti_state != TD_THR_ZOMBIE )
  {
    ti.th_p = th_p;
    newlist.push_back(ti);
  }
  return 0;
}

//--------------------------------------------------------------------------
void linux_debmod_t::new_thread(thrinfo_t *info, bool is_suspended)
{
  int tid = info->ti_lid;
  threads_t::iterator p = threads.find(tid);
  if ( p == threads.end() ) // not found
  {
    if ( !is_suspended )
      dbg_freeze_threads(tid, false);

#ifdef TDEB
    msg("thread %d is new\n", tid);
    ::display_thrinfo(*info);
#endif

    td_err_e err;

    td_thr_events_t events;
    td_event_emptyset(&events);
    td_event_addset(&events, TD_CREATE);
    td_event_addset(&events, TD_DEATH);
#ifndef __ANDROID__
    td_event_addset(&events, TD_CATCHSIG);
#endif
    err = td_thr_set_event(info->th_p, &events);
    DIE_IF_FAILED("td_thr_set_event", err);

    err = td_thr_event_enable(info->th_p, 1);
    COMPLAIN_IF_FAILED("td_thr_event_enable", err);
    if ( err != TD_OK )
    {
#ifdef TDEB
      msg("%d: thread dead already? not adding to list.\n", tid);
#endif
      return;
    }

    debug_event_t ev;
    ev.eid     = THREAD_START;
    ev.pid     = process_handle;
    ev.tid     = tid;
#ifndef __ANDROID__
    ev.ea      = (ea_t)info->ti_startfunc;
#endif
    ev.handled = true;
    add_thread(tid);
    enqueue_event(ev, IN_FRONT);
    // attach to the thread and make it ready for debugging
    if ( qptrace(PTRACE_ATTACH, tid, 0, 0) != 0 )
      INTERR(30197);
    int status;
    int tid2 = check_for_signal(tid, &status, -1); // consume SIGSTOP
    if ( tid2 != tid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP )
    {
      get_thread(tid)->waiting_sigstop = true;
      if ( tid2 > 0 )
        store_pending_signal(tid2, status);
    }
  }
  get_thread(tid)->thr = info->th_p;
}

//--------------------------------------------------------------------------
void linux_debmod_t::dead_thread(int tid, thstate_t state)
{
  threads_t::iterator p = threads.find(tid);
  if ( p != threads.end() )
  {
#ifdef TDEB
    msg("thread %d died\n", tid);
#endif
    set_thread_state(p->second, state);
    debug_event_t ev;
    ev.eid     = THREAD_EXIT;
    ev.pid     = process_handle;
    ev.tid     = tid;
    ev.ea      = BADADDR;
    ev.handled = true;
    ev.exit_code = 0; // ???
    enqueue_event(ev, IN_BACK);
    if ( state == DEAD )
      del_thread(tid);
  }
  else
  {
    msg("unknown thread %d died\n", tid);
  }
}

//--------------------------------------------------------------------------
void linux_debmod_t::tdb_update_threads(void)
{
  if ( ta != NULL )
  {
    thrinfovec_t newlist;
    td_err_e err = td_ta_thr_iter(ta, update_threads_cb, &newlist,
                                  TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
                                  TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    COMPLAIN_IF_FAILED("td_ta_thr_iter", err);
    if ( err != TD_OK )
      return;

    // generate THREAD_START events
    for ( int i=0; i < newlist.size(); i++ )
    {
      // the main thread is already suspended
      new_thread(&newlist[i], i == 0);
    }
  }
}

//--------------------------------------------------------------------------
bool linux_debmod_t::tdb_enable_event(td_event_e event, internal_bpt *bp)
{
  td_notify_t notify;
  td_err_e err = td_ta_event_addr(ta, event, &notify);
  COMPLAIN_IF_FAILED("td_ta_event_addr", err);
  if ( err != TD_OK )
    return false;
  bool ok = add_internal_bp(*bp, size_t(notify.u.bptaddr));
  if ( !ok )
  {
    dmsg("%a: failed to add thread_db breakpoint\n", ea_t(notify.u.bptaddr));
    return false;
  }
  debdeb("%a: added BP for thread event %s\n", bp->bpt_addr, event == TD_CREATE ? "TD_CREATE" : "TD_DEATH");
  return true;
}

//--------------------------------------------------------------------------
// returns true: multithreaded application has been detected
bool linux_debmod_t::tdb_new(int pid)
{
  if ( ta == NULL )
  {
    if ( !tdb_inited )
      return false; // no libthread_db
#ifdef TDEB
    msg("checking pid %d with thread_db\n", pid);
#endif
    prochandle.pid = pid;
    td_err_e err = td_ta_new(&prochandle, &ta);
    // the call might fail the first time if libc is not loaded yet
    // so don't show misleading message to the user
    // COMPLAIN_IF_FAILED("td_ta_new", err);
    if ( err != TD_OK )
    {
      ta = NULL;
      return false;
    }

    td_thrhandle_t th;
    err = td_ta_map_lwp2thr(ta, pid, &th);
    COMPLAIN_IF_FAILED("td_ta_map_lwp2thr", err);
    if ( err != TD_OK )
      return false;

    err = td_thr_event_enable(&th, TD_CREATE);
    DIE_IF_FAILED("td_thr_event_enable(TD_CREATE)", err);
#ifndef __ANDROID__
    err = td_thr_event_enable(&th, TD_DEATH);
    DIE_IF_FAILED("td_thr_event_enable(TD_DEATH)", err);
#endif

    // set breakpoints for thread birth/death
    td_thr_events_t events;
    td_event_emptyset(&events);
    td_event_addset(&events, TD_CREATE);
    td_event_addset(&events, TD_DEATH);
    err = td_ta_set_event(ta, &events);
    DIE_IF_FAILED("td_ta_set_event", err);

    tdb_enable_event(TD_CREATE, &birth_bpt);
#ifndef __ANDROID__
    tdb_enable_event(TD_DEATH, &death_bpt);
#endif
#ifdef TDEB
    msg("thread support has been enabled, birth_bpt=%a death_bpt=%a\n", birth_bpt.bpt_addr, death_bpt.bpt_addr);
#endif

    tdb_update_threads();
  }
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::tdb_delete(void)
{
  if ( ta != NULL )
  {
    td_ta_delete(ta);
    ta = NULL;
    psname_cache.clear();
  }
}
