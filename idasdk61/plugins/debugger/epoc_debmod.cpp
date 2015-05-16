/*
        Symbian debugger module
*/

#include <windows.h>

#include <ida.hpp>
#include <err.h>
#include <idp.hpp>
#include <srarea.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include "consts.h"
#include "epoc_debmod.h"
#include "metrotrk.cpp"

extern debugger_t debugger;
bool debug_debugger;

static const int Treg = 20;        // number of T bit of ARM processor in IDA

//--------------------------------------------------------------------------
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4355)
#endif
epoc_debmod_t::epoc_debmod_t(void) : trk(this)
{
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

//--------------------------------------------------------------------------
epoc_debmod_t::~epoc_debmod_t(void)
{
}

//--------------------------------------------------------------------------
bool idaapi epoc_debmod_t::close_remote(void)
{
  trk.term();
  return true;
}

//--------------------------------------------------------------------------
bool idaapi epoc_debmod_t::open_remote(const char * /*hostname*/, int port_number, const char * /*password*/)
{
  if ( trk.init(port_number) )
    return true;
  warning("Could not open serial port: %s", winerr(GetLastError()));
  return false;
}

//--------------------------------------------------------------------------
void epoc_debmod_t::cleanup(void)
{
  inherited::cleanup();
  proclist.clear();
  dlls_to_import.clear();
  dlls.clear();
  stepping.clear();
  threads.clear();
  events.clear();
  bpts.clear();
  process_name.clear();
  exited = false;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  qnotused(type);
  QASSERT(30018, type == BPT_SOFT); // other types are not supported yet
  bpts_t::iterator p = bpts.find(ea);
  if ( p != bpts.end() )
  {
    // already has a bpt at the specified address
    // unfortunately the kernel may ask to set several bpts at the same addr
    p->second.cnt++;
    return 1;
  }
  bool thumb = getSR(ea, Treg);
  int bid = trk.add_bpt(trk.current_pid(), -1, (int)ea, len, 1, thumb);
  if ( bid == -1 )
    return 0; // failed
  bpts.insert(std::make_pair(ea, bpt_info_t(bid, 1)));
  return 1; // ok
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_del_bpt(bpttype_t /*type*/, ea_t ea, const uchar * /*orig_bytes*/, int /*len*/)
{
  bpts_t::iterator p = bpts.find(ea);
  if ( p == bpts.end() )
    return 0; // failed
  if ( --p->second.cnt == 0 )
  {
    int bid = p->second.bid;
    bpts.erase(p);
    if ( !trk.del_bpt(bid) )
      return 0; // failed? odd
  }
  return 1; // ok
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_init(bool _debug_debugger)
{
  cleanup();
  debug_debugger = ::debug_debugger = _debug_debugger;
  return trk.ping() && trk.connect();
}

//--------------------------------------------------------------------------
void idaapi epoc_debmod_t::dbg_term(void)
{
  trk.disconnect();
  return trk.term();
}

//--------------------------------------------------------------------------
// input is valid only if n==0
int idaapi epoc_debmod_t::dbg_process_get_info(int n, const char * /*input*/, process_info_t *info)
{
  if ( n == 0 ) // initialize the list
  {
    proclist.clear();
    if ( !trk.get_process_list(proclist) )
      return 0;
#if 0 // commented out because we can not match file names with process names
    if ( input != NULL )
    { // remove all unmatching processes from the list
      qstring inpbuf;
      input = qbasename(input);
      const char *end = strchr(input, '.');
      if ( end != NULL )
      { // ignore everything after '.' (remove extension)
        inpbuf = qstring(input, end-input);
        input = inpbuf.c_str();
      }
      for ( int i=proclist.size()-1; i >= 0; i-- )
        if ( strstr(proclist[i].name.c_str(), input) == NULL )
          proclist.erase(proclist.begin()+i);
    }
#endif
  }
  if ( n >= proclist.size() )
    return 0;
  if ( info != NULL )
  {
    proclist_entry_t &pe = proclist[n];
    info->pid = pe.pid;
    qstrncpy(info->name, pe.name.c_str(), sizeof(info->name));
  }
  return 1;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_detach_process(void)
{
  return 0; // can not detach
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_start_process(
  const char *path,
  const char *args,
  const char * /*startdir*/,
  int /* flags */,
  const char * /*input_path*/,
  uint32 /* input_file_crc32 */)
{
  // ideally here we should check if the input_path exists on the device
  // unfortunately, TRK refuses to open files in c:\sys\bin
  if ( !trk.create_process(path, args, &pi) )
  {
    warning("%s: %s", path, get_trk_error_name(trk.pkt[1]));
    return 0;
  }
  // create fake PROCESS_START event because TRK does not have it
  create_process_start_event(path);
  // add entry to thread list
  trk.get_thread_list(pi.pid, &threads);
  return 1;
}

//--------------------------------------------------------------------------
void epoc_debmod_t::create_process_start_event(const char *path)
{
  debug_event_t ev;
  ev.eid = PROCESS_START;
  ev.pid = pi.pid;
  ev.tid = pi.tid;
  ev.ea = BADADDR;
  ev.handled = false;
  qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
  process_name = path;
  ev.modinfo.base = pi.codeaddr;
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = BADADDR;
  events.enqueue(ev, IN_BACK);
}

//--------------------------------------------------------------------------
const exception_info_t *epoc_debmod_t::find_exception_by_desc(const char *desc) const
{
  qvector<exception_info_t>::const_iterator p;
  for ( p=exceptions.begin(); p != exceptions.end(); ++p )
  {
    const char *tpl = p->desc.c_str();
    size_t len = p->desc.length();
    if ( strstr(tpl, "panic") != NULL )
      len = strchr(tpl, ' ') - tpl; // just first word
    if ( strnicmp(tpl, desc, len) == 0 )
      return &*p;
  }
  return NULL;
}

//--------------------------------------------------------------------------
void epoc_debmod_t::add_dll(const image_info_t &ii)
{
  dlls.insert(std::make_pair(ii.codeaddr, ii));
  dlls_to_import.insert(ii.codeaddr);
}

//--------------------------------------------------------------------------
void epoc_debmod_t::del_dll(const char *name)
{
  for ( images_t::iterator p=dlls.begin(); p != dlls.end(); ++p )
  {
    if ( strcmp(p->second.name.c_str(), name) == 0 )
    {
      dlls_to_import.erase(p->first);
      dlls.erase(p);
      return;
    }
  }
  msg("Unknown DLL %s got unloaded\n", name);
}

//--------------------------------------------------------------------------
static thread_list_entry_t *find_thread(thread_list_t &threads, thid_t tid)
{
  for ( thread_list_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->tid == tid )
      return &*p;
  return NULL;
}

inline const thread_list_entry_t *find_thread(const thread_list_t &threads, thid_t tid)
{
  thread_list_t &tl = CONST_CAST(thread_list_t &)(threads);
  return find_thread(tl, tid);
}

//--------------------------------------------------------------------------
inline thread_list_entry_t *epoc_debmod_t::get_thread(thid_t tid)
{
  return find_thread(threads, tid);
}

//--------------------------------------------------------------------------
bool metrotrk_t::handle_notification(uchar seq, void *ud) // plugin version
{
  epoc_debmod_t &dm = *(epoc_debmod_t *)ud;
  int i = 0;
  bool suspend = true;
  debug_event_t ev;
  uchar type = extract_byte(i);
  switch ( type )
  {
    case TrkOSNotifyCreated:
      {
        image_info_t ii;
        uint16 item = extract_int16(i);
        QASSERT(30019, item == TrkOSDLLItem);
        qnotused(item);
        ii.pid       = extract_int32(i);
        ii.tid       = extract_int32(i);
        ii.codeaddr  = extract_int32(i);
        ii.dataaddr  = extract_int32(i);
        ii.name      = extract_pstr(i);
        ev.eid = LIBRARY_LOAD;
        ev.pid = ii.pid;
        ev.tid = ii.tid;
        ev.ea = BADADDR;
        ev.handled = false;
        qstrncpy(ev.modinfo.name, ii.name.c_str(), sizeof(ev.modinfo.name));
        ev.modinfo.base = ii.codeaddr;
        ev.modinfo.size = 0;
        ev.modinfo.rebase_to = BADADDR;
        dm.add_dll(ii);
      }
      break;

    case TrkOSNotifyDeleted:
      {
        uint16 item = extract_int16(i);
        if ( debug_debugger )
          msg("NotifyDeleted Item: %s\n", get_os_item_name(item));
        switch ( item )
        {
          case TrkOSProcessItem:
            {
              uint32 exitcode = extract_int32(i);
              uint32 pid      = extract_int32(i);
              ev.eid = PROCESS_EXIT;
              ev.pid = pid;
              ev.tid = -1;
              ev.ea = BADADDR;
              ev.handled = false;
              ev.exit_code = exitcode;
              tpi.pid = -1;
              dm.exited = true;
            }
            break;
          case TrkOSDLLItem:
            {
              int32 pid = extract_int32(i);
              int32 tid = extract_int32(i);
              qstring name = extract_pstr(i);
              ev.eid = LIBRARY_UNLOAD;
              ev.pid = pid;
              ev.tid = tid;
              ev.ea = BADADDR;
              ev.handled = false;
              qstrncpy(ev.info, name.c_str(), sizeof(ev.info));
              dm.del_dll(name.c_str());
            }
            break;
          default:
            INTERR(30020); // not implemented
        }
      }
      break;

    case TrkNotifyStopped:
      {
        ev.ea  = extract_int32(i);
        ev.pid = extract_int32(i);
        ev.tid = extract_int32(i);
        qstring desc = extract_pstr(i);
        if ( debug_debugger )
        {
          msg("  Current PC: %08X\n", ev.ea);
          msg("  Process ID: %08X\n", ev.pid);
          msg("  Thread ID : %08X\n", ev.tid);
          msg("  Name      : %s\n", desc.c_str());
        }
        ev.handled = false;
        // there are various reasons why the app may stop
        if ( desc.empty() ) // bpt
        {
          // bpt exists?
          if ( dm.bpts.find(ev.ea) != dm.bpts.end() )
          {
            ev.eid = BREAKPOINT;
            ev.bpt.hea = BADADDR;
            ev.bpt.kea = BADADDR;
            if ( dm.get_failed_lowcnd(ev.tid, ev.ea) != NULL )
            {
              ev.handled = true;
              suspend = false;
            }
          }
          else // no, this must be a single step
          {
            ev.eid = STEP;
          }
          break;
        }
        // an exception
        ev.eid = EXCEPTION;
        ev.exc.ea = BADADDR;
        qstrncpy(ev.exc.info, desc.c_str(), sizeof(ev.exc.info));
        // trk returns the exception description, but no code.
        // convert the description to the code
        const exception_info_t *ei = dm.find_exception_by_desc(desc.c_str());
        if ( ei != NULL )
        {
          int code = ei->code;
          ev.exc.code = code;
          ev.exc.can_cont = code != 20        // abort
                         && code != 21        // kill
                         && code < 25;        // regular exception
          ev.handled = ei->handle();
          suspend = ei->break_on();
        }
        else
        {
          ev.exc.code = 25; // just something
          ev.exc.can_cont = true;
        }
      }
      break;

    default:
      // unexpected packet?!
//      msg("Unexpected packet %d\n", type);
      return false;
  }
  return dm.handle_notification(ev, seq, suspend);
}

//--------------------------------------------------------------------------
// generate events for entries that are present in A but not in B.
void epoc_debmod_t::gen_thread_events(
        const thread_list_t &a,
        const thread_list_t &b,
        debug_event_t &ev)
{
  for ( thread_list_t::const_iterator p=a.begin(); p != a.end(); ++p )
  {
    thid_t tid = p->tid;
    if ( !find_thread(b, tid) )
    {
      ev.tid = tid;
      events.enqueue(ev, IN_FRONT);
    }
  }
}

//--------------------------------------------------------------------------
// nb: thread events are prepended to the event queue
bool epoc_debmod_t::refresh_threads(void)
{
  thread_list_t tlist;
  bool ok = trk.get_thread_list(pi.pid, &tlist);
  if ( ok )
  {
    // generate THREAD_START events
    debug_event_t ev;
    ev.handled = true;
    ev.ea      = BADADDR;
    ev.pid     = pi.pid;
    ev.eid     = THREAD_START;
    gen_thread_events(tlist, threads, ev);
    // generate THREAD_EXIT events
    ev.eid     = THREAD_EXIT;
    gen_thread_events(threads, tlist, ev);
    threads.swap(tlist);
  }
  return ok;
}

//--------------------------------------------------------------------------
bool epoc_debmod_t::handle_notification(const debug_event_t &ev, int seq, bool suspend)
{
  bool done = false;
  if ( !exited )
  {
    trk.send_reply_ok(seq);
    if ( ev.tid != -1 && get_thread(ev.tid) == NULL )
    {
      events.enqueue(ev, IN_BACK);
      // new thread has been detected, refresh the thread list
      refresh_threads();
      // we have to report thread changes, so suspend the application
      done = true;
    }
  }
  if ( !done )
  {
    if ( !suspend )
      dbg_continue_after_event(&ev);
    else
      events.enqueue(ev, IN_BACK);
  }
  return true;
}

//--------------------------------------------------------------------------
gdecode_t idaapi epoc_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  while ( true )
  {
    // are there any pending events?
    if ( events.retrieve(event) )
    {
      if ( debug_debugger )
        debdeb("GDE: %s\n", debug_event_str(event));
      return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
    }
    // no pending events, check the target
    trk.poll_for_event(timeout_ms);
    if ( events.empty() )
      break;
  }
  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_attach_process(pid_t pid, int /*event_id*/)
{
  if ( !trk.attach_process(pid) )
    return 0;

  // get information on the existing threads
  trk.get_thread_list(pid, &threads);
  if ( threads.empty() )
  {
    trk.disconnect();
    return 0;       // something is wrong
  }

  pi.pid = pid;
  pi.tid = threads[0].tid;
  pi.codeaddr = (uint32)BADADDR; // unknown :(
  pi.dataaddr = (uint32)BADADDR;
  trk.tpi = pi;
  create_process_start_event(threads[0].name.c_str());

  // create THREAD_START events for all threads except the first
  thread_list_t t0;
  t0.push_back(threads[0]);
  debug_event_t ev;
  ev.eid     = THREAD_START;
  ev.pid     = pid;
  ev.ea      = BADADDR;
  ev.handled = true;
  gen_thread_events(threads, t0, ev);

  // create PROCESS_ATTACH event
  ev.eid = PROCESS_ATTACH;
  ev.tid = pi.tid;
  qstrncpy(ev.modinfo.name, threads[0].name.c_str(), sizeof(ev.modinfo.name));
  process_name = ev.modinfo.name;
  ev.modinfo.base = BADADDR; // unknown :(
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = BADADDR;
  events.enqueue(ev, IN_BACK);
  return 1;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_prepare_to_pause_process(void)
{
  return trk.suspend_thread(pi.pid, pi.tid);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_exit_process(void)
{
  if ( trk.current_pid() == -1 )
    return true; // already terminated
  return trk.terminate_process(pi.pid);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( exited
    || event->eid == LIBRARY_UNLOAD   // TRK doesn't need this?
    || event->eid == THREAD_START     // fake event - btw, how do we detect thread creation?
    || event->eid == PROCESS_EXIT )   // After EXIT TRK does not accept 'continue'
  {
    return 1;
  }

  // if there are pending events, do not resume the app
  // in fact, the whole debugger logic is flawed.
  // it must be ready for a bunch of events, process all of them
  // and only after that resume the whole application or part of it.
  // fixme: rewrite event handling in the debugger
  if ( !events.empty() )
    return 1;

  // was single stepping asked?
  stepping_t::iterator p = stepping.find(event->tid);
  if ( p != stepping.end() )
  {
    stepping.erase(p);
    ea_t end = event->ea + get_item_size(event->ea);
    return trk.step_thread(event->pid, event->tid, (int32)event->ea, (int32)end, true);
  }
  int tid = event->tid == -1 ? pi.tid : event->tid;
  return trk.resume_thread(event->pid, tid);
}

//--------------------------------------------------------------------------
// currently this function doesn't work because the dlls are usually
// not present. besides, we will have to implement the import_dll() function
bool epoc_debmod_t::import_dll_to_database(ea_t imagebase)
{
  images_t::iterator p = dlls.find(imagebase);
  if ( p == dlls.end() )
  {
    dwarning("import_dll_to_database: can't find dll name for imagebase %a", imagebase);
    return false;
  }

  if ( imagebase >= 0x80000000 )
    return false; // we have no access to system memory anyway

  const char *dllname = p->second.name.c_str();
  linput_t *li = open_linput(dllname, false);
  if ( li == NULL )
  {
    return false;
  }

  // prepare nice name prefix for exported functions names
  char prefix[MAXSTR];
  qstrncpy(prefix, qbasename(dllname), sizeof(prefix));
  char *ptr = strrchr(prefix, '.');
  if ( ptr != NULL )
    *ptr = '\0';

  bool ok = false;
//  bool ok = import_dll(prefix, li, imagebase, (void *)this);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
void idaapi epoc_debmod_t::dbg_stopped_at_debug_event(void)
{
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    import_dll_to_database(*p);
    dlls_to_import.erase(p++);
  }
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return trk.suspend_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_thread_continue(thid_t tid)
{
  return trk.resume_thread(pi.pid, tid);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_thread_set_step(thid_t tid)
{
  stepping[tid] = true;
  return 1;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_read_registers(thid_t tid, int, regval_t *values)
{
  uint32 rvals[17];
  int n = qnumber(rvals);
  if ( exited || !trk.read_regs(pi.pid, tid, 0, n, rvals) )
    return 0;

  for ( int i=0; i < n; i++ )
  {
    debdeb("%cR%d: %08X", i==8 ? '\n' : ' ', i, rvals[i]);
    values[i].ival = rvals[i];
  }
  debdeb("\n");

  // if we read the PC and PSW values, check that our virtual register T
  // and real PSW at that address are the same. If not, copy real T to our
  // virtual register T
  if ( n == qnumber(rvals) ) // PC and PSW are read?
  {
    ea_t pc = rvals[15];
    int real_t = (rvals[16] & 0x20) != 0;
    int virt_t = getSR(pc, Treg) != 0;
    if ( real_t != virt_t )
      splitSRarea1(pc, Treg, real_t, SR_autostart);
  }
  return 1;
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  uint32 v = (uint32)value->ival;
  debdeb("write_reg R%d <- %08X\n", reg_idx, v);
  return trk.write_regs(pi.pid, tid, reg_idx, 1, &v);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_get_memory_info(meminfo_vec_t & /*areas*/)
{
  return 0; // failed - we will rely on manual regions
}

//--------------------------------------------------------------------------
ssize_t idaapi epoc_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  if ( ea == 0 )
    return 0;

  if ( debug_debugger )
    msg("%a: read memory %d bytes\n", ea, size);
  ssize_t nread = trk.read_memory(pi.pid, pi.tid, (int32)ea, buffer, size);
  if ( nread < 0 )
    nread = 0; // ida terminates the app upon fatal errors
  return nread;
}

//--------------------------------------------------------------------------
ssize_t idaapi epoc_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  if ( ea == 0 )
    return 0;
  ssize_t written = trk.write_memory(pi.pid, pi.tid, (int32)ea, buffer, size);
  if ( written < 0 )
    written = 0; // ida terminates the app upon fatal errors
  return written;
}

//--------------------------------------------------------------------------
int  idaapi epoc_debmod_t::dbg_open_file(const char *file, uint32 *fsize, bool readonly)
{
  if ( fsize != NULL )
    *fsize = 0;
  int h = trk.open_file(file, readonly ? TrkFileOpenRead : TrkFileOpenCreate);
  if ( h > 0 )
  {
    if ( readonly && fsize != NULL )
    {
      // problem: trk does not have the ftell call
      // we will have to find the file size using the binary search
      // it seems the read_file() doesn't work at all!
      size_t size = 0x100000; // assume big file
      size_t delta = size;
      while ( (delta>>=1) > 0 )
      {
        uchar dummy;
        if ( dbg_read_file(h, uint32(size-1), &dummy, 1) == 1 )
          size += delta;
        else
          size -= delta;
      }
      *fsize = uint32(size - 1);
    }
  }
  else
  {
    set_qerrno(eOS);
    // fixme: set errno
  }
  return h;
}

//--------------------------------------------------------------------------
void idaapi epoc_debmod_t::dbg_close_file(int fn)
{
  trk.close_file(fn, 0);
}

//--------------------------------------------------------------------------
ssize_t idaapi epoc_debmod_t::dbg_read_file(int fn, uint32 off, void *buf, size_t size)
{
  if ( !trk.seek_file(fn, off, SEEK_SET) )
    return -1;
  return trk.read_file(fn, buf, size);
}

//--------------------------------------------------------------------------
ssize_t idaapi epoc_debmod_t::dbg_write_file(int fn, uint32 off, const void *buf, size_t size)
{
  if ( !trk.seek_file(fn, off, SEEK_SET) )
    return -1;
  return trk.write_file(fn, buf, size);
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_thread_get_sreg_base(
        thid_t,
        int,
        ea_t *)
{
  return 0; // not implemented
}

//--------------------------------------------------------------------------
int idaapi epoc_debmod_t::dbg_is_ok_bpt(bpttype_t /*type*/, ea_t /*ea*/, int /*len*/)
{
  return BPT_BAD_ADDR; // not supported
}
