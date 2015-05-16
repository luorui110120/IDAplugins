#ifndef __LINUX_DEBUGGER_MODULE__
#define __LINUX_DEBUGGER_MODULE__

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#ifdef __ANDROID__
#  include <linux/user.h>
#else
#  include <sys/user.h>
#endif

extern "C"
{
#include <thread_db.h>
}

#include <map>
#include <set>
#include <deque>

#ifdef __ARM__
#  define BASE_DEBUGGER_MODULE arm_debmod_t
#  include "arm_debmod.h"
#  define BPT_CODE_SIZE ARM_BPT_SIZE
#else
#  define BASE_DEBUGGER_MODULE pc_debmod_t
#  include "pc_debmod.h"
#  define BPT_CODE_SIZE X86_BPT_SIZE
#endif

typedef int HANDLE;
typedef uint32 DWORD;
#define INVALID_HANDLE_VALUE (-1)

using std::pair;
using std::make_pair;

typedef qvector<process_info_t> processes_t;
typedef std::set<ea_t> easet_t;         // set of addresses
typedef std::map<ea_t, qstring> ea2name_t;
typedef std::map<qstring, ea_t> name2ea_t;

// image information
struct image_info_t
{
  image_info_t() : base(BADADDR), size(0) {}
  image_info_t(
        ea_t _base,
        asize_t _size,
        const qstring &_fname,
        const qstring &_soname)
    : base(_base), size(_size), fname(_fname), soname(_soname) { }
  ea_t base;
  asize_t size;         // image size, currently 0
  qstring fname;
  qstring soname;
  ea2name_t names;
};
typedef std::map<ea_t, image_info_t> images_t; // key: image base address

enum thstate_t
{
  RUNNING,            // running
  STOPPED,            // waiting to be resumed after waitpid
  DYING,              // we got a notification that the thread is about to die
  DEAD,               // dead thread; ignore any signals from it
};

// thread information
struct thread_info_t
{
  thread_info_t(int t)
    : tid(t), suspend_count(0), user_suspend(0), child_signum(0), single_step(false),
      state(STOPPED), waiting_sigstop(false), got_pending_status(false), thr(NULL) {}
  int tid;
  int suspend_count;
  int user_suspend;
  int child_signum;
  bool single_step;
  thstate_t state;
  bool waiting_sigstop;
  bool got_pending_status;
  int pending_status;
  const td_thrhandle_t *thr;
  bool is_running(void) const
  {
    return state == RUNNING && !waiting_sigstop && !got_pending_status;
  }
};

typedef std::map<HANDLE, thread_info_t> threads_t; // (tid -> info)

struct thrinfo_t;

enum ps_err_e
{
  PS_OK,      /* Success.  */
  PS_ERR,     /* Generic error.  */
  PS_BADPID,  /* Bad process handle.  */
  PS_BADLID,  /* Bad LWP id.  */
  PS_BADADDR, /* Bad address.  */
  PS_NOSYM,   /* Symbol not found.  */
  PS_NOFREGS  /* FPU register set not available.  */
};
struct ps_prochandle
{
  pid_t pid;
};

#define UINT32_C uint32

struct internal_bpt
{
  ea_t bpt_addr;
  uchar saved[BPT_CODE_SIZE];
  uchar nsaved;
  internal_bpt(): bpt_addr(0), nsaved(0) {};
};

struct mapfp_entry_t
{
  ea_t ea1;
  ea_t ea2;
  ea_t offset;
  uint64 inode;
  char perm[8];
  char device[8];
  qstring fname;
};

class linux_debmod_t: public BASE_DEBUGGER_MODULE
{
  typedef BASE_DEBUGGER_MODULE inherited;

  // thread_db related data and functions:
  struct ps_prochandle prochandle;
  td_thragent_t *ta;

  internal_bpt birth_bpt; //thread created
  internal_bpt death_bpt; //thread exited
  internal_bpt shlib_bpt; //shared lib list changed
  bool complained_shlib_bpt;

  void find_android_lib(ea_t base, char *lib, size_t bufsize);
  bool add_android_shlib_bpt(const meminfo_vec_t &miv, bool attaching);

  bool add_internal_bp(internal_bpt &bp, ea_t addr);
  bool erase_internal_bp(internal_bpt &bp);

  bool tdb_enable_event(td_event_e event, internal_bpt *bp);
  void tdb_update_threads(void);
  bool tdb_new(int pid);
  void tdb_delete(void);
  void tdb_handle_messages(int pid);
  void new_thread(thrinfo_t *info, bool is_suspended);
  void dead_thread(int tid, thstate_t state);

  // list of debug names not yet sent to IDA
  name_info_t pending_names;
  name_info_t nptl_names;

  struct waitpid_thread_t *wpt;
  void enable_waiter(int pid);
  pid_t check_for_signal(int pid, int *status, int timeout_ms);

public:
  // processes list information
  processes_t processes;
  easet_t dlls_to_import;          // list of dlls to import information from
  images_t dlls;                   // list of loaded DLLs
  images_t images;                 // list of detected PE images
  threads_t threads;

  // debugged process information
  HANDLE process_handle;
  HANDLE thread_handle;
  bool is_dll;             // Is dynamic library?
  bool exited;             // Did the process exit?

  easet_t bpts;     // breakpoint list
  easet_t removed_bpts; // removed breakpoints

  FILE *mapfp;             // map file handle

  int npending_signals;    // number of pending signals
  bool may_run;
  bool requested_to_suspend;
  bool in_event;           // IDA kernel is handling a debugger event

  ea_t r_debug_ea;
  qstring interp;

  qstring exe_path;        // name of the executable file

  linux_debmod_t();
  ~linux_debmod_t();

  void add_thread(int tid);
  void del_thread(int tid);
  thread_info_t *get_thread(thid_t tid);
  bool retrieve_pending_signal(pid_t *pid, int *status);
  int get_debug_event(debug_event_t *event, int timeout_ms);
  bool del_pending_event(event_id_t id, const char *module_name);
  void enqueue_event(const debug_event_t &ev, queue_pos_t pos);
  bool suspend_all_threads(void);
  bool resume_all_threads(void);
  int dbg_freeze_threads(thid_t tid, bool exclude=true);
  int dbg_thaw_threads(thid_t tid, bool exclude=true);
  void set_thread_state(thread_info_t &ti, thstate_t state);
  bool resume_app(thid_t tid);
  bool has_pending_events(void);
  bool read_asciiz(tid_t tid, ea_t ea, char *buf, size_t bufsize, bool suspend=false);
  int _read_memory(int tid, ea_t ea, void *buffer, int size, bool suspend=false);
  int _write_memory(int tid, ea_t ea, const void *buffer, int size, bool suspend=false);
  void add_dll(ea_t base, asize_t size, const char *modname, const char *soname);
  asize_t calc_module_size(const meminfo_vec_t &miv, const memory_info_t *mi);
  bool import_dll(image_info_t &ii, name_info_t &ni);
  void enum_names(const char *libpath=NULL);
  bool add_shlib_bpt(const meminfo_vec_t &miv, bool attaching);
  bool is_bptsize(int size);
  bool is_bptcode(const void *buffer, int size);
  bool gen_library_events(int tid);
  bool emulate_retn(int tid);
  void cleanup(void);
  void refresh_process_list(void);
  bool handle_process_start(pid_t pid, bool attaching);
  int get_memory_info(meminfo_vec_t &areas, bool suspend);
  bool set_hwbpts(HANDLE hThread);
  virtual bool refresh_hwbpts();
  void handle_dll_movements(const meminfo_vec_t &miv);
  bool idaapi thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea);
  bool read_mapping(mapfp_entry_t *me);
  bool get_soname(const char *fname, qstring *soname);
  ea_t find_pending_name(const char *name);
  bool handle_hwbpt(debug_event_t *event);

  //
  virtual int idaapi dbg_init(bool _debug_debugger);
  virtual void idaapi dbg_term(void);
  virtual int  idaapi dbg_process_get_info(int n,
    const char *input,
    process_info_t *info);
  virtual int  idaapi dbg_detach_process(void);
  virtual int  idaapi dbg_start_process(const char *path,
    const char *args,
    const char *startdir,
    int flags,
    const char *input_path,
    uint32 input_file_crc32);
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms);
  virtual int  idaapi dbg_attach_process(pid_t process_id, int event_id);
  virtual int  idaapi dbg_prepare_to_pause_process(void);
  virtual int  idaapi dbg_exit_process(void);
  virtual int  idaapi dbg_continue_after_event(const debug_event_t *event);
  virtual void idaapi dbg_stopped_at_debug_event(void);
  virtual int  idaapi dbg_thread_suspend(thid_t thread_id);
  virtual int  idaapi dbg_thread_continue(thid_t thread_id);
  virtual int  idaapi dbg_thread_set_step(thid_t thread_id);
  virtual int  idaapi dbg_read_registers(thid_t thread_id,
    int clsmask,
    regval_t *values);
  virtual int  idaapi dbg_write_register(thid_t thread_id,
    int reg_idx,
    const regval_t *value);
  virtual int  idaapi dbg_thread_get_sreg_base(thid_t thread_id,
    int sreg_value,
    ea_t *ea);
  virtual int  idaapi dbg_get_memory_info(meminfo_vec_t &areas);
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size);
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size);
  virtual int  idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len);
  virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len);
  virtual int  idaapi dbg_open_file(const char *file, uint32 *fsize, bool readonly);
  virtual void idaapi dbg_close_file(int fn);
  virtual ssize_t idaapi dbg_read_file(int fn, uint32 off, void *buf, size_t size);
  virtual ssize_t idaapi dbg_write_file(int fn, uint32 off, const void *buf, size_t size);
  virtual int  idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize);
  virtual bool idaapi write_registers(
    thid_t tid,
    int start,
    int count,
    const regval_t *values,
    const int *indices);
  virtual int dbg_freeze_threads_except(thid_t tid) { return dbg_freeze_threads(tid); }
  virtual int dbg_thaw_threads_except(thid_t tid) { return dbg_thaw_threads(tid); }

  // thread_db
  void display_thrinfo(thid_t tid);
  void display_all_threads();
};

//--------------------------------------------------------------------------
// A separate thread to wait for child events.
struct waitpid_thread_t
{
  int mytid;
  qthread_t mythread;
  qsemaphore_t wait_now; // the main thread will raise this semaphore when
                         // waiting on signals is required
  qsemaphore_t signal_ready; // a new signal arrived?
  bool shutdown;         // time to terminate?
  bool waiting;          // this field is used only by the main thread
  int wait_flags;

  // current event info
  int pid;
  int status;

  waitpid_thread_t(qsemaphore_t wait_now, qsemaphore_t signal_ready);
  ~waitpid_thread_t(void);
  int run(void);
  pid_t qwait(void);
};

#endif
