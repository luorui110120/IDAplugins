#ifndef __WIN32_DEBUGGER_MODULE__
#define __WIN32_DEBUGGER_MODULE__

#include <algorithm>
#include <map>
#include <set>

using std::for_each;

#ifdef _MSC_VER
using std::pair;
using std::make_pair;
#endif

#ifdef __ARM__
#  define BASE_DEBUGGER_MODULE wince_debmod_t
#  include "wince_debmod.h"
#  define BPT_CODE_SIZE ARM_BPT_SIZE
#else
#  define BASE_DEBUGGER_MODULE pc_debmod_t
#  include "deb_pc.hpp"
#  include "pc_debmod.h"
#  define BPT_CODE_SIZE X86_BPT_SIZE
#endif

#include <Tlhelp32.h>

#include "../../ldr/pe/pe.h"

// AMD64: for some reason the GetThreadContext function overwrites an area bigger
// than the declared CONTEXT structure.
// We redefine the structure to workaround this
#ifdef __X64__
struct MyContext : public CONTEXT
{
  uchar dummy[0x230];
};
#define CONTEXT MyContext
#endif

// Type definitions

class win32_debmod_t;

// image information
struct image_info_t
{
  image_info_t(win32_debmod_t *);
  image_info_t(win32_debmod_t *, ea_t _base, const qstring &_name);
  image_info_t(win32_debmod_t *, ea_t _base, uval_t _imagesize, const qstring &_name);
  image_info_t(win32_debmod_t *, const LOAD_DLL_DEBUG_INFO &i, const char *_name);
  image_info_t(win32_debmod_t *, const module_info_t &m);

  win32_debmod_t *sess;
  ea_t base;
  uval_t imagesize;
  qstring name;
  LOAD_DLL_DEBUG_INFO dll_info;
};

typedef std::map<ea_t, image_info_t> images_t; // key: image base address

#ifdef __ARM__
  #define RC_GENERAL ARM_RC_GENERAL
  #define RC_ALL     ARM_RC_ALL
#else
  #define RC_GENERAL X86_RC_GENERAL
  #define RC_ALL     X86_RC_ALL
#endif

// thread information
struct thread_info_t : public CREATE_THREAD_DEBUG_INFO
{
  thread_info_t(const CREATE_THREAD_DEBUG_INFO &i, thid_t t)
    : CREATE_THREAD_DEBUG_INFO(i), tid(t), suspend_count(0), bpt_ea(BADADDR), flags(0)
  {
    ctx.ContextFlags = 0;
  }
  thid_t tid;                   // thread id
  int suspend_count;
  ea_t bpt_ea;
  int flags;
#define THR_CLSMASK 0x0007      // valid register classes in CONTEXT structure
                                // we use X86_RC.. constants here
#define THR_TRACING 0x0100      // expecting a STEP event
#define THR_FSSAVED 0x0200      // remembered FS value
  CONTEXT ctx;
  // for some reason the FS register gets spoiled in the following conditions:
  //  - operating system is WinXP running under VMware
  //  - sysenter in NtMapViewOfSection is executed with single stepping bit set
  // Naturally, the program crashes later because of that.
  // To avoid this, we remember the FS value and reset it if it gets spoiled after sysenter
  uint32 initial_fs_value;
  void invalidate_context(void) { flags &= ~THR_CLSMASK; ctx.ContextFlags = 0; }
  bool read_context(int clsmask);
  bool is_tracing(void) const { return (flags & THR_TRACING) != 0; }
  void set_tracing(void) { flags |= THR_TRACING; }
  void clr_tracing(void) { flags &= ~THR_TRACING; }
  ea_t get_ip(void) { return read_context(RC_GENERAL) ? ctx.Eip : BADADDR; }
};

// Check if the context structure has valid values at the specified portion
// portion is a conbination of CONTEXT_... bitmasks
inline bool has_portion(const CONTEXT &ctx, int portion)
{
  return (ctx.ContextFlags & portion & 0xFFFF) != 0;
}

// (tid -> info)
struct threads_t: public std::map<DWORD, thread_info_t>
{
  thread_info_t *get(DWORD tid)
  {
    const iterator it = find(tid);
    if ( it == end() )
      return NULL;
    return &it->second;
  }
};

typedef int (*process_cb_t)(debmod_t *, PROCESSENTRY32 *pe32, void *ud);
typedef int (*module_cb_t)(debmod_t *, MODULEENTRY32 *me32, void *ud);

typedef qvector<process_info_t> processes_t;

enum attach_status_t
{
  as_none,       // no attach to process requested
  as_attaching,  // waiting for CREATE_PROCESS_DEBUG_EVENT, indicating the process is attached
  as_breakpoint, // waiting for first breakpoint, indicating the process was properly initialized and suspended
  as_attached,   // process was successfully attached
  as_detaching,  // waiting for next get_debug_event() request, to return the process as detached
};

// set of addresses
typedef std::set<ea_t> easet_t;

// structure for the internal breakpoint information for threads
struct internal_bpt_info_t
{
  int count;            // number of times this breakpoint is 'set'
  uchar orig_bytes[BPT_CODE_SIZE]; // original byte values
};
typedef std::map<ea_t, internal_bpt_info_t> bpt_info_t;

class win32_debmod_t: public BASE_DEBUGGER_MODULE
{
private:
  gdecode_t get_debug_event(debug_event_t *event, int timeout_ms);
  void check_thread(bool must_be_main_thread);
public:
  // debugged process information
  qstring process_path;
  DWORD pid;
  HANDLE process_handle;
  HANDLE thread_handle;
  attach_status_t attach_status;
  int attach_evid;
  ea_t debug_break_ea;          // The address of the kernel breakpoint
                                // 0 means we haven't determined it yet
                                // BADADDR means do not try to determine it
  bool expecting_debug_break;

  images_t curproc; // image of the running process
  images_t dlls; // list of loaded DLLs
  images_t images; // list of detected PE images
  images_t thread_areas; // list of areas related to threads
  images_t class_areas;  // list of areas related to class names

  easet_t dlls_to_import;          // list of dlls to import information from

  bpt_info_t thread_bpts;
  easet_t kernel_bpts;  // set of ida kernel software bpts

  threads_t threads;

  // ID of a thread for which we must emulate a STEP event on XP (using a breakpoint)
  thid_t winxp_step_thread;

  CREATE_PROCESS_DEBUG_INFO cpdi;

  debug_event_t *in_event; // current debug event
  bool fake_suspend_event;
  bool exiting;
  bool DebugBreakProcess_requested;
  processes_t processes;

  // Module specific methods, to be implemented
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

  void patch_context_struct(CONTEXT &ctx, int reg_idx, const regval_t * value);
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
  //
  win32_debmod_t();
  ~win32_debmod_t();

  void handle_pdb_request();
  uint32 calc_imagesize(ea_t base);
  void get_filename_for(
    ea_t image_name_ea,
    bool is_unicode,
    ea_t image_base,
    char *buf,
    size_t bufsize,
    HANDLE process_handle,
    const char *process_path);
  ea_t get_dll_export(
    const images_t &dlls,
    ea_t imagebase,
    const char *exported_name);
  bool create_process(const char *path,
    const char *args,
    const char *startdir,
    bool is_gui,
    PROCESS_INFORMATION *ProcessInformation);
  void show_debug_event(
    const DEBUG_EVENT &ev,
    HANDLE process_handle,
    const char *process_path);

  ssize_t _read_memory(ea_t ea, void *buffer, size_t size, bool suspend = false);
  ssize_t _write_memory(ea_t ea, const void *buffer, size_t size, bool suspend = false);

  int rdmsr(int reg, uint64 *value);
  int wrmsr(int reg, uint64 value);
  int kldbgdrv_access_msr(struct SYSDBG_MSR *msr, bool write);

  // !! OVERWRITTEN METHODS !!
  bool refresh_hwbpts();

  // Utility methods
  gdecode_t handle_exception(debug_event_t *event,
    EXCEPTION_RECORD &er,
    bool was_thread_bpt,
    bool firsttime);
  ssize_t access_memory(ea_t ea, void *buffer, ssize_t size, bool write, bool suspend);
  inline void resume_all_threads(bool raw = false);
  inline void suspend_all_threads(bool raw = false);
  size_t add_dll(image_info_t &ii);
  HANDLE get_thread_handle(thid_t tid);
  int for_each_process(process_cb_t process_cb, void *ud);
  static int get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud);
  void get_debugged_module_info(module_info_t *dmi);
  int for_each_module(DWORD pid, module_cb_t module_cb, void *ud);
  static int process_get_info_cb(debmod_t *, PROCESSENTRY32 *pe32, void *);
  bool myCloseHandle(HANDLE &h);
  void cleanup(void);
  void restore_original_bytes(ea_t ea, bool really_restore = true);
  int save_original_bytes(ea_t ea);
  bool set_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpts(ea_t ea);
  bool has_bpt_at(ea_t ea);
  bool can_access(ea_t addr);
  ea_t get_kernel_bpt_ea(ea_t ea);
  void create_attach_event(debug_event_t *event);
  bool check_for_hwbpt(debug_event_t *event);
  static int get_process_filename(debmod_t *sess, PROCESSENTRY32 *pe32, void *ud);
  ea_t _get_memory_info(ea_t ea, memory_info_t *info);
  bool get_dll_exports(
    const images_t &dlls,
    ea_t imagebase,
    name_info_t &ni,
    const char *exported_name = NULL);
  bool get_filename_from_process(ea_t name_ea,
    bool is_unicode,
    char *buf,
    size_t bufsize);
    bool get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize);
    bool add_thread_areas(
      HANDLE process_handle,
      thid_t tid,
      images_t &thread_areas,
      images_t &class_areas);
  ea_t get_pe_header(ea_t ea, peheader_t *nh);
  bool set_debug_hook(ea_t base);
  bool get_pe_export_name_from_process(ea_t imagebase,
    char *name,
    size_t namesize);

  bool get_mapped_filename(
    HANDLE process_handle,
    ea_t imagebase,
    char *buf,
    size_t bufsize);

  void show_exception_record(const EXCEPTION_RECORD &er, int level=0);

  ea_t pstos0(ea_t ea);
  ea_t s0tops(ea_t ea);

  bool prepare_to_stop_process(debug_event_t *, const threads_t &);
  bool disable_hwbpts();
  bool enable_hwbpts();
  bool may_write(ea_t ea);
  LPVOID correct_exe_image_base(LPVOID base);
#ifdef UNDER_CE
  ea_t get_process_base(size_t size);
#endif
  bool clear_tbit(thread_info_t &th);
  void invalidate_all_contexts(void);

  virtual bool idaapi write_registers(
    thid_t thread_id,
    int start,
    int count,
    const regval_t *values,
    const int *indices = NULL);

  virtual int dbg_freeze_threads_except(thid_t tid);
  virtual int dbg_thaw_threads_except(thid_t tid);
};

ea_t s0tops(ea_t ea);

#endif