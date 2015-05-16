#ifndef __MAC_DEBUGGER_MODULE__
#define __MAC_DEBUGGER_MODULE__

/*
*  This is the mach (MAC OS X) debugger module
*
*  Functions unique for Mach (MAC OS X)
*
*/

#include <pro.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <ua.hpp>

#define MD msg("at line %d\n", __LINE__);

#define processor_t mach_processor_t

#include <grp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <mach-o/loader.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <mach/mach.h>
#include <mach/shared_memory_server.h>

#ifdef __arm__
#include "debmod.h"
#include "deb_arm.hpp"
#  define BASE_DEBUGGER_MODULE arm_debmod_t
#else
#include "pc_debmod.h"
#  define BASE_DEBUGGER_MODULE pc_debmod_t
#endif
#ifndef __LINUX__       // linux gcc can not compile macho-o headers
#include "symmacho.hpp"
#endif

#include <set>
#include <map>

typedef int HANDLE;

#define INVALID_HANDLE_VALUE (-1)

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERNAL DATA
//
//--------------------------------------------------------------------------
// processes list information
typedef qvector<process_info_t> processes_t;

enum run_state_t
{
  rs_running,
  rs_pausing,
  rs_suspended, // used by iphone
  rs_exiting,
  rs_exited
};

// image information
struct image_info_t
{
  image_info_t() : base(BADADDR), imagesize(0) {}
  image_info_t(ea_t _base, uint32 _imagesize, const qstring &_name)
    : base(_base), imagesize(_imagesize), name(_name) {}
  ea_t base;
  uint32 imagesize;
  qstring name;
};

typedef std::map<ea_t, image_info_t> images_t; // key: image base address

typedef std::set<ea_t> easet_t;         // set of addresses

union my_mach_msg_t
{
  mach_msg_header_t hdr;
  char data[1024];
  void display(const char *header);
};

enum block_type_t
{
  bl_none,                      // process is running
  bl_signal,                    // blocked due to a signal (must say PTRACE_CONT)
  bl_exception,                 // blocked due to an exception (must say task_resume())
};

// thread information
struct ida_thread_info_t
{
  ida_thread_info_t(thid_t t, mach_port_t p)
    : tid(t), port(p), child_signum(0), asked_step(false), single_step(false),
    pending_sigstop(false) {}
  int tid;
  mach_port_t port;
  int child_signum;
  bool asked_step;
  bool single_step;
  bool pending_sigstop;
  block_type_t block;
  my_mach_msg_t excmsg;
  bool blocked(void) const { return block != bl_none; }
};

typedef std::map<int, ida_thread_info_t> threads_t; // (tid -> info)

struct mach_exception_port_info_t
{
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  mach_msg_type_number_t count;
};

typedef qvector<struct nlist_64> nlists_t;
typedef qvector<dyld_raw_info> dyriv_t;

//--------------------------------------------------------------------------
struct mach_exception_info_t
{
  task_t task_port;
  thread_t thread_port;
  exception_type_t exception_type;
  exception_data_t exception_data;
  mach_msg_type_number_t data_count;
};

class mac_debmod_t: public BASE_DEBUGGER_MODULE
{
  typedef BASE_DEBUGGER_MODULE inherited;
public:
  processes_t processes;

  // debugged process information
  mach_port_t task;        // debugged application's task port
  int pid;                 // process id

  bool in_ptrace;          // We use ptrace to start the debugging session
                           // but since it is badly broken, we detach and
                           // revert to low-level mach api immediately after that
  bool is_dll;             // Is dynamic library?

  run_state_t run_state;

  ea_t dylib;              // address of dylib mach-o header
  ea_t dylib_infos;        // address of _dyld_all_image_infos
  dyld_raw_infos dyri;

  images_t dlls; // list of loaded dynamic libraries

  easet_t dlls_to_import;          // list of dlls to import information from

  inline bool exited(void)
  {
    return run_state == rs_exited;
  }

  threads_t threads;

  struct stored_signal_t
  {
    pid_t pid;
    int status;
  };
  typedef qvector<stored_signal_t> stored_signals_t;
  static stored_signals_t pending_signals; // signals retrieved by other threads

  easet_t bpts;            // breakpoint list

  bool attaching;          // Handling events linked to PTRACE_ATTACH, don't run the program yet
  bool is_leopard;

  mach_port_t exc_port;
  mach_exception_port_info_t saved_exceptions;

  mac_debmod_t();
  ~mac_debmod_t();

  void handle_dyld_bpt(const debug_event_t *event);
  bool retrieve_pending_signal(int *status);
  kern_return_t read_mem(ea_t ea, void *buffer, int size);
  void unblock_all_threads();
  void resume_all_threads();
  bool suspend_all_threads();
  bool my_resume_thread(ida_thread_info_t &ti);
  pid_t qwait(int *status, bool hang);
  void get_debug_events(int timeout_ms);
  kern_return_t
    catch_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    exception_data_t code_vector,
    mach_msg_type_number_t code_count);
  ea_t get_ip(thid_t tid);
  uval_t get_dr(thid_t tid, int idx);
  bool set_dr(thid_t tid, int idx, uval_t value);
  bool idaapi thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea);
  int get_memory_info(meminfo_vec_t &miv, bool suspend);
  image_info_t *get_image(ea_t addr, asize_t size);
  void init_dylib(ea_t addr, const char *fname);
  void update_dylib(void);
  bool exist_dll(const dyriv_t &riv, ea_t base);
  bool is_dylib_header(ea_t base, char *filename, size_t namesize);
  virtual bool refresh_hwbpts();
  virtual bool set_hwbpts(HANDLE hThread);
  bool handle_process_start(pid_t _pid);
  void term_exception_ports(void);
  void init_exception_ports(void);
  thid_t init_main_thread(void);
  bool update_threads(void);
  bool thread_exit_event_planned(thid_t tid);
  void refresh_process_list(void);
  void cleanup(void);
  bool xfer_memory(ea_t ea, void *buffer, int size, bool write);
  bool import_dll_to_database(ea_t imagebase, name_info_t &ni);
  bool import_dll(linput_t *li, ea_t base, name_info_t &ni);
  void add_dll(ea_t addr, const char *fname);
  int _write_memory(ea_t ea, const void *buffer, int size, bool suspend=false);
  int _read_memory(ea_t ea, void *buffer, int size, bool suspend=false);
  bool xfer_page(ea_t ea, void *buffer, int size, bool write);
  kern_return_t write_mem(ea_t ea, void *buffer, int size);
  int exception_to_signal(const mach_exception_info_t *exinf);
  bool check_for_exception(int timeout, mach_exception_info_t *exinf);
  bool handle_signal(
        int code,
        debug_event_t *event,
        block_type_t block,
        const my_mach_msg_t *excmsg);
  bool check_for_exception(
        int timeout,
        mach_exception_info_t *exinf,
        my_mach_msg_t *excmsg);
  bool is_task_valid(task_t task);
  int32 qptrace(int request, pid_t pid, caddr_t addr, int data);
  ida_thread_info_t *get_thread(thid_t tid);

  //--------------------------------------------------------------------------
  #define DEFINE_GET_STATE_FUNC(name, type, flavor)        \
  bool name(thid_t tid, type *state)                       \
  {                                                        \
    ida_thread_info_t *ti = get_thread(tid);               \
    if ( ti == NULL )                                      \
      return false;                                        \
    mach_port_t port = ti->port;                           \
    mach_msg_type_number_t stateCount = flavor ## _COUNT;  \
    kern_return_t err;                                     \
    err = thread_get_state(port,                           \
                           flavor,                         \
                           (thread_state_t)state,          \
                           &stateCount);                   \
    QASSERT(30105, stateCount == flavor ## _COUNT);               \
    if ( err != KERN_SUCCESS )                             \
    {                                                      \
      debdeb("tid=%d port=%d: " #name ": %s\n", tid, port, mach_error_string(err)); \
      return false;                                        \
    }                                                      \
    return true;                                           \
  }

  #define DEFINE_SET_STATE_FUNC(name, type, flavor)        \
  bool name(thid_t tid, const type *state)                 \
  {                                                        \
    ida_thread_info_t *ti = get_thread(tid);               \
    if ( ti == NULL )                                      \
      return false;                                        \
    mach_port_t port = ti->port;                           \
    mach_msg_type_number_t stateCount = flavor ## _COUNT;  \
    kern_return_t err;                                     \
    err = thread_set_state(port,                           \
                           flavor,                         \
                           (thread_state_t)state,          \
                           stateCount);                    \
    QASSERT(30106, stateCount == flavor ## _COUNT);               \
    return err == KERN_SUCCESS;                            \
  }

  //--------------------------------------------------------------------------
#ifdef __arm__
  DEFINE_GET_STATE_FUNC(get_thread_state, arm_thread_state_t, ARM_THREAD_STATE, ARM_THREAD_STATE_COUNT)
  DEFINE_SET_STATE_FUNC(set_thread_state, const arm_thread_state_t, ARM_THREAD_STATE, ARM_THREAD_STATE_COUNT)
//  DEFINE_GET_STATE_FUNC(get_float_state, arm_vfp_state_t, ARM_FLOAT_STATE, ARM_FLOAT_STATE_COUNT)
//  DEFINE_SET_STATE_FUNC(set_float_state, const arm_vfp_state_t, ARM_FLOAT_STATE, ARM_FLOAT_STATE_COUNT)
#define machine_thread_state_t arm_thread_state_t
#define machine_float_state_t  arm_vfp_state_t
#define IDA_THREAD_STATE       ARM_THREAD_STATE
#define IDA_THREAD_STATE_COUNT ARM_THREAD_STATE_COUNT
// redefine EXC_MASK_ALL (default value is 0x7FE which is not accepted by task_set_exception_ports)
#undef EXC_MASK_ALL
#define EXC_MASK_ALL 0x3FE
#else
#ifdef __X64__
#define IDA_THREAD_STATE          x86_THREAD_STATE64
#define IDA_FLOAT_STATE           x86_FLOAT_STATE64
#define IDA_EXCEPTION_STATE       x86_EXCEPTION_STATE64
#define IDA_DEBUG_STATE           x86_DEBUG_STATE64
#define IDA_THREAD_STATE_COUNT    x86_THREAD_STATE64_COUNT
#define IDA_FLOAT_STATE_COUNT     x86_FLOAT_STATE64_COUNT
#define IDA_EXCEPTION_STATE_COUNT x86_EXCEPTION_STATE64_COUNT
#define IDA_DEBUG_STATE_COUNT     x86_DEBUG_STATE64_COUNT
#define machine_thread_state_t    x86_thread_state64_t
#define machine_float_state_t     x86_float_state64_t
#define machine_debug_state_t     x86_debug_state64_t
#define __eflags __rflags
#define __eax    __rax
#define __ebx    __rbx
#define __ecx    __rcx
#define __edx    __rdx
#define __esi    __rsi
#define __edi    __rdi
#define __ebp    __rbp
#define __esp    __rsp
#define __eip    __rip
#else
#define IDA_THREAD_STATE          x86_THREAD_STATE32
#define IDA_FLOAT_STATE           x86_FLOAT_STATE32
#define IDA_EXCEPTION_STATE       x86_EXCEPTION_STATE32
#define IDA_DEBUG_STATE           x86_DEBUG_STATE32
#define IDA_THREAD_STATE_COUNT    x86_THREAD_STATE32_COUNT
#define IDA_FLOAT_STATE_COUNT     x86_FLOAT_STATE32_COUNT
#define IDA_EXCEPTION_STATE_COUNT x86_EXCEPTION_STATE32_COUNT
#define IDA_DEBUG_STATE_COUNT     x86_DEBUG_STATE32_COUNT
#define machine_thread_state_t    x86_thread_state32_t
#define machine_float_state_t     x86_float_state32_t
#define machine_debug_state_t     x86_debug_state32_t
#endif
  DEFINE_GET_STATE_FUNC(get_thread_state, machine_thread_state_t, IDA_THREAD_STATE)
  DEFINE_SET_STATE_FUNC(set_thread_state, machine_thread_state_t, IDA_THREAD_STATE)
  DEFINE_GET_STATE_FUNC(get_float_state,  machine_float_state_t,  IDA_FLOAT_STATE)
  DEFINE_SET_STATE_FUNC(set_float_state,  machine_float_state_t,  IDA_FLOAT_STATE)
  DEFINE_GET_STATE_FUNC(get_debug_state,  machine_debug_state_t,  IDA_DEBUG_STATE)
  DEFINE_SET_STATE_FUNC(set_debug_state,  machine_debug_state_t,  IDA_DEBUG_STATE)
#endif
  //--------------------------------------------------------------------------
  inline thid_t maintid(void)
  {
    return threads.begin()->first;
  }

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
  virtual int  idaapi dbg_get_memory_info(meminfo_vec_t &miv);
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size);
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size);
  virtual int  idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len);
  virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len);
  virtual int  idaapi dbg_open_file(const char *file, uint32 *fsize, bool readonly);
  virtual void idaapi dbg_close_file(int fn);
  virtual ssize_t idaapi dbg_read_file(int fn, uint32 off, void *buf, size_t size);
  virtual ssize_t idaapi dbg_write_file(int fn, uint32 off, const void *buf, size_t size);
  virtual bool idaapi write_registers(
    thid_t tid,
    int start,
    int count,
    const regval_t *values,
    const int *indices);

  //
#ifdef __arm__
  int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) { return 0; }
#endif

  virtual int dbg_freeze_threads_except(thid_t tid);
  virtual int dbg_thaw_threads_except(thid_t tid);
};

#endif
