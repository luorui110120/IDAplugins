//
// This file is included from other files, do not directly compile it.
// It contains the implementation of debugger plugin callback functions
//

#include <err.h>
#include <name.hpp>

void idaapi s_stopped_at_debug_event(void)
{
  g_dbgmod.dbg_stopped_at_debug_event();
#ifndef RPC_CLIENT
  // Pass the debug names to the kernel
  g_dbgmod.set_debug_names();
#endif
}

//--------------------------------------------------------------------------
// This code is compiled for local debuggers (like win32_user.w32)
#ifndef RPC_CLIENT

ssize_t dvmsg(int code, rpc_engine_t *, const char *format, va_list va)
{
  if ( code == 0 )
    return vmsg(format, va);
  if ( code > 0 )
    vwarning(format, va);
  else
    verror(format, va);
  return 0;
}

void dmsg(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(0, rpc, format, va);
}

void derror(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(-1, rpc, format, va);
}

void dwarning(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(1, rpc, format, va);
}

#endif // end of 'local debugger' code

bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }

//--------------------------------------------------------------------------
void report_idc_error(rpc_engine_t *, ea_t ea, error_t code, ssize_t errval, const char *errprm)
{
  // copy errval/errprm to the locations expected by qstrerror()
  if ( errprm != NULL && errprm != get_error_string(0) )
    QPRM(1, errprm);
  else if ( code == eOS )
    errno = errval;
  else
    set_error_data(0, errval);
  char buf[MAXSTR];
  qstrerror(code, buf, sizeof(buf));
  warning("AUTOHIDE NONE\n%a: %s", ea, buf);
}

//--------------------------------------------------------------------------
int for_all_debuggers(debmod_visitor_t &v)
{
  return v.visit(&g_dbgmod);
}

gdecode_t idaapi s_get_debug_event(debug_event_t *event, int timeout_ms)
{
  return g_dbgmod.dbg_get_debug_event(event, timeout_ms);
}

int idaapi s_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  return g_dbgmod.dbg_write_register(tid, reg_idx, value);
}

int idaapi s_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  return g_dbgmod.dbg_read_registers(tid, clsmask, values);
}

int idaapi s_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  return g_dbgmod.dbg_is_ok_bpt(type, ea, len);
}

int idaapi s_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  return g_dbgmod.dbg_update_bpts(bpts, nadd, ndel);
}

int idaapi s_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
  return g_dbgmod.dbg_update_lowcnds(lowcnds, nlowcnds);
}

int idaapi s_eval_lowcnd(thid_t tid, ea_t ea)
{
  return g_dbgmod.dbg_eval_lowcnd(tid, ea);
}

int idaapi s_process_get_info(int n,
                              const char *input,
                              process_info_t *info)
{
  return g_dbgmod.dbg_process_get_info(n, input, info);
}

int idaapi s_init(bool _debug_debugger)
{
  g_dbgmod.debugger_flags = debugger.flags;
  return g_dbgmod.dbg_init(_debug_debugger);
}

int  idaapi s_attach_process(pid_t process_id, int event_id)
{
  return g_dbgmod.dbg_attach_process(process_id, event_id);
}

int  idaapi s_detach_process(void)
{
  return g_dbgmod.dbg_detach_process();
}

int  idaapi s_prepare_to_pause_process(void)
{
  return g_dbgmod.dbg_prepare_to_pause_process();
}

int  idaapi s_exit_process(void)
{
  return g_dbgmod.dbg_exit_process();
}

int  idaapi s_continue_after_event(const debug_event_t *event)
{
  return g_dbgmod.dbg_continue_after_event(event);
}

void idaapi s_set_exception_info(const exception_info_t *info, int qty)
{
  g_dbgmod.dbg_set_exception_info(info, qty);
}

int  idaapi s_thread_suspend(thid_t thread_id)
{
  return g_dbgmod.dbg_thread_suspend(thread_id);
}

int  idaapi s_thread_continue(thid_t thread_id)
{
  return g_dbgmod.dbg_thread_continue(thread_id);
}

int  idaapi s_thread_set_step(thid_t thread_id)
{
  return g_dbgmod.dbg_thread_set_step(thread_id);
}

ssize_t idaapi s_read_memory(ea_t ea, void *buffer, size_t size)
{
  return g_dbgmod.dbg_read_memory(ea, buffer, size);
}

ssize_t idaapi s_write_memory(ea_t ea, const void *buffer, size_t size)
{
  return g_dbgmod.dbg_write_memory(ea, buffer, size);
}

int idaapi s_thread_get_sreg_base(thid_t thread_id,
                                  int sreg_value,
                                  ea_t *ea)
{
  return g_dbgmod.dbg_thread_get_sreg_base(thread_id, sreg_value, ea);
}

ea_t idaapi s_map_address(ea_t ea, const regval_t *regs, int regnum)
{
  return g_dbgmod.map_address(ea, regs, regnum);
}

int  idaapi s_get_memory_info(meminfo_vec_t &areas)
{
  return g_dbgmod.dbg_get_memory_info(areas);
}

int idaapi s_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  return g_dbgmod.dbg_start_process(path, args, startdir, flags, input_path, input_file_crc32);
}

//--------------------------------------------------------------------------
int idaapi s_open_file(const char *file, uint32 *fsize, bool readonly)
{
  return g_dbgmod.dbg_open_file(file, fsize, readonly);
}

//--------------------------------------------------------------------------
void idaapi s_close_file(int fn)
{
  return g_dbgmod.dbg_close_file(fn);
}

//--------------------------------------------------------------------------
ssize_t idaapi s_read_file(int fn, uint32 off, void *buf, size_t size)
{
  return g_dbgmod.dbg_read_file(fn, off, buf, size);
}

//--------------------------------------------------------------------------
ssize_t idaapi s_write_file(int fn, uint32 off, const void *buf, size_t size)
{
  return g_dbgmod.dbg_write_file(fn, off, buf, size);
}

//--------------------------------------------------------------------------
bool idaapi s_update_call_stack(thid_t tid, call_stack_t *trace)
{
  return g_dbgmod.dbg_update_call_stack(tid, trace);
}

//--------------------------------------------------------------------------
ea_t idaapi s_appcall(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_info_t *fti,
        int nargs,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags)
{
  return g_dbgmod.dbg_appcall(func_ea, tid, fti, nargs, regargs, stkargs, retregs, errbuf, event, flags);
}

//--------------------------------------------------------------------------
int idaapi s_cleanup_appcall(thid_t tid)
{
  return g_dbgmod.dbg_cleanup_appcall(tid);
}

//--------------------------------------------------------------------------
int idaapi s_ioctl(int fn,
                     const void *buf,
                     size_t size,
                     void **poutbuf,
                     ssize_t *poutsize)
{
  return g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
}

#ifdef REMOTE_DEBUGGER
bool s_close_remote()
{
  return g_dbgmod.close_remote();
}
bool s_open_remote(const char *hostname, int port_number, const char *password)
{
  return g_dbgmod.open_remote(hostname, port_number, password);
}
#else
bool s_open_remote(const char *, int, const char *)
{
  return true;
}

bool s_close_remote(void)
{
  return true;
}

#endif

//--------------------------------------------------------------------------
// Local debuggers must call setup_lowcnd_regfuncs() in order to handle
// register read/write requests from low level bpts.
void init_dbg_idcfuncs(bool init)
{
#if !defined(ENABLE_LOWCNDS) ||                 \
     defined(REMOTE_DEBUGGER) ||                \
     DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  qnotused(init);
#else
  setup_lowcnd_regfuncs(init ? GetRegValue : NULL ,
                        init ? SetRegValue : NULL);
#endif
}
