#ifndef __RPC_DEBUGGER_MODULE__
#define __RPC_DEBUGGER_MODULE__

#include "debmod.h"
#include "rpc_client.h"

class rpc_debmod_t : public debmod_t, public rpc_client_t
{
public:
  rpc_debmod_t();
  bool open_remote(const char *hostname, int port_number, const char *password);
  void connection_failed(rpc_packet_t *rp);
  bool close_remote();
  void neterr(const char *module);

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
  {
    return rpc_engine_t::send_ioctl(fn, buf, size, poutbuf, poutsize);
  }

//--------------------------------------------------------------------------
  inline int getint(ushort code)
  {
    bytevec_t cmd = prepare_rpc_packet((uchar)code);
    return process_long(cmd);
  }
  int getint2(uchar code, int x);

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
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty);
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
  virtual int  idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len);
  virtual int  idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len);
  virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len);
  virtual int  idaapi dbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
  virtual int  idaapi dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds);
  virtual int  idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea);
  virtual int  idaapi dbg_open_file(const char *file, uint32 *fsize, bool readonly);
  virtual void idaapi dbg_close_file(int fn);
  virtual ssize_t idaapi dbg_read_file(int fn, uint32 off, void *buf, size_t size);
  virtual ssize_t idaapi dbg_write_file(int fn, uint32 off, const void *buf, size_t size);
  virtual int  idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize);
  virtual int  idaapi get_system_specific_errno(void) const;
  virtual bool idaapi dbg_update_call_stack(thid_t, call_stack_t *);
  virtual ea_t idaapi dbg_appcall(
    ea_t func_ea,
    thid_t tid,
    const struct func_type_info_t *fti,
    int nargs,
    const struct regobjs_t *regargs,
    struct relobj_t *stkargs,
    struct regobjs_t *retregs,
    qstring *errbuf,
    debug_event_t *event,
    int flags);
  virtual int idaapi dbg_cleanup_appcall(thid_t tid);
  virtual int get_regidx(const char *, int *) { INTERR(30116); }
};

#endif
