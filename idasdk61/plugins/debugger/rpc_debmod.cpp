#include "rpc_debmod.h"
#include <segment.hpp>

//--------------------------------------------------------------------------
rpc_debmod_t::rpc_debmod_t() : rpc_client_t(NULL)
{
  const register_info_t *regs = debugger.registers;
  nregs = debugger.registers_size;
  for ( int i=0; i < nregs; i++, regs++ )
  {
    if ( (regs->flags & REGISTER_SP) != 0 )
      sp_idx = i;
    if ( (regs->flags & REGISTER_IP) != 0 )
      pc_idx = i;
  }
  bpt_code.append(debugger.bpt_bytes, debugger.bpt_size);
  rpc = this;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::handle_ioctl(
  int fn,
  const void *buf,
  size_t size,
  void **poutbuf,
  ssize_t *poutsize)
{
  return rpc_engine_t::send_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
inline int get_expected_addrsize(void)
{
  if ( is_miniidb() )
#ifdef __EA64__
    return 8;
#else
    return 4;
#endif
  return inf.is_64bit() ? 8 : 4;
}

//--------------------------------------------------------------------------
bool rpc_debmod_t::open_remote(const char *hostname, int port_number, const char *password)
{
  rpc_packet_t *rp = NULL;
  irs = init_client_irs(hostname, port_number);
  if ( irs == NULL )
  {
failed:
    connection_failed(rp);
    return false;
  }

  rp = recv_request();
  if ( rp == NULL )
    goto failed;

  if ( rp->code != RPC_OPEN )  // is this an ida debugger server?
  {
    connection_failed(rp);
    rpc_client_t::dwarning("ICON ERROR\nAUTOHIDE NONE\n"
                           "Bogus remote server");
    return false;
  }

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  int version = extract_long(&answer, end);
  int remote_debugger_id = extract_long(&answer, end);
  int easize = extract_long(&answer, end);
  qstring errstr;
  if ( version != IDD_INTERFACE_VERSION )
    errstr.sprnt("protocol version is %d, expected %d", version, IDD_INTERFACE_VERSION);
  else if ( remote_debugger_id != debugger.id )
    errstr.sprnt("debugger id is %d, expected %d (%s)", remote_debugger_id, debugger.id, debugger.name);
  else if ( easize != get_expected_addrsize() )
    errstr.sprnt("address size is %d bytes, expected %d", easize, inf.is_64bit() ? 8 : 4);
  if ( !errstr.empty() )
  {
    connection_failed(rp);
    bytevec_t cmd = prepare_rpc_packet(RPC_OK);
    append_dd(cmd, false);
    send_request(cmd);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
      "Incompatible debugging server:\n"
      "%s\n", errstr.c_str());
    return false;
  }
  qfree(rp);

  bytevec_t cmd = prepare_rpc_packet(RPC_OK);
  append_dd(cmd, true);
  append_str(cmd, password);
  send_request(cmd);

  rp = recv_request();
  if ( rp == NULL || rp->code != RPC_OK )
    goto failed;

  answer = (uchar *)(rp+1);
  end = answer + rp->length;
  bool password_ok = extract_long(&answer, end);
  if ( !password_ok )  // is this an ida debugger server?
  {
    connection_failed(rp);
    warning("ICON ERROR\nAUTOHIDE NONE\n"
      "Bad password");
    return false;
  }

  qfree(rp);
  return true;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_add_bpt(bpttype_t, ea_t, int)
{
  INTERR(30114);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_del_bpt(bpttype_t, ea_t, const uchar *, int)
{
  INTERR(30115);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
  ea_t ea = 0;
  bytevec_t cmd = prepare_rpc_packet(RPC_UPDATE_LOWCNDS);
  append_dd(cmd, nlowcnds);
  const lowcnd_t *lc = lowcnds;
  for ( int i=0; i < nlowcnds; i++, lc++ )
  {
    append_ea64(cmd, lc->ea-ea); ea = lc->ea;
    append_str(cmd, lc->cndbody);
    if ( !lc->cndbody.empty() )
    {
      append_db(cmd, lc->type);
      append_db(cmd, lc->orgbytes.size());
      append_memory(cmd, lc->orgbytes.begin(), lc->orgbytes.size());
      append_ea64(cmd, lc->cmd.ea);
      if ( lc->cmd.ea != BADADDR )
        append_memory(cmd, &lc->cmd, sizeof(lc->cmd));
    }
  }
  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_eval_lowcnd(thid_t tid, ea_t ea)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_EVAL_LOWCND);
  append_dd(cmd, tid);
  append_ea64(cmd, ea);
  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  int skipped = 0;
  update_bpt_info_t *b;
  update_bpt_info_t *bend = bpts + nadd;
  for ( b=bpts; b != bend; b++ )
    if ( b->code != BPT_OK )
      skipped++;
  if ( skipped == nadd && ndel == 0 )
    return 0; // no bpts to update

  bytevec_t cmd = prepare_rpc_packet(RPC_UPDATE_BPTS);
  append_dd(cmd, nadd-skipped);
  append_dd(cmd, ndel);
  ea_t ea = 0;
  for ( b=bpts; b != bend; b++ )
  {
    if ( b->code == BPT_OK )
    {
      append_ea64(cmd, b->ea-ea); ea = b->ea;
      append_db(cmd, (b->size << 4) | b->type);
    }
  }

  ea = 0;
  bend += ndel;
  for ( ; b != bend; b++ )
  {
    append_ea64(cmd, b->ea-ea); ea = b->ea;
    append_db(cmd, b->orgbytes.size());
    append_memory(cmd, b->orgbytes.begin(), b->orgbytes.size());
    append_db(cmd, b->type);
  }

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *ptr = (uchar *)(rp+1);
  const uchar *end = ptr + rp->length;

  int ret = extract_long(&ptr, end);
  bend = bpts + nadd;
  for ( b=bpts; b != bend; b++ )
  {
    if ( b->code == BPT_OK )
    {
      uchar v = extract_byte(&ptr, end);
      b->code = v & 0xF;
      if ( b->code == BPT_OK && b->type == BPT_SOFT )
      {
        uchar len = v >> 4;
        b->orgbytes.resize(len);
        extract_memory(&ptr, end, b->orgbytes.begin(), len);
      }
    }
  }

  bend += ndel;
  for ( ; b != bend; b++ )
    b->code = extract_byte(&ptr, end);

  return ret;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_get_sreg_base(thid_t tid, int sreg_value, ea_t *ea)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_GET_SREG_BASE);
  append_dd(cmd, tid);
  append_dd(cmd, sreg_value);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end);

  if ( result )
    *ea = extract_ea64(&answer, end);

  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_set_exception_info(const exception_info_t *table, int qty)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_SET_EXCEPTION_INFO);
  append_dd(cmd, qty);
  append_exception_info(cmd, table, qty);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_open_file(const char *file, uint32 *fsize, bool readonly)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_OPEN_FILE);
  append_str(cmd, file);
  append_dd(cmd, readonly);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int fn = extract_long(&answer, end);
  if ( fn != -1 )
  {
    if ( fsize != NULL && readonly )
      *fsize = extract_long(&answer, end);
  }
  else
  {
    qerrcode(extract_long(&answer, end));
  }
  qfree(rp);
  return fn;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_close_file(int fn)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_CLOSE_FILE);
  append_dd(cmd, fn);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_read_file(int fn, uint32 off, void *buf, size_t size)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_READ_FILE);
  append_dd(cmd, fn);
  append_dd(cmd, off);
  append_dd(cmd, (uint32)size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int32 rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));

  if ( rsize > 0 )
  {
    if ( rsize > size )
      error("rpc_read_file: protocol error");
    extract_memory(&answer, end, buf, rsize);
  }
  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_write_file(int fn, uint32 off, const void *buf, size_t size)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_WRITE_FILE);
  append_dd(cmd, fn);
  append_dd(cmd, off);
  append_dd(cmd, (uint32)size);
  append_memory(cmd, buf, size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int32 rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));

  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_ISOK_BPT);
  append_dd(cmd, type);
  append_ea64(cmd, ea);
  append_dd(cmd, len+1);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int rpc_debmod_t::getint2(uchar code, int x)
{
  bytevec_t cmd = prepare_rpc_packet(code);
  append_dd(cmd, x);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_init(bool _debug_debugger)
{
  has_pending_event = false;
  poll_debug_events = false;

  bytevec_t cmd = prepare_rpc_packet(RPC_INIT);
  append_dd(cmd, debugger.flags);
  append_dd(cmd, _debug_debugger);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_term(void)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_TERM);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
// input is valid only if n==0
int idaapi rpc_debmod_t::dbg_process_get_info(int n, const char *input, process_info_t *info)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_GET_PROCESS_INFO);
  append_dd(cmd, n);
  if ( n == 0 )
    append_str(cmd, input);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL ) return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end);
  if ( result )
    extract_process_info(&answer, end, info);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_detach_process(void)
{
  return getint(RPC_DETACH_PROCESS);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_START_PROCESS);
  append_str(cmd, path);
  append_str(cmd, args);
  append_str(cmd, startdir);
  append_dd(cmd, flags);
  append_str(cmd, input_path);
  append_dd(cmd, input_file_crc32);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
gdecode_t idaapi rpc_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  if ( has_pending_event )
  {
    verbev(("get_debug_event => has pending event, returning it\n"));
    *event = pending_event;
    has_pending_event = false;
    poll_debug_events = false;
    return GDE_ONE_EVENT;
  }

  gdecode_t result = GDE_NO_EVENT;
  if ( poll_debug_events )
  {
    // do we have something waiting?
    if ( irs_ready(irs, timeout_ms) != 0 )
    {
      verbev(("get_debug_event => remote has an event for us\n"));
      // get the packet - it should be RPC_EVENT (nothing else can be)
      bytevec_t empty;
      rpc_packet_t *rp = process_request(empty);
      verbev(("get_debug_event => processed remote event, has=%d\n", has_pending_event));
      if ( rp != NULL || !has_pending_event )
      {
        warning("rpc: event protocol error (rp=%p has_event=%d)", rp, has_pending_event);
        return GDE_ERROR;
      }
    }
  }
  else
  {
    verbev(("get_debug_event => first time, send GET_DEBUG_EVENT\n"));
    bytevec_t cmd = prepare_rpc_packet(RPC_GET_DEBUG_EVENT);
    append_dd(cmd, timeout_ms);

    rpc_packet_t *rp = process_request(cmd);
    if ( rp == NULL )
      return GDE_ERROR;
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;

    result = gdecode_t(extract_long(&answer, end));
    if ( result >= GDE_ONE_EVENT )
      extract_debug_event(&answer, end, event);
    else
      poll_debug_events = true;
    verbev(("get_debug_event => remote said %d, poll=%d now\n", result, poll_debug_events));
    qfree(rp);
  }
  return result;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_attach_process(pid_t pid, int event_id)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_ATTACH_PROCESS);
  append_dd(cmd, pid);
  append_dd(cmd, event_id);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_prepare_to_pause_process(void)
{
  return getint(RPC_PREPARE_TO_PAUSE_PROCESS);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_exit_process(void)
{
  return getint(RPC_EXIT_PROCESS);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_CONTINUE_AFTER_EVENT);
  append_debug_event(cmd, event);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_stopped_at_debug_event(void)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_STOPPED_AT_DEBUG_EVENT);

  qfree(process_request(cmd));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return getint2(RPC_TH_SUSPEND, tid);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_continue(thid_t tid)
{
  return getint2(RPC_TH_CONTINUE, tid);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_set_step(thid_t tid)
{
  return getint2(RPC_TH_SET_STEP, tid);
}

//--------------------------------------------------------------------------
// prepare bitmap of registers belonging to the specified classes
// return size of the bitmap in bits (always the total number of registers)
static int calc_regmap(bytevec_t *regmap, int clsmask)
{
  int nregs = debugger.registers_size;
  regmap->resize((nregs+7)/8, 0);
  for ( int i=0; i < nregs; i++ )
    if ( (debugger.registers[i].register_class & clsmask) != 0 )
      regmap->set_bit(i);
  return nregs;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_READ_REGS);
  append_dd(cmd, tid);
  append_dd(cmd, clsmask);
  // append additional information about the class structure
  bytevec_t regmap;
  int nregs = calc_regmap(&regmap, clsmask);
  append_dd(cmd, nregs);
  append_memory(cmd, regmap.begin(), regmap.size());

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  if ( result )
    extract_regvals(&answer, end, values, nregs, regmap.begin());
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_WRITE_REG);
  append_dd(cmd, tid);
  append_dd(cmd, reg_idx);
  append_regvals(cmd, value, 1, NULL);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_get_memory_info(meminfo_vec_t &areas)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_GET_MEMORY_INFO);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end) - 2;
  if ( result > 0 )
  {
    int n = extract_long(&answer, end);
    areas.resize(n);
    for ( int i=0; i < n; i++ )
      extract_memory_info(&answer, end, &areas[i]);
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_READ_MEMORY);
  append_ea64(cmd, ea);
  append_dd(cmd, (uint32)size);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  if ( result > 0 )
    extract_memory(&answer, end, buffer, result);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_WRITE_MEMORY);
  append_ea64(cmd, ea);
  append_dd(cmd, (uint32)size);
  append_memory(cmd, buffer, size);

  return process_long(cmd);
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::dbg_update_call_stack(thid_t tid, call_stack_t *trace)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_UPDATE_CALL_STACK);
  append_dd(cmd, tid);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return false;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end);
  if ( result )
    extract_call_stack(&answer, end, trace);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ea_t idaapi rpc_debmod_t::dbg_appcall(
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
  bytevec_t cmd = prepare_rpc_packet(RPC_APPCALL);
  append_ea64(cmd, func_ea);
  append_dd(cmd, tid);
  append_dd(cmd, nargs);
  append_dd(cmd, flags);
  regobjs_t *rr = (flags & APPCALL_MANUAL) == 0 ? retregs : NULL;
  append_appcall(cmd, *fti, *regargs, *stkargs, rr);

  rpc_packet_t *rp = process_request(cmd);
  if ( rp == NULL )
    return BADADDR;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  ea_t sp = extract_ea64(&answer, end);
  if ( sp == BADADDR )
  {
    if ( (flags & APPCALL_DEBEV) != 0 )
      extract_debug_event(&answer, end, event);
    if ( errbuf != NULL )
      *errbuf = extract_str(&answer, end);
  }
  else if ( (flags & APPCALL_MANUAL) == 0 )
  {
    if ( retregs != NULL )
      extract_regobjs(&answer, end, retregs, true);
  }
  qfree(rp);
  return sp;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_cleanup_appcall(thid_t tid)
{
  bytevec_t cmd = prepare_rpc_packet(RPC_CLEANUP_APPCALL);
  append_dd(cmd, tid);
  return process_long(cmd);
}

//--------------------------------------------------------------------------
bool rpc_debmod_t::close_remote()
{
  bytevec_t cmd = prepare_rpc_packet(RPC_OK);
  send_request(cmd);
  term_client_irs(irs);
  irs = NULL;
  network_error_code = 0;
  return true;
}

//--------------------------------------------------------------------------
void rpc_debmod_t::neterr(const char *module)
{
  int code = irs_error(irs);
  error("%s: %s", module, winerr(code));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::get_system_specific_errno(void) const
{
  return irs_error(irs);
}

//--------------------------------------------------------------------------
void rpc_debmod_t::connection_failed(rpc_packet_t *rp)
{
  if ( rp != NULL )
    qfree(rp);
  term_irs();
}
