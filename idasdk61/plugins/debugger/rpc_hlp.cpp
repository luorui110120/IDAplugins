
#include <pro.h>
#include <typeinf.hpp>
#include "rpc_hlp.h"
using namespace std;

//--------------------------------------------------------------------------
const char *get_rpc_name(int code)
{
  switch ( code )
  {
    case RPC_OK                      : return "RPC_OK";
    case RPC_UNK                     : return "RPC_UNK";
    case RPC_MEM                     : return "RPC_MEM";
    case RPC_OPEN                    : return "RPC_OPEN";
    case RPC_EVENT                   : return "RPC_EVENT";
    case RPC_EVOK                    : return "RPC_EVOK";
    case RPC_INIT                    : return "RPC_INIT";
    case RPC_TERM                    : return "RPC_TERM";
    case RPC_GET_PROCESS_INFO        : return "RPC_GET_PROCESS_INFO";
    case RPC_DETACH_PROCESS          : return "RPC_DETACH_PROCESS";
    case RPC_START_PROCESS           : return "RPC_START_PROCESS";
    case RPC_GET_DEBUG_EVENT         : return "RPC_GET_DEBUG_EVENT";
    case RPC_ATTACH_PROCESS          : return "RPC_ATTACH_PROCESS";
    case RPC_PREPARE_TO_PAUSE_PROCESS: return "RPC_PREPARE_TO_PAUSE_PROCESS";
    case RPC_EXIT_PROCESS            : return "RPC_EXIT_PROCESS";
    case RPC_CONTINUE_AFTER_EVENT    : return "RPC_CONTINUE_AFTER_EVENT";
    case RPC_STOPPED_AT_DEBUG_EVENT  : return "RPC_STOPPED_AT_DEBUG_EVENT";
    case RPC_TH_SUSPEND              : return "RPC_TH_SUSPEND";
    case RPC_TH_CONTINUE             : return "RPC_TH_CONTINUE";
    case RPC_TH_SET_STEP             : return "RPC_TH_SET_STEP";
    case RPC_READ_REGS               : return "RPC_READ_REGS";
    case RPC_WRITE_REG               : return "RPC_WRITE_REG";
    case RPC_GET_MEMORY_INFO         : return "RPC_GET_MEMORY_INFO";
    case RPC_READ_MEMORY             : return "RPC_READ_MEMORY";
    case RPC_WRITE_MEMORY            : return "RPC_WRITE_MEMORY";
    case RPC_ISOK_BPT                : return "RPC_ISOK_BPT";
    case RPC_UPDATE_BPTS             : return "RPC_UPDATE_BPTS";
    case RPC_UPDATE_LOWCNDS          : return "RPC_UPDATE_LOWCNDS";
    case RPC_EVAL_LOWCND             : return "RPC_EVAL_LOWCND";
    case RPC_GET_SREG_BASE           : return "RPC_GET_SREG_BASE";
    case RPC_SET_EXCEPTION_INFO      : return "RPC_SET_EXCEPTION_INFO";
    case RPC_OPEN_FILE               : return "RPC_OPEN_FILE";
    case RPC_CLOSE_FILE              : return "RPC_CLOSE_FILE";
    case RPC_READ_FILE               : return "RPC_READ_FILE";
    case RPC_WRITE_FILE              : return "RPC_WRITE_FILE";
    case RPC_IOCTL                   : return "RPC_IOCTL";
    case RPC_UPDATE_CALL_STACK       : return "RPC_UPDATE_CALL_STACK";
    case RPC_APPCALL                 : return "RPC_APPCALL";
    case RPC_CLEANUP_APPCALL         : return "RPC_CLEANUP_APPCALL";
    case RPC_SET_DEBUG_NAMES         : return "RPC_SET_DEBUG_NAMES";
    case RPC_SYNC_STUB               : return "RPC_SYNC_STUB";
    case RPC_ERROR                   : return "RPC_ERROR";
    case RPC_MSG                     : return "RPC_MSG";
    case RPC_WARNING                 : return "RPC_WARNING";
    case RPC_HANDLE_DEBUG_EVENT      : return "RPC_HANDLE_DEBUG_EVENT";
    case RPC_REPORT_IDC_ERROR        : return "RPC_REPORT_IDC_ERROR";
  }
  static char buf[16];
  qsnprintf(buf, sizeof(buf), "RPC_%d", code);
  return buf;
}

//--------------------------------------------------------------------------
void finalize_packet(bytevec_t &cmd)
{
  rpc_packet_t *rp = (rpc_packet_t *)cmd.begin();
  rp->length = qhtonl(uint32(cmd.size() - sizeof(rpc_packet_t)));
}

//--------------------------------------------------------------------------
char *extract_str(const uchar **ptr, const uchar *end)
{
  char *str = (char *)*ptr;
  *ptr = (const uchar *)strchr(str, '\0') + 1;
  if ( *ptr > end )
    *ptr = end;
  return str;
}

//--------------------------------------------------------------------------
void append_memory_info(bytevec_t &s, const memory_info_t *info)
{
  append_ea64(s, info->sbase);
  append_ea64(s, info->startEA - (info->sbase << 4));
  append_ea64(s, info->size());
  append_dd(s, info->perm | (info->bitness<<4));
  append_str(s, info->name.c_str());
  append_str(s, info->sclass.c_str());
}

//--------------------------------------------------------------------------
void extract_memory_info(const uchar **ptr, const uchar *end, memory_info_t *info)
{
  info->sbase   = extract_ea64(ptr, end);
  info->startEA = (info->sbase << 4) + extract_ea64(ptr, end);
  info->endEA   = info->startEA + extract_ea64(ptr, end);
  int v = extract_long(ptr, end);
  info->perm    = uchar(v);
  info->bitness = uchar(v>>4);
  info->name    = extract_str(ptr, end);
  info->sclass  = extract_str(ptr, end);
}

//--------------------------------------------------------------------------
void append_process_info(bytevec_t &s, const process_info_t *info)
{
  append_dd(s, info->pid);
  append_str(s, info->name);
}

//--------------------------------------------------------------------------
void extract_process_info(const uchar **ptr, const uchar *end, process_info_t *info)
{
  info->pid = extract_long(ptr, end);
  char *name = extract_str(ptr, end);
  qstrncpy(info->name, name, sizeof(info->name));
}

//--------------------------------------------------------------------------
void append_module_info(bytevec_t &s, const module_info_t *info)
{
  append_str(s, info->name);
  append_ea64(s, info->base);
  append_ea64(s, info->size);
  append_ea64(s, info->rebase_to);
}

//--------------------------------------------------------------------------
void extract_module_info(const uchar **ptr, const uchar *end, module_info_t *info)
{
  char *name = extract_str(ptr, end);
  info->base = extract_ea64(ptr, end);
  info->size = extract_ea64(ptr, end);
  info->rebase_to = extract_ea64(ptr, end);
  qstrncpy(info->name, name, sizeof(info->name));
}

//--------------------------------------------------------------------------
void append_exception(bytevec_t &s, const e_exception_t *e)
{
  append_dd(s, e->code);
  append_dd(s, e->can_cont);
  append_ea64(s, e->ea);
  append_str(s, e->info);
}

//--------------------------------------------------------------------------
void extract_exception(const uchar **ptr, const uchar *end, e_exception_t *exc)
{
  exc->code     = extract_long(ptr, end);
  exc->can_cont = extract_long(ptr, end);
  exc->ea       = extract_ea64(ptr, end);
  char *info    = extract_str(ptr, end);
  qstrncpy(exc->info, info, sizeof(exc->info));
}

//--------------------------------------------------------------------------
void extract_debug_event(const uchar **ptr, const uchar *end, debug_event_t *ev)
{
  ev->eid     = event_id_t(extract_long(ptr, end));
  ev->pid     = extract_long(ptr, end);
  ev->tid     = extract_long(ptr, end);
  ev->ea      = extract_ea64(ptr, end);
  ev->handled = extract_long(ptr, end);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      extract_module_info(ptr, end, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      ev->exit_code = extract_long(ptr, end);
      break;
    case BREAKPOINT:     // Breakpoint reached
      extract_breakpoint(ptr, end, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      extract_exception(ptr, end, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      qstrncpy(ev->info, extract_str(ptr, end), sizeof(ev->info));
      break;
  }
}

//--------------------------------------------------------------------------
void append_debug_event(bytevec_t &s, const debug_event_t *ev)
{
  append_dd(s, ev->eid);
  append_dd(s, ev->pid);
  append_dd(s, ev->tid);
  append_ea64  (s, ev->ea);
  append_dd(s, ev->handled);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      append_module_info(s, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      append_dd(s, ev->exit_code);
      break;
    case BREAKPOINT:     // Breakpoint reached
      append_breakpoint(s, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      append_exception(s, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      append_str(s, ev->info);
      break;
  }
}

//--------------------------------------------------------------------------
exception_info_t *extract_exception_info(
        const uchar **ptr,
        const uchar *end,
        int qty)
{
  exception_info_t *extable = NULL;
  if ( qty > 0 )
  {
    extable = new exception_info_t[qty];
    if ( extable != NULL )
    {
      for ( int i=0; i < qty; i++ )
      {
        extable[i].code  = extract_long(ptr, end);
        extable[i].flags = extract_long(ptr, end);
        extable[i].name  = extract_str(ptr, end);
        extable[i].desc  = extract_str(ptr, end);
      }
    }
  }
  return extable;
}

//--------------------------------------------------------------------------
void append_exception_info(bytevec_t &s, const exception_info_t *table, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    append_dd(s, table[i].code);
    append_dd(s, table[i].flags);
    append_str(s, table[i].name.c_str());
    append_str(s, table[i].desc.c_str());
  }
}

//--------------------------------------------------------------------------
void extract_call_stack(const uchar **ptr, const uchar *end, call_stack_t *trace)
{
  trace->dirty = false;
  int n = extract_long(ptr, end);
  trace->resize(n);
  for ( int i=0; i < n; i++ )
  {
    call_stack_info_t &ci = (*trace)[i];
    ci.callea = extract_ea64(ptr, end);
    ci.funcea = extract_ea64(ptr, end);
    ci.fp     = extract_ea64(ptr, end);
    ci.funcok = extract_long(ptr, end);
  }
}

//--------------------------------------------------------------------------
void append_call_stack(bytevec_t &s, const call_stack_t &trace)
{
  int n = trace.size();
  append_dd(s, n);
  for ( int i=0; i < n; i++ )
  {
    const call_stack_info_t &ci = trace[i];
    append_ea64(s, ci.callea);
    append_ea64(s, ci.funcea);
    append_ea64(s, ci.fp);
    append_dd(s, ci.funcok);
  }
}

//--------------------------------------------------------------------------
static void extract_func_type_info(
        const uchar **ptr,
        const uchar *end,
        func_type_info_t *fti)
{
  fti->flags     = extract_long(ptr, end);
  fti->rettype   = extract_type(ptr, end);
  fti->retfields = extract_type(ptr, end);
  fti->retloc    = extract_long(ptr, end);
  fti->stkargs   = extract_long(ptr, end);
  fti->cc        = extract_byte(ptr, end);
  fti->basetype  = extract_byte(ptr, end);

  int n = extract_long(ptr, end);
  fti->spoiled.resize(n);
  for ( int i=0; i < n; i++ )
  {
    reg_info_t &ri = fti->spoiled[i];
    ri.reg  = extract_long(ptr, end);
    ri.size = extract_long(ptr, end);
  }

  n = extract_long(ptr, end);
  fti->resize(n);
  for ( int i=0; i < n; i++ )
  {
    funcarg_info_t &fa = (*fti)[i];
    fa.argloc = extract_long(ptr, end);
    fa.name   = extract_str (ptr, end);
    fa.type   = extract_type(ptr, end);
    fa.fields = extract_type(ptr, end);
  }
}

//--------------------------------------------------------------------------
void extract_regobjs(const uchar **ptr, const uchar *end, regobjs_t *regargs, bool with_values)
{
  int n = extract_long(ptr, end);
  regargs->resize(n);
  for ( int i=0; i < n; i++ )
  {
    regobj_t &ro = (*regargs)[i];
    ro.regidx   = extract_long(ptr, end);
    int size = extract_long(ptr, end);
    ro.value.resize(size);
    if ( with_values )
    {
      ro.relocate = extract_long(ptr, end);
      extract_memory(ptr, end, ro.value.begin(), size);
    }
  }
}

//--------------------------------------------------------------------------
static void extract_relobj(
        const uchar **ptr,
        const uchar *end,
        relobj_t *stkargs)
{
  int n = extract_long(ptr, end);
  stkargs->resize(n);
  extract_memory(ptr, end, &(*stkargs)[0], n);

  stkargs->base = extract_ea64(ptr, end);

  n = extract_long(ptr, end);
  stkargs->ri.resize(n);
  extract_memory(ptr, end, stkargs->ri.begin(), n);
}

//--------------------------------------------------------------------------
void extract_appcall(
        const uchar **ptr,
        const uchar *end,
        func_type_info_t *fti,
        regobjs_t *regargs,
        relobj_t *stkargs,
        regobjs_t *retregs)
{
  extract_func_type_info(ptr, end, fti);
  extract_regobjs(ptr, end, regargs, true);
  extract_relobj(ptr, end, stkargs);
  if ( retregs != NULL )
    extract_regobjs(ptr, end, retregs, false);
}

//--------------------------------------------------------------------------
static void append_func_type_info(bytevec_t &s, const func_type_info_t &fti)
{
  append_dd(s, fti.flags);
  append_type(s, fti.rettype);
  append_type(s, fti.retfields);
  append_dd(s, fti.retloc);
  append_dd(s, fti.stkargs);
  append_db(s, fti.cc);
  append_db(s, fti.basetype);

  append_dd(s, fti.spoiled.size());
  for ( size_t i=0; i < fti.spoiled.size(); i++ )
  {
    const reg_info_t &ri = fti.spoiled[i];
    append_dd(s, ri.reg);
    append_dd(s, ri.size);
  }

  append_dd(s, fti.size());
  for ( size_t i=0; i < fti.size(); i++ )
  {
    const funcarg_info_t &fa = fti[i];
    append_dd(s, fa.argloc);
    append_str(s, fa.name);
    append_type(s, fa.type);
    append_type(s, fa.fields);
  }
}

//--------------------------------------------------------------------------
void append_regobjs(bytevec_t &s, const regobjs_t &regargs, bool with_values)
{
  append_dd(s, regargs.size());
  for ( size_t i=0; i < regargs.size(); i++ )
  {
    const regobj_t &ro = regargs[i];
    append_dd(s, ro.regidx);
    append_dd(s, ro.value.size());
    if ( with_values )
    {
      append_dd(s, ro.relocate);
      append_memory(s, ro.value.begin(), ro.value.size());
    }
  }
}

//--------------------------------------------------------------------------
static void append_relobj(bytevec_t &s, const relobj_t &stkargs)
{
  append_dd(s, stkargs.size());
  append_memory(s, stkargs.begin(), stkargs.size());

  append_ea64(s, stkargs.base);

  append_dd(s, stkargs.ri.size());
  append_memory(s, stkargs.ri.begin(), stkargs.ri.size());
}

//--------------------------------------------------------------------------
void append_appcall(
        bytevec_t &s,
        const func_type_info_t &fti,
        const regobjs_t &regargs,
        const relobj_t &stkargs,
        const regobjs_t *retregs)
{
  append_func_type_info(s, fti);
  append_regobjs(s, regargs, true);
  append_relobj(s, stkargs);
  if ( retregs != NULL )
    append_regobjs(s, *retregs, false);
}

//--------------------------------------------------------------------------
static void append_regval(bytevec_t &s, const regval_t *value)
{
  append_dd(s, value->rvtype+2);
  if ( value->rvtype == RVT_INT )
  {
    append_dq(s, value->ival+1);
  }
  else if ( value->rvtype == RVT_FLOAT )
  {
    append_memory(s, value->fval, sizeof(value->fval));
  }
  else
  {
    const bytevec_t &b = value->bytes();
    append_dd(s, b.size());
    append_memory(s, b.begin(), b.size());
  }
}

//--------------------------------------------------------------------------
static void extract_regval(const uchar **ptr, const uchar *end, regval_t *value)
{
  value->clear();
  value->rvtype = extract_long(ptr, end) - 2;
  if ( value->rvtype == RVT_INT )
  {
    value->ival = unpack_dq(ptr, end) - 1;
  }
  else if ( value->rvtype == RVT_FLOAT )
  {
    extract_memory(ptr, end, value->fval, sizeof(value->fval));
  }
  else
  {
    bytevec_t &b = value->_set_bytes();
    int size = extract_long(ptr, end);
    b.resize(size);
    extract_memory(ptr, end, b.begin(), size);
  }
}

//--------------------------------------------------------------------------
void extract_regvals(
        const uchar **ptr,
        const uchar *end,
        regval_t *values,
        int n,
        const uchar *regmap)
{
  for ( int i=0; i < n && *ptr < end; i++ )
    if ( regmap == NULL || test_bit(regmap, i) )
      extract_regval(ptr, end, values+i);
}

//--------------------------------------------------------------------------
void append_regvals(bytevec_t &s, const regval_t *values, int n, const uchar *regmap)
{
  for ( int i=0; i < n; i++ )
    if ( regmap == NULL || test_bit(regmap, i) )
      append_regval(s, values+i);
}

