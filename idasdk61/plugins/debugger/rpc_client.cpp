
//  This file is included in the debugger stub that runs on the computer with IDA

#include <pro.h>
#include <name.hpp>
#include "rpc_client.h"

//--------------------------------------------------------------------------
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

//--------------------------------------------------------------------------
// check and send to the remote server the specified stub
// do it only if its crc does not match the specified crc
// this function runs on the local machine with ida interface
static uchar *sync_stub(const char *fname, uint32 crc, size_t *psize)
{
  bool complain = true;
  uchar *retval = NULL;
  char path[QMAXPATH];
  if ( getsysfile(path, sizeof(path), fname, NULL) != NULL )
  {
    linput_t *li = open_linput(path, false);
    if ( li != NULL )
    {
      int32 size = qlsize(li);
      if ( size > 0 )
      {
        bytevec_t buf;
        buf.resize(size);
        if ( qlread(li, buf.begin(), size) == size )
        {
          complain = false;
          if ( calc_crc32(0, buf.begin(), size) != crc )
          {
            *psize = size;
            retval = buf.extract();
          }
          else
          {
            msg("Kernel debugger stub is up to date...\n");
            *psize = 1;       // signal ok
          }
        }
      }
      close_linput(li);
    }
  }
  if ( complain )
    warning("AUTOHIDE NONE\nCould not find/read debugger stub %s", fname);
  return retval;
}

//--------------------------------------------------------------------------
rpc_client_t::rpc_client_t(SOCKET rpc_socket): rpc_engine_t(rpc_socket)
{
  memset(&pending_event, 0, sizeof(debug_event_t));
  is_server = false;
}

//--------------------------------------------------------------------------
// requests received from the server.
// here the client handles certain server -> client requests
bytevec_t rpc_client_t::perform_request(const rpc_packet_t *rp)
{
  const uchar *ptr = (const uchar *)(rp + 1);
  const uchar *end = ptr + rp->length;
  bytevec_t cmd = prepare_rpc_packet(RPC_OK);

  switch ( rp->code )
  {
    // send_debug_names_to_ida() is thread safe
    case RPC_SET_DEBUG_NAMES:
      {
        int qty = extract_long(&ptr, end);
        ea_t *addrs = new ea_t[qty];
        if ( addrs == NULL )
          goto nomem;

        char **names = new char *[qty];
        if ( names == NULL )
        {
          delete [] addrs;
          goto nomem;
        }
        char name[MAXSTR];
        ea_t old = 0;
        name[0] = '\0';
        for ( int i=0; i < qty; i++ )
        {
          adiff_t o2 = extract_ea64(&ptr, end);
          if ( extract_long(&ptr, end) )
            o2 = -o2;
          old += o2;
          addrs[i] = old;
          int oldlen = extract_long(&ptr, end);
          qstrncpy(&name[oldlen], extract_str(&ptr, end), sizeof(name)-oldlen);
          names[i] = qstrdup(name);
        }
        int result = send_debug_names_to_ida(addrs, names, qty);
        verb(("set_debug_name(qty=%d) => %d\n", qty, result));
        append_dd(cmd, result);
        for ( int i=0; i < qty; i++ )
          qfree(names[i]);
        delete [] addrs;
        delete [] names;
      }
      break;

    // send_debug_event_to_ida() is thread safe
    case RPC_HANDLE_DEBUG_EVENT:
      {
        debug_event_t ev;
        extract_debug_event(&ptr, end, &ev);
        int rqflags = extract_long(&ptr, end);
        int code = send_debug_event_to_ida(&ev, rqflags);
        append_dd(cmd, code);
      }
      break;

    // sync_stub() is thread safe
    case RPC_SYNC_STUB:
      {
        char *fname = extract_str(&ptr, end);
        uint32 crc = extract_long(&ptr, end);
        size_t size = 0;
        uchar *contents = sync_stub(fname, crc, &size);
        append_dd(cmd, (uint32)size);
        if ( contents != NULL )
        {
          append_memory(cmd, contents, size);
          qfree(contents);
        }
      }
      break;

    // msg/error/warning are thread safe
    case RPC_ERROR:
    case RPC_MSG:
    case RPC_WARNING:
      {
        char *str = extract_str(&ptr, end);
        if ( rp->code == RPC_MSG)
          msg("%s", str);
        else if ( rp->code == RPC_ERROR )
          error("%s", str);
        else
          warning("%s", str);
      }
      break;

    // no external functions are called
    case RPC_EVENT:
      {
        extract_debug_event(&ptr, end, &pending_event);
        has_pending_event = true;
        cmd = prepare_rpc_packet(RPC_EVOK);
        verbev(("got event, storing it and sending RPC_EVOK\n"));
      }
      break;

    // i doubt that this code is used on the client side
    // ioctl_handler is NULL
    case RPC_IOCTL:
      {
        int code = handle_ioctl_packet(cmd, ptr, end);
        if ( code != RPC_OK )
          return prepare_rpc_packet((uchar)code);
      }
      break;

    // report_idc_error() is thread safe
    case RPC_REPORT_IDC_ERROR:
      {
        ea_t ea = extract_ea64(&ptr, end);
        error_t code = extract_long(&ptr, end);
        const char *errprm;
        ssize_t errval;
        if ( extract_byte(&ptr, end) )
        {
          errprm = extract_str(&ptr, end);
          errval = (ssize_t)errprm;
        }
        else
        {
          errprm = NULL;
          errval = extract_ea64(&ptr, end);
        }
        report_idc_error(NULL, ea, code, errval, errprm);
      }
      break;

    default:
      return prepare_rpc_packet(RPC_UNK);
nomem:
      return prepare_rpc_packet(RPC_MEM);
  }
  return cmd;
}

//--------------------------------------------------------------------------
// do nothing, we don't need to poll
int rpc_client_t::poll_events(int /*timeout_ms*/)
{
  return 0;
}
