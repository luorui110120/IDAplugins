#ifndef __RPC_ENGINE__
#define __RPC_ENGINE__

#include <ua.hpp>
#include <idd.hpp>
#include <area.hpp>
#include <diskio.hpp>
#include "rpc_hlp.h"
#include "debmod.h"

#ifdef UNDER_CE
#  ifndef USE_ASYNC
#    define USE_ASYNC
#  endif
#endif

#ifdef USE_ASYNC
#  include "async.h"
#else
#  include "tcpip.h"
#endif

#ifdef VERBOSE_ENABLED
#define verb(x)  do { if ( verbose ) msg x; } while(0)
#else
#define verb(x)  //msg x
#endif
#define verbev(x)  //msg x

class rpc_engine_t
{
public:
  // 0 means everything is ok
  ssize_t network_error_code;
  bool has_pending_event;
  bool poll_debug_events;
  SOCKET rpc_socket;
  idarpc_stream_t *irs;
  bool verbose;

  bool is_server;
protected:
  int recv_all(void *ptr, int left, bool poll);
  int process_long(bytevec_t &cmd);

  // pointer to the ioctl request handler. initialize this in your
  // debugger stub if you need to handle ioctl requests from the server.
public:
  ioctl_handler_t *ioctl_handler;

public:
  int handle_ioctl_packet(bytevec_t &cmd, const uchar *ptr, const uchar *end);
  virtual ~rpc_engine_t();
  rpc_engine_t(SOCKET rpc_socket);

  int send_request(bytevec_t &s);
  rpc_packet_t *recv_request(void);
  rpc_packet_t *process_request(bytevec_t &cmd, bool must_login=false);

  virtual bytevec_t perform_request(const rpc_packet_t *rp) = 0;
  virtual int poll_events(int timeout_ms) = 0;

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
  void set_ioctl_handler(ioctl_handler_t *h) { ioctl_handler = h; }
  DECLARE_UD_REPORTING(msg, this);
  DECLARE_UD_REPORTING(warning, this);
  DECLARE_UD_REPORTING(error, this);

  void term_irs();
};

#endif
