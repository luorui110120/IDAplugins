// ActiveSync transport
#ifndef __ASYNC__
#define __ASYNC__

// async.h must be included before other files because of windows.h
#include <windows.h>
#include <fpro.h>
#include "rapi/rapi.h"
#include "consts.h"

#ifndef SOCKET
#  define SOCKET int*
#endif

#ifdef UNDER_CE
#  define errno GetLastError()
#  pragma comment(lib, "ws2")
#else
#  ifdef _MSC_VER
#    pragma comment(lib, "wsock32")
#  endif
#endif

#ifdef ASYNC_TEST
#define qfree free
#define qalloc malloc
#define qrealloc realloc
#endif

struct async_stream_t
{
  IRAPIStream *s;
  HANDLE rt;
  bool stop_connection;
  HANDLE data_ready;
  HANDLE buffer_ready;
  DWORD read_size;
#define MIN_BUF_SIZE    (1024+5)        // read_memory uses such amount of memory
  uchar *read_data;
  HRESULT last_code;
  bool waiting_for_header;

  ~async_stream_t(void);
  int read_loop(void);
  ssize_t qrecv(void *buf, size_t n);
  bool init(IRAPIStream *s);
};

idarpc_stream_t *init_client_irs(const char *hostname, int port_number);
void setup_irs(idarpc_stream_t *);
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n, int timeout);
bool init_irs_layer(void);
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n);
int irs_ready(idarpc_stream_t *irs, int timeout_ms);
void term_server_irs(idarpc_stream_t *irs);
void term_client_irs(idarpc_stream_t *irs);
int irs_error(idarpc_stream_t *);
idarpc_stream_t *init_server_irs(void *stream);
bool irs_peername(idarpc_stream_t *, char *buf, size_t bufsize);

//void irs_term(idarpc_stream_t *irs);

#endif
