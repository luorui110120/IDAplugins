#ifdef _WIN32
#define WINVER 0x0501  /* needed for ipv6 bits */
#include <winsock2.h>
#ifdef __BORLANDC__
#pragma warn -8060 // Possibly incorrect assignment
#pragma warn -8061 // Initialization is only partially bracketed
#endif
#include <Ws2tcpip.h>
#pragma comment(lib, "WS2_32.lib")
#endif

#include "tcpip.h"
#include <kernwin.hpp>

static void neterr(const char *module)
{
  int code = get_network_error();
  error("%s: %s", module, winerr(code));
}

//-------------------------------------------------------------------------
#if defined(__NT__)
void NT_CDECL term_sockets(void)
{
  WSACleanup();
}

//-------------------------------------------------------------------------
#ifdef __BORLANDC__
#pragma warn -8084 // Suggest parentheses to clarify precedence
#endif

bool init_irs_layer(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD( 2, 0 );

  err = WSAStartup( wVersionRequested, &wsaData );
  if ( err != 0 )
    return false;

  atexit(term_sockets);

  /* Confirm that the WinSock DLL supports 2.0.*/
  /* Note that if the DLL supports versions greater    */
  /* than 2.0 in addition to 2.0, it will still return */
  /* 2.0 in wVersion since that is the version we      */
  /* requested.                                        */

  if ( LOBYTE( wsaData.wVersion ) != 2 ||
       HIBYTE( wsaData.wVersion ) != 0 )
    /* Tell the user that we couldn't find a usable */
    /* WinSock DLL.                                  */
    return false;

  /* The WinSock DLL is acceptable. Proceed. */
  return true;
}
#else
void term_sockets(void) {}
bool init_irs_layer(void) { return true; }
#endif

//-------------------------------------------------------------------------
static inline SOCKET sock_from_irs(idarpc_stream_t *irs)
{
  return (SOCKET)irs;
}

//-------------------------------------------------------------------------
void irs_term(idarpc_stream_t *irs)
{
  closesocket(sock_from_irs(irs));
  term_sockets();
}

//-------------------------------------------------------------------------
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n)
{
  return qsend(sock_from_irs(irs), buf, (int)n);
}

//-------------------------------------------------------------------------
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n, int timeout)
{
  if ( timeout != -1 && !irs_ready(irs, timeout) )
  {
    SET_SYSTEM_SPECIFIC_ERRNO(SYSTEM_SPECIFIC_TIMEOUT_ERROR);
    return -1; // no data
  }
  return qrecv(sock_from_irs(irs), buf, (int)n);
}

//-------------------------------------------------------------------------
int irs_error(idarpc_stream_t *)
{
  return get_network_error();
}

//-------------------------------------------------------------------------
int irs_ready(idarpc_stream_t *irs, int timeout)
{
  static hit_counter_t *hc = NULL;
  if ( hc == NULL )
    hc = create_hit_counter("irs_ready");
  incrementer_t inc(*hc);

  SOCKET s = sock_from_irs(irs);
  int milliseconds = timeout;
  int seconds = milliseconds / 1000;
  milliseconds %= 1000;
  struct timeval tv = { seconds, milliseconds * 1000 };
  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(s, &rd);
  int code = select(int(s+1),
         &rd, NULL,
         NULL,
         seconds != -1 ? &tv : NULL);
  if ( code == 0 )
    inc.failed();
  return code;
}

//--------------------------------------------------------------------------
void setup_irs(idarpc_stream_t *irs)
{
  SOCKET socket = sock_from_irs(irs);
  /* Set socket options.  We try to make the port reusable and have it
     close as fast as possible without waiting in unnecessary wait states
     on close.
   */
  int on = 1;
  char *const ptr = (char *)&on;
  if ( setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, ptr, sizeof(on)) != 0 )
    neterr("setsockopt1");

  /* Enable TCP keep alive process. */
  if ( setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, ptr, sizeof(on)) != 0 )
    neterr("setsockopt2");

  /* Speed up the interactive response. */
  if ( setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, ptr, sizeof(on)) != 0 )
    neterr("setsockopt3");
}

//-------------------------------------------------------------------------
void term_server_irs(idarpc_stream_t *irs)
{
  closesocket(sock_from_irs(irs));
}

//-------------------------------------------------------------------------
void term_client_irs(idarpc_stream_t *irs)
{
  term_server_irs(irs);
  term_sockets();
}

//-------------------------------------------------------------------------
static in_addr name_to_addr(const char *name)
{
  in_addr addr;
  addr.s_addr = inet_addr(name);
  if ( addr.s_addr == INADDR_NONE )
  {
    struct hostent *he = gethostbyname(name);
    if ( he != NULL )
    {
#define INADDRSZ   4
//      warning("addrtype = %d addr=%08lX", he->h_addrtype, *(uint32*)he->h_addr);
      memcpy(&addr, he->h_addr, INADDRSZ);
      return addr;
    }
  }
  return addr;
}

//-------------------------------------------------------------------------
bool name_to_sockaddr(const char *name, ushort port, sockaddr_in *sa)
{
  memset(sa, 0, sizeof(sockaddr_in));
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  sa->sin_addr = name_to_addr(name);
  return sa->sin_addr.s_addr != INADDR_NONE;
}

//-------------------------------------------------------------------------
idarpc_stream_t *init_client_irs(const char *hostname, int port_number)
{
  if ( hostname[0] == '\0' )
  {
    warning("AUTOHIDE NONE\n"
            "Please specify the hostname in Debugger, Process options");
    return NULL;
  }

  if ( !init_irs_layer() )
  {
    warning("AUTOHIDE NONE\n"
            "Could not initialize sockets: %s", winerr(get_network_error()));
    return NULL;
  }

  struct addrinfo ai, *res, *e;
  char port[33];

  // try to enumerate all possible addresses
  memset(&ai,0, sizeof(ai));
  ai.ai_flags = AI_CANONNAME;
  ai.ai_family = PF_UNSPEC;
  ai.ai_socktype = SOCK_STREAM;
  qsnprintf(port, sizeof(port), "%d", port_number);

  bool ok = false;
  const char *errstr = NULL;
  SOCKET sock = INVALID_SOCKET;
  int code = getaddrinfo(hostname, port, &ai, &res);
  if ( code != 0 )
  { // failed to resolve the name
    errstr = gai_strerror(code);
  }
  else
  {
    for ( e = res; !ok && e != NULL; e = e->ai_next )
    {
      char uaddr[INET6_ADDRSTRLEN+1];
      char uport[33];
      if ( getnameinfo(e->ai_addr, e->ai_addrlen, uaddr, sizeof(uaddr),
                       uport, sizeof(uport), NI_NUMERICHOST | NI_NUMERICSERV) != 0 )
      {
NETERR:
        errstr = winerr(get_network_error());
        continue;
      }
      sock = socket(e->ai_family, e->ai_socktype, e->ai_protocol);
      if ( sock == INVALID_SOCKET )
        goto NETERR;

      setup_irs((idarpc_stream_t*)sock);

      if ( connect(sock, e->ai_addr, e->ai_addrlen) == SOCKET_ERROR )
      {
        errstr = winerr(get_network_error());
        closesocket(sock);
        continue;
      }
      ok = true;
    }
    freeaddrinfo(res);
  }
  if ( !ok )
  {
    msg("Could not connect to %s: %s\n", hostname, errstr);
    return NULL;
  }

  return (idarpc_stream_t*)sock;
}

//-------------------------------------------------------------------------
static bool sockaddr_to_name(
        const struct sockaddr *addr,
        socklen_t len,
        char *buf,
        size_t bufsize)
{
  char *ptr = buf;
  char *end = buf + bufsize;
  // get dns name
  if ( getnameinfo(addr, len,
                   ptr, end-ptr,
                   NULL, 0,
                   NI_NAMEREQD) == 0 )
  {
    ptr = tail(ptr);
    APPCHAR(ptr, end, '(');
  }
  // get ip address
  if ( getnameinfo(addr, len,
                   ptr, end-ptr,
                   NULL, 0,
                   NI_NUMERICHOST) == 0 )
  {
    bool app = ptr > buf;
    ptr = tail(ptr);
    if ( app )
      APPEND(ptr, end, ")");
  }
  else
  {
    if ( ptr > buf )
      *--ptr = '\0';
  }
  return ptr > buf;
}

//-------------------------------------------------------------------------
bool irs_peername(idarpc_stream_t *irs, char *buf, size_t bufsize)
{
  struct sockaddr addr;
  socklen_t len = sizeof(addr);
  if ( getpeername(sock_from_irs(irs), &addr, &len) != 0 )
    return false;

  return sockaddr_to_name(&addr, len, buf, bufsize);
}

//-------------------------------------------------------------------------
bool irs_getname(idarpc_stream_t *irs, char *buf, size_t bufsize)
{
  struct sockaddr addr;
  socklen_t len = sizeof(addr);
  if ( getsockname(sock_from_irs(irs), &addr, &len) != 0 )
    return false;

  return sockaddr_to_name(&addr, len, buf, bufsize);
}
