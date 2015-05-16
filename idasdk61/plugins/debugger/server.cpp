/*
       IDA Pro remote debugger server
*/

#include <fpro.h>
#include <expr.hpp>
#ifndef UNDER_CE
#  include <signal.h>
#endif

#include <map>
#include <algorithm>

#ifdef __NT__
//#  ifndef SIGHUP
//#    define SIGHUP 1
//#  endif
#  if defined(__X64__)
#    define SYSTEM "Windows"
#  elif defined(UNDER_CE)
#    define SYSTEM "WindowsCE"
#    define USE_ASYNC
#  else
#    define SYSTEM "Windows"
#  endif
#  ifdef USE_ASYNC
#    define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_USER
#  else
#    define socklen_t int
#    define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#  endif
#else   // not NT, i.e. UNIX
#  if defined(__LINUX__)
#    if defined(__ARM__)
#      if defined(__ANDROID__)
#        define SYSTEM "Android"
#      else
#        define SYSTEM "ARM Linux"
#      endif
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_LINUX_USER
#    else
#      define SYSTEM "Linux"
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#    endif
     // linux debugger can not be multithreaded because it uses thread_db.
     // i doubt that this library is meant to be used with multiple
     // applications simultaneously.
#    define __SINGLE_THREADED_SERVER__
#  elif defined(__MAC__)
#    if defined(__arm__)
#      define SYSTEM "iPhone"
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_IPHONE_USER
#    else
#      define SYSTEM "Mac OS X"
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_MACOSX_USER
#    endif
#  else
#    error "Unknown platform"
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#  ifdef LIBWRAP
extern "C" const char *check_connection(int);
#  endif // LIBWRAP
#endif // !__NT__

#ifdef __X64__
#define SYSBITS " 64-bit"
#else
#define SYSBITS " 32-bit"
#endif

#ifdef UNDER_CE
#  include "async.h"
#  ifndef __SINGLE_THREADED_SERVER__
#    define __SINGLE_THREADED_SERVER__
#  endif
#else
#  include "tcpip.h"
#endif

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#include "debmod.h"
#include "rpc_hlp.h"
#include "rpc_server.h"

// sizeof(ea_t)==8 and sizeof(size_t)==4 servers can not be used to debug 64-bit
// applications. but to debug 32-bit applications, simple 32-bit servers
// are enough and can work with both 32-bit and 64-bit versions of ida.
// so, there is no need to build sizeof(ea_t)==8 and sizeof(size_t)==4 servers
#if defined(__EA64__) != defined(__X64__)
#error "Mixed mode servers do not make sense, they should not be compiled"
#endif

//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
static const char *server_password = NULL;
static bool verbose = false;

#ifdef __SINGLE_THREADED_SERVER__

static bool init_lock(void) { return true; }
bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }

#else

static qmutex_t g_mutex = NULL;

//--------------------------------------------------------------------------
static bool init_lock(void)
{
  g_mutex = qmutex_create();
  return g_mutex != NULL;
}

//--------------------------------------------------------------------------
bool lock_begin()
{
  return qmutex_lock(g_mutex);
}

//--------------------------------------------------------------------------
bool lock_end()
{
  return qmutex_unlock(g_mutex);
}
#endif

//--------------------------------------------------------------------------
#ifdef __SINGLE_THREADED_SERVER__

rpc_server_t *g_global_server = NULL;

int for_all_debuggers(debmod_visitor_t &v)
{
  return g_global_server == NULL ? 0 : v.visit(g_global_server->get_debugger_instance());
}
#else

typedef std::map<rpc_server_t *, qthread_t> rpc_server_list_t;
static rpc_server_list_t clients_list;

qmutex_t g_lock = NULL;

// perform an action (func) on all debuggers
int for_all_debuggers(debmod_visitor_t &v)
{
  int code = 0;
  qmutex_lock(g_lock);
  {
    rpc_server_list_t::iterator it;
    for ( it=clients_list.begin(); it != clients_list.end(); ++it )
    {
      code = v.visit(it->first->get_debugger_instance());
      if ( code != 0 )
        break;
    }
  } qmutex_unlock(g_lock);
  return code;
}

#endif

#ifndef USE_ASYNC

// Set this variable before generating SIGINT for internal purposes
bool ignore_sigint = false;

static SOCKET listen_socket = INVALID_SOCKET;

//--------------------------------------------------------------------------
void neterr(idarpc_stream_t *irs, const char *module)
{
  int code = irs_error(irs);
  qeprintf("%s: %s\n", module, winerr(code));
  exit(1);
}

//--------------------------------------------------------------------------
static void NT_CDECL shutdown_gracefully(int signum)
{
  if ( signum == SIGINT && ignore_sigint )
  {
    ignore_sigint = false;
    return;
  }

#if defined(__NT__) || defined(__ARM__) // strsignal() is not available
  qeprintf("got signal #%d, terminating\n", signum);
#else
  qeprintf("%s: terminating the server\n", strsignal(signum));
#endif

#ifdef __SINGLE_THREADED_SERVER__

  if ( g_global_server != NULL )
  {
    debmod_t *d = g_global_server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process();
    g_global_server->term_irs();
  }
#else
  qmutex_lock(g_lock);

  for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
  {
    rpc_server_t *server = it->first;
    qthread_t thr = it->second;

    // free thread
    if ( thr != NULL )
      qthread_free(thr);

    if ( server == NULL || server->irs == NULL )
      continue;

    debmod_t *d = server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process(); // kill the process instead of letting it run in wild

    server->term_irs();
  }

  clients_list.clear();
  qmutex_unlock(g_lock);
  qmutex_free(g_lock);
#endif

  if ( listen_socket != INVALID_SOCKET )
    closesocket(listen_socket);

  term_subsystem();
  _exit(1);
}
#endif

//--------------------------------------------------------------------------
static void handle_single_session(rpc_server_t *server)
{
  static int s_sess_id = 1;
  int sid = s_sess_id++;

  char peername[MAXSTR];
  if ( !irs_peername(server->irs, peername, sizeof(peername)) )
    qstrncpy(peername, "(unknown)", sizeof(peername));
  lprintf("=========================================================\n"
          "[%d] Accepting connection from %s...\n", sid, peername);

  bytevec_t open = prepare_rpc_packet(RPC_OPEN);
  append_dd(open, IDD_INTERFACE_VERSION);
  append_dd(open, DEBUGGER_ID);
  append_dd(open, sizeof(ea_t));

  rpc_packet_t *rp = server->process_request(open, true);

  if ( rp == NULL )
  {
    lprintf("Could not establish the connection\n");

    delete server;
    return;
  }

  // Answer is beyond the rpc_packet_t buffer
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  bool send_response = true;

  bool ok = extract_long(&answer, end);
  if ( !ok )
  {
    lprintf("Incompatible IDA Pro version\n");
    send_response = false;
  }
  else if ( server_password != NULL )
  {
    char *pass = extract_str(&answer, end);
    if ( strcmp(pass, server_password) != '\0' )
    {
      lprintf("Bad password\n");
      ok = false;
    }
  }

  qfree(rp);

  if ( send_response )
  {
    open = prepare_rpc_packet(RPC_OK);
    append_dd(open, ok);
    server->send_request(open);

    if ( ok )
    {
      // the main loop: handle client requests until it drops the connection
      // or sends us RPC_OK (see rpc_debmod_t::close_remote)
      bytevec_t cmd;
      rpc_packet_t *packet = server->process_request(cmd);
      if ( packet != NULL )
        qfree(packet);
    }
  }
  server->network_error_code = 0;

  lprintf("[%d] Closing connection from %s...\n", sid, peername);

  server->term_irs();

#ifndef __SINGLE_THREADED_SERVER__
  // Remove the session from the list
  qmutex_lock(g_lock);
  for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
  {
    if ( it->first != server )
      continue;

    // free the thread resources
    qthread_free(it->second);

    // remove client from the list
    clients_list.erase(it);
    break;
  }
  qmutex_unlock(g_lock);
#endif

  // Free the debug session
  delete server;
}

int idaapi thread_handle_session(void *ctx)
{
  rpc_server_t *server = (rpc_server_t *)ctx;
  handle_single_session(server);
  return 0;
}

void handle_session(rpc_server_t *server)
{
#ifndef __SINGLE_THREADED_SERVER__
  qthread_t t = qthread_create(thread_handle_session, (void *)server);
  // Add the session to the list
  qmutex_lock(g_lock);
  clients_list[server] = t;
  qmutex_unlock(g_lock);
#else
  g_global_server = server;
  handle_single_session(server);
  g_global_server = NULL;
#endif
}

//--------------------------------------------------------------------------
// For Pocket PC, we create a DLL
// This DLL should never exit(), of course, but just close the connection
#ifdef UNDER_CE

#include "rapi/rapi.h"

static bool in_use = false;
static uchar *ptr;

static int display_exception(int code, EXCEPTION_POINTERS *ep)
{
  /*
  CONTEXT &ctx = *(ep->ContextRecord);
  EXCEPTION_RECORD &er = *(ep->ExceptionRecord);
  char name[MAXSTR];
  get_exception_name(er.ExceptionCode, name, sizeof(name));
  // find our imagebase
  ptr = (uchar*)(size_t(ptr) & ~0xFFF); // point to the beginning of a page
  while ( !IsBadReadPtr(ptr, 2) )
    ptr -= 0x1000;

  msg("%08lX: debugger server %s (BASE %08lX)\n", ctx.Pc-(uint32)ptr, name, ptr);

  DEBUG_CONTEXT(ctx);
  //  show_exception_record(er);
  */
  return EXCEPTION_EXECUTE_HANDLER;
  //  return EXCEPTION_CONTINUE_SEARCH;
}

//--------------------------------------------------------------------------
static DWORD calc_our_crc32(const char *fname)
{
  linput_t *li = open_linput(fname, false);
  DWORD crc32 = calc_file_crc32(li);
  close_linput(li);
  return crc32;
}

//--------------------------------------------------------------------------
extern "C"
{
  BOOL WINAPI SetKMode(BOOL fMode);
  DWORD WINAPI SetProcPermissions(DWORD newperms);
};

class get_permissions_t
{
  DWORD dwPerm;
  BOOL bMode;
public:
  get_permissions_t(void)
  {
    bMode = SetKMode(TRUE); // Switch to kernel mode
    dwPerm = SetProcPermissions(0xFFFFFFFF); // Set access rights to the whole system
  }
  ~get_permissions_t(void)
  {
    SetProcPermissions(dwPerm);
    SetKMode(bMode);
  }
};

//--------------------------------------------------------------------------
// __try handler can't be placed in fuction which requires object unwinding
static idarpc_stream_t *protected_privileged_session(IRAPIStream* pStream)
{
  try
  {
    idarpc_stream_t *irs = init_server_irs(pStream);
    if ( irs == NULL )
      return NULL;

    rpc_server_t *server = new rpc_server_t((SOCKET)irs);
    server->verbose = verbose;
    server->set_debugger_instance(create_debug_session());

    g_global_server = server;

#ifdef UNDER_CE
      static bool inited = false;
      if ( !inited )
      {
        inited = true;
        init_idc();
      }
#endif
    handle_session(server);
    return irs;
  }
  //__except ( display_exception(GetExceptionCode(), GetExceptionInformation()) )
  catch(...)
  {
    return NULL;
  }
}

//--------------------------------------------------------------------------
extern "C" __declspec(dllexport)
int ida_server(DWORD dwInput, BYTE* pInput,
               DWORD* pcbOutput, BYTE** ppOutput,
               IRAPIStream* pStream)
{
  lprintf("IDA " SYSTEM SYSBITS " remote debug server v1.%d.\n"
    "Copyright Hex-Rays 2004-2011\n", IDD_INTERFACE_VERSION);

  // Call the debugger module to initialize its subsystem once
  if ( !init_subsystem() )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  // check our crc32
  DWORD crc32 = calc_our_crc32((char *)pInput);
  DWORD dummy = 0;
  pStream->Write(&crc32, sizeof(crc32), &dummy);
  if ( dummy != sizeof(crc32) )
  {
ERR:
    pStream->Release();
    //    lprintf("Debugger server checksum mismatch - shutting down\n");
    return ERROR_CRC;
  }
  DWORD ok;
  dummy = 0;
  pStream->Read(&ok, sizeof(ok), &dummy);
  if ( dummy != sizeof(ok) || ok != 1 )
    goto ERR;

  // only one instance is allowed
  if ( in_use )
  {
    static const char busy[] = "BUSY";
    pStream->Write(busy, sizeof(busy)-1, &dummy);
    pStream->Release();
    return ERROR_BUSY;
  }
  in_use = true;

  ptr = (uchar*)ida_server;
  idarpc_stream_t *irs;
  {
    get_permissions_t all_permissions;
    irs = protected_privileged_session(pStream);
  }

  if ( irs != NULL )
    term_server_irs(irs);

  in_use = false;
  return 0;
}

#else

//--------------------------------------------------------------------------
// debugger remote server - TCP/IP mode
int NT_CDECL main(int argc, char *argv[])
{
  int port_number = DEBUGGER_PORT_NUMBER;
  lprintf("IDA " SYSTEM SYSBITS " remote debug server(" __SERVER_TYPE__ ") v1.%d. Hex-Rays (c) 2004-2011\n", IDD_INTERFACE_VERSION);
  while ( argc > 1 && (argv[1][0] == '-' || argv[1][0] == '/'))
  {
    switch ( argv[1][1] )
    {
    case 'p':
      port_number = atoi(&argv[1][2]);
      break;
    case 'P':
      server_password = argv[1] + 2;
      break;
    case 'v':
      verbose = true;
      break;
    default:
      error("usage: ida_remote [switches]\n"
        "  -p...  port number\n"
        "  -P...  password\n"
        "  -v     verbose\n");
    }
    argv++;
    argc--;
  }

#ifdef ENABLE_LOWCNDS
  init_idc();
#endif

  // call the debugger module to initialize its subsystem once
  if ( !init_lock()
    || !init_subsystem()
#ifndef __SINGLE_THREADED_SERVER__
    || ((g_lock = qmutex_create())== NULL)
#endif
    )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

#ifndef __NT__
  signal(SIGHUP, shutdown_gracefully);
#endif
  signal(SIGINT, shutdown_gracefully);
  signal(SIGTERM, shutdown_gracefully);
  signal(SIGSEGV, shutdown_gracefully);
  //  signal(SIGPIPE, SIG_IGN);

  if ( !init_irs_layer() )
  {
    neterr(NULL, "init_sockets");
  }

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);
  if ( listen_socket == -1 )
    neterr(NULL, "socket");

  idarpc_stream_t *irs = (idarpc_stream_t *)listen_socket;
  setup_irs(irs);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = qhtons(short(port_number));

  if ( bind(listen_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
    neterr(irs, "bind");

  if ( listen(listen_socket, SOMAXCONN) == SOCKET_ERROR )
    neterr(irs, "listen");

  hostent *local_host = gethostbyname("");
  if ( local_host != NULL )
  {
    const char *local_ip = inet_ntoa(*(struct in_addr *)*local_host->h_addr_list);
    if ( local_host->h_name != NULL && local_ip != NULL )
      lprintf("Host %s (%s): ", local_host->h_name, local_ip);
    else if ( local_ip != NULL )
      lprintf("Host %s: ", local_ip);
  }
  lprintf("Listening on port #%u...\n", port_number);

  while ( true )
  {
    sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    SOCKET rpc_socket = accept(listen_socket, (sockaddr *)&sa, &salen);
    if ( rpc_socket == -1 )
    {
      if ( errno != EINTR )
        neterr(irs, "accept");
      continue;
    }
#if defined(__LINUX__) && defined(LIBWRAP)
    const char *p = check_connection(rpc_socket);
    if ( p != NULL )
    {
      fprintf(stderr,
        "ida-server CONNECTION REFUSED from %s (tcp_wrappers)\n", p);
      shutdown(rpc_socket, 2);
      close(rpc_socket);
      continue;
    }
#endif // defined(__LINUX__) && defined(LIBWRAP)

    rpc_server_t *server = new rpc_server_t(rpc_socket);
    server->verbose = verbose;
    server->set_debugger_instance(create_debug_session());
    handle_session(server);
  }
/* NOTREACHED
  term_lock();
  term_subsystem();
#ifndef __SINGLE_THREADED_SERVER__
  qmutex_free(g_lock);
#endif
*/
}

#endif
