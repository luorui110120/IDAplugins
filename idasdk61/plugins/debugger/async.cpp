#include "async.h"
#include <err.h>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
int async_stream_t::read_loop(void)
{
  while ( !stop_connection )
  {
    last_code = s->Read(read_data, read_size, &read_size);
    SetEvent(data_ready);
    if ( stop_connection )
      break;
    WaitForSingleObject(buffer_ready, TIMEOUT_INFINITY);
  }
  return 0;
}

//--------------------------------------------------------------------------
ssize_t async_stream_t::qrecv(void *buf, size_t n)
{
  idastate_t oldstate = setStat(st_Work);
  WaitForSingleObject(data_ready, TIMEOUT_INFINITY);
  ResetEvent(data_ready);
  setStat(oldstate);

  if ( FAILED(last_code) || n != read_size ) // desync in the packet handling
  {
    if ( SUCCEEDED(last_code) )
      last_code = ERROR_INVALID_DATA;
    SetLastError(last_code);
    return -1;
  }

  // copy read data
  memcpy(buf, read_data, n);

  // prepare new buffer
  read_size = 0;
  if ( waiting_for_header )     // got a header?
  {
    rpc_packet_t *p = (rpc_packet_t *)read_data;
    if ( p->length == MC4('B','U','S','Y') )
    { // wince debugger server is busy
      last_code = ERROR_BUSY;
      return -1;
    }
    read_size = qntohl(p->length);
    waiting_for_header = false;
  }
  if ( read_size == 0 )         // no packet tail?
  {
    waiting_for_header = true;
    read_size = sizeof(rpc_packet_t);
  }
  if ( read_size > MIN_BUF_SIZE )
    read_data = qrealloc_array<uchar>(read_data, read_size);
  if ( read_data == NULL )
    nomem("async::qrecv, read_size=%x", read_size);
  SetEvent(buffer_ready);
  return SUCCEEDED(last_code) ? n : -1;
}

//--------------------------------------------------------------------------
static DWORD WINAPI read_thread(void *ud)
{
  async_stream_t &as = *(async_stream_t *)ud;
  return as.read_loop();
}

//--------------------------------------------------------------------------
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n, int)
{
  async_stream_t &as = *(async_stream_t *)irs;
  return as.qrecv(buf, n);
}

//--------------------------------------------------------------------------
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n)
{
  async_stream_t &as = *(async_stream_t *)irs;
  DWORD written = 0;
  HRESULT hr = as.s->Write(buf, (DWORD)n, &written);
  if ( SUCCEEDED(hr) && written > 0 && written <= n )
    return written;
  as.last_code = hr;
  return -1;
}

//--------------------------------------------------------------------------
int irs_ready(idarpc_stream_t *irs, int timeout)
{
  async_stream_t &as = *(async_stream_t *)irs;
  switch ( WaitForSingleObject(as.data_ready, timeout) )
  {
    case WAIT_OBJECT_0:
      return 1;   // yes, data ready
    case WAIT_TIMEOUT:
      return 0;
  }
  return -1;    // error
}

//--------------------------------------------------------------------------
int irs_error(idarpc_stream_t *irs)
{
  async_stream_t &as = *(async_stream_t *)irs;
  return as.last_code;
}

//--------------------------------------------------------------------------
async_stream_t::~async_stream_t(void)
{
  stop_connection = true;
  if ( rt != NULL )
  {
    WaitForSingleObject(rt, 100);
    TerminateThread(rt, 0);
    CloseHandle(rt);
    rt = NULL;
  }
  if ( data_ready != NULL )
  {
    CloseHandle(data_ready);
    data_ready = NULL;
  }
  if ( buffer_ready != NULL )
  {
    CloseHandle(buffer_ready);
    buffer_ready = NULL;
  }
  if ( read_data != NULL )
  {
    qfree(read_data);
    read_data = NULL;
  }
#ifdef UNDER_CE // this code hangs for some reason on the desktop!
  if ( s != NULL )
  {
    s->Release();
    s = NULL;
  }
#endif
}

//--------------------------------------------------------------------------
bool async_stream_t::init(IRAPIStream *_s)
{
  memset(this, 0, sizeof(*this));
  s = _s;
  waiting_for_header = true;
  read_size = sizeof(rpc_packet_t);
  read_data = (uchar *)qalloc(MIN_BUF_SIZE);
  if ( read_data == NULL )
    return false;
  data_ready = CreateEvent(NULL, true, false, NULL);
  if ( data_ready == NULL )
    return false;
  buffer_ready = CreateEvent(NULL, false, false, NULL);
  if ( buffer_ready == NULL )
    return false;
  DWORD dummy_tid;
  rt = CreateThread(NULL, 0, read_thread, this, 0, &dummy_tid);
  if ( rt == NULL )
    return false;
  return true;
}

//--------------------------------------------------------------------------
void term_server_irs(idarpc_stream_t *irs)
{
  async_stream_t *as = (async_stream_t *)irs;
  delete as;
}

//--------------------------------------------------------------------------
idarpc_stream_t *init_server_irs(void *stream)
{
  IRAPIStream *s = (IRAPIStream *)stream;
  async_stream_t *as = new async_stream_t;
  if ( as != NULL && !as->init(s) )
  {
    delete as;
    as = NULL;
  }
  return (idarpc_stream_t *)as;
}

//--------------------------------------------------------------------------
bool irs_peername(idarpc_stream_t *, char *buf, size_t bufsize)
{
  // since this function is called only from the server, we cheat and
  // always return "desktop":
  qstrncpy(buf, "desktop", bufsize);
  return true;
}

#ifdef __NT__   // to compile rapitest.cpp
#if !defined(UNDER_CE)
//--------------------------------------------------------------------------
bool init_irs_layer(void)
{
  return true;
}

//--------------------------------------------------------------------------
void setup_irs(idarpc_stream_t *)
{
}

//--------------------------------------------------------------------------
typedef HRESULT STDAPICALLTYPE tCeRapiInit(void);
typedef HRESULT STDAPICALLTYPE tCeRapiInitEx(RAPIINIT * pRapiInit);
typedef HRESULT STDAPICALLTYPE tCeRapiUninit(void);
typedef HRESULT STDAPICALLTYPE tCeRapiGetError(void);
typedef HRESULT STDAPICALLTYPE tCeRapiInvoke(LPCWSTR, LPCWSTR,DWORD,BYTE *, DWORD *,BYTE **, IRAPIStream **,DWORD);
typedef HANDLE  STDAPICALLTYPE tCeCreateFile(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    STDAPICALLTYPE tCeWriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    STDAPICALLTYPE tCeCloseHandle(HANDLE);
typedef DWORD   STDAPICALLTYPE tCeGetLastError(void);

static HINSTANCE rapi_handle = NULL;
static tCeRapiInit    *pCeRapiInit;
static tCeRapiInitEx  *pCeRapiInitEx;
static tCeRapiUninit  *pCeRapiUninit;
static tCeRapiInvoke  *pCeRapiInvoke;
static tCeCreateFile  *pCeCreateFile;
static tCeWriteFile   *pCeWriteFile;
static tCeCloseHandle *pCeCloseHandle;
static tCeRapiGetError *pCeRapiGetError;
static tCeGetLastError *pCeGetLastError;

//--------------------------------------------------------------------------
static void unload_rapi_functions(void)
{
  FreeLibrary(rapi_handle);
  rapi_handle = NULL;
}

//--------------------------------------------------------------------------
static bool load_rapi_functions(void)
{
  if ( rapi_handle == NULL )
  {
    rapi_handle = LoadLibrary(TEXT("rapi.dll"));
    if ( rapi_handle != NULL )
    {
      *(FARPROC*)&pCeRapiInit     = GetProcAddress(rapi_handle, "CeRapiInit");
      *(FARPROC*)&pCeRapiInitEx   = GetProcAddress(rapi_handle, "CeRapiInitEx");
      *(FARPROC*)&pCeRapiUninit   = GetProcAddress(rapi_handle, "CeRapiUninit");
      *(FARPROC*)&pCeRapiInvoke   = GetProcAddress(rapi_handle, "CeRapiInvoke");
      *(FARPROC*)&pCeCreateFile   = GetProcAddress(rapi_handle, "CeCreateFile");
      *(FARPROC*)&pCeWriteFile    = GetProcAddress(rapi_handle, "CeWriteFile");
      *(FARPROC*)&pCeCloseHandle  = GetProcAddress(rapi_handle, "CeCloseHandle");
      *(FARPROC*)&pCeRapiGetError = GetProcAddress(rapi_handle, "CeRapiGetError");
      *(FARPROC*)&pCeGetLastError = GetProcAddress(rapi_handle, "CeGetLastError");
      if ( pCeRapiInit    != NULL
        && pCeRapiUninit  != NULL
        && pCeRapiInvoke  != NULL
        && pCeCreateFile  != NULL
        && pCeWriteFile   != NULL
        && pCeCloseHandle != NULL
        && pCeRapiGetError!= NULL
        && pCeGetLastError!= NULL )
      {
        return true;
      }
      unload_rapi_functions();
    }
    warning("AUTOHIDE NONE\n"
            "Could not find RAPI functions in the system.\n"
            "Probably Microsoft ActiveSync has not been installed yet.");
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
static DWORD get_errcode(void)
{
  DWORD code = pCeGetLastError();
  if ( code != 0 )
    return code;
  return pCeRapiGetError();
}

//--------------------------------------------------------------------------
static DWORD copy_debugger_server(const char *local, const wchar_t *remote)
{
  DWORD code;
  HANDLE h;
  msg("Copying the debugger server to PocketPC...\n");
  while ( true )
  {
    // the desktop computer is too fast -- wait for the remote to shut down
    Sleep(100);
    h = pCeCreateFile(remote, GENERIC_WRITE, 0,
                      NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if ( h != INVALID_HANDLE_VALUE )
      break;
    code = get_errcode();
    if ( code != 0 )
      return code;
    // no errors? try again
  }

  FILE *fp = fopenRB(local);
  if ( fp == NULL )
  {
    pCeCloseHandle(h);
    return ERROR_FILE_NOT_FOUND;
  }
  int32 size = efilelength(fp);
  uchar *buf = (uchar *)qalloc(size);
  if ( buf == NULL )
    nomem("copy_debugger_server");
  eread(fp, buf, size);
  qfclose(fp);

  DWORD copied;
  if ( !pCeWriteFile(h, buf, size, &copied, NULL) || size != copied )
  {
    code = get_errcode();
    qfree(buf);
    pCeCloseHandle(h);
    return code;
  }
  pCeCloseHandle(h);
  return 0;
}

//--------------------------------------------------------------------------
void term_client_irs(idarpc_stream_t *irs)
{
  term_server_irs(irs);
  pCeRapiUninit();
  unload_rapi_functions();
  msg("Connection to the Windows CE device has been stopped.\n");
}

//--------------------------------------------------------------------------
idarpc_stream_t *init_client_irs(const char * /*hostname*/, int /*port_number*/)
{
  if ( !load_rapi_functions() )
    return NULL;

  show_wait_box("Connecting to Windows CE device");
  HRESULT hr;
  if ( pCeRapiInitEx != NULL )
  {
    RAPIINIT ri = { sizeof(RAPIINIT) };
    hr = pCeRapiInitEx(&ri);
    if ( !FAILED(hr) )
    {
      while ( 1 )
      {
        // check for user break
        if ( wasBreak() )
        {
          hide_wait_box();
          return NULL;
        }

        // wait on the event
        if ( WaitForSingleObject(ri.heRapiInit, 100) == WAIT_OBJECT_0 )
        {
          // If the RAPI init is done, check the result.
          hr = ri.hrRapiInit;
          break;
        }
      }
    }
  }
  else
  {
    hr = pCeRapiInit();
  }

  if ( FAILED(hr) )
  {
    hide_wait_box();
    warning("AUTOHIDE NONE\n"
            "Could not connect to the Windows CE device: %s", winerr(hr));
    SetLastError(hr);
    return NULL;
  }

#ifdef ASYNC_TEST
#define DLLNAME   "rapi_arm.dll"
#define WDLLNAME L"rapi_arm.dll"
#else
#define DLLNAME   "wince_remote_arm.dll"
#define WDLLNAME L"wince_remote_arm.dll"
#endif
  // local and remote server names
  static const wchar_t remote_wdll[] = L"\\Windows\\" WDLLNAME;
  static uchar remote_dll[] = "\\Windows\\" DLLNAME;
  char local_dll[QMAXPATH];
  if ( !getsysfile(local_dll, sizeof(local_dll), DLLNAME, NULL) )
    local_dll[0] = '\0';

  DWORD local_crc32 = 0;
  IRAPIStream *s = NULL;
  bool cancelled;

  while ( true )
  {
    cancelled = wasBreak();
    if ( cancelled )
      break;

    DWORD cbOut;
    hr = pCeRapiInvoke(remote_wdll, L"ida_server",
                       sizeof(remote_dll), remote_dll,
                       &cbOut, NULL,
                       &s, 0);
    if ( FAILED(hr) )
    {
      msg("Could not invoke debugger server at PocketPC: %s\n", winerr(hr));
COPY:
      int code;
      if ( local_dll[0] != '\0' )
      {
        code = copy_debugger_server(local_dll, remote_wdll);
        if ( code == 0 )
          continue; // try to start the server again
      }
      else
      {
        code = ERROR_FILE_NOT_FOUND;
      }
      hide_wait_box();
      warning("AUTOHIDE NONE\n"
              "Could not copy remote debugger server: %s", winerr(code));
      pCeRapiUninit();
      return NULL;
    }
    break;
  }

  hide_wait_box();

  if ( cancelled )
  {
    pCeRapiUninit();
    warning("AUTOHIDE NONE\n"
            "Cancelled by the user's request");
    SetLastError(ERROR_CANCELLED);
    return NULL;
  }

  // get remote checksum
  DWORD remote_crc32;
  DWORD nread = 0;
  hr = s->Read(&remote_crc32, sizeof(remote_crc32), &nread);
  if ( FAILED(hr) || nread != sizeof(remote_crc32) )
  {
    pCeRapiUninit();
    warning("AUTOHIDE NONE\n"
            "Failed to get remote crc32: %s", winerr(hr));
    SetLastError(hr);
    return NULL;
  }
  // check that remote DLL has good checksum
  DWORD crc_ok = true;
  if ( local_dll[0] == '\0' )
  {
    msg("Could not find local copy of %s, crc32 check is not performed\n", DLLNAME);
  }
  else
  {
    if ( local_crc32 == 0 )
    {
      linput_t *li = open_linput(local_dll, false);
      local_crc32 = calc_file_crc32(li);
      close_linput(li);
    }
    crc_ok = local_crc32 == remote_crc32;
  }
  DWORD dummy;
  s->Write(&crc_ok, sizeof(crc_ok), &dummy);
  if ( !crc_ok || dummy != sizeof(crc_ok) )
  {
    s->Release();
    show_wait_box("Updating remote debugger server");
    goto COPY;
  }

  async_stream_t *as = new async_stream_t;
  if ( as == NULL || !as->init(s) )
  {
    int code = GetLastError();
    delete as;

    warning("AUTOHIDE NONE\n"
            "Failed to start communication threads: %s", winerr(code));
    SetLastError(code);

    return NULL;
  }
  msg("Connection to the Windows CE device has been established.\n");
  return (idarpc_stream_t *)as;
}

#endif
#endif

