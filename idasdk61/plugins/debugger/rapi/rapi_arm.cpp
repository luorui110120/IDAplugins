#define ASYNC_TEST
#include "../async.cpp"

// simple echoing server

static bool in_use;

//--------------------------------------------------------------------------
static int display_exception(int code, EXCEPTION_POINTERS *ep)
{
  EXCEPTION_RECORD &er = *(ep->ExceptionRecord);
  printf("EXCEPTION %08lX IN RAPI_ARM\n", er.ExceptionCode);
  return EXCEPTION_EXECUTE_HANDLER;
}

//--------------------------------------------------------------------------
void handle_session(idarpc_stream_t *irs)
{
  rpc_packet_t rp;
  while ( irs_recv(irs, &rp, sizeof(rp), -1) == sizeof(rp) )
    irs_send(irs, &rp, sizeof(rp));
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
extern "C" __declspec(dllexport)
int ida_server(DWORD dwInput, BYTE* pInput,
               DWORD* pcbOutput, BYTE** ppOutput,
               IRAPIStream* pStream)
{
  printf("RAPI TEST SERVER\n");
  DWORD crc32 = calc_our_crc32((char *)pInput);
  DWORD dummy = 0;
  pStream->Write(&crc32, sizeof(crc32), &dummy);
  if ( dummy != sizeof(crc32) )
  {
ERR:
    pStream->Release();
//    printf("Debugger server checksum mismatch - shutting down\n");
    return ERROR_CRC;
  }
  DWORD ok;
  dummy = 0;
  pStream->Read(&ok, sizeof(ok), &dummy);
  if ( dummy != sizeof(ok) || ok != 1 )
    goto ERR;

  idarpc_stream_t *irs = init_server_irs(pStream);
  if ( irs == NULL )
    return 0;

  // only one instance is allowed
  if ( in_use )
  {
    static const char busy[] = "ERROR_BUSY";
    irs_send(irs, busy, sizeof(busy));
    term_server_irs(irs);
    SetLastError(ERROR_BUSY);
    return ERROR_BUSY;
  }
  in_use = true;

  __try
  {
    handle_session(irs);
  }
  __except ( display_exception(GetExceptionCode(), GetExceptionInformation()) )
  {
  }
  term_server_irs(irs);

  in_use = false;
  return 0;
}
