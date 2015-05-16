// test console application to call in stream mode

#define UNICODE
#include <conio.h>

#define ASYNC_TEST
#include "../async.cpp"
//--------------------------------------------------------------------------
int main(int /*argc*/, char* /*argv*/[])
{
  idarpc_stream_t *irs = init_client_irs(NULL, 0);
  if ( irs == NULL )
  {
    printf("Error: %s\n", winerr(GetLastError()));
    return 1;
  }
  printf("READY\n");
  while( true )
  {
    char c = getch();
    if ( c == 0x1B )
      break;
    qprintf("%c", c);
    rpc_packet_t rp;
    rp.length = 0;
    rp.code = c;
    if ( irs_send(irs, &rp, sizeof(rp)) != sizeof(rp) )
    {
      printf("irs_send: %s\n", winerr(irs_error(irs)));
      break;
    }
    memset(&rp, 0, sizeof(rp));
    if ( irs_recv(irs, &rp, sizeof(rp), -1) != sizeof(rp) )
    {
      printf("irs_recv: %s\n", winerr(irs_error(irs)));
      break;
    }
    qprintf("%c", rp.code);
  }
  qprintf("\n");
  term_client_irs(irs);
  return 0;
}
