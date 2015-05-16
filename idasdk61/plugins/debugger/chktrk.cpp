/*
        Sample driver program for Metrowerks communication
*/

#include <windows.h>

#include <fpro.h>
#include <err.h>
#include <diskio.hpp>
#include <kernwin.hpp>

#define DEBUGGER_PORT_NUMBER 23946
#include "metrotrk.h"
#include "metrotrk.cpp"

bool debug_debugger = true;

//-------------------------------------------------------------------------
// TRK command: handle notification packet. Returns true if handled
bool metrotrk_t::handle_notification(uchar seq, void *) // standalone version
{
  int i = 0;
  uint32 pid = -1;
  uint32 tid = -1;
  switch ( extract_byte(i) )
  {
    case TrkOSNotifyCreated:
      {
        uint16 item     = extract_int16(i);
        QASSERT(30006, item == TrkOSDLLItem);
        pid             = extract_int32(i);
        tid             = extract_int32(i);
        uint32 codeaddr = extract_int32(i);
        uint32 dataaddr = extract_int32(i);
        qstring name    = extract_pstr(i);
        if ( debug_debugger )
        {
          msg("NotifyCreated Item: %s\n", get_os_item_name(item));
          msg("  Process ID: %08X\n", pid);
          msg("  Thread ID : %08X\n", tid);
          msg("  CodeAddr  : %08X\n", codeaddr);
          msg("  DataAddr  : %08X\n", dataaddr);
          msg("  Name      : %s\n", name.c_str());
        }
      }
      break;

    case TrkOSNotifyDeleted:
      {
        uint16 item = extract_int16(i);
        if ( debug_debugger )
          msg("NotifyDeleted Item: %s\n", get_os_item_name(item));
        switch ( item )
        {
          case TrkOSProcessItem:
            {
              uint32 exitcode = extract_int32(i);
              uint32 pid      = extract_int32(i);
              if ( debug_debugger )
              {
                msg("  Process ID: %08X\n", pid);
                msg("  ExitCode  : %08X\n", exitcode);
              }
              tpi.pid = -1;
            }
            break;
          case TrkOSDLLItem:
            {
              pid = extract_int32(i);
              tid = extract_int32(i);
              qstring name = extract_pstr(i);
              if ( debug_debugger )
              {
                msg("  Process ID: %08X\n", pid);
                msg("  Thread ID : %08X\n", tid);
                msg("  Name      : %s\n", name.c_str());
              }
            }
            break;
          default:
            INTERR(30007); // not implemented
        }
      }
      break;

    case TrkNotifyStopped:
      {
        uint32 pc  = extract_int32(i);
        uint32 pid = extract_int32(i);
        uint32 tid = extract_int32(i);
        qstring desc = extract_pstr(i);
        if ( debug_debugger )
        {
          msg("  Current PC: %08X\n", pc);
          msg("  Process ID: %08X\n", pid);
          msg("  Thread ID : %08X\n", tid);
          msg("  Name      : %s\n", desc.c_str());
        }
      }
      break;

    default:
      return false;
  }
  if ( debug_debugger && pkt.size() > i )
    show_hex(&pkt[i], pkt.size()-i, "NOTIFY EXTRA BYTES (%d) ", pkt.size()-i);

  // send reply
  send_reply_ok(seq);

  // ask to continue
  if ( pid != -1 && tid != -1 )
  {
    if ( !resume_thread(pid, tid) )
      INTERR(30008);
  }

  return true;
}

//-------------------------------------------------------------------------
/*
static int parse_file_mode(const char *ptr)
{
  int mode = 0;
  while ( *ptr != 0 )
  {
    switch ( *ptr++ )
    {
      case 'w': mode |= TrkFileOpenCreate|TrkFileOpenRead; break;
      case 'r': mode |= TrkFileOpenRead;   break;
      case 'b': mode |= TrkFileOpenBinary; break;
      case 'x': mode |= TrkFileOpenExec;   break;
      case '+': mode |= TrkFileOpenAppend; break;
      default: error("Illegal file mode %c", ptr[-1]);
    }
  }
  return mode;
}
*/

//-------------------------------------------------------------------------
int __cdecl main(int argc, char *argv[])
{
  if ( argc < 2 )
USAGE:
    error("usage: chktrk portnum [sis-fname]");

  int port = atoi(argv[1]);
  if ( port == 0 )
    goto USAGE;

  metrotrk_t trk(NULL);
  if ( !trk.init(port) )
    error("COM%d: %s\n", port, winerr(GetLastError()));

  if ( !trk.ping() )
    INTERR(30009);
  if ( !trk.connect() )
    INTERR(30010);

//  proclist_t proclist;
//  ok = trk.get_process_list(proclist);  QASSERT(30011, ok);
//  for ( int i=0; i < proclist.size(); i++ )
//    msg("%08X %d %s\n", proclist[i].pid, proclist[i].priority, proclist[i].name.c_str());
//
//  msg("\nThread of proc[0]\n");
//  thread_list_t threadlist;
//  ok = trk.get_thread_list(proclist[0].pid, threadlist);  QASSERT(30012, ok);
//  for ( int i=0; i < threadlist.size(); i++ )
//  {
//    msg("%08X %d %s %s\n",
//        threadlist[i].tid,
//        threadlist[i].priority,
//        threadlist[i].is_suspended ? "Yes" : "No ",
//        threadlist[i].name.c_str());
//  }
//
//  for ( int i=0; i < 16; i++ )
//  {
//    uint32 v;
//    ok = trk.read_regs(proclist[0].pid, threadlist[1].tid, i, 1, &v);
//    QASSERT(30013, ok);
//    msg("R%d=%x\n", i, v);
//  }
//
//  return 0;


//  uchar mask[32];
//  trk.support_mask(mask);
//  trk_cpuinfo_t ci;
//  trk.cpu_type(&ci);
  static const char fname[] = "D:\\sys\\bin\\HelloWorldBasic.exe";
  if ( argc > 2 )
  {
    const char *sisname = argv[2]; // "helloworldbasic_signed.sis";
    char drive = 'd';
    trk.install_sis_file(sisname, drive);
  }
  trk_process_info_t pi;
  if ( !trk.create_process(fname, NULL, &pi) )
    INTERR(30014);
  if ( !trk.resume_thread(pi.pid, pi.tid) )
    INTERR(30015);
  while ( trk.current_pid() != -1 )
    trk.poll_for_event(100);
  return 0;
}

