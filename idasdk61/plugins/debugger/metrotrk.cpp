
#include <setupapi.h>

// This file is included from other files, do not directly compile it.
// It contains the implementation of the class to communicate with Metrowerks TRK
//

//-------------------------------------------------------------------------
// Get description of a TRK error code
static const char *get_trk_error_name(uchar error_code)
{
  switch ( error_code )
  {
    case TrkReplyNoError:              return "ok";
    case TrkReplyError:                return "generic error in CWDS message";
    case TrkReplyPacketSizeError:      return "unexpected pkt size in send msg";
    case TrkReplyCWDSError:            return "internal error occurred in CWDS";
    case TrkReplyEscapeError:          return "escape followed by frame flag";
    case TrkReplyBadFCS:               return "bad FCS in packet";
    case TrkReplyOverflow:             return "packet too long";
    case TrkReplySequenceMissing:      return "sequence ID != expected (gap in sequence)";
    case TrkReplyUnsupportedCmd:       return "command not supported";
    case TrkReplyParameterError:       return "command param out of range";
    case TrkReplyUnsupportedOption:    return "an option was not supported";
    case TrkReplyInvalidMemoryRange:   return "read/write to invalid memory";
    case TrkReplyInvalidRegisterRange: return "read/write invalid registers";
    case TrkReplyCWDSException:        return "exception occurred in CWDS";
    case TrkReplyNotStopped:           return "targeted system or thread is running";
    case TrkReplyBreakpointsFull:      return "bp resources (HW or SW) exhausted";
    case TrkReplyBreakpointConflict:   return "requested bp conflicts w/existing bp";
    case TrkReplyOsError:              return "general OS-related error";
    case TrkReplyInvalidProcessId:     return "request specified invalid process";
    case TrkReplyInvalidThreadId:      return "request specified invalid thread";
  }
  static char buf[16];
  qsnprintf(buf, sizeof(buf), "error %02X", error_code);
  return buf;
}

//-------------------------------------------------------------------------
// Get name of a TRK packet name.
static const char *get_pkttype_name(uchar type)
{
  switch ( type )
  {
    case TrkPing:                     return "Ping";
    case TrkConnect:                  return "Connect";
    case TrkDisconnect:               return "Disconnect";
    case TrkReset:                    return "Reset";
    case TrkVersions:                 return "Versions";
    case TrkSupportMask:              return "SupportMask";
    case TrkCPUType:                  return "CPUType";
    case TrkReadMemory:               return "ReadMemory";
    case TrkWriteMemory:              return "WriteMemory";
    case TrkReadRegisters:            return "ReadRegisters";
    case TrkWriteRegisters:           return "WriteRegisters";
    case TrkFillMemory:               return "FillMemory";
    case TrkCopyMemory:               return "CopyMemory";
    case TrkFlushCache:               return "FlushCache";
    case TrkContinue:                 return "Continue";
    case TrkStep:                     return "Step";
    case TrkStop:                     return "Stop";
    case TrkSetBreak:                 return "SetBreak";
    case TrkClearBreak:               return "ClearBreak";
    case TrkModifyBreakThread:        return "ModifyBreakThread";
    case TrkOSCreateItem:             return "OSCreateItem";
    case TrkOSDeleteItem:             return "OSDeleteItem";
    case TrkOSReadInfo:               return "OSReadInfo";
    case TrkOSWriteInfo:              return "OSWriteInfo";
    case TrkOSWriteFile:              return "OSWriteFile";
    case TrkOSReadFile:               return "OSReadFile";
    case TrkOSOpenFile:               return "OSOpenFile";
    case TrkOSCloseFile:              return "OSCloseFile";
    case TrkOSPositionFile:           return "OSPositionFile";
    case TrkOSInstallFile:            return "OSInstallFile";
    case TrkReplyACK:                 return "ReplyACK";
    case TrkReplyNAK:                 return "ReplyNAK";
    case TrkNotifyStopped:            return "NotifyStopped";
    case TrkOSNotifyCreated:          return "OSNotifyCreated";
    case TrkOSNotifyDeleted:          return "OSNotifyDeleted";
    case TrkWriteFile:                return "WriteFile";
    case TrkReadFile:                 return "ReadFile";
    case TrkOpenFile:                 return "OpenFile";
    case TrkCloseFile:                return "CloseFile";
    case TrkPositionFile:             return "PositionFile";
  }
  static char buf[8];
  qsnprintf(buf, sizeof(buf), "%02X", type);
  return buf;
}

//-------------------------------------------------------------------------
// Get name of an OS item for TRK
static const char *get_os_item_name(uint16 type)
{
  switch ( type )
  {
    case TrkOSProcessItem:      return "Process";
    case TrkOSThreadItem:       return "Thread";
    case TrkOSDLLItem:          return "DLL";
    case TrkOSAppItem:          return "App";
    case TrkOSMemBlockItem:     return "MemBlock";
    case TrkOSProcAttachItem:   return "ProcAttach";
    case TrkOSThreadAttachItem: return "ThreadAttach";
  }
  static char buf[16];
  qsnprintf(buf, sizeof(buf), "%04X", type);
  return buf;
}

//-------------------------------------------------------------------------
// Enumerate all serial ports and perform an action
// returns
//     -1 - error
// otherwise - code returned by serial_port_visitor_t or 0
// This code is based on EnumSerialPorts by PJ Naughter pjna@naughter.com
// http://www.naughter.com

struct serial_port_visitor_t
{
  virtual int visit(int port, const char *friendly_name) = 0;
};

static int for_all_serial_ports(serial_port_visitor_t &v)
{
  //Get the function pointers to "SetupDiGetClassDevs", "SetupDiGetClassDevs", "SetupDiEnumDeviceInfo", "SetupDiOpenDevRegKey"
  //and "SetupDiDestroyDeviceInfoList" in setupapi.dll
  HINSTANCE hSetupAPI = LoadLibrary("SETUPAPI.DLL");
  if ( hSetupAPI == NULL )
    return -1;

  typedef HKEY (__stdcall SETUPDIOPENDEVREGKEY)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, DWORD, DWORD, REGSAM);
  typedef BOOL (__stdcall SETUPDICLASSGUIDSFROMNAME)(LPCTSTR, LPGUID, DWORD, PDWORD);
  typedef BOOL (__stdcall SETUPDIDESTROYDEVICEINFOLIST)(HDEVINFO);
  typedef BOOL (__stdcall SETUPDIENUMDEVICEINFO)(HDEVINFO, DWORD, PSP_DEVINFO_DATA);
  typedef HDEVINFO (__stdcall SETUPDIGETCLASSDEVS)(LPGUID, LPCTSTR, HWND, DWORD);
  typedef BOOL (__stdcall SETUPDIGETDEVICEREGISTRYPROPERTY)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);

  SETUPDIOPENDEVREGKEY* lpfnLPSETUPDIOPENDEVREGKEY;
  SETUPDICLASSGUIDSFROMNAME* lpfnSETUPDICLASSGUIDSFROMNAME;
  SETUPDIGETCLASSDEVS* lpfnSETUPDIGETCLASSDEVS;
  SETUPDIGETDEVICEREGISTRYPROPERTY* lpfnSETUPDIGETDEVICEREGISTRYPROPERTY;
  SETUPDIDESTROYDEVICEINFOLIST* lpfnSETUPDIDESTROYDEVICEINFOLIST;
  SETUPDIENUMDEVICEINFO* lpfnSETUPDIENUMDEVICEINFO;

  *(FARPROC*)&lpfnLPSETUPDIOPENDEVREGKEY = GetProcAddress(hSetupAPI, "SetupDiOpenDevRegKey");
  *(FARPROC*)&lpfnSETUPDICLASSGUIDSFROMNAME = GetProcAddress(hSetupAPI, "SetupDiClassGuidsFromNameA");
  *(FARPROC*)&lpfnSETUPDIGETCLASSDEVS = GetProcAddress(hSetupAPI, "SetupDiGetClassDevsA");
  *(FARPROC*)&lpfnSETUPDIGETDEVICEREGISTRYPROPERTY = GetProcAddress(hSetupAPI, "SetupDiGetDeviceRegistryPropertyA");
  *(FARPROC*)&lpfnSETUPDIDESTROYDEVICEINFOLIST = GetProcAddress(hSetupAPI, "SetupDiDestroyDeviceInfoList");
  *(FARPROC*)&lpfnSETUPDIENUMDEVICEINFO = GetProcAddress(hSetupAPI, "SetupDiEnumDeviceInfo");

  if ( lpfnLPSETUPDIOPENDEVREGKEY == NULL
    || lpfnSETUPDICLASSGUIDSFROMNAME == NULL
    || lpfnSETUPDIDESTROYDEVICEINFOLIST == NULL
    || lpfnSETUPDIENUMDEVICEINFO == NULL
    || lpfnSETUPDIGETCLASSDEVS == NULL
    || lpfnSETUPDIGETDEVICEREGISTRYPROPERTY == NULL )
  {
    FreeLibrary(hSetupAPI);
    return -1;
  }

  HDEVINFO hDevInfoSet = INVALID_HANDLE_VALUE;
  // First need to convert the name "Ports" to a GUID using SetupDiClassGuidsFromName
  DWORD dwGuids = 0;
  lpfnSETUPDICLASSGUIDSFROMNAME("Ports", NULL, 0, &dwGuids);
  if ( dwGuids > 0 )
  {
    qvector<GUID> guids;
    guids.resize(dwGuids);
    if ( lpfnSETUPDICLASSGUIDSFROMNAME("Ports", guids.begin(), dwGuids, &dwGuids) )
    {
      // Now create a "device information set" which is required to enumerate all the ports
      hDevInfoSet = lpfnSETUPDIGETCLASSDEVS(guids.begin(), NULL, NULL, DIGCF_PRESENT);
    }
  }

  // Finally do the enumeration
  int code = 0;
  for ( int nIndex=0; ; nIndex++ )
  {
    // Enumerate the current device
    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    if ( !lpfnSETUPDIENUMDEVICEINFO(hDevInfoSet, nIndex, &devInfo) )
      break;

    // Get the registry key which stores the ports settings
    HKEY hDeviceKey = lpfnLPSETUPDIOPENDEVREGKEY(hDevInfoSet, &devInfo,
                               DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
    if ( hDeviceKey == NULL )
      continue;

    TCHAR name[256];
    DWORD dwSize = sizeof(name);
    DWORD dwType = 0;
    if ( RegQueryValueEx(hDeviceKey, "PortName", NULL, &dwType,
                                        (LPBYTE)name, &dwSize) == ERROR_SUCCESS
      && dwType == REG_SZ )
    {
      // If it looks like "COMX" then add it to the array which will be returned
      size_t nLen = strlen(name);
      if ( nLen > 3 )
      {
        if ( strnicmp(name, "COM", 3) == 0 )
        {
          int port = atoi(&name[3]);
          dwSize = sizeof(name);
          dwType = 0;
          if ( !lpfnSETUPDIGETDEVICEREGISTRYPROPERTY(hDevInfoSet, &devInfo,
                    SPDRP_DEVICEDESC, &dwType, (LPBYTE)name, dwSize, &dwSize)
            || dwType != REG_SZ )
          {
            name[0] = '\0';
          }
          code = v.visit(port, name);
        }
      }
    }
    RegCloseKey(hDeviceKey);
    if ( code != 0 )
      break;
  }
  lpfnSETUPDIDESTROYDEVICEINFOLIST(hDevInfoSet);
  FreeLibrary(hSetupAPI);
  return code;
}

//-------------------------------------------------------------------------
static bool is_serial_port_present(int port, qstring *friendly_name)
{
  struct serial_port_checker_t : public serial_port_visitor_t
  {
    int port;
    qstring *name;
    int visit(int p, const char *friendly_name)
    {
      if ( p == port )
      {
        if ( name != NULL )
          *name = friendly_name;
        return 1;
      }
      return 0;
    }
    serial_port_checker_t(int p, qstring *n) : port(p), name(n) {}
  };
  serial_port_checker_t spf(port, friendly_name);
  return for_all_serial_ports(spf) == 1;
}

//-------------------------------------------------------------------------
// Try to find a smartphone port. We do it by looking at the friendly name.
// If it contains "nokia", then it is our port. The searched substring may
// be specified by the EPOC_PORT_DESCRIPTION environment variable.
// Returns <= 0: could not find anything
static int find_smartphone_port(void)
{
  struct smartphone_port_finder_t : public serial_port_visitor_t
  {
    const char *desc;
    int visit(int p, const char *friendly_name)
    {
      if ( stristr(friendly_name, desc) != NULL )
        return p;
      return 0;
    }
    smartphone_port_finder_t(void)
    {
      desc = getenv("EPOC_PORT_DESCRIPTION");
      if ( desc == NULL )
        desc = "Nokia";
    }
  };
  smartphone_port_finder_t spf;
  return for_all_serial_ports(spf);
}

//-------------------------------------------------------------------------
// Initialize TRK connection over a serial port.
// Returns success.
bool metrotrk_t::init(int port)
{
  sseq = 0;

  if ( port == DEBUGGER_PORT_NUMBER )
  {
    int p = find_smartphone_port();
    if ( p > 0 )
    {
      port = p;
      msg("Using COM%d: to communicate with the smartphone...\n", port);
    }
    else
    {
      warning("Could not autodetect the smartphone port.\n"
              "Please specify it manually in the process options");
    }
  }

  char name[32];
  qsnprintf(name, sizeof(name), "\\\\.\\COM%d", port);

  qstring friendly_name;
  if ( !is_serial_port_present(port, &friendly_name) )
  {
      if ( askyn_c(0,
                   "HIDECANCEL\n"
                   "Serial port COM%d seems to be unavailable. Do you want to proceed?",
                   port ) <= 0 )
      {
        SetLastError(ERROR_DEVICE_NOT_CONNECTED);
        return false;
      }
  }
  msg("Opening serial port %s: (%s)...\n", &name[4], friendly_name.c_str());

  // port exists, open it
  hp = CreateFile(name, GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if ( hp == INVALID_HANDLE_VALUE )
    return false;
  DCB dcb;
  memset(&dcb, 0, sizeof(dcb));
  dcb.DCBlength = sizeof(dcb);
  dcb.BaudRate = CBR_115200;
  dcb.fBinary = true;
  dcb.ByteSize = 8;
  dcb.Parity = NOPARITY;
  dcb.StopBits = ONESTOPBIT;
  if ( !SetCommState(hp, &dcb) )
  {
    CloseHandle(hp);
    return false;
  }
  GetCommTimeouts(hp, &ct);
  return true;
}

//-------------------------------------------------------------------------
// Terminate TRK connection
void metrotrk_t::term(void)
{
  if ( tpi.pid != -1 )
  {
    terminate_process(tpi.pid);
    tpi.pid = -1;
  }
  if ( hp != INVALID_HANDLE_VALUE )
  {
    CloseHandle(hp);
    hp = INVALID_HANDLE_VALUE;
  }
}

//-------------------------------------------------------------------------
// Group of functions to prepare TRK packet
// Append a byte to the current packet
void metrotrk_t::append_byte(uchar byte)
{
  checksum += byte;
  if ( byte == FRAME_FLAG || byte == FRAME_ESCAPE )
  {
    byte ^= FRAME_TRANS;
    pkt.push_back(FRAME_ESCAPE);
  }
  pkt.push_back(byte);
}

//-------------------------------------------------------------------------
// Append int16 to the current packet
void metrotrk_t::append_int16(uint16 x)
{
  append_byte(x >> 8);
  append_byte((uchar)x);
}

//-------------------------------------------------------------------------
// Append int32 to the current packet
void metrotrk_t::append_int32(uint32 x)
{
  append_int16(x >> 16);
  append_int16((uint16)x);
}

//-------------------------------------------------------------------------
// Append arbitrary data to the current packet in pascal form
// (first length, then the data itself)
void metrotrk_t::append_data(const void *data, size_t len)
{
  const char *ptr = (const char *)data;
  if ( len == 0 )
    len = strlen(ptr);
  append_int16((uint16)len);
  for ( int i=0; i < len; i++ )
    append_byte(*ptr++);
}


// Prepend a byte to the current packet (no checksum correction!)
void metrotrk_t::prepend_byte(uchar byte)
{
  pkt.insert(pkt.begin(), byte);
}


//-------------------------------------------------------------------------
// Group of functions to extract data from the current TRK packet
// Extract one byte
uchar metrotrk_t::extract_byte(int &i)
{
  if ( i >= pkt.size() )
    return 0;
  return pkt[i++];
}

//-------------------------------------------------------------------------
// Extract int16
uint16 metrotrk_t::extract_int16(int &i)
{
  int hi = extract_byte(i);
  int lo = extract_byte(i);
  int x = (hi << 8) | lo;
  return uint16(x);
}

//-------------------------------------------------------------------------
// Extract int32
uint32 metrotrk_t::extract_int32(int &i)
{
  int hi = extract_int16(i);
  int lo = extract_int16(i);
  int x = (hi << 16) | lo;
  return x;
}

//-------------------------------------------------------------------------
// Extract pascal style string, make sure that there is a terminating zero
qstring metrotrk_t::extract_pstr(int &i)
{
  size_t len = extract_int16(i);
  size_t remains = pkt.size() - i;
  if ( len > remains )
    len = remains;
  qstring str((char*)&pkt[i], len);
  i += (int)len;
  return str;
}

//-------------------------------------------------------------------------
// Extract zero terminated string
qstring metrotrk_t::extract_asciiz(int &i)
{
  size_t j;
  for ( j=i; j < pkt.size(); j++ )
    if ( pkt[j] == '\0' )
      break;
  size_t len = j - i;
  j = i;
  i += (int)len;
  if ( i < pkt.size() )
    i++;
  return qstring((char*)&pkt[j], len);
}


//-------------------------------------------------------------------------
// Add header
void metrotrk_t::prepend_hdr(void)
{
  size_t len = pkt.size();
  prepend_byte((uchar)len);
  prepend_byte((uchar)(len >> 8));
  prepend_byte(0x90);
  prepend_byte(0x01);
}

//-------------------------------------------------------------------------
// Finalize and send one TRK packet
bool metrotrk_t::send_packet(void)
{
  append_byte(~checksum);
  pkt.push_back(FRAME_FLAG);
  prepend_hdr();
  if ( debug_debugger )
  {
    const char *name = get_pkttype_name(pkt[1+4]);
    uchar nseq = pkt[2+4];
    if ( pkt.size() < 0x100 )
      show_hex(pkt.begin(), pkt.size(), "\nSEND %02X %s:\n", nseq, name);
    else
      msg("\nSEND %02X %s: (%d bytes hidden)\n", nseq, name, pkt.size());
  }
  DWORD nbytes = 0;
  WriteFile(hp, pkt.begin(), (DWORD)pkt.size(), &nbytes, NULL);
  if ( nbytes != pkt.size() )
  {
    msg("write %d bytes: %s\n", pkt.size(), winerr(GetLastError()));
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
// Receive one byte from the serial port. We have to read one byte a time,
// otherwise ReadFile function pauses (apparently waiting for more characters to arrive)
bool metrotrk_t::recv_byte(uchar *byte)
{
  DWORD nread = 0;
  if ( !ReadFile(hp, byte, 1, &nread, NULL) )
    error("read: %s\n", winerr(GetLastError()));
  return nread != 0;
}

//-------------------------------------------------------------------------
// Receive a packet. If there is no data, this function will return after a while
// (timeout determined by the ReadFile function)
// We don't store packet sequence numbers and other auxiliary info in the packet
// Received packet will look like this:
//      type, errcode, data...
// So the user data starts at index 2.
bool metrotrk_t::recv_packet(uchar *seq, int timeout)
{
  set_timeout(timeout);
  uchar sum = 0;
  pkt.qclear();
  while ( pkt.empty() )
  {
    uchar b;
    // synchronize at the frame flag
    while ( true )
    {
      if ( !recv_byte(&b) )
        return false;
      if ( b == FRAME_FLAG )
        break;
    }
    sum = 0;
    set_timeout(0); // read the rest of the packet without timeouts
    for ( int idx = 0; ; idx++ )
    {
      if ( !recv_byte(&b) )
        return false;
      if ( b == FRAME_FLAG )
        break;
      if ( b == FRAME_ESCAPE )
      {
        if ( !recv_byte(&b) )
          return false;
        b ^= FRAME_TRANS;
      }
      if ( idx == 1 )
      {
        *seq = b;
      }
      else
      {
        pkt.push_back(b);
      }
      sum += b;
    }
  }
  if ( sum != 0xFF )
  {
    msg("wrong checksum %x of rcvd pkt (expected %x)\n", sum);
    return false;
  }
  pkt.pop_back();
  if ( debug_debugger )
  {
    size_t s = qmin(pkt.size(), 16);
    show_hex(pkt.begin(), s, "RECEIVED PACKET %d BYTES SEQ %x:\n", pkt.size(), *seq);
  }
  return true;
}

//-------------------------------------------------------------------------
// Send a packet and receive the reply
// Received packet will look like this:
//      type, errcode, data...
bool metrotrk_t::process_packet(size_t minsize, bool allow_extra_bytes)
{
  int cmd = pkt[1];
  if ( !send_packet() )
    return false;

  uchar seq;
  int expected_seq = sseq - 1;
  while ( true )
  {
    if ( !recv_packet(&seq, 0) )
    {
      msg("TRK: no answer...\n");
      return false;
    }
GOTPKT:
    if ( pkt.empty() )
      continue;
    if ( pkt[0] == TrkReplyACK )
    {
      if ( seq == uchar(expected_seq) )
        break;
      if ( cmd == TrkPing )
      {
        msg("wrong sequence number %x (expected %x)\n", seq, expected_seq);
        return false;
      }
      pkt.push_back(seq);
      out_of_order.push(pkt);
      continue;
    }
    if ( handle_notification(seq, ud) )
    {
      if ( !out_of_order.empty() )
      {
        pkt = out_of_order.pop();
        seq = pkt.back();
        pkt.pop_back();
        goto GOTPKT;
      }
      continue;
    }
    msg("NACK: %s\n", get_trk_error_name(pkt[1]));
    return false;
  }
  // got an ACK
  if ( pkt[1] != TrkReplyNoError )
  {
    if ( debug_debugger )
      msg("ACK: %s\n", get_trk_error_name(pkt[1]));
    return false;
  }
  minsize += 2;         // type and error code
  if ( pkt.size() < minsize )
  {
    msg("TRK: too small rcvd data %d (expected %d)\n", pkt.size()-2, minsize-2);
    return false;
  }
  if ( pkt.size() > minsize && !allow_extra_bytes && debug_debugger )
    show_hex(&pkt[2], pkt.size()-2, "PKT EXTRA BYTES (%d < %d) ", minsize-2, pkt.size()-2);
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Ping
bool metrotrk_t::ping(void)
{
  init_packet(TrkPing);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Connect. Resets the debug server
bool metrotrk_t::connect(void)
{
  init_packet(TrkConnect);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Disconnect
bool metrotrk_t::disconnect(void)
{
  init_packet(TrkDisconnect);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Get support mask
bool metrotrk_t::support_mask(uchar mask[32], uchar *protocol_level)
{
  init_packet(TrkSupportMask);
  if ( !process_packet(33) )
    return false;
  if ( mask != NULL )
    memcpy(mask, &pkt[2], sizeof(mask));
  if ( protocol_level != NULL )
    *protocol_level = pkt[2+sizeof(mask)];
  if ( debug_debugger )
  {
    if ( mask != NULL )
    {
      msg("    MASK:");
      for ( int i=0; i < sizeof(mask); i++ )
        msg("%s%02X", i == 16 ? "\n          " : " ", mask[i]);
    }
    if ( protocol_level != NULL )
      msg("\n    Protocol level: %d\n", *protocol_level);
  }
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Get CPU information
bool metrotrk_t::cpu_type(trk_cpuinfo_t *cpuinfo)
{
  init_packet(TrkCPUType);
  if ( !process_packet(sizeof(cpuinfo)) )
    return false;
  memcpy(cpuinfo, &pkt[2], sizeof(*cpuinfo));
  if ( debug_debugger )
  {
    msg("    cpuVersion       : %d.%d\n", cpuinfo->cpuMajor, cpuinfo->cpuMinor);
    msg("    bigEndian        : %s\n", cpuinfo->bigEndian ? "yes" : "no");
    msg("    defaultTypeSize  : %d\n", cpuinfo->defaultTypeSize);
    msg("    fpTypeSize       : %d\n", cpuinfo->fpTypeSize);
    msg("    extended1TypeSize: %d\n", cpuinfo->extended1TypeSize);
    msg("    extended2TypeSize: %d\n", cpuinfo->extended2TypeSize);
  }
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Open a file on the device
int metrotrk_t::open_file(const char *name, trk_open_mode_t mode)
{
  init_packet(TrkOSOpenFile);
  append_byte((uchar)mode);
  append_data(name);
  if ( !process_packet(1+4+4) )
    return -1;

  int i = 2;
  int err = extract_byte(i);
  int handle = extract_int32(i);
  int time = extract_int32(i);
  if ( debug_debugger )
  {
    msg("    Error code: %d\n", err);
    msg("    Handle    : %d\n", handle);
    msg("    Time      : %08X\n", time);
  }
  return handle;
}

//-------------------------------------------------------------------------
// TRK command: Write file chunk. This function writes up to MAX_FRAME_DATA
// bytes. Returns number of written bytes or -1 if error.
ssize_t metrotrk_t::write_file_chunk(int h, const void *bytes, size_t size)
{
  init_packet(TrkOSWriteFile);
  append_int32(h);
  append_data(bytes, size);
  if ( !process_packet(1+2) )
    return -1;

  int i = 2;
  int err = extract_byte(i);
  int length = extract_int16(i);
  if ( debug_debugger )
  {
    msg("    Error code: %d\n", err);
    msg("    Length    : %d\n", length);
  }
  return err == 0 ? length : -1;
}

//-------------------------------------------------------------------------
// TRK command: Write to file
// Returns number of written bytes or -1 if error.
ssize_t metrotrk_t::write_file(int h, const void *bytes, size_t size)
{
  size_t initial_size = size;
  const uchar *ptr = (const uchar *)bytes;
  while ( size != 0 )
  {
    size_t chunk = size > MAX_FRAME_DATA ? MAX_FRAME_DATA : size;
    ssize_t written = write_file_chunk(h, ptr, chunk);
    if ( written < 0 )
      return -1;
    size -= written;
    if ( written != chunk )
      break;
    ptr += written;
  }
  return initial_size - size;
}

//-------------------------------------------------------------------------
// TRK command: Read from file, up to MAX_FRAME_DATA bytes
// Returns number of read bytes or -1 if error.
ssize_t metrotrk_t::read_file_chunk(int h, void *bytes, size_t size)
{
  init_packet(TrkOSReadFile);
  append_int32(h);
  append_int16((uint16)size);
  if ( !process_packet(1+2, true) )
    return -1;

  int i = 2;
  int err = extract_byte(i);
  int length = extract_int16(i);
  if ( debug_debugger )
  {
    msg("    Error code: %d\n", err);
    msg("    Length    : %d\n", length);
  }
  QASSERT(30107, length < ssize_t(size));
  if ( length > 0 )
    memcpy(bytes, &pkt[i], length);
  return err == 0 ? length : -1;
}

//-------------------------------------------------------------------------
// TRK command: Read from file
// Returns number of read bytes or -1 if error.
ssize_t metrotrk_t::read_file(int h, void *bytes, size_t size)
{
  size_t initial_size = size;
  uchar *ptr = (uchar *)bytes;
  while ( size != 0 )
  {
    size_t chunk = size > MAX_FRAME_DATA ? MAX_FRAME_DATA : size;
    ssize_t nread = read_file_chunk(h, ptr, chunk);
    if ( nread < 0 )
      return -1;
    size -= nread;
    if ( nread != chunk )
      break;
    ptr += nread;
  }
  return initial_size - size;
}

//-------------------------------------------------------------------------
// TRK command: Set file position. seek_mode is one of SEEK_... constants
bool metrotrk_t::seek_file(int h, uint32 off, int seek_mode)
{
  init_packet(TrkOSPositionFile);
  append_byte((uchar)seek_mode);
  append_int32(h);
  append_int32(off);
  if ( !process_packet(1) )
    return false;

  int i = 2;
  int err = extract_byte(i);
  if ( debug_debugger )
    msg("    Error code: %d\n", err);
  return err == 0;
}

//-------------------------------------------------------------------------
// TRK command: Close file handle. In fact, TRK ignores file handles.
bool metrotrk_t::close_file(int h, int timestamp)
{
  init_packet(TrkOSCloseFile);
  append_int32(h);
  append_int32(timestamp);
  if ( !process_packet(1) )
    return false;

  int i = 2;
  int err = extract_byte(i);
  if ( debug_debugger )
    msg("    Error code: %d\n", err);
  return err == 0;
}

//-------------------------------------------------------------------------
// TRK command: Install a SIS file at the device
bool metrotrk_t::install_file(const char *fname, char drive)
{
  init_packet(TrkOSInstallFile);
  append_byte(qtoupper(drive));
  append_data(fname);
  if ( !process_packet(1) )
    return false;

  int i = 2;
  int err = extract_byte(i);
  if ( debug_debugger )
    msg("    Error code: %d\n", err);
  return err == 0;
}

//-------------------------------------------------------------------------
// Download and install the specifies SIS file to the device
bool metrotrk_t::install_sis_file(const char *local_sis_fname, char drive)
{
  FILE *fp = fopenRB(local_sis_fname);
  if ( fp == NULL )
    return false;
  int flen = efilelength(fp);
  qvector<uchar> body;
  body.resize(flen);
  qfread(fp, body.begin(), flen);
  qfclose(fp);

  static const char remote_sis_fname[] = "c:\\temporary.sis";
  int mode = TrkFileOpenCreate|TrkFileOpenRead|TrkFileOpenBinary;
  int h = open_file(remote_sis_fname, mode);   QASSERT(30108, h > 0);
  ssize_t written = write_file(h, body.begin(), body.size());
  QASSERT(30109, written == body.size()); qnotused(written);
  if ( !close_file(h, 0) )
    INTERR(30110);
  if ( !install_file(remote_sis_fname, drive) )
    INTERR(30111);
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Create process
bool metrotrk_t::create_process(
        const char *fname,
        const char *args,
        trk_process_info_t *pi)
{
  // concat the filename, command line args, and working directory
  qstring blob(fname);
  blob.append('\0');
  if ( args != NULL )
    blob.append(args);
  blob.append('\0');

  init_packet(TrkOSCreateItem);
  append_int16(TrkOSProcessItem);
  append_byte(0);               // options
  append_data(blob.begin(), blob.length());
  if ( !process_packet(sizeof(trk_process_info_t)) )
    return false;

  int i = 2;
  tpi.pid      = extract_int32(i);
  tpi.tid      = extract_int32(i);
  tpi.codeaddr = extract_int32(i);
  tpi.dataaddr = extract_int32(i);
  if ( pi != NULL )
    *pi = tpi;
  if ( debug_debugger )
  {
    msg("    Process ID: %08X\n", tpi.pid);
    msg("    Thread ID : %08X\n", tpi.tid);
    msg("    CodeAddr  : %08X\n", tpi.codeaddr);
    msg("    DataAddr  : %08X\n", tpi.dataaddr);
  }
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Attach to process
int metrotrk_t::attach_process(int pid)
{
  init_packet(TrkOSCreateItem);
  append_int16(TrkOSProcAttachItem);
  append_byte(0);               // options
  append_int32(pid);
  if ( !process_packet(4) )
    return 0;

  int i = 2;
  int tid = extract_int32(i);
  if ( debug_debugger )
    msg("    Thread ID : %08X\n", tid);
  return tid;
}

//-------------------------------------------------------------------------
// TRK command: Resume thread. -1 seems to denote all process threads
bool metrotrk_t::resume_thread(int pid, int tid)
{
  init_packet(TrkContinue);
  append_int32(pid);
  append_int32(tid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Suspend thread. -1 seems to denote all process threads
bool metrotrk_t::suspend_thread(int pid, int tid)
{
  init_packet(TrkStop);
  append_byte(2);       // stop thread?
  append_int32(pid);
  append_int32(tid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Step into/over thread
// start and end denote an address range
bool metrotrk_t::step_thread(int pid, int tid, int32 start, int32 end, bool stepinto)
{
  init_packet(TrkStep);
  append_byte(uchar(stepinto ? TrkStepIntoRange : TrkStepOverRange));
  append_int32(start);
  append_int32(end);
  append_int32(pid);
  append_int32(tid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Add breakpoint
// tid == -1 - all threads?
int metrotrk_t::add_bpt(int pid, int tid, int32 addr, size_t len, int count, bool thumb_mode)
{
  init_packet(TrkSetBreak);
  append_byte(0);       // ?
  append_byte(thumb_mode);
  append_int32(addr);
  append_int32((int32)len);
  append_int32(count);
  append_int32(pid);
  append_int32(tid);
  if ( !process_packet(4) )
    return -1;

  int i = 2;
  int bid = extract_int32(i);
  if ( debug_debugger )
    msg("    Bpt ID : %d\n", bid);
  return bid;
}

//-------------------------------------------------------------------------
// TRK command: Delete breakpoint
bool metrotrk_t::del_bpt(int bid)
{
  init_packet(TrkClearBreak);
  append_int32(bid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Change the thread the breakpoint is associated with
bool metrotrk_t::change_bpt_thread(int bid, int tid)
{
  init_packet(TrkModifyBreakThread);
  append_int32(bid);
  append_int32(tid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Terminate process
bool metrotrk_t::terminate_process(int pid)
{
  init_packet(TrkOSDeleteItem);
  append_int16(TrkOSProcessItem);
  append_int32(pid);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Get process list
bool metrotrk_t::get_process_list(proclist_t &proclist)
{
  int idx = 0;
  while ( true )
  {
    init_packet(TrkOSReadInfo);
    append_int16(TrkOSProcessList);
    append_int32(idx);
    append_byte(0);             // options
    append_int32(0);            // filter
    if ( !process_packet(8, true) )
      return false;
    int i = 2;
    int count = extract_int32(i);
    int total = extract_int32(i);
    for ( int j=0; j < count; j++ )
    {
      proclist_entry_t &pe = proclist.push_back();
      pe.pid = extract_int32(i);
      pe.priority = extract_int32(i);
      pe.name = extract_asciiz(i);
    }
    idx += count;
    if ( idx >= total )
      return true;
  }
}

//-------------------------------------------------------------------------
// TRK command: Get list of threads of the specified process
bool metrotrk_t::get_thread_list(int pid, thread_list_t *threadlist)
{
  int idx = 0;
  while ( true )
  {
    init_packet(TrkOSReadInfo);
    append_int16(TrkOSThreadList);
    append_int32(idx);
    append_byte(0);             // options
    append_int32(pid);
    if ( !process_packet(8, true) )
      return false;
    int i = 2;
    int count = extract_int32(i);
    int total = extract_int32(i);
    for ( int j=0; j < count; j++ )
    {
      thread_list_entry_t &pe = threadlist->push_back();
      pe.tid = extract_int32(i);
      pe.priority = extract_int32(i);
      pe.is_suspended = extract_byte(i);
      pe.name = extract_asciiz(i);
    }
    idx += count;
    if ( idx >= total )
      return true;
  }
}

//-------------------------------------------------------------------------
// TRK command: Write to process memory. This function can handle data
// sizes up to MAX_FRAME_DATA. Returns number of written bytes or -1 if error.
ssize_t metrotrk_t::write_memory_chunk(int pid, int tid, int32 addr, const void *bytes, size_t size)
{
  init_packet(TrkWriteMemory);
  append_byte(0);       // options
  append_int16((uint16)size);
  append_int32(addr);
  append_int32(pid);
  append_int32(tid);
  const uchar *ptr = (const uchar *)bytes;
  for ( int i=0; i < size; i++ )
    append_byte(*ptr++);
  if ( !process_packet(2) )
    return -1;

  int i = 2;
  int length = extract_int16(i);
  if ( debug_debugger )
    msg("    Length    : %d\n", length);
  return length;
}

//-------------------------------------------------------------------------
// Write to process memory
// Returns number of written bytes or -1 if error.
ssize_t metrotrk_t::write_memory(int pid, int tid, int32 addr, const void *bytes, size_t size)
{
  size_t initial_size = size;
  const uchar *ptr = (const uchar *)bytes;
  while ( size != 0 )
  {
    size_t chunk = size > MAX_FRAME_DATA ? MAX_FRAME_DATA : size;
    ssize_t written = write_memory_chunk(pid, tid, addr, ptr, chunk);
    if ( written < 0 )
      return -1;
    size -= written;
    if ( written != chunk )
      break;
    ptr += written;
    addr += (int32)written;
  }
  return initial_size - size;
}

//-------------------------------------------------------------------------
// TRK command: Read from process memory. This function can handle data sizes
// up to MAX_FRAME_DATE. Returns number of read bytes or -1 if error.
ssize_t metrotrk_t::read_memory_chunk(int pid, int tid, int32 addr, void *bytes, size_t size)
{
  init_packet(TrkReadMemory);
  append_byte(0);       // options
  append_int16((uint16)size);
  append_int32(addr);
  append_int32(pid);
  append_int32(tid);
  if ( !process_packet(2, true) )
    return -1;

  int i = 2;
  int length = extract_int16(i);
  if ( debug_debugger )
    msg("    Length    : %d\n", length);
  QASSERT(30112, length <= ssize_t(size));
  if ( length > 0 )
    memcpy(bytes, &pkt[i], length);
  return length;
}

//-------------------------------------------------------------------------
// Read from process memory.
// Returns number of read bytes or -1 if error.
ssize_t metrotrk_t::read_memory(int pid, int tid, int32 addr, void *bytes, size_t size)
{
  size_t initial_size = size;
  uchar *ptr = (uchar *)bytes;
  while ( size != 0 )
  {
    size_t chunk = size > MAX_FRAME_DATA ? MAX_FRAME_DATA : size;
    ssize_t nread = read_memory_chunk(pid, tid, addr, ptr, chunk);
    if ( nread < 0 )
      return -1;
    size -= nread;
    if ( nread != chunk )
      break;
    ptr += nread;
    addr += (int32)nread;
  }
  return initial_size - size;
}

//-------------------------------------------------------------------------
// TRK command: Read process registers
bool metrotrk_t::read_regs(int pid, int tid, int regnum, int nregs, uint32 *values)
{
  init_packet(TrkReadRegisters);
  append_byte(0);       // options
  append_int16((uint16)regnum);
  append_int16(uint16(regnum+nregs-1));
  append_int32(pid);
  append_int32(tid);
  if ( !process_packet(4*nregs) )
    return false;

  int i = 2;
  for ( int k=0; k < nregs; k++ )
    values[k] = extract_int32(i);
  return true;
}

//-------------------------------------------------------------------------
// TRK command: Write process registers
bool metrotrk_t::write_regs(int pid, int tid, int regnum, int nregs, const uint32 *values)
{
  init_packet(TrkWriteRegisters);
  append_byte(0);       // options
  append_int16((uint16)regnum);
  append_int16(uint16(regnum+nregs-1));
  append_int32(pid);
  append_int32(tid);
  for ( int k=0; k < nregs; k++ )
    append_int32(values[k]);
  return process_packet(0);
}

//-------------------------------------------------------------------------
// TRK command: Send OK reply (usually as a response to a notification packet)
bool metrotrk_t::send_reply_ok(uchar seq)
{
  init_packet();
  append_byte(TrkReplyACK);
  append_byte(seq);
  append_byte(TrkReplyNoError);
  return send_packet();
}

//-------------------------------------------------------------------------
// TRK command: Recieve and handle a notification packet. Returns true if handled
int metrotrk_t::set_timeout(int timeout_ms)
{
  if ( timeout_ms == 0 ) // infinity is 5 seconds - to avoid ida hangings
    timeout_ms = 5*1000;
  int old = ct.ReadTotalTimeoutConstant;
  if ( ct.ReadTotalTimeoutConstant != timeout_ms )
  {
    ct.ReadTotalTimeoutConstant = timeout_ms;
    SetCommTimeouts(hp, &ct);
  }
  return old;
}

//-------------------------------------------------------------------------
// TRK command: Recieve and handle a notification packet. Returns true if handled
bool metrotrk_t::poll_for_event(int timeout)
{
  if ( timeout == 0 )
    timeout = 1; // otherwise ReadFile() hangs for long time??
  uchar seq;

  bool ok = recv_packet(&seq, timeout);
  if ( ok )
  {
    if ( !handle_notification(seq, ud) )
      INTERR(30113); // only notifications are allowed
  }
  return ok;
}

