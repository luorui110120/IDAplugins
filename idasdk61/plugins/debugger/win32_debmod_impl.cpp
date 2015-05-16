//
//
//      This file contains win32 specific implementations of win32_debugger_module class
//
//

#include "win32_rpc.h"
#include "win32_undoc.h"

struct impfunc_t
{
  const char *name;
  void *fptr;
};
#define IMPFUNC(x) { TEXT(#x), &x }

static HMODULE ntdll = NULL;
static NtSystemDebugControl_t  *NtSystemDebugControl;
static NtLoadDriver_t          *NtLoadDriver;
static NtUnloadDriver_t        *NtUnloadDriver;
static RtlAdjustPrivilege_t    *RtlAdjustPrivilege;
static NtCreateFile_t          *NtCreateFile;
static NtDeviceIoControlFile_t *NtDeviceIoControlFile;

static const impfunc_t ntfuncs[] =
{
  IMPFUNC(NtSystemDebugControl),
  IMPFUNC(NtLoadDriver),
  IMPFUNC(NtUnloadDriver),
  IMPFUNC(RtlAdjustPrivilege),
  IMPFUNC(NtCreateFile),
  IMPFUNC(NtDeviceIoControlFile),
};

// To read MSRs, we use a local kernel debugger driver provided by Microsoft.
static HANDLE DriverHandle = NULL;
static UNICODE_STRING DriverPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\kldbgdrv");
static UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"\\Device\\kldbgdrv");

//--------------------------------------------------------------------------
// PE COMMON HELPER FUNCTIONS
#define lread myread     // since we can't use loader_failure()
inline void myread(linput_t *li, void *buf, size_t size)
{
  eread(qlfile(li), buf, size);
}

#include "../../ldr/pe/common.cpp"

#ifdef UNICODE
#define GetMappedFileName_Name "GetMappedFileNameW"
#define GetModuleFileNameEx_Name "GetModuleFileNameExW"
#else
#define GetMappedFileName_Name "GetMappedFileNameA"
#define GetModuleFileNameEx_Name "GetModuleFileNameExA"
#endif

// function prototypes
typedef DWORD (WINAPI *GetMappedFileName_t)(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI *GetModuleFileNameEx_t)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

// functions pointers
static GetMappedFileName_t _GetMappedFileName = NULL;
static GetModuleFileNameEx_t _GetModuleFileNameEx = NULL;

// dynamic linking information for PSAPI functions
static HMODULE hPSAPI = NULL;

// dw32 support
static DWORD system_teb_size = MEMORY_PAGE_SIZE;

//--------------------------------------------------------------------------
LPVOID win32_debmod_t::correct_exe_image_base(LPVOID base)
{
  return base;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::s0tops(ea_t ea)
{
  return ea;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::pstos0(ea_t ea)
{
  return ea;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::prepare_to_stop_process(debug_event_t *, const threads_t &)
{
  return true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::disable_hwbpts()
{
  return true;
}


bool win32_debmod_t::enable_hwbpts()
{
  return true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::may_write(ea_t /*ea*/)
{
  return true;
}

//--------------------------------------------------------------------------
static ssize_t find_signature(const uchar *sign, size_t signlen, const uchar *buf, size_t bufsize)
{
  const uchar c = sign[0];
  const uchar *end = buf + bufsize - signlen;
  for ( const uchar *ptr=buf; ptr <= end; ptr++ )
  {
    if ( *ptr != c ) continue;
    if ( memcmp(sign, ptr, signlen) == 0 )
      return ptr-buf;
  }
  return -1;
}

//--------------------------------------------------------------------------
static ssize_t find_bcc_sign(const uchar *buf, size_t bufsize)
{
  static const uchar bcc_sign[] = "fb:C++HOOK";
  ssize_t bcc_hook_off = find_signature(bcc_sign, sizeof(bcc_sign)-1, buf, bufsize);
  if ( bcc_hook_off == -1 )
    return -1;
  bcc_hook_off += sizeof(bcc_sign) - 1 + 2;
  return bcc_hook_off;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::add_thread_areas(
  HANDLE process_handle,
  thid_t tid,
  images_t &thread_areas,
  images_t &class_areas)
{
  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL )
    return false;

  // This structure is specific to NT, but stack related records are Win9X compatible
  _NT_TIB tib;
  ea_t ea_tib = EA_T(ti->lpThreadLocalBase);
  if ( _read_memory(ea_tib, &tib, sizeof(tib)) != sizeof(tib) ) // read the TIB
    return false;

  // additional test: we verify that TIB->Self contains the TIB's linear address
  if ( EA_T(tib.Self) != ea_tib )
    return false;

  // add TIB area
  char name[MAXSTR];
  qsnprintf(name, sizeof(name), "TIB[%08X]", tid);
  // we suppose the whole page is reserved for the TIB
  image_info_t ii_tib(this, ea_tib, system_teb_size, name);
  thread_areas.insert(std::make_pair(ii_tib.base, ii_tib));
  // add stack area - we also verify it is valid by analyzing SP
  if ( EA_T(tib.StackLimit) > ti->ctx.Esp || ti->ctx.Esp >= EA_T(tib.StackBase) )
    return false;

  asize_t size = EA_T(tib.StackBase) - EA_T(tib.StackLimit);
  qsnprintf(name, sizeof(name), "Stack[%08X]", tid);
  image_info_t ii_stack(this, EA_T(tib.StackLimit), size, name);
  thread_areas.insert(std::make_pair(ii_stack.base, ii_stack));
  ii_stack.name = "STACK";
  class_areas.insert(std::make_pair(ii_stack.base, ii_stack));
  // verify a Stack PAGE_GUARD page exists
  ea_t ea_guard = ii_stack.base - MEMORY_PAGE_SIZE;
  MEMORY_BASIC_INFORMATION MemoryBasicInformation;
  if ( VirtualQueryEx(process_handle, (LPCVOID)ea_guard,
                &MemoryBasicInformation, sizeof(MemoryBasicInformation)) )
  {
    if ( MemoryBasicInformation.Protect & PAGE_GUARD ) // a Stack PAGE_GUARD exists
    {
      qsnprintf(name, sizeof(name), "Stack_PAGE_GUARD[%08X]", tid);
      image_info_t ii_guard(this, ea_guard, MEMORY_PAGE_SIZE, name);
      thread_areas.insert(std::make_pair(ii_guard.base, ii_guard));
      ii_guard.name = "STACK";
      class_areas.insert(std::make_pair(ii_guard.base, ii_guard));
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// Get PE header
// In: ea=DLL imagebase, nh=buffer to keep the answer
//     child==true:ea is an address in the child process
//     child==false:ea is an address in the the debugger itself
// Returns: offset to the headers, BADADDR means failure
ea_t win32_debmod_t::get_pe_header(ea_t ea, peheader_t *nh)
{
  uint32 offset = 0;
  uint32 magic;
  if ( _read_memory(ea, &magic, sizeof(magic)) != sizeof(magic) )
    return BADADDR;
  if ( ushort(magic) == MC2('M','Z') )
  {
    if ( _read_memory(ea+PE_PTROFF, &offset, sizeof(offset)) != sizeof(offset) )
      return BADADDR;
  }
  peheader64_t pe64;
  if ( _read_memory(ea+offset, &pe64, sizeof(pe64)) != sizeof(pe64) )
    return BADADDR;
  if ( !pe64_to_pe(*nh, pe64, true) )
    return BADADDR;
  if ( nh->signature != PEEXE_ID )
    return BADADDR;
#ifdef __X64__
  if ( addrsize == 8 && !pe64.is_pe_plus() )
    addrsize = 4;
#endif
  return offset;
}

//--------------------------------------------------------------------------
// calculate dll image size
// since we could not find anything nice, we just look
// at the beginning of the DLL module in the memory and extract
// correct value from the file header
uint32 win32_debmod_t::calc_imagesize(ea_t base)
{
  peheader_t nh;
  ea_t offset = get_pe_header(base, &nh);
  if ( offset == BADADDR )
    return 0;
  return nh.imagesize;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::create_process(const char *path,
                                             const char *args,
                                             const char *startdir,
                                             bool is_gui,
                                             PROCESS_INFORMATION *ProcessInformation)
{
#ifndef __X64__
  linput_t *li = open_linput(path, false);
  if ( li == NULL )
    return false;
  pe_loader_t pl;
  pl.read_header(li, true);
  close_linput(li);
  if ( pl.pe.is_pe_plus() )
  {
    static const char server_name[] = "win64_remotex64.exe";
#ifdef __EA64__
    if ( askyn_c(1, "AUTOHIDE REGISTRY\nHIDECANCEL\nDebugging 64-bit applications is only possible with the %s server. Launch it now?", server_name) == 1 ) do
    {
      // Switch to the remote win32 debugger
      if ( !load_debugger("win32_stub", true))
      {
        warning("Failed to switch to the remote windows debugger!");
        break;
      }

      // Form the server path
      char server_exe[QMAXPATH];
      qmakepath(server_exe, sizeof(server_exe), idadir(NULL), server_name, NULL);

      // Try to launch the server
      STARTUPINFO si = {sizeof(si)};
      PROCESS_INFORMATION pi;
      if ( !::CreateProcess(server_exe, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) )
      {
        warning("Failed to run the 64-bit remote server!");
        break;
      }

      // Set the remote debugging options: localhost
      set_remote_debugger("localhost", "", -1);

      // Notify the user
      info("Debugging server has been started, please try debugging the program again.");
    } while ( false );
#else
    dwarning("AUTOHIDE NONE\n"
      "Please use %s remote server to debug 64-bit applications", server_name);
#endif
    SetLastError(ERROR_NOT_SUPPORTED);
    return false;
  }
#endif
  STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };
  // empty directory means our directory
  if ( startdir != NULL && startdir[0] == '\0' )
    startdir = NULL;
  if ( args && args[0] == '\0' )
    args = NULL;

  return CreateProcess(
    path,                                // pointer to name of executable module
    (char *)args,                        // pointer to command line string
    NULL,                                // pointer to process security attributes
    NULL,                                // pointer to thread security attributes
    FALSE,                               // handle inheritance flag
    CREATE_DEFAULT_ERROR_MODE
    |(is_gui ? 0 : CREATE_NEW_CONSOLE)
    |DEBUG_ONLY_THIS_PROCESS
    |DEBUG_PROCESS
    |NORMAL_PRIORITY_CLASS,              // creation flags
    NULL,                                // pointer to new environment block
    startdir,                            // pointer to current directory name
    &StartupInfo,                        // pointer to STARTUPINFO
    ProcessInformation);                 // pointer to PROCESS_INFORMATION
}

//--------------------------------------------------------------------------
bool win32_debmod_t::set_debug_hook(ea_t base)
{
  // the debug hook for borland is located at the very beginning of
  // the program's text segment, with a clear signature before
  peheader_t pe;
  ea_t peoff = get_pe_header(base, &pe);
  if ( peoff == BADADDR )
    return false;

  ea_t text = base + pe.text_start;
  uchar buf[4096];
  if ( _read_memory(text, buf, sizeof(buf)) != sizeof(buf) )
    return false;

  ssize_t bcc_hook_off = find_bcc_sign(buf, sizeof(buf));
  if ( bcc_hook_off == -1 )
    return false;

  uint32 bcc_hook;
  if ( _read_memory(text+bcc_hook_off, &bcc_hook, 4) != 4 )
    return false;

  // now the bcc_hook might be already relocated or not.
  // it seems that vista loads files without relocating them for
  // the 'open file' dialog box. This is an heuristic rule:
  if ( bcc_hook < base + pe.text_start || bcc_hook > base + pe.imagesize )
    return false;

  const uint32 active_hook = 2; // borland seems to want this number
  return _write_memory(bcc_hook, &active_hook, 4) == 4;
}

//--------------------------------------------------------------------------
void term_win32_subsystem(void)
{
  if ( hPSAPI != NULL )
  {
    FreeLibrary(hPSAPI);
    hPSAPI = NULL;
  }
  if ( DriverHandle != NULL )
  {
    CloseHandle(DriverHandle);
    DriverHandle = NULL;
    NtUnloadDriver(&DriverPath);
  }
}

//--------------------------------------------------------------------------
void init_win32_subsystem(void)
{
  ntdll = GetModuleHandle(TEXT("ntdll.dll"));
  if ( ntdll != NULL )
  {
    for ( int i=0; i < qnumber(ntfuncs); i++ )
      *(FARPROC*)ntfuncs[i].fptr = GetProcAddress(ntdll, ntfuncs[i].name);
  }

  // load the library
  hPSAPI = LoadLibrary(TEXT("psapi.dll"));
  if ( hPSAPI != NULL )
  {
    // find the needed functions
    *(FARPROC*)&_GetMappedFileName = GetProcAddress(hPSAPI, TEXT(GetMappedFileName_Name));
    *(FARPROC*)&_GetModuleFileNameEx = GetProcAddress(hPSAPI, TEXT(GetModuleFileNameEx_Name));
    if ( _GetMappedFileName == NULL )
    {
      FreeLibrary(hPSAPI);
      hPSAPI = NULL;
    }
  }

#ifdef __BORLANDC__
  if( is_DW32() ) // dw32 specific
  {
    __emit__(0x8C, 0xE0);       // __asm  mov  eax, fs
    __emit__(0x0F, 0x03, 0xC0); // __asm  lsl  eax, eax
    __emit__(0x40);             // __asm  inc  eax
    system_teb_size = _EAX;
  }
#endif
}

//--------------------------------------------------------------------------
bool win32_debmod_t::can_access(ea_t addr)
{
  char dummy;
  return access_memory(addr, &dummy, 1, false, false) == 1;
}

//--------------------------------------------------------------------------
// get path+name from a mapped file in the debugged process
bool win32_debmod_t::get_mapped_filename(HANDLE process_handle,
                         ea_t imagebase,
                         char *buf,
                         size_t bufsize)
{
  if ( _GetMappedFileName != NULL )
  {
    TCHAR name[QMAXPATH];
    name[0] = '\0';
    if ( !can_access(imagebase) )
      imagebase += MEMORY_PAGE_SIZE;
    if ( _GetMappedFileName(process_handle, (LPVOID)imagebase, name, qnumber(name)) )
    {
      // translate path with device name to drive letters.
      //   based on http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/obtaining_a_file_name_from_a_file_handle.asp
      TCHAR szTemp[MAX_PATH];
      szTemp[0] = '\0';
      if ( GetLogicalDriveStrings(sizeof(szTemp), szTemp) )
      {
        char szName[MAX_PATH];
        char szDrive[3] = " :";
        bool bFound = FALSE;
        char *p = szTemp;
        do
        {
          // Copy the drive letter to the template string
          szDrive[0] = *p;
          // Look up each device name
          if ( QueryDosDevice(szDrive, szName, MAX_PATH) )
          {
            size_t uNameLen = strlen(szName);
            if ( uNameLen < MAX_PATH )
            {
              bFound = strnicmp(name, szName, uNameLen) == 0;
              if ( bFound )
              {
                // Reconstruct pszFilename using szTemp
                // Replace device path with DOS path
                qstrncpy(name, szDrive, sizeof(name));
                qstrncat(name, name+uNameLen, sizeof(name));
              }
            }
          }
          // Go to the next NULL character.
          while ( *p++ );
        } while ( !bFound && *p ); // end of string
      }
      wcstr(buf, name, bufsize);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// return the address of all names exported by a DLL in 'ni'
// if 'exported_name' is given, only the address of this exported name will be returned in 'ni'
static bool get_dll_exports_from_file(
    const char *dllname,
    linput_t *li,
    ea_t imagebase,
    name_info_t &ni,
    const char *exported_name = NULL)
{
  pe_loader_t pl;
  if ( !pl.read_header(li) )
    return false;

  struct export_reader_t : public pe_export_visitor_t
  {
    const char *dllname;
    ea_t imagebase;
    name_info_t &ni;
    const char *exported_name;
    export_reader_t(const char *dll, ea_t base, name_info_t &_ni, const char *exname)
      : dllname(dll), imagebase(base), ni(_ni), exported_name(exname) {}
    int idaapi visit_export(uint32 rva, uint32 ord, const char *name, const char *)
    {
      ea_t fulladdr = imagebase + rva;
      if ( exported_name != NULL )
      {
        if ( strcmp(exported_name, name) == 0 )
        {
          ni.addrs.push_back(fulladdr);
          return 1;
        }
      }
      else
      {
        qstring n2;
        if ( name[0] == '\0' )
          n2.sprnt("%s_%u", dllname, ord);
        else
          n2.sprnt("%s_%s", dllname, name);
        ni.addrs.push_back(fulladdr);
        ni.names.push_back(n2.extract());
      }
      return 0;
    }
  };
  export_reader_t er(dllname, imagebase, ni, exported_name);
  return pl.process_exports(li, er) >= 0;
}

//--------------------------------------------------------------------------
// return the address of all names exported by a DLL in 'ni'
// if 'exported_name' is given, only the address of this exported name will be returned in 'ni'
bool win32_debmod_t::get_dll_exports(
  const images_t &dlls,
  ea_t imagebase,
  name_info_t &ni,
  const char *exported_name)
{
  char prefix[MAXSTR];
  images_t::const_iterator p = dlls.find(imagebase);
  if ( p == dlls.end() )
  {
    dwarning("get_dll_exports: can't find dll name for imagebase %a", imagebase);
    return false;
  }
  const char *dllname = p->second.name.c_str();

  linput_t *li = open_linput(dllname, false);
  if ( li == NULL )
  {
    // sysWOW64: ntdll32.dll does not exist but there is a file called ntdll.dll
    if ( stricmp(qbasename(dllname), "ntdll32.dll") != 0 )
      return false;
    qstrncpy(prefix, dllname, sizeof(prefix));
    char *fname = qbasename(prefix);
    qstrncpy(fname, "ntdll.dll", sizeof(prefix)-(fname-prefix));
    dllname = prefix;
    li = open_linput(dllname, false);
    if ( li == NULL )
      return false;
  }

  // prepare nice name prefix for exported functions names
  qstrncpy(prefix, qbasename(dllname), sizeof(prefix));
  char *ptr = strrchr(prefix, '.');
  if ( ptr != NULL )
    *ptr = '\0';
  strlwr(prefix);

  bool ok = get_dll_exports_from_file(prefix, li, imagebase, ni, exported_name);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
// get name from export directory in PE image in debugged process
bool win32_debmod_t::get_pe_export_name_from_process(
  ea_t imagebase,
  char *name,
  size_t namesize)
{
  peheader_t pe;
  ea_t peoff = get_pe_header(imagebase, &pe);
  if ( peoff != BADADDR && pe.expdir.rva != 0)
  {
    ea_t ea = imagebase + pe.expdir.rva;
    peexpdir_t expdir;
    if ( _read_memory(ea, &expdir, sizeof(expdir)) == sizeof(expdir) )
    {
      ea = imagebase + expdir.dllname;
      name[0] = '\0';
      _read_memory(ea, name, namesize);  // don't check the return code because
      // we might have read more than necessary
      if ( name[0] != '\0' )
        return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// Read/write a model specific register using the driver provided by WinDbg.
// The following requirements are imposed by this code:
//      - debugger module should be run with admin privileges
//      - System must be loaded with /debug switch (use bcdedit.exe to turn it on)
//      - Windbg local kernel debugging should be used at least once
// This code is based on a sample kindly provided by Alex Ionescu.
int win32_debmod_t::kldbgdrv_access_msr(SYSDBG_MSR *msr, bool write)
{
  NTSTATUS code;
  IO_STATUS_BLOCK IoStatusBlock;
  if ( DriverHandle == NULL )
  {
    //
    // Acquire 'load driver' privilege
    //
    BOOLEAN Old;
    code = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &Old);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to acquire 'load driver' privilege, please run as admin!\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // And need this for the driver to accept our commands
    // Additionally, system must be booted in /DEBUG mode
    //
    code = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &Old);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to acquire 'debug' privilege, is system booted in /debug mode?\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // Now load the driver
    //
    code = NtLoadDriver(&DriverPath);
    if ( FAILED(code) && code != STATUS_IMAGE_ALREADY_LOADED )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to load 'kldbgdrv', please use local kernel debugging at least once!\n"
               "Error: %s\n", winerr(code));
      return code;
    }

    //
    // Open a handle to it
    //
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &DriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    code = NtCreateFile(&DriverHandle,
                        GENERIC_READ | GENERIC_WRITE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        0,
                        FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);
    if ( FAILED(code) )
    {
      dwarning("AUTOHIDE NONE\n"
               "Failed to open 'kldbgdrv'\n"
               "Error: %s\n", winerr(code));
      return code;
    }
  }

  //
  // Package the input parameters into the private structure
  //
  KLDD_DATA_DEBUG_CONTROL KldDebugCommand;
  KldDebugCommand.Command = write ? SysDbgWriteMsr : SysDbgReadMsr;
  KldDebugCommand.InputBuffer = msr;
  KldDebugCommand.InputBufferLength = sizeof(*msr);

  //
  // Send the request -- output isn't packaged, just specify directly the buffer
  //
  code = NtDeviceIoControlFile(DriverHandle,
                               NULL,
                               NULL,
                               NULL,
                               &IoStatusBlock,
                               KLDD_CODE_DEBUG_CONTROL,
                               &KldDebugCommand,
                               sizeof(KldDebugCommand),
                               msr,
                               sizeof(*msr));
  if ( FAILED(code) )
  {
    dwarning("AUTOHIDE NONE\n"
             "Failed to access model specific register, is system booted in /debug mode?\n"
             "Error: %s\n", winerr(code));
    return code;
  }

  // all ok!
  return code;
}

//--------------------------------------------------------------------------
int win32_debmod_t::rdmsr(int reg, uint64 *value)
{
  SYSDBG_MSR msr;
  msr.reg = reg;
  msr.value = 0; // shut up the compiler

  NTSTATUS code;
  if ( NtSystemDebugControl == NULL )
    code = STATUS_NOT_IMPLEMENTED;
  else
    code = NtSystemDebugControl(SysDbgReadMsr, &msr, sizeof(msr), &msr, sizeof(msr), 0);

  // if failed to read it with SystemDebugControl, try the driver
  if ( FAILED(code) )
    code = kldbgdrv_access_msr(&msr, false);

  if ( SUCCEEDED(code) )
    *value = msr.value;
  return code;
}

//--------------------------------------------------------------------------
int win32_debmod_t::wrmsr(int reg, uint64 value)
{
  SYSDBG_MSR msr;
  msr.reg = reg;
  msr.value = value;

  NTSTATUS code;
  if ( NtSystemDebugControl == NULL )
    code = STATUS_NOT_IMPLEMENTED;
  else
    code = NtSystemDebugControl(SysDbgWriteMsr, &msr, sizeof(msr), NULL, 0, 0);

  // if failed to write it with SystemDebugControl, try the driver
  if ( FAILED(code) )
    code = kldbgdrv_access_msr(&msr, true);

  return code;
}
