//
// This file contains utility functions that can be used with different
// win32 debugger plugins
//

#if defined(__BORLANDC__) && __BORLANDC__ < 0x560
#define _IMAGEHLP_SOURCE_
#include "dbghelp.h"
#elif !defined(UNDER_CE)
#include <dbghelp.h>
#endif

#ifdef UNICODE
#define LookupPrivilegeValue_Name "LookupPrivilegeValueW"
#else
#define LookupPrivilegeValue_Name "LookupPrivilegeValueA"
#endif


//--------------------------------------------------------------------------
//
//      DEBUGGER INTERNAL DATA
//
//--------------------------------------------------------------------------
// dynamic linking information for ToolHelp functions and new XP/2K3 debug functions
static HMODULE th_handle;

// function prototypes
typedef HANDLE (WINAPI *CreateToolhelp32Snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL   (WINAPI *Process32First_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL   (WINAPI *Process32Next_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL   (WINAPI *Module32First_t)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL   (WINAPI *Module32Next_t)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL   (WINAPI *DebugActiveProcessStop_t)(DWORD dwProcessID);
typedef BOOL   (WINAPI *DebugBreakProcess_t)(HANDLE Process);
typedef BOOL   (WINAPI  *CloseToolhelp32Snapshot_t)(HANDLE hSnapshot);

// functions pointers
static CreateToolhelp32Snapshot_t _CreateToolhelp32Snapshot = NULL;
static Process32First_t           _Process32First           = NULL;
static Process32Next_t            _Process32Next            = NULL;
static Module32First_t            _Module32First            = NULL;
static Module32Next_t             _Module32Next             = NULL;
static CloseToolhelp32Snapshot_t  _CloseToolhelp32Snapshot  = NULL;
static DebugActiveProcessStop_t   _DebugActiveProcessStop   = NULL;
static DebugBreakProcess_t        _DebugBreakProcess        = NULL;
static bool use_DebugBreakProcess = true;

//--------------------------------------------------------------------------
//
//      TOOLHELP FUNCTIONS
//
//--------------------------------------------------------------------------
#ifndef __WINDBG_DEBUGGER_MODULE__ // windbg doesn't use toolhelp
static void term_toolhelp(void)
{
  if ( th_handle != NULL )
  {
    FreeLibrary(th_handle);
    th_handle = NULL;
  }
}

#ifdef UNDER_CE
#  define KERNEL_LIB_NAME   "coredll.dll"
#  define TOOLHELP_LIB_NAME "toolhelp.dll"
#else
#  define KERNEL_LIB_NAME   "kernel32.dll"
#  define TOOLHELP_LIB_NAME "kernel32.dll"
#endif

static const TCHAR *kernel_lib_name = TEXT(KERNEL_LIB_NAME);
static const TCHAR *toolhelp_lib_name = TEXT(TOOLHELP_LIB_NAME);

//--------------------------------------------------------------------------
static bool init_toolhelp(void)
{
  // load the library
  th_handle = LoadLibrary(toolhelp_lib_name);
  if ( th_handle == NULL ) return false;

  // find the needed functions
  *(FARPROC*)&_CreateToolhelp32Snapshot = GetProcAddress(th_handle, TEXT("CreateToolhelp32Snapshot"));
  *(FARPROC*)&_Process32First           = GetProcAddress(th_handle, TEXT("Process32First"));
  *(FARPROC*)&_Process32Next            = GetProcAddress(th_handle, TEXT("Process32Next"));
  *(FARPROC*)&_Module32First            = GetProcAddress(th_handle, TEXT("Module32First"));
  *(FARPROC*)&_Module32Next             = GetProcAddress(th_handle, TEXT("Module32Next"));
#ifdef UNDER_CE
  *(FARPROC*)&_CloseToolhelp32Snapshot  = GetProcAddress(th_handle, TEXT("CloseToolhelp32Snapshot"));
#endif

  bool ok = _CreateToolhelp32Snapshot != NULL
    && _Process32First != NULL
    && _Process32Next != NULL
#ifdef UNDER_CE
    && _CloseToolhelp32Snapshot  != NULL
#endif
    && _Module32First != NULL
    && _Module32Next != NULL;
  if ( !ok )
    term_toolhelp();

  *(FARPROC*)&_DebugActiveProcessStop = GetProcAddress(th_handle, TEXT("DebugActiveProcessStop"));
  *(FARPROC*)&_DebugBreakProcess      = GetProcAddress(th_handle, TEXT("DebugBreakProcess"));
  use_DebugBreakProcess = getenv("IDA_NO_DEBUGBREAKPROCESS") == NULL;
  return ok;
}
#endif

//--------------------------------------------------------------------------
// convert Windows protection modes to IDA protection modes
uchar win_prot_to_ida_perm(DWORD protection)
{
  uchar perm = 0;

  if ( protection & PAGE_READONLY )          perm |= SEGPERM_READ;
  if ( protection & PAGE_READWRITE )         perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_WRITECOPY )         perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_EXECUTE )           perm |=                                SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READ )      perm |= SEGPERM_READ                 | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READWRITE ) perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_WRITECOPY ) perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;

  return perm;
}

//--------------------------------------------------------------------------
//
//      WINDOWS VERSION
//
//--------------------------------------------------------------------------
static OSVERSIONINFO OSVersionInfo;

//--------------------------------------------------------------------------
#ifndef __WINDBG_DEBUGGER_MODULE__
static bool get_windows_version(void)
{
  OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVersionInfo);
  return GetVersionEx(&OSVersionInfo) != NULL;
}
#endif

//--------------------------------------------------------------------------
bool is_NT(void)
{
  return OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT;
}

//--------------------------------------------------------------------------
// Is strictly XP?
bool is_strictly_xp(void)
{
  return is_NT() && OSVersionInfo.dwMajorVersion == 5 && OSVersionInfo.dwMinorVersion == 1;
}

//--------------------------------------------------------------------------
bool is_DW32(void)
{
  return OSVersionInfo.dwPlatformId == 3;
}

//--------------------------------------------------------------------------
// Is at least Win2K?
bool is_2K(void)
{
  return OSVersionInfo.dwMajorVersion >= 5;
}

//--------------------------------------------------------------------------
//
//      DEBUG PRIVILEGE
//
//--------------------------------------------------------------------------
// dynamic linking information for Advapi functions
static HMODULE hAdvapi32;
// function prototypes
typedef BOOL (WINAPI *OpenProcessToken_t)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL (WINAPI *LookupPrivilegeValue_t)(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid);
typedef BOOL (WINAPI *AdjustTokenPrivileges_t)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
// functions pointers
OpenProcessToken_t      _OpenProcessToken      = NULL;
LookupPrivilegeValue_t  _LookupPrivilegeValue  = NULL;
AdjustTokenPrivileges_t _AdjustTokenPrivileges = NULL;

//--------------------------------------------------------------------------
static void term_advapi32(void)
{
  if ( hAdvapi32 != NULL )
  {
    FreeLibrary(hAdvapi32);
    hAdvapi32 = NULL;
  }
}

//--------------------------------------------------------------------------
static bool init_advapi32(void)
{
  // load the library
  hAdvapi32 = LoadLibrary(TEXT("advapi32.dll"));
  if ( hAdvapi32 == NULL )
    return false;

  // find the needed functions
  *(FARPROC*)&_OpenProcessToken       = GetProcAddress(hAdvapi32, TEXT("OpenProcessToken"));
  *(FARPROC*)&_LookupPrivilegeValue   = GetProcAddress(hAdvapi32, TEXT(LookupPrivilegeValue_Name));
  *(FARPROC*)&_AdjustTokenPrivileges  = GetProcAddress(hAdvapi32, TEXT("AdjustTokenPrivileges"));

  bool ok = _OpenProcessToken      != NULL
         && _LookupPrivilegeValue  != NULL
         && _AdjustTokenPrivileges != NULL;
  if ( !ok )
  {
    int code = GetLastError();
    term_advapi32();
    SetLastError(code);
  }
  return ok;
}


//--------------------------------------------------------------------------
// based on code from:
// http://support.microsoft.com/support/kb/articles/Q131/0/65.asp
bool enable_privilege(LPCTSTR privilege, bool enable)
{
  if ( !is_NT() ) // no privileges on 9X/ME
    return true;

  if ( !init_advapi32() )
    return false;

  HANDLE hToken;
  bool ok = false;
  int code = ERROR_SUCCESS;
  if ( _OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
  {
    LUID luid;
    if ( _LookupPrivilegeValue(NULL, privilege, &luid) )
    {
      TOKEN_PRIVILEGES tp;
      memset(&tp, 0, sizeof(tp));
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
      _AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
      code = GetLastError();
      ok = (code == ERROR_SUCCESS);
    }
    CloseHandle(hToken);
  }
  term_advapi32();
  if ( !ok )
    SetLastError(code);
  return ok;
}
