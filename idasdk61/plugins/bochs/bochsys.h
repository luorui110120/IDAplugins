/*
 *      Interactive disassembler (IDA).
 *      ALL RIGHTS RESERVED.
 *      Copyright (c) 1990-2008 Hex-Rays
 *
 *
 *      This file defines the functions prototypes that are exported by bochsys.dll
 *
 *
 */

#ifndef __BOCHSYS_DLL__
#define __BOCHSYS_DLL__

#include <windows.h>

//--------------------------------------------------------------------------
// These functions are similar to MS Windows functions. Please refer
// to the SDK documentation for more information on how to use them.
extern FARPROC WINAPI BxGetProcAddress(HMODULE hMod, LPCSTR ProcName);
extern HMODULE WINAPI BxGetModuleHandleA(LPCSTR ModuleFileName);
extern HMODULE WINAPI BxLoadLibraryA(LPCTSTR lpFileName);
extern LPVOID  WINAPI BxVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
extern BOOL    WINAPI BxVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
extern DWORD   WINAPI BxExitProcess(DWORD);
extern DWORD   WINAPI BxGetTickCount(VOID);
extern BOOL    WINAPI BxVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
extern DWORD   WINAPI BxWin32SetLastError(DWORD ErrorCode);
extern DWORD   WINAPI BxWin32GetLastError(VOID);
extern DWORD   WINAPI BxWin32GetCommandLineA(VOID);
extern DWORD   WINAPI BxWin32GetCommandLineW(VOID);
extern LPVOID  WINAPI BxWin32TlsGetValue(DWORD dwTlsIndex);
extern BOOL    WINAPI BxWin32TlsSetValue(DWORD dwTlsIndex,LPVOID lpTlsValue);
extern BOOL    WINAPI BxWin32TlsFree(DWORD dwTlsIndex);
extern DWORD   WINAPI BxWin32TlsAlloc(VOID);

//--------------------------------------------------------------------------
// Installs an exception handler. Only one exception handler
// can be installed at one time. You need to uninstall one
// before reinstalling another.
// These two functions will return non-zero on success.
typedef DWORD (*PEXCEPTION_HANDLER)(PEXCEPTION_RECORD, struct _EXCEPTION_REGISTRATION_RECORD *, PCONTEXT,struct _EXCEPTION_REGISTRATION_RECORD **);

extern DWORD   WINAPI BxInstallSEH(PEXCEPTION_HANDLER Handler);
extern DWORD   WINAPI BxUninstallSEH();

#endif