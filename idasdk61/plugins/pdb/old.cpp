
// Old interface to PDB files
// It is used as a fallback method if DIA interface fails

#include <windows.h>

#pragma pack(push, 8)
#include "cvconst.h"
#undef __specstrings // VS 2005 chokes in dbghelp.h otherwise
#include "dbghelp.h"
#pragma pack(pop)

#ifdef __BORLANDC__
#if __BORLANDC__ < 0x560
#include "bc5_add.h"
#endif
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <err.h>
#ifndef PDB2TIL
#include <auto.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#endif
#include "oldpdb.h"

typedef
BOOL IMAGEAPI SymEnumerateSymbols64_t(
    IN HANDLE                       hProcess,
    IN DWORD64                      BaseOfDll,
    IN PSYM_ENUMSYMBOLS_CALLBACK64  EnumSymbolsCallback64,
    IN PVOID                        UserContext
    );

//----------------------------------------------------------------------
typedef DWORD IMAGEAPI SymSetOptions_t(IN DWORD SymOptions);
typedef BOOL IMAGEAPI SymInitialize_t(IN HANDLE hProcess, IN LPCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64 IMAGEAPI SymLoadModule64_t(IN HANDLE hProcess, IN HANDLE hFile, IN PSTR ImageName, IN PSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL IMAGEAPI SymEnumSymbols_t(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN PCSTR Mask, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL IMAGEAPI SymUnloadModule64_t(IN HANDLE hProcess, IN DWORD64 BaseOfDll);
typedef BOOL IMAGEAPI SymCleanup_t(IN HANDLE hProcess);

static HINSTANCE dbghelp = NULL;
static SymSetOptions_t     *pSymSetOptions     = NULL;
static SymInitialize_t     *pSymInitialize     = NULL;
static SymLoadModule64_t   *pSymLoadModule64   = NULL;
static SymEnumSymbols_t    *pSymEnumSymbols    = NULL;
static SymUnloadModule64_t *pSymUnloadModule64 = NULL;
static SymCleanup_t        *pSymCleanup        = NULL;
static SymEnumerateSymbols64_t *pSymEnumerateSymbols64 = NULL;

//----------------------------------------------------------------------
// Dynamically load and link to DBGHELP or IMAGEHLP libraries
// Return: success
static bool setup_pointers(void)
{
  char dll[QMAXPATH];
  if ( !search_path("dbghelp.dll", dll, sizeof(dll), false) )
    return false;

  dbghelp = LoadLibrary(dll);
  if ( dbghelp == NULL )
  {
    deb(IDA_DEBUG_PLUGIN, "PDB plugin: failed to load DBGHELP.DLL");
  }
  else
  {
    *(FARPROC*)&pSymSetOptions     = GetProcAddress(dbghelp, "SymSetOptions");
    *(FARPROC*)&pSymInitialize     = GetProcAddress(dbghelp, "SymInitialize");
    *(FARPROC*)&pSymLoadModule64   = GetProcAddress(dbghelp, "SymLoadModule64");
    *(FARPROC*)&pSymEnumSymbols    = GetProcAddress(dbghelp, "SymEnumSymbols");
    *(FARPROC*)&pSymUnloadModule64 = GetProcAddress(dbghelp, "SymUnloadModule64");
    *(FARPROC*)&pSymCleanup        = GetProcAddress(dbghelp, "SymCleanup");
    *(FARPROC*)&pSymEnumerateSymbols64 = GetProcAddress(dbghelp, "SymEnumerateSymbols64");

    if ( pSymSetOptions     != NULL
      && pSymInitialize     != NULL
      && pSymLoadModule64   != NULL
      && pSymUnloadModule64 != NULL
      && pSymCleanup        != NULL
      && pSymEnumSymbols    != NULL  // required XP or higher
      && pSymEnumerateSymbols64 != NULL ) // will used it to load 64-bit programs
    {
      return true;
    }
  }
  deb(IDA_DEBUG_PLUGIN, "PDB plugin: Essential DBGHELP.DLL functions are missing\n");
  FreeLibrary(dbghelp);
  dbghelp = NULL;
  return false;
}

//----------------------------------------------------------------------
// New method: symbol enumeration callback
static BOOL CALLBACK EnumerateSymbolsProc(
        PSYMBOL_INFO psym,
        ULONG /*SymbolSize*/,
        PVOID delta)
{

  ea_t ea = (ea_t)(psym->Address + *(adiff_t*)delta);
  const char *name = psym->Name;

  int maybe_func = 0; // maybe
  switch ( psym->Tag )
  {
    case SymTagFunction:
    case SymTagThunk:
#ifndef PDBTOTIL
      auto_make_proc(ea); // certainly a func
#endif
      maybe_func = 1;
      break;
    case SymTagNull:
    case SymTagExe:
    case SymTagCompiland:
    case SymTagCompilandDetails:
    case SymTagCompilandEnv:
    case SymTagBlock:
    case SymTagData:
    case SymTagAnnotation:
    case SymTagLabel:
    case SymTagUDT:
    case SymTagEnum:
    case SymTagFunctionType:
    case SymTagPointerType:
    case SymTagArrayType:
    case SymTagBaseType:
    case SymTagTypedef:
    case SymTagBaseClass:
    case SymTagFunctionArgType:
    case SymTagFuncDebugStart:
    case SymTagFuncDebugEnd:
    case SymTagUsingNamespace:
    case SymTagVTableShape:
    case SymTagVTable:
    case SymTagCustom:
    case SymTagCustomType:
    case SymTagManagedType:
    case SymTagDimension:
      maybe_func = -1;
      break;
    case SymTagPublicSymbol:
    case SymTagFriend:
    default:
      break;
  }

  bool ok = apply_name(ea, name, maybe_func);
  // New dbghelp.dll/symsrv.dll files return names without the terminating zero.
  // So, as soon as we have a long name, shorter names will have garbage at the end.
  // Clean up the name to avoid problems.
  size_t len = strlen(name);
  memset((void*)name, '\0', len);
  return ok;
}

//----------------------------------------------------------------------
#if !defined(__X64__) && defined(__EA64__) // for load 64bit into 32-bit ida
// This method is used to load 64-bit applications into 32-bit IDA
static BOOL CALLBACK EnumSymbolsProc64( PCSTR   szName,
                                        DWORD64 ulAddr,
                                        ULONG   /*ulSize*/,
                                        PVOID   ud  )
{
  adiff_t delta = *(adiff_t *)ud;
  ea_t ea = ulAddr + delta;
  return apply_name(ea, szName, 0);
}
#endif

//----------------------------------------------------------------------
// Display a system error message
static void error_msg(char *name)
{
  msg("%s: %s\n", name, winerr(GetLastError()));
}

//----------------------------------------------------------------------
// Main function: do the real job here
bool old_pdb_plugin(ea_t loaded_base, const char *input, const char *spath)
{
  bool ok = false;
  adiff_t delta;
  void *fake_proc = (void *) 0xBEEFFEED;
  DWORD64 symbase;

  if ( !setup_pointers() )
    return false; // since we have unloaded the libraries, reinitialize them

  pSymSetOptions(SYMOPT_LOAD_LINES|SYMOPT_FAVOR_COMPRESSED|SYMOPT_NO_PROMPTS);

  if ( !pSymInitialize(fake_proc, spath, FALSE) )
  {
    error_msg("SymInitialize");
    return false;
  }

  symbase = pSymLoadModule64(fake_proc, 0, (char*)input, NULL, loaded_base, 0);
  if ( symbase == 0 )
    goto cleanup;

  load_vc_til();

  delta = adiff_t(loaded_base - symbase);
#if !defined(__X64__) && defined(__EA64__) // trying to load 64bit into 32-bit ida
  if ( inf.is_64bit() && pSymEnumerateSymbols64 != NULL )
    ok = pSymEnumerateSymbols64(fake_proc, symbase, EnumSymbolsProc64, &delta);
  else
#endif
    ok = pSymEnumSymbols(fake_proc, (DWORD) symbase, "", EnumerateSymbolsProc, &delta);
  if ( !ok )
  {
    error_msg("EnumSymbols");
    goto unload;
  }

unload:
  if ( !pSymUnloadModule64(fake_proc, symbase) )
    error_msg("SymUnloadModule64:");

cleanup:
  if ( !pSymCleanup(fake_proc) )
    error_msg("SymCleanup");

  if ( dbghelp != NULL )
  {
    FreeLibrary(dbghelp);
    dbghelp = NULL;
  }
  return ok;
}
