#include "common.h"

const char *print_pdb_register(int machine, int reg);

//----------------------------------------------------------------------
// Common code for PDB handling
//----------------------------------------------------------------------
class CCallback : public IDiaLoadCallback2,
                  public IDiaReadExeAtRVACallback,
                  public IDiaReadExeAtOffsetCallback
{
  int m_nRefCount;
  ea_t m_load_address;
  HANDLE hFile;
  input_exe_reader_t exe_reader;
  input_mem_reader_t mem_reader;
public:
  CCallback(input_exe_reader_t _exe_reader, input_mem_reader_t _mem_reader):
      exe_reader(_exe_reader), mem_reader(_mem_reader),
      m_load_address(BADADDR), m_nRefCount(0), hFile(INVALID_HANDLE_VALUE) { }
  virtual ~CCallback()
  {
    if (hFile != INVALID_HANDLE_VALUE)
      CloseHandle(hFile);
  }

  void SetLoadAddress(ea_t load_address)
  {
    m_load_address = load_address;
  }

  void OpenExe(LPCWSTR FileName)
  {
#ifdef REMOTEPDB
    if ( exe_reader != NULL )
      return;
#endif
    hFile = CreateFileW(
      FileName,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);
  }

  // IUnknown
  ULONG STDMETHODCALLTYPE AddRef()
  {
    return ++m_nRefCount;
  }

  ULONG STDMETHODCALLTYPE Release()
  {
    if ( --m_nRefCount == 0 )
    {
      delete this;
      return 0;
    }
    return m_nRefCount;
  }

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID rid, void **ppUnk)
  {
    if ( ppUnk == NULL )
      return E_INVALIDARG;
    if ( rid == __uuidof(IDiaLoadCallback2) || rid == __uuidof(IDiaLoadCallback) )
        *ppUnk = (IDiaLoadCallback2 *)this;
#ifndef BUILDING_EFD
    else if ( rid == __uuidof( IDiaReadExeAtRVACallback ) && m_load_address != BADADDR )
        *ppUnk = (IDiaReadExeAtRVACallback *)this;
#endif
    else if ( rid == __uuidof(IDiaReadExeAtOffsetCallback) )
      *ppUnk = (IDiaReadExeAtOffsetCallback *)this;
    else if ( rid == __uuidof(IUnknown) )
        *ppUnk = (IUnknown *)(IDiaLoadCallback *)this;
    else
        *ppUnk = NULL;
    if ( *ppUnk == NULL )
      return E_NOINTERFACE;
    AddRef();
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyDebugDir(
              BOOL /* fExecutable */,
              DWORD /* cbData */,
              BYTE /* data */ [])
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE NotifyOpenDBG(
              LPCOLESTR /* dbgPath */,
              HRESULT /* resultCode */)
  {
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyOpenPDB(
              LPCOLESTR /* pdbPath */,
              HRESULT /* resultCode */)
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictRegistryAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictOriginalPathAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictReferencePathAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictDBGAccess()
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSystemRootAccess()
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE ReadExecutableAtRVA(
   DWORD  relativeVirtualAddress,
   DWORD  cbData,
   DWORD* pcbData,
   BYTE   data[] )
  {
#ifndef BUILDING_EFD
#ifdef REMOTEPDB
    if ( mem_reader != NULL )
    {
      uint32 read;
      bool ok = mem_reader(m_load_address + relativeVirtualAddress, cbData, data, &read);
      if ( !ok )
        return E_FAIL;
      *pcbData = read;
      return S_OK;
    }
#endif
    if ( get_many_bytes(m_load_address + relativeVirtualAddress, data, cbData) )
    {
      *pcbData = cbData;
      return S_OK;
    }
#else
    qnotused(relativeVirtualAddress);
    qnotused(cbData);
    qnotused(pcbData);
    qnotused(data);
#endif
    return S_FALSE;
  }

  // IDiaReadExeAtOffsetCallback
  HRESULT STDMETHODCALLTYPE ReadExecutableAt(
    DWORDLONG fileOffset,
    DWORD cbData,
    DWORD *pcbData,
    BYTE *pbData)
  {
#ifdef REMOTEPDB
    if ( exe_reader != NULL )
    {
      uint32 read;
      bool ok = exe_reader(fileOffset, cbData, pbData, &read);
      if ( !ok )
        return E_FAIL;
      *pcbData = read;
      return S_OK;
    }
#endif
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)fileOffset;
    return hFile == INVALID_HANDLE_VALUE ||
        !SetFilePointerEx(hFile, pos, NULL, FILE_BEGIN) ||
        !ReadFile(hFile, pbData, cbData, pcbData, NULL) ? E_FAIL : S_OK;
  }
};

//---------------------------------------------------------------------------
template<class T> void print_generic(T t)
{
  IDiaPropertyStorage *pPropertyStorage;
  HRESULT hr = t->QueryInterface(__uuidof(IDiaPropertyStorage), (void **)&pPropertyStorage);
  if ( hr == S_OK )
  {
    print_property_storage(pPropertyStorage);
    pPropertyStorage->Release();
  }
}

static const char *g_pdb_errors[] =
{
  "Operation successful (E_PDB_OK)",
  "(E_PDB_USAGE)",
  "Out of memory (E_PDB_OUT_OF_MEMORY)",
  "(E_PDB_FILE_SYSTEM)",
  "Failed to open the file, or the file has an invalid format (E_PDB_NOT_FOUND)",
  "Signature does not match (E_PDB_INVALID_SIG)",
  "Age does not match (E_PDB_INVALID_AGE)",
  "(E_PDB_PRECOMP_REQUIRED)",
  "(E_PDB_OUT_OF_TI)",
  "(E_PDB_NOT_IMPLEMENTED)",
  "(E_PDB_V1_PDB)",
  "Attempted to access a file with an obsolete format (E_PDB_FORMAT)",
  "(E_PDB_LIMIT)",
  "(E_PDB_CORRUPT)",
  "(E_PDB_TI16)",
  "(E_PDB_ACCESS_DENIED)",
  "(E_PDB_ILLEGAL_TYPE_EDIT)",
  "(E_PDB_INVALID_EXECUTABLE)",
  "(E_PDB_DBG_NOT_FOUND)",
  "(E_PDB_NO_DEBUG_INFO)",
  "(E_PDB_INVALID_EXE_TIMESTAMP)",
  "(E_PDB_RESERVED)",
  "(E_PDB_DEBUG_INFO_NOT_IN_PDB)",
  "(E_PDB_SYMSRV_BAD_CACHE_PATH)",
  "(E_PDB_SYMSRV_CACHE_FULL)",
};

//---------------------------------------------------------------------------
static const char *pdberr(int code)
{
  switch ( code )
  {                         // tab in first pos is flag for replace warning to msg
    case E_INVALIDARG:      return "Invalid parameter.";
    case E_UNEXPECTED:      return "Data source has already been prepared.";
    default:
      if ( code >= E_PDB_OK && (code - E_PDB_OK) < qnumber(g_pdb_errors) )
        return g_pdb_errors[code - E_PDB_OK];
  }
  return winerr(code);
}

//----------------------------------------------------------------------
size_t get_symbol_length(IDiaSymbol *sym)
{
  DWORD64 size = 0;
  DWORD tag = 0;
  sym->get_symTag(&tag);
  if ( tag == SymTagData )
  {
    IDiaSymbol *pType;
    if ( sym->get_type(&pType) == S_OK )
    {
      pType->get_length(&size);
      pType->Release();
    }
  }
  else
  {
    sym->get_length(&size);
  }
  return size_t(size);
}

//----------------------------------------------------------------------
// Helper vistor class used when enumerating a symbol's children
struct children_visitor_t
{
  virtual HRESULT visit_child(IDiaSymbol *child) = 0;
  virtual ~children_visitor_t() {}
};

//----------------------------------------------------------------------
static HRESULT for_all_children(
  IDiaSymbol *sym,
  enum SymTagEnum type,
  children_visitor_t &cv)
{
  IDiaEnumSymbols *pEnumSymbols;
  HRESULT hr = sym->findChildren(type, NULL, nsNone, &pEnumSymbols);
  if ( SUCCEEDED(hr) )
  {
    while ( true )
    {
      ULONG celt = 0;
      IDiaSymbol *pChild;
      hr = pEnumSymbols->Next(1, &pChild, &celt);
      if ( FAILED(hr) || celt != 1 )
      {
        hr = S_OK; // end of enumeration
        break;
      }
      hr = cv.visit_child(pChild);
      pChild->Release();
      if ( FAILED(hr) )
        break;
    }
    pEnumSymbols->Release();
  }
  return hr;
}

#ifdef BUILDING_EFD
#ifndef PDBTOTIL
//----------------------------------------------------------------------
struct file_visitor_t
{
  virtual HRESULT visit_compiland(IDiaSymbol *sym) = 0;
  virtual HRESULT visit_file(IDiaSourceFile *file) = 0;
};

static HRESULT for_all_files(
  IDiaSession *pSession,
  IDiaSymbol *pGlobal,
  file_visitor_t &fv)
{
  // In order to find the source files, we have to look at the image's compilands/modules
  struct file_helper_t : children_visitor_t
  {
    IDiaSession *pSession;
    file_visitor_t &fv;
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      HRESULT hr = fv.visit_compiland(sym);
      if ( SUCCEEDED(hr) )
      {
        IDiaEnumSourceFiles *pEnumSourceFiles;
        if ( SUCCEEDED(pSession->findFile(sym, NULL, nsNone, &pEnumSourceFiles)) )
        {
          DWORD celt;
          IDiaSourceFile *pSourceFile;
          while ( SUCCEEDED(pEnumSourceFiles->Next(1, &pSourceFile, &celt))
               && (celt == 1) )
          {
            hr = fv.visit_file(pSourceFile);
            pSourceFile->Release();
          }
          pEnumSourceFiles->Release();
        }
      }
      return hr;
    }
    file_helper_t(IDiaSession *s, file_visitor_t &v) : pSession(s), fv(v) {}
  };
  file_helper_t fh(pSession, fv);
  return for_all_children(pGlobal, SymTagCompiland, fh);
}
#endif
#endif

//----------------------------------------------------------------------
static HRESULT for_all_subtags(
  IDiaSymbol *pGlobal,
  enum SymTagEnum type,
  children_visitor_t &fv)
{
  struct subtag_helper_t : children_visitor_t
  {
    enum SymTagEnum type;
    children_visitor_t &fv;
    virtual HRESULT visit_child(IDiaSymbol *sym)
    {
      return for_all_children(sym, type, fv);
    }
    subtag_helper_t(enum SymTagEnum t, children_visitor_t &v) : type(t), fv(v) {}
  };
  subtag_helper_t fh(type, fv);
  return for_all_children(pGlobal, SymTagCompiland, fh);
}

//----------------------------------------------------------------------
inline HRESULT for_all_funcs(IDiaSymbol *pGlobal, children_visitor_t &fv)
{
  return for_all_subtags(pGlobal, SymTagFunction, fv);
}

//----------------------------------------------------------------------
static const char *print_symtag(uint32 tag)
{
  static const char *const names[] =
  {
    "Null",
    "Exe",
    "Compiland",
    "CompilandDetails",
    "CompilandEnv",
    "Function",
    "Block",
    "Data",
    "Annotation",
    "Label",
    "PublicSymbol",
    "UDT",
    "Enum",
    "FunctionType",
    "PointerType",
    "ArrayType",
    "BaseType",
    "Typedef",
    "BaseClass",
    "Friend",
    "FunctionArgType",
    "FuncDebugStart",
    "FuncDebugEnd",
    "UsingNamespace",
    "VTableShape",
    "VTable",
    "Custom",
    "Thunk",
    "CustomType",
    "ManagedType",
    "Dimension"
  };
  return tag < qnumber(names) ? names[tag] : "???";
}

#include "../../ldr/windmp/common.h" // for get_special_folder

//----------------------------------------------------------------------
class DECLSPEC_UUID("4C41678E-887B-4365-A09E-925D28DB33C2") DiaSource90;
class DECLSPEC_UUID("1fbd5ec4-b8e4-4d94-9efe-7ccaf9132c98") DiaSource80;
class DECLSPEC_UUID("31495af6-0897-4f1e-8dac-1447f10174a1") DiaSource71;
static const GUID *const g_d90 = &__uuidof(DiaSource90);  // msdia90.dll
static const GUID *const g_d80 = &__uuidof(DiaSource80);  // msdia80.dll
static const GUID *const g_d71 = &__uuidof(DiaSource71);  // msdia71.dll
static const GUID *const g_msdiav[] = { g_d90, g_d80, g_d71 };
static const int         g_diaver[] = { 900,   800,   710 };
static const char *g_diadlls[] = { "msdia90.dll", "msdia80.dll", "msdia71.dll"};

//----------------------------------------------------------------------
HRESULT __stdcall CoCreateInstanceNoReg(
  LPCTSTR szDllName,
  IN REFCLSID rclsid,
  IUnknown* pUnkOuter,
  IN REFIID riid,
  OUT LPVOID FAR* ppv,
  OUT HMODULE *phMod)
{
  // http://lallousx86.wordpress.com/2007/01/29/emulating-cocreateinstance/
  HRESULT hr = REGDB_E_CLASSNOTREG;
  HMODULE hDll;
  do
  {
    hDll = LoadLibrary(szDllName);
    if ( hDll == NULL )
      break;

    HRESULT (__stdcall *GetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID FAR* ppv);
    *(FARPROC*)&GetClassObject = GetProcAddress(hDll, "DllGetClassObject");
    if ( GetClassObject == NULL )
      break;

    IClassFactory *pIFactory;
    hr = GetClassObject(rclsid, IID_IClassFactory, (LPVOID *)&pIFactory);
    if ( FAILED(hr) )
      break;

    hr = pIFactory->CreateInstance(pUnkOuter, riid, ppv);
    pIFactory->Release();
  } while (false);

  if ( FAILED(hr) && hDll != NULL )
    FreeLibrary(hDll);
  else
    *phMod = hDll;

  return hr;
}

  //----------------------------------------------------------------------
static void get_input_and_sym_path(
        const char *input_file,
        const char *user_spath,
        qwstring &winput,
        qwstring &wspath)
{
  char env_sympath[4096];
  char temp_path[QMAXPATH];
  char spath[sizeof(spath_prefix)+sizeof(temp_path)+sizeof(spath_suffix)];
  // no symbol path passed? let us compute default values
  if ( user_spath == NULL || user_spath[0] == '\0' )
  {
    // no env var?
    if ( GetEnvironmentVariable("_NT_SYMBOL_PATH", env_sympath, sizeof(env_sympath)) == 0
      || GetLastError() == ERROR_ENVVAR_NOT_FOUND )
    {
      if ( !GetTempPath(sizeof(temp_path), temp_path) )
        temp_path[0] = '\0';
      else
        qstrncat(temp_path, "ida", sizeof(temp_path));
      qsnprintf(spath, sizeof(spath), "%s%s%s", spath_prefix, temp_path, spath_suffix);
      user_spath = spath;
    }
    else
    {
      user_spath = env_sympath;
    }
  }
  c2ustr(user_spath, &wspath);
  c2ustr(input_file, &winput);
}

//----------------------------------------------------------------------
struct pdb_session_t
{
  HMODULE dia_hmod;
  int refcount;
  int dia_ver;
  IDiaDataSource *pSource;
  IDiaSession *pSession;
  IDiaSymbol *pGlobal;

  pdb_session_t(): dia_ver(0), refcount(1), dia_hmod(NULL),
    pSource(NULL), pGlobal(NULL), pSession(NULL)
  {
  }

  void close()
  {
    if ( pGlobal != NULL )
    {
      pGlobal->Release();
      pGlobal = NULL;
    }

    if ( pSession != NULL )
    {
      pSession->Release();
      pSession = NULL;
    }

    if ( pSource != NULL )
    {
      pSource->Release();
      pSource = NULL;
    }

    if ( dia_hmod != NULL )
    {
      FreeLibrary(dia_hmod);
      dia_hmod = NULL;
    }
  }

  HRESULT open(
    const char *input_file,
    const char *user_spath = NULL,
    ea_t load_address = BADADDR,
    input_exe_reader_t exe_reader = NULL,
    input_mem_reader_t mem_reader = NULL)
  {
    // Already open?
    if ( pSession != NULL )
      return S_OK;

    HRESULT hr;
    do
    {
      // No interface was created?
      hr = create_dia_source();
      if ( FAILED(hr) )
        break;

      qwstring wpath, winput;
      get_input_and_sym_path(input_file, user_spath, winput, wpath);

      if ( exe_reader == NULL && mem_reader == NULL )
        // Try to load input file as PDB
        hr = pSource->loadDataFromPdb(winput.c_str());
      else
        hr = E_FAIL;

      // Failed? Try to load as EXE
      if ( FAILED(hr) )
      {
        CCallback callback(exe_reader, mem_reader);
        callback.AddRef();

        // Open the executable
        callback.OpenExe(winput.c_str());

        // When the debugger is active, first try to load debug directory from the memory
        ea_t load_address_order[2];
#ifndef BUILDING_EFD
        if ( get_process_state() != DSTATE_NOTASK )
        {
          load_address_order[0] = load_address;
          load_address_order[1] = BADADDR;
        }
        else
#endif
        {
          load_address_order[0] = BADADDR;
          load_address_order[1] = load_address;
        }

        for ( int i=0; i < qnumber(load_address_order); i++ )
        {
          callback.SetLoadAddress(load_address_order[i]);
          hr = pSource->loadDataForExe(winput.c_str(), wpath.c_str(), (IDiaLoadCallback *)&callback);
          if ( SUCCEEDED(hr) )
            break;
        }
      }

      // Failed? Then nothing else to try, quit
      if ( FAILED(hr) )
        break;

      // Open a session for querying symbols
      hr = pSource->openSession(&pSession);
      if ( FAILED(hr) )
        break;

      // Set load address
      if ( load_address != BADADDR )
        pSession->put_loadAddress(load_address);

      // Retrieve a reference to the global scope
      hr = pSession->get_globalScope(&pGlobal);
      if ( FAILED(hr) )
        break;

      hr = S_OK;
    } while ( false );

    // Make sure we cleanup
    if ( FAILED(hr) )
      close();

    return hr;
  }

  //----------------------------------------------------------------------
  HRESULT create_dia_source()
  {
    HRESULT hr;
    // VC80/90 CRT installs msdiaNN.dll in this folder:
    // "C:\Program Files (x86)\Common Files\microsoft shared\VC"
    char common_files[QMAXPATH];
    qstring vc_shared;
    if ( get_special_folder(CSIDL_PROGRAM_FILES_COMMON, common_files, sizeof(common_files)) )
    {
      vc_shared = common_files;
      vc_shared.append("\\Microsoft Shared\\VC");
    }

    for ( size_t i=0; i < qnumber(g_msdiav); i++ )
    {
      // Try to create using CoCreateInstance()
      hr = CoCreateInstance(*g_msdiav[i],
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(IDiaDataSource),
        (void**)&pSource);

      // Try to create with CoCreateInstanceNoReg()
      if ( FAILED(hr) )
      {
        // Search for this interface in DIA dlls
        char path[QMAXPATH];
        if ( !search_path(g_diadlls[i], path, sizeof(path), false)
          && (vc_shared.empty() || SearchPathA(vc_shared.c_str(), g_diadlls[i], NULL, qnumber(path), path, NULL) == 0) )
          continue;

        for ( size_t j=0; j < qnumber(g_msdiav); j++ )
        {
          hr = CoCreateInstanceNoReg(
            path,
            *g_msdiav[j],
            NULL,
            __uuidof(IDiaDataSource),
            (void**)&pSource,
            &dia_hmod);

          if ( SUCCEEDED(hr) )
          {
            static bool displayed = false;
            if ( !displayed )
            {
              displayed = true;
              msg("PDB: using DIA dll \"%s\"\n", path);
            }
            i = j;
            break;
          }
        }
      }

      if ( SUCCEEDED(hr) )
      {
        dia_ver = g_diaver[i];
        static bool displayed = false;
        if ( !displayed )
        {
          displayed = true;
          msg("PDB: DIA interface version %d.%d\n", dia_ver/100, dia_ver%100);
        }
        return hr;
      }
    }
    return E_NOINTERFACE;
  }
};

//----------------------------------------------------------------------
class pdb_handler_t
{
  static bool co_initialized;
  static int instance_count;
public:
  pdb_session_t *session;

  //----------------------------------------------------------------------
  pdb_handler_t(void)
  {
    session = new pdb_session_t();
    instance_count++;
  }

  //----------------------------------------------------------------------
  ~pdb_handler_t()
  {
    if ( session->refcount > 1 )
    {
      session->refcount--;
    }
    else
    {
      session->close();
      delete session;
      instance_count--;
    }

    if ( co_initialized && instance_count == 0 )
    {
      CoUninitialize();
      co_initialized = false;
    }
  }

  //----------------------------------------------------------------------
  pdb_handler_t(const pdb_handler_t &r)
  {
    session = r.session;
    session->refcount++;
  }

  //----------------------------------------------------------------------
  pdb_handler_t &operator =(const pdb_handler_t &r)
  {
    if ( session->refcount > 1 )
    {
      // unlink
      session->refcount--;
    }
    else
    {
      session->close();
      instance_count--;
    }
    session = r.session;
    session->refcount++;

    return *this;
  }

  //----------------------------------------------------------------------
  void close()
  {
    // shared instance? then detach
    if ( session->refcount > 1 )
    {
      // unlink
      session->refcount--;
      session = new pdb_session_t();
      instance_count++;
    }
    else
    {
      session->close();
    }
  }

  //----------------------------------------------------------------------
  const bool opened() const
  {
    return session->pSource != NULL;
  }

  //----------------------------------------------------------------------
  DWORD get_machine_type()
  {
    // Retrieve the machine type
    DWORD machine;
    DWORD dwMachType;
    if ( session == NULL || session->pGlobal->get_machineType(&dwMachType) != S_OK )
      dwMachType = IMAGE_FILE_MACHINE_I386;

    switch ( dwMachType )
    {
    default:
      machine = CV_CFL_80386;
      break;
    case IMAGE_FILE_MACHINE_IA64:
      machine = CV_CFL_IA64;
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      machine = CV_CFL_AMD64;
      break;
    case IMAGE_FILE_MACHINE_THUMB:
    case IMAGE_FILE_MACHINE_ARM:
      machine = CV_CFL_ARM6;
      break;
    }
    return machine;
  }

  //----------------------------------------------------------------------
  HRESULT open(
          const char *input_file,
          const char *user_spath = NULL,
          ea_t load_address = BADADDR,
          input_exe_reader_t exe_reader = NULL,
          input_mem_reader_t mem_reader = NULL)
  {
    if ( opened() )
      return S_OK;

    // Not initialized yet?
    if ( !co_initialized )
    {
      // Initialize COM
      CoInitialize(NULL);
      co_initialized = true;
    }
    return session->open(input_file, user_spath, load_address, exe_reader, mem_reader);
  }
};

bool pdb_handler_t::co_initialized = false;
int pdb_handler_t::instance_count = 0;

//----------------------------------------------------------------------
static HRESULT handle_pdb_file(
        const char *input_file,
        const char *user_spath,
        HRESULT handler(IDiaDataSource *pSource,
                        IDiaSession *pSession,
                        IDiaSymbol *pGlobal,
                        int machine_type,
                        int dia_version,
                        void *ud),
        ea_t load_address=BADADDR,
        input_exe_reader_t exe_reader = NULL,
        input_mem_reader_t mem_reader = NULL,
        void *ud=NULL)
{
  pdb_handler_t pdb;
  HRESULT hr = pdb.open(input_file, user_spath, load_address, exe_reader, mem_reader);
  if ( FAILED(hr) )
    return hr;
  else
    return handler(pdb.session->pSource,
                   pdb.session->pSession,
                   pdb.session->pGlobal,
                   pdb.get_machine_type(),
                   pdb.session->dia_ver,
                   ud);
}
