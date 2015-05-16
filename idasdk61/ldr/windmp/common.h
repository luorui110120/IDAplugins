#ifndef __WINDMP_COMMON__
#define __WINDMP_COMMON__

#include <diskio.hpp>
#include <area.hpp>

#define WDOPT_DBGMODE 0x1

int get_windmp_ldr_options();
void set_windmp_ldr_options(int opt);
void prepare_symbol_name(qstring &name, size_t *mod_sep_pos);
bool was_input_crash_dump(qstring *fn = NULL);
void get_filename_no_ext(const char *path, qstring *name);
bool detect_dbgtools_path(char *path, size_t path_size);
bool pc_get_dbgtools_path(char *path, size_t path_size);
bool is_crash_dump_file(linput_t *li);
bool is_crash_dump_file(const char *filename);
void get_def_sympath(char *path, size_t sz);
bool is_sympath_set();
bool is_crash_dump_loader();
struct IDebugDataSpaces4;
HRESULT read_process_memory(
        IDebugDataSpaces4 *space,
        const areavec_t *inited_areas,
        IN ULONG64  Offset,
        OUT PVOID  Buffer,
        IN ULONG  BufferSize,
        OUT OPTIONAL PULONG BytesRead);

bool get_minidump_mslist(
        HMODULE dbghlp_hmod,
        const char *dmpfile,
        areavec_t *mslist);


// define some common CSIDLs
#ifndef CSIDL_PROGRAM_FILES
#define CSIDL_PROGRAM_FILES 0x26
#endif
#ifndef CSIDL_PROGRAM_FILES_COMMON
#define CSIDL_PROGRAM_FILES_COMMON 0x2B
#endif
//--------------------------------------------------------------------------
// get a folder location by CSIDL
// path should be of at least MAX_PATH size
inline bool get_special_folder(int csidl, char *buf, size_t bufsize)
{
   // required by the API
   if ( bufsize < MAX_PATH )
     return false;

   typedef BOOL (WINAPI *SHGetSpecialFolderPath_t)(
     HWND hwndOwner, LPTSTR lpszPath,
     int nFolder,
     BOOL fCreate);

   HMODULE hmod_shell32 = LoadLibrary("shell32.dll");
   if ( hmod_shell32 == NULL )
     return false;

   SHGetSpecialFolderPath_t pSHGetSpecialFolderPath = NULL;
   *(FARPROC*)&pSHGetSpecialFolderPath = GetProcAddress(hmod_shell32, "SHGetSpecialFolderPathA");
   bool ok = pSHGetSpecialFolderPath != NULL
          && pSHGetSpecialFolderPath(NULL, buf, csidl, FALSE) != FALSE;
   FreeLibrary(hmod_shell32);
   return ok;
}
#endif
