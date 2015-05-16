// This file contains functions usable only for WinCE systems

#include <windows.h>

#define USE_ASYNC
#include <pro.h>
#include <fpro.h>
#include <area.hpp>
#include <idd.hpp>
#include "wince.hpp"
#include "xscale/Breakpoint.h"
#include "rpc_server.h"

static KDataStruct &kd = *(KDataStruct *)KDataStructAddr;
o32_lite *process_o32_ptr;
ea_t slot;
ea_t process_vbase;
int process_objcnt;

//--------------------------------------------------------------------------
// debug print to ida message window
inline void dmsg(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  dmsg(g_global_server, format, va);
  va_end(va);
}

//--------------------------------------------------------------------------
static bool is_ce600(void)
{
  static int ce600 = -1;
  if ( ce600 == -1 )
  {
    OSVERSIONINFO ver;
    ver.dwOSVersionInfoSize = sizeof(ver);
    ce600 = GetVersionEx(&ver)
      && ver.dwPlatformId == VER_PLATFORM_WIN32_CE
      && ver.dwMajorVersion >= 6;
  }
  return ce600 == 0 ? false : true;
}

//--------------------------------------------------------------------------
static bool is_ce500(void)
{
  static int ce500 = -1;
  if ( ce500 == -1 )
  {
    OSVERSIONINFO ver;
    ver.dwOSVersionInfoSize = sizeof(ver);
    ce500 = GetVersionEx(&ver)
         && ver.dwPlatformId == VER_PLATFORM_WIN32_CE
         && ver.dwMajorVersion >= 5;
  }
  return ce500 == 0 ? false : true;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::create_process(const char *path,
                    const char *args,
                    const char * /*startdir*/,
                    bool is_gui,
                    PROCESS_INFORMATION *ProcessInformation)
{
  wchar_t wpath[MAXSTR];
  wchar_t wargs_buffer[MAXSTR];
  wchar_t *wargs = NULL;
  if ( args != NULL )
  {
    cwstr(wargs_buffer, args, qnumber(wargs_buffer));
    wargs = wargs_buffer;
  }
  cwstr(wpath, path, qnumber(wpath));
  return CreateProcess(
          wpath,                               // pointer to name of executable module
          wargs,                               // pointer to command line string
          NULL,                                // pointer to process security attributes
          NULL,                                // pointer to thread security attributes
          false,                               // handle inheritance flag
           (is_gui ? 0 : CREATE_NEW_CONSOLE)   // creation flags
          |DEBUG_ONLY_THIS_PROCESS
          |DEBUG_PROCESS,
          NULL,                                // pointer to new environment block
          NULL,                                // pointer to current directory name
          NULL,                                // pointer to STARTUPINFO
          ProcessInformation);                 // pointer to PROCESS_INFORMATION
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_process_base(size_t size)
{
  ea_t ea = kd.aInfo[KINX_PROCARRAY];
  for ( int i=0; i < MAX_PROCESSES; i++, ea+=size )
  {
    if ( is_ce500() )
    {
      win500_process_t &p = *(win500_process_t*)ea;
      if ( p.dwVMBase == slot )
      {
        process_objcnt = p.e32.objcnt;
        process_o32_ptr = p.o32_ptr;
        process_vbase = p.e32.vbase;
        return p.e32.vbase; // we always use slot 0
      }
    }
    else
    {
      win420_process_t &p = *(win420_process_t*)ea;
      if ( p.dwVMBase == slot )
      {
        process_objcnt = p.e32.objcnt;
        process_o32_ptr = p.o32_ptr;
        process_vbase = p.e32.vbase;
        return p.e32.vbase; // we always use slot 0
      }
    }
  }
  warning("WinCE: could not find process base for slot 0x%08X", slot);
  return 0;
}

//--------------------------------------------------------------------------
ea_t get_process_slot(HANDLE phandle)
{
  size_t size = is_ce500()
                  ? sizeof(win500_process_t)
                  : sizeof(win420_process_t);
  __try
  {
    ea_t ea = kd.aInfo[KINX_PROCARRAY];
    for ( int i=0; i < MAX_PROCESSES; i++, ea+=size )
    {
      win420_process_t &p = *(win420_process_t*)ea;
      if ( p.hProc == phandle )
        return p.dwVMBase;
    }
  }
  __except ( EXCEPTION_EXECUTE_HANDLER )
  {
  }
  warning("WinCE: could not find process slot for 0x%08X", phandle);
  return 0;
}

//--------------------------------------------------------------------------
LPVOID win32_debmod_t::correct_exe_image_base(LPVOID base)
{
  // we have to correct the image base for Windows CE since
  // the kernel returns only the slot number, not the image base
  if ( is_ce600() )
    return base;

  slot = (ea_t)base;

  ea_t ea;
  __try
  {
    size_t size = is_ce500()
                    ? sizeof(win500_process_t)
                    : sizeof(win420_process_t);
    ea = get_process_base(size);
  }
  __except ( EXCEPTION_EXECUTE_HANDLER )
  {
  }
  base = (LPVOID)ea;
  return base;
}

//--------------------------------------------------------------------------
bool myread(ea_t ea, void *buf, size_t bufsize)
{
  bool ok = true;
  __try
  {
    void *ptr = (void *)ea;
    memcpy(buf, ptr, bufsize);
  }
  __except ( EXCEPTION_EXECUTE_HANDLER )
  {
    msg("failed to read windows ce system data\n");
    ok = false;
  }
  return ok;
}

//--------------------------------------------------------------------------
static int enumerate_modules(int (*func)(wince_module_t *wm, void *),
                             void *ud,
                             wince_module_t *result)
{
  int code = 0;
  size_t size = is_ce500()
              ? sizeof(win500_module_t)
              : sizeof(win420_module_t);
  __try
  {
    KDataStruct kd;
    if ( !myread(KDataStructAddr, &kd, sizeof(kd)) )
      return 0;
    ea_t ea = kd.aInfo[KINX_MODULES];
    while ( ea != 0 )
    {
      wince_module_t wm;
      if ( !myread(ea, &wm, size) )
        return 0;
      code = func(&wm, ud);
      if ( code != 0 )
      {
        if ( result != NULL )
          memcpy(result, &wm, size);
        break;
      }
      win420_module_t *ptr = (win420_module_t*)&wm;
      ea = (ea_t)ptr->pMod;
    }
  }
  __except ( EXCEPTION_EXECUTE_HANDLER )
  {
    msg("failed to obtain module list\n");
  }
  return code;
}

//--------------------------------------------------------------------------
#define DEFINE_GET_FIELD(name, type)            \
inline type &get_ ## name(wince_module_t *wm)   \
{                                               \
  if ( is_ce500() )                             \
  {                                             \
    win500_module_t *w = (win500_module_t *)wm; \
    return w->name;                             \
  }                                             \
  else                                          \
  {                                             \
    win420_module_t *w = (win420_module_t *)wm; \
    return w->name;                             \
  }                                             \
}

DEFINE_GET_FIELD(e32, common_e32_lite)
DEFINE_GET_FIELD(o32_ptr, o32_lite *)

//--------------------------------------------------------------------------
static int match_module_base(wince_module_t *wm, void *ud)
{
  ea_t base = *(ea_t *)ud;
  return get_e32(wm).vbase == base;
}

//--------------------------------------------------------------------------
static int match_module_baseptr(wince_module_t *wm, void *ud)
{
  ea_t base = *(ea_t *)ud;
  if ( is_ce500() )
  {
    win500_module_t *w = (win500_module_t *)wm;
    return (ea_t)w->BasePtr == base;
  }
  else
  {
    win420_module_t *w = (win420_module_t *)wm;
    return (ea_t)w->BasePtr == base;
  }
}

//--------------------------------------------------------------------------
static int match_module_name(wince_module_t *wm, void *ud)
{
  const char *name = (const char *)ud;
  char buf[64];
  win420_module_t *w = (win420_module_t *)wm;
  if ( getstr((ea_t)w->lpszModName, buf, sizeof(buf), true) )
  {
    set_file_ext(buf, sizeof(buf), buf, "");
    return stricmp(buf, name) == 0;
  }
  return 0;
}

//--------------------------------------------------------------------------
static bool find_module(ea_t imagebase, wince_module_t *wm)
{
  return enumerate_modules(match_module_base,    &imagebase, wm)
      || enumerate_modules(match_module_baseptr, &imagebase, wm);
}

//--------------------------------------------------------------------------
bool find_module_by_name(const char *name, wince_module_t *wm)
{
  char buf[64];
  set_file_ext(buf, sizeof(buf), name, "");
  return enumerate_modules(match_module_name, buf, wm);
}

//--------------------------------------------------------------------------
uint32 win32_debmod_t::calc_imagesize(ea_t ea)
{
  wince_module_t wm;
  if ( find_module(ea, &wm) )
    return get_e32(&wm).vsize;
  return 0;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::get_dll_exports(
        const images_t &dlls,
        ea_t imagebase,
        name_info_t &ni,
        const char *exported_name)
{
  int i;
  wince_module_t wm;
  if ( !find_module(imagebase, &wm) )
    return false;

  common_e32_lite &e32 = get_e32(&wm);
  petab_t *pexpdir;
  if ( is_ce500() )
  {
    win500_e32_lite *e32_500 = (win500_e32_lite *)&e32;
    pexpdir = &e32_500->unit[E32_LITE_EXP];
  }
  else
  {
    win420_e32_lite *e32_420 = (win420_e32_lite *)&e32;
    pexpdir = &e32_420->unit[E32_LITE_EXP];
  }

  petab_t &expdir = *pexpdir;
  if ( expdir.size <= 0 )
    return false;

  // calculate the export directory address
  ea_t o32_ptr = (ea_t)get_o32_ptr(&wm);
  ea_t exp_ea = BADADDR;

  // no memory or bad object count
  o32_lite *ao32 = new o32_lite[e32.objcnt];
  if ( ao32 == NULL )
    return false;

  if ( myread(o32_ptr, ao32, e32.objcnt * sizeof(o32_lite)) )
  {
    for ( i=0; i < e32.objcnt; i++ )
    {
      o32_lite &o32 = ao32[i];
      if ( expdir.rva >= o32.rva && expdir.rva+expdir.size <= o32.rva+o32.vsize )
        exp_ea = o32.realaddr + (expdir.rva - o32.rva);
    }
  }
  delete [] ao32;
  if ( exp_ea == BADADDR )
    return false;

  // read export section
  uchar *data = new uchar[expdir.size];
  if ( data == NULL )
    return false;

  bool ok = false;
  const uint32 *end = (const uint32 *)(data + expdir.size);
  if ( myread(exp_ea, data, expdir.size) )
  {
    peexpdir_t &ed = *(peexpdir_t *)data;
    char *dllname = (char *)data + ed.dllname - expdir.rva;
    if ( dllname < (char *)data || dllname >= (char*)end )
      dllname = "";
    char *dot = strrchr(dllname, '.');
    if ( dot != NULL )
      *dot = '\0';

    const uint32 *names = (const uint32 *)(data + ed.namtab - expdir.rva);
    const uint16 *ords  = (const uint16 *)(data + ed.ordtab - expdir.rva);
    const uint32 *addrs = (const uint32 *)(data + ed.adrtab - expdir.rva);
    if ( names < end && (uint32*)ords < end && addrs < end )
    {
      // ordinals -> names
      typedef std::map<int, qstring> expfunc_t;
      expfunc_t funcs;
      for ( i=0; i < ed.nnames; i++ )
      {
        const char *name = (char*)data + names[i] - expdir.rva;
        if ( name >= (char*)data && name < (char*)end )
          funcs.insert(make_pair(ed.ordbase + ords[i], qstring(name)));
      }
      for ( i=0; i < ed.naddrs; i++ )
      {
        char buf[MAXSTR];
        uint32 adr = addrs[i];
        if ( adr == 0 )
          continue;
        int ord = ed.ordbase + i;
        ea_t fulladdr = imagebase + adr;
        expfunc_t::iterator p = funcs.find(ord);
        if ( p != funcs.end() )
          qsnprintf(buf, sizeof(buf), "%s_%s", dllname, p->second.c_str());
        else
          qsnprintf(buf, sizeof(buf), "%s_%d", dllname, ord);
        ni.addrs.push_back(fulladdr);
        ni.names.push_back(qstrdup(buf));
        ok = true;
      }
    }
  }
  delete [] data;
  return ok;
}

//--------------------------------------------------------------------------
// WinCE device seems to freeze and require a hard reset if a bpt is
// set at coredll (and other system areas?)
// we never write there
bool win32_debmod_t::may_write(ea_t ea)
{
  static area_t forbidden_area;
  if ( forbidden_area.startEA == 0 )
  {
    wince_module_t coredll;
    find_module_by_name("coredll", &coredll);
    common_e32_lite &e32 = get_e32(&coredll);
    forbidden_area.startEA = e32.vbase;
    forbidden_area.endEA   = e32.vbase + e32.vsize;
  }
  if ( ea >= 0x80000000 || forbidden_area.contains(ea) )
  {
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
// Windows CE does not implement some functions, we do it here
//--------------------------------------------------------------------------
WINBASEAPI
BOOL
WINAPI
VirtualProtectEx(
    IN  HANDLE hProcess,
    IN  LPVOID lpAddress,
    IN  SIZE_T dwSize,
    IN  DWORD flNewProtect,
    OUT PDWORD lpflOldProtect)
{
  SetLastError(E_NOTIMPL);
  return FALSE;
}

//--------------------------------------------------------------------------
// the following function is from
//   Willem Jan Hengeveld  <itsme@xs4all.nl> http://www.xs4all.nl/~itsme/
static DWORD PhysToVirt(DWORD dwPhysOffset)
{
// reverse map physical address to virtual.
    for (DWORD ixPage= 0x800 ; ixPage < 0xa00 ; ixPage++)
    {
        DWORD dwEntry= ((DWORD*)0xfffd0000)[ixPage];
        if ( ((dwEntry&3)==2 )
            && ((dwEntry&0xfff00000)==(dwPhysOffset&0xfff00000)))
            return (dwPhysOffset&0xfffff)|(ixPage<<20);
    }
//    debug("Physical address %08lx is not mapped\n", dwPhysOffset);
    return 0;
}

//--------------------------------------------------------------------------
inline bool is_used_memblock(const MEMBLOCK *pmb)
{
  return pmb != NULL_BLOCK && pmb != RESERVED_BLOCK;
}

//--------------------------------------------------------------------------
inline bool is_used_page(uint32 page)
{
  return page != 0 && (page & 0xFFF00000) != 0xFFF00000;
}

//--------------------------------------------------------------------------
static bool is_kernpage_used(ea_t ea, uint *size)
{
  // via pagetable at 0xfffd0000
  //  fedcba9876543210fedcba9876543210
  //  sssssssbbbbbbbbbpppp............
  int ixPage = (ea >> 20) & 0xFFF;
  // first level page table (uncached) (2nd half is r/o)
  int dwEntry = ((DWORD*)0xFFFD0000)[ixPage];
  *size = (1 << 20);
  if ( (dwEntry & 3) == 2 )
  {
    // section descriptor
    return true;
  }
  else if ( (dwEntry & 0xfffff) == 0 )
  {
    return false;
  }
  else if ( (dwEntry & 3) == 1 )
  {
    *size = (1 << 12);
    // coarse page table entry
    int phys_2nd_tlb = ea & ~0x3f;
    int virt_2nd_tlb = PhysToVirt(phys_2nd_tlb);
    if ( virt_2nd_tlb == 0 )
      return false;

    int ix2ndPage = (ea>>12) & 0xff;
    int dw2ndEntry = ((DWORD*)virt_2nd_tlb)[ix2ndPage];
    if ( (dw2ndEntry & 3) ==1 )
    {
      // large page
      return true;
    }
    else if ( (dw2ndEntry & 3) == 2 )
    {
      // small page
      return true;
    }
    return false;
  }
  return false;
}

//--------------------------------------------------------------------------
struct area_info_t
{
  ea_t end;
  bool used;
  area_info_t(void) {}
  area_info_t(ea_t ea, bool b) : end(ea), used(b) {}
};

typedef std::map<ea_t, area_info_t> areas_t;
static areas_t kernel_areas;

//--------------------------------------------------------------------------
static ea_t find_process_area_end(ea_t ea, ea_t *next_process_area)
{
  *next_process_area = BADADDR;
  bool exiting = g_global_server == NULL
    || ((win32_debmod_t *)g_global_server->get_debugger_instance())->exiting;

  if ( !exiting && (ea & 0xFE000000) == slot )
  {
    ea -= slot;
    ea_t rva = ea - process_vbase;
    for ( int i=0; i < process_objcnt; i++ )
    {
      o32_lite &o32 = process_o32_ptr[i];
      if ( ea < o32.rva+process_vbase && *next_process_area == BADADDR )
        *next_process_area = process_vbase + o32.rva;
      else if ( rva >= o32.rva && rva < o32.rva + o32.vsize )
      {
        ea = slot + process_vbase + o32.rva + o32.vsize;
        ea += PAGE_SIZE - 1;
        ea &= ~(PAGE_SIZE - 1);
        return ea;
      }
    }
  }
  return BADADDR;
}

//--------------------------------------------------------------------------
static ea_t find_region_end(ea_t ea, bool *used)
{
  ea_t section = ea & ~((1<<VA_SECTION)-1);

  // redirect slot 0 to the process slot
  if ( (ea & 0xFE000000) == 0 )
    ea |= slot;

  if ( (ea < 0x80000000) || ((ea & 0xfe000000) == 0xc2000000) )
  {
    ea_t next;
    ea_t end = find_process_area_end(ea, &next);
    if ( end != BADADDR )
    {
      *used = true;
      return end;
    }

    // via section table
    //  fedcba9876543210fedcba9876543210
    //  sssssssbbbbbbbbbpppp............
    const SECTION *pscn;
    if ( (ea & 0x80000000) != 0 )
    {
      DWORD (&KInfoTable)[32] = kd.aInfo;
      pscn = (SECTION*)KInfoTable[KINX_NKSECTION];
    }
    else
    {
      // calculate the address of the section table dynamically
      // if this variable is declared static, the compiler generates wrong code
      SECTION *(&SectionTable)[64] = kd.aSections;
      pscn = SectionTable[ea>>VA_SECTION];
    }
    const SECTION &scn = *pscn;

    int ixBlock = (ea >> VA_BLOCK) & BLOCK_MASK;
    int ixPage  = (ea >> VA_PAGE) & PAGE_MASK;
    const MEMBLOCK *pmb = scn[ixBlock];

    bool block_exists = is_used_memblock(pmb);
    bool use = *used = block_exists && is_used_page(pmb->aPages[ixPage]);
    // find end of the region, never cross the section boundary
    while ( true )
    {
      if ( block_exists )
      {
        while ( ++ixPage < PAGE_MASK+1 )
          if ( is_used_page(pmb->aPages[ixPage]) != use )
            goto stopscan;
      }
      ixPage = 0;
      if ( ++ixBlock == BLOCK_MASK+1 )
        break;
      pmb = scn[ixBlock];
      block_exists = is_used_memblock(pmb);
      if ( block_exists != use )
        break;
      ixPage = -1;     // so that after ++ it will be 0
    }
stopscan:
    end = section + (ixBlock << VA_BLOCK) + (ixPage << VA_PAGE);
    if ( next != BADADDR && end > next )
      end = next;
    return end;
  }
  else // we suppose that the kernel memory layout does not change
  {
    int use, i;
    if ( kernel_areas.empty() )
    {
      static const area_t used[] =
      {
        area_t(0xFFFD0000, 0xFFFD4000),
        area_t(0xFFFF0000, 0xFFFFCC00),
      };
      static const area_t free[] =
      {
        area_t(0xFFF00000, 0xFFFD0000),
        area_t(0xFFFD4000, 0xFFFF0000),
      };
      for ( i=0; i < qnumber(used); i++ )
        kernel_areas[used[i].startEA] = area_info_t(used[i].endEA, true);

      for ( i=0; i < qnumber(free); i++ )
        kernel_areas[free[i].startEA] = area_info_t(free[i].endEA, false);
    }

    areas_t::iterator p = kernel_areas.find(ea);
    if ( p != kernel_areas.end() )
    {
      area_info_t &ai = p->second;
      use = ai.used;
      ea = ai.end;
    }
    else
    {
      uint size;
      use = -1;
      ea_t sea = ea;
      ea_t mea = ea < 0xC2000000 ? 0xC2000000 : 0xFFF00000;
      while ( ea != 0 && ea < mea )
      {
        int ok = is_kernpage_used(ea, &size);
//        msg("kused %x: %d %x\n", ea, ok, size);
        if ( use == -1 )
          use = ok;
        if ( use != ok )
          break;
        ea += size;
      }
      area_info_t ai;
      ai.end = ea;
      ai.used = use;
      kernel_areas[sea] = ai;
    }
    *used = use;
    return ea;
  }
}

//--------------------------------------------------------------------------
WINBASEAPI
SIZE_T
WINAPI
VirtualQueryEx(
    IN HANDLE /*hProcess*/,
    IN LPCVOID lpAddress,
    OUT PMEMORY_BASIC_INFORMATION lpBuffer,
    IN SIZE_T dwLength
    )
{

  ea_t base = (ea_t)lpAddress;
  if ( base > 0xFFFFFFF0 )
    return 0;

  bool used;
  ea_t ea = base;
  __try
  {
    ea = find_region_end(base, &used);
  }
  __except ( EXCEPTION_EXECUTE_HANDLER )
  {
  }
  if ( ea == base )
    return 0;

//  dmsg("query %s:%x..%x\n", used ? "ok" : "xx", base, ea);
  lpBuffer->BaseAddress = (void *)lpAddress;
  lpBuffer->AllocationBase = (void *)lpAddress;
  lpBuffer->AllocationProtect = PAGE_EXECUTE_READWRITE;
  lpBuffer->RegionSize = ea - base;
  lpBuffer->State = used ? MEM_COMMIT : MEM_FREE;
  lpBuffer->Protect = PAGE_EXECUTE_READWRITE;
  lpBuffer->Type = MEM_IMAGE;
  return sizeof(*lpBuffer);
}

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::handle_ioctl(int fn, const void *in, size_t, void **, ssize_t *)
{
  switch ( fn )
  {
    case 0:
      return is_ce500();
    case 1:
      return slot;
    case 2:
      {
        bool old = is_xscale;
        is_xscale = *(int32*)in;
        return old;
      }
  }
  return 0;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::prepare_to_stop_process(debug_event_t *in_event, const threads_t &threads)
{
  // suspended processes can not be terminated in WindowsCE
  // so we resume the process first
  // to survive this, we have to reset the IP to a well known value
  if ( in_event != NULL )
  {
    for ( threads_t::const_iterator p=threads.begin(); p != threads.end(); ++p )
    {
      CONTEXT ctx;
      if ( GetThreadContext(p->second.hThread, &ctx) )
      {
        ctx.Eip = 0;
        SetThreadContext(p->second.hThread, &ctx);
      }
    }
    if ( !dbg_continue_after_event(in_event) )
      deberr("wince_prepare_to_stop_process: continue_after_event");
  }
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::set_debug_hook(ea_t)
{
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::add_thread_areas(
  HANDLE process_handle,
  thid_t tid,
  images_t &thread_areas,
  images_t &class_areas)
{
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::get_mapped_filename(
  HANDLE process_handle,
  ea_t imagebase,
  char *buf,
  size_t bufsize)
{
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::get_pe_export_name_from_process(
  ea_t imagebase,
  char *name,
  size_t namesize)
{
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::disable_hwbpts()
{
  return wince_debmod_t::disable_hwbpts();
}

//--------------------------------------------------------------------------
bool win32_debmod_t::enable_hwbpts()
{
  return wince_debmod_t::enable_hwbpts();
}

//--------------------------------------------------------------------------
// map process slot to slot 0
ea_t win32_debmod_t::pstos0(ea_t ea)
{
  return ::pstos0(ea);
}

//--------------------------------------------------------------------------
// map slot 0 to the process slot
ea_t win32_debmod_t::s0tops(ea_t ea)
{
  return ::s0tops(ea);
}

//--------------------------------------------------------------------------
int win32_debmod_t::rdmsr(int reg, uint64 *value)
{
  return STATUS_NOT_IMPLEMENTED;
}

//--------------------------------------------------------------------------
int win32_debmod_t::wrmsr(int reg, uint64 value)
{
  return STATUS_NOT_IMPLEMENTED;
}
