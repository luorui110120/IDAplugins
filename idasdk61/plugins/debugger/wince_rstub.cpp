#define REMOTE_DEBUGGER
#define RPC_CLIENT
#define USE_ASYNC

char wanted_name[] = "Remote WinCE debugger";
#define DEBUGGER_NAME  "wince"
#define PROCESSOR_NAME "arm"
#define TARGET_PROCESSOR PLFM_ARM
#define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_USER
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE       \
                     | DBG_FLAG_NOHOST       \
                     | DBG_FLAG_FAKE_ATTACH  \
                     | DBG_FLAG_HWDATBPT_ONE \
                     | DBG_FLAG_CLEAN_EXIT   \
                     | DBG_FLAG_NOPASSWORD   \
                     | DBG_FLAG_NOSTARTDIR   \
                     | DBG_FLAG_EXITSHOTOK   \
                     | DBG_FLAG_LOWCNDS

#define SET_DBG_OPTIONS set_wince_options
#define S_MAP_ADDRESS   local_pstos0
#define S_FILETYPE      f_PE
#define win32_init_plugin       init_plugin
#define win32_term_plugin       term_plugin

#include "async.h"
#include <err.h>
#include <ua.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include "rpc_client.h"
#include "rpc_debmod.h"

rpc_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"
#include "arm_local_impl.cpp"
#include "win32_local_impl.cpp"

void show_wince_rom(void);
static ea_t idaapi local_pstos0(ea_t ea, const regval_t *, int);
static bool enable_hwbpts(bool enable);
static const char *idaapi set_wince_options(const char *keyword, int value_type, const void *value);

#include "wince.hpp"
#include "common_local_impl.cpp"
#include <map>

ea_t slot;

//----------------------------------------------------------------------
// map process slot to slot 0
static ea_t idaapi local_pstos0(ea_t ea, const regval_t *, int)
{
  if ( slot == BADADDR )
  {
    slot = s_ioctl(1, NULL, 0, NULL, NULL);        // get slot number
  }
  return pstos0(ea);
}

//----------------------------------------------------------------------
static bool enable_hwbpts(bool enable)
{
  int32 x = enable;
  return s_ioctl(2, &x, sizeof(x), NULL, NULL);
}

//----------------------------------------------------------------------
static const char *idaapi set_wince_options(const char *keyword, int value_type, const void *value)
{
  static int hwbpts = 0;
  if ( keyword == NULL ) // interactive call
  {
    static const char form[] =
      "Windows CE debugger specific options\n"
      "\n"
      "  <Enable hardware breakpoints:C>>\n"
      "\n";

    if ( !AskUsingForm_c(form, &hwbpts) )
      return IDPOPT_OK;
//    show_wince_rom();
  }
  else
  {
    if ( strcmp(keyword, "HWBPTS_ENABLED") != 0 )
      return IDPOPT_BADKEY;
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    hwbpts = *(int*)value;
  }
  if ( debugger_inited )
    enable_hwbpts(hwbpts);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
/*static*/ bool myread(ea_t ea, void *buf, size_t size)
{
  if ( s_read_memory(ea, buf, size) != size )
  {
    msg("%a: rpc read memory error\n", ea);
    return false;
  }
  return true;
}

//----------------------------------------------------------------------
static char *ftime2str(FILETIME *ft, char *buf, size_t bufsize)
{
  SYSTEMTIME s;
  if ( FileTimeToSystemTime(ft, &s) )
    qsnprintf(buf, bufsize, "%02d-%02d-%04d %02d:%02d:%02d",
                s.wDay, s.wMonth, s.wYear, s.wHour, s.wMinute, s.wSecond);
  else
    qsnprintf(buf, bufsize, "%08lX %08lX", ft->dwLowDateTime, ft->dwHighDateTime);
  return buf;
}

//----------------------------------------------------------------------
static const char *const petab_names[] =
{
  "expdir",
  "impdir",
  "resdir",
  "excdir",
  "secdir",
  "reltab",
  "debdir",
  "desstr",
  "cputab",
};

static void dump_common_e32_lite(const common_e32_lite &e32)
{
  msg("  nobjs     : %d\n",    e32.objcnt);
  msg("  ceversion : %d.%d\n", e32.cevermajor, e32.ceverminor);
  msg("  stackmax  : %08lX\n", e32.stackmax);
  msg("  vbase     : %08lX\n", e32.vbase);
  msg("  vsize     : %08lX\n", e32.vsize);
  msg("  sect14rva : %08lX\n", e32.sect14rva);
  msg("  sect14size: %08lX\n", e32.sect14size);
}

static void dump_win420_e32_lite(const win420_e32_lite &e32)
{
  dump_common_e32_lite(e32);
  for ( int i=0; i < qnumber(e32.unit); i++ )
  {
    ea_t rva = e32.unit[i].rva;
    size_t size = e32.unit[i].size;
    msg("  %s %08lX %08lX\n", petab_names[i], rva, size);
  }
}

static void dump_win500_e32_lite(const win500_e32_lite &e32)
{
  dump_common_e32_lite(e32);
  msg("  timestamp : %08lX\n", e32.timestamp);
  for ( int i=0; i < qnumber(e32.unit); i++ )
  {
    ea_t rva = e32.unit[i].rva;
    size_t size = e32.unit[i].size;
    msg("  %s %08lX %08lX\n", petab_names[i], rva, size);
  }
}

//----------------------------------------------------------------------
static bool dump_expdir(ea_t base, const uchar *data, const petab_t &expdir)
{
  const uint32 *end = (const uint32 *)(data + expdir.size);
//  show_hex(data, expdir.size, "EXPDIR\n");
  peexpdir_t &ed = *(peexpdir_t *)data;
  const char *stime = "(undefined)";
  if ( ed.datetime != 0 )
  {
    stime = qctime(ed.datetime);
    if ( stime == NULL )
      stime = "(null)\n";
  }
  msg("Flags         : %08lX\n", ed.flags);
  msg("Time stamp    : %s", stime);
  msg("Version       : %d.%d\n", ed.major, ed.minor);
  msg("DLL name      : %08lX ", ed.dllname);
  const uchar *dllname = data + ed.dllname - expdir.rva;
  if ( dllname < data || dllname >= (uchar*)end )
    dllname = (const uchar*)"???";
  msg("%s\n", dllname);
  msg("Ordinals base : %ld.\n", ed.ordbase);
  msg("# of addresses: %ld.\n", ed.naddrs);
  msg("# of names    : %ld.\n", ed.nnames);
  const uint32 *names = (const uint32 *)(data + ed.namtab - expdir.rva);
  const ushort *ords  = (const ushort *)(data + ed.ordtab - expdir.rva);
  const uint32 *addrs = (const uint32 *)(data + ed.adrtab - expdir.rva);
//  msg("end=%x names=%x ord=%x addrs=%x\n", end, names, ords, addrs);
  if ( names > end || (uint32*)ords > end || addrs > end )
    return false;
  typedef std::map<int, qstring> expfunc_t;      // ordinals -> names
  expfunc_t funcs;
  for ( int i=0; i < ed.nnames; i++ )
  {
    const char *name = (char*)data + names[i] - expdir.rva;
    if ( name < (char*)data || name >= (char*)end )
      name = "";
    funcs.insert(std::make_pair(ed.ordbase + ords[i], qstring(name)));
  }
  for ( int i=0; i < ed.naddrs; i++ )
  {
    uint32 adr = addrs[i];
    if ( adr == 0 )
      continue;
    int ord = ed.ordbase + i;
    ea_t fulladdr = base + adr;
    msg("%3d. %08lX", ord, fulladdr);
    expfunc_t::iterator p = funcs.find(ord);
    if ( p != funcs.end() )
      msg(" %s\n", p->second.c_str());
    else
      msg("\n");
  }
  return true;
}

//----------------------------------------------------------------------
static bool dump_expdir(ea_t base, ea_t ea, const petab_t &expdir)
{
  uchar *data = new uchar[expdir.size];
  if ( data == NULL )
    nomem("dump_expdir");

  bool ok = myread(ea, data, expdir.size)
         && dump_expdir(base, data, expdir);
  delete data;
  return ok;
}

//----------------------------------------------------------------------
static bool dump_o32_lites(ea_t base,
                           ea_t o32_ptr,
                           int nobjs,
                           const petab_t &expdir,
                           bool for_module)
{
  msg("  OBJECTS\n");
  msg("  #   vsize    rva    realaddr  access   flags    psize   dataptr\n");
  msg("  - -------- -------- -------- -------- -------- -------- --------\n");
  ea_t exp_rva = BADADDR;
  for ( int i=0; i < nobjs; i++ )
  {
    o32_lite o32;
    if ( !myread(o32_ptr+i*sizeof(o32), &o32, sizeof(o32)) )
      return false;
    msg("  %d %08lX %08lX %08lX %08lX %08lX %08lX",
        i,
        o32.vsize,
        o32.rva,
        o32.realaddr,
        o32.access,
        o32.flags,
        o32.psize,
        o32.dataptr);
    if ( o32.flags & IMAGE_SCN_CNT_CODE               ) msg(" CNT_CODE");
    if ( o32.flags & IMAGE_SCN_CNT_INITIALIZED_DATA   ) msg(" CNT_INITIALIZED_DATA");
    if ( o32.flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) msg(" CNT_UNINITIALIZED_DATA");
    if ( o32.flags & IMAGE_SCN_LNK_INFO               ) msg(" LNK_INFO");
    if ( o32.flags & IMAGE_SCN_LNK_REMOVE             ) msg(" LNK_REMOVE");
    if ( o32.flags & IMAGE_SCN_LNK_COMDAT             ) msg(" LNK_COMDAT");
    if ( o32.flags & IMAGE_SCN_COMPRESSED             ) msg(" COMPRESSED");
    if ( o32.flags & IMAGE_SCN_NO_DEFER_SPEC_EXC      ) msg(" NO_DEFER_SPEC_EXC");
    if ( o32.flags & IMAGE_SCN_GPREL                  ) msg(" GPREL");
    if ( o32.flags & IMAGE_SCN_MEM_FARDATA            ) msg(" MEM_FARDATA");
    if ( o32.flags & IMAGE_SCN_MEM_PURGEABLE          ) msg(" MEM_PURGEABLE");
    if ( o32.flags & IMAGE_SCN_MEM_16BIT              ) msg(" MEM_16BIT");
    if ( o32.flags & IMAGE_SCN_MEM_LOCKED             ) msg(" MEM_LOCKED");
    if ( o32.flags & IMAGE_SCN_MEM_PRELOAD            ) msg(" MEM_PRELOAD");
    if ( o32.flags & IMAGE_SCN_LNK_NRELOC_OVFL        ) msg(" LNK_NRELOC_OVFL");
    if ( o32.flags & IMAGE_SCN_MEM_DISCARDABLE        ) msg(" MEM_DISCARDABLE");
    if ( o32.flags & IMAGE_SCN_MEM_NOT_CACHED         ) msg(" MEM_NOT_CACHED");
    if ( o32.flags & IMAGE_SCN_MEM_NOT_PAGED          ) msg(" MEM_NOT_PAGED");
    if ( o32.flags & IMAGE_SCN_MEM_SHARED             ) msg(" MEM_SHARED");
    if ( o32.flags & IMAGE_SCN_MEM_EXECUTE            ) msg(" MEM_EXECUTE");
    if ( o32.flags & IMAGE_SCN_MEM_READ               ) msg(" MEM_READ");
    if ( o32.flags & IMAGE_SCN_MEM_WRITE              ) msg(" MEM_WRITE");
    msg("\n");
    if ( expdir.rva >= o32.rva && expdir.rva+expdir.size <= o32.rva+o32.vsize )
      exp_rva = o32.realaddr + (expdir.rva - o32.rva);
  }
  if ( expdir.size > 0 )
  {
    if ( exp_rva == BADADDR )
    {
      msg("COULD NOT FIND EXPORT DIRECTORY!\n");
      return false;
    }
    if ( !for_module )
      exp_rva += base;
    return dump_expdir(base, exp_rva, expdir);
  }
  return true;
}

//----------------------------------------------------------------------
static void dump_e32_rom(const e32_rom_t &e32)
{
  msg("  nobjs     : %d\n",    e32.nobjs);
  msg("  flags     : %04X\n",  e32.flags);
  if ( e32.flags & PEF_BRVHI ) msg("    Big endian: MSB precedes LSB in memory\n");
  if ( e32.flags & PEF_UP    ) msg("    File should be run only on a UP machine\n");
  if ( e32.flags & PEF_DLL   ) msg("    Dynamic Link Library (DLL)\n");
  if ( e32.flags & PEF_SYS   ) msg("    System file\n");
  if ( e32.flags & PEF_NSWAP ) msg("    Copy and run from swap file if on network media\n");
  if ( e32.flags & PEF_SWAP  ) msg("    Copy and run from swap file if removable media\n");
  if ( e32.flags & PEF_NODEB ) msg("    Debugging info stripped\n");
  if ( e32.flags & PEF_32BIT ) msg("    32-bit word machine\n");
  if ( e32.flags & PEF_BRVLO ) msg("    Little endian: LSB precedes MSB in memory\n");
  if ( e32.flags & PEF_16BIT ) msg("    16-bit word machine\n");
  if ( e32.flags & PEF_2GB   ) msg("    App can handle > 2gb addresses\n");
  if ( e32.flags & PEF_TMWKS ) msg("    Aggressively trim working set\n");
  if ( e32.flags & PEF_NOSYM ) msg("    Local symbols stripped\n");
  if ( e32.flags & PEF_NOLIN ) msg("    Line numbers stripped\n");
  if ( e32.flags & PEF_EXEC  ) msg("    Image is executable\n");
  if ( e32.flags & PEF_NOFIX ) msg("    Relocation info stripped\n");
  msg("  entry     : %08lX\n", e32.entry);
  msg("  vbase     : %08lX\n", e32.vbase);
  msg("  subsys    : %d.%d\n", e32.subsysmajor, e32.subsysminor);
  msg("  stackmax  : %08lX\n", e32.stackmax);
  msg("  vsize     : %08lX\n", e32.vsize);
  msg("  sect14rva : %08lX\n", e32.sect14rva);
  msg("  sect14size: %08lX\n", e32.sect14size);
  msg("  subsys    : %04X ",   e32.subsys);
  switch ( e32.subsys )
  {
    case PES_UNKNOWN: msg("Unknown"); break;
    case PES_NATIVE : msg("Native"); break;
    case PES_WINGUI : msg("Windows GUI"); break;
    case PES_WINCHAR: msg("Windows Character"); break;
    case PES_OS2CHAR: msg("OS/2 Character"); break;
    case PES_POSIX  : msg("Posix Character"); break;
    case PES_WINCE  : msg("Runs on Windows CE."); break;
    case PES_EFI_APP: msg("EFI application."); break;
    case PES_EFI_BDV: msg("EFI driver that provides boot services."); break;
    case PES_EFI_RDV: msg("EFI driver that provides runtime services."); break;
    default:          msg("???"); break;
  }
  msg("\n");
  for ( int i=0; i < qnumber(e32.unit); i++ )
  {
    ea_t rva = e32.unit[i].rva;
    size_t size = e32.unit[i].size;
    msg("  %s %08lX %08lX\n", petab_names[i], rva, size);
  }
}

//----------------------------------------------------------------------
static bool dump_o32_roms(ea_t o32_ptr, int nobjs)
{
  msg("  OBJECTS\n");
  msg("  #   vsize    rva      psize   dataptr realaddr  flags\n");
  msg("  - -------- -------- -------- -------- -------- --------\n");
  for ( int i=0; i < nobjs; i++ )
  {
    o32_rom_t o32;
    if ( !myread(o32_ptr+i*sizeof(o32), &o32, sizeof(o32)) )
      return false;
    msg("  %d %08lX %08lX %08lX %08lX %08lX %08lX",
        i,
        o32.vsize,
        o32.rva,
        o32.psize,
        o32.dataptr,
        o32.realaddr,
        o32.flags);
    if ( o32.flags & IMAGE_SCN_CNT_CODE               ) msg(" CNT_CODE");
    if ( o32.flags & IMAGE_SCN_CNT_INITIALIZED_DATA   ) msg(" CNT_INITIALIZED_DATA");
    if ( o32.flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA ) msg(" CNT_UNINITIALIZED_DATA");
    if ( o32.flags & IMAGE_SCN_LNK_INFO               ) msg(" LNK_INFO");
    if ( o32.flags & IMAGE_SCN_LNK_REMOVE             ) msg(" LNK_REMOVE");
    if ( o32.flags & IMAGE_SCN_LNK_COMDAT             ) msg(" LNK_COMDAT");
    if ( o32.flags & IMAGE_SCN_COMPRESSED             ) msg(" COMPRESSED");
    if ( o32.flags & IMAGE_SCN_NO_DEFER_SPEC_EXC      ) msg(" NO_DEFER_SPEC_EXC");
    if ( o32.flags & IMAGE_SCN_GPREL                  ) msg(" GPREL");
    if ( o32.flags & IMAGE_SCN_MEM_FARDATA            ) msg(" MEM_FARDATA");
    if ( o32.flags & IMAGE_SCN_MEM_PURGEABLE          ) msg(" MEM_PURGEABLE");
    if ( o32.flags & IMAGE_SCN_MEM_16BIT              ) msg(" MEM_16BIT");
    if ( o32.flags & IMAGE_SCN_MEM_LOCKED             ) msg(" MEM_LOCKED");
    if ( o32.flags & IMAGE_SCN_MEM_PRELOAD            ) msg(" MEM_PRELOAD");
    if ( o32.flags & IMAGE_SCN_LNK_NRELOC_OVFL        ) msg(" LNK_NRELOC_OVFL");
    if ( o32.flags & IMAGE_SCN_MEM_DISCARDABLE        ) msg(" MEM_DISCARDABLE");
    if ( o32.flags & IMAGE_SCN_MEM_NOT_CACHED         ) msg(" MEM_NOT_CACHED");
    if ( o32.flags & IMAGE_SCN_MEM_NOT_PAGED          ) msg(" MEM_NOT_PAGED");
    if ( o32.flags & IMAGE_SCN_MEM_SHARED             ) msg(" MEM_SHARED");
    if ( o32.flags & IMAGE_SCN_MEM_EXECUTE            ) msg(" MEM_EXECUTE");
    if ( o32.flags & IMAGE_SCN_MEM_READ               ) msg(" MEM_READ");
    if ( o32.flags & IMAGE_SCN_MEM_WRITE              ) msg(" MEM_WRITE");
    msg("\n");
  }
  return true;
}

//----------------------------------------------------------------------
static void dump_openexe(const openexe_t &oe)
{
  msg("oe.union1    : %08lX\n", oe.hf);
  msg("oe.filetype  : %02X\n",  oe.filetype);
  msg("oe.bIsOID    : %d\n",    oe.bIsOID);
  msg("oe.pagemode  : %04X\n",  oe.pagemode);
  msg("oe.union2    : %08lX\n", oe.offset);
  msg("oe.union3    : %08lX\n", oe.lpName);
}

//----------------------------------------------------------------------
static bool dump_e32_o32(const common_e32_lite &e32,
                         o32_lite *o32_ptr,
                         uint32 base,
                         bool isce500,
                         bool for_module)
{
  petab_t *expdir;
  if ( isce500 )
  {
    win500_e32_lite &e = *(win500_e32_lite*)&e32;
    dump_win500_e32_lite(e);
    expdir = &e.unit[E32_LITE_EXP];
  }
  else
  {
    win420_e32_lite &e = *(win420_e32_lite*)&e32;
    dump_win420_e32_lite(e);
    expdir = &e.unit[E32_LITE_EXP];
  }
  msg("o32_ptr      : %08lX\n", o32_ptr);
  if ( o32_ptr == 0 )
    return true;
  return dump_o32_lites(base, EA_T(o32_ptr), e32.objcnt, *expdir, for_module);
}

//----------------------------------------------------------------------
static bool dump_stdnames(const LPName *pStdNames)
{
  char buf[MAXSTR];
  msg("pStdNames[3] : %08lX %08lX %08lX", pStdNames[0], pStdNames[1], pStdNames[2]);
  for ( int i=0; i < 3; i++ )
  {
    buf[0] = '\0';
    if ( pStdNames[i] != NULL
      && !getstr(EA_T(pStdNames[i]), buf, sizeof(buf), true) )
    {
      return false;
    }
    msg(" \"%s\"", buf);
  }
  msg("\n");
  return true;
}

//----------------------------------------------------------------------
static bool dump_process(const win420_process_t &wp)
{
  char buf[MAXSTR];
  if ( wp.pTh == NULL )
    return true;
  msg("procnum      : %02X\n",  wp.procnum);
  msg("DbgActive    : %02X\n",  wp.DbgActive);
  msg("bChainDebug  : %02X\n",  wp.bChainDebug);
  msg("bTrustLevel  : %02X\n",  wp.bTrustLevel);
  msg("pProxList    : %08lX\n", wp.pProxList);
  msg("hProc        : %08lX\n", wp.hProc);
  msg("dwVMBase     : %08lX\n", wp.dwVMBase);
  msg("pTh          : %08lX\n", wp.pTh);
  msg("aky          : %08lX\n", wp.aky);
  msg("BasePtr      : %08lX\n", wp.BasePtr);
  msg("hDbgrThrd    : %08lX\n", wp.hDbgrThrd);
  if ( !getstr(EA_T(wp.lpszProcName), buf, sizeof(buf), true) )
    return false;
  msg("lpszProcName : %08lX %s\n", wp.lpszProcName, buf);
  msg("tlsLowUsed   : %08lX\n", wp.tlsLowUsed);
  msg("tlsHighUsed  : %08lX\n", wp.tlsHighUsed);
  msg("pfnEH        : %08lX\n", wp.pfnEH);
  msg("ZonePtr      : %08lX\n", wp.ZonePtr);
  msg("pMainTh      : %08lX\n", wp.pMainTh);
  msg("pmodResource : %08lX\n", wp.pmodResource);
  dump_stdnames(wp.pStdNames);
  if ( !getstr(EA_T(wp.pcmdline), buf, sizeof(buf), true) )
    return false;
  msg("pcmdline     : %08lX \"%s\"\n", wp.pcmdline, buf);
  msg("dwDyingThreads: %08lX\n", wp.dwDyingThreads);
  dump_openexe(wp.oe);
  if ( !dump_e32_o32(wp.e32, wp.o32_ptr, wp.dwVMBase, false, false) )
    return false;
  msg("pExtPdata    : %08lX\n", wp.pExtPdata);
  msg("bPrio        : %d\n", wp.bPrio);
  msg("fNoDebug     : %d\n", wp.fNoDebug);
  msg("wPad         : %04X\n", wp.wPad);
  msg("queue.head   : %04X\n",  wp.pgqueue.idxHead);
  msg("queue.tail   : %04X\n",  wp.pgqueue.idxTail);

#if HARDWARE_PT_PER_PROC
  for ( int i=0; i < HARDWARE_PT_PER_PROC; i++ )
    msg("pPTBL %2d: %08lX\n", i, wp.pPTBL[i]);
#endif
  msg("----------\n");
  return true;
}

//----------------------------------------------------------------------
static bool dump_process(const win500_process_t &wp)
{
  char buf[MAXSTR];
  if ( wp.pTh == NULL )
    return true;
  msg("procnum      : %02X\n",  wp.procnum);
  msg("DbgActive    : %02X\n",  wp.DbgActive);
  msg("bChainDebug  : %02X\n",  wp.bChainDebug);
  msg("bTrustLevel  : %02X\n",  wp.bTrustLevel);
  msg("pProxList    : %08lX\n", wp.pProxList);
  msg("hProc        : %08lX\n", wp.hProc);
  msg("dwVMBase     : %08lX\n", wp.dwVMBase);
  msg("pTh          : %08lX\n", wp.pTh);
  msg("aky          : %08lX\n", wp.aky);
  msg("BasePtr      : %08lX\n", wp.BasePtr);
  msg("hDbgrThrd    : %08lX\n", wp.hDbgrThrd);
  if ( !getstr(EA_T(wp.lpszProcName), buf, sizeof(buf), true) )
    return false;
  msg("lpszProcName : %08lX %s\n", wp.lpszProcName, buf);
  msg("tlsLowUsed   : %08lX\n", wp.tlsLowUsed);
  msg("tlsHighUsed  : %08lX\n", wp.tlsHighUsed);
  msg("pfnEH        : %08lX\n", wp.pfnEH);
  msg("ZonePtr      : %08lX\n", wp.ZonePtr);
  msg("pMainTh      : %08lX\n", wp.pMainTh);
  msg("pmodResource : %08lX\n", wp.pmodResource);
  dump_stdnames(wp.pStdNames);
  if ( !getstr(EA_T(wp.pcmdline), buf, sizeof(buf), true) )
    return false;
  msg("pcmdline     : %08lX \"%s\"\n", wp.pcmdline, buf);
  msg("dwDyingThreads: %08lX\n", wp.dwDyingThreads);
  dump_openexe(wp.oe);
  if ( !dump_e32_o32(wp.e32, wp.o32_ptr, wp.dwVMBase, true, false) )
    return false;
  msg("pExtPdata    : %08lX\n", wp.pExtPdata);
  msg("bPrio        : %d\n", wp.bPrio);
  msg("fNoDebug     : %d\n", wp.fNoDebug);
  msg("wModCount    : %d\n", wp.wModCount);
  msg("queue.head   : %04X\n",  wp.pgqueue.idxHead);
  msg("queue.tail   : %04X\n",  wp.pgqueue.idxTail);
  msg("pLastModList : %08lX\n", wp.pLastModList);
  msg("hTok         : %08lX\n", wp.hTok);

#if HARDWARE_PT_PER_PROC
  for ( int i=0; i < HARDWARE_PT_PER_PROC; i++ )
    msg("pPTBL %2d: %08lX\n", i, wp.pPTBL[i]);
#endif
  msg("pShimInfo          %08lX\n", wp.pShimInfo);
  msg("----------\n");
  return true;
}

//----------------------------------------------------------------------
static bool dump_module(const win420_module_t &wm)
{
  char buf[MAXSTR];
  msg("\n");
  msg("lpSelf       : %08lX\n", wm.lpSelf);
  msg("pMod         : %08lX\n", wm.pMod);
  if ( !getstr(EA_T(wm.lpszModName), buf, sizeof(buf), true) )
    return false;
  msg("lpszModName  : %08lX %s\n", wm.lpszModName, buf);
  msg("inuse        : %08lX\n", wm.inuse);
  msg("calledfunc   : %08lX\n", wm.calledfunc);
  msg("refcnts      :");
  for ( int i=0; i < qnumber(wm.refcnt); i++ )
   msg(" %d", wm.refcnt[i]);
  msg("\n");
  msg("BasePtr      : %08lX\n", wm.BasePtr);
  msg("DbgFlags     : %08lX\n", wm.DbgFlags);
  msg("ZonePtr      : %08lX\n", wm.ZonePtr);
  msg("startip      : %08lX\n", wm.startip);
  dump_openexe(wm.oe);
  if ( !dump_e32_o32(wm.e32, wm.o32_ptr, wm.e32.vbase, false, true) )
    return false;
  msg("dwNoNotify   : %08lX\n", wm.dwNoNotify);
  msg("wFlags       : %04X\n",  wm.wFlags);
  msg("bTrustLevel  : %02X\n",  wm.bTrustLevel);
  msg("bPadding     : %02X\n",  wm.bPadding);
  msg("pmodResource : %08lX\n", wm.pmodResource);
  msg("rwLow        : %08lX\n", wm.rwLow);
  msg("rwHigh       : %08lX\n", wm.rwHigh);

  msg("pgqueue.idxHead: %04X\n",  wm.pgqueue.idxHead);
  msg("pgqueue.idxTail: %04X\n",  wm.pgqueue.idxTail);
  return true;
}

//----------------------------------------------------------------------
static bool dump_module(const win500_module_t &wm)
{
  char buf[MAXSTR];
  msg("\n");
  msg("lpSelf       : %08lX\n", wm.lpSelf);
  msg("pMod         : %08lX\n", wm.pMod);
  if ( !getstr(EA_T(wm.lpszModName), buf, sizeof(buf), true) )
    return false;
  msg("lpszModName  : %08lX %s\n", wm.lpszModName, buf);
  msg("inuse        : %08lX\n", wm.inuse);
  msg("refcnts      :");
  for ( int i=0; i < qnumber(wm.refcnt); i++ )
   msg(" %d", wm.refcnt[i]);
  msg("\n");
  msg("BasePtr      : %08lX\n", wm.BasePtr);
  msg("DbgFlags     : %08lX\n", wm.DbgFlags);
  msg("ZonePtr      : %08lX\n", wm.ZonePtr);
  msg("startip      : %08lX\n", wm.startip);
  dump_openexe(wm.oe);
  if ( !dump_e32_o32(wm.e32, wm.o32_ptr, wm.e32.vbase, true, true) )
    return false;
  msg("dwNoNotify   : %08lX\n", wm.dwNoNotify);
  msg("wFlags       : %04X\n",  wm.wFlags);
  msg("bTrustLevel  : %02X\n",  wm.bTrustLevel);
  msg("bPadding     : %02X\n",  wm.bPadding);
  msg("pmodResource : %08lX\n", wm.pmodResource);
  msg("rwLow        : %08lX\n", wm.rwLow);
  msg("rwHigh       : %08lX\n", wm.rwHigh);

  msg("pgqueue.idxHead: %04X\n",  wm.pgqueue.idxHead);
  msg("pgqueue.idxTail: %04X\n",  wm.pgqueue.idxTail);
  msg("pShimInfo    : %08lX\n", wm.pShimInfo);
  return true;
}

//----------------------------------------------------------------------
struct ce_name_info_t
{
  int idx;
  const char *name;
};

static const char *find_name(int idx, const ce_name_info_t *ninfo, size_t qty)
{
  for ( size_t i=0; i < qty; i++ )
    if ( ninfo[i].idx == idx )
      return ninfo[i].name;
  return "";
}

//----------------------------------------------------------------------
static bool dump_section(int n, const SECTION *sptr)
{
  SECTION s;
  uint32 base = n << 25;
  msg("%2d. SECTION %08lX for memory @ %08lX\n", n, sptr, base);
  memset(&s, 0xFF, sizeof(s));
  if ( !myread(EA_T(sptr), &s, sizeof(s)) )
    return false;
  msg("   #   at       start      end      alk  use fl base  hpf locks pages\n");
  msg("  --- -------- -------- -------- -------- -- -- ---- ---- ---- --------\n");
  for ( int i=0; i < qnumber(s); i++ )
  {
    const wince_memblock_t *mb0 = s[i];
    if ( mb0 == RESERVED_BLOCK || mb0 == NULL_BLOCK )
      continue;
    uint32 start = base  + i * 64*1024;
    uint32 end   = start + 64*1024;
    msg("  %3d %08lX %08lX %08lX ", i, mb0, start, end);
    wince_memblock_t mb;
    if ( !myread(EA_T(mb0), &mb, sizeof(wince_memblock_t)) )
      return false;
    msg("%08lX %02X %02X %04X %04X %04X %08lX ",
        mb.alk,
        mb.cUses,
        mb.flags,
        uint16(mb.ixBase),
        uint16(mb.hPf),
        uint16(mb.cLocks),
        mb.aPages);
    uint32 vm[16];
    if ( !myread(EA_T(mb.aPages), vm, sizeof(vm)) )
      return false;
    char pages[16];
    for ( int j=0; j < qnumber(vm); j++ )
      pages[j] = (vm[j] == 0) ? '.' : 'x';
    msg("%16.16s\n", pages);
  }
  return true;
}

//----------------------------------------------------------------------
static void dump_kdata(void)
{
  KDataStruct kd;
  if ( !myread(KDataStructAddr, &kd, sizeof(kd)) )
    return;
  msg("KDataStruct at %08lX\n", KDataStructAddr);
  msg("lpvTls           : %08lX\n", kd.lpvTls);
  static const ce_name_info_t ah_names[] =
  {
    { SH_WIN32,         "SH_WIN32"        },
    { SH_CURTHREAD,     "SH_CURTHREAD"    },
    { SH_CURPROC,       "SH_CURPROC"      },
    { SH_KWIN32,        "SH_KWIN32"       },
    { SH_GDI,           "SH_GDI"          },
    { SH_WMGR,          "SH_WMGR"         },
    { SH_WNET,          "SH_WNET"         },
    { SH_COMM,          "SH_COMM"         },
    { SH_FILESYS_APIS,  "SH_FILESYS_APIS" },
    { SH_SHELL,         "SH_SHELL"        },
    { SH_DEVMGR_APIS,   "SH_DEVMGR_APIS"  },
    { SH_TAPI,          "SH_TAPI"         },
    { SH_PATCHER,       "SH_PATCHER"      },
    { SH_SERVICES,      "SH_SERVICES"     },
  };
  for ( int i=0; i < qnumber(kd.ahSys); i++ )
    msg("SYSTEM HANDLE %2d: %08lX %s\n", i, kd.ahSys[i], find_name(i, ah_names, qnumber(ah_names)));

  msg("bResched  : %d\n",    kd.bResched);
  msg("cNest     : %02X\n",  kd.cNest);
  msg("bPowerOff : %d\n",    kd.bPowerOff);
  msg("bProfileOn: %d\n",    kd.bProfileOn);
  msg("unused    : %08lX\n", kd.unused);
  msg("rsvd2     : %08lX\n", kd.rsvd2);
  msg("pCurPrc   : %08lX\n", kd.pCurPrc);
  msg("pCurThd   : %08lX\n", kd.pCurThd);
  msg("dwKCRes   : %08lX\n", kd.dwKCRes);
  msg("handleBase: %08lX\n", kd.handleBase);
  for ( int i=0; i < qnumber(kd.aSections); i++ )
    msg("SECTION %2d: %08lX\n", i, kd.aSections[i]);

//  for ( int i=0; i < qnumber(kd.aSections); i++ )
  ea_t slot = s_ioctl(1, NULL, 0, NULL, NULL);        // get slot number
  msg("SLOT=%a\n", slot);
  int i = int(slot >> 25);
  if ( !dump_section(i, kd.aSections[i]) )
    return;

  bool ce500 = s_ioctl(0, NULL, 0, NULL, NULL);        // GetVersionEx

  for ( int i=0; i < MAX_PROCESSES; i++ )
  {
    if ( ce500 )
    {
      win500_process_t p;
      if ( !myread(kd.aInfo[KINX_PROCARRAY]+i*sizeof(p), &p, sizeof(p)) )
        return;
      if ( !dump_process(p) )
        return;
    }
    else
    {
      win420_process_t p;
      if ( !myread(kd.aInfo[KINX_PROCARRAY]+i*sizeof(p), &p, sizeof(p)) )
        return;
      if ( !dump_process(p) )
        return;
    }
  }

//  for ( int i=0; i < qnumber(kd.alpeIntrEvents); i++ )
//    msg("INTR EVENT %2d: %08lX DATA %08lX\n", i, kd.alpeIntrEvents[i], kd.alpvIntrData[i]);
  msg("pAPIReturn  : %08lX\n", kd.pAPIReturn);
  msg("pMap        : %08lX\n", kd.pMap);
  msg("dwInDebugger: %08lX\n", kd.dwInDebugger);
  msg("pCurFPUOwner: %08lX\n", kd.pCurFPUOwner);
  msg("pCpuASIDPrc : %08lX\n", kd.pCpuASIDPrc);
  msg("nMemForPT   : %08lX\n", kd.nMemForPT);
//  for ( int i=0; i < qnumber(kd.alPad); i++ )
//    msg("PADDING %2d: %08lX\n", i, kd.alPad[i]);

  static const ce_name_info_t info_names[] =
  {
    { KINX_PROCARRAY,    "PROCARRAY"    },
    { KINX_PAGESIZE,     "PAGESIZE"     },
    { KINX_PFN_SHIFT,    "PFN_SHIFT"    },
    { KINX_PFN_MASK,     "PFN_MASK"     },
    { KINX_PAGEFREE,     "PAGEFREE"     },
    { KINX_SYSPAGES,     "SYSPAGES"     },
    { KINX_KHEAP,        "KHEAP"        },
    { KINX_SECTIONS,     "SECTIONS"     },
    { KINX_MEMINFO,      "MEMINFO"      },
    { KINX_MODULES,      "MODULES"      },
    { KINX_DLL_LOW,      "DLL_LOW"      },
    { KINX_NUMPAGES,     "NUMPAGES"     },
    { KINX_PTOC,         "PTOC"         },
    { KINX_KDATA_ADDR,   "KDATA_ADDR"   },
    { KINX_GWESHEAPINFO, "GWESHEAPINFO" },
    { KINX_TIMEZONEBIAS, "TIMEZONEBIAS" },
    { KINX_PENDEVENTS,   "PENDEVENTS"   },
    { KINX_KERNRESERVE,  "KERNRESERVE"  },
    { KINX_API_MASK,     "API_MASK"     },
    { KINX_NLS_CP,       "NLS_CP"       },
    { KINX_NLS_SYSLOC,   "NLS_SYSLOC"   },
    { KINX_NLS_USERLOC,  "NLS_USERLOC"  },
    { KINX_HEAP_WASTE,   "HEAP_WASTE"   },
    { KINX_DEBUGGER,     "DEBUGGER"     },
    { KINX_APISETS,      "APISETS"      },
    { KINX_MINPAGEFREE,  "MINPAGEFREE"  },
    { KINX_CELOGSTATUS,  "CELOGSTATUS"  },
    { KINX_NKSECTION,    "NKSECTION"    },
    { KINX_PWR_EVTS,     "PWR_EVTS"     },
    { KINX_NKSIG,        "NKSIG"        },
  };

  for ( int i=0; i < qnumber(kd.aInfo); i++ )
    msg("INFO %2d: %08lX %s\n", i, kd.aInfo[i], find_name(i, info_names, qnumber(info_names)));

  ea_t ea = kd.aInfo[KINX_MODULES];
  while ( ea != 0 )
  {
    wince_module_t wm;
    if ( !myread(ea, &wm, sizeof(wm)) )
      return;
    if ( ce500 )
    {
      win500_module_t &w500 = *(win500_module_t*)&wm;
      if ( !dump_module(w500) )
        return;
      ea = EA_T(w500.pMod);
    }
    else
    {
      win420_module_t &w420 = *(win420_module_t*)&wm;
      if ( !dump_module(w420) )
        return;
      ea = EA_T(w420.pMod);
    }
  }
  msg("KDATA DUMP COMPLETED\n");
};

//----------------------------------------------------------------------
void show_wince_rom(void)
{
  wince_romptr_t wrp;
  ea_t off = get_screen_ea();
  if ( !myread(off, &wrp, sizeof(wrp))
    || memcmp(wrp.magic, ROMPTR_MAGIC, 4) != 0 )
  {
    dump_kdata();
    return;
  }
  msg("EXEC @: %08lX MAGIC '%4.4s' OFFSET %08lX\n", off, wrp.magic, wrp.offset);
  off = wrp.offset;
  wince_romhdr_t wrh;
  if ( !myread(off, &wrh, sizeof(wrh)) )
    return;

  msg("dllfirst       : %08lX\n", wrh.dllfirst);
  msg("dlllast        : %08lX\n", wrh.dlllast);
  msg("physfirst      : %08lX\n", wrh.physfirst);
  msg("physlast       : %08lX\n", wrh.physlast);
  msg("nummods        : %d\n",    wrh.nummods);
  msg("ulRAMStart     : %08lX\n", wrh.ulRAMStart);
  msg("ulRAMFree      : %08lX\n", wrh.ulRAMFree);
  msg("ulRAMEnd       : %08lX\n", wrh.ulRAMEnd);
  msg("ulCopyEntries  : %08lX\n", wrh.ulCopyEntries);
  msg("ulCopyOffset   : %08lX\n", wrh.ulCopyOffset);
  msg("ulProfileLen   : %08lX\n", wrh.ulProfileLen);
  msg("ulProfileOffset: %08lX\n", wrh.ulProfileOffset);
  msg("numfiles       : %d\n",    wrh.numfiles);
  msg("ulKernelFlags  : %08lX\n", wrh.ulKernelFlags);
  if ( wrh.ulKernelFlags & WKF_NOPAGE ) msg("  Demand paging is disabled.\n");
  if ( wrh.ulKernelFlags & WKF_NOKERN ) msg("  Disable full-kernel mode.\n");
  if ( wrh.ulKernelFlags & WKF_TROROM ) msg("  Trust only modules from the ROM MODULES section.\n");
  if ( wrh.ulKernelFlags & WKF_NFSTLB ) msg("  Use this flag to stop flushing soft TLB (x86 only).\n");
  if ( wrh.ulKernelFlags & WKF_OKBASE ) msg("  Honor the /base linker setting for DLLs.\n");
  msg("ulFSRamPercent : %08lX\n", wrh.ulFSRamPercent);
  msg("ulDrivglobStart: %08lX\n", wrh.ulDrivglobStart);
  msg("ulDrivglobLen  : %08lX\n", wrh.ulDrivglobLen);
  msg("usCPUType      : %04X\n",  wrh.usCPUType);
  msg("usMiscFlags    : %04X\n",  wrh.usMiscFlags);
  msg("pExtensions    : %08lX\n", wrh.pExtensions);
  msg("ulTrackingStart: %08lX\n", wrh.ulTrackingStart);
  msg("ulTrackingLen  : %08lX\n", wrh.ulTrackingLen);
  off += sizeof(wrh);

  ea_t tocs = off;
  if ( wrh.nummods != 0 )
  {
    msg("\nMODULE ENTRIES\n");
    msg("#  Attrs         FileTime       Size     Name      e32      o32     load\n");
    msg("- -------- ------------------- -------- -------- -------- -------- --------\n");
    for ( int i=0; i < wrh.nummods; i++ )
    {
      toc_entry_t te;
      if ( !myread(tocs+i*sizeof(te), &te, sizeof(te)) )
        return;
      char ftime[32];
      msg("%d %08lX %19s %08lX %08lX %08lX %08lX %08lX",
          i,
          te.attrs,
          ftime2str(&te.time, ftime, sizeof(ftime)),
          te.size,
          te.name,
          te.e32,
          te.o32,
          te.load);
      char buf[MAXSTR];
      if ( !getstr(te.name, buf, sizeof(buf), false) )
        return;
      msg(" %s\n", buf);
    }
    off += sizeof(toc_entry_t)*wrh.nummods;
  }

  ea_t files = off;
  if ( wrh.numfiles != 0 )
  {
    msg("\nFILE ENTRIES\n");
    msg("#  Attrs         FileTime      RealSize CompSize   Name     load\n");
    msg("- -------- ------------------- -------- -------- -------- --------\n");
    for ( int i=0; i < wrh.numfiles; i++ )
    {
      file_entry_t fe;
      if ( !myread(files+i*sizeof(fe), &fe, sizeof(fe)) )
        return;
      char ftime[32];
      msg("%d %08lX %19s %08lX %08lX %08lX %08lX",
          i,
          fe.attrs,
          ftime2str(&fe.time, ftime, sizeof(ftime)),
          fe.realsize,
          fe.compsize,
          fe.name,
          fe.load);
      char buf[MAXSTR];
      if ( !getstr(fe.name, buf, sizeof(buf), false) )
        return;
      msg(" %s\n", buf);
    }
  }

  if ( wrh.ulCopyEntries != 0 )
  {
    msg("\nCOPY ENTRIES\n");
    msg("#  Source    Dest   CopyLen  DestLen\n");
    msg("- -------- -------- -------- --------\n");
    for ( int i=0; i < wrh.ulCopyEntries; i++ )
    {
      copy_entry_t ce;
      if ( !myread(wrh.ulCopyOffset+i*sizeof(ce), &ce, sizeof(ce)) )
        return;
      msg("%d %08lX %08lX %08lX %08lX\n",
          i,
          ce.source,
          ce.dest,
          ce.copylen,
          ce.destlen);
    }
  }

  if ( wrh.pExtensions != 0 )
  {
    msg("\nROM EXTENSIONS\n");
    msg("#   Type    DataPtr Length   Reserved           Name\n");
    msg("- -------- -------- -------- -------- ------------------------\n");
    ea_t ext = wrh.pExtensions;
    for ( int i=0; ext != 0; i++ )
    {
      romext_t re;
      if ( !myread(ext, &re, sizeof(re)) )
        return;
      msg("%d %08lX %08lX %08lX %08lX %24.24s\n",
        i,
        re.type,
        re.dataptr,
        re.length,
        re.reserved,
        re.name);
      ext = re.next;
    }
  }

  for ( int i=0; i < wrh.nummods; i++ )
  {
    toc_entry_t te;
    if ( !myread(tocs+i*sizeof(te), &te, sizeof(te)) )
        return;
    char buf[MAXSTR];
    if ( !getstr(te.name, buf, sizeof(buf), false) )
      return;
    msg("\n%d. MODULE %s\n", i, buf);
    e32_rom_t e32;
    if ( !myread(te.e32, &e32, sizeof(e32)) )
      return;
    dump_e32_rom(e32);
    if ( !dump_o32_roms(te.o32, e32.nobjs) )
      return;
  }
  msg("DUMP COMPLETED\n");
}

