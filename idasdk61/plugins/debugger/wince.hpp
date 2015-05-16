
#ifndef WINCE_HPP
#define WINCE_HPP

#include "../../ldr/pe/pe.h"

// Declared in pwinbase.h
extern "C" BOOL WINAPI AttachDebugger(LPCWSTR dbgname);

// The following functions are absent in Windows CE and
// we implement them ourselves:

WINBASEAPI SIZE_T WINAPI VirtualQueryEx(
                                        IN HANDLE /*hProcess*/,
                                        IN LPCVOID lpAddress,
                                        OUT PMEMORY_BASIC_INFORMATION lpBuffer,
                                        IN SIZE_T dwLength);

WINBASEAPI BOOL WINAPI VirtualProtectEx(
                                        IN  HANDLE hProcess,
                                        IN  LPVOID lpAddress,
                                        IN  SIZE_T dwSize,
                                        IN  DWORD flNewProtect,
                                        OUT PDWORD lpflOldProtect);

//--------------------------------------------------------------------------
struct wince_romptr_t
{
  uchar magic[4];
#define ROMPTR_MAGIC "ECEC"
  uint32 offset;
};

struct wince_romhdr_t
{
  uint32 dllfirst;           // First DLL address.
  uint32 dlllast;            // Last DLL address.
  uint32 physfirst;          // First physical address.
  uint32 physlast;           // Highest physical address.
  uint32 nummods;            // Number of TOC entries.
  uint32 ulRAMStart;         // Start of RAM.
  uint32 ulRAMFree;          // Start of RAM free space.
  uint32 ulRAMEnd;           // End of RAM.
  uint32 ulCopyEntries;      // Number of copy section entries.
  uint32 ulCopyOffset;       // Offset to the copy section.
  uint32 ulProfileLen;       // Length of profile entries in RAM.
  uint32 ulProfileOffset;    // Offset to the profile entries.
  uint32 numfiles;           // Number of files.
  uint32 ulKernelFlags;      // Optional kernel flags from the ROMFLAGS
                             // configuration option.
#define WKF_NOPAGE 0x00000001// Demand paging is disabled.
#define WKF_NOKERN 0x00000002// Disable full-kernel mode.
#define WKF_TROROM 0x00000010// Trust only modules from the ROM MODULES section.
#define WKF_NFSTLB 0x00000020// Use this flag to stop flushing soft TLB (x86 only).
#define WKF_OKBASE 0x00000040// Honor the /base linker setting for DLLs.
  uint32 ulFSRamPercent;     // Percentage of RAM used for the file system
                             // from the FSRAMPERCENT configuration option.
                             // Each byte represents the number of 4-KB blocks per MB
                             // allocated for the file system, as follows:
                             // byte 0 = # of 4-KB blocks per MB in the first two MB
                             // byte 1 = # of 4-KB blocks per MB in the second two MB
                             // byte 2 = # of 4-KB blocks per MB in the third two MB
                             // byte 3 = # of 4-KB blocks per MB in the remaining memory
  uint32 ulDrivglobStart;    // Device driver global starting address.
  uint32 ulDrivglobLen;      // Device driver global length.
  uint16 usCPUType;          // CPU type.
  uint16 usMiscFlags;        // Miscellaneous flags.
  uint32 pExtensions;        // Pointer to ROM header extensions.
  uint32 ulTrackingStart;    // Tracking memory starting address.
  uint32 ulTrackingLen;      // Tracking memory ending address.
};

// followed by wince_romhdr_t.nummods entries:
struct toc_entry_t           // MODULE BIB section structure
{
  uint32 attrs;
  FILETIME time;
  uint32 size;
  uint32 name;
  uint32 e32;                // Offset to E32 structure
  uint32 o32;                // Offset to O32 structure
  uint32 load;               // MODULE load buffer offset
};

// followed by wince_romhdr_t.numfiles entries:
struct file_entry_t          // FILES BIB section structure
{
  uint32 attrs;
  FILETIME time;
  uint32 realsize;           // real file size
  uint32 compsize;           // compressed file size
  uint32 name;
  uint32 load;               // FILES load buffer offset
};

// seems to be followed by this:
// (but copy entries have their own pointer in wince_romhdr_t)
struct copy_entry_t
{
  uint32 source;             // copy source address
  uint32 dest;               // copy destination address
  uint32 copylen;            // copy length
  uint32 destlen;            // copy destination length
                             // (zero fill to end if > ulCopyLen)
};

// pointed to by wince_romhdr_t.pExtensions
struct romext_t
{
  char  name[24];
  uint32 type;
  uint32 dataptr;
  uint32 length;
  uint32 reserved;
  uint32 next;               // pointer to next extension if any
};


// pointed by toc_entry_t.e32
struct e32_rom_t
{
  uint16  nobjs;             // Number of memory objects
  uint16  flags;             // Image flags
  uint32  entry;             // Relative virt. addr. of entry point
  uint32  vbase;             // Virtual base address of module
  uint16  subsysmajor;       // The subsystem major version number
  uint16  subsysminor;       // The subsystem minor version number

  uint32  stackmax;          // Maximum stack size
  uint32  vsize;             // Virtual size of the entire image
  uint32  sect14rva;         // section 14 rva
  uint32  sect14size;        // section 14 size

  petab_t unit[9];           // Array of extra info units
  uint16  subsys;            // The subsystem type
};

// pointed by toc_entry_t.o32, e32.nobjs objects of this type
struct o32_rom_t
{
  uint32 vsize;              // Virtual memory size
  uint32 rva;                // Object relative virtual address
  uint32 psize;              // Physical file size of init. data
  uint32 dataptr;            // Image pages offset
  uint32 realaddr;           // pointer to actual
  uint32 flags;              // Attribute flags for the object
#define IMAGE_SCN_CNT_CODE               0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080  // Section contains uninitialized data.
#define IMAGE_SCN_LNK_INFO               0x00000200  // Section contains comments or some other type of information.
#define IMAGE_SCN_LNK_REMOVE             0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT             0x00001000  // Section contents comdat.
#define IMAGE_SCN_COMPRESSED             0x00002000  // Section is compressed
#define IMAGE_SCN_NO_DEFER_SPEC_EXC      0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                  0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA            0x00008000
#define IMAGE_SCN_MEM_PURGEABLE          0x00020000
#define IMAGE_SCN_MEM_16BIT              0x00020000
#define IMAGE_SCN_MEM_LOCKED             0x00040000
#define IMAGE_SCN_MEM_PRELOAD            0x00080000
#define IMAGE_SCN_LNK_NRELOC_OVFL        0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED         0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED          0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED             0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE            0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ               0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE              0x80000000  // Section is writeable.
};

struct xipchain_entry_t
{
  LPVOID pvAddr;             // Address of the XIP region.
  DWORD dwLength;            // Specifies the size of the XIP region.
  DWORD dwMaxLength;         // Specifies the maximum size of the XIP region.
  USHORT usOrder;            // Order of the entries to be used when ROMChain_t is filled in by the OEM.
  USHORT usFlags;            // Flag or status of the XIP region.
#define ROMXIP_OK_TO_LOAD 1  // Load the XIP region.
#define ROMXIP_IS_SIGNED  2  // The XIP regions are signed.
  DWORD dwVersion;           // Specifies the version number of the region.
#define XIP_NAMELEN  32      // max name length of XIP
  CHAR szName[XIP_NAMELEN];  // Name of the XIP region, which is typically the .bin
                             // file's name without the .bin suffix.
  DWORD dwAlgoFlags;         // Specifies the algorithm to use for signature verification.
  DWORD dwKeyLen;            // Specifies the length of the byPublicKey key.
  BYTE byPublicKey[596];     // Public key data used to verify the XIP region.
};

// the following information comes from http://www.xfocus.net/articles/200411/747.html
typedef struct PROCESS *PPROCESS;
typedef struct THREAD *PTHREAD;
typedef struct EVENT *LPEVENT;
typedef struct PROXY *LPPROXY;
typedef uint32 ACCESSKEY;
typedef void *LPName;
typedef void *PMODULELIST;
#ifndef UNDER_CE
typedef enum _EXCEPTION_DISPOSITION (WINAPI *PEXCEPTION_ROUTINE)(
                struct _EXCEPTION_RECORD*,void*,struct _CONTEXT*,void*);
typedef struct DBGPARAM *LPDBGPARAM;
typedef DWORD CEOID;
#endif

#define VA_BLOCK        16
#define VA_SECTION      25
#define BLOCK_MASK      0x1FF
#define PAGE_SIZE       4096

#if PAGE_SIZE == 4096
  #define VA_PAGE       12
  #define PAGE_MASK     0x00F
#elif PAGE_SIZE == 2048
  #define VA_PAGE       11
  #define PAGE_MASK     0x01F
#elif PAGE_SIZE == 1024
  #define VA_PAGE       10
  #define PAGE_MASK     0x03F
#else
  #error "Unsupported Page Size"
#endif

struct wince_memblock_t
{
  uint32 alk;             // 00: key code for this set of pages
  uchar  cUses;           // 04: # of page table entries sharing this leaf
  uchar  flags;           // 05: mapping flags
  short  ixBase;          // 06: first block in region
  short  hPf;             // 08: handle to pager
  short  cLocks;          // 0a: lock count
  uint32 *aPages;         // 0c: pointer to the VA of hardware page table
};

typedef wince_memblock_t MEMBLOCK;
#define RESERVED_BLOCK  ((wince_memblock_t*)1)
#define NULL_BLOCK      ((wince_memblock_t*)0)

typedef wince_memblock_t *SECTION[0x200];


#define KDataStructAddr 0xFFFFC800

struct KDataStruct
{
  LPDWORD lpvTls;         // 0x000 Current thread local storage pointer
#define NUM_SYS_HANDLES 32
  HANDLE  ahSys[NUM_SYS_HANDLES]; // 0x004 If this moves, change kapi.h
#define SH_WIN32                0
#define SH_CURTHREAD            1
#define SH_CURPROC              2
#define SH_KWIN32               3       // OBSOLETE
#define SH_GDI                  16
#define SH_WMGR                 17
#define SH_WNET                 18      // WNet APIs for network redirector
#define SH_COMM                 19      // Communications not "COM"
#define SH_FILESYS_APIS         20      // File system APIS
#define SH_SHELL                21
#define SH_DEVMGR_APIS          22      // File system device manager
#define SH_TAPI                 23
#define SH_PATCHER              24
#define SH_SERVICES             26

  char    bResched;       // 0x084 reschedule flag
  char    cNest;          // 0x085 kernel exception nesting
  char    bPowerOff;      // 0x086 TRUE during "power off" processing
  char    bProfileOn;     // 0x087 TRUE if profiling enabled
  uint32  unused;         // 0x088 unused
  uint32  rsvd2;          // 0x08c was DiffMSec
  PPROCESS pCurPrc;       // 0x090 ptr to current PROCESS struct
  PTHREAD pCurThd;        // 0x094 ptr to current THREAD struct
  DWORD   dwKCRes;        // 0x098
  uint32  handleBase;     // 0x09c handle table base address
  SECTION *aSections[64]; // 0x0a0 section table for virutal memory
#define SYSINTR_MAX_DEVICES 32
  LPEVENT alpeIntrEvents[SYSINTR_MAX_DEVICES];// 0x1a0
  LPVOID  alpvIntrData[SYSINTR_MAX_DEVICES];  // 0x220
  uint32  pAPIReturn;     // 0x2a0 direct API return address for kernel mode
  uchar   *pMap;          // 0x2a4 ptr to MemoryMap array
  DWORD   dwInDebugger;   // 0x2a8 !0 when in debugger
  PTHREAD pCurFPUOwner;   // 0x2ac current FPU owner
  PPROCESS pCpuASIDPrc;   // 0x2b0 current ASID proc
  int32   nMemForPT;      // 0x2b4 - Memory used for PageTables

  int32   alPad[18];      // 0x2b8 - padding
  DWORD   aInfo[32];      // 0x300 - misc. kernel info
  // PUBLIC/COMMON/OAK/INC/pkfuncs.h
#define KINX_PROCARRAY    ((0x300-0x300)/4) //  address of process array
#define KINX_PAGESIZE     ((0x304-0x300)/4) //  system page size
#define KINX_PFN_SHIFT    ((0x308-0x300)/4) //  shift for page # in PTE
#define KINX_PFN_MASK     ((0x30c-0x300)/4) //  mask for page # in PTE
#define KINX_PAGEFREE     ((0x310-0x300)/4) //  # of free physical pages
#define KINX_SYSPAGES     ((0x314-0x300)/4) //  # of pages used by kernel
#define KINX_KHEAP        ((0x318-0x300)/4) //  ptr to kernel heap array
#define KINX_SECTIONS     ((0x31c-0x300)/4) //  ptr to SectionTable array
#define KINX_MEMINFO      ((0x320-0x300)/4) //  ptr to system MemoryInfo struct
#define KINX_MODULES      ((0x324-0x300)/4) //  ptr to module list
#define KINX_DLL_LOW      ((0x328-0x300)/4) //  lower bound of DLL shared space
#define KINX_NUMPAGES     ((0x32c-0x300)/4) //  total # of RAM pages
#define KINX_PTOC         ((0x330-0x300)/4) //  ptr to ROM table of contents
#define KINX_KDATA_ADDR   ((0x334-0x300)/4) //  kernel mode version of KData
#define KINX_GWESHEAPINFO ((0x338-0x300)/4) //  Current amount of gwes heap in use
#define KINX_TIMEZONEBIAS ((0x33c-0x300)/4) //  Fast timezone bias info
#define KINX_PENDEVENTS   ((0x340-0x300)/4) //  bit mask for pending interrupt events
#define KINX_KERNRESERVE  ((0x344-0x300)/4) //  number of kernel reserved pages
#define KINX_API_MASK     ((0x348-0x300)/4) //  bit mask for registered api sets
#define KINX_NLS_CP       ((0x34c-0x300)/4) //  hiword OEM code page, loword ANSI code page
#define KINX_NLS_SYSLOC   ((0x350-0x300)/4) //  Default System locale
#define KINX_NLS_USERLOC  ((0x354-0x300)/4) //  Default User locale
#define KINX_HEAP_WASTE   ((0x358-0x300)/4) //  Kernel heap wasted space
#define KINX_DEBUGGER     ((0x35c-0x300)/4) //  For use by debugger for protocol communication
#define KINX_APISETS      ((0x360-0x300)/4) //  APIset pointers
#define KINX_MINPAGEFREE  ((0x364-0x300)/4) //  water mark of the minimum number of free pages
#define KINX_CELOGSTATUS  ((0x368-0x300)/4) //  CeLog status flags
#define KINX_NKSECTION    ((0x36c-0x300)/4) //  Address of NKSection
#define KINX_PWR_EVTS     ((0x370-0x300)/4) //  Events to be set after power on
#define KINX_NKSIG        ((0x37c-0x300)/4) //  last entry of KINFO -- signature when NK is ready

      /* 0x380 - interlocked api code */
      /* 0x400 - end */
};


struct openexe_t
{
  union
  {
    int hppfs;             // ppfs handle
    HANDLE hf;             // object store handle
    toc_entry_t *tocptr;   // rom entry pointer
  };                       // 0x64
  BYTE filetype;           // 0x68
  BYTE bIsOID;             // 0x69
  WORD pagemode;           // 0x6a
  union
  {
    DWORD offset;
    DWORD dwExtRomAttrib;
  };                       // 0x6c
  union
  {
    char *lpName;
    CEOID ceOid;
  };                       // 0x70
};

struct PGPOOL_Q
{
  WORD    idxHead;            // head of the queue
  WORD    idxTail;            // tail of the queue
};

struct common_e32_lite
{
  ushort objcnt;      // 0x74 Number of memory objects
  uchar cevermajor;   // 0x76 version of CE built for
  uchar ceverminor;   // 0x77 version of CE built for
  uint32 stackmax;    // 0x78 Maximum stack size
  uint32 vbase;       // 0x7c Virtual base address of module
  uint32 vsize;       // 0x80 Virtual size of the entire image
  uint32 sect14rva;   // 0x84 section 14 rva
  uint32 sect14size;  // 0x88 section 14 size
};

struct win420_e32_lite : public common_e32_lite
{
  petab_t unit[6];     // 0x8c  Array of extra info units
#define E32_LITE_EXP 0 // Export table position
#define E32_LITE_IMP 1 // Import table position
#define E32_LITE_RES 2 // Resource table position
#define E32_LITE_EXC 3 // Exception table position
#define E32_LITE_SEC 4 // Security table position
#define E32_LITE_FIX 5 // Fixup table position
#define E32_LITE_DEB 6 // Debug table position
};

struct win500_e32_lite : public common_e32_lite
{
  uint32 timestamp;   // 0x8c time stamp?
  petab_t unit[7];    // 0x90  Array of extra info units
};

typedef uint32 wince_e32_lite[sizeof(win500_e32_lite)/4];

struct o32_lite
{
  uint32 vsize;
  uint32 rva;
  uint32 realaddr;
  uint32 access;
  uint32 flags;
  uint32 psize;
  uint32 dataptr;
};

struct win420_module_t
{
  LPVOID      lpSelf;                 // 0x00 Self pointer for validation
  win420_module_t *pMod;              // 0x04 Next module in chain
  LPWSTR      lpszModName;            // 0x08 Module name
  DWORD       inuse;                  // 0x0c Bit vector of use
  DWORD       calledfunc;             // 0x10 Called entry but not exit
#define MAX_PROCESSES 32
  WORD        refcnt[MAX_PROCESSES];  // 0x14 Reference count per process
  LPVOID      BasePtr;                // 0x54 Base pointer of dll load (not 0 based)
  DWORD       DbgFlags;               // 0x58 Debug flags
  LPDBGPARAM  ZonePtr;                // 0x5c Debug zone pointer
  uint32      startip;                // 0x60 0 based entrypoint
  openexe_t   oe;                     // 0x64 Pointer to executable file handle
  win420_e32_lite e32;                // 0x74 E32 header
  o32_lite   *o32_ptr;                // 0xbc O32 chain ptr
  DWORD       dwNoNotify;             // 0xc0 1 bit per process, set if notifications disabled
  WORD        wFlags;                 // 0xc4
  BYTE        bTrustLevel;            // 0xc6
  BYTE        bPadding;               // 0xc7
  win420_module_t *pmodResource;      // 0xc8 module that contains the resources
  DWORD       rwLow;                  // 0xcc base address of RW section for ROM DLL
  DWORD       rwHigh;                 // 0xd0 high address RW section for ROM DLL
  PGPOOL_Q    pgqueue;                // 0xd4 list of the page owned by the module
};

struct win500_module_t
{
  LPVOID      lpSelf;                 // 0x00 Self pointer for validation
  win500_module_t *pMod;              // 0x04 Next module in chain
  LPWSTR      lpszModName;            // 0x08 Module name
  DWORD       inuse;                  // 0x0c Bit vector of use
  WORD        refcnt[MAX_PROCESSES];  // 0x10 Reference count per process
  LPVOID      BasePtr;                // 0x50 Base pointer of dll load (not 0 based)
  DWORD       DbgFlags;               // 0x54 Debug flags
  LPDBGPARAM  ZonePtr;                // 0x58 Debug zone pointer
  uint32      startip;                // 0x5c 0 based entrypoint
  openexe_t   oe;                     // 0x60 Pointer to executable file handle
  win500_e32_lite e32;                // 0x70 E32 header
  o32_lite   *o32_ptr;                // 0x   O32 chain ptr
  DWORD       dwNoNotify;             // 0x   1 bit per process, set if notifications disabled
  WORD        wFlags;                 // 0x
  BYTE        bTrustLevel;            // 0x
  BYTE        bPadding;               // 0x
  win500_module_t *pmodResource;      // 0x   module that contains the resources
  DWORD       rwLow;                  // 0x   base address of RW section for ROM DLL
  DWORD       rwHigh;                 // 0x   high address RW section for ROM DLL
  PGPOOL_Q    pgqueue;                // 0x   list of the page owned by the module
  LPVOID      pShimInfo;              // 0x   pointer to shim information
};

typedef uint32 wince_module_t[sizeof(win500_module_t)/4];

#define HARDWARE_PT_PER_PROC 8

struct win420_process_t
{
  BYTE        procnum;        /* 00: ID of this process [ie: it's slot number] */
  BYTE        DbgActive;      /* 01: ID of process currently DebugActiveProcess'ing this process */
  BYTE        bChainDebug;    /* 02: Did the creator want to debug child processes? */
  BYTE        bTrustLevel;    /* 03: level of trust of this exe */
#define OFFSET_TRUSTLVL     3   // offset of the bTrustLevel member in Process structure
  LPPROXY     pProxList;      /* 04: list of proxies to threads blocked on this process */
  HANDLE      hProc;          /* 08: handle for this process, needed only for SC_GetProcFromPtr */
  DWORD       dwVMBase;       /* 0C: base of process's memory section, or 0 if not in use */
  PTHREAD     pTh;            /* 10: first thread in this process */
  ACCESSKEY   aky;            /* 14: default address space key for process's threads */
  LPVOID      BasePtr;        /* 18: Base pointer of exe load */
  HANDLE      hDbgrThrd;      /* 1C: handle of thread debugging this process, if any */
  LPWSTR      lpszProcName;   /* 20: name of process */
  DWORD       tlsLowUsed;     /* 24: TLS in use bitmask (first 32 slots) */
  DWORD       tlsHighUsed;    /* 28: TLS in use bitmask (second 32 slots) */
  PEXCEPTION_ROUTINE pfnEH;   /* 2C: process exception handler */
  LPDBGPARAM  ZonePtr;        /* 30: Debug zone pointer */
  PTHREAD     pMainTh;        /* 34  primary thread in this process*/
  wince_module_t *pmodResource;   /* 38: module that contains the resources */
  LPName      pStdNames[3];   /* 3C: Pointer to names for stdio */
  LPCWSTR     pcmdline;       /* 48: Pointer to command line */
  DWORD       dwDyingThreads; /* 4C: number of pending dying threads */
  openexe_t   oe;             /* 50: Pointer to executable file handle */
  win420_e32_lite e32;        /* ??: structure containing exe header */
  o32_lite    *o32_ptr;       /* ??: o32 array pointer for exe */
  LPVOID      pExtPdata;      /* ??: extend pdata */
  BYTE        bPrio;          /* ??: highest priority of all threads of the process */
  BYTE        fNoDebug;       /* ??: this process cannot be debugged */
  WORD        wPad;           /* padding */
  PGPOOL_Q    pgqueue;        /* ??: list of the page owned by the process */
#if HARDWARE_PT_PER_PROC
  uint32      pPTBL[HARDWARE_PT_PER_PROC];   /* hardware page tables */
#endif
};

struct win500_process_t
{
  BYTE        procnum;        /* 00: ID of this process [ie: it's slot number] */
  BYTE        DbgActive;      /* 01: ID of process currently DebugActiveProcess'ing this process */
  BYTE        bChainDebug;    /* 02: Did the creator want to debug child processes? */
  BYTE        bTrustLevel;    /* 03: level of trust of this exe */
  LPPROXY     pProxList;      /* 04: list of proxies to threads blocked on this process */
  HANDLE      hProc;          /* 08: handle for this process, needed only for SC_GetProcFromPtr */
  DWORD       dwVMBase;       /* 0C: base of process's memory section, or 0 if not in use */
  PTHREAD     pTh;            /* 10: first thread in this process */
  ACCESSKEY   aky;            /* 14: default address space key for process's threads */
  LPVOID      BasePtr;        /* 18: Base pointer of exe load */
  HANDLE      hDbgrThrd;      /* 1C: handle of thread debugging this process, if any */
  LPWSTR      lpszProcName;   /* 20: name of process */
  DWORD       tlsLowUsed;     /* 24: TLS in use bitmask (first 32 slots) */
  DWORD       tlsHighUsed;    /* 28: TLS in use bitmask (second 32 slots) */
  PEXCEPTION_ROUTINE pfnEH;   /* 2C: process exception handler */
  LPDBGPARAM  ZonePtr;        /* 30: Debug zone pointer */
  PTHREAD     pMainTh;        /* 34  primary thread in this process*/
  wince_module_t *pmodResource;   /* 38: module that contains the resources */
  LPName      pStdNames[3];   /* 3C: Pointer to names for stdio */
  LPCWSTR     pcmdline;       /* 48: Pointer to command line */
  DWORD       dwDyingThreads; /* 4C: number of pending dying threads */
  openexe_t   oe;             /* 50: Pointer to executable file handle */
  win500_e32_lite e32;        /* ??: structure containing exe header */
  o32_lite    *o32_ptr;       /* ??: o32 array pointer for exe */
  LPVOID      pExtPdata;      /* ??: extend pdata */
  BYTE        bPrio;          /* ??: highest priority of all threads of the process */
  BYTE        fNoDebug;       /* ??: this process cannot be debugged */
  WORD        wModCount;      /* ??: # of modules in pLastModList */
  PGPOOL_Q    pgqueue;        /* ??: list of the page owned by the process */
  PMODULELIST pLastModList;   /* ??: the list of modules that just loaded/unloaded into the process */
  HANDLE      hTok;           /* ??: process default token */
#if HARDWARE_PT_PER_PROC
  uint32      pPTBL[HARDWARE_PT_PER_PROC];   /* hardware page tables */
#endif
  LPVOID      pShimInfo;      /* pointer to shim information */
};

// different definitions for local and remote parts:
bool myread(ea_t ea, void *buf, size_t bufsize);
//----------------------------------------------------------------------
inline bool getstr(ea_t ea, char *buf, size_t bufsize, bool is_unicode)
{
  while ( bufsize > 0 )
  {
    buf[0] = '\0';
    ea_t mea = (ea + 4096) & ~4095;       // page boundary
    size_t toread = mea - ea;
    if ( bufsize < toread )
      toread = bufsize;
    if ( !myread(ea, buf, toread) )
      break;
    if ( is_unicode )
    {
      size_t n = toread / 2;
      char *p1 = buf;
      char *p2 = buf;
      for ( size_t i=0; i < n; i++,p2++ )
        *p1++ = *p2++;
    }
    // did we get the string including the final zero?
    for ( int i=0; i < toread; i++ )
      if ( buf[i] == '\0' )
        return true;
    // nope
    buf += toread;
    ea += toread;
    bufsize -= toread;
  }
  return false;
}

extern ea_t slot;

//--------------------------------------------------------------------------
inline ea_t pstos0(ea_t ea)        // map process slot to slot 0
{
  if ( (ea & 0xFE000000) == slot ) // redirect our process addresses
    ea  &= ~0xFE000000;            // to slot 0
  return ea;
}

//--------------------------------------------------------------------------
inline ea_t s0tops(ea_t ea)        // map slot 0 to the process slot
{
  if ( (ea & 0xFE000000) == 0 )
    ea |= slot;
  return ea;
}

ea_t get_process_slot(HANDLE phandle);
bool find_module_by_name(const char *name, wince_module_t *wm);

#endif // WINCE_HPP
