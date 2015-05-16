/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PRODIR_H
#define _PRODIR_H
#pragma pack(push, 1)

//
//      This file contains unified interface to qfindfirst/qfindnext/qfindclose
//      functions.
//
//      These are low level functions, it is better to use enumerate_files()
//      from diskio.hpp
//

#if defined(__MSDOS__) || defined(__OS2__) || defined(__NT__)
#define __FAT__
#define SDIRCHAR "\\"
#define DIRCHAR '\\'
#define DRVCHAR ':'
#else
#define SDIRCHAR "/"
#define DIRCHAR '/'
#endif

#define EXTCHAR '.'     // extension character is '.' for all systems

//----------------------------------------------------------------------------
// The follwing fields of qffblk_t structure may be used:
//      ff_name         file path
//      ff_fsize        file size
//      ff_attrib       file attribute
//      ff_ftime        file time stamp (ms dos fat format)
//      ff_fdate        file date stamp (ms dos fat format)
#if defined(__UNIX__)
  #define MAXPATH   QMAXPATH
  struct qffblk_t                        // Unix
  {
    // user fields:
    int ff_attrib;
      #define FA_DIREC S_IFDIR
      #define FA_ARCH   0
      #define FA_RDONLY 0
    char ff_name[QMAXPATH];
    uint32 ff_fsize;
    uint16 ff_fdate;
    uint16 ff_ftime;
    // private fields:
    void *filelist;
    int fileidx, fileqty;
    char dirpath[QMAXPATH];
    char pattern[QMAXPATH];
    int attr;
  };
#elif defined (__X64__)
  #define MAXPATH   _MAX_PATH
  struct qffblk_t : public __finddata64_t  // Win64 - use Visual Studio's ffblk
  {
    intptr_t handle;
    int attr;
      #define FA_RDONLY   0x01
      #define FA_DIREC    0x10
      #define FA_ARCH     0x20
    #define ff_name   name
    #define ff_attrib attrib
    #define ff_fsize  size
    unsigned short ff_ftime;
    unsigned short ff_fdate;
  };
#elif defined(UNDER_CE)
  #include <windows.h>
  #define MAXPATH   MAX_PATH
  struct qffblk_t : public WIN32_FIND_DATA // WinCE
  {
    HANDLE handle;
    char ff_name[QMAXPATH];
    #define ff_attrib           dwFileAttributes
      #define FA_RDONLY   0x01
      #define FA_DIREC    0x10
      #define FA_ARCH     0x20
    #define ff_fsize            nFileSizeLow
    unsigned short ff_ftime;
    unsigned short ff_fdate;
    int attr;
  };
#else
  #define MAXPATH   260
  struct qffblk_t                       // Win32 - use Borland's ffblk
  {
    long           ff_reserved;
    long           ff_fsize;
    unsigned long  ff_attrib;
      #define FA_RDONLY   0x01
      #define FA_DIREC    0x10
      #define FA_ARCH     0x20
    unsigned short ff_ftime;
    unsigned short ff_fdate;
    char           ff_name[MAXPATH];
  };
#endif

#if defined(__UNIX__)
  #define MAXDRIVE              QMAXPATH
  #define MAXDIR                QMAXPATH
  #define MAXFILE               QMAXPATH
  #define MAXEXT                QMAXPATH
#elif !defined(__BORLANDC__)
  #define MAXDRIVE              _MAX_DRIVE
  #define MAXDIR                _MAX_DIR
  #define MAXFILE               _MAX_FNAME
  #define MAXEXT                _MAX_EXT
#endif

// Find first file that matches the pattern
//      pattern - file name pattern, usually with * and ? wildcards
//      blk     - structure that will hold the answer
//                blk->ff_name will hold the file name, for example
//      attr    - the desired file types (FA_DIREC or 0)
// Returns: 0 if found a file, other values mean error

idaman THREAD_SAFE int ida_export qfindfirst(const char *pattern, qffblk_t *blk, int attr);


// Find next file that matches the pattern
//      blk     - structure that holds the current state
//                blk->ff_name will hold the next file name upon return
// Returns: 0 if found the next file, other values mean error

idaman THREAD_SAFE int ida_export qfindnext(qffblk_t *blk);

// Stop the file enumeration and free internal structures
//      blk     - file enumeration structure

idaman THREAD_SAFE void ida_export qfindclose(qffblk_t *blk);


#ifndef NO_OBSOLETE_FUNCS
#define ffblk                    qffblk_t
#define findfirst(file,blk,attr) qfindfirst(file,blk,attr)
#define findnext(blk)            qfindnext(blk)
#define findclose(blk)           qfindclose(blk)
#endif

#pragma pack(pop)
#endif // _PRODIR_H
