/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _DISKIO_HPP
#define _DISKIO_HPP
#pragma pack(push, 1)

//
//      This file contains file I/O functions for IDA.
//      You should not use standard C file I/O functions in modules.
//      Use functions from this header, pro.h and fpro.h instead.
//
//      Also this file declares a call_system() function.
//

#include <stdio.h>

//-------------------------------------------------------------------------
//      S E A R C H   F O R   F I L E S
//-------------------------------------------------------------------------


// Get IDA directory (if subdir==NULL)
// or the specified subdirectory

idaman THREAD_SAFE const char *ida_export idadir(const char *subdir);


// Search for IDA system file
// This function searches for a file in
//  1. get_user_idadir() subdirectory
//  2. ida (sub)directory
//  3. current directory
//      filename - name of file to search
// returns: NULL-not found, otherwise - pointer to full file name
// if the subdir is specified, the file is looked in the specified subdirectory
// of the ida directory first


idaman THREAD_SAFE char *ida_export getsysfile(
        char *buf,
        size_t bufsize,
        const char *filename,
        const char *subdir);

#define CFG_SUBDIR "cfg"
#define IDC_SUBDIR "idc"
#define IDS_SUBDIR "ids"
#define IDP_SUBDIR "procs"
#define LDR_SUBDIR "loaders"
#define SIG_SUBDIR "sig"
#define TIL_SUBDIR "til"
#define PLG_SUBDIR "plugins"

// Get user ida related directory
// Under Linux: $HOME/.ida
// Under Windows: Application Data\Hex-Rays\IDA Pro
// If the directory did not exist, it will be created

idaman THREAD_SAFE const char *ida_export get_user_idadir(void);


// enumerate files in the specified directory
// while func() returns 0
//      answer  - buffer to contain the file name for which func()!=0
//                (answer may be == NULL)
//      answer_size - size of 'answer'
//      path    - directory to enumerate files in
//      fname   - mask of file names to enumerate
//      func    - callback function called for each file
//                      file - full file name (with path)
//                      ud   - user data
//                if 'func' returns non-zero value, the enumeration
//                is stopped and the return code is
//                is returned to the caller.
//      ud      - user data. this pointer will be passed to
//                the callback function
// returns zero or the code returned by func()

idaman THREAD_SAFE int ida_export enumerate_files(
        char *answer,
        size_t answer_size,
        const char *path,
        const char *fname,
        int (idaapi*func)(const char *file,void *ud),
        void *ud);


// enumerate IDA system files
// while func() returns 0
//      answer  - buffer to contain the file name for which func()!=0
//                (answer may be == NULL)
//      answer_size - size of 'answer'
//      subdir  - IDA subdirectory or NULL
//      fname   - mask of file names to enumerate
//      func    - callback function called for each file
//                      file - full file name (with path)
//                      ud   - user data
//                if 'func' returns non-zero value, the enumeration
//                is stopped and full path of the current file
//                is returned to the caller.
//      ud      - user data. this pointer will be passed to
//                the callback function
// returns zero or the code returned by func()

inline THREAD_SAFE int idaapi enumerate_system_files(
       char *answer,
       size_t answer_size,
       const char *subdir,
       const char *fname,
       int (idaapi*func)(const char *file,void *ud),
       void *ud)
{
  return enumerate_files(answer, answer_size, idadir(subdir), fname, func, ud);
}

//-------------------------------------------------------------------------
//      O P E N / R E A D / W R I T E / C L O S E   F I L E S
//-------------------------------------------------------------------------

//      There are two sets of "open file" functions.
//      The first set tries to open a file and returns: success or failure
//      The second set is "open or die": if the file cannot be opened
//      then the function will display an error message and exit.


// Open a new file for write in text mode, deny write
// If a file exists, it will be removed.
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenWT(const char *file);


// Open a new file for write in binary mode, deny read/write
// If a file exists, it will be removed.
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenWB(const char *file);


// Open a file for read in text mode, deny write
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenRT(const char *file);


// Open a file for read in binary mode, deny write
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenRB(const char *file);


// Open a file for read/write in binary mode, deny write
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenM(const char *file);


// Open a file for append in text mode, deny none
// returns: NULL-failure

idaman THREAD_SAFE FILE *ida_export fopenA(const char *file);


// Open a file for read in binary mode or die, deny write
// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openR(const char *file);


// Open a file for read in text mode or die, deny write
// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openRT(const char *file);


// Open a file for read/write in binary mode or die, deny read/write
// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export openM(const char *file);


// Open a new file for write in binary mode or die, deny read/write
// If a file exists, it will be removed.
// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export ecreate(const char *file);


// Open a new file for write in text mode or die, deny read/write
// If a file exists, it will be removed.
// If a file cannot be opened, this function displays a message and exits.

idaman THREAD_SAFE FILE *ida_export ecreateT(const char *file);


// Close a file or die.
// If a file cannot be closed, this function displays a message and exits.

idaman THREAD_SAFE void ida_export eclose(FILE *fp);


// Read from file or die.
//      fp   - pointer to file
//      buf  - buffer to read in
//      size - number of bytes to read
// If a read error occurs, this function displays a message and exits.

idaman THREAD_SAFE void ida_export eread(FILE *fp, void *buf, ssize_t size);


// Write to file or die.
//      fp   - pointer to file
//      buf  - buffer to write
//      size - number of bytes to write
// If a write error occurs, this function displays a message and exits.

idaman THREAD_SAFE void ida_export ewrite(FILE *fp, const void *buf, ssize_t size);


// Position in the file or die.
//      fp   - pointer to file
//      pos  - absolute position in the file
// If an error occurs, this function displays a message and exits.

idaman THREAD_SAFE void ida_export eseek(FILE *fp, int32 pos);


//-------------------------------------------------------------------------
//      F I L E   S I Z E   /   D I S K   S P A C E
//-------------------------------------------------------------------------

// Get length of file in bytes
//      fp   - pointer to file

idaman THREAD_SAFE uint32 ida_export efilelength(FILE *fp);


// Change size of file or die.
//      fp   - pointer to file
//      size - new size of file
// If the file is expanded, it is expanded with zero bytes.
// If an error occurs, this function displays a message and exits.

idaman THREAD_SAFE void ida_export echsize(FILE *fp,uint32 size);


// Get free disk space in bytes
//      path - name of any directory on the disk to get information about

idaman THREAD_SAFE uint64 ida_export getdspace(const char *path);


//-------------------------------------------------------------------------
//      I / O  P O R T  D E F I N I T I O N S  F I L E
//-------------------------------------------------------------------------
struct ioport_bit_t
{
  char *name;           // name of the bit (attention: may be NULL!)
  char *cmt;            // comment
};

typedef ioport_bit_t ioport_bits_t[16];

struct ioport_t
{
  ea_t address;         // address of the port
  char *name;           // name of the port
  char *cmt;            // comment
  ioport_bits_t *bits;  // bit names
  void *userdata;       // arbitrary data. initialized by NULL.
};

// read i/o port definitions from a config file
//      _numports - place to put the number of ports
//      file      - config file name
//      default_device - contains device name to load. If default_device[0] == 0
//                  then the default device is determined by .default directive
//                  in the config file
//      dsize     - sizeof(default_device)
//      callback  - callback to call when the input line can't be parsed normally
//                    line - input line to parse
//                  returns error message. if NULL, then the line is parsed ok.
// returns: array of ioports
// The format of the input file:
// ; each device definition begins with a line like this:
// ;
// ;       .devicename
// ;
// ;  after it go the port definitions in this format:
// ;
// ;       portname        address
// ;
// ;  the bit definitions (optional) are represented like this:
// ;
// ;       portname.bitname  bitnumber
// ;
// ; lines beginning with a space are ignored.
// ; comment lines should be started with ';' character.
// ;
// ; the default device is specified at the start of the file
// ;
// ;       .default device_name
// ;
// ; all lines non conforming to the format are passed to the callback function
// It is allowed to have a symbol mapped to several addresses
// but all addresses must be unique

idaman THREAD_SAFE ioport_t *ida_export read_ioports(
        size_t *_numports,
        const char *file,
        char *default_device,
        size_t dsize,
        const char *(idaapi* callback)(
                const ioport_t *ports,
                size_t numports,
                const char *line));

// Allow the user to choose the ioport device
//      file      - config file name
//      device    - in: contains default device name. If default_device[0] == 0
//                  then the default device is determined by .default directive
//                  in the config file
//                  out: the selected device name
//      device_size - size of the 'device' buffer
//      parse_params - if present (non NULL), then defines a callback which
//                  will be called for all lines not starting with a dot (.)
//                  This callback may parse these lines are prepare a simple
//                  processor parameter string. This string will be displayed
//                  along with the device name.
//                  if it returns IOPORT_SKIP_DEVICE, then the current
//                  device will not be included in the list.
// returns: true  - the user selected a device, its name is in 'device'
//          false - the selection was cancelled. if device=="NONE" upon return,
//                  then no devices were found in the configuration file

idaman THREAD_SAFE bool ida_export choose_ioport_device(
        const char *file,
        char *device,
        size_t device_size,
        const char *(idaapi* parse_params)(
                const char *line,
                char *buf,
                size_t bufsize));

#define IOPORT_SKIP_DEVICE ((const char *)(-1))


// Find ioport in the array of ioports
idaman THREAD_SAFE const ioport_t *ida_export find_ioport(const ioport_t *ports, size_t numports, ea_t address);


// Find ioport bit in the array of ioports
idaman THREAD_SAFE const ioport_bit_t *ida_export find_ioport_bit(const ioport_t *ports, size_t numports, ea_t address, size_t bit);


// Free ioports array. The 'userdata' field is not examined!
idaman THREAD_SAFE void ida_export free_ioports(ioport_t *ports, size_t numports);


//-------------------------------------------------------------------------
//      S Y S T E M  S P E C I F I C  C A L L S
//-------------------------------------------------------------------------

// Execute a operating system command
// This function suspends the interface (Tvision), runs the command
// and redraw the screen.
//      command - command to execute. If NULL, a shell is activated
// Returns: the error code returned by system() call.

idaman THREAD_SAFE int ida_export call_system(const char *command);


//-------------------------------------------------------------------------
//       L O A D E R  I N P U T  S O U R C E  F U N C T I O N S
//-------------------------------------------------------------------------

// Starting with v4.8 IDA can load and run remote files.
// In order to do that, we replace the FILE* in the loader modules
// with an abstract input source. The source might be linked to
// a local or remote file

class linput_t;         // loader input source


// Linput types
enum linput_type_t
{
  LINPUT_NONE,          // invalid linput
  LINPUT_LOCAL,         // local file
  LINPUT_RFILE,         // remote file (dbg->open_file, read_file)
  LINPUT_PROCMEM,       // debugged process memory (dbg->read_memory)
  LINPUT_GENERIC        // generic linput
};


// The following functions may be used to work with the input source:

// Read the input source
// If failed, inform the user and ask him if he wants to continue
// If he does not, this function will not return (loader_failure will be called)
// This function may be called only from loaders!

idaman void ida_export lread(linput_t *li, void *buf, size_t size);


// Read the input source
// Return number of read bytes or -1

idaman ssize_t ida_export qlread(linput_t *li, void *buf, size_t size);


// Read one line from the input source
// Returns: NULL if failure, othersize 's'

idaman char *ida_export qlgets(char *s, size_t len, linput_t *li);


// Read one character from the input source
// Returns: EOF if failure, otherwise the read character

idaman int ida_export qlgetc(linput_t *li);


// Read multiple bytes and swap if necessary
//      li - input file
//      buf - pointer to output buffer
//      size - number of bytes to read
//      mf - big endian?
// Returns 0-ok, -1-failure

idaman int ida_export lreadbytes(linput_t *li, void *buf, size_t size, bool mf);

#define DEF_LREADBYTES(read, type, size)                        \
inline int idaapi read(linput_t *li, type *res, bool mf) \
               { return lreadbytes(li, res, size, mf); }
DEF_LREADBYTES(lread2bytes, int16, 2)
DEF_LREADBYTES(lread2bytes, uint16, 2)
DEF_LREADBYTES(lread4bytes, int32, 4)
DEF_LREADBYTES(lread4bytes, uint32, 4)
DEF_LREADBYTES(lread8bytes, int64, 8)
DEF_LREADBYTES(lread8bytes, uint64, 8)
#undef DEF_LREADBYTES


// Read a zero-terminated string from the input
// If fpos == -1 then no seek will be performed
idaman char *ida_export qlgetz(
        linput_t *li,
        int32 fpos,
        char *buf,
        size_t bufsize);


// Get the input source size

idaman int32 ida_export qlsize(linput_t *li);


// Set input source position
// Returns the new position (not 0 as fseek!)

idaman int32 ida_export qlseek(linput_t *li, int32 pos, int whence=SEEK_SET);


// Get input source position

inline int32 idaapi qltell(linput_t *li) { return qlseek(li, 0, SEEK_CUR); }


// Open loader input

idaman linput_t *ida_export open_linput(const char *file, bool remote);


// Close loader input

idaman void ida_export close_linput(linput_t *li);


// Get FILE* from the input source
// If the input source is linked to a remote file, then return NULL
// Otherwise return the undeflying FILE*
// Please do not use this function if possible.

idaman FILE *ida_export qlfile(linput_t *li);


// Convert FILE * to input source
// Used to have a linput_t temporarily - call unmake_linput to free
// the slot after the use

idaman linput_t *ida_export make_linput(FILE *fp);
idaman void ida_export unmake_linput(linput_t *li);


// Generic linput class - may be used to create a linput_t instance for
// any data source
struct generic_linput_t
{
  // The following two fields must be filled before calling create_generic_linput

  uint32 filesize;      // input file size
  uint32 blocksize;     // preferred block size to work with
                        // read/write sizes will be in multiples of this number
                        // for example, 4096 is a nice value
                        // blocksize 0 means that the filesize is unknown.
                        // the internal cache will be disabled in this case.
                        // also, seeks from the file end will fail.
                        // blocksize=-1 means error

  virtual ssize_t idaapi read(off_t off, void *buffer, size_t nbytes) = 0;
  DEFINE_VIRTUAL_DTOR(generic_linput_t)
};

// Create a generic linput
//      generic_linput_t  - linput description
//                          This object will be destroyed by close_linput()
//                          using "delete gl;"

idaman linput_t *ida_export create_generic_linput(generic_linput_t *gl);


// Create a linput for process memory
//      start - starting address of the input
//      size  - size of the memory area to represent as linput
//              if unknown, may be passed as 0
// This linput will use dbg->read_memory() to read data

idaman linput_t *ida_export create_memory_linput(ea_t start, asize_t size);


// Get linput type

inline linput_type_t idaapi get_linput_type(linput_t *li)
{
  return *(linput_type_t *)li;
}


// only for the kernel
generic_linput_t *create_remote_linput(const char *file);


#ifndef NO_OBSOLETE_FUNCS
idaman int ida_export set_thread_priority(ushort pclass,int32 delta);
#endif
#pragma pack(pop)
#endif // _DISKIO_HPP
