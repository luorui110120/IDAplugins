#ifndef __NT__
#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
#define CONTROL_C_EXIT                      STATUS_CONTROL_C_EXIT
#define DBG_CONTROL_C                    0x40010005L
#define DBG_CONTROL_BREAK                0x40010008L
#define STATUS_GUARD_PAGE_VIOLATION      0x80000001L
#define STATUS_DATATYPE_MISALIGNMENT     0x80000002L
#define STATUS_BREAKPOINT                0x80000003L
#define STATUS_SINGLE_STEP               0x80000004L
#define STATUS_ACCESS_VIOLATION          0xC0000005L
#define STATUS_IN_PAGE_ERROR             0xC0000006L
#define STATUS_INVALID_HANDLE            0xC0000008L
#define STATUS_NO_MEMORY                 0xC0000017L
#define STATUS_ILLEGAL_INSTRUCTION       0xC000001DL
#define STATUS_NONCONTINUABLE_EXCEPTION  0xC0000025L
#define STATUS_INVALID_DISPOSITION       0xC0000026L
#define STATUS_ARRAY_BOUNDS_EXCEEDED     0xC000008CL
#define STATUS_FLOAT_DENORMAL_OPERAND    0xC000008DL
#define STATUS_FLOAT_DIVIDE_BY_ZERO      0xC000008EL
#define STATUS_FLOAT_INEXACT_RESULT      0xC000008FL
#define STATUS_FLOAT_INVALID_OPERATION   0xC0000090L
#define STATUS_FLOAT_OVERFLOW            0xC0000091L
#define STATUS_FLOAT_STACK_CHECK         0xC0000092L
#define STATUS_FLOAT_UNDERFLOW           0xC0000093L
#define STATUS_INTEGER_DIVIDE_BY_ZERO    0xC0000094L
#define STATUS_INTEGER_OVERFLOW          0xC0000095L
#define STATUS_PRIVILEGED_INSTRUCTION    0xC0000096L
#define STATUS_STACK_OVERFLOW            0xC00000FDL
#define STATUS_CONTROL_C_EXIT            0xC000013AL
#define STATUS_FLOAT_MULTIPLE_FAULTS     0xC00002B4L
#define STATUS_FLOAT_MULTIPLE_TRAPS      0xC00002B5L
#define STATUS_REG_NAT_CONSUMPTION       0xC00002C9L
#define SUCCEEDED(x) (x >= 0)
#define FAILED(x) (x < 0)
#endif

#include <expr.hpp>
#include <loader.hpp>
#include "../../ldr/pe/pe.h"
#include "win32_rpc.h"
#include "rpc_hlp.h"

//--------------------------------------------------------------------------
static const char idc_win32_rdmsr_args[] = { VT_LONG, 0 };
static error_t idaapi idc_win32_rdmsr(idc_value_t *argv, idc_value_t *res)
{
  uint64 value = 0; // shut up the compiler
  uval_t reg = argv[0].num;
#ifdef RPC_CLIENT
  void *out = NULL;
  ssize_t outsize;
  int code = g_dbgmod.send_ioctl(WIN32_IOCTL_RDMSR, &reg, sizeof(reg), &out, &outsize);
  if ( SUCCEEDED(code) && outsize == sizeof(value) )
    value = *(uint64*)out;
  qfree(out);
#else
  int code = g_dbgmod.rdmsr(reg, &value);
#endif
  if ( FAILED(code) )
  {
    res->num = code;
    return set_qerrno(eExecThrow); // read error, raise exception
  }
  res->set_int64(value);
  return eOk;
}

//--------------------------------------------------------------------------
static const char idc_win32_wrmsr_args[] = { VT_LONG, VT_INT64, 0 };
static error_t idaapi idc_win32_wrmsr(idc_value_t *argv, idc_value_t *res)
{
  win32_wrmsr_t msr;
  msr.reg = argv[0].num;
  msr.value = argv[1].i64;
#ifdef RPC_CLIENT
  res->num = g_dbgmod.send_ioctl(WIN32_IOCTL_WRMSR, &msr, sizeof(msr), NULL, NULL);
#else
  res->num = g_dbgmod.wrmsr(msr.reg, msr.value);
#endif
  return eOk;
}

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
static bool register_idc_funcs(bool reg)
{
  static const extfun_t funcs[] =
  {
    { IDC_READ_MSR,    idc_win32_rdmsr,     idc_win32_rdmsr_args     },
    { IDC_WRITE_MSR,   idc_win32_wrmsr,     idc_win32_wrmsr_args     },
  };
  for ( int i=0; i < qnumber(funcs); i++ )
    if ( !set_idc_func_ex(funcs[i].name, reg ? funcs[i].fp : NULL, funcs[i].args, 0) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  if ( is_miniidb() || inf.is_snapshot() )
    return;
  netnode penode;
  penode.create(PE_NODE);
  ea_t currentbase = new_base;
  ea_t imagebase = ea_t(penode.altval(PE_ALT_IMAGEBASE)); // loading address (usually pe.imagebase)

  if ( imagebase == 0 )
  {
    warning("AUTOHIDE DATABASE\n"
            "IDA Pro couldn't automatically determine if the program should be\n"
            "rebased in the database because the database format is too old and\n"
            "doesn't contain enough information.\n"
            "Create a new database if you want automated rebasing to work properly.\n"
            "Note you can always manually rebase the program by using the\n"
            "Edit, Segments, Rebase program command.");
  }
  else if ( imagebase != currentbase )
  {
    int code = rebase_program(currentbase - imagebase, MSF_FIXONCE);
    if ( code != MOVE_SEGM_OK )
    {
      msg("Failed to rebase program, error code %d\n", code);
      warning("ICON ERROR\n"
              "AUTOHIDE NONE\n"
              "IDA Pro failed to rebase the program.\n"
              "Most likely it happened because of the debugger\n"
              "segments created to reflect the real memory state.\n\n"
              "Please stop the debugger and rebase the program manually.\n"
              "For that, please select the whole program and\n"
              "use Edit, Segments, Rebase program with delta 0x%a",
                                        currentbase - imagebase);
    }
  }
}

//--------------------------------------------------------------------------
bool read_pe_header(peheader_t *pe)
{
  netnode penode;
  penode.create(PE_NODE);
  return penode.valobj(pe, sizeof(peheader_t)) > 0;
}

#if defined(RPC_CLIENT) && defined(ENABLE_REMOTEPDB)
//--------------------------------------------------------------------------
static int copy_from_remote(const char *lname, const char *rname)
{
  int code = 0;
  uint32 fsize;
  int fn = dbg->open_file(rname, &fsize, true);
  if ( fn != -1 )
  {
    FILE *outf = qfopen(lname, "wb");
    if ( outf != NULL )
    {
      uint32 offs = 0;
      uint32 bufsize = qmin(1024*4, fsize);
      if ( bufsize > 0 )
      {
        char *buf = (char *)qalloc(bufsize);
        while ( offs < fsize )
        {
          uint32 toread = qmin(bufsize, fsize - offs);
          if ( dbg->read_file(fn, offs, buf, toread) != ssize_t(toread) 
            || qfwrite(outf, buf, toread) != ssize_t(toread) )
          {
            code = qerrcode();
            break;
          }
          offs += toread;
        }
      }
      qfclose(outf);
    }
    else
    {
      code = qerrcode();
    }
    dbg->close_file(fn);
  }
  else
  {
    code = qerrcode();
  }
  return code;
}

// filename for the IOCTL read callback
static const char *input_filename;

//--------------------------------------------------------------------------
static int idaapi do_til_for_file(ea_t baseea,
  const char *filename,
  const char *tilname,
  const char *dpath,
  const char *spath,
  char *errbuf,
  uint32 bufsize)
{
  bytevec_t cmd;

  // start the conversion
  append_memory(cmd, &inf.cc, sizeof(inf.cc));
  append_ea64(cmd, baseea);
  append_str(cmd, filename);
  append_str(cmd, dpath);
  append_str(cmd, spath);
  void *outbuf = NULL;
  ssize_t outsize = 0;
  input_filename  = filename;
  int rc = internal_ioctl(WIN32_IOCTL_STARTPDB, &cmd[0], cmd.size(), &outbuf, &outsize);
  if ( rc == 0 )
  {
    if ( outbuf != NULL )
      qfree(outbuf);
    qstrncpy(errbuf, "PDB symbol extraction is not supported by the remote server", bufsize);
    return 3;
  }
  if ( rc < 0 )
  {
    if ( rc == -1 || outbuf == NULL )
    {
      qstrncpy(errbuf, "Network error", bufsize);
    }
    else
    {
      // error text in outbuf
      size_t minsize = qmin(outsize, bufsize);
      qstrncpy(errbuf, (char*)outbuf, minsize);
      qfree(outbuf);
    }
    return 3;
  }
  if ( outbuf != NULL )
    qfree(outbuf);
  // rc is the conversion id
  cmd.clear();
  append_dd(cmd, rc);
  qstring remote_til_file;
  msg("Retrieving symbols...");
  bool done = false;
  while ( !done )
  {
    outbuf = NULL;
    rc = internal_ioctl(WIN32_IOCTL_DONEPDB, &cmd[0], cmd.size(), &outbuf, &outsize);
    if ( rc == 0 )
    {
      // not supported
      if ( outbuf != NULL )
        qfree(outbuf);
      qstrncpy(errbuf, "PDB symbol extraction is not supported by the remote server", bufsize);
      return 3;
    }
    if ( rc < 0 )
    {
      // error text in outbuf
      if ( outbuf != NULL )
      {
        size_t minsize = qmin(outsize, bufsize);
        qstrncpy(errbuf, (char*)outbuf, minsize);
        qfree(outbuf);
      }
      return 3;
    }
    if ( rc == 2 )
    {
      // done, til filename is in output buffer
      remote_til_file.append((char*)outbuf, outsize);
      done = true;
    }
    else if ( rc == 1 )
    {
      // in progress
      msg(".");
      done = wasBreak();
      qsleep(500);
    }
    if ( outbuf != NULL )
      qfree(outbuf);
  }
  if ( rc == 1 )
  {
    msg("cancelled.\n");
    qstrncpy(errbuf, "Cancelled by user", bufsize);
    return 3;
  }
  if ( rc == 2 && !remote_til_file.empty() )
  {
    msg("done.\n");
    rc = copy_from_remote(tilname, remote_til_file.c_str());
    if ( rc != 0 )
    {
      char *errend = qstpncpy(errbuf, "Error copying til file from remote host: ", bufsize);
      size_t leftsize = bufsize - (errend - errbuf);
      qstrerror(rc, errend, leftsize);
      return 3;
    }
    // delete the temp til file on the remote server
    cmd.qclear();
    append_str(cmd, remote_til_file.c_str());
    outbuf = NULL;
    internal_ioctl(WIN32_IOCTL_RMFILE, &remote_til_file[0], remote_til_file.size(), &outbuf, &outsize);
    if ( outbuf != NULL )
      qfree(outbuf);
  }
  else
  {
    qstrncpy(errbuf, "Internal error", bufsize);
    return 3;
  }
  return 2;
}

//--------------------------------------------------------------------------
static int idaapi idp_callback(void *, int code, va_list va)
{
  switch ( code )
  {
    case processor_t::til_for_file: // extract symbols/types from a file/module in memory, if possible, and convert to a .til
                                    // args: ea_t ea        - base address of the module
                                    // const char *filename - input filename
                                    // const char *tilfname - where to write the resulting .til
                                    // const char *dpath    - PDB download path (server-side)
                                    // const char *spath    - PDB sympath
                                    //       char *errbuf
                                    //       uint32 bufsize
                                    // returns: 2+error_code
      {
        ea_t baseea = va_arg(va, ea_t);
        const char *filename = va_arg(va, const char *);
        const char *tilname  = va_arg(va, const char *);
        const char *dpath    = va_arg(va, const char *);
        const char *spath    = va_arg(va, const char *);
        char *errbuf         = va_arg(va, char *);
        uint32 bufsize       = va_arg(va, uint32);        
        return do_til_for_file(baseea, filename, tilname, dpath, spath, errbuf, bufsize);
      }
  }
  return 0;
}

//--------------------------------------------------------------------------
// handler on IDA: Server -> IDA
static int ioctl_handler(
  class rpc_engine_t * /*rpc*/,
  int fn,
  const void *buf,
  size_t size,
  void **poutbuf,
  ssize_t *poutsize)
{
  qnotused(size);
  switch ( fn )
  {
    case WIN32_IOCTL_READFILE:
      {
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;
        uint64 offset        = unpack_dq(&ptr, end);
        uint32 length        = unpack_dd(&ptr, end);
        *poutbuf = NULL;
        *poutsize = 0;
        if ( length != 0 )
        {
          FILE *infile = qfopen(input_filename, "rb");
          if ( infile == NULL )
            return -2;

          void *buf = qalloc(length);

          if ( buf == NULL )
            return -2;
          
          qfseek(infile, offset, SEEK_SET);
          int readlen = qfread(infile, buf, length);
          qfclose(infile);

          if ( readlen < 0 || readlen > length )
          {
            qfree(buf);
            return -2;
          }
          *poutbuf = buf;
          *poutsize = readlen;
        }
        return 1;
      }
  }
  return 0;
}
#endif

//--------------------------------------------------------------------------
// Initialize Win32 debugger plugin
static bool win32_init_plugin(void)
{
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif
  if ( !netnode::inited() || is_miniidb() || inf.is_snapshot() )
  {
#ifdef __NT__
    // local debugger is available if we are running under Windows
    return true;
#else
    // for other systems only the remote debugger is available
    return debugger.is_remote();
#endif
  }

  if ( inf.filetype != f_PE )
    return false; // only PE files
#ifdef USE_ASYNC        // connection to PocketPC device
  if ( ph.id != PLFM_ARM )
    return false; // only ARM
#else
  if ( ph.id != PLFM_386 )
    return false; // only IBM PC
#endif

  // find out the pe header
  peheader_t pe;
  if ( !read_pe_header(&pe) )
    return false;

  if ( pe.subsys != PES_UNKNOWN )  // Unknown
  {
#ifdef USE_ASYNC        // connection to PocketPC device
    // debug only wince applications
    if ( pe.subsys != PES_WINCE )  // Windows CE
      return false;
#else
    // debug only gui or console applications
    if ( pe.subsys != PES_WINGUI && pe.subsys != PES_WINCHAR )
      return false;
#endif
  }
#if defined(RPC_CLIENT) && defined(ENABLE_REMOTEPDB)
  hook_to_notification_point(HT_IDP, idp_callback, NULL);
  g_dbgmod.set_ioctl_handler(ioctl_handler);
#endif
  return true;
}

//--------------------------------------------------------------------------
inline void win32_term_plugin(void)
{
#ifdef RPC_CLIENT
#ifdef ENABLE_REMOTEPDB
  unhook_from_notification_point(HT_IDP, idp_callback, NULL);
#endif
#else
  term_subsystem();
#endif
}

#ifndef HAVE_PLUGIN_COMMENTS
//--------------------------------------------------------------------------
char comment[] = "Userland win32 debugger plugin.";

char help[] =
        "A sample Userland win32 debugger plugin\n"
        "\n"
        "This module shows you how to create debugger plugins.\n";

#endif
