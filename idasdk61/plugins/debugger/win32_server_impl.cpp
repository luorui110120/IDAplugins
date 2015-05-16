//
//
//      This file contains win32 specific implementations of win32_debugger_module class
//      server-side functionality only
//
//

#include <pro.h>
#include "win32_rpc.h"
#include "win32_debmod.h"
#include "rpc_hlp.h"

#ifdef ENABLE_REMOTEPDB

#include "tilfuncs.hpp"

//---------------------------------------------------------- main thread ---
void win32_debmod_t::handle_pdb_request()
{
  if ( pdbthread.req_kind == 1 )
  {
    // read input file
    bytevec_t cmd;
    append_dq(cmd, pdbthread.off_ea);
    append_dd(cmd, pdbthread.count);
    void *outbuf = NULL;
    ssize_t outsize = 0;
    // send request to IDA
    int rc = send_ioctl(WIN32_IOCTL_READFILE, &cmd[0], cmd.size(), &outbuf, &outsize);
    if ( rc == 1 && outbuf != NULL )
    {
      // OK
      size_t copylen = qmin(pdbthread.count, outsize);
      memcpy(pdbthread.buffer, outbuf, copylen);
      pdbthread.count = copylen;
      pdbthread.req_result = true;
    }
    else
    {
      pdbthread.req_result = false;
    }
    if ( outbuf != NULL )
      qfree(outbuf);
  }
  else if ( pdbthread.req_kind == 2 )
  {
    // read memory
    ssize_t rc = _read_memory(ea_t(pdbthread.off_ea), pdbthread.buffer, pdbthread.count);
    if ( rc >= 0 )
      pdbthread.count = rc;
    pdbthread.req_result = rc >= 0;
  }
  else
  {
    // unknown request
    pdbthread.req_result = false;
  }
}

#else
void win32_debmod_t::handle_pdb_request()
{
}
#endif

//---------------------------------------------------------- main thread ---
int idaapi win32_debmod_t::handle_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
  qnotused(size);
  switch ( fn )
  {
    case WIN32_IOCTL_RDMSR:
      QASSERT(30119, size == sizeof(uval_t));
      {
        uint64 value;
        uval_t reg = *(uval_t *)buf;
        int code = rdmsr(reg, &value);
        if ( SUCCEEDED(code) )
        {
          *poutbuf = qalloc(sizeof(value));
          if ( *poutbuf != NULL )
          {
            memcpy(*poutbuf, &value, sizeof(value));
            *poutsize = sizeof(value);
          }
        }
        return code;
      }

    case WIN32_IOCTL_WRMSR:
      QASSERT(30120, size == sizeof(win32_wrmsr_t));
      {
        win32_wrmsr_t &msr = *(win32_wrmsr_t *)buf;
        return wrmsr(msr.reg, msr.value);
      }

#ifdef ENABLE_REMOTEPDB

    case WIN32_IOCTL_STARTPDB:
      QASSERT(30192, size >= sizeof(uint64));
      {
        qstring errmsg;
        if ( pdbthread.is_running() )
        {
          errmsg = "Only one PDB conversion at a time is supported!";
PDBERROR:
          *poutsize = errmsg.size();
          *poutbuf = errmsg.extract();
          return -2;
        }
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;
        compiler_info_t cc;
        extract_memory(&ptr, end, &cc, sizeof(cc));
        ea_t base_ea = extract_ea64(&ptr, end);
        const char *pdbfile = extract_str(&ptr, end);
        const char *dpath   = extract_str(&ptr, end);
        const char *spath   = extract_str(&ptr, end);
        if ( !pdbthread.do_convert(cc, base_ea, pdbfile, dpath, spath) )
        {
          errmsg = "Error starting PDB conversion!";
          goto PDBERROR;
        }
        return 0x1234; // dummy ID
      }

    case WIN32_IOCTL_DONEPDB:
      {
        qstring errmsg;
        if ( !pdbthread.is_running() )
        {
          errmsg = "PDB conversion is not started!";
PDBERROR2:
          *poutsize = errmsg.size();
          *poutbuf = errmsg.extract();
          return -2;
        }
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;
        uint32 id = extract_long(&ptr, end);
        if ( id != 0x1234 )
        {
          errmsg = "Bad conversion ID";
          goto PDBERROR2;
        }
        if ( pdbthread.is_waiting_req() )
        {
          // we've got a read request, handle it now
          handle_pdb_request();
          pdbthread.post_req_done();
        }
        if ( pdbthread.is_done() )
        {
          // done
          pdbthread.finalize();
          *poutsize = pdbthread.tilfname.size();
          *poutbuf = pdbthread.tilfname.extract();
          return 2;
        }
        else
        {
          // not done yet
          return 1;
        }
      }

    case WIN32_IOCTL_RMFILE:
      {
        qstring errmsg;
        const uchar *ptr = (const uchar *)buf;
        const uchar *end = ptr + size;
        const char *filename = extract_str(&ptr, end);
        if ( filename == NULL )
        {
          errmsg = "Filename missing";
PDBERROR3:
          *poutsize = errmsg.size();
          *poutbuf = errmsg.extract();
          return -2;
        }
        if ( unlink(filename) != 0 )
        {
          errmsg = "Error deleting file";
          goto PDBERROR3;
        }
        return 1;
      }

#endif // REMOTEPDB

    default:
      break;
  }
  return 0;
}
