#ifndef __RPC_HLP__
#define __RPC_HLP__

//
//
//      This file contains common RPC routines such as packet creation and parsing
//      You also find here RPC request codes and error numbers definitions
//

#include <string>
#include <ua.hpp>
#include <area.hpp>
#include <idd.hpp>
#include "consts.h"

inline uchar extract_byte(const uchar **ptr, const uchar *end)
{
  return unpack_db(ptr, end);
}
inline uint32 extract_long(const uchar **ptr, const uchar *end)
{
  return unpack_dd(ptr, end);
}

inline bytevec_t prepare_rpc_packet(uchar code)
{
  rpc_packet_t rp;
  rp.length = 0;
  rp.code   = code;
  return bytevec_t((char *)&rp, sizeof(rp));
}

void finalize_packet(bytevec_t &cmd);
const char *get_rpc_name(int code);

inline void append_str(bytevec_t &s, const char *str)
{
  if ( str == NULL )
    str = "";
  size_t len = strlen(str) + 1;
  s.append(str, len);
}
inline void append_str(bytevec_t &s, const qstring &str) { append_str(s, str.c_str()); }
char *extract_str(const uchar **ptr, const uchar *end);

inline void append_type(bytevec_t &s, const type_t *str) { append_str(s, (char *)str); }
inline void append_type(bytevec_t &s, const qtype &str) { append_str(s, *(qstring*)&str); }
inline type_t *extract_type(const uchar **ptr, const uchar *end) { return (type_t *)extract_str(ptr, end); }


void extract_memory_info(const uchar **ptr, const uchar *end, memory_info_t *info);
void append_memory_info(bytevec_t &s, const memory_info_t *info);

// we pass ea_t as a 64-bit quantity (to be able to debug 32-bit programs with ida64)
// adding 1 to the address ensures that BADADDR is passed correctly.
// without it, 32-bit server would return 0xffffffff and ida64 would not consider it
// as a BADADDR.
inline void append_ea64(bytevec_t &s, ea_t ea) { append_dq(s, ea+1); }
inline ea_t extract_ea64(const uchar **ptr, const uchar *end) { return ea_t(unpack_dq(ptr, end)-1); }

void append_exception_info(bytevec_t &s, const exception_info_t *table, int qty);
exception_info_t *extract_exception_info(const uchar **ptr, const uchar *end,int qty);

inline void extract_memory(const uchar **ptr, const uchar *end, void *buf, size_t size)
{
  if ( buf != NULL )
    memcpy(buf, *ptr, size);
  *ptr += size;
  if ( *ptr > end )
    *ptr = end;
}

inline void append_memory(bytevec_t &s, const void *buf, size_t size)
{
  if ( size != 0 )
    s.append((char *)buf, size);
}

void extract_regvals(
        const uchar **ptr,
        const uchar *end,
        regval_t *values,
        int n,
        const uchar *regmap);
void append_regvals(bytevec_t &s, const regval_t *values, int n, const uchar *regmap);
void append_debug_event(bytevec_t &s, const debug_event_t *ev);
void extract_debug_event(const uchar **ptr, const uchar *end, debug_event_t *ev);
void extract_exception(const uchar **ptr, const uchar *end, e_exception_t *exc);
void append_exception(bytevec_t &s, const e_exception_t *e);

inline void append_breakpoint(bytevec_t &s, const e_breakpoint_t *info)
{
  append_ea64(s, info->hea);
  append_ea64(s, info->kea);
}

inline void extract_breakpoint(const uchar **ptr, const uchar *end, e_breakpoint_t *info)
{
  info->hea = extract_ea64(ptr, end);
  info->kea = extract_ea64(ptr, end);
}
void extract_module_info(const uchar **ptr, const uchar *end, module_info_t *info);
void append_module_info(bytevec_t &s, const module_info_t *info);
void extract_process_info(const uchar **ptr, const uchar *end, process_info_t *info);
void append_process_info(bytevec_t &s, const process_info_t *info);

void extract_call_stack(const uchar **ptr, const uchar *end, call_stack_t *trace);
void append_call_stack(bytevec_t &s, const call_stack_t &trace);

void extract_regobjs(const uchar **ptr, const uchar *end, regobjs_t *regargs, bool with_values);
void append_regobjs(bytevec_t &s, const regobjs_t &regargs, bool with_values);

void extract_appcall(
        const uchar **ptr,
        const uchar *end,
        func_type_info_t *fti,
        regobjs_t *regargs,
        relobj_t *stkargs,
        regobjs_t *retregs);
void append_appcall(
        bytevec_t &s,
        const func_type_info_t &fti,
        const regobjs_t &regargs,
        const relobj_t &stkargs,
        const regobjs_t *retregs);

#endif
