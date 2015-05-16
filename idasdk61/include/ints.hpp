/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */


#ifndef _INTS_HPP
#define _INTS_HPP
#pragma pack(push, 1)           // IDA uses 1 byte alignments!

//
//      This file contains functions that deal with the predefined comments
//

class insn_t;
class WorkReg;

//--------------------------------------------------------------------
//      P R E D E F I N E D   C O M M E N T S
//--------------------------------------------------------------------

// Get predefined comment
//      cmd - current instruction information
//      buf - buffer for the comment
//      bufsize - size of the output buffer
// returns: size of comment or -1

idaman ssize_t ida_export get_predef_insn_cmt(
        const insn_t &cmd,
        char *buf,
        size_t bufsize);


// Get predefined comment
//      info   - text string with description of operand and register values
//               This string consists of equations
//                      reg=value ...
//               where reg may be any word register name,
//                      or Op1,Op2 - for first or second operands
//      wrktyp - icode of instruction to get comment about
//      buf - buffer for the comment
//      bufsize - size of the output buffer
// returns: size of comment or -1

idaman ssize_t ida_export get_predef_cmt(
        const char *info,
        int wrktyp,
        char *buf,
        size_t bufsize);


// Get predefined VxD function name.
//      vxdnum  - number of VxD
//      funcnum - number of function in the VxD
//      buf - buffer for the comment
//      bufsize - size of the output buffer
// returns: comment or NULL

#ifdef _IDP_HPP
inline char *idaapi get_vxd_func_name(
        int vxdnum,
        int funcnum,
        char *buf,
        size_t bufsize)
{
  buf[0] = '\0';
  ph.notify(ph.get_vxd_name, vxdnum, funcnum, buf, bufsize);
  return buf[0] ? buf : NULL;
}
#endif



//--------------------------------------------------------------------
// Private definitions
//--------------------------------------------------------------------

void init_predefs(void);
void term_predefs(void);

#define R_work  100                     // Command code
#define R_Op1   101
#define R_Op2   102
#define R_idp   103
#define R_filetype 104
#define R_auxpref 105
#define R_Op3   106
#define R_Op4   107
#define R_Op5   108
#define R_Op6   109

#define A_CASECODE 0xF0000000L          // Alt for caser
#define A_NETINIT  0x10000001L          // for node numbers

#pragma pack(pop)
#endif // _INTS_HPP
