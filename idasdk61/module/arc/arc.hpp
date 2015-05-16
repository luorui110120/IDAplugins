/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

        /* ARC code, based on IDA SDK, written by Felix Domke <tmbinc@gmx.net> */

#ifndef _ARC_HPP
#define _ARC_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

enum processor_subtype_t
{
  prc_arc = 0,                      // plain arc
};

extern processor_subtype_t ptype;

// The predefined locations
typedef struct {
  uchar proc;
  uchar addr;
  uchar bit;
  char *name;
  char *cmt;
} predefined_t;

extern predefined_t sregs[];        // lr/sr name table
predefined_t *GetPredefined(predefined_t *ptr, int addr);
int IsPredefined(const char *name);

enum arc_reg_t
{
  FP = 27,
  SP = 28,
};


//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi segstart(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);

int idaapi is_sp_based(const op_t &x);
bool idaapi create_func_frame(func_t *pfn);
int idaapi arc_get_frame_retsize(func_t *pfn);

#endif
