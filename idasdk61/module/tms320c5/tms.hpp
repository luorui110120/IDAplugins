/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef _TMS_HPP
#define _TMS_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <srarea.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:
#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1
#define o_cond          o_idpspec2

#define sib     specflag1
#define Cond    reg

extern int nprc;        // processor number
#define PT_TMS320C5     0
#define PT_TMS320C2     1

inline bool isC2(void) { return nprc == PT_TMS320C2; }


//------------------------------------------------------------------------
enum TMS_registers { rAcc,rP,rBMAR,rAr0,rAr1,rAr2,rAr3,rAr4,rAr5,rAr6,rAr7,rVcs,rVds,rDP };

enum TMS_bits { bit_intm,bit_ovm,bit_cnf,bit_sxm,bit_hm,bit_tc,bit_xf,bit_c };

//------------------------------------------------------------------------
struct predefined_t
{
  uchar addr;
  const char *name;
  const char *cmt;
};

extern predefined_t iregs[];

bool is_mpy(void);
ea_t prevInstruction(ea_t ea);
int   find_ar(ea_t *res);
//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi segstart(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);
void    idaapi tms_assumes(ea_t ea);

#endif
