/*
 *      National Semiconductor Corporation CR16 processor module for IDA Pro.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _CR16_HPP
#define _CR16_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#define near
#define far
#include "ins.hpp"

// ============================================================
// варианты битновых полей для specflags1 (specflag2 - не исп.)
//-----------------------------------------------
// дополнительные биты к типу ячейки
#define URR_PAIR        (0x01)  // косвенно, через регистр

//------------------------------------------------------------------------
// список регистров процессора
enum CR16_registers { rNULLReg,
        rR0,rR1,rR2,rR3,rR4,rR5,rR6,rR7,
        rR8,rR9,rR10,rR11,rR12,rR13,rRA,rSP,
        // Спецрегистры
        rPC,rISP,rINTBASE,rPSR,rCFG,rDSR,rDCR,rCARL,rCARH,
        rINTBASEL,rINTBASEH,
        rVcs, rVds};


#if IDP_INTERFACE_VERSION > 37
extern char deviceparams[];
extern char device[];
#endif

//------------------------------------------------------------------------
void    idaapi CR16_header(void);
void    idaapi CR16_footer(void);

void    idaapi CR16_segstart(ea_t ea);

int     idaapi CR16_ana(void);
int     idaapi CR16_emu(void);
void    idaapi CR16_out(void);
bool    idaapi CR16_outop(op_t &op);

void    idaapi CR16_data(ea_t ea);

#endif
