/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PDP_HPP
#define _PDP_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include "pdp_ml.h"
extern pdp_ml_t m;

#define UAS_SECT        0x0001          // Segments are named .SECTION

extern int pflag;

//----------------------------------------------------------------------
// Redefine temporary names
//
#define         bytecmd    auxpref_chars.low

#define         segval     specval_shorts.low
#define         addr16     addr_shorts.low
#define         ill_imm    specflag1

#define         o_fpreg    o_idpspec0
#define         o_number   o_idpspec1
//------------------------------------------------------------------------
enum pdp_registers { rR0,rR1,rR2,rR3,rR4,rR5,rSP,rPC,
                     rAC0,rAC1,rAC2,rAC3,rAC4,rAC5,
                        rVcs,rVds };

//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi segstart(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);

void    idaapi pdp_data(ea_t ea);

#endif

