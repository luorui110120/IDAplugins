/*
 *      Rockwell C39 processor module for IDA Pro.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _C39_HPP
#define _C39_HPP

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
#define URR_IND         (0x01)  // косвенно, через регистр

//------------------------------------------------------------------------
// список регистров процессора
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum C39_registers ENUM8BIT { rNULLReg,
        rA, rX,rY,
        rVcs, rVds};

#if IDP_INTERFACE_VERSION > 37
extern char deviceparams[];
extern char device[];
#endif

//------------------------------------------------------------------------
void    idaapi C39_header(void);
void    idaapi C39_footer(void);

void    idaapi C39_segstart(ea_t ea);

int     idaapi C39_ana(void);
int     idaapi C39_emu(void);
void    idaapi C39_out(void);
bool    idaapi C39_outop(op_t &op);

void    idaapi C39_data(ea_t ea);

#endif
