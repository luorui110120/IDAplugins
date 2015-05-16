/*
 *      TLCS900 processor module for IDA Pro.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _TOSH_HPP
#define _TOSH_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"

//-----------------------------------------------
// Вспомогательные биты в инкременте/декременте
#define URB_DECR        (0x80)  // декремент
#define URB_DCMASK      (0x07)  // маска декремента
#define URB_UDEC        (0x40)  // одиночный декремент
#define URB_UINC        (0x20)  // одиночный инкремент

// вспомогательные биты в specflag1
#define URB_WORD        (1)     // второй индексный регистр - слово
#define URB_LDA         (2)     // инструкция использует адрес, а не его содержимое
#define URB_LDA2        (4)     // Same, but may constant!

//------------------------------------------------------------------------
// список регистров процессора
enum T900_registers { rNULLReg,
        rW, rA, rB, rC, rD, rE, rH, rL,
        rWA, rBC, rDE, rHL, rIX, rIY, rIZ, rSP,
        rXWA, rXBC, rXDE, rXHL, rXIX, rXIY, rXIZ, rXSP,
        rIXL, rIXH, rIYL, rIYH, rIZL, rIZH, rSPL, rSPH,
        rVcs, rVds};

// всякие разные фразы
enum T900_phrases{rNULLPh,
        fCF,fCLT,fCLE,fCULE,fCPE,fCMI,fCZ,fCC,
        fCT,fCGE,fCGT,fCUGT,fCPO,fCPL,fCNZ,fCNC,
        fSF,fSF1,
        fSR, fPC};

#if IDP_INTERFACE_VERSION > 37
extern char deviceparams[];
extern char device[];
#endif

//------------------------------------------------------------------------
void idaapi T900_header(void);
void idaapi T900_footer(void);

void idaapi T900_segstart(ea_t ea);

int  idaapi T900_ana(void);
int  idaapi T900_emu(void);
void idaapi T900_out(void);
bool idaapi T900_outop(op_t &op);

void idaapi T900_data(ea_t ea);

#endif
