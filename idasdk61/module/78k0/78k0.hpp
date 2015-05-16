/*
 *      NEC 78K0 processor module for IDA Pro.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef _78K0_HPP
#define _78K0_HPP

#include <ida.hpp>
#include <idp.hpp>

#include "../idaidp.hpp"
#include "ins.hpp"

// subtype of out format
#define FormOut       specflag1
//o_mem, o_near
#define FORM_OUT_VSK    (0x01)
// o_mem, o_reg, o_near
#define FORM_OUT_SKOBA  (0x02)
// o_reg
#define FORM_OUT_PLUS   (0x04)
#define FORM_OUT_DISP   (0x08)
#define FORM_OUT_REG    (0x10)
// o_bit
#define FORM_OUT_HL             (0x04)
#define FORM_OUT_PSW    (0x08)
#define FORM_OUT_A              (0x10)
#define FORM_OUT_SFR    (0x20)
#define FORM_OUT_S_ADDR (0x40)
// o_reg
#define SecondReg       specflag2

//bit operand
#define o_bit           o_idpspec0

//------------------------------------------------------------------------
enum N78K_registers { rX, rA, rC, rB, rE, rD, rL, rH, rAX, rBC, rDE, rHL,
                     rPSW, rSP, bCY, rRB0, rRB1, rRB2, rRB3,
                     rVcs, rVds };

//------------------------------------------------------------------------

#if IDP_INTERFACE_VERSION > 37
extern char deviceparams[];
extern char device[];
bool nec_find_ioport_bit(int port, int bit);
#endif

//------------------------------------------------------------------------
void    idaapi N78K_header(void);
void    idaapi N78K_footer(void);

void    idaapi N78K_segstart(ea_t ea);

int     idaapi N78K_ana(void);
int     idaapi N78K_emu(void);
void    idaapi N78K_out(void);
bool    idaapi N78K_outop(op_t &op);
void    idaapi N78K_data(ea_t ea);

#endif

