/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _I960_HPP
#define _I960_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"

//Absolute offset (<4096)       offset                   exp                 MEMA o_imm
//Absolute displacement         disp                     exp                 MEMB o_imm
//Register Indirect             abase                    (reg)               o_phrase, index=-1, scale=1
//  with offset                 abase+offset             exp(reg)            o_displ, index=-1,scale=1
//  with displacement           abase+disp               exp(reg)            o_displ, index=-1,scale=1
//  with index                  abase+(index*scale)      (reg)[reg*scale]    o_phrase, index=index
//  with index and displacement abase+(index*scale)+disp exp(reg)[reg*scale] o_displ
//Index with displacement       (index*scale) + disp     exp[reg*scale]      o_displ, reg=index, index=-1
//IP with displacement          IP+disp+8                exp(IP)             o_near

#define index   specflag1           // o_displ, o_phrase
#define scale   specflag2           // o_displ, o_phrase

#define aux_t  0x0001           // .t suffix
#define aux_f  0x0002           // .f suffix
#define aux_ip 0x0004           // ip relative addressing

//------------------------------------------------------------------
enum regnum_t
{
  LR0, LR1, LR2,  LR3,  LR4,  LR5,  LR6,  LR7,
  LR8, LR9, LR10, LR11, LR12, LR13, LR14, LR15,
  GR0, GR1, GR2,  GR3,  GR4,  GR5,  GR6,  GR7,
  GR8, GR9, GR10, GR11, GR12, GR13, GR14, GR15,
  SF0, SF31=SF0+31,
  PC,  AC,  IP,  TC,
  FP0, FP1, FP2, FP3,
  ds, cs,
  MAXREG = cs,
  PFP    = LR0,
  SP     = LR1,
  RIP    = LR2,
  FP     = GR15,
  IPND   = SF0+0,
  IMSK   = SF0+1,
  DMAC   = SF0+2,
};

//------------------------------------------------------------------
extern netnode helper;
extern uint32 idpflags;

#define IDP_STRICT      0x0001  // Strictly adhere to instruction encodings

inline bool is_strict(void) { return (idpflags & IDP_STRICT) != 0; }

ea_t calc_mem(ea_t ea);         // map virtual to physical ea
const char *find_sym(ea_t address);
//------------------------------------------------------------------
void interr(const char *module);

void idaapi header(void);
void idaapi footer(void);

void idaapi segstart(ea_t ea);
void idaapi segend(ea_t ea);
void idaapi assumes(ea_t ea);         // function to produce assume directives

void idaapi out(void);
int  idaapi outspec(ea_t ea,uchar segtype);

int  idaapi ana(void);
int  idaapi emu(void);
bool idaapi outop(op_t &op);
void idaapi data(ea_t ea);

int  idaapi is_align_insn(ea_t ea);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?

#endif // _I960_HPP
