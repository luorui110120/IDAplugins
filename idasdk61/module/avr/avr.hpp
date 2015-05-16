/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Atmel AVR - 8-bit RISC processor
 *
 */

#ifndef _AVR_HPP
#define _AVR_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//---------------------------------
// Operand types:

enum phrase_t ENUM_SIZE(uint16)
{
  PH_X,         // X
  PH_XPLUS,     // X+
  PH_MINUSX,    // -X
  PH_Y,         // Y
  PH_YPLUS,     // Y+
  PH_MINUSY,    // -Y
  PH_Z,         // Z
  PH_ZPLUS,     // Z+
  PH_MINUSZ,    // -Z
};


#define o_port  o_idpspec0      // port number in x.addr

//------------------------------------------------------------------
enum RegNo
{
   R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
   R8,   R9,  R10,  R11,  R12,  R13,  R14,  R15,
  R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
  R24,  R25,  R26,  R27,  R28,  R29,  R30,  R31,
  rVcs, rVds,    // virtual registers for code and data segments
};

//------------------------------------------------------------------
// I/O port definitions

const char *find_port(ea_t address);
const char *find_bit(ea_t address, size_t bit);

// memory configuration

extern uint32 ramsize;
extern uint32 romsize;
extern uint32 eepromsize;
extern ea_t ram;
extern netnode helper;
extern char device[];

//------------------------------------------------------------------
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

#endif // _AVR_HPP
