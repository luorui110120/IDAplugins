/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _F2MC_HPP
#define _F2MC_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"

//------------------------------------------------------------------
enum regnum_t
{
  A,         // accumulator
  AL,        // accumulator
  AH,        // accumulator
  PC,        // program counter
  SP,        // stack pointer
  R0,
  R1,
  R2,
  R3,
  R4,
  R5,
  R6,
  R7,
  RW0,
  RW1,
  RW2,
  RW3,
  RW4,
  RW5,
  RW6,
  RW7,
  RL0,
  RL1,
  RL2,
  RL3,

  PCB,        // program bank register
  DTB,        // data bank register
  ADB,        // additional data bank register
  SSB,        // system stack bank register
  USB,        // user stack bank register
  CCR,        // condition code register
  DPR,        // direct page register
  rVcs, rVds, // virtual registers for code and data segments

  SPB,       // stack pointer bank register
  PS,        // processor status
  ILM,       // interrupt level mask register
  RP         // register bank pointer
};

//------------------------------------------------------------------
// specific processor records

#define default_bank segpref
#define prefix_bank auxpref_chars.high
#define op_bank auxpref_chars.low
// o_phrase = @reg+(index) (index if PHRASE_INDEX)
 #define at specflag1 // number of @ indirections (dtyp @ = op.dtyp)
 #define special_mode specflag2
  #define MODE_INC 1
  #define MODE_INDEX 2
 #define index specval_shorts.high
#define o_reglist o_idpspec0
// o_disp = @reg+value
#define addr_dtyp specflag3
 #define MODE_BIT 1
  #define byte_bit specflag4

//------------------------------------------------------------------
// specific device name

extern char device[MAXSTR];
extern char deviceparams[MAXSTR];

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t F2MC16L  = 0;
const proctype_t F2MC16LX = 1;

extern proctype_t ptype;    // contains processor type

extern ea_t dataseg;
//------------------------------------------------------------------
extern netnode helper;

#define F2MC_MACRO  0x0001  // use instruction macros

extern ushort idpflags;

inline ea_t calc_code_mem(ea_t ea)
  { return toEA(cmd.cs, ea); }
inline ea_t calc_data_mem(ea_t ea)
  { return toEA(cmd.cs, ea); }

int get_signed(int byte,int mask);

const char *find_sym(ea_t address);
const ioport_bit_t *find_bits(ea_t address);
const char *find_bit(ea_t address, int bit);
ea_t calc_code_mem(ea_t ea);
ea_t calc_data_mem(ea_t ea);
ea_t map_port(ea_t from);
//------------------------------------------------------------------
void idaapi header(void);
void idaapi footer(void);

void idaapi segstart(ea_t ea);
void idaapi segend(ea_t ea);
void idaapi assumes(ea_t ea);         // function to produce assume directives

void idaapi out(void);

int  idaapi ana(void);
int  idaapi emu(void);
bool idaapi outop(op_t &op);
void idaapi data(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const op_t &x);

#endif // _F2MC_HPP
