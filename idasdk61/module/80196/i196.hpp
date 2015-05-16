/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#ifndef _I196_HPP
#define _I196_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <srarea.hpp>

//------------------------------------------------------------------------
// customization of cmd structure:

#define o_indirect      o_idpspec0      // [addr]
#define o_indirect_inc  o_idpspec1      // [addr]+
#define o_indexed       o_idpspec2      // addr[value]
#define o_bit           o_idpspec3

extern uint32 intmem;
extern uint32 sfrmem;

extern int extended;

//------------------------------------------------------------------------

enum i196_registers { rVcs, rVds, WSR, WSR1 };

typedef struct
{
  uchar addr;
  const char *name;
  const char *cmt;
} predefined_t;

extern predefined_t iregs[];

//------------------------------------------------------------------------

void idaapi header( void );
void idaapi footer( void );

void idaapi segstart( ea_t ea );
void idaapi segend( ea_t ea );

int  idaapi ana( void );
int  idaapi emu( void );
void idaapi out( void );
bool idaapi outop( op_t &op );

//void i196_data(ea_t ea);

#endif
