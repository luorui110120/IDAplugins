/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _TMS320C54_HPP
#define _TMS320C54_HPP

#include "../idaidp.hpp"
#include <diskio.hpp>
#include "ins.hpp"

// #define TMS320C54_NO_NAME_NO_REF

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  PC,  // program counter
  A,   // accumulator
  B,   // accumulator

  // flags
  ASM, // 5-bit accumulator shift mode field in ST1
  ARP, // auxiliary register pointer
  TS,  // shift value (bits 5-0 of T)
  OVB,
  OVA,
  C,
  TC,
  CMPT,
  FRCT,
  C16,
  SXM,
  OVM,
  INTM,
  HM,
  XF,
  BRAF,

  // CPU memory mapped registers
  IMR,
  IFR,
  ST0,
  ST1,
  AL,
  AH,
  AG,
  BL,
  BH,
  BG,
  T,   // temporary register
  TRN, // transition register
  AR0,
  AR1,
  AR2,
  AR3,
  AR4,
  AR5,
  AR6,
  AR7,
  SP,  // stack pointer
  BK,
  BRC,
  RSA,
  REA,
  PMST,

  // segment registers
  XPC, // program counter extension register
  CPL, // compiler mode
  DP,  // data page pointer
  rVcs, rVds,  // virtual registers for code and data segments
  rnone = 0xFF,   // no register
};

//------------------------------------------------------------------
// specific condition codes
#define COND_A 0x0
#define COND_B 0x8

#define COND_GEQ 0x2
#define COND_LT  0x3
#define COND_NEQ 0x4
#define COND_EQ  0x5
#define COND_GT  0x6
#define COND_LEQ 0x7


#define COND4_AGEQ (COND_A | COND_GEQ)
#define COND4_ALT  (COND_A | COND_LT)
#define COND4_ANEQ (COND_A | COND_NEQ)
#define COND4_AEQ  (COND_A | COND_EQ)
#define COND4_AGT  (COND_A | COND_GT)
#define COND4_ALEQ (COND_A | COND_LEQ)

#define COND4_BGEQ (COND_B | COND_GEQ)
#define COND4_BLT  (COND_B | COND_LT)
#define COND4_BNEQ (COND_B | COND_NEQ)
#define COND4_BEQ  (COND_B | COND_EQ)
#define COND4_BGT  (COND_B | COND_GT)
#define COND4_BLEQ (COND_B | COND_LEQ)


#define COND8_FROM_COND4 0x40

#define COND8_UNC  0x00
#define COND8_NBIO 0x02
#define COND8_BIO  0x03
#define COND8_NC   0x08
#define COND8_C    0x0C
#define COND8_NTC  0x20
#define COND8_TC   0x30
#define COND8_AGEQ (COND8_FROM_COND4 | COND4_AGEQ)
#define COND8_ALT  (COND8_FROM_COND4 | COND4_ALT)
#define COND8_ANEQ (COND8_FROM_COND4 | COND4_ANEQ)
#define COND8_AEQ  (COND8_FROM_COND4 | COND4_AEQ)
#define COND8_AGT  (COND8_FROM_COND4 | COND4_AGT)
#define COND8_ALEQ (COND8_FROM_COND4 | COND4_ALEQ)
#define COND8_ANOV 0x60
#define COND8_AOV  0x70
#define COND8_BGEQ (COND8_FROM_COND4 | COND4_BGEQ)
#define COND8_BLT  (COND8_FROM_COND4 | COND4_BLT)
#define COND8_BNEQ (COND8_FROM_COND4 | COND4_BNEQ)
#define COND8_BEQ  (COND8_FROM_COND4 | COND4_BEQ)
#define COND8_BGT  (COND8_FROM_COND4 | COND4_BGT)
#define COND8_BLEQ (COND8_FROM_COND4 | COND4_BLEQ)
#define COND8_BNOV (COND_B | COND8_ANOV)
#define COND8_BOV  (COND_B | COND8_AOV)

//------------------------------------------------------------------
// specific processor records

#define o_bit    o_idpspec0
#define o_cond8  o_idpspec1
#define o_cond2  o_idpspec2
#define o_local  o_idpspec3
#define o_mmr    o_idpspec4
#define o_farmem o_idpspec5

#define Op4_type  auxpref_chars.low
#define Op4_value auxpref_chars.high
#define IsParallel segpref

// != 0 => MOD = IndirectAddressingMOD-1
#define IndirectAddressingMOD specflag1
#define ABSOLUTE_INDIRECT_ADRESSING 0xF // special "indirect" adressing
                                        // (in fact absolute adressing)
#define Signed specflag1
#define NoCardinal specflag2
#define IOimm specflag3

//------------------------------------------------------------------
// specific device name

extern char device[MAXSTR];

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

const proctype_t TMS320C54 = 0;

extern proctype_t ptype;    // contains processor type

extern ea_t dataseg;
//------------------------------------------------------------------
extern netnode helper;

#define TMS320C54_IO           0x0001  // use I/O definitions
#define TMS320C54_MMR          0x0002  // use memory mapped registers

extern ushort idpflags;

ea_t use_mapping(ea_t ea);

ea_t calc_code_mem(ea_t ea, bool is_near = true);
ea_t calc_data_mem(ea_t ea, bool is_mem = true);

regnum_t get_mapped_register(ea_t ea);
const char *get_cond8(char value);
int get_signed(int byte,int mask);

const char *find_sym(ea_t address);
const ioport_bit_t *find_bits(ea_t address);
const char *find_bit(ea_t address, int bit);
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

void idaapi gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v);
bool idaapi create_func_frame(func_t *pfn);
int idaapi tms_get_frame_retsize(func_t *pfn);
int idaapi is_align_insn(ea_t ea);
bool is_basic_block_end(void); // 0-no, 2-yes

#endif // _TMS320C54_HPP
