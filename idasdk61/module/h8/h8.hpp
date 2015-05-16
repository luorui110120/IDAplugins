/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _H8_HPP
#define _H8_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//---------------------------------
// Operand types:

/*
o_reg    1 Register direct Rn
           x.reg
o_phrase 2 Register indirect @ERn
           x.phrase contains register number
           x.phtype contains phrase type (normal, post, pre)
o_displ  3 Register indirect with displacement @(d:16,ERn)/@(d:32,ERn)
           x.reg, x.addr, aux_disp16, aux_disp32
o_phrase 4 Register indirect with post-increment @ERn+
           Register indirect with pre-decrement  @-ERn
o_mem    5 Absolute address @aa:8/@aa:16/@aa:24/@aa:32
           x.addr
o_imm    6 Immediate #xx:8/#xx:16/#xx:32
           x.value
o_displ  7 Program-counter relative @(d:8,PC)/@(d:16,PC)
o_memind 8 Memory indirect @@aa:8
           x.addr
o_reglist  Register list
           x.reg, x.nregs
*/

#define o_memind        o_idpspec0
#define o_reglist       o_idpspec1

#define phtype          specflag1       // phrase type:
const int ph_normal = 0;                // just simple indirection
const int ph_pre    = 1;                // predecrement
const int ph_post   = 2;                // postincrement

#define nregs           specflag1       // o_reglist: number of registers

//------------------------------------------------------------------
#define aux_byte        0x0001          // .b postfix
#define aux_word        0x0002          // .w postfix
#define aux_long        0x0004          // .l postfix
#define aux_disp16      0x0008          // 16bit displacement
#define aux_disp24      0x0010          // 24bit displacement
#define aux_disp32      0x0020          // 32bit displacement

//------------------------------------------------------------------
#ifdef _MSC_VER
#define ENUM8BIT : uint8
#else
#define ENUM8BIT
#endif
enum regnum_t ENUM8BIT
{
  R0,    R1,    R2,    R3,    R4,    R5,    R6,    R7, SP=R7,
  E0,    E1,    E2,    E3,    E4,    E5,    E6,    E7,
  R0H,   R1H,   R2H,   R3H,   R4H,   R5H,   R6H,   R7H,
  R0L,   R1L,   R2L,   R3L,   R4L,   R5L,   R6L,   R7L,
  ER0,   ER1,   ER2,   ER3,   ER4,   ER5,   ER6,   ER7,
  MACL,  MACH,
  PC,
  CCR,   EXR,
  rVcs, rVds,    // virtual registers for code and data segments
};

//------------------------------------------------------------------
// processor types

typedef uchar proctype_t;

static const proctype_t none  = 0;
static const proctype_t ADV   = 1;      // advanced mode
static const proctype_t P300  = 2;
static const proctype_t P2000 = 4;
static const proctype_t P2600 = 8;

static const proctype_t P30A = P300  | ADV;
static const proctype_t P26A = P2600 | ADV;

extern proctype_t ptype;        // contains all bits which correspond
                                // to the supported processors set

inline bool advanced(void) { return (ptype & ADV) != 0; }

//------------------------------------------------------------------
extern netnode helper;

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
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const op_t &x);

int idaapi h8_get_frame_retsize(func_t *);
int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?
int get_displ_outf(const op_t &x);

#endif // _H8_HPP
