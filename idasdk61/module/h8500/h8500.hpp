/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _H8500_HPP
#define _H8500_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <srarea.hpp>

//---------------------------------
// Operand types:

/*
o_reg    1 Register direct Rn
           x.reg
o_phrase 2 Register indirect @Rn
           x.phrase contains register number
           x.phtype contains phrase type (normal, post, pre)
o_displ  3 Register indirect with displacement @(d:8,Rn)/@(d:16,Rn)
           x.reg, x.addr, aux_disp16, aux_disp32
o_mem    5 Absolute address @aa:8/@aa:16/@aa:24
           x.page, x.addr
o_imm    6 Immediate #xx:8/#xx:16/#xx:32
           x.value
o_displ  7 Program-counter relative @(d:8,PC)/@(d:16,PC)
o_reglist  Register list
           x.reg
*/

#define o_reglist       o_idpspec0

#define phtype          specflag1       // phrase type:
const int ph_normal = 0;                // just simple indirection
const int ph_pre    = 1;                // predecrement
const int ph_post   = 2;                // postincrement

#define page            specflag1       // o_mem, page number if aux_page
//------------------------------------------------------------------
#define aux_byte        0x0001          // .b postfix
#define aux_word        0x0002          // .w postfix
#define aux_disp8       0x0004          //  8bit displacement
#define aux_disp16      0x0008          // 16bit displacement
#define aux_disp24      0x0010          // 24bit displacement
#define aux_page        0x0020          // implicit page using BR
#define aux_f           0x0040          // /f postfix
#define aux_ne          0x0080          // /ne postfix
#define aux_eq          0x0100          // /eq postfix
#define aux_mov16       0x0200          // mov #xx:16, ...

//------------------------------------------------------------------
enum regnum_t
{
  R0,    R1,    R2,    R3,    R4,    R5,    R6, FP=R6, R7, SP=R7,
  SR, CCR, RES1, BR, EP, DP, CP, TP, // RES1 is forbidden
};

//------------------------------------------------------------------
extern netnode helper;
extern ushort idpflags;

#define AFIDP_MIXSIZE   0x0001  // Disassemble mixed size instructions

ea_t calc_mem(op_t &x);         // map virtual to physical ea
const char *find_sym(int address);
//------------------------------------------------------------------
void interr(const char *module);
int calc_opimm_flags(void);
int calc_opdispl_flags(void);

void idaapi header(void);
void idaapi footer(void);

void idaapi segstart(ea_t ea);
void idaapi segend(ea_t ea);
void idaapi assume(ea_t ea);         // function to produce assume directives

void idaapi out(void);
int  idaapi outspec(ea_t ea,uchar segtype);

int  idaapi ana(void);
int  idaapi emu(void);
bool idaapi outop(op_t &op);
void idaapi data(ea_t ea);

int  idaapi is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const op_t &x);

int idaapi h8500_get_frame_retsize(func_t *);
int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?

#endif // _H8500_HPP
