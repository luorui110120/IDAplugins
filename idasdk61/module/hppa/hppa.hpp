
/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#ifndef _HPPA_HPP
#define _HPPA_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <srarea.hpp>

//------------------------------------------------------------------

#define aux_cndc   0x0007   // condition bits c
#define aux_cndf   0x0008   // condition bits f
#define aux_cndd   0x0010   // condition bits d
#define aux_space  0x0020   // space register present

#define o_based   o_idpspec2    // (%r5)
                                // o_phrase: %r4(%r5)
                                // o_displ:  55(%r5)
#define sid        specflag1
#define secreg     specflag2    // for o_phrase, the index register
//------------------------------------------------------------------
enum RegNo
{
  // general registers
  R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
  R8,   R9,   R10,  R11,  R12,  R13,  R14,  R15,
  R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
  R24,  R25,  R26,  DP,   R28,  R29,  SP,   R31,
  // space registers
  SR0,  SR1,  SR2,  SR3,  SR4,  SR5,  SR6,  SR7,
  // control registers
  CR0,   CR1,   CR2,   CR3,   CR4,   CR5,   CR6,   CR7,
  CR8,   CR9,   CR10,  CR11,  CR12,  CR13,  CR14,  CR15,
  CR16,  CR17,  CR18,  CR19,  CR20,  CR21,  CR22,  CR23,
  CR24,  CR25,  CR26,  CR27,  CR28,  CR29,  CR30,  CR31,
  // floating-point registers
  F0,   F1,   F2,   F3,   F4,   F5,   F6,   F7,
  F8,   F9,   F10,  F11,  F12,  F13,  F14,  F15,
  F16,  F17,  F18,  F19,  F20,  F21,  F22,  F23,
  F24,  F25,  F26,  F27,  F28,  F29,  F30,  F31,
  // register halves (valid only for fmpyadd/sub)
  F16L, F17L, F18L, F19L, F20L, F21L, F22L, F23L,
  F24L, F25L, F26L, F27L, F28L, F29L, F30L, F31L,
  F16R, F17R, F18R, F19R, F20R, F21R, F22R, F23R,
  F24R, F25R, F26R, F27R, F28R, F29R, F30R, F31R,
  // condition bits
  CA0, CA1, CA2, CA3, CA4, CA5, CA6,

  DPSEG, rVcs, rVds,    // virtual registers for code and data segments
};

//------------------------------------------------------------------
// Bit definitions.
// Note that the bit order is unusual: the LSB is BIT31
// This is a so-called big-endian bit order.
#define BIT31   0x00000001L
#define BIT30   0x00000002L
#define BIT29   0x00000004L
#define BIT28   0x00000008L
#define BIT27   0x00000010L
#define BIT26   0x00000020L
#define BIT25   0x00000040L
#define BIT24   0x00000080L
#define BIT23   0x00000100L
#define BIT22   0x00000200L
#define BIT21   0x00000400L
#define BIT20   0x00000800L
#define BIT19   0x00001000L
#define BIT18   0x00002000L
#define BIT17   0x00004000L
#define BIT16   0x00008000L
#define BIT15   0x00010000L
#define BIT14   0x00020000L
#define BIT13   0x00040000L
#define BIT12   0x00080000L
#define BIT11   0x00100000L
#define BIT10   0x00200000L
#define BIT9    0x00400000L
#define BIT8    0x00800000L
#define BIT7    0x01000000L
#define BIT6    0x02000000L
#define BIT5    0x04000000L
#define BIT4    0x08000000L
#define BIT3    0x10000000L
#define BIT2    0x20000000L
#define BIT1    0x40000000L
#define BIT0    0x80000000L

//------------------------------------------------------------------
extern ea_t got;

extern netnode helper;          // altval(-1) -> idpflags
                                // altval(ea) -> function frame register or 0

#define IDP_SIMPLIFY 0x0001     // simplify instructions
#define IDP_PSW_W    0x0002     // W-bit in PSW is set
#define IDP_MNEMONIC 0x0004     // use mnemonic register names

extern ushort idpflags;

inline bool dosimple(void)      { return (idpflags & IDP_SIMPLIFY) != 0; }
inline bool psw_w(void)         { return (idpflags & IDP_PSW_W) != 0; }
inline bool mnemonic(void)      { return (idpflags & IDP_MNEMONIC) != 0; }

ea_t calc_mem(ea_t ea);         // map virtual to phisycal ea
const char *get_syscall_name(int syscall);

typedef int proc_t;
const proc_t PROC_HPPA = 0;    // HPPA big endian

extern proc_t ptype;               // processor type

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
int  idaapi hppa_get_frame_retsize(func_t *);

int idaapi is_sp_based(const op_t &x);
int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?
bool is_basic_block_end(void);

//--------------------------------------------------------------------------
// functions to get various fields from the instruction code
inline int opcode(uint32 code) { return (code>>26) & 0x3F; }
inline int r06(uint32 code) { return (code>>21) & 0x1F; }
inline int r11(uint32 code) { return (code>>16) & 0x1F; }
inline int r22(uint32 code) { return (code>> 5) & 0x1F; }
inline int r27(uint32 code) { return (code>> 0) & 0x1F; }
inline int get11(uint32 code)  // 11bit field for branches
{
  return ((code>>3) & 0x3FF) | ((code&4)<<(10-2));
}
inline int32 get17(uint32 code)
{
  return ((code&1) << 16)
       | (r11(code) << 11)
       | get11(code);
}
inline sval_t as21(uint32 x)
{
  //           1         2
  // 012345678901234567890  bit number
  // 2         1
  // 098765432109876543210  shift amount
  x =    (((x>>12) & 0x003) << 0)  //  2: x{7..8}
       | (((x>>16) & 0x01F) << 2)  //  5: x{0..4}
       | (((x>>14) & 0x003) << 7)  //  2: x{5..6}
       | (((x>> 1) & 0x7FF) << 9)  // 11: x{9..19}
       | (((x>> 0) & 0x001) <<20); //  1: x{20}
  return int32(x << 11);
}
inline int assemble_16(int x, int y)
{
  if ( psw_w() )
  {
    int r = 0;
    if ( y & 1 )
    {
      x ^= 3;
      r = 0x8000;
    }
    return ((y>>1) & 0x1FFF) | (x<<13) | r;
  }
  return ((y>>1) & 0x1FFF) | ((y&1) ? 0xE000 : 0);
}
inline int get_ldo(uint32 code) { return assemble_16((code>>14)&3,code & 0x3FFF); }

//--------------------------------------------------------------------------

char *build_insn_completer(uint32 code, char *buf, size_t bufsize);
ea_t calc_possible_memref(op_t &x);


// type system functions
int hppa_calc_arglocs(const type_t *type, cm_t cc, uint32 *arglocs);
int hppa_use_arg_types(ea_t caller,
                       const type_t * const *types,
                       const char * const *names,
                       const uint32 *arglocs,
                       int n,
                       const type_t **rtypes,
                       const char **rnames,
                       uint32 *rlocs,
                       int rn);
int hppa_use_regvar_type(ea_t ea,
                         const type_t * const *types,
                         const char * const *names,
                         const uint32 *regs,
                         int n);

#endif // _HPPA_HPP
