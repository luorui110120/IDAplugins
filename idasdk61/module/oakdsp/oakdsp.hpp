
#ifndef _OAKDSP_HPP
#define _OAKDSP_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//------------------------------------------------------------------

#define aux_cc                  0x000F   // condition code
#define aux_comma_cc            0x0010   // comma before cond
#define aux_iret_context        0x0020

#define cmd_cycles insnpref

#define phtype     specflag1 // o_phrase: phrase type
//0 (Rn)
//1 (Rn)+1
//2 (Rn)-1
//3 (Rn)+s
//4 (any_reg)

#define amode           specflag2 // addressing options & other
#define amode_short     0x01
#define amode_long      0x02
#define amode_x         0x04  // X:
#define amode_p         0x08  // P:
#define amode_neg       0x10  // -
#define amode_signed    0x10  // - if x<0


#define o_textphrase    o_idpspec0 // text type
#define o_local         o_idpspec1

#define textphtype      specflag1  // o_texttype: phrase type

#define text_swap       0x01
//(a0, b0)
//(a0, b1)
//(a1, b0)
//(a1, b1)
//(a0, b0), (a1, b1)
//(a0, b1), (a1, b0)
//(a0, b0, a1)
//(a0, b1, a1)
//(a1, b0, a0)
//(a1, b1, a0)
//(b0, a0, b1)
//(b0, a1, b1)
//(b1, a0, b0)
//(b1, a1, b0)

#define text_banke      0x02
//[r0], [r1], [r4], [cfgi]

#define text_cntx       0x03
//s
//r

#define text_dmod       0x04
//dmod

#define text_eu         0x05
//eu

#define mix_mode        0x80000000      //Func rrrrr should use both input value and param

//------------------------------------------------------------------
#define UAS_GNU 0x0001          // GNU assembler
//------------------------------------------------------------------
enum RegNo
{
  R0, R1, R2, R3, R4, R5,         //DAAU Registers
  RB,                             //Base Register
  Y,                              //Input Register
  ST0, ST1, ST2,                  //Status Registers
  P,                              //Output Register
  PC,                             //Program Counter
  SP,                             //Software Stack Pointer
  CFGI, CFGJ,                     //DAAU Configuration Registers
  B0H, B1H, B0L, B1L,             //Accumulator B
  EXT0, EXT1, EXT2, EXT3,         //External registers
  A0, A1, A0L, A1L, A0H, A1H,     //Accumulator A
  LC,                             //Loop Counter
  SV,                             //Shift Value Register
  X,                              //Input Register
  DVM,                            //Data Value Match Register
  MIXP,                           //Minimal/Maximal Pointer Register
  ICR,                            //Internal Configuration Register
  PS,                             //Product Shifter Control
  REPC,                           //Internal Repeat Counter
  B0, B1,                         //Accumulator B
  MODI,MODJ,                      //Modulo Modifier
  STEPI, STEPJ,                   //Linear (Step) Modifier
  PAGE,                           //Short Direct Addressing Mode Page
  vCS, vDS,                       //virtual registers for code and data segments
};


//------------------------------------------------------------------
// condition codes
enum cc_t
{
  cc_true,      //Always
  cc_eq,        //Equal to zero Z = 1
  cc_neq,       //Not equal to zero Z = 0
  cc_gt,        //Greater than zero M = 0 and Z = 0
  cc_ge,        //Greater than or equal to zero M = 0
  cc_lt,        //Less than zero M =1
  cc_le,        //Less than or equal to zero M = 1 or Z = 1
  cc_nn,        //Normalized flag is cleared N = 0
  cc_v,         //Overflow flag is set V = 1
  cc_c,         //Carry flag is set C = 1
  cc_e,         //Extension flag is set E = 1
  cc_l,         //Limit flag is set L = 1
  cc_nr,        //flag is cleared R = 0
  cc_niu0,      //Input user pin 0 is cleared
  cc_iu0,       //Input user pin 0 is set
  cc_iu1,       //Input user pin 1 is set
};

//------------------------------------------------------------------
extern char device[];
extern int procnum;


extern netnode helper;

#define IDP_SIMPLIFY 0x0001     // simplify instructions
#define IDP_PSW_W    0x0002     // W-bit in PSW is set

extern ushort idpflags;

inline bool dosimple(void)      { return (idpflags & IDP_SIMPLIFY) != 0; }
inline bool psw_w(void)         { return (idpflags & IDP_PSW_W) != 0; }

extern ea_t xmem;
ea_t calc_mem(op_t &x);

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
void idaapi oakdsp_data(ea_t ea);

int  idaapi is_align_insn(ea_t ea);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi is_sp_based(const op_t &x);
void idaapi gen_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v);
int  idaapi OAK_get_frame_retsize(func_t *pfn);

int is_jump_func(const func_t *pfn, ea_t *jump_target);
int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?

void init_analyzer(void);
void init_emu(void);

const char *find_port(ea_t address);

#endif // _OAKDSP_HPP
