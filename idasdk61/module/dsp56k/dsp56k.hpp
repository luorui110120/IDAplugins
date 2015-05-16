
#ifndef _DSP56K_HPP
#define _DSP56K_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//------------------------------------------------------------------

#define aux_cc     0x000F   // condition code
#define aux_su     0x0003   // sign/unsing code

#define phtype    specflag1 // o_phrase: phrase type
// 0 (Rn)–Nn
// 1 (Rn)+Nn
// 2 (Rn)–
// 3 (Rn)+
// 4 (Rn)
// 5 (Rn+Nn)
// 7 –(Rn)
// 8 $+Rn
// 9 (a1)
// 10 (b1)

#define amode           specflag2 // addressing mode
#define amode_ioshort   0x01  // <<
#define amode_short     0x02  // <
#define amode_long      0x04  // >
#define amode_neg       0x08  // -
#define amode_x         0x10  // X:
#define amode_y         0x20  // Y:
#define amode_p         0x40  // P:
#define amode_l         0x80  // L:

#define imode           specflag3 // IF mode
#define imode_if        0x01 // IFcc
#define imode_ifu       0x02 // IFUcc

#define o_iftype        o_idpspec0 //IF type

#define o_vsltype       o_idpspec1 //VSL 2-nd operand type

//------------------------------------------------------------------
#define UAS_GNU 0x0001          // GNU assembler
//------------------------------------------------------------------
enum RegNo ENUM_SIZE(uint16)
{
  // data arithmetic logic unit
  X, X0, X1,
  Y, Y0, Y1,
  // accumulator registers
  A, A0, A1, A2,
  B, B0, B1, B2,
  AB,    // a1:b1
  BA,    // b1:a1
  A10,   // a1:a0
  B10,   // b1:b0
  // address generation unit (AGU)
  R0, R1, R2, R3, R4, R5, R6, R7,  // pointers
  N0, N1, N2, N3, N4, N5, N6, N7,  // offsets
  M0, M1, M2, M3, M4, M5, M6, M7,  // modifiers
  // Program Control Unit
  PC,  // Program Counter (16 Bits)
  MR,  // Mode Register (8 Bits)
  CCR, // Condition Code Register (8 Bits)
  SR,  // Status Register (MR:CCR, 16 Bits)
  OMR, // Operating Mode Register (8 Bits)
  LA,  // Hardware Loop Address Register (16 Bits)
  LC,  // Hardware Loop Counter (16 Bits)
  SP,  // System Stack Pointer (6 Bits)
  SS,  // System Stack RAM (15X32 Bits)
  SSH, // Upper 16 Bits of the Contents of the Current Top of Stack
  SSL, // Lower 16 Bits of the Contents of the Current Top of Stack
  SZ,  // Stack Size register
  SC,  // Stack Counter register
  EP,  // Extension Pointer register
  VBA, // Vector Base Address Register

  vCS, vDS,       // virtual registers for code and data segments

};


//------------------------------------------------------------------
// condition codes
enum cc_t
{
  cc_CC, // carry clear (higher or same) C=0
  cc_GE, // greater than or equal N Å V=0
  cc_NE, // not equal Z=0
  cc_PL, // plus N=0
  cc_NN, // not normalized Z+(U·E)=0
  cc_EC, // extension clear E=0
  cc_LC, // limit clear L=0
  cc_GT, // greater than Z+(N Å V)=0
  cc_CS, // carry set (lower) C=1
  cc_LT, // less than N Å V=1
  cc_EQ, // equal Z=1
  cc_MI, // minus N=1
  cc_NR, // normalized Z+(U·E)=1
  cc_ES, // extension set E=1
  cc_LS, // limit set L=1
  cc_LE, // less than or equal Z+(N Å V)=1
};

//------------------------------------------------------------------

enum PMoveClass
{
  cl_0 = 0,     //No Parallel move
  cl_1,         //X Memory Data Move (common)
  cl_1_3,       //X Memory Data Move with short displacement
  cl_2,         //Dual X Memory Data Read
  cl_3,         //X Memory Data Write and Register Data Move
};

//------------------------------------------------------------------
// signed/unsigned codes
enum su_t
{
  s_SS, // signed * signed
  s_SU, // signed * unsigned
  s_UU, // unsigned * unsigned
};

//------------------------------------------------------------------
// DSP56K instruction may have many operands. We keep them separately
// in the following structure.

struct addargs_t
{
  ea_t ea;
  int nargs;
  op_t args[4][2];
};

extern addargs_t aa;

// Make sure that the 'aa' structure is up to date.
void fill_additional_args(void);

//------------------------------------------------------------------
extern char device[];
extern int procnum; // 0 - dsp56k, 1 - dsp561xx, 2 - dsp563xx, 3 - dsp566xx

inline bool is561xx(void) { return procnum == 1; }
inline bool is563xx(void) { return procnum == 2; }
inline bool is566xx(void) { return procnum == 3; }

extern netnode helper;

#define IDP_SIMPLIFY 0x0001     // simplify instructions
#define IDP_PSW_W    0x0002     // W-bit in PSW is set

extern ushort idpflags;

inline bool dosimple(void)      { return (idpflags & IDP_SIMPLIFY) != 0; }
inline bool psw_w(void)         { return (idpflags & IDP_PSW_W) != 0; }

extern ea_t xmem;
extern ea_t ymem;
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
void idaapi dsp56k_data(ea_t ea);

int  idaapi is_align_insn(ea_t ea);
int  idaapi is_sp_based(const op_t &x);

int is_sane_insn(int nocrefs);
int may_be_func(void);           // can a function start here?

void init_analyzer(void);
const char *find_port(ea_t address);

#endif // _DSP56K_HPP
