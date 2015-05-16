#ifndef __NECV850_INC__
#define __NECV850_INC__

#include "../idaidp.hpp"
#include <list>
#include <pro.h>
#include <fpro.h>
#include <area.hpp>
#include <idd.hpp>
#include <ida.hpp>
#include <algorithm>
#include <name.hpp>
#include <idp.hpp>
#include <ieee.h>


 #ifndef SIGN_EXTEND
   #define SIGN_EXTEND(type, var, nbits) \
     if ( var & (1 << (nbits-1)) ) \
       var |= ~type((1 << nbits)-1)
 #endif


//----------------------------------------------------------------------
// Specific flags

//
// Used in op_t.specflag1
#define N850F_USEBRACKETS     0x01
#define N850F_OUTSIGNED       0x02

#define o_reglist               o_idpspec1      // Register list (for DISPOSE)

//
// Used in cmd.auxpref
#define N850F_SP                 0x00000001 // instruction modifies the stack pointer
#define N850F_ADDR_OP1           0x00000002 // designate that cmd.Op1 has an addr
#define N850F_ADDR_OP2           0x00000004 // designate that cmd.Op2 has an addr
#define N850F_CALL               0x00000008 // instruction will create a call near and not a flow


//----------------------------------------------------------------------
// Registers def
enum NEC850_Registers
{
  rZERO,
  rR1,   rR2,   rSP /* r3 */, rGP /* r4 */,
  rR5,   rR6,   rR7,   rR8,
  rR9,   rR10,  rR11,  rR12,
  rR13,  rR14,  rR15,  rR16,
  rR17,  rR18,  rR19,  rR20,
  rR21,  rR22,  rR23,  rR24,
  rR25,  rR26,  rR27,  rR28,
  rR29,  rEP,   rR31,
  // system registers start here
  rEIPC,  rEIPSW,  rFEPC,  rFEPSW,
  rECR,   rPSW,    rSR6,   rSR7,
  rSR8,   rSR9,    rSR10,  rSR11,
  rSR12,  rSR13,   rSR14,  rSR15,
  rSR16,  rSR17,   rSR18,  rSR19,
  rSR20,  rSR21,   rSR22,  rSR23,
  rSR24,  rSR25,   rSR26,  rSR27,
  rSR28,  rSR29,   rSR30,  rSR31,

  // segment registers
  rVep, // virtual element pointer segment register
  rVcs, rVds,

  rLastRegister
};

//----------------------------------------------------------------------
// Prototypes

// prototypes -- out.cpp
void idaapi nec850_header(void);
void idaapi nec850_segstart(ea_t ea);
void idaapi nec850_segend(ea_t ea);
void idaapi nec850_footer(void);
void idaapi nec850_out(void);
bool idaapi nec850_outop(op_t &x);

// prototypes -- ana.cpp
int  idaapi nec850_ana(void);
int  detect_inst_len(uint16 w);
int  fetch_instruction(uint32 *w);
bool decode_instruction(uint32 w, insn_t &cmd);

// prototypes -- emu.cpp
int  idaapi nec850_emu(void);
bool idaapi nec850_is_switch ( switch_info_ex_t *si );
bool idaapi nec850_create_func_frame(func_t *pfn);
int  idaapi nec850_get_frame_retsize(func_t *pfn);
int  idaapi nec850_is_sp_based(const op_t &x);
int  nec850_is_sane_insn(int no_crefs);

extern const char *RegNames[];
extern bool is_v850e;
extern ea_t g_gp_ea;

#endif
