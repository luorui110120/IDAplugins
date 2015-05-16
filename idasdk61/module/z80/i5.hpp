/*
 *      Interactive disassembler (IDA).
 *      Version 2.06
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef I5HPP
#define I5HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//------------------------------------------------------------------
// customization of cmd structure:
#define o_cond  o_idpspec0

#define Cond    reg


//------------------------------------------------------------------
enum opcond_t          // condition code types
{
  oc_nz,
  oc_z,
  oc_nc,
  oc_c,
  oc_po,
  oc_pe,
  oc_p,
  oc_m,
  oc_not
};

//------------------------------------------------------------------
#define _PT_64180       0x01                    // HD64180
#define _PT_Z80         0x02                    // Z80
#define _PT_8085        0x04                    // Intel 8085
#define _PT_Z180        0x08                    // Z180
#define _PT_Z380        0x10                    // Z380
#define _PT_GB          0x20                    // GameBoy

#define PT_GB            _PT_GB
#define PT_Z380          _PT_Z380
#define PT_Z180         ( PT_Z380 | _PT_Z180)
#define PT_64180        ( PT_Z180 | _PT_64180)
#define PT_Z80          ( PT_64180| _PT_Z80  | _PT_GB)
#define PT_8085         ( PT_Z80  | _PT_8085 )

extern int pflag;

inline bool isGB(void)    { return (pflag & PT_GB)  != 0;   }
inline bool isZ380(void)  { return (pflag & PT_Z380)!= 0;   }
inline bool isZ180(void)  { return (pflag & PT_Z180)!= 0;   }
inline bool isZ80(void)   { return (pflag & PT_Z80) != 0;   }
inline bool is64180(void) { return (pflag & PT_64180) != 0; }
inline bool is8085(void)  { return !isZ80();                }

enum RegNo ENUM_SIZE(uint16)
{

 R_b = 0,
 R_c = 1,
 R_d = 2,
 R_e = 3,
 R_h = 4,
 R_l = 5,
 R_a = 7,
 R_bc = 8,
 R_de = 9,
 R_hl = 10,
 R_af = 11,
 R_sp = 12,
 R_ix = 13,
 R_iy = 14,
 R_af2 = 15,
 R_r = 16,
 R_i = 17,
 R_f = 18,
 R_xl = 19,
 R_xh = 20,
 R_yl = 21,
 R_yh = 22,

 R_w,
 R_lw,
 R_ixl,
 R_ixu,
 R_dsr,
 R_xsr,
 R_iyl,
 R_iyu,
 R_ysr,
 R_sr,
 R_ib,
 R_iw,
 R_xm,
 R_lck,
 R_bc2,
 R_de2,
 R_hl2,
 R_ix2,
 R_iy2,
 R_b2,
 R_c2,
 R_d2,
 R_e2,
 R_h2,
 R_l2,
 R_m2,
 R_a2,

 R_vcs,            // virtual code segment register
 R_vds             // virtual data segment register
};


extern char device[];
extern char deviceparams[];
//------------------------------------------------------------------

void idaapi i5_header(void);
void idaapi i5_footer(void);

void idaapi i5_assumes(ea_t ea);
void idaapi i5_segstart(ea_t ea);

int   idaapi i5_ana(void);
int   idaapi i5_emu(void);
void  idaapi i5_out(void);
bool  idaapi i5_outop(op_t &op);

//------------------------------------------------------------------
const char *z80_find_ioport(uval_t port);
const char *z80_find_ioport_bit(int port, int bit);

//------------------------------------------------------------------
#define UAS_NOENS   0x0001              // I5: don't specify start addr in the .end directive
#define UAS_NPAIR   0x0002              // I5: pairs are denoted by 1 char ('b')
#define UAS_UNDOC   0x0004              // I5: does assembler support undoc-d instrs?
#define UAS_MKIMM   0x0008              // I5: place # in front of imm operand
#define UAS_MKOFF   0x0010              // I5: offset(ix) form
#define UAS_CNDUP   0x0020              // I5: conditions UPPERCASE
#define UAS_FUNNY   0x0040              // I5: special for A80
#define UAS_CSEGS   0x0080              // I5: generate 'cseg' directives
#define UAS_TOFF    0x0100              // I5: (ix+-10)
#define UAS_ZMASM   0x0200              // ZMASM
#define UAS_GBASM   0x0400              // RGBASM


#define aux_off16   0x0001              // o_displ: off16

#endif // I5HPP
