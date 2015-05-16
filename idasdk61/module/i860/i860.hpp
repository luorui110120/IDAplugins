/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#ifndef __I860_HPP
#define __I860_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

                                // Intel 860 cmd.auxpref bits:
#define aux_dual        0x1     // is dual
#define aux_sdbl        0x2     // source double
#define aux_rdbl        0x4     // result double

#define _PT_860XR       0x01                    // Intel 860 XR
#define _PT_860XP       0x02                    // Intel 860 XP

#define PT_860XP         _PT_860XP
#define PT_860XR        ( PT_860XP | _PT_860XR )

extern int pflag;

inline int is860XP(void) { return (pflag & PT_860XP) != 0; }

//------------------------------------------------------------------------

enum i860RegNo {
  R_r0,  R_r1,  R_r2,  R_r3,  R_r4,  R_r5,  R_r6,  R_r7,
  R_r8,  R_r9,  R_r10, R_r11, R_r12, R_r13, R_r14, R_r15,
  R_r16, R_r17, R_r18, R_r19, R_r20, R_r21, R_r22, R_r23,
  R_r24, R_r25, R_r26, R_r27, R_r28, R_r29, R_r30, R_r31,

  R_f0,  R_f1,  R_f2,  R_f3,  R_f4,  R_f5,  R_f6,  R_f7,
  R_f8,  R_f9,  R_f10, R_f11, R_f12, R_f13, R_f14, R_f15,
  R_f16, R_f17, R_f18, R_f19, R_f20, R_f21, R_f22, R_f23,
  R_f24, R_f25, R_f26, R_f27, R_f28, R_f29, R_f30, R_f31,

  R_fir,
  R_psr,
  R_dirbase,
  R_db,
  R_fsr,
  R_epsr,
  R_bear,
  R_ccr,
  R_p0,
  R_p1,
  R_p2,
  R_p3,
  R_vcs,R_vds           // virtual segment registers
};

#define bit0    (1L<<0)
#define bit1    (1L<<1)
#define bit2    (1L<<2)
#define bit3    (1L<<3)
#define bit4    (1L<<4)
#define bit5    (1L<<5)
#define bit6    (1L<<6)
#define bit7    (1L<<7)
#define bit8    (1L<<8)
#define bit9    (1L<<9)
#define bit10   (1L<<10)
#define bit11   (1L<<11)
#define bit12   (1L<<12)
#define bit13   (1L<<13)
#define bit14   (1L<<14)
#define bit15   (1L<<15)
#define bit16   (1L<<16)
#define bit17   (1L<<17)
#define bit18   (1L<<18)
#define bit19   (1L<<19)
#define bit20   (1L<<20)
#define bit21   (1L<<21)
#define bit22   (1L<<22)
#define bit23   (1L<<23)
#define bit24   (1L<<24)
#define bit25   (1L<<25)
#define bit26   (1L<<26)
#define bit27   (1L<<27)
#define bit28   (1L<<28)
#define bit29   (1L<<29)
#define bit30   (1L<<30)
#define bit31   (1L<<31)

#define Rbit    bit7            // Result is double precision
#define Sbit    bit8            // Source is double precision
#define Dbit    bit9            // Dual Instruction
#define Pbit    bit10           // Pipelining

void    idaapi i860_header(void);
void    idaapi i860_footer(void);

void    idaapi i860_segstart(ea_t ea);

int     idaapi i860_ana(void);
int     idaapi i860_emu(void);
void    idaapi i860_out(void);
bool    idaapi i860_outop(op_t &op);

#endif
