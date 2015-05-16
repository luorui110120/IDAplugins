/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su, ig@datarescue.com
 *                              FIDO:   2:5020/209
 *
 */

#ifndef _I51_HPP
#define _I51_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

// 8051 bit references:

#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1

// fRi indirect register number (for o_phrase):
#define indreg          specflag1

// 80251 bit references (bit address in x.addr):

#define o_bit251        o_idpspec2
#define b251_bit        specflag1               // bit number
#define b251_bitneg     specflag2               // negate?


// cmd.auxpref bits:

#define aux_0ext      0x0001  // high bit 0-extension immediate value
#define aux_1ext      0x0002  // high bit 1-extension immediate value


// ash.uflag bit meanings:

#define UAS_PSAM        0x0001          // PseudoSam: use funny form of
                                        // equ for intmem
#define UAS_SECT        0x0002          // Segments are named .SECTION
#define UAS_NOSEG       0x0004          // No 'segment' directives
#define UAS_NOBIT       0x0008          // No bit.# names, use bit_#
#define UAS_SELSG       0x0010          // Segment should be selected by its name
#define UAS_EQCLN       0x0020          // ':' in EQU directives
#define UAS_AUBIT       0x0040          // Don't use BIT directives -
                                        // assembler generates bit names itself
#define UAS_CDSEG       0x0080          // Only DSEG,CSEG,XSEG
#define UAS_NODS        0x0100          // No .DS directives in Code segment
#define UAS_NOENS       0x0200          // don't specify start addr in the .end directive
#define UAS_PBIT        0x0400          // assembler knows about predefined bits
#define UAS_PBYTNODEF   0x0800          // do not define predefined byte names

enum processor_subtype_t
{
                // odd types are binary mode
                // even types are source modes
  prc_51 = 0,                      // plain 8051
  prc_251_bin,                     // 80251 in binary mode
  prc_251 = prc_251_bin,           // the same... (a shortcut)
  prc_251_src,                     // 80251 in source mode
  prc_930_bin,                     // 8x930 in source mode
  prc_930 = prc_930_bin,           // the same... (a shortcut)
  prc_930_src,                     // 8x930 in source mode
};

extern processor_subtype_t ptype;
extern char device[];
extern char deviceparams[];

extern ea_t intmem;               // address of the internal memory
extern ea_t sfrmem;               // address of SFR memory

ea_t map_addr(asize_t off, int opnum, bool isdata);

//------------------------------------------------------------------------
// Registers
enum i51_registers
{
  rAcc, rAB, rB,
  rR0, rR1, rR2, rR3, rR4, rR5, rR6, rR7,
  rR8, rR9, r10, r11, rR12, rR13, rR14, rR15,
  rWR0,  rWR2,  rWR4,  rWR6,  rWR8,  rWR10, rWR12, rWR14,
  rWR16, rWR18, rWR20, rWR22, rWR24, rWR26, rWR28, rWR30,
  rDR0,  rDR4,  rDR8,  rDR12, rDR16, rDR20, rDR24, rDR28,
  rDR32, rDR36, rDR40, rDR44, rDR48, rDR52, rDR56, rDR60,
  rDptr, rC, rPC,
  rVcs, rVds            // these 2 registers are required by the IDA kernel
};

// Indirect addressing modes without a displacement:
enum i51_phrases
{
  fR0,                  // @R0
  fR1,                  // @R1
  fDptr,                // @DPTR
  fAdptr,               // @A+DPTR
  fApc,                 // @A+PC
  fRi,                  // @WRj or @DRj, reg number in indreg
};

const ioport_t *find_sym(int address);
const ioport_bit_t *find_bit(ea_t address, int bit);
bool IsPredefined(const char *name);

//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi segstart(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);

void    idaapi i51_data(ea_t ea);

bool idaapi is_sane_insn(bool no_crefs);

#endif
