/*
        This module has been created by Petr Novak
 */

#ifndef _XA_HPP
#define _XA_HPP

#include "../idaidp.hpp"
#include "ins.hpp"

//------------------------------------------------------------------------
// customization of the 'cmd' structure:

// XA bit references:

#define o_bit           o_idpspec0
#define o_bitnot        o_idpspec1

// fRi and other indirect register number (for o_phrase):
#define indreg          specflag1

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
  prc_xaG3 = 0,                    // XAG3
};

extern processor_subtype_t ptype;

#define INTMEMBASE      (2L << 24)
#define SFRBASE         (INTMEMBASE + 0x400)
#define EXTRAMBASE      (1L << 24)

inline ea_t map_addr(ea_t off)
{
  return ((off >= 0x800) ? EXTRAMBASE : INTMEMBASE) + off;
}

#define DS      0x441
#define ES      0x442
#define CS      0x443

//------------------------------------------------------------------------
// Registers
enum xa_registers
{
  rR0L, rR0H, rR1L, rR1H, rR2L, rR2H, rR3L, rR3H, rR4L, rR4H,
  rR5L, rR5H, rR6L, rR6H, rR7L, rR7H,
  rR0, rR1, rR2, rR3, rR4, rR5, rR6, rR7,
  rR8, rR9, rR10, rR11, rR12, rR13, rR14, rR15,
  rA, rDPTR, rC, rPC, rUSP,
  rCS, rDS, rES
};

// Indirect addressing modes without a displacement:
enum xa_phrases
{
  fAdptr,               // [A+DPTR]
  fApc,                 // [A+PC]
  fRi,                  // [Ri], reg number in indreg
  fRii,                 // [[Ri]], reg number in indreg
  fRip,                 // [Ri+], reg number in indreg
  fRipi,                // [[Ri+]], reg number in indreg
  fRid8,                // [Ri+d8], reg number in indreg
  fRid16,               // [Ri+d16], reg number in indreg
  fRlistL,              // PUSH/POP list of registers lower half
  fRlistH,              // PUSH/POP upper half of registers
};


// The predefined locations
struct predefined_t
{
  uchar proc;
  uint16 addr;
  uchar bit;
  const char *name;
  const char *cmt;
};

extern predefined_t iregs[];        // internal memory byte names
extern predefined_t ibits[];        // internal memory bit names
predefined_t *GetPredefined(predefined_t *ptr,int addr,int bit);
int IsPredefined(const char *name);

//------------------------------------------------------------------------
void    idaapi header(void);
void    idaapi footer(void);

void    idaapi segstart(ea_t ea);

int     idaapi ana(void);
int     idaapi emu(void);
void    idaapi out(void);
bool    idaapi outop(op_t &op);

void    idaapi xa_data(ea_t ea);

bool idaapi xa_create_func(func_t *pfn);

bool idaapi xa_is_switch(switch_info_ex_t *si);

int idaapi xa_frame_retsize(func_t *pfn);

void idaapi xa_stkvar_def(char *buf, size_t bufsize, const member_t *mptr, sval_t v);

int idaapi xa_align_insn(ea_t ea);

#endif
