
#ifndef _M32R_HPP
#define _M32R_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>

// Flags for operand specflag1

#define NEXT_INSN_PARALLEL_NOP          0x0001     // next insn is a // nop
#define NEXT_INSN_PARALLEL_DSP          0x0002     // next insn is a // dsp
#define NEXT_INSN_PARALLEL_OTHER        0x0004       // next insn is an other // insn

#define SYNTHETIC_SHORT                 0x0010     // insn is synthetic short (ex bc.s)
#define SYNTHETIC_LONG                  0x0020     // insn is synthetic long (ex bc.l)

#define HAS_MSB                         0x0100     // insn _has_ its MSB to 1

// Flags for idpflags

#define NETNODE_USE_INSN_SYNTHETIC      0x0001     // use synthetic instructions
#define NETNODE_USE_REG_ALIASES         0x0002     // use register aliases

// Synthetic instructions list:

/*
    m32r :

    bc.s label          bc label [8-bit offset]
    bc.l label          bc label [24-bit offset]
    bl.s label          bl label [8-bit offset]
    bl.l label          bl label [24-bit offset]
    bnc.s label         bnc label [8-bit offset]
    bnc.l label         bnc label [24-bit offset]
    bra.s label         bra label [8-bit offset]
    bra.l label         bra label [24-bit offset]
    ldi8 reg, #const    ldi reg, #const [8-bit constant]
    ldi16 reg, #const   ldi reg, #const [16-bit constant]
    push reg            st reg, @-sp
    pop reg             ld reg, @sp+

    m32rx :

    bcl.s label         bcl label [8 bit offset]
    bcl.l label         bcl label [24 bit offset]
    bncl.s label        bncl label [8 bit offset]
    bncl.l label        bncl label [24 bit offset]
*/

// Register aliases list:

/*
    m32r :

    r13         fp
    r14         lr
    r15         sp

    cr0         psw
    cr1         cbr
    cr2         spi
    cr3         spu
    cr6         bpc

    m32rx :

    cr8            bbpsw
    cr14        bbpc
*/

// define some shortcuts
#define rFP        rR13
#define rLR        rR14
#define rSP        rR15
#define rPSW       rCR0
#define rCBR       rCR1
#define rSPI       rCR2
#define rSPU       rCR3
#define rBPC       rCR6
#define rFPSR      rCR7

// m32rx only
#define rBBPSW    rCR8
#define rBBPC    rCR14

// m32r registers
enum m32r_registers {
    // General-purpose registers
    rR0, rR1, rR2, rR3, rR4,
    rR5, rR6, rR7, rR8, rR9,
    rR10, rR11, rR12, rR13, rR14, rR15,

    // Control registers
    rCR0, rCR1, rCR2, rCR3, rCR6,

    // Program counter
    rPC,

    // m32rx special registers

    rA0, rA1,                                        // Accumulators
    rCR4, rCR5, rCR7, rCR8, rCR9,                    // Add. control registers
    rCR10, rCR11, rCR12, rCR13, rCR14, rCR15,

    rVcs, rVds    // these 2 registers are required by the IDA kernel
};

// m32r indirect addressing mode
enum m32r_phrases {
    fRI,        // @R         Register indirect
    fRIBA,      // @R+        Register indirect update before add
    fRIAA,      // @+R        Register indirect update after add
    fRIAS       // @-R        Register indirect update after sub
};

// this module supports 2 processors: m32r and m32rx
enum processor_subtype_t {
    prc_m32r = 0,
    prc_m32rx = 1
};

extern processor_subtype_t ptype;

// idpflags helpers
extern uint32 idpflags;
inline bool use_synthetic_insn(void)     { return idpflags & NETNODE_USE_INSN_SYNTHETIC; }
inline bool use_reg_aliases(void)         { return idpflags & NETNODE_USE_REG_ALIASES; }

extern char device[];

// exporting our routines
void idaapi header(void);
void idaapi footer(void);
void idaapi gen_segm_header(ea_t addr);
int idaapi ana(void);
int idaapi emu(void);
void idaapi out(void);
bool idaapi outop(op_t &op);
void patch_regnames(void);
const ioport_t *find_sym(ea_t address);
bool idaapi create_func_frame(func_t *pfn);
int  idaapi m32r_get_frame_retsize(func_t *pfn);
int  idaapi is_sp_based(const op_t &op);
bool idaapi can_have_type(op_t &op);
void do_interr(const char *file, const int line, const char *message, ...);

// we need those horrible macros to print the current filename and line number in the 'warning' message box
#define interr(msg)         do_interr(__FILE__, __LINE__, msg)
#define interr2(msg,a)      do_interr(__FILE__, __LINE__, msg, a)
#define interr3(msg,a,b)    do_interr(__FILE__, __LINE__, msg, a, b)

// exporting the register names (needed by patch_regnames())
extern const char *RegNames[];

#endif /* _M32R_HPP */

