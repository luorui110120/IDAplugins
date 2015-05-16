
#ifndef __M7700_HPP
#define __M7700_HPP

#include "../idaidp.hpp"
#include "ins.hpp"
#include <diskio.hpp>
#include <frame.hpp>
#include <srarea.hpp> // for getSR()

// flags for cmd.op[n].specflag1
#define OP_IMM_WITHOUT_SHARP    0x0001  // don't display the # for this immediate
#define OP_ADDR_IND             0x0002  // this address should be printed between '(' ')'
#define OP_DISPL_IND            0x0004  // this displacement should be printed between '(' ')'
#define OP_DISPL_IND_P1         0x0008  // only the first parameter of the displacement
                                        // should be printed between '(' ')'
#define OP_ADDR_R               0x0010  // addr operand used in 'read' context
#define OP_ADDR_W               0x0020  // addr operand used in 'write' context
#define OP_ADDR_DR_REL          0x0040  // addr operand is relative to DR (direct page register)

// specflag1 helpers
inline bool is_imm_without_sharp(op_t &op)  { return op.specflag1 & OP_IMM_WITHOUT_SHARP; }
inline bool is_addr_ind(op_t &op)           { return op.specflag1 & OP_ADDR_IND; }
inline bool is_addr_read(op_t &op)          { return op.specflag1 & OP_ADDR_R; }
inline bool is_addr_write(op_t &op)         { return op.specflag1 & OP_ADDR_W; }
inline bool is_displ_ind(op_t &op)          { return op.specflag1 & OP_DISPL_IND; }
inline bool is_displ_ind_p1(op_t &op)       { return op.specflag1 & OP_DISPL_IND_P1; }
inline bool is_addr_dr_rel(op_t &op)        { return op.specflag1 & OP_ADDR_DR_REL; }

// flags for cmd.auxpref
#define INSN_LONG_FORMAT        0x0001  // we need to write an additionnal 'l'
                                        // after the insn mnemonic.
// auxpref helpers
inline bool is_insn_long_format() { return cmd.auxpref & INSN_LONG_FORMAT; }

// flags for ash.uflag
#define UAS_SEGM                0x0001  // segments are named "segment XXX"
#define UAS_INDX_NOSPACE        0x0002  // no spaces between operands in indirect X addressing mode
#define UAS_END_WITHOUT_LABEL   0x0004  // do not print the entry point label after end directive
#define UAS_DEVICE_DIR          0x0008  // supports device declaration directives
#define UAS_BITMASK_LIST        0x0010  // supports list instead of bitmask for some special insn
                                        // like clp, psh...

// 7700 registers
enum m7700_registers {
    rA,     // accumulator A
    rB,     // accumulator B
    rX,     // index X
    rY,     // index Y
    rS,     // stack pointer
    rPC,    // program counter
    rPG,    // program bank register
    rDT,    // data bank register
    rPS,    // processor status register
    rDR,    // direct page register
    rfM,    // data length flag
    rfX,    // index register length flag
    rVcs, rVds     // these 2 registers are required by the IDA kernel
};

// this module supports 2 processors: m7700, m7750
enum processor_subtype_t {
    prc_m7700 = 0,
    prc_m7750 = 1
};

extern processor_subtype_t ptype;

extern char device[];

// shortcut for a new operand type
#define o_bit              o_idpspec0

// exporting our routines
void idaapi header(void);
void idaapi footer(void);
int idaapi ana(void);
int idaapi emu(void);
void idaapi out(void);
bool idaapi outop(op_t &op);
void idaapi gen_segm_header(ea_t ea);
void idaapi gen_assumes(ea_t ea);
const ioport_t *find_sym(ea_t address);
const ioport_bit_t *find_bit(ea_t address, size_t bit);
bool idaapi create_func_frame(func_t *pfn);
int idaapi idp_get_frame_retsize(func_t *pfn);

#endif // __M7700_HPP
